//! RESEARCH ONLY: frozen target forecast binding and bounded owner audit.
//! No environment, clock, adaptive estimate or outcome is consulted in choose().
use std::sync::{Arc, Mutex, OnceLock};
use std::collections::BTreeMap;

pub const PLAN_VERSION: &str = "frozen-target-v1";
pub const FORECAST_SHA256: &str = "5e5081cd1ebdc9ddb78391fdb8f7eaaabdb74586bda86bbc6d590a238e153ef5";
pub const MIX_SEED: u64 = 0x5354505f544d0001;
pub const EVIDENCE_CAPACITY: usize = 4096;
pub const MAX_PLAN_K: u32 = 32000;
static CONFIG: OnceLock<(&'static str, f64, f64, u64)> = OnceLock::new();

pub(crate) fn initialize(selector:u32, profile:Option<&str>, cost:u32, cap:u32, empirical:u32) -> Result<(),String> {
    if selector > 2 { return Err("STP_P4_TARGET_VALIDATION must be 0, 1 or 2".into()); }
    if empirical != 1 || (selector == 0 && (cost != 0 || cap != 25)) || (selector != 0 && (cost != 1 || cap != 0)) {
        return Err("target validation requires empirical1; selector0/cost0/cap25 or selector1|2/cost1/cap0".into());
    }
    let c = match profile {
        Some("g4") => ("g4",0.04354000000000002,333.33333333333337,MIX_SEED),
        Some("b20r20") => ("b20r20",0.005739999999999967,33.333333333333336,MIX_SEED),
        _ => return Err("target validation requires STP_COHORT_PROFILE=g4 or b20r20".into())
    };
    let _=risk_config(); // validate the optional research knobs before sending
    let _=tail_config();
    let _=dup_config();
    let _=rand_config();
    crate::stp::initialize_delay_event();
    let _=CONFIG.set(c); Ok(())
}
/// p4-cc-calm research override: STP_TV_P (design loss p), STP_TV_H (exposure scale H), STP_TV_E (exponent e):
/// target miss = p / (1 + (K/H)^e). All three must be set together; unset = frozen anchors with e=1.
static OVERRIDE: OnceLock<Option<(f64,f64,f64)>> = OnceLock::new();
fn tv_override() -> Option<(f64,f64,f64)> {
    *OVERRIDE.get_or_init(|| {
        let g=|n:&str| crate::ship::policy_var(n).ok().map(|v| v.parse::<f64>().expect(n));
        match (g("STP_TV_P"),g("STP_TV_H"),g("STP_TV_E")) {
            (Some(p),Some(h),Some(e)) => { assert!(p>0.&&p<0.5&&h>0.&&e>0.); Some((p,h,e)) }
            (None,None,None) => None,
            _ => panic!("STP_TV_P/STP_TV_H/STP_TV_E must be set together"),
        }
    })
}
/// Coherent connection-local risk and random-loss evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct RiskSnapshot {
    rate:u64, anchor:u64, latest_rtt_ns:u64, min_rtt_ns:u64, qd_ref_ns:u64, mode:char,
    smoothed_rtt_ns:u64, latch_ns:Option<u64>, event_ns:Option<u64>,
    rand:RandState, rand_guard_until_ns:u64,
}
/// Shared only by one connection and its send queues/root owners.
#[derive(Clone, Default)]
pub(crate) struct RiskState(Arc<Mutex<RiskSnapshot>>);
impl std::fmt::Debug for RiskState {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("RiskState { .. }")}
}
impl RiskState {
    pub(crate) fn same_connection(&self,other:&Self)->bool {Arc::ptr_eq(&self.0,&other.0)}
}
fn risk_now_ns() -> u64 {
    static START:OnceLock<std::time::Instant>=OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_nanos().min((u64::MAX-1) as u128) as u64+1
}
fn refresh_latch(s:&mut RiskSnapshot) { update_latch(s,risk_config(),risk_now_ns()); }
pub(crate) fn risk_rate(state: &RiskState,rate:u64, anchor:u64, mode:char, smoothed_rtt_ns:u64) {
    let mut s=state.0.lock().unwrap(); s.rate=rate; s.anchor=anchor; s.mode=mode;
    s.smoothed_rtt_ns=smoothed_rtt_ns; refresh_latch(&mut s);
}
pub(crate) fn risk_rtt(state: &RiskState,sample_ns:u64, min_rtt_ns:u64) {
    let mut s=state.0.lock().unwrap(); s.latest_rtt_ns=sample_ns; s.min_rtt_ns=min_rtt_ns; refresh_latch(&mut s);
}
pub(crate) fn risk_congestion(state: &RiskState,anchor:u64, rtt_ns:u64, guard_rtts:f64, recovery_rtts:u64, queue_signal:bool) {
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s); s.anchor=anchor;
    s.event_ns=Some(risk_now_ns());
    if rand_config().is_some() {
        // Only queue evidence (accepted CE/delay), never a loss-only cut.
        let now=s.event_ns.unwrap();
        rand_queue_guard(&mut s,queue_signal,now,rtt_ns,guard_rtts,recovery_rtts);
    }
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns);
    if qd!=0 { s.qd_ref_ns=qd; }
    refresh_latch(&mut s);
}
/// RAND shares its connection's risk snapshot. Corrections of declared spurious
/// losses are intentionally ignored.
#[derive(Clone, Copy, Debug)]
struct RandConfig { mult:f64, alpha:f64, max:f64 }
fn rand_config()->Option<RandConfig> {
    static RAND:OnceLock<Option<RandConfig>>=OnceLock::new();
    *RAND.get_or_init(|| {
        if !env_switch("STP_TV_RAND") {return None;}
        let base=tv_override().expect("STP_TV_RAND requires STP_TV_P/STP_TV_H/STP_TV_E").0;
        let required=|n:&str| {
            let x=crate::ship::policy_var(n).unwrap_or_else(|_|panic!("{n} is required when RAND is on"))
                .parse::<f64>().unwrap_or_else(|_|panic!("{n} must be finite"));
            assert!(x.is_finite(),"{n} must be finite"); x
        };
        let (mult,half,max)=(required("STP_TV_RAND_MULT"),required("STP_TV_RAND_HALF_PKTS"),required("STP_TV_RAND_MAX"));
        assert!(mult>=1.,"STP_TV_RAND_MULT must be >=1");
        assert!(half>0.,"STP_TV_RAND_HALF_PKTS must be >0");
        assert!(max>0. && max<1. && max>=base,"STP_TV_RAND_MAX must be in (0,1) and >= STP_TV_P");
        Some(RandConfig{mult,alpha:-(-std::f64::consts::LN_2/half).exp_m1(),max})
    })
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct RandState { p:f64, bg_packets:u64, bg_lost:u64, p_base:f64 }
impl RandState {
    fn observe(&mut self,cfg:Option<RandConfig>,background:bool,lost:bool) {
        let Some(c)=cfg else {return};
        if !background {return;}
        self.bg_packets=self.bg_packets.saturating_add(1);
        self.bg_lost=self.bg_lost.saturating_add(u64::from(lost));
        self.p+=c.alpha*((if lost {1.}else{0.})-self.p);
    }
    fn base(self,c:RandConfig,floor:f64)->f64 {(c.mult*self.p).max(floor).min(c.max)}
}
fn rand_queue_guard(s:&mut RiskSnapshot,queue_signal:bool,now:u64,rtt_ns:u64,guard_rtts:f64,recovery_rtts:u64) {
    if !queue_signal {return;}
    // Separate accepted-event clock: app-limit rebasing cannot extend this guard.
    let duration=if rtt_ns==0 {u64::MAX}else{(rtt_ns as f64*guard_rtts.max(recovery_rtts as f64)) as u64};
    s.rand_guard_until_ns=s.rand_guard_until_ns.max(now.saturating_add(duration));
}
/// Estimator-only missing-signal semantics. Admission/duplication retain their
/// original unknown-anchor/queue fallbacks. An absent ramp is not congestion.
fn background_risk(s:RiskSnapshot,c:RiskConfig)->f64 {
    let ramp=|x:f64,lo:f64,hi:f64|((x-lo)/(hi-lo)).clamp(0.,1.);
    let cc=(s.anchor!=0).then(||ramp(s.rate as f64/s.anchor as f64,c.lo,c.hi));
    let queue=(s.qd_ref_ns!=0).then(||ramp(s.latest_rtt_ns.saturating_sub(s.min_rtt_ns) as f64/s.qd_ref_ns as f64,c.lo2,c.hi2));
    match c.src {
        1=>cc.unwrap_or(0.),2=>queue.unwrap_or(0.),
        3=>cc.unwrap_or(0.).max(queue.unwrap_or(0.)),
        // With one missing AND operand, use the available signal; both absent=0.
        4=>match (cc,queue) {(Some(a),Some(b))=>a.min(b),(a,b)=>a.or(b).unwrap_or(0.)},
        _=>unreachable!(),
    }
}
fn background_from(s:RiskSnapshot,cfg:Option<RiskConfig>,now:u64,outage:bool)->bool {
    // Use raw risk: STEP=1/2 must not turn the intermediate ramp into background.
    // HOLD/latch is a duplication/step device, not a congestion signal: ignored here.
    !outage && now>s.rand_guard_until_ns
        && cfg.is_none_or(|c|background_risk(s,c)==0.)
}
pub(crate) fn rand_enabled()->bool {rand_config().is_some()}
pub(crate) fn rand_background(state: &RiskState,outage:bool)->bool {
    if !rand_enabled() {return false;}
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    background_from(*s,risk_config(),risk_now_ns(),outage)
}
pub(crate) fn rand_resolved(state: &RiskState,background:bool,lost:bool) {
    if !background {return;}
    let mut s=state.0.lock().unwrap(); s.rand.observe(rand_config(),background,lost);
}
/// Resolved eligible DATA counters and current/last-admitted ppm gauges.
pub(crate) fn rand_counters(state: &RiskState,)->(u64,u64,u64,u64) {
    if !rand_enabled() {return (0,0,0,0);}
    let r=state.0.lock().unwrap().rand;
    (r.bg_packets,r.bg_lost,(r.p*1e6).round() as u64,(r.p_base*1e6).round() as u64)
}
fn rand_admission_from(s:RiskSnapshot,cfg:Option<RiskConfig>,base:f64,rand:Option<RandConfig>)->RiskAdmission {
    let Some(c)=rand else {return admission_from(s,cfg,base)};
    let p_base=s.rand.base(c,base);
    let cfg=cfg.map(|c|RiskConfig{phi:c.phi.max(p_base),..c});
    let mut a=admission_from(s,cfg,p_base);
    if cfg.is_none() {a.p_eff=p_base;}
    a.p_base=p_base; a
}
#[derive(Clone, Copy, Debug)]
struct RiskConfig { src:u32, lo:f64, hi:f64, lo2:f64, hi2:f64, phi:f64, eps:Option<f64>, step:u32, hold:Option<(f64,f64)> }
static RISK_CONFIG: OnceLock<Option<RiskConfig>> = OnceLock::new();
fn step_config()->u32 {
    crate::ship::policy_var("STP_TV_RISK_STEP").map_or(0,|v|match v.as_str() {
        "0"=>0,"1"=>1,"2"=>2,_=>panic!("STP_TV_RISK_STEP must be 0, 1 or 2"),
    })
}
fn risk_config() -> Option<RiskConfig> {
    *RISK_CONFIG.get_or_init(|| {
        let src=crate::ship::policy_var("STP_TV_RISK_SRC").map_or(0, |v| v.parse::<u32>().expect("STP_TV_RISK_SRC must be 0, 1, 2, 3 or 4"));
        assert!(src<=4,"STP_TV_RISK_SRC must be 0, 1, 2, 3 or 4");
        if src==0 {
            assert!(crate::ship::policy_var_os("STP_TV_RISK_TAIL").is_none(),"STP_TV_RISK_TAIL requires STP_TV_RISK_SRC != 0");
            assert!(step_config()==0,"STP_TV_RISK_STEP=1 or 2 requires STP_TV_RISK_SRC != 0");
            assert!(!env_switch("STP_TV_DUP"),"STP_TV_DUP=1 requires STP_TV_RISK_SRC != 0");
            for n in ["STP_TV_RISK_HOLD_RTTS","STP_TV_RISK_HOLD_MAX_RTTS"] {
                assert!(crate::ship::policy_var_os(n).is_none(),"{n} requires STP_TV_RISK_SRC != 0");
            }
            return None;
        }
        assert!(tv_override().is_some(),"risk requires STP_TV_P/STP_TV_H/STP_TV_E (P is the base floor)");
        let required=|n:&str| {
            let v=crate::ship::policy_var(n).unwrap_or_else(|_|panic!("{n} is required when risk is on"));
            let x=v.parse::<f64>().unwrap_or_else(|_|panic!("{n} must be a finite number"));
            assert!(x.is_finite(),"{n} must be finite"); x
        };
        let (lo,hi)=(required("STP_TV_RISK_LO"),required("STP_TV_RISK_HI"));
        assert!(lo<hi,"STP_TV_RISK_LO must be less than STP_TV_RISK_HI");
        let (lo2,hi2)=if src==3 || src==4 {(required("STP_TV_RISK_LO2"),required("STP_TV_RISK_HI2"))}else{(lo,hi)};
        assert!(lo2<hi2,"STP_TV_RISK_LO2 must be less than STP_TV_RISK_HI2");
        let phi=required("STP_TV_RISK_PHI");
        assert!(phi>0.&&phi<1.,"STP_TV_RISK_PHI must be in (0,1)");
        let eps=crate::ship::policy_var("STP_TV_RISK_EPS").ok().map(|_|required("STP_TV_RISK_EPS"));
        assert!(eps.is_none_or(|x|x>0.&&x<1.),"STP_TV_RISK_EPS must be in (0,1)");
        let step=step_config();
        let hold=crate::ship::policy_var_os("STP_TV_RISK_HOLD_RTTS").map(|_| {
            assert!(step!=0,"STP_TV_RISK_HOLD_RTTS requires STP_TV_RISK_STEP=1 or 2");
            let (h,m)=(required("STP_TV_RISK_HOLD_RTTS"),required("STP_TV_RISK_HOLD_MAX_RTTS"));
            assert!(h>=0. && m>0.,"HOLD_RTTS must be >=0 and HOLD_MAX_RTTS >0"); (h,m)
        });
        assert!(hold.is_some() || crate::ship::policy_var_os("STP_TV_RISK_HOLD_MAX_RTTS").is_none(),"HOLD_MAX_RTTS requires HOLD_RTTS");
        // LO/LO2 remain mandatory and validated even in step mode (only HI matters).
        Some(RiskConfig{src,lo,hi,lo2,hi2,phi,eps,step,hold})
    })
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RiskAdmission {
    pub risk:f64, pub p_eff:f64, pub rate_over_anchor:f64,
    pub queue_delay_us:f64, pub qd_ref_us:f64, pub mode:char,
    pub p_base:f64, // RAND-only, frozen per logical root; 0 when off.
}
fn raw_risk(s:RiskSnapshot,c:RiskConfig)->f64 {
    let ratio=if s.anchor==0 {0.}else{s.rate as f64/s.anchor as f64};
    let ramp=|x:f64,lo:f64,hi:f64| ((x-lo)/(hi-lo)).clamp(0.,1.);
    let cc=if s.anchor==0 {1.}else{ramp(ratio,c.lo,c.hi)};
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns);
    let queue=if s.qd_ref_ns==0 {cc}else{ramp(qd as f64/s.qd_ref_ns as f64,c.lo2,c.hi2)};
    match c.src {1=>cc,2=>queue,3=>cc.max(queue),4=>cc.min(queue),_=>unreachable!()}
}
/// Hold from the most recent accepted event AFTER this latch. No event: false-alarm
/// cap from latch time. Unknown smoothed RTT cannot expire a hold. A still-high
/// step may immediately re-latch; low raw risk cannot truncate an active hold.
fn update_latch(s:&mut RiskSnapshot,cfg:Option<RiskConfig>,now:u64) {
    let Some(c)=cfg else {return};
    let Some((h,m))=c.hold else {return};
    if let Some(start)=s.latch_ns {
        let event=s.event_ns.filter(|&t|t>start);
        let expired=s.smoothed_rtt_ns!=0 && match event {
            Some(t)=>now.saturating_sub(t) as f64 >= h*s.smoothed_rtt_ns as f64,
            None=>now.saturating_sub(start) as f64 >= m*s.smoothed_rtt_ns as f64,
        };
        if expired {s.latch_ns=None;}
    }
    if s.latch_ns.is_none() && raw_risk(*s,c)>=1. {s.latch_ns=Some(now);}
}
fn decision_risk(s:RiskSnapshot,c:RiskConfig,step:bool)->f64 {
    let raw=raw_risk(s,c);
    if step {if raw>=1. || (c.hold.is_some() && s.latch_ns.is_some()) {1.}else{0.}}else{raw}
}
fn admission_from(s:RiskSnapshot, cfg:Option<RiskConfig>, base:f64) -> RiskAdmission {
    let ratio=if s.anchor==0 {0.}else{s.rate as f64/s.anchor as f64};
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns);
    // STEP=2 scopes step/hold to duplication; coded roots and tails retain the ramp.
    let risk=cfg.map_or(0.,|c|decision_risk(s,c,c.step==1));
    RiskAdmission{p_base:0.,risk,p_eff:cfg.map_or(0.,|c|base+(c.phi-base)*risk),rate_over_anchor:ratio,
        queue_delay_us:qd as f64/1000.,qd_ref_us:s.qd_ref_ns as f64/1000.,mode:s.mode}
}
fn env_switch(n:&str)->bool {
    crate::ship::policy_var(n).ok().is_some_and(|v| {assert!(v=="0" || v=="1","{n} must be 0 or 1"); v=="1"})
}
fn dup_config()->bool {
    static DUP:OnceLock<bool>=OnceLock::new();
    *DUP.get_or_init(|| {let on=env_switch("STP_TV_DUP"); assert!(!on || risk_config().is_some(),"STP_TV_DUP requires risk");on})
}
pub(crate) fn duplicate_at_risk(enabled:bool,risk:f64)->bool {enabled && risk>=1.}
fn duplicate_from(s:RiskSnapshot,cfg:Option<RiskConfig>)->bool {
    cfg.is_some_and(|c|duplicate_at_risk(true,decision_risk(s,c,c.step!=0)))
}
pub(crate) fn duplicate_now(state: &RiskState,)->bool {
    if !dup_config() {return false;}
    let cfg=risk_config();
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    duplicate_from(*s,cfg)
}
/// Called exactly once at first root admission; reused for all its groups/segments.
pub(crate) fn risk_admission(state: &RiskState,) -> RiskAdmission {
    let cfg=risk_config();
    // Off must not newly parse P/H/E in the baseline selector-0 arm.
    let rand=rand_config();
    let base=if cfg.is_some() || rand.is_some() {tv_override().unwrap().0}else{0.};
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    let a=rand_admission_from(*s,cfg,base,rand);
    if rand.is_some() {s.rand.p_base=a.p_base;}
    a
}
fn tail_config() -> Option<f64> {
    static TAIL:OnceLock<Option<f64>>=OnceLock::new();
    *TAIL.get_or_init(|| crate::ship::policy_var("STP_TV_RISK_TAIL").ok().map(|v| {
        assert!(risk_config().is_some(),"STP_TV_RISK_TAIL requires STP_TV_RISK_SRC != 0");
        let t=v.parse::<f64>().expect("STP_TV_RISK_TAIL must be finite and positive RTTs");
        assert!(t.is_finite() && t>0.,"STP_TV_RISK_TAIL must be finite and positive RTTs"); t
    }))
}
#[derive(Clone,Copy,Debug,Default,PartialEq)]
pub(crate) struct TailPlan {pub risk:f64,pub k:u32,pub added:u32}
/// Exposure uses CC micro-packets/s and smoothed RTT nanoseconds. Tail mixing is
/// domain-separated from admission: draw(admission_draw XOR ASCII "TAIL_RSV").
fn tail_from(k:u32,remaining:u32,selector:u32,profile:&str,mix_draw:u64,s:RiskSnapshot,rtt_ns:u64,cfg:Option<RiskConfig>,tail:Option<f64>,root_base:f64) -> Result<TailPlan,String> {
    let Some(t)=tail else {return Ok(TailPlan::default())};
    let c=cfg.ok_or("tail requires risk")?;
    let a=if root_base>0. {admission_from(s,Some(RiskConfig{phi:c.phi.max(root_base),..c}),root_base)}
        else {admission_from(s,Some(c),tv_override().map_or(0.005,|o|o.0))};
    let kt=((s.rate as f64/1_000_000.)*(rtt_ns as f64/1e9)*t).ceil().min(k as f64) as u32;
    let reserve=if kt==0 {0}else{plan_for_risk(kt,selector,profile,draw(mix_draw^0x5441494c5f525356),a,Some(c))?.proactive};
    Ok(TailPlan{risk:a.risk,k:kt,added:reserve.saturating_sub(remaining)})
}
pub(crate) fn tail_plan(state: &RiskState,k:u32,remaining:u32,selector:u32,mix_draw:u64,root_base:f64) -> Result<TailPlan,String> {
    let tail=tail_config();
    if tail.is_none() {return Ok(TailPlan::default())}
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    let rtt=s.smoothed_rtt_ns;
    tail_from(k,remaining,selector,configuration().0,mix_draw,*s,rtt,risk_config(),tail,root_base)
}
pub fn configuration() -> (&'static str,f64,f64,u64) { CONFIG.get().copied().unwrap_or(("uninitialized",0.,0.,MIX_SEED)) }

#[derive(Clone,Copy,Debug,Default,PartialEq)]
pub struct Plan { pub k:u32, pub proactive:u32, pub lower:u32, pub upper:u32, pub upper_probability:f64, pub mix_threshold:u64, pub mix_draw:u64 }
/// SplitMix64 finalizer, predeclared seed and admission sequence, independent of timing and outcomes.
pub fn draw(sequence:u64) -> u64 {
    let mut z=MIX_SEED.wrapping_add(sequence.wrapping_mul(0x9e3779b97f4a7c15));
    z=(z^(z>>30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z=(z^(z>>27)).wrapping_mul(0x94d049bb133111eb); z^(z>>31)
}
/// Normalized binomial mass from its mode, same recurrence as frozen forecast.py.
fn delivery(k:u32,r:u32,p:f64) -> f64 {
    let n=k+r; let mode=(((n+1) as f64*p).floor() as u32).min(n);
    let mut total=1.; let mut good=if mode<=r {1.} else {0.}; let mut mass=1.;
    for i in (1..=mode).rev() { mass*=i as f64/(n-i+1) as f64*(1.-p)/p; total+=mass; if i-1<=r {good+=mass;} }
    mass=1.; for i in mode..n { mass*=(n-i) as f64/(i+1) as f64*p/(1.-p); total+=mass; if i+1<=r {good+=mass;} }
    (good/total).clamp(0.,1.)
}
pub fn frozen_plan(k:u32,selector:u32,profile:&str,mix_draw:u64) -> Result<Plan,String> {
    plan_with_loss(k,selector,profile,mix_draw,None)
}
pub(crate) fn plan_at_admission(k:u32,selector:u32,profile:&str,mix_draw:u64,a:RiskAdmission) -> Result<Plan,String> {
    if risk_config().is_none() && rand_enabled() {return plan_with_loss(k,selector,profile,mix_draw,Some((a.p_eff,None)));}
    plan_for_risk(k,selector,profile,mix_draw,a,risk_config())
}
fn plan_for_risk(k:u32,selector:u32,profile:&str,mix_draw:u64,a:RiskAdmission,cfg:Option<RiskConfig>) -> Result<Plan,String> {
    plan_with_loss(k,selector,profile,mix_draw,cfg.map(|c|(a.p_eff,c.eps)))
}
/// Revalidate a captured plan using its admission-time loss, never a live snapshot.
#[cfg(any(test,feature="research_target_validation"))]
pub fn plan_from_evidence(r:&OwnerEvidence,profile:&str) -> Result<Plan,String> {
    plan_with_loss(r.k,r.selector,profile,r.mix_draw,risk_config().map(|c|(r.p_eff,c.eps)).or_else(||rand_config().map(|_|(r.p_eff,None))))
}
fn plan_with_loss(k:u32,selector:u32,profile:&str,mix_draw:u64,loss:Option<(f64,Option<f64>)>) -> Result<Plan,String> {
    plan_with_policy(k,selector,profile,mix_draw,loss,tv_override())
}
fn plan_with_policy(k:u32,selector:u32,profile:&str,mix_draw:u64,loss:Option<(f64,Option<f64>)>,policy:Option<(f64,f64,f64)>) -> Result<Plan,String> {
    if k==0 || k>MAX_PLAN_K || !(1..=2).contains(&selector) {return Err("unsupported frozen target K/selector".into());}
    let (base,h,e)=match (policy,profile) {(Some(o),_)=>o,(None,"g4")=>(0.04354000000000002,333.33333333333337,1.),(None,"b20r20")=>(0.005739999999999967,33.333333333333336,1.),_=>return Err("unknown frozen profile".into())};
    let p=loss.map_or(base,|v|v.0);
    if !p.is_finite() || p<=0. || p>=1. {return Err("invalid admission design loss".into());}
    #[cfg(feature="research_target_validation")]
    {
    // p4-cc-calm research: STP_TV_ZERO_MIN_K=K -> no proactive parity for native K >= K (post-seal top-up covers them).
    static ZERO_MIN_K: OnceLock<Option<u32>> = OnceLock::new();
    let zmk=*ZERO_MIN_K.get_or_init(|| crate::ship::policy_var("STP_TV_ZERO_MIN_K").ok().map(|v| v.parse::<u32>().expect("STP_TV_ZERO_MIN_K")));
    static ZERO_MAX_K: OnceLock<Option<u32>> = OnceLock::new();   // STP_TV_ZERO_MAX_K=M: zero band is K in [Z, M) (exclusive)
    let zxk=*ZERO_MAX_K.get_or_init(|| crate::ship::policy_var("STP_TV_ZERO_MAX_K").ok().map(|v| v.parse::<u32>().expect("STP_TV_ZERO_MAX_K")));
    if zmk.is_some_and(|z| k>=z) && zxk.is_none_or(|m| k<m) {return Ok(Plan{k,proactive:0,lower:0,upper:0,upper_probability:0.,mix_threshold:0,mix_draw});}
    }
    let target=loss.and_then(|v|v.1).unwrap_or_else(||p/(1.+(k as f64/h).powf(e)));
    let good=|r| 1.-delivery(k,r,p)<=target;
    let mut hi=0;
    if !good(0) {hi=1;while !good(hi) {hi=hi.checked_mul(2).filter(|v|*v<=MAX_PLAN_K).ok_or("unbounded frozen reserve")?;} let mut lo=0;while lo+1<hi {let mid=(lo+hi)/2;if good(mid){hi=mid;}else{lo=mid;}}}
    let lo=hi.saturating_sub(1); let dlo=delivery(k,lo,p);let dhi=delivery(k,hi,p);
    let w=if dhi>dlo {((1.-target-dlo)/(dhi-dlo)).clamp(0.,1.)}else{0.};
    // floor(w*2^64). Endpoint 1 is handled separately; never wrap 2^64.
    let threshold=(w*18446744073709551616.).floor() as u64;
    let proactive=if selector==1 || w==1. || mix_draw<threshold {hi}else{lo};
    Ok(Plan{k,proactive,lower:lo,upper:hi,upper_probability:w,mix_threshold:threshold,mix_draw})
}

#[cfg(any(test,feature="research_target_validation"))]
#[derive(Clone,Copy,Debug,Default,PartialEq)]
pub struct OwnerEvidence {
    pub generation:u64, pub root_id:u64, pub package_id:u64, pub root_ordinal:u64, pub app_tag:[u8;8],
    pub segment_offset:u32, pub selector:u32, pub k:u32, pub current_k:u32, pub groups:u32,
    pub proactive:u32, pub lower:u32, pub upper:u32, pub w_bits:u64, pub mix_threshold:u64, pub mix_draw:u64,
    pub known_losses:u32, pub planned_repairs:u32, pub sources_emitted:u64, pub repairs_emitted:u64,
    pub started_ns:u64, pub sealed_ns:u64, pub sealed:bool, pub restarts:u32,
    pub risk:f64, pub p_eff:f64, pub rate_over_anchor:f64,
    pub queue_delay_us:f64, pub qd_ref_us:f64, pub mode:char,
    pub tail_risk:f64, pub tail_k:u32, pub tail_added:u32,
}
pub(crate) fn active()->bool {CONFIG.get().is_some()}
#[cfg(any(test,feature="research_target_validation"))]
pub(crate) type Owner = Arc<Mutex<OwnerEvidence>>;
#[cfg(any(test,feature="research_target_validation"))]
#[derive(Debug,Default)]
pub struct Evidence {pub rows:Vec<OwnerEvidence>,pub dropped:u64}
#[cfg(any(test,feature="research_target_validation"))]
#[derive(Default)]
struct Audit {next:u64, rows:BTreeMap<u64,Owner>,dropped:u64}
#[cfg(feature="research_target_validation")]
static AUDIT:OnceLock<Mutex<Audit>>=OnceLock::new();
#[cfg(feature="research_target_validation")]
fn audit()->&'static Mutex<Audit> {AUDIT.get_or_init(Default::default)}
#[cfg(any(test,feature="research_target_validation"))]
pub(crate) fn register(mut row:OwnerEvidence)->Owner {
    #[cfg(feature="research_target_validation")]
    {
        let mut a=audit().lock().unwrap();a.next=a.next.checked_add(1).expect("owner sequence exhausted");row.generation=a.next;
        let owner=Arc::new(Mutex::new(row));
        if a.rows.len()<EVIDENCE_CAPACITY {let key=a.next;a.rows.insert(key,owner.clone());}else{a.dropped=a.dropped.saturating_add(1);}
        owner
    }
    #[cfg(not(feature="research_target_validation"))]
    { Arc::new(Mutex::new(row)) }
}
/// Cumulative snapshots; deduplicate generation, retaining latest. Completed owners retire only
/// after all slot/commit references are gone, so the last snapshot includes real syscall commits.
#[cfg(feature="research_target_validation")]
pub fn take()->Evidence {
    let mut a=audit().lock().unwrap();let mut rows=Vec::with_capacity(a.rows.len());
    a.rows.retain(|_,owner|{rows.push(owner.lock().unwrap().clone());Arc::strong_count(owner)>1});
    Evidence{rows,dropped:a.dropped}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature="research_target_validation")]
    #[test] fn unfrozen_research_risk_child() {
        let Ok(case)=std::env::var("STP_RC_UNFROZEN_PROBE") else {return;};
        let cfg=risk_config();
        if case=="src0" {assert!(cfg.is_none());}
        else {
            let cfg=cfg.unwrap();
            assert_eq!(cfg.step,0);
            assert!(cfg.hold.is_none());
            assert!(cfg.eps.is_none());
        }
        assert!(tail_config().is_none());
        assert!(!dup_config());
    }
    #[cfg(feature="research_target_validation")]
    #[test] fn unfrozen_research_can_disable_risk_or_step_without_inherited_dependencies() {
        for case in ["src0","step0"] {
            let mut child=std::process::Command::new(std::env::current_exe().unwrap());
            child.args(["--exact","target_validation::tests::unfrozen_research_risk_child","--nocapture"]);
            for (key,_) in std::env::vars().filter(|(k,_)|k.starts_with("STP_")) {child.env_remove(key);}
            child.env("STP_POLICY_FROZEN","0").env("STP_RC_UNFROZEN_PROBE",case);
            if case=="src0" {child.env("STP_TV_RISK_SRC","0");}
            else {
                for (key,value) in FROZEN_RESEARCH_RISK_FOR_TEST {
                    child.env(key,value);
                }
            }
            let out=child.output().unwrap();
            assert!(out.status.success(),"{case}: {}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
        }
    }
    #[cfg(feature="research_target_validation")]
    const FROZEN_RESEARCH_RISK_FOR_TEST:&[(&str,&str)]=&[
        ("STP_TV_P","0.001"),("STP_TV_H","33.333333333333336"),("STP_TV_E","1"),
        ("STP_TV_RISK_SRC","4"),("STP_TV_RISK_STEP","0"),
        ("STP_TV_RISK_LO","0.98"),("STP_TV_RISK_HI","1.02"),
        ("STP_TV_RISK_LO2","0.5"),("STP_TV_RISK_HI2","0.7"),("STP_TV_RISK_PHI","0.1"),
    ];
    fn rand_test_config()->RandConfig {RandConfig{mult:2.,alpha:-(-std::f64::consts::LN_2/1000.).exp_m1(),max:0.1}}
    fn rand_test_risk()->RiskConfig {RiskConfig{src:1,lo:0.9,hi:1.1,lo2:0.8,hi2:1.,phi:0.12,eps:Some(0.001),step:2,hold:None}}
    #[test] fn rand_estimator_converges_background_only() {
        let c=rand_test_config(); let mut r=RandState::default();
        // Exactly 0.35% loss, uniformly spread in deterministic 2000-packet blocks.
        for i in 0..100_000 {r.observe(Some(c),true,(i%2000)*7%2000<7);}
        assert!((r.p-0.0035).abs()<0.0004,"estimate {}",r.p);
        assert_eq!((r.bg_packets,r.bg_lost),(100_000,350));
        let before=r;
        for _ in 0..100_000 {r.observe(Some(c),false,true);}
        assert_eq!(r,before,"congested losses do not update counts OR EWMA");
        let mut half=RandState{p:1.,..Default::default()};
        for _ in 0..1000 {half.observe(Some(c),true,false);}
        assert!((half.p-0.5).abs()<1e-12,"packet half-life");
    }
    #[test] fn rand_background_uses_send_ramp_and_event_recovery() {
        let c=rand_test_risk();
        let s=RiskSnapshot{rate:80,anchor:100,rand_guard_until_ns:100,..Default::default()};
        assert!(background_from(s,Some(c),101,false));
        assert!(!background_from(s,Some(c),100,false));
        assert!(!background_from(s,Some(c),101,true));
        assert!(background_from(RiskSnapshot{latch_ns:Some(10),..s},Some(c),101,false),"hold latch alone is not congestion");
        assert!(background_from(RiskSnapshot{latch_ns:Some(10),anchor:0,..s},Some(c),101,false),"hold latched with anchor 0 is background");
        for src in 1..=4 {
            let c=RiskConfig{src,..c};
            let high=RiskSnapshot{rate:100,latest_rtt_ns:190,min_rtt_ns:100,qd_ref_ns:100,..s};
            assert!(!background_from(high,Some(c),101,false),"SRC{src} raw ramp must not be STEP-rounded to background");
        }
        assert!(background_from(RiskSnapshot{anchor:0,..s},Some(c),101,false),"no anchor is not congestion evidence");
        // Eligibility is captured at send; later event/risk changes cannot relabel it.
        let background=background_from(s,Some(c),101,false);
        let mut r=RandState::default();r.observe(Some(rand_test_config()),background,true);
        assert_eq!((r.bg_packets,r.bg_lost),(1,1));
    }
    #[test] fn rand_missing_ramps_and_queue_only_event_guards() {
        let c=rand_test_risk();let rc=rand_test_config();
        let mut s=RiskSnapshot::default();
        for src in 1..=4 {assert!(background_from(s,Some(RiskConfig{src,..c}),1,false),"SRC{src}: both ramps unknown are background");}
        let queue_high=RiskSnapshot{latest_rtt_ns:200,min_rtt_ns:100,qd_ref_ns:100,..s};
        for src in [2,3,4] {assert!(!background_from(queue_high,Some(RiskConfig{src,..c}),1,false),"known queue signal must exclude");}
        let cc_high=RiskSnapshot{rate:120,anchor:100,..s};
        for src in [1,3,4] {assert!(!background_from(cc_high,Some(RiskConfig{src,..c}),1,false),"known CC signal must exclude");}
        assert!(background_from(cc_high,Some(RiskConfig{src:2,..c}),1,false),"SRC2 missing queue is not a CC fallback for estimator");
        s.rate=80;s.anchor=100;
        // Frequent accepted LOSS events do not create an exclusion window.
        for now in 1..=1000 {
            rand_queue_guard(&mut s,false,now,100,0.5,9);
            let background=background_from(s,Some(c),now,false);
            s.rand.observe(Some(rc),background,now%10==0);
        }
        assert_eq!((s.rand.bg_packets,s.rand.bg_lost),(1000,100));
        assert_eq!(s.rand_guard_until_ns,0);
        // Both ECN CE and delay use the same accepted queue-event guard.
        for event in ["CE","delay"] {
            let mut guarded=s;rand_queue_guard(&mut guarded,true,1000,100,0.5,9);
            assert_eq!(guarded.rand_guard_until_ns,1900);
            assert!(!background_from(guarded,Some(c),1900,false),"{event} recovery");
            assert!(background_from(guarded,Some(c),1901,false));
            let before=guarded.rand;guarded.rand.observe(Some(rc),false,true);assert_eq!(guarded.rand,before);
        }
    }
    #[test] fn rand_base_floor_multiplier_ceiling_and_phi_floor() {
        let c=rand_test_config();
        for (p,want) in [(0.,0.001),(0.0001,0.001),(0.0035,0.007),(0.2,0.1)] {
            let s=RiskSnapshot{rand:RandState{p,..Default::default()},rate:80,anchor:100,..Default::default()};
            let a=rand_admission_from(s,Some(rand_test_risk()),0.001,Some(c));
            assert_eq!(a.p_base,want);assert_eq!(a.p_eff,want);assert_eq!(a.risk,0.);
        }
        let s=RiskSnapshot{rand:RandState{p:0.2,..Default::default()},rate:120,anchor:100,..Default::default()};
        let a=rand_admission_from(s,Some(RiskConfig{phi:0.02,..rand_test_risk()}),0.001,Some(c));
        assert_eq!((a.risk,a.p_base,a.p_eff),(1.,0.1,0.1),"risk must never ramp DOWN below RAND base");
        assert_eq!(rand_admission_from(s,None,0.001,Some(c)).p_eff,0.1);
    }
    #[test] fn rand_unset_full_state_and_plan_exact() {
        let c=rand_test_risk();let mut s=RiskSnapshot{rate:80,anchor:100,..Default::default()};let initial=s;
        for i in 0..1000 {s.rand.observe(None,true,i%3==0);}
        assert_eq!(s,initial,"off changes no estimator or snapshot state");
        for cfg in [None,Some(c),Some(RiskConfig{phi:0.0001,..c})] {for rate in [80,100,120] {
            let s=RiskSnapshot{rate,..s};
            let old=admission_from(s,cfg,0.001);let new=rand_admission_from(s,cfg,0.001,None);
            assert_eq!(format!("{old:?}"),format!("{new:?}"));
            for k in [4,71,704] {for selector in [1,2] {for d in [0,draw(7),u64::MAX] {
                assert_eq!(plan_for_risk(k,selector,"g4",d,old,cfg).unwrap(),plan_for_risk(k,selector,"g4",d,new,cfg).unwrap());
            }}}
        }}
    }
    #[test] fn rand_root_freeze_and_dup_unchanged() {
        let c=rand_test_risk();let rc=rand_test_config();
        let mut s=RiskSnapshot{rate:80,anchor:100,..Default::default()};
        let frozen=rand_admission_from(s,Some(c),0.001,Some(rc));
        let plan=plan_for_risk(704,2,"g4",draw(5),frozen,Some(c)).unwrap();
        let dup=duplicate_from(s,Some(c));
        for _ in 0..1000 {s.rand.observe(Some(rc),true,true);}
        let next=rand_admission_from(s,Some(c),0.001,Some(rc));
        assert!(next.p_base>frozen.p_base);
        assert_ne!(plan,plan_for_risk(704,2,"g4",draw(5),next,Some(c)).unwrap());
        assert_eq!(plan,plan_for_risk(704,2,"g4",draw(5),frozen,Some(c)).unwrap());
        assert_eq!(duplicate_from(s,Some(c)),dup,"RAND does not trigger duplication");
        let tail=|s|tail_from(704,0,2,"g4",draw(5),s,100_000_000,Some(c),Some(1.),frozen.p_base).unwrap();
        let old=RiskSnapshot{rand:RandState::default(),..s};assert_eq!(tail(s),tail(old),"tail reuses root base, not live RAND");
    }
    #[test] fn risk_tail_off_increases_only_and_exposure_clamp() {
        let c=RiskConfig{src:1,lo:0.9,hi:1.1,lo2:0.9,hi2:1.1,phi:0.12,eps:Some(0.001),step:0,hold:None};
        let s=RiskSnapshot{rate:100_000_000,anchor:80_000_000,latest_rtt_ns:200_000_000,min_rtt_ns:100_000_000,qd_ref_ns:100_000_000,mode:'G',..Default::default()};
        let calc=|k,remaining,tail|tail_from(k,remaining,2,"g4",draw(3),s,100_000_000,Some(c),tail,0.).unwrap();
        assert_eq!(calc(704,0,None),TailPlan::default());
        let a=calc(704,0,Some(1.05));assert_eq!(a.k,11);assert_eq!(a.risk,1.);assert!(a.added>0);
        assert_eq!(calc(704,a.added,Some(1.05)).added,0);
        assert_eq!(calc(704,a.added+10,Some(1.05)).added,0);
        assert_eq!(calc(2,0,Some(100.)).k,2);
        assert_eq!(calc(704,0,Some(1.)).k,10,"smoothed RTT, not latest sample");
        let reserve=plan_for_risk(a.k,2,"g4",draw(draw(3)^0x5441494c5f525356),admission_from(s,Some(c),tv_override().map_or(0.005,|o|o.0)),Some(c)).unwrap().proactive;
        assert_eq!(a.added,reserve);
        assert_ne!(draw(draw(3)^0x5441494c5f525356),draw(3));
    }
    #[test] fn risk_step_hold_event_max_and_relatch() {
        let c=RiskConfig{src:1,lo:0.9,hi:1.1,lo2:0.9,hi2:1.1,phi:0.12,eps:None,step:1,hold:Some((2.,5.))};
        let mut s=RiskSnapshot{rate:109,anchor:100,smoothed_rtt_ns:100,..Default::default()};
        let risk=|s|admission_from(s,Some(c),0.005).risk;
        update_latch(&mut s,Some(c),10);assert_eq!(risk(s),0.);assert_eq!(s.latch_ns,None);
        s.rate=110;update_latch(&mut s,Some(c),20);assert_eq!(risk(s),1.);assert_eq!(s.latch_ns,Some(20));
        s.rate=80;s.event_ns=Some(19);update_latch(&mut s,Some(c),519);assert_eq!(risk(s),1.,"pre-latch event does not qualify");
        update_latch(&mut s,Some(c),520);assert_eq!(risk(s),0.,"false alarm cap, exactly m RTTs");
        s.rate=120;update_latch(&mut s,Some(c),600);s.rate=80;s.event_ns=Some(650);
        update_latch(&mut s,Some(c),849);assert_eq!(risk(s),1.);
        s.event_ns=Some(800);update_latch(&mut s,Some(c),999);assert_eq!(risk(s),1.,"latest event extends hold");
        update_latch(&mut s,Some(c),1000);assert_eq!(risk(s),0.);
        s.rate=120;update_latch(&mut s,Some(c),1100);update_latch(&mut s,Some(c),1600);
        assert_eq!(s.latch_ns,Some(1600));assert_eq!(risk(s),1.,"still high can re-latch immediately");
        s.smoothed_rtt_ns=0;s.rate=80;update_latch(&mut s,Some(c),u64::MAX);assert_eq!(risk(s),1.);
        s.smoothed_rtt_ns=100;s.event_ns=Some(1700);
        update_latch(&mut s,Some(RiskConfig{hold:Some((0.,5.)),..c}),1700);assert_eq!(s.latch_ns,None,"zero hold releases at event");
        for (enabled,r,want) in [(false,1.,false),(true,0.999,false),(true,1.,true),(true,0.,false)] {
            assert_eq!(duplicate_at_risk(enabled,r),want);
        }
        let c=RiskConfig{hold:None,..c};s.rate=109;assert_eq!(admission_from(s,Some(c),0.005).risk,0.);
        s.rate=110;assert_eq!(admission_from(s,Some(c),0.005).risk,1.);
    }
    #[test] fn risk_step_two_scopes_hold_to_duplication_only() {
        let c=RiskConfig{src:1,lo:0.9,hi:1.1,lo2:0.9,hi2:1.1,phi:0.12,eps:Some(0.001),step:2,hold:Some((2.,5.))};
        let continuous=RiskConfig{step:0,hold:None,..c};
        let both=RiskConfig{step:1,..c};
        let base=tv_override().map_or(0.005,|o|o.0);
        let mut s=RiskSnapshot{rate:100_000_000,anchor:100_000_000,smoothed_rtt_ns:100_000_000,..Default::default()};
        update_latch(&mut s,Some(c),10);
        assert!(!duplicate_from(s,Some(c)));assert_eq!(s.latch_ns,None);
        assert!((admission_from(s,Some(c),base).risk-0.5).abs()<1e-12);
        assert_eq!(admission_from(s,Some(both),base).risk,0.);
        s.rate=120_000_000;update_latch(&mut s,Some(c),20);
        assert_eq!(s.latch_ns,Some(20));assert!(duplicate_from(s,Some(c)));
        for rate in [80_000_000,100_000_000,109_000_000,120_000_000] {
            let s=RiskSnapshot{rate,..s};
            let a=admission_from(s,Some(c),base);
            let plain=admission_from(s,Some(continuous),base);
            assert_eq!((a.risk,a.p_eff),(plain.risk,plain.p_eff));
            assert!(duplicate_from(s,Some(c)),"active hold protects wholes even below the ramp threshold");
            assert_eq!(admission_from(s,Some(both),base).risk,1.,"STEP=1 still scopes hold to admission too");
            for selector in [1,2] {
                assert_eq!(plan_for_risk(704,selector,"g4",draw(3),a,Some(c)).unwrap(),
                    plan_for_risk(704,selector,"g4",draw(3),plain,Some(continuous)).unwrap());
                let tail=|cfg|tail_from(704,0,selector,"g4",draw(3),s,s.smoothed_rtt_ns,Some(cfg),Some(1.),0.).unwrap();
                assert_eq!(tail(c),tail(continuous),"TAIL must use continuous risk under STEP=2");
                assert_eq!(tail(both).risk,1.,"STEP=1 keeps stepped TAIL risk");
            }
        }
        s.rate=80_000_000;update_latch(&mut s,Some(c),500_000_019);assert!(duplicate_from(s,Some(c)));
        update_latch(&mut s,Some(c),500_000_020);assert!(!duplicate_from(s,Some(c)));assert_eq!(s.latch_ns,None);
        let no_hold=RiskConfig{hold:None,..c};
        assert!(!duplicate_from(RiskSnapshot{rate:109_000_000,..s},Some(no_hold)));
        assert!(duplicate_from(RiskSnapshot{rate:120_000_000,..s},Some(no_hold)));
        assert!(!duplicate_from(s,None));
    }
    #[test] fn risk_off_does_not_parse_base() {
        if risk_config().is_none() && !rand_enabled() {
            let a=risk_admission(&RiskState::default());
            assert_eq!((a.risk,a.p_eff),(0.,0.));
        }
    }
    /// Also run in fresh test processes with risk env on: validates OnceLock binding
    /// and evidence replay without depending on or mutating the live snapshot.
    #[test] fn risk_environment_binding() {
        let cfg=risk_config();
        let base=tv_override().map_or(0.005,|o|o.0);
        let s=RiskSnapshot{rate:105,anchor:100,latest_rtt_ns:195_000,min_rtt_ns:100_000,qd_ref_ns:100_000,mode:'G',..Default::default()};
        let a=admission_from(s,cfg,base);
        if let Some(c)=cfg {assert_eq!(a.p_eff,base+(c.phi-base)*a.risk);}
        else {assert_eq!((a.risk,a.p_eff),(0.,0.));}
        for selector in [1,2] {
            let p=plan_at_admission(704,selector,"g4",draw(11),a).unwrap();
            let r=OwnerEvidence{k:704,selector,mix_draw:draw(11),risk:a.risk,p_eff:a.p_eff,..Default::default()};
            assert_eq!(p,plan_from_evidence(&r,"g4").unwrap());
            if cfg.is_none() {assert_eq!(p,frozen_plan(704,selector,"g4",draw(11)).unwrap());}
        }
    }
    #[test] fn risk_plan_monotone_and_off_exact() {
        let c=RiskConfig{src:1,lo:0.9,hi:1.1,lo2:0.8,hi2:1.,phi:0.12,eps:None,step:0,hold:None};
        let s=RiskSnapshot{rate:80,anchor:100,latest_rtt_ns:120_000,min_rtt_ns:100_000,qd_ref_ns:25_000,mode:'G',..Default::default()};
        let mut previous=None;
        for rate in [80,90,95,100,105,110,120] {
            let a=admission_from(RiskSnapshot{rate,..s},Some(c),0.005);
            let p=plan_for_risk(704,2,"g4",draw(3),a,Some(c)).unwrap();
            if let Some((old_risk,old_p,old_n))=previous {
                assert!(a.risk>=old_risk && a.p_eff>=old_p && p.proactive>=old_n);
            }
            previous=Some((a.risk,a.p_eff,p.proactive));
        }
        let low=admission_from(s,Some(c),0.005);
        let high=admission_from(RiskSnapshot{rate:120,..s},Some(c),0.005);
        assert_eq!((low.risk,high.risk),(0.,1.));
        assert!(high.p_eff>low.p_eff);
        assert!(plan_for_risk(704,2,"g4",draw(3),high,Some(c)).unwrap().proactive>
            plan_for_risk(704,2,"g4",draw(3),low,Some(c)).unwrap().proactive);
        for profile in ["g4","b20r20"] {for k in [2,8,71,704,1408] {for selector in [1,2] {for d in [0,draw(7),u64::MAX] {
            let a=admission_from(s,None,0.005);
            assert_eq!(a.risk,0.); assert_eq!(a.p_eff,0.);
            assert_eq!(plan_for_risk(k,selector,profile,d,a,None).unwrap(),frozen_plan(k,selector,profile,d).unwrap());
        }}}}
        let fixed=RiskConfig{eps:Some(0.001),..c};
        let p=plan_for_risk(71,1,"g4",0,high,Some(fixed)).unwrap();
        assert!(1.-delivery(71,p.upper,high.p_eff)<=0.001);
        assert!(1.-delivery(71,p.lower,high.p_eff)>0.001);
    }
    #[test] fn risk_sources_and_queue_fallback() {
        let c=RiskConfig{src:2,lo:0.9,hi:1.1,lo2:0.9,hi2:1.1,phi:0.12,eps:None,step:0,hold:None};
        let s=RiskSnapshot{rate:80,anchor:100,latest_rtt_ns:200_000,min_rtt_ns:100_000,qd_ref_ns:100_000,mode:'P',..Default::default()};
        let queue=admission_from(s,Some(c),0.005);
        assert!((queue.risk-0.5).abs()<1e-12);
        assert_eq!((queue.queue_delay_us,queue.qd_ref_us,queue.mode),(100.,100.,'P'));
        assert_eq!(admission_from(RiskSnapshot{qd_ref_ns:0,..s},Some(c),0.005).risk,0.);
        assert_eq!(admission_from(RiskSnapshot{anchor:0,qd_ref_ns:0,..s},Some(c),0.005).risk,1.);
        let max=admission_from(s,Some(RiskConfig{src:3,lo2:0.5,hi2:0.8,..c}),0.005);
        assert_eq!(max.risk,1.);
        assert_eq!(admission_from(RiskSnapshot{latest_rtt_ns:50_000,..s},Some(c),0.005).queue_delay_us,0.);
    }
    #[test] fn risk_source_four_min_and_queue_fallback() {
        let c=RiskConfig{src:4,lo:0.5,hi:1.5,lo2:0.,hi2:2.,phi:0.12,eps:None,step:0,hold:None};
        let s=RiskSnapshot{rate:100,anchor:100,latest_rtt_ns:200,min_rtt_ns:100,qd_ref_ns:100,..Default::default()};
        for (rate,qd,want) in [(75,150,0.25),(125,50,0.25),(125,150,0.75),(200,200,1.),(200,0,0.),(0,200,0.)] {
            let s=RiskSnapshot{rate,latest_rtt_ns:100+qd,..s};
            assert_eq!(admission_from(s,Some(c),0.005).risk,want);
            assert_eq!(raw_risk(s,c),raw_risk(s,RiskConfig{src:1,..c}).min(raw_risk(s,RiskConfig{src:2,..c})));
        }
        assert_eq!(raw_risk(RiskSnapshot{qd_ref_ns:0,..s},c),0.5,"unknown queue reference uses CC LO/HI, not LO2/HI2");
        assert_eq!(raw_risk(RiskSnapshot{anchor:0,qd_ref_ns:0,..s},c),1.);
        assert_eq!(raw_risk(RiskSnapshot{anchor:0,..s},c),0.5,"unknown anchor leaves queue as the AND limiter");
        assert_eq!(raw_risk(RiskSnapshot{latest_rtt_ns:50,..s},c),0.,"negative queue delay saturates to zero");
        let step=RiskConfig{step:2,..c};
        assert!(!duplicate_from(RiskSnapshot{rate:200,..s},Some(step)),"both ramps must reach 1");
        assert!(duplicate_from(RiskSnapshot{rate:200,latest_rtt_ns:300,..s},Some(step)));
    }
    // The original independent forecast is retained as an algorithm regression;
    // the ship-policy stream below separately pins the frozen candidate defaults.
    fn historical_plan(k:u32,selector:u32,profile:&str,draw:u64)->Result<Plan,String> {
        plan_with_policy(k,selector,profile,draw,None,None)
    }
    #[test] fn target_validation_bounds_and_mix() {
        for profile in ["g4","b20r20"] {for k in [2,4,8,15,29,71,141,352,704,1408,32000] {
            let p=historical_plan(k,1,profile,0).unwrap();let low=historical_plan(k,2,profile,u64::MAX).unwrap();let high=historical_plan(k,2,profile,0).unwrap();
            assert_eq!(p.proactive,p.upper);assert!(low.proactive<=high.proactive);assert!(p.upper-p.lower<=1);
            let (q,h)=if profile=="g4"{(0.04354000000000002,333.33333333333337)}else{(0.005739999999999967,33.333333333333336)};
            assert!(1.-delivery(k,p.upper,q)<=q/(1.+k as f64/h));
            if p.upper>0 {assert!(1.-delivery(k,p.lower,q)>q/(1.+k as f64/h));}
        }}
        assert!(historical_plan(32001,1,"g4",0).is_err());assert!(historical_plan(0,1,"g4",0).is_err());
        let p=historical_plan(2,2,"g4",0).unwrap();let n=100000;let count=(0..n).filter(|i|draw(*i)<p.mix_threshold).count();
        assert!((count as f64/n as f64-p.upper_probability).abs()<0.005);
    }
    #[test] fn target_validation_all_frozen_forecast_points() {
        // Literal pins from forecast SHA5e5081..., not regenerated fitted predictions.
        let points:[(&str,u32,u32,u32,u32,f64);20]=[
            ("g4",2000,2,0,1,0.5260208047736915),
            ("g4",5000,4,0,1,0.8239210855597839),
            ("g4",10000,8,1,2,0.2749555789463314),
            ("g4",20000,15,1,2,0.9472806972414322),
            ("g4",40000,29,3,4,0.2503082256553574),
            ("g4",100000,71,6,7,0.4819763806090949),
            ("g4",200000,141,11,12,0.22040325529030852),
            ("g4",500000,352,24,25,0.4123701712070357),
            ("g4",1000000,704,44,45,0.9405951779467268),
            ("g4",2000000,1408,84,85,0.025701970656195002),
            ("b20r20",2000,2,0,1,0.5315161803604964),
            ("b20r20",5000,4,0,1,0.7861027258168535),
            ("b20r20",10000,8,0,1,0.9207747478666105),
            ("b20r20",20000,15,0,1,0.9973295818917699),
            ("b20r20",40000,29,1,2,0.8090634332006742),
            ("b20r20",100000,71,2,3,0.8814185467443365),
            ("b20r20",200000,141,4,5,0.36239245692874866),
            ("b20r20",500000,352,7,8,0.7827219415782769),
            ("b20r20",1000000,704,12,13,0.3149582354150017),
            ("b20r20",2000000,1408,19,20,0.9524840481573436),
        ];
        for (profile,size,k,lo,hi,w) in points {
            let p=historical_plan(k,2,profile,0).unwrap();
            assert_eq!((p.lower,p.upper),(lo,hi));
            assert!((p.upper_probability-w).abs()<1e-10,"{profile}/{size}: {} vs {w}",p.upper_probability);
            assert_eq!(historical_plan(k,1,profile,u64::MAX).unwrap().proactive,hi);
            assert_eq!(historical_plan(k,2,profile,p.mix_threshold).unwrap().proactive,lo);
            if p.mix_threshold>0 {assert_eq!(historical_plan(k,2,profile,p.mix_threshold-1).unwrap().proactive,hi);}
            let count=(1..=100000).filter(|&i|draw(i)<p.mix_threshold).count();
            assert!((count as f64/100000.-w).abs()<0.006);
            eprintln!("frozen {profile} size={size} K={k} lo={lo} hi={hi} w={} delta={} mix100000={count}",p.upper_probability,p.upper_probability-w);
        }
    }
    #[cfg(feature="research_target_validation")]
    #[test] fn target_validation_evidence_bounded_and_terminal_commit_snapshot() {
        let _=take();let before=audit().lock().unwrap().dropped;
        let mut owners=Vec::new();for _ in 0..=EVIDENCE_CAPACITY {owners.push(register(OwnerEvidence::default()));}
        let sample=owners[0].clone();let id=sample.lock().unwrap().generation;
        let snapshot=take();assert!(snapshot.rows.len()<=EVIDENCE_CAPACITY);assert_eq!(snapshot.dropped,before+1);
        sample.lock().unwrap().sealed=true;sample.lock().unwrap().repairs_emitted=7;
        drop(sample);drop(owners);
        let end=take();assert_eq!(end.rows.iter().find(|r|r.generation==id).unwrap().repairs_emitted,7);
        assert!(take().rows.is_empty());assert_eq!(take().dropped,before+1);
    }

}

#[cfg(test)]
mod frozen_candidate_tests {
    use super::*;
    #[test]
    fn global_research_candidate_plan_stream_is_identical() {
    initialize(2,Some("b20r20"),1,0,1).unwrap();
    let state=RiskState::default();
    let mut hash=0xcbf29ce484222325u64;
    let mut feed=|x:u64| {for b in x.to_le_bytes() {hash^=b as u64;hash=hash.wrapping_mul(0x100000001b3);}};
    for (step,(rate,rtt,lost)) in [(80,100_000_000,false),(99,150_000_000,true),(101,170_000_000,false),(120,200_000_000,true),(80,100_000_000,false)].into_iter().enumerate() {
        risk_rate(&state,rate*1_000_000,100_000_000,'G',1_000_000_000);
        risk_rtt(&state,rtt,100_000_000);
        if step==2 {risk_congestion(&state,100_000_000,1_000_000_000,0.5,9,true);}
        let bg=rand_background(&state,false);
        for i in 0..5000 {rand_resolved(&state,bg,lost && i%31==0);}
        let a=risk_admission(&state);
        feed(a.risk.to_bits());feed(a.p_eff.to_bits());feed(a.p_base.to_bits());
        feed(u64::from(duplicate_now(&state)));
        for k in [2,4,8,15,29,71,141,352,704,1408,32000] {
            let draw=draw(step as u64+1);
            let p=plan_at_admission(k,2,"b20r20",draw,a).unwrap();
            for x in [p.k as u64,p.proactive as u64,p.lower as u64,p.upper as u64,p.upper_probability.to_bits(),p.mix_threshold,p.mix_draw] {feed(x);}
            let t=tail_plan(&state,k,p.proactive,2,draw,a.p_base).unwrap();
            for x in [t.risk.to_bits(),t.k as u64,t.added as u64] {feed(x);}
        }
    }
    assert_eq!(hash,0x86eb981be053c15a,"global-research candidate plan stream");

    }
    #[test]
    fn congestion_and_random_loss_are_connection_local() {
        let calm=RiskState::default(); let busy=RiskState::default();
        risk_rate(&calm,80_000_000,100_000_000,'G',1_000_000_000);
        risk_rate(&busy,80_000_000,100_000_000,'G',1_000_000_000);
        let before=risk_admission(&calm);
        let expected=plan_at_admission(704,2,"b20r20",draw(1),before).unwrap();
        for i in 0..5000 {rand_resolved(&busy,true,i%10==0);}
        risk_rate(&busy,120_000_000,100_000_000,'G',1_000_000_000);
        risk_rtt(&busy,200_000_000,100_000_000);
        risk_congestion(&busy,100_000_000,1_000_000_000,0.5,9,true);
        let after=risk_admission(&calm);
        assert_eq!((after.risk,after.p_eff,after.p_base),(before.risk,before.p_eff,before.p_base));
        assert_eq!(plan_at_admission(704,2,"b20r20",draw(1),after).unwrap(),expected);
        let other=risk_admission(&busy);
        assert!(plan_at_admission(704,2,"b20r20",draw(1),other).unwrap().proactive>expected.proactive);
        assert!(!duplicate_now(&calm)); assert!(duplicate_now(&busy));
        assert_eq!(rand_counters(&calm),(0,0,0,1000));
        assert_eq!(rand_counters(&busy).0,5000);
    }
}
