use std::sync::{Arc, Mutex, OnceLock}; use std::collections::BTreeMap;
pub const PLAN_VERSION: &str = "frozen-target-v1";
pub const FORECAST_SHA256: &str = "5e5081cd1ebdc9ddb78391fdb8f7eaaabdb74586bda86bbc6d590a238e153ef5";
pub const MIX_SEED: u64 = 0x5354505f544d0001; pub const EVIDENCE_CAPACITY: usize = 4096;
pub const MAX_PLAN_K: u32 = 32000;
const fn adaptive_root_source_upper(total:usize)->u64 {
    if total==0 {return 0;}
    let units=total/crate::stp::ADAPTIVE_MIN_UNIT_LEN; let units=if units==0 {1}else{units};
    (units+(total-units)/crate::stp::FEC_MIN_BLOCK_BYTES) as u64 }
const MAX_TAIL_PLAN_K: u32 = adaptive_root_source_upper(crate::stp::MAX_JUMBOGRAM_LEN) as u32;
static CONFIG: OnceLock<(&'static str, f64, f64, u64)> = OnceLock::new();
pub(crate) fn initialize(selector:u32, profile:Option<&str>, cost:u32, cap:u32, empirical:u32) -> Result<(),String> {
    if selector > 2 { return Err("STP_P4_TARGET_VALIDATION must be 0, 1 or 2".into()); }
    if empirical != 1 || (selector == 0 && (cost != 0 || cap != 25)) || (selector != 0 && (cost != 1 || cap != 0)) {
        return Err("target validation requires empirical1; selector0/cost0/cap25 or selector1|2/cost1/cap0".into()); }
    let c = match profile {
        Some("g4") => ("g4",0.04354000000000002,333.33333333333337,MIX_SEED),
        Some("b20r20") => ("b20r20",0.005739999999999967,33.333333333333336,MIX_SEED),
        _ => return Err("target validation requires STP_COHORT_PROFILE=g4 or b20r20".into()) };
    let _=risk_config(); let _=tail_config(); let _=dup_config(); let _=rand_config();
    crate::stp::initialize_delay_event();
    let _=CONFIG.set(c); Ok(()) }
static OVERRIDE: OnceLock<Option<(f64,f64,f64)>> = OnceLock::new();
fn tv_override() -> Option<(f64,f64,f64)> {
    *OVERRIDE.get_or_init(|| {
        let g=|n:&str| crate::ship::policy_var(n).ok().map(|v| v.parse::<f64>().expect(n));
        match (g("STP_TV_P"),g("STP_TV_H"),g("STP_TV_E")) {
            (Some(p),Some(h),Some(e)) => { assert!(p>0.&&p<0.5&&h>0.&&e>0.); Some((p,h,e)) }
            (None,None,None) => None,
            _ => panic!("STP_TV_P/STP_TV_H/STP_TV_E must be set together"), } }) }
#[derive(Clone, Copy, Debug, Default, PartialEq)] struct RiskSnapshot {
    rate:u64, anchor:u64, latest_rtt_ns:u64, min_rtt_ns:u64, qd_ref_ns:u64, mode:char,
    smoothed_rtt_ns:u64, latch_ns:Option<u64>, event_ns:Option<u64>,
    rand:RandState, rand_guard_until_ns:u64, }
#[derive(Clone, Default)] pub(crate) struct RiskState(Arc<Mutex<RiskSnapshot>>);
impl std::fmt::Debug for RiskState {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("RiskState { .. }")} }
impl RiskState { pub(crate) fn same_connection(&self,other:&Self)->bool {Arc::ptr_eq(&self.0,&other.0)} }
fn risk_now_ns() -> u64 {
    static START:OnceLock<std::time::Instant>=OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_nanos().min((u64::MAX-1) as u128) as u64+1 }
fn refresh_latch(s:&mut RiskSnapshot) { update_latch(s,risk_config(),risk_now_ns()); }
pub(crate) fn risk_rate(state: &RiskState,rate:u64, anchor:u64, mode:char, smoothed_rtt_ns:u64) {
    let mut s=state.0.lock().unwrap(); s.rate=rate; s.anchor=anchor; s.mode=mode;
    s.smoothed_rtt_ns=smoothed_rtt_ns; refresh_latch(&mut s); }
pub(crate) fn risk_rtt(state: &RiskState,sample_ns:u64, min_rtt_ns:u64) {
    let mut s=state.0.lock().unwrap(); s.latest_rtt_ns=sample_ns; s.min_rtt_ns=min_rtt_ns; refresh_latch(&mut s); }
pub(crate) fn risk_congestion(state: &RiskState,anchor:u64, rtt_ns:u64, guard_rtts:f64, recovery_rtts:u64, queue_signal:bool) {
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s); s.anchor=anchor; s.event_ns=Some(risk_now_ns());
    if rand_config().is_some() {
        let now=s.event_ns.unwrap();
        rand_queue_guard(&mut s,queue_signal,now,rtt_ns,guard_rtts,recovery_rtts); }
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns);
    if qd!=0 { s.qd_ref_ns=qd; }
    refresh_latch(&mut s); }
#[derive(Clone, Copy, Debug)] struct RandConfig { mult:f64, alpha:f64, max:f64 }
fn rand_config()->Option<RandConfig> {
    static RAND:OnceLock<Option<RandConfig>>=OnceLock::new();
    *RAND.get_or_init(|| {
        if !env_switch("STP_TV_RAND") {return None;}
        let base=tv_override().expect("STP_TV_RAND requires STP_TV_P/STP_TV_H/STP_TV_E").0;
        let required=|n:&str| {
            let x=crate::ship::policy_var(n).unwrap_or_else(|_|panic!("{n} is required when RAND is on"))
                .parse::<f64>().unwrap_or_else(|_|panic!("{n} must be finite"));
            assert!(x.is_finite(),"{n} must be finite"); x };
        let (mult,half,max)=(required("STP_TV_RAND_MULT"),required("STP_TV_RAND_HALF_PKTS"),required("STP_TV_RAND_MAX"));
        assert!(mult>=1.,"STP_TV_RAND_MULT must be >=1"); assert!(half>0.,"STP_TV_RAND_HALF_PKTS must be >0");
        assert!(max>0. && max<1. && max>=base,"STP_TV_RAND_MAX must be in (0,1) and >= STP_TV_P");
        Some(RandConfig{mult,alpha:-(-std::f64::consts::LN_2/half).exp_m1(),max}) }) }
#[derive(Clone, Copy, Debug, Default, PartialEq)] struct RandState { p:f64, bg_packets:u64, bg_lost:u64, p_base:f64 }
impl RandState {
    fn observe(&mut self,cfg:Option<RandConfig>,background:bool,lost:bool) {
        let Some(c)=cfg else {return};
        if !background {return;}
        self.bg_packets=self.bg_packets.saturating_add(1); self.bg_lost=self.bg_lost.saturating_add(u64::from(lost));
        self.p+=c.alpha*((if lost {1.}else{0.})-self.p); }
    fn base(self,c:RandConfig,floor:f64)->f64 {(c.mult*self.p).max(floor).min(c.max)} }
fn rand_queue_guard(s:&mut RiskSnapshot,queue_signal:bool,now:u64,rtt_ns:u64,guard_rtts:f64,recovery_rtts:u64) {
    if !queue_signal {return;}
    let duration=if rtt_ns==0 {u64::MAX}else{(rtt_ns as f64*guard_rtts.max(recovery_rtts as f64)) as u64};
    s.rand_guard_until_ns=s.rand_guard_until_ns.max(now.saturating_add(duration)); }
fn background_risk(s:RiskSnapshot,c:RiskConfig)->f64 {
    let ramp=|x:f64,lo:f64,hi:f64|((x-lo)/(hi-lo)).clamp(0.,1.);
    let cc=(s.anchor!=0).then(||ramp(s.rate as f64/s.anchor as f64,c.lo,c.hi));
    let queue=(s.qd_ref_ns!=0).then(||ramp(s.latest_rtt_ns.saturating_sub(s.min_rtt_ns) as f64/s.qd_ref_ns as f64,c.lo2,c.hi2));
    match c.src {
        1=>cc.unwrap_or(0.),2=>queue.unwrap_or(0.),
        3=>cc.unwrap_or(0.).max(queue.unwrap_or(0.)),
        4=>match (cc,queue) {(Some(a),Some(b))=>a.min(b),(a,b)=>a.or(b).unwrap_or(0.)},
        _=>unreachable!(), } }
fn background_from(s:RiskSnapshot,cfg:Option<RiskConfig>,now:u64,outage:bool)->bool {
    !outage && now>s.rand_guard_until_ns
        && cfg.is_none_or(|c|background_risk(s,c)==0.) }
pub(crate) fn rand_enabled()->bool {rand_config().is_some()}
pub(crate) fn rand_background(state: &RiskState,outage:bool)->bool {
    if !rand_enabled() {return false;}
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    background_from(*s,risk_config(),risk_now_ns(),outage) }
pub(crate) fn rand_resolved(state: &RiskState,background:bool,lost:bool) {
    if !background {return;}
    let mut s=state.0.lock().unwrap(); s.rand.observe(rand_config(),background,lost); }
pub(crate) fn rand_counters(state: &RiskState,)->(u64,u64,u64,u64) {
    if !rand_enabled() {return (0,0,0,0);}
    let r=state.0.lock().unwrap().rand;
    (r.bg_packets,r.bg_lost,(r.p*1e6).round() as u64,(r.p_base*1e6).round() as u64) }
fn rand_admission_from(s:RiskSnapshot,cfg:Option<RiskConfig>,base:f64,rand:Option<RandConfig>)->RiskAdmission {
    let Some(c)=rand else {return admission_from(s,cfg,base)}; let p_base=s.rand.base(c,base);
    let cfg=cfg.map(|c|RiskConfig{phi:c.phi.max(p_base),..c}); let mut a=admission_from(s,cfg,p_base);
    if cfg.is_none() {a.p_eff=p_base;}
    a.p_base=p_base; a }
#[derive(Clone, Copy, Debug)]
struct RiskConfig { src:u32, lo:f64, hi:f64, lo2:f64, hi2:f64, phi:f64, eps:Option<f64>, step:u32, hold:Option<(f64,f64)> }
static RISK_CONFIG: OnceLock<Option<RiskConfig>> = OnceLock::new();
fn step_config()->u32 {
    crate::ship::policy_var("STP_TV_RISK_STEP").map_or(0,|v|match v.as_str() {
        "0"=>0,"1"=>1,"2"=>2,_=>panic!("STP_TV_RISK_STEP must be 0, 1 or 2"), }) }
fn risk_config() -> Option<RiskConfig> {
    *RISK_CONFIG.get_or_init(|| {
        let src=crate::ship::policy_var("STP_TV_RISK_SRC").map_or(0, |v| v.parse::<u32>().expect("STP_TV_RISK_SRC must be 0, 1, 2, 3 or 4"));
        assert!(src<=4,"STP_TV_RISK_SRC must be 0, 1, 2, 3 or 4");
        if src==0 {
            assert!(crate::ship::policy_var_os("STP_TV_RISK_TAIL").is_none(),"STP_TV_RISK_TAIL requires STP_TV_RISK_SRC != 0");
            assert!(step_config()==0,"STP_TV_RISK_STEP=1 or 2 requires STP_TV_RISK_SRC != 0");
            assert!(!env_switch("STP_TV_DUP"),"STP_TV_DUP=1 requires STP_TV_RISK_SRC != 0");
            for n in ["STP_TV_RISK_HOLD_RTTS","STP_TV_RISK_HOLD_MAX_RTTS"] {
                assert!(crate::ship::policy_var_os(n).is_none(),"{n} requires STP_TV_RISK_SRC != 0"); }
            return None; }
        assert!(tv_override().is_some(),"risk requires STP_TV_P/STP_TV_H/STP_TV_E (P is the base floor)");
        let required=|n:&str| {
            let v=crate::ship::policy_var(n).unwrap_or_else(|_|panic!("{n} is required when risk is on"));
            let x=v.parse::<f64>().unwrap_or_else(|_|panic!("{n} must be a finite number"));
            assert!(x.is_finite(),"{n} must be finite"); x };
        let (lo,hi)=(required("STP_TV_RISK_LO"),required("STP_TV_RISK_HI"));
        assert!(lo<hi,"STP_TV_RISK_LO must be less than STP_TV_RISK_HI");
        let (lo2,hi2)=if src==3 || src==4 {(required("STP_TV_RISK_LO2"),required("STP_TV_RISK_HI2"))}else{(lo,hi)};
        assert!(lo2<hi2,"STP_TV_RISK_LO2 must be less than STP_TV_RISK_HI2"); let phi=required("STP_TV_RISK_PHI");
        assert!(phi>0.&&phi<1.,"STP_TV_RISK_PHI must be in (0,1)");
        let eps=crate::ship::policy_var("STP_TV_RISK_EPS").ok().map(|_|required("STP_TV_RISK_EPS"));
        assert!(eps.is_none_or(|x|x>0.&&x<1.),"STP_TV_RISK_EPS must be in (0,1)"); let step=step_config();
        let hold=crate::ship::policy_var_os("STP_TV_RISK_HOLD_RTTS").map(|_| {
            assert!(step!=0,"STP_TV_RISK_HOLD_RTTS requires STP_TV_RISK_STEP=1 or 2");
            let (h,m)=(required("STP_TV_RISK_HOLD_RTTS"),required("STP_TV_RISK_HOLD_MAX_RTTS"));
            assert!(h>=0. && m>0.,"HOLD_RTTS must be >=0 and HOLD_MAX_RTTS >0"); (h,m) });
        assert!(hold.is_some() || crate::ship::policy_var_os("STP_TV_RISK_HOLD_MAX_RTTS").is_none(),"HOLD_MAX_RTTS requires HOLD_RTTS");
        Some(RiskConfig{src,lo,hi,lo2,hi2,phi,eps,step,hold}) }) }
#[derive(Clone, Copy, Debug, Default)] pub(crate) struct RiskAdmission {
    pub risk:f64, pub p_eff:f64, pub rate_over_anchor:f64, pub queue_delay_us:f64, pub qd_ref_us:f64, pub mode:char,
    pub p_base:f64, }
fn raw_risk(s:RiskSnapshot,c:RiskConfig)->f64 {
    let ratio=if s.anchor==0 {0.}else{s.rate as f64/s.anchor as f64};
    let ramp=|x:f64,lo:f64,hi:f64| ((x-lo)/(hi-lo)).clamp(0.,1.); let cc=if s.anchor==0 {1.}else{ramp(ratio,c.lo,c.hi)};
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns);
    let queue=if s.qd_ref_ns==0 {cc}else{ramp(qd as f64/s.qd_ref_ns as f64,c.lo2,c.hi2)};
    match c.src {1=>cc,2=>queue,3=>cc.max(queue),4=>cc.min(queue),_=>unreachable!()} }
fn update_latch(s:&mut RiskSnapshot,cfg:Option<RiskConfig>,now:u64) {
    let Some(c)=cfg else {return}; let Some((h,m))=c.hold else {return};
    if let Some(start)=s.latch_ns {
        let event=s.event_ns.filter(|&t|t>start);
        let expired=s.smoothed_rtt_ns!=0 && match event {
            Some(t)=>now.saturating_sub(t) as f64 >= h*s.smoothed_rtt_ns as f64,
            None=>now.saturating_sub(start) as f64 >= m*s.smoothed_rtt_ns as f64, };
        if expired {s.latch_ns=None;} }
    if s.latch_ns.is_none() && raw_risk(*s,c)>=1. {s.latch_ns=Some(now);} }
fn decision_risk(s:RiskSnapshot,c:RiskConfig,step:bool)->f64 {
    let raw=raw_risk(s,c);
    if step {if raw>=1. || (c.hold.is_some() && s.latch_ns.is_some()) {1.}else{0.}}else{raw} }
fn admission_from(s:RiskSnapshot, cfg:Option<RiskConfig>, base:f64) -> RiskAdmission {
    let ratio=if s.anchor==0 {0.}else{s.rate as f64/s.anchor as f64};
    let qd=s.latest_rtt_ns.saturating_sub(s.min_rtt_ns); let risk=cfg.map_or(0.,|c|decision_risk(s,c,c.step==1));
    RiskAdmission{p_base:0.,risk,p_eff:cfg.map_or(0.,|c|base+(c.phi-base)*risk),rate_over_anchor:ratio,
        queue_delay_us:qd as f64/1000.,qd_ref_us:s.qd_ref_ns as f64/1000.,mode:s.mode} }
fn env_switch(n:&str)->bool {
    crate::ship::policy_var(n).ok().is_some_and(|v| {assert!(v=="0" || v=="1","{n} must be 0 or 1"); v=="1"}) }
fn dup_config()->bool {
    static DUP:OnceLock<bool>=OnceLock::new();
    *DUP.get_or_init(|| {let on=env_switch("STP_TV_DUP"); assert!(!on || risk_config().is_some(),"STP_TV_DUP requires risk");on}) }
pub(crate) fn duplicate_at_risk(enabled:bool,risk:f64)->bool {enabled && risk>=1.}
fn duplicate_from(s:RiskSnapshot,cfg:Option<RiskConfig>)->bool {
    cfg.is_some_and(|c|duplicate_at_risk(true,decision_risk(s,c,c.step!=0))) }
pub(crate) fn duplicate_now(state: &RiskState,)->bool {
    if !dup_config() {return false;}
    let cfg=risk_config(); let mut s=state.0.lock().unwrap(); refresh_latch(&mut s);
    duplicate_from(*s,cfg) }
pub(crate) fn risk_admission(state: &RiskState,) -> RiskAdmission {
    let cfg=risk_config(); let rand=rand_config();
    let base=if cfg.is_some() || rand.is_some() {tv_override().unwrap().0}else{0.};
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s); let a=rand_admission_from(*s,cfg,base,rand);
    if rand.is_some() {s.rand.p_base=a.p_base;}
    a }
fn tail_config() -> Option<f64> {
    static TAIL:OnceLock<Option<f64>>=OnceLock::new();
    *TAIL.get_or_init(|| crate::ship::policy_var("STP_TV_RISK_TAIL").ok().map(|v| {
        assert!(risk_config().is_some(),"STP_TV_RISK_TAIL requires STP_TV_RISK_SRC != 0");
        let t=v.parse::<f64>().expect("STP_TV_RISK_TAIL must be finite and positive RTTs");
        assert!(t.is_finite() && t>0.,"STP_TV_RISK_TAIL must be finite and positive RTTs"); t })) }
#[derive(Clone,Copy,Debug,Default,PartialEq)] pub(crate) struct TailPlan {pub risk:f64,pub k:u32,pub added:u32}
fn tail_from(k:u32,remaining:u32,selector:u32,profile:&str,mix_draw:u64,s:RiskSnapshot,rtt_ns:u64,cfg:Option<RiskConfig>,tail:Option<f64>,root_base:f64) -> Result<TailPlan,String> {
    let Some(t)=tail else {return Ok(TailPlan::default())}; let c=cfg.ok_or("tail requires risk")?;
    if k>MAX_TAIL_PLAN_K || !t.is_finite() || t<=0. || !root_base.is_finite() || !(0. ..1.).contains(&root_base) {
        return Err("unsupported tail exposure/root base".into()); }
    let a=if root_base>0. {admission_from(s,Some(RiskConfig{phi:c.phi.max(root_base),..c}),root_base)}
        else {admission_from(s,Some(c),tv_override().map_or(0.005,|o|o.0))};
    let kt=((s.rate as f64/1_000_000.)*(rtt_ns as f64/1e9)*t).ceil().min(k as f64) as u32;
    let tail_draw=draw(mix_draw^0x5441494c5f525356);
    let reserve=if kt==0 {0}else if kt<=MAX_PLAN_K {
        plan_for_risk(kt,selector,profile,tail_draw,a,Some(c))?.proactive
    }else {
        plan_with_policy_max(kt,selector,profile,tail_draw,Some((a.p_eff,c.eps)),tv_override(),MAX_TAIL_PLAN_K)?.proactive };
    Ok(TailPlan{risk:a.risk,k:kt,added:reserve.saturating_sub(remaining)}) }
pub(crate) fn tail_plan(state: &RiskState,k:u32,remaining:u32,selector:u32,mix_draw:u64,root_base:f64) -> Result<TailPlan,String> {
    let tail=tail_config();
    if tail.is_none() {return Ok(TailPlan::default())}
    let mut s=state.0.lock().unwrap(); refresh_latch(&mut s); let rtt=s.smoothed_rtt_ns;
    tail_from(k,remaining,selector,configuration().0,mix_draw,*s,rtt,risk_config(),tail,root_base) }
pub fn configuration() -> (&'static str,f64,f64,u64) { CONFIG.get().copied().unwrap_or(("uninitialized",0.,0.,MIX_SEED)) }
#[derive(Clone,Copy,Debug,Default,PartialEq)]
pub struct Plan { pub k:u32, pub proactive:u32, pub lower:u32, pub upper:u32, pub upper_probability:f64, pub mix_threshold:u64, pub mix_draw:u64 }
pub fn draw(sequence:u64) -> u64 {
    let mut z=MIX_SEED.wrapping_add(sequence.wrapping_mul(0x9e3779b97f4a7c15));
    z=(z^(z>>30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z=(z^(z>>27)).wrapping_mul(0x94d049bb133111eb); z^(z>>31) }
fn delivery(k:u32,r:u32,p:f64) -> f64 {
    let n=k+r; let mode=(((n+1) as f64*p).floor() as u32).min(n);
    let mut total=1.; let mut good=if mode<=r {1.} else {0.}; let mut mass=1.;
    for i in (1..=mode).rev() { mass*=i as f64/(n-i+1) as f64*(1.-p)/p; total+=mass; if i-1<=r {good+=mass;} }
    mass=1.; for i in mode..n { mass*=(n-i) as f64/(i+1) as f64*p/(1.-p); total+=mass; if i+1<=r {good+=mass;} }
    (good/total).clamp(0.,1.) }
fn tail_delivery(k:u32,r:u32,p:f64) -> (f64,u32) {
    let n=k+r; let mode=(((n+1) as f64*p).floor() as u32).min(n);
    let mut total=1.; let mut good=if mode<=r {1.}else{0.}; let mut terms=1; let mut mass=1.; let mut i=mode;
    while i>0 {
        let q=i as f64/(n-i+1) as f64*(1.-p)/p;
        if q<1. && mass*q/(1.-q)<=f64::EPSILON*0.25*total {break;}
        mass*=q; i-=1; terms+=1; total+=mass; if i<=r {good+=mass;} }
    mass=1.; i=mode;
    while i<n {
        let q=(n-i) as f64/(i+1) as f64*p/(1.-p);
        if q<1. && mass*q/(1.-q)<=f64::EPSILON*0.25*total {break;}
        mass*=q; i+=1; terms+=1; total+=mass; if i<=r {good+=mass;} }
    ((good/total).clamp(0.,1.),terms) }
pub fn frozen_plan(k:u32,selector:u32,profile:&str,mix_draw:u64) -> Result<Plan,String> {
    plan_with_loss(k,selector,profile,mix_draw,None) }
pub(crate) fn plan_at_admission(k:u32,selector:u32,profile:&str,mix_draw:u64,a:RiskAdmission) -> Result<Plan,String> {
    if risk_config().is_none() && rand_enabled() {return plan_with_loss(k,selector,profile,mix_draw,Some((a.p_eff,None)));}
    plan_for_risk(k,selector,profile,mix_draw,a,risk_config()) }
fn plan_for_risk(k:u32,selector:u32,profile:&str,mix_draw:u64,a:RiskAdmission,cfg:Option<RiskConfig>) -> Result<Plan,String> {
    plan_with_loss(k,selector,profile,mix_draw,cfg.map(|c|(a.p_eff,c.eps))) }
fn validate_unit_extent(offset:u32,len:u32,total:u32) -> Result<(),String> {
    if len==0 || total==0 || offset.checked_add(len).is_none_or(|end|end>total) {
        return Err("invalid immutable unit extent".into()); }
    Ok(()) }
pub(crate) fn plan_at_unit_admission(k:u32,selector:u32,profile:&str,root_draw:u64,a:RiskAdmission,unit_offset:u32,unit_len:u32,root_total:u32) -> Result<Plan,String> {
    validate_unit_extent(unit_offset,unit_len,root_total)?;
    if unit_len==root_total {return plan_at_admission(k,selector,profile,root_draw,a);}
    let loss=risk_config().map(|c|(a.p_eff,c.eps)).or_else(||rand_config().map(|_|(a.p_eff,None)));
    let loss=unit_loss(profile,loss,unit_offset,unit_len,root_total,tv_override())?;
    let mix_draw=draw(root_draw^(0x554e495400000000|u64::from(unit_offset)));
    plan_with_loss(k,selector,profile,mix_draw,Some(loss)) }
pub(crate) fn adaptive_unit_packet_upper(k:u32,profile:&str,a:RiskAdmission,root_total:u32)->Result<u32,String> {
    if k==0 || k>MAX_PLAN_K {return Err("unsupported frozen target K/selector".into());}
    let loss=risk_config().map(|c|(a.p_eff,c.eps)).or_else(||rand_config().map(|_|(a.p_eff,None)));
    let (p,epsilon)=unit_loss(profile,loss,0,crate::stp::ADAPTIVE_MIN_UNIT_LEN as u32,root_total,tv_override())?;
    let epsilon=epsilon.ok_or("missing unit epsilon")?; let upper=reserve_upper(|r|delivery(k,r,p),epsilon,MAX_PLAN_K)?;
    k.checked_add(upper).ok_or_else(||"unit packet bound overflow".into()) }
fn reserve_upper(cdf:impl Fn(u32)->f64,target:f64,max_k:u32)->Result<u32,String> {
    let good=|r|1.-cdf(r)<=target; let mut hi=0;
    if !good(0) {hi=1;while !good(hi) {hi=hi.checked_mul(2).filter(|v|*v<=max_k).ok_or("unbounded frozen reserve")?;} let mut lo=0;while lo+1<hi {let mid=(lo+hi)/2;if good(mid){hi=mid;}else{lo=mid;}}}
    Ok(hi) }
fn policy_parameters(profile:&str,policy:Option<(f64,f64,f64)>) -> Result<(f64,f64,f64),String> {
    match (policy,profile) {(Some(o),_)=>Ok(o),(None,"g4")=>Ok((0.04354000000000002,333.33333333333337,1.)),(None,"b20r20")=>Ok((0.005739999999999967,33.333333333333336,1.)),_=>Err("unknown frozen profile".into())}
}
fn unit_loss(profile:&str,loss:Option<(f64,Option<f64>)>,offset:u32,len:u32,total:u32,policy:Option<(f64,f64,f64)>) -> Result<(f64,Option<f64>),String> {
    validate_unit_extent(offset,len,total)?; let (base,h,e)=policy_parameters(profile,policy)?;
    let p=loss.map_or(base,|v|v.0);
    if !p.is_finite() || p<=0. || p>=1. || !h.is_finite() || h<=0. || !e.is_finite() || e<=0. {
        return Err("invalid unit admission loss/policy".into()); }
    let root_k=adaptive_root_source_upper(total as usize);
    let root_epsilon=loss.and_then(|v|v.1).unwrap_or_else(||p/(1.+(root_k as f64/h).powf(e)));
    let epsilon=root_epsilon*(len as f64/total as f64);
    if !root_epsilon.is_finite() || root_epsilon<=0. || root_epsilon>1. || !epsilon.is_finite() || epsilon<=0. || epsilon>1. {
        return Err("invalid unit admission epsilon".into()); }
    Ok((p,Some(epsilon))) }
#[cfg(feature="research_target_validation")]
pub fn plan_from_evidence(r:&OwnerEvidence,profile:&str) -> Result<Plan,String> {
    let mut loss=risk_config().map(|c|(r.p_eff,c.eps)).or_else(||rand_config().map(|_|(r.p_eff,None)));
    if r.unit_len!=0 || r.root_total!=0 {
        validate_unit_extent(r.segment_offset,r.unit_len,r.root_total)?;
        if r.unit_len!=r.root_total {
            loss=Some(unit_loss(profile,loss,r.segment_offset,r.unit_len,r.root_total,tv_override())?); } }
    plan_with_loss(r.k,r.selector,profile,r.mix_draw,loss) }
fn plan_with_loss(k:u32,selector:u32,profile:&str,mix_draw:u64,loss:Option<(f64,Option<f64>)>) -> Result<Plan,String> {
    plan_with_policy(k,selector,profile,mix_draw,loss,tv_override()) }
fn plan_with_policy(k:u32,selector:u32,profile:&str,mix_draw:u64,loss:Option<(f64,Option<f64>)>,policy:Option<(f64,f64,f64)>) -> Result<Plan,String> {
    plan_with_policy_max(k,selector,profile,mix_draw,loss,policy,MAX_PLAN_K) }
fn plan_with_policy_max(k:u32,selector:u32,profile:&str,mix_draw:u64,loss:Option<(f64,Option<f64>)>,policy:Option<(f64,f64,f64)>,max_k:u32) -> Result<Plan,String> {
    if max_k>MAX_TAIL_PLAN_K || k==0 || k>max_k || !(1..=2).contains(&selector) {return Err("unsupported frozen target K/selector".into());}
    let (base,h,e)=policy_parameters(profile,policy)?; let p=loss.map_or(base,|v|v.0);
    if !p.is_finite() || p<=0. || p>=1. {return Err("invalid admission design loss".into());}
    let target=loss.and_then(|v|v.1).unwrap_or_else(||p/(1.+(k as f64/h).powf(e)));
    if !target.is_finite() || target<=0. || target>1. || (max_k>MAX_PLAN_K && target==1.) {return Err("invalid admission epsilon".into());}
    #[cfg(feature="research_target_validation")] {
    static ZERO_MIN_K: OnceLock<Option<u32>> = OnceLock::new();
    let zmk=*ZERO_MIN_K.get_or_init(|| crate::ship::policy_var("STP_TV_ZERO_MIN_K").ok().map(|v| v.parse::<u32>().expect("STP_TV_ZERO_MIN_K")));
    static ZERO_MAX_K: OnceLock<Option<u32>> = OnceLock::new();
    let zxk=*ZERO_MAX_K.get_or_init(|| crate::ship::policy_var("STP_TV_ZERO_MAX_K").ok().map(|v| v.parse::<u32>().expect("STP_TV_ZERO_MAX_K")));
    if zmk.is_some_and(|z| k>=z) && zxk.is_none_or(|m| k<m) {return Ok(Plan{k,proactive:0,lower:0,upper:0,upper_probability:0.,mix_threshold:0,mix_draw});}
    }
    let cdf=|r| if k<=MAX_PLAN_K {delivery(k,r,p)}else{tail_delivery(k,r,p).0};
    let hi=reserve_upper(&cdf,target,max_k)?; let lo=hi.saturating_sub(1); let dlo=cdf(lo);let dhi=cdf(hi);
    let w=if dhi>dlo {((1.-target-dlo)/(dhi-dlo)).clamp(0.,1.)}else{0.};
    let threshold=(w*18446744073709551616.).floor() as u64;
    let proactive=if selector==1 || w==1. || mix_draw<threshold {hi}else{lo};
    Ok(Plan{k,proactive,lower:lo,upper:hi,upper_probability:w,mix_threshold:threshold,mix_draw}) }
#[cfg(feature="research_target_validation")] #[derive(Clone,Copy,Debug,Default,PartialEq)] pub struct OwnerEvidence {
    pub generation:u64, pub root_id:u64, pub package_id:u64, pub root_ordinal:u64, pub app_tag:[u8;8],
    pub segment_offset:u32, pub selector:u32, pub k:u32, pub current_k:u32, pub groups:u32,
    pub unit_len:u32, pub root_total:u32,
    pub proactive:u32, pub lower:u32, pub upper:u32, pub w_bits:u64, pub mix_threshold:u64, pub mix_draw:u64,
    pub known_losses:u32, pub planned_repairs:u32, pub sources_emitted:u64, pub repairs_emitted:u64,
    pub started_ns:u64, pub sealed_ns:u64, pub sealed:bool, pub restarts:u32,
    pub risk:f64, pub p_eff:f64, pub rate_over_anchor:f64, pub queue_delay_us:f64, pub qd_ref_us:f64, pub mode:char,
    pub tail_risk:f64, pub tail_k:u32, pub tail_added:u32, }
pub(crate) fn active()->bool {CONFIG.get().is_some()}
#[cfg(feature="research_target_validation")] pub(crate) type Owner = Arc<Mutex<OwnerEvidence>>;
#[cfg(feature="research_target_validation")] #[derive(Debug,Default)]
pub struct Evidence {pub rows:Vec<OwnerEvidence>,pub dropped:u64}
#[cfg(feature="research_target_validation")] #[derive(Default)]
struct Audit {next:u64, rows:BTreeMap<u64,Owner>,dropped:u64}
#[cfg(feature="research_target_validation")] static AUDIT:OnceLock<Mutex<Audit>>=OnceLock::new();
#[cfg(feature="research_target_validation")] fn audit()->&'static Mutex<Audit> {AUDIT.get_or_init(Default::default)}
#[cfg(feature="research_target_validation")] pub(crate) fn register(mut row:OwnerEvidence)->Owner {
    #[cfg(feature="research_target_validation")] {
        let mut a=audit().lock().unwrap();a.next=a.next.checked_add(1).expect("owner sequence exhausted");row.generation=a.next;
        let owner=Arc::new(Mutex::new(row));
        if a.rows.len()<EVIDENCE_CAPACITY {let key=a.next;a.rows.insert(key,owner.clone());}else{a.dropped=a.dropped.saturating_add(1);}
        owner }
    #[cfg(not(feature="research_target_validation"))] { Arc::new(Mutex::new(row)) } }
#[cfg(feature="research_target_validation")] pub fn take()->Evidence {
    let mut a=audit().lock().unwrap();let mut rows=Vec::with_capacity(a.rows.len());
    a.rows.retain(|_,owner|{rows.push(owner.lock().unwrap().clone());Arc::strong_count(owner)>1});
    Evidence{rows,dropped:a.dropped} }
