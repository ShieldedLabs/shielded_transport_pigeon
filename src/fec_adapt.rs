//! Adaptive FEC redundancy: a per-connection packet-loss estimate and the per-message number of
//! Wirehair blocks it implies.
//!
//! The sender feeds cumulative finalized DATA outcomes (ACKed or declared lost) into a
//! [`LossTracker`] once per network-thread tick. The tracker turns them into short-term loss
//! samples (one per `bucket_ns`, and only once `min_packets` were finalized in the bucket, so a sample
//! is never a handful of packets), and an estimator turns the samples into a loss estimate that
//! pools finalized counts over a bounded time window. Clean traffic dilutes old loss rather
//! than holding one burst at its maximum. Everything is O(1) per tick with small fixed memory
//! (16 count slots and the span-tail sketch) and no allocation.
//!
//! [`repair_blocks`] picks, for a message of K source blocks, the smallest N with
//! P(fewer than K of N blocks arrive) <= eps under independent loss p.

#[cfg(feature="research_budget_diagnostic")]
type DemandCapture=crate::budget_diagnostic::Demand;
#[cfg(not(feature="research_budget_diagnostic"))]
type DemandCapture=();

/// MessageBound/P4 ships by default; older policies remain research overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepairPolicy { Reliability, MeanOpen, MeanTopup, Streaming, MessageBound }
static RESEARCH_POLICY: std::sync::OnceLock<RepairPolicy> = std::sync::OnceLock::new();
static RESEARCH_INTERLEAVE_WIDTH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static RESEARCH_SLIPSTREAM: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static RESEARCH_MEDIUM_BONUS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
static RESEARCH_EVENT_REPAIR: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// RESEARCH-ONLY p4-event-repair strength q (E0/E5/E10): percent of each exposed group's source K granted once per
/// logical root at its first qualifying accepted congestion event. Default 0 = baseline.
#[doc(hidden)]
pub fn research_p4_event_repair() -> u32 { RESEARCH_EVENT_REPAIR.get().copied().unwrap_or(0) }
pub(crate) fn parse_event_repair(value: Option<&str>, policy: RepairPolicy, width: usize, slipstream: bool, bonus: u32) -> Result<u32, String> {
    let q = match value.unwrap_or("0") { "0" => 0, "5" => 5, "10" => 10,
        _ => return Err("STP_P4_EVENT_REPAIR must be 0, 5 or 10".to_string()) };
    if q != 0 && (policy != RepairPolicy::MessageBound || width != 1 || slipstream || bonus != 0) {
        return Err("STP_P4_EVENT_REPAIR requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0".to_string());
    }
    Ok(q)
}
static RESEARCH_BASE_PARITY: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// RESEARCH-ONLY p4-burst-base absolute packet-count base parity model (B0/B1). Default 0 = baseline.
#[doc(hidden)]
pub fn research_p4_base_parity_model() -> u32 { RESEARCH_BASE_PARITY.get().copied().unwrap_or(0) }
pub(crate) fn parse_base_parity_model(value: Option<&str>, policy: RepairPolicy, width: usize, slipstream: bool, bonus: u32, event: u32) -> Result<u32, String> {
    let m = match value.unwrap_or("0") { "0" => 0, "1" => 1,
        _ => return Err("STP_P4_BASE_PARITY_MODEL must be 0 or 1".to_string()) };
    if m != 0 && (policy != RepairPolicy::MessageBound || width != 1 || slipstream || bonus != 0 || event != 0) {
        return Err("STP_P4_BASE_PARITY_MODEL requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0".to_string());
    }
    Ok(m)
}
static RESEARCH_BUDGET_BASE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// RESEARCH-ONLY C0/C1 budgeted base model; 0 is the unchanged E0 policy.
#[doc(hidden)]
pub fn research_p4_budget_base() -> u32 { RESEARCH_BUDGET_BASE.get().copied().unwrap_or(0) }
pub(crate) fn parse_budget_base(value: Option<&str>, policy: RepairPolicy, width: usize, slipstream: bool, bonus: u32, event: u32, base: u32) -> Result<u32, String> {
    let m = match value.unwrap_or("0") { "0" => 0, "1" => 1,
        _ => return Err("STP_P4_BUDGET_BASE must be 0 or 1".to_string()) };
    if m != 0 && (policy != RepairPolicy::MessageBound || width != 1 || slipstream || bonus != 0 || event != 0 || base != 0) {
        return Err("STP_P4_BUDGET_BASE requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0".to_string());
    }
    Ok(m)
}
static RESEARCH_TARGET_VALIDATION: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// Frozen forecast selector: 0 previous baseline, 1 gradual target, 2 neighboring mixture.
#[doc(hidden)]
pub fn research_p4_target_validation() -> u32 { RESEARCH_TARGET_VALIDATION.get().copied().unwrap_or(0) }
fn parse_target_validation(value:Option<&str>) -> Result<u32,String> {
    let v=match value {Some("0")=>0,Some("1")=>1,Some("2")=>2,None if !true=>0,
        _=>return Err("STP_P4_TARGET_VALIDATION must be explicitly 0, 1 or 2".into())};
    if v!=0 && !true {return Err("target validation requires feature research_target_validation".into());} Ok(v)
}
static RESEARCH_COST_SMOOTH: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// Research-only policy selector; zero preserves empirical calibration exactly.
#[doc(hidden)]
pub fn research_p4_cost_smooth() -> u32 { RESEARCH_COST_SMOOTH.get().copied().unwrap_or(0) }
fn parse_cost_smooth(value: Option<&str>) -> Result<u32, String> {
    let v = match value.unwrap_or("0") { "0" => 0, "1" => 1,
        _ => return Err("STP_P4_COST_SMOOTH must be 0 or 1".into()) };
    if v == 1 && !true {
        return Err("STP_P4_COST_SMOOTH=1 requires feature research_cost_smooth".into());
    }
    Ok(v)
}
static RESEARCH_REPAIR_CAP_PERCENT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// Frozen process-start research ceiling; no environment reads in transport planning.
#[doc(hidden)]
pub fn research_p4_repair_cap_percent() -> u32 { RESEARCH_REPAIR_CAP_PERCENT.get().copied().unwrap_or(15) }
pub(crate) fn parse_repair_cap_percent(value: Option<&str>, policy: RepairPolicy, width: usize, slipstream: bool, bonus: u32, event: u32, base: u32, budget: u32) -> Result<u32, String> {
    let cap = match value.unwrap_or("15") { "15" => 15, "25" => 25, "0" if true => 0,
        _ => return Err("STP_P4_REPAIR_CAP_PERCENT must be 15 or 25".to_string()) };
    if cap != 15 && !true {
        return Err("STP_P4_REPAIR_CAP_PERCENT=25 requires feature research_budget25".to_string());
    }
    if cap != 15 && (policy != RepairPolicy::MessageBound || width != 1 || slipstream || bonus != 0 || event != 0 || base != 0 || budget != 1) {
        return Err("STP_P4_REPAIR_CAP_PERCENT=25 requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0, STP_P4_BUDGET_BASE=1".to_string());
    }
    Ok(cap)
}
static RESEARCH_EMPIRICAL_TAIL: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// Process-start selector, frozen across all roots, segments, TU retries and adaptive resets.
#[doc(hidden)]
pub fn research_p4_empirical_tail_calibration() -> u32 { RESEARCH_EMPIRICAL_TAIL.get().copied().unwrap_or(0) }
pub(crate) fn parse_empirical_tail(value: Option<&str>, policy: RepairPolicy, width: usize, slipstream: bool, bonus: u32, event: u32, base: u32, budget: u32, cap: u32) -> Result<u32, String> {
    let q = match value.unwrap_or("0") { "0" => 0, "1" => 1,
        _ => return Err("STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1".into()) };
    if q != 0 && !true {
        return Err("STP_P4_EMPIRICAL_TAIL_CALIBRATION=1 requires feature research_empirical_calibration".into());
    }
    // Compiling this experiment requires the same isolated policy for BOTH arms, even env=0.
    if true && (policy != RepairPolicy::MessageBound || width != 1 || slipstream || bonus != 0 || event != 0 || base != 0 || budget != 1 || (cap != 25 && !(true && cap == 0))) {
        return Err("empirical calibration requires P4/W1/SS0/bonus0/event0/model0/budget_base1/cap25".into());
    }
    Ok(q)
}
pub(crate) fn research_slipstream() -> bool {
    RepairPolicy::selected() == RepairPolicy::MessageBound && RESEARCH_SLIPSTREAM.get().copied().unwrap_or(false)
}
/// Benchmark configuration echo; no environment reads after initialization.
#[doc(hidden)]
pub fn research_p4_configuration() -> (&'static str, usize, bool, u32) {
    let policy = match RepairPolicy::selected() {
        RepairPolicy::Reliability => "P0", RepairPolicy::MeanOpen => "P1",
        RepairPolicy::MeanTopup => "P2", RepairPolicy::Streaming => "P3", RepairPolicy::MessageBound => "P4",
    };
    (policy, research_interleave_width(), research_slipstream(), research_medium_bonus())
}
fn parse_medium_bonus(value: Option<&str>, policy: RepairPolicy) -> Result<u32, String> {
    let percent = value.unwrap_or("0").parse::<u32>().ok().filter(|v| *v <= 100)
        .ok_or_else(|| "STP_P4_MEDIUM_BONUS_PERCENT must be an integer 0..=100".to_string())?;
    if percent != 0 && policy != RepairPolicy::MessageBound {
        return Err("STP_P4_MEDIUM_BONUS_PERCENT applies only to P4".to_string());
    }
    Ok(percent)
}
pub(crate) fn research_medium_bonus() -> u32 { RESEARCH_MEDIUM_BONUS.get().copied().unwrap_or(0) }
/// Fixed extra initial parity percentage in the shipped policy (zero in rc1).
pub fn category_bonus_percent() -> u32 { research_medium_bonus() }
fn parse_interleave_width(value: Option<&str>) -> Result<usize, String> {
    match value {
        None | Some("1") => Ok(1), Some("2") => Ok(2), Some("4") => Ok(4),
        _ => Err("STP_P4_INTERLEAVE_WIDTH must be 1, 2, or 4".to_string()),
    }
}
pub(crate) fn research_interleave_width() -> usize {
    // Benchmark initialization is opt-in. Merely setting an environment variable
    // does nothing for normal library construction; P0-P3 always remain serial.
    if RepairPolicy::selected() == RepairPolicy::MessageBound {
        RESEARCH_INTERLEAVE_WIDTH.get().copied().unwrap_or(1)
    } else { 1 }
}
impl RepairPolicy {
    fn selected() -> Self { RESEARCH_POLICY.get().copied().unwrap_or(Self::MessageBound) }
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            Some("P1") => Ok(Self::MeanOpen), Some("P2") => Ok(Self::MeanTopup),
            Some("P3") => Ok(Self::Streaming), Some("P4") => Ok(Self::MessageBound),
            Some("P0") => Ok(Self::Reliability), None => Ok(Self::MessageBound),
            Some(other) => Err(format!("unknown STP_RACE_POLICY {other:?}; expected P0, P1, P2, P3, or P4")),
        }
    }
    pub fn feedback(self) -> bool { self != Self::MeanOpen }
}
/// Benchmark process-start hook; normal library applications retain the shipped policy.
/// With no override, both this hook and normal library construction select P4.
#[doc(hidden)]
pub fn initialize_research_policy() -> Result<(), String> {
    if RESEARCH_POLICY.get().is_some() { return Ok(()); }
    let value = match crate::ship::policy_var("STP_RACE_POLICY") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err("STP_RACE_POLICY must be valid Unicode".to_string()),
    };
    let policy = RepairPolicy::parse(value.as_deref())?;
    let width = match crate::ship::policy_var("STP_P4_INTERLEAVE_WIDTH") {
        Ok(value) => parse_interleave_width(Some(&value))?,
        Err(std::env::VarError::NotPresent) => 1,
        Err(_) => return Err("STP_P4_INTERLEAVE_WIDTH must be valid Unicode".to_string()),
    };
    let slipstream = match crate::ship::policy_var("STP_P4_SLIPSTREAM") {
        Ok(v) if v == "1" => true,
        Ok(v) if v == "0" => false,
        Err(std::env::VarError::NotPresent) => false,
        _ => return Err("STP_P4_SLIPSTREAM must be 0 or 1".to_string()),
    };
    if slipstream && width != 1 { return Err("slipstream requires STP_P4_INTERLEAVE_WIDTH=1".to_string()); }
    let bonus = match crate::ship::policy_var("STP_P4_MEDIUM_BONUS_PERCENT") {
        Ok(v) => parse_medium_bonus(Some(&v), policy)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err("STP_P4_MEDIUM_BONUS_PERCENT must be an integer 0..=100".to_string()),
    };
    let event = match crate::ship::policy_var("STP_P4_EVENT_REPAIR") {
        Ok(v) => parse_event_repair(Some(&v), policy, width, slipstream, bonus)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err("STP_P4_EVENT_REPAIR must be 0, 5 or 10".to_string()),
    };
    let base = match crate::ship::policy_var("STP_P4_BASE_PARITY_MODEL") {
        Ok(v) => parse_base_parity_model(Some(&v), policy, width, slipstream, bonus, event)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err("STP_P4_BASE_PARITY_MODEL must be 0 or 1".to_string()),
    };
    let budget = match crate::ship::policy_var("STP_P4_BUDGET_BASE") {
        Ok(v) => parse_budget_base(Some(&v), policy, width, slipstream, bonus, event, base)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err("STP_P4_BUDGET_BASE must be 0 or 1".to_string()),
    };
    let cost = match crate::ship::policy_var("STP_P4_COST_SMOOTH") {
        Ok(v) => parse_cost_smooth(Some(&v))?,
        Err(std::env::VarError::NotPresent) => parse_cost_smooth(None)?,
        Err(_) => return Err("STP_P4_COST_SMOOTH must be 0 or 1".into()),
    };
    let cap = match crate::ship::policy_var("STP_P4_REPAIR_CAP_PERCENT") {
        Ok(v) => parse_repair_cap_percent(Some(&v), policy, width, slipstream, bonus, event, base, budget)?,
        Err(std::env::VarError::NotPresent) => 15,
        Err(_) => return Err("STP_P4_REPAIR_CAP_PERCENT must be 15 or 25".to_string()),
    };
    let empirical = match crate::ship::policy_var("STP_P4_EMPIRICAL_TAIL_CALIBRATION") {
        Ok(v) => parse_empirical_tail(Some(&v), policy, width, slipstream, bonus, event, base, budget, cap)?,
        Err(std::env::VarError::NotPresent) => parse_empirical_tail(None, policy, width, slipstream, bonus, event, base, budget, cap)?,
        Err(_) => return Err("STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1".into()),
    };
    if (cost == 1 && (cap != 0 || empirical != 1)) || (cost == 0 && cap == 0) {
        return Err("cost smooth requires selector1/cap0/empirical1; cap0 is forbidden for selector0".into());
    }
    let target=match crate::ship::policy_var("STP_P4_TARGET_VALIDATION") {
        Ok(v)=>parse_target_validation(Some(&v))?,
        Err(std::env::VarError::NotPresent)=>parse_target_validation(None)?,
        Err(_)=>return Err("STP_P4_TARGET_VALIDATION must be explicitly 0, 1 or 2".into()),
    };

    crate::target_validation::initialize(target,crate::ship::policy_var("STP_COHORT_PROFILE").ok().as_deref(),cost,cap,empirical)?;
    let _=RESEARCH_TARGET_VALIDATION.set(target);
    let _ = RESEARCH_COST_SMOOTH.set(cost);
    let _ = RESEARCH_EMPIRICAL_TAIL.set(empirical);
    let _ = RESEARCH_REPAIR_CAP_PERCENT.set(cap);
    let _ = RESEARCH_BUDGET_BASE.set(budget);
    let _ = RESEARCH_BASE_PARITY.set(base);
    let _ = RESEARCH_EVENT_REPAIR.set(event);
    let _ = RESEARCH_MEDIUM_BONUS.set(bonus);
    let _ = RESEARCH_SLIPSTREAM.set(slipstream);
    let _ = RESEARCH_INTERLEAVE_WIDTH.set(width);
    let _ = RESEARCH_POLICY.set(policy);
    Ok(())
}

/// Expected source AND repair loss, plus two decoder-rank symbols, capped at K.
pub(crate) fn mean_repairs(k: u64, p: f64) -> u64 {
    if k == 0 { return 0; }
    ((k as f64 * p.clamp(0.0, 0.9) / (1.0 - p.clamp(0.0, 0.9))).ceil() as u64)
        .saturating_add(2).min(k)
}

/// Internal span-tail protection policy. The sole configuration lives in ship.rs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AdaptiveFecConfig {
    pub eps: f64,
    pub min_loss: f64,
    pub initial_loss: f64,
    pub max_redundancy: f64,
    pub extra_blocks: u32,
    pub bucket_ns: u64,
    pub min_packets: u64,
    pub slot_ns: u64,
    pub slots: usize,
    pub window_ns: u64,
}
impl Default for AdaptiveFecConfig {
    fn default() -> Self { crate::ship::FEC }
}
// Retainable messages have feedback rescue as a delivery backstop. Pre-sent parity
// targets a 2% chance of needing that extra RTT, not packet-loss-scale reliability.
const RESCUE_LATENCY_TAIL: f64 = 0.02;

/// Upper-tail standard normal quantile: z with P(Z > z) = eps (Abramowitz-Stegun 26.2.23,
/// |error| < 4.5e-4). eps is clamped to [1e-300, 0.5].
pub fn z_for_eps(eps: f64) -> f64 {
    let eps = eps.clamp(1e-300, 0.5);
    let t = (-2.0 * eps.ln()).sqrt();
    t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (1.0 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t)
}

/// Smallest N (returned as N - K, the repair block count, before `extra`/cap) such that a loss count
/// L ~ Binomial(N, p) satisfies P(L > N - K) <= eps, using the normal approximation with a
/// Cornish-Fisher skew correction: the (1-eps) quantile of L is about Np + z*sigma + (z^2-1)(1-2p)/6.
/// So N(1-p) - z*sqrt(N p (1-p)) >= K + c with c = (z^2-1)(1-2p)/6, solved as a quadratic in sqrt(N).
/// The constant c (~3.6 blocks at eps=1e-6) is what gives small K proportionally more repair.
pub fn formula_repair_blocks(k: u64, p: f64, z: f64) -> u64 {
    let p = p.clamp(1e-9, 0.9);
    let s = (p * (1.0 - p)).sqrt();
    let c = ((z * z - 1.0) * (1.0 - 2.0 * p) / 6.0).max(0.0);
    let kk = k as f64 + c;
    let x = (z * s + (z * z * s * s + 4.0 * (1.0 - p) * kk).sqrt()) / (2.0 * (1.0 - p));
    let n = (x * x).ceil() as u64;
    n.saturating_sub(k)
}

/// Exact P(L >= m) for L ~ Binomial(n, p), n small (pmf recurrence; used for n <= EXACT_MAX_N).
fn binomial_tail(n: u64, p: f64, m: u64) -> f64 {
    if m == 0 { return 1.0; }
    if m > n { return 0.0; }
    let mut pmf = (1.0 - p).powi(n as i32);
    let r = p / (1.0 - p);
    let mut tail = 0.0;
    for j in 0..=n {
        if j >= m { tail += pmf; }
        pmf *= (n - j) as f64 / (j + 1) as f64 * r;
    }
    tail
}
const EXACT_MAX_K: u64 = 128;

/// Like [`formula_repair_blocks`], but exact (binomial) for k <= 128, where the normal
/// approximation overshoots by 1-3 blocks. `eps` is the target the exact search uses.
pub fn min_repair_blocks(k: u64, p: f64, z: f64, eps: f64) -> u64 {
    if k > EXACT_MAX_K { return formula_repair_blocks(k, p, z); }
    let p = p.clamp(1e-9, 0.9);
    let mut n = k;
    // P(fewer than k of n arrive) = P(L >= n - k + 1); bounded: the formula's answer always passes.
    let limit = k + formula_repair_blocks(k, p, z);
    while n < limit && binomial_tail(n, p, n - k + 1) > eps { n += 1; }
    n - k
}

/// p4-burst-base: smallest loss COUNT q with P(Bin(n, p) > q) <= eps. Exact binomial search for
/// n <= 128, else the Cornish-Fisher count quantile ceil(np + z*sqrt(np(1-p)) + (z^2-1)(1-2p)/6).
/// Always clamped to 0..=n. An independent-loss prior, not a burst model.
pub fn iid_count_quantile(n: u64, p: f64, eps: f64) -> u64 {
    if n == 0 { return 0; }
    let p = p.clamp(1e-9, 0.9);
    let eps = eps.clamp(1e-300, 0.5);
    if n <= EXACT_MAX_K {
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if binomial_tail(n, p, mid + 1) <= eps { hi = mid; } else { lo = mid + 1; }
        }
        return lo;
    }
    let z = z_for_eps(eps);
    let np = n as f64 * p;
    let q = np + z * (np * (1.0 - p)).sqrt() + (z * z - 1.0) * (1.0 - 2.0 * p) / 6.0;
    if !(q > 0.0) { return 0; }
    (q.ceil() as u64).min(n)
}
/// p4-burst-base internal per-root target (an empirical target, not a guarantee).
pub(crate) const BASE_EPS_ROOT: f64 = 0.001;
/// Exact research replay oracle; this does not query or modify a transport sketch.

#[doc(hidden)]
pub fn research_iid_count_quantile(n:u64,p:f64,eps:f64)->u64 {iid_count_quantile(n,p,eps)}

#[doc(hidden)]
pub fn research_base_group_eps(codecs:usize)->f64 {base_group_eps(codecs)}
/// Union-bound share of the root target for one Wirehair codec (all segments and layout groups).
pub(crate) fn base_group_eps(codecs: usize) -> f64 { BASE_EPS_ROOT / codecs.max(1) as f64 }
/// Legacy default retained for callers/tests; the selected ceiling never enters the demand model.
pub(crate) fn budget_repair_limit(k: u64) -> u64 { budget_repair_limit_for_cap(k, 15) }
/// Exact floor(cap*K/100), with a wide intermediate even at the u64 boundary.
pub(crate) fn budget_repair_limit_for_cap(k: u64, cap_percent: u32) -> u64 {
    assert!(cap_percent == 15 || cap_percent == 25);
    (cap_percent as u128 * k as u128 / 100) as u64
}
/// Iteration budget for the monotone fixed points; exhaustion falls back to the safe cap Kg.
const BASE_ITER_LIMIT: usize = 64;

/// Repair blocks for a message of `k` source blocks under loss estimate `p` (already floored).
pub fn repair_blocks(k: u64, p: f64, z: f64, eps: f64, extra: u32, max_redundancy: f64) -> u64 {
    let r = min_repair_blocks(k, p, z, eps) + extra as u64;
    let cap = ((k as f64 * max_redundancy).ceil() as u64).max(1);
    r.clamp(1, cap)
}

/// Accumulates finalized/lost DATA deltas into short-term loss samples.
#[derive(Clone, Copy, Debug)]
struct ShortTerm { start_ns: u64, finalized: u64, lost: u64 }

/// Per-connection loss tracker: short-term buckets plus one estimator. Fixed size, no allocation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LossTracker {
    cfg: AdaptiveFecConfig,
    st: ShortTerm,
    ring: [(u64, u64, u64); 16],
    have_sample: bool,
    last_sample: f64,
    cached: f64,
    mean: f64,
    last_refresh_ns: u64,
}

impl LossTracker {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        LossTracker { cfg, st: ShortTerm { start_ns: now_ns, finalized: 0, lost: 0 }, ring: [(u64::MAX, 0, 0); 16], have_sample: false, last_sample: 0.0, cached: cfg.initial_loss, mean: cfg.initial_loss, last_refresh_ns: now_ns }
    }

    /// Feed counter deltas since the previous call. O(1) (refresh is a fixed 16-slot loop at
    /// most once per `bucket_ns`).
    pub fn on_tick(&mut self, now_ns: u64, finalized_delta: u64, lost_delta: u64) {
        debug_assert!(lost_delta <= finalized_delta);
        self.st.finalized += finalized_delta;
        self.st.lost += lost_delta;
        let elapsed = now_ns.saturating_sub(self.st.start_ns);
        if elapsed >= self.cfg.bucket_ns && (self.st.finalized >= self.cfg.min_packets.max(1)
            || self.st.lost >= self.cfg.min_packets.max(4).div_ceil(4)) {
            // Preserve prompt sampling of substantial loss even on sparse paths.
            let sample = self.st;
            self.st = ShortTerm { start_ns: now_ns, finalized: 0, lost: 0 };
            self.on_sample(now_ns, sample.finalized, sample.lost);
        } else if now_ns.saturating_sub(self.last_refresh_ns) >= self.cfg.bucket_ns {
            self.refresh(now_ns);
        }
    }

    fn on_sample(&mut self, now_ns: u64, finalized: u64, lost: u64) {
        let loss = lost as f64 / finalized as f64;
        self.mean = if self.have_sample { self.mean * 0.875 + loss * 0.125 } else { loss };
        self.have_sample = true;
        self.last_sample = loss;
        let cfg = self.cfg;
        let n = cfg.slots.clamp(1, 16);
        let idx = now_ns / cfg.slot_ns.max(1);
        let s = &mut self.ring[(idx % n as u64) as usize];
        if s.0 != idx { *s = (idx, 0, 0); }
        s.1 += finalized;
        s.2 += lost;
        self.refresh(now_ns);
    }

    fn refresh(&mut self, now_ns: u64) {
        self.last_refresh_ns = now_ns;
        if !self.have_sample { return; }
        let cfg = self.cfg;
        let n = cfg.slots.clamp(1, 16) as u64;
        let idx = now_ns / cfg.slot_ns.max(1);
        // Pool counts, not maxima of ratios: clean outcomes dilute a burst immediately.
        // The existing time horizon still bounds memory and expires stale evidence.
        let (finalized, lost) = self.ring.iter()
            .filter(|s| s.0 != u64::MAX && s.0 + n > idx)
            .fold((0u64, 0u64), |(f, l), s| (f + s.1, l + s.2));
        self.cached = lost as f64 / finalized.max(1) as f64;
    }

    /// Current loss estimate (raw; before the `min_loss` floor). `initial_loss` until the first sample.
    pub fn estimate(&self) -> f64 { self.cached }
    pub fn last_sample(&self) -> f64 { self.last_sample }
    pub fn config(&self) -> &AdaptiveFecConfig { &self.cfg }
}

/// What the sender records per FEC-coded message (opt-in, see NetworkThreadOptions).
#[derive(Clone, Copy, Debug, Default)]
pub struct FecMessageInfo {
    /// First 8 bytes of the message, little-endian, zero padded: lets an application match records.
    pub tag: u64,
    pub message_len: usize,
    pub k: u32,
    /// Block count planned when the message started, and actually sent (larger after top-up).
    pub n_planned: u32,
    pub n_sent: u32,
    /// Loss rate the plan was sized for (after the floor); the packet-loss estimate.
    pub loss_estimate: f64,
    /// Own packets declared lost while the message was being sent.
    pub lost_during_send: u32,
    /// Research group identity and feedback repair counters (opt-in recording only).
    pub package_id: u64,
    pub root_id: u64,
    pub segment_offset: u32,
    pub block_bytes: u32,
    pub rescue_rounds: u8,
    pub rescue_symbols: u32,
    /// Sent repairs beyond the initial plan, attributed at plan growth to
    /// known-loss deficit or unresolved-tail allowance (excluding P3 rescue).
    pub during_message_topup: u32,
    pub tail_repairs: u32,
    /// Connection-wide peak post-send/suspended source quota; P4 never leases it.
    pub peak_retained_source_bytes: u64,
}

/// Fixed-memory losses-in-span sketch. Sixteen dyadic sliding windows (2..65536 packets),
/// sampled at 16 phases/window, feed two time-rotating 64-bin histograms per scale.
/// Counts 0..31 are exact; larger bins round UP (at most 50%). Queries use the next larger
/// span, never IID scaling. Small sample sets use their maximum. This is an empirical tail,
/// not a guarantee for unseen losses or a calibrated confidence bound.
///
/// Memory is independent of bandwidth, RTT, connection lifetime, and packet rate: a fixed
/// 65536-bit history, fixed histograms and a fixed bitset matching STP's already-bounded ACK
/// sequence ring (to exclude ACK-only and probe packets from the data sequence).
// Exact counts below 128, then sixteen upward-rounded buckets per doubling.
// This is still a fixed-size empirical sketch, not density/IID scaling of bursts.
const SPAN_LOSS_BINS: usize = 288;
#[derive(Clone, Debug)]
pub(crate) struct SpanLossProfile {
    data_sent: [u64; crate::stp::PACKETS_WAITING_ACK_WORDS],
    history: [u64; 1024],
    counts: [u32; 16],
    hist: [[[u32; SPAN_LOSS_BINS]; 16]; 2],
    epochs: [u64; 2],
    seen: u64,
    lost_total: u64,
    sent_total: u64,
    pending_peak: u64,
}
impl Default for SpanLossProfile {
    fn default() -> Self {
        Self { data_sent: [0; crate::stp::PACKETS_WAITING_ACK_WORDS], history: [0; 1024], counts: [0; 16], hist: [[[0; SPAN_LOSS_BINS]; 16]; 2], epochs: [u64::MAX; 2], seen: 0, lost_total: 0, sent_total: 0, pending_peak: 0 }
    }
}
impl SpanLossProfile {
    fn bin(losses: u32) -> usize {
        if losses < 128 { return losses as usize; }
        let log = 31 - losses.leading_zeros();
        let base = 1u32 << log;
        128 + (log as usize - 7) * 16 + (losses - base).div_ceil(base / 16) as usize
    }
    fn upper(bin: usize) -> u64 {
        if bin < 128 { return bin as u64; }
        let base = 128u64 << ((bin - 128) / 16);
        base + ((bin - 128) % 16) as u64 * (base / 16)
    }
    pub fn on_data_sent(&mut self, seq: u64) {
        let bit = seq as usize % (self.data_sent.len() * 64);
        self.data_sent[bit / 64] |= 1u64 << (bit % 64);
        self.sent_total += 1;
        self.pending_peak = self.pending_peak.max(self.unresolved_data_packets());
    }
    /// Sent data not yet retired by STP's existing ordered ACK/loss ring. Includes ACKed data
    /// behind a missing earlier sequence: conservative without assuming in-order arrival.
    pub fn unresolved_data_packets(&self) -> u64 { self.sent_total.saturating_sub(self.seen) }
    /// Feed each retired sequence exactly once, in order. Loss declarations are conservative:
    /// a late ACK does not undo the tail histogram (use only where declarations are trustworthy).
    pub fn on_sequence_finalized(&mut self, seq: u64, lost: bool, now_ns: u64, window_ns: u64) {
        let bit = seq as usize % (self.data_sent.len() * 64);
        if self.data_sent[bit / 64] & (1u64 << (bit % 64)) == 0 { return; }
        self.data_sent[bit / 64] &= !(1u64 << (bit % 64));
        self.on_outcome(lost, now_ns, window_ns);
    }
    pub fn on_outcome(&mut self, lost: bool, now_ns: u64, window_ns: u64) {
        let epoch = now_ns / (window_ns / 2).max(1);
        let h = epoch as usize % 2;
        if self.epochs[h] != epoch { self.hist[h] = [[0; SPAN_LOSS_BINS]; 16]; self.epochs[h] = epoch; }
        let pos = self.seen as usize & 65535;
        // Read the old ring before writing: the 65536-packet window expires this very bit.
        for scale in 0..16 {
            let n = 2usize << scale;
            let old = (pos + 65536 - n) & 65535;
            let expired = (self.history[old / 64] >> (old % 64)) & 1;
            self.counts[scale] = self.counts[scale] + lost as u32 - expired as u32;
            let stride = (n / 16).max(1);
            if self.seen + 1 >= n as u64 && (self.seen + 1) % stride as u64 == 0 {
                let bin = Self::bin(self.counts[scale]);
                self.hist[h][scale][bin] = self.hist[h][scale][bin].saturating_add(1);
            }
        }
        if lost { self.history[pos / 64] |= 1u64 << (pos % 64); }
        else { self.history[pos / 64] &= !(1u64 << (pos % 64)); }
        self.seen += 1;
        self.lost_total += lost as u64;
    }
    /// Upper observed (1-eps) loss quantile for a span at least n packets long. For spans beyond
    /// 65536, union bound the subspans conservatively; those long messages should use FEC groups.
    pub fn tail_losses(&self, n: u64, eps: f64) -> Option<u64> {
        let latest = self.epochs.iter().copied().filter(|x| *x != u64::MAX).max()?;
        self.tail_losses_latest(n, eps, latest)
    }
    /// p4-burst-base: the same quantile, but histograms expire relative to NOW, not to the newest
    /// observation epoch (a quiet period does not keep an old burst history alive).
    pub fn tail_losses_now(&self, n: u64, eps: f64, now_ns: u64, window_ns: u64) -> Option<u64> {
        let now_epoch = now_ns / (window_ns / 2).max(1);
        let latest = self.epochs.iter().copied().filter(|x| *x != u64::MAX).max()?.max(now_epoch);
        self.tail_losses_latest(n, eps, latest)
    }
    fn tail_losses_latest(&self,n:u64,eps:f64,latest:u64)->Option<u64> { self.tail_losses_latest_details(n,eps,latest).0 }
    fn tail_losses_now_details(&self,n:u64,eps:f64,now_ns:u64,window_ns:u64)->(Option<u64>,u16,u64) {
        let Some(latest)=self.epochs.iter().copied().filter(|x|*x!=u64::MAX).max() else {return(None,0,0);};
        self.tail_losses_latest_details(n,eps,latest.max(now_ns/(window_ns/2).max(1)))
    }
    fn tail_losses_latest_details(&self,n:u64,eps:f64,latest:u64)->(Option<u64>,u16,u64) {
        let pieces = n.div_ceil(65536).max(1);
        let n = n.div_ceil(pieces).max(2);
        let scale = (64 - (n - 1).leading_zeros() as usize).saturating_sub(1).min(15);
        let mut bins = [0u64; SPAN_LOSS_BINS];
        for h in 0..2 {
            if self.epochs[h] != u64::MAX && self.epochs[h] + 1 >= latest {
                for (b, count) in bins.iter_mut().zip(self.hist[h][scale]) { *b += count as u64; }
            }
        }
        let total: u64 = bins.iter().sum();
        if total == 0 { return (None,scale as u16,0); }
        let allowed_tail = (total as f64 * (eps / pieces as f64).clamp(0.0, 0.5)).floor() as u64;
        let rank = total - allowed_tail;
        let mut acc = 0;
        for (b, count) in bins.iter().enumerate() {
            acc += count;
            if acc >= rank { return (Some(Self::upper(b)*pieces),scale as u16,total); }
        }
        (None,scale as u16,total)
    }
    /// Size-sensitive target: never weaker than cfg.eps or packet loss; beyond 64 source
    /// blocks it tightens as sqrt(64/K), since expensive messages merit greater reliability.
    pub fn target_failure(&self, k: u64, cfg: &AdaptiveFecConfig) -> f64 {
        let p = if self.seen < 4096 { cfg.initial_loss } else { (self.lost_total as f64 / self.seen as f64).max(1e-6) };
        cfg.eps.min(p * (64.0 / k.max(1) as f64).min(1.0).sqrt()).clamp(1e-9, 0.5)
    }
    fn repair_blocks(&self, k: u64, cfg: &AdaptiveFecConfig, _z: f64) -> u64 {
        self.margin_blocks(k, k, cfg)
    }
    fn margin_blocks(&self, k: u64, whole_message_k: u64, cfg: &AdaptiveFecConfig) -> u64 {
        self.margin_blocks_for_groups(k, whole_message_k, 1, cfg)
    }
    fn margin_blocks_for_groups(&self, k: u64, whole_message_k: u64, groups: usize, cfg: &AdaptiveFecConfig) -> u64 {
        self.margin_blocks_for_groups_with_floor(k, whole_message_k, groups, cfg, true)
    }
    fn margin_blocks_for_groups_with_floor(&self, k: u64, whole_message_k: u64, groups: usize, cfg: &AdaptiveFecConfig, burst_tail: bool) -> u64 {
        let cap = ((k as f64 * cfg.max_redundancy).ceil() as u64).max(1);
        // Retainable messages use a latency-tail budget; oversized/unretainable
        // messages preserve the original size-sensitive reliability target and floor.
        let prior = if self.seen < 4096 { cfg.initial_loss } else { cfg.min_loss };
        let message_eps = if burst_tail { self.target_failure(whole_message_k, cfg) }
            else { RESCUE_LATENCY_TAIL };
        let eps = message_eps / groups.max(1) as f64;
        let floor = if burst_tail { 12.min(k) } else { 0 };
        let mut r = repair_blocks(k, prior, z_for_eps(eps), eps, cfg.extra_blocks, cfg.max_redundancy).max(floor).min(cap);
        for _ in 0..32 {
            let Some(q) = self.tail_losses(k + r, eps) else { break; };
            let next = r.max(q.saturating_add(cfg.extra_blocks as u64).max(1)).min(cap);
            if next == r { break; }
            r = next;
        }
        r
    }
}

/// Per-connection adaptive state: tracker plus counter baselines. Lives in UnreliableSendBuffer.
#[derive(Clone, Debug)]
pub(crate) struct FecAdaptiveState {
    pub tracker: LossTracker,
    pub policy: RepairPolicy,
    last_finalized: u64,
    last_lost: u64,
    /// Floored loss estimate used for new messages.
    pub p: f64,
    /// Fixed size, independent of bandwidth and packet rate.
    span: Box<SpanLossProfile>,
    /// p4-burst-base (B1 only consults these): env model flag, latest known time, and the blind
    /// horizon H = packets the connection may send in one loss timeout (None = unknown/cold).
    base_parity: bool,
    budget_base: bool,
    repair_cap_percent: u32,
    cost_smooth: bool,
    target_validation:u32,
    empirical_tail: bool,
    /// Unique state lifetime: an outage reset must invalidate every old slot anchor.
    data_generation: u64,
    diagnostic_created_ns:u64,
    base_now_ns: u64,
    base_horizon: Option<u64>,
}

impl FecAdaptiveState {
    #[cfg(test)]
    pub(crate) fn reliability_for_test(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        let mut state = Self::baseline_for_test(cfg, now_ns);
        state.policy = RepairPolicy::Reliability;
        state
    }

    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        initialize_research_policy().expect("invalid transport research policy");
        let tracker = LossTracker::new(cfg, now_ns);
        FecAdaptiveState { tracker, policy: RepairPolicy::selected(), last_finalized: 0, last_lost: 0, p: tracker.estimate().max(cfg.min_loss), span: Box::new(SpanLossProfile::default()),
            base_parity: research_p4_base_parity_model() == 1, budget_base: research_p4_budget_base() == 1, repair_cap_percent: research_p4_repair_cap_percent(),
            empirical_tail: research_p4_empirical_tail_calibration() == 1,
            cost_smooth: research_p4_cost_smooth() == 1,
            target_validation:research_p4_target_validation(),
            data_generation: { static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1); NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) }, base_now_ns: now_ns, base_horizon: None,
            diagnostic_created_ns:now_ns }
    }
    /// Pre-RC P4 fixture policy for tests of scheduler/ownership invariants. It is
    /// deliberately independent of the process-start ship/research selection.
    #[cfg(test)]
    pub(crate) fn baseline_for_test(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        let mut a=Self::new(cfg,now_ns);
        a.policy=RepairPolicy::MessageBound;
        a.base_parity=false; a.budget_base=false; a.repair_cap_percent=15;
        a.empirical_tail=false; a.cost_smooth=false; a.target_validation=0;
        a
    }
    /// Both counters describe the same DATA outcomes, attributed at ordered retirement.
    /// Like the span sketch, declarations remain conservative if later ACKed: subtracting
    /// global spurious counters could credit unrelated DATA losses or include control packets.
    pub fn on_tick(&mut self, now_ns: u64) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        let finalized = self.span.seen;
        let lost = self.span.lost_total;
        self.tracker.on_tick(now_ns, finalized - self.last_finalized, lost - self.last_lost);
        self.last_finalized = finalized;
        self.last_lost = lost;
        self.p = if self.policy == RepairPolicy::Reliability { self.tracker.estimate().max(self.tracker.cfg.min_loss) }
            else { self.tracker.mean };
    }
    pub fn on_data_sent(&mut self, seq: u64) {
        self.span.on_data_sent(seq);
    }
    pub fn on_sequence_finalized(&mut self, seq: u64, lost: bool, now_ns: u64) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        self.span.on_sequence_finalized(seq, lost, now_ns, self.tracker.cfg.window_ns);
    }
    /// Whole-message failure target, divided among independent Wirehair groups.
    pub fn group_failure_target(&self, whole_message_k: u64, groups: usize) -> f64 {
        let c = &self.tracker.cfg;
        self.span.target_failure(whole_message_k, c) / groups.max(1) as f64
    }
    /// Repair blocks for a new message of k source blocks.
    pub fn repair_blocks(&self, k: u64) -> u64 { self.repair_blocks_for_group(k, k, 1) }
    pub fn repair_blocks_for_group(&self, k: u64, whole_message_k: u64, groups: usize) -> u64 {
        self.repair_blocks_for_group_at_tail(k, whole_message_k, groups, true)
    }
    pub fn repair_blocks_for_group_at_tail(&self, k: u64, whole_message_k: u64, groups: usize, burst_tail: bool) -> u64 {
        if matches!(self.policy, RepairPolicy::Streaming | RepairPolicy::MessageBound) { return 2.min(k); }
        if self.policy != RepairPolicy::Reliability { return mean_repairs(k, self.p); }
        let c = &self.tracker.cfg;
        let span = &self.span;
        let horizon = if span.seen >= 4096 { k.min(span.pending_peak.max(1)) } else { k };
        let cap = ((k as f64 * c.max_redundancy).ceil() as u64).max(1).min(k);
        let r = span.margin_blocks_for_groups_with_floor(horizon, whole_message_k, groups, c, burst_tail);
        r.max(if burst_tail { 12.min(k) } else { 0 }).min(cap)
    }
    /// Extra fresh repairs for a single-group message; no retransmission or feedback wait.
    pub fn extra_repair_blocks_needed_now(&self, k: u64, blocks_sent: u64, repair_blocks_sent: u64, own_declared_lost: u64) -> u64 {
        self.extra_repair_blocks_needed_for_group(k, k, 1, blocks_sent, repair_blocks_sent, own_declared_lost)
    }
    /// Per-group own-loss budget, with whole-message target allocated by a union bound.
    /// Connection-wide unresolved data conservatively bounds each group's tail; it is NOT
    /// divided by group count (interleaving does not prove equal loss ownership).
    pub fn extra_repair_blocks_needed_for_group(&self, k: u64, whole_message_k: u64, groups: usize, blocks_sent: u64, repair_blocks_sent: u64, own_declared_lost: u64) -> u64 {
        self.extra_repair_blocks_needed_for_group_at_tail(k, whole_message_k, groups, blocks_sent, repair_blocks_sent, own_declared_lost, true)
    }
    pub fn extra_repair_blocks_needed_for_group_at_tail(&self, k: u64, whole_message_k: u64, groups: usize, blocks_sent: u64, repair_blocks_sent: u64, own_declared_lost: u64, burst_tail: bool) -> u64 {
        let span = &self.span;
        if k == 0 { return 0; }
        let c = &self.tracker.cfg;
        let cap = ((k as f64 * c.max_redundancy).ceil() as u64).min(k);
        let floor = if burst_tail { 12.min(k) } else { 0 };
        let unsent_sources = k.saturating_sub(blocks_sent.saturating_sub(repair_blocks_sent));
        let pending = span.unresolved_data_packets().saturating_add(unsent_sources);
        let mut total_repairs = own_declared_lost.saturating_add(floor).min(cap);
        for _ in 0..32 {
            let horizon = pending.saturating_add(total_repairs.saturating_sub(repair_blocks_sent)).min(k.saturating_add(total_repairs)).max(1);
            let margin = span.margin_blocks_for_groups_with_floor(horizon, whole_message_k, groups, c, burst_tail).max(floor);
            let next = total_repairs.max(own_declared_lost.saturating_add(margin)).min(cap);
            if next == total_repairs { break; }
            total_repairs = next;
        }
        total_repairs.saturating_sub(repair_blocks_sent)
    }
    /// p4-burst-base model B1 is in force for new P4 plans.
    pub fn base_parity_active(&self) -> bool { self.base_parity && self.policy == RepairPolicy::MessageBound }
    #[cfg(test)]
    pub(crate) fn set_base_parity_for_test(&mut self, on: bool) { self.base_parity = on; }
    pub fn budget_base_active(&self) -> bool { self.budget_base && self.policy == RepairPolicy::MessageBound }
    #[cfg(test)]
    pub(crate) fn set_budget_base_for_test(&mut self, on: bool) { self.budget_base = on; }
    #[cfg(test)]
    pub(crate) fn set_empirical_for_test(&mut self,on:bool) {self.empirical_tail=on;}
    pub fn repair_cap_percent(&self) -> u32 { self.repair_cap_percent }
    pub(crate) fn target_selector(&self)->u32 {
        {self.target_validation}

    }
    #[cfg(test)]
    pub(crate) fn set_target_for_test(&mut self,selector:u32) { self.set_cost_smooth_for_test();self.target_validation=selector; }

    pub(crate) fn cost_smooth_active(&self) -> bool {
        { self.cost_smooth && self.budget_base_active() }

    }
    #[cfg(test)]
    pub(crate) fn set_cost_smooth_for_test(&mut self) { self.cost_smooth=true; self.budget_base=true; self.repair_cap_percent=0; }

    #[cfg(test)]
    pub(crate) fn set_repair_cap_for_test(&mut self, cap: u32) { assert!(cap == 15 || cap == 25); self.repair_cap_percent = cap; }
    /// Dense DATA origin BEFORE the first actual commit; control/pending/failed sends never advance S.
    pub fn data_anchor(&self) -> (u64, u64) { (self.data_generation, self.span.sent_total) }
    /// Enclosing interval, not own occupancy: retain foreign DATA inside [A,S), exclude older prefix.
    /// One extra covers the packet currently being constructed but not yet committed. An invalid
    /// generation has no tighter ownership proof, so use global backlog AND own unresolved exposure.
    pub fn budget_unresolved_span(&self, anchor: Option<(u64, u64)>, own: u64) -> (u64, bool) {
        match anchor {
            Some((generation, a)) if generation == self.data_generation && a <= self.span.sent_total =>
                (self.span.sent_total.saturating_sub(self.span.seen.max(a)).max(own).saturating_add(1), false),
            _ => (self.span.unresolved_data_packets().max(own).saturating_add(1), true),
        }
    }
    fn empirical_tail_active(&self)->bool {
        {self.empirical_tail}
    }
    pub fn budget_tail_repairs(&self,kg:u64,start:u64,d:u64,rs:u64,ug:u64,eps:f64,uc:u64)->(u64,bool) {
        self.budget_tail_impl(kg,start,d,rs,ug,if self.empirical_tail_active() {eps*10.0}else{eps},eps,uc,
            None)
    }
    /// The transport uses explicit codec allocation for bit-exact .01/codecs, not (.001/codecs)*10.
    pub fn budget_tail_for_codecs(&self,kg:u64,start:u64,d:u64,rs:u64,ug:u64,codecs:usize,uc:u64,
        whole_k:u64,
        capture:Option<&mut DemandCapture>)->(u64,bool) {

        if self.cost_smooth_active() { return self.cost_tail(kg,whole_k,start,d,rs,ug,codecs,uc,capture); }
        self.budget_tail_impl(kg,start,d,rs,ug,if self.empirical_tail_active() {0.01/codecs.max(1) as f64}else{base_group_eps(codecs)},base_group_eps(codecs),uc,
            capture)
    }
    /// Smooth packet-price risk budget, NOT an exact expected-cost minimizer or delivery guarantee.
    /// Retry exposure grows with whole-root source work K and K/H feedback windows.
    /// A packet-loss-referenced target prevents an intermediate-size reliability trough.

    fn cost_target(&self,whole_k:u64,codecs:usize,known_multi:bool)->Option<(f64,f64,u64)> {
        if !self.p.is_finite() || !(0.0..1.0).contains(&self.p) || !self.tracker.cfg.min_loss.is_finite() || !(0.0..1.0).contains(&self.tracker.cfg.min_loss) {return None;}
        let p=self.p.max(self.tracker.cfg.min_loss);
        if p==0.0 || whole_k==0 || whole_k>u32::MAX as u64 {return None;}
        let h=self.base_horizon.unwrap_or(whole_k).max(1) as f64;
        let eps=(p/(1.0+whole_k as f64/h)/codecs.max(1) as f64).clamp(1e-12,0.5);
        // Wirehair documents ~.02 mean extra symbols, not a worst-case bound. Model a
        // geometric rank-risk prior .02 per extra equation, weighted by >=2 erasures;
        // first repair is XOR and every sampled single erasure decodes without a reserve.
        // This is an ASSUMED rank-tail heuristic, not a calibrated tail or bound.
        // Native fixtures do NOT establish this geometric distribution.
        let zero=(1.0-p).powf(whole_k as f64);
        let one=whole_k as f64*p*(1.0-p).powf(whole_k.saturating_sub(1) as f64);
        let multi=(1.0-zero-one).clamp(0.0,1.0);
        let empirical_multi=self.span.tail_losses_now(whole_k,eps*0.5,self.base_now_ns,self.tracker.cfg.window_ns).is_some_and(|q|q>=2);
        let mut rank_risk=0.02*if known_multi || empirical_multi {1.0}else{multi};
        let mut reserve=0;
        while rank_risk>eps*0.5 && reserve<16 {rank_risk*=0.02;reserve+=1;}
        Some((eps,p,reserve))
    }

    fn cost_tail(&self,kg:u64,whole_k:u64,start:u64,d:u64,rs:u64,ug:u64,codecs:usize,uc:u64,
        mut capture:Option<&mut DemandCapture>)->(u64,bool) {
        let fail=|capture:Option<&mut DemandCapture>| {
            let known=start.max(d);
            let retained=if kg<=u32::MAX as u64 && known<=u32::MAX as u64-kg {known}else{start};
            #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture {c.header.flags|=8|16;c.header.result_r=retained.min(u32::MAX as u64)as u32;}
            (retained,true)
        };
        if kg==0 {return if start==0 && d==0 {(0,false)}else{fail(capture)};}
        let Some((eps,p,rank))=self.cost_target(whole_k,codecs,d>=2) else{return fail(capture);};
        let Some(limit)=(u32::MAX as u64).checked_sub(kg) else{return fail(capture);};
        if start>limit {return fail(capture);}
        #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture.as_deref_mut() {c.header.eps_e=eps*0.5;c.header.eps_i=eps*0.5;c.header.iid_p=p;c.header.query_now_ns=self.base_now_ns;}
        let mut r=start;
        for i in 0..BASE_ITER_LIMIT {
            let e=r.saturating_sub(rs);
            let Some(n)=uc.checked_add(e) else{return fail(capture);};
            if n>u32::MAX as u64 {return fail(capture);}
            let (empirical,scale,samples)=self.span.tail_losses_now_details(n,eps*0.5,self.base_now_ns,self.tracker.cfg.window_ns);
            let iid=if p<=0.9 {iid_count_quantile(n,p,eps*0.5)}else if n<=EXACT_MAX_K {
                // Use the success-count complement: loss-PMF initialization underflows
                // near p=1. Do not inherit the baseline model's artificial p<=.9 clip.
                let(mut lo,mut hi)=(0,n);
                while lo<hi {let mid=(lo+hi)/2;if 1.0-binomial_tail(n,1.0-p,n-mid)<=eps*0.5 {hi=mid;}else{lo=mid+1;}}
                lo
            }else{
                let z=z_for_eps(eps*0.5);
                (n as f64*p+z*(n as f64*p*(1.0-p)).sqrt()+((z*z-1.0)*(1.0-2.0*p)/6.0).max(0.0)).ceil().min(n as f64) as u64
            };
            let selected=empirical.unwrap_or(0).max(iid).min(n);
            let Some(exposure)=ug.checked_add(e) else{return fail(capture);};
            let speculative=exposure.min(selected).saturating_add(rank);
            let Some(want)=d.checked_add(speculative) else{return fail(capture);};
            let next=r.max(want);
            #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture.as_deref_mut() {
                if i<crate::budget_diagnostic::DEMAND_ITERATION_LIMIT && next<=limit {
                    c.iterations[i]=crate::budget_diagnostic::DemandIteration {r,e,n,samples,empirical:empirical.unwrap_or(0),iid,selected,next_r:next as u32,scale,flags:u16::from(empirical.is_some())|if next==r {2}else{0}};
                    c.header.iterations_count=(i+1)as u8;c.header.result_r=next as u32;
                }else{c.header.flags|=16;}
            }
            if next>limit {return fail(capture);}
            if next==r {return(r,false);}
            r=next;
        }
        // A 100%-loss tail has no finite fixed point. Refuse speculative growth explicitly;
        // do not interpret iteration exhaustion as permission to allocate the index ceiling.
        fail(capture)
    }
    fn budget_tail_impl(&self,kg:u64,start:u64,d:u64,rs:u64,ug:u64,eps_e:f64,eps_i:f64,uc:u64,
        mut capture:Option<&mut DemandCapture>)->(u64,bool) {
        #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture.as_deref_mut() {
            let h=&mut c.header;h.adaptive_generation=self.data_generation;h.adaptive_created_ns=self.diagnostic_created_ns;h.ns=self.base_now_ns;h.query_now_ns=self.base_now_ns;h.s=self.span.sent_total;h.f=self.span.seen;
            h.eps_e=eps_e;h.eps_i=eps_i;h.iid_p=if self.span.seen<4096 {self.tracker.cfg.initial_loss}else{self.tracker.cfg.min_loss};
        }
        let mut r=start.min(kg);
        for _iteration in 0..BASE_ITER_LIMIT {
            let e=r.saturating_sub(rs);
            let n=uc.saturating_add(e);
            let(selected,_empirical,_iid,_scale,_samples)=self.budget_count_details(n,eps_e,eps_i);
            let future=ug.saturating_add(e).min(selected);
            let want=r.max(d.saturating_add(2).saturating_add(future));
            let next=want.min(kg);
            #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture.as_deref_mut() {
                if _iteration<crate::budget_diagnostic::DEMAND_ITERATION_LIMIT && next<=u32::MAX as u64 {
                    c.iterations[_iteration]=crate::budget_diagnostic::DemandIteration {r,e,n,samples:_samples,empirical:_empirical.unwrap_or(0),iid:_iid,selected,next_r:next as u32,scale:_scale,
                        flags:u16::from(_empirical.is_some())|if next==r {2}else{0}|if want>kg {4}else{0}|if _iteration+1==BASE_ITER_LIMIT&&next!=r {8}else{0}};
                    c.header.iterations_count=(_iteration+1)as u8;
                } else {c.header.flags|=16;}
                c.header.result_r=next.min(u32::MAX as u64)as u32;
                c.header.flags=(c.header.flags&!4)|if want>kg {4}else{0};
            }
            if next==r {return(r,want>kg);}
            r=next;
        }
        #[cfg(feature="research_budget_diagnostic")]
        if let Some(c)=capture {c.header.result_r=kg.min(u32::MAX as u64)as u32;c.header.flags|=8|16;}
        (kg,true)
    }
    /// Returns cached query terms from ONE traversal, with the raw empirical Option preserved.
    fn budget_count_details(&self,n:u64,eps_e:f64,eps_i:f64)->(u64,Option<u64>,u64,u16,u64) {
        if n==0 {return(0,None,0,0,0);}
        let c=&self.tracker.cfg;
        let prior=if self.span.seen<4096 {c.initial_loss}else{c.min_loss};
        let(empirical,scale,samples)=self.span.tail_losses_now_details(n,eps_e,self.base_now_ns,c.window_ns);
        let iid=iid_count_quantile(n,prior,eps_i);
        (empirical.unwrap_or(0).max(iid).min(n),empirical,iid,scale,samples)
    }
    #[cfg(test)]
    fn budget_count_quantile(&self,n:u64,eps:f64)->u64 {self.budget_count_details(n,if self.empirical_tail_active() {eps*10.0}else{eps},eps).0}
    /// Connection context, refreshed every send loop from the ACTUAL allowed pacing rate (micro-packets
    /// per second) and the CURRENT loss timeout. H = ceil(rate * timeout / 1e15) packets; an unknown
    /// timeout (no RTT sample) or H == 0 leaves H unknown, and plans then assume the cold prior h = Kg.
    pub fn set_base_context(&mut self, now_ns: u64, rate_upps: u64, timeout_ns: Option<u64>) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        self.base_horizon = timeout_ns.map(|t| (rate_upps as u128 * t as u128).div_ceil(1_000_000_000_000_000).min(u64::MAX as u128) as u64)
            .filter(|&h| h > 0);
    }
    pub fn base_horizon(&self) -> Option<u64> { self.base_horizon }
    /// Q(n, eps): loss COUNT not exceeded with probability 1-eps among n DATA packets: the larger of the
    /// NOW-expired empirical contiguous-span tail and the IID prior count quantile, clamped to 0..=n.
    pub fn base_count_quantile(&self, n: u64, eps: f64) -> u64 {
        if n == 0 { return 0; }
        let c = &self.tracker.cfg;
        let prior = if self.span.seen < 4096 { c.initial_loss } else { c.min_loss };
        let empirical = self.span.tail_losses_now(n, eps, self.base_now_ns, c.window_ns).unwrap_or(0);
        empirical.max(iid_count_quantile(n, prior, eps)).min(n)
    }
    /// Immutable initial base b for a codec of kg sources: least fixed point of
    /// b = min(kg, max(b, 2 + Q(h + b))) from min(2, kg), h = min(kg, H) (h = kg while H is unknown).
    /// Returns (b, cap_bound): cap_bound = the uncapped requirement exceeded kg (target infeasible),
    /// or the iteration budget ran out and the safe cap kg was used.
    pub fn base_initial_repairs(&self, kg: u64, eps: f64) -> (u64, bool) {
        let h = self.base_horizon.map_or(kg, |h| h.min(kg));
        let mut b = 2.min(kg);
        for _ in 0..BASE_ITER_LIMIT {
            let want = b.max(2u64.saturating_add(self.base_count_quantile(h.saturating_add(b), eps)));
            let next = want.min(kg);
            if next == b { return (b, want > kg); }
            b = next;
        }
        (kg, true)
    }
    /// Tail total repairs R for one codec once its sources are all sent: least fixed point above
    /// start of R = min(kg, max(R, d + 2 + min(ug + E, Q(uc + E)))), E = R - rs (planned unsent repairs),
    /// d = own finalized losses (coefficient 1), ug = own unresolved symbols, uc = connection-wide
    /// unresolved DATA (all queues/segments, not divided). Nondecreasing; budget exhaustion => kg.
    pub fn base_tail_repairs(&self, kg: u64, start: u64, d: u64, rs: u64, ug: u64, eps: f64) -> (u64, bool) {
        let uc = self.span.unresolved_data_packets();
        let mut r = start.min(kg);
        for _ in 0..BASE_ITER_LIMIT {
            let e = r.saturating_sub(rs);
            let future = ug.saturating_add(e).min(self.base_count_quantile(uc.saturating_add(e), eps));
            let want = r.max(d.saturating_add(2).saturating_add(future));
            let next = want.min(kg);
            if next == r { return (r, want > kg); }
            r = next;
        }
        (kg, true)
    }
    /// Redundancy (ppm) of a ~1000-block message, for the send queue's byte capacity.
    pub fn representative_ppm(&self) -> u32 {
        (self.repair_blocks(1000) * 1000).clamp(1, 1_000_000) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ln P(L >= m) for L ~ Binomial(n, p), exact (log-space recurrence over the tail).
    fn ln_tail(n: u64, p: f64, m: u64) -> f64 {
        if m == 0 { return 0.0; }
        if m > n { return f64::NEG_INFINITY; }
        // ln pmf(m) via ln-factorials by summation (n <= ~1e5 is fine in a test).
        let lnfact = |x: u64| (1..=x).map(|i| (i as f64).ln()).sum::<f64>();
        let mut lp = lnfact(n) - lnfact(m) - lnfact(n - m) + m as f64 * p.ln() + (n - m) as f64 * (1.0 - p).ln();
        let mut acc = lp; // running log-sum-exp
        let r = (p / (1.0 - p)).ln();
        for j in m..n {
            lp += ((n - j) as f64 / (j + 1) as f64).ln() + r;
            if lp < acc - 40.0 { break; }
            acc = acc.max(lp) + (1.0 + (-(acc - lp).abs()).exp()).ln();
        }
        acc
    }
    /// P(fewer than k of n arrive) = P(L >= n-k+1).
    fn fail_prob(k: u64, n: u64, p: f64) -> f64 { ln_tail(n, p, n - k + 1).exp() }
    fn exact_min_n(k: u64, p: f64, eps: f64) -> u64 {
        let mut n = k;
        while fail_prob(k, n, p) > eps { n += 1; }
        n
    }

    #[test]
    fn research_selector_validates_before_network_start() {
        assert_eq!(RepairPolicy::parse(None).unwrap(), RepairPolicy::MessageBound);
        assert_eq!(RepairPolicy::selected(), RepairPolicy::MessageBound);
        assert_eq!(FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0).policy, RepairPolicy::MessageBound);
        assert_eq!(RepairPolicy::parse(Some("P0")).unwrap(), RepairPolicy::Reliability);
        for value in ["P0", "P1", "P2", "P3", "P4"] { assert!(RepairPolicy::parse(Some(value)).is_ok()); }
        assert!(RepairPolicy::parse(Some("typo")).unwrap_err().contains("expected P0"));
        assert_eq!(parse_medium_bonus(None, RepairPolicy::MessageBound).unwrap(), 0);
        assert_eq!(parse_medium_bonus(Some("10"), RepairPolicy::MessageBound).unwrap(), 10);
        assert_eq!(parse_medium_bonus(Some("100"), RepairPolicy::MessageBound).unwrap(), 100);
        for bad in ["101", "-1", "1.0", "typo", ""] {
            assert_eq!(parse_medium_bonus(Some(bad), RepairPolicy::MessageBound).unwrap_err(),
                "STP_P4_MEDIUM_BONUS_PERCENT must be an integer 0..=100");
        }
        assert_eq!(parse_medium_bonus(Some("10"), RepairPolicy::Streaming).unwrap_err(), "STP_P4_MEDIUM_BONUS_PERCENT applies only to P4");
    }

    #[test]
    fn mean_policy_is_a_mean_not_a_max_hold_or_tail() {
        let cfg = AdaptiveFecConfig { min_packets: 100, ..Default::default() };
        let mut t = LossTracker::new(cfg, 0);
        t.on_sample(1, 100, 2);
        t.on_sample(2, 100, 10);
        assert!((t.mean - 0.03).abs() < 1e-9);
        t.on_sample(3, 100, 2);
        assert!(t.mean < 0.03);
        assert!((t.estimate() - 14.0 / 300.0).abs() < 1e-9);
        assert_eq!(mean_repairs(1000, 0.02), 23);
        for k in [0, 1, 2, 12, 1000, u32::MAX as u64] {
            assert!(mean_repairs(k, 0.9) <= k);
        }
    }

    #[test]
    fn z_matches_known_values() {
        assert!((z_for_eps(0.025) - 1.95996).abs() < 2e-3);
        assert!((z_for_eps(1e-6) - 4.75342).abs() < 2e-3);
        assert!((z_for_eps(1e-9) - 5.99781).abs() < 2e-3);
    }

    #[test]
    fn formula_vs_exact_binomial() {
        let eps = 1e-6;
        let z = z_for_eps(eps);
        for &k in &[2u64, 10, 100, 1000, 5500, 36000] {
            for &p in &[0.005, 0.02, 0.05] {
                let n_exact = exact_min_n(k, p, eps);
                let n = k + formula_repair_blocks(k, p, z);
                let f = fail_prob(k, n, p);
                let n2 = k + min_repair_blocks(k, p, z, eps);
                if k <= EXACT_MAX_K { assert_eq!(n2, n_exact, "exact path K={k} p={p}"); } else { assert_eq!(n2, n); }
                println!("K={k:>6} p={p:<5} exact N={n_exact:>6} ({:.2}%) approx N={n:>6} ({:.2}%) fail={f:.2e}", 100.0 * (n_exact - k) as f64 / k as f64, 100.0 * (n - k) as f64 / k as f64);
                // Never meaningfully worse than eps, never more than 3 blocks + 1% above the exact minimum.
                assert!(f <= 3.0 * eps, "K={k} p={p}: fail {f:e}");
                assert!(n <= n_exact + 3 + n_exact / 100, "K={k} p={p}: N {n} vs exact {n_exact}");
            }
        }
    }

    #[test]
    fn small_k_gets_proportionally_more() {
        let z = z_for_eps(1e-6);
        let r = |k: u64| repair_blocks(k, 0.02, z, 1e-6, 1, 1.0) as f64 / k as f64;
        assert!(r(10) > r(100) && r(100) > r(1000) && r(1000) > r(36000));
        assert!(r(36000) > 0.02);
        assert_eq!(repair_blocks(2, 0.5, z, 1e-6, 1, 1.0), 2); // capped at 100%
    }

    #[test]
    fn finalized_loss_burst_dilutes_instead_of_ten_minute_max_hold() {
        let cfg = AdaptiveFecConfig::default();
        let mut t = LossTracker::new(cfg, 0);
        // Reference reproduces the previous max-over-slots algorithm, but receives
        // correctly matched cohorts too, isolating retention from the population bug.
        let mut old = [(u64::MAX, 0.0f64); 16];
        let mut old_recovery = None;
        let mut new_recovery = None;
        let mut mean_recovery = None;
        for second in 1..=600u64 {
            let lost = if second == 1 { 500 } else { 0 };
            let now = second * 1_000_000_000;
            t.on_tick(now, 1000, lost);
            let idx = now / cfg.slot_ns;
            let s = &mut old[idx as usize % cfg.slots];
            if s.0 != idx { *s = (idx, 0.0); }
            s.1 = s.1.max(lost as f64 / 1000.0);
            let max_hold = old.iter().filter(|s| s.0 != u64::MAX && s.0 + cfg.slots as u64 > idx)
                .map(|s| s.1).fold(0.0, f64::max);
            if max_hold <= 0.01 && old_recovery.is_none() { old_recovery = Some(second - 1); }
            if t.estimate() <= 0.01 && new_recovery.is_none() { new_recovery = Some(second - 1); }
            if t.mean <= 0.01 && mean_recovery.is_none() { mean_recovery = Some(second - 1); }
            if second < 600 {
                assert!((max_hold - 0.5).abs() < 1e-9);
                assert!((t.estimate() - 0.5 / second as f64).abs() < 1e-9);
            }
        }
        assert_eq!(old_recovery, Some(599));
        assert_eq!(new_recovery, Some(49));
        assert_eq!(mean_recovery, Some(30));
        assert_eq!(t.estimate(), 0.0);
        println!("50% loss for 1s then clean 1000 finalized DATA/s: p>1% duration after burst old_max=599s pooled=49s research_EWMA=30s; old stays 50% until expiry, pooled halves after 1s");
    }

    #[test]
    fn finalized_loss_weights_packets_and_expires_without_new_traffic() {
        let cfg = AdaptiveFecConfig::default();
        let mut t = LossTracker::new(cfg, 0);
        t.on_tick(1_000_000_000, 1000, 500);
        t.on_tick(2_000_000_000, 10000, 0);
        assert!((t.estimate() - 500.0 / 11000.0).abs() < 1e-9);
        t.on_tick(600_000_000_000, 0, 0);
        assert_eq!(t.estimate(), 0.0);
        // A real all-lost small cohort remains bounded and is diluted by clean finalizations.
        let mut t = LossTracker::new(cfg, 0);
        t.on_tick(1_000_000_000, 125, 125);
        assert_eq!(t.estimate(), 1.0);
        t.on_tick(2_000_000_000, 500, 0);
        assert_eq!(t.estimate(), 0.2);
    }

    #[test]
    fn finalized_loss_delayed_burst_uses_one_data_population() {
        for policy in [RepairPolicy::Reliability, RepairPolicy::Streaming] {
            let mut a = FecAdaptiveState::baseline_for_test(Default::default(), 0);
            a.policy = policy;
            // Send 1000 DATA plus interleaved controls, then stop sending. No outcomes yet.
            for seq in 0..1000 { a.on_data_sent(2 * seq); }
            a.on_tick(1_000_000_000);
            assert_eq!(a.tracker.estimate(), crate::ship::FEC.initial_loss);
            // One delayed retirement batch: 20% lost, despite zero new sends this tick.
            // The old lost/sent drought branch would sample min(200/1, 1) = 100%.
            for seq in 0..1000 {
                a.on_sequence_finalized(2 * seq, seq < 200, 2_000_000_000);
                a.on_sequence_finalized(2 * seq + 1, true, 2_000_000_000);
                // Duplicate retirement / late ACK cannot add a second outcome or credit another loss.
                a.on_sequence_finalized(2 * seq, false, 2_100_000_000);
            }
            a.on_tick(3_000_000_000);
            assert_eq!(a.span.seen, 1000);
            assert_eq!(a.span.lost_total, 200);
            assert!((a.tracker.last_sample() - 0.2).abs() < 1e-9);
            assert!((a.p - 0.2).abs() < 1e-7, "{}", a.p);
        }
    }

    #[test]
    fn finalized_loss_steady_one_percent() {
        let mut a = FecAdaptiveState::baseline_for_test(Default::default(), 0);
        for second in 1..=120 {
            for i in 0..1000 {
                let seq = (second - 1) * 1000 + i;
                a.on_data_sent(seq);
                a.on_sequence_finalized(seq, i % 100 == 0, second * 1_000_000_000);
            }
            a.on_tick(second * 1_000_000_000);
            assert!((a.p - 0.01).abs() < 1e-7, "second={second} p={}", a.p);
        }
    }

    #[test]
    fn span_profile_sliding_counts_match_reference() {
        let mut s = SpanLossProfile::default();
        let mut bits = Vec::new();
        let mut rng = 4321u64;
        for i in 0..140000usize {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            let lost = rng % 100 < 3;
            bits.push(lost);
            s.on_outcome(lost, i as u64 * 10000, 600_000_000_000);
            if i % 997 == 0 {
                for scale in 0..16 {
                    let n = 2usize << scale;
                    let begin = (i + 1).saturating_sub(n);
                    let expected = bits[begin..=i].iter().filter(|x| **x).count();
                    assert_eq!(s.counts[scale] as usize, expected, "packet {i} span {n}");
                }
            }
        }
        for x in 0..=65536u32 { assert!(SpanLossProfile::upper(SpanLossProfile::bin(x)) >= x as u64); }
    }

    #[test]
    fn finer_span_bins_are_upward_only_at_every_count_and_keep_quantile_rank() {
        let mut previous = 0;
        for losses in 0..=65536u32 {
            let bin = SpanLossProfile::bin(losses);
            assert!(bin < SPAN_LOSS_BINS);
            let upper = SpanLossProfile::upper(bin);
            assert!(upper >= losses as u64);
            assert!(upper >= previous);
            assert!(upper - losses as u64 <= (losses as u64).div_ceil(16));
            previous = upper;
        }
        assert_eq!(SpanLossProfile::upper(SpanLossProfile::bin(286)), 288);
        assert_eq!(SpanLossProfile::upper(SpanLossProfile::bin(331)), 336);
        let mut span = SpanLossProfile::default();
        span.epochs[0] = 0;
        span.hist[0][9][SpanLossProfile::bin(286)] = 100;
        span.hist[0][9][SpanLossProfile::bin(331)] = 1;
        // Horizon 513..1024 selects the same 1024-symbol empirical samples;
        // only count-rounding slack changes, never the selected tail rank.
        assert_eq!(span.tail_losses(700, 0.001), Some(336));
        assert_eq!(span.tail_losses(700, 0.02), Some(288));
    }

    #[test]
    fn span_tail_sees_bursts_and_excludes_non_data() {
        let mut s = SpanLossProfile::default();
        for i in 0..20000u64 {
            // Same 1% mean, but packets 0..9 of each 1000 are consecutive losses.
            s.on_data_sent(2*i);
            s.on_sequence_finalized(2*i, i % 1000 < 10, i * 10000, 600_000_000_000);
            s.on_sequence_finalized(2*i+1, true, i * 10000, 600_000_000_000);
        }
        assert_eq!(s.seen, 20000);
        assert_eq!(s.lost_total, 200);
        assert!(s.tail_losses(32, 0.001).unwrap() >= 10);
        let cfg = AdaptiveFecConfig { eps: 0.001, ..Default::default() };
        assert!(s.repair_blocks(32, &cfg, z_for_eps(cfg.eps)) >= 11);
        assert!(s.target_failure(32768, &cfg) < s.target_failure(32, &cfg));
        assert!(std::mem::size_of::<SpanLossProfile>() < 96 * 1024);
    }

    #[test]
    fn rescue_latency_budget_ignores_rare_loss_blips() {
        // This regression exercises P0 retention/reliability, not the shipped P4 lifecycle.
        let mut a = FecAdaptiveState::reliability_for_test(crate::ship::FEC, 0);
        // Six isolated losses in 100,000 packets must not set a reliability-scale tail.
        for base in (0..100000).step_by(20) {
            for seq in base..base+20 { a.on_data_sent(seq); }
            for seq in base..base+20 {
                a.on_sequence_finalized(seq, seq < 6 * 15000 && seq % 15000 == 0, seq * 1000);
            }
        }
        let r = a.repair_blocks_for_group_at_tail(12, 12, 1, false);
        assert!(r <= 2, "rare-blip initial margin {r}");
        let topup = a.extra_repair_blocks_needed_for_group_at_tail(12, 12, 1, 12, 0, 0, false);
        assert!(topup <= 2, "rare-blip top-up margin {topup}");
        // Without retained rescue, retain the full 12-symbol protection contract.
        assert_eq!(a.repair_blocks_for_group_at_tail(12, 12, 1, true), 12);
    }

    #[test]
    fn interior_margin_keeps_loss_risk_without_absolute_burst_floor() {
        // This regression exercises P0 retention/reliability, not the shipped P4 lifecycle.
        let mut a = FecAdaptiveState::reliability_for_test(crate::ship::FEC, 0);
        for seq in 0..10000 {
            a.on_data_sent(seq);
            a.on_sequence_finalized(seq, false, seq * 1000);
        }
        let r = a.repair_blocks_for_group_at_tail(12, 12, 1, false);
        assert!((1..=5).contains(&r), "clean interior {r}");
        assert_eq!(a.repair_blocks_for_group_at_tail(12, 12, 1, true), 12);
        assert!(a.extra_repair_blocks_needed_for_group_at_tail(12, 12, 1, 12, 0, 0, false) <= 5);
        // Frequent learned 10-packet clusters exceed the 2% latency-tail budget.
        for base in (10000..20000).step_by(100) {
            for seq in base..base+100 { a.on_data_sent(seq); }
            for seq in base..base+100 {
                a.on_sequence_finalized(seq, seq % 100 < 10, seq * 1000);
            }
        }
        let clustered = a.repair_blocks_for_group_at_tail(12, 12, 1, false);
        assert!(clustered >= 11, "clustered {clustered}");
    }

    #[test]
    fn real_span_floor_is_capped_at_source_count() {
        let s = SpanLossProfile::default();
        for k in [2, 12, 64, 740, 36613] {
            let r = s.repair_blocks(k, &crate::ship::FEC, 0.0);
            assert!(r >= 12.min(k) && r <= k);
        }
    }

    #[test]
    fn span_closed_loop_counts_pending_and_budgets_only_tail() {
        // This regression exercises P0 retention/reliability, not the shipped P4 lifecycle.
        let cfg = AdaptiveFecConfig { eps: 0.5, ..Default::default() };
        let mut a = FecAdaptiveState::reliability_for_test(cfg, 0);
        for seq in 0..10000 {
            a.on_data_sent(seq * 2);
            a.on_sequence_finalized(seq * 2, seq % 10000 == 3, seq * 1000);
            // ACK-only sequence and duplicate retirement must not decrement pending twice.
            a.on_sequence_finalized(seq * 2 + 1, true, seq * 1000);
            a.on_sequence_finalized(seq * 2, false, seq * 1000);
        }
        for seq in 20000..20100 { a.on_data_sent(seq); }
        assert_eq!(a.span.as_ref().unresolved_data_packets(), 100);
        let k = 36613;
        let closed = a.extra_repair_blocks_needed_now(k, k, 0, 80);
        assert!(closed >= 92 && closed < 150, "{closed}");
        let already = a.extra_repair_blocks_needed_now(k, k+closed, closed, 80);
        assert_eq!(already, 0);
        let short = a.extra_repair_blocks_needed_now(64, 64, 0, 0);
        assert!(short >= 12 && short <= 64);
        assert_eq!(a.extra_repair_blocks_needed_now(k, k, 0, k*2), k);
        let initial = a.repair_blocks(k);
        assert!(initial < 30, "tail initial {initial}");
        let limited = FecAdaptiveState::reliability_for_test(AdaptiveFecConfig { max_redundancy: 0.01, ..cfg }, 0);
        assert_eq!(limited.repair_blocks(740), 8);
        assert_eq!(limited.extra_repair_blocks_needed_now(740, 740, 0, 80), 8);
    }

    #[test]
    fn span_histograms_expire_by_time_not_packet_rate() {
        let mut s = SpanLossProfile::default();
        for i in 0..1000 { s.on_outcome(i < 10, 0, 200); }
        assert!(s.tail_losses(32, 1e-3).unwrap() >= 10);
        // Retained history must also drain; after a two-half-window gap both old histograms expire.
        for _ in 0..65536 { s.on_outcome(false, 300, 200); }
        assert_eq!(s.tail_losses(32, 1e-3), Some(0));
    }

    #[test]
    fn event_repair_env_values_and_required_baseline_settings() {
        let p4 = RepairPolicy::MessageBound;
        assert_eq!(parse_event_repair(None, p4, 1, false, 0), Ok(0));
        for (v, q) in [("0", 0), ("5", 5), ("10", 10)] { assert_eq!(parse_event_repair(Some(v), p4, 1, false, 0), Ok(q)); }
        for bad in ["", "2", "4", "05", "10%", " 5", "-5"] { assert!(parse_event_repair(Some(bad), p4, 1, false, 0).is_err(), "{bad}"); }
        assert!(parse_event_repair(Some("5"), p4, 2, false, 0).is_err());
        assert!(parse_event_repair(Some("5"), p4, 1, true, 0).is_err());
        assert!(parse_event_repair(Some("10"), p4, 1, false, 10).is_err());
        assert!(parse_event_repair(Some("5"), RepairPolicy::Streaming, 1, false, 0).is_err());
        assert_eq!(parse_event_repair(Some("0"), RepairPolicy::Streaming, 2, true, 10), Ok(0));
    }
    #[test]
    #[ignore = "microbenchmark; run release with --ignored --nocapture"]
    fn span_cost_per_packet() {
        let mut s = SpanLossProfile::default();
        let n = 5_000_000u64;
        let now = std::time::Instant::now();
        for i in 0..n {
            s.on_data_sent(i);
            s.on_sequence_finalized(i, i % 10000 < 3, i * 1000, 600_000_000_000);
            std::hint::black_box(&s);
        }
        println!("span_profile_bytes={} packet_update_ns={:.2}", std::mem::size_of::<SpanLossProfile>(), now.elapsed().as_nanos() as f64 / n as f64);
        let cfg = AdaptiveFecConfig { eps: 0.001, ..Default::default() };
        let now = std::time::Instant::now();
        for i in 0..100000 { std::hint::black_box(s.repair_blocks(2 + i % 63000, &cfg, 3.09)); }
        println!("repair_query_ns={:.2}", now.elapsed().as_nanos() as f64 / 100000.0);
        let cfg = AdaptiveFecConfig { eps: 0.5, ..Default::default() };
        let mut a = FecAdaptiveState::baseline_for_test(cfg, 0);
        for i in n..n+1000 { s.on_data_sent(i); }
        a.span = Box::new(s);
        let now = std::time::Instant::now();
        for _ in 0..100000 { std::hint::black_box(a.extra_repair_blocks_needed_now(36613, 36613, 0, 20)); }
        println!("closed_loop_query_ns={:.2}", now.elapsed().as_nanos() as f64 / 100000.0);
    }
}

// ---- p4-burst-base (RESEARCH) ----
#[cfg(test)]
mod burst_base_tests {
    use super::*;
    const W: u64 = 600_000_000_000; // ship::FEC window_ns

    fn b1() -> FecAdaptiveState {
        let mut a = FecAdaptiveState::baseline_for_test(crate::ship::FEC, 1);
        a.policy = RepairPolicy::MessageBound;
        a.set_base_parity_for_test(true);
        a
    }
    /// Feed a finalized DATA trace; `lost(i)` decides each packet.
    fn feed(a: &mut FecAdaptiveState, first: u64, count: u64, now: u64, lost: impl Fn(u64) -> bool) {
        for s in first..first + count { a.on_data_sent(s); a.on_sequence_finalized(s, lost(s), now); }
    }

    #[test]
    fn window_constant_matches_shipped_config() { assert_eq!(crate::ship::FEC.window_ns, W); }

    #[test]
    fn iid_count_quantile_is_exact_minimum_for_small_n() {
        assert_eq!(iid_count_quantile(0, 0.01, 1e-3), 0, "Q(0, e) = 0");
        for n in 1..=EXACT_MAX_K {
            for p in [0.005, 0.01, 0.1, 0.5] {
                for eps in [1e-3, 1e-3 / 7.0, 1e-6] {
                    let q = iid_count_quantile(n, p, eps);
                    assert!(q <= n);
                    assert!(binomial_tail(n, p, q + 1) <= eps, "n={n} p={p} eps={eps} q={q}");
                    assert!(q == 0 || binomial_tail(n, p, q) > eps, "not minimal: n={n} p={p} eps={eps} q={q}");
                }
            }
        }
        assert_eq!(iid_count_quantile(1, 0.01, 1e-3), 1);
        assert_eq!(iid_count_quantile(10, 0.01, 1e-3), 2); // P(>1)=0.0043, P(>2)=1.1e-4
    }

    #[test]
    fn iid_count_quantile_large_n_cornish_fisher_and_clamp() {
        // np=100, sd=9.9499, z(1e-3)=3.0902: 100 + 30.748 + (9.549-1)(0.98)/6 = 132.14 -> 133.
        assert_eq!(iid_count_quantile(10_000, 0.01, 1e-3), 133);
        let mut last = 0;
        for n in [129u64, 200, 1000, 4096, 65536, 1 << 30] {
            let q = iid_count_quantile(n, 0.01, 1e-3);
            assert!(q >= last && q <= n); last = q;
        }
        assert_eq!(iid_count_quantile(129, 0.9, 1e-12), 129, "clamped to n");
        assert_eq!(iid_count_quantile(129, 1e-12, 0.5), 0, "clamped to 0");
        // Continuity at the exact/approximate seam stays within a couple of packets.
        let (e, c) = (iid_count_quantile(128, 0.01, 1e-3), iid_count_quantile(129, 0.01, 1e-3));
        assert!(c + 2 >= e && c <= e + 2, "{e} {c}");
    }

    #[test]
    fn count_quantile_cold_uses_initial_prior_and_zero_is_zero() {
        let a = b1();
        assert_eq!(a.base_count_quantile(0, 1e-3), 0);
        for n in [1u64, 5, 64, 500, 5000] {
            assert_eq!(a.base_count_quantile(n, 1e-3), iid_count_quantile(n, a.tracker.cfg.initial_loss, 1e-3), "n={n}");
        }
    }

    #[test]
    fn periodic_isolated_vs_time_dense_clusters_same_average() {
        // Both traces lose exactly 1% of 65536 packets.
        let mut periodic = b1();
        feed(&mut periodic, 0, 65536, 1, |s| s % 100 == 0);
        let mut clustered = b1();
        feed(&mut clustered, 0, 65536, 1, |s| s % 3200 < 32);
        assert_eq!((periodic.span.lost_total, clustered.span.lost_total), (656, 672), "both ~1.0%");
        let prior = crate::ship::FEC.min_loss;
        for n in [16u64, 64, 256] {
            let (p, c) = (periodic.base_count_quantile(n, 1e-3), clustered.base_count_quantile(n, 1e-3));
            let emp = periodic.span.tail_losses_now(n, 1e-3, 1, W).unwrap();
            assert!(emp <= n.div_ceil(100), "n={n} periodic span count {emp}");
            assert_eq!(p, emp.max(iid_count_quantile(n, prior, 1e-3)), "n={n}");
            assert!(c >= 16.min(n) && c > p, "n={n}: clustered tail sees the burst, got {c} vs periodic {p}");
        }
    }

    #[test]
    fn empirical_tail_expires_relative_to_now_but_b0_query_unchanged() {
        let mut a = b1();
        feed(&mut a, 0, 65536, 1, |s| s % 3200 < 32);
        let burst = a.base_count_quantile(64, 1e-3);
        assert!(burst >= 32);
        // Quiet for over a full window: the B0 query still keys off the newest observation epoch...
        a.set_base_context(1 + W + W / 2 + 1, 0, None);
        assert!(a.span.tail_losses(64, 1e-3).unwrap() >= 32, "B0/P0 query untouched");
        // ...while B1 expires it by NOW back to the prior.
        assert_eq!(a.base_count_quantile(64, 1e-3), iid_count_quantile(64, a.tracker.cfg.min_loss, 1e-3));
        // Within the previous half-window it is still live.
        let mut b = b1();
        feed(&mut b, 0, 65536, 1, |s| s % 3200 < 32);
        b.set_base_context(W / 2 + 5, 0, None);
        assert_eq!(b.base_count_quantile(64, 1e-3), burst);
    }

    #[test]
    fn horizon_from_rate_and_timeout_overflow_safe() {
        let mut a = b1();
        assert_eq!(a.base_horizon(), None);
        a.set_base_context(0, 1_000 * 1_000_000, Some(200_000_000)); // 1000 pps x 0.2 s
        assert_eq!(a.base_horizon(), Some(200));
        a.set_base_context(0, 1_000 * 1_000_000, Some(200_000_001));
        assert_eq!(a.base_horizon(), Some(201), "ceil");
        a.set_base_context(0, 0, Some(1));
        assert_eq!(a.base_horizon(), None, "H == 0 is unknown");
        a.set_base_context(0, u64::MAX, Some(u64::MAX));
        assert_eq!(a.base_horizon(), Some((u64::MAX as u128 * u64::MAX as u128).div_ceil(1_000_000_000_000_000).min(u64::MAX as u128) as u64));
        a.set_base_context(0, 1_000_000_000_000, None);
        assert_eq!(a.base_horizon(), None);
    }

    #[test]
    fn initial_base_plateaus_at_blind_horizon_not_linear_percent() {
        let mut a = b1();
        let eps = base_group_eps(1);
        // Cold: h = Kg grows with K (but sublinearly).
        let cold: Vec<u64> = [50u64, 200, 1000, 1800].iter().map(|&k| a.base_initial_repairs(k, eps).0).collect();
        assert!(cold.windows(2).all(|w| w[0] <= w[1]) && cold[0] < cold[3], "{cold:?}");
        assert!((cold[3] as f64 / 1800.0) < (cold[0] as f64 / 50.0), "not a fixed percentage: {cold:?}");
        // Known blind horizon H = 100 packets: plateau once K >= H.
        a.set_base_context(1, 500 * 1_000_000, Some(200_000_000));
        assert_eq!(a.base_horizon(), Some(100));
        let warm: Vec<u64> = [50u64, 100, 200, 1000, 1800].iter().map(|&k| a.base_initial_repairs(k, eps).0).collect();
        assert!(warm[0] <= warm[1]);
        assert_eq!(warm[1], warm[2]); assert_eq!(warm[2], warm[3]); assert_eq!(warm[3], warm[4]);
        // Each b is the least fixed point b = 2 + Q(h + b).
        for (&k, &b) in [50u64, 100, 200, 1000, 1800].iter().zip(&warm) {
            let h = k.min(100);
            assert_eq!(b, 2 + a.base_count_quantile(h + b, eps), "k={k}");
            assert!(b == 2 || b - 1 < 2 + a.base_count_quantile(h + b - 1, eps));
        }
        // Higher rate or longer timeout raises H, and the plateau.
        a.set_base_context(1, 5_000 * 1_000_000, Some(200_000_000));
        assert!(a.base_initial_repairs(1800, eps).0 > warm[4]);
        // Smaller eps (more codecs) never lowers b.
        assert!(a.base_initial_repairs(1800, base_group_eps(8)).0 >= a.base_initial_repairs(1800, eps).0);
    }

    #[test]
    fn initial_base_small_k_caps_and_cap_flag() {
        let a = b1();
        let eps = base_group_eps(1);
        assert_eq!(a.base_initial_repairs(1, eps), (1, true));
        assert_eq!(a.base_initial_repairs(2, eps), (2, true));
        let (b, capped) = a.base_initial_repairs(3, eps);
        assert_eq!((b, capped), (3, true), "2 + Q(6) at 1% prior is 3 > ... capped at K");
        let (b, capped) = a.base_initial_repairs(1000, eps);
        assert!(!capped && b < 1000);
        // Heavy history: the cap binds and is flagged.
        let mut h = b1();
        feed(&mut h, 0, 65536, 1, |s| s % 4 != 0);
        assert_eq!(h.base_initial_repairs(10, eps), (10, true));
    }

    #[test]
    fn tail_known_loss_is_one_for_one_and_planned_exposure_counts() {
        let mut a = b1();
        feed(&mut a, 0, 8192, 1, |s| s % 200 == 0);
        for s in 8192..8292 { a.on_data_sent(s); } // uc = 100 unresolved
        let eps = base_group_eps(1);
        let kg = 1000;
        // All planned repairs already sent (E = 0): R = d + 2 + min(ug, Q(uc)).
        let r0 = a.base_tail_repairs(kg, 0, 0, 1000, 40, eps).0;
        assert_eq!(r0, 2 + 40u64.min(a.base_count_quantile(100, eps)));
        for d in [1u64, 5, 17, 100] {
            assert_eq!(a.base_tail_repairs(kg, 0, d, 1000, 40, eps).0, r0 + d, "known loss d={d} replaced 1:1, no double count");
        }
        // Planned-but-unsent repairs E add exposure on the global count (fixed point, not 1:1 double count).
        let r_unsent = a.base_tail_repairs(kg, 0, 5, 0, 40, eps).0;
        let e = r_unsent;
        assert_eq!(r_unsent, 5 + 2 + (40 + e).min(a.base_count_quantile(100 + e, eps)));
        assert!(r_unsent >= r0 + 5);
        // Own exposure caps the global quantile.
        assert_eq!(a.base_tail_repairs(kg, 0, 0, 1000, 0, eps).0, 2);
        // Old R is a lower bound (no refunds) and repeated refresh does not compound.
        assert_eq!(a.base_tail_repairs(kg, 77, 0, 1000, 40, eps).0, 77);
        let mut r = 0;
        for _ in 0..50 { let next = a.base_tail_repairs(kg, r, 5, 3, 40, eps).0; if r != 0 { assert_eq!(next, r); } r = next; }
        // Cap.
        assert_eq!(a.base_tail_repairs(10, 0, 9, 0, 40, eps), (10, true));
        assert_eq!(a.base_tail_repairs(10, 10, 0, 1000, 0, eps), (10, false));
    }

    #[test]
    fn tail_uses_connection_wide_pending_not_divided() {
        let mut a = b1();
        feed(&mut a, 0, 65536, 1, |s| s % 3200 < 32);
        let eps = base_group_eps(2);
        let next = 65536;
        for s in next..next + 10 { a.on_data_sent(s); }
        let small = a.base_tail_repairs(1000, 0, 0, 1000, 200, eps).0;
        // Other queues/segments put 2000 more DATA packets in flight; own ug unchanged.
        for s in next + 10..next + 2010 { a.on_data_sent(s); }
        let big = a.base_tail_repairs(1000, 0, 0, 1000, 200, eps).0;
        assert!(big > small, "{small} {big}");
        assert_eq!(big, 2 + 200u64.min(a.base_count_quantile(2010, eps)));
    }

    #[test]
    fn b0_and_non_p4_are_inactive() {
        let mut a = FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0);
        assert_eq!(research_p4_base_parity_model(), 0);
        assert!(!a.base_parity_active(), "default B0");
        a.set_base_parity_for_test(true);
        for p in [RepairPolicy::Reliability, RepairPolicy::MeanOpen, RepairPolicy::MeanTopup, RepairPolicy::Streaming] {
            a.policy = p; assert!(!a.base_parity_active());
        }
        a.policy = RepairPolicy::MessageBound; assert!(a.base_parity_active());
        assert_eq!(a.repair_blocks_for_group(500, 500, 1), 2, "baseline P4 initial unchanged");
    }

    #[test]
    fn parse_all_combinations() {
        use RepairPolicy::*;
        let bad = "STP_P4_BASE_PARITY_MODEL must be 0 or 1";
        let incompatible = "STP_P4_BASE_PARITY_MODEL requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0";
        for v in ["", " 1", "1 ", "01", "00", "2", "-1", "true", "1.0"] {
            assert_eq!(parse_base_parity_model(Some(v), MessageBound, 1, false, 0, 0), Err(bad.to_string()), "{v:?}");
        }
        for policy in [Reliability, MeanOpen, MeanTopup, Streaming, MessageBound] {
            for width in [1, 2, 4] { for slip in [false, true] { for bonus in [0, 10] { for event in [0, 5, 10] {
                assert_eq!(parse_base_parity_model(None, policy, width, slip, bonus, event), Ok(0));
                assert_eq!(parse_base_parity_model(Some("0"), policy, width, slip, bonus, event), Ok(0));
                let ok = policy == MessageBound && width == 1 && !slip && bonus == 0 && event == 0;
                assert_eq!(parse_base_parity_model(Some("1"), policy, width, slip, bonus, event),
                    if ok { Ok(1) } else { Err(incompatible.to_string()) });
            } } } }
        }
    }

    /// Child half of the subprocess env test: only acts when the parent sets STP_BASE_PROBE.
    #[test]
    fn env_probe_child() {
        if std::env::var("STP_BASE_PROBE").is_err() { return; }
        let r = initialize_research_policy();
        println!("PROBE<{:?}|{}>", r, research_p4_base_parity_model());
    }

    // Legacy policy startup is exercised by the four predecessor-feature full gates.
    // This feature intentionally refuses those non-isolated policies before transport starts.
    #[cfg(feature="research_target_validation")]
    #[ignore = "historical predecessor-feature configuration, not frozen RC defaults"]
    #[test]
    fn env_subprocess_default_valid_bad_and_incompatible() {
        let probe = |vars: &[(&str, &str)]| -> String {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact", "fec_adapt::burst_base_tests::env_probe_child", "--nocapture", "--test-threads=1"]);
            for (k, _) in std::env::vars() { if k.starts_with("STP_") { c.env_remove(k); } }
            c.env("STP_BASE_PROBE", "1");
            for (k, v) in vars { c.env(k, v); }
            let out = String::from_utf8(c.output().unwrap().stdout).unwrap();
            let s = out.find("PROBE<").expect(&out);
            out[s + 6..s + out[s..].find(">\n").unwrap()].to_string()
        };
        let bad = "Err(\"STP_P4_BASE_PARITY_MODEL must be 0 or 1\")|0";
        let inc = "Err(\"STP_P4_BASE_PARITY_MODEL requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0\")|0";
        assert_eq!(probe(&[]), "Ok(())|0");
        assert_eq!(probe(&[("STP_P4_BASE_PARITY_MODEL", "0")]), "Ok(())|0");
        assert_eq!(probe(&[("STP_P4_BASE_PARITY_MODEL", "1")]), "Ok(())|1", "default policy is P4");
        assert_eq!(probe(&[("STP_RACE_POLICY", "P4"), ("STP_P4_BASE_PARITY_MODEL", "1")]), "Ok(())|1");
        for v in ["", "2", " 1", "01", "yes"] { assert_eq!(probe(&[("STP_P4_BASE_PARITY_MODEL", v)]), bad, "{v:?}"); }
        for p in ["P0", "P1", "P2", "P3"] {
            assert_eq!(probe(&[("STP_RACE_POLICY", p), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
            assert_eq!(probe(&[("STP_RACE_POLICY", p), ("STP_P4_BASE_PARITY_MODEL", "0")]), "Ok(())|0");
        }
        assert_eq!(probe(&[("STP_P4_INTERLEAVE_WIDTH", "2"), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
        assert_eq!(probe(&[("STP_P4_INTERLEAVE_WIDTH", "4"), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
        assert_eq!(probe(&[("STP_P4_SLIPSTREAM", "1"), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
        assert_eq!(probe(&[("STP_P4_MEDIUM_BONUS_PERCENT", "10"), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
        assert_eq!(probe(&[("STP_P4_EVENT_REPAIR", "5"), ("STP_P4_BASE_PARITY_MODEL", "1")]), inc);
        assert_eq!(probe(&[("STP_P4_EVENT_REPAIR", "10"), ("STP_P4_BASE_PARITY_MODEL", "0")]), "Ok(())|0");
        assert_eq!(probe(&[("STP_P4_MEDIUM_BONUS_PERCENT", "0"), ("STP_P4_SLIPSTREAM", "0"), ("STP_P4_EVENT_REPAIR", "0"), ("STP_P4_INTERLEAVE_WIDTH", "1"), ("STP_P4_BASE_PARITY_MODEL", "1")]), "Ok(())|1");
        // Earlier variables' errors keep precedence.
        assert_eq!(probe(&[("STP_P4_EVENT_REPAIR", "7"), ("STP_P4_BASE_PARITY_MODEL", "9")]), "Err(\"STP_P4_EVENT_REPAIR must be 0, 5 or 10\")|0");
        #[cfg(unix)] {
            use std::os::unix::ffi::OsStrExt;
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact", "fec_adapt::burst_base_tests::env_probe_child", "--nocapture", "--test-threads=1"]);
            for (k, _) in std::env::vars() { if k.starts_with("STP_") { c.env_remove(k); } }
            c.env("STP_BASE_PROBE", "1").env("STP_P4_BASE_PARITY_MODEL", std::ffi::OsStr::from_bytes(b"\xff"));
            let out = String::from_utf8_lossy(&c.output().unwrap().stdout).to_string();
            assert!(out.contains(&format!("PROBE<{bad}>")), "{out}");
        }
    }
}

#[cfg(test)]
mod budget_base_tests {
    use super::*;
    fn state() -> FecAdaptiveState {
        let mut a = FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0);
        a.policy = RepairPolicy::MessageBound; a.set_budget_base_for_test(true); a
    }
    #[test]
    fn budget_base_floor_boundaries_and_overflow_safe() {
        for (k, r) in [(0,0),(1,0),(6,0),(7,1),(8,1),(13,1),(14,2),(20,3)] {
            assert_eq!(budget_repair_limit(k), r);
        }
        for k in [u64::MAX, u64::MAX - 1, u64::MAX / 15, 64000] {
            let q = budget_repair_limit(k);
            assert!(q as u128 * 100 <= k as u128 * 15);
            assert!((q as u128 + 1) * 100 > k as u128 * 15);
        }
    }
    #[test]
    fn budget_base_parse_contract_and_precedence() {
        let p = RepairPolicy::MessageBound;
        assert_eq!(parse_budget_base(None, p, 1, false, 0, 0, 0), Ok(0));
        assert_eq!(parse_budget_base(Some("1"), p, 1, false, 0, 0, 0), Ok(1));
        assert_eq!(parse_budget_base(Some("0"), RepairPolicy::Streaming, 4, true, 100, 5, 1), Ok(0));
        for v in ["", "2", "01", "-1", " 1", "true"] {
            assert_eq!(parse_budget_base(Some(v), p, 1, false, 0, 0, 0).unwrap_err(), "STP_P4_BUDGET_BASE must be 0 or 1");
        }
        let expected = "STP_P4_BUDGET_BASE requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0";
        for (p,w,ss,b,e,old) in [(RepairPolicy::Streaming,1,false,0,0,0), (p,2,false,0,0,0), (p,1,true,0,0,0), (p,1,false,10,0,0), (p,1,false,0,5,0), (p,1,false,0,0,1)] {
            assert_eq!(parse_budget_base(Some("1"), p,w,ss,b,e,old).unwrap_err(), expected);
        }
    }
    #[test]
    fn budget_base_span_ownership_actual_commits_foreign_intervals_and_reset() {
        let mut a = state();
        for seq in 0..1000 { a.on_data_sent(seq); } // previous sealed prefix, still unresolved
        let anchor = a.data_anchor();
        assert_eq!(a.budget_unresolved_span(Some(anchor), 0), (1, false));
        // Merely preparing/refusing a packet never calls on_data_sent, hence cannot move A/S.
        assert_eq!(a.data_anchor(), anchor);
        for seq in 1000..1010 { a.on_data_sent(seq); } // our message
        for seq in 1010..1100 { a.on_data_sent(seq); } // foreign retained/queue packets inside interval
        assert_eq!(a.budget_unresolved_span(Some(anchor), 10), (101, false));
        for seq in 0..1050 { a.on_sequence_finalized(seq, false, 1); }
        assert_eq!(a.budget_unresolved_span(Some(anchor), 10), (51, false), "ordered F, not own occupancy");
        assert_eq!(a.budget_unresolved_span(Some(anchor), 60), (61, false), "uncommitted/abandoned own build bounded too");
        assert_eq!(a.clone().budget_unresolved_span(Some(anchor), 10), (51, false));
        let fresh = state();
        assert_eq!(fresh.budget_unresolved_span(Some(anchor), 10), (11, true), "caller must use conservative maximum demand on generation mismatch");
    }
    #[test]
    fn budget_base_tail_keeps_future_repairs_and_own_exposure_cap() {
        let a = state();
        let eps = base_group_eps(1);
        let r = a.budget_tail_repairs(1000, 0, 5, 1000, 0, eps, 0).0;
        assert_eq!(r, 7);
        assert_eq!(a.budget_tail_repairs(1000, 0, 6, 1000, 0, eps, 0).0, r + 1);
        let future = a.budget_tail_repairs(1000, 0, 5, 0, 0, eps, 0).0;
        assert!(future > r, "planned future E must enter Q even with no own pending yet");
        assert_eq!(a.budget_tail_repairs(1000, 0, 5, 1000, 0, eps, 1_000_000).0, 7, "own exposure caps foreign loss count");
    }
    #[test]
    fn budget_base_env_child() {
        if std::env::var_os("STP_BUDGET_PROBE").is_none() { return; }
        println!("BUDGET<{:?}|{}>", initialize_research_policy(), research_p4_budget_base());
    }
    // Legacy policy startup is exercised by the four predecessor-feature full gates.
    // This feature intentionally refuses those non-isolated policies before transport starts.
    #[cfg(feature="research_target_validation")]
    #[ignore = "historical predecessor-feature configuration, not frozen RC defaults"]
    #[test]
    fn budget_base_env_subprocess() {
        let probe = |vars: &[(&str, &str)]| {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact", "fec_adapt::budget_base_tests::budget_base_env_child", "--nocapture"]);
            for (k, _) in std::env::vars() { if k.starts_with("STP_") { c.env_remove(k); } }
            c.env("STP_BUDGET_PROBE", "1");
            for (k,v) in vars { c.env(k,v); }
            let out = c.output().unwrap(); assert!(out.status.success());
            String::from_utf8(out.stdout).unwrap()
        };
        assert!(probe(&[]).contains("BUDGET<Ok(())|0>"));
        assert!(probe(&[("STP_P4_BUDGET_BASE","1")]).contains("BUDGET<Ok(())|1>"));
        assert!(probe(&[("STP_P4_BUDGET_BASE","9")]).contains("STP_P4_BUDGET_BASE must be 0 or 1"));
        assert!(probe(&[("STP_P4_BASE_PARITY_MODEL","1"),("STP_P4_BUDGET_BASE","1")]).contains("STP_P4_BASE_PARITY_MODEL=0"));
        assert!(probe(&[("STP_P4_BASE_PARITY_MODEL","9"),("STP_P4_BUDGET_BASE","9")]).contains("STP_P4_BASE_PARITY_MODEL must be 0 or 1"));
        #[cfg(unix)] {
            use std::os::unix::ffi::OsStrExt;
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact", "fec_adapt::budget_base_tests::budget_base_env_child", "--nocapture"]);
            for (k,_) in std::env::vars() { if k.starts_with("STP_") { c.env_remove(k); } }
            c.env("STP_BUDGET_PROBE","1").env("STP_P4_BUDGET_BASE", std::ffi::OsStr::from_bytes(b"\xff"));
            assert!(String::from_utf8_lossy(&c.output().unwrap().stdout).contains("STP_P4_BUDGET_BASE must be 0 or 1"));
        }
    }
}

#[cfg(test)]
mod budget25_tests {
    use super::*;
    #[test]
    fn budget25_floor_boundaries_and_u64_overflow() {
        for (k, l15, l25) in [(0,0,0),(2,0,0),(4,0,1),(8,1,2),(71,10,17),(704,105,176)] {
            assert_eq!(budget_repair_limit_for_cap(k,15), l15);
            assert_eq!(budget_repair_limit_for_cap(k,25), l25);
        }
        for cap in [15,25] { for k in [u64::MAX,u64::MAX-1,u64::MAX/25,u64::MAX/15,64000] {
            let q=budget_repair_limit_for_cap(k,cap) as u128;let n=cap as u128*k as u128;
            assert!(q*100<=n && (q+1)*100>n);
        }}
    }
    #[test]
    fn budget25_env_child() {
        if std::env::var_os("STP_BUDGET25_PROBE").is_none() { return; }
        println!("CAP<{:?}|{}>",initialize_research_policy(),research_p4_repair_cap_percent());
    }
    // Legacy policy startup is exercised by the four predecessor-feature full gates.
    // This feature intentionally refuses those non-isolated policies before transport starts.
    #[cfg(feature="research_target_validation")]
    #[ignore = "historical predecessor-feature configuration, not frozen RC defaults"]
    #[test]
    fn budget25_env_subprocess_feature_gate_and_exact_values() {
        let probe=|vars:&[(&str,&str)]| {
            let mut c=std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact","fec_adapt::budget25_tests::budget25_env_child","--nocapture"]);
            for (k,_) in std::env::vars_os() { if k.to_string_lossy().starts_with("STP_") {c.env_remove(k);} }
            c.env("STP_BUDGET25_PROBE","1");for (k,v) in vars {c.env(k,v);}
            let out=c.output().unwrap();assert!(out.status.success());String::from_utf8(out.stdout).unwrap()
        };
        assert!(probe(&[]).contains("CAP<Ok(())|15>"));
        assert!(probe(&[("STP_P4_REPAIR_CAP_PERCENT","15")]).contains("CAP<Ok(())|15>"));
        for v in ["","0","17","025","15.0"," 25","25 ","-25"] {
            assert!(probe(&[("STP_P4_REPAIR_CAP_PERCENT",v)]).contains("STP_P4_REPAIR_CAP_PERCENT must be 15 or 25"));
        }
        let selected=probe(&[("STP_P4_BUDGET_BASE","1"),("STP_P4_REPAIR_CAP_PERCENT","25")]);
        assert!(selected.contains(if true {"CAP<Ok(())|25>"} else {"requires feature research_budget25"}));
        assert!(probe(&[("STP_P4_REPAIR_CAP_PERCENT","25")]).contains(if true {"STP_P4_BUDGET_BASE=1"} else {"requires feature research_budget25"}));
        let p=RepairPolicy::MessageBound;
        for (p,w,ss,b,e,base,budget) in [(RepairPolicy::Streaming,1,false,0,0,0,1),(p,2,false,0,0,0,1),(p,1,true,0,0,0,1),(p,1,false,1,0,0,1),(p,1,false,0,5,0,1),(p,1,false,0,0,1,1),(p,1,false,0,0,0,0)] {
            assert!(parse_repair_cap_percent(Some("25"),p,w,ss,b,e,base,budget).is_err());
            assert_eq!(parse_repair_cap_percent(Some("15"),p,w,ss,b,e,base,budget),Ok(15));
        }
        #[cfg(unix)] {
            use std::os::unix::ffi::OsStrExt;
            let mut c=std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact","fec_adapt::budget25_tests::budget25_env_child","--nocapture"]);
            for (k,_) in std::env::vars_os() {if k.to_string_lossy().starts_with("STP_"){c.env_remove(k);}}
            c.env("STP_BUDGET25_PROBE","1").env("STP_P4_REPAIR_CAP_PERCENT",std::ffi::OsStr::from_bytes(b"\xff"));
            let out=c.output().unwrap();assert!(out.status.success());assert!(String::from_utf8_lossy(&out.stdout).contains("STP_P4_REPAIR_CAP_PERCENT must be 15 or 25"));
        }
    }
    #[test] fn empirical_selector_strict_and_isolated() {
        let parse = |v, policy, w, ss, bonus, event, model, budget, cap| parse_empirical_tail(v,policy,w,ss,bonus,event,model,budget,cap);
        assert_eq!(parse(None,RepairPolicy::MessageBound,1,false,0,0,0,1,25).unwrap(),0);
        for bad in ["", "01", "2", "true", " 1", "-1"] { assert!(parse(Some(bad),RepairPolicy::MessageBound,1,false,0,0,0,1,25).is_err()); }
        assert_eq!(parse(Some("1"),RepairPolicy::MessageBound,1,false,0,0,0,1,25).is_ok(),true);
        if true { for v in ["0","1"] {
            for tuple in [(RepairPolicy::Reliability,1,false,0,0,0,1,25),(RepairPolicy::MessageBound,2,false,0,0,0,1,25),(RepairPolicy::MessageBound,1,true,0,0,0,1,25),(RepairPolicy::MessageBound,1,false,1,0,0,1,25),(RepairPolicy::MessageBound,1,false,0,1,0,1,25),(RepairPolicy::MessageBound,1,false,0,0,1,1,25),(RepairPolicy::MessageBound,1,false,0,0,0,0,25),(RepairPolicy::MessageBound,1,false,0,0,0,1,15)] {
                assert!(parse(Some(v),tuple.0,tuple.1,tuple.2,tuple.3,tuple.4,tuple.5,tuple.6,tuple.7).is_err());
            }
        }}
    }
    #[test] fn empirical_budget_only_split_targets_and_original_q001() {
        let mut a=FecAdaptiveState::baseline_for_test(crate::ship::FEC,1_000_000_000);
        // A rare observed cluster: .001 includes it, .01 excludes it; same IID prior.
        a.span.epochs=[0,u64::MAX];a.span.seen=10_000;
        for scale in 0..16 { a.span.hist[0][scale][0]=9_980;a.span.hist[0][scale][17]=20; }
        let eps=base_group_eps(1);
        for n in [1,2,16,40,65,128,1000,65537] { assert_eq!(a.budget_count_quantile(n,eps),a.base_count_quantile(n,eps)); }
        let original=a.budget_tail_repairs(71,2,0,0,38,eps,39);
        a.empirical_tail=true;
        assert_eq!(a.budget_count_quantile(40,eps),iid_count_quantile(40,a.tracker.cfg.min_loss,eps));
        assert!(a.budget_tail_repairs(71,2,0,0,38,eps,39).0<original.0);
        assert_eq!(a.base_count_quantile(40,eps),17); // unrelated B1 remains unchanged
        // With all exposure finalized, d has coefficient exactly one in BOTH arms.
        for arm in [false,true] {a.empirical_tail=arm;for d in 0..20 { assert_eq!(a.budget_tail_repairs(71,2,d,71,0,eps,0).0,d+2); }}
    }

}

#[cfg(all(test,feature="research_budget_diagnostic"))]
mod empirical_capture_tests {

    #[test] fn empirical_initialized_policy_child() {
        if std::env::var_os("STP_EMPIRICAL_POLICY_PROBE").is_none(){return;}
        let r=initialize_research_policy();
        match r {Ok(())=>println!("INITIALIZED<ok:{}>",research_p4_empirical_tail_calibration()),Err(e)=>println!("INITIALIZED<err:{e}>")}
    }
    #[cfg(feature="research_target_validation")]
    #[ignore = "historical predecessor-feature configuration, not frozen RC defaults"]
    #[test] fn empirical_initialized_process_selectors_and_forbidden_policies() {
        let probe=|arm:Option<&str>,change:Option<(&str,&std::ffi::OsStr)>| {
            let mut c=std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact","fec_adapt::empirical_capture_tests::empirical_initialized_policy_child","--nocapture","--test-threads=1"]);
            for(k,_)in std::env::vars_os(){if k.to_string_lossy().starts_with("STP_"){c.env_remove(k);}}
            c.env("STP_EMPIRICAL_POLICY_PROBE","1").env("STP_P4_BUDGET_BASE","1").env("STP_P4_REPAIR_CAP_PERCENT","25");
            if let Some(a)=arm {c.env("STP_P4_EMPIRICAL_TAIL_CALIBRATION",a);}
            if let Some((k,v))=change {c.env(k,v);}
            let out=c.output().unwrap();assert!(out.status.success());let text=String::from_utf8(out.stdout).unwrap();
            text.split("INITIALIZED<").nth(1).unwrap().split(">\n").next().unwrap().to_owned()
        };
        assert_eq!(probe(None,None),"ok:0");
        let budget="STP_P4_BUDGET_BASE requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0";
        let cap="STP_P4_REPAIR_CAP_PERCENT=25 requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0, STP_P4_BUDGET_BASE=1";
        let isolated="empirical calibration requires P4/W1/SS0/bonus0/event0/model0/budget_base1/cap25";
        for arm in ["0","1"] {
            assert_eq!(probe(Some(arm),None),format!("ok:{arm}"));
            for(k,v,expected)in [("STP_P4_BASE_PARITY_MODEL","1",budget),("STP_P4_BUDGET_BASE","0",cap),("STP_P4_REPAIR_CAP_PERCENT","15",isolated),("STP_P4_INTERLEAVE_WIDTH","2",budget),("STP_P4_INTERLEAVE_WIDTH","4",budget),("STP_P4_SLIPSTREAM","1",budget),("STP_RACE_POLICY","P3",budget),("STP_P4_MEDIUM_BONUS_PERCENT","1",budget),("STP_P4_EVENT_REPAIR","5",budget)] {
                assert_eq!(probe(Some(arm),Some((k,std::ffi::OsStr::new(v)))),format!("err:{expected}"),"arm={arm} {k}={v}");
            }
        }
        for bad in ["","01","2","true"," 1","-1"] {
            assert_eq!(probe(Some(bad),None),"err:STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1");
        }
        #[cfg(unix)] {use std::os::unix::ffi::OsStrExt;assert_eq!(probe(None,Some(("STP_P4_EMPIRICAL_TAIL_CALIBRATION",std::ffi::OsStr::from_bytes(b"\xff")))),"err:STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1");}
    }
    use super::*;
    use crate::budget_diagnostic as diag;
    fn replay(c:&diag::Demand)->(u64,bool) {
        let h=&c.header;let mut r=h.start.min(h.k) as u64;
        assert!(h.iterations_count>0);
        for (i,t) in c.iterations[..h.iterations_count as usize].iter().enumerate() {
            assert_eq!(t.r,r);assert_eq!(t.e,r.saturating_sub(h.rs as u64));assert_eq!(t.n,h.uc.saturating_add(t.e));
            assert_eq!(t.iid,iid_count_quantile(t.n,h.iid_p,h.eps_i));
            assert_eq!(t.selected,t.n.min(if t.flags&1!=0 {t.empirical}else{0}.max(t.iid)));
            let want=r.max((h.d as u64).saturating_add(2).saturating_add(h.ug.saturating_add(t.e).min(t.selected)));
            assert_eq!(t.next_r as u64,want.min(h.k as u64));
            if t.next_r as u64==r {assert_eq!(i+1,h.iterations_count as usize);return(r,want>h.k as u64);}
            r=t.next_r as u64;
        }
        assert_eq!(h.flags&8,8);(h.k as u64,true)
    }
    #[test] fn empirical_cached_queries_exact_replay_and_predecessor_q001() {
        let mut a=FecAdaptiveState::baseline_for_test(crate::ship::FEC,1_000_000_000);
        for history in 0..3 {
            a.span=Box::new(SpanLossProfile::default());
            if history!=0 {a.span.epochs=[0,u64::MAX];a.span.seen=10_000;for scale in 0..16{a.span.hist[0][scale][0]=9980;a.span.hist[0][scale][17]=20;}}
            if history==2 {a.base_now_ns=1_000_000_000_000;}else{a.base_now_ns=1_000_000_000;}
            for arm in [false,true] {a.empirical_tail=arm;
                for k in [1,2,4,8,71,704,100_000] {for d in [0,1,3] {for own in [0,30,71] {for codecs in [1,3,7] {
                    let start=2.min(k);let rs=1;let uc=own+1;
                    let mut c=diag::Demand::default();c.header=diag::DemandHeader{k:k as u32,start:start as u32,rs:rs as u32,d:d as u32,ug:own,uc,..Default::default()};
                    let actual=a.budget_tail_for_codecs(k,start,d,rs,own,codecs,uc,k,Some(&mut c));
                    assert_eq!(replay(&c),actual);assert_eq!(c.header.result_r as u64,actual.0);
                    assert_eq!(c.header.eps_e.to_bits(),(if arm{0.01/codecs as f64}else{base_group_eps(codecs)}).to_bits());
                    assert_eq!(a.budget_tail_for_codecs(k,start,d,rs,own,codecs,uc,k,None),actual);
                    if !arm {
                        // Exact frozen predecessor loop, not just clipped output.
                        let mut r=start.min(k);let mut expected=(k,true);
                        for _ in 0..64 {let e=r.saturating_sub(rs);let future=own.saturating_add(e).min(a.base_count_quantile(uc.saturating_add(e),base_group_eps(codecs)));let want=r.max(d.saturating_add(2).saturating_add(future));let next=want.min(k);if next==r{expected=(r,want>k);break;}r=next;}
                        assert_eq!(actual,expected);
                    }
                }}}}
            }
        }
    }
    #[test] fn empirical_iteration_limit_explicit_without_changing_computation() {
        let mut a=FecAdaptiveState::baseline_for_test(crate::ship::FEC,1);a.span.epochs=[0,u64::MAX];a.span.seen=10_000;
        for scale in 0..16 {a.span.hist[0][scale][SpanLossProfile::bin(65536)]=10_000;}
        let mut c=diag::Demand::default();c.header=diag::DemandHeader{k:1000,start:2,uc:0,ug:0,..Default::default()};
        let actual=a.budget_tail_for_codecs(1000,2,0,0,0,1,0,1000,Some(&mut c));
        assert_eq!(actual,(1000,true));assert_eq!(c.header.iterations_count,64);assert_eq!(c.header.flags&8,8);
        assert_eq!(c.iterations[63].flags&8,8);assert_eq!(replay(&c),actual);
        assert_eq!(c.iterations[63].next_r,130);assert_eq!(c.header.flags&4,0);
        assert!(actual.1); // legacy cap-bound bool STILL means either exceeded K OR fallback.
        assert_eq!(c.header.flags&16,16);
        assert_eq!(a.budget_tail_for_codecs(1000,2,0,0,0,1,0,1000,None),actual);
    }
}

/// Socket-free research fixture: seeds the REAL bounded span sketch with finalized outcomes,
/// followed by uc-1 unresolved DATA commits, then executes the REAL budget query with cached capture.
/// Outcome timestamps are `now_ns`; created_ns is actual constructor input. No transport state is modified.
#[cfg(feature="research_budget_diagnostic")]
#[doc(hidden)]
pub fn research_demand_fixture(k:u32,start:u32,d:u32,rs:u32,ug:u64,uc:u64,codecs:usize,selector:u32,created_ns:u64,now_ns:u64,outcomes:&[bool])->crate::budget_diagnostic::Demand {
    assert!(selector<=1&&created_ns<=now_ns&&uc>0&&uc<=65536&&outcomes.len()<=65536);
    let mut a=FecAdaptiveState::new(crate::ship::FEC,created_ns);a.empirical_tail=selector==1;
    for(i,&lost)in outcomes.iter().enumerate(){a.on_data_sent(i as u64);a.on_sequence_finalized(i as u64,lost,now_ns);}
    for i in 0..uc-1 {a.on_data_sent(outcomes.len()as u64+i);}
    a.on_tick(now_ns);
    let mut c=crate::budget_diagnostic::Demand::default();
    c.header=crate::budget_diagnostic::DemandHeader{k,start,d,rs,ug,uc,codec_count:codecs as u32,..Default::default()};
    a.budget_tail_for_codecs(k as u64,start as u64,d as u64,rs as u64,ug,codecs,uc,{k as u64},Some(&mut c));c
}

#[cfg(test)]
mod cost_smooth_tests {
    use super::*;
    fn state(p:f64)->FecAdaptiveState {
        let mut a=FecAdaptiveState::baseline_for_test(crate::ship::FEC,1);
        a.p=p;a.set_cost_smooth_for_test();a.set_base_context(1,500_000_000,Some(200_000_000));a
    }
    #[test]
    fn cost_smooth_absolute_uncapped_middle_risk_and_known_loss_unit_cost() {
        let mut a=state(0.0265);
        let mut previous=1.0;
        for k in [2,4,8,15,29,71,1000,100_000] {
            let (eps,_,_)=a.cost_target(k,1,false).unwrap();
            assert!(eps<=a.p && eps<previous);previous=eps;
            let (r,failed)=a.cost_tail(k,k,1,0,0,k.min(100),1,k.min(100),None);
            assert!(!failed,"K={k}");
            let (monotone,failed)=a.cost_tail(k,k,r+1,0,0,k.min(100),1,k.min(100),None);
            assert!(!failed && monotone>=r+1);
            eprintln!("smooth K={k} eps={eps:.8} R={r}");
        }
        a.p=0.8;
        let (r,failed)=a.cost_tail(2,2,1,0,0,2,1,2,None);
        assert!(!failed && r>2,"uncapped R={r} failed={failed}");
        let (r,failed)=a.cost_tail(15,15,1,0,0,15,1,15,None);
        assert!(!failed && r>3,"K15 must exceed old floor25 allowance");
        let mut history=state(0.75);
        for i in 0..8192 {history.span.on_outcome(i%4!=0,1,history.tracker.cfg.window_ns);}
        let (r,failed)=history.cost_tail(2,2,1,0,0,2,1,2,None);
        assert!(!failed && r>2,"adverse empirical history R={r} failed={failed}");
        eprintln!("adverse synthetic 75% contiguous history K2 R={r} (>100%)");
        a.p=0.0265;
        let rank=a.cost_target(100,1,true).unwrap().2;
        for d in 10..20 {
            assert_eq!(a.cost_tail(100,100,1,d,1000,0,1,0,None),(d+rank,false));
        }
    }
    #[cfg(feature="research_budget_diagnostic")]
    #[test]
    fn cost_smooth_failure_is_explicit_bounded_never_index_ceiling() {
        let mut a=state(0.01);
        assert_eq!(a.cost_tail(0,0,0,0,0,0,1,0,None),(0,false));
        a.tracker.on_sample(2_000_000_000,500,0);a.p=a.tracker.mean;
        assert_eq!(a.p,0.0);
        assert!(!a.cost_tail(2,2,1,0,0,2,1,2,None).1,"clean tracker sample must retain finite loss floor");
        for p in [-1.0,f64::NAN,f64::INFINITY,1.0] {
            a.p=p;assert_eq!(a.cost_tail(2,2,1,0,0,2,1,2,None),(1,true));
        }
        a.p=0.01;
        assert_eq!(a.cost_tail(2,2,1,0,0,2,1,u64::MAX,None),(1,true));
        a.span.epochs=[0,u64::MAX];
        for scale in 0..16 {a.span.hist[0][scale][SpanLossProfile::bin(2u32<<scale)]=100;}
        let mut record=crate::budget_diagnostic::Demand::default();
        assert_eq!(a.cost_tail(2,2,1,0,0,2,1,2,Some(&mut record)),(1,true));
        assert_eq!(record.header.flags&24,24);
    }
    #[cfg(feature="research_target_validation")]
    #[test]
    fn cost_smooth_process_selector_contract() {
        for (selector,cap,empirical,ok) in [("0","25","1",true),("1","0","1",true),("0","0","1",false),("1","25","1",false),("1","0","0",false),("2","0","1",false)] {
            let mut c=std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact","fec_adapt::cost_smooth_tests::cost_smooth_policy_child","--nocapture"]);
            for(k,_)in std::env::vars_os(){if k.to_string_lossy().starts_with("STP_"){c.env_remove(k);}}

            c.env("STP_P4_TARGET_VALIDATION",if selector=="1" {"1"}else{"0"}).env("STP_COHORT_PROFILE","g4");
            c.env("STP_COST_PROBE","1").env("STP_P4_BUDGET_BASE","1").env("STP_P4_COST_SMOOTH",selector).env("STP_P4_REPAIR_CAP_PERCENT",cap).env("STP_P4_EMPIRICAL_TAIL_CALIBRATION",empirical);
            let out=c.output().unwrap();assert!(out.status.success());let text=String::from_utf8_lossy(&out.stdout);
            assert!(text.contains(if ok {"COST<Ok"}else{"COST<Err"}),"{selector}/{cap}/{empirical}: {text}");
            if ok {assert!(text.contains(&format!("|{selector}|{cap}>")));}
        }
    }
    #[test]
    fn cost_smooth_policy_child() {
        if std::env::var_os("STP_COST_PROBE").is_none(){return;}
        let r=initialize_research_policy();println!("COST<{r:?}|{}|{}>",research_p4_cost_smooth(),research_p4_repair_cap_percent());
    }
    #[test]
    fn cost_smooth_native_sampled_erasure_rank_observations() {
        for k in [2usize, 3, 4, 8, 15, 32, 64, 128] {
            let data = std::sync::Arc::new((0..k*64).map(|i| (i*17) as u8).collect::<Vec<_>>());
            let mut enc = crate::fec::encode(data.clone(),64).unwrap();
            let blocks = (0..k+4).map(|i|enc.block(i as u32).unwrap()).collect::<Vec<_>>();
            let mut fails=[0usize;4];
            for missing in 0..k {
                let mut dec=crate::fec::Decoder::new(data.len(),64).unwrap();
                for i in 0..k {if i!=missing {dec.add(i as u32,&blocks[i]).unwrap();}}
                for r in 0..4 {
                    dec.add((k+r) as u32,&blocks[k+r]).unwrap();
                    if !dec.is_done() {fails[r]+=1;} else {assert_eq!(dec.recover().unwrap(),*data);}
                }
            }
            eprintln!("native single erasure K={k}: failures after R1..4={fails:?}/{k}");
            assert_eq!(fails[0],0,"first XOR repair covers every single erasure in these exact fixtures");
            let mut pair_fails=[0usize;3];
            for first in 0..k.min(16) {
                let second=(first+k/2)%k;
                let mut dec=crate::fec::Decoder::new(data.len(),64).unwrap();
                for i in 0..k {if i!=first && i!=second {dec.add(i as u32,&blocks[i]).unwrap();}}
                for r in 0..4 {
                    dec.add((k+r)as u32,&blocks[k+r]).unwrap();
                    if r>0 && !dec.is_done(){pair_fails[r-1]+=1;}
                }
            }
            eprintln!("native paired erasure K={k}: failures after R2..4={pair_fails:?}/{}",k.min(16));
        }
    }
}

#[cfg(test)]
mod target_validation_policy_tests {
    use super::*;
    #[test] fn target_validation_parser_feature_gate() {
        assert_eq!(parse_target_validation(Some("0")).unwrap(),0);
        assert_eq!(parse_target_validation(None).is_err(),true);
        for v in ["1","2"] {assert_eq!(parse_target_validation(Some(v)).is_ok(),true);}
        for v in ["","3","01","1.0"," 1","1 ","-1"] {assert!(parse_target_validation(Some(v)).is_err());}
    }

    #[test] fn target_validation_initialized_child() {
        if std::env::var_os("STP_TARGET_PROBE").is_none(){return;}
        let result=initialize_research_policy();println!("TARGET<{result:?}|{}|{:?}>",research_p4_target_validation(),crate::target_validation::configuration());
        if result.is_ok() {let mut a=FecAdaptiveState::baseline_for_test(crate::ship::FEC,0);assert_eq!(a.target_selector(),research_p4_target_validation());assert!(initialize_research_policy().is_ok());}
    }

    #[cfg(feature="research_target_validation")]
    #[test] fn target_validation_initialized_strict_matrix() {
        let probe=|tv:Option<&str>,cost:&str,cap:&str,emp:&str,profile:&str,change:Option<(&str,&str)>| {
            let mut c=std::process::Command::new(std::env::current_exe().unwrap());
            c.args(["--exact","fec_adapt::target_validation_policy_tests::target_validation_initialized_child","--nocapture"]);
            for(k,_)in std::env::vars_os(){if k.to_string_lossy().starts_with("STP_"){c.env_remove(k);}}
            c.env("STP_TARGET_PROBE","1").env("STP_P4_BUDGET_BASE","1").env("STP_P4_COST_SMOOTH",cost).env("STP_P4_REPAIR_CAP_PERCENT",cap).env("STP_P4_EMPIRICAL_TAIL_CALIBRATION",emp).env("STP_COHORT_PROFILE",profile);
            if let Some(tv)=tv {c.env("STP_P4_TARGET_VALIDATION",tv);}if let Some((k,v))=change{c.env(k,v);}
            let out=c.output().unwrap();assert!(out.status.success());String::from_utf8_lossy(&out.stdout).contains("TARGET<Ok")
        };
        for profile in ["g4","b20r20"] {for (tv,cost,cap) in [("0","0","25"),("1","1","0"),("2","1","0")] {assert!(probe(Some(tv),cost,cap,"1",profile,None));}}
        for tv in [None,Some(""),Some("3"),Some("01")] {assert!(!probe(tv,"0","25","1","g4",None));}
        for (tv,cost,cap,emp,profile) in [("0","1","0","1","g4"),("1","0","25","1","g4"),("2","1","25","1","g4"),("1","1","0","0","g4"),("0","0","25","0","g4"),("1","1","0","1","x"),("0","0","25","1","")] {assert!(!probe(Some(tv),cost,cap,emp,profile,None));}
        for (key,value) in [("STP_RACE_POLICY","P3"),("STP_P4_INTERLEAVE_WIDTH","2"),("STP_P4_SLIPSTREAM","1"),("STP_P4_MEDIUM_BONUS_PERCENT","1"),("STP_P4_EVENT_REPAIR","5"),("STP_P4_BASE_PARITY_MODEL","1"),("STP_P4_BUDGET_BASE","0")] {assert!(!probe(Some("1"),"1","0","1","g4",Some((key,value))));}
    }
}
