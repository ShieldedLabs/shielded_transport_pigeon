#[cfg(feature = "research_budget_diagnostic")]
type DemandCapture = crate::budget_diagnostic::Demand;
#[cfg(not(feature = "research_budget_diagnostic"))]
type DemandCapture = ();
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepairPolicy {
    Reliability,
    MeanOpen,
    MeanTopup,
    Streaming,
    MessageBound,
}
static RESEARCH_POLICY: std::sync::OnceLock<RepairPolicy> = std::sync::OnceLock::new();
static RESEARCH_INTERLEAVE_WIDTH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static RESEARCH_SLIPSTREAM: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static RESEARCH_MEDIUM_BONUS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
/// Each research knob is published once by `initialize_research_policy`; its hidden getter
/// reports the default until then.
macro_rules! research_settings {
    ($($slot:ident, $getter:ident, $default:expr;)*) => {$(
        static $slot: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        #[doc(hidden)]
        pub fn $getter() -> u32 {
            $slot.get().copied().unwrap_or($default)
        }
    )*};
}
research_settings! {
    RESEARCH_EVENT_REPAIR, research_p4_event_repair, 0;
    RESEARCH_BASE_PARITY, research_p4_base_parity_model, 0;
    RESEARCH_BUDGET_BASE, research_p4_budget_base, 0;
    RESEARCH_TARGET_VALIDATION, research_p4_target_validation, 0;
    RESEARCH_COST_SMOOTH, research_p4_cost_smooth, 0;
    RESEARCH_REPAIR_CAP_PERCENT, research_p4_repair_cap_percent, 15;
    RESEARCH_EMPIRICAL_TAIL, research_p4_empirical_tail_calibration, 0;
}
/// Accepts exactly the decimal spelling of one of `accepted`; `None` means `default`.
macro_rules! choice {
    ($value:expr, $default:expr, &[$($accepted:literal),+], $error:expr $(,)?) => {
        match ($value).unwrap_or($default) {
            $(stringify!($accepted) => Ok($accepted),)+
            _ => Err(($error).to_string()),
        }
    };
}
/// The P4 experiments stack: each one requires P4 at width 1 without slipstream and every
/// earlier experiment in `earlier` left at 0.
fn p4_isolated(policy: RepairPolicy, width: usize, slipstream: bool, earlier: &[u32]) -> bool {
    policy == RepairPolicy::MessageBound
        && width == 1
        && !slipstream
        && earlier.iter().all(|&v| v == 0)
}
pub(crate) fn parse_event_repair(
    value: Option<&str>,
    policy: RepairPolicy,
    width: usize,
    slipstream: bool,
    bonus: u32,
) -> Result<u32, String> {
    let q = choice!(
        value,
        "0",
        &[0, 5, 10],
        "STP_P4_EVENT_REPAIR must be 0, 5 or 10",
    )?;
    if q != 0 && !p4_isolated(policy, width, slipstream, &[bonus]) {
        return Err("STP_P4_EVENT_REPAIR requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0".to_string());
    }
    Ok(q)
}
pub(crate) fn parse_base_parity_model(
    value: Option<&str>,
    policy: RepairPolicy,
    width: usize,
    slipstream: bool,
    bonus: u32,
    event: u32,
) -> Result<u32, String> {
    let m = choice!(
        value,
        "0",
        &[0, 1],
        "STP_P4_BASE_PARITY_MODEL must be 0 or 1",
    )?;
    if m != 0 && !p4_isolated(policy, width, slipstream, &[bonus, event]) {
        return Err("STP_P4_BASE_PARITY_MODEL requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0".to_string());
    }
    Ok(m)
}
pub(crate) fn parse_budget_base(
    value: Option<&str>,
    policy: RepairPolicy,
    width: usize,
    slipstream: bool,
    bonus: u32,
    event: u32,
    base: u32,
) -> Result<u32, String> {
    let m = choice!(value, "0", &[0, 1], "STP_P4_BUDGET_BASE must be 0 or 1")?;
    if m != 0 && !p4_isolated(policy, width, slipstream, &[bonus, event, base]) {
        return Err("STP_P4_BUDGET_BASE requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0".to_string());
    }
    Ok(m)
}
/// Unlike the other knobs this one has no default: it must be set explicitly.
fn parse_target_validation(value: Option<&str>) -> Result<u32, String> {
    let error = "STP_P4_TARGET_VALIDATION must be explicitly 0, 1 or 2";
    choice!(
        Some(value.ok_or_else(|| error.to_string())?),
        "",
        &[0, 1, 2],
        error,
    )
}
fn parse_cost_smooth(value: Option<&str>) -> Result<u32, String> {
    choice!(value, "0", &[0, 1], "STP_P4_COST_SMOOTH must be 0 or 1")
}
pub(crate) fn parse_repair_cap_percent(
    value: Option<&str>,
    policy: RepairPolicy,
    width: usize,
    slipstream: bool,
    bonus: u32,
    event: u32,
    base: u32,
    budget: u32,
) -> Result<u32, String> {
    let error = "STP_P4_REPAIR_CAP_PERCENT must be 15 or 25";
    let cap = choice!(value, "15", &[15, 25, 0], error)?;
    if cap != 15 && !(p4_isolated(policy, width, slipstream, &[bonus, event, base]) && budget == 1)
    {
        return Err("STP_P4_REPAIR_CAP_PERCENT=25 requires P4, STP_P4_INTERLEAVE_WIDTH=1, STP_P4_SLIPSTREAM=0, STP_P4_MEDIUM_BONUS_PERCENT=0, STP_P4_EVENT_REPAIR=0, STP_P4_BASE_PARITY_MODEL=0, STP_P4_BUDGET_BASE=1".to_string());
    }
    Ok(cap)
}
/// The prerequisites apply even when calibration is 0.
pub(crate) fn parse_empirical_tail(
    value: Option<&str>,
    policy: RepairPolicy,
    width: usize,
    slipstream: bool,
    bonus: u32,
    event: u32,
    base: u32,
    budget: u32,
    cap: u32,
) -> Result<u32, String> {
    let error = "STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1";
    let q = choice!(value, "0", &[0, 1], error)?;
    if !(p4_isolated(policy, width, slipstream, &[bonus, event, base])
        && budget == 1
        && (cap == 25 || cap == 0))
    {
        return Err(
            "empirical calibration requires P4/W1/SS0/bonus0/event0/model0/budget_base1/cap25"
                .into(),
        );
    }
    Ok(q)
}
pub(crate) fn research_slipstream() -> bool {
    RepairPolicy::selected() == RepairPolicy::MessageBound
        && RESEARCH_SLIPSTREAM.get().copied().unwrap_or(false)
}
#[doc(hidden)]
pub fn research_p4_configuration() -> (&'static str, usize, bool, u32) {
    let policy = match RepairPolicy::selected() {
        RepairPolicy::Reliability => "P0",
        RepairPolicy::MeanOpen => "P1",
        RepairPolicy::MeanTopup => "P2",
        RepairPolicy::Streaming => "P3",
        RepairPolicy::MessageBound => "P4",
    };
    (
        policy,
        research_interleave_width(),
        research_slipstream(),
        research_medium_bonus(),
    )
}
fn parse_medium_bonus(value: Option<&str>, policy: RepairPolicy) -> Result<u32, String> {
    let percent = value
        .unwrap_or("0")
        .parse::<u32>()
        .ok()
        .filter(|v| *v <= 100)
        .ok_or_else(|| "STP_P4_MEDIUM_BONUS_PERCENT must be an integer 0..=100".to_string())?;
    if percent != 0 && policy != RepairPolicy::MessageBound {
        return Err("STP_P4_MEDIUM_BONUS_PERCENT applies only to P4".to_string());
    }
    Ok(percent)
}
pub(crate) fn research_medium_bonus() -> u32 {
    RESEARCH_MEDIUM_BONUS.get().copied().unwrap_or(0)
}
pub fn category_bonus_percent() -> u32 {
    research_medium_bonus()
}
fn parse_interleave_width(value: Option<&str>) -> Result<usize, String> {
    match value {
        None | Some("1") => Ok(1),
        Some("2") => Ok(2),
        Some("4") => Ok(4),
        _ => Err("STP_P4_INTERLEAVE_WIDTH must be 1, 2, or 4".to_string()),
    }
}
pub(crate) fn research_interleave_width() -> usize {
    if RepairPolicy::selected() == RepairPolicy::MessageBound {
        RESEARCH_INTERLEAVE_WIDTH.get().copied().unwrap_or(1)
    } else {
        1
    }
}
impl RepairPolicy {
    fn selected() -> Self {
        RESEARCH_POLICY.get().copied().unwrap_or(Self::MessageBound)
    }
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            Some("P1") => Ok(Self::MeanOpen),
            Some("P2") => Ok(Self::MeanTopup),
            Some("P3") => Ok(Self::Streaming),
            Some("P4") => Ok(Self::MessageBound),
            Some("P0") => Ok(Self::Reliability),
            None => Ok(Self::MessageBound),
            Some(other) => Err(format!(
                "unknown STP_RACE_POLICY {other:?}; expected P0, P1, P2, P3, or P4"
            )),
        }
    }
    pub fn feedback(self) -> bool {
        self != Self::MeanOpen
    }
}
fn policy_choice<T>(
    name: &str,
    invalid: &str,
    parse: impl FnOnce(Option<&str>) -> Result<T, String>,
) -> Result<T, String> {
    match crate::ship::policy_var(name) {
        Ok(value) => parse(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse(None),
        Err(_) => Err(invalid.to_string()),
    }
}
#[doc(hidden)]
pub fn initialize_research_policy() -> Result<(), String> {
    if RESEARCH_POLICY.get().is_some() {
        return Ok(());
    }
    let policy = policy_choice(
        "STP_RACE_POLICY",
        "STP_RACE_POLICY must be valid Unicode",
        RepairPolicy::parse,
    )?;
    let width = policy_choice(
        "STP_P4_INTERLEAVE_WIDTH",
        "STP_P4_INTERLEAVE_WIDTH must be valid Unicode",
        parse_interleave_width,
    )?;
    let slipstream = policy_choice(
        "STP_P4_SLIPSTREAM",
        "STP_P4_SLIPSTREAM must be 0 or 1",
        |v| match v {
            Some("1") => Ok(true),
            None | Some("0") => Ok(false),
            _ => Err("STP_P4_SLIPSTREAM must be 0 or 1".to_string()),
        },
    )?;
    if slipstream && width != 1 {
        return Err("slipstream requires STP_P4_INTERLEAVE_WIDTH=1".to_string());
    }
    let bonus = policy_choice(
        "STP_P4_MEDIUM_BONUS_PERCENT",
        "STP_P4_MEDIUM_BONUS_PERCENT must be an integer 0..=100",
        |v| parse_medium_bonus(v, policy),
    )?;
    let event = policy_choice(
        "STP_P4_EVENT_REPAIR",
        "STP_P4_EVENT_REPAIR must be 0, 5 or 10",
        |v| parse_event_repair(v, policy, width, slipstream, bonus),
    )?;
    let base = policy_choice(
        "STP_P4_BASE_PARITY_MODEL",
        "STP_P4_BASE_PARITY_MODEL must be 0 or 1",
        |v| parse_base_parity_model(v, policy, width, slipstream, bonus, event),
    )?;
    let budget = policy_choice(
        "STP_P4_BUDGET_BASE",
        "STP_P4_BUDGET_BASE must be 0 or 1",
        |v| parse_budget_base(v, policy, width, slipstream, bonus, event, base),
    )?;
    let cost = policy_choice(
        "STP_P4_COST_SMOOTH",
        "STP_P4_COST_SMOOTH must be 0 or 1",
        parse_cost_smooth,
    )?;
    let cap = policy_choice(
        "STP_P4_REPAIR_CAP_PERCENT",
        "STP_P4_REPAIR_CAP_PERCENT must be 15 or 25",
        |v| parse_repair_cap_percent(v, policy, width, slipstream, bonus, event, base, budget),
    )?;
    let empirical = policy_choice(
        "STP_P4_EMPIRICAL_TAIL_CALIBRATION",
        "STP_P4_EMPIRICAL_TAIL_CALIBRATION must be 0 or 1",
        |v| {
            parse_empirical_tail(
                v, policy, width, slipstream, bonus, event, base, budget, cap,
            )
        },
    )?;
    if (cost == 1 && (cap != 0 || empirical != 1)) || (cost == 0 && cap == 0) {
        return Err(
            "cost smooth requires selector1/cap0/empirical1; cap0 is forbidden for selector0"
                .into(),
        );
    }
    let target = policy_choice(
        "STP_P4_TARGET_VALIDATION",
        "STP_P4_TARGET_VALIDATION must be explicitly 0, 1 or 2",
        parse_target_validation,
    )?;
    crate::target_validation::initialize(
        target,
        crate::ship::policy_var("STP_COHORT_PROFILE")
            .ok()
            .as_deref(),
        cost,
        cap,
        empirical,
    )?;
    let _ = RESEARCH_TARGET_VALIDATION.set(target);
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
pub(crate) fn mean_repairs(k: u64, p: f64) -> u64 {
    if k == 0 {
        return 0;
    }
    ((k as f64 * p.clamp(0.0, 0.9) / (1.0 - p.clamp(0.0, 0.9))).ceil() as u64)
        .saturating_add(2)
        .min(k)
}
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
    fn default() -> Self {
        crate::ship::FEC
    }
}
const RESCUE_LATENCY_TAIL: f64 = 0.02;
pub fn z_for_eps(eps: f64) -> f64 {
    let eps = eps.clamp(1e-300, 0.5);
    let t = (-2.0 * eps.ln()).sqrt();
    t - (2.515517 + 0.802853 * t + 0.010328 * t * t)
        / (1.0 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t)
}
pub fn formula_repair_blocks(k: u64, p: f64, z: f64) -> u64 {
    let p = p.clamp(1e-9, 0.9);
    let s = (p * (1.0 - p)).sqrt();
    let c = ((z * z - 1.0) * (1.0 - 2.0 * p) / 6.0).max(0.0);
    let kk = k as f64 + c;
    let x = (z * s + (z * z * s * s + 4.0 * (1.0 - p) * kk).sqrt()) / (2.0 * (1.0 - p));
    let n = (x * x).ceil() as u64;
    n.saturating_sub(k)
}
fn binomial_tail(n: u64, p: f64, m: u64) -> f64 {
    if m == 0 {
        return 1.0;
    }
    if m > n {
        return 0.0;
    }
    let mut pmf = (1.0 - p).powi(n as i32);
    let r = p / (1.0 - p);
    let mut tail = 0.0;
    for j in 0..=n {
        if j >= m {
            tail += pmf;
        }
        pmf *= (n - j) as f64 / (j + 1) as f64 * r;
    }
    tail
}
const EXACT_MAX_K: u64 = 128;
pub fn min_repair_blocks(k: u64, p: f64, z: f64, eps: f64) -> u64 {
    if k > EXACT_MAX_K {
        return formula_repair_blocks(k, p, z);
    }
    let p = p.clamp(1e-9, 0.9);
    let mut n = k;
    let limit = k + formula_repair_blocks(k, p, z);
    while n < limit && binomial_tail(n, p, n - k + 1) > eps {
        n += 1;
    }
    n - k
}
pub fn iid_count_quantile(n: u64, p: f64, eps: f64) -> u64 {
    if n == 0 {
        return 0;
    }
    let p = p.clamp(1e-9, 0.9);
    let eps = eps.clamp(1e-300, 0.5);
    if n <= EXACT_MAX_K {
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if binomial_tail(n, p, mid + 1) <= eps {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return lo;
    }
    let z = z_for_eps(eps);
    let np = n as f64 * p;
    let q = np + z * (np * (1.0 - p)).sqrt() + (z * z - 1.0) * (1.0 - 2.0 * p) / 6.0;
    if !(q > 0.0) {
        return 0;
    }
    (q.ceil() as u64).min(n)
}
pub(crate) const BASE_EPS_ROOT: f64 = 0.001;
#[doc(hidden)]
pub fn research_iid_count_quantile(n: u64, p: f64, eps: f64) -> u64 {
    iid_count_quantile(n, p, eps)
}
#[doc(hidden)]
pub fn research_base_group_eps(codecs: usize) -> f64 {
    base_group_eps(codecs)
}
pub(crate) fn base_group_eps(codecs: usize) -> f64 {
    BASE_EPS_ROOT / codecs.max(1) as f64
}
pub(crate) fn budget_repair_limit(k: u64) -> u64 {
    budget_repair_limit_for_cap(k, 15)
}
pub(crate) fn budget_repair_limit_for_cap(k: u64, cap_percent: u32) -> u64 {
    assert!(cap_percent == 15 || cap_percent == 25);
    (cap_percent as u128 * k as u128 / 100) as u64
}
const BASE_ITER_LIMIT: usize = 64;
pub fn repair_blocks(k: u64, p: f64, z: f64, eps: f64, extra: u32, max_redundancy: f64) -> u64 {
    let r = min_repair_blocks(k, p, z, eps) + extra as u64;
    let cap = ((k as f64 * max_redundancy).ceil() as u64).max(1);
    r.clamp(1, cap)
}
#[derive(Clone, Copy, Debug)]
struct ShortTerm {
    start_ns: u64,
    finalized: u64,
    lost: u64,
}
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
        LossTracker {
            cfg,
            st: ShortTerm {
                start_ns: now_ns,
                finalized: 0,
                lost: 0,
            },
            ring: [(u64::MAX, 0, 0); 16],
            have_sample: false,
            last_sample: 0.0,
            cached: cfg.initial_loss,
            mean: cfg.initial_loss,
            last_refresh_ns: now_ns,
        }
    }
    pub fn on_tick(&mut self, now_ns: u64, finalized_delta: u64, lost_delta: u64) {
        debug_assert!(lost_delta <= finalized_delta);
        self.st.finalized += finalized_delta;
        self.st.lost += lost_delta;
        let elapsed = now_ns.saturating_sub(self.st.start_ns);
        if elapsed >= self.cfg.bucket_ns
            && (self.st.finalized >= self.cfg.min_packets.max(1)
                || self.st.lost >= self.cfg.min_packets.max(4).div_ceil(4))
        {
            let sample = self.st;
            self.st = ShortTerm {
                start_ns: now_ns,
                finalized: 0,
                lost: 0,
            };
            self.on_sample(now_ns, sample.finalized, sample.lost);
        } else if now_ns.saturating_sub(self.last_refresh_ns) >= self.cfg.bucket_ns {
            self.refresh(now_ns);
        }
    }
    fn on_sample(&mut self, now_ns: u64, finalized: u64, lost: u64) {
        let loss = lost as f64 / finalized as f64;
        self.mean = if self.have_sample {
            self.mean * 0.875 + loss * 0.125
        } else {
            loss
        };
        self.have_sample = true;
        self.last_sample = loss;
        let cfg = self.cfg;
        let n = cfg.slots.clamp(1, 16);
        let idx = now_ns / cfg.slot_ns.max(1);
        let s = &mut self.ring[(idx % n as u64) as usize];
        if s.0 != idx {
            *s = (idx, 0, 0);
        }
        s.1 += finalized;
        s.2 += lost;
        self.refresh(now_ns);
    }
    fn refresh(&mut self, now_ns: u64) {
        self.last_refresh_ns = now_ns;
        if !self.have_sample {
            return;
        }
        let cfg = self.cfg;
        let n = cfg.slots.clamp(1, 16) as u64;
        let idx = now_ns / cfg.slot_ns.max(1);
        let (finalized, lost) = self
            .ring
            .iter()
            .filter(|s| s.0 != u64::MAX && s.0 + n > idx)
            .fold((0u64, 0u64), |(f, l), s| (f + s.1, l + s.2));
        self.cached = lost as f64 / finalized.max(1) as f64;
    }
    pub fn estimate(&self) -> f64 {
        self.cached
    }
    pub fn last_sample(&self) -> f64 {
        self.last_sample
    }
    pub fn config(&self) -> &AdaptiveFecConfig {
        &self.cfg
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct FecMessageInfo {
    pub tag: u64,
    pub message_len: usize,
    pub k: u32,
    pub n_planned: u32,
    pub n_sent: u32,
    pub loss_estimate: f64,
    pub lost_during_send: u32,
    pub package_id: u64,
    pub root_id: u64,
    pub segment_offset: u32,
    pub block_bytes: u32,
    pub rescue_rounds: u8,
    pub rescue_symbols: u32,
    pub during_message_topup: u32,
    pub tail_repairs: u32,
    pub peak_retained_source_bytes: u64,
}
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
        Self {
            data_sent: [0; crate::stp::PACKETS_WAITING_ACK_WORDS],
            history: [0; 1024],
            counts: [0; 16],
            hist: [[[0; SPAN_LOSS_BINS]; 16]; 2],
            epochs: [u64::MAX; 2],
            seen: 0,
            lost_total: 0,
            sent_total: 0,
            pending_peak: 0,
        }
    }
}
impl SpanLossProfile {
    fn bin(losses: u32) -> usize {
        if losses < 128 {
            return losses as usize;
        }
        let log = 31 - losses.leading_zeros();
        let base = 1u32 << log;
        128 + (log as usize - 7) * 16 + (losses - base).div_ceil(base / 16) as usize
    }
    fn upper(bin: usize) -> u64 {
        if bin < 128 {
            return bin as u64;
        }
        let base = 128u64 << ((bin - 128) / 16);
        base + ((bin - 128) % 16) as u64 * (base / 16)
    }
    pub fn on_data_sent(&mut self, seq: u64) {
        let bit = seq as usize % (self.data_sent.len() * 64);
        self.data_sent[bit / 64] |= 1u64 << (bit % 64);
        self.sent_total += 1;
        self.pending_peak = self.pending_peak.max(self.unresolved_data_packets());
    }
    pub fn unresolved_data_packets(&self) -> u64 {
        self.sent_total.saturating_sub(self.seen)
    }
    pub fn on_sequence_finalized(&mut self, seq: u64, lost: bool, now_ns: u64, window_ns: u64) {
        let bit = seq as usize % (self.data_sent.len() * 64);
        if self.data_sent[bit / 64] & (1u64 << (bit % 64)) == 0 {
            return;
        }
        self.data_sent[bit / 64] &= !(1u64 << (bit % 64));
        self.on_outcome(lost, now_ns, window_ns);
    }
    pub fn on_outcome(&mut self, lost: bool, now_ns: u64, window_ns: u64) {
        let epoch = now_ns / (window_ns / 2).max(1);
        let h = epoch as usize % 2;
        if self.epochs[h] != epoch {
            self.hist[h] = [[0; SPAN_LOSS_BINS]; 16];
            self.epochs[h] = epoch;
        }
        let pos = self.seen as usize & 65535;
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
        if lost {
            self.history[pos / 64] |= 1u64 << (pos % 64);
        } else {
            self.history[pos / 64] &= !(1u64 << (pos % 64));
        }
        self.seen += 1;
        self.lost_total += lost as u64;
    }
    pub fn tail_losses(&self, n: u64, eps: f64) -> Option<u64> {
        let latest = self
            .epochs
            .iter()
            .copied()
            .filter(|x| *x != u64::MAX)
            .max()?;
        self.tail_losses_latest_details(n, eps, latest).0
    }
    pub fn tail_losses_now(&self, n: u64, eps: f64, now_ns: u64, window_ns: u64) -> Option<u64> {
        self.tail_losses_now_details(n, eps, now_ns, window_ns).0
    }
    fn tail_losses_now_details(
        &self,
        n: u64,
        eps: f64,
        now_ns: u64,
        window_ns: u64,
    ) -> (Option<u64>, u16, u64) {
        let Some(latest) = self.epochs.iter().copied().filter(|x| *x != u64::MAX).max() else {
            return (None, 0, 0);
        };
        self.tail_losses_latest_details(n, eps, latest.max(now_ns / (window_ns / 2).max(1)))
    }
    fn tail_losses_latest_details(&self, n: u64, eps: f64, latest: u64) -> (Option<u64>, u16, u64) {
        let pieces = n.div_ceil(65536).max(1);
        let n = n.div_ceil(pieces).max(2);
        let scale = (64 - (n - 1).leading_zeros() as usize)
            .saturating_sub(1)
            .min(15);
        let mut bins = [0u64; SPAN_LOSS_BINS];
        for h in 0..2 {
            if self.epochs[h] != u64::MAX && self.epochs[h] + 1 >= latest {
                for (b, count) in bins.iter_mut().zip(self.hist[h][scale]) {
                    *b += count as u64;
                }
            }
        }
        let total: u64 = bins.iter().sum();
        if total == 0 {
            return (None, scale as u16, 0);
        }
        let allowed_tail = (total as f64 * (eps / pieces as f64).clamp(0.0, 0.5)).floor() as u64;
        let rank = total - allowed_tail;
        let mut acc = 0;
        for (b, count) in bins.iter().enumerate() {
            acc += count;
            if acc >= rank {
                return (Some(Self::upper(b) * pieces), scale as u16, total);
            }
        }
        (None, scale as u16, total)
    }
    pub fn target_failure(&self, k: u64, cfg: &AdaptiveFecConfig) -> f64 {
        let p = if self.seen < 4096 {
            cfg.initial_loss
        } else {
            (self.lost_total as f64 / self.seen as f64).max(1e-6)
        };
        cfg.eps
            .min(p * (64.0 / k.max(1) as f64).min(1.0).sqrt())
            .clamp(1e-9, 0.5)
    }
    fn repair_blocks(&self, k: u64, cfg: &AdaptiveFecConfig, _z: f64) -> u64 {
        self.margin_blocks_for_groups_with_floor(k, k, 1, cfg, true)
    }
    fn margin_blocks_for_groups_with_floor(
        &self,
        k: u64,
        whole_message_k: u64,
        groups: usize,
        cfg: &AdaptiveFecConfig,
        burst_tail: bool,
    ) -> u64 {
        let cap = ((k as f64 * cfg.max_redundancy).ceil() as u64).max(1);
        let prior = if self.seen < 4096 {
            cfg.initial_loss
        } else {
            cfg.min_loss
        };
        let message_eps = if burst_tail {
            self.target_failure(whole_message_k, cfg)
        } else {
            RESCUE_LATENCY_TAIL
        };
        let eps = message_eps / groups.max(1) as f64;
        let floor = if burst_tail { 12.min(k) } else { 0 };
        let mut r = repair_blocks(
            k,
            prior,
            z_for_eps(eps),
            eps,
            cfg.extra_blocks,
            cfg.max_redundancy,
        )
        .max(floor)
        .min(cap);
        for _ in 0..32 {
            let Some(q) = self.tail_losses(k + r, eps) else {
                break;
            };
            let next = r
                .max(q.saturating_add(cfg.extra_blocks as u64).max(1))
                .min(cap);
            if next == r {
                break;
            }
            r = next;
        }
        r
    }
}
#[derive(Clone, Debug)]
pub(crate) struct FecAdaptiveState {
    pub tracker: LossTracker,
    pub policy: RepairPolicy,
    last_finalized: u64,
    last_lost: u64,
    pub p: f64,
    span: Box<SpanLossProfile>,
    base_parity: bool,
    budget_base: bool,
    repair_cap_percent: u32,
    cost_smooth: bool,
    target_validation: u32,
    empirical_tail: bool,
    data_generation: u64,
    diagnostic_created_ns: u64,
    base_now_ns: u64,
    base_horizon: Option<u64>,
}
impl FecAdaptiveState {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        initialize_research_policy().expect("invalid transport research policy");
        let tracker = LossTracker::new(cfg, now_ns);
        FecAdaptiveState {
            tracker,
            policy: RepairPolicy::selected(),
            last_finalized: 0,
            last_lost: 0,
            p: tracker.estimate().max(cfg.min_loss),
            span: Box::new(SpanLossProfile::default()),
            base_parity: research_p4_base_parity_model() == 1,
            budget_base: research_p4_budget_base() == 1,
            repair_cap_percent: research_p4_repair_cap_percent(),
            empirical_tail: research_p4_empirical_tail_calibration() == 1,
            cost_smooth: research_p4_cost_smooth() == 1,
            target_validation: research_p4_target_validation(),
            data_generation: {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
            base_now_ns: now_ns,
            base_horizon: None,
            diagnostic_created_ns: now_ns,
        }
    }
    pub fn on_tick(&mut self, now_ns: u64) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        let finalized = self.span.seen;
        let lost = self.span.lost_total;
        self.tracker.on_tick(
            now_ns,
            finalized - self.last_finalized,
            lost - self.last_lost,
        );
        self.last_finalized = finalized;
        self.last_lost = lost;
        self.p = if self.policy == RepairPolicy::Reliability {
            self.tracker.estimate().max(self.tracker.cfg.min_loss)
        } else {
            self.tracker.mean
        };
    }
    pub fn on_data_sent(&mut self, seq: u64) {
        self.span.on_data_sent(seq);
    }
    pub fn on_sequence_finalized(&mut self, seq: u64, lost: bool, now_ns: u64) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        self.span
            .on_sequence_finalized(seq, lost, now_ns, self.tracker.cfg.window_ns);
    }
    pub fn group_failure_target(&self, whole_message_k: u64, groups: usize) -> f64 {
        let c = &self.tracker.cfg;
        self.span.target_failure(whole_message_k, c) / groups.max(1) as f64
    }
    pub fn repair_blocks(&self, k: u64) -> u64 {
        self.repair_blocks_for_group(k, k, 1)
    }
    pub fn repair_blocks_for_group(&self, k: u64, whole_message_k: u64, groups: usize) -> u64 {
        self.repair_blocks_for_group_at_tail(k, whole_message_k, groups, true)
    }
    pub fn repair_blocks_for_group_at_tail(
        &self,
        k: u64,
        whole_message_k: u64,
        groups: usize,
        burst_tail: bool,
    ) -> u64 {
        if matches!(
            self.policy,
            RepairPolicy::Streaming | RepairPolicy::MessageBound
        ) {
            return 2.min(k);
        }
        if self.policy != RepairPolicy::Reliability {
            return mean_repairs(k, self.p);
        }
        let c = &self.tracker.cfg;
        let span = &self.span;
        let horizon = if span.seen >= 4096 {
            k.min(span.pending_peak.max(1))
        } else {
            k
        };
        let cap = ((k as f64 * c.max_redundancy).ceil() as u64).max(1).min(k);
        let r = span.margin_blocks_for_groups_with_floor(
            horizon,
            whole_message_k,
            groups,
            c,
            burst_tail,
        );
        r.max(if burst_tail { 12.min(k) } else { 0 }).min(cap)
    }
    pub fn extra_repair_blocks_needed_now(
        &self,
        k: u64,
        blocks_sent: u64,
        repair_blocks_sent: u64,
        own_declared_lost: u64,
    ) -> u64 {
        self.extra_repair_blocks_needed_for_group(
            k,
            k,
            1,
            blocks_sent,
            repair_blocks_sent,
            own_declared_lost,
        )
    }
    pub fn extra_repair_blocks_needed_for_group(
        &self,
        k: u64,
        whole_message_k: u64,
        groups: usize,
        blocks_sent: u64,
        repair_blocks_sent: u64,
        own_declared_lost: u64,
    ) -> u64 {
        self.extra_repair_blocks_needed_for_group_at_tail(
            k,
            whole_message_k,
            groups,
            blocks_sent,
            repair_blocks_sent,
            own_declared_lost,
            true,
        )
    }
    pub fn extra_repair_blocks_needed_for_group_at_tail(
        &self,
        k: u64,
        whole_message_k: u64,
        groups: usize,
        blocks_sent: u64,
        repair_blocks_sent: u64,
        own_declared_lost: u64,
        burst_tail: bool,
    ) -> u64 {
        let span = &self.span;
        if k == 0 {
            return 0;
        }
        let c = &self.tracker.cfg;
        let cap = ((k as f64 * c.max_redundancy).ceil() as u64).min(k);
        let floor = if burst_tail { 12.min(k) } else { 0 };
        let unsent_sources = k.saturating_sub(blocks_sent.saturating_sub(repair_blocks_sent));
        let pending = span
            .unresolved_data_packets()
            .saturating_add(unsent_sources);
        let mut total_repairs = own_declared_lost.saturating_add(floor).min(cap);
        for _ in 0..32 {
            let horizon = pending
                .saturating_add(total_repairs.saturating_sub(repair_blocks_sent))
                .min(k.saturating_add(total_repairs))
                .max(1);
            let margin = span
                .margin_blocks_for_groups_with_floor(
                    horizon,
                    whole_message_k,
                    groups,
                    c,
                    burst_tail,
                )
                .max(floor);
            let next = total_repairs
                .max(own_declared_lost.saturating_add(margin))
                .min(cap);
            if next == total_repairs {
                break;
            }
            total_repairs = next;
        }
        total_repairs.saturating_sub(repair_blocks_sent)
    }
    pub fn base_parity_active(&self) -> bool {
        self.base_parity && self.policy == RepairPolicy::MessageBound
    }
    pub fn budget_base_active(&self) -> bool {
        self.budget_base && self.policy == RepairPolicy::MessageBound
    }
    pub fn repair_cap_percent(&self) -> u32 {
        self.repair_cap_percent
    }
    pub(crate) fn target_selector(&self) -> u32 {
        self.target_validation
    }
    pub(crate) fn unresolved_data_packets(&self) -> u64 {
        self.span.unresolved_data_packets()
    }
    pub(crate) fn cost_smooth_active(&self) -> bool {
        self.cost_smooth && self.budget_base_active()
    }
    pub fn data_anchor(&self) -> (u64, u64) {
        (self.data_generation, self.span.sent_total)
    }
    pub fn budget_unresolved_span(&self, anchor: Option<(u64, u64)>, own: u64) -> (u64, bool) {
        match anchor {
            Some((generation, a))
                if generation == self.data_generation && a <= self.span.sent_total =>
            {
                (
                    self.span
                        .sent_total
                        .saturating_sub(self.span.seen.max(a))
                        .max(own)
                        .saturating_add(1),
                    false,
                )
            }
            _ => (
                self.span
                    .unresolved_data_packets()
                    .max(own)
                    .saturating_add(1),
                true,
            ),
        }
    }
    fn empirical_tail_active(&self) -> bool {
        self.empirical_tail
    }
    pub fn budget_tail_repairs(
        &self,
        kg: u64,
        start: u64,
        d: u64,
        rs: u64,
        ug: u64,
        eps: f64,
        uc: u64,
    ) -> (u64, bool) {
        self.budget_tail_impl(
            kg,
            start,
            d,
            rs,
            ug,
            if self.empirical_tail_active() {
                eps * 10.0
            } else {
                eps
            },
            eps,
            uc,
            None,
        )
    }
    pub fn budget_tail_for_codecs(
        &self,
        kg: u64,
        start: u64,
        d: u64,
        rs: u64,
        ug: u64,
        codecs: usize,
        uc: u64,
        whole_k: u64,
        capture: Option<&mut DemandCapture>,
    ) -> (u64, bool) {
        if self.cost_smooth_active() {
            return self.cost_tail(kg, whole_k, start, d, rs, ug, codecs, uc, capture);
        }
        self.budget_tail_impl(
            kg,
            start,
            d,
            rs,
            ug,
            if self.empirical_tail_active() {
                0.01 / codecs.max(1) as f64
            } else {
                base_group_eps(codecs)
            },
            base_group_eps(codecs),
            uc,
            capture,
        )
    }
    fn cost_target(
        &self,
        whole_k: u64,
        codecs: usize,
        known_multi: bool,
    ) -> Option<(f64, f64, u64)> {
        if !self.p.is_finite()
            || !(0.0..1.0).contains(&self.p)
            || !self.tracker.cfg.min_loss.is_finite()
            || !(0.0..1.0).contains(&self.tracker.cfg.min_loss)
        {
            return None;
        }
        let p = self.p.max(self.tracker.cfg.min_loss);
        if p == 0.0 || whole_k == 0 || whole_k > u32::MAX as u64 {
            return None;
        }
        let h = self.base_horizon.unwrap_or(whole_k).max(1) as f64;
        let eps = (p / (1.0 + whole_k as f64 / h) / codecs.max(1) as f64).clamp(1e-12, 0.5);
        // Wirehair documents ~.02 mean extra symbols, not a worst-case bound. Model a geometric rank-risk prior .02 per
        // extra equation, weighted by >=2 erasures; first repair is XOR and every sampled single erasure decodes
        // without a reserve. This is an ASSUMED rank-tail heuristic, not a calibrated tail or bound. Native fixtures do
        // NOT establish this geometric distribution.
        let zero = (1.0 - p).powf(whole_k as f64);
        let one = whole_k as f64 * p * (1.0 - p).powf(whole_k.saturating_sub(1) as f64);
        let multi = (1.0 - zero - one).clamp(0.0, 1.0);
        let empirical_multi = self
            .span
            .tail_losses_now(
                whole_k,
                eps * 0.5,
                self.base_now_ns,
                self.tracker.cfg.window_ns,
            )
            .is_some_and(|q| q >= 2);
        let mut rank_risk = 0.02
            * if known_multi || empirical_multi {
                1.0
            } else {
                multi
            };
        let mut reserve = 0;
        while rank_risk > eps * 0.5 && reserve < 16 {
            rank_risk *= 0.02;
            reserve += 1;
        }
        Some((eps, p, reserve))
    }
    fn cost_tail(
        &self,
        kg: u64,
        whole_k: u64,
        start: u64,
        d: u64,
        rs: u64,
        ug: u64,
        codecs: usize,
        uc: u64,
        mut capture: Option<&mut DemandCapture>,
    ) -> (u64, bool) {
        let fail = |capture: Option<&mut DemandCapture>| {
            let known = start.max(d);
            let retained = if kg <= u32::MAX as u64 && known <= u32::MAX as u64 - kg {
                known
            } else {
                start
            };
            #[cfg(feature = "research_budget_diagnostic")]
            if let Some(c) = capture {
                c.header.flags |= 8 | 16;
                c.header.result_r = retained.min(u32::MAX as u64) as u32;
            }
            (retained, true)
        };
        if kg == 0 {
            return if start == 0 && d == 0 {
                (0, false)
            } else {
                fail(capture)
            };
        }
        let Some((eps, p, rank)) = self.cost_target(whole_k, codecs, d >= 2) else {
            return fail(capture);
        };
        let Some(limit) = (u32::MAX as u64).checked_sub(kg) else {
            return fail(capture);
        };
        if start > limit {
            return fail(capture);
        }
        #[cfg(feature = "research_budget_diagnostic")]
        if let Some(c) = capture.as_deref_mut() {
            c.header.eps_e = eps * 0.5;
            c.header.eps_i = eps * 0.5;
            c.header.iid_p = p;
            c.header.query_now_ns = self.base_now_ns;
        }
        let mut r = start;
        for i in 0..BASE_ITER_LIMIT {
            let e = r.saturating_sub(rs);
            let Some(n) = uc.checked_add(e) else {
                return fail(capture);
            };
            if n > u32::MAX as u64 {
                return fail(capture);
            }
            let (empirical, scale, samples) = self.span.tail_losses_now_details(
                n,
                eps * 0.5,
                self.base_now_ns,
                self.tracker.cfg.window_ns,
            );
            let iid = if p <= 0.9 {
                iid_count_quantile(n, p, eps * 0.5)
            } else if n <= EXACT_MAX_K {
                let (mut lo, mut hi) = (0, n);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if 1.0 - binomial_tail(n, 1.0 - p, n - mid) <= eps * 0.5 {
                        hi = mid;
                    } else {
                        lo = mid + 1;
                    }
                }
                lo
            } else {
                let z = z_for_eps(eps * 0.5);
                (n as f64 * p
                    + z * (n as f64 * p * (1.0 - p)).sqrt()
                    + ((z * z - 1.0) * (1.0 - 2.0 * p) / 6.0).max(0.0))
                .ceil()
                .min(n as f64) as u64
            };
            let selected = empirical.unwrap_or(0).max(iid).min(n);
            let Some(exposure) = ug.checked_add(e) else {
                return fail(capture);
            };
            let speculative = exposure.min(selected).saturating_add(rank);
            let Some(want) = d.checked_add(speculative) else {
                return fail(capture);
            };
            let next = r.max(want);
            #[cfg(feature = "research_budget_diagnostic")]
            if let Some(c) = capture.as_deref_mut() {
                if i < crate::budget_diagnostic::DEMAND_ITERATION_LIMIT && next <= limit {
                    c.iterations[i] = crate::budget_diagnostic::DemandIteration {
                        r,
                        e,
                        n,
                        samples,
                        empirical: empirical.unwrap_or(0),
                        iid,
                        selected,
                        next_r: next as u32,
                        scale,
                        flags: u16::from(empirical.is_some()) | if next == r { 2 } else { 0 },
                    };
                    c.header.iterations_count = (i + 1) as u8;
                    c.header.result_r = next as u32;
                } else {
                    c.header.flags |= 16;
                }
            }
            if next > limit {
                return fail(capture);
            }
            if next == r {
                return (r, false);
            }
            r = next;
        }
        fail(capture)
    }
    fn budget_tail_impl(
        &self,
        kg: u64,
        start: u64,
        d: u64,
        rs: u64,
        ug: u64,
        eps_e: f64,
        eps_i: f64,
        uc: u64,
        mut capture: Option<&mut DemandCapture>,
    ) -> (u64, bool) {
        #[cfg(feature = "research_budget_diagnostic")]
        if let Some(c) = capture.as_deref_mut() {
            let h = &mut c.header;
            h.adaptive_generation = self.data_generation;
            h.adaptive_created_ns = self.diagnostic_created_ns;
            h.ns = self.base_now_ns;
            h.query_now_ns = self.base_now_ns;
            h.s = self.span.sent_total;
            h.f = self.span.seen;
            h.eps_e = eps_e;
            h.eps_i = eps_i;
            h.iid_p = if self.span.seen < 4096 {
                self.tracker.cfg.initial_loss
            } else {
                self.tracker.cfg.min_loss
            };
        }
        let mut r = start.min(kg);
        for _iteration in 0..BASE_ITER_LIMIT {
            let e = r.saturating_sub(rs);
            let n = uc.saturating_add(e);
            let (selected, _empirical, _iid, _scale, _samples) =
                self.budget_count_details(n, eps_e, eps_i);
            let future = ug.saturating_add(e).min(selected);
            let want = r.max(d.saturating_add(2).saturating_add(future));
            let next = want.min(kg);
            #[cfg(feature = "research_budget_diagnostic")]
            if let Some(c) = capture.as_deref_mut() {
                if _iteration < crate::budget_diagnostic::DEMAND_ITERATION_LIMIT
                    && next <= u32::MAX as u64
                {
                    c.iterations[_iteration] = crate::budget_diagnostic::DemandIteration {
                        r,
                        e,
                        n,
                        samples: _samples,
                        empirical: _empirical.unwrap_or(0),
                        iid: _iid,
                        selected,
                        next_r: next as u32,
                        scale: _scale,
                        flags: u16::from(_empirical.is_some())
                            | if next == r { 2 } else { 0 }
                            | if want > kg { 4 } else { 0 }
                            | if _iteration + 1 == BASE_ITER_LIMIT && next != r {
                                8
                            } else {
                                0
                            },
                    };
                    c.header.iterations_count = (_iteration + 1) as u8;
                } else {
                    c.header.flags |= 16;
                }
                c.header.result_r = next.min(u32::MAX as u64) as u32;
                c.header.flags = (c.header.flags & !4) | if want > kg { 4 } else { 0 };
            }
            if next == r {
                return (r, want > kg);
            }
            r = next;
        }
        #[cfg(feature = "research_budget_diagnostic")]
        if let Some(c) = capture {
            c.header.result_r = kg.min(u32::MAX as u64) as u32;
            c.header.flags |= 8 | 16;
        }
        (kg, true)
    }
    fn budget_count_details(
        &self,
        n: u64,
        eps_e: f64,
        eps_i: f64,
    ) -> (u64, Option<u64>, u64, u16, u64) {
        if n == 0 {
            return (0, None, 0, 0, 0);
        }
        let c = &self.tracker.cfg;
        let prior = if self.span.seen < 4096 {
            c.initial_loss
        } else {
            c.min_loss
        };
        let (empirical, scale, samples) =
            self.span
                .tail_losses_now_details(n, eps_e, self.base_now_ns, c.window_ns);
        let iid = iid_count_quantile(n, prior, eps_i);
        (
            empirical.unwrap_or(0).max(iid).min(n),
            empirical,
            iid,
            scale,
            samples,
        )
    }
    pub fn set_base_context(&mut self, now_ns: u64, rate_upps: u64, timeout_ns: Option<u64>) {
        self.base_now_ns = self.base_now_ns.max(now_ns);
        self.base_horizon = timeout_ns
            .map(|t| {
                (rate_upps as u128 * t as u128)
                    .div_ceil(1_000_000_000_000_000)
                    .min(u64::MAX as u128) as u64
            })
            .filter(|&h| h > 0);
    }
    pub fn base_horizon(&self) -> Option<u64> {
        self.base_horizon
    }
    pub fn base_count_quantile(&self, n: u64, eps: f64) -> u64 {
        self.budget_count_details(n, eps, eps).0
    }
    pub fn base_initial_repairs(&self, kg: u64, eps: f64) -> (u64, bool) {
        let h = self.base_horizon.map_or(kg, |h| h.min(kg));
        let mut b = 2.min(kg);
        for _ in 0..BASE_ITER_LIMIT {
            let want =
                b.max(2u64.saturating_add(self.base_count_quantile(h.saturating_add(b), eps)));
            let next = want.min(kg);
            if next == b {
                return (b, want > kg);
            }
            b = next;
        }
        (kg, true)
    }
    pub fn base_tail_repairs(
        &self,
        kg: u64,
        start: u64,
        d: u64,
        rs: u64,
        ug: u64,
        eps: f64,
    ) -> (u64, bool) {
        self.budget_tail_impl(
            kg,
            start,
            d,
            rs,
            ug,
            eps,
            eps,
            self.span.unresolved_data_packets(),
            None,
        )
    }
    pub fn representative_ppm(&self) -> u32 {
        (self.repair_blocks(1000) * 1000).clamp(1, 1_000_000) as u32
    }
}
#[cfg(feature = "research_budget_diagnostic")]
#[doc(hidden)]
pub fn research_demand_fixture(
    k: u32,
    start: u32,
    d: u32,
    rs: u32,
    ug: u64,
    uc: u64,
    codecs: usize,
    selector: u32,
    created_ns: u64,
    now_ns: u64,
    outcomes: &[bool],
) -> crate::budget_diagnostic::Demand {
    assert!(
        selector <= 1 && created_ns <= now_ns && uc > 0 && uc <= 65536 && outcomes.len() <= 65536
    );
    let mut a = FecAdaptiveState::new(crate::ship::FEC, created_ns);
    a.empirical_tail = selector == 1;
    for (i, &lost) in outcomes.iter().enumerate() {
        a.on_data_sent(i as u64);
        a.on_sequence_finalized(i as u64, lost, now_ns);
    }
    for i in 0..uc - 1 {
        a.on_data_sent(outcomes.len() as u64 + i);
    }
    a.on_tick(now_ns);
    let mut c = crate::budget_diagnostic::Demand::default();
    c.header = crate::budget_diagnostic::DemandHeader {
        k,
        start,
        d,
        rs,
        ug,
        uc,
        codec_count: codecs as u32,
        ..Default::default()
    };
    a.budget_tail_for_codecs(
        k as u64,
        start as u64,
        d as u64,
        rs as u64,
        ug,
        codecs,
        uc,
        { k as u64 },
        Some(&mut c),
    );
    c
}
