//! Adaptive FEC redundancy: a per-connection packet-loss estimate and the per-message number of
//! Wirehair blocks it implies.
//!
//! The sender feeds its own cumulative (packets_sent, packets_lost) counters into a
//! [`LossTracker`] once per network-thread tick. The tracker turns them into short-term loss
//! samples (one per `bucket_ns`, and only once `min_packets` were sent in the bucket, so a sample
//! is never a handful of packets), and an estimator turns the samples into a loss estimate that
//! latches up quickly and comes down slowly. Everything is O(1) per tick with small fixed memory
//! (V1: 16 slots, V3: 2 x 32 bins) and no allocation.
//!
//! [`repair_blocks`] picks, for a message of K source blocks, the smallest N with
//! P(fewer than K of N blocks arrive) <= eps under independent loss p.

/// Which estimator turns short-term loss samples into the loss estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossEstimatorKind {
    /// V1 tiered max-hold: a ring of `slots` per-interval maxima (`slot_ns` each); estimate = max of
    /// the ring. A spike latches the estimate up at once and expires `slots * slot_ns` later,
    /// falling to the highest remaining slot.
    TieredMaxHold,
    /// V2 peak follower: est = max(sample, est decayed with half-life `half_life_ns`).
    PeakDecay,
    /// V3 high quantile: `quantile` of the samples of the last 1-2 half-windows (`window_ns / 2`
    /// each), from two fixed 32-bin log-spaced histograms.
    Quantile,
}

#[derive(Clone, Copy, Debug)]
pub struct AdaptiveFecConfig {
    pub kind: LossEstimatorKind,
    /// Target probability that a message cannot be decoded (given the loss estimate is right).
    pub eps: f64,
    /// Lower bound on the loss rate used for sizing (the estimate is never trusted below this).
    pub min_loss: f64,
    /// Loss rate assumed before the first sample.
    pub initial_loss: f64,
    /// Upper bound on repair blocks as a fraction of K (1.0 = 100%).
    pub max_redundancy: f64,
    /// Repair blocks always added on top of the formula, for Wirehair's own decoding overhead
    /// (it needs K + 0.02 blocks on average). The total is never below 1 repair block.
    pub extra_blocks: u32,
    /// Short-term loss bucket: closes after this long AND `min_packets` sent.
    pub bucket_ns: u64,
    pub min_packets: u64,
    /// V1: slot length and slot count (hold = slots * slot_ns). slots <= 16.
    pub slot_ns: u64,
    pub slots: usize,
    /// V2: half-life of the decay.
    pub half_life_ns: u64,
    /// V3: window (two half-window histograms) and quantile.
    pub window_ns: u64,
    pub quantile: f64,
    /// Add repair blocks to the message being sent when its own packets are declared lost
    /// (receivers do not need N, so a message can grow while it is sent).
    pub topup: bool,
    /// What the tracker consumes; see [`LossSignal`].
    pub loss_signal: LossSignal,
}

/// The loss count fed to the estimator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossSignal {
    /// The sender's declared losses as they happen (unacked after ~2 RTT), spurious ones included.
    Declared,
    /// Declared losses minus those later found spurious (an ack arrived for the packet after
    /// all), with the counters delayed by `delay_ns` so a late ack can cancel its declaration
    /// before the loss reaches the estimator. delay_ns <= 3 s (LOSS_SIGNAL_RING x 50 ms).
    NetOfSpurious { delay_ns: u64 },
}
pub const LOSS_SIGNAL_SNAPSHOT_NS: u64 = 50_000_000;
pub const LOSS_SIGNAL_RING: usize = 64;

impl Default for AdaptiveFecConfig {
    fn default() -> Self {
        AdaptiveFecConfig {
            kind: LossEstimatorKind::TieredMaxHold,
            eps: 1e-6,
            min_loss: 0.005,
            initial_loss: 0.01,
            max_redundancy: 1.0,
            extra_blocks: 1,
            bucket_ns: 1_000_000_000,
            min_packets: 500,
            slot_ns: 60_000_000_000,
            slots: 10,
            half_life_ns: 180_000_000_000,
            window_ns: 600_000_000_000,
            quantile: 0.97,
            topup: false,
            loss_signal: LossSignal::NetOfSpurious { delay_ns: 1_000_000_000 },
        }
    }
}

impl AdaptiveFecConfig {
    /// Scales every time constant by `f` (tests and benchmarks run with shortened clocks).
    pub fn scale_time(mut self, f: f64) -> Self {
        let s = |x: u64| ((x as f64 * f) as u64).max(1);
        self.slot_ns = s(self.slot_ns);
        self.half_life_ns = s(self.half_life_ns);
        self.window_ns = s(self.window_ns);
        self
    }
}

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

/// Repair blocks for a message of `k` source blocks under loss estimate `p` (already floored).
pub fn repair_blocks(k: u64, p: f64, z: f64, eps: f64, extra: u32, max_redundancy: f64) -> u64 {
    let r = min_repair_blocks(k, p, z, eps) + extra as u64;
    let cap = ((k as f64 * max_redundancy).ceil() as u64).max(1);
    r.clamp(1, cap)
}

/// Accumulates sent/lost deltas into short-term loss samples.
#[derive(Clone, Copy, Debug)]
struct ShortTerm { start_ns: u64, sent: u64, lost: u64 }

#[derive(Clone, Copy, Debug)]
enum Est {
    /// (slot index, max loss in slot) ring.
    V1 { ring: [(u64, f32); 16] },
    V2 { est: f64, at_ns: u64 },
    /// Per half-window: sample counts per log bin, and the largest sample seen in each bin.
    V3 { hist: [[u32; 32]; 2], bmax: [[f64; 32]; 2], half: [u64; 2] },
}

const V3_LO: f64 = 1e-3;
const V3_HI: f64 = 0.5;
fn v3_bin(loss: f64) -> usize {
    if loss < V3_LO { return 0; }
    let f = (loss / V3_LO).ln() / (V3_HI / V3_LO).ln(); // 0..1 over [LO, HI]
    (1 + (f * 30.0).floor() as i64).clamp(1, 31) as usize
}
/// Upper edge of a bin (bin 0 -> V3_LO).
#[cfg(test)]
fn v3_upper(bin: usize) -> f64 { V3_LO * (V3_HI / V3_LO).powf(bin as f64 / 30.0) }

/// Per-connection loss tracker: short-term buckets plus one estimator. Fixed size, no allocation.
#[derive(Clone, Copy, Debug)]
pub struct LossTracker {
    cfg: AdaptiveFecConfig,
    st: ShortTerm,
    est: Est,
    have_sample: bool,
    last_sample: f64,
    cached: f64,
    last_refresh_ns: u64,
}

impl LossTracker {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        let est = match cfg.kind {
            LossEstimatorKind::TieredMaxHold => Est::V1 { ring: [(u64::MAX, 0.0); 16] },
            LossEstimatorKind::PeakDecay => Est::V2 { est: 0.0, at_ns: now_ns },
            LossEstimatorKind::Quantile => Est::V3 { hist: [[0; 32]; 2], bmax: [[0.0; 32]; 2], half: [u64::MAX; 2] },
        };
        LossTracker { cfg, st: ShortTerm { start_ns: now_ns, sent: 0, lost: 0 }, est, have_sample: false, last_sample: 0.0, cached: cfg.initial_loss, last_refresh_ns: now_ns }
    }

    /// Feed counter deltas since the previous call. O(1) (V1/V3 refresh is a fixed 16/64 loop at
    /// most once per `bucket_ns`).
    pub fn on_tick(&mut self, now_ns: u64, sent_delta: u64, lost_delta: u64) {
        self.st.sent += sent_delta;
        self.st.lost += lost_delta;
        let elapsed = now_ns.saturating_sub(self.st.start_ns);
        if elapsed >= self.cfg.bucket_ns && self.st.sent >= self.cfg.min_packets.max(1) {
            let loss = (self.st.lost as f64 / self.st.sent as f64).min(1.0);
            self.st = ShortTerm { start_ns: now_ns, sent: 0, lost: 0 };
            self.on_sample(now_ns, loss);
        } else if self.st.sent < self.cfg.min_packets && elapsed >= self.cfg.bucket_ns && self.st.lost * 4 >= self.cfg.min_packets.max(4) {
            // A burst so large it is unambiguous even on a short sample: lost >= min_packets/4.
            let loss = (self.st.lost as f64 / self.st.sent.max(1) as f64).min(1.0);
            self.st = ShortTerm { start_ns: now_ns, sent: 0, lost: 0 };
            self.on_sample(now_ns, loss);
        } else if now_ns.saturating_sub(self.last_refresh_ns) >= self.cfg.bucket_ns {
            self.refresh(now_ns);
        }
    }

    fn on_sample(&mut self, now_ns: u64, loss: f64) {
        self.have_sample = true;
        self.last_sample = loss;
        let cfg = self.cfg;
        match &mut self.est {
            Est::V1 { ring } => {
                let n = cfg.slots.clamp(1, 16);
                let idx = now_ns / cfg.slot_ns.max(1);
                let s = &mut ring[(idx % n as u64) as usize];
                if s.0 != idx { *s = (idx, 0.0); }
                s.1 = s.1.max(loss as f32);
            }
            Est::V2 { est, at_ns } => {
                let dt = now_ns.saturating_sub(*at_ns) as f64;
                *est = loss.max(*est * (0.5f64).powf(dt / cfg.half_life_ns.max(1) as f64));
                *at_ns = now_ns;
            }
            Est::V3 { hist, bmax, half } => {
                let idx = now_ns / (cfg.window_ns / 2).max(1);
                let h = (idx % 2) as usize;
                if half[h] != idx { hist[h] = [0; 32]; bmax[h] = [0.0; 32]; half[h] = idx; }
                let b = v3_bin(loss);
                hist[h][b] += 1;
                bmax[h][b] = bmax[h][b].max(loss);
            }
        }
        self.refresh(now_ns);
    }

    fn refresh(&mut self, now_ns: u64) {
        self.last_refresh_ns = now_ns;
        if !self.have_sample { return; }
        let cfg = self.cfg;
        self.cached = match &self.est {
            Est::V1 { ring } => {
                let n = cfg.slots.clamp(1, 16) as u64;
                let idx = now_ns / cfg.slot_ns.max(1);
                ring.iter().filter(|s| s.0 != u64::MAX && s.0 + n > idx).map(|s| s.1 as f64).fold(0.0, f64::max)
            }
            Est::V2 { est, at_ns } => *est * (0.5f64).powf(now_ns.saturating_sub(*at_ns) as f64 / cfg.half_life_ns.max(1) as f64),
            Est::V3 { hist, bmax, half } => {
                let idx = now_ns / (cfg.window_ns / 2).max(1);
                let mut c = [0u32; 32];
                let mut m = [0f64; 32];
                let mut total = 0u64;
                for h in 0..2 {
                    if half[h] != u64::MAX && half[h] + 2 > idx {
                        for b in 0..32 { c[b] += hist[h][b]; m[b] = m[b].max(bmax[h][b]); total += hist[h][b] as u64; }
                    }
                }
                if total == 0 { 0.0 } else {
                    // Smallest bin whose cumulative count reaches quantile * total; the largest
                    // sample actually seen in it. (The bin's upper edge overstated the quantile by
                    // up to one bin width, 23%, e.g. a 7.8% sample read as 9.5%.)
                    let target = (cfg.quantile * total as f64).ceil().max(1.0) as u64;
                    let mut acc = 0u64;
                    let mut bin = 31;
                    for b in 0..32 { acc += c[b] as u64; if acc >= target { bin = b; break; } }
                    m[bin]
                }
            }
        };
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
    /// Loss rate the plan was sized for (after the floor); 0 for fixed redundancy.
    pub loss_estimate: f64,
    /// Own packets declared lost while the message was being sent.
    pub lost_during_send: u32,
}

/// Per-connection adaptive state: tracker plus counter baselines. Lives in UnreliableSendBuffer.
#[derive(Clone, Copy, Debug)]
pub struct FecAdaptiveState {
    pub tracker: LossTracker,
    z: f64,
    last_sent: u64,
    last_lost: u64,
    /// LossSignal::NetOfSpurious: (time, sent, declared lost) snapshots every LOSS_SIGNAL_SNAPSHOT_NS.
    ring: [(u64, u64, u64); LOSS_SIGNAL_RING],
    ring_head: usize,
    /// Floored loss estimate used for new messages.
    pub p: f64,
}

impl FecAdaptiveState {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64, sent: u64, lost: u64) -> Self {
        let tracker = LossTracker::new(cfg, now_ns);
        FecAdaptiveState { tracker, z: z_for_eps(cfg.eps), last_sent: sent, last_lost: lost, ring: [(now_ns, sent, lost); LOSS_SIGNAL_RING], ring_head: 0, p: tracker.estimate().max(cfg.min_loss) }
    }
    /// Feed the connection's cumulative counters: packets sent, declared lost, and declarations
    /// found spurious so far.
    pub fn on_tick(&mut self, now_ns: u64, sent: u64, lost: u64, spurious: u64) {
        let (sent, lost) = match self.tracker.cfg.loss_signal {
            LossSignal::Declared => (sent, lost),
            LossSignal::NetOfSpurious { delay_ns } => {
                if now_ns.saturating_sub(self.ring[self.ring_head].0) >= LOSS_SIGNAL_SNAPSHOT_NS {
                    self.ring_head = (self.ring_head + 1) % LOSS_SIGNAL_RING;
                    self.ring[self.ring_head] = (now_ns, sent, lost);
                }
                // Newest snapshot at least delay_ns old (the oldest one if none is).
                let back = ((delay_ns + LOSS_SIGNAL_SNAPSHOT_NS - 1) / LOSS_SIGNAL_SNAPSHOT_NS).min(LOSS_SIGNAL_RING as u64 - 1) as usize;
                let (_, s, l) = self.ring[(self.ring_head + LOSS_SIGNAL_RING - back) % LOSS_SIGNAL_RING];
                (s, l.saturating_sub(spurious))
            }
        };
        // Monotone: a correction that arrives after its loss was consumed nets out of later losses.
        let (ds, dl) = (sent.saturating_sub(self.last_sent), lost.saturating_sub(self.last_lost));
        self.last_sent = self.last_sent.max(sent);
        self.last_lost = self.last_lost.max(lost);
        self.tracker.on_tick(now_ns, ds, dl);
        self.p = self.tracker.estimate().max(self.tracker.cfg.min_loss);
    }
    /// Repair blocks for a new message of k source blocks.
    pub fn repair_blocks(&self, k: u64) -> u64 {
        let c = &self.tracker.cfg;
        repair_blocks(k, self.p, self.z, c.eps, c.extra_blocks, c.max_redundancy)
    }
    /// Total blocks for a message of k source blocks of which `lost` sent ones are known lost.
    pub fn topped_up_blocks(&self, k: u64, lost: u64, p_at_start: f64) -> u64 {
        let c = &self.tracker.cfg;
        let p = self.p.max(p_at_start);
        let r = repair_blocks(k + lost, p, self.z, c.eps, c.extra_blocks, c.max_redundancy * k as f64 / (k + lost) as f64);
        k + lost + r
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

    fn feed(t: &mut LossTracker, from_s: f64, to_s: f64, loss: f64, pps: u64) {
        // Ticks every 100 ms on exact integer times.
        for i in (from_s * 10.0).round() as u64..(to_s * 10.0).round() as u64 {
            let lost = (pps as f64 * 0.1 * loss).round() as u64;
            t.on_tick((i + 1) * 100_000_000, pps / 10, lost);
        }
    }

    #[test]
    fn v1_latches_and_steps_down() {
        let cfg = AdaptiveFecConfig { kind: LossEstimatorKind::TieredMaxHold, slot_ns: 1_000_000_000, slots: 10, min_packets: 100, ..Default::default() };
        let mut t = LossTracker::new(cfg, 0);
        feed(&mut t, 0.0, 5.0, 0.01, 1000);
        assert!((t.estimate() - 0.01).abs() < 1e-3);
        feed(&mut t, 5.0, 6.0, 0.05, 1000); // spike
        assert!((t.estimate() - 0.05).abs() < 2e-3, "spike: {} {}", t.estimate(), t.last_sample());
        feed(&mut t, 6.0, 15.5, 0.0, 1000);
        assert!((t.estimate() - 0.05).abs() < 2e-3, "held: {}", t.estimate());
        feed(&mut t, 15.5, 17.5, 0.0, 1000);
        assert!(t.estimate() < 0.011, "expired to next level: {}", t.estimate());
    }

    #[test]
    fn v2_decays() {
        let cfg = AdaptiveFecConfig { kind: LossEstimatorKind::PeakDecay, half_life_ns: 2_000_000_000, min_packets: 100, ..Default::default() };
        let mut t = LossTracker::new(cfg, 0);
        feed(&mut t, 0.0, 2.0, 0.04, 1000);
        assert!((t.estimate() - 0.04).abs() < 2e-3);
        feed(&mut t, 2.0, 6.05, 0.0, 1000);
        assert!((t.estimate() - 0.01).abs() < 2e-3, "{}", t.estimate());
    }

    #[test]
    fn v3_ignores_lone_spike_tracks_sustained() {
        let cfg = AdaptiveFecConfig { kind: LossEstimatorKind::Quantile, window_ns: 100_000_000_000, quantile: 0.95, min_packets: 100, ..Default::default() };
        let mut t = LossTracker::new(cfg, 0);
        feed(&mut t, 0.0, 40.0, 0.01, 1000);
        feed(&mut t, 40.0, 41.0, 0.08, 1000);
        feed(&mut t, 41.0, 45.0, 0.01, 1000);
        let e = t.estimate();
        assert!(e >= 0.01 && e < 0.013, "{e}");
        feed(&mut t, 45.0, 60.0, 0.04, 1000);
        let e = t.estimate();
        assert!(e >= 0.04 && e < 0.05, "{e}");
    }

    #[test]
    fn net_of_spurious_cancels_late_acked_declarations() {
        // 1% declared loss at 10k pps for 30 s, all of it found spurious ~200 ms later.
        let base = AdaptiveFecConfig { kind: LossEstimatorKind::TieredMaxHold, slot_ns: 1_000_000_000, slots: 10, min_packets: 100, ..Default::default() };
        let run = |signal: LossSignal| {
            let mut a = FecAdaptiveState::new(AdaptiveFecConfig { loss_signal: signal, ..base }, 0, 0, 0);
            for i in 1..=3000u64 {
                let t = i * 10_000_000;
                let (sent, lost) = (i * 100, i);
                let spurious = i.saturating_sub(20); // the ack shows up 20 ticks (200 ms) later
                a.on_tick(t, sent, lost, spurious);
            }
            a.tracker.estimate()
        };
        let declared = run(LossSignal::Declared);
        let net = run(LossSignal::NetOfSpurious { delay_ns: 1_000_000_000 });
        assert!(declared > 0.009, "{declared}");
        assert!(net < 0.001, "{net}");
        // Genuine loss (never acked) still gets through, just 1 s later.
        let mut a = FecAdaptiveState::new(AdaptiveFecConfig { loss_signal: LossSignal::NetOfSpurious { delay_ns: 1_000_000_000 }, ..base }, 0, 0, 0);
        for i in 1..=3000u64 { a.on_tick(i * 10_000_000, i * 100, i, 0); }
        assert!(a.tracker.estimate() > 0.009, "{}", a.tracker.estimate());
    }
}
