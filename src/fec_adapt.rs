//! Adaptive FEC redundancy: a per-connection packet-loss estimate and the per-message number of
//! Wirehair blocks it implies.
//!
//! The sender feeds its own cumulative (packets_sent, packets_lost) counters into a
//! [`LossTracker`] once per network-thread tick. The tracker turns them into short-term loss
//! samples (one per `bucket_ns`, and only once `min_packets` were sent in the bucket, so a sample
//! is never a handful of packets), and an estimator turns the samples into a loss estimate that
//! latches up quickly and comes down slowly. Everything is O(1) per tick with small fixed memory
//! (16 max-hold slots and the span-tail sketch) and no allocation.
//!
//! [`repair_blocks`] picks, for a message of K source blocks, the smallest N with
//! P(fewer than K of N blocks arrive) <= eps under independent loss p.

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
    pub loss_delay_ns: u64,
}
impl Default for AdaptiveFecConfig {
    fn default() -> Self { crate::ship::FEC }
}
// Retainable messages have feedback rescue as a delivery backstop. Pre-sent parity
// targets a 2% chance of needing that extra RTT, not packet-loss-scale reliability.
const RESCUE_LATENCY_TAIL: f64 = 0.02;
const LOSS_SIGNAL_SNAPSHOT_NS: u64 = 50_000_000;
const LOSS_SIGNAL_RING: usize = 64;

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

/// Per-connection loss tracker: short-term buckets plus one estimator. Fixed size, no allocation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LossTracker {
    cfg: AdaptiveFecConfig,
    st: ShortTerm,
    ring: [(u64, f32); 16],
    have_sample: bool,
    last_sample: f64,
    cached: f64,
    last_refresh_ns: u64,
}

impl LossTracker {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64) -> Self {
        LossTracker { cfg, st: ShortTerm { start_ns: now_ns, sent: 0, lost: 0 }, ring: [(u64::MAX, 0.0); 16], have_sample: false, last_sample: 0.0, cached: cfg.initial_loss, last_refresh_ns: now_ns }
    }

    /// Feed counter deltas since the previous call. O(1) (refresh is a fixed 16-slot loop at
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
        let n = cfg.slots.clamp(1, 16);
        let idx = now_ns / cfg.slot_ns.max(1);
        let s = &mut self.ring[(idx % n as u64) as usize];
        if s.0 != idx { *s = (idx, 0.0); }
        s.1 = s.1.max(loss as f32);
        self.refresh(now_ns);
    }

    fn refresh(&mut self, now_ns: u64) {
        self.last_refresh_ns = now_ns;
        if !self.have_sample { return; }
        let cfg = self.cfg;
        let n = cfg.slots.clamp(1, 16) as u64;
        let idx = now_ns / cfg.slot_ns.max(1);
        self.cached = self.ring.iter().filter(|s| s.0 != u64::MAX && s.0 + n > idx).map(|s| s.1 as f64).fold(0.0, f64::max);
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
#[derive(Clone, Debug)]
pub(crate) struct SpanLossProfile {
    data_sent: [u64; crate::stp::PACKETS_WAITING_ACK_WORDS],
    history: [u64; 1024],
    counts: [u32; 16],
    hist: [[[u32; 64]; 16]; 2],
    epochs: [u64; 2],
    seen: u64,
    lost_total: u64,
    sent_total: u64,
    pending_peak: u64,
}
impl Default for SpanLossProfile {
    fn default() -> Self {
        Self { data_sent: [0; crate::stp::PACKETS_WAITING_ACK_WORDS], history: [0; 1024], counts: [0; 16], hist: [[[0; 64]; 16]; 2], epochs: [u64::MAX; 2], seen: 0, lost_total: 0, sent_total: 0, pending_peak: 0 }
    }
}
impl SpanLossProfile {
    fn bin(losses: u32) -> usize {
        if losses < 32 { return losses as usize; }
        let log = 31 - losses.leading_zeros();
        let base = 1u32 << log;
        32 + (log as usize - 5) * 2 + (losses > base + base / 2) as usize
    }
    fn upper(bin: usize) -> u64 {
        if bin < 32 { return bin as u64; }
        let base = 32u64 << ((bin - 32) / 2);
        if (bin - 32) % 2 == 0 { base + base / 2 } else { base * 2 }
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
        if self.epochs[h] != epoch { self.hist[h] = [[0; 64]; 16]; self.epochs[h] = epoch; }
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
        let pieces = n.div_ceil(65536).max(1);
        let n = n.div_ceil(pieces).max(2);
        let scale = (64 - (n - 1).leading_zeros() as usize).saturating_sub(1).min(15);
        let latest = self.epochs.iter().copied().filter(|x| *x != u64::MAX).max()?;
        let mut bins = [0u64; 64];
        for h in 0..2 {
            if self.epochs[h] != u64::MAX && self.epochs[h] + 1 >= latest {
                for (b, count) in bins.iter_mut().zip(self.hist[h][scale]) { *b += count as u64; }
            }
        }
        let total: u64 = bins.iter().sum();
        if total == 0 { return None; }
        let allowed_tail = (total as f64 * (eps / pieces as f64).clamp(0.0, 0.5)).floor() as u64;
        let rank = total - allowed_tail;
        let mut acc = 0;
        for (b, count) in bins.iter().enumerate() {
            acc += count;
            if acc >= rank { return Some(Self::upper(b) * pieces); }
        }
        None
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
    last_sent: u64,
    last_lost: u64,
    /// Net-of-spurious: (time, sent, declared lost) snapshots every LOSS_SIGNAL_SNAPSHOT_NS.
    ring: [(u64, u64, u64); LOSS_SIGNAL_RING],
    ring_head: usize,
    /// Floored loss estimate used for new messages.
    pub p: f64,
    /// Fixed size, independent of bandwidth and packet rate.
    span: Box<SpanLossProfile>,
}

impl FecAdaptiveState {
    pub fn new(cfg: AdaptiveFecConfig, now_ns: u64, sent: u64, lost: u64) -> Self {
        let tracker = LossTracker::new(cfg, now_ns);
        FecAdaptiveState { tracker, last_sent: sent, last_lost: lost, ring: [(now_ns, sent, lost); LOSS_SIGNAL_RING], ring_head: 0, p: tracker.estimate().max(cfg.min_loss), span: Box::new(SpanLossProfile::default()) }
    }
    /// Feed the connection's cumulative counters: packets sent, declared lost, and declarations
    /// found spurious so far.
    pub fn on_tick(&mut self, now_ns: u64, sent: u64, lost: u64, spurious: u64) {
        if now_ns.saturating_sub(self.ring[self.ring_head].0) >= LOSS_SIGNAL_SNAPSHOT_NS {
            self.ring_head = (self.ring_head + 1) % LOSS_SIGNAL_RING;
            self.ring[self.ring_head] = (now_ns, sent, lost);
        }
        // Net of spurious declarations, delayed so late ACKs can cancel false losses.
        let delay_ns = self.tracker.cfg.loss_delay_ns;
        let back = ((delay_ns + LOSS_SIGNAL_SNAPSHOT_NS - 1) / LOSS_SIGNAL_SNAPSHOT_NS).min(LOSS_SIGNAL_RING as u64 - 1) as usize;
        let (_, sent, lost) = self.ring[(self.ring_head + LOSS_SIGNAL_RING - back) % LOSS_SIGNAL_RING];
        let lost = lost.saturating_sub(spurious);
        // Monotone: a correction that arrives after its loss was consumed nets out of later losses.
        let (ds, dl) = (sent.saturating_sub(self.last_sent), lost.saturating_sub(self.last_lost));
        self.last_sent = self.last_sent.max(sent);
        self.last_lost = self.last_lost.max(lost);
        self.tracker.on_tick(now_ns, ds, dl);
        self.p = self.tracker.estimate().max(self.tracker.cfg.min_loss);
    }
    pub fn on_data_sent(&mut self, seq: u64) {
        self.span.on_data_sent(seq);
    }
    pub fn on_sequence_finalized(&mut self, seq: u64, lost: bool, now_ns: u64) {
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
        let cfg = AdaptiveFecConfig { slot_ns: 1_000_000_000, slots: 10, min_packets: 100, ..Default::default() };
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
    fn net_of_spurious_cancels_late_acked_declarations() {
        // 1% declared loss at 10k pps for 30 s, all of it found spurious ~200 ms later.
        let base = AdaptiveFecConfig { slot_ns: 1_000_000_000, slots: 10, min_packets: 100, ..Default::default() };
        let mut a = FecAdaptiveState::new(base, 0, 0, 0);
        for i in 1..=3000u64 {
            let t = i * 10_000_000;
            a.on_tick(t, i * 100, i, i.saturating_sub(20));
        }
        let net = a.tracker.estimate();
        assert!(net < 0.001, "{net}");
        // Genuine loss (never acked) still gets through, just 1 s later.
        let mut a = FecAdaptiveState::new(base, 0, 0, 0);
        for i in 1..=3000u64 { a.on_tick(i * 10_000_000, i * 100, i, 0); }
        assert!(a.tracker.estimate() > 0.009, "{}", a.tracker.estimate());
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
        assert!(std::mem::size_of::<SpanLossProfile>() < 50000);
    }

    #[test]
    fn rescue_latency_budget_ignores_rare_loss_blips() {
        let mut a = FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0);
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
        let mut a = FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0);
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
        let cfg = AdaptiveFecConfig { eps: 0.5, ..Default::default() };
        let mut a = FecAdaptiveState::new(cfg, 0, 0, 0);
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
        let limited = FecAdaptiveState::new(AdaptiveFecConfig { max_redundancy: 0.01, ..cfg }, 0, 0, 0);
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
        let mut a = FecAdaptiveState::new(cfg, 0, 0, 0);
        for i in n..n+1000 { s.on_data_sent(i); }
        a.span = Box::new(s);
        let now = std::time::Instant::now();
        for _ in 0..100000 { std::hint::black_box(a.extra_repair_blocks_needed_now(36613, 36613, 0, 20)); }
        println!("closed_loop_query_ns={:.2}", now.elapsed().as_nanos() as f64 / 100000.0);
    }
}
