//! Cumulative packet polynomials and bounded, confirmed execution history.
//! Absolute counters stay integer; floating point is used only for local curve deltas.
use std::collections::VecDeque;

pub const MAX_DEGREE: usize = 11;
pub const MAX_HISTORY_RECORDS: usize = 2048;
pub const MAX_LOCAL_COUNT: f64 = (1u64 << 48) as f64;

#[derive(Clone, Debug, PartialEq)]
pub enum CurveError {
    NonFinite,
    InvalidDuration,
    InvalidDegree,
    NegativeRate,
    CounterPrecision,
    Discontinuous,
}

/// Local cumulative packets, in powers of elapsed seconds. c[0] must be zero.
#[derive(Clone, Debug)]
pub struct PacketPolynomial {
    coefficients: Vec<f64>,
    duration_ns: u64,
}
impl PacketPolynomial {
    pub fn new(coefficients: Vec<f64>, duration_ns: u64) -> Result<Self, CurveError> {
        if duration_ns == 0 {
            return Err(CurveError::InvalidDuration);
        }
        if coefficients.len() < 2 || coefficients.len() > MAX_DEGREE + 1 {
            return Err(CurveError::InvalidDegree);
        }
        if coefficients.iter().any(|c| !c.is_finite()) {
            return Err(CurveError::NonFinite);
        }
        if coefficients[0] != 0.0 {
            return Err(CurveError::Discontinuous);
        }
        let p = Self {
            coefficients,
            duration_ns,
        };
        let d = p.rate_coefficients();
        let duration = duration_ns as f64 / 1e9;
        // All extrema of the derivative are checked, rather than accepting a
        // sampled curve that could run backwards between sample points.
        let mut extrema = roots(&derivative(&d), 0.0, duration);
        extrema.extend([0.0, duration]);
        if extrema.iter().any(|t| eval(&d, *t) < -1e-9) {
            return Err(CurveError::NegativeRate);
        }
        let total = p.count(duration_ns);
        if !total.is_finite() {
            return Err(CurveError::NonFinite);
        }
        if total < 0.0 || total > MAX_LOCAL_COUNT {
            return Err(CurveError::CounterPrecision);
        }
        Ok(p)
    }
    pub fn from_rate(rate: &[f64], duration_ns: u64) -> Result<Self, CurveError> {
        let mut c = vec![0.0];
        c.extend(rate.iter().enumerate().map(|(i, r)| r / (i + 1) as f64));
        Self::new(c, duration_ns)
    }
    pub fn duration_ns(&self) -> u64 {
        self.duration_ns
    }
    pub fn count(&self, elapsed_ns: u64) -> f64 {
        eval(
            &self.coefficients,
            elapsed_ns.min(self.duration_ns) as f64 / 1e9,
        )
    }
    pub fn rate(&self, elapsed_ns: u64) -> f64 {
        eval(
            &self.rate_coefficients(),
            elapsed_ns.min(self.duration_ns) as f64 / 1e9,
        )
        .max(0.0)
    }
    fn rate_coefficients(&self) -> Vec<f64> {
        derivative(&self.coefficients)
    }
    pub fn inverse(&self, count: f64) -> Option<u64> {
        if !count.is_finite() || count < 0.0 || count > self.count(self.duration_ns) + 1e-8 {
            return None;
        }
        let mut lo = 0;
        let mut hi = self.duration_ns;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.count(mid) >= count {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Some(lo)
    }
}

#[derive(Clone, Debug)]
pub struct PacketSchedule {
    pieces: Vec<PacketPolynomial>,
}
impl PacketSchedule {
    pub fn new(pieces: Vec<PacketPolynomial>) -> Result<Self, CurveError> {
        if pieces.is_empty() || pieces.len() > 128 {
            return Err(CurveError::InvalidDegree);
        }
        let count: f64 = pieces.iter().map(|p| p.count(p.duration_ns)).sum();
        if count > MAX_LOCAL_COUNT {
            return Err(CurveError::CounterPrecision);
        }
        if pieces
            .iter()
            .try_fold(0u64, |n, p| n.checked_add(p.duration_ns))
            .is_none()
        {
            return Err(CurveError::InvalidDuration);
        }
        Ok(Self { pieces })
    }
    pub fn constant(pps: f64, duration_ns: u64) -> Result<Self, CurveError> {
        Self::new(vec![PacketPolynomial::from_rate(&[pps], duration_ns)?])
    }
    pub fn pieces(&self) -> &[PacketPolynomial] {
        &self.pieces
    }
    pub fn duration_ns(&self) -> u64 {
        self.pieces.iter().map(|p| p.duration_ns).sum()
    }
    pub fn count(&self, mut elapsed: u64) -> f64 {
        let mut n = 0.0;
        for p in &self.pieces {
            n += p.count(elapsed);
            if elapsed <= p.duration_ns {
                break;
            }
            elapsed -= p.duration_ns;
        }
        n
    }
    pub fn rate(&self, mut elapsed: u64) -> f64 {
        for p in &self.pieces {
            if elapsed <= p.duration_ns {
                return p.rate(elapsed);
            }
            elapsed -= p.duration_ns;
        }
        0.0
    }
    pub fn inverse(&self, mut count: f64) -> Option<u64> {
        if !count.is_finite() || count < 0.0 {
            return None;
        }
        let mut elapsed = 0;
        for p in &self.pieces {
            let n = p.count(p.duration_ns);
            if count <= n + 1e-8 {
                return p.inverse(count.min(n)).map(|t| elapsed + t);
            }
            count -= n;
            elapsed += p.duration_ns;
        }
        None
    }
}

pub(crate) fn eval(c: &[f64], t: f64) -> f64 {
    c.iter().rev().fold(0.0, |n, c| n * t + c)
}
pub(crate) fn derivative(c: &[f64]) -> Vec<f64> {
    c.iter()
        .enumerate()
        .skip(1)
        .map(|(i, c)| *c * i as f64)
        .collect()
}
/// Isolate real polynomial roots using the derivative's extrema (degree <= 10).
pub(crate) fn roots(c: &[f64], lo: f64, hi: f64) -> Vec<f64> {
    let mut c = c.to_vec();
    while c.last() == Some(&0.0) {
        c.pop();
    }
    if c.len() <= 1 {
        return vec![];
    }
    if c.len() == 2 {
        let r = -c[0] / c[1];
        return if r > lo && r < hi { vec![r] } else { vec![] };
    }
    let mut points = vec![lo];
    points.extend(roots(&derivative(&c), lo, hi));
    points.push(hi);
    let mut out = vec![];
    for w in points.windows(2) {
        let (mut a, mut b) = (w[0], w[1]);
        let fa = eval(&c, a);
        let fb = eval(&c, b);
        if fa == 0.0 && a > lo {
            out.push(a);
        }
        if fa.signum() == fb.signum() {
            continue;
        }
        for _ in 0..64 {
            let m = (a + b) * 0.5;
            if eval(&c, m).signum() == fa.signum() {
                a = m;
            } else {
                b = m;
            }
        }
        out.push((a + b) * 0.5);
    }
    out.sort_by(|a, b| a.total_cmp(b));
    out.dedup_by(|a, b| (*a - *b).abs() < 1e-10);
    out
}
pub(crate) fn shift(c: &[f64], offset: f64) -> Vec<f64> {
    let mut out = vec![0.0; c.len()];
    for (i, value) in c.iter().enumerate() {
        let mut choose = 1.0;
        for (j, o) in out.iter_mut().enumerate().take(i + 1) {
            *o += value * choose * offset.powi((i - j) as i32);
            choose *= (i - j) as f64 / (j + 1) as f64;
        }
    }
    out
}

/// Convert the existing pps controller to cumulative pieces, splitting at phase,
/// linear-cap and floor crossings. Coefficients are local (seconds, packets), not
/// absolute counters, so nonce precision does not depend on the age of a connection.
pub fn controller_schedule(
    t_ns: u64,
    r_upps: u64,
    k_ns: u64,
    cc: &crate::stp::CongestionControlOptions,
    horizon_ns: u64,
) -> Result<PacketSchedule, CurveError> {
    if k_ns == 0 {
        return PacketSchedule::constant(r_upps.max(cc.rate_floor_upps) as f64 / 1e6, horizon_ns);
    }
    let k = k_ns as f64 / 1e9;
    let r = r_upps as f64 / 1e6;
    let growth = cc.min_growth_uppsps / 1e6;
    let cap_slope = cc.max_growth_uppsps / 1e6;
    let p_start = k;
    let g_start = cc.time_pg * k;
    let s_start = cc.time_gs * k;
    let p_slope = r * (cc.rate_pg - cc.rate_rp) / (g_start - p_start);
    let g_span = s_start - g_start;
    let a = (r * (cc.rate_gs - cc.rate_pg) - p_slope * g_span) / g_span.powi(2);
    let start = t_ns as f64 / 1e9;
    let end = start + horizon_ns as f64 / 1e9;
    let mut phases = vec![start];
    phases.extend(
        [p_start, g_start, s_start]
            .into_iter()
            .filter(|t| *t > start && *t < end),
    );
    phases.push(end);
    let mut pieces = Vec::new();
    let mut emitted_ns = 0;
    for w in phases.windows(2) {
        let t = w[0];
        let (origin, mut rate, cap) = if t < p_start {
            let drop = r * (cc.rate_rp - cc.beta);
            (
                0.0,
                vec![r * cc.beta, 2.0 * drop / k + growth, -drop / k.powi(2)],
                None,
            )
        } else if t < g_start {
            (
                p_start,
                vec![r * cc.rate_rp + growth * p_start, p_slope + growth],
                Some(vec![
                    r * cc.rate_rp + growth * t + cap_slope * (t - p_start),
                    cap_slope + growth,
                ]),
            )
        } else if t < s_start {
            (
                g_start,
                vec![r * cc.rate_pg + growth * g_start, p_slope + growth, a],
                Some(vec![
                    r + growth * t + cap_slope * (t - p_start),
                    cap_slope + growth,
                ]),
            )
        } else {
            let mut v = vec![0.0; 11];
            v[0] = r * cc.rate_gs + growth * s_start;
            v[1] = p_slope + 2.0 * a * g_span + growth;
            v[10] = r * (1.0 - cc.beta) * 10.0 / (3.0 * k).powi(10);
            (
                s_start,
                v,
                Some(vec![
                    r + growth * t + cap_slope * (t - p_start),
                    cap_slope + growth,
                ]),
            )
        };
        rate = shift(&rate, t - origin);
        let duration = w[1] - t;
        let floor = cc.rate_floor_upps as f64 / 1e6;
        let mut boundaries = vec![0.0, duration];
        let mut floor_diff = rate.clone();
        floor_diff[0] -= floor;
        boundaries.extend(roots(&floor_diff, 0.0, duration));
        if let Some(cap) = &cap {
            let mut diff = rate.clone();
            for (i, c) in cap.iter().enumerate() {
                diff[i] -= c;
            }
            boundaries.extend(roots(&diff, 0.0, duration));
            let mut diff = cap.clone();
            diff[0] -= floor;
            boundaries.extend(roots(&diff, 0.0, duration));
        }
        boundaries.sort_by(|a, b| a.total_cmp(b));
        boundaries.dedup_by(|a, b| (*a - *b).abs() < 1e-12);
        for b in boundaries.windows(2) {
            let midpoint = (b[0] + b[1]) * 0.5;
            let capped = cap
                .as_ref()
                .is_some_and(|c| eval(c, midpoint) < eval(&rate, midpoint));
            let selected = if capped { cap.as_ref().unwrap() } else { &rate };
            let local = if eval(selected, midpoint) < floor {
                vec![floor]
            } else {
                shift(selected, b[0])
            };
            // Round absolute boundaries once: rounded durations still sum to horizon exactly.
            let stop_ns = (((t - start + b[1]) * 1e9).round() as u64).min(horizon_ns);
            if stop_ns > emitted_ns {
                pieces.push(PacketPolynomial::from_rate(&local, stop_ns - emitted_ns)?);
                emitted_ns = stop_ns;
            }
        }
    }
    PacketSchedule::new(pieces)
}

pub const HISTORY_TIME_NS: u64 = 10_000_000_000;
pub const CONTROLLER_HORIZON_NS: u64 = 500_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    QueueEmpty,
    InFlight,
    CpuLate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopPoint {
    pub time_ns: u64,
    pub completed: u64,
    pub reason: StopReason,
}

/// A confirmed sequence interval on one cumulative curve. One record per batch,
/// never per packet. Flat pieces have an empty sequence interval.
#[derive(Clone, Debug)]
pub struct ExecutionRecord {
    pub first_sequence: u64,
    pub end_sequence: u64,
    pub start_ns: u64,
    pub end_ns: u64,
    pub origin_ns: u64,
    pub base_sequence: u64,
    pub count_offset: f64,
    pub schedule: std::sync::Arc<PacketSchedule>,
    pub stop: Option<StopReason>,
}
#[derive(Debug, Default)]
pub struct ExecutionHistory {
    records: VecDeque<ExecutionRecord>,
}
impl ExecutionHistory {
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn records(&self) -> &VecDeque<ExecutionRecord> {
        &self.records
    }
    fn push(&mut self, record: ExecutionRecord, now: u64) {
        if record.first_sequence == record.end_sequence {
            if let Some(last) = self
                .records
                .back_mut()
                .filter(|r| r.stop == record.stop && r.first_sequence == r.end_sequence)
            {
                last.end_ns = record.end_ns;
                self.evict(now);
                return;
            }
        }
        if let Some(last) = self.records.back_mut().filter(|r| {
            r.stop.is_none()
                && record.stop.is_none()
                && r.end_sequence == record.first_sequence
                && r.origin_ns == record.origin_ns
                && r.base_sequence == record.base_sequence
                && r.count_offset == record.count_offset
                && std::sync::Arc::ptr_eq(&r.schedule, &record.schedule)
        }) {
            // Without per-batch actual timestamp corrections, adjacent executed
            // intervals on the same curve are exactly one invertible segment.
            last.end_sequence = record.end_sequence;
            last.end_ns = record.end_ns;
        } else {
            self.records.push_back(record);
        }
        self.evict(now);
    }
    fn evict(&mut self, now: u64) {
        while self.records.len() > MAX_HISTORY_RECORDS
            || self
                .records
                .front()
                .is_some_and(|r| r.end_ns < now.saturating_sub(HISTORY_TIME_NS))
        {
            self.records.pop_front();
        }
    }
    pub fn lookup(&self, sequence: u64) -> Option<u64> {
        let index = self.records.partition_point(|r| r.end_sequence <= sequence);
        let r = self.records.get(index)?;
        if sequence < r.first_sequence || r.stop.is_some() {
            return None;
        }
        let count = (sequence.checked_sub(r.base_sequence)? + 1) as f64 - r.count_offset;
        r.schedule
            .inverse(count)
            .and_then(|t| r.origin_ns.checked_add(t))
    }
}

/// Synchronous adapter for STP's existing network thread. Curve replacements
/// preserve fractional credit; starvation truncates at the *inverse* stop point.
#[derive(Debug)]
pub struct CurvePacer {
    pub history: ExecutionHistory,
    pub stop: Option<StopPoint>,
    schedule: std::sync::Arc<PacketSchedule>,
    origin_ns: u64,
    base_sequence: u64,
    count_offset: f64,
    last_tick_ns: u64,
    key: (u64, u64, u64, bool),
    first_sequence: u64,
    pub allowance: u64,
    // Diagnostics are streaming aggregates; no debug timestamp table either.
    pub error_samples: u64,
    pub error_abs_sum_ns: u64,
    pub error_max_ns: u64,
}
impl CurvePacer {
    pub fn new(now: u64, sequence: u64) -> Self {
        Self {
            history: ExecutionHistory::default(),
            stop: Some(StopPoint {
                time_ns: now,
                completed: sequence,
                reason: StopReason::QueueEmpty,
            }),
            schedule: std::sync::Arc::new(
                PacketSchedule::constant(0.0, CONTROLLER_HORIZON_NS).unwrap(),
            ),
            origin_ns: now,
            base_sequence: sequence,
            count_offset: 0.0,
            last_tick_ns: now,
            key: (0, 0, 0, false),
            first_sequence: sequence,
            allowance: 0,
            error_samples: 0,
            error_abs_sum_ns: 0,
            error_max_ns: 0,
        }
    }
    fn flat_until(&mut self, now: u64) {
        if let Some(stop) = self.stop {
            self.history.push(
                ExecutionRecord {
                    first_sequence: stop.completed,
                    end_sequence: stop.completed,
                    start_ns: stop.time_ns,
                    end_ns: now.max(stop.time_ns),
                    origin_ns: stop.time_ns,
                    base_sequence: stop.completed,
                    count_offset: 0.0,
                    schedule: std::sync::Arc::new(
                        PacketSchedule::constant(0.0, now.saturating_sub(stop.time_ns).max(1))
                            .unwrap(),
                    ),
                    stop: Some(stop.reason),
                },
                now,
            );
        }
    }
    /// Drop accumulated execution debt, just like queue starvation. The inverse
    /// of the last completed count closes the rising piece; the following flat
    /// ends at now and begin() resumes from (now, sequence). A time-domain
    /// tolerance works across variable pps and never allocates per-packet state.
    pub fn stop_if_late(&mut self, now: u64, sequence: u64, tolerance_ns: u64) -> bool {
        if self.stop.is_some() {
            return false;
        }
        let count = (sequence - self.base_sequence) as f64 - self.count_offset;
        let completed_ns = self.origin_ns + self.schedule.inverse(count.max(0.0)).unwrap_or(0);
        if now.saturating_sub(completed_ns) <= tolerance_ns {
            return false;
        }
        self.stop = Some(StopPoint {
            time_ns: completed_ns,
            completed: sequence,
            reason: StopReason::CpuLate,
        });
        self.flat_until(now);
        self.last_tick_ns = now;
        true
    }
    pub fn begin(
        &mut self,
        now: u64,
        sequence: u64,
        has_work: bool,
        key: (u64, u64, u64, bool),
        schedule: impl FnOnce(u64) -> PacketSchedule,
    ) -> u64 {
        self.history.evict(now);
        self.first_sequence = sequence;
        if self.stop.is_some() {
            self.flat_until(now);
            if !has_work {
                self.allowance = 0;
                return 0;
            }
            self.schedule = std::sync::Arc::new(schedule(now));
            self.origin_ns = now;
            self.base_sequence = sequence;
            self.count_offset = 0.0;
            self.stop = None;
            self.key = key;
        } else if key != self.key
            || now.saturating_sub(self.origin_ns) >= self.schedule.duration_ns()
        {
            // End the predecessor at the last confirmed execution boundary. Its
            // unexecuted phase belongs to the successor (not to unsent packets).
            let fraction = (self.count_offset
                + self
                    .schedule
                    .count(self.last_tick_ns.saturating_sub(self.origin_ns))
                - (sequence - self.base_sequence) as f64)
                .clamp(0.0, 1.0);
            self.schedule = std::sync::Arc::new(schedule(self.last_tick_ns));
            self.origin_ns = self.last_tick_ns;
            self.base_sequence = sequence;
            self.count_offset = fraction;
            self.key = key;
        }
        let target = self.base_sequence
            + (self.count_offset + self.schedule.count(now.saturating_sub(self.origin_ns))).floor()
                as u64;
        self.first_sequence = sequence;
        self.allowance = target.saturating_sub(sequence);
        self.allowance
    }
    /// Estimate an in-progress send directly from its curve. Used only for
    /// measurement; RTT and loss lookups use confirmed history after finish().
    pub fn observe_send(&mut self, sequence: u64, actual_ns: u64) {
        let count = (sequence - self.base_sequence + 1) as f64 - self.count_offset;
        if let Some(elapsed) = self.schedule.inverse(count) {
            let error = actual_ns.abs_diff(self.origin_ns + elapsed);
            self.error_samples += 1;
            self.error_abs_sum_ns = self.error_abs_sum_ns.saturating_add(error);
            self.error_max_ns = self.error_max_ns.max(error);
        }
    }
    pub fn finish(&mut self, now: u64, sequence: u64, reason: Option<StopReason>) {
        if self.stop.is_some() {
            self.last_tick_ns = now;
            return;
        }
        let count = (sequence - self.base_sequence) as f64 - self.count_offset;
        let stop_ns = self.origin_ns + self.schedule.inverse(count.max(0.0)).unwrap_or(0);
        if sequence > self.first_sequence {
            self.history.push(
                ExecutionRecord {
                    first_sequence: self.first_sequence,
                    end_sequence: sequence,
                    start_ns: self.last_tick_ns,
                    end_ns: stop_ns,
                    origin_ns: self.origin_ns,
                    base_sequence: self.base_sequence,
                    count_offset: self.count_offset,
                    schedule: self.schedule.clone(),
                    stop: None,
                },
                now,
            );
        }
        if let Some(reason) = reason {
            self.stop = Some(StopPoint {
                time_ns: stop_ns,
                completed: sequence,
                reason,
            });
            self.flat_until(now);
        }
        self.last_tick_ns = now;
    }
    /// ACK nonces are not rate controlled (like the precise baseline). Skip them
    /// without giving away earned paced slots; empty sequence intervals cannot
    /// steal a data packet's inverse. ACKs themselves are never RTT sampled.
    pub fn skip_ack(&mut self) {
        self.base_sequence += 1;
        self.first_sequence += 1;
        if let Some(stop) = &mut self.stop {
            stop.completed += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eval_inverse_and_validation() {
        let p = PacketPolynomial::from_rate(&[2.0, 4.0, 3.0], 2_000_000_000).unwrap();
        assert_eq!(p.count(1_000_000_000), 5.0);
        assert_eq!(p.inverse(5.0), Some(1_000_000_000));
        assert_eq!(p.rate(1_000_000_000), 9.0);
        for t in (0..2_000_000_000).step_by(1_234_567) {
            assert!(p.inverse(p.count(t)).unwrap().abs_diff(t) <= 1);
        }
        assert_eq!(
            PacketPolynomial::from_rate(&[0.2499, -1.0, 1.0], 1_000_000_000).unwrap_err(),
            CurveError::NegativeRate
        );
        assert!(PacketPolynomial::from_rate(&[f64::NAN], 1).is_err());
        assert!(PacketPolynomial::from_rate(&[1e20], 1_000_000_000).is_err());
    }
    #[test]
    fn starvation_flat_resume_and_ack_gap() {
        let mut p = CurvePacer::new(0, 9);
        let schedule = |_| PacketSchedule::constant(600.0, CONTROLLER_HORIZON_NS).unwrap();
        assert_eq!(p.begin(0, 9, true, (1, 1, 1, false), schedule), 0);
        p.finish(0, 9, None);
        assert_eq!(p.begin(10_000_000, 9, true, (1, 1, 1, false), schedule), 6);
        p.finish(10_000_000, 13, Some(StopReason::QueueEmpty));
        assert_eq!(p.stop.unwrap().time_ns, 6_666_667);
        assert_eq!(p.history.lookup(12), Some(6_666_667));
        for now in (20_000_000..100_000_000).step_by(1_000_000) {
            assert_eq!(p.begin(now, 13, false, (1, 1, 1, false), schedule), 0);
            p.finish(now, 13, Some(StopReason::QueueEmpty));
            assert!(p.history.len() <= 3);
        }
        assert_eq!(
            p.begin(100_000_000, 13, true, (1, 1, 1, false), schedule),
            0
        );
        p.finish(100_000_000, 13, None);
        p.skip_ack(); // sequence 13 is an ACK, sequence 14 is next data.
        assert_eq!(
            p.begin(110_000_000, 14, true, (1, 1, 1, false), schedule),
            6
        );
        p.finish(110_000_000, 20, None);
        assert_eq!(p.history.lookup(13), None);
        assert_eq!(p.history.lookup(14), Some(101_666_667));
        assert!(
            p.history
                .records()
                .iter()
                .any(|r| r.stop.is_some() && r.start_ns == 6_666_667 && r.end_ns == 100_000_000)
        );
    }
    #[test]
    fn history_bounds_time_and_high_absolute_counters() {
        let base = (1u64 << 54) + 1;
        let mut p = CurvePacer::new(0, base);
        let schedule = |_| PacketSchedule::constant(1000.0, CONTROLLER_HORIZON_NS).unwrap();
        let key = (1, 1, 1, false);
        p.begin(0, base, true, key, schedule);
        p.finish(0, base, None);
        for i in 1..5000 {
            let now = i * 1_000_000;
            // Force controller replacement every tick to exercise the hard cap,
            // independently of the coalescing fast path.
            assert_eq!(
                p.begin(now, base + i - 1, true, (i, 1, 1, false), schedule),
                1
            );
            p.finish(now, base + i, None);
            assert!(p.history.len() <= MAX_HISTORY_RECORDS);
        }
        assert_eq!(p.history.lookup(base), None);
        assert_eq!(p.history.lookup(base + 4998), Some(4_999_000_000));
        p.begin(20_000_000_000, base + 4999, false, key, schedule);
        assert!(p.history.is_empty());
    }
    #[test]
    fn coalescing_is_independent_of_packet_rate_and_cadence() {
        for pps in [1000u64, 1_000_000] {
            let mut p = CurvePacer::new(0, 0);
            let schedule = |_| PacketSchedule::constant(pps as f64, CONTROLLER_HORIZON_NS).unwrap();
            let key = (1, 1, 1, false);
            p.begin(0, 0, true, key, schedule);
            p.finish(0, 0, None);
            for i in 1..=1000 {
                let seq = (i - 1) * pps / 1000;
                assert_eq!(p.begin(i * 1_000_000, seq, true, key, schedule), pps / 1000);
                p.finish(i * 1_000_000, seq + pps / 1000, None);
            }
            assert!(
                p.history.len() <= 4,
                "{} records at {pps} pps",
                p.history.len()
            );
            assert_eq!(p.history.lookup(pps - 1), Some(1_000_000_000));
            assert_eq!(p.history.lookup(0), Some(1_000_000_000 / pps));
        }
    }
    #[test]
    fn fractional_credit_survives_controller_replacements() {
        let mut p = CurvePacer::new(0, 0);
        let schedule = |_| PacketSchedule::constant(100.5, CONTROLLER_HORIZON_NS).unwrap();
        p.begin(0, 0, true, (0, 1, 1, false), schedule);
        p.finish(0, 0, None);
        let mut sequence = 0;
        for i in 1..=100 {
            sequence += p.begin(i * 10_000_000, sequence, true, (i, 1, 1, false), schedule);
            assert_eq!(sequence, (i as f64 * 1.005).floor() as u64);
            p.finish(i * 10_000_000, sequence, None);
        }
        assert_eq!(sequence, 100);
    }
    #[test]
    fn flat_polynomial_piece_has_no_packets() {
        let s = PacketSchedule::new(vec![
            PacketPolynomial::from_rate(&[2.0], 1_000_000_000).unwrap(),
            PacketPolynomial::from_rate(&[0.0], 1_000_000_000).unwrap(),
            PacketPolynomial::from_rate(&[2.0], 1_000_000_000).unwrap(),
        ])
        .unwrap();
        assert_eq!(s.count(1_500_000_000), 2.0);
        assert_eq!(s.inverse(2.0), Some(1_000_000_000));
        assert_eq!(s.inverse(3.0), Some(2_500_000_000));
        assert_eq!(s.rate(1_500_000_000), 0.0);
    }
    #[test]
    fn cpu_debt_stops_at_completed_count_and_resumes_at_now() {
        let mut p = CurvePacer::new(0, 0);
        let schedule = |_| PacketSchedule::constant(1000.0, CONTROLLER_HORIZON_NS).unwrap();
        let key = (1, 1, 1, false);
        p.begin(0, 0, true, key, schedule);
        p.finish(0, 0, None);
        assert_eq!(p.begin(2_000_000, 0, true, key, schedule), 2);
        p.finish(2_500_000, 2, None);
        assert!(!p.stop_if_late(4_000_000, 2, 4_000_000));
        // CPU stalls 18 ms. Never send the 18-packet catch-up burst.
        assert!(p.stop_if_late(20_000_000, 2, 4_000_000));
        assert_eq!(
            p.stop.unwrap(),
            StopPoint {
                time_ns: 2_000_000,
                completed: 2,
                reason: StopReason::CpuLate,
            }
        );
        assert_eq!(p.history.lookup(1), Some(2_000_000));
        assert_eq!(p.begin(20_000_000, 2, true, key, schedule), 0);
        p.finish(20_000_000, 2, None);
        assert_eq!(p.begin(22_000_000, 2, true, key, schedule), 2);
        p.observe_send(2, 22_000_000);
        p.observe_send(3, 22_500_000);
        p.finish(22_500_000, 4, None);
        assert_eq!(p.history.lookup(2), Some(21_000_000));
        assert_eq!(p.error_max_ns, 1_000_000);
        assert!(
            p.history
                .records()
                .iter()
                .any(|r| r.stop == Some(StopReason::CpuLate)
                    && r.start_ns == 2_000_000
                    && r.end_ns == 20_000_000)
        );
        // A partial CPU-budgeted execution truncates the curve too.
        assert_eq!(p.begin(24_000_000, 4, true, key, schedule), 2);
        p.finish(26_000_000, 5, Some(StopReason::CpuLate));
        assert_eq!(p.stop.unwrap().time_ns, 23_000_000);
        assert_eq!(p.history.lookup(4), Some(23_000_000));
        assert_eq!(p.begin(26_000_000, 5, true, key, schedule), 0);
    }
    #[test]
    fn controller_derivative_matches_pps_across_phases_caps_floor() {
        for cc in [
            crate::stp::CongestionControlOptions::legacy(),
            crate::stp::CongestionControlOptions::balanced(),
            crate::stp::CongestionControlOptions {
                rate_floor_upps: 800_000_000,
                initial_rate_upps: 1_000_000_000,
                ..crate::stp::CongestionControlOptions::legacy()
            },
        ] {
            for k in [1_000_000, 30_000_000, 1_800_000_000] {
                for t in [0, k / 2, k, k * 2, k * 5, k * 15, k * 20, k * 30] {
                    let s = controller_schedule(t, 1_000_000_000, k, &cc, CONTROLLER_HORIZON_NS)
                        .unwrap();
                    assert_eq!(s.duration_ns(), CONTROLLER_HORIZON_NS);
                    for dt in (1..CONTROLLER_HORIZON_NS).step_by(997_001) {
                        let expected =
                            crate::stp::cubic_rate_with_options(t + dt, 1_000_000_000, k, &cc)
                                .0
                                .max(cc.rate_floor_upps) as f64
                                / 1e6;
                        assert!(
                            (s.rate(dt) - expected).abs() < expected * 1e-6 + 0.01,
                            "t={t} dt={dt} k={k} got={} expected={expected}",
                            s.rate(dt)
                        );
                    }
                }
            }
        }
    }
}
