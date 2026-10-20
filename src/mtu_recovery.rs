//! Time-driven reachability recovery, independent of application message sizes.
//! Records are only consulted after native authenticated first-positive ACK admission.

pub(crate) const SMALL: u64 = 512;
pub(crate) const PERIOD: u64 = 250_000_000;

/// Boundary revalidation backoff; interior bracket refinement uses only the floor.
pub(crate) fn upward_retry_delay(failures: u64) -> u64 {
    (failures.min(11).pow(2) * PERIOD).clamp(500_000_000, 30_000_000_000)
}
const UPPER_LIFETIME: u64 = 30_000_000_000;
const MIN_GAIN: u64 = 8;

/// A settled boundary gets a sparse, RTT-aware recheck, independently of the
/// failures encountered while locating it. The generic RTT budget cannot be
/// inflated by the upward probe's own delayed receipt.
fn boundary_retry_delay(failures: u64, generic_budget: u64) -> u64 {
    generic_budget.max(5_000_000_000)
        .saturating_mul(1u64 << failures.min(3))
        .min(30_000_000_000)
}

/// An expired learned upper remains a useful *target* for a settled bracket,
/// not fresh promotion proof. Testing it directly avoids both a coarse-search
/// burst on a fixed cap and missing a partial path increase below the next rung.
fn settled_boundary_plan(current: u64, upper: u64, boundary_after: u64,
    hold: u64, last: u64) -> Option<(u64, u64)> {
    if upper <= current || upper - current > MIN_GAIN { return None; }
    Some((upper, boundary_after.max(hold)
        .max(last.saturating_add(upward_retry_delay(0)))))
}

/// Interior/coarse fallback shared by issuance and wakeups. Recovery intercepts
/// settled boundaries first; only an unsettled expired bound returns to coarse.
fn upward_plan(current: u64, upper: u64, until: u64, hold: u64,
    last: u64, failures: u64, now: u64) -> Option<(u64, u64)> {
    let coarse = [1452, 1472, 2048, 4096, 8192, 9216]
        .into_iter().find(|&size| size > current)?;
    if now < until && upper > current {
        if upper - current > MIN_GAIN {
            return Some((current + (upper - current) / 2,
                last.saturating_add(upward_retry_delay(0))));
        }
        return Some((coarse, until.max(hold)
            .max(last.saturating_add(upward_retry_delay(failures)))));
    }
    Some((coarse, hold.max(last.saturating_add(upward_retry_delay(failures)))))
}
const BASE_STALL: u64 = 1_000_000_000;
const MAX_STALL: u64 = 30_000_000_000;
const REPEATED: usize = 2;
const UPWARD_HOLD: u64 = 10_000_000_000;
const RECORDS: usize = 4096;
// Sixty-four seconds at four generic probes/s; covers the capped 32s window.
const GENERIC_RECORDS: usize = 256;
const PACKET_RECORDS: usize = RECORDS - GENERIC_RECORDS;
/// Heap storage charged in the connection's process-budget reservation.
pub(crate) const HISTORY_BYTES: usize = RECORDS * std::mem::size_of::<Sent>();

#[derive(Clone, Copy, Debug)]
struct Sent {
    sequence: u64,
    time: u64,
    bytes: u16,
    ordinary: bool,
    generic: bool,
    acknowledged: bool,
}
impl Sent {
    const EMPTY: Self = Self {
        sequence: u64::MAX,
        time: 0,
        bytes: 0,
        ordinary: false,
        generic: false,
        acknowledged: false,
    };
}

#[derive(Debug)]
pub(crate) struct Recovery {
    records: Box<[Sent]>,
    generic_cursor: usize,
    generic_count: usize,
    generic_srtt: u64,
    generic_rttvar: u64,
    pub(crate) next_probe: u64,
    probe_current: bool,
    pub(crate) upward_after: u64,
    recent_upper: u64,
    upper_until: u64,
    boundary_after: u64,
    boundary_failures: u64,
    last_large_progress: u64,
    startup: Startup,
}
/// RESEARCH: startup-only TU bootstrap. A new connection starts at SMALL and
/// offers one 1204 probe. Only that exact attempt's fresh accepted success
/// permits one prompt 1452 probe without the 500 ms floor. Nothing re-arms it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Startup { Candidate, Issued, Prompt, Done }
pub(crate) const STARTUP_TU: u64 = 1204;
const STARTUP_PROMPT_TU: u64 = 1452;
impl Recovery {
    /// The only constructor that arms the startup candidate.
    pub(crate) fn new_connection(now: u64) -> Self {
        Self { startup: Startup::Candidate, ..Self::new(now) }
    }
    pub(crate) fn new(now: u64) -> Self {
        Self {
            records: vec![Sent::EMPTY; RECORDS].into_boxed_slice(),
            generic_cursor: 0,
            generic_count: 0,
            generic_srtt: 0,
            generic_rttvar: 0,
            next_probe: now,
            probe_current: false,
            upward_after: 0,
            recent_upper: 0,
            upper_until: 0,
            boundary_after: 0,
            boundary_failures: 0,
            last_large_progress: now,
            startup: Startup::Done,
        }
    }
    pub(crate) fn sent(
        &mut self,
        sequence: u64,
        bytes: u64,
        now: u64,
        ordinary: bool,
        generic: bool,
    ) {
        debug_assert!(bytes <= u16::MAX as u64);
        let record = Sent {
            sequence,
            time: now,
            bytes: bytes as u16,
            ordinary,
            generic,
            acknowledged: false,
        };
        self.records[sequence as usize % PACKET_RECORDS] = record;
        if generic {
            self.records[PACKET_RECORDS + self.generic_cursor] = record;
            self.generic_cursor = (self.generic_cursor + 1) % GENERIC_RECORDS;
            self.generic_count = (self.generic_count + 1).min(GENERIC_RECORDS);
        }
    }
    // Generic nonces are monotonic even when ordinary traffic interleaves. Search
    // logical chronological order across the physical ring wrap, never all256
    // entries on a high-rate ordinary metadata miss.
    fn generic_index(&self, sequence: u64) -> Option<usize> {
        let oldest = if self.generic_count == GENERIC_RECORDS { self.generic_cursor } else { 0 };
        let (mut lo, mut hi) = (0, self.generic_count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let index = PACKET_RECORDS + (oldest + mid) % GENERIC_RECORDS;
            match self.records[index].sequence.cmp(&sequence) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(index),
            }
        }
        None
    }
    fn observe_generic_rtt(&mut self, raw: u64) {
        let sample = raw.max(100_000);
        if self.generic_srtt == 0 {
            self.generic_srtt = sample;
            self.generic_rttvar = sample / 2;
        } else {
            self.generic_rttvar = self.generic_rttvar.saturating_mul(3)
                .saturating_add(self.generic_srtt.abs_diff(sample)) / 4;
            self.generic_srtt = self.generic_srtt.saturating_mul(7).saturating_add(sample) / 8;
        }
    }
    fn stall_budget(&self) -> u64 {
        BASE_STALL.max(self.generic_srtt.saturating_add(self.generic_rttvar.saturating_mul(4)))
            .max(self.generic_srtt.saturating_mul(2)
                .saturating_add(crate::ship::ACK.max_delay_us as u64 * 1000))
            .min(MAX_STALL)
    }
    /// Exact emitted UDP payload size, including protected generic history.
    /// Unknown metadata cannot establish a size mismatch or positive proof.
    pub(crate) fn sent_bytes(&self, sequence: u64) -> Option<u16> {
        let record = &self.records[sequence as usize % PACKET_RECORDS];
        if record.sequence == sequence { return Some(record.bytes); }
        self.generic_index(sequence).map(|i| self.records[i].bytes)
    }
    pub(crate) fn is_generic(&self, sequence: u64) -> bool {
        let record = &self.records[sequence as usize % PACKET_RECORDS];
        if record.sequence == sequence { return record.generic; }
        self.generic_index(sequence).is_some()
    }
    pub(crate) fn probe_size(&self, current_tu: u64) -> u64 {
        if self.probe_current { current_tu } else { SMALL }
    }
    pub(crate) fn scheduled_probe_sent(&mut self, now: u64, bytes: u64) {
        self.next_probe = now.saturating_add(PERIOD);
        self.probe_current = bytes == SMALL;
    }
    pub(crate) fn large_stalled(&self, now: u64) -> bool {
        now.saturating_sub(self.last_large_progress) >= self.stall_budget()
    }
    pub(crate) fn can_promote(&self, bytes: u64, sent: u64, now: u64) -> bool {
        (now >= self.upward_after
            || (now < self.upper_until && bytes < self.recent_upper))
            && self.upward_fresh(sent, now)
    }
    pub(crate) fn upward_fresh(&self, sent: u64, now: u64) -> bool {
        sent != 0 && sent != u64::MAX
            && now.saturating_sub(sent) <= self.stall_budget().saturating_add(BASE_STALL)
    }
    pub(crate) fn upward_plan(&self, current: u64, last: u64, failures: u64,
        now: u64) -> Option<(u64, u64)> {
        let (size, due) = settled_boundary_plan(current, self.recent_upper, self.boundary_after,
            self.upward_after, last).or_else(|| {
                upward_plan(current, self.recent_upper, self.upper_until,
                    self.upward_after, last, failures, now)
            })?;
        Some(match self.startup {
            // Size only: the due is the ordinary first-issuance deadline.
            Startup::Candidate if current == SMALL && last == 0 => (STARTUP_TU, due),
            // One prompt rung once 1204 is actually effective; the hold still applies.
            Startup::Prompt if current == STARTUP_TU && size == STARTUP_PROMPT_TU =>
                (size, self.upward_after.max(last)),
            _ => (size, due),
        })
    }
    pub(crate) fn startup_state(&self) -> Startup { self.startup }
    /// RESEARCH adaptive units: the initial 1204 trial has neither succeeded nor
    /// failed yet. Done (cancel/outage/shrink) and Prompt both settle it.
    pub(crate) fn assessment_unresolved(&self) -> bool {
        matches!(self.startup, Startup::Candidate | Startup::Issued)
    }
    /// Call only when an attempt is actually being issued (after the due check).
    /// A Prompt is consumed by the next issuance whatever its cadence.
    pub(crate) fn upward_issued(&mut self, size: u64) {
        self.startup = if self.startup == Startup::Candidate && size == STARTUP_TU {
            Startup::Issued
        } else { Startup::Done };
    }
    /// Outcome of the issued attempt; only an accepted, fresh, promoted 1204 arms Prompt.
    pub(crate) fn upward_finished(&mut self, size: u64, promoted: bool) {
        if self.startup == Startup::Issued {
            self.startup = if promoted && size == STARTUP_TU { Startup::Prompt } else { Startup::Done };
        }
    }
    /// Outage entry clears probe identity without an outcome: no late proof may arm Prompt.
    pub(crate) fn startup_cancel(&mut self) { self.startup = Startup::Done; }
    fn arm_boundary(&mut self, current: u64, now: u64) {
        if self.recent_upper > current && self.recent_upper - current <= MIN_GAIN {
            if self.boundary_after == 0 {
                // Snapshot the independent RTT budget when arming. Later samples
                // neither postpone a due recheck forever nor create a hot wakeup.
                self.boundary_after = now.saturating_add(
                    boundary_retry_delay(self.boundary_failures, self.stall_budget()));
            }
        } else {
            self.boundary_after = 0;
            self.boundary_failures = 0;
        }
    }
    pub(crate) fn upward_failed(&mut self, current: u64, bytes: u64, now: u64) {
        if bytes <= current { return; }
        let boundary = self.boundary_after != 0 && bytes == self.recent_upper
            && self.recent_upper > current && self.recent_upper - current <= MIN_GAIN;
        self.recent_upper = if now < self.upper_until && self.recent_upper > current {
            self.recent_upper.min(bytes)
        } else { bytes };
        self.upper_until = now.saturating_add(UPPER_LIFETIME);
        if boundary {
            self.boundary_failures = self.boundary_failures.saturating_add(1);
            self.boundary_after = now.saturating_add(
                boundary_retry_delay(self.boundary_failures, self.stall_budget()));
        } else { self.arm_boundary(current, now); }
    }
    pub(crate) fn effective_tu(&mut self, old: u64, new: u64, now: u64) {
        if new < old {
            self.startup = Startup::Done;
            self.recent_upper = old;
            self.upper_until = now.saturating_add(UPPER_LIFETIME);
            self.boundary_after = 0;
            self.boundary_failures = 0;
        } else if new >= self.recent_upper {
            self.recent_upper = 0;
            self.upper_until = 0;
            self.boundary_after = 0;
            self.boundary_failures = 0;
        }
        self.arm_boundary(new, now);
    }
    /// Normal large ACKs take O(1). Only fresh small receipts scan bounded history.
    /// Ordinary historical loss and unconfirmed upward probes are not evidence.
    pub(crate) fn acknowledged(&mut self, sequence: u64, now: u64, current_tu: u64) -> bool {
        let record = &mut self.records[sequence as usize % PACKET_RECORDS];
        let mut sent = Sent::EMPTY;
        if record.sequence == sequence {
            sent = *record;
            *record = Sent::EMPTY;
        }
        if sent.generic || sent.sequence == u64::MAX {
            let Some(index) = self.generic_index(sequence) else {
                    // Exact metadata was overwritten. A native first positive
                    // might be healthy ordinary progress: it can only veto.
                    self.last_large_progress = now;
                    return false;
                };
            let record = &mut self.records[index];
            if record.acknowledged { return false; }
            sent = *record;
            // Keep positive generic evidence; first-positive admission stays exact.
            record.acknowledged = true;
            // Reject outside the absolute supported window before training: an
            // ancient withheld receipt cannot inflate a healthy path's budget.
            let raw = now.saturating_sub(sent.time);
            if raw > MAX_STALL + BASE_STALL { return false; }
            // Full accepted-send time, before adaptive freshness/classification.
            // Ordinary/upward receipts never train this independent RTT estimate.
            self.observe_generic_rtt(raw);
        }
        let stall = self.stall_budget();
        let max_proof_age = stall + BASE_STALL;
        if now.saturating_sub(sent.time) > max_proof_age {
            return false;
        }
        if sent.bytes as u64 > SMALL
            && (sent.ordinary || (sent.generic && sent.bytes as u64 == current_tu)) {
            self.last_large_progress = now;
            return false;
        }
        if sent.bytes as u64 != SMALL { return false; }
        self.ready(now, current_tu)
    }
    /// Recheck after the whole ACK: later samples may change the RTT budget,
    /// and later larger progress must veto every earlier small candidate.
    pub(crate) fn ready(&self, now: u64, current_tu: u64) -> bool {
        if current_tu <= SMALL || !self.large_stalled(now) { return false; }
        let stall = self.stall_budget();
        let max_proof_age = stall + BASE_STALL;
        let mut failures = 0;
        let mut small_positives = 0;
        for r in self.records[PACKET_RECORDS..].iter() {
            let age = now.saturating_sub(r.time);
            if r.sequence == u64::MAX || r.time <= self.last_large_progress {
                continue;
            }
            if r.acknowledged && r.bytes as u64 == SMALL && age <= max_proof_age {
                small_positives += 1;
            } else if !r.acknowledged && r.bytes as u64 == current_tu
                && (stall..=stall + 2 * BASE_STALL).contains(&age) {
                failures += 1;
            }
        }
        failures >= REPEATED && small_positives >= REPEATED
    }
    /// Commit only after the whole ACK has been admitted: large progress in the
    /// same bitmap must veto a small proof regardless of sequence ordering.
    pub(crate) fn downshifted(&mut self, now: u64) {
        self.upward_after = now.saturating_add(UPWARD_HOLD);
        self.records.fill(Sent::EMPTY);
        self.generic_cursor = 0;
        self.generic_count = 0;
        self.last_large_progress = now;
        self.startup = Startup::Done;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_pure_plan_is_sparse_rtt_aware_and_never_coarse() {
        const SEC: u64 = 1_000_000_000;
        for (budget, base) in [(SEC, 5 * SEC), (3 * SEC + 10_000_000, 5 * SEC),
            (5 * SEC + 10_000_000, 5 * SEC + 10_000_000)] {
            for (failures, expected) in [(0, base), (1, (base * 2).min(30 * SEC)),
                (2, (base * 4).min(30 * SEC)), (3, 30 * SEC), (u64::MAX, 30 * SEC)] {
                assert_eq!(boundary_retry_delay(failures, budget), expected);
            }
        }
        assert_eq!(boundary_retry_delay(u64::MAX, u64::MAX), 30 * SEC);
        assert_eq!(settled_boundary_plan(1068, 1076, 20 * SEC, 0, 15 * SEC),
            Some((1076, 20 * SEC)));
        assert_eq!(settled_boundary_plan(1068, 1076, 20 * SEC, 25 * SEC, 15 * SEC),
            Some((1076, 25 * SEC)));
        assert_eq!(settled_boundary_plan(1068, 1076, 20 * SEC, 0, 20 * SEC),
            Some((1076, 20 * SEC + 500_000_000)));
        assert_eq!(settled_boundary_plan(1068, 1076, 80 * SEC, 0, 50 * SEC),
            Some((1076, 80 * SEC)), "30s expiry cannot change a settled target to a coarse rung");
        assert_eq!(settled_boundary_plan(1068, 1077, 20 * SEC, 0, 0), None);
        assert_eq!(settled_boundary_plan(1068, 1068, 20 * SEC, 0, 0), None);
        assert_eq!(settled_boundary_plan(1068, 0, 20 * SEC, 0, 0), None);
        assert_eq!(settled_boundary_plan(1068, 1076, 0, 0, u64::MAX - 1),
            Some((1076, u64::MAX)));
    }
    #[test]
    fn boundary_clock_settles_once_and_counts_only_exact_boundary_failures() {
        const SEC: u64 = 1_000_000_000;
        for rtt in [20_000_000, 1_500_000_000, 2_500_000_000] {
            for settle_by_success in [false, true] {
                let mut r = Recovery::new(SEC);
                for _ in 0..64 { r.observe_generic_rtt(rtt); }
                let base = 5_000_000_000u64.max(r.stall_budget());
                r.effective_tu(1472, 1060, SEC);
                if settle_by_success {
                    r.upward_failed(1060, 1076, SEC + 1);
                    assert_eq!(r.boundary_after, 0);
                    r.effective_tu(1060, 1068, SEC + 2);
                } else { r.upward_failed(1068, 1076, SEC + 2); }
                let armed = SEC + 2 + base;
                assert_eq!(r.boundary_after, armed);
                assert_eq!(r.boundary_failures, 0);
                // Neither an ordinary send nor another interior floor gain
                // rearms the settled timer. Reads do not move its deadline.
                r.sent(1, 1068, SEC + 3, true, false);
                r.effective_tu(1068, 1070, SEC + 4);
                assert_eq!(r.boundary_after, armed);
                assert_eq!(r.upward_plan(1070, SEC, 100, armed), Some((1076, armed)));
                let mut sent = armed;
                for n in 1..=5u64 {
                    let declared = sent + 2 * rtt;
                    r.upward_failed(1070, 1076, declared);
                    assert_eq!(r.boundary_failures, n);
                    let due = declared + boundary_retry_delay(n, r.stall_budget());
                    assert_eq!(r.upward_plan(1070, sent, 100, due), Some((1076, due)));
                    assert_eq!(r.upward_plan(1070, sent, 100, due + 31 * SEC),
                        Some((1076, due)), "expiry must not replace settled revalidation");
                    sent = due;
                }
                // A small partial lift admits the old boundary; its exact proof
                // releases the search to coarse discovery, not the old ceiling.
                assert!(r.can_promote(1076, sent, sent + rtt));
                r.effective_tu(1070, 1076, sent + rtt);
                assert_eq!((r.recent_upper, r.boundary_after, r.boundary_failures), (0, 0, 0));
                assert_eq!(r.upward_plan(1076, sent, 0, sent + rtt).unwrap().0, 1452);
                r.effective_tu(1076, SMALL, sent + rtt + 1);
                assert_eq!((r.boundary_after, r.boundary_failures), (0, 0));
            }
        }
    }
    #[test]
    fn upward_plan_has_bounded_refinement_expiry_and_saturating_deadlines() {
        assert_eq!(upward_plan(1204, 0, 0, 0, 0, 0, 0), Some((1452, 500_000_000)));
        assert_eq!(upward_plan(1452, 0, 0, 0, 0, 0, 0).unwrap().0, 1472);
        assert_eq!(upward_plan(1472, 0, 0, 0, 0, 0, 0).unwrap().0, 2048);
        assert_eq!(upward_plan(512, 1472, 30_000_000_000, 10_000_000_000,
            0, 100, 0), Some((992, 500_000_000)));
        assert_eq!(upward_plan(1464, 1472, 30_000_000_000, 10_000_000_000,
            1, 100, 2), Some((1472, 30_000_000_001)));
        assert_eq!(upward_plan(1464, 1472, 30_000_000_000, 0,
            0, 0, 30_000_000_000), Some((1472, 500_000_000)));
        assert_eq!(upward_plan(9216, 0, 0, 0, 0, 0, 0), None);
        assert_eq!(upward_plan(512, 1204, u64::MAX, 0,
            u64::MAX - 1, 0, u64::MAX - 1), Some((858, u64::MAX)));
    }
    #[test]
    fn upward_upper_is_exclusive_temporary_and_resets_at_effective_tu() {
        let mut r = Recovery::new(1);
        r.downshifted(1);
        r.effective_tu(1472, SMALL, 2);
        assert!(r.can_promote(992, 2, 3));
        assert!(!r.can_promote(1472, 2, 3));
        r.upward_failed(SMALL, 1232, 4);
        r.upward_failed(SMALL, 1400, 5);
        assert_eq!((r.recent_upper, r.upper_until), (1232, 30_000_000_005));
        r.upward_failed(SMALL, SMALL, 6);
        assert_eq!((r.recent_upper, r.upper_until), (1232, 30_000_000_005));
        r.effective_tu(SMALL, 1112, 7);
        assert_eq!(r.recent_upper, 1232, "promotion retains useful bracket");
        assert_eq!(r.upward_plan(1112, 1, 100, 8).unwrap().0, 1172);
        assert_eq!(r.upward_plan(1112, 1, 100, 30_000_000_005).unwrap().0, 1452);
        r.effective_tu(1112, SMALL, 9);
        assert_eq!(r.recent_upper, 1112, "shrink seeds effective TU, not prior upper");
        r.effective_tu(SMALL, 1112, 10);
        assert_eq!((r.recent_upper, r.upper_until), (0, 0));
    }
    #[test]
    fn upward_confirmation_requires_fresh_exact_record_and_finished_hold() {
        let mut r = Recovery::new(0);
        assert!(r.can_promote(1452, 1, 2 * BASE_STALL + 1));
        assert!(!r.can_promote(1452, 1, 2 * BASE_STALL + 2));
        assert!(!r.can_promote(1452, 0, 1));
        assert!(!r.can_promote(1452, u64::MAX, 1));
        r.downshifted(1_000_000_000);
        assert!(!r.can_promote(1452, r.upward_after - 1, r.upward_after - 1));
        assert!(r.can_promote(1452, r.upward_after - 1, r.upward_after));
    }
    #[test]
    fn rtt_windows_preserve_20ms_baseline_and_do_not_self_justify_upward_age() {
        let start = 10_000_000_000;
        let mut r = Recovery::new(start);
        r.sent(0, SMALL, start + 1, false, true);
        assert!(!r.acknowledged(0, start + 20_000_001, 1204));
        assert_eq!(r.stall_budget(), BASE_STALL);
        assert!(!r.large_stalled(start + BASE_STALL - 1));
        assert!(r.large_stalled(start + BASE_STALL));
        assert!(r.can_promote(1452, start, start + 2 * BASE_STALL));
        assert!(!r.can_promote(1452, start, start + 2 * BASE_STALL + 1));
        assert!(!r.can_promote(1452, start, start + 2_500_000_000));
        let before = (r.generic_srtt, r.generic_rttvar);
        assert!(!r.acknowledged(0, start + 2_500_000_000, 1204), "duplicate cannot teach RTT");
        r.sent(1, 1204, start + 2, true, false);
        assert!(!r.acknowledged(1, start + 2_500_000_002, 1204));
        assert_eq!((r.generic_srtt, r.generic_rttvar), before, "ordinary does not train generic RTT");
        let mut slow = Recovery::new(start);
        slow.sent(0, SMALL, start, false, true);
        assert!(!slow.acknowledged(0, start + 2_500_000_000, 1204));
        assert_eq!(slow.stall_budget(), 7_500_000_000);
        assert!(slow.can_promote(1452, start + 1, start + 2_500_000_001));
    }

    #[test]
    fn rtt_generic_1500_and_2500ms_healthy_paths_and_real_size_blackholes() {
        use std::collections::VecDeque;
        for rtt in [1_500_000_000, 2_500_000_000] {
            for blackhole in [false, true] {
                let start = 10_000_000_000;
                let blackhole_at = start + 15_000_000_000;
                let mut r = Recovery::new(start);
                let mut pending = VecDeque::new();
                let mut decision = None;
                for tick in 0..240u64 {
                    let now = start + 1 + tick * PERIOD;
                    let size = r.probe_size(1204);
                    r.sent(tick, size, now, false, true);
                    r.scheduled_probe_sent(now, size);
                    if !blackhole || now < blackhole_at || size == SMALL {
                        pending.push_back((tick, now + rtt));
                    }
                    let mut proof = false;
                    while pending.front().is_some_and(|&(_, due)| due <= now) {
                        let (seq, _) = pending.pop_front().unwrap();
                        proof |= r.acknowledged(seq, now, 1204);
                    }
                    if proof && r.ready(now, 1204) {
                        decision = Some(now);
                        break;
                    }
                }
                if blackhole {
                    let when = decision.expect("fresh small proof plus aged current failures must recover");
                    assert!(when > blackhole_at + rtt);
                    assert!(when < blackhole_at + 20_000_000_000, "rtt={rtt} when={when}");
                } else {
                    assert!(decision.is_none(), "healthy rtt={rtt} cannot look like a size blackhole");
                }
            }
        }
    }

    #[test]
    fn rtt_budget_caps_at_30_seconds_and_keeps_finite_freshness_edges() {
        let mut r = Recovery::new(0);
        r.observe_generic_rtt(60_000_000_000);
        assert_eq!(r.stall_budget(), MAX_STALL);
        assert!(r.can_promote(1452, 1, 31_000_000_001));
        assert!(!r.can_promote(1452, 1, 31_000_000_002));
        assert!(!r.large_stalled(29_999_999_999));
        assert!(r.large_stalled(30_000_000_000));
        r.observe_generic_rtt(u64::MAX);
        assert_eq!(r.stall_budget(), MAX_STALL);
    }

    #[test]
    fn rtt_absolute_stale_outliers_cannot_train_or_overflow_generic_budget() {
        for age in [MAX_STALL + BASE_STALL + 1, 60_000_000_000, u64::MAX - 1] {
            let mut r = Recovery::new(0);
            r.observe_generic_rtt(20_000_000);
            let before = (r.generic_srtt, r.generic_rttvar);
            r.sent(1, SMALL, 1, false, true);
            assert!(!r.acknowledged(1, 1 + age, 1204));
            assert_eq!((r.generic_srtt, r.generic_rttvar), before);
            assert_eq!(r.stall_budget(), BASE_STALL);
            assert!(r.records[r.generic_index(1).unwrap()].acknowledged);
        }
        let mut r = Recovery::new(u64::MAX - 40_000_000);
        r.sent(1, SMALL, u64::MAX - 20_000_000, false, true);
        assert!(!r.acknowledged(1, u64::MAX, 1204));
        assert_eq!(r.generic_srtt, 20_000_000);
        assert_eq!(r.stall_budget(), BASE_STALL);
        let mut edge = Recovery::new(0);
        edge.sent(1, SMALL, 1, false, true);
        assert!(!edge.acknowledged(1, 31_000_000_001, 1204));
        assert_eq!(edge.stall_budget(), MAX_STALL, "absolute inclusive edge may train");
    }

    #[test]
    fn rtt_generic_binary_lookup_wrap_churn_unknown_and_reset() {
        let mut r = Recovery::new(0);
        let total = GENERIC_RECORDS * 3 + 13;
        for i in 0..total {
            let sequence = i as u64 * 3;
            r.sent(sequence, SMALL, sequence + 1, false, true);
            for offset in [1, 2] { r.sent(sequence + offset, 1204, sequence + 1, true, false); }
        }
        for i in 0..5000 { r.sent((total * 3 + i) as u64, 1204, 10_000, true, false); }
        for i in 0..total {
            let sequence = i as u64 * 3;
            let retained = i >= total - GENERIC_RECORDS;
            assert_eq!(r.generic_index(sequence).is_some(), retained, "i={i}");
            assert_eq!(r.is_generic(sequence), retained);
            assert_eq!(r.sent_bytes(sequence), retained.then_some(SMALL as u16));
            assert!(!r.is_generic(sequence + 1));
        }
        assert!(r.generic_index(u64::MAX - 1).is_none());
        assert!(!r.acknowledged(0, 20_000, 1204));
        assert_eq!(r.generic_srtt, 0, "overwritten unknown cannot train RTT");
        r.downshifted(30_000);
        assert_eq!((r.generic_cursor, r.generic_count), (0, 0));
        assert!(r.generic_index((total as u64 - 1) * 3).is_none());
        let sequence = (total * 3 + 5001) as u64;
        r.sent(sequence, SMALL, 40_000, false, true);
        assert!(r.generic_index(sequence).is_some());
        assert_eq!((r.generic_cursor, r.generic_count), (1, 1));
    }

    #[test]
    fn history_allocation_is_bounded() {
        let r = Recovery::new(0);
        assert_eq!(r.records.len(), RECORDS);
        assert_eq!(std::mem::size_of_val(r.records.as_ref()), 96 * 1024);
    }
    #[test]
    fn application_packets_do_not_move_alternating_generic_probe_schedule() {
        let mut r = Recovery::new(10);
        for (seq, bytes) in [80, 512, 1000, 1204, 9000].into_iter().enumerate() {
            r.sent(seq as u64, bytes, 100, true, false);
            assert_eq!(r.next_probe, 10);
        }
        for size in [512, 1204, 512, 1204] {
            assert_eq!(r.probe_size(1204), size);
            r.scheduled_probe_sent(300, size);
            assert_eq!(r.next_probe, 300 + PERIOD);
        }
        for _ in 0..8 {
            assert_eq!(r.probe_size(512), 512);
            r.scheduled_probe_sent(300, 512);
        }
    }
    #[test]
    fn overwritten_metadata_and_protected_generic_history_have_distinct_lifetimes() {
        let mut r = Recovery::new(0);
        r.sent(1, 512, 10, false, true);
        r.sent(1 + PACKET_RECORDS as u64, 1204, 20, true, false);
        assert_eq!(r.records[1].sequence, 1 + PACKET_RECORDS as u64);
        assert!(r.is_generic(1), "generic proof survives real nonce-slot overwrite");
        assert!(!r.is_generic(1 + PACKET_RECORDS as u64));
        assert!(!r.acknowledged(1, 100, 1204));
        for seq in 2..=1 + GENERIC_RECORDS as u64 {
            r.sent(seq, 512, 200, false, true);
        }
        assert!(!r.is_generic(1), "chronological ledger is bounded too");
        assert!(!r.acknowledged(1, 300, 1204));
        assert_eq!(r.last_large_progress, 300, "unknown positive may only veto");
    }
}
