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
