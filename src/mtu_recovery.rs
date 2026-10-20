//! Time-driven reachability recovery, independent of application message sizes.
//! Records are only consulted after native authenticated first-positive ACK admission.

pub(crate) const SMALL: u64 = 512;
pub(crate) const PERIOD: u64 = 250_000_000;
const MAX_PROOF_AGE: u64 = 2_000_000_000;
const MAX_FAILURE_AGE: u64 = 3_000_000_000;
const STALL: u64 = 1_000_000_000;
const REPEATED: usize = 2;
const UPWARD_HOLD: u64 = 10_000_000_000;
const RECORDS: usize = 4096;
// Four seconds at the generic schedule, protected from ordinary-send churn.
const GENERIC_RECORDS: usize = 16;
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
    pub(crate) next_probe: u64,
    probe_current: bool,
    pub(crate) upward_after: u64,
    last_large_progress: u64,
}
impl Recovery {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            records: vec![Sent::EMPTY; RECORDS].into_boxed_slice(),
            generic_cursor: 0,
            next_probe: now,
            probe_current: false,
            upward_after: 0,
            last_large_progress: now,
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
        }
    }
    pub(crate) fn is_generic(&self, sequence: u64) -> bool {
        let record = &self.records[sequence as usize % PACKET_RECORDS];
        if record.sequence == sequence { return record.generic; }
        self.records[PACKET_RECORDS..].iter().any(|r| r.sequence == sequence)
    }
    pub(crate) fn probe_size(&self, current_tu: u64) -> u64 {
        if self.probe_current { current_tu } else { SMALL }
    }
    pub(crate) fn scheduled_probe_sent(&mut self, now: u64, bytes: u64) {
        self.next_probe = now.saturating_add(PERIOD);
        self.probe_current = bytes == SMALL;
    }
    pub(crate) fn large_stalled(&self, now: u64) -> bool {
        now.saturating_sub(self.last_large_progress) >= STALL
    }
    pub(crate) fn can_promote(&self, sent: u64, now: u64) -> bool {
        now >= self.upward_after
            && sent != 0
            && sent != u64::MAX
            && now.saturating_sub(sent) <= MAX_PROOF_AGE
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
            let Some(record) = self.records[PACKET_RECORDS..].iter_mut()
                .find(|r| r.sequence == sequence) else {
                    // Exact metadata was overwritten. A native first positive
                    // might be healthy ordinary progress: it can only veto.
                    self.last_large_progress = now;
                    return false;
                };
            if record.acknowledged { return false; }
            sent = *record;
            // Keep positive generic evidence; first-positive admission stays exact.
            record.acknowledged = true;
        }
        if now.saturating_sub(sent.time) > MAX_PROOF_AGE {
            return false;
        }
        if sent.bytes as u64 > SMALL
            && (sent.ordinary || (sent.generic && sent.bytes as u64 == current_tu)) {
            self.last_large_progress = now;
            return false;
        }
        if current_tu <= SMALL || sent.bytes as u64 != SMALL || !self.large_stalled(now) {
            return false;
        }
        let mut failures = 0;
        let mut small_positives = 0;
        for r in self.records[PACKET_RECORDS..].iter() {
            let age = now.saturating_sub(r.time);
            if r.sequence == u64::MAX || r.time <= self.last_large_progress {
                continue;
            }
            if r.acknowledged && r.bytes as u64 == SMALL && age <= MAX_PROOF_AGE {
                small_positives += 1;
            } else if !r.acknowledged && r.bytes as u64 == current_tu
                && (STALL..=MAX_FAILURE_AGE).contains(&age) {
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
        self.last_large_progress = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upward_confirmation_requires_fresh_exact_record_and_finished_hold() {
        let mut r = Recovery::new(0);
        assert!(r.can_promote(1, MAX_PROOF_AGE + 1));
        assert!(!r.can_promote(1, MAX_PROOF_AGE + 2));
        assert!(!r.can_promote(0, 1));
        assert!(!r.can_promote(u64::MAX, 1));
        r.downshifted(1_000_000_000);
        assert!(!r.can_promote(r.upward_after - 1, r.upward_after - 1));
        assert!(r.can_promote(r.upward_after - 1, r.upward_after));
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
