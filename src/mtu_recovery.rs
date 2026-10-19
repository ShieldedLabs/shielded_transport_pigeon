//! Time-driven reachability recovery, independent of application message sizes.
//! Records are only consulted after native authenticated first-positive ACK admission.

pub(crate) const SMALL: u64 = 512;
pub(crate) const PERIOD: u64 = 250_000_000;
const MAX_PROOF_AGE: u64 = 2_000_000_000;
const STALL: u64 = 1_000_000_000;
const UPWARD_HOLD: u64 = 10_000_000_000;
const RECORDS: usize = 4096;
/// Heap storage charged in the connection's process-budget reservation.
pub(crate) const HISTORY_BYTES: usize = RECORDS * std::mem::size_of::<Sent>();

#[derive(Clone, Copy, Debug)]
struct Sent {
    sequence: u64,
    time: u64,
    bytes: u16,
    ordinary: bool,
    generic: bool,
}
impl Sent {
    const EMPTY: Self = Self {
        sequence: u64::MAX,
        time: 0,
        bytes: 0,
        ordinary: false,
        generic: false,
    };
}

#[derive(Debug)]
pub(crate) struct Recovery {
    records: Box<[Sent]>,
    pub(crate) next_small: u64,
    pub(crate) upward_after: u64,
    last_large_progress: u64,
}
impl Recovery {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            records: vec![Sent::EMPTY; RECORDS].into_boxed_slice(),
            next_small: now,
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
        self.records[sequence as usize % RECORDS] = Sent {
            sequence,
            time: now,
            bytes: bytes as u16,
            ordinary,
            generic,
        };
    }
    pub(crate) fn is_generic(&self, sequence: u64) -> bool {
        let record = &self.records[sequence as usize % RECORDS];
        record.sequence == sequence && record.generic
    }
    pub(crate) fn scheduled_small_sent(&mut self, now: u64) {
        self.next_small = now.saturating_add(PERIOD);
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
    /// Returns a fresh small proof with aged, unacknowledged larger ordinary work.
    /// Normal large ACKs take O(1); only eligible small proofs scan bounded history.
    pub(crate) fn acknowledged(&mut self, sequence: u64, now: u64) -> bool {
        let record = &mut self.records[sequence as usize % RECORDS];
        if record.sequence != sequence {
            return false;
        }
        let sent = *record;
        *record = Sent::EMPTY;
        if now.saturating_sub(sent.time) > MAX_PROOF_AGE {
            return false;
        }
        if sent.bytes as u64 > SMALL && sent.ordinary {
            self.last_large_progress = now;
            return false;
        }
        if sent.bytes as u64 != SMALL || !self.large_stalled(now) {
            return false;
        }
        self.records.iter().any(|r| {
            r.sequence != u64::MAX
                && r.ordinary
                && r.bytes as u64 > SMALL
                && now.saturating_sub(r.time) >= STALL
        })
    }
    /// Commit only after the whole ACK has been admitted: large progress in the
    /// same bitmap must veto a small proof regardless of sequence ordering.
    pub(crate) fn downshifted(&mut self, now: u64) {
        self.upward_after = now.saturating_add(UPWARD_HOLD);
        for record in &mut self.records {
            if record.ordinary && record.bytes as u64 > SMALL {
                *record = Sent::EMPTY;
            }
        }
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
    fn application_packets_do_not_move_generic_probe_schedule() {
        let mut r = Recovery::new(10);
        for (seq, bytes) in [80, 512, 1000, 1204, 9000].into_iter().enumerate() {
            r.sent(seq as u64, bytes, 100, true, false);
            assert_eq!(r.next_small, 10);
        }
        r.scheduled_small_sent(300);
        assert_eq!(r.next_small, 300 + PERIOD);
    }
    #[test]
    fn exact_small_proof_and_stalled_large_required() {
        let mut r = Recovery::new(0);
        r.sent(1, 1204, 1, true, false);
        r.sent(2, 512, 900_000_000, true, false);
        assert!(!r.acknowledged(3, 1_100_000_000));
        assert!(r.acknowledged(2, 1_100_000_000));
        r.downshifted(1_100_000_000);
        assert_eq!(r.upward_after, 11_100_000_000);
        assert!(!r.acknowledged(2, 1_200_000_000));
    }
    #[test]
    fn recent_and_same_bitmap_large_progress_prevent_downshift() {
        let mut r = Recovery::new(0);
        r.sent(1, 1204, 1, true, false);
        r.sent(2, 512, 900_000_000, false, false);
        r.sent(3, 1204, 900_000_000, true, false);
        assert!(r.acknowledged(2, 1_100_000_000));
        assert!(!r.acknowledged(3, 1_100_000_000));
        assert!(!r.large_stalled(1_100_000_000));
        r.sent(4, 512, 1_200_000_000, true, false);
        assert!(!r.acknowledged(4, 1_200_000_000));
    }
    #[test]
    fn stale_small_and_probe_only_failures_do_not_prove_recovery() {
        let mut r = Recovery::new(0);
        r.sent(1, 1204, 1, true, false);
        r.sent(2, 512, 2, false, false);
        assert!(!r.acknowledged(2, MAX_PROOF_AGE + 3));
        r.sent(1, 1400, 1, false, false);
        r.sent(2, 512, 900_000_000, false, false);
        assert!(!r.acknowledged(2, 1_100_000_000));
    }
    #[test]
    fn overwritten_sequence_cannot_supply_a_proof() {
        let mut r = Recovery::new(0);
        r.sent(1, 512, 10, false, false);
        r.sent(1 + RECORDS as u64, 512, 20, false, false);
        assert!(!r.acknowledged(1, 100));
    }
}
