//! Sparse receiver loss feedback. Arrival-time tolerance is ONLY a reordering
//! filter; congestion control remains rate-based, driven by declared loss and CE.
use crate::ack::{AckReceiver, AckOptions, BitmapAck};
pub const NACK_PAYLOAD_LEN: usize = 328;
const MISSING_RANGES: usize = 8;
const LATE_ON_WIRE: usize = 8;
const LATE_CACHE: usize = 32;
const LATE_REPEATS: u8 = 8;
const HISTORY: u64 = 4096;
const EXPIRY_NS: u64 = 20_000_000_000;
const MAX_DELAY_US: u32 = 5000;
const REORDER_US: u32 = 3000;
const PACKET_THRESHOLD: u16 = 16;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range { pub start: u64, pub len: u32 }
impl Range { pub fn end(&self) -> u64 { self.start + self.len as u64 } }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NackAck {
    pub highest: u64, pub sample_seq: u64, pub delay_us: u32, pub ce_count: u32,
    pub loss_count: u32, pub max_delay_us: u32, pub reorder_us: u32,
    pub bitmap: [u64; 16], pub missing: [Range; MISSING_RANGES], pub missing_len: u8,
    pub late: [u64; LATE_ON_WIRE], pub late_len: u8,
}
impl NackAck {
    pub fn encode(&self) -> [u8; NACK_PAYLOAD_LEN] {
        assert!(self.late_len as usize <= LATE_ON_WIRE && self.missing_len as usize <= MISSING_RANGES);
        let mut b = [0; NACK_PAYLOAD_LEN];
        b[0..8].copy_from_slice(&self.highest.to_le_bytes());
        b[8..16].copy_from_slice(&self.sample_seq.to_le_bytes());
        for (i, v) in [self.delay_us, self.ce_count, self.loss_count, self.max_delay_us].iter().enumerate() {
            b[16+i*4..20+i*4].copy_from_slice(&v.to_le_bytes());
        }
        b[32..34].copy_from_slice(&(self.late_len as u16).to_le_bytes());
        b[34..36].copy_from_slice(&(self.missing_len as u16).to_le_bytes());
        b[36..40].copy_from_slice(&self.reorder_us.to_le_bytes());
        for (i, w) in self.bitmap.iter().enumerate() { b[40+i*8..48+i*8].copy_from_slice(&w.to_le_bytes()); }
        for (i, r) in self.missing_ranges().iter().enumerate() {
            b[168+i*12..176+i*12].copy_from_slice(&r.start.to_le_bytes());
            b[176+i*12..180+i*12].copy_from_slice(&r.len.to_le_bytes());
        }
        for (i, seq) in self.late_sequences().iter().enumerate() { b[264+i*8..272+i*8].copy_from_slice(&seq.to_le_bytes()); }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != NACK_PAYLOAD_LEN { return None; }
        let u32_at = |o| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let u64_at = |o| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let nl = u16::from_le_bytes(b[32..34].try_into().ok()?) as usize;
        let nm = u16::from_le_bytes(b[34..36].try_into().ok()?) as usize;
        if nl > LATE_ON_WIRE || nm > MISSING_RANGES { return None; }
        let mut a = Self { highest: u64_at(0), sample_seq: u64_at(8), delay_us: u32_at(16), ce_count: u32_at(20),
            loss_count: u32_at(24), max_delay_us: u32_at(28), reorder_us: u32_at(36), bitmap: [0;16], missing: [Range::default(); MISSING_RANGES], missing_len: nm as u8, late: [0;LATE_ON_WIRE], late_len: nl as u8 };
        if a.highest >= crate::sequence::ACK_SPACE || a.sample_seq > a.highest { return None; }
        for (i,w) in a.bitmap.iter_mut().enumerate() { *w = u64_at(40+i*8); }
        if !a.feedback().contains(a.highest) { return None; }
        for i in 0..nl {
            let seq = u64_at(264+i*8);
            if seq > a.highest || (i > 0 && a.late[i-1] >= seq) { return None; }
            a.late[i] = seq;
        }
        let feedback = a.feedback();
        for i in 0..nm {
            let r = Range { start: u64_at(168+i*12), len: u32_at(176+i*12) };
            if r.len == 0 || r.len as u64 > HISTORY || r.start < a.highest.saturating_sub(HISTORY-1) || r.start > a.highest || r.start.checked_add(r.len as u64)? > a.highest+1 { return None; }
            if i > 0 && a.missing[i-1].end() > r.start { return None; }
            if (r.start..r.end()).any(|seq| seq == a.sample_seq || feedback.contains(seq) || a.late_sequences().contains(&seq)) { return None; }
            a.missing[i] = r;
        }
        Some(a)
    }
    pub fn missing_ranges(&self) -> &[Range] { &self.missing[..self.missing_len as usize] }
    pub fn late_sequences(&self) -> &[u64] { &self.late[..self.late_len as usize] }
    pub fn acknowledged(&self) -> impl Iterator<Item=u64> + '_ { self.late_sequences().iter().copied() }
    pub fn lost(&self) -> impl Iterator<Item=u64> + '_ { self.missing_ranges().iter().flat_map(|r| r.start..r.end()) }
    pub fn feedback(&self) -> BitmapAck {
        BitmapAck { highest: self.highest, sample_seq: self.sample_seq, delay_us: self.delay_us, ce_count: self.ce_count, bitmap: self.bitmap }
    }
}
#[derive(Debug, Clone, Copy, Default)]
struct LatePositive { seq: u64, since: u64, remaining: u8 }
#[derive(Debug)]
pub struct NackReceiver {
    pub receipts: AckReceiver,
    highest: Option<u64>,
    // One-time allocation, no arrival or ACK construction allocates. Ring slots
    // are expired before reuse, so gaps are strictly bounded by4096 positions.
    hole_since: Box<[u64;4096]>, holes: [u64;64], declared: [u64;64],
    hole_count: u16,
    late: [LatePositive; LATE_CACHE], late_insert: usize, late_cursor: usize,
    pub late_overflows: u64,
    pub losses: u64, pub false_nacks: u64, pub expired: u64,
    learned_reorder_ns: u64, last_decay_ns: u64, next_tick_ns: u64, fallback_cap_ns: u64,
    pub effective_reorder_us: u32, cursor: u64,
}
impl Default for NackReceiver {
    fn default() -> Self { Self { receipts: AckReceiver::default(), highest: None,
        hole_since: Box::new([0;4096]), holes: [0;64], declared: [0;64], hole_count: 0,
        late: [LatePositive::default();LATE_CACHE], late_insert: 0, late_cursor: 0,
        late_overflows: 0, losses: 0, false_nacks: 0, expired: 0,
        learned_reorder_ns: 0, last_decay_ns: 0, next_tick_ns: 0, fallback_cap_ns: 1_000_000_000, effective_reorder_us: 0, cursor: 0 } }
}
/// Sorted set-bit iteration from a sequence-indexed ring. O(64+set bits), no allocation.
fn sequences(bits: [u64;64], highest: u64) -> impl Iterator<Item=u64> {
    let base = highest.saturating_sub(HISTORY-1);
    let shift = base % 64;
    (0..64).flat_map(move |i| {
        let slot = (base/64 + i) as usize % 64;
        let mut word = bits[slot] >> shift;
        if shift != 0 { word |= bits[(slot+1)%64] << (64-shift); }
        std::iter::from_fn(move || {
            if word == 0 { return None; }
            let bit = word.trailing_zeros(); word &= word-1;
            Some(base+i*64+bit as u64)
        })
    }).filter(move |&seq| seq <= highest)
}
impl NackReceiver {
    /// A receiver-side proxy for the unchanged sender timeout floor (2 smoothed
    /// RTTs), not a congestion signal. Sender timeout still runs independently;
    /// it can always beat receiver feedback, including on asymmetric paths.
    pub fn update_rtt(&mut self, rtt_us: u64) {
        if rtt_us > 0 { self.fallback_cap_ns = rtt_us.saturating_mul(2000).clamp(100_000, 1_000_000_000); }
    }
    fn clear_slot(&mut self, seq: u64) -> bool {
        let i = (seq%HISTORY) as usize; let bit = 1 << (i%64);
        let had = self.holes[i/64] & bit != 0;
        if had { self.holes[i/64] &= !bit; self.hole_count -= 1; }
        self.declared[i/64] &= !bit;
        had
    }
    fn late_valid(p: &LatePositive, highest: u64, now: u64) -> bool {
        p.remaining > 0 && highest.saturating_sub(p.seq) < HISTORY && now.saturating_sub(p.since) < EXPIRY_NS
    }
    pub fn receive(&mut self, seq: u64, now: u64, ce: bool, options: AckOptions, timer: &mut u64) -> bool {
        if !matches!(options, AckOptions::Nack) { return false; }
        let mut ignored = u64::MAX;
        let got = self.receipts.receive(seq, now, ce, AckOptions::LowLatency { every_packets: u16::MAX, max_delay_us: MAX_DELAY_US }, &mut ignored);
        if !got { return false; }
        let highest = self.highest.unwrap_or(seq).max(seq);
        let first_packet = self.highest.is_none();
        let first = self.highest.map_or(0, |h| h+1);
        if seq >= first {
            let mut start = first;
            if seq.saturating_sub(first) >= HISTORY {
                self.expired += self.hole_count as u64;
                self.holes.fill(0); self.declared.fill(0); self.hole_count = 0;
                start = seq-HISTORY+1;
            }
            // A single in-order arrival is one ring operation; jumps do at most
            //4096 bounded operations, amortized one per advanced sequence.
            for missing in start..=seq {
                if self.clear_slot(missing) { self.expired += 1; }
                if missing < seq {
                    let i = (missing%HISTORY) as usize;
                    self.holes[i/64] |= 1 << (i%64);
                    self.hole_since[i] = now; self.hole_count += 1;
                }
            }
        }
        let i = (seq%HISTORY) as usize; let bit = 1 << (i%64);
        let cancelled = self.declared[i/64] & bit != 0;
        if self.holes[i/64] & bit != 0 {
            if cancelled { self.false_nacks += 1; *timer = (*timer).min(now); }
            self.learned_reorder_ns = self.learned_reorder_ns.max(now.saturating_sub(self.hole_since[i]).saturating_mul(2).min(1_000_000_000));
            self.clear_slot(seq);
        }
        if cancelled || highest.saturating_sub(seq) >= 1024 {
            let slot = self.late_insert % LATE_CACHE;
            if Self::late_valid(&self.late[slot], highest, now) { self.late_overflows += 1; }
            self.late[slot] = LatePositive { seq, since: now, remaining: LATE_REPEATS };
            self.late_insert = (slot+1)%LATE_CACHE;
            *timer = (*timer).min(now);
        }
        self.highest = Some(highest);
        *timer = (*timer).min(if ce || first_packet { now } else { now + MAX_DELAY_US as u64 * 1000 });
        self.tick(now, options, timer);
        true
    }
    /// Called from the send loop so a quiet gap can mature without another arrival.
    pub fn tick(&mut self, now: u64, options: AckOptions, timer: &mut u64) {
        if !matches!(options, AckOptions::Nack) || self.highest.is_none() || now < self.next_tick_ns { return; }
        self.next_tick_ns = now + 1_000_000;
        if now.saturating_sub(self.last_decay_ns) >= 1_000_000_000 {
            self.learned_reorder_ns = self.learned_reorder_ns * 15 / 16;
            self.last_decay_ns = now;
        }
        let tolerance = self.learned_reorder_ns.max(REORDER_US as u64 * 1000).min(self.fallback_cap_ns);
        self.effective_reorder_us = (tolerance/1000) as u32;
        let highest = self.highest.unwrap();
        let mut repeat = self.late.iter().any(|p| Self::late_valid(p, highest, now));
        if self.hole_count > 0 {
            for seq in sequences(self.holes, highest) {
                let i = (seq%HISTORY) as usize; let bit = 1 << (i%64);
                if now.saturating_sub(self.hole_since[i]) >= EXPIRY_NS { self.clear_slot(seq); self.expired += 1; continue; }
                if self.declared[i/64] & bit == 0 && highest.saturating_sub(seq) >= PACKET_THRESHOLD as u64 && now.saturating_sub(self.hole_since[i]) >= tolerance {
                    self.declared[i/64] |= bit; self.losses += 1; *timer = (*timer).min(now);
                }
                repeat |= self.declared[i/64] & bit != 0;
            }
        }
        if repeat { *timer = (*timer).min(now + 20_000_000); }
    }
    pub fn ack(&mut self, now: u64, options: AckOptions) -> NackAck {
        assert!(matches!(options, AckOptions::Nack));
        let b = self.receipts.ack(now);
        let mut a = NackAck { highest: b.highest, sample_seq: b.sample_seq, delay_us: b.delay_us, ce_count: b.ce_count,
            loss_count: self.losses as u32, max_delay_us: MAX_DELAY_US, reorder_us: self.effective_reorder_us,
            bitmap: b.bitmap, missing: [Range::default();MISSING_RANGES], missing_len: 0,
            late: [0;LATE_ON_WIRE], late_len: 0 };
        // Fixed late-positive cache rotates, each ID repeated up to8 times. No
        // sample change or dropped cancellation ACK can silently erase it.
        for i in 0..LATE_CACHE {
            let slot = (self.late_cursor+i)%LATE_CACHE;
            let p = &mut self.late[slot];
            if !Self::late_valid(p, b.highest, now) { p.remaining = 0; continue; }
            a.late[a.late_len as usize] = p.seq; a.late_len += 1; p.remaining -= 1;
            if a.late_len as usize == LATE_ON_WIRE { self.late_cursor = (slot+1)%LATE_CACHE; break; }
        }
        a.late[..a.late_len as usize].sort_unstable();
        // Rotating missing ranges, assembled directly from set-bit iteration.
        // Skip lower ranges this time, then wrap; always bound on-wire work.
        let cursor = self.cursor;
        let mut last = None;
        let iter = sequences(self.declared, b.highest).filter(move |&s| s >= cursor)
            .chain(sequences(self.declared, b.highest).filter(move |&s| s < cursor));
        for seq in iter {
            let n = a.missing_len as usize;
            if n > 0 && a.missing[n-1].end() == seq { a.missing[n-1].len += 1; }
            else {
                if n == MISSING_RANGES { break; }
                a.missing[n] = Range { start: seq, len: 1 }; a.missing_len += 1;
            }
            last = Some(seq);
        }
        if let Some(seq) = last { self.cursor = if seq >= b.highest { b.highest.saturating_sub(HISTORY-1) } else { seq+1 }; }
        a.missing[..a.missing_len as usize].sort_by_key(|r| r.start);
        a
    }
    pub fn sent(&mut self, now: u64) { self.receipts.sent(now); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const OPT: AckOptions = AckOptions::Nack;
    #[test]
    fn both_distance_and_time_required_repeat_and_cancel() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        r.receive(0, 0, false, OPT, &mut t);
        for s in 2..18 { r.receive(s, s*1000, false, OPT, &mut t); }
        assert_eq!(r.losses, 0);
        r.tick(2_000_000, OPT, &mut t); assert_eq!(r.losses, 0);
        r.tick(4_000_000, OPT, &mut t); assert_eq!(r.losses, 1);
        let a = r.ack(4_000_000, OPT);
        assert_eq!(a.lost().collect::<Vec<_>>(), vec![1]);
        assert_eq!(NackAck::decode(&a.encode()), Some(a.clone()));
        r.sent(4_000_000); assert_eq!(r.ack(5_000_000, OPT).loss_count, 1);
        r.receive(1, 6_000_000, false, OPT, &mut t);
        assert_eq!(r.false_nacks, 1);
        let a = r.ack(6_000_000, OPT);
        assert!(a.missing_ranges().is_empty()); assert_eq!(a.loss_count, 1);
        assert!(a.feedback().acknowledged().chain(a.acknowledged()).any(|s| s == 1));
        assert!(r.effective_reorder_us >= 11000);
    }
    #[test]
    fn tail_loss_does_not_mature_without_distance_and_expiry_is_bounded() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        r.receive(3, 0, false, OPT, &mut t);
        r.tick(100_000_000, OPT, &mut t); assert_eq!(r.losses, 0);
        r.tick(EXPIRY_NS+1, OPT, &mut t); assert!(r.hole_count == 0); assert_eq!(r.expired, 3);
    }
    #[test]
    fn ce_is_cumulative_duplicate_not_resampled_invalid_ranges_rejected() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        assert!(r.receive(0, 0, true, OPT, &mut t));
        assert!(!r.receive(0, 1, true, OPT, &mut t));
        let mut a = r.ack(2000, OPT); assert_eq!(a.ce_count, 1);
        assert_eq!(NackAck::decode(&a.encode()), Some(a.clone()));
        a.missing[0] = Range { start: 0, len: 1 }; a.missing_len = 1;
        assert!(NackAck::decode(&a.encode()).is_none());
    }
    #[test]
    fn repeated_missing_ranges_rotate_over_capacity() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        for s in (0..100).step_by(2) { r.receive(s, s*1000, false, OPT, &mut t); }
        r.tick(4_000_000, OPT, &mut t);
        let a = r.ack(4_000_000, OPT); let b = r.ack(5_000_000, OPT);
        assert_eq!(a.missing_ranges().len(), MISSING_RANGES); assert_ne!(a.missing, b.missing);
        assert!(NackAck::decode(&a.encode()).is_some());
    }

    #[test]
    fn all_positive_runs_repeat_not_only_latest_sixteen() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        for s in (0..100).step_by(2) { r.receive(s, s*1000, false, OPT, &mut t); }
        for n in 0..100 {
            let a = r.ack(1_000_000+n, OPT);
            for s in (0..100).step_by(2) { assert!(a.feedback().contains(s), "missing positive {s}"); }
        }
    }
    #[test]
    fn cancellation_outside_bitmap_survives_sample_changes_and_lost_ack() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        r.receive(0, 0, false, OPT, &mut t);
        for s in 2..2000 { r.receive(s, s*1000, false, OPT, &mut t); }
        r.tick(5_000_000, OPT, &mut t);
        assert!(r.ack(5_000_000, OPT).lost().any(|s| s == 1));
        r.receive(1, 6_000_000, false, OPT, &mut t);
        r.receive(2000, 6_000_001, false, OPT, &mut t);
        let a = r.ack(6_000_002, OPT); // imagine this feedback is dropped
        assert!(a.acknowledged().any(|s| s == 1));
        assert_eq!(NackAck::decode(&a.encode()), Some(a));
        for s in 2001..2005 {
            r.receive(s, 7_000_000+s, false, OPT, &mut t);
            let a = r.ack(8_000_000+s, OPT);
            assert!(a.acknowledged().any(|s| s == 1));
            assert!(!a.lost().any(|s| s == 1));
        }
    }
    #[test]
    fn holes_bounded_between_ticks_and_late_repetition_expires() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        for s in [0, 4096, 8192, 12288] { r.receive(s, 10, false, OPT, &mut t); assert!((r.hole_count as u64) < HISTORY); }
        assert_ne!(NACK_PAYLOAD_LEN, 152); assert_ne!(NACK_PAYLOAD_LEN, 516); assert!(NACK_PAYLOAD_LEN < 517);
    }

    #[test]
    fn reorder_then_clean_decay_and_sender_timeout_cap() {
        let mut r = NackReceiver::default(); let mut timer = u64::MAX;
        r.update_rtt(200_000);
        r.receive(0, 0, false, OPT, &mut timer);
        for seq in 2..20 { r.receive(seq, seq*1000, false, OPT, &mut timer); }
        r.receive(1, 100_000_000, false, OPT, &mut timer);
        r.tick(102_000_000, OPT, &mut timer);
        assert!(r.effective_reorder_us > 190_000);
        // A clean phase decays the observation by15/16 per second, toward3ms.
        for second in 1..=100 { r.receive(19+second, second*1_000_000_000, false, OPT, &mut timer); }
        assert_eq!(r.effective_reorder_us, REORDER_US);
        r.learned_reorder_ns = 900_000_000;
        r.update_rtt(40_000);
        r.tick(101_000_000_000, OPT, &mut timer);
        assert_eq!(r.effective_reorder_us, 80_000);
        r.update_rtt(10_000_000);
        r.tick(102_000_000_000, OPT, &mut timer);
        assert!(r.effective_reorder_us <= 1_000_000);
    }
}
