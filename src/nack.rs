//! Sparse receiver loss feedback. Arrival-time tolerance is ONLY a reordering
//! filter; congestion control remains rate-based, driven by declared loss and CE.
use crate::ack::{AckReceiver, AckOptions, BitmapAck};
pub const NACK_PAYLOAD_LEN: usize = 328;
const POSITIVE_RANGES: usize = 16;
const MISSING_RANGES: usize = 8;
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
    pub positive: Vec<Range>, pub missing: Vec<Range>,
}
impl NackAck {
    pub fn encode(&self) -> [u8; NACK_PAYLOAD_LEN] {
        assert!(self.positive.len() <= POSITIVE_RANGES && self.missing.len() <= MISSING_RANGES);
        let mut b = [0; NACK_PAYLOAD_LEN];
        b[0..8].copy_from_slice(&self.highest.to_le_bytes());
        b[8..16].copy_from_slice(&self.sample_seq.to_le_bytes());
        for (i, v) in [self.delay_us, self.ce_count, self.loss_count, self.max_delay_us].iter().enumerate() {
            b[16+i*4..20+i*4].copy_from_slice(&v.to_le_bytes());
        }
        b[32..34].copy_from_slice(&(self.positive.len() as u16).to_le_bytes());
        b[34..36].copy_from_slice(&(self.missing.len() as u16).to_le_bytes());
        b[36..40].copy_from_slice(&self.reorder_us.to_le_bytes());
        for (i, r) in self.positive.iter().enumerate().chain(self.missing.iter().enumerate().map(|(i,r)| (i+POSITIVE_RANGES,r))) {
            b[40+i*12..48+i*12].copy_from_slice(&r.start.to_le_bytes());
            b[48+i*12..52+i*12].copy_from_slice(&r.len.to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != NACK_PAYLOAD_LEN { return None; }
        let u32_at = |o| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let u64_at = |o| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let np = u16::from_le_bytes(b[32..34].try_into().ok()?) as usize;
        let nm = u16::from_le_bytes(b[34..36].try_into().ok()?) as usize;
        if np > POSITIVE_RANGES || nm > MISSING_RANGES { return None; }
        let mut a = Self { highest: u64_at(0), sample_seq: u64_at(8), delay_us: u32_at(16), ce_count: u32_at(20),
            loss_count: u32_at(24), max_delay_us: u32_at(28), reorder_us: u32_at(36), positive: Vec::new(), missing: Vec::new() };
        if a.highest >= crate::sequence::ACK_SPACE || a.sample_seq > a.highest { return None; }
        for (start, n, out) in [(0, np, &mut a.positive), (POSITIVE_RANGES, nm, &mut a.missing)] {
            for i in start..start+n {
                let r = Range { start: u64_at(40+i*12), len: u32_at(48+i*12) };
                if r.len == 0 || r.len as u64 > HISTORY || r.start > a.highest || r.start.checked_add(r.len as u64)? > a.highest+1 { return None; }
                if out.last().is_some_and(|p: &Range| p.end() > r.start) { return None; }
                out.push(r);
            }
        }
        if !a.positive.iter().any(|r| r.start <= a.highest && r.end() > a.highest) { return None; }
        if a.missing.iter().any(|m| m.start <= a.sample_seq && a.sample_seq < m.end()
            || a.positive.iter().any(|p| m.start < p.end() && p.start < m.end())) { return None; }
        Some(a)
    }
    pub fn acknowledged(&self) -> impl Iterator<Item=u64> + '_ {
        self.positive.iter().flat_map(|r| r.start..r.end()).chain(std::iter::once(self.sample_seq))
    }
    pub fn lost(&self) -> impl Iterator<Item=u64> + '_ { self.missing.iter().flat_map(|r| r.start..r.end()) }
    /// Existing sender RTT/CE processing consumes this header; positive ranges are
    /// processed separately. Only a newly ACKed sample may contribute an RTT.
    pub fn feedback(&self) -> BitmapAck {
        let mut bitmap = [0;16];
        let base = self.highest.saturating_sub(1023);
        let i = self.highest-base;
        bitmap[(i/64) as usize] |= 1 << (i%64);
        BitmapAck { highest: self.highest, sample_seq: self.sample_seq, delay_us: self.delay_us, ce_count: self.ce_count, bitmap }
    }
}
#[derive(Debug)]
struct Hole { seq: u64, since: u64, declared: bool }
#[derive(Debug, Default)]
pub struct NackReceiver {
    pub receipts: AckReceiver,
    highest: Option<u64>, holes: Vec<Hole>,
    pub losses: u64, pub false_nacks: u64, pub expired: u64,
    learned_reorder_ns: u64, last_decay_ns: u64, next_tick_ns: u64,
    pub effective_reorder_us: u32, cursor: usize,
}
impl NackReceiver {
    pub fn receive(&mut self, seq: u64, now: u64, ce: bool, options: AckOptions, timer: &mut u64) -> bool {
        if !matches!(options, AckOptions::Nack) { return false; }
        let max_delay_us = MAX_DELAY_US;
        let mut ignored = u64::MAX;
        let got = self.receipts.receive(seq, now, ce, AckOptions::LowLatency { every_packets: u16::MAX, max_delay_us }, &mut ignored);
        if !got { return false; }
        let first = self.highest.map_or(0, |h| h+1);
        if seq > first {
            for missing in first.max(seq.saturating_sub(HISTORY-1))..seq {
                self.holes.push(Hole { seq: missing, since: now, declared: false });
            }
        }
        if let Some(i) = self.holes.iter().position(|h| h.seq == seq) {
            let hole = self.holes.remove(i);
            if hole.declared { self.false_nacks += 1; }
            // Learn from reordered arrivals, never from the RTT/congestion curve.
            self.learned_reorder_ns = self.learned_reorder_ns.max(now.saturating_sub(hole.since).saturating_mul(2).min(100_000_000));
            if hole.declared { *timer = (*timer).min(now); } // positive cancellation
        }
        let first_packet = self.highest.is_none();
        self.highest = Some(self.highest.unwrap_or(seq).max(seq));
        *timer = (*timer).min(if ce || first_packet { now } else { now + max_delay_us.max(1000) as u64 * 1000 });
        self.tick(now, options, timer);
        true
    }
    /// Called from the send loop so a quiet gap can mature without another arrival.
    pub fn tick(&mut self, now: u64, options: AckOptions, timer: &mut u64) {
        if !matches!(options, AckOptions::Nack) { return; }
        let (max_delay_us, reorder_us, packet_threshold) = (MAX_DELAY_US, REORDER_US, PACKET_THRESHOLD);
        if self.highest.is_none() || now < self.next_tick_ns { return; }
        self.next_tick_ns = now + 1_000_000;
        if now.saturating_sub(self.last_decay_ns) >= 1_000_000_000 {
            self.learned_reorder_ns = self.learned_reorder_ns * 15 / 16;
            self.last_decay_ns = now;
        }
        let tolerance = self.learned_reorder_ns.max(reorder_us.max(1000) as u64 * 1000);
        self.effective_reorder_us = (tolerance/1000) as u32;
        let highest = self.highest.unwrap();
        self.holes.retain(|h| {
            let expire = highest.saturating_sub(h.seq) >= HISTORY || now.saturating_sub(h.since) >= EXPIRY_NS;
            if expire { self.expired += 1; } !expire
        });
        for h in &mut self.holes {
            if !h.declared && highest.saturating_sub(h.seq) >= packet_threshold.max(1) as u64 && now.saturating_sub(h.since) >= tolerance {
                h.declared = true; self.losses += 1; *timer = (*timer).min(now);
            }
        }
        if self.holes.iter().any(|h| h.declared) {
            *timer = (*timer).min(now + 20_000_000.min(max_delay_us.max(1000) as u64 * 1000 * 4));
        }
    }
    pub fn ack(&mut self, now: u64, options: AckOptions) -> NackAck {
        assert!(matches!(options, AckOptions::Nack));
        let max_delay_us = MAX_DELAY_US;
        let bitmap = self.receipts.ack(now);
        // Send the most recent 16 positive runs; missing runs rotate to avoid a
        // long-lived old gap starving new loss attribution. All memory is bounded.
        let mut positive = Vec::<Range>::new();
        for seq in bitmap.acknowledged().filter(|&s| bitmap.contains(s)) {
            if let Some(r) = positive.last_mut().filter(|r| r.end() == seq) { r.len += 1; }
            else { positive.push(Range { start: seq, len: 1 }); }
        }
        if positive.len() > POSITIVE_RANGES { positive.drain(..positive.len()-POSITIVE_RANGES); }
        let mut ranges = Vec::<Range>::new();
        for h in self.holes.iter().filter(|h| h.declared) {
            if let Some(r) = ranges.last_mut().filter(|r| r.end() == h.seq) { r.len += 1; }
            else { ranges.push(Range { start: h.seq, len: 1 }); }
        }
        let mut missing = Vec::new();
        if !ranges.is_empty() {
            let start = self.cursor % ranges.len();
            for i in 0..ranges.len().min(MISSING_RANGES) { missing.push(ranges[(start+i)%ranges.len()]); }
            self.cursor = (start + missing.len()) % ranges.len();
            missing.sort_by_key(|r| r.start);
        }
        NackAck { highest: bitmap.highest, sample_seq: bitmap.sample_seq, delay_us: bitmap.delay_us, ce_count: bitmap.ce_count,
            loss_count: self.losses as u32, max_delay_us, reorder_us: self.effective_reorder_us, positive, missing }
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
        assert!(a.missing.is_empty()); assert_eq!(a.loss_count, 1);
        assert!(a.acknowledged().any(|s| s == 1));
        assert!(r.effective_reorder_us >= 11000);
    }
    #[test]
    fn tail_loss_does_not_mature_without_distance_and_expiry_is_bounded() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        r.receive(3, 0, false, OPT, &mut t);
        r.tick(100_000_000, OPT, &mut t); assert_eq!(r.losses, 0);
        r.tick(EXPIRY_NS+1, OPT, &mut t); assert!(r.holes.is_empty()); assert_eq!(r.expired, 3);
    }
    #[test]
    fn ce_is_cumulative_duplicate_not_resampled_invalid_ranges_rejected() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        assert!(r.receive(0, 0, true, OPT, &mut t));
        assert!(!r.receive(0, 1, true, OPT, &mut t));
        let mut a = r.ack(2000, OPT); assert_eq!(a.ce_count, 1);
        assert_eq!(NackAck::decode(&a.encode()), Some(a.clone()));
        a.missing.push(Range { start: 0, len: 1 });
        assert!(NackAck::decode(&a.encode()).is_none());
    }
    #[test]
    fn repeated_missing_ranges_rotate_over_capacity() {
        let mut r = NackReceiver::default(); let mut t = u64::MAX;
        for s in (0..100).step_by(2) { r.receive(s, s*1000, false, OPT, &mut t); }
        r.tick(4_000_000, OPT, &mut t);
        let a = r.ack(4_000_000, OPT); let b = r.ack(5_000_000, OPT);
        assert_eq!(a.missing.len(), MISSING_RANGES); assert_ne!(a.missing, b.missing);
        assert!(NackAck::decode(&a.encode()).is_some());
    }
}
