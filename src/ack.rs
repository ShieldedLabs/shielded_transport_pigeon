//! Size-identified acknowledgements with explicit receipt windows and bounded history.
pub const ACK_PAYLOAD_LEN: usize = 152;
pub const ACK_BITMAP_BITS: u64 = 960;
const HISTORY_BITS: u64 = 262144;

/// Internal adaptive batching limits; chosen once in ship.rs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AckPolicy {
    pub every_packets: u16,
    pub max_delay_us: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapAck {
    pub highest: u64,
    pub receipt_base: u64,
    /// Most recently received unique packet, also acknowledged even outside the bitmap.
    pub sample_seq: u64,
    /// Exact UDP payload size of sample_seq, including STP framing and authentication.
    pub sample_udp_payload_bytes: u16,
    pub delay_us: u32,
    /// Cumulative unique data-class packets marked by kernel CE or receiver overload.
    /// A packet contributes at most once, saturating at u64::MAX (close before exhaustion).
    pub ce_count: u64,
    pub bitmap: [u64; 15],
}
impl BitmapAck {
    pub fn base(&self) -> u64 { self.receipt_base }
    pub fn encode(&self) -> [u8; ACK_PAYLOAD_LEN] {
        let mut b = [0; ACK_PAYLOAD_LEN];
        b[..8].copy_from_slice(&self.receipt_base.to_le_bytes());
        b[8..16].copy_from_slice(&self.sample_seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.ce_count.to_le_bytes());
        b[24..28].copy_from_slice(&self.delay_us.to_le_bytes());
        b[28] = 1; // Bitmap plus exact sample size; byte 29 is reserved zero.
        b[30..32].copy_from_slice(&self.sample_udp_payload_bytes.to_le_bytes());
        for (i, w) in self.bitmap.iter().enumerate() { b[32+i*8..40+i*8].copy_from_slice(&w.to_le_bytes()); }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != ACK_PAYLOAD_LEN || b[28] != 1 || b[29] != 0 || b[30..32] == [0; 2] { return None; }
        let mut a = Self {
            highest: 0,
            receipt_base: u64::from_le_bytes(b[..8].try_into().ok()?),
            sample_seq: u64::from_le_bytes(b[8..16].try_into().ok()?),
            ce_count: u64::from_le_bytes(b[16..24].try_into().ok()?),
            sample_udp_payload_bytes: u16::from_le_bytes(b[30..32].try_into().ok()?),
            delay_us: u32::from_le_bytes(b[24..28].try_into().ok()?), bitmap: [0; 15],
        };
        if a.receipt_base >= crate::sequence::ACK_SPACE || a.sample_seq >= crate::sequence::ACK_SPACE { return None; }
        for (i, w) in a.bitmap.iter_mut().enumerate() { *w = u64::from_le_bytes(b[32+i*8..40+i*8].try_into().ok()?); }
        a.highest = a.sample_seq;
        for (i, &word) in a.bitmap.iter().enumerate() {
            if word != 0 {
                let seq = a.receipt_base.checked_add(i as u64 * 64 + 63 - word.leading_zeros() as u64)?;
                if seq >= crate::sequence::ACK_SPACE { return None; }
                a.highest = a.highest.max(seq);
            }
        }
        Some(a)
    }
    pub fn contains(&self, seq: u64) -> bool {
        let Some(bit) = seq.checked_sub(self.base()).filter(|&n| n < ACK_BITMAP_BITS) else { return false; };
        self.bitmap[(bit / 64) as usize] & (1 << (bit % 64)) != 0
    }
    /// Intersect receipt words with sender pending/lost rings before set-bit iteration.
    /// Repeated receipt bits are normally already cleared; skipping whole words keeps
    /// sender work near O(16 + newly acknowledged packets), not O(1024) per ACK.
    pub fn relevant(&self, waiting: &[u64], lost: &[u64]) -> Self {
        debug_assert_eq!(waiting.len(), lost.len());
        let mut a = self.clone();
        let base = self.base();
        let shift = base % 64;
        for (i, w) in a.bitmap.iter_mut().enumerate() {
            let slot = (base / 64 + i as u64) as usize % waiting.len();
            let mut mask = (waiting[slot] | lost[slot]) >> shift;
            if shift != 0 {
                let next = (slot + 1) % waiting.len();
                mask |= (waiting[next] | lost[next]) << (64 - shift);
            }
            *w &= mask;
        }
        a
    }
    /// Set-bit iteration; missing bits never constitute a loss declaration.
    pub fn acknowledged(&self) -> impl Iterator<Item=u64> + '_ {
        self.bitmap.iter().enumerate().flat_map(move |(i, &word)| {
            let mut w = word;
            std::iter::from_fn(move || {
                if w == 0 { return None; }
                let bit = w.trailing_zeros(); w &= w - 1;
                Some(self.base() + i as u64 * 64 + bit as u64)
            })
        }).chain(
            (!self.contains(self.sample_seq)).then_some(self.sample_seq))
    }
}

#[derive(Debug)]
pub struct AckReceiver {
    history: Box<[u64]>,
    highest: Option<u64>,
    sample_seq: u64,
    sample_time_ns: u64,
    sample_udp_payload_bytes: u16,
    ce_count: u64,
    pending: u16,
    last_arrival_ns: Option<u64>,
    mean_gap_ns: u64,
    gap_seq: Option<u64>,
    gap_since_ns: u64,
    last_ack_ns: Option<u64>,
    feedback_pages: std::collections::VecDeque<(u64, u8)>,
}
impl Default for AckReceiver {
    fn default() -> Self { Self { history: vec![0; (HISTORY_BITS/64) as usize].into_boxed_slice(), highest: None, sample_seq: 0, sample_time_ns: 0, sample_udp_payload_bytes: 0, ce_count: 0, pending: 0, last_arrival_ns: None, mean_gap_ns: 1_000_000, gap_seq: None, gap_since_ns: 0, last_ack_ns: None, feedback_pages: std::collections::VecDeque::new() } }
}
impl AckReceiver {
    /// Returns false for duplicate/too-old data; duplicates still refresh ACK feedback.
    pub fn receive(&mut self, seq: u64, now: u64, ce: bool, timer: &mut u64) -> bool {
        self.receive_with_rtt(seq, now, ce, timer, 0, 1204)
    }
    pub fn receive_with_rtt(&mut self, seq: u64, now: u64, ce: bool, timer: &mut u64, rtt_us: u64, wire_bytes: usize) -> bool {
        let Ok(sample_udp_payload_bytes) = u16::try_from(wire_bytes) else { return false; };
        if sample_udp_payload_bytes == 0 || seq >= crate::sequence::ACK_SPACE { return false; }
        let old_highest = self.highest;
        if old_highest.is_some_and(|h| seq < h.saturating_sub(HISTORY_BITS - 1)) { return false; }
        if let Some(h) = old_highest {
            if seq > h {
                if seq - h >= HISTORY_BITS { self.history.fill(0); }
                else { for s in h+1..=seq { self.history[(s % HISTORY_BITS / 64) as usize] &= !(1 << (s % 64)); } }
            }
        }
        let word = &mut self.history[(seq % HISTORY_BITS / 64) as usize];
        let mask = 1 << (seq % 64);
        if *word & mask != 0 {
            let deadline = {
                self.last_ack_ns.map_or(now, |last| last.saturating_add((rtt_us * 1000 / 16).max(1_000_000)))
            };
            *timer = (*timer).min(deadline); return false;
        }
        *word |= mask;
        self.highest = Some(old_highest.unwrap_or(seq).max(seq));
        self.sample_seq = seq;
        self.sample_time_ns = now;
        self.sample_udp_payload_bytes = sample_udp_payload_bytes;
        if ce { self.ce_count = self.ce_count.saturating_add(1); }
        let floor = self.highest.unwrap().saturating_sub(HISTORY_BITS - 1);
        self.feedback_pages.retain(|&(base, _)| base.saturating_add(ACK_BITMAP_BITS) > floor);
        let page = seq / ACK_BITMAP_BITS * ACK_BITMAP_BITS;
        if let Some((_, repeats)) = self.feedback_pages.iter_mut().find(|(base, _)| *base == page) { *repeats = 3; }
        else { self.feedback_pages.push_back((page, 3)); }
        if let Some(last) = self.last_arrival_ns {
            let gap = now.saturating_sub(last).clamp(1000, 100_000_000);
            self.mean_gap_ns = (self.mean_gap_ns * 7 + gap) / 8;
        }
        self.last_arrival_ns = Some(now);
        let (every_packets, max_delay_us) = self.policy(rtt_us, wire_bytes);
        self.pending = self.pending.saturating_add(1);
        let deadline = {
            let highest = self.highest.unwrap();
            if old_highest.is_some_and(|h| seq > h + 1) && self.gap_seq.is_none() {
                self.gap_seq = Some(old_highest.unwrap()+1); self.gap_since_ns = now;
            }
            if let Some(mut gap) = self.gap_seq {
                gap = gap.max(highest.saturating_sub(HISTORY_BITS-1));
                while gap <= highest && self.history[(gap%HISTORY_BITS/64) as usize] & (1 << (gap%64)) != 0 { gap += 1; }
                self.gap_seq = (gap <= highest).then_some(gap);
            }
            let mut due = if old_highest.is_none() || self.pending >= every_packets.max(1) { now }
                else { now.saturating_add(max_delay_us as u64 * 1000) };
            // Reordering is not a new loss event for each arrival. Wait for a persistent
            // gap (or16 later packets), then pace urgent feedback. Urgent
            // feedback is bounded even during sustained reordering.
            let reorder_ns = (rtt_us * 1000 / 16).max(1_000_000);
            if ce || self.gap_seq.is_some() {
                let matured = if ce || self.gap_seq.is_some_and(|gap| highest.saturating_sub(gap) >= 16) { now }
                    else { self.gap_since_ns.saturating_add(reorder_ns).max(now) };
                let guard_ns = reorder_ns.max((every_packets as u64 * self.mean_gap_ns).min(max_delay_us as u64 * 1000));
                let earliest = self.last_ack_ns.map_or(matured, |last| matured.max(last.saturating_add(guard_ns)));
                due = due.min(earliest);
            }
            due
        };
        *timer = (*timer).min(deadline);
        true
    }
    fn policy(&self, rtt_us: u64, wire_bytes: usize) -> (u16, u32) {
        let AckPolicy { every_packets, max_delay_us } = crate::ship::ACK;
        let pps = 1_000_000_000 / self.mean_gap_ns.max(1);
        // Use the encrypted UDP ACK size. At least this packet group
        // is needed for <=2% overhead, except when the delay cap forces a flush.
        let ack_bytes = (crate::stp::CONNECTED_HEADER_SIZE + ACK_PAYLOAD_LEN + 16) as u64;
        let budget_packets = (ack_bytes * 50).div_ceil(wire_bytes.max(1) as u64);
        let minimum = (every_packets as u64).max(budget_packets).clamp(1, 64);
        let n = pps.div_ceil(1000).clamp(minimum, 64);
        let budget_us = n * self.mean_gap_ns / 1000;
        let t = (rtt_us / 8).clamp(1000, max_delay_us.max(1000) as u64).max(budget_us).min(max_delay_us as u64);
        (n as u16, t as u32)
    }
    pub fn ack(&self, now: u64) -> BitmapAck {
        let highest = self.highest.unwrap_or(0);
        let base = self.feedback_pages.front().map_or(highest.saturating_sub(ACK_BITMAP_BITS - 1), |&(base, _)| base);
        let mut bitmap = [0; 15];
        let floor = highest.saturating_sub(HISTORY_BITS - 1);
        // Bounded by the fixed ACK size, independent of the sequence gap.
        for bit in 0..ACK_BITMAP_BITS {
            let seq = base + bit;
            if seq >= floor && seq <= highest && self.history[(seq%HISTORY_BITS/64) as usize] & (1 << (seq%64)) != 0 {
                bitmap[(bit/64) as usize] |= 1 << (bit%64);
            }
        }
        let mut a = BitmapAck { highest: self.sample_seq, receipt_base: base, sample_seq: self.sample_seq,
            delay_us: (now.saturating_sub(self.sample_time_ns)/1000).min(u32::MAX as u64) as u32,
            sample_udp_payload_bytes: self.sample_udp_payload_bytes,
            ce_count: self.ce_count, bitmap };
        a.highest = a.acknowledged().max().unwrap_or(a.sample_seq);
        a
    }
    pub fn sent(&mut self, now: u64) {
        self.pending = 0; self.last_ack_ns = Some(now);
        if let Some((page, repeats)) = self.feedback_pages.pop_front() {
            if repeats > 1 { self.feedback_pages.push_back((page, repeats-1)); }
        }
    }
    pub fn feedback_deadline(&self, now: u64) -> u64 {
        if self.feedback_pages.is_empty() { u64::MAX }
        else { now.saturating_add(crate::ship::ACK.max_delay_us as u64 * 1000) }
    }

}

/// Cumulative feedback is idempotent under ACK loss, duplication and reordering.
pub fn update_ce_count(previous: &mut u64, incoming: u64) -> bool {
    if incoming <= *previous { return false; }
    *previous = incoming;
    true
}

/// A peer cannot have admitted more unique CE packets than we sent. Reject an
/// impossible count before touching the baseline; delayed lower counts are inert.
pub fn update_ce_count_bounded(previous: &mut u64, incoming: u64, sent: u64) -> bool {
    incoming <= sent && update_ce_count(previous, incoming)
}
