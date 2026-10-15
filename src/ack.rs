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
    pub delay_us: u32,
    /// Cumulative number of unique CE-marked data/probe/keepalive packets, saturating at u64::MAX (close before exhaustion).
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
        // bytes 28..32: encoding 0 (bitmap), reserved zero.
        for (i, w) in self.bitmap.iter().enumerate() { b[32+i*8..40+i*8].copy_from_slice(&w.to_le_bytes()); }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != ACK_PAYLOAD_LEN || b[28..32] != [0; 4] { return None; }
        let mut a = Self {
            highest: 0,
            receipt_base: u64::from_le_bytes(b[..8].try_into().ok()?),
            sample_seq: u64::from_le_bytes(b[8..16].try_into().ok()?),
            ce_count: u64::from_le_bytes(b[16..24].try_into().ok()?),
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
    fn default() -> Self { Self { history: vec![0; (HISTORY_BITS/64) as usize].into_boxed_slice(), highest: None, sample_seq: 0, sample_time_ns: 0, ce_count: 0, pending: 0, last_arrival_ns: None, mean_gap_ns: 1_000_000, gap_seq: None, gap_since_ns: 0, last_ack_ns: None, feedback_pages: std::collections::VecDeque::new() } }
}
impl AckReceiver {
    /// Returns false for duplicate/too-old data; duplicates still refresh ACK feedback.
    pub fn receive(&mut self, seq: u64, now: u64, ce: bool, timer: &mut u64) -> bool {
        self.receive_with_rtt(seq, now, ce, timer, 0, 1204)
    }
    pub fn receive_with_rtt(&mut self, seq: u64, now: u64, ce: bool, timer: &mut u64, rtt_us: u64, wire_bytes: usize) -> bool {
        if seq >= crate::sequence::ACK_SPACE { return false; }
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
        // 182 bytes is the encrypted UDP ACK size. At least this packet group
        // is needed for <=2% overhead, except when the delay cap forces a flush.
        let budget_packets = (182u64 * 50).div_ceil(wire_bytes.max(1) as u64);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_schedules_the_only_ack_format() {
        let mut r = AckReceiver::default();
        let mut timer = u64::MAX;
        assert!(r.receive(0, 0, false, &mut timer));
        assert_eq!(timer, 0);
        assert!(r.ack(0).contains(0));
    }

    fn recv(r: &mut AckReceiver, seq: u64, t: u64, ce: bool) -> (bool, u64) {
        let mut timer = u64::MAX;
        let ok = r.receive(seq, t, ce, &mut timer);
        (ok, timer)
    }
    #[test]
    fn encoding_and_reordered_arrivals() {
        let mut r = AckReceiver::default();
        recv(&mut r, 0, 1000, false); recv(&mut r, 2, 2000, true);
        assert!(!r.ack(3000).contains(1));
        assert!(recv(&mut r, 1, 4000, false).0);
        let a = r.ack(9000);
        assert_eq!(a.acknowledged().collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!((a.sample_seq, a.delay_us, a.ce_count), (1, 5, 1));
        assert_eq!(BitmapAck::decode(&a.encode()), Some(a));
        assert!(BitmapAck::decode(&[0; ACK_PAYLOAD_LEN-1]).is_none());
    }
    #[test]
    fn rolling_history_and_explicit_late_sample() {
        let mut r = AckReceiver::default();
        for s in 0..5000 { recv(&mut r, s, s*1000, false); }
        assert_eq!(r.ack(5_000_000).acknowledged().count(), 961);
        assert_eq!(recv(&mut r, 4096, 6_000_000, true).0, false); // duplicate after ring wrap
        assert_eq!(recv(&mut r, 0, 6_000_000, true).0, false); // duplicate already received
        let mut r = AckReceiver::default();
        recv(&mut r, 0, 0, false); recv(&mut r, 3000, 1000, false);
        recv(&mut r, 1, 2000, true);
        let a = r.ack(3000);
        assert!(a.contains(1));
        assert_eq!(a.acknowledged().collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(a.ce_count, 1);
    }
    #[test]
    fn count_timer_duplicates_and_ce_are_idempotent() {
        let mut r = AckReceiver::default(); let mut timer = u64::MAX;
        r.receive(0, 0, false, &mut timer);
        r.sent(0); timer = u64::MAX;
        for s in 1..8 { assert!(r.receive(s, s*100, false, &mut timer)); }
        assert!(timer > 700 && timer <= 10_000_100);
        r.receive(8, 800, false, &mut timer);
        assert_eq!(timer, 800);
        assert!(!r.receive(8, 900, true, &mut timer));
        assert_eq!(r.ack(1000).ce_count, 0);
        let mut ce = 0;
        assert!(update_ce_count(&mut ce, 2));
        assert!(!update_ce_count(&mut ce, 2)); assert!(!update_ce_count(&mut ce, 1));
        ce = u32::MAX as u64; assert!(update_ce_count(&mut ce, 1u64 << 40));
    }
    #[test]
    fn bitmap_alignment_and_gaps() {
        let mut r = AckReceiver::default();
        for s in 0..10000 { if s%7 != 0 { recv(&mut r, s, s, false); } }
        let a = r.ack(10001);
        for s in a.base()..a.base()+ACK_BITMAP_BITS { assert_eq!(a.contains(s), s%7 != 0, "seq {s}"); }
    }
    #[test]
    fn lost_and_reordered_acks_repeat_positive_receipts() {
        let mut r = AckReceiver::default();
        recv(&mut r, 10, 1000, true);
        let old = r.ack(2000); // ACK lost on the network
        recv(&mut r, 12, 3000, false);
        let new = r.ack(4000);
        assert!(new.contains(10)); assert!(!new.contains(11));
        let mut seen_ce = 0;
        assert!(update_ce_count(&mut seen_ce, new.ce_count));
        assert!(!update_ce_count(&mut seen_ce, old.ce_count));
        recv(&mut r, 11, 5000, false);
        assert_eq!(r.ack(6000).acknowledged().collect::<Vec<_>>(), vec![10, 11, 12]);
        // A duplicate cannot change the sample, its delay origin, or cumulative CE.
        recv(&mut r, 11, 7000, true);
        let a = r.ack(9000);
        assert_eq!((a.sample_seq, a.delay_us, a.ce_count), (11, 4, 1));
    }
    #[test]
    fn malformed_and_future_bitmap_positions() {
        let mut r = AckReceiver::default(); recv(&mut r, 1, 0, false);
        let a = r.ack(0);
        let mut bytes = a.encode(); bytes[28] = 1;
        assert!(BitmapAck::decode(&bytes).is_none());
        bytes = a.encode(); bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(BitmapAck::decode(&bytes).is_none());
    }
    #[test]
    fn relevant_masks_align_across_ring_wrap_and_keep_late_losses() {
        for highest in [1030, 4000, 262150] {
            let mut r = AckReceiver::default();
            for s in highest-1023..=highest { recv(&mut r, s, s, false); }
            let mut a = r.ack(highest+1);
            a.receipt_base = highest - 959;
            a.bitmap = [u64::MAX; 15];
            let mut waiting = [0u64; 4096]; let mut lost = [0u64; 4096];
            let keep = [highest-900, highest-800, highest-63, highest];
            for (i, &s) in keep.iter().enumerate() {
                let ring = if i%2 == 0 { &mut waiting } else { &mut lost };
                ring[(s%262144/64) as usize] |= 1 << (s%64);
            }
            assert_eq!(a.relevant(&waiting, &lost).acknowledged().collect::<Vec<_>>(), keep);
            assert_eq!(a.relevant(&[0; 4096], &[0; 4096]).acknowledged().collect::<Vec<_>>(), vec![highest]);
        }
    }
    #[test]
    fn adaptive_policy_balances_budget_rtt_and_delay_cap() {
        let mut r = AckReceiver::default();
        assert_eq!(r.policy(10000, 1472), (8, 8000));
        r.mean_gap_ns = 100_000;
        assert_eq!(r.policy(10000, 1472), (10, 1250));
        r.mean_gap_ns = 20_000;
        assert_eq!(r.policy(10000, 1472), (50, 1250));
        r.mean_gap_ns = 1000;
        assert_eq!(r.policy(200000, 539), (64, 10000));
        r.mean_gap_ns = 1_000_000;
        assert_eq!(r.policy(10000, 539), (17, 10000)); // deadline cap wins; budget cannot be met
    }
    #[test]
    fn adaptive_waits_for_reordering_and_rate_limits_ce() {
        let mut r = AckReceiver::default();
        let mut timer = u64::MAX;
        assert!(r.receive_with_rtt(0, 0, false, &mut timer, 40000, 1472));
        r.sent(0); timer = u64::MAX;
        assert!(r.receive_with_rtt(2, 100_000, false, &mut timer, 40000, 1472));
        assert!(timer >= 2_500_000); // no immediate ACK for a transient gap
        assert!(r.receive_with_rtt(1, 200_000, false, &mut timer, 40000, 1472));
        assert!(r.gap_seq.is_none());
        r.sent(300_000); timer = u64::MAX;
        r.receive_with_rtt(3, 400_000, true, &mut timer, 40000, 1472);
        assert!(timer > 400_000); // CE burst shares the bounded urgent-feedback budget
        r.sent(400_000); timer = u64::MAX;
        r.receive_with_rtt(4, 20_000_000, true, &mut timer, 40000, 1472);
        assert_eq!(timer, 20_000_000); // first CE after the guard is immediate
        assert_eq!(r.ack(20_000_000).ce_count, 2);
    }
    #[test]
    fn hello_sizes_are_not_ack_sizes() {
        use crate::stp::*;
        assert_eq!(6+32+MAGIC2_BLOCK_SIZE, 327);
        for magic in [CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b] {
            let client = new_keypair_from_connect_magic1(magic).unwrap();
            let server = new_keypair_from_connect_magic1(magic).unwrap();
            let params = crypto_string_from_connect_magic1(magic).unwrap();
            let prologue = magic.to_le_bytes();
            let mut c = snow::Builder::new(params.parse().unwrap()).prologue(&prologue[..6]).unwrap().local_private_key(&client.private).unwrap().remote_public_key(&server.public).unwrap().build_initiator().unwrap();
            let mut s = snow::Builder::new(params.parse().unwrap()).prologue(&prologue[..6]).unwrap().local_private_key(&server.private).unwrap().build_responder().unwrap();
            let mut packet = [0; 1024]; let mut payload = [0; 1024];
            let n = c.write_message(&build_magic2_client_block(), &mut packet).unwrap();
            assert_eq!(n+6, 391);
            s.read_message(&packet[..n], &mut payload).unwrap();
            let n = s.write_message(&[0; 40], &mut packet).unwrap();
            assert_eq!(n+6, 94);
            for hello_udp_len in [327, 78, 391, 94] {
                assert_ne!(hello_udp_len, ACK_PAYLOAD_LEN+30);
                assert_ne!(hello_udp_len, ACK_PAYLOAD_LEN+14);
            }
        }
    }
    #[test]
    fn integrated_packet_size_inventory() {
        use crate::stp::*;
        // (crypto, bitmap ACK, minimum trimmed data, initial keepalive/probe).
        for (magic, expected) in [
            (CONNECT_MAGIC1_PLAIN_TEXT, [166, 531, 1204]),
            (CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, [182, 547, 1204]),
            (CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b, [182, 547, 1204]),
        ] {
            let overhead = total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic).unwrap();
            let sizes = [ACK_PAYLOAD_LEN + overhead, 517 + overhead, 1204];
            assert_eq!(sizes, expected);
            for udp_len in [sizes[1], sizes[2]] {
                assert!(udp_len - overhead >= 517);
                assert_ne!(udp_len - overhead, 152);
            }
        }
        // Outer dispatch handles these before authenticated ordinary-traffic classification.
        assert_eq!([6 + 32 + MAGIC2_BLOCK_SIZE, 6 + 32 + 48 + MAGIC2_BLOCK_SIZE + 16, 6 + 32 + 40, 6 + 32 + 40 + 16], [327, 391, 78, 94]);
    }

    #[test]
    fn repeated_arbitrary_windows_cover_deep_reordering_and_idle_feedback() {
        let mut r = AckReceiver::default();
        let seqs = [200000, 1, 1921, 40000, 100000, 120000, 12345];
        let mut expected = std::collections::BTreeSet::from(seqs);
        for (t, seq) in seqs.into_iter().enumerate() { assert!(recv(&mut r, seq, t as u64, false).0); }
        let pages = r.feedback_pages.len();
        let mut counts = std::collections::BTreeMap::<u64,usize>::new();
        for t in 0..pages*3 {
            assert_ne!(r.feedback_deadline(t as u64),u64::MAX);
            let a = r.ack(t as u64);
            assert_eq!(BitmapAck::decode(&a.encode()),Some(a.clone()));
            *counts.entry(a.receipt_base).or_default() += 1;
            for seq in a.acknowledged() { expected.remove(&seq); }
            r.sent(t as u64);
        }
        assert!(expected.is_empty()); assert!(counts.values().all(|&n| n==3));
        assert_eq!(r.feedback_deadline(100),u64::MAX);
        // A late arrival starts a fresh older window without resetting sample timing.
        assert!(recv(&mut r, 20, 100, true).0);
        let a=r.ack(1100); assert!(a.contains(20)); assert_eq!((a.sample_seq,a.delay_us,a.ce_count),(20,1,1));
        let mut arbitrary=a.clone(); arbitrary.receipt_base=19; arbitrary.bitmap=[0;15]; arbitrary.bitmap[0]=2;
        assert_eq!(BitmapAck::decode(&arbitrary.encode()).unwrap().acknowledged().collect::<Vec<_>>(),vec![20]);
    }

    #[test]
    fn size_cannot_collide_with_data_keepalive_or_probe() {
        use crate::stp::*;
        use crate::native_sockets::ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY;
        for magic in [CONNECT_MAGIC1_PLAIN_TEXT, CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s] {
            let overhead = total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic).unwrap();
            assert!(ACK_PAYLOAD_LEN + overhead < ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY);
        }
    }
    #[test]
    fn impossible_ce_counts_never_poison_the_baseline() {
        let mut ce = 3;
        for bad in [2, 3, 11, u64::MAX] {
            assert!(!update_ce_count_bounded(&mut ce, bad, 10));
            assert_eq!(ce, 3);
        }
        assert!(update_ce_count_bounded(&mut ce, 5, 10));
        assert_eq!(ce, 5);
        assert!(!update_ce_count_bounded(&mut ce, 4, 12));
        assert!(update_ce_count_bounded(&mut ce, 12, 12));
        assert_eq!(ce, 12);
    }

}
