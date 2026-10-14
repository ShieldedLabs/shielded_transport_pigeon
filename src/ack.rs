//! Size-identified low-delay acknowledgements. No allocation or bandwidth-sized history.
pub const ACK_PAYLOAD_LEN: usize = 152;
pub const ACK_BITMAP_BITS: u64 = 1024;
const HISTORY_BITS: u64 = 4096;

#[derive(Debug, Clone, Copy)]
pub enum AckOptions {
    /// Original 516-byte bitmap and 50 ms timer; for old peers and comparisons.
    Legacy,
    /// ACK at this packet count or delay, whichever comes first. Gaps, reordering,
    /// duplicates and CE schedule an immediate ACK (coalesced within a receive batch).
    LowLatency { every_packets: u16, max_delay_us: u32 },
    /// Rate/RTT-scaled batching. Packet threshold grows up to64, targeting1000 ACK/s;
    /// deadline uses RTT/8 plus a packet-budget floor, bounded by max_delay_us.
    Adaptive { every_packets: u16, max_delay_us: u32 },
}
impl Default for AckOptions {
    fn default() -> Self { Self::LowLatency { every_packets: 8, max_delay_us: 1000 } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapAck {
    pub highest: u64,
    /// Most recently received unique packet, also acknowledged even outside the bitmap.
    pub sample_seq: u64,
    pub delay_us: u32,
    /// Cumulative number of unique CE-marked data/probe/keepalive packets, modulo 2^32.
    pub ce_count: u32,
    pub bitmap: [u64; 16],
}
impl BitmapAck {
    pub fn base(&self) -> u64 { self.highest.saturating_sub(ACK_BITMAP_BITS - 1) }
    pub fn encode(&self) -> [u8; ACK_PAYLOAD_LEN] {
        let mut b = [0; ACK_PAYLOAD_LEN];
        b[..8].copy_from_slice(&self.highest.to_le_bytes());
        b[8..16].copy_from_slice(&self.sample_seq.to_le_bytes());
        b[16..20].copy_from_slice(&self.delay_us.to_le_bytes());
        b[20..24].copy_from_slice(&self.ce_count.to_le_bytes());
        for (i, w) in self.bitmap.iter().enumerate() { b[24+i*8..32+i*8].copy_from_slice(&w.to_le_bytes()); }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != ACK_PAYLOAD_LEN { return None; }
        let mut a = Self {
            highest: u64::from_le_bytes(b[..8].try_into().ok()?),
            sample_seq: u64::from_le_bytes(b[8..16].try_into().ok()?),
            delay_us: u32::from_le_bytes(b[16..20].try_into().ok()?),
            ce_count: u32::from_le_bytes(b[20..24].try_into().ok()?), bitmap: [0; 16],
        };
        for (i, w) in a.bitmap.iter_mut().enumerate() { *w = u64::from_le_bytes(b[24+i*8..32+i*8].try_into().ok()?); }
        if a.sample_seq > a.highest || !a.contains(a.highest) { return None; }
        Some(a)
    }
    pub fn contains(&self, seq: u64) -> bool {
        if seq < self.base() || seq > self.highest { return false; }
        let bit = seq - self.base();
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
        }).filter(|&s| s <= self.highest).chain(
            (!self.contains(self.sample_seq)).then_some(self.sample_seq))
    }
}

#[derive(Debug)]
pub struct AckReceiver {
    history: [u64; 64],
    highest: Option<u64>,
    sample_seq: u64,
    sample_time_ns: u64,
    ce_count: u32,
    pending: u16,
    last_arrival_ns: Option<u64>,
    mean_gap_ns: u64,
}
impl Default for AckReceiver {
    fn default() -> Self { Self { history: [0; 64], highest: None, sample_seq: 0, sample_time_ns: 0, ce_count: 0, pending: 0, last_arrival_ns: None, mean_gap_ns: 1_000_000 } }
}
impl AckReceiver {
    /// Returns false for duplicate/too-old data; duplicates still refresh ACK feedback.
    pub fn receive(&mut self, seq: u64, now: u64, ce: bool, options: AckOptions, timer: &mut u64) -> bool {
        self.receive_with_rtt(seq, now, ce, options, timer, 0, 1184)
    }
    pub fn receive_with_rtt(&mut self, seq: u64, now: u64, ce: bool, options: AckOptions, timer: &mut u64, rtt_us: u64, wire_bytes: usize) -> bool {
        if matches!(options, AckOptions::Legacy) { return false; }
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
        if *word & mask != 0 { *timer = (*timer).min(now); return false; }
        *word |= mask;
        self.highest = Some(old_highest.unwrap_or(seq).max(seq));
        self.sample_seq = seq;
        self.sample_time_ns = now;
        if ce { self.ce_count = self.ce_count.wrapping_add(1); }
        if let Some(last) = self.last_arrival_ns {
            let gap = now.saturating_sub(last).clamp(1000, 100_000_000);
            self.mean_gap_ns = (self.mean_gap_ns * 7 + gap) / 8;
        }
        self.last_arrival_ns = Some(now);
        let (every_packets, max_delay_us) = self.policy(options, rtt_us, wire_bytes);
        self.pending = self.pending.saturating_add(1);
        let urgent = ce || old_highest.is_none_or(|h| seq != h + 1) || self.pending >= every_packets.max(1);
        *timer = (*timer).min(now.saturating_add(if urgent { 0 } else { max_delay_us as u64 * 1000 }));
        true
    }
    fn policy(&self, options: AckOptions, rtt_us: u64, wire_bytes: usize) -> (u16, u32) {
        match options {
            AckOptions::LowLatency { every_packets, max_delay_us } => (every_packets, max_delay_us),
            AckOptions::Adaptive { every_packets, max_delay_us } => {
                let pps = 1_000_000_000 / self.mean_gap_ns.max(1);
                // 174 bytes is the encrypted UDP ACK size. At least this packet group
                // is needed for <=2% overhead, except when the delay cap forces a flush.
                let budget_packets = (174u64 * 50).div_ceil(wire_bytes.max(1) as u64);
                let minimum = (every_packets as u64).max(budget_packets).clamp(1, 64);
                let n = pps.div_ceil(1000).clamp(minimum, 64);
                let budget_us = n * self.mean_gap_ns / 1000;
                let t = (rtt_us / 8).clamp(1000, max_delay_us.max(1000) as u64).max(budget_us).min(max_delay_us as u64);
                (n as u16, t as u32)
            }
            AckOptions::Legacy => (0, 0),
        }
    }
    pub fn ack(&self, now: u64) -> BitmapAck {
        let highest = self.highest.unwrap_or(0);
        let base = highest.saturating_sub(ACK_BITMAP_BITS - 1);
        let mut bitmap = [0; 16];
        let shift = base % 64;
        for (i, w) in bitmap.iter_mut().enumerate() {
            let slot = (base / 64 + i as u64) as usize % 64;
            *w = self.history[slot] >> shift;
            if shift != 0 { *w |= self.history[(slot+1)%64] << (64-shift); }
        }
        // During connection start, positions beyond highest wrap around to old history.
        let used = (highest-base+1) as usize;
        if used < 1024 {
            if used % 64 != 0 { bitmap[used/64] &= (1 << (used%64))-1; }
            for w in &mut bitmap[(used+63)/64..] { *w = 0; }
        }
        BitmapAck { highest, sample_seq: self.sample_seq,
            delay_us: (now.saturating_sub(self.sample_time_ns)/1000).min(u32::MAX as u64) as u32,
            ce_count: self.ce_count, bitmap }
    }
    pub fn sent(&mut self) { self.pending = 0; }
}

/// Cumulative feedback is idempotent under ACK loss, duplication and reordering.
pub fn update_ce_count(previous: &mut u32, incoming: u32) -> bool {
    let delta = incoming.wrapping_sub(*previous);
    if delta == 0 || delta >= 1 << 31 { return false; }
    *previous = incoming;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn recv(r: &mut AckReceiver, seq: u64, t: u64, ce: bool) -> (bool, u64) {
        let mut timer = u64::MAX;
        let ok = r.receive(seq, t, ce, AckOptions::default(), &mut timer);
        (ok, timer)
    }
    #[test]
    fn encoding_and_reordered_arrivals() {
        let mut r = AckReceiver::default();
        recv(&mut r, 0, 1000, false); recv(&mut r, 2, 2000, true);
        assert!(!r.ack(3000).contains(1));
        assert_eq!(recv(&mut r, 1, 4000, false), (true, 4000));
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
        assert_eq!(r.ack(5_000_000).acknowledged().count(), 1024);
        assert_eq!(recv(&mut r, 4096, 6_000_000, true).0, false); // duplicate after ring wrap
        assert_eq!(recv(&mut r, 0, 6_000_000, true).0, false); // outside history
        let mut r = AckReceiver::default();
        recv(&mut r, 0, 0, false); recv(&mut r, 3000, 1000, false);
        recv(&mut r, 1, 2000, true);
        let a = r.ack(3000);
        assert!(!a.contains(1));
        assert_eq!(a.acknowledged().collect::<Vec<_>>(), vec![3000, 1]);
        assert_eq!(a.ce_count, 1);
    }
    #[test]
    fn count_timer_duplicates_and_ce_are_idempotent() {
        let mut r = AckReceiver::default(); let mut timer = u64::MAX;
        r.receive(0, 0, false, AckOptions::default(), &mut timer);
        r.sent(); timer = u64::MAX;
        for s in 1..8 { assert!(r.receive(s, s*100, false, AckOptions::default(), &mut timer)); }
        assert_eq!(timer, 1_000_100);
        r.receive(8, 800, false, AckOptions::default(), &mut timer);
        assert_eq!(timer, 800);
        assert!(!r.receive(8, 900, true, AckOptions::default(), &mut timer));
        assert_eq!(r.ack(1000).ce_count, 0);
        let mut ce = 0;
        assert!(update_ce_count(&mut ce, 2));
        assert!(!update_ce_count(&mut ce, 2)); assert!(!update_ce_count(&mut ce, 1));
        ce = u32::MAX; assert!(update_ce_count(&mut ce, 0));
    }
    #[test]
    fn bitmap_alignment_and_gaps() {
        let mut r = AckReceiver::default();
        for s in 0..10000 { if s%7 != 0 { recv(&mut r, s, s, false); } }
        let a = r.ack(10001);
        for s in a.base()..=a.highest { assert_eq!(a.contains(s), s%7 != 0, "seq {s}"); }
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
        let mut a = r.ack(0); a.sample_seq = 2;
        assert!(BitmapAck::decode(&a.encode()).is_none());
        a.sample_seq = 1; a.bitmap[0] = 0;
        assert!(BitmapAck::decode(&a.encode()).is_none());
        a.bitmap[0] = u64::MAX;
        assert_eq!(BitmapAck::decode(&a.encode()).unwrap().acknowledged().collect::<Vec<_>>(), vec![0, 1]);
    }
    #[test]
    fn relevant_masks_align_across_ring_wrap_and_keep_late_losses() {
        for highest in [1030, 4000, 262150] {
            let mut r = AckReceiver::default();
            for s in highest-1023..=highest { recv(&mut r, s, s, false); }
            let a = r.ack(highest+1);
            let mut waiting = [0u64; 4096]; let mut lost = [0u64; 4096];
            let keep = [highest-1000, highest-800, highest-63, highest];
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
        let opts = AckOptions::Adaptive { every_packets: 8, max_delay_us: 10000 };
        assert_eq!(r.policy(opts, 10000, 1472), (8, 8000));
        r.mean_gap_ns = 100_000;
        assert_eq!(r.policy(opts, 10000, 1472), (10, 1250));
        r.mean_gap_ns = 20_000;
        assert_eq!(r.policy(opts, 10000, 1472), (50, 1250));
        r.mean_gap_ns = 1000;
        assert_eq!(r.policy(opts, 200000, 539), (64, 10000));
        r.mean_gap_ns = 1_000_000;
        assert_eq!(r.policy(opts, 10000, 539), (17, 10000)); // deadline cap wins; budget cannot be met
    }
    #[test]
    fn hello_sizes_are_not_ack_sizes() {
        use crate::stp::*;
        assert_eq!(6+32+MAGIC2_BLOCK_SIZE, 295);
        for magic in [CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b] {
            let client = new_keypair_from_connect_magic1(magic).unwrap();
            let server = new_keypair_from_connect_magic1(magic).unwrap();
            let params = crypto_string_from_connect_magic1(magic).unwrap();
            let prologue = magic.to_le_bytes();
            let mut c = snow::Builder::new(params.parse().unwrap()).prologue(&prologue[..6]).unwrap().local_private_key(&client.private).unwrap().remote_public_key(&server.public).unwrap().build_initiator().unwrap();
            let mut s = snow::Builder::new(params.parse().unwrap()).prologue(&prologue[..6]).unwrap().local_private_key(&server.private).unwrap().build_responder().unwrap();
            let mut packet = [0; 1024]; let mut payload = [0; 1024];
            let n = c.write_message(&build_magic2_client_block(), &mut packet).unwrap();
            assert_eq!(n+6, 359);
            s.read_message(&packet[..n], &mut payload).unwrap();
            let n = s.write_message(&1u64.to_le_bytes(), &mut packet).unwrap();
            assert_eq!(n+6, 62);
            for hello_udp_len in [295, 46, 359, 62] {
                assert_ne!(hello_udp_len, ACK_PAYLOAD_LEN+22);
                assert_ne!(hello_udp_len, ACK_PAYLOAD_LEN+6);
                assert_ne!(hello_udp_len, 516+22);
                assert_ne!(hello_udp_len, 516+6);
            }
        }
    }
    #[test]
    fn size_cannot_collide_with_data_keepalive_or_probe() {
        use crate::stp::*;
        use crate::native_sockets::ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY;
        assert_ne!(ACK_PAYLOAD_LEN, std::mem::size_of::<AckField>());
        for magic in [CONNECT_MAGIC1_PLAIN_TEXT, CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s] {
            let overhead = total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic).unwrap();
            assert!(ACK_PAYLOAD_LEN + overhead < ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY);
        }
    }
}
