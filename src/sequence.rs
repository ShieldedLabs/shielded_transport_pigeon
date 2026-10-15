//! Connected packet nonces: dense data [0,2^63), independent ACK [2^63,2^64).
//! The complete nonce is transmitted verbatim; there is no half-cycle inference.
pub const ACK_SPACE: u64 = 1 << 63;
const REPLAY_BITS: u64 = 262144;
pub fn to_wire(nonce: u64) -> u64 { nonce }
pub fn is_ack_space(wire: u64) -> bool { wire & ACK_SPACE != 0 }

#[derive(Debug, Clone)]
struct Space {
    highest: Option<u64>,
    history: Box<[u64]>,
}
impl Default for Space {
    fn default() -> Self { Self { highest: None, history: vec![0; (REPLAY_BITS / 64) as usize].into_boxed_slice() } }
}
impl Space {
    fn commit(&mut self, seq: u64) -> bool {
        if let Some(h) = self.highest {
            if seq < h.saturating_sub(REPLAY_BITS - 1) { return false; }
            if seq > h {
                if seq - h >= REPLAY_BITS { self.history.fill(0); }
                else {
                    for s in h+1..=seq { self.history[(s % REPLAY_BITS / 64) as usize] &= !(1 << (s % 64)); }
                }
            }
        }
        let word = &mut self.history[(seq % REPLAY_BITS / 64) as usize];
        let bit = 1 << (seq % 64);
        if *word & bit != 0 { return false; }
        *word |= bit;
        self.highest = Some(self.highest.unwrap_or(seq).max(seq));
        true
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReceiveSequences { data: Space, ack: Space }
impl ReceiveSequences {
    /// Non-mutating: call before AEAD decryption, commit only after authentication
    /// and validating that the decrypted size agrees with the nonce space.
    pub fn candidate(&self, wire: u64) -> u64 { wire }
    pub fn commit(&mut self, nonce: u64) -> bool {
        if nonce & ACK_SPACE != 0 { self.ack.commit(nonce & !ACK_SPACE) } else { self.data.commit(nonce) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separate_spaces_and_duplicate_replay_rejection() {
        let mut r = ReceiveSequences::default();
        for s in 0..100 {
            for nonce in [s, ACK_SPACE+s] {
                assert_eq!(r.candidate(to_wire(nonce)), nonce);
                assert!(r.commit(nonce));
                assert!(!r.commit(nonce));
            }
            assert_ne!(to_wire(s), to_wire(ACK_SPACE+s));
        }
        assert!(r.commit(5000));
        assert!(!r.commit(0));
        assert_eq!(r.candidate(to_wire(ACK_SPACE+100)), ACK_SPACE+100);
    }
    #[test]
    fn virtual_wrap_31_32_and_reordered_previous_cycle() {
        for boundary in [1 << 31, 1 << 32, 1u64 << 40] {
            let mut r = ReceiveSequences::default();
            // Force known authenticated state near the boundary, not an arbitrary
            // first wire packet: an initial epoch cannot be inferred from 31 bits.
            for base in [0, ACK_SPACE] {
                assert!(r.commit(base+boundary-3));
                for seq in [boundary-2, boundary, boundary-1, boundary+1] {
                    let nonce = base+seq;
                    assert_eq!(r.candidate(to_wire(nonce)), nonce);
                    assert!(r.commit(nonce));
                }
                assert!(!r.commit(base+boundary-1));
            }
        }
    }
    #[test]
    fn unauthenticated_candidates_never_change_extension() {
        let mut r = ReceiveSequences::default();
        assert!(r.commit((1 << 31)-3));
        let original = r.candidate(to_wire((1 << 31)-2));
        for w in [u64::MAX, 0, 123456789] { let _ = r.candidate(w); }
        assert_eq!(r.candidate(to_wire((1 << 31)-2)), original);
    }
    fn cipher_pair() -> (crate::stp::ConnectionCipherTriplet, crate::stp::ConnectionCipherTriplet) {
        let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let ka = snow::Builder::new(params.clone()).generate_keypair().unwrap();
        let kb = snow::Builder::new(params.clone()).generate_keypair().unwrap();
        let mut a = snow::Builder::new(params.clone()).local_private_key(&ka.private).unwrap().remote_public_key(&kb.public).unwrap().build_initiator().unwrap();
        let mut b = snow::Builder::new(params).local_private_key(&kb.private).unwrap().build_responder().unwrap();
        let mut enc = [0; 1024]; let mut dec = [0; 1024];
        let n = a.write_message(&[], &mut enc).unwrap(); b.read_message(&enc[..n], &mut dec).unwrap();
        let n = b.write_message(&[], &mut enc).unwrap(); a.read_message(&enc[..n], &mut dec).unwrap();
        (crate::stp::ConnectionCipherTriplet::new_from_old_init_only(a.into_stateless_transport_mode().unwrap()),
         crate::stp::ConnectionCipherTriplet::new_from_old_init_only(b.into_stateless_transport_mode().unwrap()))
    }
    #[test]
    fn encrypted_wrap_rotation_old_key_and_nonce_space_binding() {
        let (mut sender, mut receiver) = cipher_pair();
        let mut seqs = ReceiveSequences::default();
        let boundary = 1u64 << 32;
        seqs.commit(boundary-2); seqs.commit(ACK_SPACE+boundary-2);
        let mut enc = [0; 1024]; let mut dec = [0; 1024];
        let mut delayed = Vec::new();
        for seq in [boundary-1, boundary, boundary+1] {
            for base in [0, ACK_SPACE] {
                let nonce = base+seq;
                let n = sender.current.write_message(nonce, b"authenticated payload", &mut enc).unwrap();
                assert_eq!(seqs.candidate(to_wire(nonce)), nonce);
                assert!(receiver.current.read_message(nonce ^ ACK_SPACE, &enc[..n], &mut dec).is_err());
                if seq == boundary-1 { delayed.push((nonce, enc[..n].to_vec())); }
                if seq == boundary && base == 0 { // After sender rekey, new incoming key authenticates.
                    assert!(receiver.current.read_message(nonce, &enc[..n], &mut dec).is_err());
                    receiver.new.read_message(nonce, &enc[..n], &mut dec).unwrap();
                    receiver.ratchet_forward_incoming();
                } else { receiver.current.read_message(nonce, &enc[..n], &mut dec).unwrap(); }
                assert!(seqs.commit(nonce));
            }
            if seq == boundary-1 { sender.advance_outgoing(); }
        }
        for (nonce, packet) in delayed {
            receiver.old.as_ref().unwrap().read_message(nonce, &packet, &mut dec).unwrap();
            assert!(!seqs.commit(nonce)); // Rekey cannot reset the anti-replay history.
        }
    }
    #[test]
    fn full_nonce_survives_arbitrary_forward_gaps() {
        let mut r = ReceiveSequences::default();
        for s in [0, 1 << 32, 1 << 48, (1 << 63) - 2] {
            for n in [s, ACK_SPACE | s] {
                assert_eq!(r.candidate(to_wire(n)), n);
                assert!(r.commit(n));
            }
        }
    }
}
