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
    fn fresh(&self,seq:u64)->bool {
        let Some(h)=self.highest else {return true};
        if seq>h {return true;}
        seq>=h.saturating_sub(REPLAY_BITS-1) && self.history[(seq%REPLAY_BITS/64) as usize] & (1<<(seq%64))==0
    }
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
    /// Non-mutating replay admission, for atomic research whole-frame reservation.
    pub(crate) fn fresh(&self,nonce:u64)->bool {
        if nonce & ACK_SPACE != 0 {self.ack.fresh(nonce & !ACK_SPACE)}else{self.data.fresh(nonce)}
    }
    pub fn commit(&mut self, nonce: u64) -> bool {
        if nonce & ACK_SPACE != 0 { self.ack.commit(nonce & !ACK_SPACE) } else { self.data.commit(nonce) }
    }
}
