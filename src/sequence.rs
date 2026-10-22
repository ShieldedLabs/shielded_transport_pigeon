//! Connected packet nonces: dense data [0,2^63), independent ACK [2^63,2^64).
//! The wire carries low 31 counter bits; ACK class restores bit 63 internally.
pub const ACK_SPACE: u64 = 1 << 63; const REPLAY_BITS: u64 = 262144; pub const COUNTER_MASK: u32 = 0x7fff_ffff;
const COUNTER_CYCLE: u64 = 1 << 31; const MAX_COUNTER: u64 = ACK_SPACE - 2;
/// Nearest legal full counter to the largest authenticated counter (initially 0).
/// At an exact half-cycle tie choose the smaller counter. No wrap at either end.
pub fn reconstruct(low: u32, largest: Option<u64>, ack: bool) -> u64 {
    let anchor = largest.unwrap_or(0) & !ACK_SPACE;
    let base = (anchor & !(COUNTER_CYCLE - 1)) | (low & COUNTER_MASK) as u64; let mut best = None;
    for candidate in [base.checked_sub(COUNTER_CYCLE), Some(base), base.checked_add(COUNTER_CYCLE)].into_iter().flatten() {
        if candidate > MAX_COUNTER { continue; }
        if best.is_none_or(|b: u64| (candidate.abs_diff(anchor), candidate) < (b.abs_diff(anchor), b)) {
            best = Some(candidate); } }
    best.expect("every low counter has a legal representative") | if ack { ACK_SPACE } else { 0 } }
pub fn to_wire(nonce: u64) -> u64 { nonce }
pub fn is_ack_space(wire: u64) -> bool { wire & ACK_SPACE != 0 }
#[derive(Debug, Clone)] struct Space { highest: Option<u64>, history: Box<[u64]>, }
impl Default for Space {
    fn default() -> Self { Self { highest: None, history: vec![0; (REPLAY_BITS / 64) as usize].into_boxed_slice() } } }
impl Space {
    fn fresh(&self,seq:u64)->bool {
        let Some(h)=self.highest else {return true};
        if seq>h {return true;}
        seq>=h.saturating_sub(REPLAY_BITS-1) && self.history[(seq%REPLAY_BITS/64) as usize] & (1<<(seq%64))==0 }
    fn commit(&mut self, seq: u64) -> bool {
        if let Some(h) = self.highest {
            if seq < h.saturating_sub(REPLAY_BITS - 1) { return false; }
            if seq > h {
                if seq - h >= REPLAY_BITS { self.history.fill(0); }
                else { for s in h+1..=seq { self.history[(s % REPLAY_BITS / 64) as usize] &= !(1 << (s % 64)); } } } }
        let word = &mut self.history[(seq % REPLAY_BITS / 64) as usize]; let bit = 1 << (seq % 64);
        if *word & bit != 0 { return false; }
        *word |= bit; self.highest = Some(self.highest.unwrap_or(seq).max(seq));
        true } }
#[derive(Debug, Clone, Default)]
pub struct ReceiveSequences { data: Space, ack: Space, authenticated: [Option<u64>; 2] }
impl ReceiveSequences {
    pub fn candidate(&self, wire: u64) -> u64 { wire }
    pub fn compact_candidate(&self, wire: u32, ack: bool) -> u64 {
        reconstruct(wire, self.authenticated[ack as usize], ack) }
    pub fn authenticated(&mut self, nonce: u64) {
        let anchor = &mut self.authenticated[is_ack_space(nonce) as usize]; let counter = nonce & !ACK_SPACE;
        *anchor = Some(anchor.unwrap_or(counter).max(counter)); }
    pub(crate) fn fresh(&self,nonce:u64)->bool {
        if nonce & ACK_SPACE != 0 {self.ack.fresh(nonce & !ACK_SPACE)}else{self.data.fresh(nonce)} }
    pub fn commit(&mut self, nonce: u64) -> bool {
        if nonce & ACK_SPACE != 0 { self.ack.commit(nonce & !ACK_SPACE) } else { self.data.commit(nonce) } } }
