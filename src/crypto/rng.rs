#[derive(Clone)] pub struct ChaCha20Rng { key: [u8; 32], counter: u64, buffer: [u8; 64], word_index: usize, }
impl ChaCha20Rng {
    pub fn from_seed(seed: [u8; 32]) -> Self { Self { key: seed, counter: 0, buffer: [0; 64], word_index: 16, } }
    pub fn seed_from_u64(mut state: u64) -> Self {
        let mut seed = [0; 32];
        for chunk in seed.chunks_exact_mut(4) {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(11634580027462260723);
            let xorshifted = (((state >> 18) ^ state) >> 27) as u32; let value = xorshifted.rotate_right((state >> 59) as u32);
            chunk.copy_from_slice(&value.to_le_bytes()); }
        Self::from_seed(seed) }
    #[inline] fn refill(&mut self) {
        self.buffer = super::chacha20::block(&self.key, self.counter, 0); self.counter = self.counter.wrapping_add(1);
        self.word_index = 0; }
    #[inline] pub fn next_u32(&mut self) -> u32 {
        if self.word_index == 16 { self.refill(); }
        let offset = self.word_index * 4; self.word_index += 1;
        u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().unwrap()) }
    #[inline] pub fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64; let hi = self.next_u32() as u64;
        lo | (hi << 32) }
    pub fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        while !dest.is_empty() {
            if self.word_index == 16 { self.refill(); }
            let offset = self.word_index * 4; let take = dest.len().min(64 - offset);
            dest[..take].copy_from_slice(&self.buffer[offset..offset + take]); self.word_index += take.div_ceil(4);
            dest = &mut dest[take..]; } }
    pub fn fill(&mut self, dest: &mut [u8]) { self.fill_bytes(dest); } }
impl Drop for ChaCha20Rng { fn drop(&mut self) { super::wipe(&mut self.key); super::wipe(&mut self.buffer); } }
