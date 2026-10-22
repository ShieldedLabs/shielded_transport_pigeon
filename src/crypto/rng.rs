//! ChaCha20 random stream compatible with rand_chacha 0.9 and rand_core 0.9.
//!
//! Seed expansion and word-consumption rules adapted from rand_core 0.9.3
//! and rand_chacha 0.9.0, https://github.com/rust-random/rand, under MIT:
//!
//! Copyright 2018 Developers of the Rand project
//! Copyright (c) 2014 The Rust Project Developers
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to
//! deal in the Software without restriction, including without limitation the
//! rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//! sell copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in
//! all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//! FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//! IN THE SOFTWARE.

/// Deterministic ChaCha20 stream with a 64-bit block counter and stream zero.
///
/// `seed_from_u64` is for reproducible tests, not secret key generation: its
/// seed has at most 64 bits of entropy. Use an OS-generated 32-byte seed for
/// cryptographic use. Partial fills discard unused bytes of the final u32,
/// exactly as rand_core::block::BlockRng does.
///
/// Drop wipes this instance's key and output buffer with volatile writes. This
/// does not guarantee erasure of caller-owned seeds, clones, or copies left in
/// registers or memory by moves and compiler-generated temporaries.
#[derive(Clone)]
pub struct ChaCha20Rng {
    key: [u8; 32],
    counter: u64,
    buffer: [u8; 64],
    word_index: usize,
}
impl ChaCha20Rng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: seed,
            counter: 0,
            buffer: [0; 64],
            word_index: 16,
        }
    }
    pub fn seed_from_u64(mut state: u64) -> Self {
        let mut seed = [0; 32];
        for chunk in seed.chunks_exact_mut(4) {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(11634580027462260723);
            let xorshifted = (((state >> 18) ^ state) >> 27) as u32;
            let value = xorshifted.rotate_right((state >> 59) as u32);
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        Self::from_seed(seed)
    }
    #[inline]
    fn refill(&mut self) {
        self.buffer = super::chacha20::block(&self.key, self.counter, 0);
        self.counter = self.counter.wrapping_add(1);
        self.word_index = 0;
    }
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        if self.word_index == 16 {
            self.refill();
        }
        let offset = self.word_index * 4;
        self.word_index += 1;
        u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().unwrap())
    }
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        let hi = self.next_u32() as u64;
        lo | (hi << 32)
    }
    pub fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        while !dest.is_empty() {
            if self.word_index == 16 {
                self.refill();
            }
            let offset = self.word_index * 4;
            let take = dest.len().min(64 - offset);
            dest[..take].copy_from_slice(&self.buffer[offset..offset + take]);
            // The upstream BlockRng consumes whole words, including when
            // the last requested byte is in the middle of a word.
            self.word_index += take.div_ceil(4);
            dest = &mut dest[take..];
        }
    }
    pub fn fill(&mut self, dest: &mut [u8]) {
        self.fill_bytes(dest);
    }
}

impl Drop for ChaCha20Rng {
    fn drop(&mut self) {
        super::wipe(&mut self.key);
        super::wipe(&mut self.buffer);
    }
}
