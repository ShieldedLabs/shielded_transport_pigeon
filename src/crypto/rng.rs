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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropping_original_preserves_clone_stream() {
        let mut original = ChaCha20Rng::seed_from_u64(19);
        original.fill_bytes(&mut [0; 7]);
        let mut cloned = original.clone();
        let mut expected = [0; 513];
        original.fill_bytes(&mut expected);
        drop(original);
        let mut actual = [0; 513];
        cloned.fill_bytes(&mut actual);
        assert_eq!(actual, expected);
    }
    #[test]
    fn original_chacha20_zero_vector() {
        // Bernstein's original ChaCha20, zero key/counter/64-bit nonce.
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        let mut bytes = [0; 64];
        ChaCha20Rng::from_seed([0; 32]).fill_bytes(&mut bytes);
        assert_eq!(bytes, expected);
    }
    #[test]
    fn rand_chacha_seed_from_u64_vectors() {
        // Generated with the dependency versions in the original Cargo.lock:
        // rand_chacha 0.9.0 and rand_core 0.9.5.
        let vectors = [
            (
                0,
                [
                    2180380594, 104652502, 1862083240, 4217733758, 25432000, 3696978537,
                    3534157108, 798113791,
                ],
            ),
            (
                1,
                [
                    1346647962, 2657312837, 2713153734, 657148285, 175834942, 2348138134,
                    2030532263, 1851016421,
                ],
            ),
            (
                19,
                [
                    4192914470, 3863904707, 4133012985, 3973509725, 2249218731, 712606703,
                    2345272826, 3801548320,
                ],
            ),
            (
                u64::MAX,
                [
                    1739146126, 1070697805, 144332205, 272869498, 1857488666, 3857814574,
                    558305090, 3522848942,
                ],
            ),
        ];
        for (seed, expected) in vectors {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            assert_eq!(
                core::array::from_fn::<_, 8, _>(|_| rng.next_u32()),
                expected
            );
        }
    }
    #[test]
    fn mixed_reads_consume_whole_words() {
        let mut reference = ChaCha20Rng::seed_from_u64(19);
        let mut rng = reference.clone();
        let mut bytes = [0; 512];
        reference.fill_bytes(&mut bytes);
        let mut cursor = 0;
        for len in [0usize, 1, 3, 4, 5, 17, 63, 65, 0, 2] {
            let mut out = vec![0; len];
            rng.fill_bytes(&mut out);
            assert_eq!(&out, &bytes[cursor..cursor + len]);
            cursor += len.div_ceil(4) * 4;
            assert_eq!(
                rng.next_u32(),
                u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap())
            );
            cursor += 4;
            assert_eq!(
                rng.next_u64(),
                u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap())
            );
            cursor += 8;
        }
    }
}
