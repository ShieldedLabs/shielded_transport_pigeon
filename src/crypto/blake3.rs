//! BLAKE3 with incremental hashing, extendable output, and a portable fallback.
//!
//! Compression and chunk processing adapted from BLAKE3 1.8.2
//! (https://github.com/BLAKE3-team/BLAKE3), by the BLAKE3 team, under
//! CC0-1.0: https://creativecommons.org/publicdomain/zero/1.0/legalcode.
//! The upstream implementation is available under CC0 or Apache-2.0;
//! this adaptation elects CC0. Bulk input uses runtime-detected AVX2 Rust
//! intrinsics on x86/x86_64; no assembly, native builds, or external crates.

use core::fmt;

pub const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const MAX_DEPTH: usize = 54;
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];
const CHUNK_START: u8 = 1;
const CHUNK_END: u8 = 2;
const PARENT: u8 = 4;
const ROOT: u8 = 8;

#[inline(always)]
fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

#[inline(always)]
fn round(s: &mut [u32; 16], m: &[u32; 16], round: usize) {
    let p = MSG_SCHEDULE[round];
    g(s, 0, 4, 8, 12, m[p[0]], m[p[1]]);
    g(s, 1, 5, 9, 13, m[p[2]], m[p[3]]);
    g(s, 2, 6, 10, 14, m[p[4]], m[p[5]]);
    g(s, 3, 7, 11, 15, m[p[6]], m[p[7]]);
    g(s, 0, 5, 10, 15, m[p[8]], m[p[9]]);
    g(s, 1, 6, 11, 12, m[p[10]], m[p[11]]);
    g(s, 2, 7, 8, 13, m[p[12]], m[p[13]]);
    g(s, 3, 4, 9, 14, m[p[14]], m[p[15]]);
}

#[inline]
fn compress(cv: &[u32; 8], block: &[u8; 64], len: u8, counter: u64, flags: u8) -> [u32; 16] {
    let mut m = [0; 16];
    for (word, bytes) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    let mut s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        len as u32,
        flags as u32,
    ];
    round(&mut s, &m, 0);
    round(&mut s, &m, 1);
    round(&mut s, &m, 2);
    round(&mut s, &m, 3);
    round(&mut s, &m, 4);
    round(&mut s, &m, 5);
    round(&mut s, &m, 6);
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

#[derive(Clone)]
struct Output {
    cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    len: u8,
    counter: u64,
    flags: u8,
}
impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        compress(&self.cv, &self.block, self.len, self.counter, self.flags)[..8]
            .try_into()
            .unwrap()
    }
    fn root_block(&self, counter: u64) -> [u8; BLOCK_LEN] {
        let words = compress(&self.cv, &self.block, self.len, counter, self.flags | ROOT);
        let mut bytes = [0; BLOCK_LEN];
        for (dst, word) in bytes.chunks_exact_mut(4).zip(words) {
            dst.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    counter: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: u8,
    blocks: u8,
}
impl ChunkState {
    fn new(counter: u64) -> Self {
        Self {
            cv: IV,
            counter,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            blocks: 0,
        }
    }
    fn len(&self) -> usize {
        self.blocks as usize * BLOCK_LEN + self.buf_len as usize
    }
    fn start_flag(&self) -> u8 {
        if self.blocks == 0 { CHUNK_START } else { 0 }
    }
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // Keep the final block buffered, since CHUNK_END is not known until
            // another byte arrives or finalize is called.
            if self.buf_len as usize == BLOCK_LEN {
                self.cv = compress(
                    &self.cv,
                    &self.buf,
                    BLOCK_LEN as u8,
                    self.counter,
                    self.start_flag(),
                )[..8]
                    .try_into()
                    .unwrap();
                self.blocks += 1;
                self.buf = [0; BLOCK_LEN];
                self.buf_len = 0;
            }
            let take = input.len().min(BLOCK_LEN - self.buf_len as usize);
            self.buf[self.buf_len as usize..self.buf_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.buf_len += take as u8;
            input = &input[take..];
        }
    }
    fn output(&self) -> Output {
        Output {
            cv: self.cv,
            block: self.buf,
            len: self.buf_len,
            counter: self.counter,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut block = [0; BLOCK_LEN];
    for (dst, word) in block.chunks_exact_mut(4).zip(left.iter().chain(right)) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    Output {
        cv: IV,
        block,
        len: BLOCK_LEN as u8,
        counter: 0,
        flags: PARENT,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash([u8; OUT_LEN]);
impl Hash {
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(2 * OUT_LEN);
        for byte in self.0 {
            write!(&mut s, "{byte:02x}").unwrap();
        }
        s
    }
}
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// Incremental, unkeyed BLAKE3. Finalization does not consume the hasher.
#[derive(Clone)]
pub struct Hasher {
    chunk: ChunkState,
    stack: [[u32; 8]; MAX_DEPTH],
    stack_len: usize,
}
impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}
impl Hasher {
    pub fn new() -> Self {
        Self {
            chunk: ChunkState::new(0),
            stack: [[0; 8]; MAX_DEPTH],
            stack_len: 0,
        }
    }
    fn push_chunk(&mut self, mut cv: [u32; 8], total_chunks: u64) {
        let mut n = total_chunks;
        // Each trailing zero completes a subtree with a left sibling.
        while n & 1 == 0 {
            self.stack_len -= 1;
            cv = parent_output(&self.stack[self.stack_len], &cv).chaining_value();
            n >>= 1;
        }
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
    }
    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let simd = input.len() >= 8 * CHUNK_LEN && std::is_x86_feature_detected!("avx2");
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let simd = false;
        self.update_impl(input, simd)
    }
    fn update_impl(&mut self, mut input: &[u8], _simd: bool) -> &mut Self {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total_chunks = self.chunk.counter + 1;
                self.push_chunk(cv, total_chunks);
                self.chunk = ChunkState::new(total_chunks);
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if _simd && self.chunk.len() == 0 && input.len() >= 8 * CHUNK_LEN {
                let mut out = [0; 8 * OUT_LEN];
                let pointers = core::array::from_fn(|i| input[i * CHUNK_LEN..].as_ptr());
                // SAFETY: AVX2 was detected at runtime by update(). Each of
                // the eight pointers addresses a complete 1024-byte chunk;
                // hash8 reads exactly 16 complete blocks from each pointer.
                unsafe {
                    avx2::hash8(
                        &pointers,
                        CHUNK_LEN / BLOCK_LEN,
                        &IV,
                        self.chunk.counter,
                        true,
                        0,
                        CHUNK_START,
                        CHUNK_END,
                        &mut out,
                    );
                }
                let chunks = if input.len() == 8 * CHUNK_LEN { 7 } else { 8 };
                for bytes in out[..chunks * OUT_LEN].chunks_exact(OUT_LEN) {
                    let mut cv = [0; 8];
                    for (word, b) in cv.iter_mut().zip(bytes.chunks_exact(4)) {
                        *word = u32::from_le_bytes(b.try_into().unwrap());
                    }
                    self.chunk.counter += 1;
                    self.push_chunk(cv, self.chunk.counter);
                }
                // Leave the final chunk in ChunkState even when its size is
                // exactly 1024: finalization needs its Output, not only its CV.
                input = &input[chunks * CHUNK_LEN..];
                continue;
            }
            let take = input.len().min(CHUNK_LEN - self.chunk.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }
    fn output(&self) -> Output {
        let mut output = self.chunk.output();
        for left in self.stack[..self.stack_len].iter().rev() {
            output = parent_output(left, &output.chaining_value());
        }
        output
    }
    pub fn finalize(&self) -> Hash {
        Hash(self.output().root_block(0)[..OUT_LEN].try_into().unwrap())
    }
    pub fn finalize_xof(&self) -> OutputReader {
        OutputReader {
            output: self.output(),
            block_counter: 0,
            offset: 0,
        }
    }
}
pub fn hash(input: &[u8]) -> Hash {
    if input.len() <= CHUNK_LEN {
        // The common short-message case does not need a tree stack.
        let mut chunk = ChunkState::new(0);
        chunk.update(input);
        Hash(chunk.output().root_block(0)[..OUT_LEN].try_into().unwrap())
    } else {
        Hasher::new().update(input).finalize()
    }
}

#[derive(Clone)]
pub struct OutputReader {
    output: Output,
    block_counter: u64,
    offset: usize,
}
impl OutputReader {
    pub fn fill(&mut self, mut dest: &mut [u8]) {
        while !dest.is_empty() {
            let block = self.output.root_block(self.block_counter);
            let take = dest.len().min(BLOCK_LEN - self.offset);
            dest[..take].copy_from_slice(&block[self.offset..self.offset + take]);
            dest = &mut dest[take..];
            self.offset += take;
            if self.offset == BLOCK_LEN {
                self.offset = 0;
                self.block_counter = self.block_counter.wrapping_add(1);
            }
        }
    }
}

// Eight independent chunks in parallel, adapted from BLAKE3 1.8.7
// src/rust_avx2.rs, under CC0-1.0 as above. Only called after AVX2
// runtime detection and with eight complete, in-bounds chunk pointers.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
mod avx2 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::{BLOCK_LEN, IV, MSG_SCHEDULE, OUT_LEN};
    type CVWords = [u32; 8];
    fn counter_low(n: u64) -> u32 {
        n as u32
    }
    fn counter_high(n: u64) -> u32 {
        (n >> 32) as u32
    }

    pub const DEGREE: usize = 8;

    #[inline(always)]
    unsafe fn loadu(src: *const u8) -> __m256i {
        // This is an unaligned load, so the pointer cast is allowed.
        unsafe { _mm256_loadu_si256(src as *const __m256i) }
    }

    #[inline(always)]
    unsafe fn storeu(src: __m256i, dest: *mut u8) {
        // This is an unaligned store, so the pointer cast is allowed.
        unsafe { _mm256_storeu_si256(dest as *mut __m256i, src) }
    }

    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    #[inline(always)]
    unsafe fn set1(x: u32) -> __m256i {
        unsafe { _mm256_set1_epi32(x as i32) }
    }

    #[inline(always)]
    unsafe fn set8(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32) -> __m256i {
        unsafe {
            _mm256_setr_epi32(
                a as i32, b as i32, c as i32, d as i32, e as i32, f as i32, g as i32, h as i32,
            )
        }
    }

    // These rotations are the "simple/shifts version". For the
    // "complicated/shuffles version", see
    // https://github.com/sneves/blake2-avx2/blob/b3723921f668df09ece52dcd225a36d4a4eea1d9/blake2s-common.h#L63-L66.
    // For a discussion of the tradeoffs, see
    // https://github.com/sneves/blake2-avx2/pull/5. Due to an LLVM bug
    // (https://bugs.llvm.org/show_bug.cgi?id=44379), this version performs better
    // on recent x86 chips.

    #[inline(always)]
    unsafe fn rot16(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32(x, 16), _mm256_slli_epi32(x, 32 - 16)) }
    }

    #[inline(always)]
    unsafe fn rot12(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32(x, 12), _mm256_slli_epi32(x, 32 - 12)) }
    }

    #[inline(always)]
    unsafe fn rot8(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32(x, 8), _mm256_slli_epi32(x, 32 - 8)) }
    }

    #[inline(always)]
    unsafe fn rot7(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32(x, 7), _mm256_slli_epi32(x, 32 - 7)) }
    }

    #[inline(always)]
    unsafe fn round(v: &mut [__m256i; 16], m: &[__m256i; 16], r: usize) {
        unsafe {
            v[0] = add(v[0], m[MSG_SCHEDULE[r][0] as usize]);
            v[1] = add(v[1], m[MSG_SCHEDULE[r][2] as usize]);
            v[2] = add(v[2], m[MSG_SCHEDULE[r][4] as usize]);
            v[3] = add(v[3], m[MSG_SCHEDULE[r][6] as usize]);
            v[0] = add(v[0], v[4]);
            v[1] = add(v[1], v[5]);
            v[2] = add(v[2], v[6]);
            v[3] = add(v[3], v[7]);
            v[12] = xor(v[12], v[0]);
            v[13] = xor(v[13], v[1]);
            v[14] = xor(v[14], v[2]);
            v[15] = xor(v[15], v[3]);
            v[12] = rot16(v[12]);
            v[13] = rot16(v[13]);
            v[14] = rot16(v[14]);
            v[15] = rot16(v[15]);
            v[8] = add(v[8], v[12]);
            v[9] = add(v[9], v[13]);
            v[10] = add(v[10], v[14]);
            v[11] = add(v[11], v[15]);
            v[4] = xor(v[4], v[8]);
            v[5] = xor(v[5], v[9]);
            v[6] = xor(v[6], v[10]);
            v[7] = xor(v[7], v[11]);
            v[4] = rot12(v[4]);
            v[5] = rot12(v[5]);
            v[6] = rot12(v[6]);
            v[7] = rot12(v[7]);
            v[0] = add(v[0], m[MSG_SCHEDULE[r][1] as usize]);
            v[1] = add(v[1], m[MSG_SCHEDULE[r][3] as usize]);
            v[2] = add(v[2], m[MSG_SCHEDULE[r][5] as usize]);
            v[3] = add(v[3], m[MSG_SCHEDULE[r][7] as usize]);
            v[0] = add(v[0], v[4]);
            v[1] = add(v[1], v[5]);
            v[2] = add(v[2], v[6]);
            v[3] = add(v[3], v[7]);
            v[12] = xor(v[12], v[0]);
            v[13] = xor(v[13], v[1]);
            v[14] = xor(v[14], v[2]);
            v[15] = xor(v[15], v[3]);
            v[12] = rot8(v[12]);
            v[13] = rot8(v[13]);
            v[14] = rot8(v[14]);
            v[15] = rot8(v[15]);
            v[8] = add(v[8], v[12]);
            v[9] = add(v[9], v[13]);
            v[10] = add(v[10], v[14]);
            v[11] = add(v[11], v[15]);
            v[4] = xor(v[4], v[8]);
            v[5] = xor(v[5], v[9]);
            v[6] = xor(v[6], v[10]);
            v[7] = xor(v[7], v[11]);
            v[4] = rot7(v[4]);
            v[5] = rot7(v[5]);
            v[6] = rot7(v[6]);
            v[7] = rot7(v[7]);

            v[0] = add(v[0], m[MSG_SCHEDULE[r][8] as usize]);
            v[1] = add(v[1], m[MSG_SCHEDULE[r][10] as usize]);
            v[2] = add(v[2], m[MSG_SCHEDULE[r][12] as usize]);
            v[3] = add(v[3], m[MSG_SCHEDULE[r][14] as usize]);
            v[0] = add(v[0], v[5]);
            v[1] = add(v[1], v[6]);
            v[2] = add(v[2], v[7]);
            v[3] = add(v[3], v[4]);
            v[15] = xor(v[15], v[0]);
            v[12] = xor(v[12], v[1]);
            v[13] = xor(v[13], v[2]);
            v[14] = xor(v[14], v[3]);
            v[15] = rot16(v[15]);
            v[12] = rot16(v[12]);
            v[13] = rot16(v[13]);
            v[14] = rot16(v[14]);
            v[10] = add(v[10], v[15]);
            v[11] = add(v[11], v[12]);
            v[8] = add(v[8], v[13]);
            v[9] = add(v[9], v[14]);
            v[5] = xor(v[5], v[10]);
            v[6] = xor(v[6], v[11]);
            v[7] = xor(v[7], v[8]);
            v[4] = xor(v[4], v[9]);
            v[5] = rot12(v[5]);
            v[6] = rot12(v[6]);
            v[7] = rot12(v[7]);
            v[4] = rot12(v[4]);
            v[0] = add(v[0], m[MSG_SCHEDULE[r][9] as usize]);
            v[1] = add(v[1], m[MSG_SCHEDULE[r][11] as usize]);
            v[2] = add(v[2], m[MSG_SCHEDULE[r][13] as usize]);
            v[3] = add(v[3], m[MSG_SCHEDULE[r][15] as usize]);
            v[0] = add(v[0], v[5]);
            v[1] = add(v[1], v[6]);
            v[2] = add(v[2], v[7]);
            v[3] = add(v[3], v[4]);
            v[15] = xor(v[15], v[0]);
            v[12] = xor(v[12], v[1]);
            v[13] = xor(v[13], v[2]);
            v[14] = xor(v[14], v[3]);
            v[15] = rot8(v[15]);
            v[12] = rot8(v[12]);
            v[13] = rot8(v[13]);
            v[14] = rot8(v[14]);
            v[10] = add(v[10], v[15]);
            v[11] = add(v[11], v[12]);
            v[8] = add(v[8], v[13]);
            v[9] = add(v[9], v[14]);
            v[5] = xor(v[5], v[10]);
            v[6] = xor(v[6], v[11]);
            v[7] = xor(v[7], v[8]);
            v[4] = xor(v[4], v[9]);
            v[5] = rot7(v[5]);
            v[6] = rot7(v[6]);
            v[7] = rot7(v[7]);
            v[4] = rot7(v[4]);
        }
    }

    #[inline(always)]
    unsafe fn interleave128(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
        unsafe {
            (
                _mm256_permute2x128_si256(a, b, 0x20),
                _mm256_permute2x128_si256(a, b, 0x31),
            )
        }
    }

    // There are several ways to do a transposition. We could do it naively, with 8 separate
    // _mm256_set_epi32 instructions, referencing each of the 32 words explicitly. Or we could copy
    // the vecs into contiguous storage and then use gather instructions. This third approach is to use
    // a series of unpack instructions to interleave the vectors. In my benchmarks, interleaving is the
    // fastest approach. To test this, run `cargo +nightly bench --bench libtest load_8` in the
    // https://github.com/oconnor663/bao_experiments repo.
    #[inline(always)]
    unsafe fn transpose_vecs(vecs: &mut [__m256i; DEGREE]) {
        unsafe {
            // Interleave 32-bit lanes. The low unpack is lanes 00/11/44/55, and the high is 22/33/66/77.
            let ab_0145 = _mm256_unpacklo_epi32(vecs[0], vecs[1]);
            let ab_2367 = _mm256_unpackhi_epi32(vecs[0], vecs[1]);
            let cd_0145 = _mm256_unpacklo_epi32(vecs[2], vecs[3]);
            let cd_2367 = _mm256_unpackhi_epi32(vecs[2], vecs[3]);
            let ef_0145 = _mm256_unpacklo_epi32(vecs[4], vecs[5]);
            let ef_2367 = _mm256_unpackhi_epi32(vecs[4], vecs[5]);
            let gh_0145 = _mm256_unpacklo_epi32(vecs[6], vecs[7]);
            let gh_2367 = _mm256_unpackhi_epi32(vecs[6], vecs[7]);

            // Interleave 64-bit lanes. The low unpack is lanes 00/22 and the high is 11/33.
            let abcd_04 = _mm256_unpacklo_epi64(ab_0145, cd_0145);
            let abcd_15 = _mm256_unpackhi_epi64(ab_0145, cd_0145);
            let abcd_26 = _mm256_unpacklo_epi64(ab_2367, cd_2367);
            let abcd_37 = _mm256_unpackhi_epi64(ab_2367, cd_2367);
            let efgh_04 = _mm256_unpacklo_epi64(ef_0145, gh_0145);
            let efgh_15 = _mm256_unpackhi_epi64(ef_0145, gh_0145);
            let efgh_26 = _mm256_unpacklo_epi64(ef_2367, gh_2367);
            let efgh_37 = _mm256_unpackhi_epi64(ef_2367, gh_2367);

            // Interleave 128-bit lanes.
            let (abcdefgh_0, abcdefgh_4) = interleave128(abcd_04, efgh_04);
            let (abcdefgh_1, abcdefgh_5) = interleave128(abcd_15, efgh_15);
            let (abcdefgh_2, abcdefgh_6) = interleave128(abcd_26, efgh_26);
            let (abcdefgh_3, abcdefgh_7) = interleave128(abcd_37, efgh_37);

            vecs[0] = abcdefgh_0;
            vecs[1] = abcdefgh_1;
            vecs[2] = abcdefgh_2;
            vecs[3] = abcdefgh_3;
            vecs[4] = abcdefgh_4;
            vecs[5] = abcdefgh_5;
            vecs[6] = abcdefgh_6;
            vecs[7] = abcdefgh_7;
        }
    }

    #[inline(always)]
    unsafe fn transpose_msg_vecs(
        inputs: &[*const u8; DEGREE],
        block_offset: usize,
    ) -> [__m256i; 16] {
        unsafe {
            let mut vecs = [
                loadu(inputs[0].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[1].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[2].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[3].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[4].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[5].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[6].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[7].add(block_offset + 0 * 4 * DEGREE)),
                loadu(inputs[0].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[1].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[2].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[3].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[4].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[5].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[6].add(block_offset + 1 * 4 * DEGREE)),
                loadu(inputs[7].add(block_offset + 1 * 4 * DEGREE)),
            ];
            for i in 0..DEGREE {
                _mm_prefetch(
                    inputs[i].wrapping_add(block_offset + 256) as *const i8,
                    _MM_HINT_T0,
                );
            }
            let (square0, square1) = vecs.split_at_mut(DEGREE);
            transpose_vecs(square0.try_into().unwrap());
            transpose_vecs(square1.try_into().unwrap());
            vecs
        }
    }

    #[inline(always)]
    unsafe fn load_counters(counter: u64, increment_counter: bool) -> (__m256i, __m256i) {
        let mask = if increment_counter { !0 } else { 0 };
        unsafe {
            (
                set8(
                    counter_low(counter + (mask & 0)),
                    counter_low(counter + (mask & 1)),
                    counter_low(counter + (mask & 2)),
                    counter_low(counter + (mask & 3)),
                    counter_low(counter + (mask & 4)),
                    counter_low(counter + (mask & 5)),
                    counter_low(counter + (mask & 6)),
                    counter_low(counter + (mask & 7)),
                ),
                set8(
                    counter_high(counter + (mask & 0)),
                    counter_high(counter + (mask & 1)),
                    counter_high(counter + (mask & 2)),
                    counter_high(counter + (mask & 3)),
                    counter_high(counter + (mask & 4)),
                    counter_high(counter + (mask & 5)),
                    counter_high(counter + (mask & 6)),
                    counter_high(counter + (mask & 7)),
                ),
            )
        }
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn hash8(
        inputs: &[*const u8; DEGREE],
        blocks: usize,
        key: &CVWords,
        counter: u64,
        increment_counter: bool,
        flags: u8,
        flags_start: u8,
        flags_end: u8,
        out: &mut [u8; DEGREE * OUT_LEN],
    ) {
        unsafe {
            let mut h_vecs = [
                set1(key[0]),
                set1(key[1]),
                set1(key[2]),
                set1(key[3]),
                set1(key[4]),
                set1(key[5]),
                set1(key[6]),
                set1(key[7]),
            ];
            let (counter_low_vec, counter_high_vec) = load_counters(counter, increment_counter);
            let mut block_flags = flags | flags_start;

            for block in 0..blocks {
                if block + 1 == blocks {
                    block_flags |= flags_end;
                }
                let block_len_vec = set1(BLOCK_LEN as u32); // full blocks only
                let block_flags_vec = set1(block_flags as u32);
                let msg_vecs = transpose_msg_vecs(inputs, block * BLOCK_LEN);

                // The transposed compression function. Note that inlining this
                // manually here improves compile times by a lot, compared to factoring
                // it out into its own function and making it #[inline(always)]. Just
                // guessing, it might have something to do with loop unrolling.
                let mut v = [
                    h_vecs[0],
                    h_vecs[1],
                    h_vecs[2],
                    h_vecs[3],
                    h_vecs[4],
                    h_vecs[5],
                    h_vecs[6],
                    h_vecs[7],
                    set1(IV[0]),
                    set1(IV[1]),
                    set1(IV[2]),
                    set1(IV[3]),
                    counter_low_vec,
                    counter_high_vec,
                    block_len_vec,
                    block_flags_vec,
                ];
                round(&mut v, &msg_vecs, 0);
                round(&mut v, &msg_vecs, 1);
                round(&mut v, &msg_vecs, 2);
                round(&mut v, &msg_vecs, 3);
                round(&mut v, &msg_vecs, 4);
                round(&mut v, &msg_vecs, 5);
                round(&mut v, &msg_vecs, 6);
                h_vecs[0] = xor(v[0], v[8]);
                h_vecs[1] = xor(v[1], v[9]);
                h_vecs[2] = xor(v[2], v[10]);
                h_vecs[3] = xor(v[3], v[11]);
                h_vecs[4] = xor(v[4], v[12]);
                h_vecs[5] = xor(v[5], v[13]);
                h_vecs[6] = xor(v[6], v[14]);
                h_vecs[7] = xor(v[7], v[15]);

                block_flags = flags;
            }

            transpose_vecs(&mut h_vecs);
            storeu(h_vecs[0], out.as_mut_ptr().add(0 * 4 * DEGREE));
            storeu(h_vecs[1], out.as_mut_ptr().add(1 * 4 * DEGREE));
            storeu(h_vecs[2], out.as_mut_ptr().add(2 * 4 * DEGREE));
            storeu(h_vecs[3], out.as_mut_ptr().add(3 * 4 * DEGREE));
            storeu(h_vecs[4], out.as_mut_ptr().add(4 * 4 * DEGREE));
            storeu(h_vecs[5], out.as_mut_ptr().add(5 * 4 * DEGREE));
            storeu(h_vecs[6], out.as_mut_ptr().add(6 * 4 * DEGREE));
            storeu(h_vecs[7], out.as_mut_ptr().add(7 * 4 * DEGREE));
        }
    }
}
