//! Wirehair tools for the in-crate Wirehair port.
//!
//! Pure-Rust port of `third_party/wirehair/WirehairTools.{h,cpp}` and `WirehairHeavy.h`, including the per-N seed fixup
//! tables (`WirehairDenseFixups.inc`, `WirehairPeelFixups.inc`). Every constant, table and PRNG step is preserved
//! exactly; the tables at the bottom of this file are generated mechanically from the vendored C++ sources.
//!
//! Not ported: `SIMDSafeAllocate`/`SIMDSafeFree` (use a zeroed `Vec<u8>`), the `WH_SEED_KNOBS` / `WH_PEELCAP`
//! experiment (off in the vendored build), and the debug-only `CAT_DEBUG_ASSERT` checks. Preconditions that the C++
//! leaves to the caller (for example an index past a table) panic here instead of reading out of bounds.
//!
//! Original code: Copyright (c) 2012-2018 Christopher A. Taylor. All rights reserved. Rust port derived from it under
//! the same license:
//!
//! Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//! following conditions are met:
//!
//! * Redistributions of source code must retain the above copyright notice,
//!   this list of conditions and the following disclaimer.
//! * Redistributions in binary form must reproduce the above copyright notice,
//!   this list of conditions and the following disclaimer in the documentation
//!   and/or other materials provided with the distribution.
//! * Neither the name of Wirehair nor the names of its contributors may be
//!   used to endorse or promote products derived from this software without
//!   specific prior written permission.
//!
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//! INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//! DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//! SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//! SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//! WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//! OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#![allow(dead_code)]
pub const REF_LIST_MAX: usize = 32; pub const MAX_DENSE_ROWS: usize = 500; pub const MAX_EXTRA_ROWS: usize = 32;
pub const WIREHAIR_MAX_N: u32 = 64000; pub const WIREHAIR_MIN_N: u32 = 2; pub const HEAVY_ROWS: usize = 6;
pub const HEAVY_COLS: usize = 18; pub const TINY_TABLE_COUNT: u32 = 65;
pub const SMALL_TABLE_COUNT: u32 = 2048 - TINY_TABLE_COUNT; pub const DENSE_SEED_COUNT: u32 = 100;
pub const PEEL_SEED_SUBDIVISIONS: u32 = 2048; pub const MAX_DENSE_COUNT: u32 = 400;
pub const MAX_N_FOR_WEIGHT1: u32 = 2048; pub const MAX_PEEL_COUNT: u32 = 64; pub const MATRIX_SEED_COUNT: u32 = 512;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct PcgRandom { pub state: u64, pub inc: u64, }
impl PcgRandom {
    pub const fn new() -> Self { PcgRandom { state: 0, inc: 0 } }
    pub fn seeded(y: u64, x: u64) -> Self { let mut p = PcgRandom::new(); p.seed(y, x); p }
    pub fn seed(&mut self, y: u64, x: u64) {
        self.state = 0; self.inc = (y << 1) | 1; self.next(); self.state = self.state.wrapping_add(x);
        self.next(); }
    #[inline(always)] pub fn next(&mut self) -> u32 {
        let oldstate = self.state; self.state = oldstate.wrapping_mul(6364136223846793005).wrapping_add(self.inc);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32; let rot = (oldstate >> 59) as u32;
        xorshifted.rotate_right(rot) } }
#[inline(always)] pub fn rol64(n: u64, r: u32) -> u64 { n.rotate_left(r) }
#[inline(always)] pub fn ror64(n: u64, r: u32) -> u64 { n.rotate_right(r) }
#[inline(always)] pub fn nonzero_lowest_bit_index64(x: u64) -> u32 { debug_assert!(x != 0); x.trailing_zeros() }
pub fn floor_square_root16(x: u16) -> u16 {
    let nonzero_bits: u32 = if x < 0x100 { 6 } else { 31 - (x as u32).leading_zeros() };
    let table_shift = (nonzero_bits - 6) & 0xfe; let result_shift = (15 - nonzero_bits) / 2;
    let mut r: u16 = (SQUARE_ROOT_TABLE[(x >> table_shift) as usize] as u16) >> result_shift;
    if (r as u32) * (r as u32) > x as u32 { r -= 1; }
    r }
const SIEVE_TABLE_SIZE: u32 = 2 * 3 * 5 * 7; const PRIMES_UNDER_256_COUNT: usize = 50;
pub fn next_prime16(n: u16) -> u16 {
    match n { 0 | 1 => return 1, 2 => return 2, 3 => return 3, 4 | 5 => return 5, 6 | 7 => return 7, _ => {} }
    if n <= PRIMES_UNDER_256_FROM_11[PRIMES_UNDER_256_COUNT - 1] as u16 {
        let mut lo = 0usize; let mut hi = PRIMES_UNDER_256_COUNT;
        while lo < hi { let mid = (lo + hi) >> 1;
            if (PRIMES_UNDER_256_FROM_11[mid] as u16) < n { lo = mid + 1; } else { hi = mid; } }
        return PRIMES_UNDER_256_FROM_11[lo] as u16; }
    if n > 65521 { return 0; }
    let mut n = n; let mut offset: u32 = n as u32 % SIEVE_TABLE_SIZE;
    let mut next: u16 = SIEVE_TABLE[offset as usize] as u16; offset += next as u32 + 1; n = n.wrapping_add(next);
    let mut p_max: u32 = floor_square_root16(n) as u32; let mut p_max2: u32 = p_max * p_max;
    'try_next: loop {
        for &p in PRIMES_UNDER_256_FROM_11.iter() { let p = p as u32;
            if p > p_max { return n; }
            if n as u32 % p == 0 {
                if offset >= SIEVE_TABLE_SIZE { offset -= SIEVE_TABLE_SIZE; }
                next = SIEVE_TABLE[offset as usize] as u16; offset += next as u32 + 1;
                n = n.wrapping_add(next).wrapping_add(1);
                if p_max2 < n as u32 { p_max += 1; p_max2 = p_max * p_max; }
                continue 'try_next; } }
        return n; } }
#[inline(always)] fn random64(prng: &mut PcgRandom) -> u64 {
    let rv1 = prng.next(); let rv2 = prng.next();
    ((rv2 as u64) << 32) | rv1 as u64 }
pub fn add_invertible_gf2_matrix(matrix: &mut [u64], offset: u32, pitch_words: u32, n: u32) {
    let pitch = pitch_words as usize;
    if n >= MATRIX_SEED_COUNT { let mut row = 0usize;
        for ii in 0..n { let column_i = offset + ii; matrix[row + (column_i >> 6) as usize] ^= 1u64 << (column_i & 63);
            if ii + 1 < n { let column_j = column_i + 1;
                matrix[row + (column_j >> 6) as usize] ^= 1u64 << (column_j & 63); }
            row += pitch; }
        return; }
    let seed = INVERTIBLE_MATRIX_SEEDS[n as usize]; let mut prng = PcgRandom::seeded(seed as u64, 0);
    let shift = offset & 63; let mut row = (offset >> 6) as usize;
    for _row_i in 0..n { let mut dest = row; let mut target = n; let word0 = random64(&mut prng); let mut temp0 = word0;
        let mut written0 = 64 - shift;
        if target < 64 { temp0 &= (1u64 << target) - 1; if written0 > target { written0 = target; } }
        matrix[dest] ^= temp0 << shift; dest += 1; target -= written0; let mut prev = word0;
        if target != 0 {
            loop { let mut temp: u64 = 0;
                if shift != 0 { temp = prev >> (64 - shift); }
                let mut word: u64 = 0;
                if target > shift { word = random64(&mut prng); temp |= word << shift; }
                if target < 64 { temp &= (1u64 << target) - 1; }
                matrix[dest] ^= temp;
                if target <= 64 { break; }
                target -= 64; dest += 1;
                prev = word; } }
        row += pitch; } }
#[inline(always)] fn deck_step(deck: &mut [u16], ii: u32, jj: u32) {
    deck[ii as usize] = deck[jj as usize];
    deck[jj as usize] = ii as u16; }
pub fn shuffle_deck16(prng: &mut PcgRandom, deck: &mut [u16], count: u32) {
    if count == 0 { return; }
    let deck = &mut deck[..count as usize]; deck[0] = 0;
    if count <= 256 { let mut ii: u32 = 1;
        loop { let rv = prng.next();
            match count - ii {
                0 => return,
                1 => { let jj = (rv >> 16) as u8 as u32 % ii; deck_step(deck, ii, jj); return; }
                2 => { let jj = (rv >> 8) as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 16) as u8 as u32 % ii; deck_step(deck, ii, jj);
                    return; }
                3 => { let jj = rv as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 8) as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 16) as u8 as u32 % ii; deck_step(deck, ii, jj);
                    return; }
                _ => { let jj = rv as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 8) as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 16) as u8 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 24) as u8 as u32 % ii; deck_step(deck, ii, jj);
                    ii += 1; } } } } else {
        let mut ii: u32 = 1;
        loop { let rv = prng.next();
            match count - ii {
                0 => return,
                1 => { let jj = rv as u16 as u32 % ii; deck_step(deck, ii, jj); return; }
                _ => { let jj = rv as u16 as u32 % ii; deck_step(deck, ii, jj); ii += 1;
                    let jj = (rv >> 16) as u16 as u32 % ii; deck_step(deck, ii, jj);
                    ii += 1; } } } } }
#[inline(always)] pub fn iterate_next_column(x: &mut u16, b: u16, p: u16, a: u16) {
    let mut next: u32 = *x as u32 + a as u32;
    if next >= p as u32 { next -= p as u32; }
    *x = next as u16;
    if *x >= b { let distance_to_p: u16 = p.wrapping_sub(*x);
        if a >= distance_to_p { *x = a - distance_to_p;
        } else { *x = ((((a as u32) << 16).wrapping_sub(distance_to_p as u32)) % a as u32) as u16; } } }
pub const P1: u32 = 33554431; const P2: u32 = PEEL_COUNT_DISTRIBUTION[1]; const P3: u32 = PEEL_COUNT_DISTRIBUTION[2];
pub fn generate_peel_row_weight(rv: u32, block_count: u16) -> u16 { let mut rv = rv;
    if block_count as u32 <= MAX_N_FOR_WEIGHT1 { if rv < P1 { return 1; } rv -= P1; }
    if rv <= P2 { return 2; }
    if rv <= P3 { return 3; }
    let mut weight: u16 = PEEL_WEIGHT_FIRST_BY_TOP_BYTE[(rv >> 24) as usize] as u16;
    loop { let entry = PEEL_COUNT_DISTRIBUTION[weight as usize]; weight += 1; if rv <= entry { break; } }
    weight }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct PeelRowParameters {
    pub peel_count: u16, pub peel_first: u16, pub peel_add: u16, pub mix_first: u16,
    pub mix_add: u16, }
impl PeelRowParameters {
    pub fn new(row_seed: u32, p_seed: u32, peel_column_count: u16, mix_column_count: u16) -> Self {
        let mut p = PeelRowParameters::default(); p.initialize(row_seed, p_seed, peel_column_count, mix_column_count);
        p }
    pub fn initialize(&mut self, row_seed: u32, p_seed: u32, peel_column_count: u16, mix_column_count: u16,) {
        let mut prng = PcgRandom::seeded(row_seed as u64, p_seed as u64);
        let weight = generate_peel_row_weight(prng.next(), peel_column_count); let max_weight = peel_column_count / 2;
        self.peel_count = if weight > max_weight { max_weight } else { weight }; let rv_peel = prng.next();
        self.peel_add = ((rv_peel as u16 as u32 % (peel_column_count as u32 - 1)) + 1) as u16;
        self.peel_first = ((rv_peel >> 16) as u16 as u32 % peel_column_count as u32) as u16; let rv_mix = prng.next();
        self.mix_add = ((rv_mix as u16 as u32 % (mix_column_count as u32 - 1)) + 1) as u16;
        self.mix_first = ((rv_mix >> 16) as u16 as u32 % mix_column_count as u32) as u16; } }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct PeelRowIterator {
    columns_remaining: u16, next_column: u16, adder: u16, column_count: u16,
    column_count_next_prime: u16, }
impl PeelRowIterator {
    #[inline(always)] pub fn new(params: &PeelRowParameters, column_count: u16, column_count_next_prime: u16) -> Self {
        PeelRowIterator {
            next_column: params.peel_first, columns_remaining: params.peel_count.wrapping_sub(1),
            adder: params.peel_add, column_count,
            column_count_next_prime, } }
    #[inline(always)] pub fn get_column(&self) -> u16 { self.next_column }
    #[inline(always)] pub fn iterate(&mut self) -> bool {
        if self.columns_remaining == 0 { return false; }
        self.columns_remaining -= 1;
        iterate_next_column(&mut self.next_column, self.column_count, self.column_count_next_prime, self.adder, );
        true } }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowMixIterator { pub columns: [u16; RowMixIterator::COLUMN_COUNT], }
impl RowMixIterator { pub const COLUMN_COUNT: usize = 3;
    #[inline(always)] pub fn new(params: &PeelRowParameters, column_count: u16, column_count_next_prime: u16) -> Self {
        let mut x = params.mix_first; let mut columns = [0u16; Self::COLUMN_COUNT]; columns[0] = x;
        for c in columns.iter_mut().skip(1) {
            iterate_next_column(&mut x, column_count, column_count_next_prime, params.mix_add);
            *c = x; }
        RowMixIterator { columns } } }
const HEAVY_BYTE_LOOKUP: [[u8; 4]; 16] = [[0, 0, 0, 0], [1, 0, 0, 0], [0, 1, 0, 0], [1, 1, 0, 0],
    [0, 0, 1, 0], [1, 0, 1, 0], [0, 1, 1, 0], [1, 1, 1, 0], [0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1], [1, 1, 0, 1],
    [0, 0, 1, 1], [1, 0, 1, 1], [0, 1, 1, 1], [1, 1, 1, 1], ];
#[inline(always)]
pub fn heavy_window_word(bits: u32) -> u32 { u32::from_ne_bytes(HEAVY_BYTE_LOOKUP[(bits & 15) as usize]) }
#[inline(always)] pub fn add_heavy_window(destination: &mut [u8], bits: u32, coefficient: u8) {
    let d = &mut destination[..4]; let mut w = [0u8; 4]; w.copy_from_slice(d);
    let word = u32::from_ne_bytes(w) ^ heavy_window_word(bits).wrapping_mul(coefficient as u32);
    d.copy_from_slice(&word.to_ne_bytes()); }
pub fn interpolate_dense_count(n0: u16, n1: u16, count0: u16, count1: u16, n: u32) -> u16 {
    let offset = n as i64 - n0 as i64; let count_delta = count1 as i64 - count0 as i64;
    let numerator = offset * count_delta; let denominator = n1 as i64 - n0 as i64;
    let count = count0 as i64 + numerator / denominator;
    count as u16 }
pub fn get_dense_count(n: u32) -> u16 { let (low, high): ((u16, u16), (u16, u16));
    if n < TINY_TABLE_COUNT + SMALL_TABLE_COUNT {
        if n < TINY_TABLE_COUNT { return TINY_DENSE_COUNTS[n as usize] as u16; } else if n <= 500 {
            low = (64, 26); high = (500, 35);
        } else if n <= 1000 { low = (500, 35); high = (1000, 48); } else { low = (1000, 48); high = (2048, 62); }
    } else {
        let mut lo = 0usize; let mut hi = DENSE_POINTS.len() - 1;
        loop { let mid = (hi + lo) / 2;
            if mid == lo { break; }
            if n > DENSE_POINTS[mid].0 as u32 { lo = mid; } else { hi = mid; } }
        low = DENSE_POINTS[lo];
        high = DENSE_POINTS[lo + 1]; }
    let mut dense_count = interpolate_dense_count(low.0, high.0, low.1, high.1, n);
    match dense_count % 4 {
        0 => dense_count = dense_count.wrapping_add(2),
        1 => dense_count = dense_count.wrapping_add(1),
        3 => dense_count = dense_count.wrapping_add(3),
        _ => {} }
    dense_count }
pub fn get_dense_seed_pre_fixup(n: u32, dense_count: u32) -> u16 {
    if n < TINY_TABLE_COUNT { TINY_DENSE_SEEDS[n as usize] } else if n < TINY_TABLE_COUNT + SMALL_TABLE_COUNT {
        SMALL_DENSE_SEEDS[(n - TINY_TABLE_COUNT) as usize] as u16
    } else { DENSE_SEEDS[(dense_count / 4) as usize] as u16 } }
fn find_fixup(table: &[(u16, u8)], n: u32) -> Option<u8> { let (mut lo, mut hi) = (0usize, table.len());
    while lo < hi { let mid = (lo + hi) >> 1; if (table[mid].0 as u32) < n { lo = mid + 1; } else { hi = mid; } }
    if lo < table.len() && table[lo].0 as u32 == n { Some(table[lo].1) } else { None } }
pub fn get_dense_seed(n: u32, dense_count: u32) -> u16 {
    if let Some(seed) = find_fixup(&DENSE_SEED_FIXUPS, n) {
        if dense_count == get_dense_count(n) as u32 { return seed as u16; } }
    get_dense_seed_pre_fixup(n, dense_count) }
pub fn get_peel_seed_pre_fixup(n: u32) -> u16 {
    if n < TINY_TABLE_COUNT + SMALL_TABLE_COUNT {
        SMALL_PEEL_SEEDS[n as usize] as u16 } else { PEEL_SEEDS[(n % PEEL_SEED_SUBDIVISIONS) as usize] as u16 } }
pub fn get_peel_seed(n: u32) -> u16 {
    if let Some(seed) = find_fixup(&PEEL_SEED_FIXUPS, n) { return seed as u16; }
    get_peel_seed_pre_fixup(n) }
#[allow(unused_imports)] pub use self::PcgRandom as PCGRandom;
pub(crate) const SQUARE_ROOT_TABLE: [u8; 256] = [0, 16, 16, 16, 32, 32, 32, 32, 32, 48, 48, 48, 48, 48, 48, 48,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 96, 96, 96, 96, 96, 96, 96, 96, 96,
    96, 96, 96, 96, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 128, 129, 130, 131, 132,
    133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 143, 144, 145, 146, 147, 148, 149, 150, 150, 151, 152, 153,
    154, 155, 155, 156, 157, 158, 159, 159, 160, 161, 162, 163, 163, 164, 165, 166, 167, 167, 168, 169, 170, 170, 171,
    172, 173, 173, 174, 175, 175, 176, 177, 178, 178, 179, 180, 181, 181, 182, 183, 183, 184, 185, 185, 186, 187, 187,
    188, 189, 189, 190, 191, 191, 192, 193, 193, 194, 195, 195, 196, 197, 197, 198, 199, 199, 200, 201, 201, 202, 203,
    203, 204, 204, 205, 206, 206, 207, 207, 208, 209, 209, 210, 211, 211, 212, 212, 213, 214, 214, 215, 215, 216, 217,
    217, 218, 218, 219, 219, 220, 221, 221, 222, 222, 223, 223, 224, 225, 225, 226, 226, 227, 227, 228, 229, 229, 230,
    230, 231, 231, 232, 232, 233, 234, 234, 235, 235, 236, 236, 237, 237, 238, 238, 239, 239, 240, 241, 241, 242, 242,
    243, 243, 244, 244, 245, 245, 246, 246, 247, 247,
    248, 248, 249, 249, 250, 250, 251, 251, 252, 252, 253, 253, 254, 254, 255, 255, ];
pub(crate) const SIEVE_TABLE: [u8; 210] = [1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 0, 3, 2,
    1, 0, 1, 0, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 1, 0, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 5,
    4, 3, 2, 1, 0, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4,
    3, 2, 1, 0, 3, 2, 1, 0, 1, 0, 3, 2, 1, 0, 1, 0, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 5,
    4, 3, 2, 1, 0, 1, 0, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 1, 0, 5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 1, 0, 3, 2,
    1, 0, 5, 4, 3, 2, 1, 0, 1, 0, 5, 4, 3, 2, 1, 0, 3, 2, 1, 0, 1, 0, 3, 2, 1, 0, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2,
    1, 0, ];
pub(crate) const PRIMES_UNDER_256_FROM_11: [u8; 50] = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239,
    241, 251, ];
pub(crate) const INVERTIBLE_MATRIX_SEEDS: [u8; 512] = [0, 1, 4, 2, 0, 12, 0, 1, 1, 0, 2, 2, 1, 4, 1, 1,
    1, 9, 9, 1, 0, 0, 0, 0, 2, 2, 2, 4, 3, 4, 1, 1, 0, 0, 0, 0, 7, 1, 6, 2, 5, 1, 0, 4, 0, 0, 10, 0, 11, 3, 3, 2, 10, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 1, 6, 4, 0, 2, 3, 0, 0, 0, 1, 0, 0, 3, 3, 3, 1, 4, 0, 2, 2, 3, 1, 6, 0, 4, 1, 2, 3, 1, 1, 7,
    0, 7, 0, 0, 3, 5, 2, 6, 1, 3, 3, 0, 7, 0, 0, 4, 7, 1, 7, 5, 4, 1, 4, 4, 4, 6, 3, 0, 0, 4, 5, 5, 1, 8, 1, 1, 0, 2, 4,
    4, 2, 2, 2, 4, 5, 0, 0, 2, 0, 2, 4, 1, 3, 3, 3, 0, 4, 0, 0, 0, 0, 0, 0, 2, 1, 1, 17, 3, 3, 3, 2, 9, 14, 3, 2, 5, 1,
    1, 6, 3, 1, 6, 0, 0, 5, 5, 3, 3, 0, 0, 0, 0, 7, 4, 7, 7, 10, 0, 1, 1, 9, 0, 0, 0, 1, 3, 0, 1, 2, 0, 2, 4, 1, 4, 0,
    0, 2, 0, 4, 3, 3, 1, 0, 1, 10, 12, 5, 2, 2, 4, 1, 0, 1, 1, 1, 0, 6, 4, 0, 0, 0, 3, 1, 3, 5, 0, 10, 2, 0, 3, 3, 1, 1,
    0, 1, 6, 19, 2, 2, 1, 3, 5, 3, 1, 1, 1, 4, 4, 0, 0, 3, 2, 8, 1, 14, 3, 0, 0, 1, 0, 1, 1, 4, 1, 1, 2, 0, 6, 8, 6, 5,
    0, 0, 0, 6, 1, 1, 4, 1, 6, 3, 0, 0, 1, 6, 3, 2, 2, 1, 3, 1, 9, 6, 8, 3, 1, 0, 3, 0, 0, 1, 1, 5, 2, 2, 4, 0, 1, 2, 2,
    6, 5, 7, 6, 0, 10, 3, 5, 0, 0, 0, 4, 0, 2, 10, 3, 1, 2, 2, 0, 2, 0, 9, 0, 0, 5, 3, 4, 4, 4, 2, 0, 7, 0, 0, 0, 0, 2,
    5, 0, 0, 0, 4, 5, 0, 0, 2, 4, 7, 3, 2, 2, 0, 1, 8, 1, 0, 2, 2, 2, 6, 2, 0, 0, 0, 9, 0, 0, 0, 1, 0, 1, 1, 3, 0, 0, 3,
    3, 3, 5, 0, 0, 1, 0, 1, 1, 1, 14, 12, 9, 2, 11, 3, 2, 3, 3, 3, 3, 7, 6, 6, 0, 0, 0, 11, 0, 0, 3, 2, 1, 1, 1, 2, 3,
    2, 3, 3, 3, 3, 3, 0, 0, 0, 1, 8, 4, 3, 4, 4, 4, 1, 4, 6, 0, 6, 4, 3, 7, 6, 0, 1, 3, 3, 0, 2, 1, 1, 1, 1, 2, 0, 1, 0,
    0, 8, 3, 2, 2, 2, 2, 2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 9,
    0, 0, 2, 3, 2, 0, 0, 10, 11, 0, 0, 0, 2, 0, 6, 0, ];
pub(crate) const PEEL_COUNT_DISTRIBUTION: [u32; 64] = [
    0x00000000, 0x7fffffff, 0xaaaaaaa9, 0xbfffffff, 0xcccccccb, 0xd5555554, 0xdb6db6da, 0xdfffffff, 0xe38e38e2,
    0xe6666665, 0xe8ba2e8a, 0xeaaaaaa9, 0xec4ec4eb, 0xedb6db6c, 0xeeeeeeed, 0xefffffff, 0xf0f0f0ef, 0xf1c71c70,
    0xf286bca0, 0xf3333332, 0xf3cf3cf2, 0xf45d1744, 0xf4de9bd2, 0xf5555554, 0xf5c28f5b, 0xf6276275, 0xf684bda0,
    0xf6db6db5, 0xf72c234e, 0xf7777776, 0xf7bdef7a, 0xf7ffffff, 0xf83e0f82, 0xf8787877, 0xf8af8af7, 0xf8e38e37,
    0xf914c1b9, 0xf9435e4f, 0xf96f96f8, 0xf9999998, 0xf9c18f9b, 0xf9e79e78, 0xfa0be82e, 0xfa2e8ba1, 0xfa4fa4f9,
    0xfa6f4de8, 0xfa8d9df4, 0xfaaaaaa9, 0xfac687d5, 0xfae147ad, 0xfafafaf9, 0xfb13b13a, 0xfb2b78c0, 0xfb425ecf,
    0xfb586fb4, 0xfb6db6da,
    0xfb823edf, 0xfb9611a6, 0xfba93867, 0xfbbbbbba, 0xfbcda3ab, 0xfbdef7bc, 0xfbefbefa, 0xffffffff, ];
pub(crate) const PEEL_WEIGHT_FIRST_BY_TOP_BYTE: [u8; 256] = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
    16, 17, 18, 19, 21, 23, 25, 28, 32, 36, 42, 51, 63, 63, 63, 63, ];
pub(crate) const TINY_DENSE_COUNTS: [u8; 65] = [0, 0, 2, 3, 3, 5, 6, 6, 6, 7, 9, 10, 10, 10, 12, 14,
    13, 14, 12, 12, 15, 16, 21, 14, 14, 13, 18, 21, 22, 21, 13, 22, 13, 24, 14, 17, 16, 24, 30, 26, 24, 18, 15, 15, 24,
    18, 21, 17, 14, 16, 21, 18, 17, 22, 25, 20, 17, 18, 21, 18, 23, 20, 19, 23,
    19, ];
pub(crate) const TINY_DENSE_SEEDS: [u16; 65] = [
    0, 0, 12678, 31247, 24246, 6830, 10311, 18975, 46844, 888, 38598, 63780, 12170, 24444, 55961, 13141, 53472, 55486,
    28496, 27214, 49117, 60737, 62051, 59811, 3052, 33624, 35793, 8210, 32674, 36155, 10819, 52727, 9692, 26215, 33106,
    34092, 18779, 61056, 4502, 7786, 36397, 53163, 36617, 16009, 60476, 31637, 38086, 32027, 968, 59896, 27819, 10193,
    64755, 41508, 44381, 41571, 52121, 23594, 313, 38382, 48549, 44868, 43789, 8396,
    1902, ];
pub(crate) const SMALL_DENSE_SEEDS: [u8; 1983] = [
    28, 34, 248, 36, 160, 229, 20, 209, 229, 27, 76, 188, 144, 26, 95, 176, 51, 20, 78, 4, 121, 26, 79, 158, 196, 93,
    233, 4, 1, 1, 8, 214, 150, 139, 93, 135, 224, 4, 62, 27, 89, 74, 150, 69, 3, 119, 126, 72, 145, 60, 110, 57, 18,
    182, 140, 5, 110, 8, 158, 57, 196, 68, 39, 138, 3, 17, 124, 119, 32, 53, 69, 47, 158, 39, 12, 131, 44, 68, 187, 168,
    226, 173, 92, 46, 112, 89, 102, 114, 231, 84, 25, 237, 65, 36, 151, 93, 119, 118, 147, 123, 155, 62, 120, 95, 161,
    59, 137, 12, 91, 30, 119, 104, 111, 203, 11, 109, 207, 234, 97, 117, 31, 139, 207, 181, 73, 127, 169, 181, 80, 246,
    29, 100, 6, 32, 88, 2, 67, 133, 185, 236, 225, 16, 148, 36, 16, 115, 85, 108, 160, 101, 171, 213, 34, 107, 238, 85,
    89, 13, 77, 14, 133, 57, 136, 242, 208, 5, 225, 141, 176, 155, 64, 196, 142, 82, 79, 64, 99, 95, 74, 60, 180, 72,
    27, 39, 13, 237, 26, 60, 125, 22, 188, 134, 131, 6, 25, 43, 180, 61, 51, 4, 81, 250, 85, 123, 68, 107, 129, 42, 8,
    160, 143, 107, 181, 24, 106, 126, 2, 199, 23, 160, 49, 109, 217, 108, 170, 238, 123, 5, 4, 148, 48, 45, 153, 1, 121,
    52, 105, 255, 114, 172, 115, 184, 66, 220, 75, 173, 133, 160, 77, 220, 209, 63, 248, 241, 64, 228, 70, 77, 175, 29,
    18, 166, 144, 89, 66, 131, 113, 226, 22, 223, 149, 125, 24, 175, 51, 99, 31, 145, 101, 19, 106, 15, 235, 118, 221,
    175, 148, 116, 18, 22, 156, 25, 87, 154, 22, 229, 7, 178, 201, 116, 44, 45, 9, 237, 115, 218, 86, 198, 107, 94, 31,
    49, 224, 10, 43, 231, 87, 72, 48, 4, 177, 213, 84, 54, 143, 238, 33, 155, 81, 29, 57, 188, 8, 240, 148, 25, 32, 34,
    156, 199, 154, 128, 130, 24, 39, 182, 33, 75, 13, 143, 41, 137, 15, 241, 21, 92, 177, 159, 73, 71, 36, 46, 103, 7,
    106, 123, 12, 195, 114, 87, 255, 82, 110, 50, 89, 172, 158, 0, 176, 242, 127, 208, 110, 239, 75, 141, 58, 168, 178,
    150, 212, 160, 91, 24, 90, 184, 60, 56, 190, 171, 48, 26, 220, 86, 143, 153, 90, 60, 46, 90, 74, 63, 116, 245, 92,
    176, 160, 70, 116, 76, 61, 199, 220, 86, 21, 253, 77, 90, 18, 240, 16, 103, 72, 11, 66, 26, 210, 187, 54, 193, 95,
    81, 209, 28, 51, 108, 72, 61, 6, 73, 12, 54, 154, 123, 140, 45, 46, 108, 152, 84, 244, 11, 28, 205, 64, 38, 18, 135,
    102, 1, 52, 36, 73, 27, 102, 42, 0, 86, 28, 28, 197, 176, 160, 182, 166, 31, 156, 156, 156, 1, 244, 168, 235, 103,
    43, 152, 55, 82, 153, 217, 35, 185, 152, 123, 228, 106, 184, 121, 39, 226, 32, 182, 64, 157, 205, 91, 139, 139, 42,
    10, 84, 52, 66, 188, 197, 161, 60, 224, 83, 19, 205, 40, 48, 30, 47, 233, 152, 162, 4, 236, 230, 39, 190, 240, 85,
    98, 217, 93, 12, 27, 150, 62, 53, 7, 142, 96, 192, 27, 252, 166, 4, 16, 78, 8, 16, 248, 59, 170, 26, 193, 48, 1, 70,
    52, 18, 146, 24, 133, 123, 235, 171, 205, 45, 130, 107, 250, 73, 173, 85, 47, 1, 95, 64, 188, 25, 118, 40, 30, 47,
    132, 4, 51, 125, 155, 70, 166, 210, 189, 204, 143, 226, 185, 63, 254, 248, 93, 100, 202, 167, 155, 47, 28, 196, 190,
    5, 242, 55, 51, 152, 88, 248, 48, 68, 24, 169, 254, 33, 65, 191, 1, 245, 243, 12, 48, 41, 180, 189, 171, 51, 14, 61,
    142, 14, 134, 209, 123, 157, 192, 149, 200, 137, 204, 158, 196, 114, 83, 39, 58, 237, 54, 134, 195, 20, 143, 184,
    156, 16, 40, 17, 208, 101, 95, 23, 99, 26, 108, 211, 215, 14, 218, 115, 180, 132, 4, 190, 117, 116, 15, 161, 139,
    40, 215, 124, 148, 206, 12, 169, 48, 90, 28, 22, 8, 144, 249, 39, 15, 251, 80, 128, 151, 91, 132, 17, 112, 167, 121,
    33, 111, 0, 153, 228, 20, 196, 93, 113, 43, 139, 14, 193, 140, 72, 58, 201, 157, 176, 131, 10, 39, 18, 37, 157, 6,
    45, 8, 36, 144, 236, 79, 52, 181, 11, 125, 86, 219, 96, 3, 15, 21, 42, 16, 160, 156, 196, 65, 210, 172, 10, 2, 0,
    127, 41, 84, 107, 215, 17, 94, 115, 168, 95, 163, 40, 144, 203, 102, 173, 26, 102, 72, 76, 10, 193, 48, 225, 192,
    194, 209, 13, 88, 224, 253, 34, 128, 197, 129, 146, 9, 168, 87, 36, 183, 2, 171, 117, 6, 122, 118, 5, 38, 87, 61,
    96, 95, 217, 188, 233, 203, 101, 252, 180, 27, 9, 210, 157, 200, 57, 7, 41, 92, 119, 37, 125, 42, 138, 208, 68, 223,
    36, 30, 59, 139, 61, 59, 252, 161, 31, 114, 7, 168, 59, 210, 23, 83, 114, 63, 29, 24, 128, 93, 180, 107, 132, 84,
    178, 60, 100, 181, 98, 65, 28, 81, 155, 2, 228, 226, 138, 143, 31, 219, 180, 90, 59, 228, 159, 207, 50, 24, 58, 215,
    91, 89, 77, 67, 114, 237, 45, 10, 150, 8, 230, 180, 1, 253, 104, 22, 3, 7, 112, 83, 93, 98, 96, 71, 6, 144, 106,
    168, 239, 89, 72, 29, 102, 182, 144, 19, 11, 223, 65, 47, 144, 26, 58, 144, 152, 15, 29, 140, 53, 119, 166, 102,
    165, 145, 30, 30, 137, 183, 24, 23, 40, 232, 151, 108, 43, 243, 61, 89, 233, 66, 219, 72, 208, 42, 247, 8, 144, 15,
    0, 71, 53, 11, 234, 58, 197, 12, 140, 57, 32, 61, 149, 95, 99, 73, 115, 79, 163, 79, 102, 57, 248, 105, 32, 59, 235,
    28, 211, 78, 220, 93, 3, 7, 44, 231, 204, 124, 224, 250, 131, 232, 173, 99, 111, 118, 180, 108, 178, 44, 205, 241,
    169, 29, 5, 18, 139, 192, 54, 28, 69, 193, 41, 113, 179, 62, 131, 25, 1, 125, 62, 11, 237, 135, 73, 105, 242, 100,
    175, 90, 236, 197, 156, 85, 39, 96, 63, 60, 100, 69, 243, 88, 243, 158, 114, 13, 139, 169, 125, 52, 44, 23, 234, 41,
    120, 226, 236, 80, 84, 26, 204, 188, 39, 16, 126, 202, 103, 64, 174, 68, 115, 152, 69, 163, 225, 181, 39, 189, 38,
    2, 95, 120, 164, 49, 253, 208, 60, 13, 35, 108, 77, 140, 55, 87, 219, 76, 36, 98, 161, 70, 45, 167, 50, 139, 153,
    122, 216, 229, 19, 218, 117, 13, 155, 175, 53, 252, 138, 160, 52, 74, 67, 46, 205, 116, 100, 105, 118, 33, 22, 181,
    105, 151, 176, 112, 74, 168, 179, 50, 13, 28, 27, 229, 203, 139, 253, 204, 57, 8, 23, 216, 99, 209, 3, 1, 167, 120,
    89, 81, 43, 20, 135, 142, 233, 109, 216, 198, 10, 128, 162, 213, 174, 57, 37, 26, 82, 16, 220, 122, 27, 2, 139, 160,
    179, 71, 62, 177, 90, 0, 243, 93, 24, 39, 48, 93, 174, 129, 222, 63, 60, 19, 154, 65, 35, 226, 90, 43, 189, 28, 83,
    207, 239, 244, 11, 166, 74, 184, 207, 12, 85, 109, 58, 30, 9, 163, 217, 230, 149, 178, 248, 22, 147, 6, 206, 88,
    178, 7, 50, 158, 18, 173, 251, 6, 68, 234, 11, 69, 245, 10, 123, 189, 78, 183, 14, 6, 23, 15, 44, 145, 162, 45, 19,
    39, 121, 101, 156, 25, 181, 14, 148, 32, 184, 49, 91, 60, 15, 101, 93, 143, 29, 220, 145, 117, 26, 94, 26, 92, 133,
    67, 101, 121, 25, 8, 35, 74, 232, 137, 35, 138, 206, 78, 137, 160, 145, 183, 217, 149, 37, 3, 7, 226, 30, 164, 228,
    32, 126, 115, 66, 223, 45, 16, 254, 144, 226, 40, 20, 126, 4, 162, 89, 171, 13, 223, 162, 104, 226, 1, 47, 238, 232,
    199, 109, 86, 100, 44, 126, 226, 105, 246, 62, 21, 65, 130, 32, 210, 58, 168, 236, 233, 166, 35, 229, 113, 127, 76,
    153, 123, 240, 97, 13, 140, 31, 230, 175, 37, 80, 48, 197, 108, 169, 183, 35, 118, 48, 16, 176, 97, 77, 26, 186, 63,
    150, 183, 146, 31, 25, 120, 4, 39, 7, 60, 23, 242, 62, 141, 39, 115, 103, 111, 114, 130, 198, 10, 39, 184, 106, 129,
    59, 76, 111, 159, 69, 116, 58, 59, 85, 29, 88, 155, 112, 2, 250, 26, 33, 224, 136, 66, 218, 137, 36, 44, 150, 135,
    117, 106, 74, 155, 64, 201, 178, 86, 127, 3, 141, 49, 11, 173, 79, 114, 83, 156, 16, 20, 205, 179, 70, 157, 97, 138,
    50, 125, 71, 75, 43, 87, 180, 198, 161, 27, 221, 119, 49, 159, 142, 221, 200, 127, 120, 130, 195, 31, 22, 153, 78,
    184, 137, 57, 79, 116, 58, 21, 70, 68, 121, 83, 111, 63, 85, 28, 34, 27, 200, 150, 89, 147, 160, 129, 75, 59, 140,
    84, 29, 132, 101, 142, 83, 175, 50, 96, 142, 56, 1, 222, 104, 128, 241, 195, 70, 151, 10, 0, 103, 16, 56, 237, 191,
    127, 35, 4, 30, 157, 96, 79, 224, 12, 153, 210, 95, 29, 191, 62, 132, 216, 166, 73, 28, 222, 150, 109, 59, 165, 12,
    103, 90, 214, 7, 10, 64, 58, 229, 35, 1, 60, 172, 63, 162, 178, 186, 83, 63, 108, 103, 207, 221, 119, 50, 8, 138,
    192, 17, 162, 36, 64, 3, 156, 206, 5, 174, 65, 31, 165, 116, 90, 89, 155, 28, 108, 44, 192, 195, 5, 52, 25, 27, 157,
    117, 82, 181, 121, 78, 224, 39, 40, 84, 15, 1, 107, 122, 103, 240, 105, 71, 207, 218, 24, 89, 50, 199, 207, 159, 37,
    3, 182, 32, 242, 134, 147, 20, 5, 194, 129, 162, 226, 57, 50, 65, 53, 172, 242, 16, 28, 107, 169, 139, 179, 53, 72,
    192, 182, 186, 85, 112, 234, 65, 35, 17, 79, 156, 185, 12, 83, 29, 41, 183, 3, 91, 71, 245, 45, 240, 121, 72, 54,
    20, 211, 233, 205, 126, 13, 94, 181, 107, 33, 84, 85, 197, 115, 58, 29, 83, 165, 32, 151, 29, 72, 218, 233, 164,
    230, 149, 27, 207, 164, 130, 148, 75, 183, 31, 152, 87, 30, 5, 191, 5, 53, 136, 63, 225, 204, 40, 149, 124, 108,
    240, 255, 13, 24, 189, 127, 154, 142, 247, 11, 116, 47, 114, 130, 87, 35, 141, 216, 90, 79, 19, 72, 237, 240, 18,
    102, 24, 35, 122, 65, 111, 117, 141, 155, 119, 12, 4, 157, 100, 107, 8, 55, 102, 249, 142, 99, 152, 204, 35, 176,
    214, 236, 125, 17, 41, 226, 228, 48, 76, 141, 16, 252, 238, 57, 64, 64, 118, 196, 163, 26, 246, 86, 197, 100, 40, 0,
    185, 78, 21, 177, 179, 50, 178, 57, 8, 30, 160, 52, 158, 38, 33, 82, 121, 225, 189, 185, 22, 172, 90, 49, 9, 4, 49,
    19, 114, 168, 117, 53, 243, 63, 33, 76, 231, 105, 238, 16, 187, 11, 20, 23, 166, 77, 243, 86, 34, 249, 253, 3, 7,
    52, 57, 177, 177, 23, 233, 60, 127, 113, 200, 13, 56, 40, 197, 71, 149, 242, 81, 87, 167, 254, 171, 115, 53, 10, 12,
    77, 8, 66, 207, 123, 141, 2, 46, 95, 83, 140, 20, 22, 179, 245, 165, 160, 238, 20, 22, 57, 112, 48, 95, 220,
    15, 187, 42, 7, 99, 58, 31, 45, 36, 43, 94, 76, 54, 217, 200, ];
pub(crate) const SMALL_PEEL_SEEDS: [u8; 2048] = [0, 0, 0, 11, 1, 0, 0, 0, 1, 0, 0, 0, 5, 1, 0, 0,
    4, 11, 0, 0, 0, 3, 0, 1, 7, 2, 3, 12, 11, 9, 2, 3, 0, 3, 1, 9, 21, 46, 5, 8, 27, 4, 37, 37, 69, 5, 180, 8, 30, 201,
    21, 23, 12, 59, 151, 77, 214, 216, 221, 46, 23, 89, 39, 11, 46, 228, 189, 11, 18, 24, 41, 229, 31, 123, 11, 39, 119,
    19, 10, 102, 178, 23, 131, 210, 2, 116, 219, 34, 43, 105, 22, 128, 87, 187, 179, 89, 70, 54, 65, 173, 190, 85, 98,
    98, 238, 16, 57, 80, 67, 115, 135, 178, 80, 195, 135, 183, 113, 116, 199, 137, 4, 152, 33, 146, 185, 46, 153, 141,
    1, 0, 4, 3, 0, 7, 0, 3, 6, 13, 5, 2, 1, 0, 2, 3, 1, 3, 2, 1, 1, 4, 2, 2, 3, 0, 3, 7, 1, 0, 5, 0, 0, 4, 0, 4, 1, 5,
    0, 2, 4, 130, 5, 6, 10, 6, 0, 4, 3, 0, 16, 2, 4, 0, 19, 0, 7, 0, 7, 5, 0, 4, 1, 4, 5, 1, 4, 2, 8, 7, 15, 7, 3, 1, 1,
    2, 2, 0, 2, 2, 14, 3, 6, 6, 5, 3, 2, 12, 14, 12, 22, 16, 3, 2, 3, 6, 5, 10, 2, 1, 1, 0, 1, 6, 2, 0, 7, 9, 10, 5, 1,
    10, 4, 2, 2, 2, 9, 3, 1, 1, 33, 5, 11, 4, 4, 7, 8, 0, 0, 3, 0, 10, 3, 1, 5, 7, 5, 37, 9, 0, 10, 12, 2, 13, 2, 3, 12,
    5, 20, 0, 5, 0, 0, 20, 9, 2, 23, 12, 31, 2, 14, 3, 3, 2, 23, 4, 0, 14, 1, 3, 10, 4, 22, 5, 28, 0, 23, 19, 4, 13, 14,
    4, 29, 12, 19, 21, 5, 1, 5, 1, 22, 2, 7, 3, 5, 30, 11, 18, 2, 15, 60, 9, 6, 0, 8, 7, 1, 9, 4, 13, 0, 37, 42, 23, 29,
    8, 5, 5, 9, 17, 8, 5, 8, 51, 17, 2, 3, 21, 11, 27, 30, 51, 10, 7, 45, 7, 13, 12, 5, 30, 12, 24, 50, 47, 60, 98, 31,
    47, 23, 4, 16, 45, 10, 2, 27, 45, 42, 11, 44, 81, 34, 26, 3, 7, 22, 2, 5, 19, 16, 8, 63, 9, 39, 71, 41, 6, 51, 2,
    88, 4, 13, 6, 19, 7, 35, 23, 6, 42, 4, 2, 26, 35, 37, 49, 45, 19, 40, 63, 78, 37, 30, 1, 19, 2, 8, 1, 15, 31, 0, 6,
    12, 0, 16, 4, 10, 86, 25, 9, 18, 21, 13, 0, 50, 62, 0, 43, 107, 8, 29, 19, 60, 35, 81, 11, 118, 10, 39, 53, 4, 11,
    37, 78, 33, 32, 61, 7, 19, 21, 26, 7, 6, 11, 81, 44, 72, 37, 3, 17, 98, 28, 15, 11, 113, 42, 163, 98, 15, 122, 13,
    119, 12, 50, 45, 4, 85, 37, 124, 40, 0, 45, 113, 39, 52, 112, 19, 88, 32, 48, 36, 90, 18, 39, 15, 20, 43, 71, 74,
    183, 57, 79, 79, 0, 110, 8, 12, 100, 16, 47, 78, 93, 0, 41, 20, 1, 10, 36, 21, 162, 2, 39, 203, 16, 79, 25, 2, 1,
    158, 122, 134, 15, 36, 73, 42, 157, 91, 0, 8, 34, 242, 18, 39, 98, 211, 49, 41, 69, 5, 56, 71, 25, 110, 87, 48, 51,
    5, 69, 64, 135, 42, 122, 10, 65, 20, 126, 181, 108, 112, 124, 200, 10, 135, 14, 135, 0, 136, 11, 70, 29, 7, 199,
    226, 225, 171, 130, 50, 44, 80, 31, 89, 41, 80, 18, 65, 43, 21, 53, 70, 37, 162, 165, 91, 91, 33, 87, 105, 87, 110,
    215, 13, 32, 122, 19, 69, 18, 178, 8, 30, 28, 2, 206, 128, 61, 5, 38, 43, 9, 6, 122, 51, 17, 85, 180, 60, 16, 23,
    63, 83, 112, 80, 115, 36, 63, 18, 146, 22, 59, 83, 24, 71, 34, 10, 237, 51, 126, 2, 168, 64, 18, 37, 28, 135, 146,
    5, 80, 4, 17, 44, 105, 47, 68, 219, 26, 119, 13, 0, 138, 60, 26, 93, 24, 75, 20, 39, 21, 242, 42, 62, 17, 18, 0, 83,
    1, 36, 76, 152, 107, 138, 2, 246, 15, 65, 26, 16, 49, 203, 59, 216, 127, 64, 255, 28, 198, 137, 22, 14, 42, 20, 198,
    47, 67, 8, 48, 67, 40, 10, 244, 159, 217, 27, 208, 6, 54, 143, 3, 21, 80, 119, 82, 133, 117, 152, 107, 42, 38, 153,
    213, 45, 29, 20, 10, 140, 107, 14, 11, 33, 26, 41, 32, 123, 139, 104, 42, 213, 2, 3, 12, 79, 44, 156, 40, 65, 237,
    41, 5, 63, 52, 149, 251, 37, 10, 143, 1, 162, 90, 138, 43, 12, 97, 46, 4, 105, 43, 81, 39, 222, 107, 35, 28, 10, 62,
    48, 21, 27, 186, 105, 0, 171, 248, 6, 20, 145, 10, 52, 3, 215, 151, 13, 24, 165, 131, 170, 42, 46, 139, 114, 43, 22,
    28, 73, 48, 231, 70, 142, 77, 224, 133, 153, 46, 35, 251, 153, 108, 2, 197, 175, 37, 56, 45, 28, 6, 77, 1, 182, 112,
    43, 4, 137, 169, 19, 203, 154, 129, 13, 6, 215, 16, 47, 89, 1, 3, 53, 63, 245, 175, 45, 164, 158, 85, 236, 16, 15,
    13, 185, 171, 18, 95, 25, 19, 12, 106, 12, 254, 24, 68, 50, 107, 53, 155, 44, 5, 231, 15, 4, 103, 38, 24, 66, 38,
    166, 38, 61, 20, 129, 212, 49, 2, 3, 101, 100, 148, 106, 87, 37, 3, 2, 210, 157, 2, 68, 109, 34, 96, 26, 176, 76,
    173, 172, 46, 47, 102, 255, 233, 122, 224, 38, 27, 27, 54, 54, 47, 32, 7, 85, 148, 158, 136, 113, 145, 211, 241,
    128, 17, 88, 34, 69, 224, 246, 52, 27, 43, 30, 90, 239, 52, 82, 248, 231, 26, 81, 146, 0, 2, 216, 209, 80, 39, 14,
    46, 10, 93, 255, 170, 31, 203, 89, 242, 79, 81, 174, 225, 16, 6, 52, 244, 236, 149, 28, 74, 57, 63, 135, 25, 86, 17,
    28, 124, 18, 168, 158, 140, 125, 168, 84, 221, 245, 49, 163, 150, 100, 89, 20, 18, 8, 11, 184, 31, 30, 77, 196, 39,
    149, 200, 170, 52, 120, 29, 136, 7, 28, 45, 211, 190, 83, 34, 27, 1, 197, 163, 93, 36, 53, 177, 97, 233, 226, 80,
    238, 41, 186, 226, 45, 43, 226, 107, 20, 93, 215, 59, 125, 175, 77, 86, 123, 23, 171, 14, 28, 36, 1, 99, 9, 54, 38,
    213, 27, 38, 99, 61, 155, 186, 199, 203, 143, 112, 0, 68, 215, 177, 111, 178, 124, 21, 173, 205, 103, 47, 77, 27,
    111, 68, 252, 251, 249, 175, 97, 144, 7, 5, 43, 170, 112, 30, 18, 186, 109, 150, 129, 253, 53, 28, 42, 41, 31, 51,
    144, 0, 68, 6, 175, 71, 141, 3, 29, 114, 70, 225, 5, 34, 121, 23, 151, 240, 119, 38, 238, 8, 51, 179, 201, 7, 206,
    244, 98, 15, 53, 195, 239, 27, 200, 72, 112, 198, 23, 64, 6, 66, 153, 201, 46, 26, 78, 5, 160, 59, 209, 18, 25, 168,
    215, 128, 73, 77, 195, 26, 98, 28, 71, 73, 84, 228, 227, 67, 189, 125, 39, 60, 108, 140, 29, 86, 71, 185, 63, 65,
    98, 72, 74, 18, 58, 76, 28, 44, 36, 192, 113, 249, 55, 214, 220, 19, 177, 29, 252, 94, 129, 218, 117, 223, 17, 14,
    160, 232, 17, 25, 49, 14, 57, 93, 250, 194, 193, 37, 184, 18, 93, 28, 74, 20, 31, 1, 139, 117, 1, 25, 52, 231, 52,
    21, 53, 61, 145, 26, 73, 5, 36, 92, 66, 180, 19, 214, 8, 200, 210, 204, 21, 177, 12, 241, 154, 58, 75, 192, 17, 72,
    229, 106, 37, 179, 59, 18, 46, 166, 103, 189, 100, 88, 223, 5, 40, 118, 80, 44, 71, 60, 137, 56, 2, 235, 40, 191,
    12, 139, 129, 191, 73, 110, 11, 71, 6, 11, 60, 232, 180, 117, 63, 1, 117, 89, 47, 87, 90, 136, 229, 137, 245, 3, 19,
    249, 146, 27, 237, 225, 20, 81, 173, 119, 4, 38, 113, 82, 42, 240, 5, 10, 173, 213, 175, 17, 97, 63, 0, 13, 38, 20,
    230, 225, 120, 152, 7, 64, 94, 11, 131, 92, 112, 90, 21, 2, 62, 75, 13, 104, 138, 26, 119, 161, 42, 183, 15, 36, 63,
    121, 48, 2, 36, 71, 130, 134, 154, 127, 245, 213, 17, 155, 153, 134, 81, 29, 50, 48, 107, 77, 9, 182, 57, 16, 179,
    115, 85, 49, 77, 60, 121, 149, 134, 68, 197, 100, 114, 1, 13, 88, 3, 7, 182, 38, 46, 180, 214, 45, 30, 221, 54, 129,
    22, 52, 114, 17, 150, 110, 66, 134, 158, 242, 231, 38, 77, 216, 23, 104, 235, 132, 196, 65, 34, 43, 131, 60, 111,
    13, 32, 135, 171, 60, 135, 13, 254, 228, 91, 237, 19, 72, 51, 249, 104, 72, 145, 193, 14, 45, 81, 80, 69, 45, 193,
    30, 200, 55, 63, 121, 52, 41, 21, 41, 17, 190, 104, 67, 30, 1, 26, 88, 47, 43, 42, 26, 105, 185, 25, 88, 25, 13, 72,
    40, 18, 40, 34, 78, 80, 94, 185, 40, 33, 77, 227, 179, 118, 113, 14, 129, 126, 134, 115, 151, 137, 214, 193, 77,
    156, 249, 219, 3, 17, 109, 208, 119, 186, 65, 226, 4, 117, 102, 173, 113, 214, 4, 241, 156, 89, 228, 97, 210, 164,
    62, 183, 232, 127, 61, 20, 153, 57, 96, 166, 189, 180, 251, 23, 147, 94, 125, 133, 20, 121, 150, 80, 254, 100, 225,
    35, 160, 93, 214, 23, 25, 9, 8, 123, 238, 1, 129, 214, 5, 6, 194, 154, 24, 37, 54, 10, 252, 40, 85, 196, 165, 207,
    6, 37, 15, 197, 88, 95, 41, 129, 113, 180, 81, 84, 52, 204, 83, 171, 200, 24, 238, 70, 28, 145, 158, 117, 135, 195,
    252, 144, 183, 89, 181, 32, 12, 33, 153, 27, 19, 222, 74, 83, 139, 190, 84, 39, 48, 110, 124, 129, 3, 28, 56, 248,
    237, 147, 15, 62, 40, 71, 78, 201, 192, 8, 65, 118, 220, 31, 225, 50, 181, 80, 216, 131, 192, 48, 154, 128, 155,
    107, 203, 41, 67, 25, 185, 82, 232, 119, 13, 150, 139, 90, 248, 49, 28, 157, 244, 88, 90, 3, 151, 217, 74, 213, 17,
    86, 38, 55, 222, 163, 160, 118, 126, 206, 64, 208, 142, 132, 96, 204, 216, 35, 211, 84, 33, 194, 100, 244, 206, 132,
    74, 66, 160, 128, 177, 121, 0, 143, 8, 104, 83, 208, 184, 71, 33, 115, 50, 73, 2, 47, 171, 152, 95, 212, 5, 152,
    122, 113, 156, 111, 216, 88, 68, 210, 24, 159, 170, 231, 69, 14, 170, 254, 209, 147, 99, 138, 137, 127, 61, 203, 73,
    49, 200, 53, 75, 128, 9, 145, 32, 171, 147, 49, 203, 143, 66, 207, 56, 150, 15, 76, 91, 50, 89, 64, 209, 75, 224,
    191, 206, 136, 129, 84, 194, 4, 11, 76, 131, 160, 254, 44, 208, 117, 235, 49, 64, 71, 102, 1, 61, 215, 77, 10, 228,
    167, 82, 34, 32, 29, 75, 191, 218, 29, 165, 242, 30, 152, 190, 9, 195, 141, 134, 26, 18, 112, 93, 70, 232, 25, 67,
    253, 36, 25, 240, 133, 93, 120, 104, 246, 211, 5, 86, 184, 71, 41, 33, 158, 183, 98, 134, 6, 68, 168, 217, 204, 205,
    84, 169, 98, 93, 16, 62, 93, 80, 101, 248, 122, 156, 56, 18, 102, 171, 223, 72, 43, 4, 43, 59, 24, 200, 211, 120,
    132, 54, 112, 107, 255, 111, 66, 72, 93, 135, 215, 123, 136, 57, 217, 66, 36, 169, 185, 46, 176, 68, 190, 92, 62,
    252, 12, 11, 6, 30, 80, 157, 18, 243, 72, 4, 5, 57, 44, 66, 13, 23, 94, 237, 24, 197, 91, 127, 103, 157,
    249, 78, 72, 210, 139, 14, 77, 43, 21, 16, 12, 54, 166, 49, 32, 140, ];
pub(crate) const DENSE_SEEDS: [u8; 100] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 214, 53, 190,
    233, 221, 24, 33, 241, 138, 159, 32, 131, 17, 199, 245, 235, 87, 241, 116, 148, 16, 105, 141, 119, 181, 133, 156,
    85, 38, 152, 36, 219, 58, 160, 81, 50, 93, 27, 15, 60, 116, 117, 130, 106, 13, 138, 81, 7, 31, 34, 188, 157, 4, 145,
    150, 19, 140, 115, 255, 165, 243, 186, 249, 178, 13, 174, 242, 41, 128, 127, 177, 119, 142, 96, 39, 28, 78, 226, 42,
    38, 108, 82, 1,
    84, 112, 152, 0, ];
pub(crate) const PEEL_SEEDS: [u8; 2048] = [0, 13, 4, 7, 6, 13, 1, 6, 13, 7, 15, 13, 11, 1, 6, 7,
    13, 5, 12, 11, 7, 14, 2, 10, 13, 3, 3, 3, 1, 9, 13, 7, 2, 9, 10, 0, 2, 14, 14, 0, 13, 11, 5, 0, 15, 14, 7, 3, 15, 2,
    1, 3, 7, 2, 15, 12, 9, 10, 14, 12, 5, 13, 1, 7, 2, 4, 3, 15, 17, 11, 9, 10, 11, 4, 7, 15, 0, 14, 1, 2, 10, 7, 11, 3,
    14, 1, 3, 14, 0, 1, 7, 2, 3, 2, 17, 10, 3, 12, 0, 6, 4, 5, 9, 15, 11, 9, 18, 11, 8, 3, 6, 4, 5, 27, 9, 13, 5, 13, 5,
    12, 4, 13, 2, 7, 16, 0, 4, 5, 7, 4, 11, 12, 0, 8, 11, 9, 13, 5, 3, 4, 4, 7, 4, 7, 1, 0, 6, 14, 0, 6, 5, 11, 9, 1,
    14, 7, 1, 19, 1, 6, 12, 7, 0, 6, 17, 7, 15, 2, 11, 2, 1, 7, 13, 11, 14, 3, 4, 3, 2, 4, 22, 1, 17, 0, 13, 4, 8, 19,
    9, 12, 1, 1, 20, 15, 9, 14, 8, 2, 9, 5, 15, 3, 7, 3, 1, 4, 8, 12, 4, 2, 15, 9, 15, 22, 7, 7, 7, 9, 9, 0, 5, 4, 1, 6,
    12, 13, 9, 7, 12, 14, 3, 8, 0, 9, 16, 3, 7, 3, 0, 15, 7, 7, 6, 7, 3, 3, 12, 0, 12, 13, 5, 6, 0, 10, 14, 9, 7, 1, 15,
    2, 2, 11, 12, 11, 3, 6, 18, 11, 7, 13, 12, 0, 7, 4, 11, 2, 9, 14, 15, 11, 10, 9, 1, 7, 0, 10, 7, 6, 5, 18, 0, 9, 4,
    1, 6, 3, 0, 7, 21, 1, 2, 7, 3, 15, 5, 0, 3, 10, 9, 0, 18, 10, 1, 1, 17, 0, 4, 18, 2, 12, 4, 2, 2, 2, 9, 8, 9, 2, 9,
    3, 5, 11, 9, 3, 9, 3, 15, 2, 1, 5, 9, 15, 9, 4, 10, 12, 2, 2, 6, 5, 11, 2, 9, 5, 6, 6, 14, 10, 10, 22, 9, 4, 6, 10,
    0, 12, 6, 18, 11, 3, 4, 15, 3, 5, 10, 3, 7, 0, 24, 20, 10, 2, 7, 3, 5, 8, 6, 0, 10, 2, 16, 10, 5, 9, 9, 3, 0, 13, 2,
    14, 2, 0, 4, 0, 3, 4, 4, 12, 12, 2, 3, 0, 1, 3, 7, 2, 2, 5, 14, 7, 5, 0, 8, 9, 13, 4, 13, 5, 4, 9, 19, 2, 13, 0, 11,
    1, 3, 4, 0, 3, 3, 4, 3, 4, 15, 0, 6, 5, 9, 15, 0, 22, 3, 2, 7, 5, 10, 9, 2, 3, 17, 3, 9, 6, 2, 2, 4, 15, 11, 10, 2,
    1, 6, 3, 8, 13, 9, 9, 0, 2, 7, 1, 6, 13, 7, 0, 9, 1, 16, 2, 13, 9, 0, 12, 4, 11, 2, 3, 0, 0, 2, 9, 11, 12, 11, 18,
    1, 0, 4, 21, 3, 7, 2, 5, 7, 5, 4, 1, 12, 0, 14, 3, 17, 8, 11, 8, 9, 5, 8, 0, 3, 3, 7, 11, 8, 3, 15, 1, 15, 3, 7, 3,
    17, 10, 7, 18, 11, 0, 2, 9, 10, 4, 16, 17, 0, 7, 7, 4, 8, 13, 7, 12, 7, 0, 1, 19, 15, 3, 4, 12, 18, 8, 2, 3, 0, 13,
    22, 6, 14, 3, 1, 7, 8, 2, 6, 6, 10, 18, 12, 12, 7, 15, 1, 0, 9, 5, 11, 4, 2, 0, 1, 0, 6, 11, 2, 8, 13, 17, 4, 1, 8,
    12, 12, 1, 3, 1, 5, 19, 5, 12, 1, 11, 11, 3, 8, 3, 12, 15, 6, 13, 5, 0, 5, 10, 1, 8, 5, 7, 11, 3, 22, 5, 9, 12, 1,
    17, 0, 7, 12, 1, 8, 8, 3, 17, 3, 10, 5, 5, 3, 4, 3, 0, 9, 4, 1, 0, 9, 7, 4, 9, 1, 7, 1, 4, 3, 3, 7, 11, 4, 9, 9, 8,
    8, 5, 1, 12, 10, 7, 7, 0, 0, 10, 4, 12, 4, 4, 2, 6, 13, 7, 7, 13, 8, 2, 0, 7, 3, 12, 7, 4, 7, 4, 8, 7, 8, 7, 3, 1,
    12, 19, 17, 4, 1, 4, 12, 1, 0, 15, 0, 8, 0, 9, 1, 18, 0, 0, 7, 3, 2, 10, 12, 1, 11, 11, 18, 1, 17, 3, 13, 4, 6, 0,
    9, 0, 1, 5, 2, 2, 10, 3, 10, 12, 1, 3, 5, 2, 2, 5, 1, 5, 3, 1, 25, 0, 18, 0, 4, 2, 9, 10, 10, 5, 7, 10, 8, 7, 9, 1,
    4, 0, 0, 1, 14, 10, 7, 15, 4, 3, 7, 1, 12, 0, 6, 15, 1, 4, 12, 9, 3, 17, 1, 2, 16, 7, 0, 10, 1, 9, 10, 10, 11, 0, 7,
    4, 17, 11, 4, 5, 16, 10, 0, 10, 1, 3, 9, 6, 1, 5, 15, 5, 9, 0, 3, 14, 6, 1, 9, 1, 6, 9, 5, 9, 0, 3, 9, 2, 9, 4, 7,
    1, 1, 5, 0, 12, 6, 8, 11, 0, 1, 1, 5, 1, 7, 7, 11, 2, 11, 1, 7, 2, 4, 1, 7, 4, 15, 12, 1, 17, 16, 12, 3, 1, 10, 11,
    12, 7, 11, 11, 4, 18, 6, 5, 3, 10, 7, 3, 4, 2, 6, 9, 15, 9, 17, 4, 8, 3, 4, 4, 4, 4, 0, 1, 12, 1, 13, 13, 4, 7, 7,
    9, 9, 19, 1, 12, 16, 4, 14, 1, 5, 8, 9, 12, 2, 12, 15, 11, 10, 5, 1, 13, 6, 7, 8, 9, 1, 0, 9, 6, 14, 1, 15, 1, 5,
    13, 7, 15, 9, 3, 1, 14, 2, 10, 9, 11, 7, 2, 18, 11, 0, 8, 16, 20, 7, 11, 14, 22, 13, 1, 11, 15, 7, 5, 7, 8, 6, 7, 6,
    1, 11, 6, 12, 2, 6, 6, 1, 10, 2, 9, 15, 7, 8, 0, 12, 10, 17, 1, 0, 7, 12, 0, 2, 2, 18, 17, 0, 12, 0, 3, 1, 7, 12,
    11, 6, 5, 0, 5, 4, 3, 3, 11, 22, 1, 3, 0, 7, 14, 11, 3, 0, 2, 6, 19, 6, 10, 11, 3, 8, 4, 7, 5, 1, 2, 4, 11, 10, 4,
    9, 9, 3, 8, 1, 3, 15, 17, 1, 0, 5, 15, 0, 7, 2, 10, 1, 4, 3, 1, 8, 9, 12, 2, 6, 7, 9, 7, 1, 4, 0, 10, 11, 2, 12, 4,
    11, 3, 1, 13, 3, 2, 11, 4, 1, 5, 6, 7, 7, 12, 7, 4, 5, 10, 9, 11, 0, 9, 0, 11, 2, 6, 4, 3, 0, 10, 1, 17, 9, 10, 15,
    6, 5, 11, 4, 3, 11, 0, 13, 9, 4, 1, 14, 6, 14, 7, 4, 3, 1, 1, 0, 4, 5, 11, 2, 5, 2, 4, 13, 7, 19, 10, 3, 10, 14, 4,
    5, 3, 3, 4, 17, 2, 5, 20, 1, 9, 1, 18, 7, 7, 3, 8, 9, 12, 5, 9, 4, 11, 1, 12, 17, 0, 12, 11, 21, 13, 9, 18, 4, 4, 7,
    13, 1, 17, 0, 12, 3, 7, 0, 9, 16, 9, 13, 11, 3, 10, 5, 0, 13, 9, 0, 6, 6, 1, 12, 3, 1, 3, 9, 10, 2, 15, 8, 4, 11, 7,
    0, 9, 15, 12, 0, 12, 4, 4, 7, 2, 0, 4, 3, 1, 0, 15, 9, 0, 0, 12, 3, 6, 0, 10, 17, 10, 5, 9, 14, 2, 2, 7, 8, 7, 10,
    9, 7, 7, 4, 1, 12, 12, 5, 12, 9, 6, 7, 12, 3, 9, 14, 4, 2, 4, 6, 4, 8, 3, 1, 1, 5, 7, 0, 11, 7, 14, 7, 2, 24, 11, 4,
    13, 9, 5, 0, 17, 5, 2, 14, 7, 1, 7, 8, 1, 9, 2, 1, 1, 7, 12, 10, 21, 1, 17, 4, 9, 7, 12, 0, 1, 9, 0, 2, 6, 1, 4, 3,
    0, 11, 6, 9, 11, 12, 0, 2, 8, 0, 0, 8, 9, 1, 0, 19, 13, 3, 0, 3, 0, 7, 6, 12, 2, 6, 9, 12, 4, 1, 4, 12, 10, 15, 4,
    3, 9, 15, 1, 14, 4, 12, 9, 3, 4, 15, 0, 15, 7, 1, 9, 0, 9, 3, 4, 7, 17, 1, 6, 8, 4, 17, 7, 0, 0, 11, 2, 12, 17, 3,
    13, 7, 3, 16, 13, 0, 2, 8, 8, 8, 9, 7, 13, 14, 19, 4, 7, 12, 11, 11, 4, 6, 7, 11, 0, 0, 12, 2, 11, 14, 15, 3, 5, 9,
    0, 13, 3, 0, 7, 3, 8, 7, 14, 14, 15, 3, 0, 13, 8, 11, 1, 7, 9, 3, 9, 11, 18, 7, 3, 12, 4, 9, 21, 0, 1, 8, 0, 6, 7,
    12, 3, 1, 2, 12, 13, 3, 2, 9, 1, 9, 8, 10, 7, 11, 15, 17, 7, 0, 5, 11, 4, 13, 8, 12, 1, 3, 1, 0, 11, 5, 5, 5, 8, 7,
    5, 3, 8, 9, 5, 9, 8, 1, 7, 15, 4, 2, 1, 14, 7, 10, 17, 16, 1, 18, 8, 8, 0, 2, 1, 15, 0, 1, 3, 4, 3, 7, 4, 14, 15,
    10, 9, 1, 9, 18, 3, 0, 1, 5, 11, 11, 10, 7, 7, 9, 4, 9, 9, 1, 18, 10, 3, 20, 0, 0, 9, 0, 3, 7, 7, 4, 21, 9, 15, 7,
    5, 10, 7, 0, 6, 17, 7, 5, 16, 7, 11, 10, 10, 0, 6, 7, 7, 4, 0, 12, 4, 1, 2, 9, 2, 8, 3, 7, 2, 3, 0, 15, 11, 7, 7, 4,
    17, 9, 3, 1, 4, 4, 1, 9, 7, 5, 1, 7, 4, 6, 18, 4, 4, 0, 14, 3, 7, 11, 13, 13, 4, 11, 2, 5, 6, 9, 6, 11, 8, 6, 0, 11,
    7, 5, 0, 3, 8, 1, 0, 8, 1, 4, 7, 11, 0, 8, 8, 15, 9, 1, 19, 4, 10, 3, 11, 3, 19, 1, 2, 1, 2, 1, 9, 7, 10, 1, 0, 3,
    24, 4, 11, 15, 9, 11, 0, 3, 11, 9, 3, 13, 4, 12, 11, 1, 7, 15, 2, 1, 0, 3, 1, 6, 7, 11, 2, 4, 1, 9, 1, 5, 1, 7, 12,
    7, 5, 9, 1, 7, 9, 6, 0, 6, 9, 0, 1, 14, 21, 15, 11, 5, 9, 5, 10, 7, 12, 16, 10, 10, 3, 16, 7, 8, 12, 1, 2, 0, 8, 1,
    2, 1, 5, 0, 4, 4, 0, 4, 0, 14, 3, 2, 17, 6, 10, 17, 4, 19, 6, 0, 0, 9, 5, 3, 0, 4, 10, 1, 1, 5, 2, 9, 1, 7, 4, 0, 4,
    2, 4, 2, 11, 2, 5, 4, 5, 6, 1, 7, 4, 0, 11, 11, 3, 13, 8, 12, 1, 0, 1, 14, 7, 9, 11, 1, 7, 4, 7, 7, 0, 13, 9, 19,
    12, 8, 5, 8, 1, 5, 10, 1, 7, 2, 12, 6, 0, 15, 13, 2, 0, 8, 7, 13, 7, 0, 7, 1, 5, 1, 5, 4, 13, 3, 8, 0, 0, 0, 1, 6,
    14, 4, 0, 1, 12, 4, 5, 9, 15, 15, 9, 5, 2, 19, 1, 0, 3, 4, 2, 0, 4, 4, 3, 20, 9, 3, 4, 12, 0, 6, 4, 4, 4, 3, 1, 12,
    7, 0, 5, 3, 10, 6, 9, 8, 0, 3, 14, 9, 3, 0, 1, 11, 3, 12, 7, 0, 7, 7, 4, 8, 8, 10, 7, 14, 10, 0, 0, 15, 5, 2, 8, 9,
    6, 4, 22, 16, 13, 11, 3, 6, 6, 14, 1, 3, 4, 7, 17, 14, 5, 9, 3, 9, 0, 1, 12, 6, 2, 7, 0, 0, 5, 1, 7, 7, 4, 4, 4, 21,
    3, 3, 4, 12, 0, 9, 14, 4, 12, 0, 9, 4, 14, 14, 1, 7, 3, 14, 19, 7, 2, 11, 3, 1, 3, 14, 11, 4, 1, 9, 0, 1, 4, 1, 12,
    5, 0, 2, 14, 13, 0, 1, 1, 4, 0,
    14, 11, 16, 6, 3, 7, 6, 13, 13, 0, 1, 8, 0, 2, 1, 8, ];
pub(crate) const DENSE_POINTS: [(u16, u16); 64] = [
    (2048, 52), (2618, 54), (2826, 60), (3725, 62), (3962, 67), (4277, 65), (4547, 60), (5065, 64), (5224, 76),
    (5642, 66), (5909, 71), (6285, 76), (6583, 66), (6895, 72), (7448, 69), (7682, 76), (8046, 78), (8558, 76),
    (8963, 73), (9389, 81), (10143, 86), (11129, 94), (12593, 99), (12988, 105), (14032, 108), (14473, 114),
    (15397, 110), (16636, 113), (17698, 118), (18828, 123), (19420, 127), (20343, 136), (21979, 139), (23024, 150),
    (24119, 156), (25659, 162), (27298, 173), (29042, 176), (30898, 183), (31870, 190), (33906, 200), (35519, 211),
    (37208, 220), (38978, 234), (40205, 253), (42776, 297), (44122, 320), (45511, 336), (46944, 357), (48421, 373),
    (49177, 376), (50725, 380), (52321, 391), (53968, 388), (54811, 382), (54811, 382), (55667, 372), (57419, 362),
    (58316, 356), (60152, 347),
    (61091, 337), (62045, 334), (63014, 340), (64000, 345), ];
pub(crate) const DENSE_SEED_FIXUPS: [(u16, u8); 163] = [
    (5550, 23), (6107, 22), (7533, 12), (7564, 8), (9308, 10), (11026, 0), (11446, 2), (15371, 1), (15621, 26),
    (15711, 21), (15727, 7), (16025, 5), (16561, 3), (16719, 11), (16905, 9), (17007, 31), (17127, 29), (17160, 1),
    (17696, 4), (18716, 9), (18866, 3), (18906, 27), (19021, 24), (19113, 27), (19247, 18), (19541, 4), (19677, 1),
    (19722, 14), (20152, 6), (20233, 18), (20684, 9), (20948, 8), (20978, 0), (21131, 29), (21163, 28), (21183, 10),
    (21343, 26), (21463, 15), (21618, 4), (21629, 15), (21736, 0), (21813, 4), (21815, 23), (21869, 15), (22045, 27),
    (22613, 14), (22734, 0), (22766, 11), (22978, 30), (23087, 25), (23298, 0), (23346, 29), (23727, 1), (24166, 10),
    (24419, 2), (24555, 6), (24967, 10), (25005, 5), (25211, 11), (25363, 8), (25631, 28), (25900, 4), (25920, 16),
    (25936, 9), (25950, 0), (26137, 5), (26195, 3), (26570, 13), (26637, 12), (26650, 23), (26704, 24), (26883, 11),
    (26995, 28), (27067, 7), (27070, 2), (27106, 15), (27228, 24), (27229, 31), (27275, 17), (27428, 3), (27466, 5),
    (27620, 13), (27623, 1), (27644, 0), (27660, 0), (27731, 16), (27743, 8), (27894, 7), (27895, 2), (27963, 10),
    (27984, 13), (28239, 5), (28293, 9), (28572, 34), (29117, 15), (29257, 16), (29449, 7), (29861, 1), (30276, 9),
    (32667, 3), (33395, 13), (33562, 6), (34248, 15), (34664, 8), (35269, 13), (35533, 3), (36138, 29), (36395, 11),
    (36683, 98), (36878, 19), (37074, 10), (37762, 0), (37842, 6), (39199, 74), (39304, 96), (39507, 8), (39696, 2),
    (39758, 45), (40101, 19), (40537, 3), (41009, 141), (41087, 38), (41349, 2), (41392, 12), (41647, 15), (42296, 29),
    (42558, 156), (43493, 8), (43501, 3), (43910, 11), (44538, 114), (44870, 4), (46910, 19), (47535, 19), (47739, 35),
    (49156, 4), (49374, 2), (49448, 8), (50179, 15), (50502, 0), (51280, 52), (52627, 26), (52989, 62), (53588, 4),
    (54438, 1), (54525, 2), (54543, 49), (54718, 2), (54755, 10), (54772, 8), (56052, 28), (56235, 13), (56814, 172),
    (57305, 4), (57374, 9), (57542, 85), (57715, 19), (57750, 0), (58230, 32), (58550, 35), (58730, 18), (60318, 24),
    (61284, 12), ];
pub(crate) const PEEL_SEED_FIXUPS: [(u16, u8); 768] = [
    (2373, 19), (2547, 15), (2632, 74), (2676, 38), (2962, 11), (3061, 52), (3217, 35), (3233, 40), (3430, 35),
    (3495, 57), (3559, 4), (3724, 4), (3758, 0), (3940, 7), (4266, 4), (4276, 61), (4461, 5), (4476, 8), (4595, 78),
    (4639, 20), (4651, 22), (4654, 82), (4771, 19), (4845, 18), (4878, 36), (4891, 5), (4935, 37), (5012, 8),
    (5206, 68), (5550, 35), (5585, 29), (5628, 21), (5735, 36), (5756, 33), (5778, 5), (5915, 5), (5933, 17),
    (5988, 56), (6013, 77), (6025, 4), (6107, 37), (6160, 4), (6238, 54), (6356, 85), (6373, 38), (6423, 0), (6472, 72),
    (6532, 14), (6588, 7), (6604, 4), (6710, 43), (6740, 10), (6761, 20), (6766, 21), (6804, 74), (6894, 12),
    (6938, 87), (7091, 7), (7142, 67), (7175, 77), (7216, 34), (7231, 64), (7245, 42), (7344, 13), (7398, 14),
    (7420, 23), (7435, 52), (7439, 41), (7489, 50), (7533, 38), (7564, 19), (7733, 36), (7936, 18), (7954, 27),
    (7964, 60), (8040, 3), (8125, 35), (8152, 83), (8200, 4), (8214, 40), (8503, 81), (8523, 13), (8615, 4), (8724, 2),
    (8855, 50), (8897, 61), (8902, 44), (8985, 11), (9010, 87), (9042, 3), (9217, 5), (9304, 78), (9308, 39),
    (9430, 41), (9619, 52), (9620, 20), (9659, 20), (9677, 0), (9684, 75), (9692, 57), (9738, 5), (9752, 16), (9869, 3),
    (9889, 78), (9938, 44), (9955, 49), (9988, 73), (10038, 38), (10048, 87), (10065, 23), (10169, 85), (10263, 24),
    (10399, 57), (10520, 17), (10620, 74), (10732, 49), (10738, 36), (10759, 17), (10819, 46), (10990, 24), (11012, 10),
    (11026, 25), (11153, 41), (11169, 3), (11197, 53), (11288, 5), (11289, 24), (11330, 61), (11446, 0), (11751, 70),
    (11758, 6), (11825, 33), (12056, 61), (12094, 36), (12110, 3), (12177, 26), (12194, 36), (12202, 42), (12339, 21),
    (12397, 72), (12429, 49), (12475, 50), (12484, 81), (12490, 67), (12507, 22), (12573, 62), (12711, 67), (12712, 54),
    (12735, 9), (12857, 64), (13268, 6), (13390, 85), (13425, 10), (13495, 66), (13502, 27), (13516, 43), (13645, 21),
    (13661, 14), (13750, 20), (13806, 12), (13820, 8), (13859, 1), (13873, 37), (13893, 2), (13996, 11), (14041, 30),
    (14266, 2), (14275, 61), (14518, 22), (14548, 48), (14674, 43), (14718, 36), (14721, 34), (14821, 16), (14864, 87),
    (14964, 18), (14985, 7), (14990, 18), (15019, 2), (15125, 17), (15201, 20), (15315, 1), (15323, 13), (15371, 2),
    (15446, 11), (15543, 4), (15549, 36), (15597, 17), (15620, 2), (15621, 31), (15711, 29), (15727, 37), (15734, 12),
    (15830, 16), (15888, 0), (15896, 15), (15905, 6), (15964, 14), (15997, 16), (16025, 0), (16049, 0), (16137, 13),
    (16168, 18), (16290, 0), (16305, 12), (16402, 0), (16494, 5), (16526, 7), (16561, 1), (16565, 6), (16629, 0),
    (16719, 39), (16720, 3), (16746, 5), (16770, 2), (16835, 2), (16851, 22), (16872, 7), (16882, 1), (16904, 9),
    (16905, 21), (16930, 37), (16983, 19), (16990, 15), (16997, 23), (17007, 4), (17127, 34), (17160, 36), (17177, 6),
    (17252, 20), (17349, 1), (17444, 7), (17561, 15), (17616, 13), (17629, 0), (17662, 18), (17696, 17), (17890, 3),
    (18276, 33), (18396, 21), (18474, 14), (18540, 33), (18542, 10), (18599, 14), (18615, 10), (18627, 1), (18716, 22),
    (18733, 32), (18736, 2), (18760, 10), (18791, 0), (18804, 23), (18851, 30), (18866, 39), (18889, 11), (18906, 1),
    (18925, 7), (19021, 3), (19030, 8), (19056, 1), (19113, 32), (19173, 23), (19247, 39), (19277, 14), (19299, 10),
    (19311, 0), (19491, 4), (19510, 8), (19541, 22), (19556, 1), (19557, 24), (19561, 31), (19583, 21), (19634, 33),
    (19677, 33), (19696, 3), (19703, 3), (19722, 31), (19741, 3), (19791, 10), (19809, 34), (19845, 1), (19868, 0),
    (20037, 1), (20152, 0), (20180, 39), (20224, 3), (20233, 29), (20243, 21), (20287, 21), (20334, 0), (20346, 8),
    (20403, 31), (20416, 32), (20478, 25), (20496, 34), (20516, 13), (20587, 17), (20684, 17), (20693, 2), (20699, 7),
    (20817, 9), (20822, 23), (20866, 1), (20948, 27), (20978, 34), (20991, 25), (21015, 7), (21031, 24), (21056, 14),
    (21067, 3), (21083, 32), (21116, 25), (21131, 19), (21161, 0), (21163, 10), (21182, 0), (21183, 4), (21337, 14),
    (21343, 38), (21365, 7), (21400, 10), (21449, 26), (21463, 2), (21500, 3), (21502, 3), (21516, 7), (21556, 26),
    (21618, 11), (21629, 2), (21699, 6), (21705, 39), (21706, 7), (21736, 30), (21769, 17), (21813, 39), (21815, 0),
    (21831, 9), (21869, 20), (21928, 3), (22018, 32), (22045, 27), (22046, 17), (22092, 2), (22198, 17), (22275, 9),
    (22354, 33), (22424, 5), (22429, 12), (22539, 3), (22552, 3), (22613, 26), (22734, 8), (22766, 37), (22978, 26),
    (22984, 6), (23025, 18), (23062, 4), (23078, 24), (23087, 39), (23102, 8), (23128, 4), (23148, 7), (23165, 29),
    (23166, 2), (23189, 14), (23298, 29), (23325, 33), (23340, 5), (23346, 26), (23347, 20), (23377, 23), (23397, 10),
    (23407, 31), (23607, 33), (23643, 15), (23656, 3), (23684, 1), (23711, 4), (23727, 28), (23778, 0), (23979, 3),
    (24039, 0), (24091, 1), (24146, 2), (24166, 39), (24201, 10), (24246, 12), (24350, 18), (24384, 23), (24401, 3),
    (24405, 13), (24419, 33), (24555, 20), (24557, 9), (24685, 27), (24700, 9), (24776, 13), (24879, 38), (24888, 9),
    (24967, 29), (25005, 14), (25075, 5), (25148, 17), (25160, 3), (25172, 23), (25177, 13), (25196, 0), (25211, 25),
    (25219, 3), (25331, 30), (25342, 20), (25363, 33), (25424, 9), (25503, 3), (25625, 25), (25631, 0), (25685, 12),
    (25787, 32), (25900, 12), (25920, 30), (25921, 5), (25936, 24), (25950, 25), (25954, 0), (26002, 0), (26067, 1),
    (26116, 19), (26137, 11), (26145, 8), (26189, 7), (26194, 2), (26195, 9), (26248, 17), (26254, 13), (26349, 3),
    (26384, 18), (26419, 13), (26496, 38), (26525, 16), (26535, 12), (26570, 27), (26600, 3), (26610, 26), (26637, 23),
    (26650, 13), (26704, 28), (26855, 0), (26866, 0), (26868, 29), (26877, 27), (26883, 5), (26911, 0), (26918, 5),
    (26931, 11), (26938, 26), (26986, 17), (26995, 24), (27010, 7), (27015, 2), (27042, 8), (27046, 2), (27062, 11),
    (27067, 26), (27070, 17), (27106, 27), (27149, 11), (27158, 0), (27190, 21), (27200, 1), (27228, 21), (27229, 28),
    (27275, 22), (27336, 9), (27428, 6), (27455, 8), (27466, 0), (27518, 17), (27524, 7), (27551, 5), (27566, 8),
    (27620, 23), (27623, 30), (27644, 9), (27660, 33), (27731, 37), (27743, 37), (27794, 38), (27875, 29), (27877, 9),
    (27894, 4), (27895, 36), (27936, 25), (27963, 9), (27968, 5), (27975, 15), (27984, 39), (27989, 9), (28018, 3),
    (28086, 15), (28097, 20), (28110, 1), (28130, 10), (28141, 18), (28214, 24), (28225, 10), (28239, 171), (28262, 2),
    (28266, 31), (28291, 14), (28293, 153), (28296, 13), (28315, 5), (28388, 30), (28399, 15), (28478, 4), (28484, 20),
    (28488, 19), (28544, 30), (28549, 10), (28559, 0), (28566, 15), (28572, 137), (28593, 8), (28648, 20), (28694, 7),
    (28729, 13), (28743, 27), (28818, 17), (28858, 9), (28893, 5), (28918, 25), (28962, 13), (28983, 3), (28990, 15),
    (28995, 27), (29015, 20), (29039, 3), (29075, 6), (29117, 81), (29137, 4), (29147, 19), (29154, 23), (29160, 1),
    (29191, 3), (29255, 5), (29257, 129), (29272, 3), (29284, 0), (29353, 13), (29374, 5), (29401, 31), (29422, 21),
    (29449, 212), (29462, 1), (29589, 23), (29647, 3), (29654, 21), (29666, 5), (29674, 7), (29697, 19), (29728, 3),
    (29736, 3), (29741, 3), (29784, 7), (29799, 17), (29824, 13), (29859, 17), (29861, 214), (29888, 1), (29899, 17),
    (29911, 18), (29954, 1), (29959, 4), (29968, 19), (30017, 20), (30045, 21), (30062, 1), (30085, 1), (30088, 13),
    (30125, 5), (30139, 13), (30150, 15), (30218, 3), (30236, 1), (30252, 17), (30256, 9), (30276, 193), (30277, 27),
    (30283, 3), (30289, 20), (30327, 18), (30329, 3), (30341, 7), (30392, 5), (30395, 13), (30396, 3), (30488, 0),
    (30494, 0), (30515, 39), (30567, 7), (30614, 9), (30663, 6), (30686, 7), (30706, 1), (30724, 4), (30727, 5),
    (30742, 20), (30765, 1), (30791, 11), (30818, 19), (30883, 14), (30954, 23), (30969, 0), (31027, 7), (31043, 9),
    (31045, 7), (31107, 2), (31219, 22), (31270, 1), (31325, 10), (31349, 6), (31364, 7), (31406, 11), (31459, 24),
    (31761, 0), (31801, 1), (31873, 7), (31912, 0), (31968, 3), (32204, 51), (32667, 222), (33395, 185), (33562, 31),
    (33622, 5), (33742, 96), (33754, 3), (33826, 25), (34248, 95), (34408, 3), (34664, 194), (35096, 26), (35269, 247),
    (35533, 65), (35579, 2), (36138, 31), (36395, 170), (36683, 143), (36878, 251), (36986, 231), (37074, 179),
    (37141, 31), (37538, 41), (37762, 211), (37795, 31), (37835, 27), (37842, 253), (39042, 53), (39199, 12),
    (39304, 145), (39410, 7), (39507, 43), (39696, 193), (39758, 47), (40101, 223), (40136, 84), (40537, 107),
    (40684, 54), (40719, 20), (40735, 19), (40774, 21), (40915, 85), (40939, 5), (40960, 4), (41009, 86), (41087, 109),
    (41349, 165), (41392, 242), (41647, 43), (41818, 15), (42296, 207), (42325, 9), (42558, 151), (42644, 157),
    (42757, 173), (43493, 215), (43501, 255), (43547, 6), (43910, 25), (44119, 43), (44538, 185), (44834, 17),
    (44870, 59), (45177, 17), (45220, 33), (45253, 0), (45408, 21), (46910, 168), (47462, 141), (47495, 0), (47535, 45),
    (47621, 47), (47739, 173), (47873, 55), (48773, 31), (48884, 81), (48997, 17), (49065, 77), (49156, 19),
    (49374, 91), (49448, 82), (50156, 41), (50179, 238), (50338, 73), (50360, 54), (50502, 17), (50664, 209),
    (51280, 1), (51620, 41), (51883, 0), (52311, 9), (52327, 76), (52416, 112), (52512, 126), (52619, 14), (52627, 75),
    (52989, 107), (53421, 43), (53533, 12), (53588, 107), (54438, 17), (54441, 168), (54516, 47), (54525, 231),
    (54543, 106), (54718, 161), (54755, 237), (54772, 49), (54846, 64), (56052, 221), (56235, 113), (56814, 57),
    (56982, 51), (57064, 4), (57150, 7), (57305, 255), (57374, 74), (57429, 5), (57542, 41), (57664, 2), (57715, 25),
    (57725, 7), (57736, 30), (57750, 200), (58230, 108), (58550, 80), (58622, 22), (58730, 120), (59115, 35),
    (59383, 14), (59943, 16), (60027, 12),
    (60318, 172), (60522, 8), (60813, 31), (61284, 99), (62389, 2), (62615, 51), ];
