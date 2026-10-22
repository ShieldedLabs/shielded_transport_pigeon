//! GF(2^8) math for the in-crate Wirehair port.
//!
//! Pure-Rust port of `third_party/wirehair/gf256.{h,cpp}` (GF256_VERSION 2). Bulk operations have a portable scalar
//! kernel (used on every target, and whenever the CPU lacks SSSE3) plus x86_64 SSSE3/AVX2 kernels selected at runtime
//! with `is_x86_feature_detected!`; the SIMD kernels use the upstream split-nibble shuffle multiply. Every kernel
//! computes exactly the same bytes, so results are byte-identical to the C++ library on every target. No C, C++,
//! assembly or global target flags are needed.
//!
//! Field: polynomial index 3 of the 16 generator polynomials, i.e. `(0xa6 << 1) | 1 = 0x14D`. The
//! log/exp/mul/div/inv/sqr tables are built at compile time by the same algorithm as `gf256_init()`, so no runtime
//! initialisation call exists or is needed.
//!
//! Bulk operations take safe slices instead of raw pointers. The operation length is the destination length (or, for
//! `muladd_multi_mem`, the source length); every other operand must be at least that long or the call panics before
//! writing anything. An empty length is a no-op, matching the C++ `bytes <= 0` early return. Rust borrowing rules
//! enforce the C++ non-overlap (`restrict`) contracts; the one aliasing case the C++ API allows (`gf256_mul_mem` /
//! `gf256_div_mem` with `vz == vx`) is exposed as the `*_inplace` variants.
//!
//! Original code: Copyright (c) 2017 Christopher A. Taylor. All rights reserved. Rust port derived from it under the
//! same license:
//!
//! Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//! following conditions are met:
//!
//! * Redistributions of source code must retain the above copyright notice,
//!   this list of conditions and the following disclaimer.
//! * Redistributions in binary form must reproduce the above copyright notice,
//!   this list of conditions and the following disclaimer in the documentation
//!   and/or other materials provided with the distribution.
//! * Neither the name of GF256 nor the names of its contributors may be
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
pub const VERSION: u32 = 2;
pub const GEN_POLY: [u8; 16] = [
    0x8e, 0x95, 0x96, 0xa6, 0xaf, 0xb1, 0xb2, 0xb4, 0xb8, 0xc3, 0xc6, 0xd4, 0xe1, 0xe7, 0xf3, 0xfa,
];
pub const DEFAULT_POLYNOMIAL_INDEX: usize = 3;
pub const POLYNOMIAL: u32 = ((GEN_POLY[DEFAULT_POLYNOMIAL_INDEX] as u32) << 1) | 1;
const EXP_LEN: usize = 512 * 2 + 1;
const fn build_explog() -> ([u8; EXP_LEN], [u16; 256]) {
    let poly = POLYNOMIAL;
    let mut exptab = [0u8; EXP_LEN];
    let mut logtab = [0u16; 256];
    logtab[0] = 512;
    exptab[0] = 1;
    let mut jj = 1usize;
    while jj < 255 {
        let mut next = (exptab[jj - 1] as u32) * 2;
        if next >= 256 {
            next ^= poly;
        }
        exptab[jj] = next as u8;
        logtab[exptab[jj] as usize] = jj as u16;
        jj += 1;
    }
    exptab[255] = exptab[0];
    logtab[exptab[255] as usize] = 255;
    jj = 256;
    while jj < 2 * 255 {
        exptab[jj] = exptab[jj % 255];
        jj += 1;
    }
    exptab[2 * 255] = 1;
    jj = 2 * 255 + 1;
    while jj < 4 * 255 {
        exptab[jj] = 0;
        jj += 1;
    }
    (exptab, logtab)
}
const EXPLOG: ([u8; EXP_LEN], [u16; 256]) = build_explog();
pub static EXP_TABLE: [u8; EXP_LEN] = EXPLOG.0;
pub static LOG_TABLE: [u16; 256] = EXPLOG.1;
const fn build_muldiv(div: bool) -> [u8; 65536] {
    let exptab = EXPLOG.0;
    let logtab = EXPLOG.1;
    let mut t = [0u8; 65536];
    let mut y = 1usize;
    while y < 256 {
        let log_y = logtab[y] as u8;
        let log_yn = 255u8.wrapping_sub(log_y);
        let add = if div { log_yn } else { log_y } as usize;
        let mut x = 1usize;
        while x < 256 {
            let log_x = logtab[x] as usize;
            t[(y << 8) + x] = exptab[log_x + add];
            x += 1;
        }
        y += 1;
    }
    t
}
const MUL_CONST: [u8; 65536] = build_muldiv(false);
const DIV_CONST: [u8; 65536] = build_muldiv(true);
pub static MUL_TABLE: [u8; 65536] = MUL_CONST;
pub static DIV_TABLE: [u8; 65536] = DIV_CONST;
const fn build_inv() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        t[x] = DIV_CONST[(x << 8) + 1];
        x += 1;
    }
    t
}
const fn build_sqr() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        t[x] = MUL_CONST[(x << 8) + x];
        x += 1;
    }
    t
}
pub static INV_TABLE: [u8; 256] = build_inv();
pub static SQR_TABLE: [u8; 256] = build_sqr();
#[inline(always)]
pub fn add(x: u8, y: u8) -> u8 {
    x ^ y
}
#[inline(always)]
pub fn mul(x: u8, y: u8) -> u8 {
    MUL_TABLE[((y as usize) << 8) + x as usize]
}
#[inline(always)]
pub fn div(x: u8, y: u8) -> u8 {
    DIV_TABLE[((y as usize) << 8) + x as usize]
}
#[inline(always)]
pub fn inv(x: u8) -> u8 {
    INV_TABLE[x as usize]
}
#[inline(always)]
pub fn sqr(x: u8) -> u8 {
    SQR_TABLE[x as usize]
}
#[inline(always)]
pub fn mul_row(y: u8) -> &'static [u8; 256] {
    let base = (y as usize) << 8;
    match MUL_TABLE[base..base + 256].try_into() {
        Ok(row) => row,
        Err(_) => unreachable!(),
    }
}
static MM_LO: [[u8; 16]; 256] = build_nibble(false);
static MM_HI: [[u8; 16]; 256] = build_nibble(true);
const fn build_nibble(high: bool) -> [[u8; 16]; 256] {
    let mut t = [[0u8; 16]; 256];
    let mut y = 0usize;
    while y < 256 {
        let mut x = 0usize;
        while x < 16 {
            let v = if high { x << 4 } else { x };
            t[y][x] = MUL_CONST[(y << 8) + v];
            x += 1;
        }
        y += 1;
    }
    t
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Level {
    Scalar,
    Ssse3,
    Avx2,
}
#[inline]
fn level() -> Level {
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::{AtomicU8, Ordering};
        static CACHE: AtomicU8 = AtomicU8::new(0);
        match CACHE.load(Ordering::Relaxed) {
            1 => return Level::Scalar,
            2 => return Level::Ssse3,
            3 => return Level::Avx2,
            _ => {}
        }
        let (l, code) =
            if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("ssse3") {
                (Level::Avx2, 3)
            } else if std::is_x86_feature_detected!("ssse3") {
                (Level::Ssse3, 2)
            } else {
                (Level::Scalar, 1)
            };
        CACHE.store(code, Ordering::Relaxed);
        l
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Level::Scalar
    }
}
macro_rules! dispatch {
    ($l:expr, $f:ident ( $($a:expr),* )) => {
        match $l {
            // SAFETY: Level::Avx2 / Level::Ssse3 are only produced by `level()` after runtime detection of the feature
            // (or, in tests, by `levels()`, which applies the same detection).
            #[cfg(target_arch = "x86_64")] Level::Avx2 => unsafe { avx2::$f($($a),*) },
            #[cfg(target_arch = "x86_64")] Level::Ssse3 => unsafe { ssse3::$f($($a),*) },
            _ => scalar::$f($($a),*), } }; }
mod scalar {
    use super::mul_row;
    #[inline(always)]
    pub fn xor1(x: &mut [u8], y: &[u8]) {
        let y = &y[..x.len()];
        let mut xc = x.chunks_exact_mut(8);
        let mut yc = y.chunks_exact(8);
        for (a, b) in (&mut xc).zip(&mut yc) {
            let mut wa = [0u8; 8];
            let mut wb = [0u8; 8];
            wa.copy_from_slice(a);
            wb.copy_from_slice(b);
            let v = u64::from_ne_bytes(wa) ^ u64::from_ne_bytes(wb);
            a.copy_from_slice(&v.to_ne_bytes());
        }
        for (a, b) in xc.into_remainder().iter_mut().zip(yc.remainder()) {
            *a ^= *b;
        }
    }
    pub fn xor2(z: &mut [u8], x: &[u8], y: &[u8]) {
        let n = z.len();
        for ((a, b), c) in z.iter_mut().zip(&x[..n]).zip(&y[..n]) {
            *a ^= *b ^ *c;
        }
    }
    pub fn set2(z: &mut [u8], x: &[u8], y: &[u8]) {
        let n = z.len();
        for ((a, b), c) in z.iter_mut().zip(&x[..n]).zip(&y[..n]) {
            *a = *b ^ *c;
        }
    }
    pub fn xor_multi(z: &mut [u8], srcs: &[&[u8]], set: bool, off: usize) {
        let n = z.len();
        let z = &mut z[off..];
        let rest = if set {
            z.copy_from_slice(&srcs[0][off..n]);
            &srcs[1..]
        } else {
            srcs
        };
        for s in rest {
            xor1(z, &s[off..n]);
        }
    }
    pub fn mul(z: &mut [u8], x: &[u8], y: u8) {
        let t = mul_row(y);
        let n = z.len();
        for (a, b) in z.iter_mut().zip(&x[..n]) {
            *a = t[*b as usize];
        }
    }
    pub fn mul_inplace(z: &mut [u8], y: u8) {
        let t = mul_row(y);
        for a in z.iter_mut() {
            *a = t[*a as usize];
        }
    }
    pub fn muladd(z: &mut [u8], x: &[u8], y: u8) {
        let t = mul_row(y);
        let n = z.len();
        for (a, b) in z.iter_mut().zip(&x[..n]) {
            *a ^= t[*b as usize];
        }
    }
    pub fn mulset_multi(z: &mut [u8], srcs: &[&[u8]], scales: &[u8], off: usize) {
        let n = z.len();
        let z = &mut z[off..];
        z.fill(0);
        for (s, &c) in srcs.iter().zip(scales) {
            match c {
                0 => {}
                1 => xor1(z, &s[off..n]),
                _ => muladd(z, &s[off..n], c),
            }
        }
    }
}
#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
mod p128 {
    use super::{MM_HI, MM_LO};
    use core::arch::x86_64::*;
    pub type V = __m128i;
    pub const W: usize = 16;
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn ld(p: *const u8) -> V {
        unsafe { _mm_loadu_si128(p.cast()) }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn st(p: *mut u8, v: V) {
        unsafe { _mm_storeu_si128(p.cast(), v) }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn xor(a: V, b: V) -> V {
        unsafe { _mm_xor_si128(a, b) }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn zero() -> V {
        unsafe { _mm_setzero_si128() }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn mask() -> V {
        unsafe { _mm_set1_epi8(0x0f) }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn tables(y: u8) -> (V, V) {
        unsafe {
            (
                ld(MM_LO[y as usize].as_ptr()),
                ld(MM_HI[y as usize].as_ptr()),
            )
        }
    }
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub unsafe fn mulv(v: V, lo: V, hi: V, m: V) -> V {
        unsafe {
            let l = _mm_and_si128(v, m);
            let h = _mm_and_si128(_mm_srli_epi64::<4>(v), m);
            _mm_xor_si128(_mm_shuffle_epi8(lo, l), _mm_shuffle_epi8(hi, h))
        }
    }
}
#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
mod p256 {
    use super::{MM_HI, MM_LO};
    use core::arch::x86_64::*;
    pub type V = __m256i;
    pub const W: usize = 32;
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn ld(p: *const u8) -> V {
        unsafe { _mm256_loadu_si256(p.cast()) }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn st(p: *mut u8, v: V) {
        unsafe { _mm256_storeu_si256(p.cast(), v) }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor(a: V, b: V) -> V {
        unsafe { _mm256_xor_si256(a, b) }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn zero() -> V {
        unsafe { _mm256_setzero_si256() }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn mask() -> V {
        unsafe { _mm256_set1_epi8(0x0f) }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn tables(y: u8) -> (V, V) {
        unsafe {
            let lo = _mm_loadu_si128(MM_LO[y as usize].as_ptr().cast());
            let hi = _mm_loadu_si128(MM_HI[y as usize].as_ptr().cast());
            (
                _mm256_broadcastsi128_si256(lo),
                _mm256_broadcastsi128_si256(hi),
            )
        }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn mulv(v: V, lo: V, hi: V, m: V) -> V {
        unsafe {
            let l = _mm256_and_si256(v, m);
            let h = _mm256_and_si256(_mm256_srli_epi64::<4>(v), m);
            _mm256_xor_si256(_mm256_shuffle_epi8(lo, l), _mm256_shuffle_epi8(hi, h))
        }
    }
}
/// Builds one SIMD kernel module from a primitive module `$p` (vector width `$p::W`). Each kernel runs whole vectors (4
/// at a time, then 1 at a time) and hands the remaining `< W` bytes to the `$tail` kernel module.
///
/// SAFETY contract of every generated function: the CPU supports `$feat`, and the shared kernel contract above holds
/// (it is what keeps every raw pointer access inside its slice).
#[cfg(target_arch = "x86_64")]
macro_rules! simd_kernels {
    ($m:ident, $feat:literal, $p:ident, $tail:ident) => {
        #[allow(unused_unsafe)] mod $m {
            use super::$p::*; use super::$tail as tail;
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn xor1(z: &mut [u8], x: &[u8]) {
                let n = z.len(); debug_assert!(x.len() >= n); let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe {
                    while i + 4 * W <= n {
                        let a0 = xor(ld(zp.add(i)), ld(xp.add(i))); let a1 = xor(ld(zp.add(i + W)), ld(xp.add(i + W)));
                        let a2 = xor(ld(zp.add(i + 2 * W)), ld(xp.add(i + 2 * W)));
                        let a3 = xor(ld(zp.add(i + 3 * W)), ld(xp.add(i + 3 * W))); st(zp.add(i), a0);
                        st(zp.add(i + W), a1); st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { st(zp.add(i), xor(ld(zp.add(i)), ld(xp.add(i)))); i += W; }
                    tail::xor1(&mut z[i..], &x[i..n]); } }
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn xor2(z: &mut [u8], x: &[u8], y: &[u8]) {
                let n = z.len(); debug_assert!(x.len() >= n && y.len() >= n);
                let (zp, xp, yp) = (z.as_mut_ptr(), x.as_ptr(), y.as_ptr()); let mut i = 0;
                unsafe {
                    while i + 2 * W <= n { let a0 = xor(ld(zp.add(i)), xor(ld(xp.add(i)), ld(yp.add(i))));
                        let a1 = xor(ld(zp.add(i + W)), xor(ld(xp.add(i + W)), ld(yp.add(i + W))), ); st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        i += 2 * W; }
                    while i + W <= n { st(zp.add(i), xor(ld(zp.add(i)), xor(ld(xp.add(i)), ld(yp.add(i))))); i += W; }
                    tail::xor2(&mut z[i..], &x[i..n], &y[i..n]); } }
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn set2(z: &mut [u8], x: &[u8], y: &[u8]) {
                let n = z.len(); debug_assert!(x.len() >= n && y.len() >= n);
                let (zp, xp, yp) = (z.as_mut_ptr(), x.as_ptr(), y.as_ptr()); let mut i = 0;
                unsafe {
                    while i + 2 * W <= n {
                        let a0 = xor(ld(xp.add(i)), ld(yp.add(i))); let a1 = xor(ld(xp.add(i + W)), ld(yp.add(i + W)));
                        st(zp.add(i), a0); st(zp.add(i + W), a1);
                        i += 2 * W; }
                    while i + W <= n { st(zp.add(i), xor(ld(xp.add(i)), ld(yp.add(i)))); i += W; }
                    tail::set2(&mut z[i..], &x[i..n], &y[i..n]); } }
            #[inline] #[target_feature(enable = $feat)]
            pub unsafe fn xor_multi(z: &mut [u8], srcs: &[&[u8]], set: bool, off: usize) {
                let n = z.len(); debug_assert!(!srcs.is_empty() && srcs.iter().all(|s| s.len() >= n));
                let zp = z.as_mut_ptr();
                let (first, rest): (*const u8, &[&[u8]]) = if set {
                    (srcs[0].as_ptr(), &srcs[1..]) } else { (zp as *const u8, srcs) };
                let mut i = off;
                unsafe {
                    while i + 4 * W <= n { let mut a0 = ld(first.add(i)); let mut a1 = ld(first.add(i + W));
                        let mut a2 = ld(first.add(i + 2 * W)); let mut a3 = ld(first.add(i + 3 * W));
                        for s in rest { let p = s.as_ptr().add(i); a0 = xor(a0, ld(p)); a1 = xor(a1, ld(p.add(W)));
                            a2 = xor(a2, ld(p.add(2 * W)));
                            a3 = xor(a3, ld(p.add(3 * W))); }
                        st(zp.add(i), a0); st(zp.add(i + W), a1); st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { let mut a = ld(first.add(i));
                        for s in rest { a = xor(a, ld(s.as_ptr().add(i))); }
                        st(zp.add(i), a);
                        i += W; }
                    tail::xor_multi(z, srcs, set, i); } }
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn mul(z: &mut [u8], x: &[u8], y: u8) {
                let n = z.len(); debug_assert!(x.len() >= n); let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe { let (lo, hi) = tables(y); let m = mask();
                    while i + 4 * W <= n {
                        let a0 = mulv(ld(xp.add(i)), lo, hi, m); let a1 = mulv(ld(xp.add(i + W)), lo, hi, m);
                        let a2 = mulv(ld(xp.add(i + 2 * W)), lo, hi, m);
                        let a3 = mulv(ld(xp.add(i + 3 * W)), lo, hi, m); st(zp.add(i), a0); st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { st(zp.add(i), mulv(ld(xp.add(i)), lo, hi, m)); i += W; }
                    tail::mul(&mut z[i..], &x[i..n], y); } }
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn mul_inplace(z: &mut [u8], y: u8) {
                let n = z.len(); let zp = z.as_mut_ptr(); let mut i = 0;
                unsafe { let (lo, hi) = tables(y); let m = mask();
                    while i + 4 * W <= n {
                        let a0 = mulv(ld(zp.add(i)), lo, hi, m); let a1 = mulv(ld(zp.add(i + W)), lo, hi, m);
                        let a2 = mulv(ld(zp.add(i + 2 * W)), lo, hi, m);
                        let a3 = mulv(ld(zp.add(i + 3 * W)), lo, hi, m); st(zp.add(i), a0); st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { st(zp.add(i), mulv(ld(zp.add(i)), lo, hi, m)); i += W; }
                    tail::mul_inplace(&mut z[i..], y); } }
            #[inline] #[target_feature(enable = $feat)] pub unsafe fn muladd(z: &mut [u8], x: &[u8], y: u8) {
                let n = z.len(); debug_assert!(x.len() >= n); let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe { let (lo, hi) = tables(y); let m = mask();
                    while i + 4 * W <= n { let a0 = xor(ld(zp.add(i)), mulv(ld(xp.add(i)), lo, hi, m));
                        let a1 = xor(ld(zp.add(i + W)), mulv(ld(xp.add(i + W)), lo, hi, m));
                        let a2 = xor(ld(zp.add(i + 2 * W)), mulv(ld(xp.add(i + 2 * W)), lo, hi, m));
                        let a3 = xor(ld(zp.add(i + 3 * W)), mulv(ld(xp.add(i + 3 * W)), lo, hi, m)); st(zp.add(i), a0);
                        st(zp.add(i + W), a1); st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { st(zp.add(i), xor(ld(zp.add(i)), mulv(ld(xp.add(i)), lo, hi, m))); i += W; }
                    tail::muladd(&mut z[i..], &x[i..n], y); } }
            #[inline] #[target_feature(enable = $feat)]
            pub unsafe fn mulset_multi(z: &mut [u8], srcs: &[&[u8]], scales: &[u8], off: usize) {
                let n = z.len(); debug_assert!(scales.len() >= srcs.len() && srcs.iter().all(|s| s.len() >= n));
                let zp = z.as_mut_ptr(); let mut i = off;
                unsafe { let m = mask();
                    while i + 4 * W <= n { let (mut a0, mut a1, mut a2, mut a3) = (zero(), zero(), zero(), zero());
                        for (s, &c) in srcs.iter().zip(scales) { let p = s.as_ptr().add(i);
                            let (v0, v1, v2, v3) = (ld(p), ld(p.add(W)), ld(p.add(2 * W)), ld(p.add(3 * W)));
                            match c {
                                0 => continue,
                                1 => { a0 = xor(a0, v0); a1 = xor(a1, v1); a2 = xor(a2, v2); a3 = xor(a3, v3); }
                                _ => { let (lo, hi) = tables(c); a0 = xor(a0, mulv(v0, lo, hi, m));
                                    a1 = xor(a1, mulv(v1, lo, hi, m)); a2 = xor(a2, mulv(v2, lo, hi, m));
                                    a3 = xor(a3, mulv(v3, lo, hi, m)); } } }
                        st(zp.add(i), a0); st(zp.add(i + W), a1); st(zp.add(i + 2 * W), a2); st(zp.add(i + 3 * W), a3);
                        i += 4 * W; }
                    while i + W <= n { let mut a = zero();
                        for (s, &c) in srcs.iter().zip(scales) { let v = ld(s.as_ptr().add(i));
                            match c {
                                0 => {}
                                1 => a = xor(a, v),
                                _ => { let (lo, hi) = tables(c); a = xor(a, mulv(v, lo, hi, m)); } } }
                        st(zp.add(i), a);
                        i += W; }
                    tail::mulset_multi(z, srcs, scales, i); } } } }; }
#[cfg(target_arch = "x86_64")]
simd_kernels!(ssse3, "ssse3", p128, scalar);
#[cfg(target_arch = "x86_64")]
simd_kernels!(avx2, "avx2", p256, ssse3);
pub fn add_mem(x: &mut [u8], y: &[u8]) {
    add_mem_at(level(), x, y)
}
fn add_mem_at(l: Level, x: &mut [u8], y: &[u8]) {
    if x.is_empty() {
        return;
    }
    let y = &y[..x.len()];
    dispatch!(l, xor1(x, y))
}
pub fn add2_mem(z: &mut [u8], x: &[u8], y: &[u8]) {
    add2_mem_at(level(), z, x, y)
}
fn add2_mem_at(l: Level, z: &mut [u8], x: &[u8], y: &[u8]) {
    let n = z.len();
    if n == 0 {
        return;
    }
    let (x, y) = (&x[..n], &y[..n]);
    dispatch!(l, xor2(z, x, y))
}
pub fn addset_mem(z: &mut [u8], x: &[u8], y: &[u8]) {
    addset_mem_at(level(), z, x, y)
}
fn addset_mem_at(l: Level, z: &mut [u8], x: &[u8], y: &[u8]) {
    let n = z.len();
    if n == 0 {
        return;
    }
    let (x, y) = (&x[..n], &y[..n]);
    dispatch!(l, set2(z, x, y))
}
fn check_sources(n: usize, srcs: &[&[u8]]) {
    for s in srcs {
        assert!(s.len() >= n, "gf256: source shorter than destination");
    }
}
pub fn add_multi_mem(z: &mut [u8], srcs: &[&[u8]]) {
    add_multi_mem_at(level(), z, srcs)
}
fn add_multi_mem_at(l: Level, z: &mut [u8], srcs: &[&[u8]]) {
    let n = z.len();
    if n == 0 || srcs.is_empty() {
        return;
    }
    check_sources(n, srcs);
    dispatch!(l, xor_multi(z, srcs, false, 0))
}
pub fn addset_multi_mem(z: &mut [u8], srcs: &[&[u8]]) {
    addset_multi_mem_at(level(), z, srcs)
}
fn addset_multi_mem_at(l: Level, z: &mut [u8], srcs: &[&[u8]]) {
    let n = z.len();
    if n == 0 || srcs.is_empty() {
        return;
    }
    check_sources(n, srcs);
    if srcs.len() == 1 {
        z.copy_from_slice(&srcs[0][..n]);
        return;
    }
    dispatch!(l, xor_multi(z, srcs, true, 0))
}
pub fn mul_mem(z: &mut [u8], x: &[u8], y: u8) {
    mul_mem_at(level(), z, x, y)
}
fn mul_mem_at(l: Level, z: &mut [u8], x: &[u8], y: u8) {
    let n = z.len();
    if n == 0 {
        return;
    }
    let x = &x[..n];
    match y {
        0 => z.fill(0),
        1 => z.copy_from_slice(x),
        _ => dispatch!(l, mul(z, x, y)),
    }
}
pub fn mul_mem_inplace(z: &mut [u8], y: u8) {
    mul_mem_inplace_at(level(), z, y)
}
fn mul_mem_inplace_at(l: Level, z: &mut [u8], y: u8) {
    if z.is_empty() {
        return;
    }
    match y {
        0 => z.fill(0),
        1 => {}
        _ => dispatch!(l, mul_inplace(z, y)),
    }
}
pub fn div_mem(z: &mut [u8], x: &[u8], y: u8) {
    mul_mem(z, x, if y == 1 { 1 } else { inv(y) });
}
pub fn div_mem_inplace(z: &mut [u8], y: u8) {
    mul_mem_inplace(z, if y == 1 { 1 } else { inv(y) });
}
pub fn muladd_mem(z: &mut [u8], y: u8, x: &[u8]) {
    muladd_mem_at(level(), z, y, x)
}
fn muladd_mem_at(l: Level, z: &mut [u8], y: u8, x: &[u8]) {
    let n = z.len();
    if n == 0 {
        return;
    }
    let x = &x[..n];
    match y {
        0 => {}
        1 => dispatch!(l, xor1(z, x)),
        _ => dispatch!(l, muladd(z, x, y)),
    }
}
pub fn muladd_multi_mem(destinations: &mut [&mut [u8]], scales: &[u8], source: &[u8]) {
    muladd_multi_mem_at(level(), destinations, scales, source)
}
const MULADD_MULTI_CHUNK: usize = 4096;
fn muladd_multi_mem_at(l: Level, destinations: &mut [&mut [u8]], scales: &[u8], source: &[u8]) {
    let n = source.len();
    if n == 0 || destinations.is_empty() {
        return;
    }
    let scales = &scales[..destinations.len()];
    for d in destinations.iter() {
        assert!(d.len() >= n, "gf256: destination shorter than source");
    }
    let mut start = 0;
    while start < n {
        let end = n.min(start + MULADD_MULTI_CHUNK);
        let src = &source[start..end];
        for (d, &s) in destinations.iter_mut().zip(scales) {
            muladd_mem_at(l, &mut d[start..end], s, src);
        }
        start = end;
    }
}
pub fn mulset_multi_mem(destination: &mut [u8], sources: &[&[u8]], scales: &[u8]) {
    mulset_multi_mem_at(level(), destination, sources, scales)
}
fn mulset_multi_mem_at(l: Level, destination: &mut [u8], sources: &[&[u8]], scales: &[u8]) {
    let n = destination.len();
    if n == 0 || sources.is_empty() {
        return;
    }
    let scales = &scales[..sources.len()];
    check_sources(n, sources);
    dispatch!(l, mulset_multi(destination, sources, scales, 0))
}
pub fn memswap(x: &mut [u8], y: &mut [u8]) {
    let n = x.len();
    if n == 0 {
        return;
    }
    x.swap_with_slice(&mut y[..n]);
}
#[allow(unused_imports)]
pub use self::{
    add as gf256_add, add_mem as gf256_add_mem, add_multi_mem as gf256_add_multi_mem,
    add2_mem as gf256_add2_mem, addset_mem as gf256_addset_mem,
    addset_multi_mem as gf256_addset_multi_mem, div as gf256_div, div_mem as gf256_div_mem,
    div_mem_inplace as gf256_div_mem_inplace, inv as gf256_inv, memswap as gf256_memswap,
    mul as gf256_mul, mul_mem as gf256_mul_mem, mul_mem_inplace as gf256_mul_mem_inplace,
    muladd_mem as gf256_muladd_mem, muladd_multi_mem as gf256_muladd_multi_mem,
    mulset_multi_mem as gf256_mulset_multi_mem, sqr as gf256_sqr,
};
