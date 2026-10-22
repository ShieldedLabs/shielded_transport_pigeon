//! GF(2^8) math for the in-crate Wirehair port.
//!
//! Pure-Rust port of `third_party/wirehair/gf256.{h,cpp}` (GF256_VERSION 2).
//! Bulk operations have a portable scalar kernel (used on every target, and
//! whenever the CPU lacks SSSE3) plus x86_64 SSSE3/AVX2 kernels selected at
//! runtime with `is_x86_feature_detected!`; the SIMD kernels use the upstream
//! split-nibble shuffle multiply.  Every kernel computes exactly the same
//! bytes, so results are byte-identical to the C++ library on every target.
//! No C, C++, assembly or global target flags are needed.
//!
//! Field: polynomial index 3 of the 16 generator polynomials, i.e.
//! `(0xa6 << 1) | 1 = 0x14D`.  The log/exp/mul/div/inv/sqr tables are built at
//! compile time by the same algorithm as `gf256_init()`, so no runtime
//! initialisation call exists or is needed.
//!
//! Bulk operations take safe slices instead of raw pointers.  The operation
//! length is the destination length (or, for `muladd_multi_mem`, the source
//! length); every other operand must be at least that long or the call
//! panics before writing anything.  An empty length is a no-op, matching the
//! C++ `bytes <= 0` early return.  Rust borrowing rules enforce the C++
//! non-overlap (`restrict`) contracts; the one aliasing case the C++ API
//! allows (`gf256_mul_mem` / `gf256_div_mem` with `vz == vx`) is exposed as
//! the `*_inplace` variants.
//!
//! Original code: Copyright (c) 2017 Christopher A. Taylor.  All rights
//! reserved.  Rust port derived from it under the same license:
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
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
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//! AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//! IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//! ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//! LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//! CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//! SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//! INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//! CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//! ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//! POSSIBILITY OF SUCH DAMAGE.

#![allow(dead_code)]

/// Library version this port matches (`GF256_VERSION`).
pub const VERSION: u32 = 2;

/// The 16 irreducible generator polynomials (`GF256_GEN_POLY`).
pub const GEN_POLY: [u8; 16] = [
    0x8e, 0x95, 0x96, 0xa6, 0xaf, 0xb1, 0xb2, 0xb4, 0xb8, 0xc3, 0xc6, 0xd4, 0xe1, 0xe7, 0xf3, 0xfa,
];

/// `kDefaultPolynomialIndex`.
pub const DEFAULT_POLYNOMIAL_INDEX: usize = 3;

/// `GF256Ctx.Polynomial` = 0x14D.
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

/// `GF256Ctx.GF256_EXP_TABLE`.
pub static EXP_TABLE: [u8; EXP_LEN] = EXPLOG.0;
/// `GF256Ctx.GF256_LOG_TABLE` (log(0) = 512 sentinel, log(1) = 255).
pub static LOG_TABLE: [u16; 256] = EXPLOG.1;

/// Builds the MUL (`div == false`) or DIV table exactly as
/// `gf256_muldiv_init()` does.
const fn build_muldiv(div: bool) -> [u8; 65536] {
    let exptab = EXPLOG.0;
    let logtab = EXPLOG.1;
    let mut t = [0u8; 65536];
    let mut y = 1usize;
    while y < 256 {
        // log_y is truncated to uint8_t as in the C++ (log(1) = 255).
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

/// `GF256Ctx.GF256_MUL_TABLE`: `MUL_TABLE[(y << 8) + x] = x * y`.
pub static MUL_TABLE: [u8; 65536] = MUL_CONST;
/// `GF256Ctx.GF256_DIV_TABLE`: `DIV_TABLE[(y << 8) + x] = x / y` (x / 0 = 0).
pub static DIV_TABLE: [u8; 65536] = DIV_CONST;

const fn build_inv() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        // gf256_div(1, x)
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

/// `GF256Ctx.GF256_INV_TABLE` (inv(0) = 0).
pub static INV_TABLE: [u8; 256] = build_inv();
/// `GF256Ctx.GF256_SQR_TABLE`.
pub static SQR_TABLE: [u8; 256] = build_sqr();

//------------------------------------------------------------------------------
// Scalar math

/// return x + y
#[inline(always)]
pub fn add(x: u8, y: u8) -> u8 {
    x ^ y
}

/// return x * y
#[inline(always)]
pub fn mul(x: u8, y: u8) -> u8 {
    MUL_TABLE[((y as usize) << 8) + x as usize]
}

/// return x / y (x / 0 = 0, as the C++ table)
#[inline(always)]
pub fn div(x: u8, y: u8) -> u8 {
    DIV_TABLE[((y as usize) << 8) + x as usize]
}

/// return 1 / x (inv(0) = 0)
#[inline(always)]
pub fn inv(x: u8) -> u8 {
    INV_TABLE[x as usize]
}

/// return x * x
#[inline(always)]
pub fn sqr(x: u8) -> u8 {
    SQR_TABLE[x as usize]
}

/// The 256-entry row `t[x] = x * y` of the multiplication table.
#[inline(always)]
pub fn mul_row(y: u8) -> &'static [u8; 256] {
    let base = (y as usize) << 8;
    match MUL_TABLE[base..base + 256].try_into() {
        Ok(row) => row,
        Err(_) => unreachable!(),
    }
}

/// `GF256Ctx.MM128.TABLE_LO_Y`: `MM_LO[y][x] = x * y` for nibbles `x < 16`.
static MM_LO: [[u8; 16]; 256] = build_nibble(false);
/// `GF256Ctx.MM128.TABLE_HI_Y`: `MM_HI[y][x] = (x << 4) * y` for `x < 16`.
static MM_HI: [[u8; 16]; 256] = build_nibble(true);

/// The split-nibble shuffle tables exactly as `gf256_mul_mem_init()` builds
/// them: `x * y = MM_LO[y][x & 15] ^ MM_HI[y][x >> 4]`.
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

//------------------------------------------------------------------------------
// Kernel selection
//
// Every bulk operation has a portable scalar kernel (`scalar`, always built,
// the only one on non-x86_64 targets and the Cosmopolitan fallback when the
// CPU lacks SSSE3) and, on x86_64, SSSE3 and AVX2 kernels that implement the
// upstream gf256.cpp split-nibble shuffle multiply.  The SIMD kernels are
// `#[target_feature]` functions entered only after `is_x86_feature_detected!`
// confirmed the feature at runtime, so the crate needs no global target flags
// and still runs on baseline x86_64.  All kernels produce identical bytes.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Level {
    Scalar,
    Ssse3,
    Avx2,
}

/// The best kernel set for this CPU (detected once, then cached).
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
        let (l, code) = if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("ssse3") {
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

/// Dispatches `$f(args)` to the kernel module for `$l`.
macro_rules! dispatch {
    ($l:expr, $f:ident ( $($a:expr),* )) => {
        match $l {
            // SAFETY: Level::Avx2 / Level::Ssse3 are only produced by
            // `level()` after runtime detection of the feature (or, in
            // tests, by `levels()`, which applies the same detection).
            #[cfg(target_arch = "x86_64")]
            Level::Avx2 => unsafe { avx2::$f($($a),*) },
            #[cfg(target_arch = "x86_64")]
            Level::Ssse3 => unsafe { ssse3::$f($($a),*) },
            _ => scalar::$f($($a),*),
        }
    };
}

//------------------------------------------------------------------------------
// Portable scalar kernels
//
// Shared kernel contract (all kernel modules): `z` is the destination and
// fixes the length; every source is at least `z.len()` long (the public
// functions check this before calling); `off` is the first byte to process;
// multiply kernels see `y >= 2`; multi-source kernels see at least one source
// and `scales.len() >= srcs.len()`.

mod scalar {
    use super::mul_row;

    /// `x[] ^= y[..x.len()]`, 8 bytes at a time.
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

    /// `z[off..] (^)= srcs[0][off..] ^ ...`; `set` overwrites instead.
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

    /// `z[off..] = sum(srcs[j][off..] * scales[j])`.
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

//------------------------------------------------------------------------------
// x86_64 SIMD kernels (SSSE3 128-bit, AVX2 256-bit)

/// 128-bit primitives (SSSE3 `pshufb`).
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
        unsafe { (ld(MM_LO[y as usize].as_ptr()), ld(MM_HI[y as usize].as_ptr())) }
    }
    /// `v * y` given `tables(y)`: two nibble shuffles XORed together.
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

/// 256-bit primitives (AVX2 `vpshufb` on a table broadcast to both lanes).
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
            (_mm256_broadcastsi128_si256(lo), _mm256_broadcastsi128_si256(hi))
        }
    }
    /// `v * y` given `tables(y)`: two nibble shuffles XORed together.
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

/// Builds one SIMD kernel module from a primitive module `$p` (vector width
/// `$p::W`).  Each kernel runs whole vectors (4 at a time, then 1 at a time)
/// and hands the remaining `< W` bytes to the `$tail` kernel module.
///
/// SAFETY contract of every generated function: the CPU supports `$feat`,
/// and the shared kernel contract above holds (it is what keeps every raw
/// pointer access inside its slice).
#[cfg(target_arch = "x86_64")]
macro_rules! simd_kernels {
    ($m:ident, $feat:literal, $p:ident, $tail:ident) => {
        #[allow(unused_unsafe)]
        mod $m {
            use super::$p::*;
            use super::$tail as tail;

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn xor1(z: &mut [u8], x: &[u8]) {
                let n = z.len();
                debug_assert!(x.len() >= n);
                let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe {
                    while i + 4 * W <= n {
                        let a0 = xor(ld(zp.add(i)), ld(xp.add(i)));
                        let a1 = xor(ld(zp.add(i + W)), ld(xp.add(i + W)));
                        let a2 = xor(ld(zp.add(i + 2 * W)), ld(xp.add(i + 2 * W)));
                        let a3 = xor(ld(zp.add(i + 3 * W)), ld(xp.add(i + 3 * W)));
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), xor(ld(zp.add(i)), ld(xp.add(i))));
                        i += W;
                    }
                    tail::xor1(&mut z[i..], &x[i..n]);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn xor2(z: &mut [u8], x: &[u8], y: &[u8]) {
                let n = z.len();
                debug_assert!(x.len() >= n && y.len() >= n);
                let (zp, xp, yp) = (z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
                let mut i = 0;
                unsafe {
                    while i + 2 * W <= n {
                        let a0 = xor(ld(zp.add(i)), xor(ld(xp.add(i)), ld(yp.add(i))));
                        let a1 = xor(
                            ld(zp.add(i + W)),
                            xor(ld(xp.add(i + W)), ld(yp.add(i + W))),
                        );
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        i += 2 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), xor(ld(zp.add(i)), xor(ld(xp.add(i)), ld(yp.add(i)))));
                        i += W;
                    }
                    tail::xor2(&mut z[i..], &x[i..n], &y[i..n]);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn set2(z: &mut [u8], x: &[u8], y: &[u8]) {
                let n = z.len();
                debug_assert!(x.len() >= n && y.len() >= n);
                let (zp, xp, yp) = (z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
                let mut i = 0;
                unsafe {
                    while i + 2 * W <= n {
                        let a0 = xor(ld(xp.add(i)), ld(yp.add(i)));
                        let a1 = xor(ld(xp.add(i + W)), ld(yp.add(i + W)));
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        i += 2 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), xor(ld(xp.add(i)), ld(yp.add(i))));
                        i += W;
                    }
                    tail::set2(&mut z[i..], &x[i..n], &y[i..n]);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn xor_multi(z: &mut [u8], srcs: &[&[u8]], set: bool, off: usize) {
                let n = z.len();
                debug_assert!(!srcs.is_empty() && srcs.iter().all(|s| s.len() >= n));
                let zp = z.as_mut_ptr();
                let (first, rest): (*const u8, &[&[u8]]) = if set {
                    (srcs[0].as_ptr(), &srcs[1..])
                } else {
                    (zp as *const u8, srcs)
                };
                let mut i = off;
                unsafe {
                    while i + 4 * W <= n {
                        let mut a0 = ld(first.add(i));
                        let mut a1 = ld(first.add(i + W));
                        let mut a2 = ld(first.add(i + 2 * W));
                        let mut a3 = ld(first.add(i + 3 * W));
                        for s in rest {
                            let p = s.as_ptr().add(i);
                            a0 = xor(a0, ld(p));
                            a1 = xor(a1, ld(p.add(W)));
                            a2 = xor(a2, ld(p.add(2 * W)));
                            a3 = xor(a3, ld(p.add(3 * W)));
                        }
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        let mut a = ld(first.add(i));
                        for s in rest {
                            a = xor(a, ld(s.as_ptr().add(i)));
                        }
                        st(zp.add(i), a);
                        i += W;
                    }
                    tail::xor_multi(z, srcs, set, i);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn mul(z: &mut [u8], x: &[u8], y: u8) {
                let n = z.len();
                debug_assert!(x.len() >= n);
                let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe {
                    let (lo, hi) = tables(y);
                    let m = mask();
                    while i + 4 * W <= n {
                        let a0 = mulv(ld(xp.add(i)), lo, hi, m);
                        let a1 = mulv(ld(xp.add(i + W)), lo, hi, m);
                        let a2 = mulv(ld(xp.add(i + 2 * W)), lo, hi, m);
                        let a3 = mulv(ld(xp.add(i + 3 * W)), lo, hi, m);
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), mulv(ld(xp.add(i)), lo, hi, m));
                        i += W;
                    }
                    tail::mul(&mut z[i..], &x[i..n], y);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn mul_inplace(z: &mut [u8], y: u8) {
                let n = z.len();
                let zp = z.as_mut_ptr();
                let mut i = 0;
                unsafe {
                    let (lo, hi) = tables(y);
                    let m = mask();
                    while i + 4 * W <= n {
                        let a0 = mulv(ld(zp.add(i)), lo, hi, m);
                        let a1 = mulv(ld(zp.add(i + W)), lo, hi, m);
                        let a2 = mulv(ld(zp.add(i + 2 * W)), lo, hi, m);
                        let a3 = mulv(ld(zp.add(i + 3 * W)), lo, hi, m);
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), mulv(ld(zp.add(i)), lo, hi, m));
                        i += W;
                    }
                    tail::mul_inplace(&mut z[i..], y);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn muladd(z: &mut [u8], x: &[u8], y: u8) {
                let n = z.len();
                debug_assert!(x.len() >= n);
                let (zp, xp) = (z.as_mut_ptr(), x.as_ptr());
                let mut i = 0;
                unsafe {
                    let (lo, hi) = tables(y);
                    let m = mask();
                    while i + 4 * W <= n {
                        let a0 = xor(ld(zp.add(i)), mulv(ld(xp.add(i)), lo, hi, m));
                        let a1 = xor(ld(zp.add(i + W)), mulv(ld(xp.add(i + W)), lo, hi, m));
                        let a2 =
                            xor(ld(zp.add(i + 2 * W)), mulv(ld(xp.add(i + 2 * W)), lo, hi, m));
                        let a3 =
                            xor(ld(zp.add(i + 3 * W)), mulv(ld(xp.add(i + 3 * W)), lo, hi, m));
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        st(zp.add(i), xor(ld(zp.add(i)), mulv(ld(xp.add(i)), lo, hi, m)));
                        i += W;
                    }
                    tail::muladd(&mut z[i..], &x[i..n], y);
                }
            }

            #[inline]
            #[target_feature(enable = $feat)]
            pub unsafe fn mulset_multi(z: &mut [u8], srcs: &[&[u8]], scales: &[u8], off: usize) {
                let n = z.len();
                debug_assert!(scales.len() >= srcs.len() && srcs.iter().all(|s| s.len() >= n));
                let zp = z.as_mut_ptr();
                let mut i = off;
                unsafe {
                    let m = mask();
                    while i + 4 * W <= n {
                        let (mut a0, mut a1, mut a2, mut a3) = (zero(), zero(), zero(), zero());
                        for (s, &c) in srcs.iter().zip(scales) {
                            let p = s.as_ptr().add(i);
                            let (v0, v1, v2, v3) =
                                (ld(p), ld(p.add(W)), ld(p.add(2 * W)), ld(p.add(3 * W)));
                            match c {
                                0 => continue,
                                1 => {
                                    a0 = xor(a0, v0);
                                    a1 = xor(a1, v1);
                                    a2 = xor(a2, v2);
                                    a3 = xor(a3, v3);
                                }
                                _ => {
                                    let (lo, hi) = tables(c);
                                    a0 = xor(a0, mulv(v0, lo, hi, m));
                                    a1 = xor(a1, mulv(v1, lo, hi, m));
                                    a2 = xor(a2, mulv(v2, lo, hi, m));
                                    a3 = xor(a3, mulv(v3, lo, hi, m));
                                }
                            }
                        }
                        st(zp.add(i), a0);
                        st(zp.add(i + W), a1);
                        st(zp.add(i + 2 * W), a2);
                        st(zp.add(i + 3 * W), a3);
                        i += 4 * W;
                    }
                    while i + W <= n {
                        let mut a = zero();
                        for (s, &c) in srcs.iter().zip(scales) {
                            let v = ld(s.as_ptr().add(i));
                            match c {
                                0 => {}
                                1 => a = xor(a, v),
                                _ => {
                                    let (lo, hi) = tables(c);
                                    a = xor(a, mulv(v, lo, hi, m));
                                }
                            }
                        }
                        st(zp.add(i), a);
                        i += W;
                    }
                    tail::mulset_multi(z, srcs, scales, i);
                }
            }
        }
    };
}

#[cfg(target_arch = "x86_64")]
simd_kernels!(ssse3, "ssse3", p128, scalar);
#[cfg(target_arch = "x86_64")]
simd_kernels!(avx2, "avx2", p256, ssse3);

//------------------------------------------------------------------------------
// Bulk XOR

/// `x[] ^= y[]` over `x.len()` bytes.
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

/// `z[] ^= x[] ^ y[]` over `z.len()` bytes.
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

/// `z[] = x[] ^ y[]` over `z.len()` bytes.
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

/// `z[] ^= srcs[0][] ^ ... ^ srcs[k-1][]` over `z.len()` bytes.
/// No sources is a no-op.
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

/// `z[] = srcs[0][] ^ ... ^ srcs[k-1][]` over `z.len()` bytes.
/// One source is a copy; no sources is a no-op (destination untouched).
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

//------------------------------------------------------------------------------
// Bulk multiply

/// `z[] = x[] * y` over `z.len()` bytes.
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

/// `z[] = z[] * y` (the C++ `vz == vx` case).
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

/// `z[] = x[] / y` (multiply by the inverse; y == 0 zeroes, as the C++ does).
pub fn div_mem(z: &mut [u8], x: &[u8], y: u8) {
    mul_mem(z, x, if y == 1 { 1 } else { inv(y) });
}

/// `z[] = z[] / y`.
pub fn div_mem_inplace(z: &mut [u8], y: u8) {
    mul_mem_inplace(z, if y == 1 { 1 } else { inv(y) });
}

/// `z[] ^= x[] * y` over `z.len()` bytes (argument order as the C++).
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

/// `destinations[j][] ^= source[] * scales[j]` over `source.len()` bytes.
/// `scales.len()` must be at least `destinations.len()`.
pub fn muladd_multi_mem(destinations: &mut [&mut [u8]], scales: &[u8], source: &[u8]) {
    muladd_multi_mem_at(level(), destinations, scales, source)
}

/// Source bytes per pass over all destinations, so the source block stays
/// in L1 while every destination consumes it.
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

/// `destination[] = sum(sources[j][] * scales[j])` over `destination.len()`
/// bytes.  No sources is a no-op; all-zero scales zero the destination.
/// `scales.len()` must be at least `sources.len()`.
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

/// Swap `x[]` and `y[..x.len()]`.
pub fn memswap(x: &mut [u8], y: &mut [u8]) {
    let n = x.len();
    if n == 0 {
        return;
    }
    x.swap_with_slice(&mut y[..n]);
}

//------------------------------------------------------------------------------
// C-style aliases (same functions, `gf256_`-prefixed names)

#[allow(unused_imports)]
pub use self::{
    add as gf256_add,
    add2_mem as gf256_add2_mem,
    add_mem as gf256_add_mem,
    add_multi_mem as gf256_add_multi_mem,
    addset_mem as gf256_addset_mem,
    addset_multi_mem as gf256_addset_multi_mem,
    div as gf256_div,
    div_mem as gf256_div_mem,
    div_mem_inplace as gf256_div_mem_inplace,
    inv as gf256_inv,
    memswap as gf256_memswap,
    mul as gf256_mul,
    mul_mem as gf256_mul_mem,
    mul_mem_inplace as gf256_mul_mem_inplace,
    muladd_mem as gf256_muladd_mem,
    muladd_multi_mem as gf256_muladd_multi_mem,
    mulset_multi_mem as gf256_mulset_multi_mem,
    sqr as gf256_sqr,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_mul(mut a: u8, mut b: u8) -> u8 {
        let mut r = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= (POLYNOMIAL & 0xff) as u8;
            }
            b >>= 1;
        }
        r
    }

    #[test]
    fn field_tables() {
        assert_eq!(POLYNOMIAL, 0x14d);
        for x in 0..=255u8 {
            for y in 0..=255u8 {
                assert_eq!(mul(x, y), slow_mul(x, y));
                if y != 0 {
                    assert_eq!(mul(div(x, y), y), x);
                } else {
                    assert_eq!(div(x, y), 0);
                }
            }
            if x != 0 {
                assert_eq!(mul(x, inv(x)), 1);
            }
            assert_eq!(sqr(x), mul(x, x));
        }
        assert_eq!(inv(0), 0);
    }

    #[test]
    fn bulk_ops() {
        let x: Vec<u8> = (0..77u32).map(|i| (i * 37 + 11) as u8).collect();
        let y: Vec<u8> = (0..77u32).map(|i| (i * 91 + 5) as u8).collect();
        for n in 0..77 {
            for c in [0u8, 1, 2, 0x53, 255] {
                let mut z = y.clone();
                muladd_mem(&mut z[..n], c, &x);
                for i in 0..77 {
                    let e = if i < n { y[i] ^ mul(x[i], c) } else { y[i] };
                    assert_eq!(z[i], e);
                }
                let mut z = y.clone();
                mul_mem(&mut z[..n], &x, c);
                let mut w = x.clone();
                mul_mem_inplace(&mut w[..n], c);
                assert_eq!(&z[..n], &w[..n]);
                if c != 0 {
                    div_mem_inplace(&mut w[..n], c);
                    assert_eq!(&w[..n], &x[..n]);
                }
            }
        }
    }

    /// Every kernel level this CPU can run (scalar always first).
    fn levels() -> Vec<Level> {
        let mut v = vec![Level::Scalar];
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("ssse3") {
                v.push(Level::Ssse3);
            }
            if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("ssse3") {
                v.push(Level::Avx2);
            }
        }
        v
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        /// A scale biased towards the special 0 and 1 factors.
        fn scale(&mut self) -> u8 {
            let r = self.next();
            if r & 3 == 0 { (r >> 8 & 1) as u8 } else { (r >> 16) as u8 }
        }
    }

    fn lengths() -> Vec<usize> {
        let mut v: Vec<usize> = (0..=300).collect();
        v.extend(1100..=1200);
        for b in [511usize, 1023, 2047, 4095, 4096, 8191, 65535, 65549 - 13] {
            v.extend(b.saturating_sub(3)..=b + 3);
        }
        v.extend(65549 - 3..=65549);
        v
    }

    /// One random workload run at every level on unaligned slices; the
    /// result of every level must equal the naive byte reference.
    fn check_all(rng: &mut Rng, n: usize, ys: &[u8], k: usize) {
        let pad = 32;
        let oz = (rng.next() % 32) as usize;
        let ox = (rng.next() % 32) as usize;
        let oy = (rng.next() % 32) as usize;
        let z0 = rng.bytes(n + pad + 32);
        let x = rng.bytes(n + pad + 32);
        let yv = rng.bytes(n + pad + 32);
        let srcs_own: Vec<Vec<u8>> = (0..k).map(|_| rng.bytes(n + 32)).collect();
        let sofs: Vec<usize> = (0..k).map(|_| (rng.next() % 32) as usize).collect();
        let srcs: Vec<&[u8]> = srcs_own.iter().zip(&sofs).map(|(s, &o)| &s[o..o + n]).collect();
        let scales: Vec<u8> = (0..k).map(|_| rng.scale()).collect();
        let xs = &x[ox..ox + n];
        let ysl = &yv[oy..oy + n];
        let zr = |z: &[u8]| z[oz..oz + n].to_vec();
        let guard = |a: &[u8], b: &[u8]| {
            assert_eq!(&a[..oz], &b[..oz], "prefix clobbered");
            assert_eq!(&a[oz + n..], &b[oz + n..], "suffix clobbered");
        };
        for &l in &levels() {
            // add / add2 / addset
            let mut z = z0.clone();
            add_mem_at(l, &mut z[oz..oz + n], xs);
            guard(&z, &z0);
            let e: Vec<u8> = (0..n).map(|i| z0[oz + i] ^ xs[i]).collect();
            assert_eq!(zr(&z), e, "add {l:?} n={n}");
            let mut z = z0.clone();
            add2_mem_at(l, &mut z[oz..oz + n], xs, ysl);
            guard(&z, &z0);
            let e: Vec<u8> = (0..n).map(|i| z0[oz + i] ^ xs[i] ^ ysl[i]).collect();
            assert_eq!(zr(&z), e, "add2 {l:?} n={n}");
            let mut z = z0.clone();
            addset_mem_at(l, &mut z[oz..oz + n], xs, ysl);
            guard(&z, &z0);
            let e: Vec<u8> = (0..n).map(|i| xs[i] ^ ysl[i]).collect();
            assert_eq!(zr(&z), e, "addset {l:?} n={n}");
            for &y in ys {
                let mut z = z0.clone();
                mul_mem_at(l, &mut z[oz..oz + n], xs, y);
                guard(&z, &z0);
                let e: Vec<u8> = (0..n).map(|i| slow_mul(xs[i], y)).collect();
                assert_eq!(zr(&z), e, "mul {l:?} n={n} y={y}");
                let mut z = z0.clone();
                mul_mem_inplace_at(l, &mut z[oz..oz + n], y);
                guard(&z, &z0);
                let e: Vec<u8> = (0..n).map(|i| slow_mul(z0[oz + i], y)).collect();
                assert_eq!(zr(&z), e, "mul_inplace {l:?} n={n} y={y}");
                let mut z = z0.clone();
                muladd_mem_at(l, &mut z[oz..oz + n], y, xs);
                guard(&z, &z0);
                let e: Vec<u8> = (0..n).map(|i| z0[oz + i] ^ slow_mul(xs[i], y)).collect();
                assert_eq!(zr(&z), e, "muladd {l:?} n={n} y={y}");
            }
            // multi-source
            let mut z = z0.clone();
            add_multi_mem_at(l, &mut z[oz..oz + n], &srcs);
            guard(&z, &z0);
            let e: Vec<u8> =
                (0..n).map(|i| srcs.iter().fold(z0[oz + i], |a, s| a ^ s[i])).collect();
            assert_eq!(zr(&z), e, "add_multi {l:?} n={n} k={k}");
            let mut z = z0.clone();
            addset_multi_mem_at(l, &mut z[oz..oz + n], &srcs);
            guard(&z, &z0);
            let e: Vec<u8> = if k == 0 {
                zr(&z0)
            } else {
                (0..n).map(|i| srcs.iter().fold(0, |a, s| a ^ s[i])).collect()
            };
            assert_eq!(zr(&z), e, "addset_multi {l:?} n={n} k={k}");
            let mut z = z0.clone();
            mulset_multi_mem_at(l, &mut z[oz..oz + n], &srcs, &scales);
            guard(&z, &z0);
            let e: Vec<u8> = if k == 0 {
                zr(&z0)
            } else {
                (0..n)
                    .map(|i| srcs.iter().zip(&scales).fold(0, |a, (s, &c)| a ^ slow_mul(s[i], c)))
                    .collect()
            };
            assert_eq!(zr(&z), e, "mulset_multi {l:?} n={n} k={k}");
            // muladd_multi: k destinations, longer than the source
            let mut dst_own: Vec<Vec<u8>> = srcs_own.clone();
            let before = dst_own.clone();
            {
                let mut dsts: Vec<&mut [u8]> =
                    dst_own.iter_mut().zip(&sofs).map(|(d, &o)| &mut d[o..]).collect();
                muladd_multi_mem_at(l, &mut dsts, &scales, xs);
            }
            for j in 0..k {
                let o = sofs[j];
                for i in 0..before[j].len() {
                    let e = if i >= o && i < o + n {
                        before[j][i] ^ slow_mul(xs[i - o], scales[j])
                    } else {
                        before[j][i]
                    };
                    assert_eq!(dst_own[j][i], e, "muladd_multi {l:?} n={n} k={k} j={j}");
                }
            }
        }
    }

    #[test]
    fn simd_levels_match_reference_all_lengths() {
        let mut rng = Rng(0x5eed);
        for n in lengths() {
            let ys = [0u8, 1, rng.next() as u8, rng.next() as u8 | 2];
            let k = (rng.next() % 41) as usize;
            check_all(&mut rng, n, &ys, k);
        }
    }

    #[test]
    fn simd_levels_all_coefficients() {
        let mut rng = Rng(0xc0ef);
        let ys: Vec<u8> = (0..=255).collect();
        for n in [0usize, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 1136, 1160] {
            check_all(&mut rng, n, &ys, 3);
        }
    }

    #[test]
    fn simd_levels_source_counts() {
        let mut rng = Rng(0x50c);
        for k in 0..=40 {
            for n in [0usize, 7, 64, 129, 1136, 1160, 4099] {
                check_all(&mut rng, n, &[0, 1, 0x53], k);
            }
        }
        // Large payload, every source count class.
        for k in [0usize, 1, 2, 3, 18, 40] {
            check_all(&mut rng, 65549, &[0, 1, 0xa7], k);
        }
    }

    #[test]
    fn nibble_tables_match_mul() {
        for y in 0..256usize {
            for x in 0..256usize {
                let p = MM_LO[y][x & 15] ^ MM_HI[y][x >> 4];
                assert_eq!(p, mul(x as u8, y as u8));
            }
        }
    }

    #[test]
    #[should_panic]
    fn short_source_panics() {
        let mut z = [0u8; 40];
        let a = [1u8; 40];
        let b = [2u8; 39];
        mulset_multi_mem(&mut z, &[&a, &b], &[3, 4]);
    }
}
