//! Small random-data utilities for diagnostics, examples and reproducible tests.
//! Cryptographic keys obtain entropy directly from the operating system; this
//! module never substitutes a clock, counter or deterministic seed for entropy.

pub use crate::crypto::rng::ChaCha20Rng;

/// Construct an independently OS-seeded ChaCha20 generator.
pub fn rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    crate::platform::fill_random(&mut seed).expect("operating-system entropy unavailable");
    let rng = ChaCha20Rng::from_seed(seed);
    seed.fill(0);
    rng
}

pub trait RngCore {
    fn next_u32(&mut self) -> u32;
    fn next_u64(&mut self) -> u64;
    fn fill_bytes(&mut self, out: &mut [u8]);
}

impl RngCore for ChaCha20Rng {
    fn next_u32(&mut self) -> u32 { ChaCha20Rng::next_u32(self) }
    fn next_u64(&mut self) -> u64 { ChaCha20Rng::next_u64(self) }
    fn fill_bytes(&mut self, out: &mut [u8]) { ChaCha20Rng::fill_bytes(self, out) }
}

pub trait SeedableRng {
    fn from_seed(seed: [u8; 32]) -> Self;
    fn seed_from_u64(seed: u64) -> Self;
}

impl SeedableRng for ChaCha20Rng {
    fn from_seed(seed: [u8; 32]) -> Self { ChaCha20Rng::from_seed(seed) }
    fn seed_from_u64(seed: u64) -> Self { ChaCha20Rng::seed_from_u64(seed) }
}

pub trait RandomValue {
    fn sample<R: RngCore + ?Sized>(rng: &mut R) -> Self;
}

impl RandomValue for f64 {
    fn sample<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        // Identical 53-bit [0, 1) mapping to rand's StandardUniform<f64>.
        (rng.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }
}

/// Unbiased bounded selection, including the entire u64 domain.
fn below<R: RngCore + ?Sized>(rng: &mut R, bound: u64) -> u64 {
    if bound == 0 { return rng.next_u64(); }
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let product = (rng.next_u64() as u128) * (bound as u128);
        if product as u64 >= threshold { return (product >> 64) as u64; }
    }
}

pub trait Rng: RngCore {
    fn random<T: RandomValue>(&mut self) -> T { T::sample(self) }
    fn random_range(&mut self, range: std::ops::RangeInclusive<usize>) -> usize {
        let (lo, hi) = range.into_inner();
        assert!(lo <= hi, "empty random range");
        // usize is at most 64 bits on all supported targets. A wrapping zero
        // bound represents the full 64-bit domain, not an empty range.
        let bound = (hi as u64).wrapping_sub(lo as u64).wrapping_add(1);
        lo + below(self, bound) as usize
    }
    fn fill(&mut self, out: &mut [u8]) { self.fill_bytes(out); }
}
impl<R: RngCore + ?Sized> Rng for R {}

pub mod seq {
    use super::{RngCore, below};

    pub trait SliceRandom {
        fn shuffle<R: RngCore + ?Sized>(&mut self, rng: &mut R);
    }
    impl<T> SliceRandom for [T] {
        fn shuffle<R: RngCore + ?Sized>(&mut self, rng: &mut R) {
            // Fisher-Yates: each of n! permutations has equal probability.
            for i in (1..self.len()).rev() {
                let j = below(rng, i as u64 + 1) as usize;
                self.swap(i, j);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::seq::SliceRandom;

    #[test]
    fn bounded_values_cover_edges_without_overflow() {
        let mut rng = ChaCha20Rng::seed_from_u64(123);
        for _ in 0..10000 {
            assert_eq!(rng.random_range(9..=9), 9);
            assert!((100..=4 * 1024 * 1024).contains(&rng.random_range(100..=4 * 1024 * 1024)));
            let _: usize = rng.random_range(0..=usize::MAX);
            assert!((usize::MAX - 9..=usize::MAX).contains(&rng.random_range(usize::MAX - 9..=usize::MAX)));
            assert!((0.0..1.0).contains(&rng.random::<f64>()));
        }
    }

    #[test]
    fn seeded_shuffles_are_repeatable_permutations() {
        let mut a = ChaCha20Rng::seed_from_u64(7);
        let mut b = a.clone();
        for n in 0..128 {
            let mut x: Vec<_> = (0..n).collect();
            let mut y = x.clone();
            x.shuffle(&mut a); y.shuffle(&mut b);
            assert_eq!(x, y);
            x.sort_unstable();
            assert_eq!(x, (0..n).collect::<Vec<_>>());
        }
    }

    #[test]
    fn bounded_rejection_retries_and_full_domain() {
        struct Values { words: std::collections::VecDeque<u64> }
        impl RngCore for Values {
            fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
            fn next_u64(&mut self) -> u64 { self.words.pop_front().unwrap() }
            fn fill_bytes(&mut self, _: &mut [u8]) { unreachable!() }
        }
        let mut values = Values { words: [0, u64::MAX, 1234].into() };
        assert_eq!(below(&mut values, 10), 9); // zero product is rejected
        assert_eq!(below(&mut values, 0), 1234);
    }
}
