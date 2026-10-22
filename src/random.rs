pub use crate::crypto::rng::ChaCha20Rng;
pub fn rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32]; crate::platform::fill_random(&mut seed).expect("operating-system entropy unavailable");
    let rng = ChaCha20Rng::from_seed(seed); seed.fill(0);
    rng }
pub trait RngCore {
    fn next_u32(&mut self) -> u32; fn next_u64(&mut self) -> u64;
    fn fill_bytes(&mut self, out: &mut [u8]); }
impl RngCore for ChaCha20Rng {
    fn next_u32(&mut self) -> u32 { ChaCha20Rng::next_u32(self) }
    fn next_u64(&mut self) -> u64 { ChaCha20Rng::next_u64(self) }
    fn fill_bytes(&mut self, out: &mut [u8]) { ChaCha20Rng::fill_bytes(self, out) } }
pub trait SeedableRng { fn from_seed(seed: [u8; 32]) -> Self; fn seed_from_u64(seed: u64) -> Self; }
impl SeedableRng for ChaCha20Rng {
    fn from_seed(seed: [u8; 32]) -> Self { ChaCha20Rng::from_seed(seed) }
    fn seed_from_u64(seed: u64) -> Self { ChaCha20Rng::seed_from_u64(seed) } }
pub trait RandomValue { fn sample<R: RngCore + ?Sized>(rng: &mut R) -> Self; }
impl RandomValue for f64 {
    fn sample<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        (rng.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64)) } }
fn below<R: RngCore + ?Sized>(rng: &mut R, bound: u64) -> u64 {
    if bound == 0 { return rng.next_u64(); }
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let product = (rng.next_u64() as u128) * (bound as u128);
        if product as u64 >= threshold { return (product >> 64) as u64; } } }
pub trait Rng: RngCore {
    fn random<T: RandomValue>(&mut self) -> T { T::sample(self) }
    fn random_range(&mut self, range: std::ops::RangeInclusive<usize>) -> usize {
        let (lo, hi) = range.into_inner(); assert!(lo <= hi, "empty random range");
        let bound = (hi as u64).wrapping_sub(lo as u64).wrapping_add(1);
        lo + below(self, bound) as usize }
    fn fill(&mut self, out: &mut [u8]) { self.fill_bytes(out); } }
impl<R: RngCore + ?Sized> Rng for R {}
pub mod seq {
    use super::{RngCore, below};
    pub trait SliceRandom { fn shuffle<R: RngCore + ?Sized>(&mut self, rng: &mut R); }
    impl<T> SliceRandom for [T] {
        fn shuffle<R: RngCore + ?Sized>(&mut self, rng: &mut R) {
            for i in (1..self.len()).rev() { let j = below(rng, i as u64 + 1) as usize; self.swap(i, j); } } } }
