//! Private, dependency-free cryptography used by STP's frozen wire protocol.
//! See the upstream notices alongside the minimally adapted arithmetic.
//! No secret-bearing type logs its contents. Long-lived secrets and explicit
//! scratch buffers are wiped on drop/use; compiler/register copies cannot be
//! guaranteed erased by portable Rust and are not claimed to be.

mod aead;
mod blake2b;
mod blake2s;
pub(crate) mod blake3;
pub(crate) mod chacha20;
mod field25519;
pub mod noise;
mod poly1305;
pub(crate) mod rng;
mod x25519;

#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    } // lengths are public
    let mut difference = 0u8;
    for (a, b) in a.iter().zip(b) {
        difference |= a ^ b;
    }
    core::hint::black_box(difference) == 0
}
