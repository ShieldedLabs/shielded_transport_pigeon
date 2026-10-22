//! RFC 7748 X25519 Montgomery ladder over the unmodified arithmetic from
//! curve25519-dalek 4.1.3 (see field25519.rs and LICENSE-curve25519-dalek).
//! The ladder follows RFC 7748 section 5; all scalar bits use masked swaps.

use super::field25519::FieldElement51 as F;

pub(crate) fn clamp(mut secret: [u8; 32]) -> [u8; 32] {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

#[inline(never)]
fn swap(a: &mut F, b: &mut F, choice: u8) {
    // An optimization barrier keeps the choice opaque to the optimizer,
    // following the same principle as subtle::Choice's black_box barrier.
    let mask = 0u64.wrapping_sub(core::hint::black_box(choice as u64));
    for (a, b) in a.0.iter_mut().zip(b.0.iter_mut()) {
        let t = mask & (*a ^ *b);
        *a ^= t;
        *b ^= t;
    }
}

pub(crate) fn x25519(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let mut scalar = clamp(*secret);
    let x1 = F::from_bytes(public);
    let mut x2 = F::ONE;
    let mut z2 = F::ZERO;
    let mut x3 = x1;
    let mut z3 = F::ONE;
    let mut previous = 0;
    for t in (0..255).rev() {
        let bit = (scalar[t / 8] >> (t & 7)) & 1;
        swap(&mut x2, &mut x3, previous ^ bit);
        swap(&mut z2, &mut z3, previous ^ bit);
        previous = bit;
        let a = &x2 + &z2;
        let aa = a.square();
        let b = &x2 - &z2;
        let bb = b.square();
        let e = &aa - &bb;
        let c = &x3 + &z3;
        let d = &x3 - &z3;
        let da = &d * &a;
        let cb = &c * &b;
        x3 = (&da + &cb).square();
        z3 = &x1 * &(&da - &cb).square();
        x2 = &aa * &bb;
        z2 = &e * &(&aa + &(&F::from_limbs([121665, 0, 0, 0, 0]) * &e));
    }
    swap(&mut x2, &mut x3, previous);
    swap(&mut z2, &mut z3, previous);
    let result = (&x2 * &z2.invert()).as_bytes();
    super::wipe(&mut scalar);
    for f in [&mut x2, &mut z2, &mut x3, &mut z3] {
        for word in &mut f.0 {
            unsafe { core::ptr::write_volatile(word, 0) };
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    result
}

pub(crate) fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(secret, &base)
}
