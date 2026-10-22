//! ChaCha20 portable core, adapted from RustCrypto chacha20 0.9.1
//! (`src/backends/soft.rs`). Generic cipher trait glue was removed; the
//! round function is unchanged.
//! Copyright (c) 2019-2023 The RustCrypto Project Developers.
//! MIT OR Apache-2.0: see LICENSE-chacha20-MIT and LICENSE-RustCrypto-APACHE.

/// Original ChaCha layout: 64-bit block counter and 64-bit stream identifier.
pub(crate) fn block(key: &[u8; 32], counter: u64, stream: u64) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (word, bytes) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = stream as u32;
    state[15] = (stream >> 32) as u32;
    let mut res = state;
    for _ in 0..10 {
        quarter_round(0, 4, 8, 12, &mut res);
        quarter_round(1, 5, 9, 13, &mut res);
        quarter_round(2, 6, 10, 14, &mut res);
        quarter_round(3, 7, 11, 15, &mut res);
        quarter_round(0, 5, 10, 15, &mut res);
        quarter_round(1, 6, 11, 12, &mut res);
        quarter_round(2, 7, 8, 13, &mut res);
        quarter_round(3, 4, 9, 14, &mut res);
    }
    let mut out = [0u8; 64];
    for (i, (s1, s0)) in res.iter().zip(state.iter()).enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&s1.wrapping_add(*s0).to_le_bytes());
    }
    for word in state.iter_mut().chain(res.iter_mut()) {
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    out
}

#[inline(always)]
fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}
