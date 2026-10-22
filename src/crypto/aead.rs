//! Noise's ChaChaPoly AEAD framing (RFC 8439 section 2.8).
//! The ChaCha20 and Poly1305 arithmetic lives in the upstream-derived modules.

use super::{chacha20, noise::Error, poly1305, wipe};

fn tag(key: &[u8; 32], nonce: u64, ad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut first_block = chacha20::block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&first_block[..32]);
    let mut mac = poly1305::State::new(&poly_key);
    wipe(&mut first_block);
    wipe(&mut poly_key);
    for bytes in [ad, ciphertext] {
        for part in bytes.chunks(16) {
            let mut block = [0u8; 16];
            block[..part.len()].copy_from_slice(part);
            // AEAD padding makes every Poly1305 input block a full block,
            // including the implicit 2^128 coefficient.
            mac.compute_block(&block, false);
        }
    }
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.compute_block(&lengths, false);
    mac.finalize_mut()
}

fn xor(key: &[u8; 32], nonce: u64, input: &[u8], out: &mut [u8]) {
    for (i, chunk) in input.chunks(64).enumerate() {
        let mut block = chacha20::block(key, (i + 1) as u64, nonce);
        for (j, byte) in chunk.iter().enumerate() {
            out[64 * i + j] = byte ^ block[j];
        }
        wipe(&mut block);
    }
}

pub(super) fn seal(
    key: &[u8; 32],
    nonce: u64,
    ad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = plaintext.len().checked_add(16).ok_or(Error::Input)?;
    if out.len() < n {
        return Err(Error::Input);
    }
    xor(key, nonce, plaintext, out);
    let mac = tag(key, nonce, ad, &out[..plaintext.len()]);
    out[plaintext.len()..n].copy_from_slice(&mac);
    Ok(n)
}

pub(super) fn open(
    key: &[u8; 32],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = ciphertext.len().checked_sub(16).ok_or(Error::Decrypt)?;
    if out.len() < n {
        return Err(Error::Decrypt);
    }
    let expected = tag(key, nonce, ad, &ciphertext[..n]);
    // Authenticate before writing any plaintext. The fixed-size comparison
    // accumulates every byte and uses an optimizer barrier, never early-exits.
    if !super::constant_time_eq(&expected, &ciphertext[n..]) {
        return Err(Error::Decrypt);
    }
    xor(key, nonce, &ciphertext[..n], out);
    Ok(n)
}

pub(super) fn rekey(key: &mut [u8; 32]) {
    // Noise section 4.2: Encrypt(k, 2^64-1, empty, zeros(32))[0..32].
    // Only the ChaCha stream is needed; the discarded authentication tag
    // cannot affect the first 32 ciphertext bytes.
    let mut stream = chacha20::block(key, 1, u64::MAX);
    wipe(key);
    key.copy_from_slice(&stream[..32]);
    wipe(&mut stream);
}
