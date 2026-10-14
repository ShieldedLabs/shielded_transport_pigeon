//! Minimal safe wrapper over the vendored Wirehair fountain code (third_party/wirehair,
//! classic C API, built by build.rs).
//!
//! A message of `len` bytes is split into K = ceil(len / block_bytes) source blocks. The
//! encoder can produce any block id: ids 0..K-1 are the message itself ("systematic": block i
//! is `message[i*block_bytes..]`, the last one short), ids >= K are repair blocks of exactly
//! `block_bytes`. A decoder recovers the message from any ~K distinct ids (K + 0.02 on
//! average). Wirehair accepts 2 <= K <= 64000.
//!
//! Cost (x86_64, -O2, blocks of 1160 B): creating an encoder is the expensive step, about
//! 4 us per block (K=40000: ~155 ms, K=1000: 1.5 ms, K=256: 0.36 ms); after that each block costs ~1 us. Decoding costs about
//! 4 us per received block, plus a final solve of roughly the same size as encoder creation,
//! which lands inside the `add` call that completes the message (K=40000: ~154 ms of a
//! ~307 ms total; `recover` then copies out in ~12 ms).

use std::sync::Arc;

pub const MIN_BLOCKS: usize = 2;
pub const MAX_BLOCKS: usize = 64000;

#[allow(non_camel_case_types)]
type WirehairCodec = *mut std::ffi::c_void;
type WirehairResult = std::ffi::c_int;

const WIREHAIR_SUCCESS: WirehairResult = 0;
const WIREHAIR_NEED_MORE: WirehairResult = 1;
const WIREHAIR_VERSION: std::ffi::c_int = 2;

unsafe extern "C" {
    fn wirehair_init_(expected_version: std::ffi::c_int) -> WirehairResult;
    fn wirehair_encoder_create(reuse_opt: WirehairCodec, message: *const std::ffi::c_void, message_bytes: u64, block_bytes: u32) -> WirehairCodec;
    fn wirehair_encode(codec: WirehairCodec, block_id: std::ffi::c_uint, block_data_out: *mut std::ffi::c_void, out_bytes: u32, data_bytes_out: *mut u32) -> WirehairResult;
    fn wirehair_decoder_create(reuse_opt: WirehairCodec, message_bytes: u64, block_bytes: u32) -> WirehairCodec;
    fn wirehair_decode(codec: WirehairCodec, block_id: std::ffi::c_uint, block_data: *const std::ffi::c_void, data_bytes: u32) -> WirehairResult;
    fn wirehair_recover(codec: WirehairCodec, message_out: *mut std::ffi::c_void, message_bytes: u64) -> WirehairResult;
    fn wirehair_free(codec: WirehairCodec);
}

/// Initializes Wirehair once per process. False if the platform is unsupported.
pub fn init() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    #[allow(unsafe_code)]
    *OK.get_or_init(|| unsafe { wirehair_init_(WIREHAIR_VERSION) } == WIREHAIR_SUCCESS)
}

/// Number of source blocks for a message, or None if Wirehair cannot code it
/// (K outside 2..=64000, or sizes that do not fit its u32/u64 parameters).
pub fn block_count(message_len: usize, block_bytes: usize) -> Option<usize> {
    if block_bytes == 0 || block_bytes > u32::MAX as usize { return None; }
    let k = message_len.div_ceil(block_bytes);
    (MIN_BLOCKS..=MAX_BLOCKS).contains(&k).then_some(k)
}

/// Length of source block `id` (0..K-1) of a message; repair blocks are always `block_bytes`.
pub fn block_len(message_len: usize, block_bytes: usize, id: u32) -> usize {
    let start = id as usize * block_bytes;
    if start >= message_len { block_bytes } else { (message_len - start).min(block_bytes) }
}

pub struct Encoder {
    codec: WirehairCodec,
    // Wirehair borrows the message: it must stay alive and unmoved until the codec is freed.
    // The Arc keeps the heap buffer alive; the Vec is never mutated.
    message: Arc<Vec<u8>>,
    block_bytes: usize,
}

// The codec is only used through &mut self, and Wirehair codecs have no thread affinity.
#[allow(unsafe_code)]
unsafe impl Send for Encoder {}

/// Builds an encoder for `message` (borrowed through the Arc, not copied). This is the
/// expensive step (~4 us per block); see the module docs.
pub fn encode(message: Arc<Vec<u8>>, block_bytes: usize) -> Option<Encoder> {
    block_count(message.len(), block_bytes)?;
    if !init() { return None; }
    #[allow(unsafe_code)]
    let codec = unsafe { wirehair_encoder_create(std::ptr::null_mut(), message.as_ptr() as *const _, message.len() as u64, block_bytes as u32) };
    if codec.is_null() { return None; }
    Some(Encoder { codec, message, block_bytes })
}

impl Encoder {
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn message(&self) -> &Arc<Vec<u8>> { &self.message }

    /// Writes block `id` into `out` (at least block_bytes long); returns its length.
    pub fn block_into(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        if out.len() < self.block_bytes { return None; }
        let mut written = 0u32;
        #[allow(unsafe_code)]
        let r = unsafe { wirehair_encode(self.codec, id, out.as_mut_ptr() as *mut _, out.len().min(u32::MAX as usize) as u32, &mut written) };
        (r == WIREHAIR_SUCCESS && written as usize <= self.block_bytes).then_some(written as usize)
    }

    pub fn block(&mut self, id: u32) -> Option<Vec<u8>> {
        let mut v = vec![0u8; self.block_bytes];
        let n = self.block_into(id, &mut v)?;
        v.truncate(n);
        Some(v)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe { wirehair_free(self.codec) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStatus { NeedMore, Done }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// This block was rejected (wrong length, or conflicts with an earlier block of the same
    /// id); the decoder is unchanged and can take more blocks.
    BadBlock,
    /// The decoder cannot continue (Wirehair error code).
    Failed(i32),
}

pub struct Decoder {
    codec: WirehairCodec,
    message_len: usize,
    block_bytes: usize,
    done: bool,
}

#[allow(unsafe_code)]
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new(message_len: usize, block_bytes: usize) -> Option<Decoder> {
        block_count(message_len, block_bytes)?;
        if !init() { return None; }
        #[allow(unsafe_code)]
        let codec = unsafe { wirehair_decoder_create(std::ptr::null_mut(), message_len as u64, block_bytes as u32) };
        if codec.is_null() { return None; }
        Some(Decoder { codec, message_len, block_bytes, done: false })
    }

    pub fn message_len(&self) -> usize { self.message_len }
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn is_done(&self) -> bool { self.done }

    /// Feeds one received block. Done means `recover` will succeed; blocks after that are ignored.
    pub fn add(&mut self, id: u32, data: &[u8]) -> Result<DecodeStatus, DecodeError> {
        if self.done { return Ok(DecodeStatus::Done); }
        if data.is_empty() || data.len() > self.block_bytes { return Err(DecodeError::BadBlock); }
        #[allow(unsafe_code)]
        let r = unsafe { wirehair_decode(self.codec, id, data.as_ptr() as *const _, data.len() as u32) };
        match r {
            WIREHAIR_SUCCESS => { self.done = true; Ok(DecodeStatus::Done) }
            WIREHAIR_NEED_MORE => Ok(DecodeStatus::NeedMore),
            2 => Err(DecodeError::BadBlock), // Wirehair_InvalidInput
            e => Err(DecodeError::Failed(e)),
        }
    }

    /// The decoded message, once `add` has returned Done.
    pub fn recover(&mut self) -> Option<Vec<u8>> {
        if !self.done { return None; }
        let mut out = vec![0u8; self.message_len];
        #[allow(unsafe_code)]
        let r = unsafe { wirehair_recover(self.codec, out.as_mut_ptr() as *mut _, self.message_len as u64) };
        (r == WIREHAIR_SUCCESS).then_some(out)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe { wirehair_free(self.codec) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand::seq::SliceRandom;

    fn message(len: usize, seed: u64) -> Arc<Vec<u8>> {
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let mut v = vec![0u8; len];
        r.fill_bytes(&mut v);
        Arc::new(v)
    }

    /// Encodes, feeds the decoder the ids in `ids` until Done, and checks the result.
    /// Returns how many blocks were needed.
    fn round_trip(len: usize, bb: usize, ids: &[u32], seed: u64) -> usize {
        let m = message(len, seed);
        let k = block_count(len, bb).unwrap();
        let mut enc = encode(m.clone(), bb).unwrap();
        // Systematic blocks are the message slices.
        for id in [0u32, (k - 1) as u32] {
            let b = enc.block(id).unwrap();
            let s = id as usize * bb;
            assert_eq!(&b[..], &m[s..(s + bb).min(len)]);
            assert_eq!(b.len(), block_len(len, bb, id));
        }
        let mut dec = Decoder::new(len, bb).unwrap();
        let mut used = 0;
        for &id in ids {
            let b = enc.block(id).unwrap();
            used += 1;
            if dec.add(id, &b).unwrap() == DecodeStatus::Done {
                assert_eq!(dec.recover().unwrap(), *m);
                return used;
            }
        }
        panic!("len {len} bb {bb}: not decoded after {used} blocks (K={k})");
    }

    #[test]
    fn round_trip_no_loss() {
        for (len, bb) in [(2 * 1200, 1200), (1200 + 1, 1200), (1000 * 1200 - 17, 1200), (40000 * 1200, 1200)] {
            let k = block_count(len, bb).unwrap();
            let ids: Vec<u32> = (0..k as u32).collect();
            assert_eq!(round_trip(len, bb, &ids, len as u64), k);
        }
    }

    #[test]
    fn round_trip_with_loss() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        for (len, bb, loss) in [(2 * 1200, 1200, 0.3), (1000 * 1200 - 5, 1200, 0.05), (40000 * 1200, 1200, 0.02)] {
            let k = block_count(len, bb).unwrap();
            // Send ids 0..2K in order, each lost with probability `loss`.
            let ids: Vec<u32> = (0..2 * k as u32 + 8).filter(|_| rng.random::<f64>() >= loss).collect();
            let used = round_trip(len, bb, &ids, 3 + len as u64);
            assert!(used >= k && used <= k + 8, "len {len}: needed {used} blocks for K={k}");
        }
    }

    #[test]
    fn random_subset_k_plus_small() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let mut overheads = Vec::new();
        for trial in 0..20 {
            let (len, bb) = if trial % 2 == 0 { (1000 * 1200, 1200) } else { (97 * 333 + 5, 333) };
            let k = block_count(len, bb).unwrap();
            // A random subset of K+3 ids drawn from 0..3K: a mix of source and repair blocks.
            let mut all: Vec<u32> = (0..3 * k as u32).collect();
            all.shuffle(&mut rng);
            all.truncate(k + 3);
            overheads.push(round_trip(len, bb, &all, trial) - k);
        }
        // Wirehair needs K + ~0.02 blocks on average: K+3 must almost always be enough
        // (round_trip panics if it is not).
        assert!(overheads.iter().all(|&o| o <= 3));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(block_count(1200, 1200).is_none()); // K = 1
        assert!(block_count(64001 * 10, 10).is_none());
        assert!(Decoder::new(100, 0).is_none());
        let mut d = Decoder::new(2400, 1200).unwrap();
        assert_eq!(d.add(5, &[0u8; 1201]), Err(DecodeError::BadBlock));
        assert!(d.recover().is_none());
    }
}
