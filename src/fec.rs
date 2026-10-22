//! Safe wrapper over the in-crate Rust Wirehair fountain code.
//! Equations and repair symbols match the previously vendored classic C++ codec.
//!
//! A message of `len` bytes is split into K = ceil(len / block_bytes) source blocks. The
//! encoder can produce any block id: ids 0..K-1 are the message itself ("systematic": block i
//! is `message[i*block_bytes..]`, the last one short), ids >= K are repair blocks of exactly
//! `block_bytes`. A decoder recovers the message from any ~K distinct ids (K + 0.02 on
//! average). Wirehair accepts 2 <= K <= 64000.
//!
use std::sync::Arc;

pub const MIN_BLOCKS: usize = 2;
pub const MAX_BLOCKS: usize = 64000;

/// Hard codec-arena cap, including input, workspace, dedup and GE matrix.
/// Per-symbol charge matters even when a malicious peer chooses one-byte blocks.
/// Wirehair refuses a solve/regrow exceeding this cap rather than overallocating.
pub fn decoder_memory_limit(len: usize, block_bytes: usize) -> Option<usize> {
    let k = block_count(len, block_bytes)?;
    len.checked_mul(2)?.checked_add(k.checked_mul(256)?)?.checked_add(1 << 20)
}

/// Both ingress levels include queue slots as well as payload allocations.
pub fn ingress_slots(bytes: usize, block_bytes: usize) -> usize {
    // Include the channel's per-slot stamp/alignment and allocator metadata too.
    // The current std array channel uses less; 128 bytes leaves conservative slack.
    (bytes / (block_bytes + std::mem::size_of::<(u32, Vec<u8>)>() + 128)).max(1)
}

pub fn receive_memory_charge(layout: MessageLayout, worker: bool, ingress_bytes: usize) -> Option<usize> {
    let mut bytes = layout.len;
    for group in 0..layout.groups {
        let (_, len) = layout.group_bytes(group);
        bytes = bytes.checked_add(decoder_memory_limit(len, layout.block_bytes)?)?.checked_add(4096)?;
    }
    if worker {
        // Outer queue + grouped lane queues; include currently-handled blocks and thread bookkeeping.
        bytes = bytes.checked_add(ingress_bytes.checked_mul(2)?)?.checked_add(256 << 10)?;
    }
    Some(bytes)
}

use crate::wirehair::{self, WirehairResult};

/// Initializes the in-crate codec (its tables are compile-time constants).
pub fn init() -> bool { wirehair::init() == WirehairResult::Success }

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
    codec: Box<wirehair::Codec>,
    // Both this wrapper and the codec retain the immutable source allocation.
    message: Arc<Vec<u8>>,
    block_bytes: usize,
}

/// Builds an encoder for `message` (borrowed through the Arc, not copied).
pub fn encode(message: Arc<Vec<u8>>, block_bytes: usize) -> Option<Encoder> {
    let len = message.len();
    encode_range(message, 0, len, block_bytes)
}

fn encode_range(message: Arc<Vec<u8>>, start: usize, len: usize, block_bytes: usize) -> Option<Encoder> {
    block_count(len, block_bytes)?;
    if start.checked_add(len)? > message.len() || !init() { return None; }
    let codec = Box::new(wirehair::encoder_create(message.clone(), start, len, block_bytes as u32).ok()?);
    Some(Encoder { codec, message, block_bytes })
}

impl Encoder {
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn message(&self) -> &Arc<Vec<u8>> { &self.message }

    /// Writes block `id` into `out` (at least block_bytes long); returns its length.
    pub fn block_into(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        if out.len() < self.block_bytes { return None; }
        let cap = out.len().min(u32::MAX as usize);
        let written = self.codec.wirehair_encode(id, &mut out[..cap]).ok()? as usize;
        (written <= self.block_bytes).then_some(written)
    }

    pub fn block(&mut self, id: u32) -> Option<Vec<u8>> {
        let mut v = vec![0u8; self.block_bytes];
        let n = self.block_into(id, &mut v)?;
        v.truncate(n);
        Some(v)
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
    codec: Box<wirehair::Codec>,
    message_len: usize,
    block_bytes: usize,
    done: bool,
}

impl Decoder {
    pub fn new(message_len: usize, block_bytes: usize) -> Option<Decoder> {
        block_count(message_len, block_bytes)?;
        if !init() { return None; }
        let codec = Box::new(wirehair::decoder_create_limited(message_len as u64, block_bytes as u32,
            decoder_memory_limit(message_len, block_bytes)? as u64).ok()?);
        Some(Decoder { codec, message_len, block_bytes, done: false })
    }

    pub fn message_len(&self) -> usize { self.message_len }
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn is_done(&self) -> bool { self.done }

    /// Feeds one received block. Done means `recover` will succeed; blocks after that are ignored.
    pub fn add(&mut self, id: u32, data: &[u8]) -> Result<DecodeStatus, DecodeError> {
        if self.done { return Ok(DecodeStatus::Done); }
        if data.is_empty() || data.len() > self.block_bytes { return Err(DecodeError::BadBlock); }
        match self.codec.wirehair_decode(id, data) {
            WirehairResult::Success => { self.done = true; Ok(DecodeStatus::Done) }
            WirehairResult::NeedMore => Ok(DecodeStatus::NeedMore),
            WirehairResult::InvalidInput => Err(DecodeError::BadBlock),
            e => Err(DecodeError::Failed(e.code())),
        }
    }

    /// The decoded message, once `add` has returned Done.
    pub fn recover(&mut self) -> Option<Vec<u8>> {
        let mut out = vec![0u8; self.message_len];
        self.recover_into(&mut out).then_some(out)
    }

    /// Recovers directly into an existing message/group buffer without an intermediate copy.
    pub fn recover_into(&mut self, out: &mut [u8]) -> bool {
        if !self.done || out.len() != self.message_len { return false; }
        self.codec.wirehair_recover(out) == WirehairResult::Success
    }
}

/// Giant-message wire kind 2 partitions source blocks into balanced contiguous groups.
/// This is a wire-format constant: changing it requires a new extended-fragment kind.
pub const GROUP_MAX_BLOCKS: usize = 32000;

#[derive(Debug, Clone, Copy)]
pub struct MessageLayout {
    pub len: usize,
    pub block_bytes: usize,
    pub k: usize,
    pub groups: usize,
}

impl MessageLayout {
    pub fn new(len: usize, block_bytes: usize) -> Option<Self> {
        Self::with_group_limit(len, block_bytes, GROUP_MAX_BLOCKS)
    }

    pub fn with_group_limit(len: usize, block_bytes: usize, limit: usize) -> Option<Self> {
        if block_bytes == 0 || block_bytes > u16::MAX as usize || len > u32::MAX as usize || !(MIN_BLOCKS..=MAX_BLOCKS).contains(&limit) { return None; }
        let k = len.div_ceil(block_bytes);
        if k < MIN_BLOCKS { return None; }
        // Retain the original single-codec wire format up to Wirehair's hard limit.
        let groups = if k <= MAX_BLOCKS { 1 } else { k.div_ceil(limit) };
        Some(Self { len, block_bytes, k, groups })
    }

    /// Global source-block start and count of one balanced group (all but the last
    /// source block are full sized). No one-block tail codecs.
    pub fn group(&self, group: usize) -> (usize, usize) {
        let base = self.k / self.groups;
        let extra = self.k % self.groups;
        (group * base + group.min(extra), base + usize::from(group < extra))
    }

    pub fn group_bytes(&self, group: usize) -> (usize, usize) {
        let (start, k) = self.group(group);
        let start = start * self.block_bytes;
        (start, (k * self.block_bytes).min(self.len - start))
    }

    /// Sources are sent round-robin across groups; repairs continue round-robin.
    /// `sent` is a count, while the returned id is the stable on-wire block id.
    pub fn wire_id(&self, sent: u32) -> u32 {
        let sent = sent as usize;
        if sent >= self.k || self.groups == 1 { return sent as u32; }
        let base = self.k / self.groups;
        let full_rows = base * self.groups;
        let (group, row) = if sent < full_rows { (sent % self.groups, sent / self.groups) } else { (sent - full_rows, base) };
        (self.group(group).0 + row) as u32
    }

    /// Maps a global id to the group and that codec's local source/repair id.
    pub fn local_id(&self, id: u32) -> (usize, u32) {
        let id = id as usize;
        if id >= self.k {
            let repair = id - self.k;
            let group = repair % self.groups;
            return (group, (self.group(group).1 + repair / self.groups) as u32);
        }
        let base = self.k / self.groups;
        let extra = self.k % self.groups;
        let wide = (base + 1) * extra;
        let group = if id < wide { id / (base + 1) } else { extra + (id - wide) / base };
        (group, (id - self.group(group).0) as u32)
    }

    /// Pad the repair plan to whole round-robin rounds so every group is protected.
    pub fn round_plan(&self, n: u32) -> u32 {
        self.k as u32 + (n.saturating_sub(self.k as u32) as usize).div_ceil(self.groups) as u32 * self.groups as u32
    }
}

pub struct MessageEncoder {
    layout: MessageLayout,
    encoders: Vec<Encoder>,
}

#[allow(unsafe_code)]
unsafe impl Send for MessageEncoder {}

pub fn encode_message(message: Arc<Vec<u8>>, block_bytes: usize) -> Option<MessageEncoder> {
    let layout = MessageLayout::new(message.len(), block_bytes)?;
    encode_message_layout(message, layout)
}

pub fn encode_message_layout(message: Arc<Vec<u8>>, layout: MessageLayout) -> Option<MessageEncoder> {
    if message.len() != layout.len { return None; }
    if layout.groups == 1 {
        let encoder = encode(message, layout.block_bytes)?;
        return Some(MessageEncoder { layout, encoders: vec![encoder] });
    }
    // No library-owned helpers. Independent codec groups are constructed in
    // wire order on the caller's pump thread.
    let encoders = (0..layout.groups).map(|group| {
        let (start, len) = layout.group_bytes(group);
        encode_range(message.clone(), start, len, layout.block_bytes)
    }).collect::<Option<Vec<_>>>()?;
    Some(MessageEncoder { layout, encoders })
}

impl MessageEncoder {
    pub fn block_into(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        let (group, local) = self.layout.local_id(id);
        self.encoders[group].block_into(local, out)
    }
}

/// Inline systematic staging: one exact-length output allocation, no native codec.
/// The fixed bitmap cannot grow with peer-chosen IDs; repairs never index it.
/// Only single-group layouts up to the existing inline boundary are eligible.
pub(crate) struct SourceOnly {
    pub(crate) layout: MessageLayout,
    pub(crate) output: Vec<u8>,
    seen: [u64; 4],
    remaining: usize,
    pub(crate) native_failed: bool,
}
impl SourceOnly {
    pub(crate) fn charge(layout: MessageLayout) -> Option<usize> {
        if layout.groups != 1 || layout.k > crate::stp::FEC_INLINE_MAX_BLOCKS || layout.k > 256 { return None; }
        // Covers the fixed bitmap, Vec/layout metadata and allocator bookkeeping.
        // No per-symbol allocation: the output Vec has capacity exactly len.
        layout.len.checked_add(4096)
    }
    pub(crate) fn new(layout: MessageLayout) -> Self {
        Self { layout, output: vec![0; layout.len], seen: [0; 4], remaining: layout.k, native_failed: false }
    }
    pub(crate) fn has(&self, id: usize) -> bool { self.seen[id / 64] & (1u64 << (id % 64)) != 0 }
    pub(crate) fn insert(&mut self, id: u32, data: &[u8]) -> Result<(DecodeStatus, bool), DecodeError> {
        let id = id as usize;
        if id >= self.layout.k || data.len() != block_len(self.layout.len, self.layout.block_bytes, id as u32) {
            return Err(DecodeError::BadBlock);
        }
        let start = id * self.layout.block_bytes;
        let target = &mut self.output[start..start + data.len()];
        let mask = 1u64 << (id % 64);
        if self.seen[id / 64] & mask != 0 {
            if target != data { return Err(DecodeError::BadBlock); }
            return Ok((DecodeStatus::NeedMore, false));
        }
        target.copy_from_slice(data);
        self.seen[id / 64] |= mask;
        self.remaining -= 1;
        Ok((if self.remaining == 0 { DecodeStatus::Done } else { DecodeStatus::NeedMore }, true))
    }
    /// Caller holds BOTH the source lease and a full native lease during this
    /// allocation/feed. Failure leaves every staged source available unchanged.
    pub(crate) fn decoder(&self) -> Result<MessageDecoder, DecodeError> {
        let mut dec = MessageDecoder::with_layout(self.layout).ok_or(DecodeError::Failed(-1))?;
        for id in 0..self.layout.k {
            if self.has(id) {
                let start = id * self.layout.block_bytes;
                let end = (start + self.layout.block_bytes).min(self.layout.len);
                dec.add(id as u32, &self.output[start..end])?;
            }
        }
        Ok(dec)
    }
}

pub struct MessageDecoder {
    layout: MessageLayout,
    decoders: Vec<Option<Decoder>>,
    complete: Vec<bool>,
    remaining: usize,
    output: Vec<u8>,
}

impl MessageDecoder {
    pub fn new(len: usize, block_bytes: usize) -> Option<Self> {
        Self::with_layout(MessageLayout::new(len, block_bytes)?)
    }

    pub fn with_layout(layout: MessageLayout) -> Option<Self> {
        if !init() { return None; }
        Some(Self { layout, decoders: (0..layout.groups).map(|_| None).collect(), complete: vec![false; layout.groups], remaining: layout.groups, output: vec![0u8; layout.len] })
    }

    pub fn message_len(&self) -> usize { self.layout.len }
    pub fn block_bytes(&self) -> usize { self.layout.block_bytes }

    pub fn add(&mut self, id: u32, data: &[u8]) -> Result<DecodeStatus, DecodeError> {
        let expect = block_len(self.layout.len, self.layout.block_bytes, id);
        if data.len() != expect { return Err(DecodeError::BadBlock); }
        let (group, local) = self.layout.local_id(id);
        if !self.complete[group] {
            let (start, len) = self.layout.group_bytes(group);
            if self.decoders[group].is_none() {
                self.decoders[group] = Some(Decoder::new(len, self.layout.block_bytes).ok_or(DecodeError::Failed(-1))?);
            }
            let decoder = self.decoders[group].as_mut().unwrap();
            if decoder.add(local, data)? == DecodeStatus::Done {
                if !decoder.recover_into(&mut self.output[start..start + len]) { return Err(DecodeError::Failed(-1)); }
                self.decoders[group] = None;
                self.complete[group] = true;
                self.remaining -= 1;
            }
        }
        Ok(if self.remaining == 0 { DecodeStatus::Done } else { DecodeStatus::NeedMore })
    }

    pub fn recover(&mut self) -> Option<Vec<u8>> {
        (self.remaining == 0).then(|| std::mem::take(&mut self.output))
    }
}

/// Blocking convenience decoder for external block producers. STP Pump uses
/// persistent MessageDecoder directly, one input symbol at a time; this helper
/// never creates threads either.
pub fn decode_message_blocks(layout: MessageLayout, rx: std::sync::mpsc::Receiver<(u32, Vec<u8>)>, _ingress_bytes: usize) -> Option<Vec<u8>> {
    let mut decoder = MessageDecoder::with_layout(layout)?;
    while let Ok((id, block)) = rx.recv() {
        match decoder.add(id, &block) {
            Ok(DecodeStatus::Done) => return decoder.recover(),
            Err(DecodeError::Failed(_)) => return None,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{Rng, RngCore, SeedableRng};
    use crate::random::seq::SliceRandom;

    fn message(len: usize, seed: u64) -> Arc<Vec<u8>> {
        let mut r = crate::random::ChaCha20Rng::seed_from_u64(seed);
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
        let mut rng = crate::random::ChaCha20Rng::seed_from_u64(7);
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
        let mut rng = crate::random::ChaCha20Rng::seed_from_u64(11);
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
    fn grouped_boundaries_and_interleaving() {
        for k in [2, 64000, 64001, 64002, 96000, 96001, 1_000_000] {
            for tail in [0, 1, 1199] {
                let len = k * 1200 - tail;
                let l = MessageLayout::new(len, 1200).unwrap();
                assert_eq!(l.k, k);
                let mut seen = vec![false; k];
                for sent in 0..k as u32 {
                    let id = l.wire_id(sent);
                    assert!(!seen[id as usize]);
                    seen[id as usize] = true;
                    let (g, local) = l.local_id(id);
                    let (start, count) = l.group(g);
                    assert!(local < count as u32);
                    assert_eq!(start + local as usize, id as usize);
                }
                assert!(seen.iter().all(|x| *x));
                for g in 0..l.groups {
                    let (_, bytes) = l.group_bytes(g);
                    assert!(block_count(bytes, 1200).is_some());
                    for round in 0..3 {
                        assert_eq!(l.local_id((k + round * l.groups + g) as u32), (g, (l.group(g).1 + round) as u32));
                    }
                }
                assert_eq!((l.round_plan(k as u32 + 1) as usize - k) % l.groups, 0);
            }
        }
        assert!(MessageLayout::new(1, 0).is_none());
        assert!(MessageLayout::new(u32::MAX as usize + 1, 1200).is_none());
    }

    #[test]
    fn grouped_round_trip_loss_reordering_duplicates() {
        let len = 64001 * 128 - 17;
        let m = message(len, 7);
        let l = MessageLayout::new(len, 128).unwrap();
        assert!(l.groups > 1);
        let mut enc = encode_message(m.clone(), 128).unwrap();
        let mut dec = MessageDecoder::new(len, 128).unwrap();
        let mut ids: Vec<_> = (0..l.round_plan(l.k as u32 + 3000)).map(|s| l.wire_id(s)).collect();
        ids.shuffle(&mut crate::random::ChaCha20Rng::seed_from_u64(91));
        let mut buf = vec![0; 128];
        for (i, id) in ids.into_iter().enumerate() {
            if i % 50 == 0 { continue; }
            let n = enc.block_into(id, &mut buf).unwrap();
            let status = dec.add(id, &buf[..n]).unwrap();
            assert_eq!(dec.add(id, &buf[..n]).unwrap(), status);
            if status == DecodeStatus::Done {
                assert_eq!(dec.recover().unwrap(), *m);
                return;
            }
        }
        panic!("grouped decode failed");
    }

    #[test]
    fn parallel_groups_finish_without_input_closing_and_cancel_cleanly() {
        let m = message(64001 * 32 - 7, 12);
        let layout = MessageLayout::new(m.len(), 32).unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(128);
        let job = std::thread::spawn(move || decode_message_blocks(layout, rx, 8192));
        let mut enc = encode_message(m.clone(), 32).unwrap();
        let mut buf = vec![0; 32];
        let mut rng = crate::random::ChaCha20Rng::seed_from_u64(99);
        for sent in 0..layout.round_plan(layout.k as u32 + 4000) {
            if rng.random::<f64>() < 0.02 { continue; }
            let id = layout.wire_id(sent);
            let n = enc.block_into(id, &mut buf).unwrap();
            if tx.send((id, buf[..n].to_vec())).is_err() { break; }
        }
        assert_eq!(job.join().unwrap().unwrap(), *m); // tx deliberately remains alive
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        let job = std::thread::spawn(move || decode_message_blocks(layout, rx, 8192));
        tx.send((0, vec![0;32])).unwrap();
        drop(tx);
        assert!(job.join().unwrap().is_none());
    }

    /// Standalone codec timing with configurable group sizes; emits one JSON result.
    #[test]
    #[ignore]
    fn benchmark_giant_codec() {
        use std::time::Instant;
        let len = std::env::var("STP_CODEC_BYTES").ok().and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        let limit = std::env::var("STP_CODEC_GROUP").ok().and_then(|s| s.parse().ok()).unwrap_or(GROUP_MAX_BLOCKS);
        let bb = 1200;
        let m = Arc::new((0..len).map(|i| (i as u8).wrapping_mul(131)).collect::<Vec<_>>());
        let l = MessageLayout::with_group_limit(len, bb, limit).unwrap();
        let start = Instant::now();
        let mut enc = encode_message_layout(m.clone(), l).unwrap();
        let encode_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let mut dec = MessageDecoder::with_layout(l).unwrap();
        let mut buf = vec![0; bb];
        let mut encode_blocks_s = 0.0;
        let mut n_recv = 0;
        let mut rng = crate::random::ChaCha20Rng::seed_from_u64(777);
        for sent in 0..l.round_plan(l.k as u32 + l.k as u32 / 20) {
            // Seeded independent 2% loss. Periodic loss aliases with round-robin groups.
            if rng.random::<f64>() < 0.02 { continue; }
            let id = l.wire_id(sent);
            let data = if (id as usize) < l.k {
                let start = id as usize * bb;
                &m[start..(start + bb).min(len)]
            } else {
                let t = Instant::now();
                let n = enc.block_into(id, &mut buf).unwrap();
                encode_blocks_s += t.elapsed().as_secs_f64();
                &buf[..n]
            };
            n_recv += 1;
            if dec.add(id, data).unwrap() == DecodeStatus::Done { break; }
        }
        let decode_s = start.elapsed().as_secs_f64() - encode_blocks_s;
        assert_eq!(dec.recover().unwrap(), *m);
        println!("{{\"bytes\":{len},\"group_max\":{limit},\"groups\":{},\"k\":{},\"encode_wall_s\":{encode_s:.6},\"encode_blocks_s\":{encode_blocks_s:.6},\"decode_wall_s\":{decode_s:.6},\"received\":{n_recv}}}", l.groups, l.k);
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
    #[test]
    fn bounded_native_creation_and_channel_slots() {
        assert!(init());
        assert!(matches!(wirehair::decoder_create_limited(256000, 1000, 1024), Err(WirehairResult::Oom)));
        let slots = ingress_slots(32<<20, 1);
        assert!(slots * (1 + std::mem::size_of::<(u32, Vec<u8>)>()) <= 32<<20);
        let tiny = MessageLayout::new(1<<20, 1).unwrap();
        assert!(receive_memory_charge(tiny, true, 32<<20).unwrap() > 300<<20);
    }
}
