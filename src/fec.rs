//! Safe wrapper over the in-crate Rust Wirehair fountain code. Equations and repair symbols match the previously
//! vendored classic C++ codec.
//!
//! A message of `len` bytes is split into K = ceil(len / block_bytes) source blocks. The encoder can produce any block
//! id: ids 0..K-1 are the message itself ("systematic": block i is `message[i*block_bytes..]`, the last one short), ids
//! >= K are repair blocks of exactly `block_bytes`. A decoder recovers the message from any ~K distinct ids (K + 0.02
//! on average). Wirehair accepts 2 <= K <= 64000.
//!
use std::sync::Arc; pub const MIN_BLOCKS: usize = 2; pub const MAX_BLOCKS: usize = 64000;
/// Hard codec-arena cap, including input, workspace, dedup and GE matrix. Per-symbol charge matters even when a
/// malicious peer chooses one-byte blocks. Wirehair refuses a solve/regrow exceeding this cap rather than
/// overallocating.
pub fn decoder_memory_limit(len: usize, block_bytes: usize) -> Option<usize> { let k = block_count(len, block_bytes)?;
    len.checked_mul(2)?.checked_add(k.checked_mul(256)?)?.checked_add(1 << 20) }
pub fn ingress_slots(bytes: usize, block_bytes: usize) -> usize {
    (bytes / (block_bytes + std::mem::size_of::<(u32, Vec<u8>)>() + 128)).max(1) }
pub fn receive_memory_charge(layout: MessageLayout, worker: bool, ingress_bytes: usize) -> Option<usize> {
    let mut bytes = layout.len;
    for group in 0..layout.groups { let (_, len) = layout.group_bytes(group);
        bytes = bytes.checked_add(decoder_memory_limit(len, layout.block_bytes)?)?.checked_add(4096)?; }
    if worker { bytes = bytes.checked_add(ingress_bytes.checked_mul(2)?)?.checked_add(256 << 10)?; }
    Some(bytes) }
use crate::wirehair::{self, WirehairResult};
pub fn init() -> bool { wirehair::init() == WirehairResult::Success }
pub fn block_count(message_len: usize, block_bytes: usize) -> Option<usize> {
    if block_bytes == 0 || block_bytes > u32::MAX as usize { return None; }
    let k = message_len.div_ceil(block_bytes);
    (MIN_BLOCKS..=MAX_BLOCKS).contains(&k).then_some(k) }
pub fn block_len(message_len: usize, block_bytes: usize, id: u32) -> usize { let start = id as usize * block_bytes;
    if start >= message_len { block_bytes } else { (message_len - start).min(block_bytes) } }
pub struct Encoder { codec: Box<wirehair::Codec>, message: Arc<Vec<u8>>, block_bytes: usize, }
pub fn encode(message: Arc<Vec<u8>>, block_bytes: usize) -> Option<Encoder> { let len = message.len();
    encode_range(message, 0, len, block_bytes) }
fn encode_range(message: Arc<Vec<u8>>, start: usize, len: usize, block_bytes: usize) -> Option<Encoder> {
    block_count(len, block_bytes)?;
    if start.checked_add(len)? > message.len() || !init() { return None; }
    let codec = Box::new(wirehair::encoder_create(message.clone(), start, len, block_bytes as u32).ok()?);
    Some(Encoder { codec, message, block_bytes }) }
impl Encoder {
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn message(&self) -> &Arc<Vec<u8>> { &self.message }
    pub fn block_into(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        if out.len() < self.block_bytes { return None; }
        let cap = out.len().min(u32::MAX as usize);
        let written = self.codec.wirehair_encode(id, &mut out[..cap]).ok()? as usize;
        (written <= self.block_bytes).then_some(written) }
    pub fn block(&mut self, id: u32) -> Option<Vec<u8>> {
        let mut v = vec![0u8; self.block_bytes]; let n = self.block_into(id, &mut v)?; v.truncate(n);
        Some(v) } }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum DecodeStatus { NeedMore, Done }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum DecodeError { BadBlock, Failed(i32), }
pub struct Decoder { codec: Box<wirehair::Codec>, message_len: usize, block_bytes: usize, done: bool, }
impl Decoder {
    pub fn new(message_len: usize, block_bytes: usize) -> Option<Decoder> { block_count(message_len, block_bytes)?;
        if !init() { return None; }
        let codec = Box::new(wirehair::decoder_create_limited(message_len as u64, block_bytes as u32,
            decoder_memory_limit(message_len, block_bytes)? as u64).ok()?);
        Some(Decoder { codec, message_len, block_bytes, done: false }) }
    pub fn message_len(&self) -> usize { self.message_len }
    pub fn block_bytes(&self) -> usize { self.block_bytes }
    pub fn is_done(&self) -> bool { self.done }
    pub fn add(&mut self, id: u32, data: &[u8]) -> Result<DecodeStatus, DecodeError> {
        if self.done { return Ok(DecodeStatus::Done); }
        if data.is_empty() || data.len() > self.block_bytes { return Err(DecodeError::BadBlock); }
        match self.codec.wirehair_decode(id, data) {
            WirehairResult::Success => { self.done = true; Ok(DecodeStatus::Done) }
            WirehairResult::NeedMore => Ok(DecodeStatus::NeedMore),
            WirehairResult::InvalidInput => Err(DecodeError::BadBlock),
            e => Err(DecodeError::Failed(e.code())), } }
    pub fn recover(&mut self) -> Option<Vec<u8>> { let mut out = vec![0u8; self.message_len];
        self.recover_into(&mut out).then_some(out) }
    pub fn recover_into(&mut self, out: &mut [u8]) -> bool {
        if !self.done || out.len() != self.message_len { return false; }
        self.codec.wirehair_recover(out) == WirehairResult::Success } }
/// Giant-message wire kind 2 partitions source blocks into balanced contiguous groups. This is a wire-format constant:
/// changing it requires a new extended-fragment kind.
pub const GROUP_MAX_BLOCKS: usize = 32000;
#[derive(Debug, Clone, Copy)]
pub struct MessageLayout { pub len: usize, pub block_bytes: usize, pub k: usize, pub groups: usize, }
impl MessageLayout {
    pub fn new(len: usize, block_bytes: usize) -> Option<Self> {
        Self::with_group_limit(len, block_bytes, GROUP_MAX_BLOCKS) }
    pub fn with_group_limit(len: usize, block_bytes: usize, limit: usize) -> Option<Self> {
        if block_bytes == 0 || block_bytes > u16::MAX as usize || len > u32::MAX as usize || !(MIN_BLOCKS..=MAX_BLOCKS).contains(&limit) { return None; }
        let k = len.div_ceil(block_bytes);
        if k < MIN_BLOCKS { return None; }
        let groups = if k <= MAX_BLOCKS { 1 } else { k.div_ceil(limit) };
        Some(Self { len, block_bytes, k, groups }) }
    pub fn group(&self, group: usize) -> (usize, usize) {
        let base = self.k / self.groups; let extra = self.k % self.groups;
        (group * base + group.min(extra), base + usize::from(group < extra)) }
    pub fn group_bytes(&self, group: usize) -> (usize, usize) {
        let (start, k) = self.group(group); let start = start * self.block_bytes;
        (start, (k * self.block_bytes).min(self.len - start)) }
    pub fn wire_id(&self, sent: u32) -> u32 { let sent = sent as usize;
        if sent >= self.k || self.groups == 1 { return sent as u32; }
        let base = self.k / self.groups; let full_rows = base * self.groups;
        let (group, row) = if sent < full_rows { (sent % self.groups, sent / self.groups) } else { (sent - full_rows, base) };
        (self.group(group).0 + row) as u32 }
    pub fn local_id(&self, id: u32) -> (usize, u32) { let id = id as usize;
        if id >= self.k { let repair = id - self.k; let group = repair % self.groups;
            return (group, (self.group(group).1 + repair / self.groups) as u32); }
        let base = self.k / self.groups; let extra = self.k % self.groups; let wide = (base + 1) * extra;
        let group = if id < wide { id / (base + 1) } else { extra + (id - wide) / base };
        (group, (id - self.group(group).0) as u32) }
    pub fn round_plan(&self, n: u32) -> u32 {
        self.k as u32 + (n.saturating_sub(self.k as u32) as usize).div_ceil(self.groups) as u32 * self.groups as u32 } }
pub struct MessageEncoder { layout: MessageLayout, encoders: Vec<Encoder>, }
#[allow(unsafe_code)] unsafe impl Send for MessageEncoder {}
pub fn encode_message(message: Arc<Vec<u8>>, block_bytes: usize) -> Option<MessageEncoder> {
    let layout = MessageLayout::new(message.len(), block_bytes)?;
    encode_message_layout(message, layout) }
pub fn encode_message_layout(message: Arc<Vec<u8>>, layout: MessageLayout) -> Option<MessageEncoder> {
    if message.len() != layout.len { return None; }
    if layout.groups == 1 { let encoder = encode(message, layout.block_bytes)?;
        return Some(MessageEncoder { layout, encoders: vec![encoder] }); }
    let encoders = (0..layout.groups).map(|group| { let (start, len) = layout.group_bytes(group);
        encode_range(message.clone(), start, len, layout.block_bytes) }).collect::<Option<Vec<_>>>()?;
    Some(MessageEncoder { layout, encoders }) }
impl MessageEncoder {
    pub fn block_into(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        let (group, local) = self.layout.local_id(id);
        self.encoders[group].block_into(local, out) } }
pub(crate) struct SourceOnly {
    pub(crate) layout: MessageLayout, pub(crate) output: Vec<u8>, seen: [u64; 4], remaining: usize,
    pub(crate) native_failed: bool, }
impl SourceOnly {
    pub(crate) fn charge(layout: MessageLayout) -> Option<usize> {
        if layout.groups != 1 || layout.k > crate::stp::FEC_INLINE_MAX_BLOCKS || layout.k > 256 { return None; }
        layout.len.checked_add(4096) }
    pub(crate) fn new(layout: MessageLayout) -> Self {
        Self { layout, output: vec![0; layout.len], seen: [0; 4], remaining: layout.k, native_failed: false } }
    pub(crate) fn has(&self, id: usize) -> bool { self.seen[id / 64] & (1u64 << (id % 64)) != 0 }
    pub(crate) fn insert(&mut self, id: u32, data: &[u8]) -> Result<(DecodeStatus, bool), DecodeError> {
        let id = id as usize;
        if id >= self.layout.k || data.len() != block_len(self.layout.len, self.layout.block_bytes, id as u32) {
            return Err(DecodeError::BadBlock); }
        let start = id * self.layout.block_bytes; let target = &mut self.output[start..start + data.len()];
        let mask = 1u64 << (id % 64);
        if self.seen[id / 64] & mask != 0 {
            if target != data { return Err(DecodeError::BadBlock); }
            return Ok((DecodeStatus::NeedMore, false)); }
        target.copy_from_slice(data); self.seen[id / 64] |= mask; self.remaining -= 1;
        Ok((if self.remaining == 0 { DecodeStatus::Done } else { DecodeStatus::NeedMore }, true)) }
    pub(crate) fn decoder(&self) -> Result<MessageDecoder, DecodeError> {
        let mut dec = MessageDecoder::with_layout(self.layout).ok_or(DecodeError::Failed(-1))?;
        for id in 0..self.layout.k {
            if self.has(id) { let start = id * self.layout.block_bytes;
                let end = (start + self.layout.block_bytes).min(self.layout.len);
                dec.add(id as u32, &self.output[start..end])?; } }
        Ok(dec) } }
pub struct MessageDecoder {
    layout: MessageLayout, decoders: Vec<Option<Decoder>>, complete: Vec<bool>, remaining: usize,
    output: Vec<u8>, }
impl MessageDecoder {
    pub fn new(len: usize, block_bytes: usize) -> Option<Self> {
        Self::with_layout(MessageLayout::new(len, block_bytes)?) }
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
        if !self.complete[group] { let (start, len) = self.layout.group_bytes(group);
            if self.decoders[group].is_none() {
                self.decoders[group] = Some(Decoder::new(len, self.layout.block_bytes).ok_or(DecodeError::Failed(-1))?); }
            let decoder = self.decoders[group].as_mut().unwrap();
            if decoder.add(local, data)? == DecodeStatus::Done {
                if !decoder.recover_into(&mut self.output[start..start + len]) { return Err(DecodeError::Failed(-1)); }
                self.decoders[group] = None; self.complete[group] = true;
                self.remaining -= 1; } }
        Ok(if self.remaining == 0 { DecodeStatus::Done } else { DecodeStatus::NeedMore }) }
    pub fn recover(&mut self) -> Option<Vec<u8>> { (self.remaining == 0).then(|| std::mem::take(&mut self.output)) } }
pub fn decode_message_blocks(layout: MessageLayout, rx: std::sync::mpsc::Receiver<(u32, Vec<u8>)>, _ingress_bytes: usize) -> Option<Vec<u8>> {
    let mut decoder = MessageDecoder::with_layout(layout)?;
    while let Ok((id, block)) = rx.recv() {
        match decoder.add(id, &block) {
            Ok(DecodeStatus::Done) => return decoder.recover(),
            Err(DecodeError::Failed(_)) => return None,
            _ => {} } }
    None }
