//! Pure Rust Wirehair fountain code (O(N) MDS-like erasure code), an exact-compatibility port of the STP-vendored C++
//! library in third_party/wirehair (classic wirehair.cpp API over WirehairCodec): same equations ("wire profile"), same
//! recovery bytes, same decoded output and the same result codes, including the vendored decoder's duplicate-packet
//! identity table and memory-limit accounting.
//!
//! Copyright (c) 2012-2018 Christopher A. Taylor. All rights reserved. BSD 3-clause license; see the full notice in
//! codec.rs, gf256.rs and tools.rs.
//!
//! Layout: [`gf256`] (GF(2^8) arithmetic), [`tools`] (PRNG, seeds, row generators), [`codec`] (peeling / GE solver,
//! encoder, decoder). The facade below mirrors the C entry points one to one:
//!
//! | C++ (wirehair.h)                  | Rust                                   |
//! |-----------------------------------|----------------------------------------|
//! | `wirehair_init()`                 | [`init`] (always `Success`)            |
//! | `wirehair_encoder_create`         | [`encoder_create`] (borrows via `Arc`) |
//! | `wirehair_encode`                 | [`Codec::wirehair_encode`]             |
//! | `wirehair_decoder_create_limited` | [`decoder_create_limited`]             |
//! | `wirehair_decode`                 | [`Codec::wirehair_decode`]             |
//! | `wirehair_recover`                | [`Codec::wirehair_recover`]            |
//! | `wirehair_free`                   | `drop`                                 |
//!
//! Where the C API returns a NULL codec, the Rust constructors return `Err(result)` with the code the `_ex` variants
//! report. The C entry points STP never calls (owned-copy encoder, unlimited decoder, input detach, single-block
//! recovery, decoder-to-encoder conversion and the seed-search matrix-only feeds) are not ported.
pub mod codec;
pub mod gf256;
pub mod tools;
pub use codec::{Codec, InputSource, Mode, WireProfile, WirehairResult, packet_fingerprint128};
use std::sync::Arc;
pub const WIREHAIR_VERSION: i32 = 2;
pub const WIREHAIR_LEGACY_PROFILE_PRE_FIXUP: u64 = 0xe1b9_f77f_1c90_f680;
pub const WIREHAIR_LEGACY_PROFILE_FIXUPS_2026_07: u64 = 0x4d24_1359_db07_bb07;
pub const WIREHAIR_LEGACY_PROFILE_CURRENT: u64 = WIREHAIR_LEGACY_PROFILE_FIXUPS_2026_07;
pub fn wire_profile_from_id(profile_id: u64) -> Option<WireProfile> {
    match profile_id {
        WIREHAIR_LEGACY_PROFILE_PRE_FIXUP => Some(WireProfile::LegacyPreFixup),
        WIREHAIR_LEGACY_PROFILE_CURRENT => Some(WireProfile::LegacyCurrent),
        _ => None,
    }
}
pub fn init() -> WirehairResult {
    WirehairResult::Success
}
fn create_encoder(
    message: InputSource,
    block_bytes: u32,
    profile: WireProfile,
) -> Result<Codec, WirehairResult> {
    let message_bytes = message_len(&message);
    if message.is_none_source() || message_bytes < 1 || block_bytes < 1 {
        return Err(WirehairResult::InvalidInput);
    }
    let mut codec = Codec::new();
    codec.set_wire_profile(profile);
    let mut result = codec.initialize_encoder(message_bytes, block_bytes);
    if result == WirehairResult::Success {
        result = codec.encode_feed(message);
    }
    if result != WirehairResult::Success {
        return Err(result);
    }
    Ok(codec)
}
fn message_len(m: &InputSource) -> u64 {
    match m {
        InputSource::None => 0,
        InputSource::Owned(v) => v.len() as u64,
        InputSource::Shared { len, .. } => *len as u64,
    }
}
pub fn encoder_create(
    message: Arc<Vec<u8>>,
    start: usize,
    len: usize,
    block_bytes: u32,
) -> Result<Codec, WirehairResult> {
    encoder_create_profile(message, start, len, block_bytes, WireProfile::LegacyCurrent)
}
pub fn encoder_create_profile(
    message: Arc<Vec<u8>>,
    start: usize,
    len: usize,
    block_bytes: u32,
    profile: WireProfile,
) -> Result<Codec, WirehairResult> {
    if start
        .checked_add(len)
        .map_or(true, |end| end > message.len())
    {
        return Err(WirehairResult::InvalidInput);
    }
    create_encoder(
        InputSource::Shared {
            data: message,
            start,
            len,
        },
        block_bytes,
        profile,
    )
}
pub fn decoder_create_limited(
    message_bytes: u64,
    block_bytes: u32,
    memory_limit: u64,
) -> Result<Codec, WirehairResult> {
    decoder_create_profile(
        message_bytes,
        block_bytes,
        memory_limit,
        WireProfile::LegacyCurrent,
    )
}
pub fn decoder_create_profile(
    message_bytes: u64,
    block_bytes: u32,
    memory_limit: u64,
    profile: WireProfile,
) -> Result<Codec, WirehairResult> {
    if message_bytes < 1 || block_bytes < 1 {
        return Err(WirehairResult::InvalidInput);
    }
    let mut codec = Codec::new();
    codec.set_memory_limit(memory_limit);
    codec.set_wire_profile(profile);
    let result = codec.initialize_decoder(message_bytes, block_bytes);
    if result != WirehairResult::Success {
        return Err(result);
    }
    Ok(codec)
}
impl InputSource {
    fn is_none_source(&self) -> bool {
        matches!(self, InputSource::None)
    }
}
impl Codec {
    pub fn wirehair_encode(&self, block_id: u32, out: &mut [u8]) -> Result<u32, WirehairResult> {
        if !self.can_encode() {
            return Err(WirehairResult::InvalidInput);
        }
        let out_bytes = out.len().min(u32::MAX as usize) as u32;
        let written = self.encode(block_id, out, out_bytes);
        if written == 0 {
            return Err(WirehairResult::InvalidInput);
        }
        Ok(written)
    }
    pub fn wirehair_decode(&mut self, block_id: u32, data: &[u8]) -> WirehairResult {
        if data.is_empty() || data.len() > u32::MAX as usize {
            return WirehairResult::InvalidInput;
        }
        if !self.can_decode() {
            return WirehairResult::InvalidInput;
        }
        self.decode_feed(block_id, data)
    }
    pub fn wirehair_recover(&mut self, out: &mut [u8]) -> WirehairResult {
        self.reconstruct_output(out)
    }
}
