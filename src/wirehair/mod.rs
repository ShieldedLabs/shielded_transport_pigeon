//! Pure Rust Wirehair fountain code (O(N) MDS-like erasure code), an exact-compatibility
//! port of the STP-vendored C++ library in third_party/wirehair (classic wirehair.cpp API
//! over WirehairCodec): same equations ("wire profile"), same recovery bytes, same
//! decoded output and the same result codes, including the vendored decoder's
//! duplicate-packet identity table and memory-limit accounting.
//!
//! Copyright (c) 2012-2018 Christopher A. Taylor.  All rights reserved.
//! BSD 3-clause license; see the full notice in codec.rs, gf256.rs and tools.rs.
//!
//! Layout: [`gf256`] (GF(2^8) arithmetic), [`tools`] (PRNG, seeds, row generators),
//! [`codec`] (peeling / GE solver, encoder, decoder). The facade below mirrors the
//! C entry points one to one:
//!
//! | C++ (wirehair.h)                  | Rust                                   |
//! |-----------------------------------|----------------------------------------|
//! | `wirehair_init()`                 | [`init`] (always `Success`)            |
//! | `wirehair_encoder_create`         | [`encoder_create`] (borrows via `Arc`) |
//! | `wirehair_encoder_create_owned`   | [`encoder_create_owned`] (copies)      |
//! | `wirehair_encode`                 | [`Codec::wirehair_encode`]             |
//! | `wirehair_encoder_detach_input`   | [`Codec::detach_input`]                |
//! | `wirehair_decoder_create`         | [`decoder_create`]                     |
//! | `wirehair_decoder_create_limited` | [`decoder_create_limited`]             |
//! | `wirehair_decode`                 | [`Codec::wirehair_decode`]             |
//! | `wirehair_recover`                | [`Codec::wirehair_recover`]            |
//! | `wirehair_recover_block_ex`       | [`Codec::wirehair_recover_block`]      |
//! | `wirehair_decoder_becomes_encoder`| [`Codec::becomes_encoder`]             |
//! | `wirehair_free`                   | `drop`                                 |
//!
//! Where the C API returns a NULL codec, the Rust constructors return `Err(result)` with
//! the code the `_ex` variants report.

pub mod codec;
pub mod gf256;
pub mod tools;

use std::sync::Arc;

pub use codec::{packet_fingerprint128, Codec, InputSource, Mode, WireProfile, WirehairResult};

/// `WIREHAIR_VERSION` of the vendored header.
pub const WIREHAIR_VERSION: i32 = 2;

/// Wire profile ids (`WIREHAIR_LEGACY_PROFILE_*`).
pub const WIREHAIR_LEGACY_PROFILE_PRE_FIXUP: u64 = 0xe1b9_f77f_1c90_f680;
pub const WIREHAIR_LEGACY_PROFILE_FIXUPS_2026_07: u64 = 0x4d24_1359_db07_bb07;
pub const WIREHAIR_LEGACY_PROFILE_CURRENT: u64 = WIREHAIR_LEGACY_PROFILE_FIXUPS_2026_07;

/// Resolves a C wire profile id.
pub fn wire_profile_from_id(profile_id: u64) -> Option<WireProfile> {
    match profile_id {
        WIREHAIR_LEGACY_PROFILE_PRE_FIXUP => Some(WireProfile::LegacyPreFixup),
        WIREHAIR_LEGACY_PROFILE_CURRENT => Some(WireProfile::LegacyCurrent),
        _ => None,
    }
}

/// `wirehair_init()`: the Rust GF(256) tables are compile-time constants, so this
/// cannot fail. Kept for API parity.
pub fn init() -> WirehairResult {
    WirehairResult::Success
}

fn create_encoder(message: InputSource, block_bytes: u32, profile: WireProfile) -> Result<Codec, WirehairResult> {
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

/// `wirehair_encoder_create`: encodes `message[start..start+len]` without copying it
/// (the codec keeps the `Arc` alive, like the C++ borrowed pointer).
pub fn encoder_create(message: Arc<Vec<u8>>, start: usize, len: usize, block_bytes: u32) -> Result<Codec, WirehairResult> {
    encoder_create_profile(message, start, len, block_bytes, WireProfile::LegacyCurrent)
}

/// `wirehair_encoder_create_profile_ex` with a borrowed message.
pub fn encoder_create_profile(
    message: Arc<Vec<u8>>,
    start: usize,
    len: usize,
    block_bytes: u32,
    profile: WireProfile,
) -> Result<Codec, WirehairResult> {
    if start.checked_add(len).map_or(true, |end| end > message.len()) {
        return Err(WirehairResult::InvalidInput);
    }
    create_encoder(InputSource::Shared { data: message, start, len }, block_bytes, profile)
}

/// `wirehair_encoder_create_owned`: copies the message into codec-owned storage.
pub fn encoder_create_owned(message: &[u8], block_bytes: u32) -> Result<Codec, WirehairResult> {
    encoder_create_owned_profile(message, block_bytes, WireProfile::LegacyCurrent)
}

/// `wirehair_encoder_create_owned` with an explicit wire profile.
pub fn encoder_create_owned_profile(message: &[u8], block_bytes: u32, profile: WireProfile) -> Result<Codec, WirehairResult> {
    create_encoder(InputSource::Owned(message.to_vec()), block_bytes, profile)
}

/// `wirehair_decoder_create` (no memory limit).
pub fn decoder_create(message_bytes: u64, block_bytes: u32) -> Result<Codec, WirehairResult> {
    decoder_create_profile(message_bytes, block_bytes, u64::MAX, WireProfile::LegacyCurrent)
}

/// `wirehair_decoder_create_limited`: the decoder refuses any arena allocation that
/// would bring input + workspace + GE bytes above `memory_limit` (result `Oom`).
pub fn decoder_create_limited(message_bytes: u64, block_bytes: u32, memory_limit: u64) -> Result<Codec, WirehairResult> {
    decoder_create_profile(message_bytes, block_bytes, memory_limit, WireProfile::LegacyCurrent)
}

/// Decoder with explicit memory limit and wire profile.
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
    /// `wirehair_encode`: writes block `block_id` into `out`; returns bytes written
    /// (`block_bytes`, or the partial final size for id N-1).
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

    /// `wirehair_decode`: `Success` once decodable, `NeedMore`, or an error code.
    pub fn wirehair_decode(&mut self, block_id: u32, data: &[u8]) -> WirehairResult {
        if data.is_empty() || data.len() > u32::MAX as usize {
            return WirehairResult::InvalidInput;
        }
        if !self.can_decode() {
            return WirehairResult::InvalidInput;
        }
        self.decode_feed(block_id, data)
    }

    /// `wirehair_recover`: `out.len()` must equal the message length.
    pub fn wirehair_recover(&mut self, out: &mut [u8]) -> WirehairResult {
        self.reconstruct_output(out)
    }

    /// `wirehair_recover_block_ex`: reconstructs original block `block_id`.
    pub fn wirehair_recover_block(&self, block_id: u32, out: &mut [u8]) -> Result<u32, WirehairResult> {
        if block_id > 0xffff {
            return Err(WirehairResult::InvalidInput);
        }
        let cap = out.len().min(u32::MAX as usize) as u32;
        match self.reconstruct_block(block_id as u16, out, cap) {
            (WirehairResult::Success, n) => Ok(n),
            (r, _) => Err(r),
        }
    }

    /// `wirehair_decoder_becomes_encoder`.
    pub fn becomes_encoder(&mut self) -> WirehairResult {
        self.initialize_encoder_from_decoder()
    }
}

/// Permanent compatibility fixtures. The table below was generated by running the same
/// fixture logic against the vendored upstream C++ Wirehair (custom profile patches
/// included) and cross-checked against this port; it pins seeds/dense counts, exact
/// encoded symbols (including huge and wrapped ids and short output buffers), decoder
/// result statuses under loss/duplicates/conflicts/malformed lengths, recovery, and the
/// exact memory-limit boundary, for both wire profiles.
#[cfg(test)]
mod compat_fixtures {
    use std::sync::Arc;

    trait Api: Sized {
        fn enc(msg: &Arc<Vec<u8>>, bb: u32, pre: bool) -> Result<Self, i32>;
        fn dec(bytes: u64, bb: u32, limit: u64, pre: bool) -> Result<Self, i32>;
        fn encode(&self, id: u32, out: &mut [u8]) -> (i32, u32);
        fn decode(&mut self, id: u32, data: &[u8]) -> i32;
        fn recover(&mut self, out: &mut [u8]) -> i32;
        fn seeds(&self) -> (u64, u64, u64);
        fn alloc(&self) -> [u64; 3];
    }

    struct Fnv(u64);
    impl Fnv {
        fn new() -> Fnv {
            Fnv(0xcbf2_9ce4_8422_2325)
        }
        fn bytes(&mut self, b: &[u8]) {
            for &x in b {
                self.0 = (self.0 ^ x as u64).wrapping_mul(0x0100_0000_01b3);
            }
        }
        fn u64(&mut self, v: u64) {
            self.bytes(&v.to_le_bytes());
        }
    }

    fn xs(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// (K, block_bytes, final_bytes, pre_fixup_profile)
    const CASES: &[(u32, u32, u32, bool)] = &[
        (2, 1, 1, false),
        (2, 7, 3, true),
        (3, 16, 16, false),
        (10, 33, 1, true),
        (64, 100, 99, false),
        (128, 1200, 1200, false),
        (128, 1200, 17, true),
        (256, 64, 5, false),
        (256, 64, 64, true),
        (1000, 8, 3, false),
        (3000, 16, 9, false),
        (3000, 16, 16, true),
        (32000, 4, 1, false),
        (32000, 4, 4, true),
        (64000, 2, 1, false),
        (64000, 1, 1, true),
    ];

    /// Returns (dense, p_seed, d_seed, encode digest, decode digest, events-to-success,
    /// limited-decoder digest) for one case.
    fn fixture<A: Api>(k: u32, bb: u32, last: u32, pre: bool) -> [u64; 7] {
        let len = (k as usize - 1) * bb as usize + last as usize;
        let mut s = 0x9e37_79b9_7f4a_7c15 ^ ((k as u64) << 20) ^ ((bb as u64) << 4) ^ last as u64 ^ pre as u64;
        let msg: Vec<u8> = (0..len).map(|_| xs(&mut s) as u8).collect();
        let msg = Arc::new(msg);
        let enc = A::enc(&msg, bb, pre).expect("encoder");
        let (dense, p, d) = enc.seeds();

        let mut out = vec![0u8; bb as usize + 3];
        let mut ids: Vec<u32> = (0..k.min(16)).collect();
        ids.extend([k - 1, u32::MAX, 0x1_0000, 0xffff]);
        ids.extend(k..k + 64);
        for _ in 0..16 {
            ids.push(xs(&mut s) as u32);
        }
        let mut h = Fnv::new();
        for &id in &ids {
            out.fill(0xa5);
            let (r, w) = enc.encode(id, &mut out);
            h.u64(id as u64);
            h.u64(r as u64);
            h.u64(w as u64);
            h.bytes(&out);
        }
        // short output buffer
        let (r, w) = enc.encode(k - 1, &mut out[..last as usize - 1]);
        h.u64(r as u64 + w as u64);
        let enc_digest = h.0;

        // Lossy/duplicate/conflicting/malformed stream until success.
        let block = |id: u32| -> Vec<u8> {
            let mut b = vec![0u8; bb as usize];
            let (r, w) = enc.encode(id, &mut b);
            assert_eq!(r, 0);
            b.truncate(w as usize);
            b
        };
        let mut dec = A::dec(len as u64, bb, u64::MAX, pre).expect("decoder");
        let mut h = Fnv::new();
        let mut events = 0u64;
        let mut prev: Option<(u32, Vec<u8>)> = None;
        let mut id = 0u32;
        let mut done = false;
        while !done && id < 3 * k + 200 {
            let this = id;
            id += 1;
            if xs(&mut s) % 4 == 0 {
                continue;
            }
            let real = if this >= k && xs(&mut s) % 3 == 0 { this.wrapping_add(0x8000_0000) } else { this };
            let b = block(real);
            let mut feed = vec![(real, b.clone())];
            if let Some(pv) = &prev {
                match xs(&mut s) % 9 {
                    0 => feed.push(pv.clone()),
                    1 => {
                        let mut c = pv.clone();
                        c.1[0] ^= 0x41;
                        feed.push(c);
                    }
                    2 => feed.push((real, b[..b.len() - (b.len() > 1) as usize].to_vec())),
                    3 => feed.push((real, Vec::new())),
                    _ => {}
                }
            }
            prev = Some((real, b));
            for (fid, data) in feed {
                let r = dec.decode(fid, &data);
                events += 1;
                h.u64(fid as u64);
                h.u64(r as u64);
                if r == 0 {
                    done = true;
                }
                if r != 0 && r != 1 && r != 2 {
                    done = true;
                }
            }
        }
        let mut rec = vec![0u8; len];
        let r = dec.recover(&mut rec);
        h.u64(r as u64);
        if r == 0 {
            assert!(rec[..] == msg[..], "recovered message differs");
            h.u64(1);
        }
        let dec_digest = h.0;

        // Memory-limited decoders at the exact arena boundary of the solved decoder above:
        // one byte short refuses (Oom) at the solve, the exact charge succeeds.
        let [i, w, g] = dec.alloc();
        let mut h = Fnv::new();
        h.u64(i);
        h.u64(w);
        h.u64(g);
        for limit in [i + w + g - 1, i + w + g, i + w - 1] {
            match A::dec(len as u64, bb, limit, pre) {
                Err(e) => h.u64(100 + e as u64),
                Ok(mut ld) => {
                    for id in k / 2..2 * k + 64 {
                        let r = ld.decode(id, &block(id));
                        h.u64(r as u64);
                        if r != 1 {
                            break;
                        }
                    }
                    h.u64(ld.alloc().iter().sum::<u64>());
                }
            }
        }
        [dense, p, d, enc_digest, dec_digest, events, h.0]
    }
    struct Rs(super::Codec);
    impl Api for Rs {
        fn enc(msg: &Arc<Vec<u8>>, bb: u32, pre: bool) -> Result<Self, i32> {
            let p = if pre { super::WireProfile::LegacyPreFixup } else { super::WireProfile::LegacyCurrent };
            super::encoder_create_profile(msg.clone(), 0, msg.len(), bb, p).map(Rs).map_err(|e| e.code())
        }
        fn dec(bytes: u64, bb: u32, limit: u64, pre: bool) -> Result<Self, i32> {
            let p = if pre { super::WireProfile::LegacyPreFixup } else { super::WireProfile::LegacyCurrent };
            super::decoder_create_profile(bytes, bb, limit, p).map(Rs).map_err(|e| e.code())
        }
        fn encode(&self, id: u32, out: &mut [u8]) -> (i32, u32) {
            match self.0.wirehair_encode(id, out) {
                Ok(w) => (0, w),
                Err(e) => (e.code(), 0),
            }
        }
        fn decode(&mut self, id: u32, data: &[u8]) -> i32 {
            self.0.wirehair_decode(id, data).code()
        }
        fn recover(&mut self, out: &mut [u8]) -> i32 {
            self.0.wirehair_recover(out).code()
        }
        fn seeds(&self) -> (u64, u64, u64) {
            let s = self.0.testing_state();
            (s[9], s[10], s[11])
        }
        fn alloc(&self) -> [u64; 3] {
            let s = self.0.testing_state();
            [s[0], s[1], s[2]]
        }
    }

    #[rustfmt::skip]
    const EXPECTED: &[[u64; 8]] = &[
        [2, 0x0000000000000002, 0x0000000000000000, 0x0000000000003186, 0xad21b9d034cfea67, 0xe85f776d420d32a4, 2, 0x6ad86d864eed616d], // K 2 bb 1 last 1 pre false
        [2, 0x0000000000000002, 0x0000000000000000, 0x0000000000003186, 0xc5ee63ee9c8a733d, 0xe85f776d420d32a4, 2, 0x906756b15a75e45a], // K 2 bb 7 last 3 pre true
        [3, 0x0000000000000003, 0x000000000000000b, 0x0000000000007a0f, 0x91f37c939f2247e9, 0xad478a57b70ed784, 4, 0x7333b14bffa53abc], // K 3 bb 16 last 16 pre false
        [10, 0x0000000000000009, 0x0000000000000000, 0x00000000000096c6, 0x452659898827bd68, 0x57d35f03c16dc149, 16, 0x17ae1dd428210c13], // K 10 bb 33 last 1 pre true
        [64, 0x0000000000000013, 0x000000000000002e, 0x000000000000076e, 0xfc56b41faed42818, 0x15970bfb012362b4, 99, 0x79ca17137ddfc99f], // K 64 bb 100 last 99 pre false
        [128, 0x000000000000001e, 0x0000000000000001, 0x000000000000008a, 0x81adb0fcc716941f, 0x9b43ec9f5a1154f4, 192, 0x4dd09e1f83efc6af], // K 128 bb 1200 last 1200 pre false
        [128, 0x000000000000001e, 0x0000000000000001, 0x000000000000008a, 0x0959ab10e13f8b8b, 0x09c962ed26043d94, 180, 0x8ce825a5b9e76d13], // K 128 bb 1200 last 17 pre true
        [256, 0x000000000000001e, 0x0000000000000000, 0x0000000000000086, 0xbb8e4bd5b813711b, 0xde807c090fcae833, 372, 0x02a699bc4e5f2348], // K 256 bb 64 last 5 pre false
        [256, 0x000000000000001e, 0x0000000000000000, 0x0000000000000086, 0xc01c26db73226e1b, 0xe3ff3ff452e66ce4, 364, 0x228dbe43bf8c9986], // K 256 bb 64 last 64 pre true
        [1000, 0x0000000000000032, 0x00000000000000ef, 0x00000000000000a8, 0x1d4733ce30ea47d0, 0x847e4519ae5a20f8, 1442, 0x088f3e09af725352], // K 1000 bb 8 last 3 pre false
        [3000, 0x000000000000003e, 0x0000000000000008, 0x00000000000000be, 0x6b09c86a3fb0fe8c, 0x9e7ac9b417a0d0c5, 4350, 0x155caaddaa1ed432], // K 3000 bb 16 last 9 pre false
        [3000, 0x000000000000003e, 0x0000000000000008, 0x00000000000000be, 0x34743298f91f4cbe, 0xae7a7eeaea134809, 4325, 0x47ba0fc058866404], // K 3000 bb 16 last 16 pre true
        [32000, 0x00000000000000be, 0x0000000000000004, 0x0000000000000051, 0xa2f2b7e13188cf8a, 0x1d22f2fa6c14957b, 46449, 0x934917a50660ae02], // K 32000 bb 4 last 1 pre false
        [32000, 0x00000000000000be, 0x0000000000000004, 0x0000000000000051, 0x08139196ba461cfe, 0x9cffe664a566a037, 46138, 0xa6f572174d84c0cf], // K 32000 bb 4 last 4 pre true
        [64000, 0x000000000000015a, 0x0000000000000002, 0x0000000000000060, 0x98fe1144513ae57f, 0xb0864c6aaf129544, 92289, 0xa5f663f7ea22a4eb], // K 64000 bb 2 last 1 pre false
        [64000, 0x000000000000015a, 0x0000000000000002, 0x0000000000000060, 0x0813b6ea731cf4d2, 0xad85f378fab68da1, 92502, 0x25ed69144f946202], // K 64000 bb 1 last 1 pre true
    ];

    #[test]
    fn matches_cpp_fixtures() {
        assert_eq!(CASES.len(), EXPECTED.len());
        for (&(k, bb, last, pre), e) in CASES.iter().zip(EXPECTED) {
            assert_eq!(e[0], k as u64);
            let got = fixture::<Rs>(k, bb, last, pre);
            assert_eq!(got[..], e[1..], "K {k} bb {bb} last {last} pre {pre}");
        }
    }
}
