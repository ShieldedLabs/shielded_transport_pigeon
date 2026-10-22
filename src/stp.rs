#![allow(unsafe_code)]
#![allow(unused_variables, unused_mut, unused_imports, unused_macros, unused_assignments)]
#[cfg(feature = "research_budget_diagnostic")]
use crate::budget_diagnostic as diag;
use std::collections::{HashMap, VecDeque};
use crate::{blake3, helpers::noise as snow};


// magic1 dispatches an entire handshake/address-material interpretation, not
// just a hash/cipher suite. The current implementations below remain hardcoded
// two-flight Noise IK with raw 32-byte X25519 address keys (or test plaintext).
// A future selector may use address material such as a key hash and a different
// number/size of flights; it must specify resolution, transcript authentication,
// bounded chunking/reassembly, and immutable flight retransmission. Completion
// must supply authenticated peer identity, transcript binding and directional
// packet protection satisfying the full-nonce/rekey contract below. This is a
// design boundary, not an implemented handshake trait, PQ scheme or discovery.
// Bit zero of each six-byte selector must be one for ClientHello dispatch.
pub const CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b: u64 = 0xa891_6e3c_54d7;
pub const CONNECT_MAGIC1_PLAIN_TEXT: u64 = 0x6d43_b2f8_091b;
pub fn crypto_string_from_connect_magic1(magic: u64) -> Option<&'static str> {
    match magic {
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b => Some("Noise_IK_25519_ChaChaPoly_BLAKE2b"),
        CONNECT_MAGIC1_PLAIN_TEXT => Some("plaintext"),
        _ => None,
    }
}

pub const PROTOCOL_VERSION: u16 = 6; // RESEARCH profile 6: compact counters and key phase
// Profile and fixed wire/resource bounds are selected by magic1, not advertised.
pub const MAGIC2_BLOCK_SIZE: usize = 1 + 32 * 8;
const SERVER_HELLO_PAYLOAD_LEN: usize = 8;

pub const MAGIC2_APP_CROSSLINK: u64 = 0x5d747212563144d9;
const SERVER_SUPPORTED_MAGIC2: &[u64] = &[MAGIC2_APP_CROSSLINK];

pub fn build_magic2_client_block() -> [u8; MAGIC2_BLOCK_SIZE] {
    let mut block = [0u8; MAGIC2_BLOCK_SIZE];
    block[0] = 1;
    store_u64(&mut block[1..9], MAGIC2_APP_CROSSLINK);
    block
}

/// Server picks the first client-offered magic2 that the server supports. Returns None if no match.
/// Also validates that all slots beyond `count` are zeroed.
pub fn negotiate_magic2(client_block: &[u8]) -> Option<u64> {
    if client_block.len() != MAGIC2_BLOCK_SIZE { return None; }
    let count = client_block[0] as usize;
    if count == 0 || count > 32 { return None; }
    // Validate that padding beyond the count is all zeros.
    for i in count..32 {
        let offset = 1 + i * 8;
        if load_u64(&client_block[offset..offset + 8]) != 0 { return None; }
    }
    for i in 0..count {
        let offset = 1 + i * 8;
        let magic2 = load_u64(&client_block[offset..offset + 8]);
        if SERVER_SUPPORTED_MAGIC2.contains(&magic2) {
            return Some(magic2);
        }
    }
    None
}

/// Client validates server's chosen magic2 was in the list we sent.
pub fn validate_magic2(magic2: u64) -> bool {
    let block = build_magic2_client_block();
    let count = block[0] as usize;
    for i in 0..count {
        let offset = 1 + i * 8;
        if load_u64(&block[offset..offset + 8]) == magic2 { return true; }
    }
    false
}

pub const fn total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic: u64) -> Option<usize> {
    match magic {
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b => Some(CONNECTED_HEADER_SIZE+16),
        CONNECT_MAGIC1_PLAIN_TEXT => Some(CONNECTED_HEADER_SIZE),
        _ => None,
    }
}

/// Prefix (2), low 31 counter bits plus directional key-phase parity (4).
pub const CONNECTED_HEADER_SIZE: usize = 6;
const REKEY_AGE_NS: u64 = 600_000_000_000;
const PREVIOUS_KEY_NS: u64 = 10_000_000_000;

pub const STP_FRAGMENT_HEADER_SIZE: usize = 15;
const STP_WHOLE_HEADER_SIZE: usize = 3;

/// Self-delimiting frames. Padding is kind 255 and consumes the remaining tail.
/// Every other kind has a u16 body length, including all kind-specific metadata.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WireFrame<'a> {
    Whole(&'a [u8]),
    Plain { fin: bool, id: u64, offset: u32, data: &'a [u8] },
    Fec { kind: u64, id: u64, block_id: u32, message_len: usize, block_bytes: usize,
        segment: Option<FecSegment>, data: &'a [u8] },
    Unknown,
}
// Frozen duplication policy: first-kind prefix flags. Canonical packet identity is the
// original data nonce; a copy MUST use the immediately following data nonce.
// Both retain full independent authenticated nonces/ACKs/CE/loss accounting.

const TARGET_DUP_ORIGINAL:u8=0x10;

const TARGET_DUP_COPY:u8=0x20;

fn target_dup_kind(kind:u8)->Option<(u8,bool)> {
    let base=kind & 0x0f;
    ((1..=6).contains(&base) && matches!(kind & 0xf0,TARGET_DUP_ORIGINAL|TARGET_DUP_COPY))
        .then_some((base,kind & 0xf0==TARGET_DUP_COPY))
}

fn target_dup_counts(payload:&[u8])->(u64,bool) {
    let mut p=payload;let mut messages=0;let mut fec=false;
    while let Some((frame,n))=read_frame(p) {
        match frame {WireFrame::Whole(_)=>messages+=1,WireFrame::Fec{..}=>fec=true,_=>{}}
        p=&p[n..];
    }
    (messages,fec)
}
fn target_is_copy(_payload:&[u8])->bool {
    {return _payload.first().and_then(|&k|target_dup_kind(k)).is_some_and(|(_,copy)|copy);}

}
/// Lazy 64 KiB replay history, 262144 canonical data positions, same bound as
/// physical replay. Below its watermark identities are permanently stale (not
/// forgotten/reopened), so even arbitrarily skewed copies cannot redeliver.

fn target_dup_receive(history:&mut Option<Box<crate::sequence::ReceiveSequences>>,nonce:u64,payload:&[u8])->bool {
    let Some((_,copy))=payload.first().and_then(|&k|target_dup_kind(k)) else {return true};
    let Some(canonical)=nonce.checked_sub(u64::from(copy)) else {return false};
    history.get_or_insert_with(||Box::new(Default::default())).commit(canonical)
}
/// Atomically admit all packed wholes before committing their canonical nonce.
/// A memory-erased original cannot poison the copy's later admission. Only whole
/// delivery is suppressed: FEC/plain frames retain their existing identity dedup
/// and may still use the second packet to recover a resource-erased first arrival.

fn target_dup_prepare(history:&mut Option<Box<crate::sequence::ReceiveSequences>>,nonce:u64,payload:&[u8],
    budget:&std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>)->(bool,VecDeque<crate::receive_memory::Reservation>,bool) {
    let mut reservations=VecDeque::new();
    let Some((_,copy))=payload.first().and_then(|&k|target_dup_kind(k)) else {return (false,reservations,false)};
    let Some(canonical)=nonce.checked_sub(u64::from(copy)) else {return (true,reservations,false)};
    if history.as_ref().is_some_and(|h|!h.fresh(canonical)) {return (true,reservations,false);}
    let mut p=payload;
    while let Some((frame,n))=read_frame(p) {
        if let WireFrame::Whole(data)=frame {
            let Some(r)=budget.reserve(data.len()+256) else {return (true,VecDeque::new(),true)};
            reservations.push_back(r);
        }
        p=&p[n..];
    }
    (!target_dup_receive(history,nonce,payload),reservations,false)
}
pub(crate) fn read_frame(payload: &[u8]) -> Option<(WireFrame<'_>, usize)> {
    let kind = *payload.first()?;

    let kind=target_dup_kind(kind).map_or(kind,|(base,_)|base);
    if kind == 255 { return None; }
    let len = u16::from_le_bytes(payload.get(1..3)?.try_into().ok()?) as usize;
    let end = 3usize.checked_add(len)?;
    let body = payload.get(3..end)?;
    let frame = match kind {
        1 => WireFrame::Whole(body),
        2 | 3 => WireFrame::Plain { fin: kind == 3, id: load_u64(body.get(..8)?),
            offset: load_u32(body.get(8..12)?), data: body.get(12..)? },
        4 | 5 | 6 => {
            let segment = if kind == 6 { Some(FecSegment { root: load_u64(body.get(18..26)?),
                total: load_u32(body.get(26..30)?), offset: load_u32(body.get(30..34)?) }) } else { None };
            WireFrame::Fec { kind: match kind { 4 => STP_EXT_KIND_FEC, 5 => STP_EXT_KIND_GROUPED_FEC, _ => STP_EXT_KIND_SEGMENT_FEC },
                id: load_u64(body.get(..8)?), block_id: load_u32(body.get(8..12)?),
                message_len: load_u32(body.get(12..16)?) as usize, block_bytes: load_u16(body.get(16..18)?) as usize,
                segment, data: body.get(if kind == 6 { 34 } else { 18 }..)? }
        }
        _ => WireFrame::Unknown,
    };
    Some((frame, end))
}

/// Largest app message STP sends in one datagram at the guaranteed TU; bigger ones are split across datagrams.
pub const fn max_single_datagram_message_size(magic: u64) -> Option<usize> {
    match total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic) {
        Some(overhead) => Some(ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY - overhead - STP_WHOLE_HEADER_SIZE),
        None => None,
    }
}

pub const MIN_SECRET_KEY_SIZE: usize = 32;
pub const MIN_PUBLIC_KEY_SIZE: usize = 32;

// Quantum-resilient key sizes
pub const MAX_SECRET_KEY_SIZE: usize = 8000;
pub const MAX_PUBLIC_KEY_SIZE: usize = 8000;

pub fn new_keypair_from_connect_magic1(magic1: u64) -> Option<IdentityKeyPair> {
    if magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
        let mut ret = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b)?;
        ret.magic1 = CONNECT_MAGIC1_PLAIN_TEXT;
        return Some(ret);
    }
    if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
        let private = crate::helpers::crypto_random().ok()?;
        let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Some(IdentityKeyPair { magic1, private: private.to_vec(), public: public.to_vec() })
    } else { None }
}

pub fn new_keypair_from_connect_magic1_with_seed(magic1: u64, seed: [u8; 32]) -> Option<IdentityKeyPair> {
    if magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
        let mut ret = new_keypair_from_connect_magic1_with_seed(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b, seed)?;
        ret.magic1 = CONNECT_MAGIC1_PLAIN_TEXT;
        return Some(ret);
    }
    if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
        let mut rng = crate::crypto::rng::ChaCha20Rng::from_seed(seed);
        let mut private = [0; 32];
        rng.fill_bytes(&mut private);
        let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Some(IdentityKeyPair { magic1, private: private.to_vec(), public: public.to_vec() })
    } else { None }
}

pub fn b64(s: &[u8]) -> String {
    crate::encoding::encode(s)
}

pub fn fmt_magic1_pubkey_b64(magic1: u64, key: &Vec<u8>) -> String {
    let mut tmp = Vec::with_capacity(8 + key.len());
    tmp.extend_from_slice(&magic1.to_le_bytes()[..6]);
    tmp.extend_from_slice(&key);
    b64(&tmp)
}

#[derive(Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct STPAddress {
    pub ip: Ipv6Addr,
    pub port: u16,
    pub magic1: u64,
    pub key: Vec<u8>,
}
impl STPAddress {
    pub fn is_ipv4(&self) -> bool { self.ip.to_ipv4_mapped().is_some() }
    pub fn is_ipv6(&self) -> bool { self.ip.to_ipv4_mapped().is_none() }
    pub fn from(ip: Ipv6Addr, port: u16, kp: &IdentityKeyPair) -> Self { Self { ip, port, magic1: kp.magic1, key: kp.public.clone() } }
    pub fn connection_key(&self) -> ConnectionKey { ConnectionKey::from(self) }

    // Parse [ip]:port:magic1:key
    pub fn parse(addr: &str) -> Option<STPAddress> {
        let     addr           = addr.strip_prefix('[')?;
        let     (ip_str, rest) = addr.split_once("]:")?;
        let     ip: Ipv6Addr   = ip_str.parse().ok()?;
        let mut parts          = rest.splitn(3, ':');
        let     port: u16      = parts.next()?.parse().ok()?;
        let     b64_magic1     = parts.next()?; if b64_magic1.contains('=') { return None; }
        let     b64_key        = parts.next()?; if b64_key   .contains('=') { return None; }
        let     magic1_bytes   = crate::encoding::decode(b64_magic1)?; if magic1_bytes.len() != 6 { return None; }
        let     key            = crate::encoding::decode(b64_key)?;    if key.len() < MIN_PUBLIC_KEY_SIZE || key.len() > MAX_PUBLIC_KEY_SIZE { return None; }
        let mut buf            = [0u8; 8]; buf[..6].copy_from_slice(&magic1_bytes);
        let     magic1         = u64::from_le_bytes(buf); if magic1 & 1 == 0 { return None; }
        Some(STPAddress { ip, port, magic1, key })
    }

    pub fn to_connection_key(&self) -> ConnectionKey { self.into() }
}
impl Default for STPAddress {
    fn default() -> Self {
        Self {
            ip:     Ipv6Addr::UNSPECIFIED,
            port:   0,
            magic1: 0,
            key:    Vec::default(),
        }
    }
}
impl std::fmt::Debug for STPAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "[{:?}]:{}:{}:{}", self.ip, self.port, b64(&self.magic1.to_le_bytes()[..6]), b64(&self.key))
    }
}


pub fn fmt_byte_str(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    let n = usize::min(bytes.len(), f.precision().unwrap_or(bytes.len()));
    for i in 0..n { write!(f, "{:02x}", bytes[i])?; }
    Ok(())
}

pub fn fmt_byte_str_rev(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    let n = usize::min(bytes.len(), f.precision().unwrap_or(bytes.len()));
    for i in 0..n { write!(f, "{:02x}", bytes[n-(i+1)])?; }
    Ok(())
}

pub fn fmt_prefixed_byte_str(f: &mut std::fmt::Formatter<'_>, pre: &str, bytes: &[u8]) -> std::fmt::Result {
    write!(f, "{}", pre)?;
    fmt_byte_str(f, bytes)
}

pub fn fmt_prefixed_byte_str_rev(f: &mut std::fmt::Formatter<'_>, pre: &str, bytes: &[u8]) -> std::fmt::Result {
    write!(f, "{}", pre)?;
    fmt_byte_str_rev(f, bytes)
}

impl std::fmt::Debug for IdentityKeyPair {
    // Redacted, like Display: this type reaches a log whenever something prints a
    // struct that holds it -- `{:?}` on a connection, for one -- and a secret key
    // in a log is a secret key in every paste of that log. The old body also
    // dropped its `format!` on the floor, so the prefix never reached the writer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKeyPair {{ magic1: {}, private: REDACTED, public: \"", self.magic1)?;
        fmt_byte_str(f, &self.public)?;
        write!(f, "\" }}")
    }
}

// TODO: rename private key to secret key
#[derive(/* Copy, */ Clone, PartialEq, Eq, Hash)]
pub struct IdentityKeyPair {
    pub magic1: u64,
    pub private: Vec<u8>, // [u8; MAX_SECRET_KEY_SIZE],
    pub public:  Vec<u8>, // [u8; MAX_PUBLIC_KEY_SIZE],
}
// const_assert!(size_of::<IdentityKeyPair>().is_power_of_two());
impl std::fmt::Display for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "magic1: {} sk: REDACTED pk: {}", b64(&self.magic1.to_le_bytes()[..6]), b64(&self.public))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionKey {
    pub ip: Ipv6Addr,
    pub port: u16,
    pub key_15_bits: u16, // LSB is just always 1.
}
impl ConnectionKey {
    pub fn is_ipv4(&self) -> bool { self.ip.to_ipv4_mapped().is_some() }
    pub fn is_ipv6(&self) -> bool { self.ip.to_ipv4_mapped().is_none() }
}
impl From<&STPAddress> for ConnectionKey {
    fn from(a: &STPAddress) -> Self { Self { ip: a.ip, port: a.port, key_15_bits: load_u16(&a.key[0..2]) << 1 } }
}
impl Default for ConnectionKey {
    fn default() -> Self { Self { ip: Ipv6Addr::UNSPECIFIED, port: 0, key_15_bits: 0 } }
}

impl SliceWrite for ConnectionKey {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut o = 0;
        o += self.ip.octets().write_to(&mut buf[o..]);
        o += self.port       .write_to(&mut buf[o..]);
        o += self.key_15_bits.write_to(&mut buf[o..]);
        o
    }
}
impl SliceRead for ConnectionKey {
    fn read_from(buf: &mut &[u8]) -> Option<Self> {
        Some(Self {
            ip:          Ipv6Addr::from(<[u8; 16]>::read_from(buf)?),
            port:        SliceRead::read_from(buf)?,
            key_15_bits: SliceRead::read_from(buf)?,
        })
    }
}

// Connection-scoped, never-recycled identities. Leases bound sender retention,
// not wire identity lifetimes or receiver table positions.
#[derive(Debug)]
struct PackageAllocator {
    next: std::sync::atomic::AtomicU64,
    live: std::sync::Mutex<usize>,
}
impl PackageAllocator {
    fn new() -> Self { Self { next: std::sync::atomic::AtomicU64::new(0), live: std::sync::Mutex::new(0) } }
    fn load(&self, order: std::sync::atomic::Ordering) -> u64 { self.next.load(order) }
    fn allocate(self: &std::sync::Arc<Self>) -> Option<std::sync::Arc<PackageLease>> {
        let mut live = self.live.lock().unwrap();
        if *live >= 1024 { return None; }
        let id = self.next.fetch_update(std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed, |n| n.checked_add(1)).ok()?;
        *live += 1;
        Some(std::sync::Arc::new(PackageLease { allocator: self.clone(), id }))
    }
}
#[derive(Debug)]
struct PackageLease { allocator: std::sync::Arc<PackageAllocator>, id: u64 }
impl Drop for PackageLease {
    fn drop(&mut self) { *self.allocator.live.lock().unwrap() -= 1; }
}

/// Full-ID lookup into bounded storage, never `id % capacity`. On pressure the
/// completed/inactive identities retire first; a full live table refuses new IDs.
/// Retired identities never reopen; retained live identities may be older.
#[derive(Debug, Default)]
struct ReceiveIndex { slots: std::collections::BTreeMap<u64, usize>, floor: u64, roles: Vec<Option<ReceiveRole>> }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiveRole {
    Plain,
    Root { total: u32 },
    Fec { message_len: usize, block_bytes: usize, segment: Option<FecSegment> },
}
impl ReceiveIndex {
    fn get(&self, id: u64) -> Option<usize> { self.slots.get(&id).copied() }
    fn frame_is_stale(&self, frame: &WireFrame<'_>) -> bool {
        let stale = |id| id < self.floor && self.get(id).is_none();
        match frame {
            WireFrame::Plain { id, .. } => stale(*id),
            WireFrame::Fec { id, segment, .. } => stale(*id) || segment.is_some_and(|s| stale(s.root)),
            _ => false,
        }
    }
    // Identity metadata survives decoder/assembly retirement, until the ID itself
    // is permanently retired. Both tables share this one immutable role binding.
    fn claim(&mut self, id: u64, role: ReceiveRole) -> bool {
        let Some(index) = self.get(id) else { return false; };
        match self.roles[index] {
            Some(old) => old == role,
            None => { self.roles[index] = Some(role); true }
        }
    }
    fn admit_at(&mut self, id: u64, plain: &mut [ReassemblySlot], fec: &mut [FecRecvSlot], now_ns: u64, grace_ns: u64) -> Option<usize> {
        if id == u64::MAX { return None; }
        // Active identities may outlive thousands of newer completed messages.
        // The watermark forbids reopening retired IDs, not using retained ones.
        if let Some(index) = self.get(id) { return Some(index); }
        if id < self.floor { return None; }
        let index = if self.slots.len() < plain.len() { self.slots.len() }
            else {
                // Completed or already-erased state is cheap to retire. Never
                // erase recently ACKed live state just to admit a newer ID.
                let candidates = || self.slots.range(..id);
                let unused = |i: usize| plain[i].reservation.is_none() && plain[i].buf.is_empty()
                    && plain[i].received.is_empty() && plain[i].segment_parts.is_none()
                    && !fec[i].in_use();
                let last_active = |i: usize| plain[i].last_segment_ns.max(fec[i].last_active_ns());
                let (&retired, &index) = candidates().find(|&(_, &i)|
                    plain[i].completed || matches!(fec[i].state, FecRecvState::Done) || unused(i))
                    .or_else(|| candidates().filter(|&(_, &i)| now_ns.saturating_sub(last_active(i)) > grace_ns)
                        .min_by_key(|&(_, &i)| last_active(i)))?;
                self.slots.remove(&retired);
                self.floor = self.floor.max(retired.checked_add(1)?);
                if id < self.floor { return None; }
                plain[index] = ReassemblySlot::new();
                fec[index] = FecRecvSlot::default();
                index
            };
        if self.roles.len() <= index { self.roles.push(None); }
        self.roles[index] = None;
        self.slots.insert(id, index);
        Some(index)
    }
}

// Strict fair reservations. Leases survive moves into active rescue/suspended slots;
// no magazine borrows another's bytes or slots, so the connection total stays <=64 MiB/4096.
#[derive(Debug)]
struct RetentionQuota { byte_limit: usize, slot_limit: usize, used: std::sync::Mutex<(usize, usize)>, telemetry: std::sync::Arc<RetentionTelemetry> }
#[derive(Debug, Default)]
struct RetentionTelemetry {
    current: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}
impl RetentionQuota {
    fn new(count: usize) -> Self { Self { byte_limit: FEC_RETAIN_SOURCE_BYTES / count, slot_limit: FEC_RETAIN_SLOTS / count, used: std::sync::Mutex::new((0, 0)), telemetry: Default::default() } }
    fn acquire(self: &std::sync::Arc<Self>, bytes: usize) -> Option<std::sync::Arc<RetentionLease>> {
        let mut used = self.used.lock().unwrap();
        if bytes > self.byte_limit.saturating_sub(used.0) || used.1 >= self.slot_limit { return None; }
        used.0 += bytes; used.1 += 1;
        use std::sync::atomic::Ordering::Relaxed;
        let current = self.telemetry.current.fetch_add(bytes, Relaxed) + bytes;
        self.telemetry.peak.fetch_max(current, Relaxed);
        Some(std::sync::Arc::new(RetentionLease { quota: self.clone(), bytes }))
    }
}
#[derive(Debug)]
struct RetentionLease { quota: std::sync::Arc<RetentionQuota>, bytes: usize }
impl Drop for RetentionLease {
    fn drop(&mut self) { let mut used = self.quota.used.lock().unwrap(); used.0 -= self.bytes; used.1 -= 1; self.quota.telemetry.current.fetch_sub(self.bytes, std::sync::atomic::Ordering::Relaxed); }
}

// Lightweight logical-message ownership. The selected owner is projected into
// the legacy fields; FIFO, loss profile and connection tag rings are NEVER copied.
// Segmented roots, completed segments and ready repairs move together.
#[derive(Debug)]
struct MessageSendContext {
    current_dscp: Dscp,
    partial_send_slot: Option<(Vec<u8>, u32)>,
    send_package_id: u64,
    package_lease: Option<std::sync::Arc<PackageLease>>,
    fec_send_slot: Option<FecSendSlot>,
    p4_open: bool,
    p4_closing: bool,
    p4_tail_refreshed: bool,
    segmented_send: Option<SegmentedSend>,
    fec_retained: HashMap<u64, RetainedFecSlot>,
    retained_bytes: usize,
    rescue_ready: VecDeque<u64>,
    rescue_ready_count: usize,
    retained_next_prune_ns: u64,
    retained_last_prune_ns: u64,
    fec_rescue_package: Option<u64>,
    fec_suspended: Option<FecSendSlot>,
    slipstream_head: bool,
    slipstream_eligible: Option<bool>,
    slipstream_started: bool,
    logical_root: u64,
    logical_tag: u64,
    logical_len: usize,
    category_eligible: Option<bool>,
    budget_root: Option<std::sync::Arc<std::sync::Mutex<BudgetRoot>>>,
}
impl MessageSendContext {
    fn empty() -> Self {
        Self { current_dscp: Dscp::BestEffort, partial_send_slot: None,
            send_package_id: 0, package_lease: None, fec_send_slot: None,
            p4_open: false, p4_closing: false, p4_tail_refreshed: false,
            segmented_send: None, fec_retained: HashMap::new(), retained_bytes: 0,
            rescue_ready: VecDeque::new(), rescue_ready_count: 0,
            retained_next_prune_ns: 0, retained_last_prune_ns: 0,
            fec_rescue_package: None, fec_suspended: None,
            slipstream_head: true, slipstream_eligible: None, slipstream_started: false,
            logical_root: 0, logical_tag: 0, logical_len: 0, category_eligible: None, budget_root: None }
    }
    fn source_bytes(&self) -> usize {
        source_owner_bytes(self.partial_send_slot.as_ref(), self.segmented_send.as_ref(),
            self.fec_send_slot.as_ref(), self.fec_suspended.as_ref(), &self.fec_retained)
    }
    fn owns_package(&self, package: u64) -> bool {
        self.send_package_id == package || self.fec_rescue_package == Some(package) ||
            self.fec_retained.contains_key(&package)
    }
    fn swap(&mut self, q: &mut UnreliableSendBuffer) {
        macro_rules! swap { ($($f:ident),*) => { $(std::mem::swap(&mut self.$f, &mut q.$f);)* }; }
        swap!(current_dscp, partial_send_slot, send_package_id, package_lease,
            fec_send_slot, p4_open, p4_closing, p4_tail_refreshed, segmented_send,
            fec_retained, retained_bytes, rescue_ready, rescue_ready_count,
            retained_next_prune_ns, retained_last_prune_ns, fec_rescue_package,
            fec_suspended, slipstream_head, slipstream_eligible, slipstream_started,
            logical_root, logical_tag, logical_len, category_eligible, budget_root);
    }
}

// Shared research policy: [half RTT, two RTTs] of planned full-TU packets at
// the queue's current fair-share pps. set_rate is full *payload* TU bytes/s;
// wire TU/rate scale identically. Zero context has no special startup category.
fn medium_duration_class(packets: u32, payload_len: usize, rate: u64, rtt: u64) -> &'static str {
    let duration = packets as u128 * payload_len as u128 * 1_000_000_000;
    let horizon = rtt as u128 * rate as u128;
    if packets == 0 || horizon == 0 { "other" }
    else if duration * 2 < horizon { "short" }
    else if duration > horizon.saturating_mul(2) { "long" } else { "eligible" }
}

// Metadata-only whole-logical P4 initial train. Balanced segmentation has at
// most two distinct range lengths; no source copy, codec or worker for estimates.
// Initial P4 really plans K + min(2,K) per range. Later real plans stay on slots.
// `cap` is Some(unit cap) for a segmented root (37-byte kind 6 header, the
// unstarted remainder partitioned exactly as start_segment will at that cap),
// None for one ordinary unit (21-byte header).
fn p4_new_train(total: usize, offset: usize, payload: usize, cap: Option<usize>) -> (u32, u32) {
    if total <= payload.saturating_sub(STP_WHOLE_HEADER_SIZE) || offset >= total { return (0, 0); }
    let header = if cap.is_some() { STP_SEGMENT_FEC_HEADER_SIZE } else { STP_FEC_FRAGMENT_HEADER_SIZE };
    let Some(block) = payload.checked_sub(header).filter(|b| *b > 0) else { return (0, 0); };
    let rem = total - offset;
    let (count, short, long) = balanced_parts(rem, cap.unwrap_or(rem));
    let unit = |len| crate::fec::MessageLayout::new(len, if cap.is_some() { segment_width(len, block) } else { block }).map_or((0, 0), |l| {
        let k = l.k as u32;
        (k, l.round_plan(k.saturating_add(2.min(k))))
    });
    let (k, n) = unit(short);
    let (long_k, long_n) = if long.1 == 0 { (0, 0) } else { unit(long.0) };
    let short_count = (count - long.1) as u32;
    (short_count * k + long.1 as u32 * long_k, short_count * n + long.1 as u32 * long_n)
}
fn source_bonus(k: u64, percent: u32) -> u32 { (k * percent as u64).div_ceil(100) as u32 }
fn owner_remaining_packets(active: Option<&FecSendSlot>, suspended: Option<&FecSendSlot>,
    retained: &HashMap<u64, RetainedFecSlot>, giant: Option<&SegmentedSend>, payload: usize,
    initial: bool, percent: u32, bonus_eligible: bool) -> u32 {
    // fill_tier forbids active FEC as tail fillers: one symbol is one actual
    // emitted packet even after TU growth. Never divide by hypothetical packing.
    let mut packets = active.into_iter().chain(suspended).chain(retained.values().map(|r| &r.slot))
        .map(|f| {
            let n = if initial && f.repair_accounting.category_bonus > 0 { f.repair_accounting.unbonused_n } else { f.n };
            n.saturating_sub(f.next_id)
        }).sum::<u32>();
    if let Some(g) = giant {
        let plan = g.plan_ks.lock().unwrap();
        let (k, n) = p4_new_train(g.message.len(), g.offset, payload, Some(plan.cap));
        packets = packets.saturating_add(n);
        if !initial && bonus_eligible {
            // Every started unit lies below g.offset (the next unstarted byte).
            let prefix_k: u64 = plan.started_k();
            packets = packets.saturating_add(source_bonus(prefix_k + k as u64, percent).saturating_sub(source_bonus(prefix_k, percent)));
        }
    }
    packets
}

// Unique source allocations, including segment copies and the original giant.
// Reserve future segment copies too: queue_bytes_filled alone falls as segments
// finish while P4 may still own their codecs. Encoder Arc aliases count once.
fn source_owner_bytes(plain: Option<&(Vec<u8>, u32)>, giant: Option<&SegmentedSend>,
    active: Option<&FecSendSlot>, suspended: Option<&FecSendSlot>, retained: &HashMap<u64, RetainedFecSlot>) -> usize {
    let mut seen = Vec::new();
    let mut bytes = plain.map_or(0, |(m, _)| m.capacity());
    let mut charge = |m: &std::sync::Arc<Vec<u8>>| {
        let ptr = std::sync::Arc::as_ptr(m);
        if !seen.contains(&ptr) { seen.push(ptr); bytes += m.capacity(); }
    };
    if let Some(g) = giant { charge(&g.message); }
    for f in active.into_iter().chain(suspended).chain(retained.values().map(|r| &r.slot)) { charge(&f.message); }
    bytes + giant.map_or(0, |g| g.message.len().saturating_sub(g.offset))
}

/// One association's share of a `queued_send_bytes` counter for one queue. It is
/// queue-global, never swapped with an interleaved MessageSendContext. Admission
/// takes over the ring's charge without touching the counter. Bytes retired at the
/// existing `queue_bytes_filled` decrements stay counted until DATA through the
/// last packet this queue framed into is accepted by the socket; Drop (cancel,
/// timeout, replacement) uncounts only what this association still owns.
#[derive(Debug, Default)]
struct QueuedLedger {
    cell: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    owned: u64,
    unretired: u64,
    staged: u64,
    staged_seq: u64,
    framed: Option<u64>,
    committed: Option<u64>,
}
impl QueuedLedger {
    fn admit(&mut self, charge: crate::pump::port::lockfree::Charge) {
        let (cell, bytes) = charge.transfer();
        debug_assert!(self.cell.as_ref().is_none_or(|c| std::sync::Arc::ptr_eq(c, &cell)));
        self.cell.get_or_insert(cell);
        self.owned += bytes;
        self.unretired += bytes;
    }
    fn retire(&mut self, len: usize) {
        let bytes = (len as u64).min(self.unretired);
        if bytes == 0 { return; }
        self.unretired -= bytes;
        match self.framed {
            // A retirement after its packet already committed must not wait for
            // DATA that may never come.
            Some(seq) if self.committed.is_none_or(|c| c < seq) => {
                self.staged += bytes;
                self.staged_seq = self.staged_seq.max(seq);
            }
            _ => self.release(bytes),
        }
    }
    fn commit(&mut self, seq: u64) {
        self.committed = Some(seq);
        if self.staged != 0 && seq >= self.staged_seq {
            let bytes = std::mem::take(&mut self.staged);
            self.release(bytes);
        }
    }
    fn release(&mut self, bytes: u64) {
        self.owned -= bytes;
        if let Some(cell) = &self.cell { cell.fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed); }
    }
}
impl Drop for QueuedLedger {
    fn drop(&mut self) { if self.owned != 0 { self.release(self.owned); } }
}

#[derive(Debug)]
pub struct UnreliableSendBuffer {
    #[cfg(feature = "research_budget_diagnostic")]
    diagnostic_last: Option<diag::Layout>,
    queued_ledger: QueuedLedger,
    // A time based capacity constrained by byte counts.
    // The queue should for example probably have a minimum byte size twice that of your largest message.
    pub target_queue_size_us: u32,
    pub min_queue_size_bytes: u32,
    pub max_queue_size_bytes: u32,

    /// Message bytes (not wire bytes) of the queued messages plus the one being sent.
    pub queue_bytes_filled: usize,
    pub message_queue: VecDeque<(Dscp, Vec<u8>)>,
    current_dscp: Dscp,
    packet_dscp: Option<Dscp>,
    target_dup_no_chop:bool,
    pub partial_send_slot: Option<(Vec<u8>, u32)>,
    pub send_package_id: u64,
    package_allocator: Option<std::sync::Arc<PackageAllocator>>,
    package_lease: Option<std::sync::Arc<PackageLease>>,
    pub current_bytes_per_second: u64,
    /// Queue-capacity estimate in parts per million, updated from the adaptive policy.
    /// This is accounting, never a fixed-parity FEC selection.
    fec_capacity_overhead_ppm: u32,
    /// The FEC-coded message being sent (instead of `partial_send_slot`), if any.
    pub fec_send_slot: Option<FecSendSlot>,
    segmented_send: Option<SegmentedSend>,
    /// Adaptive FEC: per-connection loss estimate. When Some, each new message gets the repair
    /// blocks this estimate calls for (and `fec_capacity_overhead_ppm` is only a nonzero summary of it,
    /// used for the queue capacity). Maintained by the network thread.
    fec_adaptive: Option<crate::fec_adapt::FecAdaptiveState>,
    /// Sequence number of the packet the next fragment goes into (set by the network thread), so
    /// an FEC message knows which packets are its own when they are declared lost.
    pub next_packet_seq: u64,
    /// Sparse-paged nonce ring: package id (64), symbol count (32), first ordinal (32).
    /// Same fixed horizon; ACK/probe/keepalive slots are empty and do not allocate.
    fec_packet_tags: Option<PacketTags>,
    // Encoders awaiting packet outcome feedback, outside the application send queue.
    fec_retained: HashMap<u64, RetainedFecSlot>,
    retention_quota: std::sync::Arc<RetentionQuota>,
    retained_bytes: usize,
    // P4 keeps completed segments only inside this FIFO message's lifetime.
    // These are not post-message retention and never consume the rescue quota.
    p4_open: bool,
    p4_closing: bool,
    p4_tail_refreshed: bool,
    rescue_ready: VecDeque<u64>,
    rescue_ready_count: usize,
    retained_next_prune_ns: u64,
    retained_last_prune_ns: u64,
    fec_extra_packet_tags: HashMap<u64, Vec<u128>>,
    fec_rescue_package: Option<u64>,
    fec_suspended: Option<FecSendSlot>,
    fec_now_ns: u64,
    fec_rtt_ns: u64,
    // RESEARCH adaptive units: initial TU assessment unresolved, so a new
    // root caps its coded units at ADAPTIVE_PREFIX_CAP. Fixtures default settled.
    tu_unresolved: bool,
    // RESEARCH adaptive exposure: connection R/T/Q/E copied every prepare tick.
    exposure: ExposureSnapshot,
    /// Cumulative source/repair progress snapshots, when recording is enabled (Some).
    pub fec_record: Option<Vec<crate::fec_adapt::FecMessageInfo>>,
    // The fields above are the selected context's legacy projection. W1 never
    // swaps it. Only small ordinary contexts are admitted to this rolling ring.
    interleave_width: usize,
    interleave_parked: VecDeque<MessageSendContext>,
    interleave_last_packet: Option<u64>,
    slipstream: bool,
    slipstream_head: bool,
    slipstream_eligible: Option<bool>,
    slipstream_turn_head: bool,
    slipstream_packet: Option<u64>,
    // Research counters: decisions and real nonempty per-lane packet service.
    slipstream_classified: u64,
    slipstream_eligible_heads: u64,
    slipstream_head_packets: u64,
    slipstream_follow_packets: u64,
    slipstream_started: bool,
    logical_root: u64,
    logical_tag: u64,
    logical_len: usize,
    slipstream_info: SlipstreamInfo,
    slipstream_trace: Option<crate::loss_trace::SlipstreamWriter>,
    slipstream_queue: usize,
    slipstream_payload_len: usize,
    category_bonus_percent: u32,
    category_eligible: Option<bool>,
    category_bonus_messages: u64,
    category_bonus_repairs: u64,
    event_repair_q: u32,
    event_root_latched: bool,
    event_repair: EventRepairInfo,
    event_sink: std::sync::Arc<EventSink>,
    commit_marks: std::collections::BTreeMap<u64, Vec<CommitMark>>,
    budget_root: Option<std::sync::Arc<std::sync::Mutex<BudgetRoot>>>,
    budget_sink: std::sync::Arc<std::sync::Mutex<BudgetBaseInfo>>,
    target_root_sequence:u64,
    target_state:crate::target_validation::RiskState,
}

/// Sender state of one FEC-coded message: blocks 0..k-1 are slices of the message itself and
/// need no encoder; blocks k..n-1 are repair blocks from a Wirehair encoder, which is built on
/// a helper thread while the source blocks go out (creating one costs ~4 us per block, 155 ms
/// for a 48 MB message, too long to stall the network thread).
pub struct FecSendSlot {
    #[cfg(feature = "research_budget_diagnostic")]
    diagnostic: Option<diag::Layout>,
    segment: Option<FecSegment>,
    root_lease: Option<std::sync::Arc<PackageLease>>,
    plan_ks: Option<PlanKs>,
    retention_lease: Option<std::sync::Arc<RetentionLease>>,
    retain_limit: usize,
    package_lease: Option<std::sync::Arc<PackageLease>>,
    pub dscp: Dscp,
    pub message: std::sync::Arc<Vec<u8>>,
    pub block_bytes: usize,
    pub k: u32,
    pub n: u32,
    pub next_id: u32,
    encoder: FecEncoderState,
    block_buf: Vec<u8>,
    /// Sequence number of the message's first packet, own packets declared lost since, the block
    /// count planned at the start, and the loss rate the plan was sized for.
    pub first_seq: u64,
    pub lost: u32,
    pub group_lost: Vec<u32>,
    pub n_planned: u32,
    pub loss_estimate: f64,
    finalized_symbols: u32,
    send_started_ns: u64,
    original_send_duration_ns: Option<u64>,
    repair_policy: crate::fec_adapt::RepairPolicy,
    rescue_rounds: u8,
    retained_until_ns: Option<u64>,
    original_symbols: Option<u32>,
    repair_accounting: RepairAccounting,
}

#[derive(Debug, Default)]
struct RepairAccounting {
    planned_topup: u32,
    sent_topup: u32,
    sent_tail: u32,
    unbonused_n: u32,
    category_bonus: u32,
    /// p4-event-repair: immutable per-group B_g = ceil(q*K_g/100), empty = no grant (baseline path unchanged).
    event_bonus: Vec<u32>,
    /// First successful DATA commit carrying one of this slot's source ordinals: (seq, exact sent_ns).
    first_source_commit: Option<(u64, u64)>,
    /// Event-attributable planned ordinal ranges [a, b), merged, bounded by EVENT_IDS_CAP.
    event_ids: Vec<(u32, u32)>,
    event_planned: u32,
    /// Ranges not recorded because EVENT_IDS_CAP was reached.
    event_ids_overflow: u32,
    /// Shared with the owning queue once granted: every later refresh's attribution reaches the public counters.
    event_sink: Option<std::sync::Arc<EventSink>>,
    /// p4-burst-base B1: immutable initial base b_g per codec group (empty = baseline/B0 path).
    base_b: Vec<u32>,
    /// B1: planned total repairs per group (uniform rounds), monotone lower bound; never refunded.
    base_r: u32,
    /// B1, internal only (no public stat): some plan of this slot hit the cap Kg or the iteration budget.
    base_cap_bound: bool,
    // C1 only. Segment allowance is shared across TU restarts; reservations never refunded.
    budget: Option<std::sync::Arc<std::sync::Mutex<BudgetSegment>>>,
    data_anchor: Option<(u64, u64)>,
    budget_demand: u64,
    budget_shortfall: u64,
    budget_known_shortfall: u64,
    budget_limited: bool,
    budget_invalid_anchor: bool,
    #[cfg(feature="research_budget_diagnostic")]
    diagnostic_last_demand: Option<u32>,
}

/// Counters written from inside FecSendSlot::refresh_plan (any refresh path: loss, source completion, tail, rescue).
#[derive(Debug, Default)]
struct EventSink { planned: std::sync::atomic::AtomicU64, ids_overflow: std::sync::atomic::AtomicU64, overflow: std::sync::atomic::AtomicU64 }

/// RESEARCH-ONLY p4-event-repair evidence. Counters only; with q = 0 nothing is granted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventRepairInfo {
    /// Accepted (CC actually cut) events delivered to the sender, by kind.
    pub accepted_early: u64,
    pub accepted_timeout: u64,
    pub accepted_ce: u64,
    /// Accepted events lost to the bounded per-connection event queue (must be 0).
    pub accepted_dropped: u64,
    /// Accepted events while no P4 root was open / root closing (sealed) / root already granted.
    pub skip_closed: u64,
    pub skip_latched: u64,
    /// Accepted events with an open root but no slot whose first source commit precedes the evidence.
    pub skip_unexposed: u64,
    pub roots_granted: u64,
    pub slots_granted: u64,
    /// Exposed slots of a granting event not qualifying (no prior source commit / failed encoder).
    pub slots_unqualified: u64,
    /// Sum of B_g over granted groups (immutable allowance).
    pub grant_symbols: u64,
    /// LOCAL attribution only (not a counterfactual network cost): ordinals that a refresh of a granted slot planned
    /// above the same refresh computed with B_g = 0; all later refreshes included. `emitted` = such ordinals
    /// committed as DATA.
    pub planned: u64,
    pub emitted: u64,
    /// Every committed DATA FEC repair ordinal (>= k), all slots, regardless of attribution (any arm, incl. E0).
    pub repairs_emitted: u64,
    /// Accepted cuts whose ORIGINAL send history was unknown (0/MAX): CC cut kept, no repair notification.
    pub missing_anchor: u64,
    /// Prepared event-ordinal marks whose packet was never committed (abandoned before commit).
    pub marks_abandoned: u64,
    /// Ordinal-range overflow (attribution incomplete; measurement invalid if nonzero).
    pub ids_overflow: u64,
    /// Retained slots that became ready (rescue_ready) because of a grant.
    pub ready_added: u64,
    /// Nonzero iff any counter saturated while merging (measurement invalid, fail closed).
    pub counter_overflow: u64,
}
impl EventRepairInfo {
    pub fn merge(&mut self, o: EventRepairInfo) {
        let mut of = self.counter_overflow.max(o.counter_overflow);
        let mut add = |a: &mut u64, b: u64| { *a = a.checked_add(b).unwrap_or_else(|| { of = 1; u64::MAX }); };
        add(&mut self.accepted_early, o.accepted_early); add(&mut self.accepted_timeout, o.accepted_timeout);
        add(&mut self.accepted_ce, o.accepted_ce); add(&mut self.accepted_dropped, o.accepted_dropped);
        add(&mut self.skip_closed, o.skip_closed); add(&mut self.skip_latched, o.skip_latched);
        add(&mut self.skip_unexposed, o.skip_unexposed); add(&mut self.roots_granted, o.roots_granted);
        add(&mut self.slots_granted, o.slots_granted); add(&mut self.slots_unqualified, o.slots_unqualified);
        add(&mut self.grant_symbols, o.grant_symbols); add(&mut self.planned, o.planned); add(&mut self.emitted, o.emitted);
        add(&mut self.marks_abandoned, o.marks_abandoned); add(&mut self.ids_overflow, o.ids_overflow);
        add(&mut self.ready_added, o.ready_added); add(&mut self.repairs_emitted, o.repairs_emitted);
        add(&mut self.missing_anchor, o.missing_anchor);
        self.counter_overflow = of;
    }
}
/// RESEARCH-ONLY C1 sender budget audit, cumulative; C0 is all zero. Coding credits are
/// first-layout source K per distinct segment, never TU retries or padded/UDP byte counts.
/// Demand/shortfalls sum per-slot HIGH-WATER increments, not repeated refresh requests.
/// Reservations include abandoned TU plans, are never refunded, and bound actual repair commits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetBaseInfo {
    pub roots: u64,
    pub source_symbols: u64,
    pub repair_limit: u64,
    pub demand_repairs: u64,
    pub planned_repairs: u64,
    pub sources_emitted: u64,
    pub repairs_emitted: u64,
    #[cfg(feature="research_target_validation")] pub postseal_repairs_emitted:u64,
    #[cfg(feature="research_target_validation")] pub postseal_owners_reopened:u64,
    pub cap_limited_roots: u64,
    pub cap_limited_slots: u64,
    pub cap_shortfall: u64,
    pub known_loss_shortfall: u64,
    pub invalid_anchor_fallbacks: u64,
    pub counter_overflow: u64,
}
impl BudgetBaseInfo {
    pub fn merge(&mut self, other: Self) {
        let mut overflow = self.counter_overflow.max(other.counter_overflow);
        macro_rules! add { ($($f:ident),*) => { $(self.$f = self.$f.checked_add(other.$f).unwrap_or_else(|| { overflow = 1; u64::MAX });)* }; }
        add!(roots, source_symbols, repair_limit, demand_repairs, planned_repairs, sources_emitted, repairs_emitted, cap_limited_roots, cap_limited_slots, cap_shortfall, known_loss_shortfall, invalid_anchor_fallbacks);
        self.counter_overflow = overflow;
    }
}
#[derive(Debug)]
struct BudgetRoot {
    sink: std::sync::Arc<std::sync::Mutex<BudgetBaseInfo>>,
    limited: bool,
    /// Ceiling frozen at the first layout of the logical root, including later segments/TU retries.
    cap_percent: u32,
    target_draw:u64,
    target_tail_applied:bool,
    target_risk:crate::target_validation::RiskAdmission,
    target_ordinal:u64,
    target_app_tag:[u8;8],
    #[cfg(feature="research_target_validation")] target_owners:Vec<crate::target_validation::Owner>,
    target_state:crate::target_validation::RiskState,
    target_source_symbols:u64,
}
#[derive(Debug)]
struct BudgetSegment {
    target_plans:Vec<crate::target_validation::Plan>,
    #[cfg(feature="research_target_validation")] target_owner:Option<crate::target_validation::Owner>,
    target_prior_losses:u32,
    target_tail_added:u32,
    #[cfg(feature="research_budget_diagnostic")] diagnostic_owner_generation:u64,
    #[cfg(feature="research_budget_diagnostic")] diagnostic_original_k:u32,
    #[cfg(feature="research_budget_diagnostic")] diagnostic_sources_committed:u64,
    #[cfg(feature="research_budget_diagnostic")] diagnostic_counter_overflow:bool,
    root: std::sync::Arc<std::sync::Mutex<BudgetRoot>>,
    limit: u32,
    reserved: u32,
    emitted: u64,
}

/// An ACCEPTED congestion cut (the CC state actually changed), with its exact evidence anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedCcEvent { pub kind: u8, pub evidence_seq: u64, pub evidence_sent_ns: u64, pub feedback_ns: u64 }
pub const CC_EVENT_EARLY: u8 = 0;
pub const CC_EVENT_TIMEOUT: u8 = 1;
pub const CC_EVENT_CE: u8 = 2;
const CC_EVENT_QUEUE_CAP: usize = 64;
const EVENT_IDS_CAP: usize = 64;
#[derive(Debug, Default, Clone)]
struct CommitMark { event: u32, repair: u32, first_source: bool, package: u64,
    source: u32, budget: Option<std::sync::Arc<std::sync::Mutex<BudgetSegment>>> }

// Fixed per-connection retained-source budget and slot bound. Codec arenas add their
// implementation overhead; giant messages exceeding the budget keep the original policy.
const FEC_RETAIN_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const FEC_RETAIN_SLOTS: usize = 4096;
#[derive(Debug)]
struct RetainedFecSlot { slot: FecSendSlot, package: u64, expires_ns: u64 }

impl FecSendSlot {

    fn rescue_plan(&mut self) {
        if !self.repair_policy.feedback() || self.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound { return; }
        if self.finalized_symbols < self.next_id { return; }
        if self.repair_policy != crate::fec_adapt::RepairPolicy::Reliability {
            // Feedback may arrive DURING a rescue. Finish the accepted round before
            // applying its round budget; never truncate a partially emitted third round.
            if self.next_id < self.n || self.rescue_rounds >= 3 { return; }
        }
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let groups = layout.groups as u32;
        let repairs = self.next_id.saturating_sub(self.k);
        let mut deficit = 0;
        for group in 0..layout.groups {
            let k = layout.group(group).1 as u32;
            let sent = k + repairs / groups + u32::from((group as u32) < repairs % groups);
            // Two received extra symbols cover the fountain decoder's small rank deficit.
            deficit = deficit.max((k + 2).saturating_sub(sent.saturating_sub(self.group_lost[group])));
        }
        let n = self.n.max(self.next_id.saturating_add(deficit * groups));
        self.n = if self.repair_policy == crate::fec_adapt::RepairPolicy::Reliability { n }
            else { n.min(self.k.saturating_mul(2).saturating_add(2 * groups)) };
    }
    fn event_attribute(&mut self, from: u32, to: u32) {
        let acc = &mut self.repair_accounting;
        use std::sync::atomic::Ordering::Relaxed;
        let from = acc.event_ids.last().map_or(from, |&(_, b)| from.max(b));
        if from >= to { return; }
        acc.event_planned = acc.event_planned.saturating_add(to - from);
        if let Some(sink) = &acc.event_sink {
            let add = (to - from) as u64;
            if sink.planned.fetch_update(Relaxed, Relaxed, |v| v.checked_add(add)).is_err() { sink.overflow.store(1, Relaxed); }
        }
        let len = acc.event_ids.len();
        match acc.event_ids.last_mut() {
            Some(last) if last.1 == from => last.1 = to,
            _ if len >= EVENT_IDS_CAP => {
                acc.event_ids_overflow = acc.event_ids_overflow.saturating_add(1);
                if let Some(sink) = &acc.event_sink { sink.ids_overflow.fetch_add(1, Relaxed); }
            }
            _ => acc.event_ids.push((from, to)),
        }
    }
    fn event_ordinal(&self, ordinal: u32) -> bool {
        self.repair_accounting.event_ids.iter().any(|&(a, b)| (a..b).contains(&ordinal))
    }
    fn progress_info(&self) -> crate::fec_adapt::FecMessageInfo {
        let mut tag = [0u8; 8];
        let l = self.message.len().min(8);
        tag[..l].copy_from_slice(&self.message[..l]);
        crate::fec_adapt::FecMessageInfo { tag: u64::from_le_bytes(tag), message_len: self.message.len(),
            k: self.k, n_planned: self.n_planned, n_sent: self.next_id,
            loss_estimate: self.loss_estimate, lost_during_send: self.lost,
            package_id: self.package_lease.as_ref().map_or(0, |l| l.id),
            root_id: self.segment.map_or(self.package_lease.as_ref().map_or(0, |l| l.id), |s| s.root),
            segment_offset: self.segment.map_or(0, |s| s.offset), block_bytes: self.block_bytes as u32,
            rescue_rounds: self.rescue_rounds,
            rescue_symbols: self.original_symbols.map_or(0, |n| self.next_id.saturating_sub(n)),
            during_message_topup: self.repair_accounting.sent_topup,
            tail_repairs: self.repair_accounting.sent_tail,
            peak_retained_source_bytes: 0 }
    }

    // Retainable messages get a feedback fallback and need only learned risk up front.
    // Oversized messages cannot be rescued, so keep their original blind floor.
    fn plan_context(&self) -> (u64, usize, bool) {
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let total = self.segment.map_or(self.message.len(), |s| s.total as usize);
        let groups = self.segment.map_or(layout.groups, |s| segment_unit_count(s.total as usize, self.plan_ks.as_ref()));
        (segment_source_horizon(total, self.block_bytes, self.plan_ks.as_ref()), groups, self.message.len() > self.retain_limit)
    }

    /// p4-burst-base B1, the single core of every P4 refresh path (loss, source completion, open-tail
    /// refresh, final repair). While sources are still sending: R_g = d_g + b_g (known own loss replaced
    /// one-for-one above the immutable base). Once all sources are sent: the count-quantile fixed point
    /// over own unresolved symbols and connection-wide unresolved DATA. Plans only grow.
    fn refresh_base_plan(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let groups = layout.groups as u32;
        let eps = crate::fec_adapt::base_group_eps(self.base_codecs(&layout));
        let repairs = self.next_id.saturating_sub(self.k);
        let pending = self.next_id.saturating_sub(self.finalized_symbols) as u64;
        let mut r = self.repair_accounting.base_r;
        let mut cap_bound = false;
        for g in 0..layout.groups {
            let kg = layout.group(g).1 as u32;
            let d = self.group_lost[g];
            let rg = if self.next_id < self.k {
                let want = d.saturating_add(self.repair_accounting.base_b[g]);
                cap_bound |= want > kg;
                want.min(kg)
            } else {
                let rs = repairs / groups + u32::from((g as u32) < repairs % groups);
                let (rg, capped) = a.base_tail_repairs(kg as u64, r.min(kg) as u64, d as u64, rs as u64, pending, eps);
                cap_bound |= capped;
                rg as u32
            };
            r = r.max(rg);
        }
        self.repair_accounting.base_r = r;
        self.repair_accounting.base_cap_bound |= cap_bound;
        let old_n = self.n;
        let base = layout.round_plan(self.k.saturating_add(r.saturating_mul(groups)));
        self.repair_accounting.unbonused_n = self.repair_accounting.unbonused_n.max(self.n).max(base);
        self.n = self.n.max(base);
        // Same attribution as the baseline: known-loss deficit first, the rest is tail protection.
        let known = self.group_lost.iter().copied().max().unwrap_or(0);
        let known_n = self.k.saturating_add((known + 2).saturating_mul(groups));
        self.repair_accounting.planned_topup += self.n.saturating_sub(old_n).min(known_n.saturating_sub(old_n));
    }
    /// Reserve only new ordinal positions. The segment's FIRST layout grants its sole allowance;
    /// TU restart changes the codec, not the budget. Never refund even abandoned reservations.
    fn budget_plan(&mut self,demand:u32) { self.budget_plan_inner(demand,None); }
    fn budget_plan_inner(&mut self, demand:u32,capture:Option<(usize,u8)>) {
        let acc = &mut self.repair_accounting;
        let mut segment = acc.budget.as_ref().unwrap().lock().unwrap();
        let old = self.n.saturating_sub(self.k);
        let mut added = demand.saturating_sub(old).min(segment.limit.saturating_sub(segment.reserved));
        if segment.root.lock().unwrap().cap_percent==0 {
            let representable=u32::MAX-self.k-old;
            if added>representable {
                segment.root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo {counter_overflow:1,..Default::default()});
                added=0; // explicit failure, never a giant index-ceiling target
            }
        }
        #[cfg(feature="research_budget_diagnostic")]
        if let Some((checkpoint,reason))=capture {
            diag::demand_finish(checkpoint,(reason&!4)|if added>0 {4}else{0},demand,old+added,segment.diagnostic_owner_generation,segment.diagnostic_original_k,segment.limit,segment.reserved,segment.emitted,segment.diagnostic_sources_committed,segment.diagnostic_counter_overflow);
        }
        segment.reserved += added;
        #[cfg(feature="research_target_validation")]
        if let Some(owner)=&segment.target_owner {owner.lock().unwrap().planned_repairs=segment.reserved;}
        let allowed = old + added;
        self.n = self.k + allowed;
        let mut root = segment.root.lock().unwrap();
        let mut delta = BudgetBaseInfo { planned_repairs: added as u64, ..Default::default() };
        let shortfall = demand.saturating_sub(allowed) as u64;
        // Known-loss-only lower bound. Initial base, decoder rank and modeled future losses
        // are deliberately excluded; already planned parity can cover a known loss without
        // a fresh extension. Count each group's actual ordinal allocation, not max(d)*groups.
        let groups = self.group_lost.len() as u32;
        let known_shortfall = self.group_lost.iter().enumerate().map(|(g, &d)| {
            let allocated = allowed / groups + u32::from((g as u32) < allowed % groups);
            d.saturating_sub(allocated) as u64
        }).sum::<u64>();
        delta.demand_repairs = (demand as u64).saturating_sub(acc.budget_demand);
        delta.cap_shortfall = shortfall.saturating_sub(acc.budget_shortfall);
        delta.known_loss_shortfall = known_shortfall.saturating_sub(acc.budget_known_shortfall);
        acc.budget_demand = acc.budget_demand.max(demand as u64);
        acc.budget_shortfall = acc.budget_shortfall.max(shortfall);
        acc.budget_known_shortfall = acc.budget_known_shortfall.max(known_shortfall);
        if shortfall != 0 {
            if !acc.budget_limited { delta.cap_limited_slots = 1; acc.budget_limited = true; }
            if !root.limited { delta.cap_limited_roots = 1; root.limited = true; }
            acc.base_cap_bound = true;
        }
        root.sink.lock().unwrap().merge(delta);
    }
    /// Last systematic of the logical root, before even a zero-reserve owner can seal.

    fn target_tail_complete(&mut self, selector:u32) {
        if selector==0 {return;}
        if self.segment.is_some_and(|s|s.offset as usize+self.message.len()!=s.total as usize) {return;}
        let Some(budget)=self.repair_accounting.budget.clone() else {return};
        let (k,draw,root_base,target_state)={
            let b=budget.lock().unwrap();let mut root=b.root.lock().unwrap();
            if root.target_tail_applied {return;} root.target_tail_applied=true;
            let k=root.target_source_symbols;
            (u32::try_from(k).expect("tail root K overflow"),root.target_draw,root.target_risk.p_base,root.target_state.clone())
        };
        let remaining=self.n.saturating_sub(self.next_id);
        let tail=crate::target_validation::tail_plan(&target_state,k,remaining,selector,draw,root_base).expect("STP_TV_RISK_TAIL reserve search failed");
        let old=self.n;
        let demand=self.n.saturating_sub(self.k).checked_add(tail.added).expect("tail repair demand overflow");
        if tail.added!=0 {self.budget_plan(demand);}
        let mut b=budget.lock().unwrap();b.target_tail_added=self.n-old;
        #[cfg(feature="research_target_validation")]
        if let Some(owner)=&b.target_owner {let mut row=owner.lock().unwrap();row.tail_risk=tail.risk;row.tail_k=tail.k;row.tail_added=b.target_tail_added;}
    }
    fn refresh_budget_plan(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {

        {
            let segment=self.repair_accounting.budget.as_ref().unwrap().lock().unwrap();
            #[cfg(feature="research_target_validation")]
            if let Some(owner)=&segment.target_owner {owner.lock().unwrap().known_losses=segment.target_prior_losses.saturating_add(self.group_lost.iter().copied().sum::<u32>());}
            if a.target_selector()!=0 {
                // Frozen proactive plan plus exactly one replacement for EACH known own DATA loss.
                // Preserve the optional once-only tail grant; later losses still add exactly 1:1.
                let tail=segment.target_tail_added;
                let r=segment.target_prior_losses.checked_add(tail).and_then(|start|self.group_lost.iter().zip(&self.repair_accounting.base_b).try_fold(start,|sum,(&d,&b)|sum.checked_add(d)?.checked_add(b)));
                drop(segment);
                match r {Some(r) if r<=u32::MAX-self.k=>self.budget_plan(r),_=>self.repair_accounting.budget.as_ref().unwrap().lock().unwrap().root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo{counter_overflow:1,..Default::default()})}
                return;
            }
        }
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let groups = layout.groups as u32;
        let codecs = self.base_codecs(&layout);
        #[cfg(feature="research_budget_diagnostic")]
        let capture=self.next_id>=self.k && self.diagnostic.is_some() && diag::active();
        #[cfg(feature="research_budget_diagnostic")]
        let checkpoint=if capture {diag::demand_checkpoint()}else{0};
        let repairs = self.next_id.saturating_sub(self.k);
        let planned = self.n.saturating_sub(self.k);
        let own = self.next_id.saturating_sub(self.finalized_symbols) as u64;
        let (span, invalid) = a.budget_unresolved_span(self.repair_accounting.data_anchor, own);
        let invalid = invalid || self.repair_accounting.budget_invalid_anchor;
        if invalid && !self.repair_accounting.budget_invalid_anchor {
            self.repair_accounting.budget_invalid_anchor = true;
            let segment = self.repair_accounting.budget.as_ref().unwrap().lock().unwrap();
            segment.root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo { invalid_anchor_fallbacks: 1, ..Default::default() });
        }
        let mut r = 0;
        let mut known = 0;
        for g in 0..layout.groups {
            let kg = layout.group(g).1 as u32;
            let d = self.group_lost[g];
            let bg = self.repair_accounting.base_b[g];
            known = known.max(d.saturating_add(bg));
            let rg = if self.next_id < self.k {
                if a.cost_smooth_active() {d.saturating_add(bg)}else{d.saturating_add(bg).min(kg)}
            } else {
                let rs = repairs / groups + u32::from((g as u32) < repairs % groups);
                let start = planned / groups + u32::from((g as u32) < planned % groups);
                #[cfg(feature="research_budget_diagnostic")]
                let mut record=capture.then(|| {
                    let l=self.diagnostic.unwrap();let anchor=self.repair_accounting.data_anchor;
                    let mut c=diag::Demand::default();
                    c.header=diag::DemandHeader {generation:l.generation,package:l.package,root:l.root,
                        codec_index:g as u32,codec_count:codecs as u32,group_count:groups,k:kg,cap_percent:a.repair_cap_percent(),
                        old_planned:planned,d,own_finalized:self.finalized_symbols,assembled:self.next_id,rs,start,ug:own,uc:span,
                        anchor_generation:anchor.map_or(0,|a|a.0),anchor_a:anchor.map_or(0,|a|a.1),flags:u32::from(anchor.is_some())|if invalid {2}else{0},
                        segment_offset:self.segment.map_or(0,|s|s.offset),..Default::default()};c
                });
                let result=a.budget_tail_for_codecs(kg as u64,start as u64,d as u64,rs as u64,own,codecs,span,
                    segment_source_horizon(self.segment.map_or(self.message.len(),|s|s.total as usize),self.block_bytes,self.plan_ks.as_ref()),
                    #[cfg(feature="research_budget_diagnostic")] record.as_mut(), #[cfg(not(feature="research_budget_diagnostic"))] None);
                if a.cost_smooth_active() && result.1 {
                    self.repair_accounting.budget.as_ref().unwrap().lock().unwrap().root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo {counter_overflow:1,..Default::default()});
                }
                let result=result.0 as u32;
                #[cfg(feature="research_budget_diagnostic")]
                if let Some(c)=record {diag::demand_push(c);}
                result
            };
            // After an outage, old foreign in-flight DATA is no longer represented by S/F.
            // No tighter-span proof survives: demand the maximum model cap, then let the
            // HARD budget clip it. Never pretend the new generation covers the old interval.
            r = r.max(if invalid && !a.cost_smooth_active() { kg } else { rg });
        }
        let old_n = self.n;
        let demand=if a.cost_smooth_active() {
            match r.checked_mul(groups).filter(|v|*v<=u32::MAX-self.k) {
                Some(v)=>v,
                None=>{self.repair_accounting.budget.as_ref().unwrap().lock().unwrap().root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo {counter_overflow:1,..Default::default()});planned}
            }
        }else{r.saturating_mul(groups)};
        #[cfg(feature="research_budget_diagnostic")]
        let diagnostic=if capture {
            let previous=self.repair_accounting.diagnostic_last_demand.replace(demand);
            let reason=u8::from(previous.is_none())|if previous.is_some_and(|p|p!=demand){2}else{0}|if demand>planned {4}else{0};
            Some((checkpoint,reason))
        }else{None};
        self.budget_plan_inner(demand, #[cfg(feature="research_budget_diagnostic")] diagnostic, #[cfg(not(feature="research_budget_diagnostic"))] None);
        self.repair_accounting.base_r = self.n.saturating_sub(self.k).div_ceil(groups);
        self.repair_accounting.unbonused_n = self.n;
        self.repair_accounting.planned_topup += self.n.saturating_sub(old_n).min(self.k.saturating_add(known.saturating_mul(groups)).saturating_sub(old_n));
    }
    /// Wirehair codecs of the whole logical root: every segment times this layout's groups.
    fn base_codecs(&self, layout: &crate::fec::MessageLayout) -> usize {
        self.segment.map_or(layout.groups, |s| segment_unit_count(s.total as usize, self.plan_ks.as_ref()) * layout.groups)
    }

    fn refresh_plan(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {
        #[cfg(feature = "research_budget_diagnostic")]
        let before = self.n;
        self.refresh_plan_inner(a);
        #[cfg(feature = "research_budget_diagnostic")]
        if self.n != before { if let Some(l) = self.diagnostic { diag::layout_event(l, self.n, self.next_id, monotonic_clock_ns(), 1); } }
    }
    fn refresh_plan_inner(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {
        use crate::fec_adapt::RepairPolicy;
        if a.policy == RepairPolicy::MeanOpen || a.policy == RepairPolicy::MeanTopup { return; }
        if matches!(a.policy, RepairPolicy::Streaming | RepairPolicy::MessageBound) {
            // Earlier losses are replaced one-for-one at this group's extension.
            // Only the unresolved in-flight tail gets expected-loss protection.
            if self.repair_accounting.budget.is_some() { self.refresh_budget_plan(a); return; }
            if !self.repair_accounting.base_b.is_empty() { self.refresh_base_plan(a); return; }
            let pending = if self.next_id >= self.k { self.next_id.saturating_sub(self.finalized_symbols) } else { 0 };
            let margin = crate::fec_adapt::mean_repairs(pending as u64, a.p).max(2) as u32;
            let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
            let event = |g: usize| self.repair_accounting.event_bonus.get(g).copied().unwrap_or(0);
            let repairs = (0..layout.groups).map(|g| self.group_lost[g].saturating_add(margin).saturating_add(event(g)).min(layout.group(g).1 as u32)).max().unwrap();
            let old_n = self.n;
            let base = layout.round_plan(self.k.saturating_add(repairs * layout.groups as u32));
            // Event-free counterfactual of this same refresh (identical when no grant exists).
            let base0 = if self.repair_accounting.event_bonus.is_empty() { base } else {
                let r0 = (0..layout.groups).map(|g| self.group_lost[g].saturating_add(margin).min(layout.group(g).1 as u32)).max().unwrap();
                layout.round_plan(self.k.saturating_add(r0 * layout.groups as u32))
            };
            let unbonused_before = self.repair_accounting.unbonused_n;
            let bonus = self.repair_accounting.category_bonus;
            // Extend the unbonused adaptive base monotonically, then add the
            // SAME source-K bonus once. Never apply a percentage to extended N
            // or repeatedly add it to the already bonused train.
            self.repair_accounting.unbonused_n = self.repair_accounting.unbonused_n
                .max(self.n.saturating_sub(bonus)).max(base);
            let target = self.repair_accounting.unbonused_n.saturating_add(bonus);
            self.n = self.n.max(if bonus == 0 { target } else { target.min(self.k.saturating_mul(2)) });
            if !self.repair_accounting.event_bonus.is_empty() {
                // bonus == 0 is enforced for event repair, so the event-free n is max(old_n, unbonused_before, base0).
                let without = old_n.max(unbonused_before).max(base0);
                if self.n > without { self.event_attribute(without, self.n); }
            }
            // Attribute each newly planned symbol once. Known-loss deficit gets
            // priority; the rest protects unresolved packets. Initial rank symbols
            // and post-message rescue are reported separately.
            let known = self.group_lost.iter().copied().max().unwrap_or(0);
            let known_n = self.k.saturating_add((known + 2).saturating_mul(layout.groups as u32));
            self.repair_accounting.planned_topup += self.n.saturating_sub(old_n).min(known_n.saturating_sub(old_n));
            return;
        }
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let groups = layout.groups as u64;
        let sources = self.next_id.min(self.k) as u64;
        let repairs = self.next_id.saturating_sub(self.k) as u64;
        let mut per_group_repairs = 0;
        let (whole_k, target_groups, burst_tail) = self.plan_context();
        for group in 0..layout.groups {
            let k = layout.group(group).1 as u64;
            let source_sent = (sources / groups + u64::from((group as u64) < sources % groups)).min(k);
            let repair_sent = repairs / groups + u64::from((group as u64) < repairs % groups);
            let total_repairs = repair_sent + a.extra_repair_blocks_needed_for_group_at_tail(k, whole_k, target_groups, source_sent + repair_sent, repair_sent, self.group_lost[group] as u64, burst_tail);
            per_group_repairs = per_group_repairs.max(total_repairs);
        }
        // Equal complete rounds conservatively protect the most affected group, not mean loss.
        let n = self.k as u64 + per_group_repairs * groups;
        self.n = self.n.max(layout.round_plan(n.min(u32::MAX as u64) as u32));
    }
}

enum FecEncoderState {
    /// Systematic sources need no encoder; build it at first repair demand.
    Deferred,
    Ready(crate::fec::MessageEncoder),
    Failed,
}

impl std::fmt::Debug for FecSendSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FecSendSlot {{ len: {}, block_bytes: {}, k: {}, n: {}, next_id: {} }}", self.message.len(), self.block_bytes, self.k, self.n, self.next_id)
    }
}

// RESEARCH adaptive units. Started units keep their real (offset, len, K),
// including after TU growth or a same-range restart. The unstarted remainder is
// estimated as start_segment would partition it at the plan's current cap and
// the current width; each estimate is replaced when that unit starts.
#[derive(Debug, Default)]
struct UnitPlan { cap: usize, units: Vec<(u32, u32, u64)>, fenwick: Vec<u64>, total_k: u64 }
type PlanKs = std::sync::Arc<std::sync::Mutex<UnitPlan>>;
impl UnitPlan {
    fn new(cap: usize) -> PlanKs { std::sync::Arc::new(std::sync::Mutex::new(Self { cap, ..Default::default() })) }
    /// A first start appends the next contiguous range; a restart (exact same
    /// range, fresh unit id) only replaces its K. Ranges are never cut again.
    /// Units stay sorted by offset (contiguous appends), so a restart is a
    /// binary search plus an O(log n) Fenwick delta; an append is O(log n).
    fn record(&mut self, offset: u32, len: u32, k: u64) {
        if offset as usize == self.end() {
            let i = self.units.len() + 1; // 1-based Fenwick index of the new unit
            let low = i & i.wrapping_neg();
            let node = k.wrapping_add(self.fenwick_prefix(i - 1)).wrapping_sub(self.fenwick_prefix(i - low));
            self.units.push((offset, len, k));
            self.fenwick.push(node);
            self.total_k = self.total_k.checked_add(k).expect("adaptive root K overflow");
            return;
        }
        let i = self.units.partition_point(|u| u.0 < offset);
        let u = self.units.get_mut(i).filter(|u| u.0 == offset).expect("adaptive units start contiguously");
        assert_eq!(u.1, len, "adaptive unit range is immutable");
        let (old, delta) = (u.2, k.wrapping_sub(u.2));
        u.2 = k;
        self.total_k = self.total_k.checked_sub(old).and_then(|t| t.checked_add(k)).expect("adaptive root K overflow");
        let mut j = i + 1;
        while j <= self.fenwick.len() { self.fenwick[j - 1] = self.fenwick[j - 1].wrapping_add(delta); j += j & j.wrapping_neg(); }
    }
    /// Sum of K over the first `n` units (exact: every true partial sum fits u64,
    /// so wrapping deltas cancel).
    fn fenwick_prefix(&self, mut n: usize) -> u64 {
        let mut sum = 0u64;
        while n > 0 { sum = sum.wrapping_add(self.fenwick[n - 1]); n &= n - 1; }
        sum
    }
    fn end(&self) -> usize { self.units.last().map_or(0, |u| u.0 as usize + u.1 as usize) }
    fn started_k(&self) -> u64 { self.total_k }
    fn prefix_k(&self, offset: u32) -> u64 { self.fenwick_prefix(self.units.partition_point(|u| u.0 < offset)) }
}
/// Floor-aware balanced partition of `rem` bytes: g = min(ceil(R/cap), floor(R/MIN))
/// units (at least one), as (count, short_len, (long_len, long_count)) with
/// long_len = short_len + 1. Every unit of a splittable remainder is >= MIN.
/// Successive start_segment steps len=ceil(R/g(R)) produce exactly these.
fn balanced_parts(rem: usize, cap: usize) -> (usize, usize, (usize, usize)) {
    if rem == 0 { return (0, 0, (0, 0)); }
    let count = rem.div_ceil(cap.max(1)).min(rem / ADAPTIVE_MIN_UNIT_LEN).max(1);
    (count, rem / count, (rem / count + 1, rem % count))
}
/// RESEARCH one-flight exposure (frozen constants): smallest cap 892 bytes.
const ADAPTIVE_EXPOSURE_MIN_CAP: usize = 2 * ADAPTIVE_MIN_UNIT_LEN;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExposureSnapshot { rate_upps: u64, rtt_ns: Option<u64>, queues: u64, unresolved: u64 }
fn adaptive_exposure_k0(width: usize) -> usize { ADAPTIVE_EXPOSURE_MIN_CAP.div_ceil(width.max(1)).max(2) }
/// C = k*W for the LARGEST k in [k0, max(k0, floor(113920/W))] whose upper
/// initial packet train U(k) <= B = max(B0, U(k0)); B0 = ceil(R*T/(1e15*Q)) with
/// a measured RTT, else ceil(E/Q). U must be non-decreasing in k; an unknown
/// U(k0) yields the minimum cap. Wide integers, no overflow.
fn adaptive_exposure_cap(snap: ExposureSnapshot, width: usize, upper: impl Fn(u32) -> Option<u64>) -> usize {
    let w = width.max(1);
    let k0 = adaptive_exposure_k0(w);
    let kmax = (ADAPTIVE_PREFIX_CAP / w).max(k0);
    let q = u128::from(snap.queues.max(1));
    let b0 = match snap.rtt_ns {
        Some(t) => (u128::from(snap.rate_upps) * u128::from(t)).div_ceil(1_000_000_000_000_000 * q),
        None => u128::from(snap.unresolved).div_ceil(q),
    };
    let Some(u0) = u32::try_from(k0).ok().and_then(&upper) else { return k0 * w; };
    let budget = b0.max(u128::from(u0));
    let fits = |k: usize| u32::try_from(k).ok().and_then(&upper).is_some_and(|u| u128::from(u) <= budget);
    let (mut lo, mut hi) = (k0, kmax); // fits(lo) holds
    while lo < hi { let mid = lo + (hi - lo).div_ceil(2); if fits(mid) { lo = mid } else { hi = mid - 1 } }
    lo * w
}
fn adaptive_unit_len(rem: usize, cap: usize) -> usize { rem.div_ceil(balanced_parts(rem, cap).0.max(1)) }
/// Symbol width of a segmented unit: the TU width clamped to len-1 (so every
/// unit has K >= 2), never below the wire minimum symbol.
fn segment_width(len: usize, block_bytes: usize) -> usize {
    block_bytes.min(len.saturating_sub(1).max(FEC_MIN_BLOCK_BYTES))
}
fn segment_unit_k(len: usize, block_bytes: usize) -> usize { len.div_ceil(segment_width(len, block_bytes).max(1)) }
fn segment_unit_count(total: usize, plan_ks: Option<&PlanKs>) -> usize {
    let Some(plan) = plan_ks else { return total.div_ceil(FEC_SEGMENT_BYTES); };
    let plan = plan.lock().unwrap();
    plan.units.len() + balanced_parts(total.saturating_sub(plan.end()), plan.cap).0
}
fn segment_source_horizon(total: usize, block_bytes: usize,
    plan_ks: Option<&PlanKs>) -> u64 {
    let Some(plan_ks) = plan_ks else { return total.div_ceil(block_bytes) as u64; };
    let plan = plan_ks.lock().unwrap();
    let (count, short, (long, longs)) = balanced_parts(total.saturating_sub(plan.end()), plan.cap);
    let unit_k = |len| if len == 0 { 0 } else { segment_unit_k(len, block_bytes) };
    plan.started_k() + ((count - longs) * unit_k(short) + longs * unit_k(long)) as u64
}

/// TLV prefix (3), identity (8), symbol (4), unit length (4), symbol bytes (2).
pub const STP_FEC_FRAGMENT_HEADER_SIZE: usize = 21;
pub const STP_EXT_KIND_FEC: u64 = 1;
const STP_EXT_KIND_SEGMENT_FEC: u64 = 3;
const STP_SEGMENT_FEC_HEADER_SIZE: usize = 37;
const FEC_SEGMENT_BYTES: usize = 2 << 20;
/// Retained profile-3 receive floor; compact framing now leaves 453 bytes at TU512.
/// Keep this declared floor and its resource bounds independent of send width.
pub const FEC_MIN_BLOCK_BYTES: usize = 445;
/// Non-ACK plaintext admission floor; both cipher modes can carry recovery probes.
const MIN_CONNECTED_PAYLOAD: usize = crate::mtu_recovery::SMALL as usize - CONNECTED_HEADER_SIZE - 16;
pub const FEC_MAX_SOURCE_BLOCKS: usize = FEC_SEGMENT_BYTES.div_ceil(FEC_MIN_BLOCK_BYTES);

// Current senders segment every message above 2 MiB. Refuse legacy jumbo codecs
// and tiny attacker-chosen symbols before any root/decoder memory admission.
fn wire_fec_layout(len: usize, block_bytes: usize) -> Option<crate::fec::MessageLayout> {
    if len > FEC_SEGMENT_BYTES || block_bytes < FEC_MIN_BLOCK_BYTES { return None; }
    let layout = crate::fec::MessageLayout::new(len, block_bytes)?;
    (layout.k <= FEC_MAX_SOURCE_BLOCKS).then_some(layout)
}

/// RESEARCH adaptive units (wire profile 5). While the initial TU assessment is
/// unresolved a root's coded units are capped at the FIXED byte width that keeps
/// K <= FEC_INLINE_MAX_BLOCKS even at the minimum symbol; this cap never follows
/// feedback/width changes, so the byte partition cannot oscillate.
const ADAPTIVE_PREFIX_CAP: usize = FEC_MIN_BLOCK_BYTES * FEC_INLINE_MAX_BLOCKS;
/// Wire floor for EVERY unit range of a split root, including the last: one
/// byte above the minimum symbol, so a unit always has K >= 2 at its clamped
/// width and a root of total T has at most floor(T/446) extents.
pub(crate) const ADAPTIVE_MIN_UNIT_LEN: usize = FEC_MIN_BLOCK_BYTES + 1;

/// Independently coded, immutable contiguous byte range of one application message.
/// The unit's own length is its FEC message_len (kind 6 header carries all five).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecSegment { pub(crate) root: u64, total: u32, offset: u32 }

#[derive(Debug)]
struct SegmentedSend {
    plan_ks: PlanKs,
    message: std::sync::Arc<Vec<u8>>,
    offset: usize,
    root: u64,
    root_lease: Option<std::sync::Arc<PackageLease>>,
}

impl FecSegment {
    /// Profile 5: any bounded range strictly inside the root. Overlap and
    /// same-offset/different-length conflicts are the root ledger's job.
    fn valid(self, len: usize) -> bool {
        let total = self.total as usize;
        let offset = self.offset as usize;
        let Some(end) = offset.checked_add(len) else { return false; };
        total <= MAX_JUMBOGRAM_LEN && len >= 1 && len < total && len <= FEC_SEGMENT_BYTES &&
            end <= total && len >= ADAPTIVE_MIN_UNIT_LEN
    }
}
/// Balanced groups of <=32000 blocks, inferred from length/block size; same 21-byte header.
pub const STP_EXT_KIND_GROUPED_FEC: u64 = 2;
/// Redundancy is capped at 100% (n = 2k).
/// Messages with at most this many blocks have their Wirehair encoder/decoder run inline on
/// the network thread (well under 1 ms); bigger ones use a helper thread.
pub const FEC_INLINE_MAX_BLOCKS: usize = 256;

// These are scheduling quanta, not rate limits. Receive capacity must cover even
// a peer ACKing every packet; drain until empty, but do not let a flood starve sends.
const MAX_RECV_PACKETS_PER_TICK: usize = 64;
const MAX_SEND_PACKETS_PER_TICK: u64 = 64;
// One million pps, matching the existing startup ceiling. Bound long-lived cubic
// probing too; this is an arithmetic safety limit, not a congestion signal.
const MAX_CC_RATE_UPPS: u64 = 1_000_000_000_000;
// Retain at most 2 ms of quantum-limited catch-up credit. Old scheduling delays
// must not become an ever-growing burst that stops ACK service and inflates RTT.
const MAX_SEND_CATCHUP_NS: u64 = 2_000_000;

#[derive(Debug)]
struct SendPacingGrant { packets: u64, carry_ns: u64 }

/// Preserve multiply-then-divide precision without overflowing the intermediate.
fn rate_mul_div(rate: u64, multiplier: u64, divisor: u64) -> u64 {
    (rate as u128 * multiplier as u128 / divisor as u128).min(u64::MAX as u128) as u64
}

fn send_interval_ns(rate_upps: u64) -> u64 {
    (1_000_000_000_000_000 / rate_upps.max(1)).max(1)
}

// Synthetic idle ticks: the old 150 us loop consumed every unused grant.
// Preserve its first-active-tick bound rather than banking a long parked wait.
fn resume_idle_pacing(last: &mut u64, acc_ns: &mut u64, now: u64, interval_ns: u64) {
    if send_pacing_grant(now.saturating_add(1).saturating_sub(*last), interval_ns, *acc_ns).packets != 0 {
        *last = (*last).max(now.saturating_sub(interval_ns.max(150_000)));
        *acc_ns = 0;
    }
}

fn waited_across_idle_quantum(now: u64, deadline: u64, resumed: u64) -> bool {
    deadline.saturating_sub(now) > 150_000 && resumed.saturating_sub(now) > 150_000
}

// An action still overdue after this tick was gated or locally refused. Retry
// at the original loop quantum, never a zero-timeout readiness spin.
fn next_service_deadline(now: u64, due: u64) -> u64 {
    if due <= now { now.saturating_add(150_000) } else { due }
}

// Readability must not shorten the legacy active retry sleep: doing so changes
// RTT/ACK-pace sampling and can strand startup at a one-packet flight allowance.
// Pending ACK feedback is active work even on a receive-only connection.
// A send performed earlier in this pass can have an actual socket timestamp
// newer than the pass snapshot. Its elapsed age is zero, never a wrapped loss.
fn send_age_ns(now: u64, sent: u64) -> u64 { now.saturating_sub(sent) }

fn needs_active_retry(state: &ConnectionStateConnected, has_unsent_data: bool) -> bool {
    has_unsent_data || state.pending_send.is_some() || state.locally_blocked
        || state.packets_waiting_ack_tail < state.active_send_frontier
        || state.outage.since_ns.is_some()
        || (state.ack_timer != u64::MAX && state.active_ack_feedback)
}

// Generic-only flight may park, but ACK loss must still retire the oldest
// packet and enter outage at the same policy deadlines. The timeout grows with
// ACK silence: this is a lower-bound wake, recomputed on each service pass.
fn parked_send_deadline(state: &ConnectionStateConnected, now: u64, cc: &CongestionPolicy) -> u64 {
    let mut deadline = u64::MAX;
    if state.packets_waiting_ack_tail < state.send_sequence_number {
        let sent = state.send_time(state.packets_waiting_ack_tail);
        if state.RTT_mean != 0 {
            let timeout = state.loss_timer.timeout_ns(state.RTT_mean as u64 * 100_000,
                now.saturating_sub(state.last_ack_received_time), cc);
            deadline = if sent == 0 { now } else { sent.saturating_add(timeout) };
        }
        if let Some(start) = state.outage.pending_since_ns {
            deadline = deadline.min(start.max(state.last_ack_received_time).saturating_add(OUTAGE_ACK_SILENCE_NS));
        }
    }
    if state.outage.since_ns.is_some() { deadline = deadline.min(state.outage.next_probe_ns); }
    deadline
}

fn send_pacing_grant(elapsed_ns: u64, interval_ns: u64, credit_ns: u64) -> SendPacingGrant {
    let interval_ns = interval_ns.max(1);
    let budget = elapsed_ns.saturating_add(credit_ns);
    let due = budget / interval_ns;
    let packets = due.min(MAX_SEND_PACKETS_PER_TICK);
    let carry_ns = if due > packets {
        (budget - packets * interval_ns).min(MAX_SEND_CATCHUP_NS)
    } else {
        // Do not cap fractional credit: at low rates a single packet can take
        // much longer than 2 ms. Keeping the remainder makes the pps rate exact.
        budget % interval_ns
    };
    SendPacingGrant { packets, carry_ns }
}

pub enum UnreliableFragment<'a> {
    Plain { is_fin: bool, package_id: u64, data: &'a [u8], offset: u32 },
    Fec { segment: Option<FecSegment>, package_id: u64, message_len: u32, block_bytes: u16, block_id: u32, data: &'a [u8] },
}

impl UnreliableSendBuffer {
    // Standalone allocator-less buffers are internal fixtures; public callers
    // construct SendQueues, which installs the guarded shared identity allocator.
    pub(crate) fn new(target_queue_size_us: u32, min_queue_size_bytes: u32, max_queue_size_bytes: u32) -> Self {
        Self {
            #[cfg(feature = "research_budget_diagnostic")]
            diagnostic_last: None,
            queued_ledger: QueuedLedger::default(),
            target_queue_size_us,
            min_queue_size_bytes,
            max_queue_size_bytes,
            queue_bytes_filled: 0,
            message_queue: VecDeque::new(),
            current_dscp: Dscp::BestEffort,
            packet_dscp: None,
            target_dup_no_chop:false,
            partial_send_slot: None,
            send_package_id: 0,
            package_allocator: None,
            package_lease: None,
            current_bytes_per_second: 0,
            fec_capacity_overhead_ppm: 0,
            fec_send_slot: None,
            segmented_send: None,
            fec_adaptive: None,
            next_packet_seq: 0,
            fec_packet_tags: None,
            fec_retained: HashMap::new(),
            retention_quota: std::sync::Arc::new(RetentionQuota::new(1)),
            retained_bytes: 0,
            p4_open: false,
            p4_closing: false,
            p4_tail_refreshed: false,
            rescue_ready: VecDeque::new(),
            rescue_ready_count: 0,
            retained_next_prune_ns: 0,
            retained_last_prune_ns: 0,
            fec_extra_packet_tags: HashMap::new(),
            fec_rescue_package: None,
            fec_suspended: None,
            fec_now_ns: 0,
            fec_rtt_ns: 0,
            tu_unresolved: false,
            exposure: ExposureSnapshot::default(),
            fec_record: None,
            interleave_width: crate::fec_adapt::research_interleave_width(),
            interleave_parked: VecDeque::new(),
            interleave_last_packet: None,
            slipstream: crate::fec_adapt::research_slipstream(),
            slipstream_head: true,
            slipstream_eligible: None,
            slipstream_turn_head: true,
            slipstream_packet: None,
            slipstream_classified: 0,
            slipstream_eligible_heads: 0,
            slipstream_head_packets: 0,
            slipstream_follow_packets: 0,
            slipstream_started: false,
            logical_root: 0, logical_tag: 0, logical_len: 0,
            slipstream_info: SlipstreamInfo::default(),
            slipstream_trace: None,
            slipstream_queue: 0,
            slipstream_payload_len: 0,
            category_bonus_percent: crate::fec_adapt::research_medium_bonus(),
            category_eligible: None,
            category_bonus_messages: 0,
            category_bonus_repairs: 0,
            event_repair_q: crate::fec_adapt::research_p4_event_repair(),
            event_root_latched: false,
            event_repair: EventRepairInfo::default(),
            event_sink: std::sync::Arc::new(EventSink::default()),
            commit_marks: std::collections::BTreeMap::new(),
            budget_root: None, budget_sink: std::sync::Arc::new(std::sync::Mutex::new(BudgetBaseInfo::default())),
            target_root_sequence:0,
            target_state:Default::default(),
        }
    }

    fn interleave_source_bytes(&self) -> usize {
        self.interleave_parked.iter().map(MessageSendContext::source_bytes).sum::<usize>() +
            source_owner_bytes(self.partial_send_slot.as_ref(), self.segmented_send.as_ref(),
                self.fec_send_slot.as_ref(), self.fec_suspended.as_ref(), &self.fec_retained)
    }
    fn interleave_parkable(&self) -> bool {
        self.segmented_send.is_none() && self.fec_retained.is_empty() &&
            self.fec_suspended.is_none() && self.fec_rescue_package.is_none() &&
            self.fec_send_slot.as_ref().is_none_or(|f| f.segment.is_none() &&
                f.message.len() <= FEC_SEGMENT_BYTES &&
                crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).is_some_and(|l| l.groups == 1))
    }
    fn slipstream_has_owner(&self) -> bool {
        self.partial_send_slot.is_some() || self.fec_send_slot.is_some() ||
            self.segmented_send.is_some() || self.p4_open
    }
    // Research policy, not an application knob: estimate packet-train duration
    // at this application's current equal-byte fair share. Use current full TU
    // (not source bytes) and the actual source + initially planned repair train.
    // Eligible whole logical trains span [0.5 RTT, 2 RTT], inclusively; no startup rule.
    // A promoted partially sent follower uses its remaining planned train.
    fn slipstream_classify(&mut self, payload_len: usize) {
        if !self.slipstream_head || self.slipstream_eligible.is_some() { return; }
        let packets = owner_remaining_packets(self.fec_send_slot.as_ref(), self.fec_suspended.as_ref(),
            &self.fec_retained, self.segmented_send.as_ref(), payload_len, !self.slipstream_started,
            self.category_bonus_percent, self.category_eligible == Some(true));
        let reason = medium_duration_class(packets, payload_len, self.current_bytes_per_second, self.fec_rtt_ns);
        let eligible = reason == "eligible";
        self.slipstream_eligible = Some(eligible);
        self.slipstream_classified += 1;
        self.slipstream_eligible_heads += u64::from(eligible);
        let i = &mut self.slipstream_info;
        let pps = self.current_bytes_per_second as f64 / payload_len as f64;
        if i.heads_evaluated == 0 {
            i.rtt_ns_min = self.fec_rtt_ns;
            i.fair_share_pps_min = pps;
        } else {
            i.rtt_ns_min = i.rtt_ns_min.min(self.fec_rtt_ns);
            i.fair_share_pps_min = i.fair_share_pps_min.min(pps);
        }
        i.rtt_ns_max = i.rtt_ns_max.max(self.fec_rtt_ns);
        i.fair_share_pps_max = i.fair_share_pps_max.max(pps);
        i.heads_evaluated += 1;
        match reason {
            "eligible" => i.heads_eligible += 1, "short" => i.ineligible_short += 1,
            "long" => i.ineligible_long += 1, _ => i.ineligible_other += 1,
        }
        self.slipstream_trace_event("evaluate", reason, "", 0, 0, payload_len);
    }
    fn slipstream_select(&mut self, payload_len: usize, space: usize) {
        self.slipstream_payload_len = payload_len;
        if space != payload_len || self.slipstream_packet == Some(self.next_packet_seq) { return; }
        if self.slipstream_has_owner() {
            self.slipstream_classify(payload_len);
            let mut c = MessageSendContext::empty();
            c.swap(self);
            self.interleave_parked.push_back(c);
        }
        // A finished protected head is forgotten, never leased waiting for ACKs.
        // The sole following owner, including a partially sent giant, is promoted.
        if !self.interleave_parked.iter().any(|c| c.slipstream_head) {
            if let Some(c) = self.interleave_parked.front_mut() {
                c.slipstream_head = true;
                c.slipstream_eligible = None;
                self.slipstream_turn_head = true;
                self.slipstream_info.head_promotions += 1;
            } else {
                self.slipstream_head = true;
                self.slipstream_eligible = None;
                self.slipstream_turn_head = true;
                return;
            }
        }
        let head_index = self.interleave_parked.iter().position(|c| c.slipstream_head).unwrap();
        if self.interleave_parked[head_index].slipstream_eligible.is_none() {
            let mut c = self.interleave_parked.remove(head_index).unwrap();
            c.swap(self);
            self.slipstream_trace_event("promote", "", "", 0, 0, payload_len);
            self.slipstream_classify(payload_len);
            c.swap(self);
            self.interleave_parked.insert(head_index, c);
        }
        let eligible = self.interleave_parked[head_index].slipstream_eligible == Some(true);
        // Admit exactly the next FIFO logical message, any size, only for the
        // following lane. Tiny messages can retire and refill within its packet.
        if eligible && !self.slipstream_turn_head && self.interleave_parked.len() == 1 {
            if let Some((_, m)) = self.message_queue.front() {
                let reserve = m.capacity().saturating_add(if self.segmented_class(m.len(), payload_len) { m.len() } else { 0 });
                if self.interleave_source_bytes().saturating_add(reserve) <= self.current_byte_capacity() as usize {
                    let (dscp, m) = self.message_queue.pop_front().unwrap();
                    self.current_dscp = dscp;
                    self.slipstream_head = false;
                    self.slipstream_eligible = None;
                    self.start_message(m, payload_len);
                    if self.slipstream_has_owner() {
                        let mut c = MessageSendContext::empty();
                        c.swap(self);
                        self.interleave_parked.push_back(c);
                    }
                }
            }
        }
        debug_assert!(self.interleave_parked.len() <= 2);
        let unstarted = |c: &MessageSendContext| !c.slipstream_started ||
            c.fec_send_slot.as_ref().is_some_and(|f| f.next_id == 0) ||
            c.partial_send_slot.as_ref().is_some_and(|(_, offset)| *offset == 0);
        let older_unstarted = self.interleave_parked.iter().any(|c| c.slipstream_head && unstarted(c));
        let prefer_head = !eligible || self.slipstream_turn_head;
        let preferred = self.interleave_parked.iter().position(|c| c.slipstream_head == prefer_head).unwrap_or(head_index);
        let mut choice = None;
        for index in [preferred, 1usize.saturating_sub(preferred)] {
            let Some(c) = self.interleave_parked.get_mut(index) else { continue; };
            if !c.slipstream_head && unstarted(c) && older_unstarted { continue; }
            let ready_repair = c.rescue_ready.iter().any(|p| c.fec_retained.get_mut(p)
                .is_some_and(|r| Self::encoder_ready(&mut r.slot)));
            let needs_restart = |f: &FecSendSlot| {
                let header = if f.segment.is_some() { STP_SEGMENT_FEC_HEADER_SIZE } else { STP_FEC_FRAGMENT_HEADER_SIZE };
                let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
                // Match next_fragment's actual next symbol, not the maximum
                // block width: a short final systematic source may still fit.
                header + crate::fec::block_len(f.message.len(), f.block_bytes, layout.wire_id(f.next_id)) > payload_len
            };
            let needs_layout_id = c.fec_send_slot.as_ref().map_or(c.segmented_send.is_some(), needs_restart);
            let id_ready = !needs_layout_id || self.package_allocator.as_ref().is_none_or(|ids|
                *ids.live.lock().unwrap() < 1024 && ids.load(std::sync::atomic::Ordering::Relaxed) < u64::MAX);
            let ready = ready_repair || id_ready && c.fec_send_slot.as_mut().is_none_or(|f|
                (!needs_restart(f) || Self::encoder_initialized(f)) && Self::encoder_ready(f));
            if ready { choice = Some(index); break; }
        }
        let mut c = self.interleave_parked.remove(choice.unwrap_or(preferred)).unwrap();
        c.swap(self);
    }
    // Called only after real framing. One latch per emitted physical packet,
    // not per fragment, failed attempt, nonce, ACK, or immutable ciphertext retry.
    fn slipstream_emitted(&mut self, payload_len: usize) {
        if !self.slipstream { return; }
        if !self.slipstream_started {
            self.slipstream_started = true;
            if !self.slipstream_head {
                // fec_adaptive is back on SendQueues here, so label from the actual
                // owner: legacy >2 MiB, or a root start_message really segmented.
                let kind = if self.logical_len > FEC_SEGMENT_BYTES || self.segmented_send.is_some() ||
                    self.fec_send_slot.as_ref().is_some_and(|f| f.segment.is_some()) { "segmented_giant" }
                    else if self.fec_send_slot.is_some() { "ordinary_fec" } else { "tiny_whole_or_packed" };
                match kind {
                    "segmented_giant" => self.slipstream_info.follower_starts_segmented_giant += 1,
                    "ordinary_fec" => self.slipstream_info.follower_starts_ordinary_fec += 1,
                    _ => self.slipstream_info.follower_starts_tiny_whole_or_packed += 1,
                }
                self.slipstream_trace_event("start_follower", "", kind, self.logical_root, self.logical_tag, payload_len);
            }
        }
        let concurrent = 1 + self.interleave_parked.iter().filter(|c| c.slipstream_started).count() as u64;
        self.slipstream_info.max_concurrent_started_messages = self.slipstream_info.max_concurrent_started_messages.max(concurrent);
        if concurrent > 2 { self.slipstream_info.recursive_windows += 1; }
        if self.slipstream_packet == Some(self.next_packet_seq) { return; }
        self.slipstream_packet = Some(self.next_packet_seq);
        if self.slipstream_head {
            self.slipstream_head_packets += 1;
            if self.slipstream_eligible == Some(true) && (!self.interleave_parked.is_empty() || !self.message_queue.is_empty()) {
                self.slipstream_info.head_packets_alternated += 1;
            }
        } else {
            self.slipstream_follow_packets += 1;
            self.slipstream_info.follower_packets += 1;
        }
        self.slipstream_turn_head = !self.slipstream_head;
    }
    fn slipstream_trace_event(&self, event: &str, decision: &str, kind: &str, root: u64, tag: u64, payload_len: usize) {
        use std::io::Write;
        let Some(trace) = &self.slipstream_trace else { return; };
        let payload = if payload_len == 0 { self.slipstream_payload_len } else { payload_len };
        let (head_root, head_tag, head_len, packets) = if self.slipstream_head {
            (self.logical_root, self.logical_tag, self.logical_len,
                owner_remaining_packets(self.fec_send_slot.as_ref(), self.fec_suspended.as_ref(), &self.fec_retained,
                    self.segmented_send.as_ref(), payload, !self.slipstream_started, self.category_bonus_percent, self.category_eligible == Some(true)))
        } else if let Some(c) = self.interleave_parked.iter().find(|c| c.slipstream_head) {
            (c.logical_root, c.logical_tag, c.logical_len,
                owner_remaining_packets(c.fec_send_slot.as_ref(), c.fec_suspended.as_ref(), &c.fec_retained,
                    c.segmented_send.as_ref(), payload, !c.slipstream_started, self.category_bonus_percent, c.category_eligible == Some(true)))
        } else { (0, 0, 0, 0) };
        let pps = self.current_bytes_per_second as f64 / payload_len.max(self.slipstream_payload_len).max(1) as f64;
        let ms = if pps > 0.0 { packets as f64 / pps * 1000.0 } else { 0.0 };
        writeln!(trace.lock().unwrap(), "{},{},{event},{head_root},{head_tag},{head_len},{packets},{},{pps},{ms},{decision},{kind},{root},{tag}",
            self.fec_now_ns, self.slipstream_queue, self.fec_rtt_ns).expect("write slipstream trace");
    }
    fn interleave_select(&mut self, payload_len: usize, space: usize) {
        if self.slipstream { self.slipstream_select(payload_len, space); return; }
        if self.interleave_width == 1 || space != payload_len ||
            self.interleave_last_packet == Some(self.next_packet_seq) ||
            !self.fec_adaptive.as_ref().is_some_and(|a| a.policy == crate::fec_adapt::RepairPolicy::MessageBound) ||
            !self.interleave_parkable() { return; }
        self.interleave_last_packet = Some(self.next_packet_seq);
        let eligible_head = self.message_queue.front().is_some_and(|(_, m)|
            m.len() <= payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) ||
            !self.segmented_class(m.len(), payload_len) && self.fec_block_bytes(m.len(), payload_len)
                .and_then(|b| crate::fec::MessageLayout::new(m.len(), b)).is_some_and(|l| l.groups == 1));
        let selected = self.partial_send_slot.is_some() || self.fec_send_slot.is_some();
        // No peer work: exercise the exact legacy W1 path, without an idle hold.
        if self.interleave_parked.is_empty() && (!selected || !eligible_head) { return; }
        if selected {
            let mut current = MessageSendContext::empty();
            current.swap(self);
            self.interleave_parked.push_back(current);
        }
        if eligible_head && self.interleave_parked.len() < self.interleave_width {
            let bytes = self.message_queue.front().unwrap().1.capacity();
            // queue_bytes_filled continues to charge every ordinary source until
            // seal/reclaim. Admission adds no payload copy, and can't multiply
            // the existing configured queue capacity (oversized-alone stays W1).
            if self.interleave_source_bytes().saturating_add(bytes) <= self.current_byte_capacity() as usize {
                let (dscp, message) = self.message_queue.pop_front().unwrap();
                self.current_dscp = dscp;
                if self.start_message(message, payload_len) {
                    let mut added = MessageSendContext::empty();
                    added.swap(self);
                    self.interleave_parked.push_back(added);
                }
            }
        }
        // New work joins the tail. Repeated tiny arrivals cannot steal the
        // oldest message's quantum. A pending worker may be skipped for a
        // STARTED peer, but not for a younger message's first symbol. Unstarted
        // leases retain FIFO ID order: a TU restart emits source immediately
        // under its fresh ID before it can be parked again.
        let unstarted = |c: &MessageSendContext| c.fec_send_slot.as_ref().is_some_and(|f| f.next_id == 0) ||
            c.partial_send_slot.as_ref().is_some_and(|(_, offset)| *offset == 0);
        let first_start = self.interleave_parked.iter().filter(|c| unstarted(c)).map(|c| c.send_package_id).min();
        let count = self.interleave_parked.len();
        let mut selected = false;
        for _ in 0..count {
            let mut context = self.interleave_parked.pop_front().unwrap();
            let in_order = !unstarted(&context) || Some(context.send_package_id) == first_start;
            let ready = in_order && context.fec_send_slot.as_mut().is_none_or(|f|
                (f.block_bytes + STP_FEC_FRAGMENT_HEADER_SIZE <= payload_len || Self::encoder_initialized(f)) && Self::encoder_ready(f));
            if ready {
                context.swap(self);
                selected = true;
                break;
            }
            self.interleave_parked.push_back(context);
        }
        if !selected && count > 0 {
            // All eligible contexts are blocked. Project the oldest unstarted
            // owner (if any), never a younger ready first symbol. Return promptly
            // so other application queues can receive this packet's service.
            let index = first_start.and_then(|id| self.interleave_parked.iter().position(|c| c.send_package_id == id)).unwrap_or(0);
            let mut context = self.interleave_parked.remove(index).unwrap();
            context.swap(self);
        }
    }

    fn encoder_ready(f: &mut FecSendSlot) -> bool {
        if f.next_id < f.k || f.next_id >= f.n { return true; }
        Self::encoder_initialized(f)
    }
    fn encoder_initialized(f: &mut FecSendSlot) -> bool {
        if matches!(f.encoder, FecEncoderState::Deferred) {
            f.encoder = match crate::fec::encode_message(f.message.clone(), f.block_bytes) {
                Some(encoder) => FecEncoderState::Ready(encoder),
                None => {
                    #[cfg(feature = "research_cohort_observer")]
                    crate::cohort_observe::fec_encoder_failed();
                    FecEncoderState::Failed
                }
            };
        }
        true
    }

    fn can_emit(&mut self) -> bool {
        self.reclaim_finished_partial();
        if self.interleave_parked.iter_mut().any(|c| c.fec_send_slot.as_mut().is_none_or(Self::encoder_ready)) { return true; }
        if self.interleave_width > 1 && !self.message_queue.is_empty() && self.interleave_parkable() { return true; }
        if self.partial_send_slot.is_some() { return true; }
        if self.fec_rescue_package.is_none() {
            if let Some(package) = self.ready_rescue_package() {
                if let Some(r) = self.fec_retained.get_mut(&package) {
                    return Self::encoder_ready(&mut r.slot);
                }
            }
        }
        if let Some(f) = &mut self.fec_send_slot { return Self::encoder_ready(f); }
        self.has_unsent_data()
    }

    /// Start ANY connected nonce (including control). Clear a reused ring entry before fill.
    pub fn fec_prepare_packet(&mut self, seq: u64) {
        self.next_packet_seq = seq;
        if let Some(tags) = &mut self.fec_packet_tags { tags.take((seq % PACKETS_WAITING_ACK_CAPACITY) as usize); }
        self.fec_extra_packet_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
    }

    fn tag_symbol(&mut self, package: u64, ordinal: u32) {
        let index = self.next_packet_seq % PACKETS_WAITING_ACK_CAPACITY;
        let tags = self.fec_packet_tags.get_or_insert_with(PacketTags::default);
        let tag = tags.get(index as usize);
        let count = ((tag >> 32) & 0xffff_ffff) as u32;
        let tag = if count > 0 && tag >> 64 == package as u128 && (tag as u32).saturating_add(count) == ordinal {
            tag + (1u128 << 32)
        } else {
            if count > 0 { self.fec_extra_packet_tags.entry(index).or_default().push(tag); }
            ((package as u128) << 64) | (1u128 << 32) | ordinal as u128
        };
        tags.set(index as usize, tag);
    }

    fn fec_on_packet_finalized(&mut self, seq: u64, lost: bool) {
        if seq > self.next_packet_seq || self.next_packet_seq - seq >= PACKETS_WAITING_ACK_CAPACITY { return; }
        let Some(tags) = &mut self.fec_packet_tags else { return };
        let index = seq % PACKETS_WAITING_ACK_CAPACITY;
        let tag = tags.take(index as usize);
        let extra = self.fec_extra_packet_tags.remove(&index);
        self.fec_finalize_tags(seq, lost, extra.as_deref().unwrap_or(&[]));
        if tag != 0 { self.fec_finalize_tags(seq, lost, &[tag]); }
    }

    fn fec_finalize_tags(&mut self, seq: u64, lost: bool, tags: &[u128]) {
        for &tag in tags {
            let count = ((tag >> 32) & 0xffff_ffff) as u32;
            if count == 0 { continue; }
            let package = (tag >> 64) as u64;
            // Connection tags encode package identity, not the currently selected
            // message. Apply both ACK and loss to the owner's unchanged P4 path.
            if let Some(index) = self.interleave_parked.iter().position(|c| c.owns_package(package)) {
                let mut context = self.interleave_parked.remove(index).unwrap();
                context.swap(self);
                self.fec_finalize_tags(seq, lost, &[tag]);
                context.swap(self);
                self.interleave_parked.insert(index, context);
                continue;
            }
            let active = self.fec_send_slot.is_some() && package == self.fec_rescue_package.unwrap_or(self.send_package_id);
            let suspended = self.fec_suspended.is_some() && package == self.send_package_id;
            let retained = self.fec_retained.contains_key(&package);
            let was_ready = self.fec_retained.get(&package).is_some_and(|r| r.slot.next_id > 0 && r.slot.next_id < r.slot.n);
            let f = if active { self.fec_send_slot.as_mut() }
                else if suspended { self.fec_suspended.as_mut() }
                else { self.fec_retained.get_mut(&package).map(|r| &mut r.slot) };
            let Some(f) = f else { continue };
            // The last planned P4 symbol seals the message, even if feedback
            // runs before the next ordinary slot reclamation.
            if f.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound && self.p4_closing { continue; }
            let first = tag as u32;
            if seq < f.first_seq || first.saturating_add(count) > f.next_id { continue; }
            f.finalized_symbols = f.finalized_symbols.saturating_add(count);
            if lost {
                f.lost = f.lost.saturating_add(count);
                {
                    let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
                    for ordinal in first..first + count {
                        let group = layout.local_id(layout.wire_id(ordinal)).0;
                        f.group_lost[group] = f.group_lost[group].saturating_add(1);
                    }
                }
                if suspended || active && self.fec_rescue_package.is_none() || f.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound {
                    if let Some(a) = &self.fec_adaptive { f.refresh_plan(a); }
                }
            }
            if !suspended && (!active || self.fec_rescue_package.is_some()) { f.rescue_plan(); }
            if retained {
                let ready = f.next_id < f.n;
                let done = !ready && f.finalized_symbols >= f.next_id;
                if ready && !was_ready { self.rescue_ready.push_back(package); self.rescue_ready_count += 1; }
                if !ready && was_ready { self.rescue_ready_count -= 1; }
                if done { self.remove_retained(package); }
            }
        }
    }

    fn remove_retained(&mut self, package: u64) -> Option<RetainedFecSlot> {
        let r = self.fec_retained.remove(&package)?;
        self.retained_bytes -= r.slot.message.len();
        if r.slot.next_id > 0 && r.slot.next_id < r.slot.n { self.rescue_ready_count -= 1; }
        Some(r)
    }
    fn pop_oldest_retained(&mut self) -> Option<RetainedFecSlot> {
        let package = *self.fec_retained.iter().min_by_key(|(_, r)| r.expires_ns)?.0;
        self.remove_retained(package)
    }
    fn ready_rescue_package(&mut self) -> Option<u64> {
        while let Some(&package) = self.rescue_ready.front() {
            if self.fec_retained.get(&package).is_some_and(|r| r.expires_ns <= self.fec_now_ns) {
                self.remove_retained(package);
            }
            if self.fec_retained.get(&package).is_some_and(|r| r.slot.next_id > 0 && r.slot.next_id < r.slot.n) { return Some(package); }
            self.rescue_ready.pop_front();
        }
        None
    }
    fn fec_prune_retained(&mut self) {
        if self.fec_now_ns < self.retained_next_prune_ns { return; }
        let expired: Vec<u64> = self.fec_retained.iter().filter(|(_, r)| r.expires_ns <= self.fec_now_ns).map(|(&p, _)| p).collect();
        for package in expired { self.remove_retained(package); }
        // Full-map scans stay at least 1 ms apart. Nonready expired sources may
        // linger by that quantum; active/ready repairs have exact O(1) expiry guards.
        self.retained_last_prune_ns = self.fec_now_ns;
        self.retained_next_prune_ns = self.fec_now_ns.saturating_add(10_000_000)
            .min(self.fec_retained.values().map(|r| r.expires_ns).min().unwrap_or(u64::MAX))
            .max(self.fec_now_ns.saturating_add(1_000_000));
    }

    fn retain_fec(&mut self, mut slot: FecSendSlot, package: u64) {
        if slot.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound {
            if !self.p4_open || self.p4_closing || matches!(slot.encoder, FecEncoderState::Failed) { return; }
            slot.original_symbols.get_or_insert(slot.next_id);
            self.remove_retained(package);
            // Same condition that cleans an already retained unit on feedback: the
            // final ACK may have arrived while the unit was ACTIVE. Retaining it would
            // keep its package lease forever with no future ACK to free it.
            if slot.next_id >= slot.n && slot.finalized_symbols >= slot.next_id { return; }
            self.retained_bytes += slot.message.len();
            if slot.next_id < slot.n { self.rescue_ready.push_back(package); self.rescue_ready_count += 1; }
            // Open-message state: no deadline, quota lease, or post-message rounds.
            self.fec_retained.insert(package, RetainedFecSlot { slot, package, expires_ns: u64::MAX });
            return;
        }
        if !slot.repair_policy.feedback() || slot.message.len() > self.retention_quota.byte_limit || matches!(slot.encoder, FecEncoderState::Failed) { return; }
        slot.original_symbols.get_or_insert(slot.next_id);
        self.fec_prune_retained();
        self.remove_retained(package);
        if slot.retention_lease.is_none() {
            loop {
                if let Some(lease) = self.retention_quota.acquire(slot.message.len()) { slot.retention_lease = Some(lease); break; }
                if self.pop_oldest_retained().is_none() { return; }
            }
        }
        // Retain for at least 2 s or eight smoothed RTTs, plus the original train's
        // send duration (slow links/queued paths). Rescue retries do not extend that duration.
        let duration = *slot.original_send_duration_ns.get_or_insert_with(||
            self.fec_now_ns.saturating_sub(slot.send_started_ns));
        let hold_ns = self.fec_rtt_ns.saturating_mul(8).max(2_000_000_000).saturating_add(duration);
        let expires_ns = if slot.repair_policy == crate::fec_adapt::RepairPolicy::Reliability {
            self.fec_now_ns.saturating_add(hold_ns)
        } else { *slot.retained_until_ns.get_or_insert(self.fec_now_ns.saturating_add(hold_ns)) };
        if self.fec_now_ns >= expires_ns { return; }
        self.retained_bytes += slot.message.len();
        if slot.next_id > 0 && slot.next_id < slot.n { self.rescue_ready.push_back(package); self.rescue_ready_count += 1; }
        self.retained_next_prune_ns = self.retained_next_prune_ns.min(expires_ns)
            .max(self.retained_last_prune_ns.saturating_add(1_000_000));
        self.fec_retained.insert(package, RetainedFecSlot { slot, package, expires_ns });
    }

    /// Capacity in message bytes. `current_bytes_per_second` is the wire payload rate; with FEC
    /// on, a message costs about (1 + redundancy) times its size on the wire, so the time-based
    /// target is scaled down by that factor to keep the queue at the same send time. The
    /// min/max bounds are message bytes. (With FEC off this is exactly the old formula.)
    #[inline]
    pub fn current_byte_capacity(&self) -> u32 {
        let mut dynamic_target = self.target_queue_size_us as u64 * self.current_bytes_per_second / 1000_000;
        if self.fec_capacity_overhead_ppm != 0 {
            dynamic_target = dynamic_target * 1_000_000 / (1_000_000 + self.fec_capacity_overhead_ppm as u64);
        }
        dynamic_target.max(self.min_queue_size_bytes as u64).min(self.max_queue_size_bytes as u64) as u32
    }

    /// Back pressure, never drop: a message once accepted is sent. Messages are accepted in the
    /// caller's order while `queue_bytes_filled + len <= current_byte_capacity()`; a message is
    /// always accepted when nothing is queued, so a message bigger than the capacity can still go
    /// out on its own. Acceptance stops at the first message that does not fit, and that message
    /// and every one after it are returned, in order and untouched, for the caller to resubmit.
    /// (A future drop policy would hook in here, choosing what to evict instead of rejecting.)
    pub fn submit_messages(&mut self, new_messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        self.submit_classified_messages(new_messages.into_iter().map(|m| (Dscp::BestEffort, m)).collect()).into_iter().map(|(_, m)| m).collect()
    }

    pub fn submit_classified_messages(&mut self, new_messages: Vec<(Dscp, Vec<u8>)>) -> Vec<(Dscp, Vec<u8>)> {
        self.reclaim_finished_partial();
        let capacity = self.current_byte_capacity() as usize;
        let mut iter = new_messages.into_iter();
        let mut rejected = Vec::new();
        while let Some((dscp, m)) = iter.next() {
            if self.queue_bytes_filled == 0 || self.queue_bytes_filled + m.len() <= capacity {
                self.queue_bytes_filled += m.len();
                self.message_queue.push_back((dscp, m));
            } else {
                rejected.push((dscp, m));
                rejected.extend(iter);
                break;
            }
        }
        rejected
    }

    /// Largest message `submit_messages` would accept right now: u64::MAX when nothing is queued
    /// (any size goes alone), otherwise the room left under the current capacity.
    pub fn free_bytes(&mut self) -> u64 {
        self.reclaim_finished_partial();
        if self.queue_bytes_filled == 0 { return u64::MAX; }
        (self.current_byte_capacity() as u64).saturating_sub(self.queue_bytes_filled as u64)
    }

    pub fn has_unsent_data(&self) -> bool {
        if !self.interleave_parked.is_empty() { return true; }
        if !self.message_queue.is_empty() || self.segmented_send.is_some() { return true; }
        if let Some((msg, start_byte)) = &self.partial_send_slot {
            if (*start_byte as usize) < msg.len() { return true; }
        }
        if let Some(f) = &self.fec_send_slot {
            if f.next_id < f.n { return true; }
        }
        self.fec_suspended.as_ref().is_some_and(|f| f.next_id < f.n) ||
            self.rescue_ready_count != 0
    }

    // A message whose last fragment has gone out still counts against the queue until it is
    // released here.
    fn fec_expire_active_rescue(&mut self) {
        // P2/P3's deadline follows the retained slot into active service. A stalled
        // top-up or outage must not extend it; original FIFO data remains untouched.
        if self.fec_rescue_package.is_some() && self.fec_send_slot.as_ref().is_some_and(|f|
            f.repair_policy != crate::fec_adapt::RepairPolicy::Reliability &&
            f.retained_until_ns.is_some_and(|deadline| self.fec_now_ns >= deadline)) {
            self.fec_send_slot = None;
            self.fec_rescue_package = None;
            self.resume_suspended();
        }
    }
    // At the last source of the whole message, revisit every still-open
    // segment. Its own unresolved symbols, not RTT divided among segments,
    // determine its tail allowance. Ready work uses the ordinary FIFO sender.
    fn p4_refresh_tail(&mut self) {
        if !self.p4_open || self.p4_tail_refreshed || self.segmented_send.is_some() || self.fec_rescue_package.is_some() { return; }
        if !self.fec_send_slot.as_ref().is_some_and(|f| f.next_id >= f.k ||
            f.repair_accounting.budget.is_some() && f.next_id + 1 == f.k && f.n == f.k) { return; }
        self.p4_tail_refreshed = true;
        let Some(a) = &self.fec_adaptive else { return; };
        for (&package, r) in &mut self.fec_retained {
            let ready = r.slot.next_id < r.slot.n;
            r.slot.refresh_plan(a);
            if !ready && r.slot.next_id < r.slot.n {
                self.rescue_ready.push_back(package);
                self.rescue_ready_count += 1;
            }
        }
    }

    fn p4_finish_if_idle(&mut self) {
        if self.p4_open && self.fec_send_slot.is_none() && self.fec_suspended.is_none() &&
            self.segmented_send.is_none() && self.rescue_ready_count == 0 {
            if self.slipstream { self.slipstream_trace_event("end", "sealed", "", self.logical_root, self.logical_tag, 0); }
            #[cfg(feature="research_budget_diagnostic")]
            if let Some(l)=self.diagnostic_last.take() {diag::layout_event(l,l.planned,l.assembled,self.fec_now_ns,4);}
            #[cfg(feature="research_target_validation")]
            if let Some(root)=&self.budget_root {for owner in &root.lock().unwrap().target_owners {let mut row=owner.lock().unwrap();row.sealed=true;row.sealed_ns=self.fec_now_ns;}}
            self.fec_retained.clear();
            self.retained_bytes = 0;
            self.rescue_ready.clear();
            self.p4_open = false;
            self.p4_closing = false;
            self.p4_tail_refreshed = false;
            self.event_root_latched = false;
            self.budget_root = None;
        }
    }

    /// p4-event-repair: one immutable grant per logical root, at its first QUALIFYING accepted CC event. A slot
    /// qualifies iff it is exposed now (active/suspended/retained, root open and not closing) and its first source
    /// commit precedes the event evidence in both sequence and send time. No later grants, no child inheritance.
    fn p4_event_repair(&mut self, e: &AcceptedCcEvent) {
        match e.kind {
            CC_EVENT_EARLY => self.event_repair.accepted_early += 1,
            CC_EVENT_TIMEOUT => self.event_repair.accepted_timeout += 1,
            _ => self.event_repair.accepted_ce += 1,
        }
        if self.event_repair_q == 0 { return; }
        if !self.p4_open || self.p4_closing { self.event_repair.skip_closed += 1; return; }
        if self.event_root_latched { self.event_repair.skip_latched += 1; return; }
        let qualifies = |f: &FecSendSlot| f.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound
            && !matches!(f.encoder, FecEncoderState::Failed)
            // Exact commit proof + sequence order; time compared at the send-history resolution of the evidence.
            && f.repair_accounting.first_source_commit.is_some_and(|(seq, t)| seq <= e.evidence_seq && send_history_time_ns(t) <= e.evidence_sent_ns);
        let exposed = || self.fec_send_slot.iter().chain(self.fec_suspended.iter()).chain(self.fec_retained.values().map(|r| &r.slot));
        let good = exposed().filter(|f| qualifies(f)).count() as u64;
        let total = exposed().count() as u64;
        if good == 0 { self.event_repair.skip_unexposed += 1; return; }
        let Some(a) = self.fec_adaptive.take() else { self.event_repair.skip_closed += 1; return; };
        self.event_root_latched = true;
        let info = &mut self.event_repair;
        info.roots_granted += 1;
        info.slots_granted += good;
        info.slots_unqualified += total - good;
        let q = self.event_repair_q as u64;
        let sink = self.event_sink.clone();
        let mut grant = |f: &mut FecSendSlot, info: &mut EventRepairInfo| {
            if !qualifies(f) { return; }
            f.repair_accounting.event_sink = Some(sink.clone());
            let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
            f.repair_accounting.event_bonus = (0..layout.groups).map(|g| (q * layout.group(g).1 as u64).div_ceil(100) as u32).collect();
            info.grant_symbols += f.repair_accounting.event_bonus.iter().map(|&b| b as u64).sum::<u64>();
            f.refresh_plan(&a);
        };
        if let Some(f) = self.fec_send_slot.as_mut() { grant(f, info); }
        if let Some(f) = self.fec_suspended.as_mut() { grant(f, info); }
        for (&package, r) in self.fec_retained.iter_mut() {
            let was_ready = r.slot.next_id > 0 && r.slot.next_id < r.slot.n;
            grant(&mut r.slot, info);
            if r.slot.next_id < r.slot.n && !was_ready {
                self.rescue_ready.push_back(package);
                self.rescue_ready_count += 1;
                info.ready_added += 1;
            }
        }
        self.fec_adaptive = Some(a);
    }

    /// Public counters: queue-local plus refresh-time attribution from granted slots.
    fn event_info(&self) -> EventRepairInfo {
        use std::sync::atomic::Ordering::Relaxed;
        EventRepairInfo { planned: self.event_sink.planned.load(Relaxed), ids_overflow: self.event_sink.ids_overflow.load(Relaxed),
            counter_overflow: self.event_repair.counter_overflow.max(self.event_sink.overflow.load(Relaxed)), ..self.event_repair }
    }

    /// Successful DATA commit of `seq`: consume this queue's marks (event ordinals, repairs, first source).
    fn fec_commit_marks(&mut self, seq: u64, sent: u64) {
        if self.commit_marks.is_empty() { return; }
        while let Some(entry) = self.commit_marks.first_entry() {
            if *entry.key() >= seq { break; }
            self.event_repair.marks_abandoned += entry.remove().iter().map(|m| m.event as u64).sum::<u64>();
        }
        let Some(marks) = self.commit_marks.remove(&seq) else { return };
        for m in marks {
            self.event_repair.emitted += m.event as u64;
            self.event_repair.repairs_emitted += m.repair as u64;
            if let Some(budget) = &m.budget {
                let mut segment = budget.lock().unwrap();
                segment.emitted += m.repair as u64;
                #[cfg(feature="research_target_validation")]
                if let Some(owner)=&segment.target_owner {let mut row=owner.lock().unwrap();row.sources_emitted+=m.source as u64;row.repairs_emitted+=m.repair as u64;}
                #[cfg(feature="research_budget_diagnostic")]
                {
                    if let Some(next)=segment.diagnostic_sources_committed.checked_add(m.source as u64) {segment.diagnostic_sources_committed=next;}
                    else {segment.diagnostic_counter_overflow=true;}
                }
                // The reservation proof holds even when pending ciphertext outlives its slot.
                let overflow = u64::from(segment.emitted > segment.reserved as u64 || segment.reserved > segment.limit);
                segment.root.lock().unwrap().sink.lock().unwrap().merge(BudgetBaseInfo {
                    sources_emitted: m.source as u64, repairs_emitted: m.repair as u64, counter_overflow: overflow, ..Default::default() });
            }
            if !m.first_source { continue; }
            let f = if self.fec_send_slot.is_some() && m.package == self.fec_rescue_package.unwrap_or(self.send_package_id) { self.fec_send_slot.as_mut() }
                else if self.fec_suspended.is_some() && m.package == self.send_package_id { self.fec_suspended.as_mut() }
                else { self.fec_retained.get_mut(&m.package).map(|r| &mut r.slot) };
            if let Some(f) = f { f.repair_accounting.first_source_commit.get_or_insert((seq, sent)); }
        }
    }

    fn reclaim_finished_partial(&mut self) {
        self.fec_expire_active_rescue();
        if let Some((msg, start_byte)) = &self.partial_send_slot {
            if *start_byte as usize >= msg.len() {
                let msg_len = msg.len();
                self.queue_bytes_filled -= msg_len;
                self.queued_ledger.retire(msg_len);
                if self.slipstream { self.slipstream_trace_event("end", "plain", "", self.logical_root, self.logical_tag, 0); }
                self.partial_send_slot = None;
                self.package_lease = None;
                self.send_package_id = self.send_package_id.checked_add(1).expect("message identity exhausted");
            }
        }
        if let Some(f) = &self.fec_send_slot {
            if f.next_id >= f.n {
                let message_len = f.message.len();
                let rescue = self.fec_rescue_package.take();
                let package = rescue.unwrap_or(self.send_package_id);
                let mut finished = self.fec_send_slot.take().unwrap();
                if rescue.is_none() {
                    self.queue_bytes_filled -= message_len;
                    self.queued_ledger.retire(message_len);
                    self.package_lease = None;
                    self.send_package_id = self.send_package_id.checked_add(1).expect("message identity exhausted");
                }
                finished.rescue_plan();
                // Production codecs are bounded by the <=2 MiB segment size.
                // No release helper: allocation/destruction belongs to Pump too.
                if message_len > FEC_RETAIN_SOURCE_BYTES { drop(finished); }
                else { self.retain_fec(finished, package); }
                if rescue.is_some() { self.resume_suspended(); }
            }
        }
        self.p4_finish_if_idle();
    }

    /// Block size for an FEC message started in a packet with `payload_len` bytes of payload:
    /// one block plus its header fills the packet. None if the message should go plain (FEC
    /// off, fewer than 2 blocks, or outside the grouped wire length limit).
    fn fec_block_bytes(&self, message_len: usize, payload_len: usize) -> Option<usize> {
        if self.fec_adaptive.is_none() || message_len <= payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) { return None; }
        let block_bytes = payload_len.checked_sub(STP_FEC_FRAGMENT_HEADER_SIZE)?.min(0x3fff);
        crate::fec::MessageLayout::new(message_len, block_bytes)?;
        Some(block_bytes)
    }

    /// Exposure sizing applies while the TU assessment is unresolved AND a
    /// budget root exists to freeze risk; budget-base inactive keeps the legacy
    /// fixed prefix cap; settled is 2 MiB.
    fn exposure_sized(&self) -> bool {
        self.tu_unresolved && self.fec_adaptive.as_ref().is_some_and(|a| a.budget_base_active())
    }
    /// Smallest cap this queue could choose for a new unit at `payload_len`
    /// (pure: no root, risk, draw or admission). The actual cap is never below it.
    fn adaptive_unit_cap_floor(&self, payload_len: usize) -> usize {
        if !self.tu_unresolved { return FEC_SEGMENT_BYTES; }
        if !self.exposure_sized() { return ADAPTIVE_PREFIX_CAP; }
        let w = payload_len.saturating_sub(STP_SEGMENT_FEC_HEADER_SIZE).max(FEC_MIN_BLOCK_BYTES);
        adaptive_exposure_k0(w) * w
    }
    /// Cap for a NEW unit of the current root at the current width. Needs the
    /// root's frozen risk (budget_root) when exposure-sized.
    fn adaptive_unit_cap(&self, payload_len: usize, root_total: usize) -> usize {
        if !self.exposure_sized() { return self.adaptive_unit_cap_floor(payload_len); }
        let w = payload_len.saturating_sub(STP_SEGMENT_FEC_HEADER_SIZE).max(FEC_MIN_BLOCK_BYTES);
        let a = self.fec_adaptive.as_ref().unwrap();
        let risk = self.budget_root.as_ref().map(|r| r.lock().unwrap().target_risk);
        let selector = a.target_selector();
        let profile = crate::target_validation::configuration().0;
        adaptive_exposure_cap(self.exposure, w, |k| if selector == 0 {
            Some(u64::from(k) + u64::from(k.min(2)))
        } else {
            let risk = risk?;
            crate::target_validation::adaptive_unit_packet_upper(k, profile, risk, u32::try_from(root_total).ok()?).ok().map(u64::from)
        })
    }
    /// Pure queued-head class: a root that MAY split at the current width
    /// (len above the smallest possible cap). Conservative: reservations and
    /// interleave exclusion cover every root start_message could split.
    fn may_segment(&self, len: usize, payload_len: usize) -> bool {
        self.fec_adaptive.is_some() && len >= 2 * ADAPTIVE_MIN_UNIT_LEN && len > self.adaptive_unit_cap_floor(payload_len)
    }
    /// Admission/reservation class: the legacy >2 MiB giant (any FEC state,
    /// unchanged) plus a root the unresolved exposure cap may split.
    fn segmented_class(&self, len: usize, payload_len: usize) -> bool {
        len > FEC_SEGMENT_BYTES || self.may_segment(len, payload_len)
    }

    /// One logical root, one risk admission/draw/ordinal: created at the first
    /// coded start of a message, or EARLIER by start_message when the exposure
    /// cap needs the frozen root risk before the split decision. Every later
    /// unit, restart or whole-FEC start of the same message reuses it.
    fn ensure_budget_root(&mut self, root_message: &[u8]) {
        let Some(a) = self.fec_adaptive.as_ref() else { return; };
        if !a.budget_base_active() || self.budget_root.is_some() { return; }
        let cap_percent = a.repair_cap_percent();
        self.target_root_sequence=self.target_root_sequence.checked_add(1).expect("target root ordinal exhausted");
        let mut tag=[0;8];let len=root_message.len().min(8);tag[..len].copy_from_slice(&root_message[..len]);
        self.budget_sink.lock().unwrap().merge(BudgetBaseInfo{roots:1,..Default::default()});
        self.budget_root=Some(std::sync::Arc::new(std::sync::Mutex::new(BudgetRoot{sink:self.budget_sink.clone(),limited:false,cap_percent,
            target_tail_applied:false,target_risk:crate::target_validation::risk_admission(&self.target_state),
            target_draw:crate::target_validation::draw(self.target_root_sequence),target_ordinal:self.target_root_sequence,target_app_tag:tag,#[cfg(feature="research_target_validation")] target_owners:Vec::new(),target_state:self.target_state.clone(),target_source_symbols:0})));
    }

    fn start_fec(&mut self, message: std::sync::Arc<Vec<u8>>, block_bytes: usize) {
        self.start_fec_group(message, block_bytes, None, None, None, None);
    }

    fn start_fec_group(&mut self, message: std::sync::Arc<Vec<u8>>, block_bytes: usize,
        segment: Option<FecSegment>, root_lease: Option<std::sync::Arc<PackageLease>>,
        plan_ks: Option<PlanKs>,
        restart_budget: Option<std::sync::Arc<std::sync::Mutex<BudgetSegment>>>) {
        let layout = crate::fec::MessageLayout::new(message.len(), block_bytes).unwrap();
        let k = layout.k as u32;
        let a = self.fec_adaptive.as_ref().expect("adaptive FEC initialized before coding");
        if a.policy == crate::fec_adapt::RepairPolicy::MessageBound {
            self.p4_open = true;
            // A new layout (including a TU-shrink restart of the final segment)
            // has sources still to send. Revisit open tails at its completion.
            self.p4_tail_refreshed = false;
        }
        let total = segment.map_or(message.len(), |s| s.total as usize);
        if let (Some(segment), Some(ks)) = (segment, &plan_ks) {
            ks.lock().unwrap().record(segment.offset, message.len() as u32, k as u64);
        }

        if restart_budget.is_none() { self.ensure_budget_root(&message); }
        let a = self.fec_adaptive.as_ref().expect("adaptive FEC initialized before coding");

        let target_plans=if a.target_selector()!=0 {
            // Plan the CURRENT layout's K. A TU-shrink restart replans from the SAME
            // frozen root admission (root draw + risk, not a live risk/share/owner
            // admission) and the unit's immutable extent; it never reuses the old-K plan.
            let root=match &restart_budget {Some(b)=>b.lock().unwrap().root.clone(),None=>self.budget_root.clone().unwrap()};
            let (draw,risk)={let root=root.lock().unwrap();(root.target_draw,root.target_risk)};
            // Whole roots: offset 0, len == total (exact old path). Units carry their immutable range.
            let (unit_offset, unit_len) = (segment.map_or(0, |s| s.offset), message.len() as u32);
            let plans=(0..layout.groups).map(|g|crate::target_validation::plan_at_unit_admission(layout.group(g).1 as u32,a.target_selector(),crate::target_validation::configuration().0,draw,risk,unit_offset,unit_len,total as u32).unwrap_or_else(|_|{self.budget_sink.lock().unwrap().merge(BudgetBaseInfo{counter_overflow:1,..Default::default()});crate::target_validation::Plan::default()})).collect::<Vec<_>>();
            if let Some(b)=&restart_budget {b.lock().unwrap().target_plans=plans.clone();}
            plans
        }else{Vec::new()};
        let whole_k = segment_source_horizon(total, block_bytes, plan_ks.as_ref());
        let target_groups = segment.map_or(layout.groups, |s| segment_unit_count(s.total as usize, plan_ks.as_ref()));
        let repairs = (0..layout.groups).map(|g| a.repair_blocks_for_group_at_tail(layout.group(g).1 as u64,
            whole_k, target_groups, message.len() > self.retention_quota.byte_limit)).max().unwrap_or(0);
        // p4-burst-base B1: immutable absolute base per codec group from the blind horizon.
        // p4-budget-deferred C1: admission reserves ONLY decoder rank min(2, Kg) per group, never a
        // statistical Q before feedback; the full actual-span tail plan is refreshed before the first
        // repair. The hard cap still clips this (K<=6 reserves 0). B1 below is unchanged.
        // Cost-smooth instead commits one XOR repair per codec to remain open until
        // that deferred refresh. This is an explicit admission floor, not an optimum.
        let (base_b, base_cap_bound) = if a.budget_base_active() {
            ((0..layout.groups).map(|g| if a.target_selector()!=0 {
                {target_plans.get(g).map_or_else(||{self.budget_sink.lock().unwrap().merge(BudgetBaseInfo{counter_overflow:1,..Default::default()});0},|p|p.proactive)}

            }else if a.cost_smooth_active() {1}else{2.min(layout.group(g).1 as u32)}).collect::<Vec<u32>>(), false)
        } else if a.base_parity_active() {
            let codecs = segment.map_or(layout.groups, |s| segment_unit_count(s.total as usize, plan_ks.as_ref()) * layout.groups);
            let eps = crate::fec_adapt::base_group_eps(codecs);
            let mut capped = false;
            let b = (0..layout.groups).map(|g| { let (b, c) = a.base_initial_repairs(layout.group(g).1 as u64, eps); capped |= c; b as u32 }).collect::<Vec<u32>>();
            (b, capped)
        } else { (Vec::new(), false) };
        let repairs = if base_b.is_empty() { repairs } else { base_b.iter().copied().max().unwrap_or(0) as u64 };
        let base_r = repairs as u32;
        let (n, loss_estimate) = (k + if a.target_selector()!=0 {base_b.iter().copied().sum::<u32>()} else {repairs as u32 * layout.groups as u32}, a.p);
        let n_base = if a.target_selector()!=0 {n}else{layout.round_plan(n)};
        // Independent first-start category decision for BOTH scheduler lanes,
        // including the scheduler-off control. Do not inherit the protected head's
        // class. Freeze across rate/RTT changes and TU restarts of this message.
        let mut category_bonus = 0;
        if a.policy == crate::fec_adapt::RepairPolicy::MessageBound && self.category_bonus_percent != 0 {
            if self.category_eligible.is_none() {
                let payload = block_bytes + if segment.is_some() { STP_SEGMENT_FEC_HEADER_SIZE } else { STP_FEC_FRAGMENT_HEADER_SIZE };
                let cap = plan_ks.as_ref().map(|p| p.lock().unwrap().cap);
                let (_, packets) = p4_new_train(total, 0, payload, segment.and(cap));
                self.category_eligible = Some(medium_duration_class(packets, payload,
                    self.current_bytes_per_second, self.fec_rtt_ns) == "eligible");
                self.category_bonus_messages += u64::from(self.category_eligible == Some(true));
            }
            if self.category_eligible == Some(true) {
                let prefix_k = segment.zip(plan_ks.as_ref()).map_or(0, |(seg, ks)| ks.lock().unwrap().prefix_k(seg.offset));
                category_bonus = source_bonus(prefix_k + k as u64, self.category_bonus_percent)
                    .saturating_sub(source_bonus(prefix_k, self.category_bonus_percent));
            }
        }
        let n = if category_bonus == 0 { n_base } else { n_base.saturating_add(category_bonus).min(k.saturating_mul(2)) };
        self.category_bonus_repairs += n.saturating_sub(n_base) as u64;
        let encoder = if k as usize <= FEC_INLINE_MAX_BLOCKS {
            match crate::fec::encode_message(message.clone(), block_bytes) { Some(e) => FecEncoderState::Ready(e), None => { #[cfg(feature = "research_cohort_observer")] crate::cohort_observe::fec_encoder_failed(); FecEncoderState::Failed } }
        } else { FecEncoderState::Deferred };
        let anchor = a.budget_base_active().then(|| a.data_anchor());
        let budget = if a.budget_base_active() {
            Some(restart_budget.unwrap_or_else(|| {
                let root = self.budget_root.get_or_insert_with(|| {
                    self.budget_sink.lock().unwrap().merge(BudgetBaseInfo { roots: 1, ..Default::default() });
                    std::sync::Arc::new(std::sync::Mutex::new(BudgetRoot { sink: self.budget_sink.clone(), limited: false, cap_percent: a.repair_cap_percent(),
                        target_tail_applied:false,
                        target_risk:crate::target_validation::risk_admission(&self.target_state),
                        target_draw:0,target_ordinal:0,
                        target_app_tag:[0;8],#[cfg(feature="research_target_validation")] target_owners:Vec::new(),target_state:self.target_state.clone(),target_source_symbols:0 }))
                }).clone();
                let cap_percent = root.lock().unwrap().cap_percent;
                let limit = if cap_percent==0 {u32::MAX-k}else{
                    (0..layout.groups).map(|g| crate::fec_adapt::budget_repair_limit_for_cap(layout.group(g).1 as u64, cap_percent) as u32).sum()
                };
                self.budget_sink.lock().unwrap().merge(BudgetBaseInfo { source_symbols: k as u64, repair_limit: limit as u64, ..Default::default() });
                {let mut r=root.lock().unwrap();r.target_source_symbols=r.target_source_symbols.checked_add(k as u64).expect("tail root K overflow");}
                #[cfg(feature="research_target_validation")]
                let target_owner=if crate::target_validation::active() {
                    let mut r=root.lock().unwrap();let plan=target_plans.first().copied().unwrap_or_default();
                    let owner=crate::target_validation::register(crate::target_validation::OwnerEvidence{
                        root_id:segment.map_or(self.send_package_id,|s|s.root),package_id:self.send_package_id,root_ordinal:r.target_ordinal,app_tag:r.target_app_tag,
                        segment_offset:segment.map_or(0,|s|s.offset),selector:a.target_selector(),k,current_k:k,groups:layout.groups as u32,
                        proactive:n_base-k,lower:plan.lower,upper:plan.upper,w_bits:plan.upper_probability.to_bits(),mix_threshold:plan.mix_threshold,mix_draw:plan.mix_draw,
                        unit_len:message.len() as u32,root_total:total as u32,
                        risk:r.target_risk.risk,p_eff:r.target_risk.p_eff,rate_over_anchor:r.target_risk.rate_over_anchor,
                        queue_delay_us:r.target_risk.queue_delay_us,qd_ref_us:r.target_risk.qd_ref_us,mode:r.target_risk.mode,
                        started_ns:self.fec_now_ns,..Default::default()});r.target_owners.push(owner.clone());Some(owner)
                }else{None};
                std::sync::Arc::new(std::sync::Mutex::new(BudgetSegment {
                    target_plans:target_plans.clone(),
                    #[cfg(feature="research_target_validation")] target_owner,
                    target_prior_losses:0,target_tail_added:0,
                    #[cfg(feature="research_budget_diagnostic")] diagnostic_owner_generation:if diag::active(){0}else{u64::MAX},
                    #[cfg(feature="research_budget_diagnostic")] diagnostic_original_k:k,
                    #[cfg(feature="research_budget_diagnostic")] diagnostic_sources_committed:0,
                    #[cfg(feature="research_budget_diagnostic")] diagnostic_counter_overflow:false,
                    root, limit, reserved: 0, emitted: 0 }))
            }))
        } else { None };
        #[cfg(feature="research_target_validation")]
        if let Some(b)=&budget {let b=b.lock().unwrap();if let Some(owner)=&b.target_owner {let mut row=owner.lock().unwrap();if row.current_k!=k || row.package_id!=self.send_package_id {row.current_k=k;row.restarts+=1;}}}
        self.fec_packet_tags.get_or_insert_with(PacketTags::default);
        self.fec_send_slot = Some(FecSendSlot { #[cfg(feature = "research_budget_diagnostic")] diagnostic: None, segment, root_lease, plan_ks, retention_lease: None, retain_limit: self.retention_quota.byte_limit, package_lease: self.package_lease.clone(), dscp: self.current_dscp, finalized_symbols: 0, send_started_ns: self.fec_now_ns, original_send_duration_ns: None, repair_policy: a.policy, rescue_rounds: 0, retained_until_ns: None, original_symbols: None, repair_accounting: RepairAccounting { unbonused_n: n_base, category_bonus, base_b, base_r, base_cap_bound, budget, data_anchor: anchor, ..Default::default() }, group_lost: vec![0; layout.groups], message, block_bytes, k, n, next_id: 0, encoder, block_buf: vec![0u8; block_bytes], first_seq: self.next_packet_seq, lost: 0, n_planned: n, loss_estimate });
        if let Some(f) = &mut self.fec_send_slot {
            if f.repair_accounting.budget.is_some() {
                // Prefix clipping, NEVER round_plan: one extra round could violate the hard floor.
                f.n = k;
                f.budget_plan(n.saturating_sub(k));
                let count = f.n - k;
                if a.target_selector()==0 {for (g, b) in f.repair_accounting.base_b.iter_mut().enumerate() {
                    *b = count / layout.groups as u32 + u32::from((g as u32) < count % layout.groups as u32);
                }}
                #[cfg(feature="research_target_validation")]
                if let Some(owner)=&f.repair_accounting.budget.as_ref().unwrap().lock().unwrap().target_owner {let mut row=owner.lock().unwrap();if row.restarts==0 {row.proactive=count;}}
                f.repair_accounting.base_r = count.div_ceil(layout.groups as u32);
                f.n_planned = f.n;
                f.repair_accounting.unbonused_n = f.n;
            }
            #[cfg(feature = "research_budget_diagnostic")]
            if diag::active() {
                let app = f.message.get(..6).filter(|m| m[0] == 0xd5);
                f.diagnostic = Some(diag::layout_start(diag::Layout {
                    package: self.send_package_id, root: segment.map_or(self.send_package_id, |s|s.root),
                    len:f.message.len(),width:f.block_bytes,k:f.k as usize,groups:layout.groups,
                    limit:f.repair_accounting.budget.as_ref().map(|b|b.lock().unwrap().limit),
                    planned:f.n, phase:app.map(|m|m[1]),app_id:app.map(|m|u32::from_le_bytes(m[2..6].try_into().unwrap())),
                    ns:self.fec_now_ns, ..Default::default()
                }));
                self.diagnostic_last=f.diagnostic;

                if let Some(segment)=&f.repair_accounting.budget {
                    let mut segment=segment.lock().unwrap();
                    if segment.diagnostic_owner_generation==0 {segment.diagnostic_owner_generation=f.diagnostic.unwrap().generation;}
                }
            }
        }
    }

    /// Starts `msg` as the message being sent: grouped FEC if enabled and its length fits
    /// the wire format with at least two blocks at this packet size, plain otherwise.
    fn start_message(&mut self, msg: Vec<u8>, payload_len: usize) -> bool {
        self.package_lease = None;
        if let Some(ids) = self.package_allocator.clone() {
            // Receiver ring pressure is backpressure, not permission to discard a
            // retained package before its loss feedback arrives. Ready rescue can
            // still run; ACK finalization or bounded expiry releases a ring position.
            let Some(lease) = ids.allocate() else {
                self.message_queue.push_front((self.current_dscp, msg));
                return false;
            };
            self.send_package_id = lease.id;
            self.package_lease = Some(lease);
        }
        if self.slipstream {
            let mut tag = [0; 8];
            let len = msg.len().min(8);
            tag[..len].copy_from_slice(&msg[..len]);
            self.logical_root = self.send_package_id;
            self.logical_tag = u64::from_le_bytes(tag);
            self.logical_len = msg.len();
            self.slipstream_started = false;
        }
        self.category_eligible = None;
        self.budget_root = None;
        // RESEARCH adaptive units: split a root only when it exceeds the unit cap
        // (2 MiB settled; while the initial TU trial is unresolved the one-flight
        // exposure cap, or the fixed prefix cap without a budget root). A root that
        // may split freezes its ONE risk/draw/ordinal here; the split decision and
        // start_fec_group both reuse it. Smaller roots keep the old order exactly.
        // Whole fitting/tiny messages keep the ordinary kind 4 path.
        let cap = if self.may_segment(msg.len(), payload_len) {
            self.ensure_budget_root(&msg);
            self.adaptive_unit_cap(payload_len, msg.len())
        } else { usize::MAX };
        if msg.len() > cap {
            self.segmented_send = Some(SegmentedSend { plan_ks: UnitPlan::new(cap), message: std::sync::Arc::new(msg), offset: 0,
                root: self.send_package_id, root_lease: self.package_lease.take() });
            return self.start_segment(payload_len);
        }
        match self.fec_block_bytes(msg.len(), payload_len) {
            Some(block_bytes) => self.start_fec(std::sync::Arc::new(msg), block_bytes),
            None => {
                self.partial_send_slot = Some((msg, 0));
            },
        }
        true
    }

    // Allocate only when a group is ready to start, under the same 1024-position
    // allocator as every other queue. Ring pressure leaves the original at its FIFO
    // head; neither a group ID nor its encode-time TU is chosen ahead of time.
    fn start_segment(&mut self, payload_len: usize) -> bool {
        let Some(block_bytes) = payload_len.checked_sub(STP_SEGMENT_FEC_HEADER_SIZE) else { return false; };
        let source = self.segmented_send.as_ref().unwrap();
        let start = source.offset;
        // RESEARCH adaptive units: balanced partition of the REMAINING bytes at the
        // current cap (fixed prefix cap while the TU trial is unresolved, else 2 MiB).
        // Floor-aware: every range (incl. the last) is >= ADAPTIVE_MIN_UNIT_LEN and the
        // byte range is immutable once started. Width is frozen for this unit at the
        // current TU, clamped to len-1 so K >= 2 (balanced_parts/p4_new_train agree).
        let cap = self.adaptive_unit_cap(payload_len, source.message.len());
        let end = start + adaptive_unit_len(source.message.len() - start, cap);
        let lease = match self.package_allocator.clone() {
            Some(ids) => { let Some(lease) = ids.allocate() else { return false; }; Some(lease) },
            None => None,
        };
        self.send_package_id = lease.as_ref().map_or(self.send_package_id.checked_add(1).expect("message identity exhausted"), |l| l.id);
        self.package_lease = lease;
        let segment = FecSegment { root: source.root, total: source.message.len() as u32, offset: start as u32 };
        let root_lease = source.root_lease.clone();
        let plan_ks = source.plan_ks.clone();
        plan_ks.lock().unwrap().cap = cap;
        let message = std::sync::Arc::new(source.message[start..end].to_vec());
        self.segmented_send.as_mut().unwrap().offset = end;
        if end == segment.total as usize { self.segmented_send = None; }
        let block_bytes = segment_width(message.len(), block_bytes);
        self.start_fec_group(message, block_bytes, Some(segment), root_lease, Some(plan_ks), None);
        true
    }

    fn resume_suspended(&mut self) {
        self.fec_send_slot = self.fec_suspended.take();
        if let Some(f) = &mut self.fec_send_slot { f.retention_lease = None; }
    }

    // Peek only at FIFO heads. Large messages/symbols may start a packet,
    // but are never gap fillers. No codec or wire-format changes are needed.
    fn fill_tier(&mut self, payload_len: usize, space: usize, class: Option<Dscp>) -> Option<u8> {
        self.reclaim_finished_partial();
        if class.is_none() { return Some(0); }
        // A newly dequeued tiny filler must not put its first frame ahead of
        // an older context which joined RR but has not had its first quantum.
        if self.partial_send_slot.is_none() && self.fec_send_slot.is_none() &&
            self.interleave_parked.iter().any(|c| c.fec_send_slot.as_ref().is_some_and(|f| f.next_id == 0) ||
                c.partial_send_slot.as_ref().is_some_and(|(_, offset)| *offset == 0)) { return None; }
        if self.partial_send_slot.is_none() && (self.fec_send_slot.is_some() ||
            self.segmented_send.is_some() || self.ready_rescue_package().is_some()) { return None; }
        let (dscp, len, offset) = if let Some((m, offset)) = &self.partial_send_slot {
            (self.current_dscp, m.len(), *offset as usize)
        } else { let (c,m) = self.message_queue.front()?; (*c, m.len(), 0) };
        if class.is_some_and(|c| c != dscp) || len > payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) { return None; }
        if offset == 0 && len + STP_WHOLE_HEADER_SIZE <= space { return Some(1); }

        if offset==0 && self.target_dup_no_chop {return None;}
        let prefix = space.checked_sub(STP_FRAGMENT_HEADER_SIZE)?;
        if prefix == 0 { return None; }
        if offset > 0 {
            // A continuation is indivisible as a filler: never make a third part.
            return (len - offset <= prefix).then_some(3);
        }
        // Whole framing saves twelve bytes. A near-TU-sized message needs a
        // sufficient prefix so its fifteen-byte continuation fits a fresh packet.
        (len - prefix.min(len) <= payload_len.saturating_sub(STP_FRAGMENT_HEADER_SIZE)).then_some(3)
    }

    /// Next fragment for a packet with `payload_len` bytes of payload, of which `space` are still
    /// free. None: nothing to send, or the next FEC block does not fit in what is left of this
    /// packet (or its repair encoder is still being built); send the packet as it is.
    pub fn next_fragment(&mut self, payload_len: usize, space: usize) -> Option<UnreliableFragment<'_>> {
        self.reclaim_finished_partial();
        self.interleave_select(payload_len, space);
        self.fec_prune_retained();
        let rescue = if self.partial_send_slot.is_none() && self.fec_rescue_package.is_none() {
            self.ready_rescue_package()
        } else { None };
        let rescue = rescue.filter(|_| {
            if let Some(original) = &mut self.fec_send_slot {
                if original.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound { return true; }
                if original.retention_lease.is_none() {
                    original.retention_lease = self.retention_quota.acquire(original.message.len());
                }
                original.retention_lease.is_some()
            } else { true }
        });
        let dscp = if let Some(package) = rescue { self.fec_retained[&package].slot.dscp }
            else if let Some(f) = &self.fec_send_slot { f.dscp }
            else if self.partial_send_slot.is_some() || self.segmented_send.is_some() { self.current_dscp }
            else { self.message_queue.front()?.0 };
        // A physical packet contains only one class. Never upgrade bulk by packing it with EF.
        if self.packet_dscp.is_some_and(|c| c != dscp) { return None; }
        // A long original train must not block a ready rescue until its retention expires.
        // Suspend only at a fragment boundary; packet tags still route its outcome feedback.
        if self.partial_send_slot.is_none() && self.fec_rescue_package.is_none() {
            if let Some(package) = rescue {
                let r = self.remove_retained(package).unwrap();
                self.fec_suspended = self.fec_send_slot.take();
                self.fec_rescue_package = Some(r.package);
                let mut slot = r.slot;
                slot.rescue_rounds = slot.rescue_rounds.saturating_add(1);
                self.fec_send_slot = Some(slot);
            }
        }
        if self.partial_send_slot.is_none() && self.fec_send_slot.is_none() {
            if self.segmented_send.is_some() {
                if !self.start_segment(payload_len) { return None; }
            } else {
                if !self.interleave_parked.is_empty() {
                    let (_, head) = self.message_queue.front()?;
                    // Legacy tail filling and failed-encoder recursion may reach
                    // here outside the full-TU RR admission path. Only a tiny
                    // FIFO head may start, under that same physical-source cap;
                    // a medium/giant must wait for its ordinary admission turn.
                    // Recursion also obeys first-symbol FIFO, just like fill_tier.
                    let extra = head.capacity().saturating_add(if self.slipstream && self.segmented_class(head.len(), payload_len) { head.len() } else { 0 });
                    if self.slipstream && self.slipstream_head ||
                        (head.len() > payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) && (!self.slipstream || space < payload_len)) ||
                        self.interleave_source_bytes().saturating_add(extra) > self.current_byte_capacity() as usize ||
                        self.interleave_parked.iter().any(|c| c.fec_send_slot.as_ref().is_some_and(|f| f.next_id == 0) ||
                            c.partial_send_slot.as_ref().is_some_and(|(_, offset)| *offset == 0)) {
                        return None;
                    }
                }
                let (dscp, front_msg) = self.message_queue.pop_front()?;
                self.current_dscp = dscp;
                if self.slipstream && self.slipstream_head { self.slipstream_eligible = None; }
                if !self.start_message(front_msg, payload_len) { return None; }
                if self.slipstream { self.slipstream_classify(payload_len); }
            }
        }
        if self.fec_send_slot.is_some() {
            self.p4_refresh_tail();
            if self.fec_rescue_package.is_none() { if let (Some(a), Some(f)) = (&self.fec_adaptive, &mut self.fec_send_slot) {
                // Refresh learned tail risk at source completion and the final repair.
                if f.next_id >= f.k && (f.next_id == f.k || f.next_id + 1 >= f.n) {
                    f.refresh_plan(a);
                }
            } }
            let need = { let f = self.fec_send_slot.as_ref().unwrap(); (if f.segment.is_some() { STP_SEGMENT_FEC_HEADER_SIZE } else { STP_FEC_FRAGMENT_HEADER_SIZE }) + crate::fec::block_len(f.message.len(), f.block_bytes, crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap().wire_id(f.next_id)) };
            if need > space {
                if space < payload_len { return None; } // the next packet has room
                // The transmission unit shrank below the block size (black hole fallback; it
                // never shrinks otherwise). Start the message over under a new package id with
                // blocks that fit; the receiver drops the abandoned partial package in time.
                if self.fec_rescue_package.is_none() && self.fec_send_slot.as_ref().unwrap().segment.is_some() {
                    if self.slipstream && !Self::encoder_initialized(self.fec_send_slot.as_mut().unwrap()) { return None; }
                    let lease = match self.package_allocator.clone() {
                        Some(ids) => { let Some(lease) = ids.allocate() else { return None; }; Some(lease) },
                        None => None,
                    };
                    let f = self.fec_send_slot.take().unwrap();
                    self.send_package_id = lease.as_ref().map_or(self.send_package_id.checked_add(1).expect("message identity exhausted"), |l| l.id);
                    self.package_lease = lease;

                    if let Some(b)=&f.repair_accounting.budget {let mut b=b.lock().unwrap();b.target_prior_losses=b.target_prior_losses.saturating_add(f.group_lost.iter().copied().sum::<u32>());}
                    let block_bytes = segment_width(f.message.len(), payload_len - STP_SEGMENT_FEC_HEADER_SIZE);
                    self.start_fec_group(f.message, block_bytes, f.segment, f.root_lease, f.plan_ks, f.repair_accounting.budget);
                    return self.next_fragment(payload_len, space);
                }
                if (self.slipstream || self.interleave_width > 1 || self.category_bonus_percent != 0 || self.fec_send_slot.as_ref().unwrap().repair_accounting.budget.is_some()) && self.fec_rescue_package.is_none() {
                    // Ordinary research contexts restart with the SAME Arc, not
                    // try_unwrap-or-copy. Resolve a pending worker first so repeated
                    // TU changes cannot leave detached old codec jobs uncharged.
                    if !Self::encoder_initialized(self.fec_send_slot.as_mut().unwrap()) { return None; }
                    let lease = match self.package_allocator.clone() {
                        Some(ids) => { let Some(lease) = ids.allocate() else { return None; }; Some(lease) },
                        None => None,
                    };
                    let f = self.fec_send_slot.take().unwrap();
                    drop(f.encoder);
                    self.send_package_id = lease.as_ref().map_or(self.send_package_id.checked_add(1).expect("message identity exhausted"), |l| l.id);
                    self.package_lease = lease;

                    if let Some(b)=&f.repair_accounting.budget {let mut b=b.lock().unwrap();b.target_prior_losses=b.target_prior_losses.saturating_add(f.group_lost.iter().copied().sum::<u32>());}
                    self.start_fec_group(f.message, payload_len - STP_FEC_FRAGMENT_HEADER_SIZE, None, None, None, f.repair_accounting.budget);
                    return self.next_fragment(payload_len, space);
                }
                let f = self.fec_send_slot.take().unwrap();
                drop(f.encoder);
                if self.fec_rescue_package.take().is_some() {
                    self.resume_suspended();
                    return self.next_fragment(payload_len, space); // cannot change a retained package's layout
                }
                self.send_package_id = self.send_package_id.checked_add(1).expect("message identity exhausted");
                let msg = std::sync::Arc::try_unwrap(f.message).unwrap_or_else(|a| (*a).clone());
                if !self.start_message(msg, payload_len) { return None; }
                return self.next_fragment(payload_len, space);
            }
            let package_id = self.fec_rescue_package.unwrap_or(self.send_package_id);
            let mut repair_len = None;
            {
                let f = self.fec_send_slot.as_mut().unwrap();
                if f.next_id >= f.k {
                    if !Self::encoder_initialized(f) { return None; }
                    repair_len = match &mut f.encoder {
                        FecEncoderState::Ready(e) => e.block_into(f.next_id, &mut f.block_buf),
                        _ => None,
                    };
                    if repair_len.is_none() {
                        #[cfg(feature = "research_cohort_observer")]
                        if f.next_id < f.n { crate::cohort_observe::fec_repair_skipped((f.n - f.next_id) as u64); }
                        // No encoder: the source blocks are all out, end the message there.
                        f.next_id = f.n;
                    }
                }
            }
            let f = self.fec_send_slot.as_ref().unwrap();
            if f.next_id >= f.n { return self.next_fragment(payload_len, space); }
            self.tag_symbol(package_id, self.fec_send_slot.as_ref().unwrap().next_id);
            {
                // Observation only (every arm): commit-time marks; never change what is sent.
                let f = self.fec_send_slot.as_ref().unwrap();
                let first_source = f.next_id < f.k && f.repair_accounting.first_source_commit.is_none();
                let event = u32::from(f.event_ordinal(f.next_id));
                let repair = u32::from(f.next_id >= f.k);
                let source = u32::from(f.next_id < f.k);
                let budget = f.repair_accounting.budget.clone();
                if first_source || event != 0 || repair != 0 || budget.is_some() {
                    let marks = self.commit_marks.entry(self.next_packet_seq).or_default();
                    match marks.iter_mut().find(|m| m.package == package_id) {
                        Some(m) => { m.event += event; m.repair += repair; m.source += source; m.first_source |= first_source; }
                        None => marks.push(CommitMark { event, repair, first_source, package: package_id, source, budget }),
                    }
                }
            }
            let f = self.fec_send_slot.as_mut().unwrap();
            let id = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap().wire_id(f.next_id);
            if let Some(len) = repair_len {
                if f.next_id >= f.n_planned && (f.original_symbols.is_none() || f.repair_policy == crate::fec_adapt::RepairPolicy::MessageBound) {
                    if f.repair_accounting.sent_topup < f.repair_accounting.planned_topup {
                        f.repair_accounting.sent_topup += 1;
                    } else { f.repair_accounting.sent_tail += 1; }
                }
                f.next_id += 1;
                #[cfg(feature = "research_budget_diagnostic")]
                if f.next_id >= f.n { if let Some(l)=f.diagnostic {diag::layout_event(l,f.n,f.next_id,self.fec_now_ns,3);} }
                if self.p4_open && f.next_id >= f.n && self.segmented_send.is_none() &&
                    self.fec_suspended.is_none() && self.rescue_ready_count == 0 {
                    self.p4_closing = true;
                }
                if let Some(rec) = &mut self.fec_record { rec.push(f.progress_info()); }
                self.packet_dscp = Some(dscp);
                return Some(UnreliableFragment::Fec { segment: f.segment, package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.block_buf[..len] });
            }
            f.next_id += 1;
            #[cfg(feature = "research_budget_diagnostic")]
            if let Some(l)=f.diagnostic {
                if f.next_id == f.k {diag::layout_event(l,f.n,f.next_id,self.fec_now_ns,2);}
                if f.next_id >= f.n {diag::layout_event(l,f.n,f.next_id,self.fec_now_ns,3);}
            }
            // Frozen zero-reserve owners still get their source-completion decision BEFORE sealing.

            if f.next_id==f.k {if let Some(a)=&self.fec_adaptive {if a.target_selector()!=0 {f.refresh_plan(a);f.target_tail_complete(a.target_selector());}}}
            // C1 may have zero repair allowance: the final SOURCE must seal just as the final repair.
            if f.repair_accounting.budget.is_some() && self.p4_open && f.next_id >= f.n &&
                self.segmented_send.is_none() && self.fec_suspended.is_none() && self.rescue_ready_count == 0 {
                self.p4_closing = true;
            }
            if f.next_id == 1 || f.next_id == f.k {
                if let Some(rec) = &mut self.fec_record { rec.push(f.progress_info()); }
            }
            let start = id as usize * f.block_bytes;
            let end = (start + f.block_bytes).min(f.message.len());
            self.packet_dscp = Some(dscp);
            return Some(UnreliableFragment::Fec { segment: f.segment, package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.message[start..end] });
        }
        let (msg, start_byte) = self.partial_send_slot.as_ref().unwrap();
        let whole = *start_byte == 0 && msg.len() + STP_WHOLE_HEADER_SIZE <= space;

        if !whole && *start_byte==0 && msg.len()<=payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) && self.target_dup_no_chop {return None;}
        let frag_size = space.checked_sub(if whole { STP_WHOLE_HEADER_SIZE } else { STP_FRAGMENT_HEADER_SIZE })?;
        let (msg, start_byte) = self.partial_send_slot.as_mut().unwrap();
        let start = *start_byte as usize;
        // Small messages may straddle only after whole-message fillers were exhausted.
        if frag_size == 0 && !msg.is_empty() { return None; }
        let ret_size = (msg.len() - start).min(frag_size);
        // Both frag_size and msg.len() may be zero.

        *start_byte += ret_size as u32;
        self.packet_dscp = Some(dscp);
        Some(UnreliableFragment::Plain { is_fin: *start_byte as usize == msg.len(), package_id: self.send_package_id, data: &msg[start..start + ret_size], offset: start as u32 })
    }
}

/// Fixed sender magazines sharing a single packet-rate pacer. Queue indexes never go on wire.
/// The receiver still delivers to ONE connection queue immediately on completion, unordered.
#[derive(Debug)]
pub struct SendQueues {
    target_state:crate::target_validation::RiskState,
    packet_owner: Option<Box<[u8]>>,
    queues: Vec<UnreliableSendBuffer>,
    next_queue: usize,
    // Equal-weight byte service, excluding packet padding. A dormant queue receives
    // no accumulated credit; joining queues begin at the current service clock.
    scheduled_bytes: Vec<u64>,
    queue_active: Vec<bool>,
    service_clock: u64,
    fec_owner_tags: HashMap<u64, Vec<(u8, u128)>>,
    last_queue: usize,
    last_dscp: Dscp,
    fec_adaptive: Option<crate::fec_adapt::FecAdaptiveState>,
    fec_packet_tags: Option<PacketTags>,
    fec_extra_packet_tags: HashMap<u64, Vec<u128>>,
    next_packet_seq: u64,
    fec_record: Option<Vec<crate::fec_adapt::FecMessageInfo>>,
    total_bytes_per_second: u64,
    target_duplicate:Option<(u64,Dscp,Vec<u8>)>,
    target_dup_pairs:HashMap<u64,[Option<bool>;2]>,
    target_dup_fallbacks:u64,
}

impl SendQueues {
    pub fn new(count: usize, bounds: (u32, u32, u32)) -> Self {
        assert!((1..=64).contains(&count));
        let ids = std::sync::Arc::new(PackageAllocator::new());
        let telemetry = std::sync::Arc::new(RetentionTelemetry::default());
        let target_state=crate::target_validation::RiskState::default();
        let queues = (0..count).map(|index| {
            let mut q = UnreliableSendBuffer::new(bounds.0, bounds.1, bounds.2);
            q.slipstream_queue = index;
            q.target_state=target_state.clone();
            q.package_allocator = Some(ids.clone());
            let mut quota = RetentionQuota::new(count);
            quota.telemetry = telemetry.clone();
            q.retention_quota = std::sync::Arc::new(quota);
            q
        }).collect();
        Self { target_state,scheduled_bytes: vec![0; count], queue_active: vec![false; count], service_clock: 0, fec_owner_tags: HashMap::new(), packet_owner: None, queues, next_queue: 0, last_queue: 0, last_dscp: Dscp::BestEffort, fec_adaptive: None,
            fec_packet_tags: None, fec_extra_packet_tags: HashMap::new(), next_packet_seq: 0, fec_record: None, total_bytes_per_second: 0,
            target_duplicate:None,
            target_dup_pairs:HashMap::new(),
            target_dup_fallbacks:0 }
    }
    pub fn submit_messages(&mut self, queue: usize, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        self.submit_classified_messages(queue, messages.into_iter().map(|m| (Dscp::BestEffort, m)).collect()).into_iter().map(|(_, m)| m).collect()
    }
    pub fn submit_classified_messages(&mut self, queue: usize, messages: Vec<(Dscp, Vec<u8>)>) -> Vec<(Dscp, Vec<u8>)> {
        match self.queues.get_mut(queue) { Some(q) => q.submit_classified_messages(messages), None => messages }
    }
    pub fn free_bytes(&mut self) -> Vec<u64> { self.queues.iter_mut().map(|q| q.free_bytes()).collect() }
    /// Accepted DATA (or an accepted research copy, which may leave as an outage
    /// probe) releases staged queued_send_bytes. A planned copy carries the same
    /// frames, so its own acceptance releases them instead of the original's.
    fn queued_commit(&mut self, seq: u64) {
        if self.target_copy_pending() { return; }
        for q in &mut self.queues { q.queued_ledger.commit(seq); }
    }
    fn target_copy_pending(&self)->bool {
        {return self.target_duplicate.is_some();}

    }
    pub fn has_unsent_data(&self) -> bool { self.target_copy_pending() || self.queues.iter().any(|q| q.has_unsent_data()) }
    fn set_tu_unresolved(&mut self, unresolved: bool) {
        for q in &mut self.queues { q.tu_unresolved = unresolved; }
    }
    /// R = last allowed pacing (micro-pps, 0 before the first CC pass), T = a
    /// measured RTT only (0 and the u16::MAX "unknown" sentinel are not RTTs),
    /// Q = max(1, queues holding send work: has_unsent_data, the set_rate set),
    /// E = committed unresolved DATA packets from the span ledger (0 without one).
    fn exposure_snapshot(&self, rate_upps: u64, rtt_mean: u16) -> ExposureSnapshot {
        ExposureSnapshot {
            rate_upps,
            rtt_ns: (rtt_mean != 0 && rtt_mean != u16::MAX).then(|| rtt_mean as u64 * 100_000),
            queues: (self.queues.iter().filter(|q| q.has_unsent_data()).count() as u64).max(1),
            unresolved: self.fec_adaptive.as_ref().map_or(0, |a| a.unresolved_data_packets()),
        }
    }
    fn set_exposure(&mut self, exposure: ExposureSnapshot) {
        for q in &mut self.queues { q.exposure = exposure; }
    }
    fn set_time(&mut self, now: u64, rtt: u64) {
        for q in &mut self.queues { q.fec_now_ns = now; q.fec_rtt_ns = rtt; q.fec_prune_retained(); q.fec_expire_active_rescue(); }
    }
    fn set_rate(&mut self, bytes_per_second: u64) {
        self.total_bytes_per_second = bytes_per_second;
        let active = self.queues.iter().filter(|q| q.has_unsent_data()).count().max(1) as u64;
        for q in &mut self.queues { q.current_bytes_per_second = bytes_per_second / active; }
    }
    fn refresh_queue_rates(&mut self) {
        // Same connection pacer, current equal-byte serviceable weights. A burst
        // may drain/join queues between set_rate calls; only new decisions see it.
        // Off/0 preserves the original capacity/rate snapshot exactly.
        if self.total_bytes_per_second == 0 || !self.queues.iter().any(|q| q.slipstream || q.category_bonus_percent != 0) { return; }
        let active = self.queues.iter_mut().map(|q| u64::from(q.can_emit())).sum::<u64>().max(1);
        for q in &mut self.queues { q.current_bytes_per_second = self.total_bytes_per_second / active; }
    }
    fn set_overhead(&mut self) {
        let ppm = self.fec_adaptive.as_ref().unwrap().representative_ppm();
        for q in &mut self.queues { q.fec_capacity_overhead_ppm = ppm; }
    }
    fn fec_event_repair(&mut self, e: &AcceptedCcEvent) {
        for q in &mut self.queues {
            q.fec_adaptive = self.fec_adaptive.take();
            q.p4_event_repair(e);
            self.fec_adaptive = q.fec_adaptive.take();
        }
    }
    fn fec_on_data_committed(&mut self, seq: u64, sent: u64) {
        for q in &mut self.queues { q.fec_commit_marks(seq, sent); }
        self.queued_commit(seq);
    }
    fn fec_prepare_packet(&mut self, seq: u64) {
        for q in &mut self.queues {
            if let Some(marks) = q.commit_marks.remove(&seq) { q.event_repair.marks_abandoned += marks.iter().map(|m| m.event as u64).sum::<u64>(); }
        }
        self.next_packet_seq = seq;
        if let Some(owners) = &mut self.packet_owner { owners[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize] = u8::MAX; }
        if let Some(tags) = &mut self.fec_packet_tags { tags.take((seq % PACKETS_WAITING_ACK_CAPACITY) as usize); }
        self.fec_extra_packet_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
        self.fec_owner_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
    }
    fn fec_on_packet_finalized(&mut self, seq: u64, lost: bool) {

        {
            let base=if self.target_dup_pairs.contains_key(&seq) {Some(seq)}else{seq.checked_sub(1).filter(|b|self.target_dup_pairs.contains_key(b))};
            if let Some(base)=base {
                let pair=self.target_dup_pairs.get_mut(&base).unwrap();
                pair[(seq-base) as usize]=Some(lost);
                if let [Some(a),Some(b)]=*pair {
                    self.target_dup_pairs.remove(&base);
                    self.fec_finalize_original(base,a && b);
                }
                return;
            }
        }
        self.fec_finalize_original(seq,lost);
    }
    fn fec_finalize_original(&mut self, seq:u64,lost:bool) {
        if seq > self.next_packet_seq || self.next_packet_seq - seq >= PACKETS_WAITING_ACK_CAPACITY { return; }
        let Some(tags) = &mut self.fec_packet_tags else { return; };
        let index = seq % PACKETS_WAITING_ACK_CAPACITY;
        let tag = tags.take(index as usize);
        let extra = self.fec_extra_packet_tags.remove(&index);
        let Some(owners) = &mut self.packet_owner else { return; };
        let owner = std::mem::replace(&mut owners[index as usize], u8::MAX);
        let by_owner = self.fec_owner_tags.remove(&index);
        for (owner, tag) in by_owner.into_iter().flatten()
            .chain(extra.into_iter().flatten().map(|tag| (owner, tag)))
            .chain(std::iter::once((owner, tag))).filter(|(_, tag)| *tag != 0) {
            let Some(q) = self.queues.get_mut(owner as usize) else { continue; };
            q.fec_adaptive = self.fec_adaptive.take();
            q.fec_finalize_tags(seq, lost, &[tag]);
            self.fec_adaptive = q.fec_adaptive.take();
        }
    }
    // The primary/extra tag ring belongs to one queue at a time. On a packing
    // switch, preserve its tags WITH their owner rather than routing the whole
    // physical packet to the final queue. Storage is bounded by the packet ring.
    fn select_packet_owner(&mut self, owner: usize) {
        let index = (self.next_packet_seq % PACKETS_WAITING_ACK_CAPACITY) as usize;
        let owners = self.packet_owner.get_or_insert_with(|| vec![u8::MAX; PACKETS_WAITING_ACK_CAPACITY as usize].into_boxed_slice());
        let old = owners[index];
        if old == owner as u8 { return; }
        owners[index] = owner as u8;
        if let Some(tags) = &mut self.fec_packet_tags {
            let tag = tags.take(index);
            if tag != 0 { self.fec_owner_tags.entry(index as u64).or_default().push((old, tag)); }
        }
        if let Some(tags) = self.fec_extra_packet_tags.remove(&(index as u64)) {
            self.fec_owner_tags.entry(index as u64).or_default().extend(tags.into_iter().map(|tag| (old, tag)));
        }
    }

    fn take_target_copy(&mut self,payload:&mut[u8])->usize {
        let Some((base,dscp,bytes))=self.target_duplicate.take() else {return 0};
        assert_eq!(self.next_packet_seq,base+1,"duplicate must be next data-space datagram");
        assert!(bytes.len()<=payload.len(),"TU cannot shrink across a pending copy");
        payload[..bytes.len()].copy_from_slice(&bytes);payload[bytes.len()..].fill(0xff);
        payload[0]=(payload[0]&0x0f)|TARGET_DUP_COPY;self.last_dscp=dscp;
        payload.len()
    }
    fn fill_packet(&mut self, payload: &mut [u8]) -> usize {
        let duplicate=crate::target_validation::duplicate_now(&self.target_state);

        self.fill_packet_with_dup(payload,duplicate)
    }
    fn fill_packet_with_dup(&mut self,payload:&mut[u8],_duplicate:bool)->usize {

        {
            if self.target_copy_pending() {return self.take_target_copy(payload);}
            for q in &mut self.queues {q.target_dup_no_chop=_duplicate;}
        }
        let count = self.queues.len();
        self.refresh_queue_rates();
        for i in 0..count {
            let active = self.queues[i].can_emit();
            if !self.queue_active[i] { self.scheduled_bytes[i] = self.scheduled_bytes[i].max(self.service_clock); }
            self.queue_active[i] = active;
        }
        if let Some(clock) = (0..count).filter(|&i| self.queue_active[i]).map(|i| self.scheduled_bytes[i]).min() {
            self.service_clock = self.service_clock.max(clock);
        }
        if self.service_clock > 1u64 << 60 {
            for bytes in &mut self.scheduled_bytes { *bytes = bytes.saturating_sub(self.service_clock); }
            self.service_clock = 0;
        }
        let mut blocked = 0u64;
        let mut cursor = 0;
        let mut class = None;
        while cursor + STP_WHOLE_HEADER_SIZE <= payload.len() {
            self.refresh_queue_rates();
            // Least served eligible queue wins; round-robin breaks equal byte ties.
            // Head: byte scheduler. Tail: whole FIFO heads, then small-message chops.
            // Every tier is charged, including framing, never padding.
            let mut candidate = None;
            let mut best = (true, u8::MAX, u64::MAX);
            for step in 0..count {
                let i = (self.next_queue + step) % count;
                if !self.queue_active[i] || blocked & (1u64 << i) != 0 { continue; }
                if let Some(tier) = self.queues[i].fill_tier(payload.len(), payload.len()-cursor, class) {
                    // Prefer any fillable queue within one TU of the ready clock,
                    // even its chop over an indebted queue's whole message. Use
                    // indebted data only if nobody else can use these bytes.
                    let debt = class.is_some() && self.scheduled_bytes[i] > self.service_clock + payload.len() as u64;
                    let key = (debt, tier, self.scheduled_bytes[i]);
                    if key < best { best = key; candidate = Some(i); }
                }
            }
            let Some(i) = candidate else { break; };
            self.select_packet_owner(i);
            while cursor + STP_WHOLE_HEADER_SIZE <= payload.len() {
                let q = &mut self.queues[i];
                q.next_packet_seq = self.next_packet_seq;
                q.packet_dscp = class;
                q.fec_adaptive = self.fec_adaptive.take();
                q.fec_packet_tags = self.fec_packet_tags.take();
                q.fec_extra_packet_tags = std::mem::take(&mut self.fec_extra_packet_tags);
                q.fec_record = self.fec_record.take();
                let used = q.next_fragment(payload.len(), payload.len() - cursor)
                    .map(|frag| write_fragment(&mut payload[cursor..], frag)).unwrap_or(0);
                self.fec_adaptive = q.fec_adaptive.take();
                self.fec_packet_tags = q.fec_packet_tags.take();
                self.fec_extra_packet_tags = std::mem::take(&mut q.fec_extra_packet_tags);
                self.fec_record = q.fec_record.take();
                if used == 0 {
                    // Different class, no fitting whole symbol, asynchronous encoder or
                    // package-ring pressure: try another FIFO without waiting to coalesce.
                    blocked |= 1u64 << i;
                    // Tail/class mismatch is eligible next packet. A pending encoder
                    // or ID-ring stall must not pin the ready virtual clock.
                    if cursor == 0 || !q.can_emit() { self.queue_active[i] = false; }
                    break;
                }
                q.slipstream_emitted(payload.len());
                q.queued_ledger.framed = Some(self.next_packet_seq);
                class = q.packet_dscp;
                self.last_dscp = class.unwrap();
                self.last_queue = i;
                self.next_queue = (i + 1) % count;
                self.scheduled_bytes[i] += used as u64;
                cursor += used;
                self.queue_active[i] = q.can_emit();
                break; // Re-evaluate all FIFO heads and tiers after every frame.
            }
            if let Some(clock) = (0..count).filter(|&i| self.queue_active[i]).map(|i| self.scheduled_bytes[i]).min() {
                self.service_clock = self.service_clock.max(clock);
            }
        }
        if cursor == 0 {
            // Production consumes no nonce for an empty fill. A worker can become
            // ready before the same-nonce retry, so it must get a fresh RR scan.
            // Do not reset on a single blocked queue or a partially filled packet:
            // those still share this packet's one-TU scheduling quantum.
            for q in &mut self.queues { q.interleave_last_packet = None; }
            return 0;
        }
        payload[cursor..].fill(0xff);

        if _duplicate {self.plan_target_copy(payload);}
        payload.len()
    }

    fn plan_target_copy(&mut self,payload:&mut[u8]) {
        let (messages,fec)=target_dup_counts(payload);
        if messages==0 {return;}
        // The last allocatable nonce cannot be an original needing another slot.
        if self.next_packet_seq>=crate::sequence::ACK_SPACE-2 {self.target_dup_fallbacks+=1;return;}
        assert!((1..=6).contains(&payload[0]) && payload[0]&0x30==0,"research flags overlap a frame kind");
        payload[0]|=TARGET_DUP_ORIGINAL;
        self.target_duplicate=Some((self.next_packet_seq,self.last_dscp,payload.to_vec()));
        if fec {self.target_dup_pairs.insert(self.next_packet_seq,[None,None]);}
    }
}

// The network thread keeps reading sockets whether or not the consumer keeps up, so without a
// bound a flood of peer traffic (such as BFT round data re-sent during a stall) grows this queue
// until the process is killed. Drop-oldest matches the send side, and both protocols tolerate it:
// this is the unreliable channel, BFT round data is re-sent every tick, and block chunks are
// re-requested. The cap covers the accumulating queue only; the batch the consumer last took is
// its own, so the worst case is about twice this.
pub const MAX_RECV_QUEUE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct ReceiveQueue {
    pub messages: VecDeque<(ConnectionKey, Vec<u8>)>,
    reservations: VecDeque<Option<crate::receive_memory::Reservation>>,
    pub bytes: usize,
    pub peak_bytes: usize,
    pub peak_messages: usize,
    pub dropped_messages: u64,
    pub dropped_bytes: u64,
    /// Like dropped_messages, but never reset.
    pub dropped_messages_total: u64,
}

impl ReceiveQueue {
    // Counts the queue slot too, so a flood of tiny messages is bounded as well as large ones.
    pub fn entry_bytes(buf: &Vec<u8>) -> usize {
        buf.capacity() + std::mem::size_of::<(ConnectionKey, Vec<u8>)>()
    }

    pub fn push(&mut self, key: ConnectionKey, mut buf: Vec<u8>, cap_bytes: usize) {
        self.push_reserved(key, buf, cap_bytes, None);
    }

    fn push_reserved(&mut self, key: ConnectionKey, mut buf: Vec<u8>, cap_bytes: usize, mut reservation: Option<crate::receive_memory::Reservation>) {
        // Reassembly grows the buffer by doubling, so a big message can carry up to 2x its size
        // in capacity; give that back before it is counted against the cap.
        // A budgeted buffer already has admitted capacity: reallocating to shrink
        // could temporarily keep both allocations alive outside that reservation.
        if reservation.is_none() { buf.shrink_to_fit(); }
        self.bytes += Self::entry_bytes(&buf);
        if let Some(r) = &mut reservation { r.shrink(Self::entry_bytes(&buf) + 128); }
        self.reservations.push_back(reservation);
        self.messages.push_back((key, buf));
        // Never evict the message just pushed: one message bigger than the cap is still delivered.
        while self.bytes > cap_bytes && self.messages.len() > 1 {
            let Some((_, m)) = self.messages.pop_front() else { break; };
            self.reservations.pop_front();
            let n = Self::entry_bytes(&m);
            self.bytes -= n;
            self.dropped_messages += 1;
            self.dropped_messages_total += 1;
            self.dropped_bytes += n as u64;
        }
        self.peak_bytes = self.peak_bytes.max(self.bytes);
        self.peak_messages = self.peak_messages.max(self.messages.len());
    }

    pub fn take(&mut self) -> VecDeque<(ConnectionKey, Vec<u8>)> {
        self.bytes = 0;
        // Pulled messages belong to the application; retaining them is outside the transport budget.
        self.reservations.clear();
        std::mem::take(&mut self.messages)
    }
}

fn write_fragment(payload: &mut [u8], frag: UnreliableFragment<'_>) -> usize {
    let (kind, size, data) = match frag {
        UnreliableFragment::Plain { is_fin, package_id, data, offset } => {
            let whole = is_fin && offset == 0;
            let size = if whole { STP_WHOLE_HEADER_SIZE } else { STP_FRAGMENT_HEADER_SIZE };
            if !whole {
                store_u64(&mut payload[3..11], package_id);
                store_u32(&mut payload[11..15], offset);
            }
            (if whole { 1 } else if is_fin { 3 } else { 2 }, size, data)
        }
        UnreliableFragment::Fec { segment, package_id, message_len, block_bytes, block_id, data } => {
            store_u64(&mut payload[3..11], package_id);
            store_u32(&mut payload[11..15], block_id);
            store_u32(&mut payload[15..19], message_len);
            store_u16(&mut payload[19..21], block_bytes);
            let (kind, size) = if let Some(segment) = segment {
                store_u64(&mut payload[21..29], segment.root);
                store_u32(&mut payload[29..33], segment.total);
                store_u32(&mut payload[33..37], segment.offset);
                (6, STP_SEGMENT_FEC_HEADER_SIZE)
            } else { (if message_len as usize > crate::fec::MAX_BLOCKS * block_bytes as usize { 5 } else { 4 }, STP_FEC_FRAGMENT_HEADER_SIZE) };
            (kind, size, data)
        }
    };
    payload[0] = kind;
    store_u16(&mut payload[1..3], u16::try_from(size - 3 + data.len()).expect("ordinary UDP frame length"));
    payload[size..size + data.len()].copy_from_slice(data);
    size + data.len()
}

fn fill_packet_payload_with_unreliable_fragments(payload: &mut [u8], buf: &mut UnreliableSendBuffer) -> usize {
    buf.packet_dscp = None;
    let mut cursor = 0;
    while cursor + STP_WHOLE_HEADER_SIZE <= payload.len() {
        if cursor > 0 && buf.fill_tier(payload.len(), payload.len()-cursor, buf.packet_dscp).is_none() { break; }
        let Some(frag) = buf.next_fragment(payload.len(), payload.len() - cursor) else { break; };
        cursor += write_fragment(&mut payload[cursor..], frag);
    }
    if cursor == 0 { return 0; }
    payload[cursor..].fill(0xff);
    payload.len()
}

// Retain the previous bookkeeping margin and explicitly charge the new history.
const RECEIVE_CONNECTION_BYTES: usize = (512 << 10) + crate::mtu_recovery::HISTORY_BYTES;
#[derive(Debug)]
pub struct ConnectionTrackingData {
    receive_reservation: crate::receive_memory::Reservation,
    receive_budget: std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
    pub creation_time_ns: u64,
    pub my_ip: Ipv6Addr, // TODO: use an ipv6 type that supports Default!
    pub my_transport_identity_keypair: IdentityKeyPair,
    pub two_byte_send_prefix: u16,
    pub other_ip: Ipv6Addr, // TODO: use an ipv6 type that supports Default!
    pub other_port: u16,
    pub other_transport_identity: Vec<u8>,
    pub connection_state: ConnectionState,
    pub handshake_hash: [u8; 64],
    // pub reliable_streams: ReliableStreams,

    pub unreliable_send_buffer: SendQueues,
    receive_index: ReceiveIndex,
    pub unreliable_reassembly: Vec<ReassemblySlot>,
    pub unreliable_fec: Vec<FecRecvSlot>,
}
impl ConnectionTrackingData {
    pub fn address(&self) -> STPAddress {
        STPAddress {
            ip:     self.other_ip,
            port:   self.other_port,
            magic1: self.my_transport_identity_keypair.magic1,
            key:    self.other_transport_identity.clone()
        }
    }
    pub fn is_connected(&self) -> bool { self.connection_state.is_connected() }
}


#[derive(Debug, Clone)]
pub struct ConnectionCipherTriplet {
    pub old: Option<snow::StatelessTransportState>,
    pub current: snow::StatelessTransportState,
    pub new: snow::StatelessTransportState,
    outgoing_epoch: u32,
    incoming_epoch: u32,
    // Counters here omit ACK_SPACE and are indexed by nonce space, never compared across spaces.
    incoming_largest: [Option<u64>; 2],
    incoming_current_min: [Option<u64>; 2],
    incoming_older_max: [Option<u64>; 2],
    incoming_previous_floor: [Option<u64>; 2],
    outgoing_started_ns: Option<u64>,
    outgoing_confirmed: bool,
    outgoing_first_data_nonce: Option<u64>,
    previous_until_ns: u64,
}
impl ConnectionCipherTriplet {
    pub fn new_from_old_init_only(mut current: snow::StatelessTransportState) -> Self {
        current.rekey_outgoing();
        current.rekey_incoming();
        let mut new = current.clone();
        new.rekey_incoming();
        Self { old: None, current, new, outgoing_epoch: 0, incoming_epoch: 0,
            incoming_largest: [None; 2], incoming_current_min: [None; 2], incoming_older_max: [None; 2],
            incoming_previous_floor: [None; 2],
            outgoing_started_ns: None,
            outgoing_confirmed: true, outgoing_first_data_nonce: None, previous_until_ns: 0 }
    }
    fn erase_old(&mut self) {
        if let Some(mut old) = self.old.take() {
            // Snow's manual rekey overwrites both stored ChaChaPoly key arrays.
            old.rekey_manually(Some(&[0; 32]), Some(&[0; 32]));
        }
    }
    fn expire_previous(&mut self, now: u64) {
        if now > self.previous_until_ns { self.erase_old(); }
    }
    pub fn ratchet_forward_incoming(&mut self) -> bool {
        let Some(epoch) = self.incoming_epoch.checked_add(1) else { return false; };
        self.erase_old();
        // Move the original current allocation into the previous-key slot;
        // replacing it with a clone would drop an unwiped duplicate of that key.
        std::mem::swap(&mut self.current, &mut self.new);
        self.old = Some(std::mem::replace(&mut self.new, self.current.clone()));
        self.new.rekey_incoming();
        self.incoming_epoch = epoch;
        self.incoming_previous_floor = self.incoming_older_max;
        self.incoming_older_max = self.incoming_largest;
        self.incoming_current_min = [None; 2];
        true
    }
    pub fn advance_outgoing(&mut self) -> bool {
        let Some(epoch) = self.outgoing_epoch.checked_add(1) else { return false; };
        if !self.outgoing_confirmed { return false; }
        if let Some(old) = &mut self.old { old.rekey_outgoing(); }
        self.current.rekey_outgoing();
        self.new.rekey_outgoing();
        self.outgoing_epoch = epoch;
        self.outgoing_started_ns = None;
        self.outgoing_confirmed = false;
        self.outgoing_first_data_nonce = None;
        true
    }
    fn confirm_outgoing(&mut self, highest_receipt: u64) {
        if self.outgoing_first_data_nonce.is_some_and(|first| highest_receipt >= first) {
            self.outgoing_confirmed = true;
        }
    }
    fn prepare_outgoing(&mut self, now: u64, nonce: u64) -> Option<u32> {
        let aged = self.outgoing_started_ns.is_some_and(|t| now.saturating_sub(t) >= REKEY_AGE_NS);
        // Elapsed time is the only rotation trigger. Confirmation loss defers
        // successive updates; there is no packet/byte budget or budget close.
        if aged && self.outgoing_confirmed && !self.advance_outgoing() { return None; }
        self.outgoing_started_ns.get_or_insert(now);
        if !crate::sequence::is_ack_space(nonce) { self.outgoing_first_data_nonce.get_or_insert(nonce); }
        Some(self.outgoing_epoch)
    }
    fn record_incoming(&mut self, space: usize, counter: u64, previous: bool) {
        let largest = &mut self.incoming_largest[space];
        *largest = Some(largest.unwrap_or(counter).max(counter));
        if previous {
            let floor = &mut self.incoming_older_max[space];
            *floor = Some(floor.unwrap_or(counter).max(counter));
        } else {
            let min = &mut self.incoming_current_min[space];
            *min = Some(min.unwrap_or(counter).min(counter));
        }
    }
    fn open(&mut self, nonce: u64, phase: u32, header: &[u8], ciphertext: &[u8], out: &mut [u8], now: u64) -> Result<usize, snow::Error> {
        self.expire_previous(now);
        let space = crate::sequence::is_ack_space(nonce) as usize;
        let counter = nonce & !crate::sequence::ACK_SPACE;
        if counter >= crate::sequence::ACK_SPACE - 1 { return Err(snow::Error::Decrypt); }
        if phase == self.incoming_epoch & 1 {
            if self.incoming_older_max[space].is_some_and(|floor| counter <= floor) { return Err(snow::Error::Decrypt); }
            let n = self.current.read_message_with_additional_data(nonce, header, ciphertext, out)?;
            self.record_incoming(space, counter, false);
            return Ok(n);
        }
        // Previous and next have the same parity. Try only retained previous,
        // then prederived next, with monotone per-space epoch boundaries.
        // Stateless AEAD never changes keys/nonce state on either failed trial;
        // next authenticates the original ciphertext, not the scratch output.
        if phase <= 1 && now <= self.previous_until_ns &&
            self.incoming_previous_floor[space].is_none_or(|floor| counter > floor) &&
            self.incoming_current_min[space].is_none_or(|min| counter < min) {
            if let Some(old) = &self.old {
                if let Ok(n) = old.read_message_with_additional_data(nonce, header, ciphertext, out) {
                    self.record_incoming(space, counter, true);
                    return Ok(n);
                }
            }
        }
        if phase > 1 || self.incoming_epoch == u32::MAX ||
            self.incoming_largest[space].is_some_and(|max| counter <= max) { return Err(snow::Error::Decrypt); }
        let n = self.new.read_message_with_additional_data(nonce, header, ciphertext, out)?;
        // All fallible ordering and authentication checks precede promotion.
        if !self.ratchet_forward_incoming() { return Err(snow::Error::Decrypt); }
        self.previous_until_ns = now.saturating_add(PREVIOUS_KEY_NS);
        self.record_incoming(space, counter, false);
        Ok(n)
    }
}
impl Drop for ConnectionCipherTriplet {
    fn drop(&mut self) {
        self.erase_old();
        self.current.rekey_manually(Some(&[0; 32]), Some(&[0; 32]));
        self.new.rekey_manually(Some(&[0; 32]), Some(&[0; 32]));
    }
}

/// Encrypt once, then retain the exact result across local WouldBlock retries.
/// None closes the connection before actual nonce or epoch exhaustion.
fn seal_connected_packet(cipher: &mut Option<ConnectionCipherTriplet>, prefix: u16,
    nonce: u64, payload: &[u8], out: &mut [u8], now: u64) -> Option<usize> {
    if nonce == u64::MAX || nonce == crate::sequence::ACK_SPACE - 1 { return None; }
    let epoch = if let Some(c) = cipher { c.prepare_outgoing(now, nonce)? } else { 0 };
    store_u16(&mut out[..2], prefix);
    store_u32(&mut out[2..6], (nonce as u32 & crate::sequence::COUNTER_MASK) | ((epoch & 1) << 31));
    let (header, body) = out.split_at_mut(CONNECTED_HEADER_SIZE);
    let n = if let Some(c) = cipher {
        c.current.write_message_with_additional_data(nonce, header, payload, body).ok()?
    } else { body.get_mut(..payload.len())?.copy_from_slice(payload); payload.len() };
    Some(CONNECTED_HEADER_SIZE + n)
}

#[derive(Debug)]
pub enum ConnectionState {
    SendingClientHelloPlaintext {
        last_sent_time_ns: u64,
        hello_packet_payload: Vec<u8>,
    },
    SendingClientHello {
        magic1: u64,

        last_sent_time_ns: u64,
        hello_packet_payload: Vec<u8>,
        handshake: snow::HandshakeState,
    },
    SendingServerHelloPlaintext {
        magic2: u64,
        last_sent_time_ns: u64,
        hello_packet_payload: Vec<u8>,
    },
    SendingServerHello {
        cipher: ConnectionCipherTriplet,
        magic1: u64,
        magic2: u64,

        last_sent_time_ns: u64,
        hello_packet_payload: Vec<u8>,
    },
    Connected(ConnectionStateConnected),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingSendKind { Ack, Data, Keepalive, MtuProbe, Outage, Reachability, ReachabilityCurrent }
impl PendingSendKind {
    fn is_generic(self) -> bool { matches!(self, Self::Reachability | Self::ReachabilityCurrent) }
}

/// At most one refused datagram per connection. Nothing else may use its nonce
/// until these exact ciphertext bytes are accepted. Allocation is failure-only.
#[derive(Debug)]
struct PendingSend {
    kind: PendingSendKind,
    bytes: Vec<u8>,
    plaintext: Vec<u8>,
    dscp: Dscp,
}

#[derive(Debug)]
pub struct ConnectionStateConnected {
    target_state:crate::target_validation::RiskState,
    pending_send: Option<PendingSend>,
    locally_blocked: bool,
    pub cipher: Option<ConnectionCipherTriplet>,
    pub magic1: u64,
    pub magic2: u64,

    pub send_sequence_number: u64,
    pub send_ack_sequence_number: u64,
    pub receive_sequences: crate::sequence::ReceiveSequences,
    target_dup_receive:Option<Box<crate::sequence::ReceiveSequences>>,
    pub last_sent_data_packet: u64,
    pub last_sent_could_have_sent_data_packet: u64,
    pub last_ack_received_time: u64,
    // Generic reachability receipts must not repeatedly erase ordinary pacing credit.
    last_pacing_ack_received_time: u64,
    /// Fresh authenticated inbound activity; never a substitute for delivery/CC feedback.
    last_peer_packet_received_time: u64,
    pub last_status_print_time: u64,
    pub packet_since_last_print: u64,
    pub packet_lost_since_last_print: u64,
    pub max_in_flight_since_last_print: u64,

    pub ack_timer: u64,
    active_ack_feedback: bool,
    pub ack_receiver: crate::ack::AckReceiver,
    /// Highest positively acknowledged peer receipt; holes are NOT declarations of loss.
    pub highest_peer_acked: Option<u64>,
    pub peer_ack_delay_us: u32,
    pub peer_ce_count: u64,
    loss_timer: LossTimer,
    ack_hole: AckHole,
    delivery_growth: DeliveryGrowth,

    // Finite timestamp history: receipts older than ~4.3 s (bucket-phase dependent)
    // cannot feed RTT or either delivery-growth stream, even if ACK history retains them.
    // A sustained majority beyond that horizon can pin growth; fail closed, never guess a send time.
    pub send_time_band: [u64; 1024], // 1024 buckets of 4.194 ms giving 4.295 seconds of tracking.
    pub send_time_band_head_index: u64, // monotonic time ns / 4_194_304 aka 0x400000

    pub RTT_sample_sums: [u32; 16],   // sum of RTT measurements per ack, in 0.1 ms units
    pub RTT_sample_counts: [u16; 16], // count of RTT measurements per ack
    pub RTT_sample_cursor: u64,
    /// Research minimum over this connection's lifetime; intentionally NOT reset on outage.
    target_min_rtt_ns:u64,
    delay_event_window:DelayEventWindow,
    delay_giveup:DelayGiveupState,
    delay_curve_beta:Option<f64>,
    fresh_hold:FreshHold,
    pub RTT_mean: u16,
    pub RTT_mean_cursor: u64, // RTT_sample_cursor value RTT_mean was last computed from

    pub ack_arrival_times: [u64; 16], // timestamp_ns of each ack arrival, ring buffer
    pub ack_pace_estimate: u16,       // median inter-ack gap in 0.1 ms units, clamped to RTT_mean*2

    pub packets_waiting_ack_field: [u64; PACKETS_WAITING_ACK_WORDS],
    rand_background_bits:Option<Box<[u64]>>,
    // head is the send_sequence_number
    pub packets_waiting_ack_tail: u64,
    // Highest non-generic committed sequence + 1. An older generic hole keeps
    // the ordinary flight active until the tail has passed this frontier.
    active_send_frontier: u64,

    pub current_tu: u64,
    recovery: crate::mtu_recovery::Recovery,
    // Effective TU cannot change while an immutable current-TU datagram retries.
    deferred_tu: Option<u64>,
    tu_assessment_settled: bool,
    pub last_sent_tu_probe_time_ns: u64,
    pub tu_probe_sequence_number: u64,
    pub tu_probe_size: u64,
    pub tu_probe_failed_count: u64,
    // A pre-shrink attempt keeps its identity but cannot alter the reset search.
    tu_probe_obsolete: bool,

    pub packets_in_flight: u64,
    pub send_pacer_acc_ns: u64,
    pub congestion_event_time_ns: u64,
    pub congestion_event_rate_upps: u64,
    /// Startup exits only on an accepted loss/CE event (including opt-in persistent delay).
    pub cc_startup_done: bool,
    outage: OutageState,
    pub stats: ConnectionStats,
    pub loss_window_start_ns: u64,
    pub loss_count_in_window: u64,
    loss_episodes: LossEpisodes,
    pub is_app_limited: bool,
    pub app_limit_time_offset: u64,
    /// Sender feedback and receiver echo are independent directions.
    pub ecn_congestion_received: bool,
    pub ecn_oldest_send_time: u64,
    /// Sequence of the packet whose send time anchors the pending CE signal (exact CE evidence).
    pub ecn_oldest_seq: u64,
    /// ACCEPTED congestion cuts awaiting delivery to the send queues (bounded; p4-event-repair evidence).
    pub accepted_cc_events: Vec<AcceptedCcEvent>,
    pub accepted_cc_dropped: u64,
    pub accepted_cc_missing_anchor: u64,
    /// Per sequence number in [tail - CAPACITY, tail): declared lost and not yet acked since
    /// (spurious-loss detection). Same ring indexing as packets_waiting_ack_field.
    pub declared_lost_field: Box<[u64; PACKETS_WAITING_ACK_WORDS]>,
    /// Receiver ground truth over the peer's sequence numbers.
    pub rx_tracker: RxSeqTracker,
}
pub fn new_connection_state_connected(cipher: Option<ConnectionCipherTriplet>, magic1: u64, magic2: u64, timestamp_ns: u64) -> ConnectionState {
    ConnectionState::Connected(ConnectionStateConnected {
        target_state:Default::default(),
        pending_send: None,
        locally_blocked: false,
        cipher,
        magic1,
        magic2,
        send_sequence_number: 0,
        send_ack_sequence_number: crate::sequence::ACK_SPACE,
        receive_sequences: Default::default(),
        target_dup_receive:None,
        last_sent_data_packet: 0,
        last_sent_could_have_sent_data_packet: 0,
        last_ack_received_time: timestamp_ns,
        last_pacing_ack_received_time: timestamp_ns,
        last_peer_packet_received_time: timestamp_ns,
        last_status_print_time: timestamp_ns,
        packet_since_last_print: 0,
        packet_lost_since_last_print: 0,
        max_in_flight_since_last_print: 0,
        ack_timer: u64::MAX,
        active_ack_feedback: false,
        ack_receiver: Default::default(),
        highest_peer_acked: None,
        peer_ack_delay_us: 0,
        peer_ce_count: 0,
        loss_timer: LossTimer::default(),
        ack_hole: AckHole::default(),
        delivery_growth: DeliveryGrowth::new(timestamp_ns, RATE_FLOOR_UPPS),
        send_time_band: [0; 1024],
        send_time_band_head_index: 0,
        RTT_sample_sums: [0; 16],
        RTT_sample_counts: [0; 16],
        RTT_sample_cursor: 0,
        target_min_rtt_ns:u64::MAX,
        delay_event_window:DelayEventWindow::default(),
        delay_giveup:DelayGiveupState::default(),
        delay_curve_beta:None,
        fresh_hold:FreshHold::NONE,
        RTT_mean: u16::MAX,
        RTT_mean_cursor: 0,
        ack_arrival_times: [0; 16],
        ack_pace_estimate: 0,
        packets_waiting_ack_field: [0; PACKETS_WAITING_ACK_WORDS],
        rand_background_bits:None,
        packets_waiting_ack_tail: 0,
        active_send_frontier: 0,

        // RESEARCH: a new connection starts at SMALL with one startup 1204 candidate.
        current_tu: crate::mtu_recovery::SMALL,
        recovery: crate::mtu_recovery::Recovery::new_connection(timestamp_ns),
        deferred_tu: None,
        tu_assessment_settled: false,
        last_sent_tu_probe_time_ns: 0,
        tu_probe_sequence_number: u64::MAX,
        tu_probe_size: 0,
        tu_probe_failed_count: 0,
        tu_probe_obsolete: false,

        packets_in_flight: 0,
        send_pacer_acc_ns: 0,
        congestion_event_time_ns: 0,
        congestion_event_rate_upps: RATE_FLOOR_UPPS,
        cc_startup_done: false,
        outage: OutageState::default(),
        stats: ConnectionStats::default(),
        loss_window_start_ns: 0,
        loss_count_in_window: 0,
        loss_episodes: LossEpisodes::default(),
        is_app_limited: false,
        app_limit_time_offset: 0,
        ecn_congestion_received: false,
        ecn_oldest_send_time: 0,
        ecn_oldest_seq: 0,
        accepted_cc_events: Vec::new(),
        accepted_cc_dropped: 0,
        accepted_cc_missing_anchor: 0,
        declared_lost_field: Box::new([0; PACKETS_WAITING_ACK_WORDS]),
        rx_tracker: RxSeqTracker::default(),
    })
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool { if let ConnectionState::Connected(_) = self { true } else { false } }
}

/// Starting rate and lowest rate the congestion control allows, in millionths of a packet per
/// second: 100 packets/s. At the previous 1 packet/s a fresh or quiet connection paced every
/// packet up to a second apart, which added up to ~1 s to every message's delivery.
pub const RATE_FLOOR_UPPS: u64 = 100 * 1_000_000;

/// Fixed-memory research scheduler diagnostics; all zero when disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlipstreamInfo {
    pub heads_evaluated: u64,
    pub heads_eligible: u64,
    pub ineligible_short: u64,
    pub ineligible_long: u64,
    pub ineligible_other: u64,
    pub follower_starts_tiny_whole_or_packed: u64,
    pub follower_starts_ordinary_fec: u64,
    pub follower_starts_segmented_giant: u64,
    pub head_packets_alternated: u64,
    pub follower_packets: u64,
    pub head_promotions: u64,
    pub max_concurrent_started_messages: u64,
    pub recursive_windows: u64,
    pub rtt_ns_min: u64,
    pub rtt_ns_max: u64,
    pub fair_share_pps_min: f64,
    pub fair_share_pps_max: f64,
}
impl SlipstreamInfo {
    fn merge(&mut self, other: Self) {
        macro_rules! add { ($($f:ident),*) => { $(self.$f += other.$f;)* }; }
        add!(heads_evaluated, heads_eligible, ineligible_short, ineligible_long,
            ineligible_other, follower_starts_tiny_whole_or_packed, follower_starts_ordinary_fec,
            follower_starts_segmented_giant, head_packets_alternated, follower_packets,
            head_promotions, recursive_windows);
        self.max_concurrent_started_messages = self.max_concurrent_started_messages.max(other.max_concurrent_started_messages);
        if other.heads_evaluated > 0 {
            if self.heads_evaluated == other.heads_evaluated {
                self.rtt_ns_min = other.rtt_ns_min;
                self.fair_share_pps_min = other.fair_share_pps_min;
            } else {
                self.rtt_ns_min = self.rtt_ns_min.min(other.rtt_ns_min);
                self.fair_share_pps_min = self.fair_share_pps_min.min(other.fair_share_pps_min);
            }
            self.rtt_ns_max = self.rtt_ns_max.max(other.rtt_ns_max);
            self.fair_share_pps_max = self.fair_share_pps_max.max(other.fair_share_pps_max);
        }
    }
}

/// Cumulative per-connection counters, for measurement.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionStats {
    #[cfg(feature="research_target_validation")] pub loss_events_gated:u64,
    #[cfg(feature="research_target_validation")] pub loss_events_cut_queue:u64,
    #[cfg(feature="research_target_validation")] pub loss_events_cut_valve:u64,
    pub slipstream: SlipstreamInfo,
    /// Logical messages receiving the frozen duration-category bonus (any layout).
    pub category_bonus_messages: u64,
    /// Initial extra repair symbols planned across layouts (TU restarts included).
    pub category_bonus_repairs: u64,
    /// p4-event-repair evidence (all zero but accepted_* when STP_P4_EVENT_REPAIR=0).
    pub event_repair: EventRepairInfo,
    pub budget_base: BudgetBaseInfo,
    pub rand_bg_packets:u64, pub rand_bg_lost:u64,
    pub rand_p_ppm:u64, pub rand_p_base_ppm:u64,
    /// Extra kernel-committed datagrams/UDP bytes and whole messages protected.
    pub dup_datagrams:u64,
    pub dup_bytes:u64,
    pub dup_messages:u64,
    /// Eligible datagrams skipped at data-nonce exhaustion (no near-TU fallback).
    pub dup_fallbacks:u64,
    /// Persistent-delay windows above threshold; accepted is the subset passing the CE event guard.
    pub delay_events_raised:u64,
    pub delay_events_accepted:u64,
    /// Competitive give-up transitions and high-delay windows suppressed while suspended.
    pub delay_suspensions:u64,
    pub delay_rearms:u64,
    pub delay_events_suppressed:u64,
    /// Low closed windows ignored because the minimum suspension hold is active.
    pub delay_hold_blocked_rearms:u64,
    pub delay_cuts_beta_override:u64,
    /// Outcomes under the optional fractional, bounded-time effectiveness rule.
    pub delay_effective:u64,
    pub delay_ineffective:u64,
    /// Current smoothed RTT in microseconds (0 until sampled).
    pub rtt_us: u64,
    /// Last CC command in micro-packets/second, after the local pacing ceiling.
    pub cc_rate_upps: u64,
    /// Number of application queue-empty transitions (not congestion events).
    pub cc_app_limited_entries: u64,
    /// Current path transmission unit, including STP header/tag inside the UDP payload.
    pub udp_payload_tu: u64,
    /// Constant-memory send-loop burst and curve-inversion diagnostics.
    pub pacing_batches: u64,
    pub pacing_packets: u64,
    pub pacing_max_burst: u64,
    pub pacing_burst_hist: [u64; 7],
    pub pacing_error_samples: u64,
    pub pacing_error_abs_sum_ns: u64,
    pub pacing_error_max_ns: u64,
    pub pacing_history_records: u64,
    /// Total CPU of the shared network thread (Linux); not per-connection CPU.
    pub network_cpu_user_us: u64,
    pub network_cpu_sys_us: u64,
    /// Commanded slots; unused credits are discarded on starvation.
    pub pacing_commanded_packets: u64,
    /// Sequenced packets sent (data and keepalive), and their UDP payload bytes. Acks,
    /// handshake packets and transmission-unit probes are not counted.
    pub packets_sent: u64,
    pub bytes_sent: u64,
    /// ACK UDP datagrams and UDP payload bytes (prefix and authentication tag included).
    pub ack_packets_sent: u64,
    pub ack_bytes_sent: u64,
    /// Successfully emitted ACKs requesting IP CE because the shared app receive
    /// ring was full at this send attempt (not proof the OS/path preserved CE).
    pub ack_app_overload_ce_sent: u64,
    pub ack_packets_received: u64,
    pub ack_delay_us_max: u32,
    pub rtt_samples: u64,
    /// Sequenced packets declared lost (never acked in time).
    pub packets_lost: u64,
    /// Largest declared-loss fraction over four staggered approximately-RTT send-time
    /// windows (all sequenced packets; TU-probe losses excluded). Instrumentation only.
    pub max_rtt_loss_ppm: u32,
    pub max_rtt_loss_window_packets: u64,
    /// Adaptive FEC only (else 0): the floored loss estimate new messages are sized for, and the
    /// latest short-term loss sample it was built from.
    pub fec_loss_estimate: f64,
    pub fec_last_loss_sample: f64,

    // ---- sender: what happened to the declarations ----
    /// Declared-lost packets for which an ack arrived later anyway (the packet had arrived; the
    /// declaration was spurious). Counted once per packet, while the ack still reports it (the
    /// receiver's 4096-packet ack window) and within PACKETS_WAITING_ACK_CAPACITY of the tail.
    pub spurious_losses: u64,
    /// Transmission-unit probes that went unacked (not counted in packets_lost).
    pub tu_probes_lost: u64,
    /// Data packets STP_TEST_DROP_* skipped (they are counted in packets_sent).
    pub test_dropped: u64,
    /// Sequence numbers used so far: every sequenced packet including acks and TU probes.
    pub seq_numbers_used: u64,

    // ---- receiver ground truth (packets the peer sent us; every sequenced packet type) ----
    /// Authenticated sequenced packets received from the peer (duplicates excluded).
    pub rx_packets: u64,
    /// Highest peer sequence number seen + 1 (the span the peer has used, as far as we know).
    pub rx_seq_span: u64,
    /// rx_seq_span - rx_packets: sequence numbers never received (so far). The last
    /// RX_REORDER_WINDOW of them may still arrive.
    pub rx_lost: u64,
    /// Arrivals below the highest sequence number already seen (reordered or late).
    pub rx_reordered: u64,
    /// Of those, arrivals so late they had already been counted as part of a loss burst.
    pub rx_late_beyond_window: u64,
    pub rx_duplicates: u64,
    /// Loss bursts (runs of consecutive missing sequence numbers) by length: 1, 2, 3-4, 5-8,
    /// 9-16, 17-64, 65+. Final once RX_REORDER_WINDOW behind the highest seen; snapshots also
    /// count the last window provisionally.
    pub rx_burst_hist: [u64; 7],
    pub rx_bursts: u64,

    // ---- receiver message reassembly (a message can be lost after all its packets were acked) ----
    /// Messages completed (plain reassembly or FEC decode) and handed to the receive queue.
    pub rx_messages_completed: u64,
    /// Unique admitted data-class packets synthetically CE-marked while the app
    /// receive ring was full. Kernel CE on the same packet is not counted twice.
    pub rx_app_overload_ce_marks: u64,
    /// Partial messages discarded because a newer package took their slot, and the message bytes
    /// they had received (plain: bytes held; FEC: blocks x block size).
    pub rx_partial_evicted: u64,
    pub rx_partial_evicted_bytes: u64,
    /// Fragments that did not fit the partial message in their slot (it was discarded and restarted).
    pub rx_insert_failures: u64,
    /// Fragments of a package older than the one holding their slot (dropped).
    pub rx_stale_fragments: u64,
    /// Frames for permanently retired identities, ignored but physically ACKed.
    pub rx_stale_identity_frames: u64,
    /// Worker delivery minus its last successfully enqueued FEC fragment, on receiver's
    /// monotonic clock. Completion can precede surplus repair packets arriving.
    pub fec_decode_last_tail_ns: u64,
    pub fec_decode_max_tail_ns: u64,
    /// Authenticated FEC fragments erased by decoder admission or the bounded ingress queue.
    pub fec_ingress_dropped_blocks: u64,
    /// Packages refused a decoder at least once (later fragments may retry successfully).
    pub fec_decode_admission_refusals: u64,
    /// Inactive decoder workers retired after max(4 RTTs, 2 seconds).
    pub fec_decode_timeouts: u64,
    /// Oldest inactive decoder retired under admission pressure after max(4 RTTs, 2 seconds).
    pub fec_decode_preemptions: u64,
    /// Codecs first refused or retired because a peer/global worker limit was hit.
    pub fec_worker_limit_events: u64,
    /// Peak concurrently open asynchronous FEC codecs, including draining workers.
    pub fec_decode_peak_workers: u64,
    /// Plain fragments refused by the receive budget, including small whole messages.
    pub rx_plain_admission_refusals: u64,
}

/// Burst-length class boundaries of `ConnectionStats::rx_burst_hist` (inclusive upper bounds).
pub const RX_BURST_CLASS_MAX: [u64; 6] = [1, 2, 4, 8, 16, 64];
pub const RX_BURST_CLASS_NAMES: [&str; 7] = ["1", "2", "3-4", "5-8", "9-16", "17-64", "65+"];
/// Reorder tolerance of the receiver's loss tracking, in sequence numbers.
pub const RX_REORDER_WINDOW: u64 = 1024;

/// Receiver-side sequence tracking: a sliding bitmap of the last RX_REORDER_WINDOW sequence
/// numbers. A sequence number is finalized (received or missing) as it slides out, which closes
/// or extends the current loss run. O(1) amortized per packet (one finalize per sequence number).
#[derive(Debug, Clone)]
pub struct RxSeqTracker {
    base: u64,              // lowest sequence number not yet finalized
    highest_plus1: u64,
    bits: [u64; (RX_REORDER_WINDOW / 64) as usize],
    run: u64,               // current run of missing finalized sequence numbers
}

impl Default for RxSeqTracker {
    fn default() -> Self { RxSeqTracker { base: 0, highest_plus1: 0, bits: [0; (RX_REORDER_WINDOW / 64) as usize], run: 0 } }
}

impl RxSeqTracker {
    fn close_run(&mut self, stats: &mut ConnectionStats) {
        if self.run > 0 {
            let class = RX_BURST_CLASS_MAX.iter().position(|&m| self.run <= m).unwrap_or(6);
            stats.rx_burst_hist[class] += 1;
            stats.rx_bursts += 1;
            self.run = 0;
        }
    }
    fn finalize_to(&mut self, new_base: u64, stats: &mut ConnectionStats) {
        // Sequence numbers more than a window ahead of base were never in the bitmap: all missing.
        let bitmap_end = new_base.min(self.base + RX_REORDER_WINDOW);
        while self.base < bitmap_end {
            let i = (self.base % RX_REORDER_WINDOW) as usize;
            let got = self.bits[i / 64] & (1u64 << (i % 64)) != 0;
            self.bits[i / 64] &= !(1u64 << (i % 64));
            if got { self.close_run(stats); } else { self.run += 1; }
            self.base += 1;
        }
        if new_base > self.base { self.run += new_base - self.base; self.base = new_base; }
    }
    /// For a stats snapshot: count the not-yet-final window as if nothing more will arrive, so
    /// short runs see their bursts (the live tracker is untouched).
    pub fn provisional_bursts(&self, stats: &mut ConnectionStats) {
        let mut t = self.clone();
        t.finalize_to(t.highest_plus1, stats);
        t.close_run(stats);
    }
    /// One authenticated packet with (virtual) sequence number `seq` arrived.
    pub fn on_packet(&mut self, seq: u64, stats: &mut ConnectionStats) {
        if seq < self.base {
            // Already finalized as missing: it was late, not lost. (Its burst stays counted.)
            stats.rx_packets += 1;
            stats.rx_reordered += 1;
            stats.rx_late_beyond_window += 1;
        } else {
            if seq >= self.base + RX_REORDER_WINDOW { self.finalize_to(seq + 1 - RX_REORDER_WINDOW, stats); }
            let i = (seq % RX_REORDER_WINDOW) as usize;
            if self.bits[i / 64] & (1u64 << (i % 64)) != 0 { stats.rx_duplicates += 1; return; }
            self.bits[i / 64] |= 1u64 << (i % 64);
            stats.rx_packets += 1;
            if seq < self.highest_plus1 { stats.rx_reordered += 1; }
        }
        self.highest_plus1 = self.highest_plus1.max(seq + 1);
        stats.rx_seq_span = self.highest_plus1;
        stats.rx_lost = self.highest_plus1.saturating_sub(stats.rx_packets);
    }
}

/// Network-thread-wide counters, for measurement.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkThreadStats {
    /// Datagrams the kernel dropped on this socket (receive buffer full), cumulative; None where
    /// the platform does not report it (Linux: SO_MEMINFO / /proc/net/udp{,6}).
    pub kernel_rx_drops: Option<u64>,
    /// Network-thread loop: iterations, longest gap between consecutive iteration starts
    /// (includes the 150 us idle sleep), and gaps over 1 / 10 / 100 ms.
    pub loop_iterations: u64,
    pub max_loop_gap_ns: u64,
    pub loop_gaps_over_1ms: u64,
    pub loop_gaps_over_10ms: u64,
    pub loop_gaps_over_100ms: u64,
    /// Complete messages dropped because the receive queue was full (cumulative).
    pub recv_queue_dropped_messages: u64,
}

/// Test-only time-varying loss schedule (see STP_TEST_DROP_SCHEDULE in the network thread).
#[derive(Debug, Clone)]
pub struct TestDropSchedule { steps: Vec<(u64, u64)>, period_ns: Option<u64> }

impl TestDropSchedule {
    pub fn parse(spec: &str) -> Option<TestDropSchedule> {
        let mut steps = Vec::new();
        let mut period_ns = None;
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let secs = |t: &str| t.trim().trim_end_matches('s').parse::<f64>().ok().map(|x| (x * 1e9) as u64);
            if let Some(p) = part.strip_prefix('@') { period_ns = Some(secs(p)?.max(1)); continue; }
            let (t, pct) = part.split_once(':')?;
            let pct: f64 = pct.trim().trim_end_matches('%').parse().ok()?;
            steps.push((secs(t)?, (pct * 10_000.0).round().clamp(0.0, 1e6) as u64));
        }
        if steps.is_empty() { return None; }
        steps.sort();
        Some(TestDropSchedule { steps, period_ns })
    }
    fn from_env() -> Option<TestDropSchedule> {
        let v = std::env::var("STP_TEST_DROP_SCHEDULE").ok()?;
        Some(Self::parse(&v).unwrap_or_else(|| panic!("bad STP_TEST_DROP_SCHEDULE {v:?}")))
    }
    pub fn ppm_at(&self, t_ns: u64) -> u64 {
        let t = match self.period_ns { Some(p) => t_ns % p, None => t_ns };
        self.steps.iter().take_while(|s| s.0 <= t).last().map_or(0, |s| s.1)
    }
}

/// p4-event-repair: the send-history time of a packet committed at `t`, exactly as
/// increment_sequence_number_and_account encodes (t / 0x400000) and get_send_time_for_sequence_number decodes.
pub fn send_history_time_ns(t: u64) -> u64 { (t / 0x400000) * 0x400000 }

pub fn get_send_time_for_sequence_number(sequence_number: u64, send_time_band: &[u64; 1024], send_time_band_head_index: u64) -> u64 {
    if sequence_number >= send_time_band[(send_time_band_head_index % 1024) as usize] { return u64::MAX; }

    let mut cursor = send_time_band_head_index;
    while cursor > send_time_band_head_index.saturating_sub(1023) {
        if send_time_band[((cursor-1) % 1024) as usize] <= sequence_number && sequence_number < send_time_band[(cursor % 1024) as usize] {
            return cursor * 0x400000;
        }
        cursor -= 1;
    }
    0 // failed lookup
}

#[derive(Debug, PartialEq, Eq)]
enum PositiveReceipt { PendingData, PendingProbe, LateData, PreOutage }
impl PositiveReceipt {
    fn is_data(&self) -> bool { matches!(self, Self::PendingData | Self::LateData) }
    fn is_pending(&self) -> bool { matches!(self, Self::PendingData | Self::PendingProbe) }
}

impl ConnectionStateConnected {
    fn peer_expired(&self, now: u64, authenticated_peer_liveness: bool) -> bool {
        let last_activity = if authenticated_peer_liveness {
            self.last_ack_received_time.max(self.last_peer_packet_received_time)
        } else { self.last_ack_received_time };
        OutageState::expired(now, last_activity)
    }
    fn send_exhausted(&self, buf: &SendQueues) -> bool {
        self.send_sequence_number >= crate::sequence::ACK_SPACE - 1 || self.send_ack_sequence_number == u64::MAX ||
            buf.queues.first().and_then(|q| q.package_allocator.as_ref())
                .is_some_and(|ids| ids.load(std::sync::atomic::Ordering::Relaxed) == u64::MAX)
    }
    fn reserve_ack_nonce(&mut self) -> Option<u64> {
        let nonce = self.send_ack_sequence_number;
        if nonce == u64::MAX { return None; }
        self.send_ack_sequence_number = nonce.checked_add(1)?;
        Some(nonce)
    }
    fn promote_tu(&mut self, tu: u64, now: u64) {
        if self.pending_send.as_ref().is_some_and(|p| matches!(p.kind,
            PendingSendKind::Data | PendingSendKind::Keepalive | PendingSendKind::Outage | PendingSendKind::Reachability | PendingSendKind::ReachabilityCurrent)) {
            self.deferred_tu = Some(tu);
        } else { self.apply_effective_tu(tu, now); }
    }
    fn apply_effective_tu(&mut self, tu: u64, now: u64) {
        if tu < self.current_tu {
            self.tu_probe_failed_count = 0;
            self.tu_probe_obsolete = true;
        }
        self.recovery.effective_tu(self.current_tu, tu, now);
        self.current_tu = tu;
    }
    fn upward_probe_deadline(&self, now: u64) -> u64 {
        self.recovery.upward_plan(self.current_tu, self.last_sent_tu_probe_time_ns,
            self.tu_probe_failed_count, now).map_or(u64::MAX, |(_, due)| due)
    }
    fn prepare_upward_probe(&mut self, now: u64) -> bool {
        let Some((size, due)) = self.recovery.upward_plan(self.current_tu,
            self.last_sent_tu_probe_time_ns, self.tu_probe_failed_count, now) else { return false; };
        if now < due { return false; }
        self.recovery.upward_issued(size);
        self.tu_probe_size = size;
        self.tu_probe_obsolete = false;
        true
    }
    fn finish_upward_probe(&mut self, success: bool, sent: u64, now: u64) {
        self.tu_probe_sequence_number = u64::MAX;
        if self.tu_probe_obsolete || self.tu_probe_size <= self.current_tu {
            self.recovery.upward_finished(self.tu_probe_size, false);
            return;
        }
        if success {
            if !self.recovery.can_promote(self.tu_probe_size, sent, now) {
                self.recovery.upward_finished(self.tu_probe_size, false);
                return;
            }
            self.promote_tu(self.tu_probe_size, now);
            self.tu_probe_failed_count = 0;
            self.recovery.upward_finished(self.tu_probe_size, true);
        } else {
            self.recovery.upward_finished(self.tu_probe_size, false);
            self.recovery.upward_failed(self.current_tu, self.tu_probe_size, now);
            self.tu_probe_failed_count = self.tu_probe_failed_count.saturating_add(1);
        }
    }
    fn downshift_for_recovery(&mut self, copy_pending: bool, now: u64) {
        if copy_pending { self.deferred_tu = Some(crate::mtu_recovery::SMALL); }
        else { self.promote_tu(crate::mtu_recovery::SMALL, now); }
    }
    /// Validate the independently sampled nonce before admitting any ACK effects.
    /// A size report is never receipt evidence; missing history remains unknown.
    fn ack_sample_size_matches(&self, ack: &crate::ack::BitmapAck) -> bool {
        let expected = self.recovery.sent_bytes(ack.sample_seq).or_else(|| {
            (ack.sample_seq == self.tu_probe_sequence_number
                && ack.sample_seq < self.send_sequence_number)
                .then_some(self.tu_probe_size as u16)
        });
        expected.is_none_or(|bytes| bytes == ack.sample_udp_payload_bytes)
    }
    fn decode_peer_ack(&self, payload: &[u8]) -> Option<crate::ack::BitmapAck> {
        let ack = crate::ack::BitmapAck::decode(payload)?;
        (ack.highest < self.send_sequence_number && self.ack_sample_size_matches(&ack))
            .then_some(ack)
    }
    // Only call after native exact first-positive admission. A missing metadata
    // record defaults to ordinary, never suppressing real application's progress.
    fn on_positive_receipt(&mut self, sequence: u64, now: u64) -> bool {
        if !self.recovery.is_generic(sequence) { self.last_pacing_ack_received_time = now; }
        self.last_ack_received_time = now;
        self.outage.pending_since_ns = None;
        self.recovery.acknowledged(sequence, now, self.current_tu)
    }
    // The receive loop and socket-free tests share first-positive admission.
    // Clearing either ring bit here makes duplicate receipts ineligible.
    fn take_positive_receipt(&mut self, index: u64) -> Option<PositiveReceipt> {
        let bit = index % PACKETS_WAITING_ACK_CAPACITY;
        let mask = 1u64 << (bit % 64);
        if index >= self.packets_waiting_ack_tail && index < self.send_sequence_number {
            let word = &mut self.packets_waiting_ack_field[(bit / 64) as usize];
            if *word & mask == 0 { return None; }
            *word &= !mask;
            Some(if index == self.tu_probe_sequence_number {
                PositiveReceipt::PendingProbe
            } else { PositiveReceipt::PendingData })
        } else if index < self.packets_waiting_ack_tail
            && self.packets_waiting_ack_tail - index <= PACKETS_WAITING_ACK_CAPACITY {
            let word = &mut self.declared_lost_field[(bit / 64) as usize];
            if *word & mask == 0 { return None; }
            *word &= !mask;
            Some(if index < self.outage.ignore_loss_before_seq {
                PositiveReceipt::PreOutage
            } else { PositiveReceipt::LateData })
        } else { None }
    }
    fn send_time(&self, sequence: u64) -> u64 {
        get_send_time_for_sequence_number(sequence, &self.send_time_band, self.send_time_band_head_index)
    }
    fn observe_feedback_payload(&mut self, payload: &[u8]) {
        self.active_ack_feedback |= payload.first() != Some(&0xff);
    }
    fn update_feedback_deadline(&mut self, now: u64) {
        self.ack_timer = self.ack_receiver.feedback_deadline(now);
        if self.ack_timer == u64::MAX { self.active_ack_feedback = false; }
    }
    fn account_send(&mut self, actual_ns: u64) {
        self.outage.pending_since_ns.get_or_insert(actual_ns);
        if self.send_sequence_number >= crate::sequence::ACK_SPACE - 1 { return; }
        increment_sequence_number_and_account(actual_ns, &mut self.send_sequence_number,
            &mut self.send_time_band, &mut self.send_time_band_head_index, &mut self.packets_waiting_ack_field);
        self.active_send_frontier = self.send_sequence_number;
    }
}

// ring of in-flight sequence numbers; head-tail span must stay under capacity or bits alias
pub const PACKETS_WAITING_ACK_WORDS: usize = 4096;
pub const PACKETS_WAITING_ACK_CAPACITY: u64 = PACKETS_WAITING_ACK_WORDS as u64 * 64;

/// Same full nonce horizon as the old 4 MiB dense tag ring. Pages exist only
/// while they contain unresolved FEC symbols, and are freed at finalization.
#[derive(Debug)]
struct PacketTags {
    pages: Box<[Option<Box<TagPage>>]>,
}
#[derive(Debug)]
struct TagPage { tags: [u128; 256], live: usize }
impl Default for PacketTags {
    fn default() -> Self {
        Self { pages: (0..PACKETS_WAITING_ACK_CAPACITY as usize / 256).map(|_| None).collect() }
    }
}
impl PacketTags {
    fn get(&self, index: usize) -> u128 {
        self.pages[index / 256].as_ref().map_or(0, |p| p.tags[index % 256])
    }
    fn set(&mut self, index: usize, tag: u128) {
        let page = &mut self.pages[index / 256];
        if tag == 0 && page.is_none() { return; }
        let p = page.get_or_insert_with(|| Box::new(TagPage { tags: [0; 256], live: 0 }));
        let old = std::mem::replace(&mut p.tags[index % 256], tag);
        p.live = p.live + usize::from(tag != 0) - usize::from(old != 0);
        if p.live == 0 { *page = None; }
    }
    fn take(&mut self, index: usize) -> u128 {
        let tag = self.get(index);
        if tag != 0 { self.set(index, 0); }
        tag
    }
}

pub fn increment_sequence_number_and_account(send_time_ns: u64, send_sequence_number: &mut u64, send_time_band: &mut [u64; 1024], send_time_band_head_index: &mut u64, packets_waiting_ack_field: &mut [u64; PACKETS_WAITING_ACK_WORDS]) {
    {
        let bit_index = *send_sequence_number % PACKETS_WAITING_ACK_CAPACITY;
        packets_waiting_ack_field[(bit_index / 64) as usize] |= 1u64 << (bit_index % 64);
    }

    let new_head_index = send_time_ns / 0x400000;
    if new_head_index >= *send_time_band_head_index + 1023 {
        let current = *send_sequence_number;
        for i in 0..1024 { send_time_band[i] = current; }

        send_time_band[(new_head_index % 1024) as usize] = current + 1;
        *send_time_band_head_index = new_head_index;
        *send_sequence_number = current + 1;
        return;
    }
    if new_head_index > *send_time_band_head_index {
        let current = *send_sequence_number;
        // this loop does not run for the single increment case. Only jumps over slots.
        for i in *send_time_band_head_index+1..new_head_index { send_time_band[(i % 1024) as usize] = current; }

        send_time_band[(new_head_index % 1024) as usize] = current + 1;
        *send_time_band_head_index = new_head_index;
        *send_sequence_number = current + 1;
        return;
    }
    // equal
    *send_sequence_number += 1;
    send_time_band[(new_head_index % 1024) as usize] = *send_sequence_number;
}

pub fn get_connected<'a>(m: &'a HashMap::<ConnectionKey, ConnectionTrackingData>, k: &ConnectionKey) -> Option<&'a ConnectionTrackingData> {
    let connection = m.get(k)?;
    if !connection.is_connected() { return None; }
    Some(connection)
}
pub fn get_connected_mut<'a>(m: &'a mut HashMap::<ConnectionKey, ConnectionTrackingData>, k: &ConnectionKey) -> Option<&'a mut ConnectionTrackingData> {
    let connection = m.get_mut(k)?;
    if !connection.is_connected() { return None; }
    Some(connection)
}

pub fn connection_state_string(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::SendingClientHelloPlaintext { .. } => "SendingClientHelloPlaintext",
        ConnectionState::SendingClientHello          { .. } => "SendingClientHello",
        ConnectionState::SendingServerHelloPlaintext { .. } => "SendingServerHelloPlaintext",
        ConnectionState::SendingServerHello          { .. } => "SendingServerHello",
        ConnectionState::Connected(_)                        => "Connected",
    }
}

pub fn connect_to_endpoint(
    connections_map: &mut HashMap::<ConnectionKey, ConnectionTrackingData>,
    my_connect_keypair: &IdentityKeyPair,
    endpoint: &STPAddress,
    send_buffer_params: (u32, u32, u32),
    send_queue_count: usize,
    budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
    connection_receive_limit: usize,
    max_message_size: usize,
) {
    let Some(receive_reservation) = budget.reserve(RECEIVE_CONNECTION_BYTES) else { return; };
    assert!(my_connect_keypair.magic1 == endpoint.magic1);

    let magic2_block = build_magic2_client_block();
    let connection_state = if my_connect_keypair.magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
        let mut hello_packet_payload = vec![0u8; 6 + 32 + MAGIC2_BLOCK_SIZE];
        store_u48(&mut hello_packet_payload[0..6], my_connect_keypair.magic1);
        assert_eq!(my_connect_keypair.public.len(), 32);
        hello_packet_payload[6..6+32].copy_from_slice(&my_connect_keypair.public[..]);
        hello_packet_payload[6+32..6+32+MAGIC2_BLOCK_SIZE].copy_from_slice(&magic2_block);

        ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns: 0, hello_packet_payload }
    } else {
        let mut hello_packet_payload = vec![0u8; 1024];
        store_u48(&mut hello_packet_payload[0..6], my_connect_keypair.magic1);
        let mut handshake = noise_initiator(
            crypto_string_from_connect_magic1(my_connect_keypair.magic1).unwrap(),
            &hello_packet_payload[0..6], &my_connect_keypair.private, &endpoint.key).unwrap();

        let handshake_size = handshake.write_message(&magic2_block, &mut hello_packet_payload[6..]).unwrap();
        hello_packet_payload.truncate(6+handshake_size);
        hello_packet_payload.shrink_to_fit();

        ConnectionState::SendingClientHello { magic1: my_connect_keypair.magic1, last_sent_time_ns: 0, hello_packet_payload, handshake }
    };

    connections_map.insert(
        ConnectionKey::from(endpoint),
        ConnectionTrackingData {
            receive_reservation,
            receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(budget, connection_receive_limit).with_worker_limit(receive_worker_limit(max_message_size, send_queue_count)),
            creation_time_ns: monotonic_clock_ns(),
            my_ip: Ipv6Addr::UNSPECIFIED,
            my_transport_identity_keypair: my_connect_keypair.clone(),
            two_byte_send_prefix: load_u16(&my_connect_keypair.public[0..2]) << 1,
            other_ip: endpoint.ip,
            other_port: endpoint.port,
            other_transport_identity: endpoint.key.clone(),
            connection_state,
            handshake_hash: [0u8; 64],
            unreliable_send_buffer: SendQueues::new(send_queue_count, send_buffer_params),
            receive_index: ReceiveIndex::default(),
            unreliable_reassembly: ReassemblySlot::new_ring(1024),
            unreliable_fec: FecRecvSlot::new_ring(1024),
        },
    );
}

const        VERBOSE                :bool=0!=                (1);

macro_rules! pod { ($($item:item)*) => { $(#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] $item)* }; }

// This formula and flush_contiguous_segment's prefix growth form one policy.
// The decoded Vec and its lease move into the root without a second unit copy.
// Geometric growth is attempted only through shared-budget admission; it can
// exceed 1.5*total while the joining part is still live. If admission refuses,
// exact-end growth needs at most total + one unit payload bytes (destination
// end + sparse bytes <= end + total-prefix). Root metadata is 256 + 40*cap
// (8-byte extent + 32-byte part entry), cap <= max(4, 2*N) with every unit
// >= ADAPTIVE_MIN_UNIT_LEN, so N <= floor(total/446). A splittable root has
// total >= 892: 160 <= ceil(total/2) and 80*N <= 0.18*total, so this metadata
// fits in ceil(total/2) + 256 + groups*64 (SegmentParts' cached sums live in
// the slot itself, not in the charged heap tables). Thus the unchanged allowance suffices for
// exact-end progress, even when a later unit is larger than half the root.
fn segment_reassembly_peak(total: usize) -> usize {
    total + total.div_ceil(2) + total.min(FEC_SEGMENT_BYTES)
        + 256 + total.div_ceil(FEC_SEGMENT_BYTES) * 64
}

/// Base metadata of a segmented root (was 256 + groups*64 up front; ranges
/// and the sparse part table are now charged dynamically as they bind/grow).
const SEGMENT_ROOT_METADATA: usize = 256;
const FEC_INGRESS_SLOT_BYTES: usize = std::mem::size_of::<(u32, Vec<u8>)>() + 128;

fn fec_ingress_bytes(layout: crate::fec::MessageLayout) -> usize {
    // One complete source unit, including channel slots, at EACH ingress level.
    // A 2 MiB unit absorbs ~28 ms at 600 Mbit/s. Unlike a fixed 32 MiB per
    // level this scales down with the codec; decoding drains concurrently.
    (layout.k * (layout.block_bytes + FEC_INGRESS_SLOT_BYTES)).min(MAX_FEC_INGRESS_BYTES)
}

// Provisional conservative P3 allowance: Wi-Fi fleet peaked at seven codecs
// outside a ceiling-hit CC flood. Re-measure after CC overshoot and P4 fixes.
const FEC_WORKERS_PER_QUEUE: usize = 8;
// This dimension sizes the existing byte cap, not the runtime codec count.
fn receive_worker_capacity_dimension(max_message_size: usize, queues: usize) -> usize {
    let unit = max_message_size.min(FEC_SEGMENT_BYTES);
    if unit.div_ceil(FEC_MIN_BLOCK_BYTES) <= FEC_INLINE_MAX_BLOCKS { return 0; }
    (queues * max_message_size.div_ceil(unit).min(FEC_WORKERS_PER_QUEUE)).min(MAX_FEC_DECODE_WORKERS)
}
fn receive_worker_limit(max_message_size: usize, queues: usize) -> usize {
    // Smaller units may use the already reserved byte capacity without an
    // artificial per-queue permit bottleneck. Every admission still reserves
    // its full lease; the unchanged process-wide ceiling also remains hard.
    if receive_worker_capacity_dimension(max_message_size, queues) == 0 { 0 }
    else { MAX_FEC_DECODE_WORKERS }
}

/// Hard per-peer receive cap derived only from REQUIRED local application configuration.
/// Completed-but-unpulled messages share this cap, so a stalled application can
/// cause backpressure; pulling hands ownership to the application and releases it.
pub fn receive_connection_memory_limit(max_message_size: usize, queues: usize) -> Option<usize> {
    if !(1..=64).contains(&queues) { return None; }
    let max_message_size = max_message_size.min(MAX_JUMBOGRAM_LEN);
    let unit = max_message_size.min(FEC_SEGMENT_BYTES);
    let workers = receive_worker_capacity_dimension(max_message_size, queues);
    let decoder = if unit > FEC_MIN_BLOCK_BYTES {
        let layout = wire_fec_layout(unit, FEC_MIN_BLOCK_BYTES)?;
        // k*block_bytes < unit+block_bytes, and every wire width fits u16.
        // This upper bound covers all allowed widths, not just honest TU sizes.
        let ingress = (unit + u16::MAX as usize + layout.k * FEC_INGRESS_SLOT_BYTES).min(MAX_FEC_INGRESS_BYTES);
        crate::fec::receive_memory_charge(layout, workers != 0, ingress)?
    } else { 0 };
    // Inline-only peers need no workers or worker ingress; their FIFO queues can
    // each have one inline codec. Hostile extra roots still share the hard cap.
    let codecs = if workers != 0 { workers } else { queues };
    let metadata = 1024 * (256 + max_message_size.div_ceil(FEC_SEGMENT_BYTES) * 64);
    queues.checked_mul(segment_reassembly_peak(max_message_size))?
        .checked_add(codecs.checked_mul(decoder)?)?.checked_add(metadata)
}

/// Sparse decoded units of one segmented root, sorted by DESCENDING offset so
/// the lowest (next joinable) part is popped from the end in O(1). Cached sums of
/// part lengths and capacities replace per-call scans (bytes_received, charge,
/// flush). Lookup is a binary search. Insertion is a Vec insert: O(1) for in-order
/// or reverse-order arrival, an O(n) element shift in the explicit worst case
/// (ascending arrival behind a hole); n <= floor(total/ADAPTIVE_MIN_UNIT_LEN).
#[derive(Debug, Default)]
struct SegmentParts { desc: Vec<(u32, Vec<u8>)>, bytes: usize, part_capacity: usize }
impl SegmentParts {
    fn with_capacity(n: usize) -> Self { Self { desc: Vec::with_capacity(n), bytes: 0, part_capacity: 0 } }
    fn capacity(&self) -> usize { self.desc.capacity() }
    fn reserve_exact(&mut self, additional: usize) { self.desc.reserve_exact(additional) }
    fn position(&self, offset: u32) -> usize { self.desc.partition_point(|p| p.0 > offset) }
    fn contains(&self, offset: u32) -> bool { self.desc.get(self.position(offset)).is_some_and(|p| p.0 == offset) }
    /// Caller guarantees `!contains(offset)` and spare capacity (prepaid table).
    fn insert(&mut self, offset: u32, part: Vec<u8>) {
        debug_assert!(!self.contains(offset) && self.desc.len() < self.desc.capacity());
        self.bytes += part.len();
        self.part_capacity += part.capacity();
        let i = self.position(offset);
        self.desc.insert(i, (offset, part));
    }
    /// Length of the part starting exactly at `prefix`, if it is the lowest part.
    fn next_len(&self, prefix: usize) -> Option<usize> {
        self.desc.last().filter(|p| p.0 as usize == prefix).map(|p| p.1.len())
    }
    fn pop_next(&mut self) -> Vec<u8> {
        let (_, part) = self.desc.pop().expect("joinable part");
        self.bytes -= part.len();
        self.part_capacity -= part.capacity();
        part
    }
}
impl std::ops::Deref for SegmentParts {
    type Target = [(u32, Vec<u8>)];
    fn deref(&self) -> &Self::Target { &self.desc }
}

#[derive(Debug, Default)]
pub struct ReassemblySlot {
    reservation: Option<crate::receive_memory::Reservation>,
    pub buf: Vec<u8>,
    pub total_len: Option<u32>,
    pub received: Vec<(u32, u32)>, // sorted non-overlapping non-adjacent ranges: [start, end)
    pub package_id: u64,
    completed: bool,
    segment_parts: Option<SegmentParts>,
    // RESEARCH profile 5 root ledger: every admitted unit range (offset, len),
    // sorted, disjoint, immutable, kept (incl. the completed prefix) until the
    // root is done. Bound: floor(total/ADAPTIVE_MIN_UNIT_LEN) entries. A middle
    // insert is an O(n) Vec shift (explicit worst case); append is a push.
    segment_extents: Vec<(u32, u32)>,
    last_segment_ns: u64, // Last accepted plain fragment or segment symbol.
}

impl ReassemblySlot {
    pub fn new() -> Self {
        Self {
            reservation: None,
            buf: Vec::new(),
            total_len: None,
            received: Vec::new(),
            package_id: 0,
            completed: false,
            segment_parts: None,
            segment_extents: Vec::new(),
            last_segment_ns: 0,
        }
    }

    /// Message bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.segment_parts.as_ref().map_or_else(|| self.received.iter().map(|&(s, e)| (e - s) as u64).sum(),
            |parts| self.buf.len() as u64 + parts.bytes as u64)
    }

    pub fn new_ring(size: usize) -> Vec<ReassemblySlot> {
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size { vec.push(Self::new()); }
        vec
    }

    /// Plain messages never need the lazy-FEC segment path. Bound their high-water
    /// allocation and reserve only the arrived extent (not a claimed larger total).
    fn admit(&mut self, offset: usize, len: usize, budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>) -> bool {
        if self.completed { return true; }
        if self.segment_parts.is_some() { return false; }
        let Some(end) = offset.checked_add(len).filter(|&n| n <= FEC_SEGMENT_BYTES) else { return false; };
        let buf_cap = end.max(self.buf.capacity());
        let range_cap = if self.received.len() == self.received.capacity() { (self.received.capacity() * 2).max(4) } else { self.received.capacity() };
        let Some(bytes) = range_cap.checked_mul(8).and_then(|r| buf_cap.checked_add(r)?.checked_add(256)) else { return false; };
        match &mut self.reservation {
            Some(r) => { if !r.grow(bytes) { return false; } },
            None => { let Some(r) = budget.reserve(bytes) else { return false; }; self.reservation = Some(r); },
        }
        if buf_cap > self.buf.capacity() { self.buf.reserve_exact(buf_cap - self.buf.len()); }
        if range_cap > self.received.capacity() { self.received.reserve_exact(range_cap - self.received.len()); }
        true
    }

    fn admit_segment(&mut self, segment: FecSegment, layout: crate::fec::MessageLayout,
        block_id: u32, data_len: usize, now_ns: u64,
        budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>) -> bool {
        // Do not charge even metadata for a header without a valid symbol.
        if !segment.valid(layout.len) || segment.total as usize > budget.limit() ||
            !valid_fec_symbol(layout, block_id, data_len) { return false; }
        let in_use = self.completed || self.total_len.is_some() || !self.received.is_empty();
        if in_use && self.package_id != segment.root {
            if segment.root < self.package_id { return false; }
            *self = Self::new(); // eviction drops sparse parts and their charge
        }
        self.package_id = segment.root;
        if self.completed { return true; }
        if self.total_len.is_some_and(|n| n != segment.total) ||
            (!self.buf.is_empty() && self.segment_parts.is_none()) || !self.received.is_empty() { return false; }
        if self.segment_parts.is_none() {
            // First unit of this root: base metadata plus a small ledger and an
            // equally sized sparse part table, reserved in one step so a refusal
            // leaves the slot untouched. The table is prepaid with every bound
            // range (parts.cap >= extents.cap >= extents.len >= parts.len), so a
            // decoded unit hands over without growing metadata at completion.
            // Later ranges and part bytes are charged inside the unchanged hard cap.
            let Some(r) = budget.reserve(SEGMENT_ROOT_METADATA + 4 * std::mem::size_of::<(u32, u32)>()
                + 4 * std::mem::size_of::<(u32, Vec<u8>)>()) else { return false; };
            self.reservation = Some(r);
            self.segment_parts = Some(SegmentParts::with_capacity(4));
            self.segment_extents = Vec::with_capacity(4);
            self.total_len = Some(segment.total);
        }
        self.bind_segment_extent(segment, layout.len, now_ns)
    }

    /// Exact already-bound range: accepted (restart/fresh id or duplicate). Any
    /// other overlap, incl. same offset with a different length, is refused
    /// before receipt. A new range grows the charge FIRST; refusal binds nothing.
    fn bind_segment_extent(&mut self, segment: FecSegment, len: usize, now_ns: u64) -> bool {
        let (offset, end) = (segment.offset as usize, segment.offset as usize + len);
        let ext = &self.segment_extents;
        let i = ext.partition_point(|e| (e.0 as usize) < offset);
        if ext.get(i).is_some_and(|e| e.0 as usize == offset && e.1 as usize == len) {
            self.last_segment_ns = now_ns;
            return true;
        }
        if ext.get(i).is_some_and(|e| (e.0 as usize) < end) ||
            i > 0 && ext[i - 1].0 as usize + ext[i - 1].1 as usize > offset { return false; }
        if self.segment_extents.len() == self.segment_extents.capacity() {
            // Ledger and part table grow together under ONE checked charge
            // before anything binds; refusal leaves both and the charge as is.
            let cap = (self.segment_extents.capacity() * 2).max(4);
            let Some(parts_cap) = self.segment_parts.as_ref().map(|p| p.capacity().max(cap)) else { return false; };
            let charge = self.segment_charge(cap, Some(parts_cap), 0);
            let Some(reservation) = self.reservation.as_mut() else { return false; };
            if !reservation.grow(charge) { return false; }
            self.segment_extents.reserve_exact(cap - self.segment_extents.len());
            let parts = self.segment_parts.as_mut().unwrap();
            parts.reserve_exact(parts_cap - parts.len());
        }
        self.segment_extents.insert(i, (segment.offset, len as u32));
        self.last_segment_ns = now_ns;
        true
    }

    /// Whole current charge of a segmented root: base + ledger capacity + sparse
    /// part-table capacity + destination + sparse part bytes (+ `extra` bytes).
    fn segment_charge(&self, extent_cap: usize, parts_cap: Option<usize>, extra: usize) -> usize {
        let parts = self.segment_parts.as_ref();
        SEGMENT_ROOT_METADATA + extent_cap * std::mem::size_of::<(u32, u32)>()
            + parts_cap.unwrap_or_else(|| parts.map_or(0, |p| p.capacity())) * std::mem::size_of::<(u32, Vec<u8>)>()
            + self.buf.capacity() + parts.map_or(0, |p| p.part_capacity) + extra
    }

    /// Late unit (fresh id or duplicate) whose exact bound range is already in
    /// the delivered/contiguous prefix: accept coverage, allocate no decoder.
    fn segment_covered(&self, segment: FecSegment, len: usize) -> bool {
        self.package_id == segment.root && (self.completed ||
            self.segment_parts.is_some() && segment.offset as usize + len <= self.buf.len())
    }

    /// Ownership handoff of one decoded unit: the decoded Vec moves into the
    /// prepaid part table and its lease (`donor`, same budget, already shrunk by
    /// the caller to the Vec's capacity after the decode arena was released) is
    /// absorbed into the root without release/reacquire. No payload copy and no
    /// second charge of the same bytes. A stale, unbound or duplicate unit drops
    /// the Vec first and then its lease; it never touches the root charge.
    fn finish_segment(&mut self, segment: FecSegment, message: Vec<u8>, mut donor: crate::receive_memory::Reservation)
        -> Option<(Vec<u8>, crate::receive_memory::Reservation)> {
        // Same-generation identity: root id, total and an admission-bound range.
        // Only a range bound at admission may complete; it is immutable, so a
        // range wholly inside the contiguous prefix is an exact old duplicate.
        let bound = self.package_id == segment.root && !self.completed && self.total_len == Some(segment.total)
            && segment.valid(message.len()) && self.segment_extents.binary_search(&(segment.offset, message.len() as u32)).is_ok()
            && self.reservation.is_some() && donor.bytes() >= message.capacity()
            && self.segment_parts.as_ref().is_some_and(|parts| segment.offset as usize >= self.buf.len()
                && parts.len() < parts.capacity() && !parts.contains(segment.offset));
        if !bound {
            drop(message); drop(donor);
            return None; // a blocked join is retried by sweep_segment_roots
        }
        donor.shrink(message.capacity());
        if let Err(donor) = self.reservation.as_mut().unwrap().absorb(donor) {
            drop(message); drop(donor);
            return None;
        }
        // Prepaid with the bound range: this push never reallocates the table.
        self.segment_parts.as_mut().unwrap().insert(segment.offset, message);
        self.flush_contiguous_segment()
    }

    /// Join every part that extends the contiguous prefix; complete the root
    /// once the prefix covers the total. Also the retry path of the periodic
    /// root sweep. Each destination growth first tries the geometric step,
    /// then the exact end of the joining part; if both are refused the parts
    /// stay in the table under the unchanged root charge for a later retry.
    fn flush_contiguous_segment(&mut self) -> Option<(Vec<u8>, crate::receive_memory::Reservation)> {
        if self.completed { return None; }
        let total = self.total_len? as usize;
        let metadata = SEGMENT_ROOT_METADATA + self.segment_extents.capacity() * std::mem::size_of::<(u32, u32)>()
            + self.segment_parts.as_ref()?.capacity() * std::mem::size_of::<(u32, Vec<u8>)>();
        let parts = self.segment_parts.as_mut()?;
        let reservation = self.reservation.as_mut()?;
        let mut bytes: usize = parts.part_capacity;
        // Only a contiguous completed prefix grows the destination. A high-offset
        // segment remains sparse; neither a header nor one decoded group can pin
        // the claimed total. Geometric growth avoids quadratic realloc/copy work;
        // see segment_reassembly_peak for the bound of either growth step.
        // Do not concatenate into a second full-message buffer.
        while let Some(next_len) = parts.next_len(self.buf.len()) {
            if self.buf.is_empty() {
                let part = parts.pop_next();
                bytes -= part.capacity();
                self.buf = part;
            } else {
                let end = self.buf.len() + next_len;
                if end > self.buf.capacity() {
                    let geometric = (self.buf.capacity() * 2).max(end).min(total);
                    let capacity = if reservation.grow(metadata + geometric + bytes) { geometric }
                        else if reservation.grow(metadata + end + bytes) { end }
                        else { return None; }; // retained: parts, prefix and charge unchanged
                    self.buf.reserve_exact(capacity - self.buf.len());
                }
                let part = parts.pop_next();
                self.buf.extend_from_slice(&part);
                bytes -= part.capacity();
            }
            reservation.shrink(metadata + self.buf.capacity() + bytes);
        }
        if self.buf.len() != total { return None; }
        self.segment_parts = None;
        self.segment_extents = Vec::new();
        let message = std::mem::take(&mut self.buf);
        let mut reservation = self.reservation.take().unwrap();
        reservation.shrink(message.capacity() + 256);
        self.completed = true;
        self.total_len = None;
        Some((message, reservation))
    }

    fn take_complete(&mut self) -> Vec<u8> {
        self.reservation = None;
        self.completed = true;
        self.received = Vec::new();
        self.total_len = None;
        std::mem::take(&mut self.buf)
    }

    /// returns (success, is_complete)
    pub fn insert(&mut self, offset: usize, data: &[u8], is_fin: bool) -> (bool, bool) {
        if self.completed { return (true, false); } // duplicate fragments must not redeliver

        let Some(end) = offset.checked_add(data.len()).filter(|&n| n <= FEC_SEGMENT_BYTES) else { return (false, false); };
        let start = offset as u32;
        let end = end as u32;

        // If this is the final fragment, derive total_len from offset + data.len()
        if is_fin {
            if let Some(existing) = self.total_len {
                if existing != end { return (false, false); }
            } else {
                if let Some(&(_, last_end)) = self.received.last() {
                    if last_end > end { return (false, false); }
                }
                self.total_len = Some(end);
                self.buf.resize(end as usize, 0);
            }
        }

        // Empty fragment — no data to insert, bounds check offset then check completion
        if data.is_empty() {
            if let Some(tl) = self.total_len {
                if start > tl { return (false, false); }
            }
            let complete = self.total_len.is_some_and(|tl| tl == 0 || (self.received.len() == 1 && self.received[0] == (0, tl)));
            return (true, complete);
        }

        // Bounds check against total_len if known
        if let Some(tl) = self.total_len {
            if start >= tl || end > tl { return (false, false); }
        }

        // Grow buf if needed (total_len not yet known)
        if end as usize > self.buf.len() {
            self.buf.resize(end as usize, 0);
        }

        // Find all ranges that overlap or are adjacent to [start, end)
        let first = self.received.partition_point(|&(_, e)| e < start);
        let last = self.received.partition_point(|&(s, _)| s <= end);

        // Verify overlapping bytes match
        for &(rs, re) in &self.received[first..last] {
            let ov_start = start.max(rs) as usize;
            let ov_end = end.min(re) as usize;
            if ov_start < ov_end {
                let data_off = ov_start - offset;
                if self.buf[ov_start..ov_end] != data[data_off..data_off + (ov_end - ov_start)] {
                    return (false, false);
                }
            }
        }

        // Write new data (overlapping parts verified equal)
        self.buf[offset..offset + data.len()].copy_from_slice(data);

        // Merge: union of [start, end) with all overlapping/adjacent ranges
        let merged_start = if first < last { self.received[first].0.min(start) } else { start };
        let merged_end = if first < last { self.received[last - 1].1.max(end) } else { end };
        self.received.splice(first..last, std::iter::once((merged_start, merged_end)));

        let complete = self.total_len.is_some_and(|tl| self.received.len() == 1 && self.received[0] == (0, tl));
        (true, complete)
    }
}

/// Receiver state of one FEC-coded package, kept in a ring parallel to `unreliable_reassembly`
/// and addressed by the shared full-ID ReceiveIndex.
#[derive(Default)]
pub struct FecRecvSlot {
    pub package_id: u64,
    segment: Option<FecSegment>,
    state: FecRecvState,
    reservation: Option<crate::receive_memory::Reservation>,
    /// Blocks handed to this slot's decoder (for loss accounting on eviction).
    blocks_received: u32,
    last_block_ns: u64, // Last successfully admitted symbol, never a probe ACK.
    /// One recovery extension per admitted symbol; None also handles timestamp zero.
    recovery_resume_ns: Option<u64>,
    ingress_dropped: u64,
    admission_refused: bool,
    worker_limit_refused: bool,
}

#[derive(Default)]
enum FecRecvState {
    #[default]
    Empty,
    /// Inline systematic symbols, without a native codec until a repair arrives.
    SourceOnly(Box<crate::fec::SourceOnly>),
    /// Small message with repair: decoded on the network thread.
    Inline(Box<crate::fec::MessageDecoder>),
    /// Big message: persistent decoder advanced one symbol per received packet.
    /// The bounded ingress and admission accounting retain their existing limits.
    Worker { tx: std::sync::mpsc::SyncSender<(u32, Vec<u8>)>, job: Option<Box<FecDecodeJob>>, message_len: usize, block_bytes: usize, generation: std::sync::Arc<()> },
    /// Delivered (or given up): late surplus blocks of this package are ignored.
    Done,
}

impl std::fmt::Debug for FecRecvSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = match &self.state { FecRecvState::Empty => "empty", FecRecvState::SourceOnly(_) => "source-only", FecRecvState::Inline(_) => "inline", FecRecvState::Worker { .. } => "worker", FecRecvState::Done => "done" };
        write!(f, "FecRecvSlot {{ package_id: {}, state: {st} }}", self.package_id)
    }
}

impl FecRecvSlot {
    pub fn new_ring(size: usize) -> Vec<FecRecvSlot> {
        (0..size).map(|_| FecRecvSlot::default()).collect()
    }
    pub fn in_use(&self) -> bool { !matches!(self.state, FecRecvState::Empty) }
    fn last_active_ns(&self) -> u64 {
        self.last_block_ns.max(self.recovery_resume_ns.unwrap_or(0))
    }
    /// Message bytes received so far (blocks x block size).
    pub fn bytes_received(&self) -> u64 { self.blocks_received as u64 * self.params().map_or(0, |p| p.1) as u64 }
    fn params(&self) -> Option<(usize, usize)> {
        match &self.state {
            FecRecvState::SourceOnly(s) => Some((s.layout.len, s.layout.block_bytes)),
            FecRecvState::Inline(d) => Some((d.message_len(), d.block_bytes())),
            FecRecvState::Worker { message_len, block_bytes, .. } => Some((*message_len, *block_bytes)),
            _ => None,
        }
    }
}

/// Large decoder admissions per pump; overload erases a fragment and retries
/// admission later. Small (<=256-block) messages retain the source-only fast path.
pub const MAX_FEC_DECODE_WORKERS: usize = 8;
/// Byte cap for each ingress level, including channel slots (not just block payload).
pub const MAX_FEC_INGRESS_BYTES: usize = 32 << 20;

fn fec_inactive_grace_ns(rtt: u16, _pressure: bool) -> u64 {
    // Admission pressure must not discard recently ACKed decoder state. Refuse
    // the new codec until an old one meets the normal abandonment grace.
    let rtt_ns = if rtt == u16::MAX { 0 } else { rtt as u64 * 100_000 };
    (4 * rtt_ns).max(2_000_000_000)
}

/// Incomplete plain messages and roots follow fragment inactivity, not keepalive ACKs.
fn retire_inactive_segment_roots(slots: &mut [ReassemblySlot], now_ns: u64, grace_ns: u64) {
    for slot in slots {
        if !slot.completed && slot.reservation.is_some() && now_ns.saturating_sub(slot.last_segment_ns) > grace_ns {
            *slot = ReassemblySlot::new();
        }
    }
}

/// Periodic root maintenance, resumable at each root rather than each connection.
/// Retry a retained join BEFORE expiring that root. A paused scan leaves later
/// roots untouched; the caller keeps this cursor and the connection queue head.
/// Each root flush remains one indivisible work unit, like packet completion.
/// Returns (number delivered, scan finished); a finished cursor is not reset here.
fn sweep_segment_roots_bounded(slots: &mut [ReassemblySlot], cursor: &mut usize,
    now_ns: u64, grace_ns: u64, mut checkpoint: impl FnMut() -> bool,
    mut deliver: impl FnMut(Vec<u8>, crate::receive_memory::Reservation)) -> (u64, bool) {
    let mut delivered = 0;
    while *cursor < slots.len() {
        if checkpoint() { return (delivered, false); }
        let slot = &mut slots[*cursor];
        let joinable = !slot.completed && slot.segment_parts.as_ref().is_some_and(|parts|
            parts.next_len(slot.buf.len()).is_some());
        if joinable {
            if let Some((message, reservation)) = slot.flush_contiguous_segment() {
                delivered += 1;
                deliver(message, reservation);
            }
        }
        retire_inactive_segment_roots(std::slice::from_mut(slot), now_ns, grace_ns);
        *cursor += 1;
    }
    (delivered, true)
}

/// Root checkpoint for one FEC sweep entry (one call of the bounded sweep).
/// The entry's own checkpoint already paid for its first root, at any cursor:
/// a caller deadline that passed during an owed unit must still advance one
/// root, never re-run cursor-0 work forever. Later roots need a fresh sample:
/// a root join is an indivisible work unit, not cached-clock bookkeeping.
fn sweep_entry_root_checkpoint(budget: &mut crate::pump::Deadline) -> impl FnMut() -> bool + '_ {
    sweep_entry_root_checkpoint_with_clock(budget, monotonic_clock_ns)
}

fn sweep_entry_root_checkpoint_with_clock<'a>(budget: &'a mut crate::pump::Deadline,
    mut clock: impl FnMut() -> u64 + 'a) -> impl FnMut() -> bool + 'a {
    let mut first_root_prepaid = true;
    move || {
        if std::mem::take(&mut first_root_prepaid) { return false; }
        if budget.sampled(clock()) { true } else { budget.progressed(); false }
    }
}

fn valid_fec_symbol(layout: crate::fec::MessageLayout, block_id: u32, data_len: usize) -> bool {
    let expect = if (block_id as usize) < layout.k {
        crate::fec::block_len(layout.len, layout.block_bytes, block_id)
    } else { layout.block_bytes };
    data_len == expect
}

/// Retirement drops the persistent decoder and its admission guard synchronously.
/// Explicit retirement makes queued completion ineligible, even before ID eviction.
fn retire_inactive_fec_workers(slots: &mut [FecRecvSlot], now_ns: u64, grace_ns: u64, oldest_only: bool) -> u64 {
    // Worker-admission pressure only needs to free a worker. The periodic sweep
    // also expires inline decoders, so abandoned small FEC units cannot pin IDs.
    let eligible = |s: &FecRecvSlot| (matches!(s.state, FecRecvState::Worker { .. })
        || (!oldest_only && matches!(s.state, FecRecvState::SourceOnly(_) | FecRecvState::Inline(_))))
        && now_ns.saturating_sub(s.last_active_ns()) > grace_ns;
    if oldest_only {
        if let Some(index) = slots.iter().enumerate().filter(|(_, s)| eligible(s)).min_by_key(|(_, s)| s.last_active_ns()).map(|(i, _)| i) {
            slots[index].state = FecRecvState::Done;
            return 1;
        }
        return 0;
    }
    let mut retired = 0;
    for slot in slots {
        if eligible(slot) {
            slot.state = FecRecvState::Done;
            slot.reservation = None;
            retired += 1;
        }
    }
    retired
}

struct FecCompletion {
    connection_key: ConnectionKey,
    package_id: u64,
    message: Vec<u8>,
    reservation: crate::receive_memory::Reservation,
    decoder_generation: std::sync::Arc<()>,
    connection_generation: std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
}
impl FecCompletion {
    fn owns(&self, slot: &FecRecvSlot, budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>) -> bool {
        self.package_id == slot.package_id && std::sync::Arc::ptr_eq(&self.connection_generation, budget) &&
            matches!(&slot.state, FecRecvState::Worker { generation, .. } if std::sync::Arc::ptr_eq(generation, &self.decoder_generation))
    }
}

// A decoder is owned only by Pump and never shared between threads. Each
// native add/recover is a single work unit; the next symbol can wait for another
// caller budget. The old Worker name/counters remain for telemetry compatibility.
struct FecDecodeJob {
    rx: std::sync::mpsc::Receiver<(u32, Vec<u8>)>,
    decoder: crate::fec::MessageDecoder,
    reservation: Option<crate::receive_memory::Reservation>,
    _guard: FecWorkerGuard,
}

struct FecWorkerGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>, std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>, Option<std::sync::Arc<NetworkWake>>);
impl Drop for FecWorkerGuard {
    fn drop(&mut self) {
        self.1.release_worker();
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        // Kept as an optional coalescing hook for alternative port implementations.
        // The reference pump finishes slices locally and needs no decoder wake.
        if let Some(wake) = &self.2 { wake.notify(); }
    }
}

fn fec_receive_block_waking(
    slot: &mut FecRecvSlot, connection_key: ConnectionKey, package_id: u64,
    message_len: usize, block_bytes: usize, block_id: u32, data: &[u8],
    done_tx: &std::sync::mpsc::Sender<FecCompletion>,
    workers: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
    wake: Option<std::sync::Arc<NetworkWake>>,
) -> Option<(Vec<u8>, crate::receive_memory::Reservation)> {
    use crate::fec::*;
    if matches!(slot.state, FecRecvState::Done) { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(3); return None; }
    slot.blocks_received = slot.blocks_received.saturating_add(1);
    let layout = MessageLayout::new(message_len, block_bytes)?;
    if !valid_fec_symbol(layout, block_id, data.len()) { return None; }
    if slot.params().is_some_and(|p| p != (message_len, block_bytes)) { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(4); return None; }
    if !slot.in_use() {
        let worker = layout.k > FEC_INLINE_MAX_BLOCKS;
        let ingress_bytes = fec_ingress_bytes(layout);
        let source_only = !worker && (block_id as usize) < layout.k;
        let charge = if source_only { SourceOnly::charge(layout)? }
            else { receive_memory_charge(layout, worker, ingress_bytes)? };
        let reservation = if !worker || workers.load(std::sync::atomic::Ordering::Acquire) < MAX_FEC_DECODE_WORKERS {
            budget.reserve(charge)
        } else { slot.worker_limit_refused = true; None };
        let Some(reservation) = reservation else {
            slot.admission_refused = true;
            #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(5); slot.ingress_dropped += 1;
            return None;
        };
        if worker {
            if !budget.acquire_worker() {
                slot.worker_limit_refused = true;
                slot.admission_refused = true; #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(5); slot.ingress_dropped += 1; return None;
            }
            let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>)>(ingress_slots(ingress_bytes, block_bytes));
            workers.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let guard = FecWorkerGuard(workers.clone(), budget.clone(), None);
            let generation = std::sync::Arc::new(());
            let Some(decoder) = MessageDecoder::with_layout(layout) else {
                drop(guard); slot.ingress_dropped += 1; return None;
            };
            let job = Box::new(FecDecodeJob { rx, decoder, reservation: Some(reservation), _guard: guard });
            slot.state = FecRecvState::Worker { tx, job: Some(job), message_len, block_bytes, generation };
        } else if source_only {
            slot.reservation = Some(reservation);
            slot.state = FecRecvState::SourceOnly(Box::new(SourceOnly::new(layout)));
        } else {
            slot.state = match MessageDecoder::new(message_len, block_bytes) {
                Some(d) => { slot.reservation = Some(reservation); FecRecvState::Inline(Box::new(d)) },
                None => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(8); FecRecvState::Done },
            };
        }
    }
    if let FecRecvState::SourceOnly(source) = &mut slot.state {
        if (block_id as usize) < layout.k {
            let Ok((status, fresh)) = source.insert(block_id, data) else { #[cfg(feature="research_budget_diagnostic")] diag::rx_status(14); return None; };
            #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(1);
            #[cfg(feature = "research_budget_diagnostic")] if !fresh {diag::rx_status(9);}
            if fresh { slot.last_block_ns = monotonic_clock_ns(); }
            if status == DecodeStatus::Done { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(10);
                let message = std::mem::take(&mut source.output);
                slot.state = FecRecvState::Done;
                return Some((message, slot.reservation.take()?));
            }
            return None;
        }
        // Retain the source lease throughout native creation and buffered-source
        // replay. A second FULL lease accounts for output + arena + metadata,
        // including their coexistence with the staged source allocation.
        if source.native_failed { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(15); slot.ingress_dropped += 1; return None; }
        let charge = receive_memory_charge(layout, false, 0)?;
        let Some(native_reservation) = budget.reserve(charge) else {
            slot.admission_refused = true;
            #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(5); slot.ingress_dropped += 1;
            return None;
        };
        let upgraded = source.decoder().and_then(|mut dec| {
            let status = dec.add(block_id, data)?;
            let message = if status == DecodeStatus::Done { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(10);
                Some(dec.recover().ok_or(DecodeError::Failed(-1))?)
            } else { None };
            Ok((dec, message))
        });
        match upgraded {
            Ok((dec, message)) => {
                #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(if message.is_some(){7}else{6});
                // Free staged bytes before releasing their lease; move the new
                // full lease into the slot/completion with no accounting gap.
                slot.state = if message.is_some() { FecRecvState::Done } else { FecRecvState::Inline(Box::new(dec)) };
                slot.reservation = Some(native_reservation);
                slot.last_block_ns = monotonic_clock_ns();
                return message.map(|m| (m, slot.reservation.take().unwrap()));
            }
            Err(_) => {
                // One allocation/feed attempt per source state on native error.
                // All sources can still finish directly; refused repairs never
                // refresh activity or rearm recovery grace.
                source.native_failed = true;
                #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(8); slot.ingress_dropped += 1;
                return None;
            }
        }
    }
    match &mut slot.state {
        FecRecvState::Inline(dec) => { slot.last_block_ns = monotonic_clock_ns(); match dec.add(block_id, data) {
            Ok(DecodeStatus::NeedMore) => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(6); None },
            Err(DecodeError::BadBlock) => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(14); None },
            Ok(DecodeStatus::Done) => {
                let m = dec.recover(); #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(7);
                #[cfg(feature = "research_budget_diagnostic")] if m.is_none(){diag::rx_status(8);}
                slot.state = FecRecvState::Done;
                let r = slot.reservation.take()?; m.map(|m| (m, r))
            }
            Err(DecodeError::Failed(_)) => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(8); slot.state = FecRecvState::Done; slot.reservation = None; None }
        } },
        FecRecvState::Worker { tx, job, generation, .. } => {
            match tx.try_send((block_id, data.to_vec())) {
                Ok(()) => {
                    #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(11);
                    slot.last_block_ns = monotonic_clock_ns();
                    slot.recovery_resume_ns = None;
                },
                Err(std::sync::mpsc::TrySendError::Full(_)) => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(12); slot.ingress_dropped += 1 },
                // A successful completion may already be queued. Keep this
                // exact Worker live until it is drained or explicitly retired.
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => { #[cfg(feature = "research_budget_diagnostic")] diag::rx_status(13); },
            }
            // Exactly one queued symbol per packet work unit. Wirehair add and
            // recover are native indivisible calls; decoder state persists across
            // run_until calls, and eviction synchronously releases its admission.
            if let Some(active) = job {
                if let Ok((id, block)) = active.rx.try_recv() {
                    match active.decoder.add(id, &block) {
                        Ok(DecodeStatus::Done) => {
                            if let Some(message) = active.decoder.recover() {
                                let reservation = active.reservation.take().unwrap();
                                let _ = done_tx.send(FecCompletion { connection_key, package_id, message, reservation,
                                    decoder_generation: generation.clone(), connection_generation: budget.clone() });
                            }
                            *job = None;
                        }
                        Err(DecodeError::Failed(_)) => { *job = None; }
                        _ => {}
                    }
                }
            }
            None
        }
        _ => None,
    }
}

// Largest unreliable message a receiver reassembles; a peer sending a bigger one is disconnected.
// u32 lengths and offsets fit 1 GiB; FEC kind 2 partitions it into bounded Wirehair codecs.
// Both ends need this limit (and kind 2 support for messages above 64000 packets).
pub const MAX_JUMBOGRAM_LEN: usize = 1 << 30;

pub const ACK_BUFFER_TIME_NS: u64 = 50_000_000;

#[derive(Default)]
pub struct NetworkThreadPush {
    #[cfg(feature = "research_budget_diagnostic")]
    pub diagnostic_take: bool,
    pub initiate_connections: Vec<STPAddress>,
    pub wanted_connections: Vec<(STPAddress, [u8; 64])>,
    /// (connection, queue index, message traffic class, complete message). Class never
    /// changes FIFO/round-robin scheduling or congestion control. Index must be < count.
    pub send_unreliable: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
}

/// Explicit protocol telemetry returned by `LockfreeEndpoint::try_protocol_stats`.
///
/// This type also supports the crate-private historical exchange used in tests.
/// On the public rings telemetry path, `current_connections`,
/// `received_unreliable_messages` and all `send_unreliable_*` result vectors are
/// always empty. Read lifecycle/messages from `Event` instead; accepted sends
/// never produce individual results. Queue-credit and CC/FEC/thread counters are
/// snapshots, not atomic admission guarantees. Requesting this snapshot allocates
/// and can take existing internal telemetry locks; ordinary ring operations do not.
#[derive(Default)]
pub struct NetworkThreadPull {
    /// Measured core time processing this reference exchange, excluding the
    /// application's poll wait. Batch/snapshot cost scales with caller work.
    pub exchange_processing_ns: u64,
    #[cfg(feature = "research_budget_diagnostic")]
    pub diagnostic: Option<diag::Capture>,
    pub current_connections: Vec<(STPAddress, [u8; 64])>,
    pub received_unreliable_messages: VecDeque<(ConnectionKey, Vec<u8>)>,
    /// Messages from this call's `send_unreliable` that were not queued, handed back unchanged:
    /// the connection's send queue was full (see `UnreliableSendBuffer::submit_messages`), or no
    /// connection with that key exists. Per connection AND queue they keep the order they were pushed in.
    /// Nothing is dropped; resubmit them later or discard them yourself.
    pub send_unreliable_rejected: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    /// Permanent submission error: message exceeds local `max_message_size`.
    /// Returned untouched; retrying without changing size/configuration cannot succeed.
    pub send_unreliable_oversized: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    /// Distinct application error: queue index outside the fixed initialization bound.
    /// Messages are untouched, but retrying without changing the index cannot succeed.
    pub send_unreliable_invalid_queue: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    /// For every connection the network thread holds (connected or still handshaking), the
    /// largest message each indexed send queue would accept now, after this call's submissions; u64::MAX
    /// when its queue is empty. A connection missing here does not exist.
    pub unreliable_send_free_bytes: Vec<(ConnectionKey, usize, u64)>,
    /// RESEARCH-ONLY (feature `research_cohort_observer`): read-only per-connection send-work
    /// snapshot taken after this call's submissions and `free_bytes()` reclamation above.
    #[cfg(feature = "research_cohort_observer")]
    pub cohort_observation: Vec<(ConnectionKey, crate::cohort_observe::CohortObservation)>,
    /// Cumulative counters for every connected connection.
    pub connection_stats: Vec<(ConnectionKey, ConnectionStats)>,
    /// Cumulative progress snapshots at first source, source completion and every repair
    /// only with `NetworkThreadOptions::record_fec_messages`.
    pub fec_messages: Vec<(ConnectionKey, crate::fec_adapt::FecMessageInfo)>,
    /// Network-thread-wide counters (kernel drops, loop starvation).
    pub thread_stats: NetworkThreadStats,
}

pub use crate::pump::Pump;
pub use crate::pump::port::lockfree::{LockfreeEndpoint, RingConfig};
pub(crate) use crate::pump::port::Endpoint;
use crate::pump::port::{Port, Ready as CoreReady};
use crate::pump::port::lockfree::{Control, Event as RingEvent, DisconnectReason, ConnectFailure};

#[derive(Default)]
struct RingState {
    peers: HashMap<ConnectionKey, [u8; 64]>,
    connects: HashMap<ConnectionKey, STPAddress>,
    pending: VecDeque<RingEvent>,
}
// Fullness is a level on the shared application queue, not a completed-message
// event. Sample at receipt and again at each actual ACK send; never wait for app.
fn application_receive_full(port: &Port) -> bool {
    port.native.get().is_some_and(|n| !n.events.has_space())
}

impl RingState {
    fn connected(&mut self, port: &Port, address: STPAddress, hash: [u8; 64]) -> bool {
        let Some(n) = port.native.get() else { return true; };
        let peer = address.connection_key();
        if self.peers.get(&peer) == Some(&hash) { return true; }
        if !self.pending.is_empty() || !n.events.has_space() {
            n.counters.inbound_refused_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        assert!(n.emit(&port.ready, RingEvent::Connected { peer, address, handshake_hash: hash }).is_ok());
        self.peers.insert(peer, hash);
        self.connects.remove(&peer);
        true
    }
    fn disconnected(&mut self, peer: ConnectionKey, reason: DisconnectReason) {
        if self.peers.remove(&peer).is_some() { self.pending.push_back(RingEvent::Disconnected { peer, reason }); }
        if let Some(address) = self.connects.remove(&peer) {
            self.pending.push_back(RingEvent::ConnectFailed { address, reason: if reason == DisconnectReason::Local { ConnectFailure::Cancelled } else { ConnectFailure::TimedOut } });
        }
    }
    fn message(&self, port: &Port, peer: ConnectionKey, data: Vec<u8>) {
        let n = port.native.get().unwrap();
        if !self.peers.contains_key(&peer) { return; }
        if n.emit(&port.ready, RingEvent::Message { peer, data }).is_err() {
            n.counters.receive_dropped_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else { n.counters.received.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    }
    fn flush(&mut self, port: &Port) {
        let n = port.native.get().unwrap();
        for _ in 0..32 {
            if !n.events.has_space() { break; }
            let Some(event) = self.pending.pop_front() else { break; };
            assert!(n.emit(&port.ready, event).is_ok());
        }
    }
}

// Publish death on normal drop AND unwind, even if Pump was never run.
struct NetworkExit(std::sync::Arc<Port>);
impl Drop for NetworkExit {
    fn drop(&mut self) {
        self.0.exited.store(true, std::sync::atomic::Ordering::Release);
        self.0.ready.notify();
    }
}

/// All setup is synchronous; no threads are started. `max_message_size` is
/// required application configuration, and has the existing 1 GiB upper bound.
pub struct PumpConfig {
    pub keypairs: Vec<IdentityKeyPair>,
    pub port: u16,
    pub max_pps: Option<u64>,
    pub send_buffer_params: (u32, u32, u32),
    pub max_message_size: usize,
    pub options: NetworkThreadOptions,
}
pub fn new(config: PumpConfig) -> (Pump, LockfreeEndpoint) {
    new_pump_with_options(config.keypairs, config.port, config.max_pps,
        config.send_buffer_params, config.max_message_size, config.options)
}
/// Construct a caller-driven pump and its single-owner three-ring endpoint.
pub fn new_pump(keys: Vec<IdentityKeyPair>, port: u16, max_pps: Option<u64>, bounds: (u32,u32,u32), maximum: usize) -> (Pump, LockfreeEndpoint) {
    new_pump_with_options(keys, port, max_pps, bounds, maximum, Default::default())
}
pub fn new_pump_with_options(keys: Vec<IdentityKeyPair>, port: u16, max_pps: Option<u64>, bounds: (u32,u32,u32), maximum: usize, options: NetworkThreadOptions) -> (Pump, LockfreeEndpoint) {
    let rings = options.rings;
    let (pump, endpoint) = new_reference_pump_with_options(keys, port, max_pps, bounds, maximum, options);
    (pump, endpoint.into_rings(rings))
}
pub(crate) fn new_reference_pump(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32), max_message_size: usize) -> (Pump, Endpoint) {
    new_reference_pump_with_options(my_keypairs, my_port, max_pps, send_buffer_params, max_message_size, NetworkThreadOptions::default())
}

/// Internal loss/ECN-driven packet-rate policy. Values are fixed in ship.rs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CongestionPolicy {
    pub beta: f64,
    pub recovery_rtts: u64,
    pub rate_rp: f64,
    pub rate_pg: f64,
    pub rate_gs: f64,
    pub time_pg: f64,
    pub time_gs: f64,
    pub loss_threshold: u64,
    pub loss_timeout_rtts: f64,
    pub event_guard_rtts: f64,
    pub rate_floor_upps: u64,
    pub initial_rate_upps: u64,
    pub min_growth_uppsps: f64,
    pub max_growth_uppsps: f64,
    pub relative_growth_per_rtt: f64,
    pub startup_multiplier: f64,
    pub startup_backoff_rtts: f64,
}

/// Socket binding and optional measurement. The transport policy is fixed internally.
#[derive(Debug, Clone)]
pub struct NetworkThreadOptions {
    /// Independent fixed application-ring capacities.
    pub rings: RingConfig,
    /// Fixed number of FIFO queues per connection (1..=64), also sizing the peer receive cap.
    /// Total app capacity is N x max_queue_size_bytes (plus the inherited oversized-alone
    /// exception). Rescue reservations are 64 MiB/N and 4096/N per magazine, no borrowing.
    pub send_queue_count: usize,
    /// Receive allocation budget. Share the same Arc across sockets for an overall limit.
    /// None uses one process-wide 4 GiB default. Application-owned pulled messages are excluded.
    pub receive_memory: Option<std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>>,
    /// See `new_network_thread_with_bind`.
    pub bind_ip: Option<std::net::IpAddr>,
    /// Report cumulative source/repair progress in `NetworkThreadPull::fec_messages`.
    pub record_fec_messages: bool,
    /// Record loss-episode statistics only; never changes congestion control.
    pub record_loss_episodes: bool,
    /// Optional sender packet/fragment/outcome event CSV.
    pub loss_trace: Option<std::path::PathBuf>,
    #[cfg(feature = "research_budget_diagnostic")]
    pub budget_diagnostic: bool,
}

impl Default for NetworkThreadOptions {
    fn default() -> Self { Self { rings: RingConfig::default(), send_queue_count: 1, receive_memory: None, bind_ip: None, record_fec_messages: false, record_loss_episodes: false, loss_trace: None, #[cfg(feature = "research_budget_diagnostic")] budget_diagnostic: false } }
}

/// `max_message_size` is required local application configuration in both directions,
/// clamped to 1 GiB. Oversized submissions return in `send_unreliable_oversized`.
/// Both applications must configure compatible limits; no negotiation is added.
/// Panics synchronously if its receive cap plus bookkeeping cannot fit the budget.
pub(crate) fn new_reference_pump_with_options(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32), max_message_size: usize, options: NetworkThreadOptions) -> (Pump, Endpoint) {
    let bind_ip = options.bind_ip;
    let send_queue_count = options.send_queue_count;
    assert!((1..=64).contains(&send_queue_count), "send_queue_count must be 1..=64");
    static DEFAULT_RECEIVE_MEMORY: std::sync::OnceLock<std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>> = std::sync::OnceLock::new();
    let receive_memory = options.receive_memory.unwrap_or_else(|| DEFAULT_RECEIVE_MEMORY.get_or_init(|| std::sync::Arc::new(Default::default())).clone());
    let max_message_size = max_message_size.min(MAX_JUMBOGRAM_LEN);
    let connection_receive_limit = receive_connection_memory_limit(max_message_size, send_queue_count)
        .expect("receive cap arithmetic overflow");
    assert!(connection_receive_limit.checked_add(RECEIVE_CONNECTION_BYTES).is_some_and(|n| n <= receive_memory.limit()),
        "max_message_size={max_message_size} with {send_queue_count} queues requires {connection_receive_limit} receive bytes plus connection bookkeeping; process budget is {}", receive_memory.limit());
    crate::fec_adapt::initialize_research_policy().expect("invalid transport research policy");
    // One measured policy, not application configuration.
    let cc = crate::ship::CC;


    // STP setup
    socket_setup();
    monotonic_clock_setup();

    let socket = setup_and_bind_udp_socket_on(my_port, bind_ip).expect("Failed to bind socket, try again.");

    let inner = Port::new(max_message_size, send_queue_count);
    let record_fec_messages = options.record_fec_messages;
    let record_loss_episodes = options.record_loss_episodes;
    let mut loss_trace = options.loss_trace.as_deref().map(|p| crate::loss_trace::LossTrace::open(p).expect("open loss trace"));

    let thread_inner = inner.clone();

    #[cfg(feature="research_budget_diagnostic")]
    let diagnostic_enabled = options.budget_diagnostic;
    {
        let exit = NetworkExit(thread_inner.clone());
        #[cfg(feature = "research_budget_diagnostic")]
        diag::enable(diagnostic_enabled);
        // SockHandle is Copy, not RAII. This thread is the sole socket owner;
        // release the descriptor on normal shutdown AND unwinding.
        struct SocketOwner(SockHandle);
        impl Drop for SocketOwner { fn drop(&mut self) { unsafe { self.0.close(); } } }
        let socket_owner = SocketOwner(socket);
        let mut packet_memory_encrypted = new_packet_memory(); // Incoming Encrypted / Outgoing Encrypted
        let mut packet_memory_recv      = new_packet_memory(); // Incoming Decrypted
        let mut packet_memory_send      = new_packet_memory(); // Outgoing Decrypted

        let mut receive_queue = ReceiveQueue::default();
        let (fec_done_tx, fec_done_rx) = std::sync::mpsc::channel::<FecCompletion>();
        let fec_workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut fec_sweep_ns = 0;
        let mut idle_resume_ns = 0;
        // Frozen ALIVE policy: peer activity changes connection expiry
        // only; congestion/outage recovery still requires positive ACK progress.

        let authenticated_peer_liveness = crate::ship::policy_var("STP_TV_ALIVE").as_deref() == Ok("1");


        // Test-only loss injection: STP_TEST_DROP_PPM=n skips sending n per million outgoing
        // data packets while accounting them as sent, so congestion control sees real loss.
        let test_drop_ppm: u64 = std::env::var("STP_TEST_DROP_PPM").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(0).min(1_000_000);
        let mut test_drop_rng: u64 = monotonic_clock_ns() | 1;
        if test_drop_ppm != 0 { println!("STP port {my_port}: STP_TEST_DROP_PPM={test_drop_ppm}: dropping that fraction of outgoing data packets (test only)"); }
        // STP_TEST_DROP_SCHEDULE="0:0.5,20:4,25:0.5,@60": piecewise-constant drop percentage from
        // these seconds after thread start (overrides STP_TEST_DROP_PPM); a final "@T" repeats the
        // schedule with period T s. STP_TEST_DROP_BURST=n: drops come in runs of n packets (the
        // run start rate is divided by n, so the average stays the scheduled rate).
        let test_drop_schedule = TestDropSchedule::from_env();
        if let Some(sch) = &test_drop_schedule { println!("STP port {my_port}: STP_TEST_DROP_SCHEDULE: {sch:?} (test only)"); }
        let test_drop_burst: u64 = std::env::var("STP_TEST_DROP_BURST").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(1).max(1);
        let mut test_drop_burst_left = 0u64;
        let test_drop_t0 = monotonic_clock_ns();
        let mut receive_queue_report_time_ns = 0u64;
        let mut thread_stats = NetworkThreadStats::default();
        let mut last_loop_start_ns = 0u64;
        let mut kernel_drops_read_ns = 0u64;
        let mut cpu_read_ns = 0u64;
        let mut network_cpu = (0u64, 0u64);

        let mut connections_map = HashMap::<ConnectionKey, ConnectionTrackingData>::new();
        let mut ready_peers = HashMap::new();
        let mut ring_state = RingState::default();
        let mut receive_notified = false;
        let mut ready_used = 0usize;

        // Resume packet batches and connection traversal rather than restarting
        // the receive-first phase at every short caller budget.
        let mut receive_round = 0usize;
        let mut receiving = true;
        let mut send_keys = VecDeque::<ConnectionKey>::new();
        let mut fec_sweep_keys = VecDeque::<ConnectionKey>::new();
        let mut fec_sweep_root_index = 0usize;
        let mut active_wait = None::<std::time::Instant>;
        let mut wake_hint = Some(std::time::Instant::now());
        let mut pending_receive = None;
        let run = move |mut budget: crate::pump::Deadline| {
        let caller_deadline = budget.instant;
        // Capture owners explicitly: resources live even before the first call.
        let _owners = (&exit, &socket_owner);

        #[cfg(feature = "research_budget_diagnostic")]
        diag::enable(diagnostic_enabled);
        loop {
            if let Some(until) = active_wait {
                std::thread::sleep(until.saturating_duration_since(std::time::Instant::now())
                    .min(caller_deadline.saturating_duration_since(std::time::Instant::now())));
                let now = std::time::Instant::now();
                if now >= caller_deadline {
                    // Owed progress runs past the deadline, but the active quantum is never
                    // shortened: inside it only the owed command exchange may be admitted.
                    if now >= until && budget.unit_owed() { active_wait = None; }
                    else if !(budget.command_owed() && thread_inner.has_request()) { return Some(until); }
                } else { active_wait = None; }
            }
            if budget.expired() { return wake_hint; }
            if thread_inner.stop.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            {
                let t = monotonic_clock_ns();
                if budget.sampled(t) { return wake_hint; }
                if last_loop_start_ns != 0 {
                    let gap = t.saturating_sub(last_loop_start_ns);
                    thread_stats.max_loop_gap_ns = thread_stats.max_loop_gap_ns.max(gap);
                    if gap > 1_000_000 { thread_stats.loop_gaps_over_1ms += 1; }
                    if gap > 10_000_000 { thread_stats.loop_gaps_over_10ms += 1; }
                    if gap > 100_000_000 { thread_stats.loop_gaps_over_100ms += 1; }
                }
                last_loop_start_ns = t;
                thread_stats.loop_iterations += 1;
            }
            let test_drop_ppm = match &test_drop_schedule { Some(sch) => sch.ppm_at(monotonic_clock_ns().saturating_sub(test_drop_t0)), None => test_drop_ppm };
            // Do not remove a request after its admission deadline.
            // The first take of each call is exempt (forward progress).
            if !budget.command_owed() && thread_inner.has_request() && std::time::Instant::now() >= caller_deadline { return wake_hint; }
            // Native boundary: only the pump touches RingState and consumes inputs.
            // At most 32 admissions precede a protocol pass; each respects the call
            // deadline except the first owed admission (the forward-progress rule).
            if let Some(n) = thread_inner.native.get() {
                ring_state.flush(&thread_inner);
                for _ in 0..if active_wait.is_some() { 1 } else { 32 } {
                    if !budget.command_owed() && std::time::Instant::now() >= caller_deadline { break; }
                    let mut ring_admitted = false;
                    if ring_state.pending.is_empty() {
                        if let Some(control) = unsafe { n.control.pop() } {
                            n.input_drained(&thread_inner.ready, true);
                            match control {
                                Control::Connect(address) => {
                                    let peer = address.connection_key();
                                    if connections_map.contains_key(&peer) {
                                        ring_state.pending.push_back(RingEvent::ConnectFailed { address, reason: ConnectFailure::AlreadyConnected });
                                    } else if let Some(keypair) = my_keypairs.iter().find(|kp| kp.magic1 == address.magic1 && kp.public != address.key) {
                                        connect_to_endpoint(&mut connections_map, keypair, &address, send_buffer_params, send_queue_count, &receive_memory, connection_receive_limit, max_message_size);
                                        if connections_map.contains_key(&peer) { ring_state.connects.insert(peer, address); }
                                        else { ring_state.pending.push_back(RingEvent::ConnectFailed { address, reason: ConnectFailure::InvalidAddress }); }
                                    } else { ring_state.pending.push_back(RingEvent::ConnectFailed { address, reason: ConnectFailure::InvalidAddress }); }
                                }
                                Control::Disconnect(peer) => {
                                    connections_map.remove(&peer);
                                    ring_state.disconnected(peer, DisconnectReason::Local);
                                }
                            }
                            ring_admitted = true;
                        }
                    }
                    if !ring_admitted {
                        if let Some(message) = unsafe { n.send.peek() } {
                            let mut drop_kind = 0;
                            let mut fits = true;
                            if message.payload.len() > max_message_size { drop_kind = 2; }
                            else if let Some(conn) = connections_map.get_mut(&message.peer).filter(|c| c.is_connected()) {
                                if message.queue >= conn.unreliable_send_buffer.queues.len() { drop_kind = 3; }
                                else { fits = message.payload.len() as u64 <= conn.unreliable_send_buffer.queues[message.queue].free_bytes(); }
                            } else { drop_kind = 1; }
                            if fits {
                                let message = unsafe { n.send.pop() }.unwrap();
                                n.input_drained(&thread_inner.ready, false);
                                let counter = match drop_kind {
                                    1 => &n.counters.send_dropped_unknown,
                                    2 => &n.counters.send_dropped_oversized,
                                    3 => &n.counters.send_dropped_invalid_queue,
                                    _ => {
                                        let buf = &mut connections_map.get_mut(&message.peer).unwrap().unreliable_send_buffer;
                                        if let Some(charge) = message.charge { buf.queues[message.queue].queued_ledger.admit(charge); }
                                        let rejected = buf.submit_classified_messages(message.queue, vec![(message.class, message.payload)]);
                                        assert!(rejected.is_empty(), "peeked credit must admit the FIFO head");
                                        &n.counters.sent
                                    }
                                };
                                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                ring_admitted = true;
                            } else { n.counters.send_head_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                        }
                    }
                    if ring_admitted { budget.admitted(); } else { break; }
                }
                // A retained retry quantum permits only its owed admission, not
                // protocol work. This also covers a FIFO head that could not be
                // admitted: has_request alone must never shorten the quantum.
                if let Some(until) = active_wait { return Some(until); }
            }
            if let Some((mut req, disconnect)) = thread_inner.take_request() {
                budget.admitted();
                if let Some(peer) = disconnect { connections_map.remove(&peer); }
                let exchange_started = std::time::Instant::now();
                let current_time_now_ns = monotonic_clock_ns();
                if thread_inner.is_reference() { connections_map.retain(|key, value| {
                    let stp_address = value.address();
                    if value.creation_time_ns + 30_000_000_000 < current_time_now_ns && req.wanted_connections.iter().position(|(x, _)| x == &stp_address).is_none() && value.is_connected() {
                        println!("############################# KILLING CONNECTION {:?}", value);
                        return false;
                    }
                    true
                }); }
                for w in &req.initiate_connections {
                    if my_keypairs.iter().any(|kp| kp.public == w.key) {
                        continue;
                    }
                    let key = ConnectionKey {
                        ip: w.ip,
                        port: w.port,
                        key_15_bits: load_u16(&w.key[0..2]) << 1
                    };
                    if connections_map.contains_key(&key) {
                        continue;
                    }
                    for keypair in &my_keypairs {
                        if w.magic1 == keypair.magic1 {
                            connect_to_endpoint(&mut connections_map, keypair, w, send_buffer_params, send_queue_count, &receive_memory, connection_receive_limit, max_message_size);
                            break;
                        }
                    }
                }

                // Push unreliable messages to their queues, batched per connection. The sort is
                // stable so each connection's messages keep the caller's order. Whatever a queue
                // does not accept, and everything for a connection not in the map, goes back to
                // the caller untouched.
                let mut resp = NetworkThreadPull::default();
                req.send_unreliable.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
                let mut i = 0;
                while i < req.send_unreliable.len() {
                    let key = req.send_unreliable[i].0;
                    let queue = req.send_unreliable[i].1;
                    let mut j = i;
                    while j < req.send_unreliable.len() && req.send_unreliable[j].0 == key && req.send_unreliable[j].1 == queue { j += 1; }
                    let mut batch = Vec::with_capacity(j - i);
                    while i < j {
                        let (dscp, message) = (req.send_unreliable[i].2, std::mem::take(&mut req.send_unreliable[i].3));
                        if message.len() > max_message_size {
                            resp.send_unreliable_oversized.push((key, queue, dscp, message));
                        } else { batch.push((dscp, message)); }
                        i += 1;
                    }
                    let rejected = if let Some(tracking_data) = connections_map.get_mut(&key) {
                        if queue >= tracking_data.unreliable_send_buffer.queues.len() {
                            resp.send_unreliable_invalid_queue.extend(batch.into_iter().map(|(dscp, m)| (key, queue, dscp, m)));
                            continue;
                        }
                        if !tracking_data.is_connected() { batch } else {
                            tracking_data.unreliable_send_buffer.submit_classified_messages(queue, batch)
                        }
                    } else {
                        batch
                    };
                    resp.send_unreliable_rejected.extend(rejected.into_iter().map(|(dscp, m)| (key, queue, dscp, m)));
                }
                #[cfg(feature = "research_budget_diagnostic")]
                if req.diagnostic_take { resp.diagnostic = diag::take(current_time_now_ns); }
                if thread_inner.wants_stats() {
                resp.unreliable_send_free_bytes = connections_map.iter_mut()
                    .flat_map(|(key, value)| value.unreliable_send_buffer.free_bytes().into_iter().enumerate().map(|(q, bytes)| (*key, q, bytes))).collect();
                #[cfg(feature = "research_cohort_observer")]
                {
                    let test_drop_configured = test_drop_ppm != 0 || test_drop_schedule.is_some();
                    resp.cohort_observation = connections_map.iter().map(|(key, value)| (*key, cohort_observation_of(value, test_drop_configured))).collect();
                }
                if current_time_now_ns.saturating_sub(cpu_read_ns) >= 100_000_000 {
                    cpu_read_ns = current_time_now_ns;
                    #[cfg(target_os = "linux")]
                    if let Some(cpu) = crate::platform::sys::thread_cpu_time_us() {
                        network_cpu = cpu;
                    }
                }
                resp.connection_stats = connections_map.iter().filter_map(|(key, value)| match &value.connection_state {
                    ConnectionState::Connected(c) => {
                        let mut st = c.stats;

                        { (st.rand_bg_packets,st.rand_bg_lost,st.rand_p_ppm,st.rand_p_base_ppm)=crate::target_validation::rand_counters(&c.target_state); }
                        for q in &value.unreliable_send_buffer.queues {
                            st.slipstream.merge(q.slipstream_info);
                            st.category_bonus_messages += q.category_bonus_messages;
                            st.category_bonus_repairs += q.category_bonus_repairs;
                            st.event_repair.merge(q.event_info());
                            st.budget_base.merge(*q.budget_sink.lock().unwrap());
                        }
                        st.event_repair.accepted_dropped += c.accepted_cc_dropped;
                        st.event_repair.missing_anchor += c.accepted_cc_missing_anchor;
                        st.fec_decode_peak_workers = value.receive_budget.worker_peak() as u64;
                        st.seq_numbers_used = c.send_sequence_number;
                        st.udp_payload_tu = c.current_tu;
                        st.network_cpu_user_us = network_cpu.0;
                        st.network_cpu_sys_us = network_cpu.1;
                        c.rx_tracker.provisional_bursts(&mut st);
                        if let Some(a) = &value.unreliable_send_buffer.fec_adaptive {
                            st.fec_loss_estimate = a.p;
                            st.fec_last_loss_sample = a.tracker.last_sample();
                        }
                        Some((*key, st))
                    }
                    _ => None,
                }).collect();
                if current_time_now_ns.saturating_sub(kernel_drops_read_ns) >= 100_000_000 {
                    kernel_drops_read_ns = current_time_now_ns;
                    thread_stats.kernel_rx_drops = udp_socket_kernel_rx_drops(socket);
                }
                thread_stats.recv_queue_dropped_messages = receive_queue.dropped_messages_total;
                resp.thread_stats = thread_stats;
                if record_fec_messages {
                    for (key, value) in connections_map.iter_mut() {
                        let peak = value.unreliable_send_buffer.queues[0].retention_quota.telemetry.peak.load(std::sync::atomic::Ordering::Relaxed);
                        if let Some(rec) = &mut value.unreliable_send_buffer.fec_record {
                            resp.fec_messages.extend(rec.drain(..).map(|mut m| { m.peak_retained_source_bytes = peak as u64; (*key, m) }));
                        }
                    }
                }

                } // reference/explicit stats snapshot
                if thread_inner.wants_snapshot() {
                resp.current_connections = connections_map.iter().filter_map(|(key, value)| {
                    if value.is_connected() {
                        Some((value.address().clone(), value.handshake_hash))
                    } else {
                        None
                    }
                }).collect();
                resp.received_unreliable_messages = receive_queue.take();
                receive_notified = false;
                ready_used = connections_map.values().flat_map(|c| &c.unreliable_send_buffer.queues).map(|q| q.queue_bytes_filled as usize).sum();
                }
                // Native Send responses omit snapshots. Anchor a rejected
                // sender's one-shot space edge before the next protocol drain.
                if !thread_inner.is_reference() && !resp.send_unreliable_rejected.is_empty() {
                    ready_used = connections_map.values().flat_map(|c| &c.unreliable_send_buffer.queues).map(|q| q.queue_bytes_filled as usize).sum();
                }
                resp.exchange_processing_ns = exchange_started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                thread_inner.publish(resp);
            } else {

                /*  Note(Sam): Scheduling is very important for fairness and good performance under load
                    without strange bugs. Here is the strategy we will use even though it may seem CPU
                    expensive. Try to receive, then loop all connections and try to send for each of them.
                    We go to sleep if everything failed. Because we loop over all connections the calculation
                    for if we can send or not must be very cheap.
                */

                let mut should_sleep = true;

//////// BEGIN RECEIVE ////////////////////////////////////////////////////////////////////////
                // Drain ACKs before sending again. Bound the batch so a busy peer cannot
                // monopolize the thread; the socket is nonblocking, so stop as soon as empty.
                while receiving && receive_round < MAX_RECV_PACKETS_PER_TICK { // `continue` skips this packet
                    if budget.expired() { return Some(std::time::Instant::now()); }
                    let packet = if let Some(packet) = pending_receive.take() { packet } else {
                        match udp_recv_with_congestion_and_dscp(socket, &mut packet_memory_encrypted[..]) {
                            Ok(packet) => {
                                // recv already sampled RAW. Keep an unprocessed datagram
                                // across calls if receiving it consumed the remaining budget.
                                if budget.sampled(packet.6) {
                                    pending_receive = Some(packet);
                                    return Some(std::time::Instant::now());
                                }
                                packet
                            },
                            Err(_) => break,
                        }
                    };
                    receive_round += 1;
                    budget.progressed();
                    let (buf_len, other_ip_addr, other_port, ecn_marked, ecn_enabled, service_class, timestamp_ns) = packet;
                    if buf_len < 6 { continue; }

                    should_sleep = false;
                    let first_six_bytes = load_u48(&packet_memory_encrypted[0..6]);


                    if first_six_bytes & 1 != 0 { // Client Hello
                        if let Some(n) = thread_inner.native.get() {
                            if !n.events.has_space() || !ring_state.pending.is_empty() {
                                n.counters.inbound_refused_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                continue;
                            }
                        }
                        let magic1 = first_six_bytes;
                        if magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
                            for key_i in 0..my_keypairs.len() {
                                let my_kp = &my_keypairs[key_i];
                                if my_kp.magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
                                    if buf_len == 6 + 32 + MAGIC2_BLOCK_SIZE {
                                        let client_key = &packet_memory_encrypted[6..6+32];
                                        let magic2_block = &packet_memory_encrypted[6+32..6+32+MAGIC2_BLOCK_SIZE];
                                        let Some(chosen_magic2) = negotiate_magic2(magic2_block) else {
                                            break;
                                        };

                                        let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: load_u16(&client_key[0..2]) << 1 };
                                        if let Some(existing_connection) = connections_map.get_mut(&connection_key) {
                                            if &existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key {
                                                if let ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } = &mut existing_connection.connection_state {
                                                    if *client_key < *my_kp.public {
                                                        store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                                        packet_memory_send[6..6+32].copy_from_slice(&my_kp.public[..]);
                                                        packet_memory_send[6+32..6+32+SERVER_HELLO_PAYLOAD_LEN].copy_from_slice(&chosen_magic2.to_le_bytes());
                                                        let hello_packet_payload = Vec::from(&packet_memory_send[0..6+32+SERVER_HELLO_PAYLOAD_LEN]);

                                                        existing_connection.connection_state = ConnectionState::SendingServerHelloPlaintext { magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload };
                                                    }
                                                }
                                            }
                                        }
                                        else {
                                            let Some(receive_reservation) = receive_memory.reserve(RECEIVE_CONNECTION_BYTES) else { break; };
                                            let client_key = Vec::from(client_key);
                                            store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                            packet_memory_send[6..6+32].copy_from_slice(&my_kp.public[..]);
                                            packet_memory_send[6+32..6+32+SERVER_HELLO_PAYLOAD_LEN].copy_from_slice(&chosen_magic2.to_le_bytes());
                                            let hello_packet_payload = Vec::from(&packet_memory_send[0..6+32+SERVER_HELLO_PAYLOAD_LEN]);

                                            let my_ip = if other_ip_addr.to_ipv4_mapped().is_some() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
                                            connections_map.insert(
                                                connection_key,
                                                ConnectionTrackingData {
                                                    receive_reservation,
                                                    receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&receive_memory, connection_receive_limit).with_worker_limit(receive_worker_limit(max_message_size, send_queue_count)),
                                                    creation_time_ns: monotonic_clock_ns(),
                                                    my_ip,
                                                    my_transport_identity_keypair: my_kp.clone(),
                                                    two_byte_send_prefix: load_u16(&my_kp.public[0..2]) << 1,
                                                    other_ip: other_ip_addr,
                                                    other_port: other_port,
                                                    other_transport_identity: client_key,
                                                    connection_state: ConnectionState::SendingServerHelloPlaintext { magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload },
                                                    handshake_hash: [0u8; 64],
                                                    unreliable_send_buffer: SendQueues::new(send_queue_count, send_buffer_params),
                                                    receive_index: ReceiveIndex::default(),
                unreliable_reassembly: ReassemblySlot::new_ring(1024),
                                                    unreliable_fec: FecRecvSlot::new_ring(1024),
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        else if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
                            for key_i in 0..my_keypairs.len() {
                                let my_kp = &my_keypairs[key_i];
                                if my_kp.magic1 == magic1 {
                                    let mut new_handshake = noise_responder(crypto_string,
                                        &packet_memory_encrypted[0..6], &my_kp.private).unwrap();
                                    let read_message_maybe = new_handshake.read_message(&packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]);
                                    if let Ok(magic2_block_len) = read_message_maybe {
                                        if let Some(client_key) = new_handshake.get_remote_static() {
                                            let Some(chosen_magic2) = negotiate_magic2(&packet_memory_recv[..magic2_block_len]) else {
                                                break;
                                            };

                                            let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: load_u16(&client_key[0..2]) << 1 };
                                            if let Some(existing_connection) = connections_map.get_mut(&connection_key) {
                                                if &existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key {
                                                    if let ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } = &mut existing_connection.connection_state {
                                                        if *client_key < *my_kp.public {
                                                            let chosen_magic2_bytes = chosen_magic2.to_le_bytes();
                                                            store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                                            let handshake_size = new_handshake.write_message(&chosen_magic2_bytes, &mut packet_memory_send[6..]).unwrap();
                                                            let hello_packet_payload = Vec::from(&packet_memory_send[0..6+handshake_size]);

                                                            debug_assert!(new_handshake.is_handshake_finished());
                                                            existing_connection.handshake_hash = get_handshake_hash(&new_handshake);
                                                            let cipher = ConnectionCipherTriplet::new_from_old_init_only(new_handshake.into_stateless_transport_mode().expect("Cannot fail given assert above."));

                                                        existing_connection.connection_state = ConnectionState::SendingServerHello { cipher, magic1: *magic1, magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload };
                                                        }
                                                    }
                                                }
                                            }
                                            else {
                                                let Some(receive_reservation) = receive_memory.reserve(RECEIVE_CONNECTION_BYTES) else { break; };
                                                let client_key = Vec::from(client_key);
                                                let chosen_magic2_bytes = chosen_magic2.to_le_bytes();
                                                store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                                let handshake_size = new_handshake.write_message(&chosen_magic2_bytes, &mut packet_memory_send[6..]).unwrap();
                                                let hello_packet_payload = Vec::from(&packet_memory_send[0..6+handshake_size]);

                                                debug_assert!(new_handshake.is_handshake_finished());
                                                let handshake_hash = get_handshake_hash(&new_handshake);
                                                let cipher = ConnectionCipherTriplet::new_from_old_init_only(new_handshake.into_stateless_transport_mode().expect("Cannot fail given assert above."));

                                                let my_ip = if other_ip_addr.to_ipv4_mapped().is_some() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
                                                connections_map.insert(
                                                    connection_key,
                                                    ConnectionTrackingData {
                                                        receive_reservation,
                                                        receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&receive_memory, connection_receive_limit).with_worker_limit(receive_worker_limit(max_message_size, send_queue_count)),
                                                        creation_time_ns: monotonic_clock_ns(),
                                                        my_ip,
                                                        my_transport_identity_keypair: my_kp.clone(),
                                                        two_byte_send_prefix: load_u16(&my_kp.public[0..2]) << 1,
                                                        other_ip: other_ip_addr,
                                                        other_port: other_port,
                                                        other_transport_identity: client_key,
                                                        connection_state: ConnectionState::SendingServerHello { cipher, magic1, magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload },
                                                        handshake_hash,
                                                        unreliable_send_buffer: SendQueues::new(send_queue_count, send_buffer_params),
                                                    receive_index: ReceiveIndex::default(),
                unreliable_reassembly: ReassemblySlot::new_ring(1024),
                                                        unreliable_fec: FecRecvSlot::new_ring(1024),
                                                    },
                                                );

                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else { 'conn: { // Not client hello

                        let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: first_six_bytes as u16 };
                        let Some(existing_connection) = connections_map.get_mut(&connection_key) else {
                            break 'conn;
                        };

                        if !existing_connection.is_connected() && thread_inner.native.get().is_some_and(|n| !n.events.has_space() || !ring_state.pending.is_empty()) {
                            thread_inner.native.get().unwrap().counters.inbound_refused_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            break 'conn;
                        }
                        match &mut existing_connection.connection_state {
                            ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } => {
                                if first_six_bytes >> 16 == 0xffff_ffff && buf_len == 6 + 32 + SERVER_HELLO_PAYLOAD_LEN {
                                    let server_key = &packet_memory_encrypted[6..6+32];
                                    if server_key == existing_connection.other_transport_identity {
                                        let server_magic2 = load_u64(&packet_memory_encrypted[6+32..6+32+8]);
                                        if !validate_magic2(server_magic2) {
                                            break 'conn;
                                        }
                                        if VERBOSE { println!("Connected to new server {:?}", server_key); }
                                        existing_connection.connection_state = new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, server_magic2, timestamp_ns);
                                        assert!(ring_state.connected(&thread_inner, existing_connection.address(), existing_connection.handshake_hash));
                                    }
                                }
                                break 'conn;
                            }
                            ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } => {
                                if first_six_bytes >> 16 == 0xffff_ffff && buf_len >= 6 + 32 {
                                    if let Ok(payload_len) = handshake.read_message(&packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]) {
                                        debug_assert!(handshake.is_handshake_finished());
                                        existing_connection.handshake_hash = get_handshake_hash(handshake);
                                        if payload_len != SERVER_HELLO_PAYLOAD_LEN {
                                            break 'conn;
                                        }
                                        let server_magic2 = load_u64(&packet_memory_recv[0..8]);
                                        if !validate_magic2(server_magic2) {
                                            break 'conn;
                                        }
                                        if VERBOSE { println!("Connected to new server {:?}", handshake.get_remote_static().unwrap()); }

                                        // Borrow Checker crazyness required here.
                                        let new_state = new_connection_state_connected(None, *magic1, server_magic2, timestamp_ns);
                                        let old_state = std::mem::replace(&mut existing_connection.connection_state, new_state);

                                        let ConnectionState::SendingClientHello { handshake, .. } = old_state else { panic!(); };
                                        let ConnectionState::Connected(ref mut state) = existing_connection.connection_state else { panic!(); };
                                        state.cipher = Some(ConnectionCipherTriplet::new_from_old_init_only(handshake.into_stateless_transport_mode().expect("Cannot fail given assert above.")));
                                        assert!(ring_state.connected(&thread_inner, existing_connection.address(), existing_connection.handshake_hash));
                                    }
                                }
                                break 'conn;
                            }
                            ConnectionState::SendingServerHelloPlaintext { magic2, last_sent_time_ns, hello_packet_payload } => {
                                if VERBOSE { println!("Connected to new client {:?}", existing_connection.other_transport_identity); }
                                existing_connection.connection_state = new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, *magic2, timestamp_ns);
                                // FALLTHROUGH TO CONNECTED
                            }
                            ConnectionState::SendingServerHello { cipher, magic1, magic2, last_sent_time_ns, hello_packet_payload } => {
                                if buf_len < CONNECTED_HEADER_SIZE { break 'conn; }
                                let wire = load_u32(&packet_memory_encrypted[2..6]);
                                let is_ack = buf_len == CONNECTED_HEADER_SIZE + crate::ack::ACK_PAYLOAD_LEN + 16;
                                let nonce = crate::sequence::reconstruct(wire, None, is_ack);
                                let epoch = wire >> 31;
                                if cipher.open(nonce, epoch, &packet_memory_encrypted[..CONNECTED_HEADER_SIZE],
                                    &packet_memory_encrypted[CONNECTED_HEADER_SIZE..buf_len], &mut packet_memory_recv[..], timestamp_ns).is_err() {
                                    break 'conn;
                                }

                                if VERBOSE { println!("Connected to new client {:?}", existing_connection.other_transport_identity); }
                                existing_connection.connection_state = new_connection_state_connected(Some(cipher.clone()), *magic1, *magic2, timestamp_ns);
                                // FALLTHROUGH TO CONNECTED
                            }
                            ConnectionState::Connected(_) => (),
                        }
                        if !ring_state.connected(&thread_inner, existing_connection.address(), existing_connection.handshake_hash) { break 'conn; }
//////// BEGIN ORDINARY PACKET HANDLING  ////////////////////////////////////////////////////////////////////
                        if let ConnectionState::Connected(state) = &mut existing_connection.connection_state {
                            if buf_len < CONNECTED_HEADER_SIZE { break 'conn; }
                            let wire = load_u32(&packet_memory_encrypted[2..6]);
                            let tag_len = if state.cipher.is_some() { 16 } else { 0 };
                            let wire_is_ack = buf_len == CONNECTED_HEADER_SIZE + crate::ack::ACK_PAYLOAD_LEN + tag_len;
                            let nonce = state.receive_sequences.compact_candidate(wire, wire_is_ack);
                            let epoch = wire >> 31;
                            let payload;
                            if let Some(cipher) = &mut state.cipher {
                                let Ok(n) = cipher.open(nonce, epoch, &packet_memory_encrypted[..CONNECTED_HEADER_SIZE],
                                    &packet_memory_encrypted[CONNECTED_HEADER_SIZE..buf_len], &mut packet_memory_recv[..], timestamp_ns) else { break 'conn; };
                                payload = &packet_memory_recv[..n];
                            } else {
                                if epoch != 0 { break 'conn; }
                                payload = &packet_memory_encrypted[CONNECTED_HEADER_SIZE..buf_len];
                            }
                            #[cfg(feature = "research_budget_diagnostic")]
                            diag::context(existing_connection.handshake_hash, &existing_connection.my_transport_identity_keypair.public, &existing_connection.other_transport_identity);
                            // Packet TYPE is still determined by authenticated payload SIZE.
                            let is_ack = payload.len() == crate::ack::ACK_PAYLOAD_LEN;
                            if is_ack != wire_is_ack { break 'conn; }
                            state.receive_sequences.authenticated(nonce);
                            if !state.receive_sequences.commit(nonce) {
                                #[cfg(feature = "research_budget_diagnostic")]
                                if !is_ack { diag::replay(nonce,timestamp_ns,payload); }
                                break 'conn;
                            }
                            // ACK nonces are not holes in the dense data stream.
                            if !is_ack { state.rx_tracker.on_packet(nonce, &mut state.stats); }

                            if payload.len() < MIN_CONNECTED_PAYLOAD && payload.len() != crate::ack::ACK_PAYLOAD_LEN {
                                break 'conn;
                            }

                            // ACKs remain identified ONLY by exact decrypted packet size.
                            if payload.len() == crate::ack::ACK_PAYLOAD_LEN {
                                let bitmap_ack = if payload.len() == crate::ack::ACK_PAYLOAD_LEN {
                                    let Some(a) = state.decode_peer_ack(payload) else { break 'conn; };
                                    // A fresh authenticated ACK proves peer activity, not
                                    // positive receipt or round-trip outage recovery.
                                    state.last_peer_packet_received_time = timestamp_ns;
                                    if let Some(cipher) = &mut state.cipher { cipher.confirm_outgoing(a.highest); }
                                    state.peer_ack_delay_us = a.delay_us;
                                    Some(a)
                                } else { None };
                                if state.outage.since_ns.is_some() {
                                    // Only receipt of a RECENT outage probe proves round-trip recovery.
                                    // Old authentic ACKs cannot resume the outage. Fresh inbound
                                    // activity can extend research peer liveness, not ACK progress.
                                    if !bitmap_ack.as_ref().is_some_and(|a| recent_outage_probe_acked(state, a, timestamp_ns)) { break 'conn; }
                                    drain_accepted_cc_events(state, &mut existing_connection.unreliable_send_buffer);
                                    resume_outage(state, &mut existing_connection.unreliable_send_buffer,
                                        &mut existing_connection.unreliable_fec, timestamp_ns, max_pps);
                                }
                                state.stats.ack_packets_received += 1;

                                let mut RTT_acc = 0u64;
                                let mut RTT_count = 0u64;
                                let mut ack_latency_ns = 0u64;

                                let mut data_ack_progress = false;
                                let mut newly_acked_data = 0u64;
                                let mut delivery_latency_ns = 0u64;
                                let mut shadow_acked_data = 0u64;
                                let mut shadow_latency_ns = 0u64;
                                let mut oldest_newly_acked_send_time: u64 = u64::MAX;
                                let mut oldest_newly_acked_seq: u64 = 0;
                                let relevant_ack = bitmap_ack.as_ref().map(|a| a.relevant(&state.packets_waiting_ack_field, &state.declared_lost_field[..]));
                                let indices = relevant_ack.iter().flat_map(crate::ack::BitmapAck::acknowledged);
                                let mut small_recovery_proof = false;
                                for index in indices {
                                    if index < state.send_sequence_number {
                                        state.highest_peer_acked = Some(state.highest_peer_acked.unwrap_or(index).max(index));
                                    }
                                    let Some(receipt) = state.take_positive_receipt(index) else { continue; };
                                    // Upward proof identity has a full accepted timestamp;
                                    // the compact send-time band remains solely CC/RTT input.
                                    let probe_sent_ns = state.last_sent_tu_probe_time_ns;
                                    small_recovery_proof |= state.on_positive_receipt(index, timestamp_ns);
                                    if let Some(t) = &mut loss_trace { t.outcome('A', existing_connection.two_byte_send_prefix, index, timestamp_ns); }
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diag::feedback(index,timestamp_ns,if receipt.is_pending(){1}else{2});
                                    let sent_ns = state.send_time(index);
                                    if receipt.is_pending() {
                                        if sent_ns != 0 && sent_ns != u64::MAX {
                                            if sent_ns < oldest_newly_acked_send_time { oldest_newly_acked_seq = index; }
                                            oldest_newly_acked_send_time = oldest_newly_acked_send_time.min(sent_ns);
                                        }
                                        if receipt == PositiveReceipt::PendingProbe {
                                            state.finish_upward_probe(true, probe_sent_ns, timestamp_ns);
                                        } else {
                                            state.ack_hole.acknowledged(index);
                                            data_ack_progress = true;
                                            assert!(state.packets_in_flight > 0, "packets_in_flight underflow");
                                            state.packets_in_flight -= 1;
                                        }
                                    } else {
                                        // Acked after it was declared lost: the declaration was spurious.
                                        state.stats.spurious_losses += 1;
                                        if receipt == PositiveReceipt::PreOutage { state.outage.ignored_spurious += 1; }
                                    }
                                    if sent_ns != 0 && sent_ns != u64::MAX {
                                        let raw = timestamp_ns.saturating_sub(sent_ns);
                                        ack_latency_ns = ack_latency_ns.max(raw);
                                        if receipt.is_data() {
                                            if let Some(latency) = state.delivery_growth.shadow_receipt_latency(timestamp_ns, sent_ns) {
                                                shadow_acked_data += 1;
                                                shadow_latency_ns = shadow_latency_ns.max(latency);
                                            }
                                            if let Some(latency) = state.delivery_growth.receipt_latency(timestamp_ns, sent_ns) {
                                                newly_acked_data += 1;
                                                delivery_latency_ns = delivery_latency_ns.max(latency);
                                            }
                                        }
                                        // A late sample is still a truthful RTT measurement.
                                        if bitmap_ack.as_ref().is_none_or(|a| index == a.sample_seq) {
                                            let delay = bitmap_ack.as_ref().map_or(0, |a| a.delay_us as u64 * 1000);
                                            if delay < raw {

                                                {
                                                    // Same delay-corrected sample as CC, before 0.1ms quantization.
                                                    let sample=(raw-delay).max(100_000);
                                                    // Close the OLD window before admitting this sample;
                                                    // a boundary sample belongs only to the new window.
                                                    observe_delay_event(state,timestamp_ns,sample,index,sent_ns,delay_event_config(),&cc,max_pps);
                                                    state.target_min_rtt_ns=state.target_min_rtt_ns.min(sample);
                                                    crate::target_validation::risk_rtt(&state.target_state,sample,state.target_min_rtt_ns);
                                                }
                                                RTT_acc += (raw - delay).max(100_000) / 100_000;
                                                RTT_count += 1;
                                            }
                                        }
                                    }
                                }
                                if small_recovery_proof && state.current_tu > crate::mtu_recovery::SMALL
                                    && state.recovery.ready(timestamp_ns, state.current_tu) {
                                    state.recovery.downshifted(timestamp_ns);
                                    state.downshift_for_recovery(existing_connection.unreliable_send_buffer.target_copy_pending(), timestamp_ns);
                                }
                                if ack_latency_ns != 0 { state.loss_timer.observe(ack_latency_ns); }
                                state.delivery_growth.acknowledged_samples(timestamp_ns, (newly_acked_data, delivery_latency_ns),
                                    (shadow_acked_data, shadow_latency_ns), state.RTT_mean as u64 * 100_000, cc.rate_floor_upps);
                                if data_ack_progress {
                                    let before = state.congestion_event_time_ns;
                                    let context = loss_trace.as_ref().map(|_| cc_trace_context(state, timestamp_ns, &cc, max_pps));
                                    let cut = observe_ack_hole(state, timestamp_ns, &cc, max_pps);
                                    drain_accepted_cc_events(state, &mut existing_connection.unreliable_send_buffer);
                                    if state.congestion_event_time_ns != before {
                                        if let (Some(t), Some((seq, sent)), Some(context)) = (&mut loss_trace, cut, context) {
                                            t.cut(existing_connection.two_byte_send_prefix, seq, timestamp_ns, sent, "early", context);
                                        }
                                    }
                                }

                                let ce_feedback = bitmap_ack.as_ref().is_some_and(|a| crate::ack::update_ce_count_bounded(&mut state.peer_ce_count, a.ce_count, state.send_sequence_number));
                                if ecn_marked || ce_feedback {
                                    // A reordered ACK can advance CE even when all its packets were
                                    // acknowledged already. Do not consume that cumulative event silently.
                                    let anchor = if oldest_newly_acked_send_time != u64::MAX { oldest_newly_acked_send_time }
                                        else { bitmap_ack.as_ref().map_or(0, |a| state.send_time(a.sample_seq)) };
                                    let anchor_seq = if oldest_newly_acked_send_time != u64::MAX { oldest_newly_acked_seq }
                                        else { bitmap_ack.as_ref().map_or(0, |a| a.sample_seq) };
                                    if anchor != 0 && anchor != u64::MAX {
                                        state.ecn_congestion_received = true;
                                        state.ecn_oldest_send_time = anchor;
                                        state.ecn_oldest_seq = anchor_seq;
                                    }
                                }

                                if RTT_count > 0 {
                                    state.stats.rtt_samples += RTT_count;
                                    let slot = (state.RTT_sample_cursor % 16) as usize;
                                    state.RTT_sample_sums[slot] = RTT_acc as u32;
                                    state.RTT_sample_counts[slot] = RTT_count as u16;
                                    state.ack_arrival_times[slot] = timestamp_ns;
                                    state.RTT_sample_cursor += 1;

                                    // Compute ack pace: mean to establish baseline, then max of non-outliers
                                    let n = (state.RTT_sample_cursor as usize).min(16);
                                    if n >= 2 {
                                        let clamp_ns = state.RTT_mean as u64 * 200_000; // 2 * RTT_mean in ns
                                        // Pass 1: clamped mean as baseline
                                        let mut gap_sum = 0u64;
                                        let mut gap_count = 0u64;
                                        for i in 1..n {
                                            let cur = state.ack_arrival_times[((state.RTT_sample_cursor - 1 - (i as u64 - 1)) % 16) as usize];
                                            let prev = state.ack_arrival_times[((state.RTT_sample_cursor - 1 - i as u64) % 16) as usize];
                                            if prev != 0 && cur > prev {
                                                gap_sum += (cur - prev).min(clamp_ns);
                                                gap_count += 1;
                                            }
                                        }
                                        if gap_count > 0 {
                                            let mean_ns = gap_sum / gap_count;
                                            // Pass 2: max of gaps within 2x the mean (filter idle gaps)
                                            let mut max_ns = mean_ns;
                                            for i in 1..n {
                                                let cur = state.ack_arrival_times[((state.RTT_sample_cursor - 1 - (i as u64 - 1)) % 16) as usize];
                                                let prev = state.ack_arrival_times[((state.RTT_sample_cursor - 1 - i as u64) % 16) as usize];
                                                if prev != 0 && cur > prev {
                                                    let gap = cur - prev;
                                                    if gap <= mean_ns * 2 {
                                                        max_ns = max_ns.max(gap);
                                                    }
                                                }
                                            }
                                            state.ack_pace_estimate = (max_ns / 100_000) as u16;
                                        }
                                    }
                                }

                                break 'conn;
                            }
                            // This is not an ack packet. AEAD, nonce-space/type,
                            // replay and minimum-size admission have all succeeded.
                            state.last_peer_packet_received_time = timestamp_ns;

                            // Authentication/replay admission precedes allocation, but positive receipt
                            // follows it. A memory-erased packet must look lost to the sender.
                            let mut memory_erased = false;


                            let mut remaining_payload = payload;

                            let (target_skip_whole,mut target_whole_reservations,target_erased)=target_dup_prepare(
                                &mut state.target_dup_receive,nonce,payload,&existing_connection.receive_budget);

                            {memory_erased|=target_erased;}
                            while let Some((frame, consumed)) = read_frame(remaining_payload) {
                                remaining_payload = &remaining_payload[consumed..];
                                #[cfg(feature = "research_budget_diagnostic")]
                                let mut diagnostic_arrival = diag::RxGuard::new(&frame,nonce,timestamp_ns);
                                if matches!(frame, WireFrame::Unknown) { continue; }
                                // Retired identities cannot reopen. Surplus repairs/late
                                // fragments are still network receipts, not pressure loss.
                                if existing_connection.receive_index.frame_is_stale(&frame) {
                                    state.stats.rx_stale_identity_frames += 1;
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(3);
                                    continue;
                                }
                                if let WireFrame::Whole(data) = frame {
                                    if data.len() > max_message_size { break 'conn; }

                                    if target_skip_whole {continue;}

                                    let preallocated=target_whole_reservations.pop_front();

                                    let Some(reservation) = preallocated.or_else(||existing_connection.receive_budget.reserve(data.len() + 256)) else { memory_erased = true; continue; };
                                    state.stats.rx_messages_completed += 1;
                                    if thread_inner.is_reference() { receive_queue.push_reserved(connection_key, data.to_vec(), MAX_RECV_QUEUE_BYTES, Some(reservation)); } else { ring_state.message(&thread_inner, connection_key, data.to_vec()); }
                                    continue;
                                }

                                if let WireFrame::Fec { kind, id: package_id, block_id, message_len, block_bytes, segment, data } = frame {
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(4);
                                    if message_len > max_message_size || segment.is_some_and(|s| s.total as usize > max_message_size) {
                                        if VERBOSE { println!("Error, FEC message exceeds local max_message_size ({max_message_size}) from {connection_key:?}. Disconnecting..."); }
                                        connections_map.remove(&connection_key);
                                        ring_state.disconnected(connection_key, DisconnectReason::TimedOut);
                                        break 'conn;
                                    }
                                    let Some(layout) = wire_fec_layout(message_len, block_bytes) else { continue; };
                                    if !valid_fec_symbol(layout, block_id, data.len()) { continue; }
                                    if (kind == STP_EXT_KIND_GROUPED_FEC) != (layout.groups > 1) { continue; }
                                    if segment.is_some_and(|s| !s.valid(message_len) || s.root == package_id) { continue; }
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(5);
                                    let Some(slot_idx) = existing_connection.receive_index.admit_at(package_id,
                                        &mut existing_connection.unreliable_reassembly, &mut existing_connection.unreliable_fec, timestamp_ns, fec_inactive_grace_ns(state.RTT_mean, true)) else { memory_erased = true; continue; };
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(4);
                                    if !existing_connection.receive_index.claim(package_id, ReceiveRole::Fec { message_len, block_bytes, segment }) { continue; }
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(0);
                                    if let Some(segment) = segment {
                                        let Some(root_idx) = existing_connection.receive_index.admit_at(segment.root,
                                            &mut existing_connection.unreliable_reassembly, &mut existing_connection.unreliable_fec, timestamp_ns, fec_inactive_grace_ns(state.RTT_mean, true)) else { memory_erased = true; continue; };
                                        if !existing_connection.receive_index.claim(segment.root, ReceiveRole::Root { total: segment.total }) { continue; }
                                        // Root admission may have retired the unit in a very small table.
                                        if existing_connection.receive_index.get(package_id) != Some(slot_idx) { memory_erased = true; continue; }
                                        let fec_root = &mut existing_connection.unreliable_fec[root_idx];
                                        if fec_root.in_use() && fec_root.package_id != segment.root {
                                            if segment.root < fec_root.package_id { continue; }
                                            *fec_root = FecRecvSlot::default();
                                        }
                                        if !existing_connection.unreliable_reassembly[root_idx].admit_segment(segment, layout, block_id, data.len(), timestamp_ns, &existing_connection.receive_budget) {
                                            memory_erased = true; continue;
                                        }
                                        // Exact range already delivered/joined: ACK coverage, no decoder.
                                        if existing_connection.unreliable_reassembly[root_idx].segment_covered(segment, message_len) { continue; }
                                    }

                                    {
                                        // Same eviction rule as plain packages below, across both rings.
                                        let slot = &mut existing_connection.unreliable_fec[slot_idx];
                                        if slot.in_use() && slot.package_id != package_id {
                                            if package_id < slot.package_id { state.stats.rx_stale_fragments += 1; continue; }
                                            if !matches!(slot.state, FecRecvState::Done) {
                                                state.stats.rx_partial_evicted += 1;
                                                state.stats.rx_partial_evicted_bytes += slot.bytes_received();
                                            }
                                            *slot = FecRecvSlot::default();
                                        }
                                        if slot.in_use() && slot.segment != segment { continue; }
                                        slot.segment = segment;
                                        slot.package_id = package_id;
                                        let plain = &mut existing_connection.unreliable_reassembly[slot_idx];
                                        if (plain.completed || plain.total_len.is_some() || !plain.received.is_empty()) && plain.package_id != package_id && package_id > plain.package_id {
                                            if !plain.completed { state.stats.rx_partial_evicted += 1; }
                                            state.stats.rx_partial_evicted_bytes += plain.bytes_received();
                                            *plain = ReassemblySlot::new();
                                        }
                                    }
                                    if layout.k > FEC_INLINE_MAX_BLOCKS && !existing_connection.unreliable_fec[slot_idx].in_use()
                                        && (fec_workers.load(std::sync::atomic::Ordering::Acquire) >= MAX_FEC_DECODE_WORKERS || existing_connection.receive_budget.worker_limit_reached()) {
                                        let grace = fec_inactive_grace_ns(state.RTT_mean, true);
                                        let retired = retire_inactive_fec_workers(&mut existing_connection.unreliable_fec, timestamp_ns, grace, true);
                                        state.stats.fec_decode_preemptions += retired;
                                        state.stats.fec_worker_limit_events += retired;
                                    }
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diagnostic_arrival.outcome(0);
                                    let worker_refused_before = existing_connection.unreliable_fec[slot_idx].worker_limit_refused;
                                    let refused_before = existing_connection.unreliable_fec[slot_idx].admission_refused;
                                    let dropped_before = existing_connection.unreliable_fec[slot_idx].ingress_dropped;
                                    if let Some((message, mut _reservation)) = fec_receive_block_waking(&mut existing_connection.unreliable_fec[slot_idx], connection_key, package_id, message_len, block_bytes, block_id, data, &fec_done_tx, &fec_workers, &existing_connection.receive_budget, Some(thread_inner.wake.clone())) {
                                        let completed = if let Some(segment) = segment {
                                            let Some(root_idx) = existing_connection.receive_index.admit_at(segment.root,
                                            &mut existing_connection.unreliable_reassembly, &mut existing_connection.unreliable_fec, timestamp_ns, fec_inactive_grace_ns(state.RTT_mean, true)) else { memory_erased = true; drop(message); continue; };
                                            // The inline decoder is already released: the lease shrinks
                                            // to the Vec and moves with it into the root (no copy).
                                            _reservation.shrink(message.capacity());
                                            existing_connection.unreliable_reassembly[root_idx].finish_segment(segment, message, _reservation)
                                        } else { Some((message, _reservation)) };
                                        if let Some((message, reservation)) = completed {
                                            state.stats.rx_messages_completed += 1;
                                            if thread_inner.is_reference() { receive_queue.push_reserved(connection_key, message, MAX_RECV_QUEUE_BYTES, Some(reservation)); } else { ring_state.message(&thread_inner, connection_key, message); }
                                        }
                                    }
                                    memory_erased |= existing_connection.unreliable_fec[slot_idx].ingress_dropped != dropped_before;
                                    state.stats.fec_ingress_dropped_blocks += existing_connection.unreliable_fec[slot_idx].ingress_dropped - dropped_before;
                                    if !refused_before && existing_connection.unreliable_fec[slot_idx].admission_refused {
                                        state.stats.fec_decode_admission_refusals += 1;
                                    }
                                    if !worker_refused_before && existing_connection.unreliable_fec[slot_idx].worker_limit_refused {
                                        state.stats.fec_worker_limit_events += 1;
                                    }
                                    continue;
                                }

                                let WireFrame::Plain { fin: is_fin, id: package_id, offset, data: frag_data } = frame else { continue; };
                                let frag_offset = offset as u64;
                                let frag_len = frag_data.len() as u64;
                                if frag_offset + frag_len > u32::MAX as u64 {
                                    connections_map.remove(&connection_key);
                                        ring_state.disconnected(connection_key, DisconnectReason::TimedOut);
                                    break 'conn;
                                }
                                if frag_offset + frag_len > max_message_size as u64 {
                                    if VERBOSE { println!("Error, frag_offset + frag_len ({}) exceeds local max_message_size ({max_message_size}) from {connection_key:?}. Disconnecting...", frag_offset + frag_len); }
                                    connections_map.remove(&connection_key);
                                        ring_state.disconnected(connection_key, DisconnectReason::TimedOut);
                                    break 'conn;
                                }


                                let Some(slot_idx) = existing_connection.receive_index.admit_at(package_id,
                                    &mut existing_connection.unreliable_reassembly, &mut existing_connection.unreliable_fec, timestamp_ns, fec_inactive_grace_ns(state.RTT_mean, true)) else { memory_erased = true; continue; };

                                if !existing_connection.receive_index.claim(package_id, ReceiveRole::Plain) { continue; }
                                {
                                    let slot = &mut existing_connection.unreliable_reassembly[slot_idx];
                                    let slot_in_use = slot.completed || slot.total_len.is_some() || !slot.received.is_empty();
                                    if slot_in_use && slot.package_id != package_id {
                                        if package_id < slot.package_id { state.stats.rx_stale_fragments += 1; continue; }
                                        if !slot.completed { state.stats.rx_partial_evicted += 1; }
                                        state.stats.rx_partial_evicted_bytes += slot.bytes_received();
                                        *slot = ReassemblySlot::new();
                                    }
                                    slot.package_id = package_id;
                                    // A newer package also evicts an FEC package in the same slot index.
                                    let fec = &mut existing_connection.unreliable_fec[slot_idx];
                                    if fec.in_use() && fec.package_id != package_id && package_id > fec.package_id {
                                        if !matches!(fec.state, FecRecvState::Done) {
                                            state.stats.rx_partial_evicted += 1;
                                            state.stats.rx_partial_evicted_bytes += fec.bytes_received();
                                        }
                                        *fec = FecRecvSlot::default();
                                    }
                                }

                                if !existing_connection.unreliable_reassembly[slot_idx].admit(frag_offset as usize, frag_data.len(), &existing_connection.receive_budget) { state.stats.rx_plain_admission_refusals += 1; memory_erased = true; continue; }
                                let (mut success, mut complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                if !success {
                                    state.stats.rx_insert_failures += 1;
                                    existing_connection.unreliable_reassembly[slot_idx] = ReassemblySlot::new();
                                    existing_connection.unreliable_reassembly[slot_idx].package_id = package_id;
                                    if !existing_connection.unreliable_reassembly[slot_idx].admit(frag_offset as usize, frag_data.len(), &existing_connection.receive_budget) { state.stats.rx_plain_admission_refusals += 1; memory_erased = true; continue; }
                                    (success, complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                    assert!(success);
                                }
                                existing_connection.unreliable_reassembly[slot_idx].last_segment_ns = timestamp_ns;
                                if complete {
                                    state.stats.rx_messages_completed += 1;
                                    let reservation = existing_connection.unreliable_reassembly[slot_idx].reservation.take();
                                    let completed = existing_connection.unreliable_reassembly[slot_idx].take_complete();
                                    if thread_inner.is_reference() { receive_queue.push_reserved(connection_key, completed, MAX_RECV_QUEUE_BYTES, reservation); } else { ring_state.message(&thread_inner, connection_key, completed); }
                                }
                            }

                            if !memory_erased {
                                // Use the original admitted plaintext, not the consumed parser tail.
                                // Mixed/non-padding feedback retains the legacy active path until
                                // every scheduled receipt-window repeat has been sent.
                                state.observe_feedback_payload(payload);
                                let app_full = application_receive_full(&thread_inner);
                                let unique = state.ack_receiver.receive_with_rtt(nonce, timestamp_ns, ecn_marked || app_full,
                                    &mut state.ack_timer, state.stats.rtt_us, buf_len);
                                if unique && app_full && !ecn_marked { state.stats.rx_app_overload_ce_marks += 1; }
                            }

//////// END ORDINARY PACKET HANDLING  ////////////////////////////////////////////////////////////////////
                        }
                    } } // <- break 'conn lands here
                }
//////// END RECEIVE ////////////////////////////////////////////////////////////////////////
                if receiving {
                    receiving = false;
                    receive_round = 0;
                    send_keys.extend(connections_map.keys().copied());
                }

                if budget.expired() { return Some(std::time::Instant::now()); }
                // Messages finished by persistent decoder slices.
                while !budget.checkpoint() {
                    let Ok(completion) = fec_done_rx.try_recv() else { break; };
                    budget.progressed();
                    let key = completion.connection_key;
                    if let Some(conn) = connections_map.get_mut(&key) {
                        let Some(idx) = conn.receive_index.get(completion.package_id) else { continue; };
                        let slot = &mut conn.unreliable_fec[idx];
                        if !completion.owns(slot, &conn.receive_budget) { continue; }
                        let FecCompletion { message, reservation: mut _reservation, .. } = completion;
                        let tail = monotonic_clock_ns().saturating_sub(slot.last_block_ns);
                        slot.state = FecRecvState::Done;
                        let completed = if let Some(segment) = slot.segment {
                            let Some(root_idx) = conn.receive_index.get(segment.root) else { drop(message); continue; };
                            _reservation.shrink(message.capacity());
                            conn.unreliable_reassembly[root_idx].finish_segment(segment, message, _reservation)
                        } else { Some((message, _reservation)) };
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            if completed.is_some() { c.stats.rx_messages_completed += 1; }
                            c.stats.fec_decode_last_tail_ns = tail;
                            c.stats.fec_decode_max_tail_ns = c.stats.fec_decode_max_tail_ns.max(tail);
                        }
                        if let Some((message, reservation)) = completed {
                            if thread_inner.is_reference() { receive_queue.push_reserved(key, message, MAX_RECV_QUEUE_BYTES, Some(reservation)); } else { ring_state.message(&thread_inner, key, message); }
                        }
                    }
                }

//////// BEGIN SEND ////////////////////////////////////////////////////////////////////////
                let current_time_now_ns = monotonic_clock_ns();
                if budget.sampled(current_time_now_ns) { return Some(std::time::Instant::now()); }
                // Missing unreliable tails must not hold decoder admission forever.
                // Scan at most ten times/second, not once per incoming packet.
                if fec_sweep_keys.is_empty() && current_time_now_ns.saturating_sub(fec_sweep_ns) >= 100_000_000 {
                    fec_sweep_keys.extend(connections_map.keys().copied());
                    fec_sweep_ns = current_time_now_ns;
                }
                while let Some(key) = fec_sweep_keys.front().copied() {
                    if budget.sampled(monotonic_clock_ns()) { return Some(std::time::Instant::now()); }
                    budget.progressed();
                    if let Some(conn) = connections_map.get_mut(&key) {
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            let grace = if c.outage.since_ns.is_some() || current_time_now_ns.saturating_sub(c.last_ack_received_time) >= OUTAGE_ACK_SILENCE_NS {
                                OUTAGE_TIMEOUT_NS
                            } else { fec_inactive_grace_ns(c.RTT_mean, false) };
                            if fec_sweep_root_index == 0 {
                                c.stats.fec_decode_timeouts += retire_inactive_fec_workers(&mut conn.unreliable_fec, current_time_now_ns, grace, false);
                            }
                            let (delivered, done) = sweep_segment_roots_bounded(&mut conn.unreliable_reassembly,
                                &mut fec_sweep_root_index, current_time_now_ns, grace,
                                sweep_entry_root_checkpoint(&mut budget),
                                |message, reservation| if thread_inner.is_reference() { receive_queue.push_reserved(key, message, MAX_RECV_QUEUE_BYTES, Some(reservation)); } else { ring_state.message(&thread_inner, key, message); });
                            c.stats.rx_messages_completed += delivered;
                            // Keep both queue head and root cursor when the caller budget ends.
                            if !done { return Some(std::time::Instant::now()); }
                        }
                    }
                    fec_sweep_keys.pop_front();
                    fec_sweep_root_index = 0;
                }

                if receive_queue_report_time_ns + 10_000_000_000 <= current_time_now_ns {
                    if receive_queue.dropped_messages > 0 || receive_queue.peak_bytes > MAX_RECV_QUEUE_BYTES / 8 {
                        println!("STP port {my_port}: receive queue peaked at {} messages / {} B in the last 10s (cap {MAX_RECV_QUEUE_BYTES} B); dropped {} messages / {} B",
                                 receive_queue.peak_messages, receive_queue.peak_bytes, receive_queue.dropped_messages, receive_queue.dropped_bytes);
                    }
                    receive_queue.peak_messages = receive_queue.messages.len();
                    receive_queue.peak_bytes = receive_queue.bytes;
                    receive_queue.dropped_messages = 0;
                    receive_queue.dropped_bytes = 0;
                    receive_queue_report_time_ns = current_time_now_ns;
                }
                while let Some(connection_key) = send_keys.front().copied() {
                    if budget.checkpoint() { return Some(std::time::Instant::now()); }
                    send_keys.pop_front();
                    let Some(connection_tracking_data) = connections_map.get_mut(&connection_key) else { continue; };
                    let connection_key = &connection_key;
                    let keep = (|| { match &mut connection_tracking_data.connection_state {
                    ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } => {
                        return retry_handshake(connection_tracking_data.creation_time_ns, last_sent_time_ns,
                            current_time_now_ns, 30_000_000_000, || udp_send_with_congestion_and_dscp(socket,
                                connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                &hello_packet_payload, Dscp::Af21, false));
                    }
                    ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } => {
                        return retry_handshake(connection_tracking_data.creation_time_ns, last_sent_time_ns,
                            current_time_now_ns, 30_000_000_000, || udp_send_with_congestion_and_dscp(socket,
                                connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                &hello_packet_payload, Dscp::Af21, false));
                    }
                    ConnectionState::SendingServerHelloPlaintext { magic2: _, last_sent_time_ns, hello_packet_payload } => {
                        return retry_handshake(connection_tracking_data.creation_time_ns, last_sent_time_ns,
                            current_time_now_ns, 15_000_000_000, || udp_send_with_congestion_and_dscp(socket,
                                connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                &hello_packet_payload, Dscp::Af21, false));
                    }
                    ConnectionState::SendingServerHello { magic1, magic2: _, cipher, last_sent_time_ns, hello_packet_payload } => {
                        cipher.expire_previous(current_time_now_ns);
                        return retry_handshake(connection_tracking_data.creation_time_ns, last_sent_time_ns,
                            current_time_now_ns, 15_000_000_000, || udp_send_with_congestion_and_dscp(socket,
                                connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                &hello_packet_payload, Dscp::Af21, false));
                    }
                    ConnectionState::Connected(state) => {
                        // ACK completion can clear app-limited below; retain the pre-ACK idle state.
                        let idle_across_wait = state.is_app_limited
                            && state.last_sent_could_have_sent_data_packet < idle_resume_ns;
                        debug_assert!(state.magic2 != 0, "Connection entered Connected state without negotiating magic2");
                        if let Some(cipher) = &mut state.cipher { cipher.expire_previous(current_time_now_ns); }
                        if state.send_exhausted(&connection_tracking_data.unreliable_send_buffer) { return false; }
                        if state.peer_expired(current_time_now_ns, authenticated_peer_liveness) {
                            if VERBOSE { println!("Disconnected from: {:?}.", connection_tracking_data.other_transport_identity); }
                            return false; // connection timeout
                        }

                        #[cfg(feature = "research_budget_diagnostic")]
                        diag::context(connection_tracking_data.handshake_hash, &connection_tracking_data.my_transport_identity_keypair.public, &connection_tracking_data.other_transport_identity);
                        prepare_connected_send_tick(state, &mut connection_tracking_data.unreliable_send_buffer, current_time_now_ns);
                        if let Some(pending) = state.pending_send.take() {
                            // Freeze active time and discard pacing credit throughout the block,
                            // including the interval since the last failed attempt.
                            freeze_local_send(state, current_time_now_ns);
                            if let Some(t) = &mut loss_trace {
                                t.set_cc(connection_tracking_data.two_byte_send_prefix,
                                    cc_trace_context(state, current_time_now_ns, &cc, max_pps));
                            }
                            let ack_overload = pending.kind == PendingSendKind::Ack && application_receive_full(&thread_inner);
                            let sent = udp_send_with_congestion_and_dscp(socket,
                                connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                &pending.bytes, pending.dscp, ack_overload);
                            if let Some(sent) = sent {
                                if ack_overload { state.stats.ack_app_overload_ce_sent += 1; }
                                #[cfg(feature = "research_cohort_observer")]
                                crate::cohort_observe::observe_commit(pending.kind as usize, &pending.bytes);
                                commit_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                    pending.kind, sent, pending.bytes.len(), &pending.plaintext,
                                    connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut());
                                update_app_limit(state, current_time_now_ns,
                                    connection_tracking_data.unreliable_send_buffer.has_unsent_data());
                            } else { state.pending_send = Some(pending); }
                            return true; // no catch-up burst, and one refusal ends this tick
                        }

                        if current_time_now_ns > state.ack_timer {
                            { // send ack
                                let Some(virtual_nonce) = state.reserve_ack_nonce() else { return false; };
                                let a = state.ack_receiver.ack(current_time_now_ns);
                                state.stats.ack_delay_us_max = state.stats.ack_delay_us_max.max(a.delay_us);
                                let encoded = a.encode();
                                let Some(o) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                    virtual_nonce, &encoded, &mut packet_memory_send[..], current_time_now_ns) else { return false; };
                                let ack_overload = application_receive_full(&thread_inner);
                                let sent = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                    &packet_memory_send[..o], Dscp::Af21, ack_overload);
                                if sent.is_some() && ack_overload { state.stats.ack_app_overload_ce_sent += 1; }
                                if !finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                    PendingSendKind::Ack, sent, current_time_now_ns, &packet_memory_send[..o], &[], Dscp::Af21,
                                    connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut()) { return true; }
                                state.update_feedback_deadline(current_time_now_ns);
                            }
                        }

                        // Generic time-driven reachability, independent of queued message lengths.
                        // A pending ciphertext retry or planned whole-packet copy always goes first.
                        if current_time_now_ns >= state.recovery.next_probe
                            && !connection_tracking_data.unreliable_send_buffer.target_copy_pending()
                            && state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 {
                            let probe_size = state.recovery.probe_size(state.current_tu);
                            let kind = if probe_size == crate::mtu_recovery::SMALL {
                                PendingSendKind::Reachability
                            } else { PendingSendKind::ReachabilityCurrent };
                            let payload_len = probe_size as usize
                                - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                            packet_memory_send[..payload_len].fill(0xff);
                            let Some(packet_len) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                state.send_sequence_number, &packet_memory_send[..payload_len], &mut packet_memory_encrypted[..], current_time_now_ns) else { return false; };
                            let sent = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip,
                                connection_tracking_data.other_port, &packet_memory_encrypted[..packet_len], Dscp::BestEffort, false);
                            if !finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                kind, sent, current_time_now_ns, &packet_memory_encrypted[..packet_len],
                                &[], Dscp::BestEffort, connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut()) { return true; }
                        }

                        if state.outage.since_ns.is_none() && state.send_sequence_number > state.packets_waiting_ack_tail
                            && state.outage.pending_since_ns.is_some_and(|start|
                                current_time_now_ns.saturating_sub(start.max(state.last_ack_received_time)) >= OUTAGE_ACK_SILENCE_NS) {
                            enter_outage(state, &mut connection_tracking_data.unreliable_send_buffer,
                                current_time_now_ns, connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut());
                        }
                        if state.outage.since_ns.is_some() {
                            if state.outage.probe_due(current_time_now_ns) {
                                let seq = state.send_sequence_number;
                                let probe_payload_len = state.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                                packet_memory_send[..probe_payload_len].fill(0xff);

                                if connection_tracking_data.unreliable_send_buffer.target_copy_pending() {
                                    let buf=&mut connection_tracking_data.unreliable_send_buffer;
                                    buf.fec_prepare_packet(seq);buf.take_target_copy(&mut packet_memory_send[..probe_payload_len]);
                                }
                                let probe_dscp=if target_is_copy(&packet_memory_send[..probe_payload_len]) {connection_tracking_data.unreliable_send_buffer.last_dscp}else{Dscp::Af21};
                                let Some(packet_len) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                    seq, &packet_memory_send[..probe_payload_len], &mut packet_memory_encrypted[..], current_time_now_ns) else { return false; };
                                let send_time = udp_send_with_congestion_and_dscp(socket,
                                    connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                    &packet_memory_encrypted[..packet_len], probe_dscp, false);
                                finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                    PendingSendKind::Outage, send_time, current_time_now_ns, &packet_memory_encrypted[..packet_len],
                                    &packet_memory_send[..probe_payload_len], probe_dscp, connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut());
                            }
                            return true;
                        }

                        if state.congestion_event_time_ns == 0 {
                            state.congestion_event_rate_upps = cc.initial_rate_upps;
                            state.congestion_event_time_ns = current_time_now_ns;
                        }

                        if state.is_app_limited {
                            state.congestion_event_time_ns = current_time_now_ns.saturating_sub(state.app_limit_time_offset);
                        }

                        // The congestion curve is anchored to a K derived solely from RTT_mean, and the
                        // RTT sample buckets are only written when an ack lands. Between acks the mean and
                        // K are bit-identical, the re-anchor below solves for the anchor it already holds,
                        // and none of this work is observable. Both are skipped unless a sample moved.
                        if state.RTT_sample_cursor != state.RTT_mean_cursor {
                            state.RTT_mean_cursor = state.RTT_sample_cursor;
                            let previous_rtt_mean = state.RTT_mean;

                            let n = (state.RTT_sample_cursor as usize).min(16);
                            if n > 0 {
                                let mut total_sum = 0u64;
                                let mut total_count = 0u64;
                                for i in 0..n {
                                    total_sum += state.RTT_sample_sums[i] as u64;
                                    total_count += state.RTT_sample_counts[i] as u64;
                                }
                                // RTT is quantized to 0.1 ms: sub-tick paths still need a nonzero
                                // recovery period and finite loss timeout.
                                state.RTT_mean = quantized_rtt_mean(total_sum, total_count);
                                state.stats.rtt_us = state.RTT_mean as u64 * 100;
                            }

                            if state.RTT_mean != previous_rtt_mean {
                                let old_k = cc.recovery_rtts * (previous_rtt_mean as u64 * 100_000);
                                let new_k = cc.recovery_rtts * (state.RTT_mean as u64 * 100_000);
                                let current_t = current_time_now_ns.saturating_sub(state.congestion_event_time_ns);

                                // First RTT received — backdate to R→P transition
                                if previous_rtt_mean == u16::MAX {
                                    let first_t = if cc.startup_multiplier > 0.0 && !state.cc_startup_done { 0 } else { new_k };
                                    state.congestion_event_time_ns = current_time_now_ns.saturating_sub(first_t);
                                    if state.is_app_limited {
                                        state.app_limit_time_offset = first_t;
                                    }
                                }
                                else if old_k > 0 && new_k > 0 {
                                    // Move the anchor so the rate is continuous across the change in K.
                                    // No age can reach the old rate only on an unrampable curve: keep the anchor.
                                    if let Some(hi) = rtt_reanchor_age_hold(current_t, state.congestion_event_rate_upps, old_k, new_k, &connection_curve_policy(state,&cc), state.cc_startup_done, state.fresh_hold) {
                                        state.fresh_hold = fresh_hold_reanchored(state.fresh_hold, current_t, hi);
                                        state.congestion_event_time_ns = current_time_now_ns.saturating_sub(hi);
                                        if state.is_app_limited {
                                            state.app_limit_time_offset = hi;
                                        }
                                    }
                                }
                            }
                        }

                        let time_to_bandwidth_recovery = cc.recovery_rtts * (state.RTT_mean as u64 * 100_000);


                        // Kernel CE or receiver application pressure, via ACK IP CE or authenticated cumulative CE.
                        let (ce_seq, ce_sent) = (state.ecn_oldest_seq, state.ecn_oldest_send_time);
                        if apply_ecn_congestion(state, current_time_now_ns, &cc, max_pps) {
                            accept_cc_event(state, &mut connection_tracking_data.unreliable_send_buffer,
                                AcceptedCcEvent { kind: CC_EVENT_CE, evidence_seq: ce_seq, evidence_sent_ns: ce_sent, feedback_ns: current_time_now_ns });
                        }

                        if let Some(c)=delay_event_config() {
                            close_delay_event(state,current_time_now_ns,c,&cc,max_pps);
                            drain_accepted_cc_events(state,&mut connection_tracking_data.unreliable_send_buffer);
                        }

                        let time_to_considered_dropped = state.loss_timer.timeout_ns(
                            state.RTT_mean as u64 * 100_000,
                            current_time_now_ns.saturating_sub(state.last_ack_received_time), &cc);

                        // every send site (data loop, tu probe, keepalive, both ack paths) gates on ring space, so head never laps tail
                        assert!(state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY);
                        while state.packets_waiting_ack_tail < state.send_sequence_number {
                            if budget.checkpoint() { return true; }
                            let bit_index = state.packets_waiting_ack_tail % PACKETS_WAITING_ACK_CAPACITY;
                            // This slot now describes the tail packet (set below if declared lost).
                            state.declared_lost_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                            if state.packets_waiting_ack_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0 {
                                let mut send_time = state.send_time(state.packets_waiting_ack_tail);
                                let original_send_time = send_time;
                                if send_time != 0 && (state.RTT_mean == 0 || send_age_ns(current_time_now_ns, send_time) < time_to_considered_dropped) {
                                    break;
                                }
                                if send_time == 0 {
                                    let history_ns = 4_295_000_000;
                                    send_time = current_time_now_ns.saturating_sub(history_ns);
                                }

                                if state.packets_waiting_ack_tail == state.tu_probe_sequence_number {
                                    state.finish_upward_probe(false, state.last_sent_tu_probe_time_ns, current_time_now_ns);
                                    state.stats.tu_probes_lost += 1;
                                }
                                else {
                                    // Covered or early-counted losses still enter loss/FEC
                                    // statistics below, but cannot prime a duplicate cut.
                                    let trigger = count_congestion_signal(state, state.packets_waiting_ack_tail,
                                        send_time, current_time_now_ns, &cc);

                                    if trigger {
                                        let before = state.congestion_event_time_ns;
                                        let context = loss_trace.as_ref().map(|_| cc_trace_context(state, current_time_now_ns, &cc, max_pps));
                                        if apply_loss_congestion(state, send_time, current_time_now_ns, &cc, max_pps) {
                                            let seq = state.packets_waiting_ack_tail;
                                            // The 4.295 s CC fallback for missing history is not evidence: publish the ORIGINAL history only.
                                            accept_cc_event(state, &mut connection_tracking_data.unreliable_send_buffer,
                                                AcceptedCcEvent { kind: CC_EVENT_TIMEOUT, evidence_seq: seq, evidence_sent_ns: original_send_time, feedback_ns: current_time_now_ns });
                                        }
                                        if state.congestion_event_time_ns != before {
                                            if let (Some(t), Some(context)) = (&mut loss_trace, context) {
                                                t.cut(connection_tracking_data.two_byte_send_prefix, state.packets_waiting_ack_tail,
                                                    current_time_now_ns, send_time, "timeout", context);
                                            }
                                        }
                                    }
                                    assert!(state.packets_in_flight > 0, "packets_in_flight underflow");
                                    state.packets_in_flight -= 1;
                                    state.packet_lost_since_last_print += 1;
                                    state.stats.packets_lost += 1;
                                    if state.packets_waiting_ack_tail < state.outage.ignore_loss_before_seq { state.outage.ignored_losses += 1; }
                                    if let Some(t) = &mut loss_trace { t.outcome('L', connection_tracking_data.two_byte_send_prefix, state.packets_waiting_ack_tail, current_time_now_ns); }
                                    #[cfg(feature = "research_budget_diagnostic")]
                                    diag::feedback(state.packets_waiting_ack_tail,current_time_now_ns,3);
                                    state.declared_lost_field[(bit_index / 64) as usize] |= 1u64 << (bit_index % 64);
                                }
                            }
                            if record_loss_episodes {
                                let sent_ns = state.send_time(state.packets_waiting_ack_tail);
                                let lost = state.declared_lost_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0;
                                if sent_ns != 0 && sent_ns != u64::MAX {
                                    state.loss_episodes.on_packet(sent_ns, lost, state.RTT_mean as u64 * 100_000, &mut state.stats);
                                }
                            }
                            state.packets_waiting_ack_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                            let lost = state.declared_lost_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0;
                            if state.packets_waiting_ack_tail >= state.outage.ignore_loss_before_seq {
                                if let Some(a) = &mut connection_tracking_data.unreliable_send_buffer.fec_adaptive {
                                    a.on_sequence_finalized(state.packets_waiting_ack_tail, lost, current_time_now_ns);
                                }
                            }

                            rand_finalize_packet(state,state.packets_waiting_ack_tail,lost);
                            drain_accepted_cc_events(state, &mut connection_tracking_data.unreliable_send_buffer);
                            connection_tracking_data.unreliable_send_buffer.fec_on_packet_finalized(state.packets_waiting_ack_tail, lost);
                            state.packets_waiting_ack_tail += 1;
                        }

                        state.congestion_event_rate_upps = state.congestion_event_rate_upps.max(cc.rate_floor_upps);

                        let (allowed_bandwidth_upps, cubic_mode) = if state.is_app_limited {
                            // Freeze at the exact active age, including during recovery.
                            // A minimum age of two RTTs would spuriously grow an idle curve.
                            (state_rate(state, state.app_limit_time_offset, time_to_bandwidth_recovery, &connection_curve_policy(state,&cc), state.cc_startup_done).0, 'A')
                        } else {
                            state_rate(state, current_time_now_ns - state.congestion_event_time_ns, time_to_bandwidth_recovery, &connection_curve_policy(state,&cc), state.cc_startup_done)
                        };
                        // A local pacing ceiling is not evidence of network congestion.
                        let allowed_bandwidth_upps = local_rate_limit(allowed_bandwidth_upps.max(cc.rate_floor_upps), max_pps);
                        let allowed_bandwidth_upps = state.delivery_growth.limit(allowed_bandwidth_upps);
                        state.stats.cc_rate_upps = allowed_bandwidth_upps;

                        crate::target_validation::risk_rate(&state.target_state,allowed_bandwidth_upps, state.congestion_event_rate_upps, cubic_mode, if state.RTT_mean==u16::MAX {0}else{state.RTT_mean as u64*100_000});
                        if let Some(t) = &mut loss_trace {
                            let mut context = cc_trace_context(state, current_time_now_ns, &cc, max_pps);
                            context.pps = allowed_bandwidth_upps as f64 / 1_000_000.0;
                            t.set_cc(connection_tracking_data.two_byte_send_prefix, context);
                        }
                        // pps * 10^-6 * rtt * 10^-4 = p * 10^10
                        // BDP + sawtooth: pipe is full (BDP) plus ack batching excess (ack_pace_estimate is in 0.1ms units)
                        let bdp = rate_mul_div(allowed_bandwidth_upps, state.RTT_mean as u64, 10_000);
                        let sawtooth = rate_mul_div(allowed_bandwidth_upps, state.ack_pace_estimate as u64, 10_000);
                        let allowed_packets_in_flight = (bdp.saturating_add(sawtooth) / 1_000_000).max(1);

                        // 1 / (upps * 10^-6) = 10^6 / upps <- seconds
                        // ns = (10^6 / upps) * 10^9 = 10^15 / upps
                        let time_between_sends_ns = send_interval_ns(allowed_bandwidth_upps);
                        if idle_across_wait {
                            resume_idle_pacing(&mut state.last_sent_could_have_sent_data_packet,
                                &mut state.send_pacer_acc_ns, current_time_now_ns, time_between_sends_ns);
                        }
                        // This is some Unity Game developer level crap approximation but it will have to do.
                        let elapsed_ns = current_time_now_ns + 1 - state.last_sent_could_have_sent_data_packet.max(state.last_pacing_ack_received_time.saturating_sub(ACK_BUFFER_TIME_NS));
                        let grant = send_pacing_grant(elapsed_ns, time_between_sends_ns, state.send_pacer_acc_ns);
                        let mut packet_send_allowance_now = grant.packets;
                        let pacing_first_sequence = state.send_sequence_number;
                        state.stats.pacing_commanded_packets += packet_send_allowance_now;
                        let could_have_sent = packet_send_allowance_now != 0;

                        // ring space is checked live at each send site below so the head can never lap the tail within a tick

                        state.current_tu = state.current_tu.min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                        if !connection_tracking_data.unreliable_send_buffer.target_copy_pending() && state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && state.current_tu != ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64 && state.tu_probe_sequence_number == u64::MAX && state.prepare_upward_probe(current_time_now_ns) {
                            let payload_size = state.tu_probe_size as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                            let null_bytes = [0xffu8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];


                            let virtual_nonce = state.send_sequence_number;
                            let Some(packet_len) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                virtual_nonce, &null_bytes[..payload_size], &mut packet_memory_encrypted[..], current_time_now_ns) else { return false; };

                            let send_time_ns = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..packet_len], Dscp::BestEffort, false);
                            if !finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                PendingSendKind::MtuProbe, send_time_ns, current_time_now_ns, &packet_memory_encrypted[..packet_len],
                                &[], Dscp::BestEffort, connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut()) { return true; }
                        }

                        let payload_size = state.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();

                        if !connection_tracking_data.unreliable_send_buffer.target_copy_pending() && state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && state.last_sent_data_packet + 15_000_000_000/3 < current_time_now_ns {
                            let null_bytes = [0xffu8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];

                            let virtual_nonce = state.send_sequence_number;
                            let Some(packet_len) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                virtual_nonce, &null_bytes[..payload_size], &mut packet_memory_encrypted[..], current_time_now_ns) else { return false; };

                            let send_time_ns = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..packet_len], Dscp::Af21, false);
                            if !finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                PendingSendKind::Keepalive, send_time_ns, current_time_now_ns, &packet_memory_encrypted[..packet_len],
                                &[], Dscp::Af21, connection_tracking_data.two_byte_send_prefix, loss_trace.as_mut()) { return true; }
                            packet_send_allowance_now = packet_send_allowance_now.saturating_sub(1);
                        }

                        connection_tracking_data.unreliable_send_buffer.set_rate(rate_mul_div(allowed_bandwidth_upps, payload_size as u64, 1_000_000));
                        {
                            let buf = &mut connection_tracking_data.unreliable_send_buffer;
                            let a = buf.fec_adaptive.get_or_insert_with(|| crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, current_time_now_ns));
                            a.on_tick(current_time_now_ns);
                            if a.base_parity_active() || a.budget_base_active() {
                                // p4-burst-base B1 context: actual allowed pacing x current loss timeout. No RTT
                                // sample yet (0 or the u16::MAX placeholder) leaves H unknown (cold h = Kg).
                                let known = state.RTT_mean != 0 && state.RTT_mean != u16::MAX;
                                a.set_base_context(current_time_now_ns, allowed_bandwidth_upps, known.then_some(time_to_considered_dropped));
                            }
                            buf.set_overhead();
                            if record_fec_messages && buf.fec_record.is_none() { buf.fec_record = Some(Vec::new()); }
                            if let Some(t) = &loss_trace {
                                for q in &mut buf.queues {
                                    if q.slipstream && q.slipstream_trace.is_none() { q.slipstream_trace = Some(t.slipstream_writer()); }
                                }
                            }
                        }
                        let mut unreliable_payload_size = 0;
                        drain_accepted_cc_events(state, &mut connection_tracking_data.unreliable_send_buffer);
                        // A copy commit may apply a deferred shrink inside this loop. Stop
                        // before any new framing with the stale prepared width, then run
                        // the normal pacing finalizer below (no early-return credit leak).
                        while state.current_tu as usize == payload_size + total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap()
                            && !budget.expired() && state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && packet_send_allowance_now > 0 && state.packets_in_flight < allowed_packets_in_flight && {
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            { unreliable_payload_size = connection_tracking_data.unreliable_send_buffer.fill_packet(&mut packet_memory_send[..payload_size]); }
                            unreliable_payload_size > 0
                        } {

                            let virtual_nonce = state.send_sequence_number;
                            let Some(packet_len) = seal_connected_packet(&mut state.cipher, connection_tracking_data.two_byte_send_prefix,
                                virtual_nonce, &packet_memory_send[..unreliable_payload_size], &mut packet_memory_encrypted[..], current_time_now_ns) else { return false; };

                            should_sleep = false;
                            let test_drop = if test_drop_burst_left > 0 { test_drop_burst_left -= 1; true } else {
                                test_drop_ppm != 0 && {
                                    test_drop_rng ^= test_drop_rng << 13; test_drop_rng ^= test_drop_rng >> 7; test_drop_rng ^= test_drop_rng << 17;
                                    test_drop_rng % 1_000_000 < test_drop_ppm / test_drop_burst
                                } && { test_drop_burst_left = test_drop_burst - 1; true }
                            };
                            if test_drop { state.stats.test_dropped += 1; }
                            let send_time_ns = if test_drop { Some(monotonic_clock_ns()) }
                            else { udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..packet_len], connection_tracking_data.unreliable_send_buffer.last_dscp, false) };
                            if let Some(now) = send_time_ns { budget.sampled(now); }
                            budget.progressed();
                            let dscp = connection_tracking_data.unreliable_send_buffer.last_dscp;
                            if !finish_connected_send(state, &mut connection_tracking_data.unreliable_send_buffer,
                                PendingSendKind::Data, send_time_ns, current_time_now_ns, &packet_memory_encrypted[..packet_len],
                                &packet_memory_send[..payload_size], dscp, connection_tracking_data.two_byte_send_prefix,
                                loss_trace.as_mut()) { return true; }
                            packet_send_allowance_now = packet_send_allowance_now.saturating_sub(1);
                        }

                        let pacing_burst = state.send_sequence_number - pacing_first_sequence;
                        if pacing_burst != 0 {
                            state.stats.pacing_batches += 1;
                            state.stats.pacing_packets += pacing_burst;
                            state.stats.pacing_max_burst = state.stats.pacing_max_burst.max(pacing_burst);
                            let class = RX_BURST_CLASS_MAX.iter().position(|n| pacing_burst <= *n).unwrap_or(6);
                            state.stats.pacing_burst_hist[class] += 1;
                        }
                        let has_data = connection_tracking_data.unreliable_send_buffer.has_unsent_data();
                        // Pause the active curve, not its rate divided by PG.
                        // The latter only represents the uncapped legacy phase;
                        // growth envelopes can be far below PG at that age.
                        // Queue starvation is not evidence of congestion and
                        // must neither lower the command nor grow it while idle.
                        // Shared with the no-loss idle/resume regressions below.
                        update_app_limit(state, current_time_now_ns, has_data);

                        if could_have_sent {
                            state.last_sent_could_have_sent_data_packet = current_time_now_ns;
                            if packet_send_allowance_now == 0 {
                                state.send_pacer_acc_ns = grant.carry_ns;
                            }
                            else {
                                state.send_pacer_acc_ns = 0;
                            }
                        }

                        // bonus status debug print
                        if state.last_status_print_time + 1_000_000_000 < current_time_now_ns {
                            state.last_status_print_time = current_time_now_ns;
                            state.packet_since_last_print = 0;
                            state.packet_lost_since_last_print = 0;
                            state.max_in_flight_since_last_print = state.packets_in_flight;
                        }
                    }
                } true})();
                    budget.progressed();
                    if !keep { connections_map.remove(connection_key); ring_state.disconnected(*connection_key, DisconnectReason::TimedOut); }
                }
                receiving = true;
                // A pass with no unit (idle) still completes the owed unit.
                budget.progressed();

//////// END SEND ////////////////////////////////////////////////////////////////////////

                if thread_inner.native.get().is_some() {
                    let gone: Vec<_> = ring_state.peers.keys().chain(ring_state.connects.keys()).copied().filter(|k| !connections_map.contains_key(k)).collect();
                    for peer in gone { ring_state.disconnected(peer, DisconnectReason::TimedOut); }
                    ring_state.flush(&thread_inner);
                }
                if thread_inner.ready.enabled.load(std::sync::atomic::Ordering::Acquire) {
                    let mut connected = 0;
                    let mut changed = false;
                    let mut used = 0usize;
                    for (key, conn) in &connections_map {
                        used = used.saturating_add(conn.unreliable_send_buffer.queues.iter().map(|q| q.queue_bytes_filled as usize).sum::<usize>());
                        if conn.is_connected() {
                            connected += 1;
                            changed |= ready_peers.get(key) != Some(&conn.handshake_hash);
                        }
                    }
                    changed |= connected != ready_peers.len();
                    if changed {
                        ready_peers.clear();
                        ready_peers.extend(connections_map.iter().filter(|(_, c)| c.is_connected()).map(|(k, c)| (*k, c.handshake_hash)));
                    }
                    let receive_ready = !receive_notified && !receive_queue.messages.is_empty();
                    receive_notified |= receive_ready;
                    let space_ready = thread_inner.send_space_ready(used, ready_used);
                    ready_used = used;
                    if changed || receive_ready || space_ready { thread_inner.transport_ready(); }
                }

                if should_sleep {
                    let now = monotonic_clock_ns();
                    // Preserve the original active retry quantum. Quiet sockets
                    // wait on readability/commands, bounded by existing timers.
                    let mut deadline = now.saturating_add(100_000_000);
                    let mut include = |due| { deadline = deadline.min(next_service_deadline(now, due)); };
                    include(fec_sweep_ns.saturating_add(100_000_000));
                    let mut active_retry = false;
                    for conn in connections_map.values() {
                        let cipher = match &conn.connection_state {
                            ConnectionState::Connected(c) => c.cipher.as_ref(),
                            ConnectionState::SendingServerHello { cipher, .. } => Some(cipher),
                            _ => None,
                        };
                        if let Some(cipher) = cipher.filter(|c| c.old.is_some()) {
                            include(cipher.previous_until_ns.saturating_add(1));
                        }
                        match &conn.connection_state {
                            ConnectionState::Connected(c) => {
                                if needs_active_retry(c, conn.unreliable_send_buffer.has_unsent_data()) {
                                    active_retry = true;
                                    include(now.saturating_add(150_000));
                                } else {
                                    include(parked_send_deadline(c, now, &cc));
                                }
                                include(c.ack_timer.saturating_add(1));
                                if c.pending_send.is_none() && !conn.unreliable_send_buffer.target_copy_pending()
                                    && c.send_sequence_number - c.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 {
                                    include(c.recovery.next_probe);
                                }
                                include(c.last_sent_data_packet.saturating_add(5_000_000_001));
                                let last_activity = if authenticated_peer_liveness {
                                    c.last_ack_received_time.max(c.last_peer_packet_received_time)
                                } else { c.last_ack_received_time };
                                include(last_activity.saturating_add(OUTAGE_TIMEOUT_NS));
                                if c.pending_send.is_none() && !conn.unreliable_send_buffer.target_copy_pending()
                                    && c.send_sequence_number - c.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1
                                    && c.current_tu != ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64
                                    && c.tu_probe_sequence_number == u64::MAX {
                                    include(c.upward_probe_deadline(now));
                                }
                            }
                            ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, .. }
                            | ConnectionState::SendingClientHello { last_sent_time_ns, .. } => {
                                include(last_sent_time_ns.saturating_add(2_500_000_001));
                                include(conn.creation_time_ns.saturating_add(30_000_000_001));
                            }
                            ConnectionState::SendingServerHelloPlaintext { last_sent_time_ns, .. }
                            | ConnectionState::SendingServerHello { last_sent_time_ns, .. } => {
                                include(last_sent_time_ns.saturating_add(2_500_000_001));
                                include(conn.creation_time_ns.saturating_add(15_000_000_001));
                            }
                        }
                    }
                    wake_hint = Some(std::time::Instant::now() + std::time::Duration::from_nanos(deadline.saturating_sub(now)));
                    if active_retry {
                        // Unconditional active quantum, including across consecutive
                        // run_for calls; commands must not shorten this sleep.
                        active_wait = Some(std::time::Instant::now() + std::time::Duration::from_nanos(150_000));
                        wake_hint = active_wait;
                    } else if !thread_inner.has_request() {
                        thread_inner.wake.wait(socket, std::time::Duration::from_nanos(deadline.saturating_sub(now))
                            .min(caller_deadline.saturating_duration_since(std::time::Instant::now())));
                        let resumed = monotonic_clock_ns();
                        if waited_across_idle_quantum(now, deadline, resumed) { idle_resume_ns = resumed; }
                    }
                }
            }
        }
        };
        let pump = Pump { run: Box::new(run), wakeup: Some(std::time::Instant::now()) };
        (pump, Endpoint { inner })
    }
}

/// Post-congestion recovery/probing curve in millionths of a packet/second.
/// Recovery takes nine RTTs; compounded relative and absolute growth envelopes
/// bound every phase. See ship.rs for the sole policy and research evidence.
fn cubic_rate(t_ns: u64, r_max: u64, k_ns: u64) -> (u64, char) {
    cubic_rate_with_options(t_ns, r_max, k_ns, &crate::ship::CC)
}

/// Internal evaluation with the fixed policy (no application tuning API).
pub(crate) fn cubic_rate_with_options(t_ns: u64, r_max: u64, k_ns: u64, cc: &CongestionPolicy) -> (u64, char) {
    cubic_rate_additive(t_ns, t_ns, r_max, k_ns, cc)
}

// FreshHold: the min_growth additive term uses its own age `add_ns`
// (== t_ns for every ordinary epoch, which is bit-exact with the original).
fn cubic_rate_additive(t_ns: u64, add_ns: u64, r_max: u64, k_ns: u64, cc: &CongestionPolicy) -> (u64, char) {
    if k_ns == 0 { return (r_max.min(MAX_CC_RATE_UPPS), 'R'); }
    let t = t_ns as f64;
    let a = add_ns as f64;
    let r = r_max as f64;
    let k = k_ns as f64;
    let drop = r * (1.0 - cc.beta);
    let rtt_seconds = k / (cc.recovery_rtts as f64 * 1e9);
    let floor = cc.min_growth_uppsps;
    let ceiling = cc.max_growth_uppsps;
    let min_growth = floor / 1e9 * a;
    let linear_cap_slope = ceiling / 1e9;
    let finish = |rate: u64, mode| {
        // t-a == 0.0 for ordinary epochs: x - 0.0 == x exactly.
        let absolute = r * cc.beta + (floor + ceiling) / 1e9 * t - floor / 1e9 * (t - a);
        let relative = r * cc.beta * (cc.relative_growth_per_rtt * t / (rtt_seconds * 1e9)).exp() + min_growth;
        (rate.min(relative.min(absolute) as u64).min(MAX_CC_RATE_UPPS), mode)
    };

    // R: p^2 recovery from r*BETA up to r*cc.rate_rp
    let r_rp = r * cc.rate_rp; // rate at R→P
    let r_drop = r_rp - r * cc.beta; // total recovery range
    if t <= k {
        let p = 1.0 - t / k;
        let rate = r_rp - r_drop * p * p + min_growth;
        return finish((rate.max(r * cc.beta)) as u64, 'R');
    }

    let dt = t - k;
    let t_pg = (cc.time_pg - 1.0) * k; // duration of P phase
    let t_gs = (cc.time_gs - 1.0) * k; // duration of P+G phase (from end of R)

    let r_pg = r * cc.rate_pg; // rate at P→G
    let r_gs = r * cc.rate_gs; // rate at G→S

    // P: linear from r_rp to r_pg
    let p_slope = (r_pg - r_rp) / t_pg; // derivative at P exit = G entry

    if dt <= t_pg {
        let rate = r_rp + p_slope * dt + min_growth;
        let capped = r_rp + linear_cap_slope * dt + min_growth;
        let rate = rate.min(capped);
        let rate = if rate.is_finite() { rate } else { r };
        return finish(rate as u64, 'P');
    }

    // G: quadratic from (t_pg, r_pg), entry derivative = p_slope
    // rate = r_pg + p_slope*(dt-t_pg) + a*(dt-t_pg)^2
    // At dt=t_gs: rate = r_gs → solve for a
    let g_dt = t_gs - t_pg; // duration of G phase
    let a = (r_gs - r_pg - p_slope * g_dt) / (g_dt * g_dt);

    if dt <= t_gs {
        let u = dt - t_pg;
        let rate = r_pg + p_slope * u + a * u * u + min_growth;
        let capped = r + linear_cap_slope * dt + min_growth;
        let rate = rate.min(capped);
        let rate = if rate.is_finite() { rate } else { r };
        return finish(rate as u64, 'G');
    }

    // S: p^10 explosive ramp from G→S point
    // Entry derivative = p_slope + 2*a*g_dt (G exit derivative)
    let g_exit_slope = p_slope + 2.0 * a * g_dt;
    // p^10 with time constant chosen so entry derivative matches G exit:
    // d/dt(amplitude * (u/k_s)^10) at u=0 = 0, so we add a linear term
    // rate = r_gs + g_exit_slope*(dt-t_gs) + amplitude * ((dt-t_gs)/k_s)^10
    let k_s = k * 3.0; // startup time constant
    let s_amplitude = drop * 10.0; // aggressive startup amplitude
    let u = dt - t_gs;
    let ps = u / k_s;
    let ps2 = ps * ps;
    let ps5 = ps2 * ps2 * ps;
    let rate = r_gs + g_exit_slope * u + s_amplitude * ps5 * ps5 + min_growth;
    let capped = r + linear_cap_slope * dt + min_growth;
    let uncapped = rate;
    let rate = rate.min(capped);
    let rate = if rate.is_finite() { rate } else { r };
    let mode = if uncapped > capped { 'L' } else { 'S' };
    finish(rate as u64, mode)
}


/// Blocking reference exchange. Only transfers commands/observes results; the
/// caller must run Pump elsewhere. The historic 25 us poll cadence is retained
/// deliberately: replacing this with immediate handoff changes startup samples.
/// Use Endpoint::submit/try_take when the pump is not running concurrently.
pub(crate) fn service_connections(endpoint: &Endpoint, mut req: NetworkThreadPush) -> Option<NetworkThreadPull> {
    let _exchange = endpoint.inner.exchange.lock().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if endpoint.is_finished() || endpoint.inner.stop.load(std::sync::atomic::Ordering::Acquire) { return None; }
        match endpoint.submit(req) {
            Ok(()) => break,
            Err(returned) => req = returned,
        }
        if std::time::Instant::now() >= deadline { return None; }
        std::thread::sleep(std::time::Duration::from_micros(25));
    }
    loop {
        if endpoint.is_finished() { return None; }
        if let Some(response) = endpoint.try_take() { return Some(response); }
        if std::time::Instant::now() >= deadline { return None; }
        std::thread::sleep(std::time::Duration::from_micros(25));
    }
}

pub fn get_handshake_hash(handshake: &snow::HandshakeState) -> [u8; 64] {
    let handshake_hash_slice = handshake.get_handshake_hash();
    assert!(handshake_hash_slice.len() <= 64);
    let mut handshake_hash = [0u8; 64];
    handshake_hash[..handshake_hash_slice.len()].copy_from_slice(handshake_hash_slice);

    handshake_hash
}

use crate::helpers::*;
pub use crate::native_sockets::Dscp;
use crate::native_sockets::*;

// An outage is lack of round-trip progress, not a stream of independent congestion events.
const OUTAGE_ACK_SILENCE_NS: u64 = 2_000_000_000;
const OUTAGE_TIMEOUT_NS: u64 = 120_000_000_000;
const OUTAGE_FIRST_PROBE_NS: u64 = 250_000_000;
const OUTAGE_MAX_PROBE_NS: u64 = 4_000_000_000;
const OUTAGE_PROBE_RECORDS: usize = 32;

#[derive(Debug, Default)]
struct OutageState {
    since_ns: Option<u64>,
    pending_since_ns: Option<u64>,
    next_probe_ns: u64,
    probe_interval_ns: u64,
    resume_rate_upps: u64,
    ignore_loss_before_seq: u64,
    probes: [(u64, u64); OUTAGE_PROBE_RECORDS],
    probe_cursor: usize,
    max_probe_age_ns: u64,
    ignored_losses: u64,
    ignored_spurious: u64,
    pre_anchor_upps: u64,
    pre_startup_done: bool,
}
fn recent_outage_probe_acked(state: &ConnectionStateConnected, ack: &crate::ack::BitmapAck, now: u64) -> bool {
    let Some(since) = state.outage.since_ns else { return false; };
    // Scan the bounded chronological ledger once, not every ACK bit per record.
    state.outage.probes.iter().any(|&(seq, sent)| {
        let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
        sent != 0 && sent >= since && sent <= now &&
            (ack.sample_seq == seq || ack.contains(seq)) &&
            seq >= state.packets_waiting_ack_tail && seq < state.send_sequence_number &&
            state.packets_waiting_ack_field[(bit / 64) as usize] & (1 << (bit % 64)) != 0 &&
            now - sent <= state.outage.max_probe_age_ns.max(OUTAGE_MAX_PROBE_NS)
    })
}
impl OutageState {
    fn enter(&mut self, now: u64, rate: u64) {
        self.since_ns = Some(now);
        self.probes.fill((0, 0));
        self.probe_cursor = 0;
        self.next_probe_ns = now;
        self.probe_interval_ns = OUTAGE_FIRST_PROBE_NS;
        self.resume_rate_upps = rate.min(crate::ship::CC.initial_rate_upps);
    }
    fn record_probe(&mut self, sequence: u64, sent: u64) {
        self.probes[self.probe_cursor] = (sequence, sent);
        self.probe_cursor = (self.probe_cursor + 1) % OUTAGE_PROBE_RECORDS;
    }
    fn probe_due(&self, now: u64) -> bool {
        self.since_ns.is_some() && now >= self.next_probe_ns
    }
    fn probe_sent(&mut self, now: u64) {
        self.next_probe_ns = now.saturating_add(self.probe_interval_ns);
        self.probe_interval_ns = self.probe_interval_ns.saturating_mul(2).min(OUTAGE_MAX_PROBE_NS);
    }
    fn expired(now: u64, last_ack: u64) -> bool {
        now.saturating_sub(last_ack) >= OUTAGE_TIMEOUT_NS
    }
}

fn enter_outage(state: &mut ConnectionStateConnected, buf: &mut SendQueues,
    now: u64, prefix: u16, mut trace: Option<&mut crate::loss_trace::LossTrace>) {
    state.outage.pre_anchor_upps = state.congestion_event_rate_upps;
    state.outage.pre_startup_done = state.cc_startup_done;
    state.outage.enter(now, state.stats.cc_rate_upps.max(1));
    state.outage.max_probe_age_ns = OUTAGE_MAX_PROBE_NS.max(2 * state.RTT_mean as u64 * 100_000);
    for q in &mut buf.queues { q.fec_now_ns = now; q.fec_prune_retained(); }
    // Finalize the stranded train once. FEC retains/rescues its source within the existing
    // source-byte budget; no missing packet here invokes loss-based congestion control.
    while state.packets_waiting_ack_tail < state.send_sequence_number {
        let seq = state.packets_waiting_ack_tail;
        let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
        let pending = state.packets_waiting_ack_field[(bit / 64) as usize] & (1 << (bit % 64)) != 0;
        let lost = pending && seq != state.tu_probe_sequence_number;
        if pending {
            if lost {
                state.packets_in_flight = state.packets_in_flight.checked_sub(1).expect("outage flight underflow");
                state.stats.packets_lost += 1;
                state.outage.ignored_losses += 1;
                state.packet_lost_since_last_print += 1;
                state.declared_lost_field[(bit / 64) as usize] |= 1 << (bit % 64);
                if let Some(t) = trace.as_deref_mut() { t.outcome('L', prefix, seq, now); }
                #[cfg(feature = "research_budget_diagnostic")]
                diag::feedback(seq,now,4);
            } else { state.stats.tu_probes_lost += 1; }
        }
        state.packets_waiting_ack_field[(bit / 64) as usize] &= !(1 << (bit % 64));
        // Finalize source tags for rescue, but never teach SpanLossProfile an outage.
        drain_accepted_cc_events(state, buf);

        rand_finalize_packet(state,seq,lost);
        buf.fec_on_packet_finalized(seq, lost);
        state.packets_waiting_ack_tail += 1;
    }
    state.tu_probe_sequence_number = u64::MAX;
    state.recovery.startup_cancel();
    state.ecn_congestion_received = false;
    state.loss_count_in_window = 0;
    state.stats.cc_rate_upps = 0;
    println!("research outage entered at {} ns after {} ms ACK silence", now, now.saturating_sub(state.last_ack_received_time) / 1_000_000);
}

fn resume_outage(state: &mut ConnectionStateConnected, buf: &mut SendQueues,
    slots: &mut [FecRecvSlot], now: u64, max_pps: Option<u64>) {
    let Some(since) = state.outage.since_ns.take() else { return; };
    let paused = now.saturating_sub(since);
    // Freeze active retention time, not its byte budget or package identity.
    // Sources already outside retention at entry are not resurrected.
    for q in &mut buf.queues {
        for retained in q.fec_retained.values_mut() {
            retained.expires_ns = retained.expires_ns.saturating_add(paused);
            if let Some(deadline) = &mut retained.slot.retained_until_ns { *deadline = deadline.saturating_add(paused); }
        }
        for slot in [&mut q.fec_send_slot, &mut q.fec_suspended].into_iter().flatten() {
            slot.send_started_ns = slot.send_started_ns.saturating_add(paused);
            if let Some(deadline) = &mut slot.retained_until_ns { *deadline = deadline.saturating_add(paused); }
        }
    }
    // A path outage is not a stationary 100%-loss channel. Start a fresh FEC
    // observation window; source rescue plans above remain intact.
    if buf.fec_adaptive.is_some() {
        let policy = buf.fec_adaptive.as_ref().unwrap().policy;
        let mut fresh = crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,
            now);
        fresh.policy = policy;
        buf.fec_adaptive = Some(fresh);
    }
    // Receiver-only peers may notice a genuine outage late. Allow a worker one
    // fresh grace after recovery, but only another admitted symbol can rearm it:
    // probe-only round trips must not keep abandoned decoders alive indefinitely.
    for slot in slots {
        if matches!(slot.state, FecRecvState::Worker { .. }) && slot.recovery_resume_ns.is_none() {
            slot.recovery_resume_ns = Some(now);
        }
    }
    state.outage.ignore_loss_before_seq = state.send_sequence_number;
    // CALM research: a short silence answered by the first probe (tail loss after the
    // app went idle) is not a path outage: keep the learned anchor (cut by beta) and RTT
    // instead of restarting startup from the floor and overshooting the queue again.
    let short = paused <= 1_000_000_000 && state.outage.pre_startup_done;
    state.congestion_event_rate_upps = if short {
        local_rate_limit(state.outage.pre_anchor_upps, max_pps).max(crate::ship::CC.rate_floor_upps)
    } else { local_rate_limit(state.outage.resume_rate_upps, max_pps).max(1) };
    state.congestion_event_time_ns = now;
    state.delivery_growth = DeliveryGrowth::new(now, state.congestion_event_rate_upps);
    state.cc_startup_done = short;

    { state.delay_curve_beta=None; }
    fresh_hold_clear(state);
    if !short {
    state.RTT_sample_sums.fill(0);
    state.RTT_sample_counts.fill(0);
    state.RTT_sample_cursor = 0;
    state.RTT_mean_cursor = 0;
    state.RTT_mean = u16::MAX;
    }
    state.ack_arrival_times.fill(0);
    state.ack_pace_estimate = 0;
    state.send_pacer_acc_ns = 0;
    state.last_sent_could_have_sent_data_packet = now;
    state.last_sent_data_packet = now;
    state.loss_count_in_window = 0;
    state.loss_window_start_ns = now;
    state.app_limit_time_offset = 0;
    // Retained FEC encoders fix block_bytes at creation. Shrinking TU here would
    // discard their repairs via need > space; keep the authenticated path's TU.
    state.tu_probe_failed_count = 0;
    println!("research outage resumed after {} ms at {} pps", paused / 1_000_000, state.congestion_event_rate_upps / 1_000_000);
}

fn take_ecn_signal(state: &mut ConnectionStateConnected, guard_rtts: f64) -> bool {
    // Consume covered feedback too: it must not survive to a later ACK/epoch.
    let pending = std::mem::take(&mut state.ecn_congestion_received);
    let eligible = pending && state.ecn_oldest_send_time > state.congestion_event_time_ns.saturating_add((state.RTT_mean as f64 * 100_000.0 * guard_rtts) as u64);
    if eligible { state.loss_count_in_window = 0; }
    eligible
}

// All handshake flights retain their original bytes and expire even if every
// attempted send is refused. Never advance their resend time on local refusal.
fn retry_handshake(created: u64, last_sent: &mut u64, now: u64, lifetime: u64,
    send: impl FnOnce() -> Option<u64>) -> bool {
    if now.saturating_sub(created) > lifetime { return false; }
    if last_sent.saturating_add(2_500_000_000) < now && send().is_some() {
        *last_sent = if *last_sent == 0 { now - 2_500_000_000 + 10_000_000 } else { now };
    }
    true
}

/// A full local socket is not network congestion. Pause the existing active
/// curve (all phases), drop credit, and backdate on every retry, not just entry.
// Retention is wall-clock bounded even while a nonce-safe pending datagram retries.
// No NEW repair may be formed after expiry; the single pre-assembled ciphertext
// remains immutable and may still be accepted after expiry.
fn prepare_connected_send_tick(state: &mut ConnectionStateConnected, buf: &mut SendQueues, now: u64) {
    if !buf.target_state.same_connection(&state.target_state) {
        buf.target_state = state.target_state.clone();
        for q in &mut buf.queues {
            q.target_state = state.target_state.clone();
            if let Some(root)=&q.budget_root {root.lock().unwrap().target_state=state.target_state.clone();}
            for context in &mut q.interleave_parked {
                if let Some(root)=&context.budget_root {root.lock().unwrap().target_state=state.target_state.clone();}
            }
        }
    }
    // Real path outages pause the retention budget for every policy. A local
    // socket refusal is not an outage, and must still free expired sources.
    drain_accepted_cc_events(state, buf);
    if state.outage.since_ns.is_none() { buf.set_time(now, state.RTT_mean as u64 * 100_000); }
    // Latched once: the initial 1204 trial finished (success OR failure, or was
    // settled by cancel/outage/shrink) AND any promotion it caused is effective
    // (no deferred larger TU behind a pending copy). Never re-arms.
    if !state.tu_assessment_settled && !state.recovery.assessment_unresolved()
        && !state.deferred_tu.is_some_and(|tu| tu > state.current_tu) { state.tu_assessment_settled = true; }
    buf.set_tu_unresolved(!state.tu_assessment_settled);
    let exposure = buf.exposure_snapshot(state.stats.cc_rate_upps, state.RTT_mean);
    buf.set_exposure(exposure);
    if state.locally_blocked { freeze_local_send(state, now); }
}

fn freeze_local_send(state: &mut ConnectionStateConnected, now: u64) {
    update_app_limit(state, now, false);
    state.congestion_event_time_ns = now.saturating_sub(state.app_limit_time_offset);
    state.last_sent_could_have_sent_data_packet = now;
    state.send_pacer_acc_ns = 0;
}

/// RESEARCH-ONLY read of existing state (feature `research_cohort_observer`); mutates nothing.
#[cfg(feature = "research_cohort_observer")]
fn cohort_observation_of(t: &ConnectionTrackingData, test_drop_configured: bool) -> crate::cohort_observe::CohortObservation {
    let connected = match &t.connection_state { ConnectionState::Connected(c) => Some(c), _ => None };
    cohort_observation_parts(&t.unreliable_send_buffer, connected, &t.handshake_hash, test_drop_configured)
}
#[cfg(feature = "research_cohort_observer")]
fn cohort_observation_parts(buf: &SendQueues, connected: Option<&ConnectionStateConnected>, handshake_hash: &[u8; 64], test_drop_configured: bool) -> crate::cohort_observe::CohortObservation {
    use crate::cohort_observe::{CohortObservation, QueueObservation, ThreadSendCounters, next_service_seq};
    let queues = buf.queues.iter().map(|q| QueueObservation {
        queue_bytes_filled: q.queue_bytes_filled as u64,
        message_queue_len: q.message_queue.len() as u64,
        partial_send_slot: q.partial_send_slot.is_some(),
        fec_send_slot: q.fec_send_slot.is_some(),
        fec_suspended: q.fec_suspended.is_some(),
        segmented_send: q.segmented_send.is_some(),
        interleave_parked_len: q.interleave_parked.len() as u64,
        rescue_ready_count: q.rescue_ready_count as u64,
        rescue_ready_len: q.rescue_ready.len() as u64,
        p4_open: q.p4_open,
        p4_closing: q.p4_closing,
        p4_tail_refreshed: q.p4_tail_refreshed,
        fec_rescue_package: q.fec_rescue_package.is_some(),
        fec_retained_len: q.fec_retained.len() as u64,
    }).collect();
    let mut o = CohortObservation { queues, test_drop_configured, handshake_prefix: u64::from_le_bytes(handshake_hash[..8].try_into().unwrap()), ..Default::default() };
    if let Some(c) = connected {
        o.connected = true;
        // A proactive copy awaiting its next pacing slot is pending DATA too:
        // the cohort barrier must not seal a phase between original and copy.
        o.pending_send = c.pending_send.is_some() || buf.target_copy_pending();
        o.pending_send_kind = c.pending_send.as_ref().map(|p| p.kind as u8)
            .or_else(||buf.target_copy_pending().then_some(PendingSendKind::Data as u8));
        o.locally_blocked = c.locally_blocked;
        o.send_sequence_number = c.send_sequence_number;
        o.last_sent_data_packet = c.last_sent_data_packet;
        o.test_dropped = c.stats.test_dropped;
    }
    o.thread = ThreadSendCounters::read();
    o.service_seq = next_service_seq();
    o.observed_ns = monotonic_clock_ns();
    o
}

/// The send buffer has already assembled this packet. On refusal its FEC tags
/// remain attached to the uncommitted sequence; do not prepare or fill again.
fn finish_connected_send(state: &mut ConnectionStateConnected, buf: &mut SendQueues,
    kind: PendingSendKind, sent: Option<u64>, now: u64, bytes: &[u8], plaintext: &[u8],
    dscp: Dscp, prefix: u16, trace: Option<&mut crate::loss_trace::LossTrace>) -> bool {
    if let Some(sent) = sent {
        #[cfg(feature = "research_cohort_observer")]
        crate::cohort_observe::observe_commit(kind as usize, bytes);
        commit_connected_send(state, buf, kind, sent, bytes.len(), plaintext, prefix, trace);
        if kind == PendingSendKind::Ack { update_app_limit(state, now, buf.has_unsent_data()); }
        true
    } else {
        debug_assert!(state.pending_send.is_none());
        if kind != PendingSendKind::Ack {
            state.pending_send = Some(PendingSend { kind, bytes: bytes.to_vec(), plaintext: plaintext.to_vec(), dscp });
        }
        state.locally_blocked = true;
        freeze_local_send(state, now);
        false
    }
}

/// One physical DATA outcome per ring retirement, before duplicate-pair aggregation.
/// Subsequent spurious ACK corrections intentionally do not undo samples.

fn rand_finalize_packet(state:&mut ConnectionStateConnected,seq:u64,lost:bool) {
    let Some(bits)=state.rand_background_bits.as_mut() else {return};
    let bit=seq%PACKETS_WAITING_ACK_CAPACITY;
    let mask=1u64<<(bit%64);
    let background=bits[(bit/64) as usize]&mask!=0;
    bits[(bit/64) as usize]&=!mask;
    crate::target_validation::rand_resolved(&state.target_state,background,lost);
}

fn commit_connected_send(state: &mut ConnectionStateConnected, buf: &mut SendQueues,
    kind: PendingSendKind, sent: u64, len: usize, plaintext: &[u8], prefix: u16,
    trace: Option<&mut crate::loss_trace::LossTrace>) {
    state.locally_blocked = false;
    if kind == PendingSendKind::Ack {
        // A fresh accepted ACK ends an ACK-only local limit. The rejected ACK
        // changed neither batching state nor send statistics.
        state.ack_receiver.sent(sent);
        state.stats.ack_packets_sent += 1;
        state.stats.ack_bytes_sent += len as u64;
        return;
    }
    let seq = state.send_sequence_number;

    if crate::target_validation::rand_enabled() {
        let background=kind==PendingSendKind::Data && crate::target_validation::rand_background(&state.target_state,state.outage.since_ns.is_some());
        let bits=state.rand_background_bits.get_or_insert_with(||vec![0;PACKETS_WAITING_ACK_WORDS].into_boxed_slice());
        let bit=seq%PACKETS_WAITING_ACK_CAPACITY;
        bits[(bit/64) as usize]&=!(1u64<<(bit%64));
        if background {bits[(bit/64) as usize]|=1u64<<(bit%64);}
    }

    {
        state.stats.dup_fallbacks=buf.target_dup_fallbacks;
        if target_is_copy(plaintext) {
            state.stats.dup_datagrams+=1;state.stats.dup_bytes+=len as u64;
            state.stats.dup_messages+=target_dup_counts(plaintext).0;
            if kind != PendingSendKind::Data { buf.queued_commit(seq); }
        }
    }
    if kind != PendingSendKind::Data { buf.fec_prepare_packet(seq); }
    let active_frontier = state.active_send_frontier;
    state.account_send(sent);
    if kind.is_generic() { state.active_send_frontier = active_frontier; }
    state.recovery.sent(seq, len as u64, sent, kind == PendingSendKind::Data, kind.is_generic());
    if kind.is_generic() { state.recovery.scheduled_probe_sent(sent, len as u64); }
    state.packet_since_last_print += 1;
    if kind == PendingSendKind::MtuProbe {
        state.tu_probe_sequence_number = seq;
        state.last_sent_tu_probe_time_ns = sent;
        return;
    }
    if kind == PendingSendKind::Data {
        #[cfg(feature = "research_budget_diagnostic")]
        diag::tx(seq, sent, plaintext);
        buf.fec_on_data_committed(seq, sent);
        if let Some(a) = &mut buf.fec_adaptive { a.on_data_sent(seq); }
    }
    if kind == PendingSendKind::Outage || (kind.is_generic() && state.outage.since_ns.is_some()) {
        state.outage.record_probe(seq, sent);
        // Either generic probe can resume outage, but must not postpone the
        // independently backed-off current-TU outage probe schedule.
        if kind == PendingSendKind::Outage { state.outage.probe_sent(sent); }
    }
    if matches!(kind, PendingSendKind::Data | PendingSendKind::Outage) {
        if let Some(t) = trace { t.sent(prefix, seq, sent, plaintext); }
    }
    state.last_sent_data_packet = sent;
    state.packets_in_flight += 1;
    state.stats.packets_sent += 1;
    state.stats.bytes_sent += len as u64;
    // The accepted datagram used the old effective TU. Promote before framing
    // any later current-TU datagram, never by changing/resealing its ciphertext.
    if !buf.target_copy_pending() || state.deferred_tu.is_some_and(|tu| tu >= state.current_tu) {
        if let Some(tu) = state.deferred_tu.take() { state.apply_effective_tu(tu, sent); }
    }
    state.max_in_flight_since_last_print = state.max_in_flight_since_last_print.max(state.packets_in_flight);
}

/// Freeze active curve time on starvation; preserve the anchor and phase for
/// every controller, including bounded, compounded, proportional and startup.
fn update_app_limit(state: &mut ConnectionStateConnected, now_ns: u64, has_data: bool) {
    if !has_data && !state.is_app_limited {
        state.stats.cc_app_limited_entries += 1;
        state.app_limit_time_offset = now_ns.saturating_sub(state.congestion_event_time_ns);
        state.delivery_growth.app_limited_since_ns = now_ns;
        state.is_app_limited = true;
    } else if has_data && state.is_app_limited {
        let quiet_start = state.delivery_growth.app_limited_since_ns;
        state.delivery_growth.resume_after_quiet(now_ns, now_ns.saturating_sub(quiet_start),
            state.RTT_mean as u64 * 100_000);
        state.congestion_event_time_ns = now_ns.saturating_sub(state.app_limit_time_offset);
        state.is_app_limited = false;
    }
}

// Keep the CE-discovered anchor, epoch and guard; only this event's recovery
// starts at b*anchor. For b>rate_rp lift R's endpoint to b to avoid a backwards
// step at R->P. The absolute/relative growth envelopes remain unchanged.
fn connection_curve_policy(state:&ConnectionStateConnected, cc:&CongestionPolicy) -> CongestionPolicy {

    if let Some(beta)=state.delay_curve_beta {
        return CongestionPolicy { beta,rate_rp:cc.rate_rp.max(beta),..*cc };
    }
    let _=state;
    *cc
}

fn connection_rate(t_ns: u64, anchor_upps: u64, k_ns: u64, cc: &CongestionPolicy, startup_done: bool) -> (u64, char) {
    connection_rate_add(t_ns, t_ns, anchor_upps, k_ns, cc, startup_done)
}

// FRESHHOLD: `add_ns` is the additive (min_growth) age; startup ignores it.
fn connection_rate_add(t_ns: u64, add_ns: u64, anchor_upps: u64, k_ns: u64, cc: &CongestionPolicy, startup_done: bool) -> (u64, char) {
    if !startup_done {
        let rtt_ns = k_ns / cc.recovery_rtts;
        // The sentinel RTT means no sample yet: never ramp on an unknown path.
        let exponent = if rtt_ns == u16::MAX as u64 * 100_000 { 0.0 } else { cc.startup_multiplier.ln() * t_ns as f64 / rtt_ns.max(100_000) as f64 };
        ((anchor_upps as f64 * exponent.min(30.0).exp()).min(MAX_CC_RATE_UPPS as f64) as u64, 'I')
    } else { cubic_rate_additive(t_ns, add_ns, anchor_upps, k_ns, cc) }
}

// FreshHold state. phase: 0 none (ordinary, add=t),
// 1 hold (add=0; barrier_ns = frozen fresh barrier, absolute), 2 released
// (release_coord_ns = SIGNED active-age coordinate of the release, negative after a
// reanchor whose new base age is below the carried credit; release_wall_ns = absolute
// time of the true release, gating historical send-time queries).
// The fresh-subset min sample (send strictly > barrier) of the current window is
// tracked; MAX = none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreshHold { phase:u8, barrier_ns:u64, release_coord_ns:i128, release_wall_ns:u64, min_sample_ns:u64 }

impl FreshHold {
    const NONE: FreshHold = FreshHold { phase:0, barrier_ns:0, release_coord_ns:0, release_wall_ns:0, min_sample_ns:u64::MAX };
    // Additive age at active curve age t: max(0, t - release_coord) in exact i128.
    fn add(&self, t:u64) -> u64 {
        match self.phase {
            1 => 0,
            2 => (t as i128 - self.release_coord_ns).clamp(0, u64::MAX as i128) as u64,
            _ => t,
        }
    }
    // Mapping for a historical query about a packet sent at absolute time sent_ns:
    // sent at/before the true release => it was sent under HOLD (zero additive).
    fn for_send(&self, sent_ns:u64) -> FreshHold {
        if self.phase==2 && sent_ns<=self.release_wall_ns { FreshHold { phase:1, ..*self } } else { *self }
    }
}

// Released: keep additive age == credit exactly at the new active age hi (signed
// coordinate, no clamp, no credit created or destroyed). Hold/none unchanged.
fn fresh_hold_reanchored(h:FreshHold, current_t:u64, hi:u64) -> FreshHold {
    if h.phase!=2 { return h; }
    FreshHold { release_coord_ns:hi as i128 - h.add(current_t) as i128, ..h }
}

fn state_rate(state:&ConnectionStateConnected, t_ns:u64, k_ns:u64, cc:&CongestionPolicy, startup_done:bool) -> (u64, char) {
    connection_rate_add(t_ns, state.fresh_hold.add(t_ns), state.congestion_event_rate_upps, k_ns, cc, startup_done)
}

// Discovery: rate at a historical send, gated by the true release wall time.
fn state_rate_sent(state:&ConnectionStateConnected, sent_ns:u64, t_ns:u64, k_ns:u64, cc:&CongestionPolicy, startup_done:bool) -> (u64, char) {
    connection_rate_add(t_ns, state.fresh_hold.for_send(sent_ns).add(t_ns), state.congestion_event_rate_upps, k_ns, cc, startup_done)
}

// Ordinary accepted loss / ECN path / outage resume: return to ordinary additive age.
fn fresh_hold_clear(state:&mut ConnectionStateConnected) {
    state.fresh_hold=FreshHold::NONE;
}

// Age on the new-K curve that first reaches the old-K rate at `current_t`, searched
// from the original lower bound. The original upper bound is only a first guess: it
// doubles (saturating) until reached. Invariant: hi reaches the rate, and lo is the
// original bound or lo - 1 does not. None means no u64 age reaches it, which with a
// growing startup multiplier only occurs on the flat no-sample sentinel curve.
fn rtt_reanchor_age(current_t: u64, anchor_upps: u64, old_k: u64, new_k: u64, cc: &CongestionPolicy, startup_done: bool) -> Option<u64> {
    rtt_reanchor_age_hold(current_t, anchor_upps, old_k, new_k, cc, startup_done, FreshHold::NONE)
}

// FRESHHOLD: phase none keeps the original identity mapping (add=t) exactly. Hold
// (add=0) and released search with the additive credit FIXED at its current value;
// the caller then translates the release coordinate (fresh_hold_reanchored) so the
// new base age creates no additive credit.
fn rtt_reanchor_age_hold(current_t: u64, anchor_upps: u64, old_k: u64, new_k: u64, cc: &CongestionPolicy, startup_done: bool, hold: FreshHold) -> Option<u64> {
    let credit = hold.add(current_t);
    let add = |t: u64| if hold.phase == 0 { t } else { credit };
    let (old_rate, _) = connection_rate_add(current_t, add(current_t), anchor_upps, old_k, cc, startup_done);
    let reaches = |t| connection_rate_add(t, add(t), anchor_upps, new_k, cc, startup_done).0 >= old_rate;
    let mut lo = if new_k >= old_k { current_t } else { 0u64 };
    let mut hi = if new_k >= old_k { current_t.saturating_mul(2).saturating_add(new_k) } else { current_t };
    while !reaches(hi) {
        if hi == u64::MAX { return None; }
        lo = hi + 1;
        hi = hi.saturating_add(hi.max(1));
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if reaches(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(hi)
}

// Trace-only context: evaluate the same curve and local cap used by the pacer.
// A 1 ms right derivative is uniform across all curve phases, not a startup rule.
fn cc_trace_context(state: &ConnectionStateConnected, now: u64, cc: &CongestionPolicy, max_pps: Option<u64>) -> crate::loss_trace::CcContext {
    let curve=connection_curve_policy(state,cc); let cc=&curve;
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    let k = cc.recovery_rtts * rtt_ns;
    let age = if state.is_app_limited { state.app_limit_time_offset }
        else { now.saturating_sub(state.congestion_event_time_ns) };
    let (rate, mode) = state_rate(state, age, k, cc, state.cc_startup_done);
    let capped = |r: u64| state.delivery_growth.bound(local_rate_limit(r.max(cc.rate_floor_upps), max_pps));
    let rate = capped(rate);
    let next = capped(state_rate(state, age.saturating_add(1_000_000), k, cc, state.cc_startup_done).0);
    crate::loss_trace::CcContext { pps: rate as f64 / 1_000_000.0,
        slope_ppsps: if state.is_app_limited { 0.0 } else { next.saturating_sub(rate) as f64 / 1000.0 },
        rtt_ns, feedback_ns: rtt_ns.saturating_add((rtt_ns / 16).max(1_000_000))
            .saturating_add(crate::ship::ACK.max_delay_us as u64 * 1000),
        mode: if state.is_app_limited { 'A' } else { mode } }
}

fn quantized_rtt_mean(sum: u64, count: u64) -> u16 {
    (sum / count.max(1)).clamp(1, u16::MAX as u64) as u16
}

// Congestion-only fast feedback. Three distinct newer data receipts, then a fresh
// ACK frame after RTT/16 (at least 1 ms), tolerate packet/ACK reordering and batching.
// This is the receiver's existing reorder grace, not a delay-based congestion model.
const ACK_HOLE_NEWER_PACKETS: usize = 3;
const ACK_HOLE_PENDING_RANGES: usize = 16;

#[derive(Debug)]
struct AckHole {
    newest: [Option<u64>; ACK_HOLE_NEWER_PACKETS],
    cursor: u64,
    confirmed_before: u64, // qualifying holes already fed to the congestion cohort
    pending: VecDeque<(u64, u64)>, // exclusive sequence boundary, first qualifying ACK arrival
}
impl Default for AckHole {
    fn default() -> Self {
        Self { newest: [None; ACK_HOLE_NEWER_PACKETS], cursor: 0, confirmed_before: 0,
            pending: VecDeque::with_capacity(ACK_HOLE_PENDING_RANGES) }
    }
}
impl AckHole {
    fn acknowledged(&mut self, seq: u64) {
        if self.newest.contains(&Some(seq)) { return; }
        let mut incoming = Some(seq);
        for slot in &mut self.newest {
            if incoming > *slot { std::mem::swap(slot, &mut incoming); }
        }
    }
}

fn observe_ack_hole(state: &mut ConnectionStateConnected, now: u64, cc: &CongestionPolicy, max_pps: Option<u64>) -> Option<(u64, u64)> {
    if state.outage.since_ns.is_some() || state.RTT_mean == u16::MAX { return None; }
    let Some(third) = state.ack_hole.newest[ACK_HOLE_NEWER_PACKETS - 1] else { return None; };
    let grace = (state.RTT_mean as u64 * 100_000 / 16).max(1_000_000);
    let guard = state.congestion_event_time_ns.saturating_add(
        (state.RTT_mean as f64 * 100_000.0 * cc.event_guard_rtts) as u64);
    let mut seq = state.ack_hole.cursor.max(state.packets_waiting_ack_tail).max(state.outage.ignore_loss_before_seq);
    // Each advancing ACK boundary qualifies a whole range at once. Keep its own
    // arrival time: newer ranges must not borrow an older range's reorder grace.
    let covered = state.ack_hole.pending.back().map_or(seq, |&(end, _)| end.max(seq));
    if third > covered {
        if state.ack_hole.pending.len() < ACK_HOLE_PENDING_RANGES {
            state.ack_hole.pending.push_back((third, now));
        } else {
            // Fixed allocation under chatty ACKs: coalesce only the newest range,
            // restarting its grace so newly qualifying holes cannot confirm early.
            *state.ack_hole.pending.back_mut().unwrap() = (third, now);
        }
    }
    let mut cut = None;
    while let Some(&(end, since)) = state.ack_hole.pending.front() {
        if end > seq && now.saturating_sub(since) < grace { break; }
        state.ack_hole.pending.pop_front();
        while seq < end {
            // Each range and ring word is scanned once, even behind a long
            // unfinalized loss train. Cleared (reordered) holes are simply skipped.
            let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
            let word = state.packets_waiting_ack_field[(bit / 64) as usize] >> (bit % 64);
            if word == 0 { seq = (seq + 64 - bit % 64).min(end); continue; }
            seq += word.trailing_zeros() as u64;
            if seq >= end { seq = end; break; }
            let sent = state.send_time(seq);
            if seq != state.tu_probe_sequence_number && sent != 0 && sent != u64::MAX && sent > guard {
                // Only CC changes; no final-loss, retry/rescue or FEC feedback.
                let trigger = count_congestion_signal(state, seq, sent, now, cc);
                state.ack_hole.confirmed_before = seq + 1;
                if trigger {
                    if apply_loss_congestion(state, sent, now, cc, max_pps) {
                        push_accepted_cc_event(state, AcceptedCcEvent { kind: CC_EVENT_EARLY, evidence_seq: seq, evidence_sent_ns: sent, feedback_ns: now });
                    }
                    println!("congestion early ACK HOLE {seq} at {now} ns");
                    cut = Some((seq, sent));
                }
            }
            seq += 1;
        }
    }
    state.ack_hole.cursor = seq;
    cut
}

/// Loss timing observes full ACK latency (including receiver batching), independently
/// of the delay-corrected RTT used by CC. One sample per ACK, not per bitmap bit.
/// Late ACKs must participate: censoring them leaves a low-rate sender blind to jitter.
#[derive(Debug, Default)]
struct LossTimer {
    srtt_ns: u64,
    rttvar_ns: u64,
}

impl LossTimer {
    fn observe(&mut self, latency_ns: u64) {
        let sample = latency_ns.max(100_000);
        if self.srtt_ns == 0 {
            self.srtt_ns = sample;
            self.rttvar_ns = sample / 2;
        } else {
            self.rttvar_ns = (3 * self.rttvar_ns + self.srtt_ns.abs_diff(sample)) / 4;
            self.srtt_ns = (7 * self.srtt_ns + sample) / 8;
        }
    }

    fn timeout_ns(&self, rtt_ns: u64, since_ack_ns: u64, cc: &CongestionPolicy) -> u64 {
        // Keep the shipped two-RTT minimum and blackhole grace. ACK delay is
        // included in raw samples; reserve the policy cap even before a sample.
        let minimum = (rtt_ns as f64 * cc.loss_timeout_rtts) as u64
            + crate::ship::ACK.max_delay_us as u64 * 1000;
        minimum.max(self.srtt_ns.saturating_add((4 * self.rttvar_ns).max(1_000_000)))
            .max(since_ack_ns.saturating_mul(2).min(1_000_000_000))
    }
}

fn local_rate_limit(rate: u64, max_pps: Option<u64>) -> u64 {
    max_pps.map_or(rate, |limit| rate.min(limit.saturating_mul(1_000_000).max(1))).min(MAX_CC_RATE_UPPS)
}

// A clipped curve is not a rate we ever sent. Loss/ECN must cut actual pacing,
// not discover an arbitrarily high rate on the hidden time-based curve.
fn congestion_discovery_rate(state: &ConnectionStateConnected, discovered: u64, max_pps: Option<u64>) -> u64 {
    let actual = state.stats.cc_rate_upps;
    local_rate_limit(if actual == 0 { discovered } else { discovered.min(actual) }, max_pps)
}

// RESEARCH ONLY: persistent RTT inflation is an additional CE-style EVENT source.
// No bandwidth estimate or pacing model; all accepted cuts use apply_ecn_congestion.

#[derive(Clone, Copy, Debug)]
struct DelayEventConfig {
    k:f64, min_ms:f64, max_ms:f64, interval_rtts:f64, giveup:u64, hold:Option<DelayHoldConfig>,
    beta:Option<f64>, #[cfg(feature="research_target_validation")] effect:Option<DelayEffectConfig>,
}
#[cfg(feature="research_target_validation")]
#[derive(Clone, Copy, Debug)]
struct DelayEffectConfig { frac:f64, rtts:f64 }
#[cfg(feature="research_target_validation")]
#[derive(Debug)]
struct DelayEffectPending { excess_ns:u64, guard_until_ns:u64, deadline_ns:u64 }

#[derive(Clone, Copy, Debug)]
struct DelayHoldConfig { rtts:f64, max_rtts:f64 }

impl DelayHoldConfig {
    fn duration_ns(self, consecutive:u64, srtt_ns:u64) -> u64 {
        let mut rtts=self.rtts;
        // At most 2098 doublings span all positive finite f64 values. Cap
        // before converting to nanoseconds, including extreme research inputs.
        for _ in 0..consecutive.saturating_sub(1).min(2098) {
            if rtts>=self.max_rtts { break; }
            rtts=(rtts*2.).min(self.max_rtts);
        }
        (rtts*srtt_ns as f64).ceil() as u64
    }
    fn clean_ns(self, srtt_ns:u64) -> u64 { (self.max_rtts*srtt_ns as f64).ceil() as u64 }
}

impl DelayEventConfig {
    fn parse(mut get:impl FnMut(&str)->Option<String>) -> Option<Self> {
        let enabled=get("STP_CC_DELAY_EVENT").unwrap_or_else(||"0".into());
        assert!(enabled=="0" || enabled=="1", "STP_CC_DELAY_EVENT must be 0 or 1");
        if enabled=="0" { return None; }
        let mut required=|name:&str| {
            let v=get(name).unwrap_or_else(||panic!("{name} is required when STP_CC_DELAY_EVENT=1"));
            let x=v.parse::<f64>().unwrap_or_else(|_|panic!("{name} must be a finite float"));
            assert!(x.is_finite(), "{name} must be finite"); x
        };
        let mut c=Self { k:required("STP_CC_DELAY_K"), min_ms:required("STP_CC_DELAY_MIN_MS"),
            max_ms:required("STP_CC_DELAY_MAX_MS"), interval_rtts:required("STP_CC_DELAY_INTERVAL_RTTS"), giveup:0, hold:None, beta:None, #[cfg(feature="research_target_validation")] effect:None };
        if let Some(v)=get("STP_CC_DELAY_BETA") {
            let b=v.parse::<f64>().expect("STP_CC_DELAY_BETA must be a finite float in (0,1]");
            assert!(b.is_finite() && b>0. && b<=1., "STP_CC_DELAY_BETA must be in (0,1]");
            c.beta=Some(b);
        }
        // Unset/0 preserves the original delay-event path.
        c.giveup=get("STP_CC_DELAY_GIVEUP").map_or(0, |v|v.parse::<u64>()
            .unwrap_or_else(|_|panic!("STP_CC_DELAY_GIVEUP must be an integer >= 0")));
        // Never inspect hold knobs outside competitive give-up; an unset initial
        // hold also leaves MAX unread, preserving the existing give-up mode.
        if c.giveup>0 {
            if let Some(v)=get("STP_CC_DELAY_HOLD_RTTS") {
                let rtts=v.parse::<f64>().expect("STP_CC_DELAY_HOLD_RTTS must be a finite float > 0");
                assert!(rtts.is_finite() && rtts>0., "STP_CC_DELAY_HOLD_RTTS must be a finite float > 0");
                let max_rtts=get("STP_CC_DELAY_HOLD_MAX_RTTS")
                    .expect("STP_CC_DELAY_HOLD_MAX_RTTS is required when STP_CC_DELAY_HOLD_RTTS is set")
                    .parse::<f64>().expect("STP_CC_DELAY_HOLD_MAX_RTTS must be a finite float");
                assert!(max_rtts.is_finite() && max_rtts>=rtts,
                    "STP_CC_DELAY_HOLD_MAX_RTTS must be finite and >= STP_CC_DELAY_HOLD_RTTS");
                c.hold=Some(DelayHoldConfig { rtts,max_rtts });
            }
        }
        // EFFECT_RTTS is mandatory only when FRAC is enabled; neither is read
        // without GIVEUP, and an orphan EFFECT_RTTS is ignored.
        #[cfg(feature="research_target_validation")]
        if c.giveup>0 {
            if let Some(v)=get("STP_CC_DELAY_EFFECT_FRAC") {
                let frac=v.parse::<f64>().expect("STP_CC_DELAY_EFFECT_FRAC must be a finite float in (0,1)");
                assert!(frac.is_finite() && frac>0. && frac<1., "STP_CC_DELAY_EFFECT_FRAC must be in (0,1)");
                let rtts=get("STP_CC_DELAY_EFFECT_RTTS")
                    .expect("STP_CC_DELAY_EFFECT_RTTS is required when STP_CC_DELAY_EFFECT_FRAC is set")
                    .parse::<f64>().expect("STP_CC_DELAY_EFFECT_RTTS must be a finite float > 0");
                assert!(rtts.is_finite() && rtts>0., "STP_CC_DELAY_EFFECT_RTTS must be finite and > 0");
                c.effect=Some(DelayEffectConfig { frac,rtts });
            }
        }
        assert!(c.k>0., "STP_CC_DELAY_K must be > 0");
        assert!(c.min_ms>=0., "STP_CC_DELAY_MIN_MS must be >= 0");
        assert!(c.max_ms>=c.min_ms, "STP_CC_DELAY_MAX_MS must be >= STP_CC_DELAY_MIN_MS");
        assert!(c.interval_rtts>0., "STP_CC_DELAY_INTERVAL_RTTS must be > 0");
        Some(c)
    }
    fn threshold_ns(self, min_rtt_ns:u64) -> f64 {
        (self.k*min_rtt_ns as f64).clamp(self.min_ms*1e6, self.max_ms*1e6)
    }
    fn interval_ns(self, srtt_ns:u64) -> u64 { (self.interval_rtts*srtt_ns as f64).max(20_000_000.) as u64 }
}

fn delay_event_config() -> Option<DelayEventConfig> {
    static CONFIG:std::sync::OnceLock<Option<DelayEventConfig>>=std::sync::OnceLock::new();
    *CONFIG.get_or_init(||DelayEventConfig::parse(|n|crate::ship::policy_var(n).ok()))
}

pub(crate) fn initialize_delay_event() { let _=delay_event_config(); }

#[derive(Debug, Default)]
struct DelayGiveupState {
    pending_event_ns:Option<u64>, ineffective:u64, suspended:bool,
    #[cfg(feature="research_target_validation")] pending_effect:Option<DelayEffectPending>,
    // Only touched when HOLD_RTTS is set. Deadlines freeze RTT_mean at the
    // suspension/rearm transition; low windows never shorten or extend them.
    consecutive_suspensions:u64, hold_until_ns:Option<u64>, clean_until_ns:Option<u64>,
}

#[derive(Debug, Default)]
struct DelayEventWindow {
    deadline_ns:Option<u64>, min_sample_ns:Option<u64>, evidence_seq:u64, evidence_sent_ns:u64,
}

impl DelayEventWindow {
    // Fixed duration per window, based on the smoothed CC RTT at its start. The
    // first valid sample seeds SRTT before the send loop has calculated RTT_mean.
    fn observe(&mut self, now:u64, sample_ns:u64, seq:u64, sent_ns:u64, srtt_ns:u64, c:DelayEventConfig) {
        if self.deadline_ns.is_none() { self.deadline_ns=Some(now.saturating_add(c.interval_ns(srtt_ns))); }
        self.min_sample_ns=Some(self.min_sample_ns.map_or(sample_ns, |m|m.min(sample_ns)));
        self.evidence_seq=seq; self.evidence_sent_ns=sent_ns;
    }
    // Called BEFORE inserting a sample at/after the boundary, and on send ticks.
    // Empty windows do nothing; no synthetic RTT samples and no repeated idle cuts.
    fn close(&mut self, now:u64, min_rtt_ns:u64, srtt_ns:u64, c:DelayEventConfig) -> Option<(u64,u64)> {
        if !self.deadline_ns.is_some_and(|deadline|now>=deadline) { return None; }
        let sample=self.min_sample_ns;
        let evidence=(self.evidence_seq,self.evidence_sent_ns);
        *self=Self { deadline_ns:Some(now.saturating_add(c.interval_ns(srtt_ns))), ..Self::default() };
        sample.filter(|&m|m.saturating_sub(min_rtt_ns) as f64>c.threshold_ns(min_rtt_ns)).map(|_|evidence)
    }
}

// One fractional experiment at a time. Timing is a simple attribution heuristic,
// not proof of causality. Guard/deadline freeze RTT_mean at acceptance. Empty
// ticks can expire it; only nonempty post-guard windows can prove a drop.
#[cfg(feature="research_target_validation")]
fn delay_effect_update(state:&mut ConnectionStateConnected, now:u64, sample:Option<u64>,
    high:bool, c:DelayEventConfig, srtt:u64) -> bool {
    let effect=c.effect.unwrap();
    let g=&mut state.delay_giveup;
    if let Some(p)=&g.pending_effect {
        let effective=now>p.guard_until_ns && now<=p.deadline_ns && sample.is_some_and(|m|
            m.saturating_sub(state.target_min_rtt_ns) as f64<=(1.-effect.frac)*p.excess_ns as f64);
        if effective || now>p.deadline_ns {
            g.pending_effect=None;
            if effective {
                state.stats.delay_effective+=1;
                g.ineffective=0;
            } else {
                state.stats.delay_ineffective+=1;
                g.ineffective=g.ineffective.saturating_add(1);
                if g.ineffective>=c.giveup && !g.suspended {
                    g.suspended=true;
                    if let Some(h)=c.hold {
                        g.consecutive_suspensions=g.consecutive_suspensions.saturating_add(1);
                        g.hold_until_ns=Some(now.saturating_add(h.duration_ns(g.consecutive_suspensions,srtt)));
                        g.clean_until_ns=None;
                    }
                    state.stats.delay_suspensions+=1;
                }
            }
        }
    }
    // Low windows still rearm suspension subject to HOLD, but an armed low
    // window must not erase an unresolved fractional experiment or its strikes.
    if sample.is_some() && !high && g.suspended {
        if g.hold_until_ns.is_some_and(|deadline|now<deadline) {
            state.stats.delay_hold_blocked_rearms+=1;
        } else {
            state.stats.delay_rearms+=1;
            g.suspended=false; g.ineffective=0; g.hold_until_ns=None;
            if let Some(h)=c.hold { g.clean_until_ns=Some(now.saturating_add(h.clean_ns(srtt))); }
            else { *g=DelayGiveupState::default(); }
        }
    }
    if high && g.suspended { state.stats.delay_events_suppressed+=1; }
    // Do not overwrite q0/deadline with another accepted delay cut.
    g.suspended || g.pending_effect.is_some()
}

fn close_delay_event(state:&mut ConnectionStateConnected, now:u64, c:DelayEventConfig,
    cc:&CongestionPolicy, max_pps:Option<u64>) -> bool {
    let srtt=state.RTT_mean as u64*100_000;
    if c.hold.is_some() {
        let g=&mut state.delay_giveup;
        // Check before a possible new suspension, including on empty send ticks.
        if !g.suspended && g.clean_until_ns.is_some_and(|deadline|now>=deadline) {
            g.consecutive_suspensions=0;
            g.clean_until_ns=None;
        }
    }
    // Preserve the original window/cut path when give-up is disabled. A low
    // closed window must be distinguished from an empty or still-open window.
    let closed_sample=if c.giveup>0 && state.delay_event_window.deadline_ns.is_some_and(|d|now>=d) {
        state.delay_event_window.min_sample_ns
    } else { None };
    let fh_closing=state.fresh_hold.phase==1 && state.delay_event_window.deadline_ns.is_some_and(|d|now>=d);
    let event=state.delay_event_window.close(now,state.target_min_rtt_ns,srtt,c);
    // FRESHHOLD: a real close during HOLD resolves only on a nonempty fresh subset
    // (send > frozen barrier), LOW or HIGH; the resolving window is consumed whole.
    if fh_closing {
        let fresh=state.fresh_hold.min_sample_ns!=u64::MAX;
        state.fresh_hold.min_sample_ns=u64::MAX;
        if fresh {
            let age=if state.is_app_limited { state.app_limit_time_offset } else { now.saturating_sub(state.congestion_event_time_ns) };
            state.fresh_hold=FreshHold { phase:2, release_coord_ns:age as i128, release_wall_ns:now, ..FreshHold::NONE };
            return false;
        }
        // Stale-only/empty closes during HOLD are consumed too: no recut can replace
        // the frozen barrier before a fresh resolution (giveup/effect accounting skipped).
        return false;
    }
    #[cfg(feature="research_target_validation")]
    if c.effect.is_some() && delay_effect_update(state,now,closed_sample,event.is_some(),c,srtt) {
        return false;
    }
    #[cfg(feature="research_target_validation")]
    let effect_enabled=c.effect.is_some();
    #[cfg(not(feature="research_target_validation"))]
    let effect_enabled=false;
    if !effect_enabled && closed_sample.is_some() {
        let g=&mut state.delay_giveup;
        if event.is_none() {
            if let Some(h)=c.hold {
                if g.suspended && g.hold_until_ns.is_some_and(|deadline|now<deadline) {
                    state.stats.delay_hold_blocked_rearms+=1;
                    return false;
                }
                if g.suspended {
                    state.stats.delay_rearms+=1;
                    g.clean_until_ns=Some(now.saturating_add(h.clean_ns(srtt)));
                }
                g.suspended=false; g.pending_event_ns=None; g.ineffective=0;
                g.hold_until_ns=None;
            } else {
                // Original give-up: drain evidence rearms immediately, even in a guard.
                if g.suspended { state.stats.delay_rearms+=1; }
                *g=DelayGiveupState::default();
            }
        } else {
            // Resolve an accepted delay cut ONCE, at the first nonempty window
            // closing strictly after its guard. Rejected cuts never add a strike.
            if g.pending_event_ns.is_some_and(|at|now>at.saturating_add((srtt as f64*cc.event_guard_rtts) as u64)) {
                g.pending_event_ns=None;
                g.ineffective=g.ineffective.saturating_add(1);
                if g.ineffective>=c.giveup && !g.suspended {
                    g.suspended=true;
                    if let Some(h)=c.hold {
                        g.consecutive_suspensions=g.consecutive_suspensions.saturating_add(1);
                        g.hold_until_ns=Some(now.saturating_add(h.duration_ns(g.consecutive_suspensions,srtt)));
                        g.clean_until_ns=None;
                    }
                    state.stats.delay_suspensions+=1;
                }
            }
            if g.suspended {
                state.stats.delay_events_suppressed+=1;
                return false;
            }
        }
    }
    let Some((seq,sent))=event else { return false; };
    state.stats.delay_events_raised+=1;
    // Do not clobber a real pending CE signal. Use its EXACT guard and cut path,
    // including startup exit, local rate ceiling, beta recovery and risk qd_ref.
    let saved=(state.ecn_congestion_received,state.ecn_oldest_seq,state.ecn_oldest_send_time);
    state.ecn_congestion_received=true; state.ecn_oldest_seq=seq; state.ecn_oldest_send_time=sent;
    let accepted=apply_ecn_congestion(state,now,cc,max_pps);
    (state.ecn_congestion_received,state.ecn_oldest_seq,state.ecn_oldest_send_time)=saved;
    if accepted {
        state.stats.delay_events_accepted+=1;
        // FRESHHOLD enter (apply_ecn_congestion already cleared any prior phase).
        state.fresh_hold=FreshHold { phase:1, barrier_ns:now.saturating_add((state.RTT_mean as f64*100_000.0*cc.event_guard_rtts) as u64), ..FreshHold::NONE };
        if let Some(beta)=c.beta {
            state.delay_curve_beta=Some(beta);
            state.stats.delay_cuts_beta_override+=1;
        }
        #[cfg(feature="research_target_validation")]
        if let Some(effect)=c.effect {
            let guard_until_ns=now.saturating_add((srtt as f64*cc.event_guard_rtts) as u64);
            state.delay_giveup.pending_effect=Some(DelayEffectPending {
                excess_ns:closed_sample.unwrap().saturating_sub(state.target_min_rtt_ns),
                guard_until_ns,deadline_ns:guard_until_ns.saturating_add((effect.rtts*srtt as f64).ceil() as u64),
            });
        } else if c.giveup>0 { state.delay_giveup.pending_event_ns=Some(now); }
        #[cfg(not(feature="research_target_validation"))]
        if c.giveup>0 { state.delay_giveup.pending_event_ns=Some(now); }
        push_accepted_cc_event(state,AcceptedCcEvent { kind:CC_EVENT_CE,evidence_seq:seq,evidence_sent_ns:sent,feedback_ns:now });
    }
    accepted
}

fn observe_delay_event(state:&mut ConnectionStateConnected, now:u64, sample:u64, seq:u64, sent:u64,
    config:Option<DelayEventConfig>, cc:&CongestionPolicy, max_pps:Option<u64>) {
    let Some(c)=config else { return; };
    close_delay_event(state,now,c,cc,max_pps);
    let srtt=if state.RTT_sample_cursor==0 {sample} else {state.RTT_mean as u64*100_000};
    state.delay_event_window.observe(now,sample,seq,sent,srtt,c);
    // FRESHHOLD: track the fresh subset's min sample (send strictly > frozen barrier).
    let h=&mut state.fresh_hold;
    if h.phase==1 && sent>h.barrier_ns && sample<h.min_sample_ns { h.min_sample_ns=sample; }
}

// Kept separate so tests exercise the same ECN cut as the send loop.
/// Returns true iff the CE signal was accepted as a congestion cut (CC state changed).
fn apply_ecn_congestion(state: &mut ConnectionStateConnected, now: u64, cc: &CongestionPolicy, max_pps: Option<u64>) -> bool {
    if !take_ecn_signal(state, cc.event_guard_rtts) { return false; }
    let k = cc.recovery_rtts * state.RTT_mean as u64 * 100_000;
    let curve=connection_curve_policy(state,cc);
    let send_dt = state.ecn_oldest_send_time - state.congestion_event_time_ns;
    let send_t_factor = send_dt as f64 / k as f64;
    let ev_sent = state.ecn_oldest_send_time;
    let (_, send_mode) = state_rate_sent(state, ev_sent, send_dt, k, &curve, state.cc_startup_done);
    let discover_dt = if send_mode == 'P' { (k + send_dt) / 2 } else { send_dt };
    let mut discovered = state_rate_sent(state, ev_sent, discover_dt, k, &curve, state.cc_startup_done).0;
    if send_mode == 'I' {
        discovered = connection_rate(send_dt.saturating_sub((state.RTT_mean as f64 * 100_000.0 * cc.startup_backoff_rtts) as u64), state.congestion_event_rate_upps, k, &curve, false).0;
    } else if send_mode == 'G' || send_mode == 'S' {
        let r_pg = (state.congestion_event_rate_upps as f64 * cc.rate_pg) as u64;
        discovered = r_pg + ((discovered.saturating_sub(r_pg)) as f64 * 0.5) as u64;
    }
    state.congestion_event_rate_upps = congestion_discovery_rate(state, discovered, max_pps);
    state.congestion_event_time_ns = now;
    state.app_limit_time_offset = 0;
    state.cc_startup_done = true;

    { state.delay_curve_beta=None; }
    fresh_hold_clear(state);

    crate::target_validation::risk_congestion(&state.target_state,state.congestion_event_rate_upps, if state.RTT_mean==u16::MAX {0}else{state.RTT_mean as u64*100_000}, cc.event_guard_rtts, cc.recovery_rtts, true);
    println!("congestion event ECN CE ...  rate discovered: {} pps  sent:{send_mode}@{send_t_factor:.2}", state.congestion_event_rate_upps as f64 / 1000000.0);
    true
}

/// Records an ACCEPTED cut for the send queues; bounded, overflow counted (measurement-invalid if nonzero).
/// Delivers accepted cuts to the send queues; called before ANY later finalize, reclaim, resume or fill, so the
/// exposure snapshot is the one at acceptance (nothing can be emitted or sealed in between).
fn drain_accepted_cc_events(state: &mut ConnectionStateConnected, buf: &mut SendQueues) {
    if !state.accepted_cc_events.is_empty() {
        for e in std::mem::take(&mut state.accepted_cc_events) { buf.fec_event_repair(&e); }
    }
}

/// Records an accepted cut and applies it to the send queues synchronously (acceptance-time exposure snapshot).
fn accept_cc_event(state: &mut ConnectionStateConnected, buf: &mut SendQueues, e: AcceptedCcEvent) {
    push_accepted_cc_event(state, e);
    drain_accepted_cc_events(state, buf);
}

/// An unknown ORIGINAL send history (0/MAX) is never published as exposure evidence (the CC cut is unaffected).
fn push_accepted_cc_event(state: &mut ConnectionStateConnected, e: AcceptedCcEvent) {
    if e.evidence_sent_ns == 0 || e.evidence_sent_ns == u64::MAX { state.accepted_cc_missing_anchor += 1; return; }
    if state.accepted_cc_events.len() < CC_EVENT_QUEUE_CAP { state.accepted_cc_events.push(e); }
    else { state.accepted_cc_dropped += 1; }
}

/// One covered delivery stream. Retained counts keep their full send-to-ACK
/// coverage; ACK silence and raw receiver batching latency are included.
#[derive(Debug)]
struct DeliveryEvidence {
    start_ns: u64,
    packets: u64,
    latency_ns: u64,
    oldest_send_ns: u64,
    previous_packets: u64,
    previous_coverage_ns: u64,
    ceiling_upps: u64,
}
impl DeliveryEvidence {
    fn new(now: u64, ceiling_upps: u64) -> Self {
        Self { start_ns: now, packets: 0, latency_ns: 0, oldest_send_ns: u64::MAX,
            previous_packets: 0, previous_coverage_ns: 0, ceiling_upps }
    }
    fn acknowledged(&mut self, now: u64, packets: u64, latency_ns: u64, rtt_ns: u64, floor: u64) -> bool {
        if packets == 0 { return false; }
        // A small fixed headroom at the rate floor also allows sparse senders to
        // fill a feedback window. It is available only after positive delivery.
        self.ceiling_upps = self.ceiling_upps.max(floor.saturating_mul(2));
        self.packets = self.packets.saturating_add(packets);
        self.latency_ns = self.latency_ns.max(latency_ns);
        self.oldest_send_ns = self.oldest_send_ns.min(now.saturating_sub(latency_ns));
        let span = now.saturating_sub(self.start_ns);
        let feedback = rtt_ns.saturating_add(crate::ship::ACK.max_delay_us as u64 * 1000).max(self.latency_ns).max(1);
        let coverage = span.max(now.saturating_sub(self.oldest_send_ns));
        // The prior complete count is covered back to start - previous_coverage;
        // the current (possibly partial) count back to min(start, oldest_send).
        // Their union remains covered by this elapsed interval on every ACK.
        let elapsed = span.saturating_add(self.previous_coverage_ns).max(coverage);
        if elapsed >= feedback && (self.previous_packets != 0 || span >= feedback) {
            let delivered = self.packets.saturating_add(self.previous_packets);
            let rate = rate_mul_div(delivered, 1_000_000_000_000_000, elapsed);
            let ceiling = rate.max(floor).saturating_mul(2).min(MAX_CC_RATE_UPPS);
            // Partial evidence can add permission before closure; it need not
            // revoke the earlier complete sample's already-proven permission.
            self.ceiling_upps = if span < feedback { self.ceiling_upps.max(ceiling) } else { ceiling };
        }
        if span < feedback { return false; }
        self.previous_packets = self.packets;
        self.previous_coverage_ns = coverage;
        self.start_ns = now;
        self.packets = 0;
        self.latency_ns = 0;
        self.oldest_send_ns = u64::MAX;
        true
    }
}

/// Positive receipts authorize growth, not a new congestion signal. The fresh
/// horizon ignores isolated ancient receipts; the shadow admits same-epoch
/// receipts with retained valid send timestamps. Deep reordering beyond the
/// ~4.3 s send-history capacity can still hide delivery and pin growth. Each stream
/// covers every counted receipt independently, so their maximum is covered too.
/// Fixed storage, one shared command, no dependency on the curve phase.
#[derive(Debug)]
struct DeliveryGrowth {
    fresh: DeliveryEvidence,
    shadow: DeliveryEvidence,
    last_rate_upps: u64,
    receipt_not_before_ns: u64,
    epoch_ns: u64,
    app_limited_since_ns: u64,
}
impl DeliveryGrowth {
    fn new(now: u64, floor: u64) -> Self {
        Self { fresh: DeliveryEvidence::new(now, floor), shadow: DeliveryEvidence::new(now, floor),
            last_rate_upps: floor, receipt_not_before_ns: now, epoch_ns: now, app_limited_since_ns: now }
    }
    fn resume_after_quiet(&mut self, now: u64, quiet_ns: u64, rtt_ns: u64) {
        let feedback = rtt_ns.saturating_add(crate::ship::ACK.max_delay_us as u64 * 1000);
        if quiet_ns < feedback { return; }
        // Nothing queued is not a feedback gap. Discard stale measurements but
        // preserve each earned ceiling and the shared last command.
        self.fresh = DeliveryEvidence::new(now, self.fresh.ceiling_upps);
        self.shadow = DeliveryEvidence::new(now, self.shadow.ceiling_upps);
        self.receipt_not_before_ns = now;
        self.epoch_ns = now;
    }
    fn receipt_latency(&self, now: u64, sent: u64) -> Option<u64> {
        self.shadow_receipt_latency(now, sent).filter(|_| sent >= self.receipt_not_before_ns)
    }
    fn shadow_receipt_latency(&self, now: u64, sent: u64) -> Option<u64> {
        (sent != 0 && sent != u64::MAX && sent >= self.epoch_ns)
            .then(|| now.saturating_sub(sent))
    }
    fn acknowledged_samples(&mut self, now: u64, fresh: (u64, u64), shadow: (u64, u64), rtt_ns: u64, floor: u64) {
        let start = self.fresh.start_ns;
        if self.fresh.acknowledged(now, fresh.0, fresh.1, rtt_ns, floor) {
            // Admission moves, never the retained evidence's coverage.
            self.receipt_not_before_ns = start;
        }
        self.shadow.acknowledged(now, shadow.0, shadow.1, rtt_ns, floor);
    }
    fn ceiling(&self) -> u64 { self.fresh.ceiling_upps.max(self.shadow.ceiling_upps) }
    fn bound(&self, proposed: u64) -> u64 {
        // ACK starvation or an application pause is not evidence of congestion.
        // Preserve the last command; only the existing loss/ECN curve may cut it.
        proposed.min(self.ceiling().max(self.last_rate_upps))
    }
    fn limit(&mut self, proposed: u64) -> u64 {
        let rate = self.bound(proposed);
        self.last_rate_upps = rate;
        rate
    }
}

/// Returns true iff this loss was accepted as a congestion cut (outside the event guard).
fn apply_loss_congestion(state: &mut ConnectionStateConnected, send_time: u64, current_time_now_ns: u64, cc: &CongestionPolicy, max_pps: Option<u64>) -> bool {
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    // An RTT re-anchor may have moved the origin while a cohort was retiring.
    // Re-check its loss send-time, not just the packet which completed the cohort.
    if send_time <= state.congestion_event_time_ns.saturating_add((rtt_ns as f64 * cc.event_guard_rtts) as u64) { return false; }
    let time_to_bandwidth_recovery = cc.recovery_rtts * rtt_ns;
    let curve=connection_curve_policy(state,cc);
    let send_dt = send_time - state.congestion_event_time_ns;
    let send_t_factor = send_dt as f64 / time_to_bandwidth_recovery as f64;
    let (_, send_mode) = state_rate_sent(state, send_time, send_dt, time_to_bandwidth_recovery, &curve, state.cc_startup_done);
    let now_dt = current_time_now_ns - state.congestion_event_time_ns;
    let now_t_factor = now_dt as f64 / time_to_bandwidth_recovery as f64;
    let (_, now_mode) = state_rate(state, now_dt, time_to_bandwidth_recovery, &curve, state.cc_startup_done);
    // R: use rate at send time.
    // P/G/S: blend 50% toward R/P boundary rate.
    let mut discovered = state_rate_sent(state, send_time, send_dt, time_to_bandwidth_recovery, &curve, state.cc_startup_done).0;
    if send_mode == 'I' {
        discovered = connection_rate(send_dt.saturating_sub((rtt_ns as f64 * cc.startup_backoff_rtts) as u64), state.congestion_event_rate_upps, time_to_bandwidth_recovery, &curve, false).0;
    } else if send_mode != 'R' {
        let boundary = (state.congestion_event_rate_upps as f64 * cc.rate_rp) as u64;
        discovered = (discovered + boundary) / 2;
    }
    state.congestion_event_rate_upps = congestion_discovery_rate(state, discovered, max_pps);
    state.congestion_event_time_ns = current_time_now_ns;
    state.app_limit_time_offset = 0;
    state.loss_count_in_window = 0;
    state.cc_startup_done = true;

    { state.delay_curve_beta=None; }
    fresh_hold_clear(state);

    crate::target_validation::risk_congestion(&state.target_state,state.congestion_event_rate_upps, if state.RTT_mean==u16::MAX {0}else{state.RTT_mean as u64*100_000}, cc.event_guard_rtts, cc.recovery_rtts, false);
    println!("congestion event PACKET DROPPED {} ...  rate discovered: {} pps  now:{now_mode}@{now_t_factor:.2} sent:{send_mode}@{send_t_factor:.2}", state.packets_waiting_ack_tail, state.congestion_event_rate_upps as f64 / 1000000.0);
    true
}

// Early holes and timeout losses share one RTT cohort and send-time eligibility.
// The monotone early scan has already counted any unresolved hole below its
// watermark; a later timeout still finalizes loss, but cannot count it twice.
fn count_congestion_signal(state: &mut ConnectionStateConnected, seq: u64, sent: u64, now: u64, cc: &CongestionPolicy) -> bool {
    if seq < state.ack_hole.confirmed_before { return false; }
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    if now.saturating_sub(state.loss_window_start_ns) > rtt_ns {
        state.loss_window_start_ns = now;
        state.loss_count_in_window = 0;
    }
    let eligible = seq >= state.outage.ignore_loss_before_seq
        && sent > state.congestion_event_time_ns.saturating_add((rtt_ns as f64 * cc.event_guard_rtts) as u64);
    count_congestion_loss(&mut state.loss_count_in_window, eligible, cc.loss_threshold)
}

fn count_congestion_loss(count: &mut u64, eligible: bool, threshold: u64) -> bool {
    if !eligible { return false; }
    *count = count.saturating_add(1);
    *count >= threshold
}

#[derive(Debug, Default)]
struct LossEpisodeBucket { start_ns: u64, packets: u64, lost: u64 }
#[derive(Debug, Default)]
struct LossEpisodes { buckets: [LossEpisodeBucket; 4], initialized: bool }
impl LossEpisodes {
    // Four staggered tumbling windows approximate a sliding RTT window without
    // retaining packet records. Storage is 104 bytes, independent of bandwidth.
    fn on_packet(&mut self, sent_ns: u64, lost: bool, rtt_ns: u64, stats: &mut ConnectionStats) {
        let rtt_ns = rtt_ns.max(100_000);
        if !self.initialized {
            for (i, b) in self.buckets.iter_mut().enumerate() { b.start_ns = sent_ns + i as u64 * rtt_ns / 4; }
            self.initialized = true;
        }
        for b in &mut self.buckets {
            if sent_ns < b.start_ns { continue; }
            if sent_ns - b.start_ns >= rtt_ns {
                if b.packets >= 8 {
                    let ppm = (b.lost * 1_000_000 / b.packets) as u32;
                    if ppm > stats.max_rtt_loss_ppm {
                        stats.max_rtt_loss_ppm = ppm;
                        stats.max_rtt_loss_window_packets = b.packets;
                    }
                }
                b.start_ns += ((sent_ns - b.start_ns) / rtt_ns) * rtt_ns;
                b.packets = 0;
                b.lost = 0;
            }
            b.packets += 1;
            b.lost += u64::from(lost);
        }
    }
}
