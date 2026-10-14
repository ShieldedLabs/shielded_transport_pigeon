#![allow(unsafe_code)]
#![allow(unused_variables, unused_mut, unused_imports, unused_macros, unused_assignments)]
use std::collections::{HashMap, VecDeque};
use rand::SeedableRng;
use static_assertions::const_assert;


#[test]
pub fn ack_test() {
    use rand::Rng;

    println!("Begin the ack test!");

    let kp1 = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
    let kp1_pub = kp1.public.clone();
    let kp2 = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();

    socket_setup();
    monotonic_clock_setup();

    let network_thread_handle1 = new_network_thread(vec![kp1.clone()], 58493, None, (1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024));
    let network_thread_handle2 = new_network_thread(vec![kp2.clone()], 23843, None, (1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024));

    let initiate_connections = vec![ STPAddress { ip: Ipv6Addr::LOCALHOST, port: 58493, magic1: CONNECT_MAGIC1_PLAIN_TEXT, key: kp1_pub, } ];
    let ret = service_connections(&network_thread_handle2, NetworkThreadPush { initiate_connections, send_unreliable: vec![], ..Default::default() }).unwrap_or_default();
    let mut wanted_connections = ret.current_connections;

    // Build 50 messages with random sizes between 100 bytes and 4 MiB.
    // Layout: [id: u32 LE][len: u32 LE][blake3 hash: 32 bytes][random payload]
    const NUM_MESSAGES: u32 = 50;
    const HEADER_SIZE: usize = 4 + 4 + 32; // id + len + hash
    let mut rng = rand::rng();
    let mut messages: Vec<Vec<u8>> = Vec::new();

    for id in 0..NUM_MESSAGES {
        let payload_size: usize = rng.random_range(100..=(4 * 1024 * 1024));
        let total_size = HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total_size];

        // Fill payload with random data
        rng.fill(&mut buf[HEADER_SIZE..]);

        // Write header
        let hash = blake3::hash(&buf[HEADER_SIZE..]);
        buf[0..4].copy_from_slice(&id.to_le_bytes());
        buf[4..8].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[8..40].copy_from_slice(hash.as_bytes());

        println!("Message {id}: {total_size} bytes");
        messages.push(buf);
    }

    // Send all 50 messages once we have a connection
    let mut sent = false;

    loop {
        let mut send_unreliable = Vec::new();
        if !sent && !wanted_connections.is_empty() {
            for msg in &messages {
                send_unreliable.push((wanted_connections[0].0.to_connection_key(), 0, Dscp::BestEffort, msg.clone()));
            }
            sent = true;
            println!("Sent {NUM_MESSAGES} messages, waiting 10s for receive...");
        } else if !sent {
            let ret = service_connections(&network_thread_handle2, NetworkThreadPush { wanted_connections, ..Default::default() }).unwrap_or_default();
            wanted_connections = ret.current_connections;
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        } else {
            break;
        }
        let ret = service_connections(&network_thread_handle2, NetworkThreadPush { wanted_connections, send_unreliable, ..Default::default() }).unwrap_or_default();
        wanted_connections = ret.current_connections;
    }

    // Receive on the other side for 10 seconds
    let mut received_ids: HashMap<u32, u32> = HashMap::new(); // id -> count
    let mut receive_order: Vec<u32> = Vec::new();
    let mut corrupted: u32 = 0;
    let mut malformed: u32 = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

    while std::time::Instant::now() < deadline {
        let ret = service_connections(&network_thread_handle1, NetworkThreadPush::default()).unwrap_or_default();
        for (_conn_key, data) in &ret.received_unreliable_messages {
            if data.len() < HEADER_SIZE {
                malformed += 1;
                continue;
            }
            let id = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let declared_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
            let declared_hash: &[u8; 32] = data[8..40].try_into().unwrap();

            if declared_len != data.len() {
                malformed += 1;
                continue;
            }

            let actual_hash = blake3::hash(&data[HEADER_SIZE..]);
            if actual_hash.as_bytes() != declared_hash {
                corrupted += 1;
                continue;
            }

            receive_order.push(id);
            *received_ids.entry(id).or_insert(0) += 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let unique_received = received_ids.len() as u32;
    let duplicates: u32 = received_ids.values().filter(|&&c| c > 1).map(|c| c - 1).sum();
    let missing = NUM_MESSAGES - unique_received;

    println!("\n=== Results ===");
    println!("Sent:       {NUM_MESSAGES}");
    println!("Received:   {unique_received}");
    println!("Missing:    {missing}");
    println!("Duplicates: {duplicates}");
    println!("Corrupted:  {corrupted}");
    println!("Malformed:  {malformed}");
    println!("Order:      {:?}", receive_order);
}

pub fn do_the_test_program3(port: u16, my_keypair: IdentityKeyPair, beam_to: Option<STPAddress>, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32)) {
    socket_setup();
    monotonic_clock_setup();

    let network_thread_handle2 = new_network_thread(vec![my_keypair], port, max_pps, send_buffer_params);
    
    if let Some(other) = beam_to {
        let initiate_connections = vec![other];

        let ret = service_connections(&network_thread_handle2, NetworkThreadPush { initiate_connections, ..Default::default() }).unwrap_or_default();
        let mut wanted_connections = ret.current_connections;
    
        let mut i = 0;
    
        loop {
            let mut send_unreliable = Vec::new();
            if wanted_connections.len() > 0 {
                for _ in 0..50000 {
                    send_unreliable.push((wanted_connections[0].0.to_connection_key(), 0, Dscp::BestEffort, Vec::from(b"Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...")));
                }
                // the sends will be truncated anyway
            }
            let ret = service_connections(&network_thread_handle2, NetworkThreadPush { wanted_connections, send_unreliable, ..Default::default() }).unwrap_or_default();
            wanted_connections = ret.current_connections;
            std::thread::sleep(std::time::Duration::from_millis(3000));
        }
    }
    else {
        let mut wanted_connections = Vec::new();
        loop {
            let ret = service_connections(&network_thread_handle2, NetworkThreadPush { wanted_connections, ..Default::default() }).unwrap_or_default();
            wanted_connections = ret.current_connections;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

// LSB of this 48 bit value must be 1 for this to be recognized as an incoming connect handshake.
pub const CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s: u64 = 0x7193_c304_f8d5;
pub const CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b: u64 = 0xbe53_b364_1ce1;
pub const CONNECT_MAGIC1_PLAIN_TEXT: u64 = 0x5bb2_2856_ae53;
pub fn crypto_string_from_connect_magic1(magic: u64) -> Option<&'static str> {
    match magic {
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s => Some("Noise_IK_25519_ChaChaPoly_BLAKE2s"),
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b => Some("Noise_IK_25519_ChaChaPoly_BLAKE2b"),
        CONNECT_MAGIC1_PLAIN_TEXT => Some("plaintext"),
        _ => None,
    }
}

pub const MAGIC2_BLOCK_SIZE: usize = 1 + 32 * 8; // 257 bytes: 1 byte count + 32 × 8-byte magic2 values. Always send full block for constant-size.
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
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s => Some(6+16),
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b => Some(6+16),
        CONNECT_MAGIC1_PLAIN_TEXT => Some(6+0),
        _ => None,
    }
}

pub const STP_FRAGMENT_HEADER_SIZE: usize = 8;
const STP_WHOLE_HEADER_SIZE: usize = 4;

/// Low bits 11 denote a whole plain message (fin, offset=0); 01 denotes FEC,
/// 00/10 denote ordinary plain fragments. Length is 14 bits, package id 16 bits.
/// 0xffffffff is reserved for padding and cannot collide with a TU-sized message.
pub(crate) fn read_fragment_header(payload: &[u8]) -> Option<(u64, usize)> {
    let word = u32::from_le_bytes(payload.get(..4)?.try_into().ok()?);
    if word == u32::MAX { return None; }
    if word & 3 == 3 { return Some(((word & !1) as u64, STP_WHOLE_HEADER_SIZE)); }
    Some((u64::from_le_bytes(payload.get(..8)?.try_into().ok()?), STP_FRAGMENT_HEADER_SIZE))
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
        let mut ret = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s)?;
        ret.magic1 = CONNECT_MAGIC1_PLAIN_TEXT;
        return Some(ret);
    }
    if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
        let kp = snow::Builder::new(crypto_string.parse().ok()?).generate_keypair().ok()?;
        Some(IdentityKeyPair { magic1, private: kp.private, public: kp.public })
    } else { None }
}

pub fn new_keypair_from_connect_magic1_with_seed(magic1: u64, seed: [u8; 32]) -> Option<IdentityKeyPair> {
    if magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
        let mut ret = new_keypair_from_connect_magic1_with_seed(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, seed)?;
        ret.magic1 = CONNECT_MAGIC1_PLAIN_TEXT;
        return Some(ret);
    }
    if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let kp = snow::Builder::with_resolver(crypto_string.parse().ok()?, Box::new(SnowRngResolver { rng: RustIsBadRngWrapper(rng) })).generate_keypair().ok()?;
        Some(IdentityKeyPair { magic1, private: kp.private, public: kp.public })
    } else { None }
}

pub fn b64(s: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
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
        use base64::Engine;
        let     addr           = addr.strip_prefix('[')?;
        let     (ip_str, rest) = addr.split_once("]:")?;
        let     ip: Ipv6Addr   = ip_str.parse().ok()?;
        let mut parts          = rest.splitn(3, ':');
        let     port: u16      = parts.next()?.parse().ok()?;
        let     b64_magic1     = parts.next()?; if b64_magic1.contains('=') { return None; }
        let     b64_key        = parts.next()?; if b64_key   .contains('=') { return None; }
        let     magic1_bytes   = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64_magic1).ok()?; if magic1_bytes.len() != 6 { return None; }
        let     key            = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64_key).ok()?;    if key.len() < MIN_PUBLIC_KEY_SIZE || key.len() > MAX_PUBLIC_KEY_SIZE { return None; }
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

// Lease receiver ring positions while a package can still send or rescue. IDs remain
// sender-only; no receiver change or per-queue wire namespace is needed.
#[derive(Debug)]
struct PackageAllocator {
    next: std::sync::atomic::AtomicU16,
    live: std::sync::Mutex<[u16; 1024]>,
}
impl PackageAllocator {
    fn new() -> Self { Self { next: std::sync::atomic::AtomicU16::new(0), live: std::sync::Mutex::new([0; 1024]) } }
    fn load(&self, order: std::sync::atomic::Ordering) -> u16 { self.next.load(order) }
    fn store(&self, id: u16, order: std::sync::atomic::Ordering) { self.next.store(id, order); }
    fn allocate(self: &std::sync::Arc<Self>) -> Option<std::sync::Arc<PackageLease>> {
        let mut live = self.live.lock().unwrap();
        let next = self.next.load(std::sync::atomic::Ordering::Relaxed);
        for offset in 0..1024u16 {
            let id = next.wrapping_add(offset);
            let index = id as usize % 1024;
            if live[index] == 0 {
                live[index] = 1;
                // Failed probes must not burn an entire ID generation. Ring pressure
                // can retry thousands of times within one RTT; advancing on failure
                // makes new IDs look older under the receiver's 16-bit half-range rule.
                self.next.store(id.wrapping_add(1), std::sync::atomic::Ordering::Relaxed);
                return Some(std::sync::Arc::new(PackageLease { allocator: self.clone(), id }));
            }
        }
        None
    }
}
#[derive(Debug)]
struct PackageLease { allocator: std::sync::Arc<PackageAllocator>, id: u16 }
impl Drop for PackageLease {
    fn drop(&mut self) { self.allocator.live.lock().unwrap()[self.id as usize % 1024] -= 1; }
}

// Strict fair reservations. Leases survive moves into active rescue/suspended slots;
// no magazine borrows another's bytes or slots, so the connection total stays <=64 MiB/4096.
#[derive(Debug)]
struct RetentionQuota { byte_limit: usize, slot_limit: usize, used: std::sync::Mutex<(usize, usize)> }
impl RetentionQuota {
    fn new(count: usize) -> Self { Self { byte_limit: FEC_RETAIN_SOURCE_BYTES / count, slot_limit: FEC_RETAIN_SLOTS / count, used: std::sync::Mutex::new((0, 0)) } }
    fn acquire(self: &std::sync::Arc<Self>, bytes: usize) -> Option<std::sync::Arc<RetentionLease>> {
        let mut used = self.used.lock().unwrap();
        if bytes > self.byte_limit.saturating_sub(used.0) || used.1 >= self.slot_limit { return None; }
        used.0 += bytes; used.1 += 1;
        Some(std::sync::Arc::new(RetentionLease { quota: self.clone(), bytes }))
    }
}
#[derive(Debug)]
struct RetentionLease { quota: std::sync::Arc<RetentionQuota>, bytes: usize }
impl Drop for RetentionLease {
    fn drop(&mut self) { let mut used = self.quota.used.lock().unwrap(); used.0 -= self.bytes; used.1 -= 1; }
}

#[derive(Debug)]
pub struct UnreliableSendBuffer {
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
    pub partial_send_slot: Option<(Vec<u8>, u32)>,
    pub send_package_id: u16,
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
    /// Lazy fixed 2 MiB nonce ring: package id (16), symbol count (16), first ordinal (32).
    /// One ring per connection, reused across messages; ACK/probe/keepalive slots are empty.
    fec_packet_tags: Option<Box<[u64]>>,
    // Encoders awaiting packet outcome feedback, outside the application send queue.
    fec_retained: HashMap<u16, RetainedFecSlot>,
    retention_quota: std::sync::Arc<RetentionQuota>,
    retained_bytes: usize,
    rescue_ready: VecDeque<u16>,
    rescue_ready_count: usize,
    retained_next_prune_ns: u64,
    fec_extra_packet_tags: HashMap<u64, Vec<u64>>,
    fec_rescue_package: Option<u16>,
    fec_suspended: Option<FecSendSlot>,
    fec_now_ns: u64,
    fec_rtt_ns: u64,
    /// Cumulative source/repair progress snapshots, when recording is enabled (Some).
    pub fec_record: Option<Vec<crate::fec_adapt::FecMessageInfo>>,
}

/// Sender state of one FEC-coded message: blocks 0..k-1 are slices of the message itself and
/// need no encoder; blocks k..n-1 are repair blocks from a Wirehair encoder, which is built on
/// a helper thread while the source blocks go out (creating one costs ~4 us per block, 155 ms
/// for a 48 MB message, too long to stall the network thread).
pub struct FecSendSlot {
    segment: Option<FecSegment>,
    root_lease: Option<std::sync::Arc<PackageLease>>,
    plan_ks: Option<std::sync::Arc<std::sync::Mutex<Vec<u64>>>>,
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
}

// Fixed per-connection retained-source budget and slot bound. Codec arenas add their
// implementation overhead; giant messages exceeding the budget keep the original policy.
const FEC_RETAIN_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const FEC_RETAIN_SLOTS: usize = 4096;
#[derive(Debug)]
struct RetainedFecSlot { slot: FecSendSlot, package: u16, expires_ns: u64 }

impl FecSendSlot {
    fn rescue_plan(&mut self) {
        if self.finalized_symbols < self.next_id { return; }
        if self.k == 1 { // a whole raw single-packet message: its K=1 repair is a copy
            self.n = self.next_id.saturating_add(u32::from(self.next_id == self.lost));
            return;
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
        self.n = self.n.max(self.next_id.saturating_add(deficit * groups));
    }
    fn progress_info(&self) -> crate::fec_adapt::FecMessageInfo {
        let mut tag = [0u8; 8];
        let l = self.message.len().min(8);
        tag[..l].copy_from_slice(&self.message[..l]);
        crate::fec_adapt::FecMessageInfo { tag: u64::from_le_bytes(tag), message_len: self.message.len(),
            k: self.k, n_planned: self.n_planned, n_sent: self.next_id,
            loss_estimate: self.loss_estimate, lost_during_send: self.lost }
    }

    // Retainable messages get a feedback fallback and need only learned risk up front.
    // Oversized messages cannot be rescued, so keep their original blind floor.
    fn plan_context(&self) -> (u64, usize, bool) {
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let total = self.segment.map_or(self.message.len(), |s| s.total as usize);
        let groups = self.segment.map_or(layout.groups, |s| (s.total as usize).div_ceil(FEC_SEGMENT_BYTES));
        (segment_source_horizon(total, self.block_bytes, self.plan_ks.as_ref()), groups, self.message.len() > self.retain_limit)
    }

    fn refresh_plan(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {
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
    Pending(std::sync::mpsc::Receiver<Option<crate::fec::MessageEncoder>>),
    Ready(crate::fec::MessageEncoder),
    Failed,
}

impl std::fmt::Debug for FecSendSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FecSendSlot {{ len: {}, block_bytes: {}, k: {}, n: {}, next_id: {} }}", self.message.len(), self.block_bytes, self.k, self.n, self.next_id)
    }
}

// Started segments keep their real K, including after TU growth or restart.
// Future widths are unknowable: estimate those ranges at the current width,
// replacing each estimate when it starts. Shared context also updates retained tails.
fn segment_source_horizon(total: usize, block_bytes: usize,
    plan_ks: Option<&std::sync::Arc<std::sync::Mutex<Vec<u64>>>>) -> u64 {
    let Some(plan_ks) = plan_ks else { return total.div_ceil(block_bytes) as u64; };
    let ks = plan_ks.lock().unwrap();
    let group_len = total.div_ceil(ks.len());
    ks.iter().enumerate().map(|(group, &k)| if k != 0 { k }
        else { (total - group * group_len).min(group_len).div_ceil(block_bytes) as u64 }).sum()
}

/// Header of an FEC fragment: two little-endian u64 words.
///   word0: bit 0 = 1 (extended fragment; plain fragments have 0 here), bit 1 = 0,
///          bits 2..18 package id, bits 18..32 block data length, bits 32..64 block id
///   word1: bits 0..32 message length, bits 32..48 block bytes, bits 48..56 kind (1 = FEC), rest 0
pub const STP_FEC_FRAGMENT_HEADER_SIZE: usize = 16;
pub const STP_EXT_KIND_FEC: u64 = 1;
const STP_EXT_KIND_SEGMENT_FEC: u64 = 3;
const STP_SEGMENT_FEC_HEADER_SIZE: usize = 26;
const FEC_SEGMENT_BYTES: usize = 2 << 20;

/// Independently coded, fixed byte-range group of one application message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecSegment { root: u16, total: u32, offset: u32 }

#[derive(Debug)]
struct SegmentedSend {
    plan_ks: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
    message: std::sync::Arc<Vec<u8>>,
    offset: usize,
    root: u16,
    root_lease: Option<std::sync::Arc<PackageLease>>,
}

impl FecSegment {
    fn valid(self, len: usize) -> bool {
        let total = self.total as usize;
        let offset = self.offset as usize;
        total > FEC_SEGMENT_BYTES && total <= MAX_JUMBOGRAM_LEN &&
            offset < total && {
                let group_len = total.div_ceil(total.div_ceil(FEC_SEGMENT_BYTES));
                offset % group_len == 0 && len == (total - offset).min(group_len)
            }
    }
}
/// Balanced groups of <=32000 blocks, inferred from length/block size; same 16-byte header.
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
    Plain { is_fin: bool, package_id: u16, data: &'a [u8], offset: u32 },
    Fec { segment: Option<FecSegment>, package_id: u16, message_len: u32, block_bytes: u16, block_id: u32, data: &'a [u8] },
}

impl UnreliableSendBuffer {
    pub fn new(target_queue_size_us: u32, min_queue_size_bytes: u32, max_queue_size_bytes: u32) -> Self {
        Self {
            target_queue_size_us,
            min_queue_size_bytes,
            max_queue_size_bytes,
            queue_bytes_filled: 0,
            message_queue: VecDeque::new(),
            current_dscp: Dscp::BestEffort,
            packet_dscp: None,
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
            rescue_ready: VecDeque::new(),
            rescue_ready_count: 0,
            retained_next_prune_ns: 0,
            fec_extra_packet_tags: HashMap::new(),
            fec_rescue_package: None,
            fec_suspended: None,
            fec_now_ns: 0,
            fec_rtt_ns: 0,
            fec_record: None,
        }
    }

    fn encoder_ready(f: &mut FecSendSlot) -> bool {
        if f.next_id < f.k || f.next_id >= f.n { return true; }
        if let FecEncoderState::Pending(rx) = &f.encoder {
            f.encoder = match rx.try_recv() {
                Ok(Some(e)) => FecEncoderState::Ready(e),
                Ok(None) | Err(std::sync::mpsc::TryRecvError::Disconnected) => FecEncoderState::Failed,
                Err(std::sync::mpsc::TryRecvError::Empty) => return false,
            };
        }
        true
    }

    fn can_emit(&mut self) -> bool {
        self.reclaim_finished_partial();
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
        if let Some(tags) = &mut self.fec_packet_tags { tags[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize] = 0; }
        self.fec_extra_packet_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
    }

    fn tag_symbol(&mut self, package: u16, ordinal: u32) {
        let index = self.next_packet_seq % PACKETS_WAITING_ACK_CAPACITY;
        let tags = self.fec_packet_tags.get_or_insert_with(|| vec![0u64; PACKETS_WAITING_ACK_CAPACITY as usize].into_boxed_slice());
        let tag = &mut tags[index as usize];
        let count = ((*tag >> 32) & 0xffff) as u32;
        if count > 0 && *tag >> 48 == package as u64 && (*tag as u32).saturating_add(count) == ordinal {
            *tag += 1u64 << 32;
        } else {
            if count > 0 { self.fec_extra_packet_tags.entry(index).or_default().push(*tag); }
            *tag = ((package as u64) << 48) | (1u64 << 32) | ordinal as u64;
        }
    }

    #[cfg(test)]
    pub fn fec_on_packet_lost(&mut self, seq: u64) { self.fec_on_packet_finalized(seq, true); }

    fn fec_on_packet_finalized(&mut self, seq: u64, lost: bool) {
        if seq > self.next_packet_seq || self.next_packet_seq - seq >= PACKETS_WAITING_ACK_CAPACITY { return; }
        let Some(tags) = &mut self.fec_packet_tags else { return };
        let index = seq % PACKETS_WAITING_ACK_CAPACITY;
        let tag = std::mem::take(&mut tags[index as usize]);
        let extra = self.fec_extra_packet_tags.remove(&index);
        self.fec_finalize_tags(seq, lost, extra.as_deref().unwrap_or(&[]));
        if tag != 0 { self.fec_finalize_tags(seq, lost, &[tag]); }
    }

    fn fec_finalize_tags(&mut self, seq: u64, lost: bool, tags: &[u64]) {
        for &tag in tags {
            let count = ((tag >> 32) & 0xffff) as u32;
            if count == 0 { continue; }
            let package = (tag >> 48) as u16;
            let active = self.fec_send_slot.is_some() && package == self.fec_rescue_package.unwrap_or(self.send_package_id);
            let suspended = self.fec_suspended.is_some() && package == self.send_package_id;
            let retained = self.fec_retained.contains_key(&package);
            let was_ready = self.fec_retained.get(&package).is_some_and(|r| r.slot.next_id > 0 && r.slot.next_id < r.slot.n);
            let f = if active { self.fec_send_slot.as_mut() }
                else if suspended { self.fec_suspended.as_mut() }
                else { self.fec_retained.get_mut(&package).map(|r| &mut r.slot) };
            let Some(f) = f else { continue };
            let first = tag as u32;
            if seq < f.first_seq || first.saturating_add(count) > f.next_id { continue; }
            f.finalized_symbols = f.finalized_symbols.saturating_add(count);
            if lost {
                f.lost = f.lost.saturating_add(count);
                if f.k == 1 { f.group_lost[0] += count; }
                else {
                    let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
                    for ordinal in first..first + count {
                        let group = layout.local_id(layout.wire_id(ordinal)).0;
                        f.group_lost[group] = f.group_lost[group].saturating_add(1);
                    }
                }
                if suspended || active && self.fec_rescue_package.is_none() {
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

    fn remove_retained(&mut self, package: u16) -> Option<RetainedFecSlot> {
        let r = self.fec_retained.remove(&package)?;
        self.retained_bytes -= r.slot.message.len();
        if r.slot.next_id > 0 && r.slot.next_id < r.slot.n { self.rescue_ready_count -= 1; }
        Some(r)
    }
    fn pop_oldest_retained(&mut self) -> Option<RetainedFecSlot> {
        let package = *self.fec_retained.iter().min_by_key(|(_, r)| r.expires_ns)?.0;
        self.remove_retained(package)
    }
    fn ready_rescue_package(&mut self) -> Option<u16> {
        while let Some(&package) = self.rescue_ready.front() {
            if self.fec_retained.get(&package).is_some_and(|r| r.slot.next_id > 0 && r.slot.next_id < r.slot.n) { return Some(package); }
            self.rescue_ready.pop_front();
        }
        None
    }
    fn fec_prune_retained(&mut self) {
        if self.fec_now_ns < self.retained_next_prune_ns { return; }
        self.retained_next_prune_ns = self.fec_now_ns.saturating_add(10_000_000);
        let expired: Vec<u16> = self.fec_retained.iter().filter(|(_, r)| r.expires_ns < self.fec_now_ns).map(|(&p, _)| p).collect();
        for package in expired { self.remove_retained(package); }
    }

    fn retain_fec(&mut self, mut slot: FecSendSlot, package: u16) {
        if slot.message.len() > self.retention_quota.byte_limit || matches!(slot.encoder, FecEncoderState::Failed) && slot.k != 1 { return; }
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
        let expires_ns = self.fec_now_ns.saturating_add(hold_ns);
        self.retained_bytes += slot.message.len();
        if slot.next_id > 0 && slot.next_id < slot.n { self.rescue_ready.push_back(package); self.rescue_ready_count += 1; }
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
    fn reclaim_finished_partial(&mut self) {
        if let Some((msg, start_byte)) = &self.partial_send_slot {
            if *start_byte as usize >= msg.len() {
                let msg_len = msg.len();
                self.queue_bytes_filled -= msg_len;
                self.partial_send_slot = None;
                self.package_lease = None;
                self.send_package_id = self.send_package_id.wrapping_add(1);
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
                    self.package_lease = None;
                    self.send_package_id = self.send_package_id.wrapping_add(1);
                }
                finished.rescue_plan();
                // Giant codec arenas can take seconds to free under allocator contention.
                if message_len > FEC_RETAIN_SOURCE_BYTES {
                    let _ = std::thread::Builder::new().name("stp-fec-release".into()).spawn(move || drop(finished));
                } else { self.retain_fec(finished, package); }
                if rescue.is_some() { self.resume_suspended(); }
            }
        }
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

    fn start_fec(&mut self, message: std::sync::Arc<Vec<u8>>, block_bytes: usize) {
        self.start_fec_group(message, block_bytes, None, None, None);
    }

    fn start_fec_group(&mut self, message: std::sync::Arc<Vec<u8>>, block_bytes: usize,
        segment: Option<FecSegment>, root_lease: Option<std::sync::Arc<PackageLease>>,
        plan_ks: Option<std::sync::Arc<std::sync::Mutex<Vec<u64>>>>) {
        let layout = crate::fec::MessageLayout::new(message.len(), block_bytes).unwrap();
        let k = layout.k as u32;
        let a = self.fec_adaptive.as_ref().expect("adaptive FEC initialized before coding");
        let total = segment.map_or(message.len(), |s| s.total as usize);
        if let (Some(segment), Some(ks)) = (segment, &plan_ks) {
            let group_len = total.div_ceil(total.div_ceil(FEC_SEGMENT_BYTES));
            ks.lock().unwrap()[segment.offset as usize / group_len] = k as u64;
        }
        let whole_k = segment_source_horizon(total, block_bytes, plan_ks.as_ref());
        let target_groups = segment.map_or(layout.groups, |s| (s.total as usize).div_ceil(FEC_SEGMENT_BYTES));
        let repairs = (0..layout.groups).map(|g| a.repair_blocks_for_group_at_tail(layout.group(g).1 as u64,
            whole_k, target_groups, message.len() > self.retention_quota.byte_limit)).max().unwrap_or(0);
        let (n, loss_estimate) = (k + repairs as u32 * layout.groups as u32, a.p);
        let n = layout.round_plan(n);
        let encoder = if k as usize <= FEC_INLINE_MAX_BLOCKS {
            match crate::fec::encode_message(message.clone(), block_bytes) { Some(e) => FecEncoderState::Ready(e), None => FecEncoderState::Failed }
        } else {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let m = message.clone();
            match std::thread::Builder::new().name("stp-fec-encode".into()).spawn(move || { let _ = tx.send(crate::fec::encode_message(m, block_bytes)); }) {
                Ok(_) => FecEncoderState::Pending(rx),
                Err(_) => match crate::fec::encode_message(message.clone(), block_bytes) { Some(e) => FecEncoderState::Ready(e), None => FecEncoderState::Failed },
            }
        };
        self.fec_packet_tags.get_or_insert_with(|| vec![0u64; PACKETS_WAITING_ACK_CAPACITY as usize].into_boxed_slice());
        self.fec_send_slot = Some(FecSendSlot { segment, root_lease, plan_ks, retention_lease: None, retain_limit: self.retention_quota.byte_limit, package_lease: self.package_lease.clone(), dscp: self.current_dscp, finalized_symbols: 0, send_started_ns: self.fec_now_ns, original_send_duration_ns: None, group_lost: vec![0; layout.groups], message, block_bytes, k, n, next_id: 0, encoder, block_buf: vec![0u8; block_bytes], first_seq: self.next_packet_seq, lost: 0, n_planned: n, loss_estimate });
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
        if self.fec_adaptive.is_some() && msg.len() > FEC_SEGMENT_BYTES {
            self.segmented_send = Some(SegmentedSend { plan_ks: std::sync::Arc::new(std::sync::Mutex::new(vec![0; msg.len().div_ceil(FEC_SEGMENT_BYTES)])), message: std::sync::Arc::new(msg), offset: 0,
                root: self.send_package_id, root_lease: self.package_lease.take() });
            return self.start_segment(payload_len);
        }
        match self.fec_block_bytes(msg.len(), payload_len) {
            Some(block_bytes) => self.start_fec(std::sync::Arc::new(msg), block_bytes),
            None => {
                if self.fec_adaptive.is_some() && msg.len() <= payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE) {
                    let slot = FecSendSlot { segment: None, root_lease: None, plan_ks: None, retention_lease: None, retain_limit: self.retention_quota.byte_limit, package_lease: self.package_lease.clone(), dscp: self.current_dscp, message: std::sync::Arc::new(msg.clone()), block_bytes: msg.len(), k: 1, n: 1, next_id: 0,
                        encoder: FecEncoderState::Failed, block_buf: Vec::new(), first_seq: self.next_packet_seq,
                        lost: 0, group_lost: vec![0], n_planned: 1, loss_estimate: 0.0, finalized_symbols: 0, send_started_ns: self.fec_now_ns, original_send_duration_ns: Some(0) };
                    self.retain_fec(slot, self.send_package_id);
                }
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
        // Balanced fixed byte ranges make the last group at least ~1 MiB, too;
        // their boundaries do not depend on TU and are validated by the receiver.
        let group_len = source.message.len().div_ceil(source.message.len().div_ceil(FEC_SEGMENT_BYTES));
        let end = (start + group_len).min(source.message.len());
        let lease = match self.package_allocator.clone() {
            Some(ids) => { let Some(lease) = ids.allocate() else { return false; }; Some(lease) },
            None => None,
        };
        self.send_package_id = lease.as_ref().map_or(self.send_package_id.wrapping_add(1), |l| l.id);
        self.package_lease = lease;
        let segment = FecSegment { root: source.root, total: source.message.len() as u32, offset: start as u32 };
        let root_lease = source.root_lease.clone();
        let plan_ks = source.plan_ks.clone();
        let message = std::sync::Arc::new(source.message[start..end].to_vec());
        self.segmented_send.as_mut().unwrap().offset = end;
        if end == segment.total as usize { self.segmented_send = None; }
        self.start_fec_group(message, block_bytes, Some(segment), root_lease, Some(plan_ks));
        true
    }

    fn resume_suspended(&mut self) {
        self.fec_send_slot = self.fec_suspended.take();
        if let Some(f) = &mut self.fec_send_slot { f.retention_lease = None; }
    }

    /// Next fragment for a packet with `payload_len` bytes of payload, of which `space` are still
    /// free. None: nothing to send, or the next FEC block does not fit in what is left of this
    /// packet (or its repair encoder is still being built); send the packet as it is.
    pub fn next_fragment(&mut self, payload_len: usize, space: usize) -> Option<UnreliableFragment<'_>> {
        self.reclaim_finished_partial();
        self.fec_prune_retained();
        let rescue = if self.partial_send_slot.is_none() && self.fec_rescue_package.is_none() {
            self.ready_rescue_package()
        } else { None };
        let rescue = rescue.filter(|_| {
            if let Some(original) = &mut self.fec_send_slot {
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
                self.fec_send_slot = Some(r.slot);
            }
        }
        if self.partial_send_slot.is_none() && self.fec_send_slot.is_none() {
            if self.segmented_send.is_some() {
                if !self.start_segment(payload_len) { return None; }
            } else {
                let (dscp, front_msg) = self.message_queue.pop_front()?;
                self.current_dscp = dscp;
                if !self.start_message(front_msg, payload_len) { return None; }
            }
        }
        if self.fec_send_slot.is_some() {
            if self.fec_send_slot.as_ref().unwrap().k == 1 {
                let f = self.fec_send_slot.as_ref().unwrap();
                if f.message.len() + STP_WHOLE_HEADER_SIZE > space {
                    if space < payload_len { return None; }
                    // A TU shrink invalidated the whole-packet K=1 copy. Abandon this
                    // bounded rescue rather than blocking the suspended original forever.
                    self.resume_suspended();
                    self.fec_rescue_package = None;
                    return self.next_fragment(payload_len, space);
                }
                let package = self.fec_rescue_package.unwrap();
                self.tag_symbol(package, f.next_id);
                let f = self.fec_send_slot.as_mut().unwrap();
                f.next_id += 1;
                if let Some(rec) = &mut self.fec_record { rec.push(f.progress_info()); }
                self.packet_dscp = Some(dscp);
                return Some(UnreliableFragment::Plain { is_fin: true, package_id: package, data: &f.message, offset: 0 });
            }
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
                    let lease = match self.package_allocator.clone() {
                        Some(ids) => { let Some(lease) = ids.allocate() else { return None; }; Some(lease) },
                        None => None,
                    };
                    let f = self.fec_send_slot.take().unwrap();
                    self.send_package_id = lease.as_ref().map_or(self.send_package_id.wrapping_add(1), |l| l.id);
                    self.package_lease = lease;
                    self.start_fec_group(f.message, payload_len - STP_SEGMENT_FEC_HEADER_SIZE, f.segment, f.root_lease, f.plan_ks);
                    return self.next_fragment(payload_len, space);
                }
                let f = self.fec_send_slot.take().unwrap();
                drop(f.encoder);
                if self.fec_rescue_package.take().is_some() {
                    self.resume_suspended();
                    return self.next_fragment(payload_len, space); // cannot change a retained package's layout
                }
                self.send_package_id = self.send_package_id.wrapping_add(1);
                let msg = std::sync::Arc::try_unwrap(f.message).unwrap_or_else(|a| (*a).clone());
                if !self.start_message(msg, payload_len) { return None; }
                return self.next_fragment(payload_len, space);
            }
            let package_id = self.fec_rescue_package.unwrap_or(self.send_package_id);
            let mut repair_len = None;
            {
                let f = self.fec_send_slot.as_mut().unwrap();
                if f.next_id >= f.k {
                    if let FecEncoderState::Pending(rx) = &f.encoder {
                        f.encoder = match rx.try_recv() {
                            Ok(Some(e)) => FecEncoderState::Ready(e),
                            Ok(None) | Err(std::sync::mpsc::TryRecvError::Disconnected) => FecEncoderState::Failed,
                            Err(std::sync::mpsc::TryRecvError::Empty) => return None,
                        };
                    }
                    repair_len = match &mut f.encoder {
                        FecEncoderState::Ready(e) => e.block_into(f.next_id, &mut f.block_buf),
                        _ => None,
                    };
                    if repair_len.is_none() {
                        // No encoder: the source blocks are all out, end the message there.
                        f.next_id = f.n;
                    }
                }
            }
            let f = self.fec_send_slot.as_ref().unwrap();
            if f.next_id >= f.n { return self.next_fragment(payload_len, space); }
            self.tag_symbol(package_id, self.fec_send_slot.as_ref().unwrap().next_id);
            let f = self.fec_send_slot.as_mut().unwrap();
            let id = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap().wire_id(f.next_id);
            if let Some(len) = repair_len {
                f.next_id += 1;
                if let Some(rec) = &mut self.fec_record { rec.push(f.progress_info()); }
                self.packet_dscp = Some(dscp);
                return Some(UnreliableFragment::Fec { segment: f.segment, package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.block_buf[..len] });
            }
            f.next_id += 1;
            if f.next_id == 1 || f.next_id == f.k {
                if let Some(rec) = &mut self.fec_record { rec.push(f.progress_info()); }
            }
            let start = id as usize * f.block_bytes;
            let end = (start + f.block_bytes).min(f.message.len());
            self.packet_dscp = Some(dscp);
            return Some(UnreliableFragment::Fec { segment: f.segment, package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.message[start..end] });
        }
        let (msg, start_byte) = self.partial_send_slot.as_ref().unwrap();
        let whole = *start_byte == 0 && msg.len() <= payload_len.saturating_sub(STP_WHOLE_HEADER_SIZE);
        let frag_size = space.checked_sub(if whole { STP_WHOLE_HEADER_SIZE } else { STP_FRAGMENT_HEADER_SIZE })?;
        if *start_byte == 0 && msg.len() <= frag_size {
            if let Some(r) = self.fec_retained.get_mut(&self.send_package_id).filter(|r| r.slot.k == 1) {
                if r.slot.next_id > 0 && r.slot.next_id < r.slot.n { self.rescue_ready_count -= 1; }
                r.slot.next_id = 1;
                r.slot.first_seq = self.next_packet_seq;
                if let Some(rec) = &mut self.fec_record { rec.push(r.slot.progress_info()); }
                self.tag_symbol(self.send_package_id, 0);
            }
        }
        let (msg, start_byte) = self.partial_send_slot.as_mut().unwrap();
        let start = *start_byte as usize;
        // A plain message that fits a fresh packet has exactly one physical erasure event.
        // Do not fill the preceding packet's tail with a partial prefix of that message.
        if whole && msg.len() > frag_size {
            return None;
        }
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
    packet_owner: Option<Box<[u8]>>,
    queues: Vec<UnreliableSendBuffer>,
    next_queue: usize,
    // Equal-weight byte service, excluding packet padding. A dormant queue receives
    // no accumulated credit; joining queues begin at the current service clock.
    scheduled_bytes: Vec<u64>,
    queue_active: Vec<bool>,
    service_clock: u64,
    fec_owner_tags: HashMap<u64, Vec<(u8, u64)>>,
    last_queue: usize,
    last_dscp: Dscp,
    fec_adaptive: Option<crate::fec_adapt::FecAdaptiveState>,
    fec_packet_tags: Option<Box<[u64]>>,
    fec_extra_packet_tags: HashMap<u64, Vec<u64>>,
    next_packet_seq: u64,
    fec_record: Option<Vec<crate::fec_adapt::FecMessageInfo>>,
}

impl SendQueues {
    pub fn new(count: usize, bounds: (u32, u32, u32)) -> Self {
        assert!((1..=64).contains(&count));
        let ids = std::sync::Arc::new(PackageAllocator::new());
        let queues = (0..count).map(|_| {
            let mut q = UnreliableSendBuffer::new(bounds.0, bounds.1, bounds.2);
            q.package_allocator = Some(ids.clone());
            q.retention_quota = std::sync::Arc::new(RetentionQuota::new(count));
            q
        }).collect();
        Self { scheduled_bytes: vec![0; count], queue_active: vec![false; count], service_clock: 0, fec_owner_tags: HashMap::new(), packet_owner: None, queues, next_queue: 0, last_queue: 0, last_dscp: Dscp::BestEffort, fec_adaptive: None,
            fec_packet_tags: None, fec_extra_packet_tags: HashMap::new(), next_packet_seq: 0, fec_record: None }
    }
    pub fn submit_messages(&mut self, queue: usize, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        self.submit_classified_messages(queue, messages.into_iter().map(|m| (Dscp::BestEffort, m)).collect()).into_iter().map(|(_, m)| m).collect()
    }
    pub fn submit_classified_messages(&mut self, queue: usize, messages: Vec<(Dscp, Vec<u8>)>) -> Vec<(Dscp, Vec<u8>)> {
        match self.queues.get_mut(queue) { Some(q) => q.submit_classified_messages(messages), None => messages }
    }
    pub fn free_bytes(&mut self) -> Vec<u64> { self.queues.iter_mut().map(|q| q.free_bytes()).collect() }
    pub fn has_unsent_data(&self) -> bool { self.queues.iter().any(|q| q.has_unsent_data()) }
    fn set_time(&mut self, now: u64, rtt: u64) {
        for q in &mut self.queues { q.fec_now_ns = now; q.fec_rtt_ns = rtt; q.fec_prune_retained(); }
    }
    fn set_rate(&mut self, bytes_per_second: u64) {
        let active = self.queues.iter().filter(|q| q.has_unsent_data()).count().max(1) as u64;
        for q in &mut self.queues { q.current_bytes_per_second = bytes_per_second / active; }
    }
    fn set_overhead(&mut self) {
        let ppm = self.fec_adaptive.as_ref().unwrap().representative_ppm();
        for q in &mut self.queues { q.fec_capacity_overhead_ppm = ppm; }
    }
    fn fec_prepare_packet(&mut self, seq: u64) {
        self.next_packet_seq = seq;
        if let Some(owners) = &mut self.packet_owner { owners[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize] = u8::MAX; }
        if let Some(tags) = &mut self.fec_packet_tags { tags[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize] = 0; }
        self.fec_extra_packet_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
        self.fec_owner_tags.remove(&(seq % PACKETS_WAITING_ACK_CAPACITY));
    }
    fn fec_on_packet_finalized(&mut self, seq: u64, lost: bool) {
        if seq > self.next_packet_seq || self.next_packet_seq - seq >= PACKETS_WAITING_ACK_CAPACITY { return; }
        let Some(tags) = &mut self.fec_packet_tags else { return; };
        let index = seq % PACKETS_WAITING_ACK_CAPACITY;
        let tag = std::mem::take(&mut tags[index as usize]);
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
            let tag = std::mem::take(&mut tags[index]);
            if tag != 0 { self.fec_owner_tags.entry(index as u64).or_default().push((old, tag)); }
        }
        if let Some(tags) = self.fec_extra_packet_tags.remove(&(index as u64)) {
            self.fec_owner_tags.entry(index as u64).or_default().extend(tags.into_iter().map(|tag| (old, tag)));
        }
    }
    #[cfg(test)]
    fn bound_retention(&mut self) {
        for q in &self.queues {
            let used = q.retention_quota.used.lock().unwrap();
            assert!(used.0 <= q.retention_quota.byte_limit && used.1 <= q.retention_quota.slot_limit);
        }
    }
    fn fill_packet(&mut self, payload: &mut [u8]) -> usize {
        let count = self.queues.len();
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
            // Least served eligible queue wins; round-robin breaks equal byte ties.
            // A full FEC symbol or a whole small message never splits to fill a tail.
            let candidate = (0..count).map(|step| (self.next_queue + step) % count)
                .filter(|&i| self.queue_active[i] && blocked & (1u64 << i) == 0)
                .min_by_key(|&i| self.scheduled_bytes[i]);
            let Some(i) = candidate else { break; };
            let next_service = (0..count).filter(|&j| j != i && self.queue_active[j] && blocked & (1u64 << j) == 0)
                .map(|j| self.scheduled_bytes[j]).min().unwrap_or(u64::MAX);
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
                class = q.packet_dscp;
                self.last_dscp = class.unwrap();
                self.last_queue = i;
                self.next_queue = (i + 1) % count;
                self.scheduled_bytes[i] += used as u64;
                cursor += used;
                self.queue_active[i] = q.can_emit();
                if !self.queue_active[i] || self.scheduled_bytes[i] >= next_service { break; }
            }
            if let Some(clock) = (0..count).filter(|&i| self.queue_active[i]).map(|i| self.scheduled_bytes[i]).min() {
                self.service_clock = self.service_clock.max(clock);
            }
        }
        if cursor == 0 { return 0; }
        payload[cursor..].fill(0xff);
        payload.len()
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

/// Fill a full transmission unit, or return 0 if nothing was queued.
/// Padding is an authenticated terminator, never a variable-size tail.
pub(crate) fn fec_fragment_header_size(payload: &[u8]) -> Option<usize> {
    if payload.len() < STP_FEC_FRAGMENT_HEADER_SIZE { return None; }
    Some(if (load_u64(&payload[8..16]) >> 48) & 0xff == STP_EXT_KIND_SEGMENT_FEC {
        STP_SEGMENT_FEC_HEADER_SIZE
    } else { STP_FEC_FRAGMENT_HEADER_SIZE })
}

fn write_fragment(payload: &mut [u8], frag: UnreliableFragment<'_>) -> usize {
    match frag {
        UnreliableFragment::Plain { is_fin, package_id, data, offset } => {
            let header = ((is_fin as u64) << 1) | ((package_id as u64) << 2) | ((data.len() as u64) << 18) | ((offset as u64) << 32);
            let size = if is_fin && offset == 0 { STP_WHOLE_HEADER_SIZE } else { STP_FRAGMENT_HEADER_SIZE };
            if size == STP_WHOLE_HEADER_SIZE { store_u32(&mut payload[..4], header as u32 | 1); }
            else { store_u64(&mut payload[..8], header); }
            data.write_to(&mut payload[size..]);
            size + data.len()
        }
        UnreliableFragment::Fec { segment, package_id, message_len, block_bytes, block_id, data } => {
            let word0 = 1 | ((package_id as u64) << 2) | ((data.len() as u64) << 18) | ((block_id as u64) << 32);
            let kind = if segment.is_some() { STP_EXT_KIND_SEGMENT_FEC } else if message_len as usize > crate::fec::MAX_BLOCKS * block_bytes as usize { STP_EXT_KIND_GROUPED_FEC } else { STP_EXT_KIND_FEC };
            let word1 = message_len as u64 | ((block_bytes as u64) << 32) | (kind << 48);
            store_u64(&mut payload[..8], word0);
            store_u64(&mut payload[8..16], word1);
            let size = if let Some(segment) = segment {
                store_u16(&mut payload[16..18], segment.root);
                store_u32(&mut payload[18..22], segment.total);
                store_u32(&mut payload[22..26], segment.offset);
                STP_SEGMENT_FEC_HEADER_SIZE
            } else { STP_FEC_FRAGMENT_HEADER_SIZE };
            data.write_to(&mut payload[size..]);
            size + data.len()
        }
    }
}

fn fill_packet_payload_with_unreliable_fragments(payload: &mut [u8], buf: &mut UnreliableSendBuffer) -> usize {
    buf.packet_dscp = None;
    let mut cursor = 0;
    while cursor + STP_WHOLE_HEADER_SIZE <= payload.len() {
        let Some(frag) = buf.next_fragment(payload.len(), payload.len() - cursor) else { break; };
        cursor += write_fragment(&mut payload[cursor..], frag);
    }
    if cursor == 0 { return 0; }
    payload[cursor..].fill(0xff);
    payload.len()
}

const RECEIVE_CONNECTION_BYTES: usize = 512 << 10;
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
    pub old: snow::StatelessTransportState,
    pub current: snow::StatelessTransportState,
    pub new: snow::StatelessTransportState,
}
impl ConnectionCipherTriplet {
    pub fn new_from_old_init_only(mut old: snow::StatelessTransportState) -> Self {
        old.rekey_outgoing(); // target the other side's current
        let mut current = old.clone();
        current.rekey_incoming();
        let mut new = current.clone();
        new.rekey_incoming();
        Self { old, current, new }
    }
    pub fn ratchet_forward_incoming(&mut self) {
        self.old.rekey_incoming();
        self.current.rekey_incoming();
        self.new.rekey_incoming();
    }
    pub fn advance_outgoing(&mut self) {
        self.old.rekey_outgoing(); // This is a bit redundant since they are all the same.
        self.current.rekey_outgoing();
        self.new.rekey_outgoing();
    }
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

#[derive(Debug)]
pub struct ConnectionStateConnected {
    pub cipher: Option<ConnectionCipherTriplet>,
    pub magic1: u64,
    pub magic2: u64,

    pub send_sequence_number: u64,
    pub send_ack_sequence_number: u64,
    pub receive_sequences: crate::sequence::ReceiveSequences,
    pub last_sent_data_packet: u64,
    pub last_sent_could_have_sent_data_packet: u64,
    pub last_ack_received_time: u64,
    pub last_status_print_time: u64,
    pub packet_since_last_print: u64,
    pub packet_lost_since_last_print: u64,
    pub max_in_flight_since_last_print: u64,

    pub ack_timer: u64,
    pub ack_receiver: crate::ack::AckReceiver,
    /// Highest positively acknowledged peer receipt; holes are NOT declarations of loss.
    pub highest_peer_acked: Option<u64>,
    pub peer_ack_delay_us: u32,
    pub peer_ce_count: u32,
    loss_timer: LossTimer,
    ack_hole: AckHole,

    // Note(Sam): HARD ASSUMPTION that no link ever has a greater RTT than 4.295 seconds.
    pub send_time_band: [u64; 1024], // 1024 buckets of 4.194 ms giving 4.295 seconds of tracking.
    pub send_time_band_head_index: u64, // monotonic time ns / 4_194_304 aka 0x400000
    
    pub RTT_sample_sums: [u32; 16],   // sum of RTT measurements per ack, in 0.1 ms units
    pub RTT_sample_counts: [u16; 16], // count of RTT measurements per ack
    pub RTT_sample_cursor: u64,
    pub RTT_mean: u16,
    pub RTT_mean_cursor: u64, // RTT_sample_cursor value RTT_mean was last computed from

    pub ack_arrival_times: [u64; 16], // timestamp_ns of each ack arrival, ring buffer
    pub ack_pace_estimate: u16,       // median inter-ack gap in 0.1 ms units, clamped to RTT_mean*2
    
    pub packets_waiting_ack_field: [u64; PACKETS_WAITING_ACK_WORDS],
    // head is the send_sequence_number
    pub packets_waiting_ack_tail: u64,
    
    pub current_tu: u64,
    pub last_sent_tu_probe_time_ns: u64,
    pub tu_probe_sequence_number: u64,
    pub tu_probe_size: u64,
    pub tu_probe_size_advance: u64,
    pub tu_probe_failed_count: u64,
    
    pub packets_in_flight: u64,
    pub send_pacer_acc_ns: u64,
    pub congestion_event_time_ns: u64,
    pub congestion_event_rate_upps: u64,
    /// Startup exits only on a genuine loss/ECN event, never on RTT/delivery signals.
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
    /// Per sequence number in [tail - CAPACITY, tail): declared lost and not yet acked since
    /// (spurious-loss detection). Same ring indexing as packets_waiting_ack_field.
    pub declared_lost_field: Box<[u64; PACKETS_WAITING_ACK_WORDS]>,
    /// Receiver ground truth over the peer's sequence numbers.
    pub rx_tracker: RxSeqTracker,
}
pub fn new_connection_state_connected(cipher: Option<ConnectionCipherTriplet>, magic1: u64, magic2: u64, timestamp_ns: u64) -> ConnectionState {
    ConnectionState::Connected(ConnectionStateConnected {
        cipher,
        magic1,
        magic2,
        send_sequence_number: 0,
        send_ack_sequence_number: crate::sequence::ACK_SPACE,
        receive_sequences: Default::default(),
        last_sent_data_packet: 0,
        last_sent_could_have_sent_data_packet: 0,
        last_ack_received_time: timestamp_ns,
        last_status_print_time: timestamp_ns,
        packet_since_last_print: 0,
        packet_lost_since_last_print: 0,
        max_in_flight_since_last_print: 0,
        ack_timer: u64::MAX,
        ack_receiver: Default::default(),
        highest_peer_acked: None,
        peer_ack_delay_us: 0,
        peer_ce_count: 0,
        loss_timer: LossTimer::default(),
        ack_hole: AckHole::default(),
        send_time_band: [0; 1024],
        send_time_band_head_index: 0,
        RTT_sample_sums: [0; 16],
        RTT_sample_counts: [0; 16],
        RTT_sample_cursor: 0,
        RTT_mean: u16::MAX,
        RTT_mean_cursor: 0,
        ack_arrival_times: [0; 16],
        ack_pace_estimate: 0,
        packets_waiting_ack_field: [0; PACKETS_WAITING_ACK_WORDS],
        packets_waiting_ack_tail: 0,
        
        current_tu: ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY as u64,
        last_sent_tu_probe_time_ns: 0,
        tu_probe_sequence_number: u64::MAX,
        tu_probe_size: 0,
        tu_probe_size_advance: 0,
        tu_probe_failed_count: 0,
        
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

/// Cumulative per-connection counters, for measurement.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionStats {
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
    /// Partial messages discarded because a newer package took their slot, and the message bytes
    /// they had received (plain: bytes held; FEC: blocks x block size).
    pub rx_partial_evicted: u64,
    pub rx_partial_evicted_bytes: u64,
    /// Fragments that did not fit the partial message in their slot (it was discarded and restarted).
    pub rx_insert_failures: u64,
    /// Fragments of a package older than the one holding their slot (dropped).
    pub rx_stale_fragments: u64,
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
    /// Oldest inactive decoder retired under admission pressure after 2 RTTs.
    pub fec_decode_preemptions: u64,
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

impl ConnectionStateConnected {
    fn send_time(&self, sequence: u64) -> u64 {
        get_send_time_for_sequence_number(sequence, &self.send_time_band, self.send_time_band_head_index)
    }
    fn account_send(&mut self, actual_ns: u64) {
        self.outage.pending_since_ns.get_or_insert(actual_ns);
        assert!(self.send_sequence_number < crate::sequence::ACK_SPACE - 1, "data nonce space exhausted");
        increment_sequence_number_and_account(actual_ns, &mut self.send_sequence_number,
            &mut self.send_time_band, &mut self.send_time_band_head_index, &mut self.packets_waiting_ack_field);
    }
}

// ring of in-flight sequence numbers; head-tail span must stay under capacity or bits alias
pub const PACKETS_WAITING_ACK_WORDS: usize = 4096;
pub const PACKETS_WAITING_ACK_CAPACITY: u64 = PACKETS_WAITING_ACK_WORDS as u64 * 64;

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
) {
    let Some(receive_reservation) = budget.reserve(RECEIVE_CONNECTION_BYTES) else { return; };
    assert!(my_connect_keypair.magic1 == endpoint.magic1);

    if my_connect_keypair.magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
        let magic2_block = build_magic2_client_block();
        let mut hello_packet_payload = vec![0u8; 6 + 32 + MAGIC2_BLOCK_SIZE];
        store_u48(&mut hello_packet_payload[0..6], my_connect_keypair.magic1);
        assert_eq!(my_connect_keypair.public.len(), 32);
        hello_packet_payload[6..6+32].copy_from_slice(&my_connect_keypair.public[..]);
        hello_packet_payload[6+32..6+32+MAGIC2_BLOCK_SIZE].copy_from_slice(&magic2_block);

        let my_ip = if endpoint.is_ipv4() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
        connections_map.insert(
            ConnectionKey::from(endpoint),
            ConnectionTrackingData {
                receive_reservation,
                receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_share(budget),
                creation_time_ns: monotonic_clock_ns(),
                my_ip,
                my_transport_identity_keypair: my_connect_keypair.clone(),
                two_byte_send_prefix: load_u16(&my_connect_keypair.public[0..2]) << 1,
                other_ip: endpoint.ip,
                other_port: endpoint.port,
                other_transport_identity: endpoint.key.clone(),
                connection_state: ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns: 0, hello_packet_payload },
                handshake_hash: [0u8; 64],
                unreliable_send_buffer: SendQueues::new(send_queue_count, send_buffer_params),
                unreliable_reassembly: ReassemblySlot::new_ring(1024),
                unreliable_fec: FecRecvSlot::new_ring(1024),
            },
        );
    }
    else {
        let magic2_block = build_magic2_client_block();
        let mut hello_packet_payload = vec![0u8; 1024];
        store_u48(&mut hello_packet_payload[0..6], my_connect_keypair.magic1);
        let mut handshake = snow::Builder::new(crypto_string_from_connect_magic1(my_connect_keypair.magic1).unwrap().parse().unwrap())
            .prologue(&hello_packet_payload[0..6]).unwrap()
            .local_private_key(&my_connect_keypair.private[..]).unwrap()
            .remote_public_key(&endpoint.key[..]).unwrap()
            .build_initiator().unwrap();

        let handshake_size = handshake.write_message(&magic2_block, &mut hello_packet_payload[6..]).unwrap();
        hello_packet_payload.truncate(6+handshake_size);
        hello_packet_payload.shrink_to_fit();

        let my_ip = if endpoint.is_ipv4() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
        connections_map.insert(
            ConnectionKey::from(endpoint),
            ConnectionTrackingData {
                receive_reservation,
                receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_share(budget),
                creation_time_ns: monotonic_clock_ns(),
                my_ip,
                my_transport_identity_keypair: my_connect_keypair.clone(),
                two_byte_send_prefix: load_u16(&my_connect_keypair.public[0..2]) << 1,
                other_ip: endpoint.ip,
                other_port: endpoint.port,
                other_transport_identity: endpoint.key.clone(),
                connection_state: ConnectionState::SendingClientHello { magic1: my_connect_keypair.magic1, last_sent_time_ns: 0, hello_packet_payload, handshake },
                handshake_hash: [0u8; 64],
                unreliable_send_buffer: SendQueues::new(send_queue_count, send_buffer_params),
                unreliable_reassembly: ReassemblySlot::new_ring(1024),
                unreliable_fec: FecRecvSlot::new_ring(1024),
            },
        );
    }
}

const        VERBOSE                :bool=0!=                (1);
const OVERLY_VERBOSE                :bool=0!=                (0);

macro_rules! pod { ($($item:item)*) => { $(#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] $item)* }; }

#[derive(Debug, Default)]
pub struct ReassemblySlot {
    reservation: Option<crate::receive_memory::Reservation>,
    pub buf: Vec<u8>,
    pub total_len: Option<u32>,
    pub received: Vec<(u32, u32)>, // sorted non-overlapping non-adjacent ranges: [start, end)
    pub package_id: u16,
    completed: bool,
    segment_parts: Option<Vec<(u32, Vec<u8>)>>,
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
            last_segment_ns: 0,
        }
    }
    
    /// Message bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.segment_parts.as_ref().map_or_else(|| self.received.iter().map(|&(s, e)| (e - s) as u64).sum(),
            |parts| parts.iter().map(|(_, bytes)| bytes.len() as u64).sum())
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
            if (segment.root.wrapping_sub(self.package_id) as i16) < 0 { return false; }
            *self = Self::new(); // eviction drops sparse parts and their charge
        }
        self.package_id = segment.root;
        if self.completed { return true; }
        if self.total_len.is_some_and(|n| n != segment.total) ||
            (!self.buf.is_empty() || !self.received.is_empty()) { return false; }
        if self.reservation.is_none() {
            let groups = (segment.total as usize).div_ceil(FEC_SEGMENT_BYTES);
            let Some(r) = budget.reserve(256 + groups * 64) else { return false; };
            self.reservation = Some(r);
            self.segment_parts = Some(Vec::with_capacity(groups));
            self.total_len = Some(segment.total);
        }
        self.last_segment_ns = now_ns;
        true
    }

    fn finish_segment(&mut self, segment: FecSegment, message: &[u8])
        -> Option<(Vec<u8>, crate::receive_memory::Reservation)> {
        if self.package_id != segment.root || self.completed || self.total_len != Some(segment.total) ||
            !segment.valid(message.len()) { return None; }
        let parts = self.segment_parts.as_mut()?;
        let groups = (segment.total as usize).div_ceil(FEC_SEGMENT_BYTES);
        let metadata = 256 + groups * 64;
        let reservation = self.reservation.as_mut()?;
        let mut bytes: usize = parts.iter().map(|(_, bytes)| bytes.capacity()).sum();
        if !parts.iter().any(|(offset, _)| *offset == segment.offset) {
            if !reservation.grow(metadata + bytes + message.len()) { return None; }
            parts.push((segment.offset, message.to_vec()));
            bytes += message.len();
        }
        if parts.len() != groups { return None; }
        parts.sort_unstable_by_key(|(offset, _)| *offset);
        // Concatenation's temporary second allocation is admitted too; no sparse
        // high-water allocation from an unmaterialised claimed total or offset.
        let total = segment.total as usize;
        let first_cap = parts[0].1.capacity();
        if !reservation.grow(metadata + bytes + total - first_cap) { return None; }
        let mut parts = self.segment_parts.take().unwrap().into_iter();
        let mut message = parts.next().unwrap().1;
        message.reserve_exact(total - message.len());
        for (_, part) in parts { message.extend_from_slice(&part); }
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
        if self.completed { return (true, false); } // fresh-nonce K=1 rescue must not redeliver

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
/// and indexed the same way (package id % ring size).
#[derive(Default)]
pub struct FecRecvSlot {
    pub package_id: u16,
    segment: Option<FecSegment>,
    state: FecRecvState,
    reservation: Option<crate::receive_memory::Reservation>,
    /// Blocks handed to this slot's decoder (for loss accounting on eviction).
    blocks_received: u32,
    last_block_ns: u64,
    ingress_dropped: u64,
    admission_refused: bool,
}

#[derive(Default)]
enum FecRecvState {
    #[default]
    Empty,
    /// Small message: decoded on the network thread.
    Inline(crate::fec::MessageDecoder),
    /// Big message: a byte-bounded, nonblocking ingress queue feeds a decoder thread.
    /// Dropping the sender (eviction, disconnect) ends it and frees the decoder.
    Worker { tx: std::sync::mpsc::SyncSender<(u32, Vec<u8>)>, message_len: usize, block_bytes: usize },
    /// Delivered (or given up): late surplus blocks of this package are ignored.
    Done,
}

impl std::fmt::Debug for FecRecvSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = match &self.state { FecRecvState::Empty => "empty", FecRecvState::Inline(_) => "inline", FecRecvState::Worker { .. } => "worker", FecRecvState::Done => "done" };
        write!(f, "FecRecvSlot {{ package_id: {}, state: {st} }}", self.package_id)
    }
}

impl FecRecvSlot {
    pub fn new_ring(size: usize) -> Vec<FecRecvSlot> {
        (0..size).map(|_| FecRecvSlot::default()).collect()
    }
    pub fn in_use(&self) -> bool { !matches!(self.state, FecRecvState::Empty) }
    /// Message bytes received so far (blocks x block size).
    pub fn bytes_received(&self) -> u64 { self.blocks_received as u64 * self.params().map_or(0, |p| p.1) as u64 }
    fn params(&self) -> Option<(usize, usize)> {
        match &self.state {
            FecRecvState::Inline(d) => Some((d.message_len(), d.block_bytes())),
            FecRecvState::Worker { message_len, block_bytes, .. } => Some((*message_len, *block_bytes)),
            _ => None,
        }
    }
}

/// Decoder threads per network thread; overload erases a fragment and retries
/// admission later, never solves inline. Small (<=256-block) messages stay inline.
pub const MAX_FEC_DECODE_WORKERS: usize = 8;
/// Byte cap for each ingress level, including channel slots (not just block payload).
pub const MAX_FEC_INGRESS_BYTES: usize = 32 << 20;

fn fec_inactive_grace_ns(rtt: u16, pressure: bool) -> u64 {
    if pressure {
        if rtt == 0 || rtt == u16::MAX { 250_000_000 } else { 2 * rtt as u64 * 100_000 }
    } else {
        let rtt_ns = if rtt == u16::MAX { 0 } else { rtt as u64 * 100_000 };
        (4 * rtt_ns).max(2_000_000_000)
    }
}

/// Incomplete plain messages and roots follow fragment inactivity, not keepalive ACKs.
fn retire_inactive_segment_roots(slots: &mut [ReassemblySlot], now_ns: u64, grace_ns: u64) {
    for slot in slots {
        if !slot.completed && slot.reservation.is_some() && now_ns.saturating_sub(slot.last_segment_ns) > grace_ns {
            *slot = ReassemblySlot::new();
        }
    }
}

fn valid_fec_symbol(layout: crate::fec::MessageLayout, block_id: u32, data_len: usize) -> bool {
    let expect = if (block_id as usize) < layout.k {
        crate::fec::block_len(layout.len, layout.block_bytes, block_id)
    } else { layout.block_bytes };
    data_len == expect
}

/// Closing ingress lets the worker finish queued work and release its admission
/// guard. Never decrement its counters here: it may still be inside Wirehair.
/// A completed queued decode may still deliver before this package is evicted.
fn retire_inactive_fec_workers(slots: &mut [FecRecvSlot], now_ns: u64, grace_ns: u64, oldest_only: bool) -> u64 {
    let eligible = |s: &FecRecvSlot| matches!(s.state, FecRecvState::Worker { .. }) && now_ns.saturating_sub(s.last_block_ns) > grace_ns;
    if oldest_only {
        if let Some(index) = slots.iter().enumerate().filter(|(_, s)| eligible(s)).min_by_key(|(_, s)| s.last_block_ns).map(|(i, _)| i) {
            slots[index].state = FecRecvState::Done;
            return 1;
        }
        return 0;
    }
    let mut retired = 0;
    for slot in slots {
        if eligible(slot) {
            slot.state = FecRecvState::Done;
            retired += 1;
        }
    }
    retired
}

struct FecWorkerGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for FecWorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Handles one received FEC fragment for the package in `slot` (the caller has already made
/// the slot belong to `package_id`). Returns a message to deliver if decoding finished inline.
fn fec_receive_block(
    slot: &mut FecRecvSlot, connection_key: ConnectionKey, package_id: u16,
    message_len: usize, block_bytes: usize, block_id: u32, data: &[u8],
    done_tx: &std::sync::mpsc::Sender<(ConnectionKey, u16, Vec<u8>, crate::receive_memory::Reservation)>,
    workers: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
) -> Option<(Vec<u8>, crate::receive_memory::Reservation)> {
    use crate::fec::*;
    if matches!(slot.state, FecRecvState::Done) { return None; }
    slot.blocks_received = slot.blocks_received.saturating_add(1);
    let layout = MessageLayout::new(message_len, block_bytes)?;
    if !valid_fec_symbol(layout, block_id, data.len()) { return None; }
    if slot.params().is_some_and(|p| p != (message_len, block_bytes)) {
        slot.state = FecRecvState::Empty;
        slot.reservation = None;
    }
    if !slot.in_use() {
        let worker = layout.k > FEC_INLINE_MAX_BLOCKS;
        let charge = receive_memory_charge(layout, worker, MAX_FEC_INGRESS_BYTES)?;
        let reservation = if !worker || workers.load(std::sync::atomic::Ordering::Acquire) < MAX_FEC_DECODE_WORKERS {
            budget.reserve(charge)
        } else { None };
        let Some(reservation) = reservation else {
            slot.admission_refused = true;
            slot.ingress_dropped += 1;
            return None;
        };
        if worker {
            let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>)>(ingress_slots(MAX_FEC_INGRESS_BYTES, block_bytes));
            let done_tx = done_tx.clone();
            workers.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let guard = FecWorkerGuard(workers.clone());
            let r = std::thread::Builder::new().name("stp-fec-decode".into()).spawn(move || {
                let _guard = guard;
                if let Some(m) = decode_message_blocks(layout, rx, MAX_FEC_INGRESS_BYTES) {
                    // Keep the admission charge through the completion channel, including
                    // when the network thread is stalled or this connection is evicted.
                    let _ = done_tx.send((connection_key, package_id, m, reservation));
                }
            });
            if r.is_ok() { slot.state = FecRecvState::Worker { tx, message_len, block_bytes }; }
            else { slot.ingress_dropped += 1; return None; }
        } else {
            slot.state = match MessageDecoder::new(message_len, block_bytes) {
                Some(d) => { slot.reservation = Some(reservation); FecRecvState::Inline(d) },
                None => FecRecvState::Done,
            };
        }
    }
    match &mut slot.state {
        FecRecvState::Inline(dec) => match dec.add(block_id, data) {
            Ok(DecodeStatus::NeedMore) | Err(DecodeError::BadBlock) => None,
            Ok(DecodeStatus::Done) => {
                let m = dec.recover(); slot.state = FecRecvState::Done;
                let r = slot.reservation.take()?; m.map(|m| (m, r))
            }
            Err(DecodeError::Failed(_)) => { slot.state = FecRecvState::Done; slot.reservation = None; None }
        },
        FecRecvState::Worker { tx, .. } => {
            match tx.try_send((block_id, data.to_vec())) {
                Ok(()) => slot.last_block_ns = monotonic_clock_ns(),
                Err(std::sync::mpsc::TrySendError::Full(_)) => slot.ingress_dropped += 1,
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => slot.state = FecRecvState::Done,
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
    pub initiate_connections: Vec<STPAddress>,
    pub wanted_connections: Vec<(STPAddress, [u8; 64])>,
    /// (connection, queue index, message traffic class, complete message). Class never
    /// changes FIFO/round-robin scheduling or congestion control. Index must be < count.
    pub send_unreliable: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
}

#[derive(Default)]
pub struct NetworkThreadPull {
    pub current_connections: Vec<(STPAddress, [u8; 64])>,
    pub received_unreliable_messages: VecDeque<(ConnectionKey, Vec<u8>)>,
    /// Messages from this call's `send_unreliable` that were not queued, handed back unchanged:
    /// the connection's send queue was full (see `UnreliableSendBuffer::submit_messages`), or no
    /// connection with that key exists. Per connection AND queue they keep the order they were pushed in.
    /// Nothing is dropped; resubmit them later or discard them yourself.
    pub send_unreliable_rejected: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    /// Distinct application error: queue index outside the fixed initialization bound.
    /// Messages are untouched, but retrying without changing the index cannot succeed.
    pub send_unreliable_invalid_queue: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    /// For every connection the network thread holds (connected or still handshaking), the
    /// largest message each indexed send queue would accept now, after this call's submissions; u64::MAX
    /// when its queue is empty. A connection missing here does not exist.
    pub unreliable_send_free_bytes: Vec<(ConnectionKey, usize, u64)>,
    /// Cumulative counters for every connected connection.
    pub connection_stats: Vec<(ConnectionKey, ConnectionStats)>,
    /// Cumulative progress snapshots at first source, source completion and every repair
    /// (including K=1 raw rescue), only with `NetworkThreadOptions::record_fec_messages`.
    pub fec_messages: Vec<(ConnectionKey, crate::fec_adapt::FecMessageInfo)>,
    /// Network-thread-wide counters (kernel drops, loop starvation).
    pub thread_stats: NetworkThreadStats,
}

struct NetworkThreadInner {
    state: std::sync::atomic::AtomicUsize, // 0 empty, 1 full
    stop: std::sync::atomic::AtomicBool,
    push: std::cell::UnsafeCell<NetworkThreadPush>,
    pull: std::cell::UnsafeCell<NetworkThreadPull>,
}

#[allow(unsafe_code)]
unsafe impl std::marker::Sync for NetworkThreadInner {}

// Note(Sam): Using this handle from two threads at once is UB. Only one thread may call service_connections at any given time.
pub struct NetworkThreadHandle {
    inner: std::sync::Arc<NetworkThreadInner>,
    thread: Option<std::thread::JoinHandle<()>>,
    join_on_drop: bool,
}

// The network thread owns the socket, so it has to end for the port to close and for peers to
// see this node go quiet. Nothing is sent to them: they time the connection out.
impl Drop for NetworkThreadHandle {
    fn drop(&mut self) {
        self.inner.stop.store(true, std::sync::atomic::Ordering::Release);
        // A traced run must flush the final buffered events before the process exits.
        if self.join_on_drop { if let Some(t) = self.thread.take() { let _ = t.join(); } }
    }
}

pub fn new_network_thread(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32)) -> NetworkThreadHandle {
    new_network_thread_with_bind(my_keypairs, my_port, max_pps, send_buffer_params, None)
}

/// Like `new_network_thread`, but `bind_ip: Some(ip)` binds the UDP socket to that one local
/// address instead of the dual-stack wildcard, so replies leave from it (Fly.io UDP needs the
/// `fly-global-services` IPv4 address). An IPv4 bind only reaches IPv4 peers, an IPv6 bind only
/// IPv6 peers. Linux only; elsewhere a specific bind fails. `None` is `new_network_thread`.
pub fn new_network_thread_with_bind(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32), bind_ip: Option<std::net::IpAddr>) -> NetworkThreadHandle {
    new_network_thread_with_options(my_keypairs, my_port, max_pps, send_buffer_params, NetworkThreadOptions { bind_ip, ..Default::default() })
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

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct SentDatagram {
    kind: &'static str,
    expected: Option<usize>,
    bytes: Vec<u8>,
}

/// Socket binding and optional measurement. The transport policy is fixed internally.
#[derive(Debug, Clone)]
pub struct NetworkThreadOptions {
    #[cfg(test)]
    pub datagram_log: Option<std::sync::Arc<std::sync::Mutex<Vec<SentDatagram>>>>,
    /// Fixed number of sender-only FIFO queues per connection (1..=64).
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
}

impl Default for NetworkThreadOptions {
    fn default() -> Self { Self { #[cfg(test)] datagram_log: None, send_queue_count: 1, receive_memory: None, bind_ip: None, record_fec_messages: false, record_loss_episodes: false, loss_trace: None } }
}

pub fn new_network_thread_with_options(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32), options: NetworkThreadOptions) -> NetworkThreadHandle {
    let bind_ip = options.bind_ip;
    let send_queue_count = options.send_queue_count;
    assert!((1..=64).contains(&send_queue_count), "send_queue_count must be 1..=64");
    static DEFAULT_RECEIVE_MEMORY: std::sync::OnceLock<std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>> = std::sync::OnceLock::new();
    let receive_memory = options.receive_memory.unwrap_or_else(|| DEFAULT_RECEIVE_MEMORY.get_or_init(|| std::sync::Arc::new(Default::default())).clone());
    // One measured policy, not application configuration.
    let cc = crate::ship::CC;
    let cc_rate = move |t, r, k, startup_done| connection_rate(t, r, k, &cc, startup_done);


    // STP setup
    socket_setup();
    monotonic_clock_setup();

    let socket = setup_and_bind_udp_socket_on(my_port, bind_ip).expect("Failed to bind socket, try again.");

    let inner = std::sync::Arc::new(NetworkThreadInner {
        state: std::sync::atomic::AtomicUsize::new(0),
        stop: std::sync::atomic::AtomicBool::new(false),
        push: std::cell::UnsafeCell::new(NetworkThreadPush::default()),
        pull: std::cell::UnsafeCell::new(NetworkThreadPull::default()),
    });
    let record_fec_messages = options.record_fec_messages;
    let record_loss_episodes = options.record_loss_episodes;
    let mut loss_trace = options.loss_trace.as_deref().map(|p| crate::loss_trace::LossTrace::open(p).expect("open loss trace"));

    let thread_inner = inner.clone();

    #[cfg(test)]
    let datagram_log = options.datagram_log;
    let thread = std::thread::spawn(move || {
        #[cfg(test)]
        let datagram_expectation = std::cell::Cell::new(("handshake", None::<usize>));
        // Test builds observe EVERY actual native send, including handshakes. The
        // UDP relay test cross-checks these exact bytes against socket reception.
        #[cfg(test)]
        let udp_send_with_congestion_and_dscp = |socket, ip, port, bytes: &[u8], dscp, ecn| {
            let sent = crate::native_sockets::udp_send_with_congestion_and_dscp(socket, ip, port, bytes, dscp, ecn);
            let (kind, expected) = datagram_expectation.replace(("handshake", None));
            if let Some(log) = &datagram_log { log.lock().unwrap().push(SentDatagram { kind, expected, bytes: bytes.to_vec() }); }
            sent
        };

        let mut packet_memory_encrypted = new_packet_memory(); // Incoming Encrypted / Outgoing Encrypted
        let mut packet_memory_recv      = new_packet_memory(); // Incoming Decrypted
        let mut packet_memory_send      = new_packet_memory(); // Outgoing Decrypted

        let mut receive_queue = ReceiveQueue::default();
        let (fec_done_tx, fec_done_rx) = std::sync::mpsc::channel::<(ConnectionKey, u16, Vec<u8>, crate::receive_memory::Reservation)>();
        let fec_workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut fec_sweep_ns = 0;

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

        loop {
            if thread_inner.stop.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            {
                let t = monotonic_clock_ns();
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
            if thread_inner.state.load(std::sync::atomic::Ordering::Acquire) == 1 {
                let mut req = NetworkThreadPush::default();

                #[allow(unsafe_code)]
                unsafe {
                    std::mem::swap(&mut *thread_inner.push.get(), &mut req);
                }

                let current_time_now_ns = monotonic_clock_ns();
                connections_map.retain(|key, value| {
                    let stp_address = value.address();
                    if value.creation_time_ns + 30_000_000_000 < current_time_now_ns && req.wanted_connections.iter().position(|(x, _)| x == &stp_address).is_none() && value.is_connected() {
                        println!("############################# KILLING CONNECTION {:?}", value);
                        return false;
                    }
                    true
                });
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
                            connect_to_endpoint(&mut connections_map, keypair, w, send_buffer_params, send_queue_count, &receive_memory);
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
                        batch.push((req.send_unreliable[i].2, std::mem::take(&mut req.send_unreliable[i].3)));
                        i += 1;
                    }
                    let rejected = if let Some(tracking_data) = connections_map.get_mut(&key) {
                        if queue >= tracking_data.unreliable_send_buffer.queues.len() {
                            resp.send_unreliable_invalid_queue.extend(batch.into_iter().map(|(dscp, m)| (key, queue, dscp, m)));
                            continue;
                        }
                        tracking_data.unreliable_send_buffer.submit_classified_messages(queue, batch)
                    } else {
                        batch
                    };
                    resp.send_unreliable_rejected.extend(rejected.into_iter().map(|(dscp, m)| (key, queue, dscp, m)));
                }
                resp.unreliable_send_free_bytes = connections_map.iter_mut()
                    .flat_map(|(key, value)| value.unreliable_send_buffer.free_bytes().into_iter().enumerate().map(|(q, bytes)| (*key, q, bytes))).collect();
                if current_time_now_ns.saturating_sub(cpu_read_ns) >= 100_000_000 {
                    cpu_read_ns = current_time_now_ns;
                    #[cfg(target_os = "linux")]
                    unsafe {
                        let mut ru: libc::rusage = std::mem::zeroed();
                        if libc::getrusage(libc::RUSAGE_THREAD, &mut ru) == 0 {
                            let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
                            network_cpu = (us(ru.ru_utime), us(ru.ru_stime));
                        }
                    }
                }
                resp.connection_stats = connections_map.iter().filter_map(|(key, value)| match &value.connection_state {
                    ConnectionState::Connected(c) => {
                        let mut st = c.stats;
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
                        if let Some(rec) = &mut value.unreliable_send_buffer.fec_record {
                            resp.fec_messages.extend(rec.drain(..).map(|m| (*key, m)));
                        }
                    }
                }

                resp.current_connections = connections_map.iter().filter_map(|(key, value)| {
                    if value.is_connected() {
                        Some((value.address().clone(), value.handshake_hash))
                    } else {
                        None
                    }
                }).collect();
                resp.received_unreliable_messages = receive_queue.take();

                #[allow(unsafe_code)]
                unsafe {
                    std::mem::swap(&mut *thread_inner.pull.get(), &mut resp);
                }

                thread_inner.state.store(0, std::sync::atomic::Ordering::Release);
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
                for _recv_round in 0..MAX_RECV_PACKETS_PER_TICK { // `continue` skips this packet
                    let (buf_len, other_ip_addr, other_port, ecn_marked, ecn_enabled, service_class, timestamp_ns) =
                        match udp_recv_with_congestion_and_dscp(socket, &mut packet_memory_encrypted[..]) {
                            Ok(r) => r,
                            Err(_) => break,
                        };
                    if buf_len < 6 { continue; }
                    
                    should_sleep = false;
                    let first_six_bytes = load_u48(&packet_memory_encrypted[0..6]);
                    
                    
                    if first_six_bytes & 1 != 0 { // Client Hello
                        let magic1 = first_six_bytes;
                        if magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
                            for key_i in 0..my_keypairs.len() {
                                let my_kp = &my_keypairs[key_i];
                                if my_kp.magic1 == CONNECT_MAGIC1_PLAIN_TEXT {
                                    if buf_len >= 6 + 32 + MAGIC2_BLOCK_SIZE {
                                        let client_key = &packet_memory_encrypted[6..6+32];
                                        let magic2_block = &packet_memory_encrypted[6+32..6+32+MAGIC2_BLOCK_SIZE];
                                        let Some(chosen_magic2) = negotiate_magic2(magic2_block) else {
                                            // if OVERLY_VERBOSE { println!("Did NOT respond to connection: magic2 negotiation failed."); }
                                            break;
                                        };
        
                                        let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: load_u16(&client_key[0..2]) << 1 };
                                        if let Some(existing_connection) = connections_map.get_mut(&connection_key) {
                                            if &existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key {
                                                if let ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } = &mut existing_connection.connection_state {
                                                    if *client_key < *my_kp.public {
                                                        store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                                        packet_memory_send[6..6+32].copy_from_slice(&my_kp.public[..]);
                                                        store_u64(&mut packet_memory_send[6+32..6+32+8], chosen_magic2);
                                                        let hello_packet_payload = Vec::from(&packet_memory_send[0..6+32+8]);
        
                                                        existing_connection.connection_state = ConnectionState::SendingServerHelloPlaintext { magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload };
                                                        if OVERLY_VERBOSE { println!("Transitioned connection {} to SendingServerHelloPlaintext.", connection_key.key_15_bits); }
                                                    } else {
                                                        if OVERLY_VERBOSE { println!("Did NOT respond to connection {}: Lost the lexicographic compare.", connection_key.key_15_bits); }
                                                    }
                                                } else {
                                                    let state_str = connection_state_string(&existing_connection.connection_state);
                                                    if OVERLY_VERBOSE { println!("Did NOT respond to connection {}: We were not in SendingClientHelloPlaintext state. We are in {} state.", connection_key.key_15_bits, state_str); }
                                                }
                                            } else {
                                                if OVERLY_VERBOSE { println!("Did NOT respond to connection {}: Failed condition \"&existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key\"", connection_key.key_15_bits); }
                                            }
                                        }
                                        else {
                                            let Some(receive_reservation) = receive_memory.reserve(RECEIVE_CONNECTION_BYTES) else { break; };
                                            let client_key = Vec::from(client_key);
                                            store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                            packet_memory_send[6..6+32].copy_from_slice(&my_kp.public[..]);
                                            store_u64(&mut packet_memory_send[6+32..6+32+8], chosen_magic2);
                                            let hello_packet_payload = Vec::from(&packet_memory_send[0..6+32+8]);
        
                                            let my_ip = if other_ip_addr.to_ipv4_mapped().is_some() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
                                            connections_map.insert(
                                                connection_key,
                                                ConnectionTrackingData {
                                                    receive_reservation,
                                                    receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_share(&receive_memory),
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
                                                    unreliable_reassembly: ReassemblySlot::new_ring(1024),
                                                    unreliable_fec: FecRecvSlot::new_ring(1024),
                                                },
                                            );
                                            if OVERLY_VERBOSE { println!("Transitioned connection {} to SendingServerHelloPlaintext.", connection_key.key_15_bits); }
                                        }
                                    } else {
                                        if OVERLY_VERBOSE { println!("Did NOT respond to connection: The packet was too small (expected {} bytes, got {}).", 6 + 32 + MAGIC2_BLOCK_SIZE, buf_len); }
                                    }
                                }
                            }
                        }
                        else if let Some(crypto_string) = crypto_string_from_connect_magic1(magic1) {
                            for key_i in 0..my_keypairs.len() {
                                let my_kp = &my_keypairs[key_i];
                                if my_kp.magic1 == magic1 {
                                    let mut new_handshake = snow::Builder::new(crypto_string.parse().unwrap())
                                        .prologue(&packet_memory_encrypted[0..6]).unwrap()
                                        .local_private_key(&my_kp.private).unwrap()
                                        .build_responder().unwrap();
                                    let read_message_maybe = new_handshake.read_message(&packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]);
                                    if let Ok(magic2_block_len) = read_message_maybe {
                                        if let Some(client_key) = new_handshake.get_remote_static() {
                                            let Some(chosen_magic2) = negotiate_magic2(&packet_memory_recv[..magic2_block_len]) else {
                                                if OVERLY_VERBOSE { println!("Did NOT respond to Client Hello from {:?}: magic2 negotiation failed.", (other_ip_addr, other_port)); }
                                                break;
                                            };
        
                                            let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: load_u16(&client_key[0..2]) << 1 };
                                            if let Some(existing_connection) = connections_map.get_mut(&connection_key) {
                                                if &existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key {
                                                    if let ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } = &mut existing_connection.connection_state {
                                                        if *client_key < *my_kp.public {
                                                            let mut chosen_magic2_bytes = [0u8; 8];
                                                            store_u64(&mut chosen_magic2_bytes, chosen_magic2);
                                                            store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                                            let handshake_size = new_handshake.write_message(&chosen_magic2_bytes, &mut packet_memory_send[6..]).unwrap();
                                                            let hello_packet_payload = Vec::from(&packet_memory_send[0..6+handshake_size]);
        
                                                            debug_assert!(new_handshake.is_handshake_finished());
                                                            existing_connection.handshake_hash = get_handshake_hash(&new_handshake);
                                                            let cipher = ConnectionCipherTriplet::new_from_old_init_only(new_handshake.into_stateless_transport_mode().expect("Cannot fail given assert above."));
        
                                                            existing_connection.connection_state = ConnectionState::SendingServerHello { cipher, magic1: *magic1, magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload };
                                                            if OVERLY_VERBOSE { println!("Transitioned connection {} to SendingServerHello.", connection_key.key_15_bits); }
                                                        } else {
                                                            if OVERLY_VERBOSE { println!("Did NOT transition {} to SendingServerHello: We \"lost\" the contended initiator comparison.", connection_key.key_15_bits); }
                                                        }
                                                    } else {
                                                        if OVERLY_VERBOSE { println!("Did NOT transition {} to SendingServerHello: We were not in the SendingClientHello state.", connection_key.key_15_bits); }
                                                    }
                                                } else {
                                                    if OVERLY_VERBOSE { println!("Did NOT respond to client hello from {}: @Todo explanation: Following expression was false: &existing_connection.my_transport_identity_keypair == my_kp && existing_connection.other_transport_identity == client_key", connection_key.key_15_bits); }
                                                }
                                            }
                                            else {
                                                let Some(receive_reservation) = receive_memory.reserve(RECEIVE_CONNECTION_BYTES) else { break; };
                                                let client_key = Vec::from(client_key);
                                                let mut chosen_magic2_bytes = [0u8; 8];
                                                store_u64(&mut chosen_magic2_bytes, chosen_magic2);
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
                                                        receive_budget: crate::receive_memory::ReceiveMemoryBudget::connection_share(&receive_memory),
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
                                                        unreliable_reassembly: ReassemblySlot::new_ring(1024),
                                                        unreliable_fec: FecRecvSlot::new_ring(1024),
                                                    },
                                                );
        
                                                if OVERLY_VERBOSE { println!("Transitioned connection {} to SendingServerHello.", connection_key.key_15_bits); }
                                            }
                                        } else {
                                            if OVERLY_VERBOSE { println!("Did NOT respond to Client Hello from {:?}: @Todo explanation: Following expression failed: let Some(client_key) = new_handshake.get_remote_static()", (other_ip_addr, other_port)); }
                                        }
                                    } else {
                                        if OVERLY_VERBOSE { println!("Did NOT respond to Client Hello from {:?}: new_handshake.read_message failed with error = {:?}", (other_ip_addr, other_port), read_message_maybe); }
                                    }
                                }
                            }
                        }
                    }
                    else { 'conn: { // Not client hello
        
                        let connection_key = ConnectionKey { ip: other_ip_addr, port: other_port, key_15_bits: first_six_bytes as u16 };
                        let Some(existing_connection) = connections_map.get_mut(&connection_key) else {
                            if OVERLY_VERBOSE {
                                println!("Packet arrived from non-connection. Drop!");
                            }
                            break 'conn;
                        };
    
                        match &mut existing_connection.connection_state {
                            ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } => {
                                if first_six_bytes >> 16 == 0xffff_ffff && buf_len >= 6 + 32 + 8 {
                                    let server_key = &packet_memory_encrypted[6..6+32];
                                    if server_key == existing_connection.other_transport_identity {
                                        let server_magic2 = load_u64(&packet_memory_encrypted[6+32..6+32+8]);
                                        if !validate_magic2(server_magic2) {
                                            if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}: server chose magic2 {server_magic2:#x} which we did not offer."); }
                                            break 'conn;
                                        }
                                        if VERBOSE { println!("Connected to new server {:?}", server_key); }
                                        existing_connection.connection_state = new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, server_magic2, timestamp_ns);
                                    }
                                } else {
                                    if OVERLY_VERBOSE {
                                        println!("Dropping from {connection_key:?} because the plain text server hello was incorrectly sized.");
                                    }
                                }
                                break 'conn;
                            }
                            ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } => {
                                if first_six_bytes >> 16 == 0xffff_ffff && buf_len >= 6 + 32 {
                                    if let Ok(payload_len) = handshake.read_message(&packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]) {
                                        debug_assert!(handshake.is_handshake_finished());
                                        existing_connection.handshake_hash = get_handshake_hash(handshake);
                                        if payload_len != 8 {
                                            if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}: server hello payload was {payload_len} bytes, expected 8 (magic2)."); }
                                            break 'conn;
                                        }
                                        let server_magic2 = load_u64(&packet_memory_recv[0..8]);
                                        if !validate_magic2(server_magic2) {
                                            if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}: server chose magic2 {server_magic2:#x} which we did not offer."); }
                                            break 'conn;
                                        }
                                        if VERBOSE { println!("Connected to new server {:?}", handshake.get_remote_static().unwrap()); }
    
                                        // Borrow Checker crazyness required here.
                                        let new_state = new_connection_state_connected(None, *magic1, server_magic2, timestamp_ns);
                                        let old_state = std::mem::replace(&mut existing_connection.connection_state, new_state);

                                        let ConnectionState::SendingClientHello { handshake, .. } = old_state else { panic!(); };
                                        let ConnectionState::Connected(ref mut state) = existing_connection.connection_state else { panic!(); };
                                        state.cipher = Some(ConnectionCipherTriplet::new_from_old_init_only(handshake.into_stateless_transport_mode().expect("Cannot fail given assert above.")));
                                    } else {
                                        if OVERLY_VERBOSE {
                                            println!("Dropping from {connection_key:?} because this failed: let Ok(payload_len) = handshake.read_message(&packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..])");
                                        }
                                    }
                                } else {
                                    if OVERLY_VERBOSE {
                                        println!("Dropping from {connection_key:?} because this was false: first_six_bytes >> 16 == 0xffff_ffff && buf_len >= 6 + 32");
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
                                let non_virtual_nonce = crate::sequence::ReceiveSequences::default().candidate((first_six_bytes >> 16) as u32);
    
                                let mut can_decrypt = false;
                                // Optimization done here. It can never be cipher.old so we skip checking.
                                can_decrypt = cipher.current.read_message(non_virtual_nonce, &packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]).is_ok()
                                    || cipher.new.read_message(non_virtual_nonce, &packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]).is_ok();
                                if can_decrypt == false {
                                    break 'conn;
                                }
    
                                if VERBOSE { println!("Connected to new client {:?}", existing_connection.other_transport_identity); }
                                existing_connection.connection_state = new_connection_state_connected(Some(cipher.clone()), *magic1, *magic2, timestamp_ns);
                                // FALLTHROUGH TO CONNECTED
                            }
                            ConnectionState::Connected(_) => (),
                        }
//////// BEGIN ORDINARY PACKET HANDLING  ////////////////////////////////////////////////////////////////////
                        if let ConnectionState::Connected(state) = &mut existing_connection.connection_state {
                            let non_virtual_nonce = (first_six_bytes >> 16) as u32;
                            let nonce = state.receive_sequences.candidate(non_virtual_nonce);
    
                            let payload;
                            if let Some(cipher) = &mut state.cipher {
                                if let Ok(payload_len) = cipher.current.read_message(nonce as u64, &packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]) {
                                    payload = &packet_memory_recv[0..payload_len];
                                }
                                else if let Ok(payload_len) = cipher.old.read_message(nonce as u64, &packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]) {
                                    payload = &packet_memory_recv[0..payload_len];
                                }
                                else if let Ok(payload_len) = cipher.new.read_message(nonce as u64, &packet_memory_encrypted[6..buf_len], &mut packet_memory_recv[..]) {
                                    payload = &packet_memory_recv[0..payload_len];
                                    cipher.ratchet_forward_incoming();
                                }
                                else { break 'conn; }
                            }
                            else {
                                payload = &packet_memory_encrypted[6..buf_len];
                            }
                            // Packet TYPE is still determined by authenticated payload SIZE.
                            let is_ack = payload.len() == crate::ack::ACK_PAYLOAD_LEN;
                            if is_ack != crate::sequence::is_ack_space(non_virtual_nonce) { break 'conn; }
                            if !state.receive_sequences.commit(nonce) { break 'conn; }
                            // ACK nonces are not holes in the dense data stream.
                            if !is_ack { state.rx_tracker.on_packet(nonce, &mut state.stats); }
                            
                            if payload.len() < 517 && payload.len() != crate::ack::ACK_PAYLOAD_LEN {
                                if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}, payload < 517."); }
                                break 'conn;
                            }

                            // ACKs remain identified ONLY by exact decrypted packet size.
                            if payload.len() == crate::ack::ACK_PAYLOAD_LEN {
                                let bitmap_ack = if payload.len() == crate::ack::ACK_PAYLOAD_LEN {
                                    let Some(a) = crate::ack::BitmapAck::decode(payload) else { break 'conn; };
                                    if a.highest >= state.send_sequence_number { break 'conn; }
                                    state.peer_ack_delay_us = a.delay_us;
                                    Some(a)
                                } else { None };
                                if state.outage.since_ns.is_some() {
                                    // Only receipt of a RECENT outage probe proves round-trip recovery.
                                    // Replayed or withheld old authentic ACKs cannot extend the deadline.
                                    if !bitmap_ack.as_ref().is_some_and(|a| recent_outage_probe_acked(state, a, timestamp_ns)) { break 'conn; }
                                    resume_outage(state, &mut existing_connection.unreliable_send_buffer,
                                        &mut existing_connection.unreliable_fec, timestamp_ns, max_pps);
                                }
                                state.stats.ack_packets_received += 1;

                                let mut RTT_acc = 0u64;
                                let mut RTT_count = 0u64;
                                let mut ack_latency_ns = 0u64;
                                
                                let mut data_ack_progress = false;
                                let mut oldest_newly_acked_send_time: u64 = u64::MAX;
                                let relevant_ack = bitmap_ack.as_ref().map(|a| a.relevant(&state.packets_waiting_ack_field, &state.declared_lost_field[..]));
                                let indices = relevant_ack.iter().flat_map(crate::ack::BitmapAck::acknowledged);
                                for index in indices {
                                    let mut newly_acked = false;
                                    if index < state.send_sequence_number {
                                        state.highest_peer_acked = Some(state.highest_peer_acked.unwrap_or(index).max(index));
                                    }
                                    if index >= state.packets_waiting_ack_tail && index < state.send_sequence_number {
                                        let bit_index = index % PACKETS_WAITING_ACK_CAPACITY;
                                        if state.packets_waiting_ack_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0 {
                                            state.packets_waiting_ack_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                                            state.last_ack_received_time = timestamp_ns;
                                            state.outage.pending_since_ns = None;
                                            if let Some(t) = &mut loss_trace { t.outcome('A', existing_connection.two_byte_send_prefix, index, timestamp_ns); }

                                            newly_acked = true;
                                            let send_time_of_latest_ns = state.send_time(index);
                                            if send_time_of_latest_ns != 0 && send_time_of_latest_ns != u64::MAX {
                                                oldest_newly_acked_send_time = oldest_newly_acked_send_time.min(send_time_of_latest_ns);
                                            }
                                            
                                            if index == state.tu_probe_sequence_number {
                                                state.tu_probe_sequence_number = u64::MAX;
                                                state.last_sent_tu_probe_time_ns = 0;
                                                state.current_tu = state.tu_probe_size;
                                                state.tu_probe_size_advance *= 2;
                                                state.tu_probe_failed_count = 0;
                                            }
                                            else {
                                                state.ack_hole.acknowledged(index);
                                                data_ack_progress = true;
                                                assert!(state.packets_in_flight > 0, "packets_in_flight underflow");
                                                state.packets_in_flight -= 1;
                                            }
                                            
                                        }
                                    }
                                    else if index < state.packets_waiting_ack_tail && index + PACKETS_WAITING_ACK_CAPACITY >= state.packets_waiting_ack_tail {
                                        // Acked after it was declared lost: the declaration was spurious.
                                        let bit_index = index % PACKETS_WAITING_ACK_CAPACITY;
                                        let w = &mut state.declared_lost_field[(bit_index / 64) as usize];
                                        if *w & (1u64 << (bit_index % 64)) != 0 {
                                            *w &= !(1u64 << (bit_index % 64));
                                            state.stats.spurious_losses += 1;
                                            newly_acked = true;
                                            state.last_ack_received_time = timestamp_ns;
                                            state.outage.pending_since_ns = None;
                                            if index < state.outage.ignore_loss_before_seq { state.outage.ignored_spurious += 1; }
                                            if let Some(t) = &mut loss_trace { t.outcome('A', existing_connection.two_byte_send_prefix, index, timestamp_ns); }
                                        }
                                    }
                                    if newly_acked {
                                        let sent_ns = state.send_time(index);
                                        if sent_ns != 0 && sent_ns != u64::MAX {
                                            let raw = timestamp_ns.saturating_sub(sent_ns);
                                            ack_latency_ns = ack_latency_ns.max(raw);
                                            // A late sample is still a truthful RTT measurement.
                                            if bitmap_ack.as_ref().is_none_or(|a| index == a.sample_seq) {
                                                let delay = bitmap_ack.as_ref().map_or(0, |a| a.delay_us as u64 * 1000);
                                                if delay < raw {
                                                    RTT_acc += (raw - delay).max(100_000) / 100_000;
                                                    RTT_count += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                                if ack_latency_ns != 0 { state.loss_timer.observe(ack_latency_ns); }
                                if data_ack_progress {
                                    let before = state.congestion_event_time_ns;
                                    let context = loss_trace.as_ref().map(|_| cc_trace_context(state, timestamp_ns, &cc, max_pps));
                                    let cut = observe_ack_hole(state, timestamp_ns, &cc, max_pps);
                                    if state.congestion_event_time_ns != before {
                                        if let (Some(t), Some((seq, sent)), Some(context)) = (&mut loss_trace, cut, context) {
                                            t.cut(existing_connection.two_byte_send_prefix, seq, timestamp_ns, sent, "early", context);
                                        }
                                    }
                                }

                                let ce_feedback = bitmap_ack.as_ref().is_some_and(|a| crate::ack::update_ce_count(&mut state.peer_ce_count, a.ce_count));
                                if ecn_marked || ce_feedback {
                                    // A reordered ACK can advance CE even when all its packets were
                                    // acknowledged already. Do not consume that cumulative event silently.
                                    let anchor = if oldest_newly_acked_send_time != u64::MAX { oldest_newly_acked_send_time }
                                        else { bitmap_ack.as_ref().map_or(0, |a| state.send_time(a.sample_seq)) };
                                    if anchor != 0 && anchor != u64::MAX {
                                        state.ecn_congestion_received = true;
                                        state.ecn_oldest_send_time = anchor;
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
                            // This is not an ack packet.

                            // Authentication/replay admission precedes allocation, but positive receipt
                            // follows it. A memory-erased packet must look lost to the sender.
                            let mut memory_erased = false;

                            // if OVERLY_VERBOSE { println!("Got data from {:?}  data: {:?}", existing_connection.other_transport_identity, payload); }
                            
                            let mut remaining_payload = payload;
                            while let Some((header, plain_header_size)) = read_fragment_header(remaining_payload) {

                                if header & 1 != 0 {
                                    // Extended fragment (FEC); see STP_FEC_FRAGMENT_HEADER_SIZE.
                                    let data_len = ((header >> 18) & 0x3fff) as usize;
                                    let Some(fec_header_size) = fec_fragment_header_size(remaining_payload) else { break; };
                                    if remaining_payload.len() < fec_header_size + data_len {
                                        if OVERLY_VERBOSE { println!("Error, extended fragment extends beyond end of packet received from {connection_key:?}. Disconnecting..."); }
                                        connections_map.remove(&connection_key);
                                        break 'conn;
                                    }
                                    let word1 = load_u64(&remaining_payload[8..16]);
                                    let kind = (word1 >> 48) & 0xff;
                                    let segment = if kind == STP_EXT_KIND_SEGMENT_FEC {
                                        Some(FecSegment { root: load_u16(&remaining_payload[16..18]),
                                            total: load_u32(&remaining_payload[18..22]), offset: load_u32(&remaining_payload[22..26]) })
                                    } else { None };
                                    let data = &remaining_payload[fec_header_size..fec_header_size + data_len];
                                    remaining_payload = &remaining_payload[fec_header_size + data_len..];
                                    if kind != STP_EXT_KIND_FEC && kind != STP_EXT_KIND_GROUPED_FEC && kind != STP_EXT_KIND_SEGMENT_FEC { continue; } // unknown kind: skip it
                                    let package_id = ((header >> 2) & 0xffff) as u16;
                                    let block_id = (header >> 32) as u32;
                                    let message_len = (word1 & 0xffff_ffff) as usize;
                                    let block_bytes = ((word1 >> 32) & 0xffff) as usize;
                                    if message_len > MAX_JUMBOGRAM_LEN {
                                        if VERBOSE { println!("Error, FEC message length ({message_len}) exceeds MAX_JUMBOGRAM_LEN from {connection_key:?}. Disconnecting..."); }
                                        connections_map.remove(&connection_key);
                                        break 'conn;
                                    }
                                    let Some(layout) = crate::fec::MessageLayout::new(message_len, block_bytes) else { continue; };
                                    if !valid_fec_symbol(layout, block_id, data.len()) { continue; }
                                    if (kind == STP_EXT_KIND_GROUPED_FEC) != (layout.groups > 1) { continue; }
                                    if let Some(segment) = segment {
                                        if !segment.valid(message_len) || segment.root == package_id ||
                                            segment.root as usize % 1024 == package_id as usize % 1024 { continue; }
                                        let root_idx = segment.root as usize % existing_connection.unreliable_reassembly.len();
                                        let fec_root = &mut existing_connection.unreliable_fec[root_idx];
                                        if fec_root.in_use() && fec_root.package_id != segment.root {
                                            if (segment.root.wrapping_sub(fec_root.package_id) as i16) < 0 { continue; }
                                            *fec_root = FecRecvSlot::default();
                                        }
                                        if !existing_connection.unreliable_reassembly[root_idx].admit_segment(segment, layout, block_id, data.len(), timestamp_ns, &existing_connection.receive_budget) {
                                            memory_erased = true; continue;
                                        }
                                    }
                                    let slot_idx = package_id as usize % existing_connection.unreliable_fec.len();
                                    {
                                        // Same eviction rule as plain packages below, across both rings.
                                        let slot = &mut existing_connection.unreliable_fec[slot_idx];
                                        if slot.in_use() && slot.package_id != package_id {
                                            if (package_id.wrapping_sub(slot.package_id) as i16) < 0 { state.stats.rx_stale_fragments += 1; continue; }
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
                                        if (plain.completed || plain.total_len.is_some() || !plain.received.is_empty()) && plain.package_id != package_id && (package_id.wrapping_sub(plain.package_id) as i16) > 0 {
                                            if !plain.completed { state.stats.rx_partial_evicted += 1; }
                                            state.stats.rx_partial_evicted_bytes += plain.bytes_received();
                                            *plain = ReassemblySlot::new();
                                        }
                                    }
                                    if layout.k > FEC_INLINE_MAX_BLOCKS && !existing_connection.unreliable_fec[slot_idx].in_use()
                                        && fec_workers.load(std::sync::atomic::Ordering::Acquire) >= MAX_FEC_DECODE_WORKERS {
                                        let grace = fec_inactive_grace_ns(state.RTT_mean, true);
                                        state.stats.fec_decode_preemptions += retire_inactive_fec_workers(&mut existing_connection.unreliable_fec, timestamp_ns, grace, true);
                                    }
                                    let refused_before = existing_connection.unreliable_fec[slot_idx].admission_refused;
                                    let dropped_before = existing_connection.unreliable_fec[slot_idx].ingress_dropped;
                                    if let Some((message, mut _reservation)) = fec_receive_block(&mut existing_connection.unreliable_fec[slot_idx], connection_key, package_id, message_len, block_bytes, block_id, data, &fec_done_tx, &fec_workers, &existing_connection.receive_budget) {
                                        let completed = if let Some(segment) = segment {
                                            let root_idx = segment.root as usize % existing_connection.unreliable_reassembly.len();
                                            _reservation.shrink(message.capacity());
                                            existing_connection.unreliable_reassembly[root_idx].finish_segment(segment, &message)
                                        } else { Some((message, _reservation)) };
                                        if let Some((message, reservation)) = completed {
                                            state.stats.rx_messages_completed += 1;
                                            receive_queue.push_reserved(connection_key, message, MAX_RECV_QUEUE_BYTES, Some(reservation));
                                        }
                                    }
                                    memory_erased |= existing_connection.unreliable_fec[slot_idx].ingress_dropped != dropped_before;
                                    state.stats.fec_ingress_dropped_blocks += existing_connection.unreliable_fec[slot_idx].ingress_dropped - dropped_before;
                                    if !refused_before && existing_connection.unreliable_fec[slot_idx].admission_refused {
                                        state.stats.fec_decode_admission_refusals += 1;
                                    }
                                    continue;
                                }
                                
                                let is_reliable = header & 1 != 0;
                                let is_fin = header & 2 != 0;
                                let package_id = (header >> 2) & 0xffff;
                                let frag_len = (header >> 18) & 0x3fff;
                                let frag_offset = header >> 32;
                                
                                if (remaining_payload.len() as u64) < plain_header_size as u64 + frag_len {
                                    if OVERLY_VERBOSE { println!("Error, frag_len ({frag_len:?}) extends beyond end of packet received from {connection_key:?}. Disconnecting..."); }
                                    connections_map.remove(&connection_key);
                                    break 'conn;
                                }
                                let frag_data = &remaining_payload[plain_header_size..(plain_header_size+frag_len as usize)];
                                remaining_payload = &remaining_payload[(plain_header_size+frag_len as usize)..];

                                if frag_offset + frag_len > u32::MAX as u64 {
                                    if OVERLY_VERBOSE { println!("Error, frag_offset + frag_len overflows u32 from {connection_key:?}. Disconnecting..."); }
                                    connections_map.remove(&connection_key);
                                    break 'conn;
                                }
                                if frag_offset + frag_len > MAX_JUMBOGRAM_LEN as u64 {
                                    if VERBOSE { println!("Error, frag_offset + frag_len ({}) exceeds MAX_JUMBOGRAM_LEN from {connection_key:?}. Disconnecting...", frag_offset + frag_len); }
                                    connections_map.remove(&connection_key);
                                    break 'conn;
                                }

                                //if OVERLY_VERBOSE { println!("Fragment from {:?}: R:{} F:{} ID:{} L:{} O:{}", connection_key, is_reliable, is_fin, package_id, frag_len, frag_offset); }
                                
                                let package_id = package_id as u16;
                                let slot_idx = package_id as usize % existing_connection.unreliable_reassembly.len();

                                // A slot is reused every 1024 packages, and insert() happily merges fragments
                                // that are adjacent without overlapping, so a partial package left behind by
                                // packet loss would be completed by a later package's fragments into one
                                // spliced message. The slot remembers whose fragments it holds: a newer package
                                // evicts it, and a late fragment of an older package is dropped.
                                // @Todo: Make the package ID virtual. The receiver keeps the high bits of the
                                // newest ID it has seen and widens each 16-bit ID to the 64-bit value nearest
                                // it, and the slot stores that. Until then, a partial package that sits in its
                                // slot for a full 65536-package wrap can still be spliced with the package that
                                // wraps around onto its ID. The nonce above has the same @Todo.
                                {
                                    let slot = &mut existing_connection.unreliable_reassembly[slot_idx];
                                    let slot_in_use = slot.completed || slot.total_len.is_some() || !slot.received.is_empty();
                                    if slot_in_use && slot.package_id != package_id {
                                        if (package_id.wrapping_sub(slot.package_id) as i16) < 0 { state.stats.rx_stale_fragments += 1; continue; }
                                        if !slot.completed { state.stats.rx_partial_evicted += 1; }
                                        state.stats.rx_partial_evicted_bytes += slot.bytes_received();
                                        *slot = ReassemblySlot::new();
                                    }
                                    slot.package_id = package_id;
                                    // A newer package also evicts an FEC package in the same slot index.
                                    let fec = &mut existing_connection.unreliable_fec[slot_idx];
                                    if fec.in_use() && fec.package_id != package_id && (package_id.wrapping_sub(fec.package_id) as i16) > 0 {
                                        if !matches!(fec.state, FecRecvState::Done) {
                                            state.stats.rx_partial_evicted += 1;
                                            state.stats.rx_partial_evicted_bytes += fec.bytes_received();
                                        }
                                        *fec = FecRecvSlot::default();
                                    }
                                }

                                if !existing_connection.unreliable_reassembly[slot_idx].admit(frag_offset as usize, frag_data.len(), &existing_connection.receive_budget) { memory_erased = true; continue; }
                                let (mut success, mut complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                if !success {
                                    state.stats.rx_insert_failures += 1;
                                    existing_connection.unreliable_reassembly[slot_idx] = ReassemblySlot::new();
                                    existing_connection.unreliable_reassembly[slot_idx].package_id = package_id;
                                    if !existing_connection.unreliable_reassembly[slot_idx].admit(frag_offset as usize, frag_data.len(), &existing_connection.receive_budget) { memory_erased = true; continue; }
                                    (success, complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                    assert!(success);
                                }
                                existing_connection.unreliable_reassembly[slot_idx].last_segment_ns = timestamp_ns;
                                if complete {
                                    state.stats.rx_messages_completed += 1;
                                    let reservation = existing_connection.unreliable_reassembly[slot_idx].reservation.take();
                                    let completed = existing_connection.unreliable_reassembly[slot_idx].take_complete();
                                    receive_queue.push_reserved(connection_key, completed, MAX_RECV_QUEUE_BYTES, reservation);
                                }
                            }

                            if !memory_erased {
                                state.ack_receiver.receive_with_rtt(nonce, timestamp_ns, ecn_marked, &mut state.ack_timer, state.stats.rtt_us, buf_len);
                            }

//////// END ORDINARY PACKET HANDLING  ////////////////////////////////////////////////////////////////////
                        }
                    } } // <- break 'conn lands here
                }
//////// END RECEIVE ////////////////////////////////////////////////////////////////////////

                // Messages finished by FEC decoder threads.
                while let Ok((key, package_id, message, mut _reservation)) = fec_done_rx.try_recv() {
                    if let Some(conn) = connections_map.get_mut(&key) {
                        let idx = package_id as usize % conn.unreliable_fec.len();
                        let slot = &mut conn.unreliable_fec[idx];
                        if slot.package_id != package_id || !slot.in_use() { continue; } // evicted worker completion
                        let tail = monotonic_clock_ns().saturating_sub(slot.last_block_ns);
                        slot.state = FecRecvState::Done;
                        let completed = if let Some(segment) = slot.segment {
                            let root_idx = segment.root as usize % conn.unreliable_reassembly.len();
                            _reservation.shrink(message.capacity());
                            conn.unreliable_reassembly[root_idx].finish_segment(segment, &message)
                        } else { Some((message, _reservation)) };
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            if completed.is_some() { c.stats.rx_messages_completed += 1; }
                            c.stats.fec_decode_last_tail_ns = tail;
                            c.stats.fec_decode_max_tail_ns = c.stats.fec_decode_max_tail_ns.max(tail);
                        }
                        if let Some((message, reservation)) = completed {
                            receive_queue.push_reserved(key, message, MAX_RECV_QUEUE_BYTES, Some(reservation));
                        }
                    }
                }

//////// BEGIN SEND ////////////////////////////////////////////////////////////////////////
                let current_time_now_ns = monotonic_clock_ns();
                // Missing unreliable tails must not hold decoder admission forever.
                // Scan at most ten times/second, not once per incoming packet.
                if current_time_now_ns.saturating_sub(fec_sweep_ns) >= 100_000_000 {
                    for conn in connections_map.values_mut() {
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            let grace = if c.outage.since_ns.is_some() || current_time_now_ns.saturating_sub(c.last_ack_received_time) >= OUTAGE_ACK_SILENCE_NS {
                                OUTAGE_TIMEOUT_NS
                            } else { fec_inactive_grace_ns(c.RTT_mean, false) };
                            c.stats.fec_decode_timeouts += retire_inactive_fec_workers(&mut conn.unreliable_fec, current_time_now_ns, grace, false);
                            retire_inactive_segment_roots(&mut conn.unreliable_reassembly, current_time_now_ns, grace);
                        }
                    }
                    fec_sweep_ns = current_time_now_ns;
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
                connections_map.retain(|connection_key, connection_tracking_data| {match &mut connection_tracking_data.connection_state {
                    ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns, hello_packet_payload } => {
                        if *last_sent_time_ns + 2_500_000_000 < current_time_now_ns {
                            udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &hello_packet_payload, Dscp::Af21, false);
                            if *last_sent_time_ns == 0 { // cheeky optimization
                                *last_sent_time_ns = current_time_now_ns - 2_500_000_000 + 10_000_000;
                            } else {
                                *last_sent_time_ns = current_time_now_ns;
                            }
                            return true;
                        }
                        if connection_tracking_data.creation_time_ns + 30_000_000_000 < current_time_now_ns {
                            return false;
                        }
                    }
                    ConnectionState::SendingClientHello { magic1, last_sent_time_ns, hello_packet_payload, handshake } => {
                        if *last_sent_time_ns + 2_500_000_000 < current_time_now_ns {
                            udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &hello_packet_payload, Dscp::Af21, false);
                            if *last_sent_time_ns == 0 { // cheeky optimization
                                *last_sent_time_ns = current_time_now_ns - 2_500_000_000 + 10_000_000;
                            } else {
                                *last_sent_time_ns = current_time_now_ns;
                            }
                            return true;
                        }
                        if connection_tracking_data.creation_time_ns + 30_000_000_000 < current_time_now_ns {
                            return false;
                        }
                    }
                    ConnectionState::SendingServerHelloPlaintext { magic2: _, last_sent_time_ns, hello_packet_payload } => {
                        if *last_sent_time_ns + 2_500_000_000 < current_time_now_ns {
                            udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &hello_packet_payload, Dscp::Af21, false);
                            if *last_sent_time_ns == 0 { // cheeky optimization
                                *last_sent_time_ns = current_time_now_ns - 2_500_000_000 + 10_000_000;
                            } else {
                                *last_sent_time_ns = current_time_now_ns;
                            }
                            return true;
                        }
                        if connection_tracking_data.creation_time_ns + 15_000_000_000 < current_time_now_ns {
                            return false;
                        }
                    }
                    ConnectionState::SendingServerHello { magic1, magic2: _, cipher, last_sent_time_ns, hello_packet_payload } => {
                        if *last_sent_time_ns + 2_500_000_000 < current_time_now_ns {
                            udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &hello_packet_payload, Dscp::Af21, false);
                            if *last_sent_time_ns == 0 { // cheeky optimization
                                *last_sent_time_ns = current_time_now_ns - 2_500_000_000 + 10_000_000;
                            } else {
                                *last_sent_time_ns = current_time_now_ns;
                            }
                            return true;
                        }
                        if connection_tracking_data.creation_time_ns + 15_000_000_000 < current_time_now_ns {
                            return false;
                        }
                    }
                    ConnectionState::Connected(state) => {
                        debug_assert!(state.magic2 != 0, "Connection entered Connected state without negotiating magic2");
                        if OutageState::expired(current_time_now_ns, state.last_ack_received_time) {
                            if VERBOSE { println!("Disconnected from: {:?}.", connection_tracking_data.other_transport_identity); }
                            return false; // connection timeout
                        }
                        
                        if current_time_now_ns > state.ack_timer {
                            { // send ack
                                let mut o = 0;
                                let virtual_nonce = state.send_ack_sequence_number;
                                o += connection_tracking_data.two_byte_send_prefix.write_to(&mut packet_memory_send[o..]);
                                o += crate::sequence::to_wire(virtual_nonce).write_to(&mut packet_memory_send[o..]);
                                state.send_ack_sequence_number = state.send_ack_sequence_number.checked_add(1).expect("ACK nonce space exhausted");
                                
                                let a = state.ack_receiver.ack(current_time_now_ns);
                                state.stats.ack_delay_us_max = state.stats.ack_delay_us_max.max(a.delay_us);
                                let encoded = a.encode();
                                let ack_payload = &encoded[..];
                                if let Some(cipher) = &mut state.cipher { o += cipher.current.write_message(virtual_nonce, ack_payload, &mut packet_memory_send[o..]).unwrap(); }
                                else { o += ack_payload.write_to(&mut packet_memory_send[o..]); }
                                state.ack_receiver.sent(current_time_now_ns);
                                state.stats.ack_packets_sent += 1;
                                state.stats.ack_bytes_sent += o as u64;
                                #[cfg(test)]
                                datagram_expectation.set(("ack", Some(crate::ack::ACK_PAYLOAD_LEN + total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap())));
                                udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_send[..o], Dscp::Af21, false);
                                state.ack_timer = u64::MAX;
                            }
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
                                store_u16(&mut packet_memory_encrypted[0..2], connection_tracking_data.two_byte_send_prefix);
                                store_u32(&mut packet_memory_encrypted[2..6], crate::sequence::to_wire(seq));
                                // Authenticated null fragment: elicits a bitmap ACK but creates no message.
                                let probe_payload_len = state.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                                packet_memory_send[..probe_payload_len].fill(0xff);
                                let data = &packet_memory_send[..probe_payload_len];
                                let packet_len = if let Some(cipher) = &mut state.cipher {
                                    cipher.current.write_message(seq, &data, &mut packet_memory_encrypted[6..]).unwrap()
                                } else {
                                    packet_memory_encrypted[6..6+data.len()].copy_from_slice(&data);
                                    data.len()
                                };
                                #[cfg(test)]
                                datagram_expectation.set(("outage", Some(state.current_tu as usize)));
                                let send_time = udp_send_with_congestion_and_dscp(socket,
                                    connection_tracking_data.other_ip, connection_tracking_data.other_port,
                                    &packet_memory_encrypted[..6+packet_len], Dscp::Af21, false);
                                state.account_send(send_time);
                                state.outage.probes[(seq % 8) as usize] = (seq, send_time);
                                state.packets_in_flight += 1;
                                state.stats.packets_sent += 1;
                                state.stats.bytes_sent += (6 + packet_len) as u64;
                                state.last_sent_data_packet = send_time;
                                state.packet_since_last_print += 1;
                                if let Some(t) = &mut loss_trace { t.sent(connection_tracking_data.two_byte_send_prefix, seq, send_time, &data); }
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
                                    let (old_rate, _) = cc_rate(current_t, state.congestion_event_rate_upps, old_k, state.cc_startup_done);
                                    let mut lo = if new_k >= old_k { current_t } else { 0u64 };
                                    let mut hi = if new_k >= old_k { current_t * 2 + new_k } else { current_t };
                                    for _ in 0..64 {
                                        let mid = lo + (hi - lo) / 2;
                                        if cc_rate(mid, state.congestion_event_rate_upps, new_k, state.cc_startup_done).0 >= old_rate {
                                            hi = mid;
                                        } else {
                                            lo = mid + 1;
                                        }
                                    }
                                    state.congestion_event_time_ns = current_time_now_ns.saturating_sub(hi);
                                    if state.is_app_limited {
                                        state.app_limit_time_offset = hi;
                                    }
                                }
                            }
                        }

                        let time_to_bandwidth_recovery = cc.recovery_rtts * (state.RTT_mean as u64 * 100_000);


                        // ECN congestion event: the receiver saw CE-marked packets and relayed it via the ack's IP header
                        if take_ecn_signal(state, cc.event_guard_rtts) {
                            let send_dt = state.ecn_oldest_send_time - state.congestion_event_time_ns;
                            let send_t_factor = send_dt as f64 / time_to_bandwidth_recovery as f64;
                            let (_, send_mode) = cc_rate(send_dt, state.congestion_event_rate_upps, time_to_bandwidth_recovery, state.cc_startup_done);
                            let discover_dt = if send_mode == 'P' { (time_to_bandwidth_recovery + send_dt) / 2 } else { send_dt };
                            let mut discovered = cc_rate(discover_dt, state.congestion_event_rate_upps, time_to_bandwidth_recovery, state.cc_startup_done).0;
                            if send_mode == 'I' {
                                discovered = cc_rate(send_dt.saturating_sub((state.RTT_mean as f64 * 100_000.0 * cc.startup_backoff_rtts) as u64), state.congestion_event_rate_upps, time_to_bandwidth_recovery, false).0;
                            } else if send_mode == 'G' || send_mode == 'S' {
                                let r_pg = (state.congestion_event_rate_upps as f64 * cc.rate_pg) as u64;
                                discovered = r_pg + ((discovered.saturating_sub(r_pg)) as f64 * 0.5) as u64;
                            }
                            // Discovery must reflect a locally capped sender as well: otherwise
                            // a loss above a stale curve anchor would not lower actual pacing.
                            state.congestion_event_rate_upps = local_rate_limit(discovered, max_pps);
                            state.congestion_event_time_ns = current_time_now_ns;
                            state.app_limit_time_offset = 0;
                            state.cc_startup_done = true;
                            println!("congestion event ECN CE ...  rate discovered: {} pps  sent:{send_mode}@{send_t_factor:.2}", state.congestion_event_rate_upps as f64 / 1000000.0);
                        }

                        let time_to_considered_dropped = state.loss_timer.timeout_ns(
                            state.RTT_mean as u64 * 100_000,
                            current_time_now_ns.saturating_sub(state.last_ack_received_time), &cc);
                        
                        connection_tracking_data.unreliable_send_buffer.set_time(current_time_now_ns, state.RTT_mean as u64 * 100_000);
                        // every send site (data loop, tu probe, keepalive, both ack paths) gates on ring space, so head never laps tail
                        assert!(state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY);
                        while state.packets_waiting_ack_tail < state.send_sequence_number {
                            let bit_index = state.packets_waiting_ack_tail % PACKETS_WAITING_ACK_CAPACITY;
                            // This slot now describes the tail packet (set below if declared lost).
                            state.declared_lost_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                            if state.packets_waiting_ack_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0 {
                                let mut send_time = state.send_time(state.packets_waiting_ack_tail);
                                if send_time != 0 && (state.RTT_mean == 0 || (current_time_now_ns - send_time) < time_to_considered_dropped) {
                                    break;
                                }
                                if send_time == 0 {
                                    let history_ns = 4_295_000_000;
                                    send_time = current_time_now_ns.saturating_sub(history_ns);
                                }
                                
                                if state.packets_waiting_ack_tail == state.tu_probe_sequence_number {
                                    state.tu_probe_sequence_number = u64::MAX;
                                    state.tu_probe_size_advance /= 5;
                                    state.tu_probe_failed_count += 1;
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
                                        apply_loss_congestion(state, send_time, current_time_now_ns, &cc, max_pps);
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
                            connection_tracking_data.unreliable_send_buffer.fec_on_packet_finalized(state.packets_waiting_ack_tail, lost);
                            state.packets_waiting_ack_tail += 1;
                        }
                        
                        state.congestion_event_rate_upps = state.congestion_event_rate_upps.max(cc.rate_floor_upps);
                        
                        let (allowed_bandwidth_upps, cubic_mode) = if state.is_app_limited {
                            // Freeze at the exact active age, including during recovery.
                            // A minimum age of two RTTs would spuriously grow an idle curve.
                            (cc_rate(state.app_limit_time_offset, state.congestion_event_rate_upps, time_to_bandwidth_recovery, state.cc_startup_done).0, 'A')
                        } else {
                            cc_rate(current_time_now_ns - state.congestion_event_time_ns, state.congestion_event_rate_upps, time_to_bandwidth_recovery, state.cc_startup_done)
                        };
                        // A local pacing ceiling is not evidence of network congestion.
                        let allowed_bandwidth_upps = local_rate_limit(allowed_bandwidth_upps.max(cc.rate_floor_upps), max_pps);
                        state.stats.cc_rate_upps = allowed_bandwidth_upps;
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
                        // This is some Unity Game developer level crap approximation but it will have to do.
                        let elapsed_ns = current_time_now_ns + 1 - state.last_sent_could_have_sent_data_packet.max(state.last_ack_received_time.saturating_sub(ACK_BUFFER_TIME_NS));
                        let grant = send_pacing_grant(elapsed_ns, time_between_sends_ns, state.send_pacer_acc_ns);
                        let mut packet_send_allowance_now = grant.packets;
                        let pacing_first_sequence = state.send_sequence_number;
                        state.stats.pacing_commanded_packets += packet_send_allowance_now;
                        let could_have_sent = packet_send_allowance_now != 0;
                        
                        // ring space is checked live at each send site below so the head can never lap the tail within a tick

                        state.current_tu = state.current_tu.min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                        if state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && state.current_tu != ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64 && state.tu_probe_sequence_number == u64::MAX && state.last_sent_tu_probe_time_ns + (state.tu_probe_failed_count.min(50)*state.tu_probe_failed_count.min(50)*250_000_000).max(time_between_sends_ns) < current_time_now_ns {
                            state.tu_probe_size_advance = state.tu_probe_size_advance.max(1).min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                            state.tu_probe_size = (state.current_tu + state.tu_probe_size_advance).min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                            let payload_size = state.tu_probe_size as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                            let null_bytes = [0xffu8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];
                            
                            state.tu_probe_sequence_number = state.send_sequence_number;
                        
                            let virtual_nonce = state.send_sequence_number;
                            store_u16(&mut packet_memory_encrypted[0..2], connection_tracking_data.two_byte_send_prefix);
                            store_u32(&mut packet_memory_encrypted[2..6], crate::sequence::to_wire(virtual_nonce));

                            let packet_len;
                            if let Some(cipher) = &mut state.cipher {
                                packet_len = cipher.current.write_message(virtual_nonce, &null_bytes[0..payload_size], &mut packet_memory_encrypted[6..]).unwrap();
                            }
                            else {
                                (&null_bytes[0..payload_size]).write_to(&mut packet_memory_encrypted[6..]);
                                packet_len = payload_size;
                            }

                            #[cfg(test)]
                            datagram_expectation.set(("mtu_probe", Some(state.tu_probe_size as usize)));
                            let send_time_ns = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..6+packet_len], Dscp::Af21, false);
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            state.account_send(send_time_ns);
                            state.last_sent_tu_probe_time_ns = send_time_ns;
                            state.packet_since_last_print += 1;
                        }
                        
                        let payload_size = state.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                        
                        if state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && state.last_sent_data_packet + 15_000_000_000/3 < current_time_now_ns {
                            let null_bytes = [0xffu8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];
                        
                            let virtual_nonce = state.send_sequence_number;
                            store_u16(&mut packet_memory_encrypted[0..2], connection_tracking_data.two_byte_send_prefix);
                            store_u32(&mut packet_memory_encrypted[2..6], crate::sequence::to_wire(virtual_nonce));

                            let packet_len;
                            if let Some(cipher) = &mut state.cipher {
                                packet_len = cipher.current.write_message(virtual_nonce, &null_bytes[0..payload_size], &mut packet_memory_encrypted[6..]).unwrap();
                            }
                            else {
                                (&null_bytes[0..payload_size]).write_to(&mut packet_memory_encrypted[6..]);
                                packet_len = payload_size;
                            }

                            #[cfg(test)]
                            datagram_expectation.set(("keepalive", Some(state.current_tu as usize)));
                            let send_time_ns = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..6+packet_len], Dscp::Af21, false);
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            state.account_send(send_time_ns);
                            state.last_sent_data_packet = current_time_now_ns; // We use the older time here so the pacer skips less packets.
                            state.packets_in_flight += 1;
                            state.stats.packets_sent += 1;
                            state.stats.bytes_sent += 6 + packet_len as u64;
                            state.max_in_flight_since_last_print = state.max_in_flight_since_last_print.max(state.packets_in_flight);
                            packet_send_allowance_now = packet_send_allowance_now.saturating_sub(1);
                            state.packet_since_last_print += 1;
                        }

                        connection_tracking_data.unreliable_send_buffer.set_rate(rate_mul_div(allowed_bandwidth_upps, payload_size as u64, 1_000_000));
                        {
                            let buf = &mut connection_tracking_data.unreliable_send_buffer;
                            let (lost, spurious) = fec_learning_counters(state);
                            let a = buf.fec_adaptive.get_or_insert_with(|| crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, current_time_now_ns, state.stats.packets_sent, lost.saturating_sub(spurious)));
                            a.on_tick(current_time_now_ns, state.stats.packets_sent, lost, spurious);
                            buf.set_overhead();
                            if record_fec_messages && buf.fec_record.is_none() { buf.fec_record = Some(Vec::new()); }
                        }
                        let mut unreliable_payload_size = 0;
                        while state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && packet_send_allowance_now > 0 && state.packets_in_flight < allowed_packets_in_flight && {
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            unreliable_payload_size = connection_tracking_data.unreliable_send_buffer.fill_packet(&mut packet_memory_send[0..payload_size]);
                            unreliable_payload_size > 0
                        } {
                        
                            let virtual_nonce = state.send_sequence_number;
                            store_u16(&mut packet_memory_encrypted[0..2], connection_tracking_data.two_byte_send_prefix);
                            store_u32(&mut packet_memory_encrypted[2..6], crate::sequence::to_wire(virtual_nonce));

                            let packet_len;
                            if let Some(cipher) = &mut state.cipher {
                                packet_len = cipher.current.write_message(virtual_nonce, &packet_memory_send[0..unreliable_payload_size], &mut packet_memory_encrypted[6..]).unwrap();
                            }
                            else {
                                (&packet_memory_send[0..unreliable_payload_size]).write_to(&mut packet_memory_encrypted[6..]);
                                packet_len = unreliable_payload_size;
                            }

                            should_sleep = false;
                            let test_drop = if test_drop_burst_left > 0 { test_drop_burst_left -= 1; true } else {
                                test_drop_ppm != 0 && {
                                    test_drop_rng ^= test_drop_rng << 13; test_drop_rng ^= test_drop_rng >> 7; test_drop_rng ^= test_drop_rng << 17;
                                    test_drop_rng % 1_000_000 < test_drop_ppm / test_drop_burst
                                } && { test_drop_burst_left = test_drop_burst - 1; true }
                            };
                            if test_drop { state.stats.test_dropped += 1; }
                            #[cfg(test)]
                            datagram_expectation.set(("data", Some(state.current_tu as usize)));
                            let send_time_ns = if test_drop { monotonic_clock_ns() }
                            else { udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..6+packet_len], connection_tracking_data.unreliable_send_buffer.last_dscp, false) };
                            state.account_send(send_time_ns);
                            if let Some(t) = &mut loss_trace { t.sent(connection_tracking_data.two_byte_send_prefix, virtual_nonce, send_time_ns, &packet_memory_send[..payload_size]); }
                            if let Some(a) = &mut connection_tracking_data.unreliable_send_buffer.fec_adaptive {
                                a.on_data_sent(virtual_nonce);
                            }
                            state.last_sent_data_packet = current_time_now_ns; // We use the older time here so the pacer skips less packets.
                            state.packets_in_flight += 1;
                            state.stats.packets_sent += 1;
                            state.stats.bytes_sent += 6 + packet_len as u64;
                            state.max_in_flight_since_last_print = state.max_in_flight_since_last_print.max(state.packets_in_flight);
                            packet_send_allowance_now = packet_send_allowance_now.saturating_sub(1);
                            state.packet_since_last_print += 1;
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
                            let mode = cubic_mode;
                            let mean = state.RTT_mean as f64 / 10.0;
                            let ack_pace = state.ack_pace_estimate as f64 / 10.0;
                            let n = (state.RTT_sample_cursor as usize).min(16);
                            if OVERLY_VERBOSE { println!("{mode} RTT (ms): mean={mean:.1} ack_pace={ack_pace:.1} (n={n}) --- TU: {} B  failed probes: {} --- target: {} pps   in flight: {}/{} (max {})  pacing: {} us  lost/sent: {}/{}", state.current_tu, state.tu_probe_failed_count, allowed_bandwidth_upps as f64 / 1000000.0, state.packets_in_flight, allowed_packets_in_flight, state.max_in_flight_since_last_print, time_between_sends_ns / 1000, state.packet_lost_since_last_print, state.packet_since_last_print); }
                            state.packet_since_last_print = 0;
                            state.packet_lost_since_last_print = 0;
                            state.max_in_flight_since_last_print = state.packets_in_flight;
                        }
                    }
                } true});

//////// END SEND ////////////////////////////////////////////////////////////////////////

                // Idle: sleep instead of spinning on a core. 150us is well below
                // any packet-arrival timescale here and keeps the thread parked when quiet.
                if should_sleep {
                    std::thread::sleep(std::time::Duration::from_nanos(150_000));
                }
            }
        }
    });

    NetworkThreadHandle {
        inner,
        thread: Some(thread),
        join_on_drop: options.loss_trace.is_some(),
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
    if k_ns == 0 { return (r_max.min(MAX_CC_RATE_UPPS), 'R'); }
    let t = t_ns as f64;
    let r = r_max as f64;
    let k = k_ns as f64;
    let drop = r * (1.0 - cc.beta);
    let rtt_seconds = k / (cc.recovery_rtts as f64 * 1e9);
    let floor = cc.min_growth_uppsps;
    let ceiling = cc.max_growth_uppsps;
    let min_growth = floor / 1e9 * t;
    let linear_cap_slope = ceiling / 1e9;
    let finish = |rate: u64, mode| {
        let absolute = r * cc.beta + (floor + ceiling) / 1e9 * t;
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


/// Hands `req` to the network thread and returns what it last produced.
///
/// The network thread is a separate OS thread and `state` is the handshake: wait
/// for it to be idle, hand it the push queue, mark it runnable, then wait for it
/// to finish and mark itself idle again. If that thread died or wedged, waiting
/// would block forever -- which is how Zebra's shutdown drain got stuck, keeping
/// `zebrad.com` alive after its window was closed. So both waits are bounded:
/// past the deadline the thread is treated as gone and `None` is returned,
/// leaving the caller's view of the connections untouched.
pub fn service_connections(network_thread_handle: &NetworkThreadHandle, mut req: NetworkThreadPush) -> Option<NetworkThreadPull> {
    // The exchange normally takes microseconds; past this the network thread
    // is not answering.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

    while network_thread_handle.inner.state.load(std::sync::atomic::Ordering::Acquire) != 0 {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        // Sleep-poll: spinning here burned a core per caller for as long as the
        // network thread took to answer.
        std::thread::sleep(std::time::Duration::from_micros(25));
    }

    #[allow(unsafe_code)]
    unsafe {
        std::mem::swap(&mut *network_thread_handle.inner.push.get(), &mut req);
    }

    network_thread_handle.inner.state.store(1, std::sync::atomic::Ordering::Release);
    if let Some(thread) = &network_thread_handle.thread { thread.thread().unpark(); }

    while network_thread_handle.inner.state.load(std::sync::atomic::Ordering::Acquire) != 0 {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_micros(25));
    }

    let mut resp = NetworkThreadPull::default();

    #[allow(unsafe_code)]
    unsafe {
        std::mem::swap(&mut *network_thread_handle.inner.pull.get(), &mut resp);
    }

    Some(resp)
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

#[derive(Debug, Default)]
struct OutageState {
    since_ns: Option<u64>,
    pending_since_ns: Option<u64>,
    next_probe_ns: u64,
    probe_interval_ns: u64,
    resume_rate_upps: u64,
    ignore_loss_before_seq: u64,
    probes: [(u64, u64); 8],
    max_probe_age_ns: u64,
    ignored_losses: u64,
    ignored_spurious: u64,
}
fn fec_learning_counters(state: &ConnectionStateConnected) -> (u64, u64) {
    (state.stats.packets_lost.saturating_sub(state.outage.ignored_losses),
        state.stats.spurious_losses.saturating_sub(state.outage.ignored_spurious))
}
fn recent_outage_probe_acked(state: &ConnectionStateConnected, ack: &crate::ack::BitmapAck, now: u64) -> bool {
    ack.acknowledged().any(|seq| {
        let (record_seq, sent) = state.outage.probes[(seq % 8) as usize];
        let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
        seq >= state.packets_waiting_ack_tail && seq < state.send_sequence_number &&
            state.packets_waiting_ack_field[(bit / 64) as usize] & (1 << (bit % 64)) != 0 &&
            record_seq == seq && sent != 0 && now.saturating_sub(sent) <= state.outage.max_probe_age_ns.max(OUTAGE_MAX_PROBE_NS)
    })
}
impl OutageState {
    fn enter(&mut self, now: u64, rate: u64) {
        self.since_ns = Some(now);
        self.next_probe_ns = now;
        self.probe_interval_ns = OUTAGE_FIRST_PROBE_NS;
        self.resume_rate_upps = rate.min(crate::ship::CC.initial_rate_upps);
    }
    fn probe_due(&mut self, now: u64) -> bool {
        if self.since_ns.is_none() || now < self.next_probe_ns { return false; }
        self.next_probe_ns = now.saturating_add(self.probe_interval_ns);
        self.probe_interval_ns = self.probe_interval_ns.saturating_mul(2).min(OUTAGE_MAX_PROBE_NS);
        true
    }
    fn expired(now: u64, last_ack: u64) -> bool {
        now.saturating_sub(last_ack) >= OUTAGE_TIMEOUT_NS
    }
}

fn enter_outage(state: &mut ConnectionStateConnected, buf: &mut SendQueues,
    now: u64, prefix: u16, mut trace: Option<&mut crate::loss_trace::LossTrace>) {
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
            } else { state.stats.tu_probes_lost += 1; }
        }
        state.packets_waiting_ack_field[(bit / 64) as usize] &= !(1 << (bit % 64));
        // Finalize source tags for rescue, but never teach SpanLossProfile an outage.
        buf.fec_on_packet_finalized(seq, lost);
        state.packets_waiting_ack_tail += 1;
    }
    state.tu_probe_sequence_number = u64::MAX;
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
        for retained in q.fec_retained.values_mut() { retained.expires_ns = retained.expires_ns.saturating_add(paused); }
        for slot in [&mut q.fec_send_slot, &mut q.fec_suspended].into_iter().flatten() {
            slot.send_started_ns = slot.send_started_ns.saturating_add(paused);
        }
    }
    // A path outage is not a stationary 100%-loss channel. Start a fresh FEC
    // observation window; source rescue plans above remain intact.
    if buf.fec_adaptive.is_some() {
        let (lost, spurious) = fec_learning_counters(state);
        buf.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,
            now, state.stats.packets_sent, lost.saturating_sub(spurious)));
    }
    // Receiver-only peers notice the outage later, at their own keepalive. A
    // partial worker's entire silence must be paused, not only time since that
    // later entry. Round-trip recovery starts its inactivity grace afresh.
    for slot in slots {
        if matches!(slot.state, FecRecvState::Worker { .. }) { slot.last_block_ns = now; }
    }
    state.outage.ignore_loss_before_seq = state.send_sequence_number;
    state.congestion_event_rate_upps = local_rate_limit(state.outage.resume_rate_upps, max_pps).max(1);
    state.congestion_event_time_ns = now;
    state.cc_startup_done = false;
    state.RTT_sample_sums.fill(0);
    state.RTT_sample_counts.fill(0);
    state.RTT_sample_cursor = 0;
    state.RTT_mean_cursor = 0;
    state.RTT_mean = u16::MAX;
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

#[test]
fn research_outage_backoff_is_bounded_and_dead_peer_expires_at_120s() {
    let mut o = OutageState::default();
    o.enter(1_000_000_000, 5_000_000_000);
    assert_eq!(o.resume_rate_upps, crate::ship::CC.initial_rate_upps);
    for due in [1_000_000_000, 1_250_000_000, 1_750_000_000, 2_750_000_000, 4_750_000_000, 8_750_000_000] {
        assert!(!o.probe_due(due - 1));
        assert!(o.probe_due(due));
    }
    assert_eq!(o.probe_interval_ns, OUTAGE_MAX_PROBE_NS);
    assert!(!OutageState::expired(119_999_999_999, 0));
    assert!(OutageState::expired(120_000_000_000, 0));
}

#[test]
fn research_outage_finalizes_once_and_resumes_conservatively() {
    let ConnectionState::Connected(mut s) = new_connection_state_connected(None, 0, 1, 1_000_000_000) else { unreachable!() };
    let mut b = SendQueues::new(1, (100000, 1000000, 1000000));
    s.stats.cc_rate_upps = 5_000_000_000;
    s.account_send(1_000_000_000);
    s.account_send(1_001_000_000);
    s.packets_in_flight = 2;
    let cuts = s.congestion_event_rate_upps;
    enter_outage(&mut s, &mut b, 3_000_000_000, 0, None);
    assert_eq!(s.packets_in_flight, 0);
    assert_eq!(s.packets_waiting_ack_tail, 2);
    assert_eq!(s.stats.packets_lost, 2);
    assert_eq!(s.congestion_event_rate_upps, cuts);
    assert_eq!(s.stats.cc_rate_upps, 0);
    s.account_send(27_000_000_000);
    s.packets_in_flight = 1;
    resume_outage(&mut s, &mut b, &mut [], 27_010_000_000, None);
    assert!(s.outage.since_ns.is_none());
    assert_eq!(s.outage.ignore_loss_before_seq, 3);
    assert_eq!(s.congestion_event_rate_upps, crate::ship::CC.initial_rate_upps);
    assert_eq!(s.send_pacer_acc_ns, 0);
    assert_eq!(s.loss_count_in_window, 0);
    assert_eq!(s.stats.packets_lost, 2);
}

fn take_ecn_signal(state: &mut ConnectionStateConnected, guard_rtts: f64) -> bool {
    // Consume covered feedback too: it must not survive to a later ACK/epoch.
    let pending = std::mem::take(&mut state.ecn_congestion_received);
    let eligible = pending && state.ecn_oldest_send_time > state.congestion_event_time_ns.saturating_add((state.RTT_mean as f64 * 100_000.0 * guard_rtts) as u64);
    if eligible { state.loss_count_in_window = 0; }
    eligible
}

/// Freeze active curve time on starvation; preserve the anchor and phase for
/// every controller, including bounded, compounded, proportional and startup.
fn update_app_limit(state: &mut ConnectionStateConnected, now_ns: u64, has_data: bool) {
    if !has_data && !state.is_app_limited {
        state.stats.cc_app_limited_entries += 1;
        state.app_limit_time_offset = now_ns.saturating_sub(state.congestion_event_time_ns);
        state.is_app_limited = true;
    } else if has_data && state.is_app_limited {
        state.congestion_event_time_ns = now_ns.saturating_sub(state.app_limit_time_offset);
        state.is_app_limited = false;
    }
}

fn connection_rate(t_ns: u64, anchor_upps: u64, k_ns: u64, cc: &CongestionPolicy, startup_done: bool) -> (u64, char) {
    if !startup_done {
        let rtt_ns = k_ns / cc.recovery_rtts;
        // The sentinel RTT means no sample yet: never ramp on an unknown path.
        let exponent = if rtt_ns == u16::MAX as u64 * 100_000 { 0.0 } else { cc.startup_multiplier.ln() * t_ns as f64 / rtt_ns.max(100_000) as f64 };
        ((anchor_upps as f64 * exponent.min(30.0).exp()).min(MAX_CC_RATE_UPPS as f64) as u64, 'I')
    } else { cubic_rate_with_options(t_ns, anchor_upps, k_ns, cc) }
}

// Trace-only context: evaluate the same curve and local cap used by the pacer.
// A 1 ms right derivative is uniform across all curve phases, not a startup rule.
fn cc_trace_context(state: &ConnectionStateConnected, now: u64, cc: &CongestionPolicy, max_pps: Option<u64>) -> crate::loss_trace::CcContext {
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    let k = cc.recovery_rtts * rtt_ns;
    let age = if state.is_app_limited { state.app_limit_time_offset }
        else { now.saturating_sub(state.congestion_event_time_ns) };
    let (rate, mode) = connection_rate(age, state.congestion_event_rate_upps, k, cc, state.cc_startup_done);
    let capped = |r: u64| local_rate_limit(r.max(cc.rate_floor_upps), max_pps);
    let rate = capped(rate);
    let next = capped(connection_rate(age.saturating_add(1_000_000), state.congestion_event_rate_upps, k, cc, state.cc_startup_done).0);
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
                    apply_loss_congestion(state, sent, now, cc, max_pps);
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

fn apply_loss_congestion(state: &mut ConnectionStateConnected, send_time: u64, current_time_now_ns: u64, cc: &CongestionPolicy, max_pps: Option<u64>) {
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    // An RTT re-anchor may have moved the origin while a cohort was retiring.
    // Re-check its loss send-time, not just the packet which completed the cohort.
    if send_time <= state.congestion_event_time_ns.saturating_add((rtt_ns as f64 * cc.event_guard_rtts) as u64) { return; }
    let time_to_bandwidth_recovery = cc.recovery_rtts * rtt_ns;
    let send_dt = send_time - state.congestion_event_time_ns;
    let send_t_factor = send_dt as f64 / time_to_bandwidth_recovery as f64;
    let (_, send_mode) = connection_rate(send_dt, state.congestion_event_rate_upps, time_to_bandwidth_recovery, cc, state.cc_startup_done);
    let now_dt = current_time_now_ns - state.congestion_event_time_ns;
    let now_t_factor = now_dt as f64 / time_to_bandwidth_recovery as f64;
    let (_, now_mode) = connection_rate(now_dt, state.congestion_event_rate_upps, time_to_bandwidth_recovery, cc, state.cc_startup_done);
    // R: use rate at send time.
    // P/G/S: blend 50% toward R/P boundary rate.
    let mut discovered = connection_rate(send_dt, state.congestion_event_rate_upps, time_to_bandwidth_recovery, cc, state.cc_startup_done).0;
    if send_mode == 'I' {
        discovered = connection_rate(send_dt.saturating_sub((rtt_ns as f64 * cc.startup_backoff_rtts) as u64), state.congestion_event_rate_upps, time_to_bandwidth_recovery, cc, false).0;
    } else if send_mode != 'R' {
        let boundary = (state.congestion_event_rate_upps as f64 * cc.rate_rp) as u64;
        discovered = (discovered + boundary) / 2;
    }
    state.congestion_event_rate_upps = local_rate_limit(discovered, max_pps);
    state.congestion_event_time_ns = current_time_now_ns;
    state.app_limit_time_offset = 0;
    state.loss_count_in_window = 0;
    state.cc_startup_done = true;
    println!("congestion event PACKET DROPPED {} ...  rate discovered: {} pps  now:{now_mode}@{now_t_factor:.2} sent:{send_mode}@{send_t_factor:.2}", state.packets_waiting_ack_tail, state.congestion_event_rate_upps as f64 / 1000000.0);
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

#[cfg(test)]
mod congestion_tests {
    use super::*;

    fn hole_state() -> ConnectionStateConnected {
        let ConnectionState::Connected(mut s) = new_connection_state_connected(None, 0, 0, 0) else { unreachable!() };
        s.RTT_mean = 1000; // 100 ms
        s.congestion_event_rate_upps = 2_000_000_000;
        for _ in 0..8 { s.account_send(1_000_000_000); }
        // Close the send-time bucket, just as the send loop does.
        s.account_send(1_010_000_000);
        s.packets_in_flight = 9;
        s
    }
    fn data_receipt(s: &mut ConnectionStateConnected, seq: u64) {
        let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
        s.packets_waiting_ack_field[(bit / 64) as usize] &= !(1 << (bit % 64));
        s.packets_in_flight -= 1;
        s.ack_hole.acknowledged(seq);
    }

    #[test]
    fn ack_hole_requires_three_distinct_receipts_and_two_spaced_frames() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        for seq in [1, 2] { data_receipt(&mut s, seq); }
        s.ack_hole.acknowledged(2); // duplication is not a third newer receipt
        observe_ack_hole(&mut s, 1_100_000_000, &cc, None);
        assert!(!s.cc_startup_done);
        data_receipt(&mut s, 3);
        observe_ack_hole(&mut s, 1_110_000_000, &cc, None);
        assert!(!s.cc_startup_done); // one frame is not confirmation
        data_receipt(&mut s, 4);
        observe_ack_hole(&mut s, 1_115_000_000, &cc, None);
        assert!(!s.cc_startup_done); // still inside RTT/16 reordering grace
        data_receipt(&mut s, 5);
        observe_ack_hole(&mut s, 1_120_000_000, &cc, None);
        assert!(!s.cc_startup_done); // confirmed isolated loss is only one cohort member
        assert_eq!(s.loss_count_in_window, 1);
        assert_eq!(s.ack_hole.confirmed_before, 1);
        assert_eq!(s.congestion_event_time_ns, 0);
        assert_eq!(s.congestion_event_rate_upps, 2_000_000_000);
    }

    #[test]
    fn ack_hole_reordering_within_grace_does_not_cut() {
        let mut s = hole_state();
        for seq in [1, 2, 3] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &crate::ship::CC, None);
        data_receipt(&mut s, 0); // reordered original arrives before confirmation
        observe_ack_hole(&mut s, 1_105_000_000, &crate::ship::CC, None);
        data_receipt(&mut s, 4);
        observe_ack_hole(&mut s, 1_120_000_000, &crate::ship::CC, None);
        assert!(!s.cc_startup_done);
    }

    #[test]
    fn ack_hole_batch_cuts_once_on_first_confirmation_frame_and_dedups_timeouts() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        for seq in [3, 4, 5] { data_receipt(&mut s, seq); }
        assert_eq!(observe_ack_hole(&mut s, 1_100_000_000, &cc, None), None);
        assert!(!s.cc_startup_done);
        data_receipt(&mut s, 6);
        let sent = s.send_time(1);
        assert_eq!(observe_ack_hole(&mut s, 1_110_000_000, &cc, None), Some((1, sent)));
        assert!(s.cc_startup_done);
        assert_eq!(s.congestion_event_time_ns, 1_110_000_000);
        assert_eq!(s.ack_hole.confirmed_before, 3); // all three holes evaluated together
        assert_eq!(s.loss_count_in_window, 0);
        let cut = (s.congestion_event_time_ns, s.congestion_event_rate_upps);
        data_receipt(&mut s, 7);
        assert_eq!(observe_ack_hole(&mut s, 1_120_000_000, &cc, None), None);
        for seq in 0..3 {
            let sent = s.send_time(seq);
            assert!(!count_congestion_signal(&mut s, seq, sent, 1_140_000_000, &cc));
            apply_loss_congestion(&mut s, sent, 1_300_000_000, &cc, None);
        }
        assert_eq!(s.loss_count_in_window, 0);
        assert_eq!((s.congestion_event_time_ns, s.congestion_event_rate_upps), cut);
    }

    #[test]
    fn ack_hole_newer_range_keeps_its_own_confirmation_grace() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        for seq in [1, 3, 4] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &cc, None);
        data_receipt(&mut s, 5); // hole 2 only qualifies in this frame
        observe_ack_hole(&mut s, 1_105_000_000, &cc, None);
        data_receipt(&mut s, 6);
        observe_ack_hole(&mut s, 1_107_000_000, &cc, None);
        assert_eq!(s.loss_count_in_window, 1);
        assert!(!s.cc_startup_done);
        data_receipt(&mut s, 7);
        observe_ack_hole(&mut s, 1_112_000_000, &cc, None);
        assert!(s.cc_startup_done);
        assert_eq!(s.congestion_event_time_ns, 1_112_000_000);
    }

    #[test]
    fn ack_hole_advancing_frame_flood_is_bounded_and_never_shortens_grace() {
        let mut s = hole_state();
        for _ in 9..128 { s.account_send(1_010_000_000); }
        s.account_send(1_020_000_000);
        s.packets_in_flight = 129;
        let capacity = s.ack_hole.pending.capacity();
        for seq in [3, 4, 5] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &crate::ship::CC, None);
        let mut now = 1_100_000_000;
        for seq in (7..128).step_by(2) {
            data_receipt(&mut s, seq);
            now += 10_000;
            assert_eq!(observe_ack_hole(&mut s, now, &crate::ship::CC, None), None);
            assert!(s.ack_hole.pending.len() <= ACK_HOLE_PENDING_RANGES);
            assert_eq!(s.ack_hole.pending.capacity(), capacity);
            assert_eq!(s.loss_count_in_window, 0);
            assert!(!s.cc_startup_done);
        }
        assert_eq!(s.ack_hole.pending.len(), ACK_HOLE_PENDING_RANGES);
        assert_eq!(s.ack_hole.pending.back().unwrap().1, now);
        // Old ranges can mature, but the coalesced newest range still waits.
        observe_ack_hole(&mut s, 1_106_450_000, &crate::ship::CC, None);
        assert_eq!(s.ack_hole.pending.len(), 1);
        assert_eq!(s.ack_hole.pending.back().unwrap().1, now);
        assert!(s.ack_hole.cursor < s.ack_hole.pending.back().unwrap().0);
    }

    #[test]
    fn ack_hole_leaves_final_loss_and_fec_accounting_untouched() {
        let mut s = hole_state();
        for seq in [2, 3, 4] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &crate::ship::CC, None);
        data_receipt(&mut s, 5);
        observe_ack_hole(&mut s, 1_110_000_000, &crate::ship::CC, None);
        data_receipt(&mut s, 6);
        observe_ack_hole(&mut s, 1_120_000_000, &crate::ship::CC, None);
        data_receipt(&mut s, 7);
        let bits = s.packets_waiting_ack_field;
        let flight = s.packets_in_flight;
        let timeout = s.loss_timer.timeout_ns(100_000_000, 0, &crate::ship::CC);
        observe_ack_hole(&mut s, 1_130_000_000, &crate::ship::CC, None);
        assert!(s.cc_startup_done);
        assert_eq!(s.packets_waiting_ack_field, bits);
        assert_eq!(s.packets_waiting_ack_tail, 0);
        assert_eq!(s.packets_in_flight, flight);
        assert_eq!(s.stats.packets_lost, 0);
        assert_eq!(s.stats.spurious_losses, 0);
        assert_eq!(fec_learning_counters(&s), (0, 0));
        assert!(s.declared_lost_field.iter().all(|&w| w == 0));
        assert_eq!(s.loss_timer.timeout_ns(100_000_000, 0, &crate::ship::CC), timeout);
        let sent = s.send_time(0);
        assert!(1_130_000_000 - sent < timeout); // not eligible for final loss yet
        assert!(sent + timeout >= 1_200_000_000); // unchanged conservative deadline
    }

    #[test]
    fn ack_hole_is_not_counted_again_when_finalized_without_a_cut() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        for seq in [1, 2, 3] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &cc, None);
        data_receipt(&mut s, 4);
        observe_ack_hole(&mut s, 1_110_000_000, &cc, None);
        assert_eq!(s.loss_count_in_window, 1);
        let sent = s.send_time(0);
        assert!(!count_congestion_signal(&mut s, 0, sent, 1_140_000_000, &cc));
        assert_eq!(s.loss_count_in_window, 1);
        assert!(!s.cc_startup_done);
        // A distinct timeout loss participates in the same cohort.
        let sent = s.send_time(8);
        assert!(count_congestion_signal(&mut s, 8, sent, 1_140_000_000, &cc));
        apply_loss_congestion(&mut s, sent, 1_140_000_000, &cc, None);
        assert!(s.cc_startup_done);
        assert_eq!(s.loss_count_in_window, 0);
    }

    #[test]
    fn ack_hole_cohort_expires_after_one_rtt() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        for seq in [1, 2, 3] { data_receipt(&mut s, seq); }
        observe_ack_hole(&mut s, 1_100_000_000, &cc, None);
        data_receipt(&mut s, 4);
        observe_ack_hole(&mut s, 1_110_000_000, &cc, None);
        let sent = s.send_time(8);
        assert!(!count_congestion_signal(&mut s, 8, sent, 1_220_000_000, &cc));
        assert_eq!(s.loss_count_in_window, 1);
        assert!(!s.cc_startup_done);
    }

    #[test]
    fn cc_trace_uses_pacer_curve_derivative_and_freezes_at_caps_or_starvation() {
        let mut s = hole_state();
        let cc = crate::ship::CC;
        s.congestion_event_time_ns = 0;
        s.congestion_event_rate_upps = 2_000_000_000;
        let k = cc.recovery_rtts * s.RTT_mean as u64 * 100_000;
        for done in [false, true] {
            s.cc_startup_done = done;
            for age in [0, k / 2, k, 2 * k, 4 * k] {
                let c = cc_trace_context(&s, age, &cc, None);
                let a = connection_rate(age, s.congestion_event_rate_upps, k, &cc, done).0.max(cc.rate_floor_upps);
                let b = connection_rate(age + 1_000_000, s.congestion_event_rate_upps, k, &cc, done).0.max(cc.rate_floor_upps);
                assert_eq!(c.pps, a as f64 / 1_000_000.0);
                assert_eq!(c.slope_ppsps, b.saturating_sub(a) as f64 / 1000.0);
                assert_eq!(c.rtt_ns, s.RTT_mean as u64 * 100_000);
                assert_eq!(c.feedback_ns, c.rtt_ns + (c.rtt_ns / 16).max(1_000_000) + 10_000_000);
            }
        }
        let capped = cc_trace_context(&s, 4 * k, &cc, Some(100));
        assert_eq!(capped.pps, 100.0);
        assert_eq!(capped.slope_ppsps, 0.0);
        s.is_app_limited = true;
        s.app_limit_time_offset = k;
        let idle = cc_trace_context(&s, 20 * k, &cc, None);
        assert_eq!(idle.mode, 'A');
        assert_eq!(idle.slope_ppsps, 0.0);
        assert_eq!(idle.pps, connection_rate(k, s.congestion_event_rate_upps, k, &cc, true).0 as f64 / 1_000_000.0);
    }

    #[test]
    fn loss_timer_keeps_ack_delay_at_the_rate_floor() {
        let cc = crate::ship::CC;
        let mut timer = LossTimer::default();
        // At 100 pps the count trigger takes 80 ms, but the delay cap flushes
        // after 10 ms. Stable 50 ms path + 10 ms ACK delay is not a loss.
        for _ in 0..100 { timer.observe(60_000_000); }
        let timeout = timer.timeout_ns(50_000_000, 0, &cc);
        assert!(timeout >= 110_000_000);
        assert!(timeout < 200_000_000); // genuine losses still retire promptly
    }

    #[test]
    fn loss_timer_learns_late_ack_without_censoring_and_recovers() {
        let cc = crate::ship::CC;
        let mut timer = LossTimer::default();
        for _ in 0..100 { timer.observe(50_000_000); }
        assert!(timer.timeout_ns(50_000_000, 0, &cc) < 150_000_000);
        // The old two-mean-RTT detector already declared this packet lost.
        // Its late ACK must increase the timer, not just the spurious counter.
        timer.observe(160_000_000);
        assert!(timer.timeout_ns(50_000_000, 0, &cc) > 160_000_000);
        for i in 0..500 {
            timer.observe(if i % 4 == 0 { 160_000_000 } else { 50_000_000 });
            assert!(timer.timeout_ns(50_000_000, 0, &cc) > 160_000_000);
        }
        for _ in 0..100 { timer.observe(50_000_000); }
        assert!(timer.timeout_ns(50_000_000, 0, &cc) < 120_000_000);
        assert_eq!(timer.timeout_ns(50_000_000, 600_000_000, &cc), 1_000_000_000);
    }

    #[test]
    fn loss_free_app_empty_resume_preserves_every_active_curve() {
        let cc = crate::ship::CC;
        for startup_done in [false, true] {
            for rtt_ns in [40_000_000, 200_000_000] {
                let k = cc.recovery_rtts * rtt_ns;
                for age in [k / 2, k + k / 2, 3 * k, 9 * k, 30 * k] {
                    let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
                    state.congestion_event_rate_upps = 8_000_000_000;
                    state.congestion_event_time_ns = 1_000_000_000;
                    let mut now = state.congestion_event_time_ns + age;
                    let mut previous_rate = connection_rate(age, state.congestion_event_rate_upps, k, &cc, startup_done).0;
                    for cycle in 0..100 {
                        let active_age = now - state.congestion_event_time_ns;
                        let before = connection_rate(active_age, state.congestion_event_rate_upps, k, &cc, startup_done).0;
                        assert!(before >= previous_rate);
                        let anchor = state.congestion_event_rate_upps;
                        update_app_limit(&mut state, now, false);
                        now += 5_000_000_000;
                        update_app_limit(&mut state, now, false);
                        assert_eq!(state.congestion_event_rate_upps, anchor);
                        let idle = connection_rate(state.app_limit_time_offset, anchor, k, &cc, startup_done).0;
                        assert_eq!(idle, before, "idle cycle {cycle}: {cc:?}");
                        update_app_limit(&mut state, now, true);
                        let resumed = connection_rate(now - state.congestion_event_time_ns, anchor, k, &cc, startup_done).0;
                        assert_eq!(resumed, before, "resume cycle {cycle}: {cc:?}");
                        previous_rate = resumed;
                        now += 2_000_000;
                    }
                    assert_eq!(state.stats.cc_app_limited_entries, 100);
                }
            }
        }
    }

    #[test]
    fn ecn_feedback_is_consumed_once_even_when_guarded() {
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        state.RTT_mean = 2000;
        state.congestion_event_time_ns = 1_000_000_000;
        state.ecn_oldest_send_time = 1_200_000_000;
        state.ecn_congestion_received = true;
        state.loss_count_in_window = 9;
        assert!(take_ecn_signal(&mut state, 0.5));
        assert_eq!(state.loss_count_in_window, 0);
        assert!(!take_ecn_signal(&mut state, 0.5));
        state.ecn_congestion_received = true;
        state.loss_count_in_window = 3;
        state.ecn_oldest_send_time = 1_050_000_000;
        assert!(!take_ecn_signal(&mut state, 0.5));
        assert!(!state.ecn_congestion_received);
        assert_eq!(state.loss_count_in_window, 3);
        state.ecn_congestion_received = true;
        state.ecn_oldest_send_time = 1_150_000_000;
        assert!(!take_ecn_signal(&mut state, 1.0));
        assert!(!take_ecn_signal(&mut state, 0.5));
    }

    #[test]
    fn startup_is_rate_based_and_exits_to_ship_curve() {
        let cc = crate::ship::CC;
        let r = 100_000_000;
        let rtt = 200_000_000;
        let k = cc.recovery_rtts * rtt;
        assert_eq!(connection_rate(0, r, k, &cc, false), (r, 'I'));
        assert!((connection_rate(rtt, r, k, &cc, false).0 as f64 / r as f64 - 1.1).abs() < 1e-6);
        assert!((connection_rate(10*rtt, r, k, &cc, false).0 as f64 / r as f64 - 1.1f64.powi(10)).abs() < 1e-6);
        assert_eq!(connection_rate(100*rtt, r, cc.recovery_rtts * u16::MAX as u64 * 100_000, &cc, false), (r, 'I'));
        assert_eq!(connection_rate(0, r, k, &cc, true), cubic_rate(0, r, k));
        assert!(connection_rate(u64::MAX, r, k, &cc, false).0 <= 1_000_000_000_000);
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        state.RTT_mean = 2000;
        state.congestion_event_rate_upps = r;
        apply_loss_congestion(&mut state, 10*rtt, 12*rtt, &cc, None);
        assert_eq!(state.congestion_event_rate_upps, connection_rate(9*rtt, r, k, &cc, false).0);
        assert!(state.cc_startup_done);
    }

    #[test]
    fn send_quantum_bounds_backlog_without_losing_normal_rate_credit() {
        let g = send_pacing_grant(700_000_000, 10_000, 0);
        assert_eq!(g.packets, MAX_SEND_PACKETS_PER_TICK);
        assert_eq!(g.carry_ns, MAX_SEND_CATCHUP_NS);
        let next = send_pacing_grant(0, 10_000, g.carry_ns);
        assert_eq!(next.packets, MAX_SEND_PACKETS_PER_TICK);
        assert_eq!(next.carry_ns, 1_360_000);

        // A modest delayed grant is split across ticks, never silently lost.
        let first = send_pacing_grant(1_000_003, 10_000, 0);
        let second = send_pacing_grant(0, 10_000, first.carry_ns);
        assert_eq!(first.packets + second.packets, 100);
        assert_eq!(second.carry_ns, 3);

        // Fractional credit keeps exactly 100 pps even with 150 us polling;
        // this also covers credit larger than the catch-up cap at low rates.
        let mut credit = 0;
        let mut packets = 0;
        for _ in 0..20_000 {
            let g = send_pacing_grant(150_000, 10_000_000, credit);
            packets += g.packets;
            credit = g.carry_ns;
        }
        assert_eq!(packets, 300);
        assert_eq!(credit, 0);
    }

    #[test]
    fn fixed_memory_episode_meter_finds_short_loss_bursts() {
        let mut meter = LossEpisodes::default();
        let mut stats = ConnectionStats::default();
        for i in 0..1000u64 {
            meter.on_packet(i * 1_000_000 + 1, (200..250).contains(&i), 100_000_000, &mut stats);
        }
        assert_eq!(stats.max_rtt_loss_ppm, 500_000);
        assert_eq!(stats.max_rtt_loss_window_packets, 100);
        assert_eq!(std::mem::size_of::<LossEpisodes>(), 104);
        assert_eq!(stats.packets_lost, 0); // Meter never alters actual loss/CC accounting.
    }

    #[test]
    fn congestion_after_local_ceiling_still_cuts_actual_pacing() {
        let (r, k) = (1_000_000_000, 900_000_000);
        let stale_discovery = cubic_rate(20 * k, r, k).0;
        assert!(stale_discovery > r);
        // An uncapped discovery could leave actual pacing stuck at the local cap
        // even after genuine loss. Cap the new anchor, not only the final output.
        let anchor = local_rate_limit(stale_discovery, Some(1000));
        assert_eq!(anchor, r);
        assert_eq!(local_rate_limit(cubic_rate(0, anchor, k).0, Some(1000)), 670_000_000);
    }

    #[test]
    fn guarded_losses_do_not_prime_the_next_event() {
        let mut count = 0;
        for _ in 0..100 { assert!(!count_congestion_loss(&mut count, false, 2)); }
        assert_eq!(count, 0);
        assert!(!count_congestion_loss(&mut count, true, 2));
        assert!(count_congestion_loss(&mut count, true, 2));
    }

    #[test]
    fn local_ceiling_does_not_create_recovery_sawtooth() {
        let (r, k) = (1_000_000_000, 900_000_000);
        // The old local event restarted R at 0.67 * r on every cap crossing.
        assert_eq!(cubic_rate(0, r, k).0, 670_000_000);
        for t in (20 * k..40 * k).step_by(10_000_000) {
            assert_eq!(local_rate_limit(cubic_rate(t, r, k).0, Some(1000)), r);
        }
        assert_eq!(local_rate_limit(100_000_000, Some(10)), 10_000_000);
        assert_eq!(local_rate_limit(r, None), r);
    }

    #[test]
    fn sub_tick_rtt_cannot_freeze_recovery() {
        assert_eq!(quantized_rtt_mean(0, 16), 1);
        assert_eq!(quantized_rtt_mean(30, 16), 1);
        assert_eq!(quantized_rtt_mean(1830 * 16, 16), 1830);
        let k = crate::ship::CC.recovery_rtts * quantized_rtt_mean(0, 16) as u64 * 100_000;
        assert!(k > 0);
        assert!(cubic_rate(20 * k, 100_000_000, k).0 > cubic_rate(0, 100_000_000, k).0);
    }

    #[test]
    fn compounded_growth_is_monotone_and_bounded_in_every_phase() {
        let cc = crate::ship::CC;
        for r in [100_000_000, 1_000_000_000, 40_000_000_000] {
            for rtt in [100_000, 30_000_000, 200_000_000] {
                let k = cc.recovery_rtts * rtt;
                let mut previous = 0;
                for t in (0..100*k).step_by((k/1000).max(1) as usize) {
                    let rate = cubic_rate(t, r, k).0;
                    assert!(rate >= previous);
                    // Arithmetic reordering can differ by one millionth of a pps.
                    assert!(rate <= (r as f64 * cc.beta + 525e6 * t as f64 / 1e9) as u64 + 1,
                        "r={r} rtt={rtt} t={t} rate={rate}");
                    previous = rate;
                }
            }
        }
    }
}

#[cfg(test)]
mod precise_pacing_tests {
    use super::*;

    #[test]
    fn low_rate_precise_handshake_and_idle_then_burst() {
        for pps in [100, 10] {
            let port = std::net::UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap().port();
            let server_key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
            let address = STPAddress { ip: Ipv6Addr::LOCALHOST, port, magic1: CONNECT_MAGIC1_PLAIN_TEXT, key: server_key.public.clone() };
            let key = address.to_connection_key();
            let server = new_network_thread(vec![server_key], port, Some(pps), (1_000_000,1<<20,1<<20));
            let client = new_network_thread(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0, Some(pps), (1_000_000,1<<20,1<<20));
            service_connections(&client, NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut wanted = Vec::new();
            loop {
                service_connections(&server, NetworkThreadPush::default()).unwrap();
                let p = service_connections(&client, NetworkThreadPush::default()).unwrap();
                if !p.current_connections.is_empty() { wanted = p.current_connections; }
                if p.connection_stats.iter().any(|(_, s)| s.packets_sent > 0 && s.rtt_us > 0) { break; }
                assert!(std::time::Instant::now() < deadline, "{pps}pps/precise idle handshake stalled");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
            service_connections(&client, NetworkThreadPush { wanted_connections: wanted.clone(), send_unreliable: vec![(key, 0, Dscp::BestEffort, vec![42; 1000]); 3], ..Default::default() }).unwrap();
            let mut received = 0;
            while received < 3 {
                let p = service_connections(&server, NetworkThreadPush::default()).unwrap();
                for (_, message) in p.received_unreliable_messages { assert_eq!(message, vec![42; 1000]); received += 1; }
                service_connections(&client, NetworkThreadPush { wanted_connections: wanted.clone(), ..Default::default() }).unwrap();
                assert!(std::time::Instant::now() < deadline, "{pps}pps/precise burst stalled");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn idle_precise_peer_sends_control_without_application_data() {
        let port = std::net::UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap().port();
        let server_key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
        let address = STPAddress { ip: Ipv6Addr::LOCALHOST, port, magic1: CONNECT_MAGIC1_PLAIN_TEXT, key: server_key.public.clone() };
        let opts = NetworkThreadOptions::default;
        let server = new_network_thread_with_options(vec![server_key], port, None, (1_000_000,1<<20,1<<20), opts());
        let client = new_network_thread_with_options(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0, None, (1_000_000,1<<20,1<<20), opts());
        service_connections(&client, NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            service_connections(&server, NetworkThreadPush::default()).unwrap();
            let p = service_connections(&client, NetworkThreadPush::default()).unwrap();
            if p.connection_stats.iter().any(|(_,s)| s.packets_sent > 0 && s.rtt_us > 0) { return; }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("idle peer never emitted a precise-paced keepalive / probe or acquired RTT");
    }
}

#[cfg(test)]
mod fec_send_tests {
    use super::*;
    use rand::{Rng, RngCore};

    /// Parsed fragment: (package_id, Some((message_len, block_bytes, block_id)) for FEC or None for plain, is_fin, offset, data)
    type Frag = (u16, Option<(usize, usize, u32)>, bool, u32, Vec<u8>);

    fn parse_packet(mut p: &[u8]) -> Vec<Frag> {
        let mut out = Vec::new();
        while let Some((h, plain_header_size)) = read_fragment_header(p) {
            let len = ((h >> 18) & 0x3fff) as usize;
            let pkg = ((h >> 2) & 0xffff) as u16;
            if h & 1 != 0 {
                let w1 = load_u64(&p[8..16]);
                assert!(matches!(w1 >> 48, STP_EXT_KIND_FEC | STP_EXT_KIND_GROUPED_FEC));
                out.push((pkg, Some(((w1 & 0xffff_ffff) as usize, ((w1 >> 32) & 0xffff) as usize, (h >> 32) as u32)), false, 0, p[16..16 + len].to_vec()));
                p = &p[16 + len..];
            } else {
                out.push((pkg, None, h & 2 != 0, (h >> 32) as u32, p[plain_header_size..plain_header_size + len].to_vec()));
                p = &p[plain_header_size + len..];
            }
        }
        out
    }

    /// Fills packets of `payload_len` until the buffer is drained (waiting for encoder threads).
    fn drain(buf: &mut UnreliableSendBuffer, payload_len: usize, max_packets: usize) -> Vec<Vec<Frag>> {
        let mut packets = Vec::new();
        let mut mem = vec![0u8; payload_len];
        while packets.len() < max_packets {
            buf.fec_prepare_packet(packets.len() as u64);
            if fill_packet_payload_with_unreliable_fragments(&mut mem, buf) > 0 {
                packets.push(parse_packet(&mem));
            } else if buf.has_unsent_data() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            } else {
                break;
            }
        }
        packets
    }

    fn msg(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        rand::rng().fill_bytes(&mut v);
        v
    }

    fn new_buf() -> UnreliableSendBuffer {
        let mut b = UnreliableSendBuffer::new(1_000_000, 1 << 26, 1 << 26);
        let a = crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0);
        b.fec_capacity_overhead_ppm = a.representative_ppm();
        b.fec_adaptive = Some(a);
        b
    }

    #[test]
    fn thousand_byte_messages_occupy_one_physical_packet_each() {
        for payload_len in [1162, 1450, 9194] {
            let mut b = new_buf();
            // Leave a tail too short for the next message, followed by many fresh-packet messages.
            let mut messages = vec![msg(payload_len - 600)];
            messages.extend((0..200).map(|_| msg(1000)));
            assert!(b.submit_messages(messages.clone()).is_empty());
            let packets = drain(&mut b, payload_len, 300);
            for id in 1..=200 {
                let physical: Vec<_> = packets.iter().filter(|p| p.iter().any(|f| f.0 == id)).collect();
                assert_eq!(physical.len(), 1, "payload={payload_len}, package={id}");
                let fragments: Vec<_> = physical[0].iter().filter(|f| f.0 == id).collect();
                assert_eq!(fragments.len(), 1);
                let f = fragments[0];
                assert!(f.1.is_none() && f.2);
                assert_eq!(f.3, 0);
                assert_eq!(f.4, messages[id as usize]);
            }
            assert!(!b.has_unsent_data());
            assert_eq!(b.queue_bytes_filled, 0);
        }
    }

    #[test]
    fn small_plain_message_defers_tail_and_rechecks_tu() {
        let mut b = new_buf();
        assert!(b.submit_messages(vec![msg(1000)]).is_empty());
        assert!(b.next_fragment(1450, 500).is_none());
        assert_eq!(b.partial_send_slot.as_ref().unwrap().1, 0);
        match b.next_fragment(1162, 1162).unwrap() {
            UnreliableFragment::Plain { is_fin, offset, data, .. } => {
                assert!(is_fin);
                assert_eq!((offset, data.len()), (0, 1000));
            }
            _ => panic!("one-packet message must remain plain"),
        }
    }

    fn check_fec(frags: &[Frag], package_id: u16, m: &[u8], drop_every: usize) {
        let mine: Vec<&Frag> = frags.iter().filter(|f| f.0 == package_id).collect();
        let (len, bb, _) = mine[0].1.unwrap();
        assert_eq!(len, m.len());
        let k = crate::fec::block_count(len, bb).unwrap();
        let n = mine.len();
        assert!(n > k && n <= 2 * k);
        let ids: Vec<u32> = mine.iter().map(|f| f.1.unwrap().2).collect();
        assert_eq!(ids, (0..n as u32).collect::<Vec<_>>());
        for f in &mine[..k] {
            let s = f.1.unwrap().2 as usize * bb;
            assert_eq!(&f.4[..], &m[s..(s + bb).min(len)]);
        }
        let mut dec = crate::fec::Decoder::new(len, bb).unwrap();
        for (i, f) in mine.iter().enumerate() {
            if drop_every != 0 && i % drop_every == 0 { continue; }
            if dec.add(f.1.unwrap().2, &f.4).unwrap() == crate::fec::DecodeStatus::Done {
                assert_eq!(dec.recover().unwrap(), m);
                return;
            }
        }
        panic!("package {package_id} did not decode");
    }

    #[test]
    fn fec_small_inline_encoder() {
        let mut b = new_buf();
        let (m1, m2, m3) = (msg(100_000), msg(500), msg(1146 * 2));
        assert!(b.submit_messages(vec![m1.clone(), m2.clone(), m3.clone()]).is_empty());
        let frags: Vec<Frag> = drain(&mut b, 1162, 1000).into_iter().flatten().collect();
        // K = 88 source blocks; the real floor supplies at least 12 repairs.
        check_fec(&frags, 0, &m1, 25);
        // One block: plain.
        assert!(frags.iter().any(|f| f.0 == 1 && f.1.is_none() && f.4 == m2));
        // Exactly two blocks: the repair cap is two more blocks.
        check_fec(&frags, 2, &m3, 0);
        assert_eq!(b.queue_bytes_filled, 0);
    }

    #[test]
    fn fec_big_threaded_encoder() {
        let mut b = new_buf();
        let m = msg(3_000_000);
        b.queue_bytes_filled = m.len();
        b.start_fec(std::sync::Arc::new(m.clone()), 9194 - STP_FEC_FRAGMENT_HEADER_SIZE);
        let frags: Vec<Frag> = drain(&mut b, 9194, 100_000).into_iter().flatten().collect();
        check_fec(&frags, 0, &m, 60);
    }

    #[test]
    fn fec_restarts_when_tu_shrinks() {
        let mut b = new_buf();
        let m = msg(200_000);
        b.submit_messages(vec![m.clone()]);
        let mut first = drain(&mut b, 9194, 5);
        assert!(first.iter().flatten().all(|f| f.0 == 0 && f.1.unwrap().1 == 9178));
        let rest: Vec<Frag> = drain(&mut b, 1162, 10_000).into_iter().flatten().collect();
        assert!(rest.iter().all(|f| f.0 == 1 && f.1.unwrap().1 == 1146));
        check_fec(&rest, 1, &m, 0);
        first.clear();
        assert_eq!(b.queue_bytes_filled, 0);
    }

    #[test]
    fn padded_data_always_fills_current_tu() {
        let mut payload = vec![0; 9194];
        for len in [0, 1, 500, 508, 509, 600] {
            let mut b = new_buf();
            b.submit_messages(vec![vec![7; len]]);
            let used = fill_packet_payload_with_unreliable_fragments(&mut payload, &mut b);
            assert_eq!(used, payload.len());
            assert!(used > 516);
            let f = parse_packet(&payload[..used]);
            assert_eq!(f[0].4, vec![7; len]);
        }
        let mut b = new_buf();
        b.submit_messages(vec![vec![9; 200_000]]);
        let mut small = vec![0; 1162];
        assert_eq!(fill_packet_payload_with_unreliable_fragments(&mut small, &mut b), 1162);
        // An existing encoder keeps its layout, but its wire packet uses the grown TU.
        let mut grown = vec![0; 1450];
        assert_eq!(fill_packet_payload_with_unreliable_fragments(&mut grown, &mut b), 1450);
    }

    #[test]
    fn grouped_wire_round_trip_and_overload_admission() {
        let payload_len = 48;
        let m = msg(64001 * (payload_len - STP_FEC_FRAGMENT_HEADER_SIZE) - 1);
        let layout = crate::fec::MessageLayout::new(m.len(), 32).unwrap();
        let mut b = new_buf();
        b.submit_messages(vec![m.clone()]);
        let mut dec = crate::fec::MessageDecoder::new(m.len(), 32).unwrap();
        let mut packet = vec![0u8; payload_len];
        let mut sent = 0;
        let mut complete = false;
        while b.has_unsent_data() {
            b.fec_prepare_packet(sent as u64);
            if fill_packet_payload_with_unreliable_fragments(&mut packet, &mut b) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            assert_eq!(load_u64(&packet[8..16]) >> 48, STP_EXT_KIND_GROUPED_FEC);
            let f = parse_packet(&packet).remove(0);
            let id = f.1.unwrap().2;
            assert_eq!(id, layout.wire_id(sent));
            sent += 1;
            if sent % 97 == 0 { continue; }
            if dec.add(id, &f.4).unwrap() == crate::fec::DecodeStatus::Done { complete = true; }
        }
        assert!(complete);
        assert_eq!(dec.recover().unwrap(), m);
        let mut slot = FecRecvSlot::default();
        let (done, _) = std::sync::mpsc::channel();
        let workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(MAX_FEC_DECODE_WORKERS));
        let key = ConnectionKey { ip: std::net::Ipv6Addr::LOCALHOST, port: 1, key_15_bits: 0 };
        assert!(fec_receive_block(&mut slot, key, 0, 300 * 32, 32, 0, &[0;32], &done, &workers, &crate::receive_memory::ReceiveMemoryBudget::new(1<<30)).is_none());
        assert!(matches!(slot.state, FecRecvState::Empty)); // retry later; never inline a large solve
        assert!(slot.admission_refused);
        assert_eq!(slot.ingress_dropped, 1);
    }

    #[test]
    fn incomplete_fec_workers_retire_and_refused_package_retries() {
        use std::sync::atomic::Ordering::Acquire;
        let key = ConnectionKey { ip: std::net::Ipv6Addr::LOCALHOST, port: 1, key_15_bits: 0 };
        let (done, completions) = std::sync::mpsc::channel();
        let workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(2<<30);
        let mut slots = FecRecvSlot::new_ring(MAX_FEC_DECODE_WORKERS);
        let message = std::sync::Arc::new(msg(300 * 32));
        let base = 1_000_000_000;
        for (i, slot) in slots.iter_mut().enumerate() {
            slot.package_id = i as u16;
            fec_receive_block(slot, key, i as u16, message.len(), 32, 0, &message[..32], &done, &workers, &budget);
            assert!(matches!(slot.state, FecRecvState::Worker { .. }));
            slot.last_block_ns = base + i as u64 * 1000;
        }
        assert_eq!(workers.load(Acquire), MAX_FEC_DECODE_WORKERS);
        let mut retry = FecRecvSlot { package_id: 100, ..Default::default() };
        fec_receive_block(&mut retry, key, 100, message.len(), 32, 0, &message[..32], &done, &workers, &budget);
        assert!(retry.admission_refused && matches!(retry.state, FecRecvState::Empty));
        assert_eq!(retry.ingress_dropped, 1);
        let grace = fec_inactive_grace_ns(200, true); // 20 ms RTT
        assert_eq!(grace, 40_000_000);
        assert_eq!(fec_inactive_grace_ns(u16::MAX, true), 250_000_000);
        assert_eq!(fec_inactive_grace_ns(u16::MAX, false), 2_000_000_000);
        assert_eq!(retire_inactive_fec_workers(&mut slots, base + grace, grace, true), 0);
        assert_eq!(retire_inactive_fec_workers(&mut slots, base + grace + 1, grace, true), 1);
        assert!(matches!(slots[0].state, FecRecvState::Done));
        assert!(slots[1..].iter().all(|s| matches!(s.state, FecRecvState::Worker { .. })));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while workers.load(Acquire) == MAX_FEC_DECODE_WORKERS {
            assert!(std::time::Instant::now() < deadline, "retired worker did not release admission");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // The first source was erased during admission; fresh repairs still recover it.
        let mut encoder = crate::fec::encode_message(message.clone(), 32).unwrap();
        let mut block = [0u8; 32];
        for id in 1..312 {
            let n = encoder.block_into(id, &mut block).unwrap();
            fec_receive_block(&mut retry, key, 100, message.len(), 32, id, &block[..n], &done, &workers, &budget);
            assert!(workers.load(Acquire) <= MAX_FEC_DECODE_WORKERS);
        }
        let (_, id, decoded, _reservation) = completions.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(id, 100);
        assert_eq!(decoded, *message);
        // With no admission pressure, periodic retirement also releases every dead tail.
        let grace = fec_inactive_grace_ns(200, false);
        assert_eq!(retire_inactive_fec_workers(&mut slots, base + grace + 10_000, grace, false), 7);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while workers.load(Acquire) != 0 {
            assert!(std::time::Instant::now() < deadline, "idle workers did not release admission");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn fec_nonce_ring_tracks_multi_group_packets_wrap_and_slot_generation() {
        let mut b = new_buf();
        assert!(b.fec_packet_tags.is_none());
        b.start_fec(std::sync::Arc::new(msg(64001 * 32)), 32);
        let allocation = b.fec_packet_tags.as_ref().unwrap().as_ptr();
        assert_eq!(b.fec_packet_tags.as_ref().unwrap().len() * std::mem::size_of::<u64>(), 2 * 1024 * 1024);
        b.fec_prepare_packet(5);
        // TU growth packs three sequential transmission ordinals (three groups) in one packet.
        for _ in 0..3 { assert!(b.next_fragment(144, 48).is_some()); }
        b.fec_on_packet_lost(5);
        assert_eq!(b.fec_send_slot.as_ref().unwrap().group_lost, vec![1, 1, 1]);
        b.fec_prepare_packet(6);
        assert!(b.next_fragment(48, 48).is_some());
        // A non-FEC nonce reuses the same ring position: its loss cannot inherit old symbols.
        b.fec_prepare_packet(6 + PACKETS_WAITING_ACK_CAPACITY);
        b.fec_on_packet_lost(6 + PACKETS_WAITING_ACK_CAPACITY);
        b.fec_on_packet_lost(6); // outside fixed history horizon
        assert_eq!(b.fec_send_slot.as_ref().unwrap().lost, 3);
        b.send_package_id = b.send_package_id.wrapping_add(1);
        b.start_fec(std::sync::Arc::new(msg(64001 * 32)), 32);
        assert_eq!(b.fec_packet_tags.as_ref().unwrap().as_ptr(), allocation);
        b.fec_on_packet_lost(5); // former message never contributes to this slot
        assert_eq!(b.fec_send_slot.as_ref().unwrap().group_lost, vec![0, 0, 0]);
    }

    #[test]
    fn grouped_closed_loop_sizes_each_owned_tail_with_union_bound() {
        use crate::fec_adapt::*;
        let mut b = new_buf();
        let a = FecAdaptiveState::new(AdaptiveFecConfig { eps: 0.5, ..Default::default() }, 0, 0, 0);
        b.fec_adaptive = Some(a.clone());
        b.start_fec(std::sync::Arc::new(msg(64001 * 32)), 32);
        let f = b.fec_send_slot.as_mut().unwrap();
        let layout = crate::fec::MessageLayout::new(f.message.len(), 32).unwrap();
        f.next_id = f.k; // all sources sent, no repairs yet
        f.group_lost[1] = 900;
        f.lost = 900;
        f.refresh_plan(&a);
        let expected_repairs = (0..layout.groups).map(|g| a.extra_repair_blocks_needed_for_group_at_tail(layout.group(g).1 as u64, layout.k as u64, layout.groups, layout.group(g).1 as u64, 0, f.group_lost[g] as u64, false)).max().unwrap();
        assert_eq!(f.n, layout.round_plan(f.k + expected_repairs as u32 * layout.groups as u32));
        let eps = a.group_failure_target(layout.k as u64, 1);
        assert_eq!(a.group_failure_target(layout.k as u64, layout.groups) * layout.groups as f64, eps);
        assert!(expected_repairs >= 900 + 2);
        let n = f.n;
        f.group_lost[1] = 0;
        f.refresh_plan(&a);
        assert_eq!(f.n, n); // plans never shrink
    }

    #[test]
    fn oversized_message_bypasses_only_empty_queues() {
        let mut b = new_buf();
        b.min_queue_size_bytes = 64;
        b.max_queue_size_bytes = 64;
        let m = msg(65);
        assert_eq!(b.free_bytes(), u64::MAX);
        assert_eq!(b.submit_messages(vec![m.clone(), vec![1]]), vec![vec![1]]);
        assert_eq!(b.queue_bytes_filled, 65);
        assert_eq!(b.free_bytes(), 0);
        assert_eq!(drain(&mut b, 1000, 2).into_iter().flatten().next().unwrap().4, m);
        assert_eq!(b.free_bytes(), u64::MAX);

        let mut rx = ReceiveQueue::default();
        let key = ConnectionKey::default();
        rx.push(key, vec![1], 64);
        rx.push(key, m.clone(), 64);
        assert_eq!(rx.messages.len(), 1);
        assert_eq!(rx.messages[0].1, m);
        assert_eq!(rx.dropped_messages, 1);
        assert!(rx.bytes > 64);
    }

    #[test]
    fn fec_capacity_scales_with_redundancy() {
        let mut b = new_buf();
        b.min_queue_size_bytes = 0;
        b.current_bytes_per_second = 1_100_000;
        b.fec_capacity_overhead_ppm = 0;
        assert_eq!(b.current_byte_capacity(), 1_100_000);
        b.fec_capacity_overhead_ppm = 100_000;
        assert_eq!(b.current_byte_capacity(), 1_000_000);
    }
}

#[cfg(test)]
mod rx_tracker_tests {
    use super::*;

    fn run(seqs: impl IntoIterator<Item = u64>) -> ConnectionStats {
        let mut st = ConnectionStats::default();
        let mut t = RxSeqTracker::default();
        for s in seqs { t.on_packet(s, &mut st); }
        let mut snap = st;
        t.provisional_bursts(&mut snap);
        snap
    }

    #[test]
    fn bursts_reordering_and_late_arrivals() {
        // Missing: 5 (1), 10-11 (2), 20-27 (8), 3000-3099 (100); 40 arrives late but in window.
        let lost = |s: u64| s == 5 || (10..12).contains(&s) || (20..28).contains(&s) || (3000..3100).contains(&s);
        let order: Vec<u64> = (0..5000).filter(|&s| !lost(s) && s != 40).flat_map(|s| if s == 45 { vec![45, 40] } else { vec![s] }).collect();
        let st = run(order);
        assert_eq!(st.rx_seq_span, 5000);
        assert_eq!(st.rx_packets, 5000 - 111);
        assert_eq!(st.rx_lost, 111);
        assert_eq!(st.rx_reordered, 1);
        assert_eq!(st.rx_late_beyond_window, 0);
        assert_eq!(st.rx_bursts, 4);
        assert_eq!(st.rx_burst_hist, [1, 1, 0, 1, 0, 0, 1]);
        // 40 arriving after the window passed it: counted as received (late), burst stays counted.
        let late: Vec<u64> = (0..5000).filter(|&s| s != 40).chain([40]).collect();
        let st = run(late);
        assert_eq!((st.rx_lost, st.rx_late_beyond_window, st.rx_bursts), (0, 1, 1));
        // A jump far beyond the window is one burst.
        let st = run([0, 1, 100_000]);
        assert_eq!((st.rx_lost, st.rx_bursts, st.rx_burst_hist[6]), (99_998, 1, 1));
        // Duplicates are not received twice.
        let st = run([0, 1, 1, 2]);
        assert_eq!((st.rx_packets, st.rx_duplicates, st.rx_lost), (3, 1, 0));
    }
}

#[cfg(test)]
mod fec_closed_loop_tests {
    use super::*;
    use crate::fec_adapt::{AdaptiveFecConfig, FecAdaptiveState};

    #[test]
    fn ready_raw_rescue_preempts_original_and_routes_suspended_feedback() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.submit_messages(vec![vec![7; 1000], vec![8; 1433 * 512]]);
        b.fec_prepare_packet(0);
        assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Plain { package_id: 0, .. })));
        for seq in 1..=2 {
            b.fec_prepare_packet(seq);
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { package_id: 1, .. })));
        }
        b.fec_on_packet_finalized(0, true);
        b.fec_prepare_packet(3);
        assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Plain { package_id: 0, .. })));
        assert_eq!(b.fec_suspended.as_ref().unwrap().next_id, 2);
        b.fec_on_packet_finalized(1, true); // original feedback while the raw rescue owns active slot
        assert_eq!(b.fec_suspended.as_ref().unwrap().lost, 1);
        b.reclaim_finished_partial();
        b.fec_on_packet_finalized(3, false);
        assert!(b.fec_suspended.is_none());
        b.fec_prepare_packet(4);
        assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { package_id: 1, block_id: 2, .. })));
        assert_eq!(b.queue_bytes_filled, 1433 * 512);
    }

    #[test]
    fn oversized_messages_keep_floor_when_feedback_rescue_cannot_retain_them() {
        let mut a = FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0);
        for seq in 0..10000 {
            a.on_data_sent(seq);
            a.on_sequence_finalized(seq, false, seq * 1000);
        }
        let message = std::sync::Arc::new(vec![0; FEC_RETAIN_SOURCE_BYTES + 1]);
        let layout = crate::fec::MessageLayout::new(message.len(), 1433).unwrap();
        let k = layout.k as u32;
        let mut f = FecSendSlot { segment: None, root_lease: None, plan_ks: None, retention_lease: None, retain_limit: FEC_RETAIN_SOURCE_BYTES, package_lease: None, dscp: Dscp::BestEffort, message, block_bytes: 1433, k, n: k, next_id: k,
            encoder: FecEncoderState::Failed, block_buf: Vec::new(), first_seq: 0,
            lost: 0, group_lost: vec![0; layout.groups], n_planned: k,
            loss_estimate: 0.0, finalized_symbols: 0, send_started_ns: 0, original_send_duration_ns: None };
        f.refresh_plan(&a);
        assert!(f.n >= k + 12 * layout.groups as u32);
    }

    #[test]
    fn completed_raw_package_deduplicates_fresh_nonce_rescue() {
        let mut slot = ReassemblySlot::new();
        slot.package_id = 7;
        assert_eq!(slot.insert(0, &[1, 2, 3], true), (true, true));
        assert_eq!(slot.take_complete(), vec![1, 2, 3]);
        assert_eq!(slot.package_id, 7);
        assert_eq!(slot.insert(0, &[1, 2, 3], true), (true, false));
        assert!(slot.buf.is_empty());
        // Receiver replacement for a newer package clears the marker.
        slot = ReassemblySlot::new();
        slot.package_id = 1031;
        assert_eq!(slot.insert(0, &[4, 5, 6], true), (true, true));
    }

    #[test]
    fn retained_lifetime_scales_with_rtt_and_original_train() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.submit_messages(vec![vec![7; 16384]]);
        b.fec_now_ns = 1_000_000_000;
        b.fec_rtt_ns = 400_000_000;
        b.fec_prepare_packet(0);
        assert!(b.next_fragment(1449, 1449).is_some());
        let mut f = b.fec_send_slot.take().unwrap();
        f.next_id = f.n;
        b.fec_now_ns = 4_000_000_000;
        b.retain_fec(f, 0);
        assert_eq!(b.fec_retained.values().next().unwrap().expires_ns, 10_200_000_000); // 4 + 8*0.4 + 3
        let r = b.pop_oldest_retained().unwrap();
        b.fec_now_ns = 5_000_000_000;
        b.retain_fec(r.slot, 0);
        assert_eq!(b.fec_retained.values().next().unwrap().expires_ns, 11_200_000_000); // original duration stays 3
    }

    #[test]
    fn retained_rescue_has_fixed_source_and_time_bounds() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        // A large raw stand-in tests accounting without constructing a codec arena.
        for package in 0..5 {
            let slot = FecSendSlot { segment: None, root_lease: None, plan_ks: None, retention_lease: None, retain_limit: FEC_RETAIN_SOURCE_BYTES, package_lease: None, dscp: Dscp::BestEffort, message: std::sync::Arc::new(vec![0; 17 * 1024 * 1024]),
                block_bytes: 1, k: 1, n: 1, next_id: 1, encoder: FecEncoderState::Failed,
                block_buf: Vec::new(), first_seq: 0, lost: 0, group_lost: vec![0],
                n_planned: 1, loss_estimate: 0.0, finalized_symbols: 0, send_started_ns: 0, original_send_duration_ns: Some(0) };
            b.retain_fec(slot, package);
        }
        assert_eq!(b.fec_retained.len(), 3);
        assert!(b.fec_retained.values().map(|r| r.slot.message.len()).sum::<usize>() <= FEC_RETAIN_SOURCE_BYTES);
        b.fec_now_ns = 2_000_000_001;
        b.fec_prune_retained();
        assert!(b.fec_retained.is_empty());
    }

    #[test]
    fn retained_encoder_rescues_after_feedback_and_retires_after_success() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.fec_record = Some(Vec::new());
        b.submit_messages(vec![vec![7; 1433 * 12], vec![8; 1433 * 12]]);
        let mut seq = 0;
        loop {
            b.fec_prepare_packet(seq);
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { package_id: 0, .. })));
            seq += 1;
            let f = b.fec_send_slot.as_ref().unwrap();
            if f.next_id >= f.n { break; }
        }
        b.reclaim_finished_partial();
        assert!(b.fec_send_slot.is_none());
        assert_eq!(b.fec_record.as_ref().unwrap().first().unwrap().n_sent, 1);
        assert_eq!(b.fec_record.as_ref().unwrap().last().unwrap().n_sent, seq as u32);
        let initial = seq;
        for s in 0..initial { b.fec_on_packet_finalized(s, true); }
        let r = b.fec_retained.values().next().unwrap();
        assert_eq!(r.slot.n - r.slot.next_id, 14); // all originals lost: K+2 new symbols
        loop {
            b.fec_prepare_packet(seq);
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { package_id: 0, .. })));
            seq += 1;
            let f = b.fec_send_slot.as_ref().unwrap();
            if f.next_id >= f.n { break; }
        }
        b.reclaim_finished_partial();
        for s in initial..seq { b.fec_on_packet_finalized(s, false); }
        assert!(!b.fec_retained.contains_key(&0));
        assert_eq!(b.fec_record.as_ref().unwrap().last().unwrap().n_sent, seq as u32);
        assert_eq!(b.queue_bytes_filled, 1433 * 12); // rescue never charges application queue
    }

    #[test]
    fn packed_raw_messages_share_feedback_and_retry_only_on_loss() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.fec_record = Some(Vec::new());
        b.submit_messages(vec![vec![7; 100], vec![8; 100]]);
        b.fec_prepare_packet(0);
        for package in 0..2 {
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Plain { package_id, .. }) if package_id == package));
        }
        b.reclaim_finished_partial();
        b.fec_on_packet_finalized(0, true);
        assert!(b.has_unsent_data());
        for (seq, package) in [(1, 0), (2, 1)] {
            b.fec_prepare_packet(seq);
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Plain { package_id, .. }) if package_id == package));
            b.reclaim_finished_partial();
            b.fec_on_packet_finalized(seq, false);
        }
        assert!(!b.has_unsent_data());
        assert!(b.fec_retained.is_empty());
        assert_eq!(b.queue_bytes_filled, 0);
        let rec = b.fec_record.as_ref().unwrap();
        assert_eq!(rec.len(), 4);
        assert_eq!(rec.iter().map(|r| r.n_sent).collect::<Vec<_>>(), vec![1, 1, 2, 2]);
    }

    #[test]
    fn learned_margin_stays_small_for_both_interior_and_tail_messages() {
        let make = || {
            let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
            b.fec_adaptive = Some(FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
            b.submit_messages(vec![vec![0; 1433 * 12]]);
            b
        };
        let mut b = make();
        assert!(b.next_fragment(1449, 1449).is_some());
        assert!(b.fec_send_slot.as_ref().unwrap().n < 24);
        // A successor arriving while sources go out has the same learned-risk floor.
        b.submit_messages(vec![vec![0; 1433 * 12]]);
        for _ in 1..13 { assert!(b.next_fragment(1449, 1449).is_some()); }
        assert!(b.fec_send_slot.as_ref().unwrap().n < 24);
        // When the queue becomes empty, retain the encoder without adding 12 blind repairs.
        let f = b.fec_send_slot.as_mut().unwrap();
        f.next_id = f.n;
        b.message_queue.clear();
        b.reclaim_finished_partial();
        assert!(b.fec_send_slot.is_none());
        assert!(b.fec_retained.values().next().unwrap().slot.n <= 17);

        let mut b = make();
        for _ in 0..13 { assert!(b.next_fragment(1449, 1449).is_some()); }
        assert!(b.fec_send_slot.as_ref().unwrap().n <= 17); // true tail at sources done
    }

    #[test]
    fn refreshes_own_loss_budget_at_source_completion_without_a_new_loss_event() {
        let cfg = AdaptiveFecConfig { eps: 0.5, ..Default::default() };
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_capacity_overhead_ppm = 10000;
        b.fec_adaptive = Some(FecAdaptiveState::new(cfg, 0, 0, 0));
        b.start_fec(std::sync::Arc::new(vec![0u8; 1433 * 64]), 1433);
        let initial_n = b.fec_send_slot.as_ref().unwrap().n;
        for seq in 0..64 {
            b.fec_prepare_packet(seq as u64);
            assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { block_id, .. }) if block_id == seq));
            b.fec_adaptive.as_mut().unwrap().on_data_sent(seq as u64);
        }
        b.fec_send_slot.as_mut().unwrap().lost = 20;
        b.fec_send_slot.as_mut().unwrap().group_lost[0] = 20;
        b.fec_prepare_packet(64);
        assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { block_id: 64, .. })));
        let f = b.fec_send_slot.as_ref().unwrap();
        assert!(f.n > initial_n && f.n >= 86 && f.n <= 128, "initial={initial_n} n={}", f.n);
        // Existing top-up callback also uses the same bounded closed-loop budget.
        b.fec_on_packet_lost(4);
        assert_eq!(b.fec_send_slot.as_ref().unwrap().lost, 21);
        assert!(b.fec_send_slot.as_ref().unwrap().n <= 128);
    }

    #[test]
    fn sparse_plain_fragments_require_shared_byte_admission() {
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(1024);
        let mut a = ReassemblySlot::new(); let mut b = ReassemblySlot::new();
        assert!(!a.admit(MAX_JUMBOGRAM_LEN - 1, 1, &budget));
        assert_eq!(a.buf.capacity(), 0); assert_eq!(budget.used(), 0);
        assert!(a.admit(599, 1, &budget)); assert_eq!(a.insert(599, &[1], false), (true,false));
        assert!(!b.admit(599, 1, &budget)); assert_eq!(b.buf.capacity(), 0);
        drop(a); assert!(b.admit(599, 1, &budget)); drop(b); assert_eq!(budget.used(), 0);
    }
    #[test]
    fn completion_queue_keeps_reservation_until_application_takes_it() {
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(4096);
        let mut queue = ReceiveQueue::default();
        let key = ConnectionKey { ip: std::net::Ipv6Addr::LOCALHOST, port: 1, key_15_bits: 0 };
        queue.push_reserved(key, vec![1;1000], 2000, Some(budget.reserve(2000).unwrap()));
        assert_eq!(budget.used(), ReceiveQueue::entry_bytes(&queue.messages[0].1) + 128);
        queue.push_reserved(key, vec![2;1000], 1500, Some(budget.reserve(2000).unwrap()));
        assert_eq!(queue.messages.len(),1); assert!(budget.used() < 1500);
        let messages = queue.take(); assert_eq!(budget.used(),0); assert_eq!(messages.len(),1);
    }

    #[test]
    fn inline_fec_requires_and_releases_receive_budget() {
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(2<<20);
        let workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (done, _) = std::sync::mpsc::channel();
        let key = ConnectionKey { ip: std::net::Ipv6Addr::LOCALHOST, port: 1, key_15_bits: 0 };
        let mut a = FecRecvSlot::default(); let mut b = FecRecvSlot::default();
        fec_receive_block(&mut a, key, 0, 256000, 1000, 0, &[0;1000], &done, &workers, &budget);
        assert!(matches!(a.state, FecRecvState::Inline(_))); assert!(budget.used() > 256000);
        fec_receive_block(&mut b, key, 1, 256000, 1000, 0, &[0;1000], &done, &workers, &budget);
        assert!(b.admission_refused); assert_eq!(b.ingress_dropped,1);
        drop(a); assert_eq!(budget.used(),0);
    }
}

#[cfg(test)]
mod send_queue_tests {
    use super::*;
    fn packet(s: &mut SendQueues, seq: u64) -> (usize, Vec<u8>) {
        s.fec_prepare_packet(seq);
        let mut p = vec![0; 1449];
        assert!(s.fill_packet(&mut p) > 0);
        (s.last_queue, p)
    }
    #[test]
    fn backlogged_magazines_share_packets_exactly() {
        for n in [2, 3] {
            let mut s = SendQueues::new(n, (1000000, 16<<20, 16<<20));
            for q in 0..n { assert!(s.submit_messages(q, vec![vec![q as u8; 8<<20]]).is_empty()); }
            let mut counts = vec![0; n];
            for seq in 0..3000 { counts[packet(&mut s, seq).0] += 1; }
            assert!(counts.iter().all(|&c| c == 3000 / n));
        }
    }
    #[test]
    fn idle_magazine_gets_next_packet_and_full_bulk_does_not_block_enqueue() {
        let mut s = SendQueues::new(8, (1000000, 2000, 2000));
        s.submit_messages(0, vec![vec![1; 4000]]);
        assert_eq!(s.submit_messages(0, vec![vec![2; 1000]]).len(), 1);
        assert_eq!(packet(&mut s, 0).0, 0);
        assert!(s.submit_messages(7, vec![vec![3; 1000]]).is_empty());
        let (_, mixed) = packet(&mut s, 1);
        // The new FIFO goes first; the old queue can use its remaining tail.
        assert_eq!(read_fragment_header(&mixed).unwrap().1, 4);
        assert_eq!(&mixed[4..1004], &[3;1000]);
        assert_eq!(packet(&mut s, 2).0, 0);
        assert_eq!(s.submit_messages(8, vec![vec![4; 100]]).len(), 1);
    }
    #[test]
    fn fifo_and_connection_app_limited_only_when_every_magazine_empty() {
        let mut s = SendQueues::new(3, (1000000, 10000, 10000));
        assert!(!s.has_unsent_data());
        s.submit_messages(2, vec![vec![1; 3000], vec![2; 3000], vec![3; 1000], vec![4; 1000]]);
        let mut seq = 0;
        let mut seen = Vec::new();
        while s.has_unsent_data() {
            s.fec_prepare_packet(seq);
            let mut p = vec![0; 1449];
            if s.fill_packet(&mut p) == 0 { break; }
            let mut cursor = 0;
            while let Some((h, header)) = read_fragment_header(&p[cursor..]) {
                let len = ((h >> 18) & 0x3fff) as usize;
                let byte = p[cursor + header];
                if seen.last() != Some(&byte) { seen.push(byte); }
                cursor += header + len;
            }
            seq += 1;
        }
        assert_eq!(seen, [1, 2, 3, 4]);
        assert!(!s.has_unsent_data());
        s.submit_messages(1, vec![vec![5; 1000]]);
        assert!(s.has_unsent_data());
    }
    #[test]
    fn rescue_on_nonzero_magazine_counts_in_its_share_and_routes_all_feedback() {
        let mut s = SendQueues::new(2, (1000000, 2<<20, 2<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_messages(0, vec![vec![6; 1433*512]]);
        s.submit_messages(1, vec![vec![7; 1000], vec![8; 1433*512]]);
        assert_eq!(packet(&mut s, 0).0, 0);
        assert_eq!(packet(&mut s, 1).0, 1);
        packet(&mut s, 2);
        packet(&mut s, 3);
        let ordinal = s.queues[1].fec_send_slot.as_ref().unwrap().next_id;
        s.fec_on_packet_finalized(1, true);
        assert_eq!(packet(&mut s, 4).0, 1);
        assert_eq!(packet(&mut s, 5).0, 0);
        assert_eq!(s.queues[1].fec_send_slot.as_ref().unwrap().next_id, ordinal);
        s.fec_on_packet_finalized(2, true);
        assert_eq!(s.queues[1].fec_send_slot.as_ref().unwrap().lost, 1);
        s.fec_on_packet_finalized(0, true);
        assert_eq!(s.queues[0].fec_send_slot.as_ref().unwrap().lost, 1);
        packet(&mut s, 6);
        packet(&mut s, 7);
        assert!(s.queues[1].fec_suspended.is_none());
        assert_eq!(s.queues[1].fec_send_slot.as_ref().unwrap().next_id, ordinal + 1);
    }
    #[test]
    fn per_magazine_retention_reservation_preserves_small_history() {
        let mut s = SendQueues::new(2, (1000000, 1<<20, 1<<20));
        let slot = |len| FecSendSlot { segment: None, root_lease: None, plan_ks: None, retention_lease: None, retain_limit: FEC_RETAIN_SOURCE_BYTES, package_lease: None, dscp: Dscp::BestEffort, message: std::sync::Arc::new(vec![0; len]), block_bytes: len,
            k: 1, n: 1, next_id: 1, encoder: FecEncoderState::Failed, block_buf: Vec::new(),
            first_seq: 0, lost: 0, group_lost: vec![0], n_planned: 1, loss_estimate: 0.0,
            finalized_symbols: 0, send_started_ns: 0, original_send_duration_ns: None };
        s.queues[1].retain_fec(slot(1000), 0);
        s.queues[0].retain_fec(slot(32<<20), 1);
        s.queues[0].retain_fec(slot(32<<20), 2);
        s.bound_retention();
        assert_eq!(s.queues[1].fec_retained.len(), 1);
        assert_eq!(s.queues[0].fec_retained.len(), 1);
    }
}

#[cfg(test)]
mod traffic_class_tests {
    use super::*;
    #[test]
    fn packing_never_upgrades_bulk_and_equal_classes_still_pack() {
        let mut s = SendQueues::new(1, (1000000, 10000, 10000));
        s.submit_classified_messages(0, vec![(Dscp::Ef, vec![1; 100]), (Dscp::BestEffort, vec![2; 100]), (Dscp::BestEffort, vec![3; 100])]);
        let mut p = vec![0; 1449];
        s.fec_prepare_packet(0);
        assert_eq!(s.fill_packet(&mut p), p.len());
        assert_eq!(s.last_dscp, Dscp::Ef);
        assert_eq!(&p[104..112], &[255; 8]);
        s.fec_prepare_packet(1);
        assert_eq!(s.fill_packet(&mut p), p.len());
        assert_eq!(s.last_dscp, Dscp::BestEffort);
        assert_eq!(p[4], 2);
        assert_eq!(p[108], 3);
    }
    #[test]
    fn fec_sources_repairs_and_raw_rescue_keep_message_class() {
        let mut s = SendQueues::new(2, (1000000, 100000, 100000));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_classified_messages(1, vec![(Dscp::Ef, vec![1; 1000]), (Dscp::Af11, vec![2; 3000])]);
        let mut p = vec![0; 1449];
        s.fec_prepare_packet(0); assert!(s.fill_packet(&mut p) > 0); assert_eq!(s.last_dscp, Dscp::Ef);
        s.fec_on_packet_finalized(0, true);
        s.fec_prepare_packet(1); assert!(s.fill_packet(&mut p) > 0); assert_eq!(s.last_dscp, Dscp::Ef);
        for seq in 2..10 {
            s.fec_prepare_packet(seq);
            if s.fill_packet(&mut p) == 0 { break; }
            assert_eq!(s.last_dscp, Dscp::Af11);
        }
        assert!(!s.has_unsent_data());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn selected_message_class_is_received_in_ip_header_on_loopback() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        let fd = receiver.as_raw_fd();
        let enabled: libc::c_int = 1;
        unsafe { assert_eq!(libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, &enabled as *const _ as *const _, 4), 0); }
        let sender = setup_and_bind_udp_socket(0).unwrap();
        let mut s = SendQueues::new(1, (1000000, 100000, 100000));
        for class in [Dscp::BestEffort, Dscp::Af11, Dscp::Af21, Dscp::Ef] {
            s.submit_classified_messages(0, vec![(class, vec![class as u8; 1000])]);
            let mut p = vec![0; 1449];
            s.fec_prepare_packet(class as u64);
            let n = s.fill_packet(&mut p);
            assert!(n > 0);
            udp_send_with_congestion_and_dscp(sender, std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(), receiver.local_addr().unwrap().port(), &p[..n], s.last_dscp, false);
            let mut buf = [0u8; 1500];
            let mut cbuf = [0u64; 16]; // ancillary alignment
            unsafe {
                let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_iov = &mut iov; msg.msg_iovlen = 1;
                msg.msg_control = cbuf.as_mut_ptr().cast(); msg.msg_controllen = std::mem::size_of_val(&cbuf);
                assert_eq!(libc::recvmsg(fd, &mut msg, 0), n as isize);
                let mut c = libc::CMSG_FIRSTHDR(&msg);
                let mut tos = None;
                while !c.is_null() {
                    if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_TOS { tos = Some(*libc::CMSG_DATA(c)); }
                    c = libc::CMSG_NXTHDR(&msg, c);
                }
                assert_eq!(tos.unwrap() >> 2, class as u8);
            }
        }
    }
}
#[cfg(test)]
mod review_tests {
    use super::*;
    fn pkt(s: &mut SendQueues, seq: u64, len: usize) -> usize {
        s.fec_prepare_packet(seq);
        let mut p = vec![0; len];
        s.fill_packet(&mut p)
    }
    fn plain_ids(p: &[u8]) -> Vec<u16> {
        let mut v = Vec::new(); let mut c = 0;
        while let Some((h, header)) = read_fragment_header(&p[c..]) {
            v.push(((h >> 2) & 0xffff) as u16); c += header + ((h >> 18) & 0x3fff) as usize; }
        v
    }
    // A long FEC train on one magazine keeps its package id while a small-message magazine burns ids.
    #[test]
    fn review_package_window_overrun_across_queues() {
        let mut s = SendQueues::new(2, (1000000, 64<<20, 64<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_messages(1, vec![vec![7; 1433*2000]]);
        s.submit_messages(0, (0..5000).map(|i| vec![i as u8; 100]).collect());
        let mut seq = 0; let mut bulk_id = None; let mut collided_at = None;
        for _ in 0..1000 {
            s.fec_prepare_packet(seq);
            let mut p = vec![0; 1449];
            assert!(s.fill_packet(&mut p) > 0);
            if s.last_queue == 1 { bulk_id = Some(s.queues[1].send_package_id); }
            if s.last_queue == 0 { if let Some(b) = bulk_id {
                for id in plain_ids(&p) { if id % 1024 == b % 1024 && id != b && collided_at.is_none() { collided_at = Some(seq); } }
            } }
            seq += 1;
        }
        let b = bulk_id.unwrap();
        let f = s.queues[1].fec_send_slot.as_ref().unwrap();
        eprintln!("bulk id {b} still sending block {}/{}; queue 0 sent id = bulk+1024 at packet seq {:?}; allocator now {}",
            f.next_id, f.n, collided_at, s.queues[0].package_allocator.as_ref().unwrap().load(std::sync::atomic::Ordering::Relaxed));
        assert!(collided_at.is_none(), "receiver ring slot of in-flight bulk package overwritten by newer id");
    }
    // 16-bit wrap: another queue's message with the same package id finalizes/rescues a retained slot it does not own.
    #[test]
    fn review_cross_queue_package_alias_misroutes_feedback() {
        let mut s = SendQueues::new(2, (1000000, 1<<20, 1<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.queues[0].package_allocator.as_ref().unwrap().store(500, std::sync::atomic::Ordering::Relaxed);
        s.submit_messages(1, vec![vec![1; 1000]]);
        assert!(pkt(&mut s, 0, 1449) > 0); assert_eq!(s.last_queue, 1);
        assert_eq!(s.queues[1].fec_retained.len(), 1);
        // 65536 ids later (other traffic on queue 0), queue 0 reuses id 500.
        s.queues[0].package_allocator.as_ref().unwrap().store(500, std::sync::atomic::Ordering::Relaxed);
        s.submit_messages(0, vec![vec![2; 1000]]);
        assert!(pkt(&mut s, 1, 1449) > 0); assert_eq!(s.last_queue, 0);
        // Queue 0's packet is acked first; then queue 1's original is declared lost.
        s.fec_on_packet_finalized(1, false);
        let still_retained = s.queues[1].fec_retained.len();
        s.fec_on_packet_finalized(0, true);
        eprintln!("q1 retained after q0's ack: {still_retained}; q1 will rescue: {}", s.queues[1].has_unsent_data());
        assert!(s.queues[1].has_unsent_data(), "queue 1's lost message is never rescued: its slot was finalized by queue 0's ack");
    }
    // Abandoned K=1 rescue on a shrunken packet: suspended train of another class yields an empty packet.
    #[test]
    fn review_rescue_abandon_class_mismatch_returns_empty_packet() {
        let mut s = SendQueues::new(1, (1000000, 4<<20, 4<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_classified_messages(0, vec![(Dscp::Ef, vec![1; 1200]), (Dscp::BestEffort, vec![2; 1433*64])]);
        assert!(pkt(&mut s, 0, 1449) > 0); assert_eq!(s.last_dscp, Dscp::Ef);
        assert!(pkt(&mut s, 1, 1449) > 0); assert_eq!(s.last_dscp, Dscp::BestEffort);
        s.fec_on_packet_finalized(0, true);
        let n = pkt(&mut s, 2, 1000);
        eprintln!("fill after abandoned rescue: {n} bytes, has_unsent_data={}", s.has_unsent_data());
        assert!(n > 0 || !s.has_unsent_data());
    }
    // Per-packet cost of retained-slot scans added to fill_packet (bound_retention + has_unsent_data).
    #[test]
    fn review_hot_path_cost_with_full_retention() {
        let slot = |len| FecSendSlot { segment: None, root_lease: None, plan_ks: None, retention_lease: None, retain_limit: FEC_RETAIN_SOURCE_BYTES, package_lease: None, dscp: Dscp::BestEffort, message: std::sync::Arc::new(vec![0; len]), block_bytes: len,
            k: 1, n: 1, next_id: 1, encoder: FecEncoderState::Failed, block_buf: Vec::new(),
            first_seq: 0, lost: 0, group_lost: vec![0], n_planned: 1, loss_estimate: 0.0,
            finalized_symbols: 0, send_started_ns: 0, original_send_duration_ns: None };
        for (retained, QQ) in [(0usize, 1usize), (4000, 1), (4000, 0)] {
            let mut s = SendQueues::new(2, (1000000, 1<<30, 1<<30));
            for i in 0..retained { s.queues[QQ].retain_fec(slot(100), i as u16); }
            s.submit_messages(0, (0..20000).map(|_| vec![3; 1400]).collect());
            let mut p = vec![0; 1449];
            let t = std::time::Instant::now();
            for seq in 0..20000 { s.fec_prepare_packet(seq); assert!(s.fill_packet(&mut p) > 0); }
            let ns = t.elapsed().as_nanos() / 20000;
            let t = std::time::Instant::now();
            for _ in 0..20000 { s.bound_retention(); std::hint::black_box(s.has_unsent_data()); }
            eprintln!("retained={retained} in q{QQ}: fill_packet {ns} ns/pkt; bound_retention+has_unsent_data {} ns", t.elapsed().as_nanos() / 20000);
        }
    }
}

#[cfg(test)]
mod sender_lifetime_tests {
    use super::*;
    #[test]
    fn plain_originals_also_pin_receiver_ring_positions() {
        let mut s = SendQueues::new(2, (1000000, 8<<20, 8<<20));
        s.submit_messages(1, vec![vec![9; 1433*2000]]);
        s.submit_messages(0, (0..5000).map(|_| vec![8; 100]).collect());
        let mut p = vec![0; 1449]; let mut bulk = None;
        for seq in 0..1000 {
            s.fec_prepare_packet(seq); assert!(s.fill_packet(&mut p) > 0);
            if s.last_queue == 1 { bulk = Some(s.queues[1].send_package_id); }
            else if let Some(id) = bulk {
                let mut c = 0;
                while let Some((h, header)) = read_fragment_header(&p[c..]) {
                    assert_ne!(((h>>2)&0xffff) as usize % 1024, id as usize%1024);
                    c += header+((h>>18)&0x3fff) as usize;
                }
            }
        }
        assert!(s.queues[1].partial_send_slot.is_some());
    }
    #[test]
    fn rescue_and_suspended_original_hold_and_release_quota_leases() {
        let mut b = UnreliableSendBuffer::new(1000000, 100000, 100000);
        b.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.submit_messages(vec![vec![7; 1000], vec![8; 3000]]);
        b.fec_prepare_packet(0); b.next_fragment(1449, 1449).unwrap();
        b.fec_prepare_packet(1); b.next_fragment(1449, 1449).unwrap();
        b.fec_on_packet_finalized(0, true);
        b.fec_prepare_packet(2); b.next_fragment(1449, 1449).unwrap();
        assert!(b.fec_suspended.is_some());
        assert_eq!(*b.retention_quota.used.lock().unwrap(), (4000, 2));
        assert!(b.fec_send_slot.as_ref().unwrap().retention_lease.is_some());
        assert!(b.fec_suspended.as_ref().unwrap().retention_lease.is_some());
        b.reclaim_finished_partial();
        assert_eq!(*b.retention_quota.used.lock().unwrap(), (1000, 1));
        b.fec_on_packet_finalized(2, false);
        assert_eq!(*b.retention_quota.used.lock().unwrap(), (0, 0));
    }
    #[test]
    fn strict_quota_denies_unaccounted_suspension() {
        let mut b = UnreliableSendBuffer::new(1000000, 100000, 100000);
        b.retention_quota = std::sync::Arc::new(RetentionQuota { byte_limit: 3000, slot_limit: 4, used: std::sync::Mutex::new((0,0)) });
        b.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        b.submit_messages(vec![vec![7; 1000], vec![8; 3000]]);
        b.fec_prepare_packet(0); b.next_fragment(1449, 1449).unwrap();
        b.fec_prepare_packet(1); b.next_fragment(1449, 1449).unwrap();
        b.fec_on_packet_finalized(0, true);
        b.fec_prepare_packet(2);
        assert!(matches!(b.next_fragment(1449, 1449), Some(UnreliableFragment::Fec { package_id: 1, .. })));
        assert!(b.fec_suspended.is_none());
        assert_eq!(*b.retention_quota.used.lock().unwrap(), (1000,1));
    }
    #[test]
    fn packet_owner_ring_excludes_other_queues_even_with_a_forged_alias() {
        let mut s = SendQueues::new(2, (1000000, 100000, 100000));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_messages(1, vec![vec![7; 1000]]);
        let mut p = vec![0; 1449];
        s.fec_prepare_packet(0); s.fill_packet(&mut p);
        let q1_id = *s.queues[1].fec_retained.keys().next().unwrap();
        s.submit_messages(0, vec![vec![8; 1000]]);
        s.fec_prepare_packet(1); s.fill_packet(&mut p);
        // Defense in depth: pretend a tag aliases an old package despite the slot lease.
        s.fec_packet_tags.as_mut().unwrap()[1] = ((q1_id as u64)<<48)|(1u64<<32);
        s.fec_on_packet_finalized(1, false);
        assert_eq!(s.queues[1].fec_retained[&q1_id].slot.finalized_symbols, 0);
        s.fec_on_packet_finalized(0, true);
        assert!(s.queues[1].has_unsent_data());
    }
}

#[cfg(test)]
mod package_pressure_tests {
    use super::*;
    #[test]
    fn failed_ring_probes_do_not_burn_package_generations() {
        let allocator = std::sync::Arc::new(PackageAllocator::new());
        let mut leases: Vec<_> = (0..1024).map(|_| allocator.allocate().unwrap()).collect();
        let next = allocator.load(std::sync::atomic::Ordering::Relaxed);
        for _ in 0..128 { assert!(allocator.allocate().is_none()); }
        assert_eq!(allocator.load(std::sync::atomic::Ordering::Relaxed), next);
        let old = leases.remove(0).id;
        let fresh = allocator.allocate().unwrap();
        assert_eq!(fresh.id % 1024, old % 1024);
        assert!((fresh.id.wrapping_sub(old) as i16) > 0);
        assert_eq!(fresh.id, 1024);
    }
}

#[cfg(test)]
mod ring_pressure_rescue_tests {
    use super::*;
    #[test]
    fn ring_pressure_preserves_retained_sources_until_feedback() {
        let mut s = SendQueues::new(1, (1_000_000, 2<<20, 2<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_messages(0, (0..1025).map(|_| vec![1; 1000]).collect());
        for seq in 0..1024 {
            s.fec_prepare_packet(seq);
            assert!(s.fill_packet(&mut [0; 1449]) > 0);
        }
        assert_eq!(s.queues[0].fec_retained.len(), 1024);
        s.fec_prepare_packet(1024);
        assert_eq!(s.fill_packet(&mut [0; 1449]), 0);
        assert_eq!(s.queues[0].fec_retained.len(), 1024);
        s.fec_on_packet_finalized(0, true);
        s.fec_prepare_packet(1024);
        assert!(s.fill_packet(&mut [0; 1449]) > 0); // resend without allocating an ID
        s.fec_on_packet_finalized(1024, false);
        s.fec_prepare_packet(1025);
        assert!(s.fill_packet(&mut [0; 1449]) > 0); // the deferred original now has a lease
    }
}

#[cfg(test)]
mod outage_review_repros {
    use super::*;
    fn state() -> ConnectionStateConnected {
        let ConnectionState::Connected(s) = new_connection_state_connected(None, 0, 1, 1_000_000_000) else { unreachable!() }; s
    }
    fn buffer() -> SendQueues {
        let mut b = SendQueues::new(1, (100000, 1000000, 1000000));
        b.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 1_000_000_000, 0, 0)); b
    }
    #[test]
    fn resume_preserves_ready_fec_rescue_tu() {
        let mut b = buffer(); let mut s = state(); s.stats.cc_rate_upps = 100_000_000;
        s.current_tu = 1472;
        b.queues[0].fec_now_ns = 1_000_000_000;
        b.submit_messages(0, vec![vec![7; 1433 * 12]]);
        let mut seq = 0;
        loop {
            b.fec_prepare_packet(seq);
            assert!(b.fill_packet(&mut [0; 1449]) > 0);
            s.account_send(1_000_000_000 + seq * 1_000_000); s.packets_in_flight += 1;
            seq += 1;
            if b.queues[0].fec_send_slot.as_ref().is_none_or(|f| f.next_id >= f.n) { break; }
        }
        b.queues[0].reclaim_finished_partial(); assert_eq!(b.queues[0].fec_retained.len(), 1);
        enter_outage(&mut s, &mut b, 2_999_000_000, 0, None);
        assert!(b.queues[0].fec_retained[&0].slot.next_id < b.queues[0].fec_retained[&0].slot.n);
        resume_outage(&mut s, &mut b, &mut [], 27_000_000_000, None);
        b.queues[0].fec_now_ns = 27_000_000_000;
        assert_eq!(s.current_tu, 1472);
        assert!(b.fill_packet(&mut [0; 1449]) > 0);
    }
    #[test]
    fn receiver_decoder_has_full_grace_after_resume() {
        let mut s = state(); let mut b = buffer(); s.stats.cc_rate_upps = 100_000_000;
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        let mut slots = [FecRecvSlot { segment: None, reservation: None, package_id: 0, state: FecRecvState::Worker { tx, message_len: 1_000_000, block_bytes: 1000 }, blocks_received: 1, last_block_ns: 1_000_000_000, ingress_dropped: 0, admission_refused: false }];
        s.account_send(6_000_000_000); s.packets_in_flight = 1;
        enter_outage(&mut s, &mut b, 6_001_000_000, 0, None);
        assert_eq!(retire_inactive_fec_workers(&mut slots, 25_000_000_000, OUTAGE_TIMEOUT_NS, false), 0);
        // A decoder may receive delayed ingress AFTER the sender-side entry.
        slots[0].last_block_ns = 8_000_000_000;
        resume_outage(&mut s, &mut b, &mut slots, 25_000_000_000, None);
        assert_eq!(slots[0].last_block_ns, 25_000_000_000);
        assert_eq!(retire_inactive_fec_workers(&mut slots, 25_000_000_000, fec_inactive_grace_ns(s.RTT_mean, false), false), 0);
        assert!(matches!(slots[0].state, FecRecvState::Worker { .. }));
    }
    #[test]
    fn entry_does_not_resurrect_source_already_outside_retention() {
        let mut b = buffer(); let mut s = state();
        b.queues[0].fec_now_ns = 1_000_000_000;
        b.submit_messages(0, vec![vec![7; 100]]); b.fec_prepare_packet(0);
        assert!(b.fill_packet(&mut [0; 1449]) > 0); b.queues[0].reclaim_finished_partial();
        assert_eq!(b.queues[0].fec_retained.len(), 1);
        s.account_send(1_000_000_000); s.packets_in_flight = 1;
        enter_outage(&mut s, &mut b, 3_000_000_001, 0, None);
        // Boundary case: normal loss/rescue ticks were deliberately skipped;
        // a source already expired at entry is outside retention, not resurrected.
        assert!(b.queues[0].fec_retained.is_empty());
    }
    #[test]
    fn withheld_probe_ack_cannot_restart_deadline() {
        let mut s = state();
        s.outage.enter(3_000_000_000, 100_000_000);
        s.account_send(3_000_000_000);
        s.outage.probes[0] = (0, 3_000_000_000);
        let a = crate::ack::BitmapAck { highest: 0, sample_seq: 0, delay_us: 0, ce_count: 0, bitmap: [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] };
        assert!(recent_outage_probe_acked(&s, &a, 3_100_000_000));
        assert!(!recent_outage_probe_acked(&s, &a, 120_000_000_000));
        assert_eq!(s.last_ack_received_time, 1_000_000_000);
    }
    #[test]
    fn first_idle_keepalive_waits_for_feedback_before_outage() {
        let mut s = state();
        s.account_send(6_000_000_000);
        let start = s.outage.pending_since_ns.unwrap().max(s.last_ack_received_time);
        assert_eq!(start, 6_000_000_000);
        assert!(6_001_000_000u64.saturating_sub(start) < OUTAGE_ACK_SILENCE_NS);
        s.packets_waiting_ack_tail = s.send_sequence_number; // ordinary retirement empties ring
        s.account_send(8_000_000_000);
        assert_eq!(s.outage.pending_since_ns, Some(6_000_000_000));
        assert_eq!(s.last_ack_received_time, 1_000_000_000); // Sending never refreshes deadline.
    }
    #[test]
    fn outage_cumulative_losses_and_late_corrections_do_not_poison_fec() {
        let mut s = state(); let mut b = buffer();
        s.stats.packets_sent = 100;
        s.stats.packets_lost = 50;
        s.outage.ignored_losses = 50;
        s.outage.enter(3_000_000_000, 100_000_000);
        resume_outage(&mut s, &mut b, &mut [], 27_000_000_000, None);
        let fresh = crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 27_000_000_000, 100, 0);
        assert_eq!(b.fec_adaptive.as_ref().unwrap().repair_blocks(128), fresh.repair_blocks(128));
        assert_eq!(b.fec_adaptive.as_ref().unwrap().p, fresh.p);
        s.stats.packets_lost += 2; // genuine post-resume loss
        s.stats.spurious_losses += 3; // late outage ACKs
        s.outage.ignored_spurious += 3;
        assert_eq!(fec_learning_counters(&s), (2, 0));
    }
}

#[cfg(test)]
mod compact_frame_tests {
    use super::*;
    #[test]
    fn whole_messages_pack_at_four_bytes_each_and_padding_stops_in_constant_time() {
        let mut b = UnreliableSendBuffer::new(1_000_000, 10000, 10000);
        b.submit_messages((0..13).map(|i| vec![i; 80]).collect());
        let mut p = [0; 1162];
        assert_eq!(fill_packet_payload_with_unreliable_fragments(&mut p, &mut b), p.len());
        let mut cursor = 0;
        for i in 0..13 {
            let (h, size) = read_fragment_header(&p[cursor..]).unwrap();
            assert_eq!(size, 4); assert_eq!(h & 3, 2); assert_eq!(h >> 32, 0);
            assert_eq!((h >> 18) & 0x3fff, 80);
            assert_eq!(&p[cursor+size..cursor+size+80], &[i; 80]);
            cursor += size+80;
        }
        assert_eq!(cursor, 1092);
        assert!(read_fragment_header(&p[cursor..]).is_none());
        assert!(p[cursor..].iter().all(|&b| b == 255));
        for n in 0..4 { assert!(read_fragment_header(&p[cursor..cursor+n]).is_none()); }
        // Largest package id remains distinguishable from the all-ones padding marker.
        let mut q = [0; 84];
        write_fragment(&mut q, UnreliableFragment::Plain { is_fin: true, package_id: u16::MAX, data: &[7;80], offset: 0 });
        assert_eq!((read_fragment_header(&q).unwrap().0 >> 2) & 0xffff, u16::MAX as u64);
    }
}

#[cfg(test)]
mod byte_fair_packing_tests {
    use super::*;
    fn frames(p: &[u8]) -> Vec<(u16, usize, Vec<u8>)> {
        let mut out = Vec::new(); let mut cursor = 0;
        while let Some((h, size)) = read_fragment_header(&p[cursor..]) {
            let size = if h & 1 != 0 { 16 } else { size };
            let len = ((h >> 18) & 0x3fff) as usize;
            out.push((((h >> 2) & 0xffff) as u16, size, p[cursor+size..cursor+size+len].to_vec()));
            cursor += size+len;
        }
        out
    }
    #[test]
    fn unequal_whole_message_sizes_get_equal_byte_service_and_fifo() {
        for n in [2, 3] {
            let mut s = SendQueues::new(n, (1_000_000, 16<<20, 16<<20));
            for q in 0..n {
                let len = [80, 1000, 400][q];
                s.submit_messages(q, (0..10000u32).map(|i| {
                    let mut m = vec![q as u8; len]; m[..4].copy_from_slice(&i.to_le_bytes()); m
                }).collect());
            }
            let mut bytes = vec![0usize; n]; let mut seen = vec![0u32; n];
            for seq in 0..1000 {
                s.fec_prepare_packet(seq); let mut p = [0;1162];
                assert_eq!(s.fill_packet(&mut p), p.len());
                for (_, header, data) in frames(&p) {
                    let q = data[4] as usize;
                    assert_eq!(u32::from_le_bytes(data[..4].try_into().unwrap()), seen[q]);
                    seen[q] += 1; bytes[q] += header+data.len();
                }
            }
            assert!(*bytes.iter().max().unwrap()-*bytes.iter().min().unwrap() <= 2*1162, "{bytes:?}");
            assert_eq!(bytes.iter().map(|&b| b as u64).collect::<Vec<_>>(), s.scheduled_bytes);
        }
    }
    #[test]
    fn cross_queue_packing_keeps_every_sources_owner_and_rescue_feedback() {
        let mut s = SendQueues::new(2, (1_000_000, 10000, 10000));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        for q in 0..2 { s.submit_messages(q, vec![vec![q as u8;80];7]); }
        let mut p = [0;1162]; s.fec_prepare_packet(0); s.fill_packet(&mut p);
        let f = frames(&p); assert_eq!(f.len(),13);
        assert!(f.iter().any(|f| f.2[0] == 0) && f.iter().any(|f| f.2[0] == 1));
        for q in &mut s.queues { q.reclaim_finished_partial(); }
        s.fec_on_packet_finalized(0,true);
        for (package, _, data) in f {
            let owner = data[0] as usize;
            let slot = &s.queues[owner].fec_retained[&package].slot;
            assert_eq!(slot.finalized_symbols,1); assert_eq!(slot.lost,1);
            assert!(slot.next_id < slot.n);
        }
        s.bound_retention();
        // Retry both queues in one packet and route successful feedback once per source.
        s.fec_prepare_packet(1); s.fill_packet(&mut p); s.fec_on_packet_finalized(1,false);
        assert!(s.queues.iter().all(|q| q.rescue_ready_count == 0));
    }
    #[test]
    fn mtu_growth_tail_can_carry_another_queues_whole_messages_without_reencoding() {
        let mut s = SendQueues::new(2, (1_000_000, 1<<20, 1<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,0,0,0));
        s.submit_messages(0,vec![vec![9;65536]]);
        s.fec_prepare_packet(0); s.fill_packet(&mut [0;1162]);
        assert_eq!(s.queues[0].fec_send_slot.as_ref().unwrap().block_bytes,1146);
        s.submit_messages(1,vec![vec![7;80];3]);
        let mut p = [0;1449]; s.fec_prepare_packet(1); s.fill_packet(&mut p);
        let f = frames(&p);
        assert!(f.iter().any(|f| f.1 == 16 && f.2.len()==1146));
        assert_eq!(f.iter().filter(|f| f.1 == 4 && f.2.len()==80).count(),3);
        assert_eq!(s.queues[0].fec_send_slot.as_ref().unwrap().block_bytes,1146);
    }
}

#[cfg(test)]
mod uniform_udp_capture_tests {
    use super::*;
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
    use std::time::{Duration, Instant};

    /// A real UDP relay records every encrypted datagram from BOTH peers. It holds
    /// MTU discovery at 1184, then admits up to 1472, and later blackholes both
    /// directions. Send-site expectations are cross-checked against actual bytes,
    /// not just against payload construction or packet counters.
    #[test]
    fn every_encrypted_udp_datagram_has_only_current_tu_ack_or_mtu_probe_size() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let server_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        relay.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let actual = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let blackout = Arc::new(AtomicBool::new(false));
        let mtu = Arc::new(AtomicUsize::new(1184));
        let (observed, stopping, blackholing, allowed) = (actual.clone(), stop.clone(), blackout.clone(), mtu.clone());
        let forwarder = std::thread::spawn(move || {
            let mut buf = [0; 10000]; let mut client_addr = None;
            while !stopping.load(Ordering::Acquire) {
                match relay.recv_from(&mut buf) {
                    Ok((len, source)) => {
                        observed.lock().unwrap().push(buf[..len].to_vec());
                        let target = if source == server_addr { client_addr } else { client_addr = Some(source); Some(server_addr) };
                        if !blackholing.load(Ordering::Acquire) && len <= allowed.load(Ordering::Acquire) {
                            if let Some(target) = target { relay.send_to(&buf[..len], target).unwrap(); }
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => (),
                    Err(e) => panic!("UDP capture relay: {e}"),
                }
            }
        });
        let log = Arc::new(Mutex::new(Vec::new()));
        let server_key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
        let address = STPAddress { ip: "127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().to_ipv6_mapped(), port: relay_port, magic1: server_key.magic1, key: server_key.public.clone() };
        let key = address.to_connection_key();
        let options = || NetworkThreadOptions { send_queue_count: 2, datagram_log: Some(log.clone()), ..Default::default() };
        let mut server = new_network_thread_with_options(vec![server_key], port, Some(1000), (1_000_000, 16<<20, 16<<20), options());
        let mut client = new_network_thread_with_options(vec![new_keypair_from_connect_magic1(address.magic1).unwrap()], 0, Some(1000), (1_000_000, 16<<20, 16<<20), options());
        server.join_on_drop = true; client.join_on_drop = true;
        let mut cw = service_connections(&client, NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).unwrap().current_connections;
        let mut sw = Vec::new(); let mut received = Vec::new();
        let poll = |cw: &mut Vec<(STPAddress,[u8;64])>, sw: &mut Vec<(STPAddress,[u8;64])>, received: &mut Vec<Vec<u8>>| {
            let c = service_connections(&client, NetworkThreadPush { wanted_connections: cw.clone(), ..Default::default() }).unwrap();
            let tu = c.connection_stats.first().map(|(_,s)| s.udp_payload_tu).unwrap_or(0);
            *cw = c.current_connections;
            let s = service_connections(&server, NetworkThreadPush { wanted_connections: sw.clone(), ..Default::default() }).unwrap();
            *sw = s.current_connections;
            received.extend(s.received_unreliable_messages.into_iter().map(|(_,m)| m));
            tu
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while cw.is_empty() || sw.is_empty() {
            poll(&mut cw, &mut sw, &mut received);
            assert!(Instant::now() < deadline, "encrypted connection did not finish handshake");
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut messages = vec![(key,0,Dscp::BestEffort,vec![3;65536]);2];
        messages.push((key,0,Dscp::BestEffort,vec![7;4<<20]));
        messages.extend(vec![(key,1,Dscp::BestEffort,vec![1;80]);20]);
        messages.extend(vec![(key,1,Dscp::BestEffort,vec![2;1000]);10]);
        messages.push((key,1,Dscp::BestEffort,vec![]));
        service_connections(&client, NetworkThreadPush { wanted_connections: cw.clone(), send_unreliable: messages, ..Default::default() }).unwrap();
        let growth_time = Instant::now() + Duration::from_millis(200);
        while Instant::now() < growth_time { poll(&mut cw,&mut sw,&mut received); std::thread::sleep(Duration::from_millis(1)); }
        mtu.store(1472,Ordering::Release);
        while received.len() < 34 {
            poll(&mut cw,&mut sw,&mut received);
            assert!(Instant::now() < deadline, "mixed messages failed delivery: {}",received.len());
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received.iter().filter(|m| m.len()==80 && m.iter().all(|&b| b==1)).count(),20);
        assert_eq!(received.iter().filter(|m| m.len()==1000 && m.iter().all(|&b| b==2)).count(),10);
        assert_eq!(received.iter().filter(|m| m.len()==65536 && m.iter().all(|&b| b==3)).count(),2);
        assert_eq!(received.iter().filter(|m| m.len()==4<<20 && m.iter().all(|&b| b==7)).count(),1);
        assert_eq!(received.iter().filter(|m| m.is_empty()).count(),1);
        // Timing/CPU load can drain the mixed train before a held MTU probe retries.
        // Explicitly wait for authenticated TU growth, then send a whole message so
        // the size-transition assertion does not depend on thread scheduling.
        let grown_deadline = Instant::now()+Duration::from_secs(15);
        while poll(&mut cw,&mut sw,&mut received) <= 1184 {
            assert!(Instant::now()<grown_deadline,"TU did not grow after relay admission changed");
            std::thread::sleep(Duration::from_millis(1));
        }
        service_connections(&client, NetworkThreadPush { wanted_connections: cw.clone(), send_unreliable: vec![(key,1,Dscp::BestEffort,vec![6;80])], ..Default::default() }).unwrap();
        while !received.iter().any(|m| m==&vec![6;80]) {
            poll(&mut cw,&mut sw,&mut received);
            assert!(Instant::now()<grown_deadline,"post-growth whole message failed");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Outstanding authenticated traffic triggers outage probes, then resumes.
        blackout.store(true,Ordering::Release);
        service_connections(&client, NetworkThreadPush { wanted_connections: cw.clone(), send_unreliable: vec![(key,1,Dscp::BestEffort,vec![4;80])], ..Default::default() }).unwrap();
        let recovery = Instant::now()+Duration::from_secs(3);
        while Instant::now()<recovery { poll(&mut cw,&mut sw,&mut received); std::thread::sleep(Duration::from_millis(1)); }
        blackout.store(false,Ordering::Release);
        service_connections(&client, NetworkThreadPush { wanted_connections: cw.clone(), send_unreliable: vec![(key,1,Dscp::BestEffort,vec![5;1000])], ..Default::default() }).unwrap();
        let idle_end = Instant::now()+Duration::from_secs(8);
        while Instant::now()<idle_end { poll(&mut cw,&mut sw,&mut received); std::thread::sleep(Duration::from_millis(1)); }
        assert!(received.iter().any(|m| m==&vec![5;1000]),"fresh message failed after outage");
        drop(client); drop(server);
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true,Ordering::Release); forwarder.join().unwrap();
        let sent = log.lock().unwrap();
        let mut sent_packets = std::collections::BTreeMap::new();
        let mut histogram = std::collections::BTreeMap::new();
        for p in sent.iter() {
            *sent_packets.entry(p.bytes.clone()).or_insert(0usize) += 1;
            *histogram.entry((p.kind,p.bytes.len())).or_insert(0usize) += 1;
            if let Some(expected) = p.expected { assert_eq!(p.bytes.len(),expected,"{} datagram has unexpected size",p.kind); }
            else { assert_eq!(p.kind,"handshake"); }
        }
        let mut actual_packets = std::collections::BTreeMap::new();
        for packet in actual.lock().unwrap().iter() { *actual_packets.entry(packet.clone()).or_insert(0usize) += 1; }
        assert!(sent_packets==actual_packets,"native-send recording and actual UDP capture disagree");
        assert!(histogram.contains_key(&("data",1184)));
        assert!(histogram.iter().any(|((kind,size),_)| *kind=="data" && *size>1184));
        for kind in ["ack","mtu_probe","keepalive","outage"] { assert!(histogram.keys().any(|&(k,_)| k==kind),"missing {kind} coverage"); }
        assert!(histogram.iter().filter(|((k,_),_)| *k=="ack").all(|((_,size),_)| *size==174));
        println!("UDP_SIZE_HISTOGRAM kind,udp_payload_bytes,count");
        for ((kind,size),count) in histogram { println!("UDP_SIZE_HISTOGRAM {kind},{size},{count}"); }
        println!("UDP_SIZE_PROOF encrypted mixed=1x0B+20x80B+10x1000B+2x65536B+1x4MiB MTU=1184->1472 outage=3s idle=8s; every actual datagram matched send-site TU/ACK/probe expectation");
    }
}

#[cfg(test)]
mod review_uniform_tests {
use super::*;

#[test]
fn stalled_encoder_does_not_bank_service_credit() {
    let mut s = SendQueues::new(2, (1_000_000, 32 << 20, 32 << 20));
    s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
    s.submit_messages(0, vec![vec![0; 65536]]);
    let mut p = [0; 1162];
    s.fec_prepare_packet(0); assert_eq!(s.fill_packet(&mut p), 1162);
    s.fec_on_packet_finalized(0, false);
    let (_tx, rx) = std::sync::mpsc::channel();
    let f = s.queues[0].fec_send_slot.as_mut().unwrap();
    f.n = f.k + 1;
    let encoder = std::mem::replace(&mut f.encoder, FecEncoderState::Pending(rx));
    // Send all sources normally, but deterministically delay the repair encoder.
    // Use a fixed nonce gap below to separate source and stall phases.
    let mut source_seq = 1;
    while s.queues[0].fec_send_slot.as_ref().is_some_and(|f| f.next_id < f.k) {
        s.fec_prepare_packet(source_seq); assert_eq!(s.fill_packet(&mut p), 1162);
        s.fec_on_packet_finalized(source_seq, false);
        source_seq += 1;
    }
    s.submit_messages(0, vec![vec![0; 80]; 20000]);
    s.submit_messages(1, vec![vec![1; 80]; 20000]);
    for seq in 1001..=2000 {
        s.fec_prepare_packet(seq); assert_eq!(s.fill_packet(&mut p), 1162);
        s.fec_on_packet_finalized(seq, false);
    }
    eprintln!("after stalled encoder: clock={}, service={:?}", s.service_clock, s.scheduled_bytes);
    s.queues[0].fec_send_slot.as_mut().unwrap().encoder = encoder;
    let mut q1_frames = 0;
    for seq in 2001..=2100 {
        s.fec_prepare_packet(seq); assert_eq!(s.fill_packet(&mut p), 1162);
        let mut cursor = 0;
        while let Some((h, header)) = read_fragment_header(&p[cursor..]) {
            let header = if h & 1 != 0 {16} else {header};
            let len = ((h >> 18) & 0x3fff) as usize;
            if p[cursor + header] == 1 {q1_frames += 1;}
            cursor += header + len;
        }
        s.fec_on_packet_finalized(seq, false);
    }
    eprintln!("q1 frames over 100 recovery packets: {q1_frames}; service={:?}",s.scheduled_bytes);
    assert!(q1_frames > 0, "ready queue 1 is starved by credit banked while queue 0's encoder was unavailable");
}

#[test]
fn multi_owner_multi_symbol_fec_feedback_is_once_each() {
    let mut s = SendQueues::new(2, (1_000_000, 32 << 20, 32 << 20));
    s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
    for q in 0..2 {s.submit_messages(q, vec![vec![q as u8;65536]]);}
    for seq in 0..2 {s.fec_prepare_packet(seq); s.fill_packet(&mut [0;1162]);}
    let mut p = [0;9194];
    s.fec_prepare_packet(2); assert_eq!(s.fill_packet(&mut p), p.len());
    let mut cursor = 0;
    let mut count = [0u32;2];
    while let Some((h, _)) = read_fragment_header(&p[cursor..]) {
        assert_eq!(h&3,1);
        let len = ((h >> 18) & 0x3fff) as usize;
        count[p[cursor+16] as usize] += 1;
        cursor += 16 + len;
    }
    assert_eq!(count, [4,3]);
    s.fec_on_packet_finalized(2, true);
    for (q, expected) in s.queues.iter().zip(count) {
        let f = q.fec_send_slot.as_ref().unwrap();
        assert_eq!(f.finalized_symbols, expected);
        assert_eq!(f.lost, expected);
        assert_eq!(f.group_lost, vec![expected]);
    }
    s.fec_on_packet_finalized(2, true);
    for (q, expected) in s.queues.iter().zip(count) {
        assert_eq!(q.fec_send_slot.as_ref().unwrap().finalized_symbols, expected);
    }
}

#[test]
fn idle_join_and_clock_normalization_are_bounded() {
    let mut s = SendQueues::new(2, (1_000_000, 32 << 20, 32 << 20));
    s.submit_messages(0, vec![vec![0;80];20000]);
    let mut p = [0;1162];
    for seq in 0..100 {s.fec_prepare_packet(seq); s.fill_packet(&mut p);}
    s.submit_messages(1, vec![vec![1;80];20000]);
    for seq in 100..200 {s.fec_prepare_packet(seq); s.fill_packet(&mut p);}
    assert!(s.scheduled_bytes[0].abs_diff(s.scheduled_bytes[1]) <= 2324);
    let offset = (1u64 << 60) + 500;
    for b in &mut s.scheduled_bytes {*b += offset;}
    s.service_clock += offset;
    s.fec_prepare_packet(201); s.fill_packet(&mut p);
    assert!(s.service_clock < 1 << 60);
    assert!(s.scheduled_bytes[0].abs_diff(s.scheduled_bytes[1]) <= 2324);
}


}

#[cfg(test)]
mod lazy_fec_segment_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn segment_tail_policy_matches_actual_retained_unit_not_root_length() {
        let mut s = SendQueues::new(2, (1_000_000, 64<<20, 64<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0));
        s.submit_messages(0, vec![vec![7; 50<<20]]);
        let mut packet = vec![0; 1450];
        s.fec_prepare_packet(0);
        assert!(s.fill_packet(&mut packet) > 0);
        let f = s.queues[0].fec_send_slot.as_ref().unwrap();
        assert!(f.segment.unwrap().total as usize > f.retain_limit);
        assert!(f.message.len() <= f.retain_limit);
        let (whole_k, groups, burst_tail) = f.plan_context();
        assert_eq!(groups, 25);
        assert!(!burst_tail); // retain_fec retains this 2 MiB unit, not 50 MiB
        let a = s.fec_adaptive.as_ref().unwrap();
        let repairs = a.repair_blocks_for_group_at_tail(f.k as u64, whole_k, groups, false);
        let unretainable_repairs = a.repair_blocks_for_group_at_tail(f.k as u64, whole_k, groups, true);
        assert_ne!(repairs, unretainable_repairs);
        assert_eq!(f.n_planned, f.k + repairs as u32);
        let package = s.queues[0].send_package_id;
        let q = &mut s.queues[0];
        q.fec_send_slot.as_mut().unwrap().next_id = q.fec_send_slot.as_ref().unwrap().n;
        q.reclaim_finished_partial();
        let retained = &q.fec_retained[&package].slot;
        assert_eq!(retained.message.len(), 2<<20);
        assert!(retained.retention_lease.is_some());
        assert!(!retained.plan_context().2);
    }

    #[test]
    fn lazy_group_plans_use_their_own_k_after_tu_growth() {
        for learned_burst in [false, true] {
            let mut s = SendQueues::new(1, (1_000_000, 16<<20, 16<<20));
            let mut a = crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC, 0, 0, 0);
            if learned_burst {
                // The measured trace contains 331 declared losses in a 2048-packet
                // span. Its finer histogram upper bound is 336, plus one extra symbol.
                for seq in 0..8192 { a.on_data_sent(seq); }
                for seq in 0..8192 { a.on_sequence_finalized(seq, (4096..4427).contains(&seq), 100_000_000); }
            }
            s.fec_adaptive = Some(a);
            s.submit_messages(0, vec![vec![7; (4<<20)+123]]);
            let mut first_k = None;
            for group in 0..3 {
                let payload_len = if group == 0 { 1193 } else { 1450 };
                let mut packet = vec![0; payload_len];
                s.fec_prepare_packet(group);
                assert!(s.fill_packet(&mut packet) > 0);
                let f = s.queues[0].fec_send_slot.as_ref().unwrap();
                let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
                let a = s.fec_adaptive.as_ref().unwrap();
                let (whole_k, groups, tail) = f.plan_context();
                assert_eq!(groups, 3);
                let total = (4usize<<20)+123;
                let group_len = total.div_ceil(3);
                let expected_whole_k = if group == 0 { 3 * layout.k as u64 }
                    else { first_k.unwrap() as u64 + group_len.div_ceil(1424) as u64
                        + (total - 2 * group_len).div_ceil(1424) as u64 };
                assert_eq!(whole_k, expected_whole_k);
                let repairs = a.repair_blocks_for_group_at_tail(layout.k as u64, expected_whole_k, groups, tail);
                assert_eq!(f.k, layout.k as u32);
                assert_eq!(f.n_planned, f.k + repairs as u32);
                if group == 0 { first_k = Some(f.k); }
                else {
                    assert!(f.k < first_k.unwrap());
                    if learned_burst { assert_eq!(repairs, 337); }
                }
                // Advance the lazy train without waiting for background encoding.
                let f = s.queues[0].fec_send_slot.as_mut().unwrap();
                f.next_id = f.n;
            }
        }
    }

    #[test]
    fn lazy_groups_pick_up_tu_growth_burst_loss_and_deliver_original_once() {
        let mut s = SendQueues::new(1, (1_000_000, 16<<20, 16<<20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,0,0,0));
        let original = vec![91; (4<<20)+123];
        s.submit_messages(0,vec![original.clone()]);
        let mut root = ReassemblySlot::new();
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(16<<20);
        let mut decoders = HashMap::<u16,(FecSegment,crate::fec::MessageDecoder)>::new();
        let mut widths = HashMap::new();
        let mut finished = None;
        let mut first_package = None;
        let mut seq = 0;
        let mut delivered = 0;
        while s.has_unsent_data() && seq < 20000 {
            // Growth occurs during the FIRST group; later groups start at new TU.
            let payload_len = if seq < 3 {1162} else {1450};
            let mut p = vec![0;payload_len];
            s.fec_prepare_packet(seq);
            if s.fill_packet(&mut p) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1)); continue;
            }
            assert_eq!(p.len(),payload_len);
            let mut cursor = 0;
            let mut packet_lost = false;
            while let Some((h,_)) = read_fragment_header(&p[cursor..]) {
                let size = fec_fragment_header_size(&p[cursor..]).unwrap();
                assert_eq!(size,STP_SEGMENT_FEC_HEADER_SIZE);
                let word = load_u64(&p[cursor+8..cursor+16]);
                let package = ((h>>2)&0xffff) as u16;
                let id = (h>>32) as u32;
                let len = ((h>>18)&0x3fff) as usize;
                let message_len = (word & 0xffff_ffff) as usize;
                let width = ((word>>32)&0xffff) as usize;
                let segment = FecSegment {root:load_u16(&p[cursor+16..cursor+18]),
                    total:load_u32(&p[cursor+18..cursor+22]),offset:load_u32(&p[cursor+22..cursor+26])};
                assert!(segment.valid(message_len));
                assert!(root.admit_segment(segment, crate::fec::MessageLayout::new(message_len, width).unwrap(), id, len, seq, &budget));
                let first = *first_package.get_or_insert(package);
                assert_eq!(width,if package==first {1136} else {1424});
                widths.insert(segment.offset,width);
                // Deterministic contiguous loss burst in EACH independent group.
                if (10..20).contains(&id) { packet_lost=true; }
                else {
                    let (_,decoder) = decoders.entry(package).or_insert_with(|| (segment,crate::fec::MessageDecoder::new(message_len,width).unwrap()));
                    if decoder.add(id,&p[cursor+size..cursor+size+len]).unwrap()==crate::fec::DecodeStatus::Done {
                        if let Some(message) = decoder.recover() {
                            if let Some((message,reservation))=root.finish_segment(segment,&message) {
                                delivered+=1; finished=Some((message,reservation));
                            }
                        }
                    }
                }
                cursor+=size+len;
            }
            s.fec_on_packet_finalized(seq,packet_lost);
            seq+=1;
        }
        assert!(seq<20000,"group train stalled");
        assert_eq!(widths.len(),3);
        assert_eq!(delivered,1);
        let (message,reservation)=finished.unwrap();
        assert_eq!(message,original);
        assert!(budget.used() >= original.len());
        drop(reservation); assert_eq!(budget.used(),0);
        assert_eq!(s.queues[0].queue_bytes_filled,0);
        assert!(s.queues[0].segmented_send.is_none());
    }

    #[test]
    fn segment_root_admission_is_before_ack_and_survives_out_of_order_completion() {
        let budget=crate::receive_memory::ReceiveMemoryBudget::new(8<<20);
        let refused=crate::receive_memory::ReceiveMemoryBudget::new(256);
        let total=4<<20;
        let first=FecSegment{root:13,total,offset:0};
        let second=FecSegment{offset:2<<20,..first};
        let mut slot=ReassemblySlot::new();
        assert!(!slot.admit_segment(first, crate::fec::MessageLayout::new(2<<20, 1000).unwrap(), 0, 1000, 1, &refused));
        assert_eq!(refused.used(),0); assert!(slot.buf.is_empty());
        assert!(slot.admit_segment(second, crate::fec::MessageLayout::new(2<<20, 1000).unwrap(), 0, 1000, 1, &budget));
        let charge=budget.used(); assert_eq!(charge, 256 + 2 * 64);
        assert!(slot.finish_segment(second,&vec![2;2<<20]).is_none());
        assert!(slot.admit_segment(first, crate::fec::MessageLayout::new(2<<20, 1000).unwrap(), 0, 1000, 1, &budget)); assert_eq!(budget.used(),charge + (2<<20));
        let (message,reservation)=slot.finish_segment(first,&vec![1;2<<20]).unwrap();
        assert_eq!(&message[..2<<20],&vec![1;2<<20]);
        assert_eq!(&message[2<<20..],&vec![2;2<<20]);
        assert!(slot.finish_segment(first,&vec![1;2<<20]).is_none());
        drop(reservation); assert_eq!(budget.used(),0);
        for bad in [FecSegment{offset:1,..first},FecSegment{total:0,..first},FecSegment{offset:total,..first}] {
            assert!(!bad.valid(2<<20));
        }
    }

    #[test]
    fn segmented_root_id_and_all_queue_ids_share_the_bounded_allocator() {
        let mut s=SendQueues::new(2,(1_000_000,64<<20,64<<20));
        s.fec_adaptive=Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,0,0,0));
        s.submit_messages(0,vec![vec![4;4<<20]]);
        let mut p=vec![0;1162]; s.fec_prepare_packet(0); assert!(s.fill_packet(&mut p)>0);
        let f=s.queues[0].fec_send_slot.as_ref().unwrap();
        let root=f.root_lease.as_ref().unwrap().clone();
        let root_id=root.id;
        let ids=s.queues[1].package_allocator.as_ref().unwrap().clone();
        let mut leases=Vec::new();
        while let Some(lease)=ids.allocate() {
            assert_ne!(lease.id as usize%1024,root_id as usize%1024);
            leases.push(lease);
        }
        assert_eq!(leases.len(),1022); // one root, one active segment
        assert!(ids.allocate().is_none());
        let released=leases.pop().unwrap().id;
        let lease=ids.allocate().unwrap(); assert_eq!(lease.id as usize%1024,released as usize%1024);
        assert_ne!(lease.id as usize%1024,root_id as usize%1024);
        assert!(ids.live.lock().unwrap().iter().all(|&n|n<=1));
        // Root survives even after the original cursor no longer owns it.
        let root_clone=s.queues[0].fec_send_slot.as_ref().unwrap().root_lease.clone();
        s.queues[0].segmented_send=None; drop(root);
        assert_eq!(ids.live.lock().unwrap()[root_id as usize%1024],1);
        drop(root_clone);
    }

    #[test]
    fn independent_burst_loss_group_decoders_obey_eight_worker_cap() {
        let workers=Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let budget=crate::receive_memory::ReceiveMemoryBudget::new(2<<30);
        let (done,rx)=std::sync::mpsc::channel();
        let key=ConnectionKey::default();
        let mut slots:Vec<_>=(0..9).map(|_|FecRecvSlot::default()).collect();
        for (id,slot) in slots.iter_mut().enumerate() {
            slot.package_id=id as u16;
            assert!(fec_receive_block(slot,key,id as u16,2<<20,1424,0,&vec![0;1424],&done,&workers,&budget).is_none());
            assert!(workers.load(std::sync::atomic::Ordering::Acquire)<=MAX_FEC_DECODE_WORKERS);
        }
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire),8);
        assert!(slots[8].admission_refused);
        assert!(!slots[8].in_use());
        // Missing burst leaves each decoder incomplete. Closing slots releases all
        // workers/native arenas/admission charges, without decrementing early.
        drop(slots); drop(done);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(5)).is_err());
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire),0);
        assert_eq!(budget.used(),0);
    }

    #[test]
    fn review_segment_root_pin_survives_bad_data_and_worker_retirement() {
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(4 << 30);
        let segment = FecSegment { root: 4, total: MAX_JUMBOGRAM_LEN as u32, offset: 0 };
        let layout = crate::fec::MessageLayout::new(2 << 20, 1000).unwrap();
        let mut roots = ReassemblySlot::new_ring(1024);
        let mut fec = FecRecvSlot::new_ring(1024);
        let workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (done, rx) = std::sync::mpsc::channel();
        assert!(segment.valid(layout.len));
        // A 26-byte header without its symbol cannot charge the root.
        assert!(!roots[4].admit_segment(segment, layout, 0, 0, 1, &budget));
        assert_eq!(budget.used(), 0);
        assert!(roots[4].segment_parts.is_none());
        assert!(fec_receive_block(&mut fec[5], ConnectionKey::default(), 5,
            2 << 20, 1000, 0, &[], &done, &workers, &budget).is_none());
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire), 0);
        assert!(!fec[5].in_use());
        assert_eq!(budget.used(), 0);
        // A valid symbol charges only root metadata plus the bounded decoder,
        // never the claimed 1 GiB application message.
        assert!(roots[4].admit_segment(segment, layout, 0, 1000, 1, &budget));
        let metadata = 256 + 512 * 64;
        assert_eq!(budget.used(), metadata);
        assert_eq!(roots[4].buf.capacity(), 0);
        fec[5].package_id = 5;
        fec[5].segment = Some(segment);
        assert!(fec_receive_block(&mut fec[5], ConnectionKey::default(), 5,
            2 << 20, 1000, 0, &[0;1000], &done, &workers, &budget).is_none());
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire), 1);
        fec[5].last_block_ns = 1;
        let grace = fec_inactive_grace_ns(0, false);
        retire_inactive_segment_roots(&mut roots, 1 + grace, grace);
        assert!(roots[4].segment_parts.is_some());
        assert_eq!(retire_inactive_fec_workers(&mut fec, 2 + grace, grace, false), 1);
        retire_inactive_segment_roots(&mut roots, 2 + grace, grace);
        drop(done);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(5)).is_err());
        assert_eq!(workers.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(budget.used(), 0);
        // A late completed group is sparse: even the highest offset materialises
        // only its own bytes. Expiry, ring eviction and close all release it.
        let last = FecSegment { offset: (MAX_JUMBOGRAM_LEN - (2 << 20)) as u32, ..segment };
        assert!(roots[4].admit_segment(last, layout, 0, 1000, 10, &budget));
        assert!(roots[4].finish_segment(last, &vec![7; 2 << 20]).is_none());
        assert_eq!(roots[4].buf.capacity(), 0);
        assert_eq!(roots[4].bytes_received(), 2 << 20);
        assert_eq!(budget.used(), metadata + (2 << 20));
        let next = FecSegment { root: 1028, total: 4 << 20, offset: 0 };
        assert!(roots[4].admit_segment(next, layout, 0, 1000, 11, &budget));
        assert_eq!(budget.used(), 256 + 2 * 64);
        assert!(roots[4].finish_segment(next, &vec![8; 2 << 20]).is_none());
        retire_inactive_segment_roots(&mut roots, 12 + grace, grace);
        assert_eq!(budget.used(), 0);
        assert!(roots[4].admit_segment(next, layout, 0, 1000, 13, &budget));
        assert!(roots[4].finish_segment(next, &vec![8; 2 << 20]).is_none());
        drop(roots); drop(fec);
        assert_eq!(budget.used(), 0);
        let smaller_process = crate::receive_memory::ReceiveMemoryBudget::new(512 << 20);
        let share = crate::receive_memory::ReceiveMemoryBudget::connection_share(&smaller_process);
        let over_share = FecSegment { total: 256 << 20, ..segment };
        assert!(over_share.valid(layout.len)); // valid wire length, outside peer share
        assert!(!ReassemblySlot::new().admit_segment(over_share, layout, 0, 1000, 1, &share));
        assert_eq!(smaller_process.used(), 0);
    }

    #[test]
    fn near_tu_whole_messages_use_four_byte_frame_not_fec() {
        for len in 1146..=1158 {
            let mut s=SendQueues::new(1,(1_000_000,1<<20,1<<20));
            s.fec_adaptive=Some(crate::fec_adapt::FecAdaptiveState::new(crate::ship::FEC,0,0,0));
            s.submit_messages(0,vec![vec![8;len]]);
            let mut p=vec![0;1162]; s.fec_prepare_packet(0);
            assert_eq!(s.fill_packet(&mut p),1162);
            let (header,size)=read_fragment_header(&p).unwrap();
            assert_eq!(size,4); assert_eq!(header&1,0); assert_eq!((header>>18)&0x3fff,len as u64);
        }
    }
}

#[cfg(test)]
mod review2_tests {
    use super::*;

    #[test]
    fn review2_sparse_fragment_rejected_without_high_water_allocation() {
        let process = crate::receive_memory::ReceiveMemoryBudget::new(4 << 30);
        let peer = crate::receive_memory::ReceiveMemoryBudget::connection_share(&process);
        let mut slot = ReassemblySlot::new();
        for offset in [32usize << 20, MAX_JUMBOGRAM_LEN - 1, FEC_SEGMENT_BYTES, usize::MAX] {
            assert!(!slot.admit(offset, 1, &peer));
            assert_eq!(slot.insert(offset, &[0xAA], false), (false, false));
            assert_eq!(slot.insert(offset, &[0xAA], true), (false, false));
            assert_eq!(slot.buf.capacity(), 0);
            assert_eq!(peer.used(), 0);
            assert_eq!(process.used(), 0);
        }
        // The boundary itself remains legal and charged at its exact capacity.
        assert!(slot.admit(FEC_SEGMENT_BYTES - 1, 1, &peer));
        assert_eq!(slot.insert(FEC_SEGMENT_BYTES - 1, &[0xAA], true), (true, false));
        assert_eq!(slot.buf.len(), FEC_SEGMENT_BYTES);
        assert_eq!(peer.used(), slot.buf.capacity() + slot.received.capacity() * 8 + 256);
        assert_eq!(process.used(), peer.used());
        drop(slot);
        assert_eq!(peer.used(), 0);
        assert_eq!(process.used(), 0);
    }

    #[test]
    fn review2_plain_partial_expires_with_segment_roots() {
        let process = crate::receive_memory::ReceiveMemoryBudget::new(16 << 20);
        let budget = crate::receive_memory::ReceiveMemoryBudget::connection_share(&process);
        let mut slots = [ReassemblySlot::new(), ReassemblySlot::new(), ReassemblySlot::new()];
        slots[0].package_id = 1;
        assert!(slots[0].admit(100, 16, &budget));
        assert_eq!(slots[0].insert(100, &[1u8; 16], false), (true, false));
        slots[0].last_segment_ns = 1;
        let plain_charge = budget.used();
        assert!(plain_charge > 0);

        let total = 3u32 << 20;
        let group_len = (total as usize).div_ceil((total as usize).div_ceil(FEC_SEGMENT_BYTES));
        let layout = crate::fec::MessageLayout::new(group_len, 1500).unwrap();
        let seg = FecSegment { root: 5, total, offset: 0 };
        assert!(slots[1].admit_segment(seg, layout, 0, crate::fec::block_len(group_len, 1500, 0), 1, &budget));
        assert!(budget.used() > plain_charge);
        // Completion tombstones must survive the inactivity sweep.
        assert!(slots[2].admit(0, 1, &budget));
        assert_eq!(slots[2].insert(0, &[2], true), (true, true));
        assert_eq!(slots[2].take_complete(), vec![2]);

        let grace = fec_inactive_grace_ns(100, false);
        let charge = budget.used();
        retire_inactive_segment_roots(&mut slots, 1 + grace, grace);
        assert_eq!(budget.used(), charge); // strict boundary, as for FEC
        slots[0].last_segment_ns = 2; // another successfully received fragment
        retire_inactive_segment_roots(&mut slots, 2 + grace, grace);
        assert_eq!(budget.used(), plain_charge);
        assert!(slots[1].segment_parts.is_none() && slots[1].total_len.is_none());
        retire_inactive_segment_roots(&mut slots, 1 + 3_600_000_000_000, grace);
        assert_eq!(budget.used(), 0);
        assert_eq!(process.used(), 0);
        assert_eq!(slots[0].buf.capacity(), 0);
        assert!(slots[2].completed);
    }

    #[test]
    fn review2_segment_header_conflicts_refused() {
        let budget = crate::receive_memory::ReceiveMemoryBudget::new(16 << 20);
        let mut slot = ReassemblySlot::new();
        let total = 3u32 << 20;
        let group_len = (total as usize).div_ceil((total as usize).div_ceil(FEC_SEGMENT_BYTES));
        let layout = crate::fec::MessageLayout::new(group_len, 1500).unwrap();
        assert!(slot.admit_segment(FecSegment { root: 9, total, offset: 0 }, layout, 0, 1500, 1, &budget));
        let total2 = 4u32 << 20;
        let group_len2 = (total2 as usize).div_ceil((total2 as usize).div_ceil(FEC_SEGMENT_BYTES));
        let layout2 = crate::fec::MessageLayout::new(group_len2, 1500).unwrap();
        assert!(!slot.admit_segment(FecSegment { root: 9, total: total2, offset: 0 }, layout2, 0, 1500, 1, &budget));
        assert!(!slot.admit_segment(FecSegment { root: 8, total, offset: 0 }, layout, 0, 1500, 1, &budget));
        assert!(slot.admit_segment(FecSegment { root: 9 + 1024, total, offset: 0 }, layout, 0, 1500, 1, &budget));
    }

    #[test]
    fn review2_zero_length_message_delivered_once() {
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        assert!(b.submit_messages(vec![vec![]]).is_empty());
        b.fec_prepare_packet(0);
        let frag = b.next_fragment(1449, 1449).expect("empty message must produce a fragment");
        assert!(matches!(frag, UnreliableFragment::Plain { is_fin: true, data: [], offset: 0, .. }));
        let mut frame = [0u8; 8];
        let used = write_fragment(&mut frame, UnreliableFragment::Plain { is_fin: true, package_id: 7, data: &[], offset: 0 });
        assert_eq!(used, STP_WHOLE_HEADER_SIZE);
        let (header, hdr_size) = read_fragment_header(&frame).unwrap();
        assert_eq!(hdr_size, STP_WHOLE_HEADER_SIZE);
        assert_eq!(header & 2, 2);
        assert_eq!((header >> 18) & 0x3fff, 0);

        let budget = crate::receive_memory::ReceiveMemoryBudget::new(1 << 20);
        let mut slot = ReassemblySlot::new();
        slot.package_id = 7;
        assert!(slot.admit(0, 0, &budget));
        assert_eq!(slot.insert(0, &[], false), (true, false)); // non-final isn't a message
        assert_eq!(slot.insert(0, &[], true), (true, true));
        let reservation = slot.reservation.take();
        let mut queue = ReceiveQueue::default();
        let key = ConnectionKey::default();
        queue.push_reserved(key, slot.take_complete(), MAX_RECV_QUEUE_BYTES, reservation);
        assert_eq!(queue.messages.len(), 1);
        assert!(queue.messages[0].1.is_empty());
        assert_eq!(budget.used(), ReceiveQueue::entry_bytes(&queue.messages[0].1) + 128);
        for _ in 0..3 {
            assert!(slot.admit(0, 0, &budget));
            assert_eq!(slot.insert(0, &[], true), (true, false)); // rescue must not redeliver
        }
        assert_eq!(queue.take().into_iter().collect::<Vec<_>>(), vec![(key, vec![])]);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn review2_cubic_rate_bounded_after_weeks_without_congestion() {
        let cc = &crate::ship::CC;
        let k = cc.recovery_rtts * 1_000_000;
        for t in [2_000_000_000_000_000, u64::MAX] {
            let (rate, _) = connection_rate(t, 200_000_000, k, cc, true);
            let allowed = local_rate_limit(rate, None);
            assert_eq!(allowed, MAX_CC_RATE_UPPS);
            assert_eq!(send_interval_ns(allowed), 1000);
        }
        for startup_done in [false, true] {
            for k in [0, 1, 9_000_000] {
                assert!(connection_rate(u64::MAX, u64::MAX, k, cc, startup_done).0 <= MAX_CC_RATE_UPPS);
            }
        }
        assert_eq!(local_rate_limit(u64::MAX, Some(u64::MAX)), MAX_CC_RATE_UPPS);
    }

    #[test]
    fn review2_pacing_interval_zero_cannot_panic() {
        for rate in [0, 1, MAX_CC_RATE_UPPS, u64::MAX] {
            assert!(send_interval_ns(rate) >= 1);
        }
        let grant = send_pacing_grant(1_000_000_000, 0, 0);
        assert_eq!(grant.packets, MAX_SEND_PACKETS_PER_TICK);
        assert_eq!(grant.carry_ns, MAX_SEND_CATCHUP_NS);
        let grant = send_pacing_grant(0, 0, 0);
        assert_eq!(grant.packets, 0);
        assert_eq!(grant.carry_ns, 0);
    }

    #[test]
    fn review2_bdp_multiply_cannot_overflow_after_days() {
        let cc = &crate::ship::CC;
        let k = cc.recovery_rtts * 6_553_500_000;
        let (rate, _) = connection_rate(600_000_000_000_000, 200_000_000, k, cc, true);
        let allowed = local_rate_limit(rate, None);
        assert_eq!(allowed, MAX_CC_RATE_UPPS);
        let expected = allowed.checked_mul(65535).unwrap() / 10_000;
        assert_eq!(rate_mul_div(allowed, 65535, 10_000), expected);
    }

    #[test]
    fn review2_rate_products_use_wide_intermediates() {
        // Even without the safety cap, divide the full product before saturating.
        let rate = 600_000_000_000_000u64;
        assert!(rate.checked_mul(65535).is_none());
        assert_eq!(rate_mul_div(rate, 65535, 10_000), 3_932_100_000_000_000);
        assert_eq!(rate_mul_div(rate, 65507, 1_000_000), 39_304_200_000_000);
        assert_eq!(rate_mul_div(u64::MAX, u64::MAX, 1), u64::MAX);
        assert_eq!(rate_mul_div(u64::MAX, 1, 1), u64::MAX);
        for rate in [0, 1, 200_000_000, MAX_CC_RATE_UPPS] {
            for (multiplier, divisor) in [(0, 10_000), (100, 10_000), (65535, 10_000), (1472, 1_000_000)] {
                assert_eq!(rate_mul_div(rate, multiplier, divisor), rate * multiplier / divisor);
            }
        }
    }

    fn connected() -> ConnectionStateConnected {
        let ConnectionState::Connected(s) = new_connection_state_connected(None, 0, 1, 1_000_000_000) else { unreachable!() };
        s
    }

    #[test]
    fn review2_ackhole_repeated_cuts_no_panic() {
        let cc = &crate::ship::CC;
        let mut s = connected();
        s.RTT_mean = 100;
        s.cc_startup_done = true;
        s.congestion_event_rate_upps = 2_000_000_000;
        let mut now = 10_000_000_000u64;
        s.congestion_event_time_ns = now - 10_000_000;
        let mut cuts = 0u32;
        for _round in 0..50u64 {
            let hole = s.send_sequence_number;
            // 0ad3b9d shares the two-loss RTT cohort: exercise two holes, not one.
            // Six sends also close the send-time bucket holding the first holes.
            for _ in 0..6 { s.account_send(now); now += 1_000_000; }
            s.packets_in_flight += 6;
            for i in 2..6u64 {
                let bit = (hole + i) % PACKETS_WAITING_ACK_CAPACITY;
                s.packets_waiting_ack_field[(bit / 64) as usize] &= !(1u64 << (bit % 64));
                s.packets_in_flight -= 1;
                s.ack_hole.acknowledged(hole + i);
            }
            let before = s.congestion_event_rate_upps;
            for _ in 0..2 {
                observe_ack_hole(&mut s, now, cc, None);
                now += 2_000_000;
                observe_ack_hole(&mut s, now, cc, None);
            }
            if s.congestion_event_rate_upps != before { cuts += 1; }
            assert!(s.congestion_event_rate_upps <= before);
            now += 100_000_000;
        }
        assert!(cuts >= 40, "expected persistent hole pattern to cut repeatedly, got {cuts} cuts");
        assert_eq!(std::mem::size_of_val(&s.ack_hole), std::mem::size_of::<AckHole>());
    }

    #[test]
    fn review2_bitmap_ack_decode_bounds() {
        use crate::ack::BitmapAck;
        let mut a = BitmapAck { highest: 100, sample_seq: 101, delay_us: 0, ce_count: 0, bitmap: [0; 16] };
        a.bitmap[((100 - a.base()) / 64) as usize] |= 1u64 << ((100 - a.base()) % 64);
        assert!(BitmapAck::decode(&a.encode()).is_none());
        let mut b = BitmapAck { highest: 100, sample_seq: 100, delay_us: 0, ce_count: 0, bitmap: [0; 16] };
        assert!(BitmapAck::decode(&b.encode()).is_none());
        b.bitmap[((100 - b.base()) / 64) as usize] |= 1u64 << ((100 - b.base()) % 64);
        let d = BitmapAck::decode(&b.encode()).unwrap();
        assert!(d.acknowledged().all(|s| s <= d.highest));
        let waiting = vec![0u64; PACKETS_WAITING_ACK_WORDS];
        let lost = vec![0u64; PACKETS_WAITING_ACK_WORDS];
        assert!(d.relevant(&waiting, &lost).acknowledged().all(|s| s <= d.highest));
    }
}
