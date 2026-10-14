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
                send_unreliable.push((wanted_connections[0].0.to_connection_key(), msg.clone()));
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
                    send_unreliable.push((wanted_connections[0].0.to_connection_key(), Vec::from(b"Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...Test data...")));
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

/// Largest app message STP sends in one datagram at the guaranteed TU; bigger ones are split across datagrams.
pub const fn max_single_datagram_message_size(magic: u64) -> Option<usize> {
    match total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic) {
        Some(overhead) => Some(ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY - overhead - STP_FRAGMENT_HEADER_SIZE),
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

#[derive(Debug)]
pub struct UnreliableSendBuffer {
    // A time based capacity constrained by byte counts.
    // The queue should for example probably have a minimum byte size twice that of your largest message.
    pub target_queue_size_us: u32,
    pub min_queue_size_bytes: u32,
    pub max_queue_size_bytes: u32,
    
    /// Message bytes (not wire bytes) of the queued messages plus the one being sent.
    pub queue_bytes_filled: usize,
    pub message_queue: VecDeque<Vec<u8>>,
    pub partial_send_slot: Option<(Vec<u8>, u32)>,
    pub send_package_id: u16,
    pub current_bytes_per_second: u64,
    /// Forward error correction for messages that start sending from now on, in parts per
    /// million of extra coded blocks (0 = off, plain fragments exactly as without FEC). Set
    /// every tick by the network thread from `NetworkThreadHandle::set_fec_redundancy_ppm`.
    pub fec_redundancy_ppm: u32,
    /// The FEC-coded message being sent (instead of `partial_send_slot`), if any.
    pub fec_send_slot: Option<FecSendSlot>,
    /// Adaptive FEC: per-connection loss estimate. When Some, each new message gets the repair
    /// blocks this estimate calls for (and `fec_redundancy_ppm` is only a nonzero summary of it,
    /// used for the queue capacity). Maintained by the network thread.
    pub fec_adaptive: Option<crate::fec_adapt::FecAdaptiveState>,
    /// Sequence number of the packet the next fragment goes into (set by the network thread), so
    /// an FEC message knows which packets are its own when they are declared lost.
    pub next_packet_seq: u64,
    /// Lazy fixed 2 MiB nonce ring: package id (16), symbol count (16), first ordinal (32).
    /// One ring per connection, reused across messages; ACK/probe/keepalive slots are empty.
    fec_packet_tags: Option<Box<[u64]>>,
    /// Finished FEC messages, when recording is enabled (Some); drained by the network thread.
    pub fec_record: Option<Vec<crate::fec_adapt::FecMessageInfo>>,
}

/// Sender state of one FEC-coded message: blocks 0..k-1 are slices of the message itself and
/// need no encoder; blocks k..n-1 are repair blocks from a Wirehair encoder, which is built on
/// a helper thread while the source blocks go out (creating one costs ~4 us per block, 155 ms
/// for a 48 MB message, too long to stall the network thread).
pub struct FecSendSlot {
    pub message: std::sync::Arc<Vec<u8>>,
    pub block_bytes: usize,
    pub k: u32,
    pub n: u32,
    pub next_id: u32,
    encoder: FecEncoderState,
    block_buf: Vec<u8>,
    /// Sequence number of the message's first packet, own packets declared lost since, the block
    /// count planned at the start, and the loss rate the plan was sized for (0 for fixed ppm).
    pub first_seq: u64,
    pub lost: u32,
    pub group_lost: Vec<u32>,
    pub n_planned: u32,
    pub loss_estimate: f64,
}

impl FecSendSlot {
    fn refresh_plan(&mut self, a: &crate::fec_adapt::FecAdaptiveState) {
        let layout = crate::fec::MessageLayout::new(self.message.len(), self.block_bytes).unwrap();
        let groups = layout.groups as u64;
        let sources = self.next_id.min(self.k) as u64;
        let repairs = self.next_id.saturating_sub(self.k) as u64;
        let mut per_group_repairs = 0;
        for group in 0..layout.groups {
            let k = layout.group(group).1 as u64;
            let source_sent = (sources / groups + u64::from((group as u64) < sources % groups)).min(k);
            let repair_sent = repairs / groups + u64::from((group as u64) < repairs % groups);
            let total_repairs = if a.closed_loop_enabled() {
                repair_sent + a.extra_repair_blocks_needed_for_group(k, self.k as u64, layout.groups, source_sent + repair_sent, repair_sent, self.group_lost[group] as u64)
            } else {
                a.topped_up_blocks_for_group(k, self.k as u64, layout.groups, self.group_lost[group] as u64, self.loss_estimate).saturating_sub(k)
            };
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

/// Header of an FEC fragment: two little-endian u64 words.
///   word0: bit 0 = 1 (extended fragment; plain fragments have 0 here), bit 1 = 0,
///          bits 2..18 package id, bits 18..32 block data length, bits 32..64 block id
///   word1: bits 0..32 message length, bits 32..48 block bytes, bits 48..56 kind (1 = FEC), rest 0
pub const STP_FEC_FRAGMENT_HEADER_SIZE: usize = 16;
pub const STP_EXT_KIND_FEC: u64 = 1;
/// Balanced groups of <=32000 blocks, inferred from length/block size; same 16-byte header.
pub const STP_EXT_KIND_GROUPED_FEC: u64 = 2;
/// Redundancy is capped at 100% (n = 2k).
pub const MAX_FEC_REDUNDANCY_PPM: u32 = 1_000_000;
/// Messages with at most this many blocks have their Wirehair encoder/decoder run inline on
/// the network thread (well under 1 ms); bigger ones use a helper thread.
pub const FEC_INLINE_MAX_BLOCKS: usize = 256;

pub enum UnreliableFragment<'a> {
    Plain { is_fin: bool, package_id: u16, data: &'a [u8], offset: u32 },
    Fec { package_id: u16, message_len: u32, block_bytes: u16, block_id: u32, data: &'a [u8] },
}

impl UnreliableSendBuffer {
    pub fn new(target_queue_size_us: u32, min_queue_size_bytes: u32, max_queue_size_bytes: u32) -> Self {
        Self {
            target_queue_size_us,
            min_queue_size_bytes,
            max_queue_size_bytes,
            queue_bytes_filled: 0,
            message_queue: VecDeque::new(),
            partial_send_slot: None,
            send_package_id: 0,
            current_bytes_per_second: 0,
            fec_redundancy_ppm: 0,
            fec_send_slot: None,
            fec_adaptive: None,
            next_packet_seq: 0,
            fec_packet_tags: None,
            fec_record: None,
        }
    }

    /// Start ANY connected nonce (including control). Clear a reused ring entry before fill.
    pub fn fec_prepare_packet(&mut self, seq: u64) {
        self.next_packet_seq = seq;
        if let Some(tags) = &mut self.fec_packet_tags { tags[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize] = 0; }
    }

    /// Count only this active message's actually transmitted symbols, never nonce gaps.
    pub fn fec_on_packet_lost(&mut self, seq: u64) {
        let Some(f) = &mut self.fec_send_slot else { return };
        if seq < f.first_seq || seq > self.next_packet_seq || self.next_packet_seq - seq >= PACKETS_WAITING_ACK_CAPACITY || f.next_id >= f.n { return; }
        let Some(tags) = &mut self.fec_packet_tags else { return };
        let tag = std::mem::take(&mut tags[(seq % PACKETS_WAITING_ACK_CAPACITY) as usize]);
        let count = ((tag >> 32) & 0xffff) as u32;
        if count == 0 || tag >> 48 != self.send_package_id as u64 { return; }
        let first = tag as u32;
        if first.saturating_add(count) > f.next_id { return; }
        let layout = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap();
        for ordinal in first..first + count {
            let group = layout.local_id(layout.wire_id(ordinal)).0;
            f.group_lost[group] = f.group_lost[group].saturating_add(1);
        }
        f.lost = f.lost.saturating_add(count);
        if let Some(a) = &self.fec_adaptive {
            if a.tracker.config().topup { f.refresh_plan(a); }
        }
    }

    /// Capacity in message bytes. `current_bytes_per_second` is the wire payload rate; with FEC
    /// on, a message costs about (1 + redundancy) times its size on the wire, so the time-based
    /// target is scaled down by that factor to keep the queue at the same send time. The
    /// min/max bounds are message bytes. (With FEC off this is exactly the old formula.)
    #[inline]
    pub fn current_byte_capacity(&self) -> u32 {
        let mut dynamic_target = self.target_queue_size_us as u64 * self.current_bytes_per_second / 1000_000;
        if self.fec_redundancy_ppm != 0 {
            dynamic_target = dynamic_target * 1_000_000 / (1_000_000 + self.fec_redundancy_ppm as u64);
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
        self.reclaim_finished_partial();
        let capacity = self.current_byte_capacity() as usize;
        let mut iter = new_messages.into_iter();
        let mut rejected = Vec::new();
        while let Some(m) = iter.next() {
            if self.queue_bytes_filled == 0 || self.queue_bytes_filled + m.len() <= capacity {
                self.queue_bytes_filled += m.len();
                self.message_queue.push_back(m);
            } else {
                rejected.push(m);
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
        if !self.message_queue.is_empty() { return true; }
        if let Some((msg, start_byte)) = &self.partial_send_slot {
            if (*start_byte as usize) < msg.len() { return true; }
        }
        if let Some(f) = &self.fec_send_slot {
            if f.next_id < f.n { return true; }
        }
        false
    }

    // A message whose last fragment has gone out still counts against the queue until it is
    // released here.
    fn reclaim_finished_partial(&mut self) {
        if let Some((msg, start_byte)) = &self.partial_send_slot {
            if *start_byte as usize >= msg.len() {
                let msg_len = msg.len();
                self.queue_bytes_filled -= msg_len;
                self.partial_send_slot = None;
                self.send_package_id = self.send_package_id.wrapping_add(1);
            }
        }
        if let Some(f) = &self.fec_send_slot {
            if f.next_id >= f.n {
                if let Some(rec) = &mut self.fec_record {
                    let mut tag = [0u8; 8];
                    let l = f.message.len().min(8);
                    tag[..l].copy_from_slice(&f.message[..l]);
                    rec.push(crate::fec_adapt::FecMessageInfo { tag: u64::from_le_bytes(tag), message_len: f.message.len(), k: f.k, n_planned: f.n_planned, n_sent: f.next_id, loss_estimate: f.loss_estimate, lost_during_send: f.lost });
                }
                let message_len = f.message.len();
                self.queue_bytes_filled -= message_len;
                let finished = self.fec_send_slot.take();
                // Giant codec arenas can take seconds to free under allocator contention.
                // Do not stop ACK processing while returning them (and the source Arc).
                if message_len > MAX_RECV_QUEUE_BYTES {
                    let _ = std::thread::Builder::new().name("stp-fec-release".into()).spawn(move || drop(finished));
                }
                self.send_package_id = self.send_package_id.wrapping_add(1);
            }
        }
    }

    /// Block size for an FEC message started in a packet with `payload_len` bytes of payload:
    /// one block plus its header fills the packet. None if the message should go plain (FEC
    /// off, fewer than 2 blocks, or outside the grouped wire length limit).
    fn fec_block_bytes(&self, message_len: usize, payload_len: usize) -> Option<usize> {
        if self.fec_redundancy_ppm == 0 { return None; }
        let block_bytes = payload_len.checked_sub(STP_FEC_FRAGMENT_HEADER_SIZE)?.min(0x3fff);
        crate::fec::MessageLayout::new(message_len, block_bytes)?;
        Some(block_bytes)
    }

    fn start_fec(&mut self, message: std::sync::Arc<Vec<u8>>, block_bytes: usize) {
        let layout = crate::fec::MessageLayout::new(message.len(), block_bytes).unwrap();
        let k = layout.k as u32;
        let (n, loss_estimate) = match &self.fec_adaptive {
            Some(a) => {
                let repairs = (0..layout.groups).map(|g| a.repair_blocks_for_group(layout.group(g).1 as u64, k as u64, layout.groups)).max().unwrap_or(0);
                (k + repairs as u32 * layout.groups as u32, a.p)
            },
            None => {
                let ppm = self.fec_redundancy_ppm.min(MAX_FEC_REDUNDANCY_PPM) as u64;
                (k + ((k as u64 * ppm + 999_999) / 1_000_000) as u32, 0.0)
            }
        };
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
        self.fec_send_slot = Some(FecSendSlot { group_lost: vec![0; layout.groups], message, block_bytes, k, n, next_id: 0, encoder, block_buf: vec![0u8; block_bytes], first_seq: self.next_packet_seq, lost: 0, n_planned: n, loss_estimate });
    }

    /// Starts `msg` as the message being sent: grouped FEC if enabled and its length fits
    /// the wire format with at least two blocks at this packet size, plain otherwise.
    fn start_message(&mut self, msg: Vec<u8>, payload_len: usize) {
        match self.fec_block_bytes(msg.len(), payload_len) {
            Some(block_bytes) => self.start_fec(std::sync::Arc::new(msg), block_bytes),
            None => self.partial_send_slot = Some((msg, 0)),
        }
    }

    /// Next fragment for a packet with `payload_len` bytes of payload, of which `space` are still
    /// free. None: nothing to send, or the next FEC block does not fit in what is left of this
    /// packet (or its repair encoder is still being built); send the packet as it is.
    pub fn next_fragment(&mut self, payload_len: usize, space: usize) -> Option<UnreliableFragment<'_>> {
        self.reclaim_finished_partial();
        if self.partial_send_slot.is_none() && self.fec_send_slot.is_none() {
            let front_msg = self.message_queue.pop_front()?;
            self.start_message(front_msg, payload_len);
        }
        if self.fec_send_slot.is_some() {
            if let (Some(a), Some(f)) = (&self.fec_adaptive, &mut self.fec_send_slot) {
                // Refresh at source completion and the final planned repair, without tail waiting.
                if a.closed_loop_enabled() && f.next_id >= f.k && (f.next_id == f.k || f.next_id + 1 >= f.n) {
                    f.refresh_plan(a);
                }
            }
            let need = { let f = self.fec_send_slot.as_ref().unwrap(); STP_FEC_FRAGMENT_HEADER_SIZE + crate::fec::block_len(f.message.len(), f.block_bytes, crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap().wire_id(f.next_id)) };
            if need > space {
                if space < payload_len { return None; } // the next packet has room
                // The transmission unit shrank below the block size (black hole fallback; it
                // never shrinks otherwise). Start the message over under a new package id with
                // blocks that fit; the receiver drops the abandoned partial package in time.
                let f = self.fec_send_slot.take().unwrap();
                drop(f.encoder);
                self.send_package_id = self.send_package_id.wrapping_add(1);
                let msg = std::sync::Arc::try_unwrap(f.message).unwrap_or_else(|a| (*a).clone());
                self.start_message(msg, payload_len);
                return self.next_fragment(payload_len, space);
            }
            let package_id = self.send_package_id;
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
            let f = self.fec_send_slot.as_mut().unwrap();
            let id = crate::fec::MessageLayout::new(f.message.len(), f.block_bytes).unwrap().wire_id(f.next_id);
            let tag = &mut self.fec_packet_tags.as_mut().unwrap()[(self.next_packet_seq % PACKETS_WAITING_ACK_CAPACITY) as usize];
            let count = ((*tag >> 32) & 0xffff) as u16;
            if count == 0 || *tag >> 48 != package_id as u64 {
                *tag = ((package_id as u64) << 48) | (1u64 << 32) | f.next_id as u64;
            } else {
                assert!(count < u16::MAX);
                *tag += 1u64 << 32;
            }
            if let Some(len) = repair_len {
                f.next_id += 1;
                return Some(UnreliableFragment::Fec { package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.block_buf[..len] });
            }
            f.next_id += 1;
            let start = id as usize * f.block_bytes;
            let end = (start + f.block_bytes).min(f.message.len());
            return Some(UnreliableFragment::Fec { package_id, message_len: f.message.len() as u32, block_bytes: f.block_bytes as u16, block_id: id, data: &f.message[start..end] });
        }
        let frag_size = space.checked_sub(STP_FRAGMENT_HEADER_SIZE)?;
        let (msg, start_byte) = self.partial_send_slot.as_mut().unwrap();
        let start = *start_byte as usize;
        // A plain message that fits a fresh packet has exactly one physical erasure event.
        // Do not fill the preceding packet's tail with a partial prefix of that message.
        if start == 0 && msg.len() <= payload_len.saturating_sub(STP_FRAGMENT_HEADER_SIZE) && msg.len() > frag_size {
            return None;
        }
        let ret_size = (msg.len() - start).min(frag_size);
        // Both frag_size and msg.len() may be zero.

        *start_byte += ret_size as u32;
        Some(UnreliableFragment::Plain { is_fin: *start_byte as usize == msg.len(), package_id: self.send_package_id, data: &msg[start..start + ret_size], offset: start as u32 })
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
        // Reassembly grows the buffer by doubling, so a big message can carry up to 2x its size
        // in capacity; give that back before it is counted against the cap.
        buf.shrink_to_fit();
        self.bytes += Self::entry_bytes(&buf);
        self.messages.push_back((key, buf));
        // Never evict the message just pushed: one message bigger than the cap is still delivered.
        while self.bytes > cap_bytes && self.messages.len() > 1 {
            let Some((_, m)) = self.messages.pop_front() else { break; };
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
        std::mem::take(&mut self.messages)
    }
}

/// Returns the used payload length (0 when there is nothing to send). Real data
/// payloads are at least 517 bytes: exactly 516 is reserved for size-identified ACKs.
fn fill_packet_payload_with_unreliable_fragments(payload: &mut [u8], unreliable_send_buffer: &mut UnreliableSendBuffer) -> usize {
    let mut send = false;
    let mut cursor = 0;
    let payload_len = payload.len();
    while cursor + STP_FRAGMENT_HEADER_SIZE <= payload_len && let Some(frag) = unreliable_send_buffer.next_fragment(payload_len, payload_len - cursor) {
        send = true;
        match frag {
            UnreliableFragment::Plain { is_fin, package_id, data: frag_data, offset: frag_offset } => {
                let header = 0 | ((is_fin as u64) << 1) | ((package_id as u64) << 2) | ((frag_data.len() as u64 & 0x3fff) << 18) | ((frag_offset as u64) << 32);
                store_u64(&mut payload[cursor..cursor+STP_FRAGMENT_HEADER_SIZE], header);
                frag_data.write_to(&mut payload[cursor+STP_FRAGMENT_HEADER_SIZE..]);
                cursor += STP_FRAGMENT_HEADER_SIZE+frag_data.len();
            }
            UnreliableFragment::Fec { package_id, message_len, block_bytes, block_id, data } => {
                let word0 = 1 | ((package_id as u64) << 2) | ((data.len() as u64 & 0x3fff) << 18) | ((block_id as u64) << 32);
                let kind = if message_len as usize > crate::fec::MAX_BLOCKS * block_bytes as usize { STP_EXT_KIND_GROUPED_FEC } else { STP_EXT_KIND_FEC };
                let word1 = message_len as u64 | ((block_bytes as u64) << 32) | (kind << 48);
                store_u64(&mut payload[cursor..cursor+8], word0);
                store_u64(&mut payload[cursor+8..cursor+16], word1);
                data.write_to(&mut payload[cursor+STP_FEC_FRAGMENT_HEADER_SIZE..]);
                cursor += STP_FEC_FRAGMENT_HEADER_SIZE+data.len();
            }
        }
    }
    if send == false { return 0; }
    let used = cursor.max(517).min(payload.len());
    payload[cursor..].fill(0xff);
    used
}

#[derive(Debug)]
pub struct ConnectionTrackingData {
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
    
    pub unreliable_send_buffer: UnreliableSendBuffer,
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
    pub ack_field_virtual_base: u64,
    pub last_sent_data_packet: u64,
    pub last_sent_could_have_sent_data_packet: u64,
    pub last_ack_received_time: u64,
    pub last_status_print_time: u64,
    pub packet_since_last_print: u64,
    pub packet_lost_since_last_print: u64,
    pub max_in_flight_since_last_print: u64,

    pub ack_field: AckField,
    pub ack_timer: u64,
    pub ack_receiver: crate::ack::AckReceiver,
    pub nack_receiver: crate::nack::NackReceiver,
    pub peer_nack_loss_count: u32,
    /// Highest positively acknowledged peer receipt; holes are NOT declarations of loss.
    pub highest_peer_acked: Option<u64>,
    pub peer_ack_delay_us: u32,
    pub peer_ce_count: u32,

    // Note(Sam): HARD ASSUMPTION that no link ever has a greater RTT than 4.295 seconds.
    pub send_time_band: [u64; 1024], // 1024 buckets of 4.194 ms giving 4.295 seconds of tracking.
    pub send_time_band_head_index: u64, // monotonic time ns / 4_194_304 aka 0x400000
    pub curve_pacer: Option<crate::scheduling::CurvePacer>,
    pub curve_next_tick_ns: u64,
    pub pacing_diagnostics: bool,
    
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
    pub stats: ConnectionStats,
    pub loss_window_start_ns: u64,
    pub loss_count_in_window: u64,
    loss_episodes: LossEpisodes,
    loss_response: LossResponseWindow,
    pub is_app_limited: bool,
    pub app_limit_time_offset: u64,
    /// Sender feedback and receiver echo are independent directions.
    pub ecn_congestion_received: bool,
    pub ecn_echo_pending: bool,
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
        ack_field_virtual_base: 0,
        last_sent_data_packet: 0,
        last_sent_could_have_sent_data_packet: 0,
        last_ack_received_time: timestamp_ns,
        last_status_print_time: timestamp_ns,
        packet_since_last_print: 0,
        packet_lost_since_last_print: 0,
        max_in_flight_since_last_print: 0,
        ack_field: Default::default(),
        ack_timer: u64::MAX,
        ack_receiver: Default::default(),
        nack_receiver: Default::default(),
        peer_nack_loss_count: 0,
        highest_peer_acked: None,
        peer_ack_delay_us: 0,
        peer_ce_count: 0,
        send_time_band: [0; 1024],
        send_time_band_head_index: 0,
        curve_pacer: None,
        curve_next_tick_ns: 0,
        pacing_diagnostics: false,
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
        stats: ConnectionStats::default(),
        loss_window_start_ns: 0,
        loss_count_in_window: 0,
        loss_episodes: LossEpisodes::default(),
        loss_response: LossResponseWindow::default(),
        is_app_limited: false,
        app_limit_time_offset: 0,
        ecn_congestion_received: false,
        ecn_echo_pending: false,
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
    pub nack_packets_sent: u64,
    pub nack_packets_received: u64,
    pub losses_by_nack: u64,
    pub losses_by_timeout: u64,
    pub nack_losses_declared: u64,
    pub false_nacks: u64,
    pub nack_ranges_expired: u64,
    pub nack_reorder_us: u32,
    pub congestion_loss_events: u64,
    pub congestion_ecn_events: u64,
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
    fn control_work_due(&self, now_ns: u64, interval_ns: u64) -> bool {
        self.last_sent_data_packet + 5_000_000_000 < now_ns
            || (self.tu_probe_sequence_number == u64::MAX
                && self.current_tu < ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64
                && self.last_sent_tu_probe_time_ns + (self.tu_probe_failed_count.min(50).pow(2)*250_000_000).max(interval_ns) < now_ns)
    }
    fn send_time(&self, sequence: u64) -> u64 {
        match &self.curve_pacer {
            Some(p) => p.history.lookup(sequence).unwrap_or(0),
            None => get_send_time_for_sequence_number(sequence, &self.send_time_band, self.send_time_band_head_index),
        }
    }
    fn account_send(&mut self, actual_ns: u64) {
        assert!(self.send_sequence_number < crate::sequence::ACK_SPACE - 1, "data nonce space exhausted");
        let i = self.send_sequence_number % PACKETS_WAITING_ACK_CAPACITY;
        self.declared_lost_field[(i/64) as usize] &= !(1 << (i%64));
        if let Some(p) = &mut self.curve_pacer {
            if self.pacing_diagnostics { p.observe_send(self.send_sequence_number, actual_ns); }
            let index = self.send_sequence_number % PACKETS_WAITING_ACK_CAPACITY;
            self.packets_waiting_ack_field[(index / 64) as usize] |= 1u64 << (index % 64);
            self.send_sequence_number += 1;
        } else {
            increment_sequence_number_and_account(actual_ns, &mut self.send_sequence_number,
                &mut self.send_time_band, &mut self.send_time_band_head_index, &mut self.packets_waiting_ack_field);
            if self.pacing_diagnostics {
                let estimate = self.send_time(self.send_sequence_number - 1);
                if estimate != 0 && estimate != u64::MAX {
                    let error = actual_ns.abs_diff(estimate);
                    self.stats.pacing_error_samples += 1;
                    self.stats.pacing_error_abs_sum_ns = self.stats.pacing_error_abs_sum_ns.saturating_add(error);
                    self.stats.pacing_error_max_ns = self.stats.pacing_error_max_ns.max(error);
                }
            }
        }
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

/* Because rust is bad, packed is the only way for us to remove any alignment requirements and assumptions. */
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AckField {
    pub field_base: u32,
    pub field: [u64; 64], // Each entry is 1 bit. 4096 entries total.
}

impl Default for AckField { fn default() -> Self { Self { field_base: 0, field: [0u64; 64], } } }

impl AckField {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const AckField as *const u8,
                core::mem::size_of::<AckField>(),
            )
        }
    }
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
) {
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
                creation_time_ns: monotonic_clock_ns(),
                my_ip,
                my_transport_identity_keypair: my_connect_keypair.clone(),
                two_byte_send_prefix: load_u16(&my_connect_keypair.public[0..2]) << 1,
                other_ip: endpoint.ip,
                other_port: endpoint.port,
                other_transport_identity: endpoint.key.clone(),
                connection_state: ConnectionState::SendingClientHelloPlaintext { last_sent_time_ns: 0, hello_packet_payload },
                handshake_hash: [0u8; 64],
                unreliable_send_buffer: UnreliableSendBuffer::new(send_buffer_params.0, send_buffer_params.1, send_buffer_params.2),
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
                creation_time_ns: monotonic_clock_ns(),
                my_ip,
                my_transport_identity_keypair: my_connect_keypair.clone(),
                two_byte_send_prefix: load_u16(&my_connect_keypair.public[0..2]) << 1,
                other_ip: endpoint.ip,
                other_port: endpoint.port,
                other_transport_identity: endpoint.key.clone(),
                connection_state: ConnectionState::SendingClientHello { magic1: my_connect_keypair.magic1, last_sent_time_ns: 0, hello_packet_payload, handshake },
                handshake_hash: [0u8; 64],
                unreliable_send_buffer: UnreliableSendBuffer::new(send_buffer_params.0, send_buffer_params.1, send_buffer_params.2),
                unreliable_reassembly: ReassemblySlot::new_ring(1024),
                unreliable_fec: FecRecvSlot::new_ring(1024),
            },
        );
    }
}

const        VERBOSE                :bool=0!=                (1);
const OVERLY_VERBOSE                :bool=0!=                (0);

macro_rules! pod { ($($item:item)*) => { $(#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)] $item)* }; }

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReassemblySlot {
    pub buf: Vec<u8>,
    pub total_len: Option<u32>,
    pub received: Vec<(u32, u32)>, // sorted non-overlapping non-adjacent ranges: [start, end)
    pub package_id: u16,
}

impl ReassemblySlot {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            total_len: None,
            received: Vec::new(),
            package_id: 0,
        }
    }
    
    /// Message bytes received so far.
    pub fn bytes_received(&self) -> u64 { self.received.iter().map(|&(s, e)| (e - s) as u64).sum() }

    pub fn new_ring(size: usize) -> Vec<ReassemblySlot> {
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size { vec.push(Self::new()); }
        vec
    }

    /// returns (success, is_complete)
    pub fn insert(&mut self, offset: usize, data: &[u8], is_fin: bool) -> (bool, bool) {

        let start = offset as u32;
        let end = (offset + data.len()) as u32;

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
            let complete = self.total_len.is_some_and(|tl| self.received.len() == 1 && self.received[0] == (0, tl));
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
    state: FecRecvState,
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
/// Process-wide admission budget, conservatively charging 3x message bytes for output
/// plus Wirehair working buffers. Ingress queues are separately capped at 32 MiB/worker.
pub const MAX_FEC_DECODE_RESERVED_BYTES: usize = 3 << 30;
pub const MAX_FEC_INGRESS_BYTES: usize = 32 << 20;
static FEC_DECODE_RESERVED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn fec_inactive_grace_ns(rtt: u16, pressure: bool) -> u64 {
    if pressure {
        if rtt == 0 || rtt == u16::MAX { 250_000_000 } else { 2 * rtt as u64 * 100_000 }
    } else {
        let rtt_ns = if rtt == u16::MAX { 0 } else { rtt as u64 * 100_000 };
        (4 * rtt_ns).max(2_000_000_000)
    }
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

struct FecWorkerGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>, usize);
impl Drop for FecWorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        FEC_DECODE_RESERVED.fetch_sub(self.1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Handles one received FEC fragment for the package in `slot` (the caller has already made
/// the slot belong to `package_id`). Returns a message to deliver if decoding finished inline.
fn fec_receive_block(
    slot: &mut FecRecvSlot, connection_key: ConnectionKey, package_id: u16,
    message_len: usize, block_bytes: usize, block_id: u32, data: &[u8],
    done_tx: &std::sync::mpsc::Sender<(ConnectionKey, u16, Vec<u8>)>, workers: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Option<Vec<u8>> {
    use crate::fec::*;
    if matches!(slot.state, FecRecvState::Done) { return None; }
    slot.blocks_received += 1;
    // A block of the wrong length can never decode; drop it.
    let k = MessageLayout::new(message_len, block_bytes)?.k;
    let expect = if (block_id as usize) < k { block_len(message_len, block_bytes, block_id) } else { block_bytes };
    if data.len() != expect { return None; }
    if slot.params().is_some_and(|p| p != (message_len, block_bytes)) {
        // Same package id, different shape: restart like a plain slot whose insert fails.
        slot.state = FecRecvState::Empty;
    }
    if !slot.in_use() {
        let reserve = message_len.checked_mul(3)?;
        let use_worker = k > FEC_INLINE_MAX_BLOCKS && workers.load(std::sync::atomic::Ordering::Acquire) < MAX_FEC_DECODE_WORKERS
            && FEC_DECODE_RESERVED.fetch_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire,
                |used| used.checked_add(reserve).filter(|&next| next <= MAX_FEC_DECODE_RESERVED_BYTES)).is_ok();
        let mut spawned = None;
        if use_worker {
            let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>)>((MAX_FEC_INGRESS_BYTES / block_bytes).max(1));
            let done_tx = done_tx.clone();
            workers.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let guard = FecWorkerGuard(workers.clone(), reserve);
            let r = std::thread::Builder::new().name("stp-fec-decode".into()).spawn(move || {
                let _guard = guard;
                let Some(layout) = MessageLayout::new(message_len, block_bytes) else { return; };
                if let Some(m) = decode_message_blocks(layout, rx, MAX_FEC_INGRESS_BYTES) {
                    let _ = done_tx.send((connection_key, package_id, m));
                }
            });
            if r.is_ok() { spawned = Some(tx); }
        }
        slot.state = match spawned {
            Some(tx) => FecRecvState::Worker { tx, message_len, block_bytes },
            None if k <= FEC_INLINE_MAX_BLOCKS => match MessageDecoder::new(message_len, block_bytes) { Some(d) => FecRecvState::Inline(d), None => FecRecvState::Done },
            None => {
                // Admission can recover when a retired worker's guard is released.
                // Erase this fragment, not the whole package; later repairs may suffice.
                slot.admission_refused = true;
                slot.ingress_dropped += 1;
                FecRecvState::Empty
            },
        };
    }
    match &mut slot.state {
        FecRecvState::Inline(dec) => match dec.add(block_id, data) {
            Ok(DecodeStatus::NeedMore) | Err(DecodeError::BadBlock) => None,
            Ok(DecodeStatus::Done) => { let m = dec.recover(); slot.state = FecRecvState::Done; m }
            Err(DecodeError::Failed(_)) => { slot.state = FecRecvState::Done; None }
        },
        FecRecvState::Worker { tx, .. } => {
            // The worker is gone once it has decoded (or failed): nothing more to do.
            match tx.try_send((block_id, data.to_vec())) {
                Ok(()) => slot.last_block_ns = monotonic_clock_ns(),
                Err(std::sync::mpsc::TrySendError::Full(_)) => slot.ingress_dropped += 1, // an erasure, not a network-thread stall
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
    pub send_unreliable: Vec<(ConnectionKey, Vec<u8>)>,
}

#[derive(Default)]
pub struct NetworkThreadPull {
    pub current_connections: Vec<(STPAddress, [u8; 64])>,
    pub received_unreliable_messages: VecDeque<(ConnectionKey, Vec<u8>)>,
    /// Messages from this call's `send_unreliable` that were not queued, handed back unchanged:
    /// the connection's send queue was full (see `UnreliableSendBuffer::submit_messages`), or no
    /// connection with that key exists. Per connection they keep the order they were pushed in.
    /// Nothing is dropped; resubmit them later or discard them yourself.
    pub send_unreliable_rejected: Vec<(ConnectionKey, Vec<u8>)>,
    /// For every connection the network thread holds (connected or still handshaking), the
    /// largest message its send queue would accept now, after this call's submissions; u64::MAX
    /// when its queue is empty. A connection missing here does not exist.
    pub unreliable_send_free_bytes: Vec<(ConnectionKey, u64)>,
    /// Cumulative counters for every connected connection.
    pub connection_stats: Vec<(ConnectionKey, ConnectionStats)>,
    /// FEC messages whose last block went out since the previous call (only with
    /// `NetworkThreadOptions::record_fec_messages`).
    pub fec_messages: Vec<(ConnectionKey, crate::fec_adapt::FecMessageInfo)>,
    /// Network-thread-wide counters (kernel drops, loop starvation).
    pub thread_stats: NetworkThreadStats,
}

struct NetworkThreadInner {
    state: std::sync::atomic::AtomicUsize, // 0 empty, 1 full
    stop: std::sync::atomic::AtomicBool,
    push: std::cell::UnsafeCell<NetworkThreadPush>,
    pull: std::cell::UnsafeCell<NetworkThreadPull>,
    fec_redundancy_ppm: std::sync::atomic::AtomicU32,
    fec_adaptive_enabled: std::sync::atomic::AtomicBool,
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

/// Parameters of the existing R/P/G/S sending-rate curve; no alternative control law.
#[derive(Debug, Clone, Copy)]
pub struct CongestionControlOptions {
    pub beta: f64,
    pub recovery_rtts: u64,
    pub rate_rp: f64,
    pub rate_pg: f64,
    pub rate_gs: f64,
    pub time_pg: f64,
    pub time_gs: f64,
    pub loss_threshold: u64,
    /// Also require this fraction of a commanded-rate RTT's packets to be lost.
    /// Zero preserves the two-loss legacy detector; nonzero can tolerate radio noise.
    pub loss_fraction_ppm: u32,
    /// Opt-in completed send-time RTT cohort loss fraction. Below this fraction
    /// do not cut; at/above it use the normal beta cut. Uses actual packet counts,
    /// not delivery-rate estimation. Zero retains the legacy episode detector.
    pub loss_response_fraction_ppm: u32,
    /// Age-based declaration, not sequence gaps: additional reorder/jitter tolerance.
    pub loss_timeout_rtts: f64,
    pub event_guard_rtts: f64,
    /// Optional ECN-only guard override; zero inherits event_guard_rtts.
    pub ecn_event_guard_rtts: f64,
    /// Millionths of a packet per second (100_000_000 = 100 pps).
    pub rate_floor_upps: u64,
    pub initial_rate_upps: u64,
    pub min_growth_uppsps: f64,
    pub max_growth_uppsps: f64,
    /// Optional Reno-friendly additive floor: alpha / RTT_seconds^2 pps/s (0 disables).
    pub friendly_growth_alpha: f64,
    /// Optional growth ceiling as a fraction of the anchor rate per RTT (0 disables).
    /// The additive floor remains available even at low anchor rates.
    pub relative_growth_per_rtt: f64,
    /// Apply the growth envelope to R as well as P/G/S, bounding regrowth after cuts.
    pub bound_recovery_growth: bool,
    /// Compound the relative ceiling with elapsed RTTs instead of freezing its
    /// slope at the event anchor. Pure time/rate curve; no ACK/delivery estimate.
    pub compound_growth: bool,
    /// Use the compounded fractional envelope without a fixed pps/s ceiling.
    /// The R/P/G/S curve is still an upper bound. Requires bounded compound growth.
    pub proportional_growth: bool,
    /// Opt-in fixed-memory congestion-episode instrumentation, never alters the rate.
    pub record_loss_episodes: bool,
    /// Optional initial pps multiplication per RTT until first loss/ECN (0 disables).
    /// Uses only elapsed active time and RTT; no delivery/bandwidth/delay signal.
    pub startup_multiplier: f64,
    /// Anchor startup exit this many RTTs before the lost/marked packet's send.
    /// One preserves the initial experiment; larger values cut overshoot harder.
    pub startup_backoff_rtts: f64,
}
impl CongestionControlOptions {
    pub const fn legacy() -> Self {
        Self { beta: CUBIC_BETA, recovery_rtts: CUBIC_K_RTT_MULTIPLIER,
            rate_rp: RATE_RP, rate_pg: RATE_PG, rate_gs: RATE_GS, time_pg: TIME_PG, time_gs: TIME_GS,
            loss_threshold: 2, loss_fraction_ppm: 0, loss_response_fraction_ppm: 0, loss_timeout_rtts: 2.0, event_guard_rtts: 0.5, ecn_event_guard_rtts: 0.0, rate_floor_upps: RATE_FLOOR_UPPS, initial_rate_upps: RATE_FLOOR_UPPS,
            min_growth_uppsps: CUBIC_MIN_GROWTH_UPPSPS, max_growth_uppsps: CUBIC_MAX_RATE_UPPS_PER_SEC,
            friendly_growth_alpha: 0.0, relative_growth_per_rtt: 0.0, bound_recovery_growth: false, compound_growth: false, proportional_growth: false, record_loss_episodes: false, startup_multiplier: 0.0, startup_backoff_rtts: 1.0 }
    }
    /// Shorter probe plateau and stronger existing additive term; same R/P/G/S curve.
    pub const fn balanced() -> Self {
        Self { time_pg: 2.0, time_gs: 8.0, min_growth_uppsps: 25_000_000.0,
            initial_rate_upps: 1_000_000_000, ..Self::legacy() }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(self.beta > 0.0 && self.beta < 1.0 && self.beta < self.rate_rp && self.rate_rp < self.rate_pg && self.rate_pg < self.rate_gs && self.rate_gs <= 100.0) { return Err("CC rate factors need 0 < beta < RP < PG < GS <= 100"); }
        if !(1..=100).contains(&self.recovery_rtts) { return Err("CC recovery RTTs must be in 1..=100"); }
        if !(1.1 <= self.time_pg && self.time_pg * 1.1 <= self.time_gs && self.time_gs <= 100.0) { return Err("CC phase times need PG >= 1.1 and GS >= 1.1*PG, GS <= 100"); }
        let g_span = self.time_gs - self.time_pg;
        let p_slope = (self.rate_pg - self.rate_rp) / (self.time_pg - 1.0);
        if self.rate_gs - self.rate_pg - p_slope * g_span < 0.0 { return Err("CC G phase must have nonnegative curvature"); }
        if !(0.0..=10.0).contains(&self.event_guard_rtts) || !(0.0..=10.0).contains(&self.ecn_event_guard_rtts) { return Err("invalid CC guard"); }
        if !(1..=10000).contains(&self.loss_threshold) { return Err("CC loss threshold must be in 1..=10000"); }
        if !(self.rate_floor_upps > 0 && self.initial_rate_upps >= self.rate_floor_upps && self.initial_rate_upps <= 1_000_000_000_000 && self.min_growth_uppsps >= 0.0 && self.min_growth_uppsps.is_finite() && self.max_growth_uppsps > self.min_growth_uppsps && self.max_growth_uppsps <= 1e15) { return Err("invalid CC floor, initial rate or growth limits"); }
        if !(0.0..=100.0).contains(&self.friendly_growth_alpha) || !(0.0..=10.0).contains(&self.relative_growth_per_rtt) { return Err("invalid CC RTT-scaled growth envelope"); }
        if self.loss_fraction_ppm > 500_000 || self.loss_response_fraction_ppm > 500_000 || !(2.0..=10.0).contains(&self.loss_timeout_rtts) { return Err("invalid CC loss episode/reorder tolerance"); }
        if self.proportional_growth && !(self.bound_recovery_growth && self.compound_growth && self.relative_growth_per_rtt > 0.0) { return Err("CC proportional growth requires bounded compound relative growth"); }
        if self.startup_multiplier != 0.0 && !(1.01..=2.0).contains(&self.startup_multiplier) { return Err("CC startup multiplier must be zero or 1.01..=2"); }
        if !(0.0..=4.0).contains(&self.startup_backoff_rtts) { return Err("CC startup backoff must be in 0..=4 RTTs"); }
        Ok(())
    }
}
impl Default for CongestionControlOptions {
    fn default() -> Self { Self::legacy() }
}

/// Coarse wake cadence is independent of the rate-based congestion controller.
/// Polynomial pacing falls back to precise for startup or proportional growth:
/// those optional curves are not represented by the polynomial scheduler.
#[derive(Debug, Clone, Copy, Default)]
pub enum PacingOptions {
    #[default]
    Precise,
    Polynomial { cadence_ms: u64 },
}
impl PacingOptions {
    fn cadence_ns(self, cc: &CongestionControlOptions) -> Option<u64> {
        match self {
            Self::Precise => None,
            Self::Polynomial { cadence_ms } => {
                assert!([1,2,5,10].contains(&cadence_ms), "polynomial cadence must be 1, 2, 5 or 10 ms");
                if cc.startup_multiplier > 0.0 || cc.proportional_growth { None }
                else { Some(cadence_ms * 1_000_000) }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkThreadOptions {
    pub congestion_control: CongestionControlOptions,
    /// ACK format and receive-side delay; use Legacy for pre-upgrade peers.
    pub acknowledgements: crate::ack::AckOptions,
    pub pacing: PacingOptions,
    /// Polynomial send-burst wall-time budget: None uses one cadence, Some(0)
    /// disables it (re-anchor only), Some(ns) overrides it. Ignored by precise.
    /// A scheduler preemption inside one packet can still exceed the budget.
    pub polynomial_burst_budget_ns: Option<u64>,
    /// Optional per-send inversion check; do not enable when measuring CPU savings.
    pub pacing_diagnostics: bool,
    /// See `new_network_thread_with_bind`.
    pub bind_ip: Option<std::net::IpAddr>,
    /// Sender-side forward error correction for unreliable messages of 2+ packets: extra
    /// Wirehair-coded blocks in parts per million of the message's block count (20_000 = 2%),
    /// so a message survives losing about that fraction of its packets. 0 = off: plain
    /// fragments, wire bytes exactly as without FEC. Capped at 1_000_000 (100%). Receivers
    /// decode FEC messages without configuration (but must run code that knows FEC fragments).
    /// Can be changed later with `NetworkThreadHandle::set_fec_redundancy_ppm`.
    pub fec_redundancy_ppm: u32,
    /// FEC mode: None = fixed `fec_redundancy_ppm` (above). Some = adaptive: each connection
    /// estimates its packet loss from its own sent/lost counts and sizes every message's repair
    /// blocks so it fails with probability ~eps at that loss (see `fec_adapt`); then
    /// `fec_redundancy_ppm` is ignored. Toggle with `NetworkThreadHandle::set_fec_adaptive_enabled`.
    pub fec_adaptive: Option<crate::fec_adapt::AdaptiveFecConfig>,
    /// Report every finished FEC message in `NetworkThreadPull::fec_messages` (for measurement).
    pub record_fec_messages: bool,
    /// Optional sender packet/fragment/outcome event CSV; disabled by default.
    pub loss_trace: Option<std::path::PathBuf>,
}

impl NetworkThreadHandle {
    /// Changes the FEC redundancy (see `NetworkThreadOptions::fec_redundancy_ppm`) for messages
    /// that start sending from now on, on all connections.
    pub fn set_fec_redundancy_ppm(&self, ppm: u32) {
        self.inner.fec_redundancy_ppm.store(ppm.min(MAX_FEC_REDUNDANCY_PPM), std::sync::atomic::Ordering::Relaxed);
    }
    /// Switches between adaptive FEC (if `NetworkThreadOptions::fec_adaptive` was given) and the
    /// fixed `fec_redundancy_ppm`. Per-connection estimator state is dropped while switched off
    /// and starts over from `initial_loss` when switched back on.
    pub fn set_fec_adaptive_enabled(&self, on: bool) {
        self.inner.fec_adaptive_enabled.store(on, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn new_network_thread_with_options(my_keypairs: Vec<IdentityKeyPair>, my_port: u16, max_pps: Option<u64>, send_buffer_params: (u32, u32, u32), options: NetworkThreadOptions) -> NetworkThreadHandle {
    let bind_ip = options.bind_ip;
    let curve_cadence_ns = options.pacing.cadence_ns(&options.congestion_control);
    let curve_burst_budget_ns = curve_cadence_ns.and_then(|cadence|
        Some(options.polynomial_burst_budget_ns.unwrap_or(cadence)).filter(|ns| *ns != 0));
    let pacing_diagnostics = options.pacing_diagnostics;
    let cc = options.congestion_control;
    let ack_options = options.acknowledgements;
    cc.validate().expect("invalid congestion controller configuration");
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
        fec_redundancy_ppm: std::sync::atomic::AtomicU32::new(options.fec_redundancy_ppm.min(MAX_FEC_REDUNDANCY_PPM)),
        fec_adaptive_enabled: std::sync::atomic::AtomicBool::new(options.fec_adaptive.is_some()),
    });
    let fec_adaptive_cfg = options.fec_adaptive;
    let record_fec_messages = options.record_fec_messages;
    let mut loss_trace = options.loss_trace.as_deref().map(|p| crate::loss_trace::LossTrace::open(p).expect("open loss trace"));

    let thread_inner = inner.clone();

    let thread = std::thread::spawn(move || {

        let mut packet_memory_encrypted = new_packet_memory(); // Incoming Encrypted / Outgoing Encrypted
        let mut packet_memory_recv      = new_packet_memory(); // Incoming Decrypted
        let mut packet_memory_send      = new_packet_memory(); // Outgoing Decrypted

        let mut receive_queue = ReceiveQueue::default();
        let (fec_done_tx, fec_done_rx) = std::sync::mpsc::channel::<(ConnectionKey, u16, Vec<u8>)>();
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
            let fec_redundancy_ppm = thread_inner.fec_redundancy_ppm.load(std::sync::atomic::Ordering::Relaxed);
            let fec_adaptive_now = if thread_inner.fec_adaptive_enabled.load(std::sync::atomic::Ordering::Relaxed) { fec_adaptive_cfg } else { None };
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
                            connect_to_endpoint(&mut connections_map, keypair, w, send_buffer_params);
                            break;
                        }
                    }
                }
                
                // Push unreliable messages to their queues, batched per connection. The sort is
                // stable so each connection's messages keep the caller's order. Whatever a queue
                // does not accept, and everything for a connection not in the map, goes back to
                // the caller untouched.
                let mut resp = NetworkThreadPull::default();
                req.send_unreliable.sort_by(|a, b| a.0.cmp(&b.0));
                let mut i = 0;
                while i < req.send_unreliable.len() {
                    let key = req.send_unreliable[i].0;
                    let mut j = i;
                    while j < req.send_unreliable.len() && req.send_unreliable[j].0 == key { j += 1; }
                    let mut batch = Vec::with_capacity(j - i);
                    while i < j {
                        batch.push(std::mem::take(&mut req.send_unreliable[i].1));
                        i += 1;
                    }
                    let rejected = if let Some(tracking_data) = connections_map.get_mut(&key) {
                        tracking_data.unreliable_send_buffer.submit_messages(batch)
                    } else {
                        batch
                    };
                    resp.send_unreliable_rejected.extend(rejected.into_iter().map(|m| (key, m)));
                }
                resp.unreliable_send_free_bytes = connections_map.iter_mut()
                    .map(|(key, value)| (*key, value.unreliable_send_buffer.free_bytes())).collect();
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
                for _recv_round in 0..1 { // single-iteration loop: `continue` below skips the rest of this packet
                    let (buf_len, other_ip_addr, other_port, ecn_marked, ecn_enabled, service_class, timestamp_ns) =
                        match udp_recv_with_congestion_and_dscp(socket, &mut packet_memory_encrypted[..]) {
                            Ok(r) => r,
                            Err(_) => continue,
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
                                            let client_key = Vec::from(client_key);
                                            store_u48(&mut packet_memory_send[0..6], 0xffff_ffff_0000 | (load_u16(&my_kp.public[0..2]) << 1) as u64);
                                            packet_memory_send[6..6+32].copy_from_slice(&my_kp.public[..]);
                                            store_u64(&mut packet_memory_send[6+32..6+32+8], chosen_magic2);
                                            let hello_packet_payload = Vec::from(&packet_memory_send[0..6+32+8]);
        
                                            let my_ip = if other_ip_addr.to_ipv4_mapped().is_some() { Ipv6Addr::UNSPECIFIED } else { Ipv6Addr::UNSPECIFIED };
                                            connections_map.insert(
                                                connection_key,
                                                ConnectionTrackingData {
                                                    creation_time_ns: monotonic_clock_ns(),
                                                    my_ip,
                                                    my_transport_identity_keypair: my_kp.clone(),
                                                    two_byte_send_prefix: load_u16(&my_kp.public[0..2]) << 1,
                                                    other_ip: other_ip_addr,
                                                    other_port: other_port,
                                                    other_transport_identity: client_key,
                                                    connection_state: ConnectionState::SendingServerHelloPlaintext { magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload },
                                                    handshake_hash: [0u8; 64],
                                                    unreliable_send_buffer: UnreliableSendBuffer::new(send_buffer_params.0, send_buffer_params.1, send_buffer_params.2),
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
                                                        creation_time_ns: monotonic_clock_ns(),
                                                        my_ip,
                                                        my_transport_identity_keypair: my_kp.clone(),
                                                        two_byte_send_prefix: load_u16(&my_kp.public[0..2]) << 1,
                                                        other_ip: other_ip_addr,
                                                        other_port: other_port,
                                                        other_transport_identity: client_key,
                                                        connection_state: ConnectionState::SendingServerHello { cipher, magic1, magic2: chosen_magic2, last_sent_time_ns: 0, hello_packet_payload },
                                                        handshake_hash,
                                                        unreliable_send_buffer: UnreliableSendBuffer::new(send_buffer_params.0, send_buffer_params.1, send_buffer_params.2),
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
                            let is_ack = payload.len() == 516 || payload.len() == crate::ack::ACK_PAYLOAD_LEN || payload.len() == crate::nack::NACK_PAYLOAD_LEN;
                            if is_ack != crate::sequence::is_ack_space(non_virtual_nonce) { break 'conn; }
                            if !state.receive_sequences.commit(nonce) { break 'conn; }
                            // ACK nonces are not holes in the dense data stream.
                            if !is_ack { state.rx_tracker.on_packet(nonce, &mut state.stats); }
                            
                            if payload.len() < 516 && !is_ack {
                                if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}, payload < 516."); }
                                break 'conn;
                            }

                            // ACKs remain identified ONLY by exact decrypted packet size.
                            if is_ack {
                                let legacy_ack = if payload.len() == 516 { Some(unsafe { &*(payload.as_ptr() as *const AckField) }) } else { None };
                                let nack_ack = if payload.len() == crate::nack::NACK_PAYLOAD_LEN {
                                    let Some(a) = crate::nack::NackAck::decode(payload) else { break 'conn; };
                                    if a.highest >= state.send_sequence_number { break 'conn; }
                                    state.stats.nack_packets_received += 1;
                                    crate::ack::update_ce_count(&mut state.peer_nack_loss_count, a.loss_count);
                                    Some(a)
                                } else { None };
                                let bitmap_ack = if let Some(a) = &nack_ack { Some(a.feedback()) }
                                else if payload.len() == crate::ack::ACK_PAYLOAD_LEN {
                                    let Some(a) = crate::ack::BitmapAck::decode(payload) else { break 'conn; };
                                    if a.highest >= state.send_sequence_number { break 'conn; }
                                    state.peer_ack_delay_us = a.delay_us;
                                    Some(a)
                                } else { None };
                                state.stats.ack_packets_received += 1;

                                let mut RTT_acc = 0u64;
                                let mut RTT_count = 0u64;
                                
                                let mut oldest_newly_acked_send_time: u64 = u64::MAX;
                                let legacy_indices = legacy_ack.into_iter().flat_map(|ack| {
                                    let base = crate::sequence::extend(ack.field_base as u64, state.send_sequence_number.saturating_sub(1), 32);
                                    (base..base+4096).filter(move |&seq| ack.field[((seq-base)/64) as usize] & (1 << ((seq-base)%64)) != 0)
                                });
                                let relevant_ack = bitmap_ack.as_ref().map(|a| a.relevant(&state.packets_waiting_ack_field, &state.declared_lost_field[..]));
                                let indices = legacy_indices.chain(relevant_ack.iter().flat_map(crate::ack::BitmapAck::acknowledged))
                                    .chain(nack_ack.iter().flat_map(crate::nack::NackAck::acknowledged));
                                for index in indices {
                                    if index < state.send_sequence_number {
                                        state.highest_peer_acked = Some(state.highest_peer_acked.unwrap_or(index).max(index));
                                    }
                                    if index >= state.packets_waiting_ack_tail && index < state.send_sequence_number {
                                        let bit_index = index % PACKETS_WAITING_ACK_CAPACITY;
                                        if state.packets_waiting_ack_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0 {
                                            state.packets_waiting_ack_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                                            state.last_ack_received_time = timestamp_ns;
                                            if let Some(t) = &mut loss_trace { t.outcome('A', existing_connection.two_byte_send_prefix, index, timestamp_ns); }

                                            let send_time_of_latest_ns = state.send_time(index);
                                            if send_time_of_latest_ns != 0 && send_time_of_latest_ns != u64::MAX {
                                                oldest_newly_acked_send_time = oldest_newly_acked_send_time.min(send_time_of_latest_ns);
                                                // One truthful sample per new-format ACK. Its delay belongs only
                                                // to sample_seq, not every packet repeated in the bitmap.
                                                if bitmap_ack.as_ref().is_none_or(|a| index == a.sample_seq) {
                                                    let delay = bitmap_ack.as_ref().map_or(0, |a| a.delay_us as u64 * 1000);
                                                    let raw = timestamp_ns.saturating_sub(send_time_of_latest_ns);
                                                    if delay < raw {
                                                        RTT_acc += (raw - delay).max(100_000) / 100_000;
                                                        RTT_count += 1;
                                                    }
                                                }
                                            }
                                            
                                            if index == state.tu_probe_sequence_number {
                                                state.tu_probe_sequence_number = u64::MAX;
                                                state.last_sent_tu_probe_time_ns = 0;
                                                state.current_tu = state.tu_probe_size;
                                                state.tu_probe_size_advance *= 2;
                                                state.tu_probe_failed_count = 0;
                                            }
                                            else {
                                                assert!(state.packets_in_flight > 0, "packets_in_flight underflow");
                                                state.packets_in_flight -= 1;
                                            }
                                            
                                        }
                                    }
                                    if index < state.send_sequence_number && index.saturating_add(PACKETS_WAITING_ACK_CAPACITY) >= state.packets_waiting_ack_tail {
                                        // Acked after it was declared lost: the declaration was spurious.
                                        let bit_index = index % PACKETS_WAITING_ACK_CAPACITY;
                                        let w = &mut state.declared_lost_field[(bit_index / 64) as usize];
                                        if *w & (1u64 << (bit_index % 64)) != 0 {
                                            *w &= !(1u64 << (bit_index % 64));
                                            state.stats.spurious_losses += 1;
                                            if let Some(t) = &mut loss_trace { t.outcome('A', existing_connection.two_byte_send_prefix, index, timestamp_ns); }
                                        }
                                    }
                                }

                                if let Some(a) = &nack_ack {
                                    for seq in a.lost() {
                                        let cuts_before = state.stats.congestion_loss_events;
                                        if declare_packet_lost(state, seq, timestamp_ns, &cc, max_pps) {
                                            state.stats.losses_by_nack += 1;
                                            existing_connection.unreliable_send_buffer.fec_on_packet_lost(seq);
                                            if let Some(t) = &mut loss_trace {
                                                t.outcome('N', existing_connection.two_byte_send_prefix, seq, timestamp_ns);
                                                if state.stats.congestion_loss_events > cuts_before { t.outcome('C', existing_connection.two_byte_send_prefix, seq, timestamp_ns); }
                                            }
                                        }
                                    }
                                }
                                let ce_feedback = bitmap_ack.as_ref().is_some_and(|a| crate::ack::update_ce_count(&mut state.peer_ce_count, a.ce_count));
                                if (legacy_ack.is_some() && ecn_marked) || ce_feedback {
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

                            if matches!(ack_options, crate::ack::AckOptions::Nack) {
                                if !state.nack_receiver.receive(nonce, timestamp_ns, ecn_marked, ack_options, &mut state.ack_timer) { break 'conn; }
                            } else if !matches!(ack_options, crate::ack::AckOptions::Legacy) {
                                if !state.ack_receiver.receive_with_rtt(nonce as u64, timestamp_ns, ecn_marked, ack_options, &mut state.ack_timer, state.stats.rtt_us, buf_len) { break 'conn; }
                            } else {
                            if nonce < state.ack_field_virtual_base {
                                if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}, nonce too old."); }
                                break 'conn;
                            }
                            if nonce > state.ack_field_virtual_base + (1u64 << 30) {
                                if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}, nonce too far in the future.."); }
                                break 'conn;
                            }
                            
                            let bit_index = nonce-state.ack_field_virtual_base;
                            if nonce < state.ack_field_virtual_base + 4096 && 0 != (1u64 << (bit_index % 64)) & state.ack_field.field[bit_index as usize / 64] {

                                if OVERLY_VERBOSE { println!("Dropping from {connection_key:?}, nonce already received."); }
                                break 'conn;
                            }

                            if nonce >= state.ack_field_virtual_base + 4096 {
                                // ACK traffic has its own space and does not require data-ring capacity.
                                { // send ack
                                    let mut o = 0;
                                    let virtual_nonce = state.send_ack_sequence_number;
                                    o += existing_connection.two_byte_send_prefix.write_to(&mut packet_memory_send[o..]);
                                    o += crate::sequence::to_wire(virtual_nonce).write_to(&mut packet_memory_send[o..]);
                                    state.send_ack_sequence_number = state.send_ack_sequence_number.checked_add(1).expect("ACK nonce space exhausted");

                                    if let Some(cipher) = &mut state.cipher { o += cipher.current.write_message(virtual_nonce, state.ack_field.as_bytes(), &mut packet_memory_send[o..]).unwrap(); }
                                    else { o += state.ack_field.as_bytes().write_to(&mut packet_memory_send[o..]); }
                                    let ack_ecn = take_ecn_echo(state);
                                    udp_send_with_congestion_and_dscp(socket, existing_connection.other_ip, existing_connection.other_port, &packet_memory_send[..o], Dscp::Af21, ack_ecn);
                                    state.stats.ack_packets_sent += 1;
                                    state.stats.ack_bytes_sent += o as u64;
                                    state.ack_timer = u64::MAX;
                                }

                                if nonce >= state.ack_field_virtual_base + 4096 + 2048 {
                                    state.ack_field_virtual_base = nonce;
                                    state.ack_field.field_base = nonce as u32;
                                    state.ack_field.field = [0u64; 64];
                                }
                                else if nonce >= state.ack_field_virtual_base + 4096 {
                                    state.ack_field_virtual_base += 2048;
                                    state.ack_field.field_base = state.ack_field_virtual_base as u32;
                                    let mut field = state.ack_field.field;
                                    let (bottom, top) = field.split_at_mut(32);
                                    bottom.copy_from_slice(top);
                                    top.fill(0);
                                    state.ack_field.field = field;
                                }
                            }

                            let bit_index = nonce-state.ack_field_virtual_base;
                            state.ack_field.field[bit_index as usize / 64] |= 1u64 << (bit_index % 64);
                            if ecn_marked { state.ecn_echo_pending = true; }
                            if state.ack_timer == u64::MAX { state.ack_timer = timestamp_ns + ACK_BUFFER_TIME_NS; }

                            }

                            // A legitimate data packet could never this state because to be all zeroes the
                            // first fragment would have to be package_id=0 and frag_len=0. If so that is
                            // either the only fragment and followed by u64::MAX terminator OR there would
                            // be a second fragment with a package_id != 0.
                            {
                                let mut all_null = true;
                                let mut i = 0;
                                while all_null && i < payload.len() {
                                    all_null &= payload[i] == 0;
                                    i += 1;
                                }
                                if all_null { 
                                    if OVERLY_VERBOSE { println!("Received keep alive from {connection_key:?}."); }
                                    break 'conn;
                                }
                            }

                            // if OVERLY_VERBOSE { println!("Got data from {:?}  data: {:?}", existing_connection.other_transport_identity, payload); }
                            
                            let mut remaining_payload = payload;
                            while remaining_payload.len() >= 8 {
                                let header = load_u64(&remaining_payload[0..8]);
                                if header == u64::MAX { break 'conn; }

                                if header & 1 != 0 {
                                    // Extended fragment (FEC); see STP_FEC_FRAGMENT_HEADER_SIZE.
                                    let data_len = ((header >> 18) & 0x3fff) as usize;
                                    if remaining_payload.len() < STP_FEC_FRAGMENT_HEADER_SIZE + data_len {
                                        if OVERLY_VERBOSE { println!("Error, extended fragment extends beyond end of packet received from {connection_key:?}. Disconnecting..."); }
                                        connections_map.remove(&connection_key);
                                        break 'conn;
                                    }
                                    let word1 = load_u64(&remaining_payload[8..16]);
                                    let data = &remaining_payload[STP_FEC_FRAGMENT_HEADER_SIZE..STP_FEC_FRAGMENT_HEADER_SIZE + data_len];
                                    remaining_payload = &remaining_payload[STP_FEC_FRAGMENT_HEADER_SIZE + data_len..];
                                    let kind = (word1 >> 48) & 0xff;
                                    if kind != STP_EXT_KIND_FEC && kind != STP_EXT_KIND_GROUPED_FEC { continue; } // unknown kind: skip it
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
                                    if (kind == STP_EXT_KIND_GROUPED_FEC) != (layout.groups > 1) { continue; }
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
                                        slot.package_id = package_id;
                                        let plain = &mut existing_connection.unreliable_reassembly[slot_idx];
                                        if (plain.total_len.is_some() || !plain.received.is_empty()) && plain.package_id != package_id && (package_id.wrapping_sub(plain.package_id) as i16) > 0 {
                                            state.stats.rx_partial_evicted += 1;
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
                                    if let Some(message) = fec_receive_block(&mut existing_connection.unreliable_fec[slot_idx], connection_key, package_id, message_len, block_bytes, block_id, data, &fec_done_tx, &fec_workers) {
                                        state.stats.rx_messages_completed += 1;
                                        receive_queue.push(connection_key, message, MAX_RECV_QUEUE_BYTES);
                                    }
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
                                
                                if (remaining_payload.len() as u64) < 8+frag_len {
                                    if OVERLY_VERBOSE { println!("Error, frag_len ({frag_len:?}) extends beyond end of packet received from {connection_key:?}. Disconnecting..."); }
                                    connections_map.remove(&connection_key);
                                    break 'conn;
                                }
                                let frag_data = &remaining_payload[8..(8+frag_len as usize)];
                                remaining_payload = &remaining_payload[(8+frag_len as usize)..];

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
                                    let slot_in_use = slot.total_len.is_some() || !slot.received.is_empty();
                                    if slot_in_use && slot.package_id != package_id {
                                        if (package_id.wrapping_sub(slot.package_id) as i16) < 0 { state.stats.rx_stale_fragments += 1; continue; }
                                        state.stats.rx_partial_evicted += 1;
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

                                let (mut success, mut complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                if !success {
                                    state.stats.rx_insert_failures += 1;
                                    existing_connection.unreliable_reassembly[slot_idx] = ReassemblySlot::new();
                                    existing_connection.unreliable_reassembly[slot_idx].package_id = package_id;
                                    (success, complete) = existing_connection.unreliable_reassembly[slot_idx].insert(frag_offset as usize, frag_data, is_fin);
                                    assert!(success);
                                }
                                if complete {
                                    state.stats.rx_messages_completed += 1;
                                    let completed = std::mem::replace(&mut existing_connection.unreliable_reassembly[slot_idx], ReassemblySlot::new());
                                    receive_queue.push(connection_key, completed.buf, MAX_RECV_QUEUE_BYTES);
                                }
                            }

//////// END ORDINARY PACKET HANDLING  ////////////////////////////////////////////////////////////////////
                        }
                    } } // <- break 'conn lands here
                }
//////// END RECEIVE ////////////////////////////////////////////////////////////////////////

                // Messages finished by FEC decoder threads.
                while let Ok((key, package_id, message)) = fec_done_rx.try_recv() {
                    if let Some(conn) = connections_map.get_mut(&key) {
                        let idx = package_id as usize % conn.unreliable_fec.len();
                        let slot = &mut conn.unreliable_fec[idx];
                        if slot.package_id != package_id || !slot.in_use() { continue; } // evicted worker completion
                        let tail = monotonic_clock_ns().saturating_sub(slot.last_block_ns);
                        slot.state = FecRecvState::Done;
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            c.stats.rx_messages_completed += 1;
                            c.stats.fec_decode_last_tail_ns = tail;
                            c.stats.fec_decode_max_tail_ns = c.stats.fec_decode_max_tail_ns.max(tail);
                        }
                        receive_queue.push(key, message, MAX_RECV_QUEUE_BYTES);
                    }
                }

//////// BEGIN SEND ////////////////////////////////////////////////////////////////////////
                let current_time_now_ns = monotonic_clock_ns();
                // Missing unreliable tails must not hold decoder admission forever.
                // Scan at most ten times/second, not once per incoming packet.
                if current_time_now_ns.saturating_sub(fec_sweep_ns) >= 100_000_000 {
                    for conn in connections_map.values_mut() {
                        if let ConnectionState::Connected(c) = &mut conn.connection_state {
                            let grace = fec_inactive_grace_ns(c.RTT_mean, false);
                            c.stats.fec_decode_timeouts += retire_inactive_fec_workers(&mut conn.unreliable_fec, current_time_now_ns, grace, false);
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
                        state.pacing_diagnostics = pacing_diagnostics;
                        debug_assert!(state.magic2 != 0, "Connection entered Connected state without negotiating magic2");
                        if state.last_ack_received_time + 15_000_000_000 < current_time_now_ns {
                            if VERBOSE { println!("Disconnected from: {:?}.", connection_tracking_data.other_transport_identity); }
                            return false; // connection timeout
                        }
                        
                        if matches!(ack_options, crate::ack::AckOptions::Nack) {
                            state.nack_receiver.tick(current_time_now_ns, ack_options, &mut state.ack_timer);
                            state.stats.nack_losses_declared = state.nack_receiver.losses;
                            state.stats.false_nacks = state.nack_receiver.false_nacks;
                            state.stats.nack_ranges_expired = state.nack_receiver.expired;
                            state.stats.nack_reorder_us = state.nack_receiver.effective_reorder_us;
                        }
                        if current_time_now_ns > state.ack_timer {
                            { // send ack
                                let mut o = 0;
                                let virtual_nonce = state.send_ack_sequence_number;
                                o += connection_tracking_data.two_byte_send_prefix.write_to(&mut packet_memory_send[o..]);
                                o += crate::sequence::to_wire(virtual_nonce).write_to(&mut packet_memory_send[o..]);
                                state.send_ack_sequence_number = state.send_ack_sequence_number.checked_add(1).expect("ACK nonce space exhausted");
                                
                                let encoded;
                                let nack_encoded;
                                let ack_payload = match ack_options {
                                    crate::ack::AckOptions::Nack => {
                                        let a = state.nack_receiver.ack(current_time_now_ns, ack_options);
                                        state.stats.ack_delay_us_max = state.stats.ack_delay_us_max.max(a.delay_us);
                                        nack_encoded = a.encode();
                                        state.stats.nack_packets_sent += 1;
                                        &nack_encoded[..]
                                    }
                                    crate::ack::AckOptions::Legacy => state.ack_field.as_bytes(),
                                    crate::ack::AckOptions::LowLatency { .. } | crate::ack::AckOptions::Adaptive { .. } => {
                                        let a = state.ack_receiver.ack(current_time_now_ns);
                                        state.stats.ack_delay_us_max = state.stats.ack_delay_us_max.max(a.delay_us);
                                        encoded = a.encode();
                                        &encoded[..]
                                    }
                                };
                                if let Some(cipher) = &mut state.cipher { o += cipher.current.write_message(virtual_nonce, ack_payload, &mut packet_memory_send[o..]).unwrap(); }
                                else { o += ack_payload.write_to(&mut packet_memory_send[o..]); }
                                let ack_ecn = matches!(ack_options, crate::ack::AckOptions::Legacy) && take_ecn_echo(state);
                                state.ack_receiver.sent(current_time_now_ns);
                                state.nack_receiver.sent(current_time_now_ns);
                                state.stats.ack_packets_sent += 1;
                                state.stats.ack_bytes_sent += o as u64;
                                udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_send[..o], Dscp::Af21, ack_ecn);
                                state.ack_timer = u64::MAX;
                            }
                        }
                        
                        if let Some(cadence) = curve_cadence_ns {
                            if current_time_now_ns < state.curve_next_tick_ns { return true; }
                            state.curve_next_tick_ns = current_time_now_ns + cadence;
                            if state.curve_pacer.is_none() {
                                state.curve_pacer = Some(crate::scheduling::CurvePacer::new(current_time_now_ns, state.send_sequence_number));
                            }
                        }

                        if state.RTT_sample_cursor != 0 && state.last_ack_received_time + 15_000_000_000/2 < current_time_now_ns {
                            // blackhole detected, go to safe TU
                            state.current_tu = ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY as u64;
                            state.RTT_sample_cursor = 0;
                            state.RTT_mean = u16::MAX;
                            state.ack_pace_estimate = 0;
                            state.congestion_event_time_ns = 0;
                            state.congestion_event_rate_upps = cc.rate_floor_upps;
                            state.last_sent_data_packet = 0;
                            state.last_sent_could_have_sent_data_packet = 0;
                            if state.tu_probe_sequence_number != u64::MAX {
                                // Orphaning an in-flight TU probe. It was never counted in packets_in_flight,
                                // but a late ack or the tail-advance loop will try to decrement it.
                                // Count it now so the decrement balances.
                                state.packets_in_flight += 1;
                                state.max_in_flight_since_last_print = state.max_in_flight_since_last_print.max(state.packets_in_flight);
                            }
                            state.tu_probe_sequence_number = u64::MAX;
                            state.tu_probe_failed_count = 0;
                            if OVERLY_VERBOSE { println!("Blackhole detected!"); }
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
                        if take_ecn_signal(state, if cc.ecn_event_guard_rtts > 0.0 { cc.ecn_event_guard_rtts } else { cc.event_guard_rtts }) {
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
                            state.stats.congestion_ecn_events += 1;
                            if let Some(t) = &mut loss_trace { t.outcome('E', connection_tracking_data.two_byte_send_prefix, u64::MAX, current_time_now_ns); }
                            println!("congestion event ECN CE ...  rate discovered: {} pps  sent:{send_mode}@{send_t_factor:.2}", state.congestion_event_rate_upps as f64 / 1000000.0);
                        }

                        // NOTE(Sam): We may experience black holes if RTT suddenly increases since
                        // there is a cyclic dependency beteen RTT and measuring RTT because of drop.
                        
                        let time_to_considered_dropped = ((state.RTT_mean as f64 * 100_000.0 * cc.loss_timeout_rtts) as u64).max((2*(current_time_now_ns - state.last_ack_received_time)).min(1_000_000_000)) + curve_cadence_ns.unwrap_or(0);
                        
                        // every send site (data loop, tu probe, keepalive, both ack paths) gates on ring space, so head never laps tail
                        assert!(state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY);
                        while state.packets_waiting_ack_tail < state.send_sequence_number {
                            let bit_index = state.packets_waiting_ack_tail % PACKETS_WAITING_ACK_CAPACITY;
                            // A NACK may already have finalized this packet as lost.
                            if state.packets_waiting_ack_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0 {
                                let mut send_time = state.send_time(state.packets_waiting_ack_tail);
                                if send_time != 0 && (state.RTT_mean == 0 || (current_time_now_ns - send_time) < time_to_considered_dropped) {
                                    break;
                                }
                                if send_time == 0 {
                                    let history_ns = if state.curve_pacer.is_some() { crate::scheduling::HISTORY_TIME_NS } else { 4_295_000_000 };
                                    send_time = current_time_now_ns.saturating_sub(history_ns);
                                }
                                
                                let seq = state.packets_waiting_ack_tail;
                                let cuts_before = state.stats.congestion_loss_events;
                                if declare_packet_lost(state, seq, current_time_now_ns, &cc, max_pps) {
                                    state.stats.losses_by_timeout += 1;
                                    if let Some(t) = &mut loss_trace {
                                        t.outcome('L', connection_tracking_data.two_byte_send_prefix, seq, current_time_now_ns);
                                        if state.stats.congestion_loss_events > cuts_before { t.outcome('C', connection_tracking_data.two_byte_send_prefix, seq, current_time_now_ns); }
                                    }
                                    connection_tracking_data.unreliable_send_buffer.fec_on_packet_lost(seq);
                                }
                            }
                            if cc.loss_response_fraction_ppm > 0 {
                                let sent_ns = state.send_time(state.packets_waiting_ack_tail);
                                let rtt_ns = state.RTT_mean as u64 * 100_000;
                                let eligible = sent_ns != u64::MAX && sent_ns > state.congestion_event_time_ns.saturating_add((rtt_ns as f64 * cc.event_guard_rtts) as u64);
                                if eligible {
                                    let lost = state.declared_lost_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0;
                                    if let Some(loss_ns) = state.loss_response.on_packet(sent_ns, lost, rtt_ns, cc.loss_response_fraction_ppm, cc.loss_threshold) {
                                        apply_loss_congestion(state, loss_ns, current_time_now_ns, &cc, max_pps);
                                    }
                                }
                            }
                            if cc.record_loss_episodes {
                                let sent_ns = state.send_time(state.packets_waiting_ack_tail);
                                let lost = state.declared_lost_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0;
                                if sent_ns != 0 && sent_ns != u64::MAX {
                                    state.loss_episodes.on_packet(sent_ns, lost, state.RTT_mean as u64 * 100_000, &mut state.stats);
                                }
                            }
                            state.packets_waiting_ack_field[(bit_index / 64) as usize] &= !(1u64 << (bit_index % 64));
                            if let Some(a) = &mut connection_tracking_data.unreliable_send_buffer.fec_adaptive {
                                let lost = state.declared_lost_field[(bit_index / 64) as usize] & (1u64 << (bit_index % 64)) != 0;
                                a.on_sequence_finalized(state.packets_waiting_ack_tail, lost, current_time_now_ns);
                            }
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
                        // pps * 10^-6 * rtt * 10^-4 = p * 10^10
                        // BDP + sawtooth: pipe is full (BDP) plus ack batching excess (ack_pace_estimate is in 0.1ms units)
                        let bdp = allowed_bandwidth_upps * state.RTT_mean as u64 / 10_000;
                        let sawtooth = allowed_bandwidth_upps * state.ack_pace_estimate as u64 / 10_000;
                        let allowed_packets_in_flight = ((bdp + sawtooth) / 1_000_000).max(1);

                        // 1 / (upps * 10^-6) = 10^6 / upps <- seconds
                        // ns = (10^6 / upps) * 10^9 = 10^15 / upps
                        let time_between_sends_ns = 1_000_000_000_000_000 / allowed_bandwidth_upps.max(1);
                        // This is some Unity Game developer level crap approximation but it will have to do.
                        let mut packet_send_allowance_now = (current_time_now_ns + 1 - state.last_sent_could_have_sent_data_packet.max(state.last_ack_received_time.saturating_sub(ACK_BUFFER_TIME_NS))) / time_between_sends_ns;
                        let send_allowance_time_remainder = (current_time_now_ns + 1 - state.last_sent_could_have_sent_data_packet.max(state.last_ack_received_time.saturating_sub(ACK_BUFFER_TIME_NS)))
                                                                - time_between_sends_ns*packet_send_allowance_now;
                        
                        if state.send_pacer_acc_ns > time_between_sends_ns {
                            state.send_pacer_acc_ns -= time_between_sends_ns;
                            packet_send_allowance_now += 1;
                        }
                        let has_work = connection_tracking_data.unreliable_send_buffer.has_unsent_data()
                            || state.control_work_due(current_time_now_ns, time_between_sends_ns);
                        let curve_tick_ns = if curve_cadence_ns.is_some() { monotonic_clock_ns() } else { current_time_now_ns };
                        let mut curve_cpu_late = false;
                        if let Some(p) = &mut state.curve_pacer {
                            let cadence = curve_cadence_ns.unwrap();
                            // Permit one normal tick plus wake/work jitter, never
                            // an unbounded CPU catch-up burst of stale credit.
                            p.stop_if_late(curve_tick_ns, state.send_sequence_number, cadence * 2);
                            state.curve_next_tick_ns = curve_tick_ns + cadence;
                            let key = (state.congestion_event_time_ns, state.congestion_event_rate_upps, time_to_bandwidth_recovery, state.is_app_limited);
                            packet_send_allowance_now = p.begin(curve_tick_ns, state.send_sequence_number, has_work, key, |origin| {
                                if state.is_app_limited {
                                    crate::scheduling::PacketSchedule::constant(allowed_bandwidth_upps as f64 / 1e6, crate::scheduling::CONTROLLER_HORIZON_NS).unwrap()
                                } else {
                                    crate::scheduling::controller_schedule(origin.saturating_sub(state.congestion_event_time_ns), state.congestion_event_rate_upps,
                                        time_to_bandwidth_recovery, &cc, crate::scheduling::CONTROLLER_HORIZON_NS).expect("valid CC polynomial")
                                }
                            });
                        }
                        let pacing_first_sequence = state.send_sequence_number;
                        state.stats.pacing_commanded_packets += packet_send_allowance_now;
                        let could_have_sent = packet_send_allowance_now != 0;
                        
                        // ring space is checked live at each send site below so the head can never lap the tail within a tick

                        state.current_tu = state.current_tu.min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                        if state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && (curve_cadence_ns.is_none() || packet_send_allowance_now > 0) && state.current_tu != ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64 && state.tu_probe_sequence_number == u64::MAX && state.last_sent_tu_probe_time_ns + (state.tu_probe_failed_count.min(50)*state.tu_probe_failed_count.min(50)*250_000_000).max(time_between_sends_ns) < current_time_now_ns {
                            state.tu_probe_size_advance = state.tu_probe_size_advance.max(1).min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                            state.tu_probe_size = (state.current_tu + state.tu_probe_size_advance).min(ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE as u64);
                            let payload_size = state.tu_probe_size as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                            let null_bytes = [0u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];
                            
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

                            let send_time_ns = udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..6+packet_len], Dscp::Af21, false);
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            state.account_send(send_time_ns);
                            state.last_sent_tu_probe_time_ns = send_time_ns;
                            if curve_cadence_ns.is_some() { packet_send_allowance_now = packet_send_allowance_now.saturating_sub(1); }
                            state.packet_since_last_print += 1;
                        }
                        
                        let payload_size = state.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(state.magic1).unwrap();
                        
                        if state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && (curve_cadence_ns.is_none() || packet_send_allowance_now > 0) && state.last_sent_data_packet + 15_000_000_000/3 < current_time_now_ns {
                            let null_bytes = [0u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];
                        
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

                        connection_tracking_data.unreliable_send_buffer.current_bytes_per_second = payload_size as u64 * allowed_bandwidth_upps / 1000_000;
                        {
                            let buf = &mut connection_tracking_data.unreliable_send_buffer;
                            match &fec_adaptive_now {
                                Some(cfg) => {
                                    let a = buf.fec_adaptive.get_or_insert_with(|| crate::fec_adapt::FecAdaptiveState::new(*cfg, current_time_now_ns, state.stats.packets_sent, state.stats.packets_lost));
                                    a.on_tick(current_time_now_ns, state.stats.packets_sent, state.stats.packets_lost, state.stats.spurious_losses);
                                    buf.fec_redundancy_ppm = a.representative_ppm();
                                }
                                None => {
                                    buf.fec_adaptive = None;
                                    buf.fec_redundancy_ppm = fec_redundancy_ppm;
                                }
                            }
                            if record_fec_messages && buf.fec_record.is_none() { buf.fec_record = Some(Vec::new()); }
                        }
                        let mut unreliable_payload_size = 0;
                        while state.send_sequence_number - state.packets_waiting_ack_tail < PACKETS_WAITING_ACK_CAPACITY - 1 && packet_send_allowance_now > 0 && state.packets_in_flight < allowed_packets_in_flight && {
                            // Bound work within a burst as well as debt between
                            // ticks. Test BEFORE removing a fragment from its queue.
                            curve_cpu_late = curve_burst_budget_ns.is_some_and(|budget| monotonic_clock_ns() >= curve_tick_ns.saturating_add(budget));
                            !curve_cpu_late
                        } && {
                            connection_tracking_data.unreliable_send_buffer.fec_prepare_packet(state.send_sequence_number);
                            unreliable_payload_size = fill_packet_payload_with_unreliable_fragments(&mut packet_memory_send[0..payload_size], &mut connection_tracking_data.unreliable_send_buffer);
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
                            let send_time_ns = if test_drop { monotonic_clock_ns() }
                            else { udp_send_with_congestion_and_dscp(socket, connection_tracking_data.other_ip, connection_tracking_data.other_port, &packet_memory_encrypted[0..6+packet_len], Dscp::BestEffort, false) };
                            state.account_send(send_time_ns);
                            if let Some(t) = &mut loss_trace {
                                t.sent(connection_tracking_data.two_byte_send_prefix, virtual_nonce, send_time_ns, &packet_memory_send[..unreliable_payload_size]);
                                if test_drop { t.outcome('D', connection_tracking_data.two_byte_send_prefix, virtual_nonce, send_time_ns); }
                            }
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
                        // Pending keepalive/probe work must be allowed to earn its
                        // first slot, even when the application queue is empty.
                        let has_work = has_data || state.control_work_due(current_time_now_ns, time_between_sends_ns);
                        if let Some(p) = &mut state.curve_pacer {
                            let reason = if !has_work { Some(crate::scheduling::StopReason::QueueEmpty) }
                                else if curve_cpu_late { Some(crate::scheduling::StopReason::CpuLate) }
                                else if packet_send_allowance_now > 0 { Some(crate::scheduling::StopReason::InFlight) }
                                else { None };
                            let finish_ns = monotonic_clock_ns();
                            p.finish(if reason.is_some() { finish_ns } else { curve_tick_ns }, state.send_sequence_number, reason);
                            // An OS deschedule can happen within the final send;
                            // do not carry that execution debt into another tick.
                            p.stop_if_late(finish_ns, state.send_sequence_number, curve_cadence_ns.unwrap() * 2);
                            state.stats.pacing_error_samples = p.error_samples;
                            state.stats.pacing_error_abs_sum_ns = p.error_abs_sum_ns;
                            state.stats.pacing_error_max_ns = p.error_max_ns;
                            state.stats.pacing_history_records = p.history.len() as u64;
                        }
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
                                state.send_pacer_acc_ns += send_allowance_time_remainder;
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
                    let sleep_ns = if let Some(cadence) = curve_cadence_ns {
                        let now = monotonic_clock_ns();
                        connections_map.values().filter_map(|c| match &c.connection_state {
                            ConnectionState::Connected(s) => Some(s.curve_next_tick_ns.min(s.ack_timer).saturating_sub(now)),
                            _ => None,
                        }).min().unwrap_or(cadence).min(cadence)
                    } else { 150_000 };
                    if sleep_ns != 0 {
                        if curve_cadence_ns.is_some() {
                            // An application push wakes the shared network thread,
                            // not the data pacer: send ticks stay cadence-gated.
                            std::thread::park_timeout(std::time::Duration::from_nanos(sleep_ns));
                        } else {
                            std::thread::sleep(std::time::Duration::from_nanos(sleep_ns));
                        }
                    }
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

const CUBIC_BETA: f64 = 0.67;
const CUBIC_K_RTT_MULTIPLIER: u64 = 9;
const CUBIC_MAX_RATE_UPPS_PER_SEC: f64 = 83_668_000_000.0; // 1000 Mbps/s linear cap
const CUBIC_MIN_GROWTH_UPPSPS: f64 = 1_000_000.0; // 1 pps per second minimum linear growth

// -- Edit with Claude ------------------------------------------------------
// Piecewise rate curve after recovery. All times are multiples of k (the
// recovery time = CUBIC_K_RTT_MULTIPLIER * RTT).  Rate targets are
// multiples of r (the pre-drop rate, "congestion upps").
//
//  Transition times (as factors on k, cumulative from congestion event):
//    R-P  1.0  (implicit: recovery ends at t = k)
//    P-G  5.0
//    G-S  15.0
//
//  Rate targets at each transition (as factors on r):
//    R-P  0.98   (recovery stops 2% below r)
//    P-G  1.05   (5% above r)
//    G-S  4.0    (300% above r)
//
//  Curve shapes:
//    R: p^2 recovery from r*BETA up to r*RATE_RP
//    P: linear from r to r*P-G_factor, entry derivative carried into G
//    G: quadratic from P-G point, entry derivative matches P exit
//    S: p^10 explosive ramp (startup / bandwidth discovery)
//    L: linear cap at CUBIC_MAX_RATE_UPPS_PER_SEC
//
//  Modes: R P G S L
//
// Note(Claude): When changing constants below, always update this
// description block to match. The description is the source of truth
// for the curve design.
// -------------------------------------------------------------------------─
const RATE_RP: f64 = 0.98;  // rate factor at R-P transition
const RATE_PG: f64 = 1.05;  // rate factor at P-G transition
const RATE_GS: f64 = 4.0;   // rate factor at G-S transition
const TIME_PG: f64 = 5.0;   // time factor (in k) for P-G transition
const TIME_GS: f64 = 15.0;  // time factor (in k) for G-S transition

/// Evaluate the legacy CUBIC sending-rate function (use `cubic_rate_with_options` for a configured curve).
/// t_ns:  nanoseconds since the last congestion event.
/// r_max: sending rate (upps) at the time the dropped packet was sent.
/// k_ns:  time in nanoseconds to recover back to r_max.
/// Returns (target sending rate in upps, mode char: R/P/G/S/L).
pub fn cubic_rate(t_ns: u64, r_max: u64, k_ns: u64) -> (u64, char) {
    cubic_rate_with_options(t_ns, r_max, k_ns, &CongestionControlOptions::legacy())
}

/// The original rate function, with its constants supplied at runtime.
pub fn cubic_rate_with_options(t_ns: u64, r_max: u64, k_ns: u64, cc: &CongestionControlOptions) -> (u64, char) {
    if k_ns == 0 { return (r_max, 'R'); }
    let t = t_ns as f64;
    let r = r_max as f64;
    let k = k_ns as f64;
    let drop = r * (1.0 - cc.beta);
    let rtt_seconds = k / (cc.recovery_rtts as f64 * 1e9);
    let floor = if cc.friendly_growth_alpha > 0.0 {
        cc.min_growth_uppsps.max(cc.friendly_growth_alpha * 1e6 / (rtt_seconds * rtt_seconds)).min(cc.max_growth_uppsps)
    } else { cc.min_growth_uppsps };
    let ceiling = if cc.relative_growth_per_rtt > 0.0 && !cc.compound_growth {
        cc.max_growth_uppsps.min(r * cc.relative_growth_per_rtt / rtt_seconds)
    } else { cc.max_growth_uppsps };
    let min_growth = floor / 1e9 * t;
    let linear_cap_slope = if cc.proportional_growth { f64::INFINITY } else { ceiling / 1e9 };
    let finish = |rate: u64, mode| {
        if cc.bound_recovery_growth {
            let absolute = r * cc.beta + (floor + ceiling) / 1e9 * t;
            let envelope = if cc.compound_growth && cc.relative_growth_per_rtt > 0.0 {
                let relative = r * cc.beta * (cc.relative_growth_per_rtt * t / (rtt_seconds * 1e9)).exp() + min_growth;
                if cc.proportional_growth { relative.min(1e12) } else { relative.min(absolute) }
            } else { absolute };
            (rate.min(envelope as u64), mode)
        } else { (rate, mode) }
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
use crate::native_sockets::*;

fn take_ecn_echo(state: &mut ConnectionStateConnected) -> bool {
    std::mem::take(&mut state.ecn_echo_pending)
}

fn take_ecn_signal(state: &mut ConnectionStateConnected, guard_rtts: f64) -> bool {
    // Consume covered feedback too: it must not survive to a later ACK/epoch.
    let pending = std::mem::take(&mut state.ecn_congestion_received);
    let eligible = pending && state.ecn_oldest_send_time > state.congestion_event_time_ns.saturating_add((state.RTT_mean as f64 * 100_000.0 * guard_rtts) as u64);
    if eligible { state.loss_count_in_window = 0; state.loss_response = LossResponseWindow::default(); }
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

fn connection_rate(t_ns: u64, anchor_upps: u64, k_ns: u64, cc: &CongestionControlOptions, startup_done: bool) -> (u64, char) {
    if cc.startup_multiplier > 0.0 && !startup_done {
        let rtt_ns = k_ns / cc.recovery_rtts;
        // The sentinel RTT means no sample yet: never ramp on an unknown path.
        let exponent = if rtt_ns == u16::MAX as u64 * 100_000 { 0.0 } else { cc.startup_multiplier.ln() * t_ns as f64 / rtt_ns.max(100_000) as f64 };
        ((anchor_upps as f64 * exponent.min(30.0).exp()).min(1e12) as u64, 'I')
    } else { cubic_rate_with_options(t_ns, anchor_upps, k_ns, cc) }
}

fn quantized_rtt_mean(sum: u64, count: u64) -> u16 {
    (sum / count.max(1)).clamp(1, u16::MAX as u64) as u16
}

fn local_rate_limit(rate: u64, max_pps: Option<u64>) -> u64 {
    max_pps.map_or(rate, |limit| rate.min(limit.saturating_mul(1_000_000).max(1)))
}

fn congestion_loss_threshold(rate_upps: u64, rtt_ns: u64, cc: &CongestionControlOptions) -> u64 {
    // Detection uses only the commanded rate and packet loss, never ACK/delivery rate.
    let fraction = (rate_upps as u128 * rtt_ns as u128 * cc.loss_fraction_ppm as u128).div_ceil(1_000_000_000_000_000_000_000);
    cc.loss_threshold.max(fraction.min(u64::MAX as u128) as u64)
}

/// Idempotent per-sequence accounting shared by receiver NACK and sender timeout.
/// Returns true only for newly declared data loss (TU probes are not data loss).
fn declare_packet_lost(state: &mut ConnectionStateConnected, seq: u64, now: u64, cc: &CongestionControlOptions, max_pps: Option<u64>) -> bool {
    if seq < state.packets_waiting_ack_tail || seq >= state.send_sequence_number { return false; }
    let i = seq % PACKETS_WAITING_ACK_CAPACITY;
    let mask = 1u64 << (i%64);
    if state.packets_waiting_ack_field[(i/64) as usize] & mask == 0 { return false; }
    state.packets_waiting_ack_field[(i/64) as usize] &= !mask;
    if seq == state.tu_probe_sequence_number {
        state.tu_probe_sequence_number = u64::MAX;
        state.tu_probe_size_advance /= 5;
        state.tu_probe_failed_count += 1;
        state.stats.tu_probes_lost += 1;
        return false;
    }
    let mut sent = state.send_time(seq);
    if sent == 0 || sent == u64::MAX {
        let history_ns = if state.curve_pacer.is_some() { crate::scheduling::HISTORY_TIME_NS } else { 4_295_000_000 };
        sent = now.saturating_sub(history_ns);
    }
    let rtt_ns = state.RTT_mean as u64 * 100_000;
    if now.saturating_sub(state.loss_window_start_ns) > rtt_ns {
        state.loss_window_start_ns = now; state.loss_count_in_window = 0;
    }
    let eligible = sent > state.congestion_event_time_ns.saturating_add((rtt_ns as f64 * cc.event_guard_rtts) as u64);
    let threshold = if cc.loss_fraction_ppm == 0 { cc.loss_threshold } else {
        let dt = sent.saturating_sub(state.congestion_event_time_ns);
        let rate = local_rate_limit(connection_rate(dt, state.congestion_event_rate_upps, cc.recovery_rtts*rtt_ns, cc, state.cc_startup_done).0.max(cc.rate_floor_upps), max_pps);
        congestion_loss_threshold(rate, rtt_ns, cc)
    };
    if cc.loss_response_fraction_ppm == 0 && count_congestion_loss(&mut state.loss_count_in_window, eligible, threshold) {
        apply_loss_congestion(state, sent, now, cc, max_pps);
    }
    assert!(state.packets_in_flight > 0, "packets_in_flight underflow");
    state.packets_in_flight -= 1;
    state.packet_lost_since_last_print += 1;
    state.stats.packets_lost += 1;
    state.declared_lost_field[(i/64) as usize] |= mask;
    true
}

fn apply_loss_congestion(state: &mut ConnectionStateConnected, send_time: u64, current_time_now_ns: u64, cc: &CongestionControlOptions, max_pps: Option<u64>) {
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
    state.stats.congestion_loss_events += 1;
    println!("congestion event PACKET DROPPED {} ...  rate discovered: {} pps  now:{now_mode}@{now_t_factor:.2} sent:{send_mode}@{send_t_factor:.2}", state.packets_waiting_ack_tail, state.congestion_event_rate_upps as f64 / 1000000.0);
    state.loss_response = LossResponseWindow::default();
}

fn count_congestion_loss(count: &mut u64, eligible: bool, threshold: u64) -> bool {
    if !eligible { return false; }
    *count = count.saturating_add(1);
    *count >= threshold
}

/// Constant-memory send-time cohort, evaluated only when a full RTT has retired.
/// Counting ACKed and lost packets is a loss fraction, never an ACK-rate estimate.
#[derive(Debug, Default)]
struct LossResponseWindow { start_ns: u64, width_ns: u64, packets: u64, lost: u64, last_loss_ns: u64 }
impl LossResponseWindow {
    fn on_packet(&mut self, sent_ns: u64, lost: bool, rtt_ns: u64, fraction_ppm: u32, min_losses: u64) -> Option<u64> {
        let mut signal = None;
        if self.packets > 0 && sent_ns.saturating_sub(self.start_ns) >= self.width_ns {
            if self.lost >= min_losses && self.lost as u128 * 1_000_000 >= self.packets as u128 * fraction_ppm as u128 {
                signal = Some(self.last_loss_ns);
            }
            *self = Self::default();
        }
        if self.packets == 0 { self.start_ns = sent_ns; self.width_ns = rtt_ns.max(100_000); }
        self.packets += 1;
        self.lost += u64::from(lost);
        if lost { self.last_loss_ns = sent_ns; }
        signal
    }
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

    #[test]
    fn loss_free_app_empty_resume_preserves_every_active_curve() {
        let compound = CongestionControlOptions {
            max_growth_uppsps: 500e6, relative_growth_per_rtt: 0.02,
            bound_recovery_growth: true, compound_growth: true,
            ..CongestionControlOptions::balanced()
        };
        for cc in [CongestionControlOptions::legacy(), CongestionControlOptions::balanced(),
            compound, CongestionControlOptions { proportional_growth: true, ..compound },
            CongestionControlOptions { compound_growth: false, ..compound },
            CongestionControlOptions { startup_multiplier: 1.5, ..compound }] {
            for rtt_ns in [40_000_000, 200_000_000] {
                let k = cc.recovery_rtts * rtt_ns;
                for age in [k / 2, k + k / 2, 3 * k, 9 * k, 30 * k] {
                    let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
                    state.congestion_event_rate_upps = 8_000_000_000;
                    state.congestion_event_time_ns = 1_000_000_000;
                    let mut now = state.congestion_event_time_ns + age;
                    let mut previous_rate = connection_rate(age, state.congestion_event_rate_upps, k, &cc, false).0;
                    for cycle in 0..100 {
                        let active_age = now - state.congestion_event_time_ns;
                        let before = connection_rate(active_age, state.congestion_event_rate_upps, k, &cc, false).0;
                        assert!(before >= previous_rate);
                        let anchor = state.congestion_event_rate_upps;
                        update_app_limit(&mut state, now, false);
                        now += 5_000_000_000;
                        update_app_limit(&mut state, now, false);
                        assert_eq!(state.congestion_event_rate_upps, anchor);
                        let idle = connection_rate(state.app_limit_time_offset, anchor, k, &cc, false).0;
                        assert_eq!(idle, before, "idle cycle {cycle}: {cc:?}");
                        update_app_limit(&mut state, now, true);
                        let resumed = connection_rate(now - state.congestion_event_time_ns, anchor, k, &cc, false).0;
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
    fn polynomial_pacing_falls_back_only_for_unmirrored_curves() {
        let legacy = CongestionControlOptions::legacy();
        let startup = CongestionControlOptions { startup_multiplier: 1.25, ..legacy };
        let proportional = CongestionControlOptions { proportional_growth: true,
            bound_recovery_growth: true, compound_growth: true, relative_growth_per_rtt: 0.02, ..legacy };
        let loss_response = CongestionControlOptions { loss_response_fraction_ppm: 30_000,
            ecn_event_guard_rtts: 1.0, startup_backoff_rtts: 2.0, ..legacy };
        for cadence_ms in [1, 2, 5, 10] {
            let pacing = PacingOptions::Polynomial { cadence_ms };
            for cc in [legacy, CongestionControlOptions::default(), CongestionControlOptions::balanced(), loss_response] {
                assert!(cc.validate().is_ok());
                assert_eq!(pacing.cadence_ns(&cc), Some(cadence_ms * 1_000_000));
            }
            for cc in [startup, proportional] {
                assert!(cc.validate().is_ok());
                assert_eq!(pacing.cadence_ns(&cc), None);
            }
        }
        assert_eq!(PacingOptions::Precise.cadence_ns(&legacy), None);
        assert_eq!(PacingOptions::Precise.cadence_ns(&startup), None);
        assert_eq!(PacingOptions::Precise.cadence_ns(&proportional), None);
    }

    #[test]
    fn loss_cohort_uses_polynomial_execution_history() {
        use crate::scheduling::{CurvePacer, PacketSchedule, CONTROLLER_HORIZON_NS};
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        let mut pacer = CurvePacer::new(1_000_000_000, 9);
        let schedule = |_| PacketSchedule::constant(100.0, CONTROLLER_HORIZON_NS).unwrap();
        assert_eq!(pacer.begin(1_000_000_000, 9, true, (1, 1, 1, false), schedule), 0);
        pacer.finish(1_000_000_000, 9, None);
        assert_eq!(pacer.begin(1_200_000_000, 9, true, (1, 1, 1, false), schedule), 20);
        pacer.finish(1_200_000_000, 29, None);
        state.curve_pacer = Some(pacer);
        // Polynomial execution does not populate the precise pacer's timestamp band.
        assert_eq!(get_send_time_for_sequence_number(9, &state.send_time_band, state.send_time_band_head_index), u64::MAX);
        let mut window = LossResponseWindow::default();
        for i in 0..10 {
            assert_eq!(window.on_packet(state.send_time(9 + i), i < 2, 100_000_000, 30_000, 2), None);
        }
        assert_eq!(window.on_packet(state.send_time(19), false, 100_000_000, 30_000, 2), Some(1_020_000_000));
    }

    #[test]
    fn actual_loss_fraction_uses_completed_send_cohort() {
        assert_eq!(std::mem::size_of::<LossResponseWindow>(), 40);
        let mut window = LossResponseWindow::default();
        // Two scattered losses out of 100: no cut at 3%, including before closure.
        for i in 0..100 { assert_eq!(window.on_packet(1 + i * 1_000_000, i == 10 || i == 80, 100_000_000, 30_000, 2), None); }
        assert_eq!(window.on_packet(100_000_001, false, 100_000_000, 30_000, 2), None);
        // A six-packet cluster out of 100 crosses the threshold at cohort closure.
        for i in 1..100 { assert_eq!(window.on_packet(100_000_001 + i * 1_000_000, (20..26).contains(&i), 100_000_000, 30_000, 2), None); }
        assert_eq!(window.on_packet(200_000_001, false, 100_000_000, 30_000, 2), Some(125_000_001));
        // One loss in a tiny cohort still respects min_losses.
        let mut tiny = LossResponseWindow::default();
        assert_eq!(tiny.on_packet(1, true, 100_000_000, 30_000, 2), None);
        assert_eq!(tiny.on_packet(100_000_001, false, 100_000_000, 30_000, 2), None);
        let cc = CongestionControlOptions::legacy();
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        state.RTT_mean = 1000;
        state.congestion_event_time_ns = 200_000_000;
        apply_loss_congestion(&mut state, 125_000_001, 300_000_000, &cc, None);
        assert_eq!(state.congestion_event_time_ns, 200_000_000);
        assert!(!state.cc_startup_done);
    }

    #[test]
    fn ecn_echo_cannot_steal_sender_feedback_or_repeat_guarded_signals() {
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        state.RTT_mean = 2000;
        state.congestion_event_time_ns = 1_000_000_000;
        state.ecn_oldest_send_time = 1_200_000_000;
        state.ecn_congestion_received = true;
        state.ecn_echo_pending = true;
        assert!(take_ecn_echo(&mut state));
        assert!(!take_ecn_echo(&mut state));
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
        assert!(!take_ecn_echo(&mut state));
        state.ecn_echo_pending = true;
        assert!(!take_ecn_signal(&mut state, 0.5));
        assert!(take_ecn_echo(&mut state));
    }

    #[test]
    fn optional_startup_is_rate_based_and_exits_to_curve() {
        let cc = CongestionControlOptions { startup_multiplier: 1.5, ..CongestionControlOptions::legacy() };
        let r = 100_000_000;
        let rtt = 200_000_000;
        let k = cc.recovery_rtts * rtt;
        assert_eq!(connection_rate(0, r, k, &cc, false), (r, 'I'));
        assert!((connection_rate(rtt, r, k, &cc, false).0 as f64 / r as f64 - 1.5).abs() < 1e-6);
        assert!((connection_rate(10*rtt, r, k, &cc, false).0 as f64 / r as f64 - 1.5f64.powi(10)).abs() < 1e-6);
        assert_eq!(connection_rate(100*rtt, r, cc.recovery_rtts * u16::MAX as u64 * 100_000, &cc, false), (r, 'I'));
        assert_eq!(connection_rate(0, r, k, &cc, true), cubic_rate(0, r, k));
        assert!(connection_rate(u64::MAX, r, k, &cc, false).0 <= 1_000_000_000_000);
        assert_eq!(connection_rate(0, r, k, &CongestionControlOptions::legacy(), false), cubic_rate(0, r, k));
        assert!(CongestionControlOptions { startup_multiplier: f64::NAN, ..cc }.validate().is_err());
        assert!(CongestionControlOptions { startup_multiplier: 1.0, ..cc }.validate().is_err());
        assert!(CongestionControlOptions { startup_backoff_rtts: f64::NAN, ..cc }.validate().is_err());
        let cc = CongestionControlOptions { startup_backoff_rtts: 2.0, ..cc };
        let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 1, 1) else { unreachable!() };
        state.RTT_mean = 2000;
        state.congestion_event_rate_upps = r;
        apply_loss_congestion(&mut state, 10*rtt, 12*rtt, &cc, None);
        assert_eq!(state.congestion_event_rate_upps, connection_rate(8*rtt, r, k, &cc, false).0);
        assert!(state.cc_startup_done);
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
    fn radio_threshold_counts_loss_episodes_not_isolated_noise() {
        let mut cc = CongestionControlOptions::legacy();
        assert_eq!(congestion_loss_threshold(1_000_000_000, 200_000_000, &cc), 2);
        cc.loss_fraction_ppm = 50_000;
        assert_eq!(congestion_loss_threshold(1_000_000_000, 200_000_000, &cc), 10);
        assert_eq!(congestion_loss_threshold(10_000_000_000, 200_000_000, &cc), 100);
        let mut count = 0;
        for _ in 0..4 { assert!(!count_congestion_loss(&mut count, true, 10)); }
        for _ in 4..9 { assert!(!count_congestion_loss(&mut count, true, 10)); }
        assert!(count_congestion_loss(&mut count, true, 10));
        cc.loss_timeout_rtts = 1.0;
        assert!(cc.validate().is_err());
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
    fn compounded_growth_remains_bounded_without_delivery_sampling() {
        let mut cc = CongestionControlOptions::balanced();
        cc.max_growth_uppsps = 500e6;
        cc.relative_growth_per_rtt = 0.01;
        cc.bound_recovery_growth = true;
        let (r, k) = (1_000_000_000, 1_800_000_000);
        let linear = cubic_rate_with_options(60_000_000_000, r, k, &cc).0;
        cc.compound_growth = true;
        assert!(cubic_rate_with_options(60_000_000_000, r, k, &cc).0 > linear);
        let mut prev = 0;
        for t in (0..100*k).step_by((k/1000) as usize) {
            let rate = cubic_rate_with_options(t, r, k, &cc).0;
            assert!(rate >= prev);
            assert!(rate <= (r as f64 * cc.beta + 525e6 * t as f64 / 1e9) as u64);
            prev = rate;
        }
    }

    #[test]
    fn proportional_growth_scales_rate_without_fixed_pps_ceiling() {
        let mut cc = CongestionControlOptions { max_growth_uppsps: 500e6,
            min_growth_uppsps: 0.0, relative_growth_per_rtt: 0.01,
            bound_recovery_growth: true, compound_growth: true, proportional_growth: true,
            ..CongestionControlOptions::balanced() };
        let k = 1_800_000_000;
        for t in [0, k, 2*k, 8*k, 20*k] {
            let low = cubic_rate_with_options(t, 1_000_000_000, k, &cc).0;
            let high = cubic_rate_with_options(t, 40_000_000_000, k, &cc).0;
            assert!((high as f64 / low as f64 - 40.0).abs() < 1e-6);
        }
        let r = 40_000_000_000;
        let t = 20*k;
        assert!(cubic_rate_with_options(t, r, k, &cc).0 > (r as f64 * cc.beta + 500e6 * t as f64 / 1e9) as u64);
        let mut previous = 0;
        for t in (0..100*k).step_by((k/100) as usize) {
            let rate = cubic_rate_with_options(t, r, k, &cc).0;
            assert!(rate >= previous);
            assert!(rate <= (r as f64 * cc.beta * (cc.relative_growth_per_rtt * t as f64 / 200e6).exp()).min(1e12) as u64);
            previous = rate;
        }
        cc.compound_growth = false;
        assert!(cc.validate().is_err());
        cc.proportional_growth = false;
        assert!(cc.validate().is_ok());
    }

    #[test]
    fn bounded_recovery_cannot_bypass_relative_growth_limit() {
        let mut cc = CongestionControlOptions::balanced();
        cc.max_growth_uppsps = 500e6;
        cc.relative_growth_per_rtt = 0.02;
        let (r, k) = (1_000_000_000, 1_800_000_000);
        assert_eq!(cubic_rate_with_options(k, r, k, &cc).0, 1_025_000_000);
        cc.bound_recovery_growth = true;
        assert_eq!(cubic_rate_with_options(k, r, k, &cc).0, 895_000_000);
        let mut prev = 0;
        for t in (0..100*k).step_by((k/1000) as usize) {
            let rate = cubic_rate_with_options(t, r, k, &cc).0;
            assert!(rate >= prev);
            assert!(rate <= (r as f64 * cc.beta + 125e6 * t as f64 / 1e9) as u64);
            prev = rate;
        }
    }

    #[test]
    fn rtt_growth_envelope_is_rate_based_and_option_gated() {
        let mut cc = CongestionControlOptions::balanced();
        cc.max_growth_uppsps = 500e6;
        let k = 1_800_000_000;
        let base = cubic_rate_with_options(20 * k, 1_000_000_000, k, &cc).0;
        cc.relative_growth_per_rtt = 0.02;
        let slow = cubic_rate_with_options(20 * k, 1_000_000_000, k, &cc).0;
        assert!(slow < base);
        cc.relative_growth_per_rtt = 0.0;
        assert_eq!(cubic_rate_with_options(20 * k, 1_000_000_000, k, &cc).0, base);
        cc.friendly_growth_alpha = 4.0;
        assert!(cubic_rate_with_options(k, 1_000_000_000, k, &cc).0 > cubic_rate_with_options(k, 1_000_000_000, k, &CongestionControlOptions::balanced()).0);
        for rtt in [100_000, 30_000_000, 200_000_000] {
            let k = cc.recovery_rtts * rtt;
            let mut prev = 0;
            for t in (0..50*k).step_by((k/100).max(1) as usize) {
                let rate = cubic_rate_with_options(t, 1_000_000_000, k, &cc).0;
                assert!(rate >= prev);
                prev = rate;
            }
        }
        cc.friendly_growth_alpha = f64::NAN;
        assert!(cc.validate().is_err());
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
        let k = CongestionControlOptions::legacy().recovery_rtts * quantized_rtt_mean(0, 16) as u64 * 100_000;
        assert!(k > 0);
        assert!(cubic_rate(20 * k, 100_000_000, k).0 > cubic_rate(0, 100_000_000, k).0);
    }

    #[test]
    fn legacy_transition_rates() {
        let (r, k) = (1_000_000_000, 900_000_000);
        assert_eq!(cubic_rate(0, r, k), (670_000_000, 'R'));
        assert_eq!(cubic_rate(k, r, k), (980_900_000, 'R'));
        assert_eq!(cubic_rate(5 * k, r, k), (1_054_500_000, 'P'));
        assert_eq!(cubic_rate(15 * k, r, k), (4_013_499_999, 'G'));
    }

    #[test]
    fn parameters_change_only_the_original_curve() {
        let mut cc = CongestionControlOptions::legacy();
        cc.beta = 0.8;
        cc.recovery_rtts = 4;
        cc.time_pg = 2.0;
        cc.time_gs = 6.0;
        cc.validate().unwrap();
        assert_eq!(cubic_rate_with_options(0, 1_000_000_000, 800_000_000, &cc), (800_000_000, 'R'));
        assert_eq!(cubic_rate_with_options(1_600_000_000, 1_000_000_000, 800_000_000, &cc), (1_051_600_000, 'P'));
        let mut previous = 0;
        for t in (0..100_000_000_000u64).step_by(10_000_000) {
            let rate = cubic_rate_with_options(t, 1_000_000_000, 800_000_000, &cc).0;
            assert!(rate >= previous);
            previous = rate;
        }
    }

    #[test]
    fn balanced_changes_only_four_parameters() {
        let cc = CongestionControlOptions::balanced();
        let old = CongestionControlOptions::legacy();
        cc.validate().unwrap();
        assert_eq!(cc.beta, old.beta);
        assert_eq!(cc.recovery_rtts, old.recovery_rtts);
        assert_eq!((cc.rate_rp, cc.rate_pg, cc.rate_gs), (old.rate_rp, old.rate_pg, old.rate_gs));
        assert_eq!((cc.loss_threshold, cc.event_guard_rtts), (old.loss_threshold, old.event_guard_rtts));
        assert_eq!(cc.rate_floor_upps, old.rate_floor_upps);
        assert_eq!(cc.max_growth_uppsps, old.max_growth_uppsps);
        assert_eq!((cc.time_pg, cc.time_gs, cc.min_growth_uppsps, cc.initial_rate_upps), (2.0, 8.0, 25_000_000.0, 1_000_000_000));
        assert_eq!(cubic_rate_with_options(0, 1_000_000_000, 1_800_000_000, &cc), (670_000_000, 'R'));
        assert_eq!(cubic_rate_with_options(3_600_000_000, 1_000_000_000, 1_800_000_000, &cc), (1_140_000_000, 'P'));
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let base = CongestionControlOptions::legacy();
        for bad in [CongestionControlOptions { beta: f64::NAN, ..base },
            CongestionControlOptions { beta: 1.0, ..base },
            CongestionControlOptions { recovery_rtts: 0, ..base },
            CongestionControlOptions { time_pg: 1.0, ..base },
            CongestionControlOptions { time_gs: 1.5, ..base },
            CongestionControlOptions { loss_threshold: 0, ..base },
            CongestionControlOptions { initial_rate_upps: 1, ..base },
            CongestionControlOptions { event_guard_rtts: f64::NAN, ..base },
            CongestionControlOptions { time_pg: 1.1, time_gs: 100.0, ..base }] {
            assert!(bad.validate().is_err());
        }
    }
}

#[cfg(test)]
mod polynomial_pacing_tests {
    use super::*;

    #[test]
    fn low_rate_polynomial_handshake_and_idle_then_burst() {
        for (cadence_ms, pps) in [(2, 100), (5, 100), (2, 10)] {
            let port = std::net::UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap().port();
            let server_key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
            let address = STPAddress { ip: Ipv6Addr::LOCALHOST, port, magic1: CONNECT_MAGIC1_PLAIN_TEXT, key: server_key.public.clone() };
            let key = address.to_connection_key();
            let opts = || NetworkThreadOptions {
                pacing: PacingOptions::Polynomial { cadence_ms },
                congestion_control: CongestionControlOptions { initial_rate_upps: pps * 1_000_000, rate_floor_upps: pps * 1_000_000, ..CongestionControlOptions::legacy() },
                ..Default::default()
            };
            let server = new_network_thread_with_options(vec![server_key], port, None, (1_000_000,1<<20,1<<20), opts());
            let client = new_network_thread_with_options(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0, None, (1_000_000,1<<20,1<<20), opts());
            service_connections(&client, NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut wanted = Vec::new();
            loop {
                service_connections(&server, NetworkThreadPush::default()).unwrap();
                let p = service_connections(&client, NetworkThreadPush::default()).unwrap();
                if !p.current_connections.is_empty() { wanted = p.current_connections; }
                if p.connection_stats.iter().any(|(_, s)| s.packets_sent > 0 && s.rtt_us > 0) { break; }
                assert!(std::time::Instant::now() < deadline, "{pps}pps/poly{cadence_ms} idle handshake stalled");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
            service_connections(&client, NetworkThreadPush { wanted_connections: wanted.clone(), send_unreliable: vec![(key, vec![42; 1000]); 3], ..Default::default() }).unwrap();
            let mut received = 0;
            while received < 3 {
                let p = service_connections(&server, NetworkThreadPush::default()).unwrap();
                for (_, message) in p.received_unreliable_messages { assert_eq!(message, vec![42; 1000]); received += 1; }
                service_connections(&client, NetworkThreadPush { wanted_connections: wanted.clone(), ..Default::default() }).unwrap();
                assert!(std::time::Instant::now() < deadline, "{pps}pps/poly{cadence_ms} burst stalled");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn idle_polynomial_peer_sends_control_without_application_data() {
        let port = std::net::UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap().port();
        let server_key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
        let address = STPAddress { ip: Ipv6Addr::LOCALHOST, port, magic1: CONNECT_MAGIC1_PLAIN_TEXT, key: server_key.public.clone() };
        let opts = || NetworkThreadOptions { pacing: PacingOptions::Polynomial { cadence_ms: 10 }, ..Default::default() };
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
        panic!("idle peer never emitted a curve-paced keepalive / probe or acquired RTT");
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
        while p.len() >= 8 {
            let h = load_u64(&p[0..8]);
            if h == u64::MAX { break; }
            let len = ((h >> 18) & 0x3fff) as usize;
            let pkg = ((h >> 2) & 0xffff) as u16;
            if h & 1 != 0 {
                let w1 = load_u64(&p[8..16]);
                assert!(matches!(w1 >> 48, STP_EXT_KIND_FEC | STP_EXT_KIND_GROUPED_FEC));
                out.push((pkg, Some(((w1 & 0xffff_ffff) as usize, ((w1 >> 32) & 0xffff) as usize, (h >> 32) as u32)), false, 0, p[16..16 + len].to_vec()));
                p = &p[16 + len..];
            } else {
                out.push((pkg, None, h & 2 != 0, (h >> 32) as u32, p[8..8 + len].to_vec()));
                p = &p[8 + len..];
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

    fn new_buf(ppm: u32) -> UnreliableSendBuffer {
        let mut b = UnreliableSendBuffer::new(1_000_000, 1 << 26, 1 << 26);
        b.fec_redundancy_ppm = ppm;
        b
    }

    #[test]
    fn thousand_byte_messages_occupy_one_physical_packet_each() {
        for payload_len in [1162, 1450, 9194] {
            let mut b = new_buf(0);
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
        let mut b = new_buf(0);
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

    #[test]
    fn ppm_zero_sends_plain_fragments() {
        let mut b = new_buf(0);
        let (m1, m2) = (msg(20_000), msg(100));
        assert!(b.submit_messages(vec![m1.clone(), m2.clone()]).is_empty());
        let packets = drain(&mut b, 9194, 100);
        assert_eq!(packets.len(), 3);
        let frags: Vec<Frag> = packets.into_iter().flatten().collect();
        assert!(frags.iter().all(|f| f.1.is_none()));
        // 9186 + 9186 + 1628 bytes of package 0, then package 1 packed into the third packet.
        assert_eq!(frags.iter().map(|f| (f.0, f.3, f.4.len(), f.2)).collect::<Vec<_>>(), vec![(0, 0, 9186, false), (0, 9186, 9186, false), (0, 18372, 1628, true), (1, 0, 100, true)]);
        let joined: Vec<u8> = frags[..3].iter().flat_map(|f| f.4.clone()).collect();
        assert_eq!(joined, m1);
        assert_eq!(frags[3].4, m2);
        assert_eq!(b.queue_bytes_filled, 0);
    }

    fn check_fec(frags: &[Frag], package_id: u16, m: &[u8], ppm: u64, drop_every: usize) {
        let mine: Vec<&Frag> = frags.iter().filter(|f| f.0 == package_id).collect();
        let (len, bb, _) = mine[0].1.unwrap();
        assert_eq!(len, m.len());
        let k = crate::fec::block_count(len, bb).unwrap();
        let n = k + ((k as u64 * ppm).div_ceil(1_000_000)) as usize;
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
        let ppm = 50_000;
        let mut b = new_buf(ppm as u32);
        let (m1, m2, m3) = (msg(100_000), msg(500), msg(1146 * 2));
        assert!(b.submit_messages(vec![m1.clone(), m2.clone(), m3.clone()]).is_empty());
        let frags: Vec<Frag> = drain(&mut b, 1162, 1000).into_iter().flatten().collect();
        // K = 88 blocks of 1146 B, N = 88 + ceil(4.4) = 93; losing 4 of them is fine.
        check_fec(&frags, 0, &m1, ppm, 25);
        // One block: plain.
        assert!(frags.iter().any(|f| f.0 == 1 && f.1.is_none() && f.4 == m2));
        // Exactly two blocks: FEC with 3 blocks.
        check_fec(&frags, 2, &m3, ppm, 0);
        assert_eq!(b.queue_bytes_filled, 0);
    }

    #[test]
    fn fec_big_threaded_encoder() {
        let ppm = 20_000;
        let mut b = new_buf(ppm as u32);
        let m = msg(3_000_000);
        b.submit_messages(vec![m.clone()]);
        let frags: Vec<Frag> = drain(&mut b, 9194, 100_000).into_iter().flatten().collect();
        check_fec(&frags, 0, &m, ppm, 60);
    }

    #[test]
    fn fec_restarts_when_tu_shrinks() {
        let mut b = new_buf(100_000);
        let m = msg(200_000);
        b.submit_messages(vec![m.clone()]);
        let mut first = drain(&mut b, 9194, 5);
        assert!(first.iter().flatten().all(|f| f.0 == 0 && f.1.unwrap().1 == 9178));
        let rest: Vec<Frag> = drain(&mut b, 1162, 10_000).into_iter().flatten().collect();
        assert!(rest.iter().all(|f| f.0 == 1 && f.1.unwrap().1 == 1146));
        check_fec(&rest, 1, &m, 100_000, 0);
        first.clear();
        assert_eq!(b.queue_bytes_filled, 0);
    }

    #[test]
    fn trimmed_data_never_uses_ack_size() {
        let mut payload = vec![0; 9194];
        for len in [0, 1, 500, 508, 509, 600] {
            let mut b = new_buf(0);
            b.submit_messages(vec![vec![7; len]]);
            let used = fill_packet_payload_with_unreliable_fragments(&mut payload, &mut b);
            assert_eq!(used, (len + STP_FRAGMENT_HEADER_SIZE).max(517));
            assert!(used > 516);
            let f = parse_packet(&payload[..used]);
            assert_eq!(f[0].4, vec![7; len]);
        }
        let mut b = new_buf(100_000);
        b.submit_messages(vec![vec![9; 200_000]]);
        let mut small = vec![0; 1162];
        assert_eq!(fill_packet_payload_with_unreliable_fragments(&mut small, &mut b), 1162);
        // TU grew after coding started: do not pay 288B of padding per block.
        let mut grown = vec![0; 1450];
        assert_eq!(fill_packet_payload_with_unreliable_fragments(&mut grown, &mut b), 1162);
    }

    #[test]
    fn grouped_wire_round_trip_and_overload_admission() {
        let payload_len = 48;
        let m = msg(64001 * (payload_len - STP_FEC_FRAGMENT_HEADER_SIZE) - 1);
        let layout = crate::fec::MessageLayout::new(m.len(), 32).unwrap();
        let mut b = new_buf(50_000);
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
        assert!(fec_receive_block(&mut slot, key, 0, 300 * 32, 32, 0, &[0;32], &done, &workers).is_none());
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
        let mut slots = FecRecvSlot::new_ring(MAX_FEC_DECODE_WORKERS);
        let message = std::sync::Arc::new(msg(300 * 32));
        let base = 1_000_000_000;
        for (i, slot) in slots.iter_mut().enumerate() {
            slot.package_id = i as u16;
            fec_receive_block(slot, key, i as u16, message.len(), 32, 0, &message[..32], &done, &workers);
            assert!(matches!(slot.state, FecRecvState::Worker { .. }));
            slot.last_block_ns = base + i as u64 * 1000;
        }
        assert_eq!(workers.load(Acquire), MAX_FEC_DECODE_WORKERS);
        let mut retry = FecRecvSlot { package_id: 100, ..Default::default() };
        fec_receive_block(&mut retry, key, 100, message.len(), 32, 0, &message[..32], &done, &workers);
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
            fec_receive_block(&mut retry, key, 100, message.len(), 32, id, &block[..n], &done, &workers);
            assert!(workers.load(Acquire) <= MAX_FEC_DECODE_WORKERS);
        }
        let (_, id, decoded) = completions.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
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
    fn grouped_adaptive_topup_uses_owned_group_losses() {
        let mut b = new_buf(10_000);
        let a = crate::fec_adapt::FecAdaptiveState::new(crate::fec_adapt::AdaptiveFecConfig { topup: true, ..Default::default() }, 0, 0, 0);
        b.fec_adaptive = Some(a.clone());
        b.start_fec(std::sync::Arc::new(msg(64001 * 32)), 32);
        // One real group-zero source, followed by a control nonce that is NOT a symbol.
        b.fec_prepare_packet(0);
        assert!(matches!(b.next_fragment(48, 48), Some(UnreliableFragment::Fec { block_id: 0, .. })));
        b.fec_prepare_packet(1);
        let f = b.fec_send_slot.as_mut().unwrap();
        let layout = crate::fec::MessageLayout::new(f.message.len(), 32).unwrap();
        assert_eq!(layout.groups, 3);
        f.lost = 600;
        f.group_lost[0] = 600;
        let initial_p = f.loss_estimate;
        b.fec_on_packet_lost(1); // ACK/probe/keepalive gap must not own a group.
        assert_eq!(b.fec_send_slot.as_ref().unwrap().lost, 600);
        b.fec_on_packet_lost(0);
        b.fec_on_packet_lost(0); // repeated declaration must not count twice.
        let f = b.fec_send_slot.as_ref().unwrap();
        assert_eq!(f.group_lost, vec![601, 0, 0]);
        assert_eq!(f.lost, 601);
        let group_k = layout.group(0).1 as u64;
        let group_n = a.topped_up_blocks_for_group(group_k, layout.k as u64, layout.groups, 601, initial_p);
        let expected = layout.round_plan((layout.k as u64 + (group_n - group_k) * layout.groups as u64) as u32);
        assert_eq!(f.n, expected);
        let averaged = a.topped_up_blocks_for_group(group_k, layout.k as u64, layout.groups, 601u64.div_ceil(layout.groups as u64), initial_p);
        assert!(group_n > averaged); // Concentrated erasures must not be averaged away.
        assert_eq!((f.n - f.k) as usize % layout.groups, 0);
        assert_eq!(a.group_failure_target(layout.k as u64, layout.groups), a.tracker.config().eps / layout.groups as f64);
    }

    #[test]
    fn fec_nonce_ring_tracks_multi_group_packets_wrap_and_slot_generation() {
        let mut b = new_buf(30_000);
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
        let mut b = new_buf(10_000);
        let a = FecAdaptiveState::new(AdaptiveFecConfig { kind: LossEstimatorKind::SpanTail, eps: 0.5, topup: true, closed_loop: true, ..Default::default() }, 0, 0, 0);
        b.fec_adaptive = Some(a.clone());
        b.start_fec(std::sync::Arc::new(msg(64001 * 32)), 32);
        let f = b.fec_send_slot.as_mut().unwrap();
        let layout = crate::fec::MessageLayout::new(f.message.len(), 32).unwrap();
        f.next_id = f.k; // all sources sent, no repairs yet
        f.group_lost[1] = 900;
        f.lost = 900;
        f.refresh_plan(&a);
        let expected_repairs = (0..layout.groups).map(|g| a.extra_repair_blocks_needed_for_group(layout.group(g).1 as u64, layout.k as u64, layout.groups, layout.group(g).1 as u64, 0, f.group_lost[g] as u64)).max().unwrap();
        assert_eq!(f.n, layout.round_plan(f.k + expected_repairs as u32 * layout.groups as u32));
        let eps = a.group_failure_target(layout.k as u64, 1);
        assert_eq!(a.group_failure_target(layout.k as u64, layout.groups) * layout.groups as f64, eps);
        assert!(expected_repairs >= 900 + 12);
        let n = f.n;
        f.group_lost[1] = 0;
        f.refresh_plan(&a);
        assert_eq!(f.n, n); // plans never shrink
    }

    #[test]
    fn oversized_message_bypasses_only_empty_queues() {
        let mut b = new_buf(0);
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
        let mut b = new_buf(0);
        b.min_queue_size_bytes = 0;
        b.current_bytes_per_second = 1_100_000;
        assert_eq!(b.current_byte_capacity(), 1_100_000);
        b.fec_redundancy_ppm = 100_000;
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
    use crate::fec_adapt::{AdaptiveFecConfig, FecAdaptiveState, LossEstimatorKind, SpanFloorKind};

    #[test]
    fn refreshes_own_loss_budget_at_source_completion_without_a_new_loss_event() {
        let cfg = AdaptiveFecConfig { kind: LossEstimatorKind::SpanTail, topup: true, closed_loop: true, span_floor: SpanFloorKind::Real, eps: 0.5, ..Default::default() };
        let mut b = UnreliableSendBuffer::new(100000, 1000000, 1000000);
        b.fec_redundancy_ppm = 10000;
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
        assert!(f.n > initial_n && f.n >= 96 && f.n <= 128, "initial={initial_n} n={}", f.n);
        // Existing top-up callback also uses the same bounded closed-loop budget.
        b.fec_on_packet_lost(4);
        assert_eq!(b.fec_send_slot.as_ref().unwrap().lost, 21);
        assert!(b.fec_send_slot.as_ref().unwrap().n <= 128);
    }
}

#[cfg(test)]
mod nack_loss_tests {
    use super::*;
    #[test]
    fn duplicate_nack_and_timeout_cannot_account_same_loss_twice() {
        let ConnectionState::Connected(mut s) = new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, 1, 0) else { unreachable!() };
        s.RTT_mean = 200;
        s.account_send(10_000_000);
        s.packets_in_flight = 1;
        assert!(declare_packet_lost(&mut s, 0, 30_000_000, &CongestionControlOptions::legacy(), None));
        assert!(!declare_packet_lost(&mut s, 0, 40_000_000, &CongestionControlOptions::legacy(), None));
        assert_eq!(s.packets_in_flight, 0);
        assert_eq!(s.stats.packets_lost, 1);
        assert_eq!(s.declared_lost_field[0] & 1, 1);
        s.packets_waiting_ack_tail = 1;
        assert!(!declare_packet_lost(&mut s, 0, 50_000_000, &CongestionControlOptions::legacy(), None));
    }
    #[test]
    fn nack_of_probe_is_not_data_loss() {
        let ConnectionState::Connected(mut s) = new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, 1, 0) else { unreachable!() };
        s.account_send(10_000_000);
        s.tu_probe_sequence_number = 0;
        assert!(!declare_packet_lost(&mut s, 0, 30_000_000, &CongestionControlOptions::legacy(), None));
        assert_eq!(s.stats.packets_lost, 0);
        assert_eq!(s.stats.tu_probes_lost, 1);
        assert_eq!(s.packets_in_flight, 0);
    }
}
