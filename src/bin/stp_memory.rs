//! Authenticated adversarial receive-memory probes. Each invocation is a fresh process.
//! stp_memory sparse|inline|workers|pending|complete COUNT SIZE [CONNECTIONS]
//! SIZE is bytes (plain end offset / FEC message length). Never sends outside loopback.
use shielded_transport_pigeon::stp::*;
use std::{net::UdpSocket, time::Duration};

struct Peer { socket: UdpSocket, cipher: ConnectionCipherTriplet, prefix: u16, seq: u64 }
impl Peer {
    fn connect(server: &IdentityKeyPair, port: u16) -> Option<Self> {
        let magic = server.magic1;
        let params = crypto_string_from_connect_magic1(magic).unwrap().parse().unwrap();
        let key = new_keypair_from_connect_magic1(magic).unwrap();
        let prologue = &magic.to_le_bytes()[..6];
        let mut hs = snow::Builder::new(params).prologue(prologue).unwrap()
            .local_private_key(&key.private).unwrap().remote_public_key(&server.public).unwrap()
            .build_initiator().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(("127.0.0.1", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = [0u8; 2048]; b[..6].copy_from_slice(prologue);
        let n = hs.write_message(&build_magic2_client_block(), &mut b[6..]).unwrap();
        socket.send(&b[..6+n]).unwrap();
        let n = socket.recv(&mut b).ok()?;
        hs.read_message(&b[6..n], &mut [0;1024]).unwrap();
        Some(Self { socket, cipher: ConnectionCipherTriplet::new_from_old_init_only(hs.into_stateless_transport_mode().unwrap()),
            prefix: u16::from_le_bytes(key.public[..2].try_into().unwrap()) << 1, seq: 0 })
    }
    fn send(&mut self, header: u64, word: Option<u64>, bytes: &[u8]) {
        let mut payload = vec![255u8; (8 + word.map_or(0, |_| 8) + bytes.len() + 8).max(517)];
        payload[..8].copy_from_slice(&header.to_le_bytes());
        let o = if let Some(w) = word { payload[8..16].copy_from_slice(&w.to_le_bytes()); 16 } else { 8 };
        payload[o..o+bytes.len()].copy_from_slice(bytes);
        let mut b = vec![0; payload.len()+22];
        b[..2].copy_from_slice(&self.prefix.to_le_bytes());
        b[2..6].copy_from_slice(&shielded_transport_pigeon::sequence::to_wire(self.seq).to_le_bytes());
        let n = self.cipher.current.write_message(self.seq, &payload, &mut b[6..]).unwrap();
        self.socket.send(&b[..n+6]).unwrap(); self.seq += 1;
    }
    fn acked(&self) -> usize {
        self.socket.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let mut b = [0;2048]; let mut out = [0;2048]; let mut count = 0;
        while let Ok(n) = self.socket.recv(&mut b) {
            if n < 6 { continue; }
            let wire = u32::from_le_bytes(b[2..6].try_into().unwrap());
            if !shielded_transport_pigeon::sequence::is_ack_space(wire) { continue; }
            let nonce = shielded_transport_pigeon::sequence::ACK_SPACE | (wire & 0x7fffffff) as u64;
            if let Ok(n) = self.cipher.current.read_message(nonce, &b[6..n], &mut out) {
                if let Some(a) = shielded_transport_pigeon::ack::BitmapAck::decode(&out[..n]) {
                    count = count.max((0..self.seq).filter(|&s| a.contains(s) || a.sample_seq == s).count());
                }
            }
        }
        count
    }
}
fn rss() -> String {
    std::fs::read_to_string("/proc/self/status").unwrap().lines()
        .filter(|l| l.starts_with("VmRSS:") || l.starts_with("VmHWM:")).collect::<Vec<_>>().join("; ")
}
fn main() {
    let a: Vec<_> = std::env::args().collect();
    let mode = a.get(1).expect("mode"); let count: usize = a.get(2).expect("count").parse().unwrap();
    let size: usize = a.get(3).expect("size").parse().unwrap();
    let connections: usize = a.get(4).map_or(1, |v| v.parse().unwrap());
    assert!(size <= MAX_JUMBOGRAM_LEN && count <= 1024 && connections <= 4096);
    let kp = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    if mode == "pressure" { pressure(kp, count, size); return; }
    // Reserve an ephemeral port before starting STP, whose API does not expose the bound port.
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap(); let port = probe.local_addr().unwrap().port(); drop(probe);
    let cap = receive_connection_memory_limit(size, 1).expect("message-size receive cap");
    let process = (256 << 20).max(cap + (1 << 20));
    println!("max_message_size={size} per_connection_cap={cap} process_budget={process}");
    let _server = new_network_thread_with_options(vec![kp.clone()], port, None, (1_000_000, 1<<20, 1<<20), size,
        NetworkThreadOptions { bind_ip: Some("127.0.0.1".parse().unwrap()),
            receive_memory: Some(shielded_transport_pigeon::receive_memory::ReceiveMemoryBudget::new(process)), ..Default::default() });
    std::thread::sleep(Duration::from_millis(50));
    println!("baseline {}", rss());
    let mut peers = Vec::new();
    for _ in 0..connections {
        if let Some(peer) = Peer::connect(&kp, port) { peers.push(peer); }
        else { println!("connection admission refused after {} peers", peers.len()); break; }
    }
    for peer in &mut peers {
        for i in 0..count {
            match mode.as_str() {
                "pending" => {},
                "sparse" => peer.send((i as u64)<<2 | 1<<18 | ((size-1) as u64)<<32, None, &[1]),
                "complete" => {
                    for offset in (0..size).step_by(1000) {
                        let len = (size-offset).min(1000);
                        peer.send((i as u64)<<2 | ((len as u64)<<18) | ((offset as u64)<<32)
                            | if offset+len == size {2} else {0}, None, &vec![1;len]);
                        std::thread::sleep(Duration::from_micros(100));
                    }
                },
                "inline" | "workers" | "tiny" => {
                    let block = if mode == "inline" {size.div_ceil(256).max(FEC_MIN_BLOCK_BYTES)} else if mode == "tiny" {1} else {FEC_MIN_BLOCK_BYTES};
                    assert!(block <= 16383);
                    let layout = shielded_transport_pigeon::fec::MessageLayout::new(size, block).unwrap();
                    let kind = if layout.groups > 1 {STP_EXT_KIND_GROUPED_FEC} else {STP_EXT_KIND_FEC};
                    let rounds = if mode == "tiny" {layout.groups} else {1};
                    for group in 0..rounds {
                        let id = layout.group(group).0;
                        peer.send(1 | ((i as u64)<<2) | ((block as u64)<<18) | ((id as u64)<<32),
                            Some(size as u64 | (block as u64)<<32 | kind<<48), &vec![1;block]);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                },
                _ => panic!("unknown mode"),
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    let acked: usize = peers.iter().map(Peer::acked).sum();
    println!("result mode={mode} count={count} size={size} connections={connections} acked={acked} {}", rss());
}

// An honest sender, not the raw adversary: fill a small receiver budget while the
// application is stalled, then drain it. Observe loss-driven rate control and recovery.
fn pressure(server_key: IdentityKeyPair, seconds: usize, size: usize) {
    use std::time::Instant;
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap(); let port = socket.local_addr().unwrap().port(); drop(socket);
    let address = STPAddress::from("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().to_ipv6_mapped(), port, &server_key);
    let cap = receive_connection_memory_limit(size, 1).expect("message-size receive cap");
    let process = (4 << 20).max(cap + (1 << 20));
    println!("pressure max_message_size={size} per_connection_cap={cap} process_budget={process}");
    let budget = shielded_transport_pigeon::receive_memory::ReceiveMemoryBudget::new(process);
    let server = new_network_thread_with_options(vec![server_key], port, None, (1_000_000,1<<20,1<<20), size,
        NetworkThreadOptions { receive_memory: Some(budget.clone()), bind_ip: Some("127.0.0.1".parse().unwrap()), ..Default::default() });
    let client = new_network_thread(vec![new_keypair_from_connect_magic1(address.magic1).unwrap()], 0, None, (1_000_000,1<<20,1<<20), size);
    service_connections(&client, NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).unwrap();
    let start = Instant::now(); let mut client_wanted = Vec::new(); let mut server_wanted = Vec::new();
    let mut key = None; let mut pending = Vec::new(); let mut submitted = 0; let mut received = 0; let mut last_second = usize::MAX;
    while start.elapsed().as_secs_f64() < seconds as f64 {
        let second = start.elapsed().as_secs() as usize;
        // Drain for first third, stall the middle third, then resume.
        let stalled = second >= seconds/3 && second < 2*seconds/3;
        if !stalled {
            let p = service_connections(&server, NetworkThreadPush { wanted_connections: server_wanted.clone(), ..Default::default() }).unwrap();
            server_wanted = p.current_connections; received += p.received_unreliable_messages.len();
        }
        if pending.is_empty() { if let Some(k) = key { pending.push((k,0,shielded_transport_pigeon::native_sockets::Dscp::BestEffort,vec![7;size])); } }
        let p = service_connections(&client, NetworkThreadPush { wanted_connections: client_wanted.clone(), send_unreliable: std::mem::take(&mut pending), ..Default::default() }).unwrap();
        key = p.current_connections.first().map(|(a,_)| ConnectionKey::from(a)); client_wanted = p.current_connections;
        pending = p.send_unreliable_rejected;
        if key.is_some() && pending.is_empty() { submitted += 1; }
        if second != last_second {
            if let Some((_,s)) = p.connection_stats.first() {
                println!("pressure second={second} stalled={stalled} pps={} sent={} lost={} submitted={submitted} delivered={received} budget_used={} budget_peak={} {}",
                    s.cc_rate_upps as f64/1e6,s.packets_sent,s.packets_lost,budget.used(),budget.peak(),rss());
            }
            last_second = second;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
}
