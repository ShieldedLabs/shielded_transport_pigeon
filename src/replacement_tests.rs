use super::*;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAGIC: u64 = CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b;
const APP: u64 = 0x89444182b302528e;
fn key(byte: u8) -> IdentityKeyPair {
    IdentityKeyPair {
        magic1: MAGIC,
        private: vec![byte; 32],
        public: curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped([byte; 32])
            .to_bytes()
            .to_vec(),
    }
}
fn socket() -> UdpSocket {
    let s = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    s.set_nonblocking(true).unwrap();
    s
}
fn free_port() -> u16 {
    socket().local_addr().unwrap().port()
}
fn address(k: &IdentityKeyPair, port: u16) -> STPAddress {
    STPAddress {
        ip: Ipv6Addr::LOCALHOST,
        port,
        magic1: k.magic1,
        key: k.public.clone(),
    }
}
fn pump(k: &IdentityKeyPair, port: u16, receive: usize) -> (Pump, LockfreeEndpoint) {
    pump_with_budget(k, port, receive, None)
}
fn pump_with_budget(
    k: &IdentityKeyPair,
    port: u16,
    receive: usize,
    receive_memory: Option<std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>>,
) -> (Pump, LockfreeEndpoint) {
    new_pump_with_options(
        vec![k.clone()],
        port,
        None,
        (100_000, 4096, 65536),
        4096,
        NetworkThreadOptions {
            receive_memory,
            rings: RingConfig {
                send: 16,
                control: 16,
                receive,
            },
            ..Default::default()
        },
    )
}
fn drive(pump: &mut Pump, ms: u64) {
    pump.run_for(Duration::from_millis(ms));
}
fn drain(app: &mut LockfreeEndpoint) -> Vec<RingEvent> {
    let mut events = Vec::new();
    while let Some(e) = app.try_recv() {
        events.push(e);
    }
    events
}
fn hello(
    k: &IdentityKeyPair,
    server: &IdentityKeyPair,
    offer: &[u8],
) -> (snow::HandshakeState, Vec<u8>) {
    let prologue = MAGIC.to_le_bytes();
    let mut h = noise_initiator(
        crypto_string_from_connect_magic1(MAGIC).unwrap(),
        &prologue[..6],
        &k.private,
        &server.public,
    )
    .unwrap();
    let mut flight = vec![0; 1024];
    flight[..6].copy_from_slice(&prologue[..6]);
    let n = h.write_message(offer, &mut flight[6..]).unwrap();
    flight.truncate(6 + n);
    (h, flight)
}
fn response(s: &UdpSocket, pump: &mut Pump) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0; 10000];
    while Instant::now() < deadline {
        drive(pump, 2);
        while let Ok((n, _)) = s.recv_from(&mut buf) {
            if n == 62 && load_u48(&buf[..6]) >> 16 == 0xffff_ffff {
                return buf[..n].to_vec();
            }
        }
    }
    panic!("no ServerHello");
}
fn finish(mut h: snow::HandshakeState, flight: &[u8]) -> (ConnectionCipherTriplet, [u8; 64]) {
    let mut out = [0; 512];
    assert_eq!(h.read_message(&flight[6..], &mut out).unwrap(), 8);
    assert_eq!(load_u64(&out[..8]), APP);
    let hash = get_handshake_hash(&h);
    (
        ConnectionCipherTriplet::new_from_old_init_only(h.into_stateless_transport_mode().unwrap()),
        hash,
    )
}
fn packet(
    cipher: &mut ConnectionCipherTriplet,
    k: &IdentityKeyPair,
    nonce: u64,
    message: &[u8],
) -> Vec<u8> {
    let mut plaintext = vec![0xff; 490];
    if !message.is_empty() {
        plaintext[0] = 1;
        store_u16(&mut plaintext[1..3], message.len() as u16);
        plaintext[3..3 + message.len()].copy_from_slice(message);
    }
    let mut output = vec![0; 512];
    let mut c = Some(cipher.clone());
    let n = seal_connected_packet(
        &mut c,
        load_u16(&k.public[..2]) << 1,
        nonce,
        &plaintext,
        &mut output,
        monotonic_clock_ns(),
    )
    .unwrap();
    *cipher = c.unwrap();
    output.truncate(n);
    output
}
struct Server {
    pump: Pump,
    app: LockfreeEndpoint,
    key: IdentityKeyPair,
    addr: SocketAddr,
    raw: UdpSocket,
    client: IdentityKeyPair,
    original: Vec<u8>,
    old: ConnectionCipherTriplet,
    hash: [u8; 64],
}
impl Server {
    fn new(capacity: usize) -> Self {
        Self::with_client(capacity, key(19))
    }
    fn with_client(capacity: usize, client: IdentityKeyPair) -> Self {
        Self::at_port(capacity, client, free_port())
    }
    fn at_port(capacity: usize, client: IdentityKeyPair, port: u16) -> Self {
        Self::with_pump(capacity, client, port, pump(&key(41), port, capacity))
    }
    fn with_pump(
        capacity: usize,
        client: IdentityKeyPair,
        port: u16,
        (mut p, mut app): (Pump, LockfreeEndpoint),
    ) -> Self {
        let server = key(41);
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let raw = socket();
        let (h, original) = hello(&client, &server, &build_magic2_client_block());
        raw.send_to(&original, addr).unwrap();
        let flight = response(&raw, &mut p);
        let (mut old, hash) = finish(h, &flight);
        let confirm = packet(&mut old, &client, 0, b"initial");
        raw.send_to(&confirm, addr).unwrap();
        drive(&mut p, 10);
        let events = drain(&mut app);
        assert!(
            matches!(events.first(), Some(RingEvent::Connected { handshake_hash, .. }) if *handshake_hash == hash)
        );
        if capacity > 1 {
            assert!(
                matches!(events.get(1), Some(RingEvent::Message { data, .. }) if data == b"initial")
            );
        }
        Self {
            pump: p,
            app,
            key: server,
            addr,
            raw,
            client,
            original,
            old,
            hash,
        }
    }
    fn candidate(&mut self) -> (ConnectionCipherTriplet, Vec<u8>, Vec<u8>, [u8; 64]) {
        let (h, hello) = hello(&self.client, &self.key, &build_magic2_client_block());
        self.raw.send_to(&hello, self.addr).unwrap();
        let flight = response(&self.raw, &mut self.pump);
        let (cipher, hash) = finish(h, &flight);
        (cipher, hello, flight, hash)
    }
    fn send(&mut self, bytes: &[u8]) {
        self.raw.send_to(bytes, self.addr).unwrap();
        drive(&mut self.pump, 5);
    }
}

#[test]
fn replacement_initial_confirmation_processes_packet_once() {
    let _ = Server::new(16);
}

#[test]
fn replacement_old_live_replays_and_invalid_packets_cannot_promote() {
    let mut s = Server::new(16);
    let (_new, _, _, _) = s.candidate();
    assert!(drain(&mut s.app).is_empty());
    let old = packet(&mut s.old, &s.client, 1, b"still old");
    s.send(&old);
    let events = drain(&mut s.app);
    assert!(matches!(&events[..], [RingEvent::Message { data, .. }] if data == b"still old"));
    s.send(&old); // old AEAD success, replay failure must not try/promote candidate.
    let mut invalid = old.clone();
    invalid[20] ^= 1;
    s.send(&invalid);
    assert!(drain(&mut s.app).is_empty());
    let old2 = packet(&mut s.old, &s.client, 2, b"old survives");
    s.send(&old2);
    assert!(
        matches!(&drain(&mut s.app)[..], [RingEvent::Message { data, .. }] if data == b"old survives")
    );
}

#[test]
fn replacement_confirmation_orders_events_rejects_old_and_delivers_once() {
    let mut s = Server::new(16);
    let (mut new, _, _, hash) = s.candidate();
    assert_ne!(s.hash, hash);
    let confirming = packet(&mut new, &s.client, 0, b"new");
    s.send(&confirming);
    let events = drain(&mut s.app);
    assert!(
        matches!(&events[..], [RingEvent::Disconnected { reason: DisconnectReason::Replaced, .. },
        RingEvent::Connected { handshake_hash, .. }, RingEvent::Message { data, .. }] if *handshake_hash == hash && data == b"new")
    );
    s.send(&confirming);
    let delayed_old = packet(&mut s.old, &s.client, 2, b"must not leak");
    s.send(&delayed_old);
    assert!(drain(&mut s.app).is_empty());
    let next = packet(&mut new, &s.client, 1, b"next");
    s.send(&next);
    assert!(matches!(&drain(&mut s.app)[..], [RingEvent::Message { data, .. }] if data == b"next"));
}

#[test]
fn replacement_duplicate_original_hello_is_ignored() {
    let mut s = Server::new(16);
    let original = s.original.clone();
    s.send(&original);
    drive(&mut s.pump, 35);
    let mut buf = [0; 10000];
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        assert_ne!(n, 62, "original hello must not start another responder");
    }
    assert!(drain(&mut s.app).is_empty());
}

#[test]
fn replacement_duplicate_flight_is_immutable_and_first_wins() {
    let mut s = Server::new(16);
    let (_cipher, hello, flight, _) = s.candidate();
    s.send(&hello);
    assert_eq!(response(&s.raw, &mut s.pump), flight);
    let (_, second) = hello_for(&s.client, &s.key);
    s.send(&second);
    // An unrelated authenticated hello cannot evict the first candidate.
    assert_eq!(response(&s.raw, &mut s.pump), flight);
    assert!(drain(&mut s.app).is_empty());
}
fn hello_for(k: &IdentityKeyPair, server: &IdentityKeyPair) -> (snow::HandshakeState, Vec<u8>) {
    hello(k, server, &build_magic2_client_block())
}

#[test]
fn replacement_capacity_one_and_full_ring_keep_boundary() {
    let mut s = Server::new(1);
    let (mut new, _, _, hash) = s.candidate();
    let fill = packet(&mut s.old, &s.client, 1, b"occupy");
    s.send(&fill);
    let confirm = packet(&mut new, &s.client, 0, b"drop under ordinary ring pressure");
    s.send(&confirm);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::Message { data, .. }) if data == b"occupy"));
    assert!(s.app.try_recv().is_none()); // Full ring did not retire old.
    s.send(&confirm);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::Replaced,
            ..
        })
    ));
    drive(&mut s.pump, 5);
    assert!(
        matches!(s.app.try_recv(), Some(RingEvent::Connected { handshake_hash, .. }) if handshake_hash == hash)
    );
    assert!(s.app.try_recv().is_none());
    assert!(s.app.stats().receive_dropped_full >= 1);
    let data = packet(&mut new, &s.client, 1, b"after boundary");
    s.send(&data);
    assert!(
        matches!(s.app.try_recv(), Some(RingEvent::Message { data, .. }) if data == b"after boundary")
    );
}

#[test]
fn replacement_same_port_restart_is_automatically_confirmed_while_idle() {
    let a = key(11);
    let b = key(12);
    let ap = free_port();
    let bp = free_port();
    let (mut server, mut se) = pump(&b, bp, 16);
    let (mut client, mut ce) = pump(&a, ap, 16);
    assert!(ce.try_connect(address(&b, bp)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut old_hash = None;
    while Instant::now() < deadline && old_hash.is_none() {
        drive(&mut client, 2);
        drive(&mut server, 2);
        for e in drain(&mut se) {
            if let RingEvent::Connected { handshake_hash, .. } = e {
                old_hash = Some(handshake_hash);
            }
        }
        drain(&mut ce);
    }
    assert!(
        old_hash.is_some(),
        "fresh idle initiator must confirm without app sends"
    );
    drop(ce);
    drop(client);
    let (mut client, mut ce) = pump(&a, ap, 16);
    assert!(ce.try_connect(address(&b, bp)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut events = Vec::new();
    while Instant::now() < deadline && events.len() < 2 {
        drive(&mut client, 2);
        drive(&mut server, 2);
        events.extend(drain(&mut se));
        drain(&mut ce);
    }
    assert!(
        matches!(&events[..], [RingEvent::Disconnected { reason: DisconnectReason::Replaced, .. },
        RingEvent::Connected { handshake_hash, .. }] if Some(*handshake_hash) != old_hash)
    );
}

#[test]
fn replacement_wrong_identity_application_plaintext_and_source_cannot_replace() {
    let mut s = Server::new(16);
    // A distinct key at the same source must never replace the live identity.
    let wrong = key(88);
    let (_, flight) = hello_for(&wrong, &s.key);
    s.send(&flight);
    drive(&mut s.pump, 260); // Exercise application rejection, not the cheap work gate.
    let mut bad_offer = build_magic2_client_block();
    bad_offer[1..9].fill(0);
    let (_, flight) = hello(&s.client, &s.key, &bad_offer);
    s.send(&flight);
    let mut plain = vec![0; 6 + 32 + MAGIC2_BLOCK_SIZE];
    store_u48(&mut plain[..6], CONNECT_MAGIC1_PLAIN_TEXT);
    plain[6..38].copy_from_slice(&s.client.public);
    plain[38..].copy_from_slice(&build_magic2_client_block());
    s.send(&plain);
    drive(&mut s.pump, 260); // Wrong local-key authentication must also reach Noise.
    let (_, flight) = hello_for(&s.client, &key(99));
    s.send(&flight);
    // A captured hello at a different port is not an eviction instruction.
    let elsewhere = socket();
    elsewhere.send_to(&s.original, s.addr).unwrap();
    drive(&mut s.pump, 10);
    let data = packet(&mut s.old, &s.client, 1, b"unchanged");
    elsewhere.send_to(&data, s.addr).unwrap();
    drive(&mut s.pump, 5);
    assert!(drain(&mut s.app).is_empty());
    s.send(&data);
    assert!(
        matches!(&drain(&mut s.app)[..], [RingEvent::Message { data, .. }] if data == b"unchanged")
    );
}

#[test]
fn replacement_rate_window_and_expiry_are_fixed() {
    let mut rate = ReplacementRate::default();
    for _ in 0..64 {
        assert!(rate.admit(5_000_000_000));
    }
    assert!(!rate.admit(5_999_999_999));
    assert!(rate.admit(6_000_000_000));
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(64 << 20);
    let mut map = HashMap::new();
    let a = key(1);
    let b = key(2);
    connect_to_endpoint(
        &mut map,
        &b,
        &address(&a, 42),
        (100_000, 4096, 65536),
        1,
        &budget,
        32 << 20,
        4096,
    );
    let c = map.values_mut().next().unwrap();
    c.connection_state = new_connection_state_connected(None, MAGIC, APP, 100);
    // Expiry is anchored to creation, including the exact inclusive deadline.
    c.creation_time_ns = 100;
    assert!(!c.replacement_expired(100 + REPLACEMENT_LIFETIME_NS));
    assert!(c.replacement_expired(101 + REPLACEMENT_LIFETIME_NS));
    drop(map);
    assert_eq!(budget.used(), 0);
}

fn responder(flight: &[u8], server: &IdentityKeyPair) -> snow::HandshakeState {
    let mut h = noise_responder(
        crypto_string_from_connect_magic1(MAGIC).unwrap(),
        &flight[..6],
        &server.private,
    )
    .unwrap();
    h.read_message(&flight[6..], &mut [0; 512]).unwrap();
    h
}
fn live_tracking() -> (
    ConnectionTrackingData,
    std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
    IdentityKeyPair,
    IdentityKeyPair,
) {
    let a = key(1);
    let b = key(2);
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(64 << 20);
    let mut map = HashMap::new();
    connect_to_endpoint(
        &mut map,
        &b,
        &address(&a, 42),
        (100_000, 4096, 65536),
        1,
        &budget,
        32 << 20,
        4096,
    );
    let mut c = map.remove(&address(&a, 42).connection_key()).unwrap();
    let (_, first) = hello_for(&a, &b);
    let mut h = responder(&first, &b);
    h.write_message(&APP.to_le_bytes(), &mut [0; 512]).unwrap();
    c.connection_state = new_connection_state_connected(
        Some(ConnectionCipherTriplet::new_from_old_init_only(
            h.into_stateless_transport_mode().unwrap(),
        )),
        MAGIC,
        APP,
        10_000_000_000,
    );
    c.peer_hello_digest = Some(*blake3::hash(&first).as_bytes());
    (c, budget, a, b)
}
fn prepare(
    c: &mut ConnectionTrackingData,
    budget: &std::sync::Arc<crate::receive_memory::ReceiveMemoryBudget>,
    a: &IdentityKeyPair,
    b: &IdentityKeyPair,
    now: u64,
) -> Vec<u8> {
    let (_, flight) = hello_for(a, b);
    c.prepare_replacement(
        responder(&flight, b),
        *blake3::hash(&flight).as_bytes(),
        APP,
        now,
        budget,
        32 << 20,
        4096,
        1,
        (100_000, 4096, 65536),
    );
    flight
}
fn saved(c: &ConnectionTrackingData) -> &[u8] {
    let ConnectionState::SendingServerHello {
        hello_packet_payload,
        ..
    } = &c.replacement.as_ref().unwrap().connection_state
    else {
        panic!();
    };
    hello_packet_payload
}

#[test]
fn replacement_candidate_fixed_timeout_pacing_memory_and_fresh_ephemeral() {
    let (mut c, budget, a, b) = live_tracking();
    let now = 10_000_000_000;
    let flight = prepare(&mut c, &budget, &a, &b, now);
    let original = saved(&c).to_vec();
    let digest = *blake3::hash(&flight).as_bytes();
    let hash = c.handshake_hash;
    let used = budget.used();
    assert_eq!(used, 2 * RECEIVE_CONNECTION_BYTES);
    assert!(!std::sync::Arc::ptr_eq(
        &c.receive_budget,
        &c.replacement.as_ref().unwrap().receive_budget
    ));
    // Duplicate cannot slide absolute expiry, swap response or reserve more memory.
    c.prepare_replacement(
        responder(&flight, &b),
        digest,
        APP,
        now + 1_000_000_000,
        &budget,
        32 << 20,
        4096,
        1,
        (100_000, 4096, 65536),
    );
    assert_eq!(c.replacement.as_ref().unwrap().creation_time_ns, now);
    assert_eq!(saved(&c), original);
    assert_eq!(budget.used(), used);
    let mut sent = Vec::new();
    let mut rate = ReplacementRate::default();
    for t in [
        now,
        now + 1,
        now + 10_000_001,
        now + 10_000_002,
        now + 2_510_000_002,
    ] {
        c.service_replacement(t, &mut rate, |_, _, p| {
            sent.push(p.to_vec());
            SendAttempt {
                attempted_at_ns: t,
                error: Some(55),
            }
        });
    }
    assert_eq!(sent.len(), 3);
    assert!(sent.iter().all(|p| p == &original));
    c.service_replacement(now + REPLACEMENT_LIFETIME_NS + 1, &mut rate, |_, _, _| {
        panic!("expired response")
    });
    assert!(c.replacement.is_none());
    assert!(c.is_connected());
    assert_eq!(c.handshake_hash, hash);
    assert_eq!(budget.used(), RECEIVE_CONNECTION_BYTES);
    // Replayed historical hello gets a genuinely fresh responder ephemeral, not expired keys.
    c.prepare_replacement(
        responder(&flight, &b),
        digest,
        APP,
        now + REPLACEMENT_LIFETIME_NS + 2,
        &budget,
        32 << 20,
        4096,
        1,
        (100_000, 4096, 65536),
    );
    assert_ne!(&saved(&c)[6..38], &original[6..38]);
    drop(c);
    assert_eq!(budget.used(), 0);
}

#[test]
fn replacement_admission_limits_and_failed_reservation_do_not_touch_live_state() {
    let (mut c, budget, a, b) = live_tracking();
    let now = 10_000_000_000;
    let mut work = ReplacementRate::default();
    assert!(!c.admit_replacement_work(c.peer_hello_digest.unwrap(), 0, now, &mut work));
    assert_eq!(work.used, 0);
    assert!(!c.admit_replacement_work([9; 32], MAX_REPLACEMENTS, now, &mut work));
    assert_eq!(work.used, 0);
    assert!(c.admit_replacement_work([9; 32], 0, now, &mut work));
    assert!(!c.admit_replacement_work([8; 32], 0, now + 249_999_999, &mut work));
    assert!(c.admit_replacement_work([8; 32], 0, now + 250_000_000, &mut work));
    let full = budget.reserve(budget.limit() - budget.used()).unwrap();
    prepare(&mut c, &budget, &a, &b, now);
    assert!(c.replacement.is_none());
    assert!(c.is_connected());
    drop(full);
    prepare(&mut c, &budget, &a, &b, now);
    assert!(c.replacement.is_some());
    assert!(!c.admit_replacement_work([7; 32], 0, now + 1_000_000_000, &mut work));
    assert_eq!(c.replacement.as_ref().unwrap().creation_time_ns, now);
    // Aggregate work and responses are independently bounded; denied responses are paced drops.
    let mut responses = ReplacementRate::default();
    for _ in 0..64 {
        assert!(responses.admit(now));
    }
    c.service_replacement(now, &mut responses, |_, _, _| {
        panic!("response budget bypass")
    });
    let ConnectionState::SendingServerHello {
        last_sent_time_ns, ..
    } = &c.replacement.as_ref().unwrap().connection_state
    else {
        panic!();
    };
    assert_ne!(*last_sent_time_ns, 0);
    c.service_replacement(now + 1, &mut responses, |_, _, _| panic!("hot retry"));
    drop(c);
    assert_eq!(budget.used(), 0);
}

#[test]
fn replacement_fresh_budget_rejects_old_worker_and_drops_queued_state() {
    let (mut c, budget, a, b) = live_tracking();
    assert!(
        c.unreliable_send_buffer
            .submit_messages(0, vec![vec![3; 2048]])
            .is_empty()
    );
    let generation = std::sync::Arc::new(());
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    c.unreliable_fec[0].package_id = 17;
    c.unreliable_fec[0].state = FecRecvState::Worker {
        tx,
        job: None,
        message_len: 2048,
        block_bytes: 445,
        generation: generation.clone(),
    };
    let completion = FecCompletion {
        connection_key: c.address().connection_key(),
        package_id: 17,
        message: vec![1; 2048],
        reservation: c.receive_budget.reserve(2048).unwrap(),
        decoder_generation: generation.clone(),
        connection_generation: c.receive_budget.clone(),
    };
    assert!(completion.owns(&c.unreliable_fec[0], &c.receive_budget));
    prepare(&mut c, &budget, &a, &b, 10_000_000_000);
    let fresh = c.replacement.take().unwrap();
    assert!(!fresh.unreliable_send_buffer.has_unsent_data());
    assert!(
        !completion.owns(&c.unreliable_fec[0], &fresh.receive_budget),
        "even identical decoder identity cannot cross connection budget"
    );
    assert!(!completion.owns(&fresh.unreliable_fec[0], &fresh.receive_budget));
    c = *fresh;
    assert!(matches!(c.unreliable_fec[0].state, FecRecvState::Empty));
    drop(c);
    assert!(budget.used() > 0); // old completion still owns only its old lease.
    drop(completion);
    assert_eq!(budget.used(), 0);
}

#[test]
fn replacement_captured_historical_hello_and_transport_cannot_confirm() {
    let mut s = Server::new(16);
    let historical = s.original.clone();
    let captured = packet(&mut s.old, &s.client, 1, b"captured old");
    let (mut current, _, _, _) = s.candidate();
    let confirm = packet(&mut current, &s.client, 0, b"current");
    s.send(&confirm);
    drain(&mut s.app);
    // Current digest is different: the historical hello can occupy a bounded slot,
    // but its former transport keys cannot authenticate the new responder ephemeral.
    s.send(&historical);
    let _fresh_response = response(&s.raw, &mut s.pump);
    s.send(&captured);
    assert!(drain(&mut s.app).is_empty());
    let live = packet(&mut current, &s.client, 1, b"live current");
    s.send(&live);
    assert!(
        matches!(&drain(&mut s.app)[..],[RingEvent::Message{data,..}] if data==b"live current")
    );
}

#[test]
fn replacement_same_prefix_different_full_key_is_rejected() {
    let mut prefixes = HashMap::new();
    let mut pair = None;
    for seed in 0u16..2048 {
        let mut private = [17; 32];
        private[..2].copy_from_slice(&seed.to_le_bytes());
        let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(private)
            .to_bytes()
            .to_vec();
        let kp = IdentityKeyPair {
            magic1: MAGIC,
            private: private.to_vec(),
            public,
        };
        let prefix = load_u16(&kp.public[..2]) << 1;
        if let Some(previous) = prefixes.insert(prefix, kp.clone()) {
            if previous.public != kp.public {
                pair = Some((previous, kp));
                break;
            }
        }
    }
    let (a, b) = pair.expect("deterministic birthday collision");
    let mut s = Server::with_client(16, a);
    let (_, flight) = hello_for(&b, &s.key);
    s.send(&flight);
    drive(&mut s.pump, 30);
    let mut buf = [0; 10000];
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        assert_ne!(n, 62);
    }
    let live = packet(&mut s.old, &s.client, 1, b"full identity retained");
    s.send(&live);
    assert!(
        matches!(&drain(&mut s.app)[..],[RingEvent::Message{data,..}] if data==b"full identity retained")
    );
}

#[test]
fn replacement_simultaneous_open_remains_one_shared_association() {
    let a = key(71);
    let b = key(72);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let (mut q, mut qe) = pump(&b, bp, 16);
    assert!(pe.try_connect(address(&b, bp)));
    assert!(qe.try_connect(address(&a, ap)));
    let until = Instant::now() + Duration::from_secs(3);
    let mut ah = None;
    let mut bh = None;
    while Instant::now() < until && (ah.is_none() || bh.is_none()) {
        drive(&mut p, 2);
        drive(&mut q, 2);
        for e in drain(&mut pe) {
            match e {
                RingEvent::Connected { handshake_hash, .. } => {
                    assert!(ah.is_none());
                    ah = Some(handshake_hash);
                }
                _ => panic!("unexpected lifecycle"),
            }
        }
        for e in drain(&mut qe) {
            match e {
                RingEvent::Connected { handshake_hash, .. } => {
                    assert!(bh.is_none());
                    bh = Some(handshake_hash);
                }
                _ => panic!("unexpected lifecycle"),
            }
        }
    }
    assert!(ah.is_some());
    assert_eq!(ah, bh);
}

#[test]
fn replacement_pending_boundary_orders_local_disconnect_and_releases_candidate() {
    let mut s = Server::new(1);
    let (mut new, _, _, _) = s.candidate();
    let peer = address(&s.client, s.raw.local_addr().unwrap().port()).connection_key();
    let confirm = packet(&mut new, &s.client, 0, b"drop");
    s.send(&confirm);
    assert!(s.app.try_disconnect(peer));
    drive(&mut s.pump, 5);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::Replaced,
            ..
        })
    ));
    drive(&mut s.pump, 5);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Connected { .. })
    ));
    drive(&mut s.pump, 5);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::Local,
            ..
        })
    ));
    s.send(&confirm);
    assert!(s.app.try_recv().is_none());
}

fn ack_packet(cipher: &mut ConnectionCipherTriplet, k: &IdentityKeyPair, nonce: u64) -> Vec<u8> {
    let mut output = vec![0; 174];
    let mut c = Some(cipher.clone());
    // Authenticated but semantically invalid ACK: its replay/semantic failure must
    // never cause a fallback from old keys; on fresh keys AEAD still confirms.
    let n = seal_connected_packet(
        &mut c,
        load_u16(&k.public[..2]) << 1,
        nonce,
        &[0; 152],
        &mut output,
        monotonic_clock_ns(),
    )
    .unwrap();
    *cipher = c.unwrap();
    output.truncate(n);
    output
}
#[test]
fn replacement_ack_semantics_do_not_fall_through_but_fresh_aead_confirms() {
    let mut s = Server::new(16);
    let (mut new, _, _, hash) = s.candidate();
    let old_ack = ack_packet(&mut s.old, &s.client, crate::sequence::ACK_SPACE);
    s.send(&old_ack);
    s.send(&old_ack);
    assert!(drain(&mut s.app).is_empty());
    let fresh_ack = ack_packet(&mut new, &s.client, crate::sequence::ACK_SPACE);
    s.send(&fresh_ack);
    assert!(
        matches!(&drain(&mut s.app)[..],[RingEvent::Disconnected{reason:DisconnectReason::Replaced,..},RingEvent::Connected{handshake_hash,..}] if *handshake_hash==hash)
    );
    s.send(&fresh_ack);
    assert!(drain(&mut s.app).is_empty());
    let data = packet(&mut new, &s.client, 0, b"independent data counter");
    s.send(&data);
    assert!(
        matches!(&drain(&mut s.app)[..],[RingEvent::Message{data,..}] if data==b"independent data counter")
    );
}
#[test]
fn replacement_local_disconnect_drops_unconfirmed_candidate_without_resurrection() {
    let mut s = Server::new(16);
    let (mut new, _, _, _) = s.candidate();
    let peer = address(&s.client, s.raw.local_addr().unwrap().port()).connection_key();
    assert!(s.app.try_disconnect(peer));
    drive(&mut s.pump, 5);
    assert!(matches!(
        &drain(&mut s.app)[..],
        [RingEvent::Disconnected {
            reason: DisconnectReason::Local,
            ..
        }]
    ));
    let late = packet(&mut new, &s.client, 0, b"late candidate");
    s.send(&late);
    assert!(drain(&mut s.app).is_empty());
}

#[test]
fn replacement_nonce_reconstruction_is_independent_after_old_low_counter_wrap() {
    let mut s = Server::new(16);
    // Legal compact gaps advance the old anchor across a low31 wrap.
    for nonce in [(1 << 30) - 1, (1 << 31) - 2, 3 * (1 << 30) - 3] {
        let bytes = packet(&mut s.old, &s.client, nonce, b"old high counter");
        s.send(&bytes);
        assert!(
            matches!(&drain(&mut s.app)[..],[RingEvent::Message{data,..}] if data==b"old high counter")
        );
    }
    let (mut new, _, _, hash) = s.candidate();
    // New packet zero is deliberately lost: ordinary later data confirms just as well.
    let bytes = packet(&mut new, &s.client, 1, b"new counter one");
    s.send(&bytes);
    assert!(
        matches!(&drain(&mut s.app)[..],[RingEvent::Disconnected{reason:DisconnectReason::Replaced,..},
        RingEvent::Connected{handshake_hash,..},RingEvent::Message{data,..}] if *handshake_hash==hash && data==b"new counter one")
    );
}

// Deterministic per-test-thread observations at the real pump service boundary.
struct Probe(u16);
impl Probe {
    fn new(port: u16, pair: SourceAddresses) -> Self {
        SOURCE_PROBES.with(|p| {
            assert!(p.borrow_mut().insert(port, (pair, 0)).is_none());
        });
        Self(port)
    }
    fn set(&self, pair: SourceAddresses) {
        SOURCE_PROBES.with(|p| p.borrow_mut().get_mut(&self.0).unwrap().0 = pair);
    }
    fn calls(&self) -> usize {
        SOURCE_PROBES.with(|p| p.borrow()[&self.0].1)
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        SOURCE_PROBES.with(|p| {
            p.borrow_mut().remove(&self.0);
        });
    }
}
fn sources(v4: u8, v6: u16) -> SourceAddresses {
    (
        if v4 == 0 {
            None
        } else {
            Some(std::net::Ipv4Addr::new(192, 0, 2, v4).to_ipv6_mapped())
        },
        if v6 == 0 {
            None
        } else {
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, v6))
        },
    )
}
fn shared_connection(
    p: &mut Pump,
    pe: &mut LockfreeEndpoint,
    q: &mut Pump,
    qe: &mut LockfreeEndpoint,
) -> [u8; 64] {
    let until = Instant::now() + Duration::from_secs(3);
    let mut a = None;
    let mut b = None;
    while Instant::now() < until && (a.is_none() || b.is_none()) {
        drive(p, 2);
        drive(q, 2);
        for e in drain(pe) {
            if let RingEvent::Connected { handshake_hash, .. } = e {
                assert!(a.replace(handshake_hash).is_none());
            } else {
                panic!("unexpected event before Connected");
            }
        }
        for e in drain(qe) {
            match e {
                RingEvent::Connected { handshake_hash, .. } => {
                    assert!(b.replace(handshake_hash).is_none());
                }
                RingEvent::Disconnected {
                    reason: DisconnectReason::Replaced,
                    ..
                } => assert!(b.is_none()),
                _ => panic!("unexpected remote event"),
            }
        }
    }
    assert!(a.is_some(), "local reconnection did not complete");
    assert_eq!(
        a, b,
        "idle confirmation must replace the unchanged remote association"
    );
    a.unwrap()
}

#[test]
fn address_change_latches_last_success_independently_without_debounce() {
    let mut refresh = LocalAddressRefresh::default();
    let mut map = HashMap::new();
    let mut rings = RingState::default();
    for (pair, changed, stored) in [
        (sources(0, 0), false, sources(0, 0)),
        (sources(1, 0), false, sources(1, 0)),
        (sources(0, 0), false, sources(1, 0)),
        (sources(0, 1), false, sources(1, 1)),
        (sources(1, 1), false, sources(1, 1)),
        (sources(2, 2), true, sources(2, 2)),
        (sources(2, 2), false, sources(2, 2)),
        (sources(0, 0), false, sources(2, 2)),
        (sources(2, 2), false, sources(2, 2)),
        (sources(3, 0), true, sources(3, 2)),
        (sources(0, 3), true, sources(3, 3)),
    ] {
        assert_eq!(refresh.observe(pair, &mut map, &mut rings), changed);
        assert_eq!(refresh.observed, stored);
    }
}

#[test]
fn address_change_exactly_one_probe_per_public_call_even_expired() {
    let port = free_port();
    let (mut p, _pe) = pump(&key(81), port, 16);
    let probe = Probe::new(port, sources(1, 1));
    p.run_until(Instant::now() - Duration::from_secs(1));
    assert_eq!(probe.calls(), 1);
    p.run_for(Duration::ZERO);
    assert_eq!(probe.calls(), 2);
    drive(&mut p, 15);
    assert_eq!(probe.calls(), 3);
    p.next_wakeup();
    assert_eq!(probe.calls(), 3);
}

#[test]
fn address_change_each_family_reconnects_but_failed_probes_preserve_live_sessions() {
    let a = key(82);
    let b = key(83);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let probe = Probe::new(ap, sources(1, 1));
    let _server_probe = Probe::new(bp, sources(9, 9));
    assert!(pe.try_connect(address(&b, bp)));
    let mut previous = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    for (pair, changed) in [
        (sources(0, 1), false),
        (sources(1, 1), false),
        (sources(2, 1), true),
        (sources(2, 2), true),
        (sources(0, 2), false),
        (sources(2, 2), false),
        (sources(2, 0), false),
        (sources(0, 0), false),
        (sources(2, 2), false),
        (sources(3, 3), true),
        (sources(3, 3), false),
    ] {
        probe.set(pair);
        p.run_for(Duration::ZERO);
        if changed {
            assert!(matches!(
                &drain(&mut pe)[..],
                [RingEvent::Disconnected {
                    reason: DisconnectReason::NetworkChanged,
                    ..
                }]
            ));
            assert!(p.next_wakeup().unwrap() <= Instant::now());
            let fresh = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
            assert_ne!(fresh, previous);
            previous = fresh;
        } else {
            assert!(drain(&mut pe).is_empty());
        }
        drive(&mut p, 5);
        drive(&mut q, 5);
        assert!(drain(&mut pe).is_empty());
        assert!(drain(&mut qe).is_empty());
    }
}

#[test]
fn address_change_remembers_live_incoming_identity_and_admitted_disconnect_stays_cancelled() {
    let a = key(84);
    let b = key(85);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let probe = Probe::new(ap, sources(1, 1));
    let _server_probe = Probe::new(bp, sources(9, 9));
    assert!(qe.try_connect(address(&a, ap)));
    let old = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    probe.set(sources(2, 1));
    p.run_for(Duration::ZERO);
    assert!(matches!(
        &drain(&mut pe)[..],
        [RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        }]
    ));
    let fresh = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    assert_ne!(old, fresh);
    assert!(pe.try_disconnect(address(&b, bp).connection_key()));
    drive(&mut p, 5);
    assert!(matches!(
        &drain(&mut pe)[..],
        [RingEvent::Disconnected {
            reason: DisconnectReason::Local,
            ..
        }]
    ));
    probe.set(sources(3, 1));
    drive(&mut p, 10);
    drive(&mut q, 10);
    assert!(drain(&mut pe).is_empty());
    assert!(drain(&mut qe).is_empty());
}

#[test]
fn address_change_full_capacity_one_ring_preserves_boundary_and_queued_cancellation() {
    let server = key(41);
    let client = key(19);
    let port = free_port();
    let (mut p, mut app) = pump(&server, port, 1);
    let probe = Probe::new(port, sources(1, 1));
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let raw = socket();
    let (h, original) = hello_for(&client, &server);
    raw.send_to(&original, addr).unwrap();
    let flight = response(&raw, &mut p);
    let (mut old, hash) = finish(h, &flight);
    raw.send_to(&packet(&mut old, &client, 0, b""), addr)
        .unwrap();
    drive(&mut p, 5);
    assert!(matches!(
        &drain(&mut app)[..],
        [RingEvent::Connected { .. }]
    ));
    let mut s = Server {
        pump: p,
        app,
        key: server,
        addr,
        raw,
        client,
        original,
        old,
        hash,
    };
    let fill = packet(&mut s.old, &s.client, 1, b"before boundary");
    s.send(&fill);
    probe.set(sources(2, 1));
    s.pump.run_for(Duration::ZERO);
    for n in 3..20 {
        probe.set(sources(n, 1));
        s.pump.run_for(Duration::ZERO);
    }
    let peer = address(&s.client, s.raw.local_addr().unwrap().port()).connection_key();
    assert!(s.app.try_disconnect(peer));
    assert!(
        matches!(s.app.try_recv(), Some(RingEvent::Message { data, .. }) if data == b"before boundary")
    );
    drive(&mut s.pump, 3);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    drive(&mut s.pump, 3); // queued cancellation now admitted
    probe.set(sources(30, 1));
    drive(&mut s.pump, 5);
    assert!(drain(&mut s.app).is_empty());
    let mut buf = [0; 10000];
    let mut hellos = 0;
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        hellos += usize::from(n > 6 && load_u48(&buf[..6]) == MAGIC);
    }
    drive(&mut s.pump, 20);
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        assert!(
            n <= 6 || load_u48(&buf[..6]) != MAGIC,
            "cancelled peer restarted again"
        );
    }
    assert!(hellos <= 1);
}

#[test]
fn address_change_retries_pending_handshake_with_fresh_ephemeral_and_no_false_lifecycle() {
    let a = key(86);
    let b = key(87);
    let ap = free_port();
    let raw = socket();
    let bp = raw.local_addr().unwrap().port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let probe = Probe::new(ap, sources(1, 1));
    assert!(pe.try_connect(address(&b, bp)));
    let mut previous = Vec::new();
    let mut buf = [0; 10000];
    for n in 1..7 {
        probe.set(sources(n, 1));
        drive(&mut p, 3);
        let (len, _) = raw.recv_from(&mut buf).unwrap();
        assert_eq!(load_u48(&buf[..6]), MAGIC);
        assert_ne!(&buf[6..38], previous.as_slice());
        previous = buf[6..38].to_vec();
        assert!(
            drain(&mut pe).is_empty(),
            "retried logical connect must not fail or disconnect"
        );
        while raw.recv_from(&mut buf).is_ok() {}
        assert!(len > 38);
    }
    drop(raw);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let _server_probe = Probe::new(bp, sources(9, 9));
    probe.set(sources(8, 1));
    shared_connection(&mut p, &mut pe, &mut q, &mut qe);
}

#[test]
fn address_change_discards_candidates_queues_and_worker_generations() {
    let (mut c, budget, a, b) = live_tracking();
    c.unreliable_send_buffer
        .submit_messages(0, vec![vec![3; 2048]]);
    prepare(&mut c, &budget, &a, &b, 10_000_000_000);
    let generation = std::sync::Arc::new(());
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    c.unreliable_fec[0].package_id = 17;
    c.unreliable_fec[0].state = FecRecvState::Worker {
        tx,
        job: None,
        message_len: 2048,
        block_bytes: 445,
        generation: generation.clone(),
    };
    let completion = FecCompletion {
        connection_key: c.address().connection_key(),
        package_id: 17,
        message: vec![1; 2048],
        reservation: c.receive_budget.reserve(2048).unwrap(),
        decoder_generation: generation,
        connection_generation: c.receive_budget.clone(),
    };
    let peer = c.address().connection_key();
    let mut map = HashMap::from([(peer, c)]);
    let mut rings = RingState::default();
    rings.peers.insert(peer, [7; 64]);
    let mut refresh = LocalAddressRefresh::default();
    let used = budget.used();
    let hash = map[&peer].handshake_hash;
    for pair in [
        sources(0, 0),
        sources(1, 0),
        sources(0, 0),
        sources(0, 1),
        sources(1, 1),
        sources(0, 1),
        sources(1, 0),
    ] {
        assert!(!refresh.observe(pair, &mut map, &mut rings));
        assert_eq!(map.len(), 1);
        assert!(rings.pending.is_empty());
        assert_eq!(rings.peers.get(&peer), Some(&[7; 64]));
        assert!(refresh.waiting.is_empty());
        let retained = &map[&peer];
        assert_eq!(retained.handshake_hash, hash);
        assert!(retained.replacement.is_some());
        assert!(retained.unreliable_send_buffer.has_unsent_data());
        assert!(completion.owns(&retained.unreliable_fec[0], &retained.receive_budget));
        assert_eq!(budget.used(), used);
    }
    assert!(refresh.observe(sources(2, 1), &mut map, &mut rings));
    assert!(map.is_empty());
    assert_eq!(rings.pending.len(), 1);
    let (address, identity, _) = &refresh.waiting[&peer];
    assert_eq!(*identity, b);
    connect_to_endpoint(
        &mut map,
        identity,
        address,
        (100_000, 4096, 65536),
        1,
        &budget,
        32 << 20,
        4096,
    );
    let fresh = &map[&peer];
    assert_eq!(fresh.handshake_hash, [0; 64]);
    assert!(matches!(
        fresh.connection_state,
        ConnectionState::SendingClientHello {
            last_sent_time_ns: 0,
            ..
        }
    ));
    assert!(fresh.replacement.is_none());
    assert!(!fresh.unreliable_send_buffer.has_unsent_data());
    assert!(matches!(fresh.unreliable_fec[0].state, FecRecvState::Empty));
    assert!(!completion.owns(&fresh.unreliable_fec[0], &fresh.receive_budget));
    assert!(budget.used() < 2 * RECEIVE_CONNECTION_BYTES);
    drop(map);
    drop(completion);
    assert_eq!(budget.used(), 0);
}

#[test]
fn address_change_resets_every_known_peer_but_not_unsolicited_half_handshakes() {
    let (c, budget, a, b) = live_tracking();
    let first = c.address().connection_key();
    let mut map = HashMap::from([(first, c)]);
    let mut rings = RingState::default();
    rings.peers.insert(first, [1; 64]);
    for port in [43, 44, 45] {
        connect_to_endpoint(
            &mut map,
            &b,
            &address(&a, port),
            (100_000, 4096, 65536),
            1,
            &budget,
            32 << 20,
            4096,
        );
    }
    let live = address(&a, 43).connection_key();
    map.get_mut(&live).unwrap().connection_state =
        new_connection_state_connected(None, MAGIC, APP, 1);
    rings.peers.insert(live, [2; 64]);
    let requested = address(&a, 44).connection_key();
    rings.connects.insert(requested, address(&a, 44));
    let half = address(&a, 45).connection_key();
    let mut refresh = LocalAddressRefresh::default();
    assert!(!refresh.observe((None, None), &mut map, &mut rings));
    assert!(!refresh.observe(sources(1, 0), &mut map, &mut rings));
    assert!(!refresh.observe(sources(0, 1), &mut map, &mut rings));
    assert_eq!(map.len(), 4);
    assert!(rings.pending.is_empty());
    assert!(refresh.observe(sources(2, 0), &mut map, &mut rings));
    assert!(map.is_empty());
    assert_eq!(refresh.waiting.len(), 3);
    assert!(!refresh.waiting.contains_key(&half));
    assert_eq!(rings.pending.len(), 2);
    assert_eq!(rings.connects.len(), 3);
    assert_eq!(budget.used(), 0);
    // Changing again before any work merely replaces the observation, not the
    // remembered set or its bounded lifecycle notification count.
    assert!(refresh.observe(sources(3, 1), &mut map, &mut rings));
    assert_eq!(refresh.waiting.len(), 3);
    assert_eq!(rings.pending.len(), 2);
    refresh.cancel(&requested);
    assert!(refresh.observe(sources(4, 1), &mut map, &mut rings));
    assert!(!refresh.waiting.contains_key(&requested));
}

#[test]
fn address_change_capacity_one_reconnects_after_full_disconnect_boundary_drains() {
    let a = key(88);
    let b = key(89);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 1);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let probe = Probe::new(ap, sources(1, 1));
    let _server_probe = Probe::new(bp, sources(9, 9));
    assert!(pe.try_connect(address(&b, bp)));
    let old = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    probe.set(sources(2, 1));
    p.run_for(Duration::ZERO); // occupies sole slot with Disconnected
    for _ in 0..3 {
        drive(&mut p, 2);
        drive(&mut q, 2);
    }
    assert!(matches!(
        pe.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    let fresh = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    assert_ne!(old, fresh);
}

#[test]
fn address_change_selected_fallback_is_observed_even_without_a_v6_route() {
    let (c, _budget, _, _) = live_tracking();
    let peer = c.address().connection_key();
    let mut map = HashMap::from([(peer, c)]);
    let mut rings = RingState::default();
    rings.peers.insert(peer, [1; 64]);
    let mut refresh = LocalAddressRefresh::default();
    let routes = sources(1, 0);
    let fallback = sources(0, 1).1;
    let selected = effective_source_addresses(routes, fallback);
    assert_eq!(selected.1, fallback);
    assert!(!refresh.observe(selected, &mut map, &mut rings));
    assert!(!refresh.observe(
        effective_source_addresses(routes, fallback),
        &mut map,
        &mut rings
    ));
    assert!(rings.pending.is_empty());
    let changed = effective_source_addresses(routes, sources(0, 2).1);
    assert!(refresh.observe(changed, &mut map, &mut rings));
    assert_eq!(rings.pending.len(), 1);
    assert!(map.is_empty());
    assert!(!refresh.observe(changed, &mut map, &mut rings));
    assert_eq!(rings.pending.len(), 1);
    // Losing the fallback leaves the last successfully selected source latched.
    assert!(!refresh.observe(
        effective_source_addresses(routes, None),
        &mut map,
        &mut rings
    ));
    assert_eq!(refresh.observed, changed);
    assert!(!refresh.observe(changed, &mut map, &mut rings));
    assert_eq!(rings.pending.len(), 1);
}

#[test]
fn duplicate_connect_established_is_silent_with_full_receive_and_control_rings() {
    let mut s = Server::new(1);
    let remote = address(&s.client, s.raw.local_addr().unwrap().port());
    let peer = remote.connection_key();
    let bytes = packet(&mut s.old, &s.client, 1, b"fills receive ring");
    s.send(&bytes);
    for _ in 0..16 {
        assert!(s.app.try_connect(remote.clone()));
    }
    assert!(!s.app.try_connect(remote.clone())); // arm the full-input wakeup path
    let mut outgoing = b"send behind ignored controls".to_vec();
    assert!(s.app.try_send(peer, 0, Dscp::Af21, &mut outgoing));
    drive(&mut s.pump, 10);
    assert_eq!(
        s.app.stats().sent,
        1,
        "ignored controls must not starve sends"
    );
    assert!(matches!(
        &drain(&mut s.app)[..],
        [RingEvent::Message { data, .. }] if data == b"fills receive ring"
    ));
    for _ in 0..16 {
        assert!(
            s.app.try_connect(remote.clone()),
            "control space was not returned"
        );
    }
    drive(&mut s.pump, 5);
    assert!(drain(&mut s.app).is_empty());
    let bytes = packet(&mut s.old, &s.client, 2, b"same association survives");
    s.send(&bytes);
    assert!(matches!(
        &drain(&mut s.app)[..],
        [RingEvent::Message { data, .. }] if data == b"same association survives"
    ));
    assert!(s.app.try_disconnect(peer));
    drive(&mut s.pump, 5);
    assert!(matches!(
        &drain(&mut s.app)[..],
        [RingEvent::Disconnected { peer: p, reason: DisconnectReason::Local }] if *p == peer
    ));
}

#[test]
fn duplicate_connect_pending_preserves_original_noise_handshake_and_one_success() {
    let client = key(90);
    let server = key(91);
    let port = free_port();
    let raw = socket();
    let remote = address(&server, raw.local_addr().unwrap().port());
    let (mut p, mut app) = pump(&client, port, 16);
    let _probe = Probe::new(port, sources(1, 1));
    assert!(app.try_connect(remote.clone()));
    drive(&mut p, 20);
    let mut buf = [0; 10000];
    let (len, client_addr) = raw.recv_from(&mut buf).unwrap();
    let original = buf[..len].to_vec();
    for _ in 0..3 {
        for _ in 0..16 {
            assert!(app.try_connect(remote.clone()));
        }
        drive(&mut p, 5);
        assert!(drain(&mut app).is_empty());
        while let Ok((n, _)) = raw.recv_from(&mut buf) {
            assert_eq!(
                &buf[..n],
                original,
                "duplicate recreated the Noise ephemeral"
            );
        }
    }
    // Complete the originally captured hello, not a later/recreated handshake.
    let mut h = noise_responder(
        crypto_string_from_connect_magic1(MAGIC).unwrap(),
        &original[..6],
        &server.private,
    )
    .unwrap();
    assert_eq!(
        h.read_message(&original[6..], &mut buf).unwrap(),
        MAGIC2_BLOCK_SIZE
    );
    let mut reply = [0; 1024];
    store_u48(
        &mut reply[..6],
        0xffff_ffff_0000 | (load_u16(&server.public[..2]) << 1) as u64,
    );
    let n = h
        .write_message(&APP.to_le_bytes(), &mut reply[6..])
        .unwrap();
    let hash = get_handshake_hash(&h);
    raw.send_to(&reply[..6 + n], client_addr).unwrap();
    drive(&mut p, 5);
    assert!(matches!(
        &drain(&mut app)[..],
        [RingEvent::Connected { address, handshake_hash, .. }] if *address == remote && *handshake_hash == hash
    ));
    raw.send_to(&reply[..6 + n], client_addr).unwrap();
    assert!(app.try_connect(remote));
    drive(&mut p, 5);
    assert!(drain(&mut app).is_empty());
}

#[test]
fn duplicate_connect_pending_cancels_silently_and_preserves_invalid_outcome() {
    let client = key(92);
    let server = key(93);
    let port = free_port();
    let raw = socket();
    let remote = address(&server, raw.local_addr().unwrap().port());
    let (mut p, mut app) = pump(&client, port, 16);
    let _probe = Probe::new(port, sources(1, 1));
    assert!(app.try_connect(remote.clone()));
    for _ in 0..15 {
        let mut duplicate = remote.clone();
        duplicate.magic1 = 0; // Same peer: ignore before validating a new attempt.
        assert!(app.try_control(Control::Connect(duplicate)));
    }
    drive(&mut p, 5);
    assert!(drain(&mut app).is_empty());
    assert!(app.try_disconnect(remote.connection_key()));
    let invalid = address(&client, remote.port);
    assert!(app.try_connect(invalid.clone()));
    drive(&mut p, 5);
    assert!(matches!(
        &drain(&mut app)[..],
        [RingEvent::ConnectFailed { address, reason: ConnectFailure::InvalidAddress }]
            if *address == invalid
    ));
    drive(&mut p, 5);
    assert!(drain(&mut app).is_empty());
}

#[test]
fn duplicate_connect_scheduled_restart_preserves_one_fresh_connection() {
    let a = key(94);
    let b = key(95);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let probe = Probe::new(ap, sources(1, 1));
    let _server_probe = Probe::new(bp, sources(9, 9));
    let remote = address(&b, bp);
    assert!(pe.try_connect(remote.clone()));
    let old = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    probe.set(sources(2, 1));
    p.run_for(Duration::ZERO); // Retired association is in refresh.waiting, not the map.
    for _ in 0..16 {
        assert!(pe.try_connect(remote.clone()));
    }
    assert!(matches!(
        &drain(&mut pe)[..],
        [RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        }]
    ));
    let fresh = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    assert_ne!(old, fresh);
    drive(&mut p, 5);
    drive(&mut q, 5);
    assert!(drain(&mut pe).is_empty());
    assert!(drain(&mut qe).is_empty());
}

#[test]
fn duplicate_connect_scheduled_pending_restart_keeps_original_cancellation() {
    let a = key(96);
    let b = key(97);
    let port = free_port();
    let raw = socket();
    let remote = address(&b, raw.local_addr().unwrap().port());
    let (mut p, mut app) = pump(&a, port, 16);
    let probe = Probe::new(port, sources(1, 1));
    assert!(app.try_connect(remote.clone()));
    drive(&mut p, 20);
    let mut buf = [0; 10000];
    assert!(raw.recv_from(&mut buf).is_ok());
    while raw.recv_from(&mut buf).is_ok() {}
    probe.set(sources(2, 1));
    p.run_for(Duration::ZERO);
    for _ in 0..15 {
        assert!(app.try_connect(remote.clone()));
    }
    assert!(app.try_disconnect(remote.connection_key()));
    drive(&mut p, 10);
    assert!(drain(&mut app).is_empty());
    assert!(
        raw.recv_from(&mut buf).is_err(),
        "cancelled restart constructed/sent a hello"
    );
    drive(&mut p, 5);
    assert!(drain(&mut app).is_empty());
}

#[test]
fn duplicate_connect_pending_does_not_extend_original_thirty_second_timeout() {
    let a = key(98);
    let b = key(99);
    let port = free_port();
    let raw = socket();
    let remote = address(&b, raw.local_addr().unwrap().port());
    let (mut p, mut app) = pump(&a, port, 16);
    let _probe = Probe::new(port, sources(1, 1));
    assert!(app.try_connect(remote.clone()));
    drive(&mut p, 20);
    let mut buf = [0; 10000];
    let (n, _) = raw.recv_from(&mut buf).unwrap();
    let original = buf[..n].to_vec();
    while let Ok((n, _)) = raw.recv_from(&mut buf) {
        assert_eq!(&buf[..n], original);
    }
    // No virtual protocol clock: put duplicates near the real frozen deadline.
    // Resetting either creation time or ownership would defer failure to ~58 s.
    std::thread::sleep(Duration::from_secs(28));
    for _ in 0..16 {
        assert!(app.try_connect(remote.clone()));
    }
    drive(&mut p, 3000);
    assert!(matches!(
        &drain(&mut app)[..],
        [RingEvent::ConnectFailed { address, reason: ConnectFailure::TimedOut }] if *address == remote
    ));
    while let Ok((n, _)) = raw.recv_from(&mut buf) {
        assert_eq!(
            &buf[..n],
            original,
            "duplicate changed the pending handshake"
        );
    }
    drive(&mut p, 5);
    assert!(drain(&mut app).is_empty());
}

#[test]
fn address_change_started_restart_timeout_has_one_terminal_outcome_under_backpressure() {
    let server = key(41);
    let client = key(19);
    let port = free_port();
    let (mut p, mut app) = pump(&server, port, 1);
    let probe = Probe::new(port, sources(1, 1));
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let raw = socket();
    let (h, original) = hello_for(&client, &server);
    raw.send_to(&original, addr).unwrap();
    let flight = response(&raw, &mut p);
    let (mut old, hash) = finish(h, &flight);
    raw.send_to(&packet(&mut old, &client, 0, b""), addr)
        .unwrap();
    drive(&mut p, 5);
    assert!(matches!(app.try_recv(), Some(RingEvent::Connected { .. })));
    let mut s = Server {
        pump: p,
        app,
        key: server,
        addr,
        raw,
        client,
        original,
        old,
        hash,
    };
    let remote = address(&s.client, s.raw.local_addr().unwrap().port());
    let fill = packet(&mut s.old, &s.client, 1, b"before reset");
    s.send(&fill); // sole event slot is occupied by old-association data
    probe.set(sources(2, 1));
    s.pump.run_for(Duration::ZERO);
    drive(&mut s.pump, 5); // automatic handshake starts behind pending Disconnected
    let mut buf = [0; 10000];
    let mut saw_restart = false;
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        saw_restart |= n > 6 && load_u48(&buf[..6]) == MAGIC;
    }
    assert!(saw_restart, "automatic handshake did not actually start");
    assert!(
        matches!(s.app.try_recv(), Some(RingEvent::Message { data, .. }) if data == b"before reset")
    );
    drive(&mut s.pump, 5); // Disconnected now occupies the sole slot

    // An ordinary pending request must keep its existing owner, not acquire a
    // second failure when its handshake is also restarted by a source change.
    let pending_raw = socket();
    let pending = address(&key(101), pending_raw.local_addr().unwrap().port());
    assert!(s.app.try_connect(pending.clone()));
    drive(&mut s.pump, 5);
    assert!(pending_raw.recv_from(&mut buf).is_ok());
    probe.set(sources(3, 1));
    drive(&mut s.pump, 5); // restart both logical attempts without extending their deadlines
    probe.set(sources(4, 1));
    drive(&mut s.pump, 5); // repeated resets must retain ownership, not add events
    while s.raw.recv_from(&mut buf).is_ok() {}
    while pending_raw.recv_from(&mut buf).is_ok() {}

    // A successful automatic restart must release the same terminal ownership;
    // passing its old handshake deadline must not produce a stale failure.
    let a = key(102);
    let b = key(103);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 16);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let success_probe = Probe::new(ap, sources(1, 1));
    let _remote_probe = Probe::new(bp, sources(9, 9));
    assert!(pe.try_connect(address(&b, bp)));
    let old_hash = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    success_probe.set(sources(2, 1));
    p.run_for(Duration::ZERO);
    assert!(matches!(
        pe.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    let fresh_hash = shared_connection(&mut p, &mut pe, &mut q, &mut qe);
    assert_ne!(old_hash, fresh_hash);

    // No virtual protocol clock: let the unchanged frozen 30 s timeout elapse.
    // Keep NetworkChanged in the full ring while both failures become pending.
    std::thread::sleep(Duration::from_secs(31));
    drive(&mut s.pump, 20);
    assert!(s.app.try_disconnect(remote.connection_key()));
    assert!(s.app.try_disconnect(pending.connection_key()));
    drive(&mut s.pump, 5); // Already committed genuine timeouts cannot be withdrawn.
    assert!(matches!(s.app.try_recv(), Some(RingEvent::Disconnected {
        peer, reason: DisconnectReason::NetworkChanged
    }) if peer == remote.connection_key()));
    let mut failures = Vec::new();
    for _ in 0..3 {
        drive(&mut s.pump, 5);
        failures.extend(drain(&mut s.app));
    }
    assert_eq!(
        failures.len(),
        2,
        "one terminal event per started logical attempt"
    );
    for expected in [&remote, &pending] {
        assert_eq!(
            failures
                .iter()
                .filter(|e| matches!(e,
            RingEvent::ConnectFailed { address, reason: ConnectFailure::TimedOut }
            if address == expected))
                .count(),
            1
        );
    }
    // Expiry is terminal: do not automatically restart again or emit a late
    // Disconnected/ConnectFailed on later calls or another source change.
    while s.raw.recv_from(&mut buf).is_ok() {}
    while pending_raw.recv_from(&mut buf).is_ok() {}
    probe.set(sources(5, 1));
    drive(&mut s.pump, 20);
    assert!(drain(&mut s.app).is_empty());
    assert!(s.raw.recv_from(&mut buf).is_err());
    assert!(pending_raw.recv_from(&mut buf).is_err());
    drive(&mut p, 5);
    drive(&mut q, 5);
    assert!(drain(&mut pe).is_empty(), "successful restart failed late");
    assert!(drain(&mut qe).is_empty());
}

struct RefreshClock(u16);
impl RefreshClock {
    fn new(port: u16, now: u64) -> Self {
        REFRESH_CLOCKS.with(|clocks| {
            assert!(clocks.borrow_mut().insert(port, now).is_none());
        });
        Self(port)
    }
    fn set(&self, now: u64) {
        REFRESH_CLOCKS.with(|clocks| *clocks.borrow_mut().get_mut(&self.0).unwrap() = now);
    }
}
impl Drop for RefreshClock {
    fn drop(&mut self) {
        REFRESH_CLOCKS.with(|clocks| clocks.borrow_mut().remove(&self.0));
    }
}

fn cancel_started_automatic_restart(reschedule: bool) {
    let port = free_port();
    let probe = Probe::new(port, sources(1, 1));
    let mut s = Server::at_port(1, key(19), port);
    let started = monotonic_clock_ns();
    let clock = RefreshClock::new(port, started);
    let remote = address(&s.client, s.raw.local_addr().unwrap().port());
    let fill = packet(&mut s.old, &s.client, 1, b"before cancellation");
    s.send(&fill);
    probe.set(sources(2, 1));
    s.pump.run_for(Duration::ZERO);
    drive(&mut s.pump, 5); // Start while NetworkChanged waits behind the full ring.
    let mut buf = [0; 10000];
    let mut saw_hello = false;
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        saw_hello |= n > 6 && load_u48(&buf[..6]) == MAGIC;
    }
    assert!(saw_hello, "automatic attempt must actually have started");
    if reschedule {
        clock.set(started + 10_000_000_000);
        probe.set(sources(3, 1));
        s.pump.run_for(Duration::ZERO); // Started attempt is waiting again.
    }
    for _ in 0..15 {
        assert!(s.app.try_connect(remote.clone()));
    }
    assert!(s.app.try_disconnect(remote.connection_key()));
    assert!(!s.app.try_disconnect(remote.connection_key())); // Full control ring.
    drive(&mut s.pump, 5); // Pending boundary still blocks control admission.
    assert!(
        matches!(s.app.try_recv(), Some(RingEvent::Message { data, .. })
        if data == b"before cancellation")
    );
    drive(&mut s.pump, 5);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::Disconnected {
        peer, reason: DisconnectReason::NetworkChanged
    }) if peer == remote.connection_key()));
    drive(&mut s.pump, 5);
    assert!(drain(&mut s.app).is_empty(), "cancellation must be silent");
    while s.raw.recv_from(&mut buf).is_ok() {}
    clock.set(started + 31_000_000_000);
    for n in 4..7 {
        probe.set(sources(n, 1));
        drive(&mut s.pump, 5);
        assert!(drain(&mut s.app).is_empty());
        assert!(
            s.raw.recv_from(&mut buf).is_err(),
            "cancelled peer resurrected"
        );
    }
}

#[test]
fn address_change_started_automatic_restart_cancels_silently() {
    cancel_started_automatic_restart(false);
}

#[test]
fn address_change_rescheduled_started_automatic_restart_cancels_silently() {
    cancel_started_automatic_restart(true);
}

#[test]
fn disconnect_after_success_preserves_connected_then_local_with_capacity_one() {
    let a = key(104);
    let b = key(105);
    let ap = free_port();
    let bp = free_port();
    let (mut p, mut pe) = pump(&a, ap, 1);
    let (mut q, mut qe) = pump(&b, bp, 16);
    let probe = Probe::new(ap, sources(1, 1));
    let _remote_probe = Probe::new(bp, sources(9, 9));
    let remote = address(&b, bp);
    assert!(pe.try_connect(remote.clone()));
    let until = Instant::now() + Duration::from_secs(3);
    let mut confirmed = false;
    while Instant::now() < until {
        drive(&mut p, 2);
        drive(&mut q, 2);
        confirmed |= drain(&mut qe)
            .iter()
            .any(|e| matches!(e, RingEvent::Connected { .. }));
        if confirmed {
            break;
        }
    }
    assert!(
        confirmed,
        "handshake must succeed before processing Disconnect"
    );
    assert!(pe.try_disconnect(remote.connection_key()));
    drive(&mut p, 5); // Connected occupies the sole slot; Local waits behind it.
    assert!(
        matches!(pe.try_recv(), Some(RingEvent::Connected { address, .. }) if address == remote)
    );
    drive(&mut p, 5);
    assert!(matches!(pe.try_recv(), Some(RingEvent::Disconnected {
        peer, reason: DisconnectReason::Local
    }) if peer == remote.connection_key()));
    probe.set(sources(2, 1));
    drive(&mut p, 5);
    assert!(drain(&mut pe).is_empty());
}

#[test]
fn disconnect_does_not_withdraw_committed_invalid_failure_under_backpressure() {
    let mut s = Server::new(1);
    let fill = packet(&mut s.old, &s.client, 1, b"before failure");
    s.send(&fill);
    let invalid = address(&s.key, s.raw.local_addr().unwrap().port());
    assert!(s.app.try_connect(invalid.clone()));
    drive(&mut s.pump, 5); // Failure is committed pump-side behind Message.
    assert!(s.app.try_disconnect(invalid.connection_key()));
    drive(&mut s.pump, 5);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::Message { .. })));
    drive(&mut s.pump, 5);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::ConnectFailed {
        address, reason: ConnectFailure::InvalidAddress
    }) if address == invalid));
    drive(&mut s.pump, 5);
    assert!(drain(&mut s.app).is_empty());
}

fn resource_stalled_restart_expiry(construct_before_expiry: bool) {
    let port = free_port();
    let probe = Probe::new(port, sources(1, 1));
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(128 << 20);
    let pair = pump_with_budget(&key(41), port, 1, Some(budget.clone()));
    let mut s = Server::with_pump(1, key(19), port, pair);
    let started = monotonic_clock_ns();
    let clock = RefreshClock::new(port, started);
    let remote = address(&s.client, s.raw.local_addr().unwrap().port());
    let fill = packet(&mut s.old, &s.client, 1, b"before stalled reset");
    s.send(&fill);
    probe.set(sources(2, 1));
    s.pump.run_for(Duration::ZERO); // Retire first, then pin all process resources.
    assert_eq!(budget.used(), 0);
    let mut blocked = Some(budget.reserve(budget.limit()).unwrap());
    let mut buf = [0; 10000];
    while s.raw.recv_from(&mut buf).is_ok() {}
    drive(&mut s.pump, 3);
    assert!(
        s.raw.recv_from(&mut buf).is_err(),
        "resource-stalled handshake constructed"
    );
    assert!(
        s.pump.next_wakeup().unwrap() > Instant::now(),
        "stalled wait busy-spins"
    );
    clock.set(started + 29_000_000_000);
    probe.set(sources(3, 1));
    s.pump.run_for(Duration::ZERO); // Repeated change must not reset original start.
    drive(&mut s.pump, 3);
    if construct_before_expiry {
        drop(blocked.take());
        drive(&mut s.pump, 3); // Only one second remains; construction cannot reset it.
        let mut saw_hello = false;
        while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
            saw_hello |= n > 6 && load_u48(&buf[..6]) == MAGIC;
        }
        assert!(
            saw_hello,
            "released resources must allow the delayed handshake"
        );
        probe.set(sources(4, 1));
        s.pump.run_for(Duration::ZERO); // Started and rescheduled: still the same deadline.
    }
    clock.set(started + 30_000_000_000);
    s.pump.run_for(Duration::ZERO); // Expired/zero service still admits no work.
    drive(&mut s.pump, 3); // Genuine failure commits behind pending NetworkChanged.
    assert!(s.app.try_disconnect(remote.connection_key()));
    drive(&mut s.pump, 3); // Cancellation must not withdraw the committed timeout.
    assert!(matches!(s.app.try_recv(), Some(RingEvent::Message { .. })));
    drive(&mut s.pump, 3);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    drive(&mut s.pump, 3);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::ConnectFailed {
        address, reason: ConnectFailure::TimedOut
    }) if address == remote));
    drop(blocked);
    for n in 4..7 {
        probe.set(sources(n, 1));
        drive(&mut s.pump, 3);
        assert!(drain(&mut s.app).is_empty());
        assert!(
            s.raw.recv_from(&mut buf).is_err(),
            "expired schedule resurrected"
        );
    }
}

#[test]
fn address_change_resource_stalled_schedule_expires_once_without_construction() {
    resource_stalled_restart_expiry(false);
}

#[test]
fn address_change_resource_delayed_construction_keeps_original_total_deadline() {
    resource_stalled_restart_expiry(true);
}

#[test]
fn address_change_reference_restart_expires_without_native_lifecycle_ownership() {
    let (c, _budget, _, _) = live_tracking();
    let peer = c.address().connection_key();
    let mut map = HashMap::from([(peer, c)]);
    let mut rings = RingState::default(); // Reference mode never owns native peer events.
    let mut refresh = LocalAddressRefresh::default();
    let scheduled = 100_000_000_000;
    assert!(!refresh.observe_at(sources(1, 1), &mut map, &mut rings, scheduled));
    assert!(refresh.observe_at(sources(2, 1), &mut map, &mut rings, scheduled));
    assert_eq!(
        refresh.waiting[&peer].2, scheduled,
        "live peers start at schedule time"
    );
    assert!(refresh.observe_at(
        sources(3, 1),
        &mut map,
        &mut rings,
        scheduled + 29_000_000_000
    ));
    assert_eq!(
        refresh.waiting[&peer].2, scheduled,
        "repeat changes must not extend it"
    );
    refresh.expire(scheduled + 30_000_000_000, &mut map, &mut rings);
    assert!(refresh.waiting.is_empty());
    assert!(refresh.retrying.is_empty());
    assert!(rings.connects.is_empty());
    assert!(rings.pending.is_empty());
}

#[test]
fn address_change_waiting_restart_refuses_competing_inbound_core_when_resources_free() {
    let port = free_port();
    let probe = Probe::new(port, sources(1, 1));
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(128 << 20);
    let pair = pump_with_budget(&key(41), port, 16, Some(budget.clone()));
    let mut s = Server::with_pump(16, key(19), port, pair);
    let started = monotonic_clock_ns();
    let clock = RefreshClock::new(port, started);
    let remote = address(&s.client, s.raw.local_addr().unwrap().port());
    probe.set(sources(2, 1));
    s.pump.run_for(Duration::ZERO);
    assert!(matches!(
        s.app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    assert_eq!(budget.used(), 0);
    let blocked = budget.reserve(budget.limit()).unwrap();
    // The scheduled constructor fails first; free resources just before the
    // receive batch so an incoming hello could otherwise create the same key.
    REFRESH_RELEASES.with(|releases| {
        assert!(releases.borrow_mut().insert(port, blocked).is_none());
    });
    let (_h, incoming) = hello_for(&s.client, &s.key);
    s.raw.send_to(&incoming, s.addr).unwrap();
    drive(&mut s.pump, 5);
    assert!(REFRESH_RELEASES.with(|releases| !releases.borrow().contains_key(&port)));
    let mut buf = [0; 10000];
    let mut saw_outgoing = false;
    while let Ok((n, _)) = s.raw.recv_from(&mut buf) {
        assert_ne!(n, 62, "waiting peer admitted a competing incoming core");
        saw_outgoing |= n > 6 && load_u48(&buf[..6]) == MAGIC;
    }
    assert!(
        saw_outgoing,
        "scheduled outgoing attempt did not construct after release"
    );
    assert!(drain(&mut s.app).is_empty());
    clock.set(started + 30_000_000_000);
    drive(&mut s.pump, 3);
    assert!(matches!(s.app.try_recv(), Some(RingEvent::ConnectFailed {
        address, reason: ConnectFailure::TimedOut
    }) if address == remote));
    assert!(drain(&mut s.app).is_empty());
}
