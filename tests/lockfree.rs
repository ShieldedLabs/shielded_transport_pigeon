use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
#[path = "../examples/support/lockfree_common.rs"] mod common;
use common::*;
use std::time::{Duration, Instant};

#[test]
fn independent_bool_rings_preserve_payload_on_full_and_close() {
    let (pump, mut ep, addr) = setup_with(RingConfig { send: 1, control: 1, receive: 1 }, 100);
    let mut payload = vec![7; 100]; let ptr = payload.as_ptr();
    assert!(ep.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut payload));
    assert!(payload.is_empty());
    let mut blocked = vec![9; 101]; let blocked_ptr = blocked.as_ptr();
    assert!(!ep.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut blocked));
    assert_eq!(blocked.as_ptr(), blocked_ptr); assert_eq!(blocked, vec![9; 101]);
    assert!(ep.try_connect(addr.clone())); assert!(!ep.try_connect(addr));
    assert!(ep.try_recv().is_none()); ep.close();
    assert!(!ep.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut blocked));
    assert_eq!(blocked.as_ptr(), blocked_ptr); assert_ne!(ptr, blocked_ptr);
    drop(pump); assert!(ep.is_finished()); assert!(!ep.park_until_ready());
}

#[test]
fn invalid_sends_are_counted_without_events() {
    let (mut pump, mut ep, _) = setup_with(RingConfig::default(), 100);
    send(&mut ep, ConnectionKey::default(), vec![1; 100]);
    send(&mut ep, ConnectionKey::default(), vec![1; 101]);
    pump.run_for(Duration::from_millis(5));
    let stats = ep.stats(); assert_eq!(stats.send_dropped_unknown, 1); assert_eq!(stats.send_dropped_oversized, 1);
    assert!(ep.try_recv().is_none());
}

#[test]
fn encrypted_bidirectional_roundtrip_on_caller_threads() {
    let (pa, mut a, aa) = setup(); let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, vec![17; 1_000_000]); let inbound = receive(&mut b, 1);
    assert_eq!(inbound[0], (aa.connection_key(), vec![17; 1_000_000]));
    send(&mut b, inbound[0].0, b"reply".to_vec()); assert_eq!(receive(&mut a, 1)[0].1, b"reply");
}

#[test]
fn lifecycle_order_and_exactly_once_disconnect() {
    let (pa, mut a, aa) = setup(); let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    let peer = ab.connection_key(); assert!(a.try_connect(ab));
    let end = Instant::now() + Duration::from_secs(5);
    let mut outcomes = 0; let mut a_connected = false;
    while !a_connected {
        if let Some(event) = a.try_recv() {
            match event { Event::Connected { .. } => { a_connected = true; outcomes += 1; }, Event::ConnectFailed { .. } => panic!("failed connect"), _ => panic!("unexpected event") }
        }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    send(&mut a, peer, b"ordered".to_vec());
    let mut connected = false; let mut message = false;
    while !message {
        if let Some(event) = b.try_recv() {
            match event {
                Event::Connected { peer, .. } => { assert_eq!(peer, aa.connection_key()); assert!(!connected); connected = true; },
                Event::Message { data, .. } => { assert!(connected); assert_eq!(data, b"ordered"); message = true; },
                _ => panic!("unexpected event"),
            }
        }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    assert!(a.try_disconnect(peer)); assert!(a.try_disconnect(peer));
    let mut disconnected = 0;
    while disconnected == 0 {
        if let Some(event) = a.try_recv() { match event { Event::Disconnected { peer: p, reason: DisconnectReason::Local } => { assert_eq!(p, peer); disconnected += 1; }, Event::Message { .. } => panic!("late message"), _ => outcomes += 1 } }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    // A local disconnect has no wire close. Do not let the remote initiate a new
    // connection while checking that the cancelled association stays silent.
    send(&mut b, aa.connection_key(), b"late old-association data".to_vec());
    std::thread::sleep(Duration::from_millis(20));
    while let Some(event) = a.try_recv() { assert!(!matches!(event, Event::Disconnected { .. } | Event::Message { .. })); }
    assert_eq!(disconnected, 1); assert_eq!(outcomes, 1);
}

#[test]
fn every_connect_request_has_one_outcome_including_duplicates_and_invalid() {
    let (pa, mut a, _) = setup(); let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    connect(&mut a, &mut b, ab.clone());
    assert!(a.try_connect(ab.clone())); assert!(a.try_connect(ab));
    let end = Instant::now() + Duration::from_secs(5); let mut outcomes = 0;
    while outcomes < 2 {
        if let Some(event) = a.try_recv() { assert!(matches!(event, Event::ConnectFailed { reason: ConnectFailure::AlreadyConnected, .. })); outcomes += 1; }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    assert!(a.try_recv().is_none());
}

#[test]
fn receive_full_drops_data_but_preserves_disconnect() {
    let rings = RingConfig { send: 128, control: 8, receive: 1 };
    let (pa, mut a, aa) = setup_with(rings, 2000); let (pb, mut b, ab) = setup_with(rings, 2000);
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, b"one".to_vec()); send(&mut a, peer, b"two".to_vec());
    let end = Instant::now() + Duration::from_secs(5);
    while b.stats().received + b.stats().receive_dropped_full < 2 { assert!(Instant::now() < end); std::thread::yield_now(); }
    assert_eq!(b.stats().received, 1); assert_eq!(b.stats().receive_dropped_full, 1);
    let first = b.try_recv().unwrap(); assert!(matches!(first, Event::Message { .. }));
    // Fill output with one failure then request a disconnect. The latter must
    // wait rather than disappear, and must be ordered after the earlier event.
    assert!(a.try_connect(aa));
    assert!(a.try_disconnect(peer));
    std::thread::sleep(Duration::from_millis(20));
    let mut failures = 0; let mut disconnected = 0;
    while disconnected == 0 {
        if let Some(event) = a.try_recv() { match event { Event::Disconnected { .. } => disconnected += 1, Event::ConnectFailed { .. } => failures += 1, _ => {} } }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    assert_eq!(failures, 1);
}

#[test]
fn inbound_handshake_waits_for_receive_space_then_retries() {
    let rings = RingConfig { send: 8, control: 8, receive: 1 };
    let (pa, mut a, _) = setup_with(rings, 1000); let (pb, mut b, ab) = setup_with(rings, 1000);
    // A self-connect is invalid, deterministically filling b's receive ring.
    assert!(b.try_connect(ab.clone()));
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    assert!(a.try_connect(ab));
    let end = Instant::now() + Duration::from_secs(8);
    while b.stats().inbound_refused_full == 0 { assert!(Instant::now() < end); std::thread::yield_now(); }
    let refusal = loop {
        if let Some(event) = b.try_recv() { break event; }
        assert!(Instant::now() < end); std::thread::yield_now();
    };
    assert!(matches!(refusal, Event::ConnectFailed { .. }));
    let mut ca = false; let mut cb = false;
    while !ca || !cb {
        if let Some(event) = a.try_recv() { ca |= matches!(event, Event::Connected { .. }); }
        if let Some(event) = b.try_recv() { cb |= matches!(event, Event::Connected { .. }); }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
}

#[test]
fn park_wakes_for_send_space_without_other_traffic_and_pump_drop() {
    let (mut pump, mut ep, _) = setup_with(RingConfig { send: 1, control: 1, receive: 1 }, 100);
    send(&mut ep, ConnectionKey::default(), vec![1]); let mut blocked = vec![2];
    assert!(!ep.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut blocked));
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || { assert!(ep.park_until_ready()); tx.send(ep).unwrap(); });
    pump.run_for(Duration::from_millis(5));
    let mut ep = rx.recv_timeout(Duration::from_secs(2)).unwrap(); waiter.join().unwrap();
    assert!(ep.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut blocked));
    drop(pump); assert!(ep.is_finished()); assert!(!ep.park_until_ready());
}

#[test]
fn park_for_receive_and_close() {
    let (pa, mut a, _) = setup(); let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab); send(&mut a, peer, b"park".to_vec());
    loop { if let Some(Event::Message { data, .. }) = b.try_recv() { assert_eq!(data, b"park"); break; } assert!(b.park_until_ready()); }
    a.close(); assert!(!a.park_until_ready());
}

#[test]
fn game_loop_driving_delivers_and_orders_events() {
    let (mut pa, mut a, _) = setup(); let (mut pb, mut b, ab) = setup();
    let peer = ab.connection_key(); assert!(a.try_connect(ab));
    let mut ca = false; let mut cb = false; let mut sent = false; let mut got = false;
    for _ in 0..400 {
        let frame = Instant::now(); pa.run_until(frame + Duration::from_millis(1)); pb.run_for(Duration::from_millis(1));
        while let Some(event) = a.try_recv() { ca |= matches!(event, Event::Connected { .. }); }
        while let Some(event) = b.try_recv() { match event { Event::Connected { .. } => cb = true, Event::Message { data, .. } => { assert!(cb); assert_eq!(data, b"frame"); got = true; }, _ => {} } }
        if ca && cb && !sent { send(&mut a, peer, b"frame".to_vec()); sent = true; }
        if got { break; }
        std::thread::sleep((frame + Duration::from_millis(16)).saturating_duration_since(Instant::now()));
    }
    assert!(ca && cb && sent && got);
}

#[test]
fn handle_is_send_but_not_sync() {
    fn require_send<T: Send>() {}
    require_send::<LockfreeEndpoint>();
    // If the handle became Sync, both implementations would apply and the
    // inferred marker would be ambiguous (a compile-time, dependency-free check).
    trait NotSync<Marker> { fn check() {} }
    impl<T: ?Sized> NotSync<()> for T {}
    struct IsSync;
    impl<T: ?Sized + Sync> NotSync<IsSync> for T {}
    let _ = <LockfreeEndpoint as NotSync<_>>::check;
}

#[test]
fn park_wakes_for_control_space_without_an_event() {
    let (mut pump, mut ep, _) = setup_with(RingConfig { send: 1, control: 1, receive: 1 }, 100);
    assert!(ep.try_disconnect(ConnectionKey::default()));
    assert!(!ep.try_disconnect(ConnectionKey::default()));
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || { assert!(ep.park_until_ready()); tx.send(ep).unwrap(); });
    pump.run_for(Duration::from_millis(5));
    let mut ep = rx.recv_timeout(Duration::from_secs(2)).unwrap(); waiter.join().unwrap();
    assert!(ep.try_recv().is_none()); assert!(ep.try_disconnect(ConnectionKey::default()));
    drop(pump);
}

#[test]
fn cancelled_connect_produces_exactly_one_failure() {
    let (mut pump, mut ep, _) = setup();
    let probe = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let addr = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, probe.local_addr().unwrap().port(),
        &new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap());
    assert!(ep.try_connect(addr.clone())); assert!(ep.try_disconnect(addr.connection_key()));
    pump.run_for(Duration::from_millis(5));
    assert!(matches!(ep.try_recv(), Some(Event::ConnectFailed { address, reason: ConnectFailure::Cancelled }) if address == addr));
    assert!(ep.try_recv().is_none());
}

#[test]
fn fifo_credit_blocks_other_peer_until_head_disconnects() {
    let (pa, mut a, _) = {
        let probe = std::net::UdpSocket::bind("[::1]:0").unwrap(); let port = probe.local_addr().unwrap().port(); drop(probe);
        let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
        let addr = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
        let (pump, ep) = new_pump_with_options(vec![key], port, Some(1), (1, 1, 1), 2_000_000,
            NetworkThreadOptions { rings: RingConfig { send: 8, control: 8, receive: 8 }, ..Default::default() });
        (pump, ep, addr)
    };
    let (pb, mut b, ab) = setup(); let (pc, mut c, ac) = setup();
    let _wa = Worker::start(pa); let _wb = Worker::start(pb); let _wc = Worker::start(pc);
    let kb = connect(&mut a, &mut b, ab); let kc = connect(&mut a, &mut c, ac);
    send(&mut a, kb, vec![7; 1_000_000]); send(&mut a, kb, vec![8; 100]); send(&mut a, kc, b"behind head".to_vec());
    let end = Instant::now() + Duration::from_secs(5);
    while a.stats().send_head_blocked == 0 { assert!(Instant::now() < end); std::thread::yield_now(); }
    assert_eq!(a.stats().sent, 1); assert!(c.try_recv().is_none());
    assert!(a.try_disconnect(kb));
    assert_eq!(receive(&mut c, 1)[0].1, b"behind head");
    assert!(a.stats().send_dropped_unknown >= 1);
}

#[test]
fn unreachable_connect_times_out_once_under_frozen_handshake_timer() {
    let (pump, mut ep, _) = setup(); let mut worker = Worker::start(pump);
    let probe = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, probe.local_addr().unwrap().port(),
        &new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap());
    assert!(ep.try_connect(address.clone()));
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        loop {
            if let Some(event) = ep.try_recv() { tx.send((event, ep)).ok(); break; }
            if !ep.park_until_ready() { break; }
        }
    });
    let outcome = rx.recv_timeout(Duration::from_secs(35));
    worker.stop(); waiter.join().unwrap();
    let (event, mut ep) = outcome.expect("frozen 30s handshake timer did not finish");
    assert!(matches!(event, Event::ConnectFailed { address: a, reason: ConnectFailure::TimedOut } if a == address));
    assert!(ep.try_recv().is_none());
}
