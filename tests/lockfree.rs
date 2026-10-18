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
    let (pa, mut a, _) = setup_with(rings, 2000); let (pb, mut b, ab) = setup_with(rings, 2000);
    let _wa = Worker::start(pa); let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, b"one".to_vec()); send(&mut a, peer, b"two".to_vec());
    let end = Instant::now() + Duration::from_secs(5);
    while b.stats().received + b.stats().receive_dropped_full < 2 { assert!(Instant::now() < end); std::thread::yield_now(); }
    assert_eq!(b.stats().received, 1); assert_eq!(b.stats().receive_dropped_full, 1);
    let first = b.try_recv().unwrap(); assert!(matches!(first, Event::Message { .. }));
    // Fill output with one failure then request a disconnect. The latter must
    // wait rather than disappear, and must be ordered after the earlier event.
    assert!(a.try_connect(STPAddress::from(std::net::Ipv6Addr::LOCALHOST, 0, &new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap())));
    assert!(a.try_disconnect(peer));
    let mut failures = 0; let mut disconnected = 0;
    while disconnected == 0 {
        if let Some(event) = a.try_recv() { match event { Event::Disconnected { .. } => disconnected += 1, Event::ConnectFailed { .. } => failures += 1, _ => {} } }
        assert!(Instant::now() < end); std::thread::yield_now();
    }
    // The request may actually start a plaintext handshake: don't assert a
    // timeout in a short test. Its cancellation is covered separately.
    assert!(failures <= 1);
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
    assert!(matches!(b.try_recv(), Some(Event::ConnectFailed { .. })));
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
