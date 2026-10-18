use shielded_transport_pigeon::stp::*;
use shielded_transport_pigeon::pump::{Event, LockfreeEndpoint, RingConfig};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
fn core() -> (Pump, LockfreeEndpoint) {
    new_pump(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0, None, (1_000_000, 4 << 20, 4 << 20), 2_000_000)
}
#[test]
fn endpoint_queues_without_protocol_and_preserves_full_payload() {
    let (mut pump, mut endpoint) = core();
    let mut accepted = 0;
    loop {
        let mut data = vec![42; 100]; let ptr = data.as_ptr();
        if !endpoint.try_send(ConnectionKey::default(), 0, Dscp::BestEffort, &mut data) { assert_eq!(data.as_ptr(), ptr); assert_eq!(data.len(), 100); break; }
        assert!(data.is_empty()); accepted += 1;
    }
    assert_eq!(accepted, RingConfig::default().send); assert_eq!(endpoint.stats().send_dropped_unknown, 0);
    pump.run_for(Duration::from_millis(5)); assert_eq!(endpoint.stats().send_dropped_unknown, accepted as u64);
    assert!(endpoint.try_recv().is_none());
}
#[test]
fn pump_and_single_owner_endpoint_move_between_threads() {
    fn send<T: Send>() {} send::<Pump>(); send::<LockfreeEndpoint>();
    let (mut pump, endpoint) = core(); endpoint.request_protocol_stats();
    pump = std::thread::spawn(move || { pump.run_for(Duration::from_millis(1)); pump }).join().unwrap();
    assert!(endpoint.try_protocol_stats().is_some()); endpoint.request_protocol_stats();
    pump.run_for(Duration::from_millis(1)); assert!(endpoint.try_protocol_stats().is_some());
    let ready = endpoint.readiness(); let mut seen = 0; ready.wait(&mut seen); drop(pump); ready.wait(&mut seen); assert!(endpoint.is_finished());
}
#[test]
fn caller_cancel_bool_loop_exits_and_closes_socket() {
    let (mut pump, endpoint) = core(); let cancel = Arc::new(AtomicBool::new(false)); let worker_cancel = cancel.clone();
    let worker = std::thread::spawn(move || { while !worker_cancel.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(10)); } });
    endpoint.request_protocol_stats(); let end = Instant::now() + Duration::from_secs(1);
    while endpoint.try_protocol_stats().is_none() { assert!(Instant::now() < end); std::thread::yield_now(); }
    let start = Instant::now(); cancel.store(true, Ordering::Release); worker.join().unwrap();
    assert!(start.elapsed() < Duration::from_millis(100)); assert!(endpoint.is_finished());
}
#[test]
fn quiet_pump_parks_instead_of_spinning() {
    let (mut pump, endpoint) = core(); pump.run_for(Duration::from_millis(1));
    let start = Instant::now(); pump.run_for(Duration::from_millis(50));
    assert!(start.elapsed() >= Duration::from_millis(49)); assert!(pump.next_wakeup().unwrap() > start);
    endpoint.request_protocol_stats(); pump.run_for(Duration::from_millis(1));
    let iterations = endpoint.try_protocol_stats().unwrap().thread_stats.loop_iterations;
    assert!(iterations < 20, "idle loop spun {iterations} times");
}
#[test]
fn expired_deadline_does_no_work() {
    let (mut pump, endpoint) = core(); endpoint.request_protocol_stats();
    pump.run_until(Instant::now() - Duration::from_secs(1)); assert!(endpoint.try_protocol_stats().is_none());
}
#[test]
fn deadlines_under_encrypted_fec_load_deliver_messages() {
    let socket = std::net::UdpSocket::bind("[::1]:0").unwrap(); let port = socket.local_addr().unwrap().port(); drop(socket);
    let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b).unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key); let peer = address.connection_key();
    let (mut receiver, mut rx) = new_pump(vec![key], port, Some(10_000), (1_000_000, 8 << 20, 8 << 20), 2_000_000);
    let (mut sender, mut tx) = new_pump(vec![new_keypair_from_connect_magic1(address.magic1).unwrap()], 0, Some(10_000), (1_000_000, 8 << 20, 8 << 20), 2_000_000);
    assert!(tx.try_connect(address)); let mut connected = false; let mut received = 0; let mut overshoots = Vec::new();
    let end = Instant::now() + Duration::from_secs(10);
    while received < 2 || overshoots.len() < 2000 {
        assert!(Instant::now() < end, "received {received}/2");
        for pump in [&mut sender, &mut receiver] { let deadline = Instant::now() + Duration::from_micros(100); pump.run_until(deadline); overshoots.push(Instant::now().saturating_duration_since(deadline)); }
        while let Some(event) = tx.try_recv() {
            if matches!(event, Event::Connected { .. }) && !connected {
                connected = true;
                for size in [1_000_000, 2_000_000] { assert!(tx.try_send(peer, 0, Dscp::BestEffort, &mut vec![7; size])); }
            }
        }
        while let Some(event) = rx.try_recv() { if let Event::Message { data, .. } = event { assert!(data.len() == 1_000_000 || data.len() == 2_000_000); assert!(data.iter().all(|b| *b == 7)); received += 1; } }
    }
    overshoots.sort();
    println!("pump deadline: samples={} budget_us=100 p50_us={} p99_us={} max_us={} delivered={received}/2", overshoots.len(), overshoots[overshoots.len()/2].as_micros(), overshoots[overshoots.len()*99/100].as_micros(), overshoots.last().unwrap().as_micros());
    assert!(*overshoots.last().unwrap() < Duration::from_millis(50));
}
