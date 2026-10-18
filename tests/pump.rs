use shielded_transport_pigeon::stp::*;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

#[test]
fn connected_reference_exchange_batch_cost_is_reported() {
    for (count, bytes) in [(64, 1_000_000), (1000, 100)] {
        let mut worst = 0u64;
        for _ in 0..10 {
            let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
            let port = socket.local_addr().unwrap().port(); drop(socket);
            let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap();
            let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
            let (mut receiver, rx) = new_pump(vec![key], port, None, (1_000_000, 128 << 20, 128 << 20), 2_000_000);
            let (mut sender, tx) = new_pump(vec![new_keypair_from_connect_magic1(address.magic1).unwrap()], 0,
                None, (1_000_000, 128 << 20, 128 << 20), 2_000_000);
            tx.submit(NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).ok().unwrap();
            let end = Instant::now() + Duration::from_secs(1);
            let mut wanted_tx = Vec::new(); let mut wanted_rx = Vec::new();
            let mut tx_pending = true; let mut rx_pending = false;
            while wanted_tx.is_empty() || wanted_rx.is_empty() {
                assert!(Instant::now() < end);
                sender.run_for(Duration::from_micros(500)); receiver.run_for(Duration::from_micros(500));
                if let Some(response) = tx.try_take() { wanted_tx = response.current_connections; tx_pending = false; }
                if let Some(response) = rx.try_take() { wanted_rx = response.current_connections; rx_pending = false; }
                if !tx_pending && wanted_tx.is_empty() {
                    tx.submit(NetworkThreadPush::default()).ok().unwrap(); tx_pending = true;
                }
                if !rx_pending && wanted_rx.is_empty() {
                    rx.submit(NetworkThreadPush::default()).ok().unwrap(); rx_pending = true;
                }
            }
            let key = wanted_tx[0].0.connection_key();
            let messages = (0..count).map(|_| (key, 0, Dscp::BestEffort, vec![7; bytes])).collect();
            tx.submit(NetworkThreadPush { wanted_connections: wanted_tx, send_unreliable: messages, ..Default::default() }).ok().unwrap();
            loop {
                sender.run_for(Duration::from_micros(100));
                if let Some(response) = tx.try_take() {
                    assert!(response.send_unreliable_rejected.is_empty());
                    assert!(response.send_unreliable_oversized.is_empty());
                    worst = worst.max(response.exchange_processing_ns);
                    break;
                }
                assert!(Instant::now() < end);
            }
        }
        println!("reference_exchange count={count} bytes_each={bytes} path=connected_admission repetitions=10 max_service_us={}", worst/1000);
    }
}

#[test]
fn reference_exchange_batch_cost_is_reported() {
    for (count, bytes) in [(64, 1_000_000), (1000, 100)] {
        let mut worst = Duration::ZERO;
        let mut worst_overshoot = Duration::ZERO;
        for _ in 0..10 {
            let (mut pump, endpoint) = core();
            let messages = (0..count).map(|_| (ConnectionKey::default(), 0, Dscp::BestEffort, vec![7; bytes])).collect();
            endpoint.submit(NetworkThreadPush { send_unreliable: messages, ..Default::default() }).ok().unwrap();
            let start = Instant::now();
            loop {
                let deadline = Instant::now() + Duration::from_micros(100);
                pump.run_until(deadline);
                worst_overshoot = worst_overshoot.max(Instant::now().saturating_duration_since(deadline));
                if let Some(response) = endpoint.try_take() {
                    worst = worst.max(Duration::from_nanos(response.exchange_processing_ns));
                    assert_eq!(response.send_unreliable_rejected.len(), count);
                    break;
                }
                assert!(start.elapsed() < Duration::from_secs(1));
            }
        }
        println!("reference_exchange count={count} bytes_each={bytes} path=unknown_peer_rejection repetitions=10 max_service_us={} max_overshoot_us={}", worst.as_micros(), worst_overshoot.as_micros());
    }
}

fn core() -> (Pump, Endpoint) {
    new_pump(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0,
        None, (1_000_000, 4 << 20, 4 << 20), 2_000_000)
}

#[test]
fn endpoint_queues_without_running_protocol_and_preserves_backpressure_ownership() {
    let (mut pump, endpoint) = core();
    let mut data = vec![42; 100];
    let ptr = data.as_mut_ptr();
    endpoint.submit(NetworkThreadPush { send_unreliable: vec![(ConnectionKey::default(), 0, Dscp::BestEffort, data)], ..Default::default() }).ok().unwrap();
    assert!(endpoint.try_take().is_none());
    assert!(endpoint.submit(NetworkThreadPush::default()).is_err());
    pump.run_for(Duration::from_millis(1));
    let response = endpoint.try_take().unwrap();
    assert_eq!(response.send_unreliable_rejected.len(), 1);
    assert_eq!(response.send_unreliable_rejected[0].3.as_ptr(), ptr);
    assert_eq!(response.send_unreliable_rejected[0].3, vec![42; 100]);
}

#[test]
fn pump_moves_between_threads_and_endpoint_is_concurrent() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<Pump>(); send::<Endpoint>(); sync::<Endpoint>();
    let (mut pump, endpoint) = core();
    endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
    pump = std::thread::spawn(move || { pump.run_for(Duration::from_millis(1)); pump }).join().unwrap();
    assert!(endpoint.try_take().is_some());
    endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
    pump.run_for(Duration::from_millis(1));
    assert!(endpoint.try_take().is_some());
    let ready = endpoint.readiness();
    let mut seen = 0;
    ready.wait(&mut seen);
    drop(pump);
    ready.wait(&mut seen);
    assert!(endpoint.is_finished());
}

#[test]
fn caller_cancel_bool_loop_exits_and_closes_socket() {
    let (mut pump, endpoint) = core();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let worker = std::thread::spawn(move || {
        while !worker_cancel.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(10)); }
    });
    endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
    let end = Instant::now() + Duration::from_secs(1);
    while endpoint.try_take().is_none() { assert!(Instant::now() < end); std::thread::yield_now(); }
    let start = Instant::now();
    cancel.store(true, Ordering::Release);
    worker.join().unwrap();
    assert!(start.elapsed() < Duration::from_millis(100));
    assert!(endpoint.is_finished());
}

#[test]
fn quiet_pump_parks_instead_of_spinning() {
    let (mut pump, endpoint) = core();
    pump.run_for(Duration::from_millis(1)); // setup and first sweep
    let start = Instant::now();
    pump.run_for(Duration::from_millis(50));
    assert!(start.elapsed() >= Duration::from_millis(49));
    assert!(pump.next_wakeup().unwrap() > start);
    endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
    pump.run_for(Duration::from_millis(1));
    let iterations = endpoint.try_take().unwrap().thread_stats.loop_iterations;
    assert!(iterations < 20, "idle loop spun {iterations} times");
}

#[test]
fn expired_deadline_does_no_work() {
    let (mut pump, endpoint) = core();
    endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
    pump.run_until(Instant::now() - Duration::from_secs(1));
    assert!(endpoint.try_take().is_none());
}

#[test]
fn deadlines_under_encrypted_fec_load_deliver_messages() {
    let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let port = socket.local_addr().unwrap().port(); drop(socket);
    let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b).unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
    let (mut receiver, rx) = new_pump(vec![key], port, Some(10_000), (1_000_000, 8 << 20, 8 << 20), 2_000_000);
    let (mut sender, tx) = new_pump(vec![new_keypair_from_connect_magic1(address.magic1).unwrap()], 0,
        Some(10_000), (1_000_000, 8 << 20, 8 << 20), 2_000_000);
    tx.submit(NetworkThreadPush { initiate_connections: vec![address], ..Default::default() }).ok().unwrap();
    let mut wanted_tx = Vec::new(); let mut wanted_rx = Vec::new();
    let mut tx_pending = true; let mut rx_pending = false;
    let mut submitted = false; let mut received = 0; let mut overshoots = Vec::new();
    let end = Instant::now() + Duration::from_secs(10);
    while received < 2 || overshoots.len() < 2000 {
        assert!(Instant::now() < end, "received {received}/2");
        for pump in [&mut sender, &mut receiver] {
            let deadline = Instant::now() + Duration::from_micros(100);
            pump.run_until(deadline);
            overshoots.push(Instant::now().saturating_duration_since(deadline));
        }
        if let Some(response) = tx.try_take() {
            wanted_tx = response.current_connections; tx_pending = false;
            assert!(response.send_unreliable_oversized.is_empty());
            assert!(response.send_unreliable_rejected.is_empty());
        }
        if let Some(response) = rx.try_take() {
            wanted_rx = response.current_connections; rx_pending = false;
            for (_, data) in response.received_unreliable_messages {
                assert!(data.len() == 1_000_000 || data.len() == 2_000_000);
                assert!(data.iter().all(|b| *b == 7));
                received += 1;
            }
        }
        if !tx_pending {
            let send_unreliable = if !submitted && !wanted_tx.is_empty() {
                submitted = true;
                vec![(wanted_tx[0].0.connection_key(), 0, Dscp::BestEffort, vec![7; 1_000_000]),
                     (wanted_tx[0].0.connection_key(), 0, Dscp::BestEffort, vec![7; 2_000_000])]
            } else { Vec::new() };
            tx.submit(NetworkThreadPush { wanted_connections: wanted_tx.clone(), send_unreliable, ..Default::default() }).ok().unwrap();
            tx_pending = true;
        }
        if !rx_pending {
            rx.submit(NetworkThreadPush { wanted_connections: wanted_rx.clone(), ..Default::default() }).ok().unwrap();
            rx_pending = true;
        }
    }
    overshoots.sort();
    println!("pump deadline: samples={} budget_us=100 p50_us={} p99_us={} max_us={} delivered={received}/2 elapsed_ms={}",
        overshoots.len(), overshoots[overshoots.len()/2].as_micros(), overshoots[overshoots.len()*99/100].as_micros(),
        overshoots.last().unwrap().as_micros(), 10_000-end.saturating_duration_since(Instant::now()).as_millis());
    // This is a regression alarm, not an OS real-time guarantee. The observed
    // native-call bound is separately measured by examples/pump_timing.rs.
    assert!(*overshoots.last().unwrap() < Duration::from_millis(50));
}
