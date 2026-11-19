//! Regression tests for the application boundary, its core charge ledger, and live UDP isolation.
use super::*;
use crate::pump::port::lockfree::{PeerSend, SendQueueConfig};
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

fn address(id: u8) -> STPAddress {
    STPAddress {
        ip: Ipv6Addr::LOCALHOST,
        port: 20000 + id as u16,
        magic1: CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b,
        key: vec![id; 32],
    }
}
fn boundary(
    config: SendQueueConfig,
    slots: usize,
    queues: usize,
) -> (Arc<Port>, LockfreeEndpoint, RingState, ConnectionKey) {
    let port = Port::new(1000, queues);
    let mut app = Endpoint {
        inner: port.clone(),
    }
    .into_rings(
        RingConfig {
            send: slots,
            control: 4,
            receive: 8,
        },
        config,
    );
    let mut state = RingState::default();
    let addr = address(1);
    let peer = addr.connection_key();
    assert!(state.connected(&port, addr, [1; 64]));
    assert!(matches!(app.try_recv(), Some(RingEvent::Connected { .. })));
    (port, app, state, peer)
}
fn limits(local: u64, global: u64) -> SendQueueConfig {
    SendQueueConfig {
        per_queue_bytes: Some(local),
        global_bytes: Some(global),
        ..Default::default()
    }
}
fn take(
    state: &RingState,
    peer: ConnectionKey,
    queue: usize,
) -> crate::pump::port::lockfree::SendMessage {
    let association = &state.send_peers[&peer];
    let message = unsafe { association.queues[queue].get().unwrap().ring.pop() }.unwrap();
    association.budget.pending.fetch_sub(1, Ordering::Relaxed);
    association.budget.released();
    message
}
fn send(app: &mut LockfreeEndpoint, peer: ConnectionKey, queue: usize, bytes: usize) {
    assert!(app.try_send(peer, queue, Dscp::BestEffort, &mut vec![7; bytes]));
}
fn rejected_unchanged(app: &mut LockfreeEndpoint, peer: ConnectionKey, queue: usize, bytes: usize) {
    let mut value = Vec::with_capacity(bytes + 13);
    value.resize(bytes, 9);
    let original = (value.as_ptr(), value.len(), value.capacity());
    assert!(!app.try_send(peer, queue, Dscp::BestEffort, &mut value));
    assert_eq!(original, (value.as_ptr(), value.len(), value.capacity()));
    assert!(value.iter().all(|&n| n == 9));
}

#[test]
fn send_lane_limits_exact_global_and_allocation_preservation() {
    let (port, mut app, state, peer) = boundary(limits(10, 15), 8, 2);
    send(&mut app, peer, 0, 10);
    rejected_unchanged(&mut app, peer, 0, 1);
    rejected_unchanged(&mut app, peer, 1, 11); // a permanently over-cap head is never accepted
    send(&mut app, peer, 1, 5);
    rejected_unchanged(&mut app, peer, 1, 1);
    assert_eq!(app.queued_send_bytes(peer, 0), 10);
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .bytes
            .load(Ordering::Relaxed),
        15
    );
    drop(take(&state, peer, 0));
    send(&mut app, peer, 1, 5);
    assert_eq!(app.queued_send_bytes(peer, 1), 10);
}

#[test]
fn send_lane_core_transfer_partial_staging_count_and_drop() {
    let (port, mut app, state, peer) = boundary(limits(10, 10), 8, 1);
    let budget = &port.native.get().unwrap().budget;
    send(&mut app, peer, 0, 10);
    let message = take(&state, peer, 0);
    let mut ledger = QueuedLedger::default();
    ledger.admit(message.charge);
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 10); // ring -> core is not retirement
    assert_eq!(budget.messages.load(Ordering::Relaxed), 1);
    rejected_unchanged(&mut app, peer, 0, 1);
    ledger.framed = Some(7);
    ledger.retire(6, false); // non-final segmented codec unit
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 10);
    ledger.commit(7);
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 4);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 1);
    ledger.framed = Some(8);
    ledger.retire(4, true);
    ledger.commit(7);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 1);
    ledger.commit(8); // a local UDP drop uses this same unconditional commit path
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 0);
    assert!(ledger.cell.is_none());
    send(&mut app, peer, 0, 3);
    ledger.admit(take(&state, peer, 0).charge);
    drop(ledger); // connection teardown releases the rest exactly once
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 0);
}

#[test]
fn send_lane_empty_and_tiny_messages_share_core_count_cap() {
    let config = SendQueueConfig {
        max_queued_messages: 2,
        ..limits(10, 20)
    };
    let (port, mut app, state, peer) = boundary(config, 8, 2);
    send(&mut app, peer, 0, 0);
    send(&mut app, peer, 1, 1);
    let mut ledger = QueuedLedger::default();
    ledger.admit(take(&state, peer, 0).charge);
    rejected_unchanged(&mut app, peer, 0, 0);
    rejected_unchanged(&mut app, peer, 1, 1);
    ledger.framed = Some(2);
    ledger.retire(0, true);
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .messages
            .load(Ordering::Relaxed),
        2
    );
    ledger.commit(2);
    send(&mut app, peer, 0, 1);
}

#[test]
fn send_lane_slots_fifo_and_release_before_park() {
    let (_port, mut app, state, peer) = boundary(limits(100, 100), 2, 1);
    send(&mut app, peer, 0, 1);
    send(&mut app, peer, 0, 2);
    rejected_unchanged(&mut app, peer, 0, 3);
    let first = take(&state, peer, 0);
    assert_eq!(first.payload.len(), 1);
    assert!(app.park_until_ready()); // release preceded parking; no lost wake
    send(&mut app, peer, 0, 3);
    assert_eq!(take(&state, peer, 0).payload.len(), 2);
    assert_eq!(take(&state, peer, 0).payload.len(), 3);
}

#[test]
fn send_lane_core_byte_release_wakes_parked_endpoint() {
    let (port, mut app, state, peer) = boundary(limits(1, 1), 8, 1);
    send(&mut app, peer, 0, 1);
    let mut ledger = QueuedLedger::default();
    ledger.admit(take(&state, peer, 0).charge);
    rejected_unchanged(&mut app, peer, 0, 1); // slots available, bytes only are full
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        tx.send(app.park_until_ready()).unwrap();
        app
    });
    std::thread::sleep(Duration::from_millis(10));
    ledger.retire(1, true);
    let result = rx.recv_timeout(Duration::from_secs(2));
    if result.is_err() {
        port.stop.store(true, Ordering::Release);
        port.ready.notify();
    }
    let mut app = thread.join().unwrap();
    assert_eq!(result.unwrap(), true);
    send(&mut app, peer, 0, 1);
}

#[test]
fn send_lane_active_limit_reclaimed_after_association_churn() {
    let config = SendQueueConfig {
        max_active_queues: 1,
        ..limits(10, 100)
    };
    let (port, mut app, mut state, mut peer) = boundary(config, 2, 2);
    for id in 2..80 {
        send(&mut app, peer, 0, 1);
        drop(take(&state, peer, 0));
        rejected_unchanged(&mut app, peer, 1, 1); // idle lane retained while connected
        state.disconnected(peer, DisconnectReason::Local);
        state.flush(&port);
        assert!(matches!(
            app.try_recv(),
            Some(RingEvent::Disconnected { .. })
        ));
        assert_eq!(
            port.native
                .get()
                .unwrap()
                .budget
                .lanes
                .load(Ordering::Relaxed),
            0
        );
        assert!(state.pending.is_empty());
        let addr = address(id);
        peer = addr.connection_key();
        assert!(state.connected(&port, addr, [id; 64]));
        assert!(matches!(app.try_recv(), Some(RingEvent::Connected { .. })));
        assert_eq!(state.send_peers.len(), 1);
        assert_eq!(state.scan.len(), 1);
    }
}

#[test]
fn send_lane_unknown_invalid_and_preconnected_sends_allocate_nothing() {
    let (port, mut app, mut state, peer) = boundary(limits(10, 20), 2, 1);
    for id in 2..100 {
        send(&mut app, address(id).connection_key(), 0, 1);
    }
    send(&mut app, peer, 9, 1);
    send(&mut app, peer, 0, 1001);
    let addr = address(101);
    let other = addr.connection_key();
    assert!(state.connected(&port, addr, [101; 64]));
    send(&mut app, other, 0, 1); // Connected not consumed yet
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .lanes
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(app.stats().send_dropped_unknown, 99);
    assert_eq!(app.stats().send_dropped_invalid_queue, 1);
    assert_eq!(app.stats().send_dropped_oversized, 1);
}

#[test]
fn send_lane_replacement_cancels_old_and_publishes_fresh_handle() {
    let (port, mut app, mut state, peer) = boundary(limits(10, 20), 2, 1);
    send(&mut app, peer, 0, 7);
    let old = state.send_peers[&peer].clone();
    assert!(state.replaced(&port, address(1), [8; 64]));
    assert!(old.is_closed());
    assert_eq!(old.budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(old.budget.pending.load(Ordering::Relaxed), 0);
    send(&mut app, peer, 0, 1); // stale endpoint handle: drop, never feed replacement
    assert_eq!(app.stats().send_dropped_unknown, 1);
    assert!(matches!(
        app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::Replaced,
            ..
        })
    ));
    assert!(
        matches!(app.try_recv(), Some(RingEvent::Connected { handshake_hash, .. }) if handshake_hash == [8; 64])
    );
    send(&mut app, peer, 0, 3);
    assert_eq!(take(&state, peer, 0).payload.len(), 3);
}

#[test]
fn send_lane_close_races_producer_without_leaking_or_consuming_twice() {
    let (port, mut app, state, peer) = boundary(limits(100_000, 100_000), 128, 1);
    let association = state.send_peers[&peer].clone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let thread = std::thread::spawn(move || {
        other.wait();
        for _ in 0..10000 {
            let _ = app.try_send(peer, 0, Dscp::BestEffort, &mut vec![7; 1]);
        }
        app
    });
    barrier.wait();
    association.close();
    let app = thread.join().unwrap();
    assert_eq!(app.queued_send_bytes(peer, 0), 0);
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .bytes
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .messages
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .pending
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn send_lane_round_robin_cursor_survives_empty_and_blocked_scans() {
    let (port, _app, mut state, _peer) = boundary(limits(10, 100), 2, 64);
    for id in 2..5 {
        assert!(state.connected(&port, address(id), [id; 64]));
    }
    let mut seen = std::collections::HashSet::new();
    for _call in 0..(64 * 4) {
        // One candidate per call models the smallest deadline budget, including empty/blocked lanes.
        let (peer, _, queue) = state.next_send().unwrap();
        assert!(seen.insert((peer, queue)));
    }
    assert_eq!(seen.len(), 256);
}

#[test]
fn send_lane_default_caps_follow_maximum_and_largest_override() {
    use crate::pump::port::{Ready, lockfree::SendBudget};
    let budget = SendBudget::new(
        Default::default(),
        20_000_000,
        2,
        Arc::new(Ready::default()),
    );
    assert_eq!(&*budget.limits, &[20_000_000, 20_000_000]);
    assert_eq!(budget.global_limit, 80_000_000);
    let config = SendQueueConfig {
        queue_bytes: vec![None, Some(100_000_000)],
        ..Default::default()
    };
    assert_eq!(
        SendBudget::new(config, 1, 2, Arc::new(Ready::default())).global_limit,
        400_000_000
    );
    for config in [
        limits(0, 1),
        limits(1, 0),
        SendQueueConfig {
            queue_bytes: vec![None; 3],
            ..Default::default()
        },
        SendQueueConfig {
            max_active_queues: 0,
            ..Default::default()
        },
        SendQueueConfig {
            max_queued_messages: 0,
            ..Default::default()
        },
    ] {
        assert!(
            std::panic::catch_unwind(|| SendBudget::new(
                config,
                100,
                2,
                Arc::new(Ready::default())
            ))
            .is_err()
        );
    }
}

#[test]
fn send_lane_pending_connected_keeps_handle_after_source_change() {
    let port = Port::new(1000, 1);
    let mut app = Endpoint {
        inner: port.clone(),
    }
    .into_rings(
        RingConfig {
            send: 2,
            control: 4,
            receive: 1,
        },
        limits(10, 20),
    );
    let mut state = RingState::default();
    let peer = address(1).connection_key();
    assert!(state.connected(&port, address(1), [1; 64]));
    assert!(matches!(app.try_recv(), Some(RingEvent::Connected { .. })));
    assert!(state.replaced(&port, address(1), [2; 64]));
    assert_eq!(state.pending.len(), 1); // D(old) occupies ring; C(new) still pending
    let fresh = state.send_peers[&peer].clone();
    let mut refresh = LocalAddressRefresh::default();
    let mut connections = HashMap::new();
    let initial = (None, Some(Ipv6Addr::LOCALHOST));
    assert!(!refresh.observe_at(initial, &mut connections, &mut state, 0));
    assert!(refresh.observe_at(
        (None, Some("::2".parse().unwrap())),
        &mut connections,
        &mut state,
        1
    ));
    assert!(fresh.is_closed());
    assert!(state.send_peers.is_empty());
    assert!(matches!(
        app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::Replaced,
            ..
        })
    ));
    state.flush(&port);
    assert!(
        matches!(app.try_recv(), Some(RingEvent::Connected { handshake_hash, .. }) if handshake_hash == [2; 64])
    );
    send(&mut app, peer, 0, 1); // committed but already closed; no panic or replacement feed
    assert_eq!(app.stats().send_dropped_unknown, 1);
    state.flush(&port);
    assert!(matches!(
        app.try_recv(),
        Some(RingEvent::Disconnected {
            reason: DisconnectReason::NetworkChanged,
            ..
        })
    ));
    assert_eq!(app.queued_send_bytes(peer, 0), 0);
}

fn live_node(
    pps: Option<u64>,
    bounds: (u32, u32, u32),
    queues: usize,
) -> (Pump, LockfreeEndpoint, STPAddress, Arc<Port>) {
    live_node_with_sends(pps, bounds, queues, SendQueueConfig::default())
}
fn live_node_with_sends(
    pps: Option<u64>,
    bounds: (u32, u32, u32),
    queues: usize,
    sends: SendQueueConfig,
) -> (Pump, LockfreeEndpoint, STPAddress, Arc<Port>) {
    live_node_with_limit(pps, bounds, queues, sends, 2_000_000)
}
fn live_node_with_limit(
    pps: Option<u64>,
    bounds: (u32, u32, u32),
    queues: usize,
    sends: SendQueueConfig,
    maximum: usize,
) -> (Pump, LockfreeEndpoint, STPAddress, Arc<Port>) {
    let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let key =
        new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b).unwrap();
    let address = STPAddress::from(Ipv6Addr::LOCALHOST, port, &key);
    let options = NetworkThreadOptions {
        send_queue_count: queues,
        send_queue: sends,
        ..Default::default()
    };
    let rings = options.rings;
    let sends = options.send_queue.clone();
    let (pump, endpoint) =
        new_reference_pump_with_options(vec![key], port, pps, bounds, maximum, options);
    let inner = endpoint.inner.clone();
    (pump, endpoint.into_rings(rings, sends), address, inner)
}

#[test]
fn send_lane_udp_peer_and_logical_queue_isolation_and_pump_drop_release() {
    let (mut source_pump, mut source, _, port) = live_node(Some(20), (1_000_000, 1, 1), 2);
    let (mut slow_pump, mut slow, slow_address, _) =
        live_node(None, (1_000_000, 32 << 20, 32 << 20), 2);
    let (mut fast_pump, mut fast, fast_address, _) =
        live_node(None, (1_000_000, 32 << 20, 32 << 20), 2);
    let slow_key = slow_address.connection_key();
    let fast_key = fast_address.connection_key();
    assert!(source.try_connect(slow_address));
    assert!(source.try_connect(fast_address));
    let until = Instant::now() + Duration::from_secs(5);
    let mut connected = std::collections::HashSet::new();
    let mut inbound = 0;
    while Instant::now() < until && (connected.len() != 2 || inbound != 2) {
        source_pump.run_for(Duration::from_micros(200));
        slow_pump.run_for(Duration::from_micros(200));
        fast_pump.run_for(Duration::from_micros(200));
        while let Some(event) = source.try_recv() {
            if let RingEvent::Connected { peer, .. } = event {
                connected.insert(peer);
            }
        }
        for app in [&mut slow, &mut fast] {
            while let Some(event) = app.try_recv() {
                if matches!(event, RingEvent::Connected { .. }) {
                    inbound += 1;
                }
            }
        }
    }
    assert_eq!(connected.len(), 2);
    assert_eq!(inbound, 2);
    send(&mut source, slow_key, 0, 1_000_000);
    send(&mut source, slow_key, 0, 100);
    let queue_mark = b"OTHER-LOGICAL-QUEUE".to_vec();
    let peer_mark = b"OTHER-PEER".to_vec();
    assert!(source.try_send(slow_key, 1, Dscp::BestEffort, &mut queue_mark.clone()));
    assert!(source.try_send(fast_key, 0, Dscp::BestEffort, &mut peer_mark.clone()));
    let until = Instant::now() + Duration::from_secs(3);
    let mut queue_delivered = false;
    let mut peer_delivered = false;
    while Instant::now() < until && !(queue_delivered && peer_delivered) {
        source_pump.run_for(Duration::from_millis(2));
        slow_pump.run_for(Duration::from_micros(200));
        fast_pump.run_for(Duration::from_micros(200));
        while let Some(event) = slow.try_recv() {
            if let RingEvent::Message { data, .. } = event {
                assert_eq!(data, queue_mark);
                queue_delivered = true;
            }
        }
        while let Some(event) = fast.try_recv() {
            if let RingEvent::Message { data, .. } = event {
                assert_eq!(data, peer_mark);
                peer_delivered = true;
            }
        }
    }
    assert!(
        queue_delivered,
        "blocked queue0 starved queue1: {:?}, q0={}, q1={}, peer={} ",
        source.stats(),
        source.queued_send_bytes(slow_key, 0),
        source.queued_send_bytes(slow_key, 1),
        source.queued_send_bytes(fast_key, 0)
    );
    assert!(peer_delivered, "blocked peer starved independent peer");
    assert_eq!(source.queued_send_bytes(slow_key, 0), 1_000_100);
    assert!(source.stats().send_head_blocked > 0);
    assert_eq!(source.stats().send_dropped_unknown, 0);
    assert!(
        port.native
            .get()
            .unwrap()
            .budget
            .messages
            .load(Ordering::Relaxed)
            >= 2
    );
    drop(source_pump); // endpoint deliberately remains alive
    assert!(source.is_finished());
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .bytes
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .messages
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .pending
            .load(Ordering::Relaxed),
        0
    );
}

fn connect_pair(
    source_pump: &mut Pump,
    source: &mut LockfreeEndpoint,
    other_pump: &mut Pump,
    other: &mut LockfreeEndpoint,
    address: STPAddress,
) -> ConnectionKey {
    let peer = address.connection_key();
    assert!(source.try_connect(address));
    let until = Instant::now() + Duration::from_secs(5);
    let (mut outbound, mut inbound) = (false, false);
    while Instant::now() < until && !(outbound && inbound) {
        source_pump.run_for(Duration::from_millis(1));
        other_pump.run_for(Duration::from_millis(1));
        while let Some(e) = source.try_recv() {
            outbound |= matches!(e, RingEvent::Connected { .. });
        }
        while let Some(e) = other.try_recv() {
            inbound |= matches!(e, RingEvent::Connected { .. });
        }
    }
    assert!(outbound && inbound);
    peer
}

#[test]
fn send_lane_live_one_message_cap_retires_plain_empty_and_fec_without_new_admission() {
    for bytes in [0, 1, 5000] {
        let config = SendQueueConfig {
            max_queued_messages: 1,
            ..limits(bytes.max(1) as u64, bytes.max(1) as u64)
        };
        let (mut pump, mut app, _, port) =
            live_node_with_sends(None, (100_000, 65536, 65536), 1, config);
        let (mut remote_pump, mut remote, address, _) = live_node(None, (100_000, 65536, 65536), 1);
        let peer = connect_pair(&mut pump, &mut app, &mut remote_pump, &mut remote, address);
        send(&mut app, peer, 0, bytes);
        rejected_unchanged(&mut app, peer, 0, bytes);
        let budget = &port.native.get().unwrap().budget;
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until && budget.messages.load(Ordering::Relaxed) != 0 {
            pump.run_for(Duration::from_millis(1));
            remote_pump.run_for(Duration::from_millis(1));
            while remote.try_recv().is_some() {}
        }
        assert_eq!(
            budget.bytes.load(Ordering::Relaxed),
            0,
            "payload length {bytes}"
        );
        assert_eq!(
            budget.messages.load(Ordering::Relaxed),
            0,
            "payload length {bytes}"
        );
        assert!(app.park_until_ready());
        send(&mut app, peer, 0, bytes); // no later submission was needed to retire the previous send
    }
}

#[test]
fn send_lane_tiny_run_deadlines_and_continuous_controls_do_not_starve_later_lanes() {
    let (mut pump, mut app, _, port) = live_node(Some(1), (1_000_000, 1, 1), 64);
    let (mut remote_pump, mut remote, address, _) = live_node(None, (100_000, 65536, 65536), 64);
    let peer = connect_pair(
        &mut pump,
        &mut app,
        &mut remote_pump,
        &mut remote,
        address.clone(),
    );
    for queue in 0..64 {
        send(&mut app, peer, queue, 1);
    }
    let until = Instant::now() + Duration::from_secs(2);
    let mut calls = 0;
    while Instant::now() < until && app.stats().sent != 64 {
        let _ = app.try_connect(address.clone()); // duplicate controls must not monopolize admission
        pump.run_for(Duration::from_micros(1));
        calls += 1;
    }
    assert_eq!(app.stats().sent, 64, "after {calls} tiny calls");
    assert_eq!(
        port.native
            .get()
            .unwrap()
            .budget
            .pending
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn send_lane_charged_local_udp_failure_commits_final_retirement() {
    let (port, mut app, ring_state, peer) = boundary(limits(24, 24), 2, 1);
    send(&mut app, peer, 0, 24);
    let message = take(&ring_state, peer, 0);
    let ConnectionState::Connected(mut state) =
        new_connection_state_connected(None, CONNECT_MAGIC1_PLAIN_TEXT, 1, 1)
    else {
        unreachable!()
    };
    let mut buf = SendQueues::new(1, (100_000, 4096, 65536));
    buf.queues[0].queued_ledger.admit(message.charge);
    assert!(buf.submit_messages(0, vec![message.payload]).is_empty());
    let mut payload = [0; 506];
    buf.fec_prepare_packet(0);
    assert_eq!(buf.fill_packet_with_dup(&mut payload, false), payload.len());
    let budget = &port.native.get().unwrap().budget;
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 24);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 1);
    let mut encrypted = vec![0; payload.len() + 22];
    let len = seal_connected_packet(&mut state.cipher, 2, 0, &payload, &mut encrypted, 10).unwrap();
    finish_connected_send(
        &mut state,
        &mut buf,
        ConnectedSendKind::Data,
        SendAttempt {
            attempted_at_ns: 10,
            error: Some(55),
        },
        10,
        &encrypted[..len],
        &payload,
        2,
        None,
    );
    assert_eq!(state.stats.local_send_drops, 1);
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 0);
    send(&mut app, peer, 0, 24);
}

#[test]
fn send_lane_largest_supported_per_queue_cap_derives_nonoverflowing_global() {
    use crate::pump::port::{Ready, lockfree::SendBudget};
    let largest = u64::MAX / 4;
    let config = SendQueueConfig {
        per_queue_bytes: Some(largest),
        ..Default::default()
    };
    let budget = SendBudget::new(config, 1, 1, Arc::new(Ready::default()));
    assert_eq!(budget.global_limit, 4 * largest);
    let config = SendQueueConfig {
        global_bytes: Some(u64::MAX),
        ..Default::default()
    };
    assert_eq!(
        SendBudget::new(config, 1, 1, Arc::new(Ready::default())).global_limit,
        u64::MAX
    );
}

#[test]
fn send_lane_live_segmented_payload_holds_message_permit_until_final_extent() {
    const BYTES: usize = 3 << 20;
    let config = SendQueueConfig {
        max_queued_messages: 1,
        ..limits(BYTES as u64, BYTES as u64)
    };
    let (mut pump, mut app, _, port) =
        live_node_with_limit(Some(5000), (100_000, 8 << 20, 8 << 20), 1, config, BYTES);
    let (mut remote_pump, mut remote, address, _) = live_node_with_limit(
        None,
        (100_000, 8 << 20, 8 << 20),
        1,
        Default::default(),
        BYTES,
    );
    let peer = connect_pair(&mut pump, &mut app, &mut remote_pump, &mut remote, address);
    send(&mut app, peer, 0, BYTES);
    rejected_unchanged(&mut app, peer, 0, 1);
    let budget = &port.native.get().unwrap().budget;
    let until = Instant::now() + Duration::from_secs(15);
    let mut saw_nonfinal_retirement = false;
    let mut large_delivered = false;
    while Instant::now() < until
        && (budget.messages.load(Ordering::Relaxed) != 0 || !large_delivered)
    {
        pump.run_for(Duration::from_millis(2));
        remote_pump.run_for(Duration::from_millis(2));
        let bytes = budget.bytes.load(Ordering::Relaxed);
        if bytes != 0 && bytes < BYTES as u64 {
            saw_nonfinal_retirement = true;
            assert_eq!(budget.messages.load(Ordering::Relaxed), 1);
            rejected_unchanged(&mut app, peer, 0, 1); // bytes available, logical-message permit still held
        }
        while let Some(event) = remote.try_recv() {
            if let RingEvent::Message { data, .. } = event {
                assert_eq!(data.len(), BYTES);
                assert!(data.iter().all(|&byte| byte == 7));
                large_delivered = true;
            }
        }
    }
    assert!(
        saw_nonfinal_retirement,
        "no intermediate segmented retirement observed"
    );
    assert!(large_delivered, "segmented payload did not arrive intact");
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 0);
    send(&mut app, peer, 0, 17);
    let until = Instant::now() + Duration::from_secs(3);
    let mut small_delivered = false;
    while Instant::now() < until && !small_delivered {
        pump.run_for(Duration::from_millis(2));
        remote_pump.run_for(Duration::from_millis(2));
        while let Some(event) = remote.try_recv() {
            if let RingEvent::Message { data, .. } = event {
                assert_eq!(data, vec![7; 17]);
                small_delivered = true;
            }
        }
    }
    assert!(
        small_delivered,
        "reclaimed permit did not admit/deliver the next message"
    );
}
