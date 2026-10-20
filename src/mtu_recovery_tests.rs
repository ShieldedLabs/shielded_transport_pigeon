use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

// Caller-owned PUBLIC ring-pump driver. No reference exchange adapter.
struct Worker(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
impl Worker {
    fn start(mut pump: Pump) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let join = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                pump.run_for(Duration::from_millis(100));
            }
        });
        Self(stop, Some(join))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        self.1.take().unwrap().join().unwrap();
    }
}

fn pump_stats(endpoint: &crate::pump::port::lockfree::LockfreeEndpoint) -> NetworkThreadPull {
    endpoint.request_protocol_stats();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(stats) = endpoint.try_protocol_stats() { return stats; }
        assert!(Instant::now() < deadline, "parked pump did not service telemetry");
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn encrypted_multimegabyte_mid_codec_shrink_keeps_bytes_identity_and_pending_ciphertext() {
    let server_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    relay
        .set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let (st, dr, ob) = (stop.clone(), dropped.clone(), observed.clone());
    let forwarder = std::thread::spawn(move || {
        let mut peer = None;
        let mut count = 0;
        let mut shrink = false;
        let mut b = [0u8; 10000];
        while !st.load(Ordering::Acquire) {
            match relay.recv_from(&mut b) {
                Ok((n, src)) => {
                    ob.lock().unwrap().push(b[..n].to_vec());
                    let target = if src == server_addr {
                        peer
                    } else {
                        peer = Some(src);
                        Some(server_addr)
                    };
                    if src != server_addr && n == 1204 {
                        count += 1;
                        if count >= 40 {
                            shrink = true;
                        }
                    }
                    if n <= if shrink { 512 } else { 1204 } {
                        if let Some(to) = target {
                            relay.send_to(&b[..n], to).unwrap();
                        }
                    } else {
                        dr.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    ()
                }
                Err(e) => panic!("relay {e}"),
            }
        }
    });
    let kp =
        new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    let addr = STPAddress {
        ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
        port: relay_port,
        magic1: kp.magic1,
        key: kp.public.clone(),
    };
    let key = addr.to_connection_key();
    let log = Arc::new(Mutex::new(Vec::new()));
    let plain = Arc::new(Mutex::new(Vec::new()));
    let refused = Arc::new(Mutex::new(TestSendFailure {
        kind: Some("data"),
        remaining: 8,
        ..Default::default()
    }));
    let opts = || NetworkThreadOptions {
        send_queue_count: 2,
        datagram_log: Some(log.clone()),
        ..Default::default()
    };
    let server = new_network_thread_with_options(
        vec![kp],
        server_port,
        Some(2000),
        (1_000_000, 32 << 20, 32 << 20),
        16 << 20,
        opts(),
    );
    let client = new_network_thread_with_options(
        vec![new_keypair_from_connect_magic1(addr.magic1).unwrap()],
        0,
        Some(2000),
        (1_000_000, 32 << 20, 32 << 20),
        16 << 20,
        NetworkThreadOptions {
            send_failure: Some(refused.clone()),
            encrypted_payload_log: Some(plain.clone()),
            ..opts()
        },
    );
    let mut cw = service_connections(
        &client,
        NetworkThreadPush {
            initiate_connections: vec![addr],
            ..Default::default()
        },
    )
    .unwrap()
    .current_connections;
    let mut sw = Vec::new();
    let mut got = Vec::new();
    let mut min_tu = u64::MAX;
    let mut max_tu = 0;
    let mut handshakes = BTreeSet::new();
    let mut poll = |cw: &mut Vec<(STPAddress, [u8; 64])>,
                    sw: &mut Vec<(STPAddress, [u8; 64])>,
                    got: &mut Vec<Vec<u8>>| {
        let c = service_connections(
            &client,
            NetworkThreadPush {
                wanted_connections: cw.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        for (a, hash) in &c.current_connections {
            handshakes.insert(*hash);
        }
        for (_, s) in c.connection_stats {
            min_tu = min_tu.min(s.udp_payload_tu);
            max_tu = max_tu.max(s.udp_payload_tu);
        }
        *cw = c.current_connections;
        let s = service_connections(
            &server,
            NetworkThreadPush {
                wanted_connections: sw.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        *sw = s.current_connections;
        got.extend(s.received_unreliable_messages.into_iter().map(|(_, m)| m));
    };
    let deadline = Instant::now() + Duration::from_secs(70);
    while cw.is_empty() || sw.is_empty() {
        poll(&mut cw, &mut sw, &mut got);
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    let payload: Vec<u8> = (0..(6 << 20))
        .map(|i| ((i as u64 * 11939 + (i as u64 >> 7) * 73) ^ 0xa53f) as u8)
        .collect();
    let want_hash = blake3::hash(&payload);
    service_connections(
        &client,
        NetworkThreadPush {
            wanted_connections: cw.clone(),
            send_unreliable: vec![(key, 0, Dscp::BestEffort, payload.clone())],
            ..Default::default()
        },
    )
    .unwrap();
    while !got.iter().any(|m| m.len() == payload.len()) && Instant::now() < deadline {
        poll(&mut cw, &mut sw, &mut got);
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(poll);
    drop(client);
    drop(server);
    stop.store(true, Ordering::Release);
    forwarder.join().unwrap();
    let actual = got
        .iter()
        .find(|m| m.len() == payload.len())
        .expect("full segmented payload did not arrive after fallback");
    assert_eq!(actual, &payload);
    assert_eq!(blake3::hash(actual), want_hash);
    assert_eq!(handshakes.len(), 1, "recovery must not reconnect");
    assert_eq!(min_tu, 512);
    assert!(max_tu >= 1204);
    assert!(dropped.load(Ordering::Relaxed) > 0);
    let attempts = refused.lock().unwrap();
    assert_eq!(attempts.attempts.len(), 8);
    assert!(attempts.attempts.iter().all(|b| b == &attempts.attempts[0]));
    assert!(
        log.lock()
            .unwrap()
            .iter()
            .any(|d| d.kind == "data" && d.bytes == attempts.attempts[0])
    );
    let captured: BTreeSet<_> = observed.lock().unwrap().iter().cloned().collect();
    let mut layouts = BTreeMap::<(u64, u32), BTreeMap<u64, (usize, u32, u32)>>::new();
    for (cipher, p) in plain.lock().unwrap().iter() {
        assert!(captured.contains(cipher));
        let mut off = 0;
        while let Some((frame, n)) = read_frame(&p[off..]) {
            if let WireFrame::Fec {
                id,
                block_id,
                block_bytes,
                segment: Some(s),
                ..
            } = frame
            {
                let x = layouts
                    .entry((s.root, s.offset))
                    .or_default()
                    .entry(id)
                    .or_insert((block_bytes, block_id, block_id));
                assert_eq!(x.0, block_bytes);
                x.1 = x.1.min(block_id);
                x.2 = x.2.max(block_id);
            }
            off += n;
        }
    }
    assert!(
        layouts.values().any(|ids| ids.len() >= 2
            && ids.values().any(|x| x.0 > 445)
            && ids.values().any(|x| x.0 == 445 && x.1 == 0)),
        "first segment must restart ALL source blocks from block0 under freshunitID: {layouts:?}"
    );
    println!(
        "MTU_MULTI_MB_PROOF bytes={} blake3={} min_tu={} max_tu={} handshakes={} refused_identical={} dropped={} layouts={:?}",
        payload.len(),
        want_hash,
        min_tu,
        max_tu,
        handshakes.len(),
        attempts.attempts.len(),
        dropped.load(Ordering::Relaxed),
        layouts
    );
}

#[test]
fn recovery_downshift_waits_for_whole_and_mixed_fec_duplicate_copies() {
    for mixed in [false, true] {
        let ConnectionState::Connected(mut state) = new_connection_state_connected(
            None,
            CONNECT_MAGIC1_PLAIN_TEXT,
            MAGIC2_APP_CROSSLINK,
            1_000_000,
        ) else {
            panic!()
        };
        let tu = if mixed { 1472 } else { 1204 };
        state.current_tu = tu;
        let mut queues = SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20));
        let mut original = vec![0xff; tu as usize - 14];
        let whole = if mixed { 80usize } else { 1000 };
        original[0] = 1 | TARGET_DUP_ORIGINAL;
        original[1..3].copy_from_slice(&(whole as u16).to_le_bytes());
        original[3..3 + whole].fill(7);
        if mixed {
            let i = 3 + whole;
            original[i] = 4;
            original[i + 1..i + 3].copy_from_slice(&(18u16 + 1136).to_le_bytes());
            original[i + 3..i + 11].copy_from_slice(&99u64.to_le_bytes());
            original[i + 11..i + 15].copy_from_slice(&0u32.to_le_bytes());
            original[i + 15..i + 19].copy_from_slice(&3000u32.to_le_bytes());
            original[i + 19..i + 21].copy_from_slice(&1136u16.to_le_bytes());
            original[i + 21..i + 21 + 1136].fill(11);
        }
        queues.fec_prepare_packet(0);
        queues.target_duplicate = Some((0, Dscp::BestEffort, original.clone()));
        let ciphertext = vec![9; tu as usize];
        assert!(!finish_connected_send(
            &mut state,
            &mut queues,
            PendingSendKind::Data,
            None,
            1_000_001,
            &ciphertext,
            &original,
            Dscp::BestEffort,
            0,
            None
        ));
        state.tu_probe_failed_count = 40;
        state.downshift_for_recovery(queues.target_copy_pending(), 1_000_002);
        assert_eq!(state.tu_probe_failed_count, 40);
        assert_eq!(state.current_tu, tu);
        assert_eq!(state.deferred_tu, Some(512));
        let pending = state.pending_send.take().unwrap();
        assert_eq!(pending.bytes, ciphertext);
        commit_connected_send(
            &mut state,
            &mut queues,
            pending.kind,
            1_000_002,
            pending.bytes.len(),
            &pending.plaintext,
            0,
            None,
        );
        assert_eq!(
            state.current_tu, tu,
            "accepting refused original must NOT shrink before its copy"
        );
        assert_eq!(state.tu_probe_failed_count, 40);
        queues.fec_prepare_packet(1);
        let mut copy = vec![0u8; original.len()];
        assert_eq!(queues.take_target_copy(&mut copy), original.len());
        assert_eq!(&copy[1..], &original[1..]);
        assert_eq!(copy[0], (original[0] & 15) | TARGET_DUP_COPY);
        let copy_cipher = vec![10; tu as usize];
        assert!(!finish_connected_send(
            &mut state,
            &mut queues,
            PendingSendKind::Data,
            None,
            1_000_003,
            &copy_cipher,
            &copy,
            Dscp::BestEffort,
            0,
            None
        ));
        assert_eq!(state.current_tu, tu);
        let pending = state.pending_send.take().unwrap();
        assert_eq!(pending.bytes, copy_cipher);
        assert_eq!(pending.plaintext, copy);
        // Native Some includes a locally accepted attempt later physically lost.
        commit_connected_send(
            &mut state,
            &mut queues,
            pending.kind,
            1_000_004,
            pending.bytes.len(),
            &pending.plaintext,
            0,
            None,
        );
        assert_eq!(state.current_tu, 512);
        assert_eq!(state.tu_probe_failed_count, 0);
        assert_eq!(state.deferred_tu, None);
        assert_eq!(state.send_sequence_number, 2);
        assert_eq!(state.packets_in_flight, 2);
        assert_eq!(state.stats.packets_sent, 2);
    }
}

#[test]
fn recovery_copy_completion_stops_old_layout_with_multi_packet_pacing_grant() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let kp =
        new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    let addr = STPAddress {
        ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
        port,
        magic1: kp.magic1,
        key: kp.public.clone(),
    };
    let key = addr.to_connection_key();
    let fixture = Arc::new(AtomicUsize::new(1));
    let log = Arc::new(Mutex::new(Vec::new()));
    let plain = Arc::new(Mutex::new(Vec::new()));
    let server = new_network_thread_with_options(
        vec![kp],
        port,
        Some(2000),
        (1_000_000, 1 << 20, 1 << 20),
        1 << 20,
        NetworkThreadOptions::default(),
    );
    let client = new_network_thread_with_options(
        vec![new_keypair_from_connect_magic1(addr.magic1).unwrap()],
        0,
        Some(2000),
        (1_000_000, 1 << 20, 1 << 20),
        1 << 20,
        NetworkThreadOptions {
            datagram_log: Some(log.clone()),
            encrypted_payload_log: Some(plain.clone()),
            recovery_copy_grant_fixture: Some(fixture.clone()),
            ..Default::default()
        },
    );
    let mut cw = service_connections(
        &client,
        NetworkThreadPush {
            initiate_connections: vec![addr],
            ..Default::default()
        },
    )
    .unwrap()
    .current_connections;
    let mut sw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got = Vec::new();
    let mut max_batch = 0;
    while cw.is_empty() || sw.is_empty() {
        cw = service_connections(
            &client,
            NetworkThreadPush {
                wanted_connections: cw,
                ..Default::default()
            },
        )
        .unwrap()
        .current_connections;
        sw = service_connections(
            &server,
            NetworkThreadPush {
                wanted_connections: sw,
                ..Default::default()
            },
        )
        .unwrap()
        .current_connections;
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    let first = vec![17; 1000];
    let tail: Vec<u8> = (0..6000).map(|i| (i * 179 % 251) as u8).collect();
    service_connections(
        &client,
        NetworkThreadPush {
            wanted_connections: cw.clone(),
            send_unreliable: vec![
                (key, 0, Dscp::BestEffort, first.clone()),
                (key, 0, Dscp::BestEffort, tail.clone()),
            ],
            ..Default::default()
        },
    )
    .unwrap();
    while !(got.contains(&first) && got.contains(&tail)) && Instant::now() < deadline {
        let c = service_connections(
            &client,
            NetworkThreadPush {
                wanted_connections: cw,
                ..Default::default()
            },
        )
        .unwrap();
        cw = c.current_connections;
        for (_, s) in c.connection_stats {
            max_batch = max_batch.max(s.pacing_max_burst);
        }
        let s = service_connections(
            &server,
            NetworkThreadPush {
                wanted_connections: sw,
                ..Default::default()
            },
        )
        .unwrap();
        sw = s.current_connections;
        got.extend(s.received_unreliable_messages.into_iter().map(|(_, m)| m));
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(client);
    drop(server);
    assert!(
        got.contains(&first) && got.contains(&tail),
        "whole and FEC payloads must arrive exactly"
    );
    assert_eq!(
        fixture.load(Ordering::Acquire),
        (6 << 8) | 4,
        "copy completion must run normal pacing finalization with six credits left"
    );
    assert!(max_batch >= 2);
    let packets = log.lock().unwrap();
    let data: Vec<_> = packets.iter().filter(|p| p.kind == "data").collect();
    assert!(data.len() > 2);
    assert_eq!(data[0].bytes.len(), 1204);
    assert_eq!(data[1].bytes.len(), 1204);
    assert!(
        data[2..].iter().all(|p| p.bytes.len() <= 512),
        "no newly framed datagram may reuse old payload_size after copy commit"
    );
    let nonces: Vec<_> = data
        .iter()
        .map(|p| u64::from_le_bytes(p.bytes[2..10].try_into().unwrap()))
        .collect();
    assert!(nonces.windows(2).all(|x| x[0] < x[1]), "no nonce reuse");
    assert_eq!(nonces[1], nonces[0] + 1);
    let plain = plain.lock().unwrap();
    assert!(!target_is_copy(&plain[0].1));
    assert!(target_is_copy(&plain[1].1));
    println!(
        "MTU_COPY_GRANT_PROOF injected_grant=8 original_copy_attempts=2 remaining_grant_after_normal_finalization=6 later_new_datagrams={} all_later_new_le512=true increasing_nonces=true max_batch={max_batch}",
        data.len() - 2
    );
}

#[test]
fn recovery_small_outage_proofs_do_not_postpone_current_tu_probe_backoff() {
    let ConnectionState::Connected(mut state) = new_connection_state_connected(
        None,
        CONNECT_MAGIC1_PLAIN_TEXT,
        MAGIC2_APP_CROSSLINK,
        1_000_000_000,
    ) else {
        panic!()
    };
    let mut queues = SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20));
    state.outage.enter(1_000_000_000, 1_000_000_000);
    let due = state.outage.next_probe_ns;
    let interval = state.outage.probe_interval_ns;
    for step in 0..8 {
        let sent = 1_000_000_000 + step * crate::mtu_recovery::PERIOD;
        let sequence = state.send_sequence_number;
        commit_connected_send(
            &mut state,
            &mut queues,
            if step % 2 == 0 { PendingSendKind::Reachability }
                else { PendingSendKind::ReachabilityCurrent },
            sent,
            if step % 2 == 0 { 512 } else { 1204 },
            &[],
            0,
            None,
        );
        assert_eq!(state.outage.next_probe_ns, due);
        assert_eq!(state.outage.probe_interval_ns, interval);
        assert!(state.outage.probes.contains(&(sequence, sent)));
        assert!(state.outage.probe_due(sent));
        let ack = crate::ack::BitmapAck {
            highest: sequence,
            receipt_base: sequence,
            sample_seq: sequence,
            sample_udp_payload_bytes: if step % 2 == 0 { 512 } else { 1204 },
            delay_us: 0,
            ce_count: 0,
            bitmap: [0; 15],
        };
        assert!(recent_outage_probe_acked(&state, &ack, sent + 1));
    }
    let sent = 3_000_000_000;
    commit_connected_send(
        &mut state,
        &mut queues,
        PendingSendKind::Outage,
        sent,
        1204,
        &[],
        0,
        None,
    );
    assert_eq!(state.outage.next_probe_ns, sent + interval);
    assert_eq!(state.outage.probe_interval_ns, 2 * interval);
}

#[test]
fn recovery_history_is_charged_to_connection_admission() {
    assert_eq!(crate::mtu_recovery::HISTORY_BYTES, 96 << 10);
    assert_eq!(RECEIVE_CONNECTION_BYTES, (512 + 96) << 10);
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(RECEIVE_CONNECTION_BYTES);
    let reservation = budget.reserve(RECEIVE_CONNECTION_BYTES).unwrap();
    assert_eq!(budget.used(), RECEIVE_CONNECTION_BYTES);
    assert!(budget.reserve(1).is_none());
    drop(reservation);
    assert_eq!(budget.used(), 0);
}

#[test]
fn recovery_send_timestamp_after_tick_is_zero_age_not_loss() {
    let tick = 1_000_000_000;
    let actual_send = tick + 50_000;
    assert_eq!(send_age_ns(tick, actual_send), 0);
    assert!(send_age_ns(tick, actual_send) < 100_000);
    assert_eq!(send_age_ns(actual_send + 100_000, actual_send), 100_000);
}

#[test]
fn profile_four_small_data_is_admitted_in_both_directions_and_cipher_modes() {
    for magic in [
        CONNECT_MAGIC1_PLAIN_TEXT,
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s,
    ] {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let keypair = new_keypair_from_connect_magic1(magic).unwrap();
        let address = STPAddress {
            ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            port,
            magic1: magic,
            key: keypair.public.clone(),
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        // Phase 4 uses the same cfg(test)-only native-loop fixture to hold TU512,
        // without forced duplication or pacing grants. Production has no such knob.
        let options = || NetworkThreadOptions {
            datagram_log: Some(log.clone()),
            recovery_copy_grant_fixture: Some(Arc::new(AtomicUsize::new(4))),
            ..Default::default()
        };
        let server = new_network_thread_with_options(
            vec![keypair],
            port,
            Some(2000),
            (1_000_000, 1 << 20, 1 << 20),
            1 << 20,
            options(),
        );
        let client = new_network_thread_with_options(
            vec![new_keypair_from_connect_magic1(magic).unwrap()],
            0,
            Some(2000),
            (1_000_000, 1 << 20, 1 << 20),
            1 << 20,
            options(),
        );
        let mut cw = service_connections(
            &client,
            NetworkThreadPush {
                initiate_connections: vec![address],
                ..Default::default()
            },
        )
        .unwrap()
        .current_connections;
        let mut sw = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while cw.is_empty() || sw.is_empty() {
            cw = service_connections(
                &client,
                NetworkThreadPush {
                    wanted_connections: cw,
                    ..Default::default()
                },
            )
            .unwrap()
            .current_connections;
            sw = service_connections(
                &server,
                NetworkThreadPush {
                    wanted_connections: sw,
                    ..Default::default()
                },
            )
            .unwrap()
            .current_connections;
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let forward: Vec<u8> = (0..6000).map(|i| (i * 179 % 251) as u8).collect();
        let reverse: Vec<u8> = (0..7000).map(|i| (i * 193 % 251) as u8).collect();
        service_connections(
            &client,
            NetworkThreadPush {
                wanted_connections: cw.clone(),
                send_unreliable: vec![(
                    cw[0].0.to_connection_key(),
                    0,
                    Dscp::BestEffort,
                    forward.clone(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        service_connections(
            &server,
            NetworkThreadPush {
                wanted_connections: sw.clone(),
                send_unreliable: vec![(
                    sw[0].0.to_connection_key(),
                    0,
                    Dscp::BestEffort,
                    reverse.clone(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        let mut received_forward = false;
        let mut received_reverse = false;
        while !(received_forward && received_reverse) && Instant::now() < deadline {
            let c = service_connections(
                &client,
                NetworkThreadPush {
                    wanted_connections: cw,
                    ..Default::default()
                },
            )
            .unwrap();
            cw = c.current_connections;
            received_reverse |= c
                .received_unreliable_messages
                .iter()
                .any(|(_, m)| m == &reverse);
            let s = service_connections(
                &server,
                NetworkThreadPush {
                    wanted_connections: sw,
                    ..Default::default()
                },
            )
            .unwrap();
            sw = s.current_connections;
            received_forward |= s
                .received_unreliable_messages
                .iter()
                .any(|(_, m)| m == &forward);
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(client);
        drop(server);
        assert!(
            received_forward && received_reverse,
            "512-byte bidirectional admission for magic {magic:x}"
        );
        let log = log.lock().unwrap();
        let mut data = log.iter().filter(|d| d.kind == "data").peekable();
        assert!(data.peek().is_some());
        assert!(data.all(|d| d.bytes.len() == 512));
    }
}

#[test]
fn generic_four_pps_receipts_preserve_one_pps_ordinary_pacing_credit() {
    let start = 1_000_000_000;
    let ConnectionState::Connected(mut state) = new_connection_state_connected(
        None,
        CONNECT_MAGIC1_PLAIN_TEXT,
        MAGIC2_APP_CROSSLINK,
        start,
    ) else {
        panic!()
    };
    let mut queues = SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20));
    state.last_sent_could_have_sent_data_packet = start;
    for tick in 1..=8 {
        let sent = start + tick * crate::mtu_recovery::PERIOD;
        let sequence = state.send_sequence_number;
        commit_connected_send(
            &mut state,
            &mut queues,
            if tick % 2 == 1 { PendingSendKind::Reachability }
                else { PendingSendKind::ReachabilityCurrent },
            sent,
            if tick % 2 == 1 { 512 } else { 1204 },
            &[],
            0,
            None,
        );
        assert!(state.take_positive_receipt(sequence).is_some());
        state.on_positive_receipt(sequence, sent + 1);
        assert_eq!(state.last_ack_received_time, sent + 1);
        assert_eq!(state.last_pacing_ack_received_time, start);
        let elapsed = sent + 1
            - state.last_sent_could_have_sent_data_packet.max(
                state
                    .last_pacing_ack_received_time
                    .saturating_sub(ACK_BUFFER_TIME_NS),
            );
        if tick >= 4 {
            assert!(send_pacing_grant(elapsed, 1_000_000_000, 0).packets >= 1);
        }
    }
}

#[test]
fn mixed_positive_receipts_and_ordinary_512_always_advance_pacing_anchor() {
    for generic_first in [false, true] {
        let start = 1_000_000_000;
        let ConnectionState::Connected(mut state) = new_connection_state_connected(
            None,
            CONNECT_MAGIC1_PLAIN_TEXT,
            MAGIC2_APP_CROSSLINK,
            start,
        ) else {
            panic!()
        };
        let mut queues = SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20));
        let kinds = if generic_first {
            [PendingSendKind::Reachability, PendingSendKind::Data]
        } else {
            [PendingSendKind::Data, PendingSendKind::Reachability]
        };
        for kind in kinds {
            commit_connected_send(&mut state, &mut queues, kind, start + 1, 512, &[], 0, None);
        }
        for sequence in 0..2 {
            assert!(state.take_positive_receipt(sequence).is_some());
            state.on_positive_receipt(sequence, start + 10);
        }
        assert_eq!(state.last_pacing_ack_received_time, start + 10);
        // Unknown or overwritten metadata is not mistaken for a generic proof.
        state.account_send(start + 11);
        assert!(state.take_positive_receipt(2).is_some());
        state.on_positive_receipt(2, start + 12);
        assert_eq!(state.last_pacing_ack_received_time, start + 12);
    }
}

fn parked_fixture() -> (ConnectionStateConnected, SendQueues, u64) {
    let start = 8_000_000_000;
    let ConnectionState::Connected(state) = new_connection_state_connected(
        None,
        CONNECT_MAGIC1_PLAIN_TEXT,
        MAGIC2_APP_CROSSLINK,
        start,
    ) else {
        panic!()
    };
    (
        state,
        SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20)),
        start,
    )
}

#[test]
fn generic_only_flight_parks_with_explicit_loss_and_outage_deadlines() {
    let (mut state, mut queues, start) = parked_fixture();
    state.RTT_mean = 100; // 10 ms, matching the active policy's units.
    commit_connected_send(
        &mut state,
        &mut queues,
        PendingSendKind::Reachability,
        start,
        512,
        &[],
        0,
        None,
    );
    assert!(!needs_active_retry(&state, false));
    assert!(needs_active_retry(&state, true)); // A queued command cannot stay parked.
    let timeout = state.loss_timer.timeout_ns(10_000_000, 1, &crate::ship::CC);
    assert_eq!(
        parked_send_deadline(&state, start + 1, &crate::ship::CC),
        state.send_time(0) + timeout
    );
    state.RTT_mean = 60_000;
    assert_eq!(
        parked_send_deadline(&state, start + 1, &crate::ship::CC),
        start + OUTAGE_ACK_SILENCE_NS
    );
    state.packets_waiting_ack_tail = state.send_sequence_number;
    assert_eq!(
        parked_send_deadline(&state, start + 1, &crate::ship::CC),
        u64::MAX
    );
    state.outage.since_ns = Some(start);
    state.outage.next_probe_ns = start + 123;
    assert!(needs_active_retry(&state, false));
    assert_eq!(
        parked_send_deadline(&state, start + 1, &crate::ship::CC),
        start + 123
    );
}

#[test]
fn mixed_flights_keep_ordinary_retry_and_older_generic_holes_active() {
    for generic_first in [false, true] {
        let (mut state, mut queues, start) = parked_fixture();
        let kinds = if generic_first {
            [PendingSendKind::Reachability, PendingSendKind::Data]
        } else {
            [PendingSendKind::Data, PendingSendKind::Reachability]
        };
        for kind in kinds {
            commit_connected_send(&mut state, &mut queues, kind, start, 512, &[], 0, None);
        }
        assert!(needs_active_retry(&state, false));
        let ordinary = if generic_first { 1 } else { 0 };
        assert!(state.take_positive_receipt(ordinary).is_some());
        state.on_positive_receipt(ordinary, start + 1);
        // Positive admission alone cannot hide a generic hole before ordinary flight.
        assert!(needs_active_retry(&state, false));
        state.packets_waiting_ack_tail = state.active_send_frontier;
        assert!(!needs_active_retry(&state, false));
    }
}

#[test]
fn padding_feedback_parks_but_mixed_feedback_and_local_refusal_stay_active() {
    for ordinary_first in [false, true] {
        let (mut state, mut queues, start) = parked_fixture();
        state.observe_feedback_payload(&[0xff; 482]);
        state
            .ack_receiver
            .receive(0, start, false, &mut state.ack_timer);
        assert_ne!(state.ack_timer, u64::MAX);
        assert!(!needs_active_retry(&state, false));
        let payloads: [&[u8]; 2] = if ordinary_first {
            [&[0x01, 0xff], &[0xff]]
        } else {
            [&[0xff], &[0x01, 0xff]]
        };
        for (i, payload) in payloads.into_iter().enumerate() {
            state.observe_feedback_payload(payload);
            state
                .ack_receiver
                .receive((i as u64 + 1) * 960, start, false, &mut state.ack_timer);
        }
        assert!(needs_active_retry(&state, false));
        assert!(!finish_connected_send(
            &mut state,
            &mut queues,
            PendingSendKind::Ack,
            None,
            start,
            &[0; 78],
            &[],
            Dscp::Af21,
            0,
            None
        ));
        assert!(state.pending_send.is_none()); // ACK refusal is not a retained ciphertext.
        assert!(state.locally_blocked && needs_active_retry(&state, false));
        for _ in 0..12 {
            let now = state.ack_timer.saturating_add(1);
            if state.ack_timer == u64::MAX {
                break;
            }
            commit_connected_send(
                &mut state,
                &mut queues,
                PendingSendKind::Ack,
                now,
                78,
                &[],
                0,
                None,
            );
            state.update_feedback_deadline(now);
            assert_eq!(
                needs_active_retry(&state, false),
                state.ack_timer != u64::MAX
            );
        }
        assert_eq!(state.ack_timer, u64::MAX);
        assert!(!state.active_ack_feedback);
    }
    let (mut state, mut queues, start) = parked_fixture();
    assert!(!finish_connected_send(
        &mut state,
        &mut queues,
        PendingSendKind::Reachability,
        None,
        start,
        &[0; 512],
        &[0xff; 482],
        Dscp::BestEffort,
        0,
        None
    ));
    assert!(state.pending_send.is_some() && needs_active_retry(&state, false));
}

#[test]
fn native_initial_and_post_idle_bursts_after_multiple_generic_cycles_complete() {
    use crate::pump::port::lockfree::Event;
    for (max_pps, rounds, count, payload_size, wait_secs) in [
        (2000, 2u8, 64u8, 80usize, 5),
        // More source bytes than three maximum-TU packets: this necessarily
        // queues several ordinary datagrams across many 250 ms proof cycles.
        (1, 1, 3, 10_000, 25),
    ] {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let magic = CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s;
        let keypair = new_keypair_from_connect_magic1(magic).unwrap();
        let address = STPAddress {
            ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            port,
            magic1: magic,
            key: keypair.public.clone(),
        };
        let peer = address.connection_key();
        let log = Arc::new(Mutex::new(Vec::new()));
        let options = || NetworkThreadOptions {
            datagram_log: Some(log.clone()),
            ..Default::default()
        };
        let (server_pump, mut server) = new_pump_with_options(
            vec![keypair],
            port,
            Some(max_pps),
            (1_000_000, 1 << 20, 1 << 20),
            1 << 20,
            options(),
        );
        let (client_pump, mut client) = new_pump_with_options(
            vec![new_keypair_from_connect_magic1(magic).unwrap()],
            0,
            Some(max_pps),
            (1_000_000, 1 << 20, 1 << 20),
            1 << 20,
            options(),
        );
        let _server_worker = Worker::start(server_pump);
        let _client_worker = Worker::start(client_pump);
        assert!(client.try_connect(address));
        let (mut outgoing, mut incoming) = (false, false);
        let connected_by = Instant::now() + Duration::from_secs(5);
        while !outgoing || !incoming {
            while let Some(event) = client.try_recv() {
                match event {
                    Event::Connected { peer: p, .. } => {
                        assert_eq!(p, peer);
                        outgoing = true;
                    }
                    _ => panic!("unexpected client lifecycle event"),
                }
            }
            while let Some(event) = server.try_recv() {
                match event {
                    Event::Connected { .. } => incoming = true,
                    _ => panic!("unexpected server lifecycle event"),
                }
            }
            assert!(Instant::now() < connected_by);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut received = BTreeSet::new();
        for round in 0u8..rounds {
            let before = log
                .lock()
                .unwrap()
                .iter()
                .filter(|d| matches!(d.kind, "reachability" | "reachability_current"))
                .count();
            // No application command/service call: both retained native schedulers
            // must park and wake solely for generic send and receipt deadlines.
            std::thread::sleep(Duration::from_millis(1100));
            let after = log
                .lock()
                .unwrap()
                .iter()
                .filter(|d| matches!(d.kind, "reachability" | "reachability_current"))
                .count();
            assert!(after >= before + 4, "multiple generic idle cycles must run");
            let burst_started = Instant::now();
            let delivered_by = burst_started + Duration::from_secs(wait_secs);
            for i in 0u8..count {
                let mut bytes = vec![i; payload_size];
                bytes[0] = round * count + i;
                while !client.try_send(peer, 0, Dscp::BestEffort, &mut bytes) {
                    assert!(
                        Instant::now() < delivered_by,
                        "ring command did not wake parked pump"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            while received.len() < (round as usize + 1) * count as usize {
                while let Some(event) = server.try_recv() {
                    match event {
                        Event::Message { data, .. } => {
                            assert_eq!(data.len(), payload_size);
                            received.insert(data[0]);
                        }
                        _ => panic!("unexpected lifecycle event during burst"),
                    }
                }
                assert!(
                    Instant::now() < delivered_by,
                    "ordinary burst stalled after generic-only idle"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            if max_pps == 1 {
                assert!(burst_started.elapsed() >= Duration::from_secs(1));
                let captured = log.lock().unwrap();
                assert!(captured.iter().filter(|d| d.kind == "data").count() >= 4);
                assert!(captured.iter().filter(|d| matches!(d.kind, "reachability" | "reachability_current")).count() >= after + 4);
            }
        }
        assert_eq!(received.len(), rounds as usize * count as usize);
    }
}

// Socket-free tests use the real send commitment and native first-positive gate;
// all decisions are deferred until every positive in the ACK has been processed.
fn recovery_ack(state: &mut ConnectionStateConnected, sequences: &[u64], now: u64) -> bool {
    let mut proof = false;
    for &sequence in sequences {
        if state.take_positive_receipt(sequence).is_some() {
            proof |= state.on_positive_receipt(sequence, now);
        }
    }
    let decision = proof && state.current_tu > 512 && state.recovery.ready(now, state.current_tu);
    if decision {
        state.recovery.downshifted(now);
        state.downshift_for_recovery(false, now);
    }
    decision
}
fn recovery_send(state: &mut ConnectionStateConnected, queues: &mut SendQueues,
    kind: PendingSendKind, sent: u64, bytes: usize) -> u64 {
    let sequence = state.send_sequence_number;
    commit_connected_send(state, queues, kind, sent, bytes, &[], 0, None);
    sequence
}

#[test]
fn recovery_final_ack_budget_rechecks_failures_after_later_small_rtt_sample() {
    for late_first in [false, true] {
        let (mut state, mut queues, start) = parked_fixture();
        let seed = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, start + 1, 512);
        assert!(!recovery_ack(&mut state, &[seed], start + 20_000_001));
        let now = start + 8_000_000_000;
        let late = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, now - 3_500_000_000, 512);
        for sent in [now - 1_500_000_000, now - 1_250_000_000] {
            recovery_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent, sent, 1204);
        }
        let first = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, now - 21_000_000, 512);
        assert!(!recovery_ack(&mut state, &[first], now - 1_000_000));
        let trigger = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, now - 20_000_000, 512);
        // Bitmap iteration precedes the independent sample; both processing
        // orders are valid on wire even though data nonces are monotonic.
        let mut ack = sample_ack(if late_first { trigger } else { late }, 512);
        ack.receipt_base = if late_first { late } else { trigger };
        ack.bitmap[0] = 1;
        let ack = state.decode_peer_ack(&ack.encode()).unwrap();
        let sequences = ack.acknowledged().collect::<Vec<_>>();
        assert_eq!(sequences, if late_first { vec![late, trigger] } else { vec![trigger, late] });
        assert!(!recovery_ack(&mut state, &sequences, now),
            "final generic RTT budget must invalidate earlier immature failures");
        assert_eq!(state.current_tu, 1204);
        let mature = now + 3_000_000_000;
        let next = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, mature - 20_000_000, 512);
        assert!(recovery_ack(&mut state, &[next], mature), "the same failures eventually mature");
        assert_eq!(state.current_tu, 512);
    }
}

#[test]
fn recovery_healthy_idle_drain_ignores_old_lost_ordinary_and_is_size_independent() {
    for payload_size in [80, 512, 10_000] {
        let (mut state, mut queues, start) = parked_fixture();
        state.current_tu = 1322;
        // An old lost ordinary record survives the application stopping at45s.
        recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 1, 1322);
        let final_data = recovery_send(&mut state, &mut queues, PendingSendKind::Data,
            start + 44_976_000_000, 1322);
        assert!(!recovery_ack(&mut state, &[final_data], start + 44_977_000_000));
        let mut saw_small = 0;
        let mut saw_current = 0;
        for tick in 0..40 {
            let now = start + 45_000_000_000 + tick * crate::mtu_recovery::PERIOD;
            let size = state.recovery.probe_size(state.current_tu);
            let kind = if size == 512 { saw_small += 1; PendingSendKind::Reachability }
                else { saw_current += 1; PendingSendKind::ReachabilityCurrent };
            let sequence = recovery_send(&mut state, &mut queues, kind, now, size as usize);
            assert!(!recovery_ack(&mut state, &[sequence], now + 1_000_000));
            assert_eq!(state.current_tu, 1322, "false idle shrink after {payload_size}B app");
            assert!(!needs_active_retry(&state, false) || state.active_send_frontier > state.packets_waiting_ack_tail);
        }
        assert_eq!((saw_small, saw_current), (20, 20));
    }
}

#[test]
fn recovery_repeated_differential_probes_recover_idle_and_high_rate_blackhole() {
    for ordinary_per_slot in [0, 5000] {
        let (mut state, mut queues, start) = parked_fixture();
        state.current_tu = 1322;
        let mut decisions = 0;
        for tick in 0..=8 {
            let now = start + 1 + tick * crate::mtu_recovery::PERIOD;
            let size = state.recovery.probe_size(state.current_tu);
            let kind = if size == 512 { PendingSendKind::Reachability }
                else { PendingSendKind::ReachabilityCurrent };
            let sequence = recovery_send(&mut state, &mut queues, kind, now, size as usize);
            // More than the complete metadata ring churns between probes. The
            // protected generic ledger must retain both failures AND positives.
            for _ in 0..ordinary_per_slot {
                recovery_send(&mut state, &mut queues, PendingSendKind::Data, now + 1, 1322);
            }
            if size == 512 {
                assert!(state.recovery.is_generic(sequence));
                let changed = recovery_ack(&mut state, &[sequence], now + 10_000_000);
                decisions += usize::from(changed);
                if tick < 8 { assert!(!changed, "two aged failures required"); }
            }
        }
        assert_eq!(decisions, 1, "ordinary_per_slot={ordinary_per_slot}");
        assert_eq!(state.current_tu, 512);
        assert_eq!(state.recovery.upward_after, start + 12_010_000_001);
        assert!(!state.recovery.can_promote(1322, start + 2_100_000_000, start + 3_000_000_000));
        assert!(state.recovery.can_promote(1204, start + 2_100_000_000, start + 3_000_000_000));
    }
}

#[test]
fn upward_policy_cadence_is_bounded_and_success_preserves_the_floor() {
    use crate::mtu_recovery::upward_retry_delay;
    for (failures, delay) in [(0, 500_000_000), (1, 500_000_000),
        (2, 1_000_000_000), (10, 25_000_000_000), (11, 30_000_000_000),
        (u64::MAX, 30_000_000_000)] {
        assert_eq!(upward_retry_delay(failures), delay);
    }
    let (mut state, mut queues, start) = parked_fixture();
    assert!(state.prepare_upward_probe(start));
    assert_eq!(state.tu_probe_size, 1452);
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, start, 1452);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, start, start + 1);
    assert_eq!(state.current_tu, 1452);
    assert_eq!(state.last_sent_tu_probe_time_ns, start);
    assert_eq!(state.upward_probe_deadline(start), start + 500_000_000);
    state.stats.cc_rate_upps = 1;
    assert!(!state.prepare_upward_probe(start + 499_999_999));
    assert_eq!(state.upward_probe_deadline(start), start + 500_000_000);
    state.recovery.upward_after = start + 10_000_000_000;
    assert_eq!(state.upward_probe_deadline(start), state.recovery.upward_after);
}

#[test]
fn upward_policy_coarse_bracket_paths_stop_within_eight_bytes() {
    for (limit, shrink) in [(1452, false), (1472, false), (1322, false),
        (1366, false), (9216, false), (512, true), (700, true), (1204, true)] {
        let (mut state, mut queues, mut now) = parked_fixture();
        let start = now;
        if shrink { state.downshift_for_recovery(false, now); }
        let mut attempted = Vec::new();
        for _ in 0..24 {
            let due = state.upward_probe_deadline(now);
            // The settled bracket waits for revalidation instead of one-byte climbing.
            if due > now + 2_000_000_000 { break; }
            now = now.max(due);
            assert!(state.prepare_upward_probe(now));
            let candidate = state.tu_probe_size;
            attempted.push(candidate);
            let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
                now, candidate as usize);
            let success = candidate <= limit;
            if success {
                assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
            }
            state.finish_upward_probe(success, now, now + 20_000_000);
            now += 20_000_000;
            if state.current_tu == 9216 { break; }
        }
        assert_eq!(attempted[0], if shrink { 858 } else { 1452 });
        assert!(state.current_tu <= limit && limit - state.current_tu <= 8,
            "limit={limit}, floor={}, attempts={attempted:?}", state.current_tu);
        assert!(now - start < 10_000_000_000, "{attempted:?}");
        assert!(attempted.iter().all(|&n| n <= 9216));
        println!("BRACKET limit={limit} shrink={shrink} floor={} ns={} attempts={attempted:?}",
            state.current_tu, now - start);
    }
}

#[test]
fn upward_policy_drop_refines_inside_hold_then_revalidates_stepup_and_false_loss() {
    let (mut state, mut queues, start) = parked_fixture();
    state.promote_tu(1472, start);
    state.recovery.downshifted(start);
    state.downshift_for_recovery(false, start);
    let mut now = start;
    let mut reached = None;
    for _ in 0..16 {
        let due = state.upward_probe_deadline(now);
        if due > now + 2_000_000_000 { break; }
        now = now.max(due);
        assert!(state.prepare_upward_probe(now));
        let candidate = state.tu_probe_size;
        assert!(candidate < 1472);
        let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
            now, candidate as usize);
        let success = candidate <= 1172;
        if success { assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe)); }
        state.finish_upward_probe(success, now, now + 20_000_000);
        now += 20_000_000;
        if state.current_tu >= 1100 { reached.get_or_insert(now); }
    }
    assert!(reached.unwrap() < start + 10_000_000_000);
    assert!((1164..=1172).contains(&state.current_tu));
    let due = state.upward_probe_deadline(now);
    assert_eq!(due, (now + 5_000_000_000).max(start + 10_000_000_000));
    assert!(!state.prepare_upward_probe(due - 1));
    assert!(state.prepare_upward_probe(due));
    let boundary = state.tu_probe_size;
    assert!(boundary > state.current_tu && boundary - state.current_tu <= 8);
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
        due, boundary as usize);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, due, due + 20_000_000);
    assert_eq!(state.current_tu, boundary);
    assert_eq!(state.upward_probe_deadline(due), due + 500_000_000);
    assert!(state.prepare_upward_probe(due + 500_000_000));
    assert_eq!(state.tu_probe_size, 1452, "partial lift opens coarse discovery after exact boundary proof");
}

#[test]
fn upward_policy_resets_only_on_effective_shrink_and_obsoletes_old_attempts() {
    for success in [false, true] {
        for deferred in [false, true] {
            let (mut state, mut queues, start) = parked_fixture();
            assert!(state.prepare_upward_probe(start));
            recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, start, 1452);
            state.tu_probe_failed_count = 40;
            if deferred {
                assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::Data,
                    None, start + 1, &[9; 1204], &[], Dscp::BestEffort, 0, None));
            }
            state.downshift_for_recovery(false, start + 1);
            if deferred {
                assert_eq!((state.current_tu, state.tu_probe_failed_count), (1204, 40));
                let pending = state.pending_send.take().unwrap();
                assert_eq!(pending.bytes, vec![9; 1204]);
                commit_connected_send(&mut state, &mut queues, pending.kind, start + 2,
                    pending.bytes.len(), &pending.plaintext, 0, None);
            }
            assert_eq!((state.current_tu, state.tu_probe_failed_count), (512, 0));
            state.finish_upward_probe(success, start, start + 3);
            assert_eq!((state.current_tu, state.tu_probe_failed_count), (512, 0));
            assert!(state.prepare_upward_probe(start + 500_000_000));
            assert_eq!(state.tu_probe_size, 858);
            state.finish_upward_probe(false, start + 4, start + 5);
            assert!(state.prepare_upward_probe(start + 500_000_000));
            assert_eq!(state.tu_probe_size, 685);
        }
    }
}

#[test]
fn upward_policy_locally_refused_old_probe_keeps_immutable_tuple_across_shrink() {
    for success in [false, true] {
        let (mut state, mut queues, start) = parked_fixture();
        assert!(state.prepare_upward_probe(start));
        let old_size = state.tu_probe_size;
        let old_nonce = state.send_sequence_number;
        assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
            None, start, &vec![7; old_size as usize], &[], Dscp::BestEffort, 0, None));
        state.downshift_for_recovery(false, start);
        assert_eq!((state.current_tu, state.tu_probe_size), (512, old_size));
        let pending = state.pending_send.take().unwrap();
        assert_eq!(pending.bytes, vec![7; old_size as usize]);
        assert_eq!(state.send_sequence_number, old_nonce);
        commit_connected_send(&mut state, &mut queues, pending.kind, start + 1,
            pending.bytes.len(), &pending.plaintext, 0, None);
        assert_eq!((state.tu_probe_sequence_number, state.tu_probe_size), (old_nonce, old_size));
        state.finish_upward_probe(success, start + 1, start + 2);
        assert_eq!((state.current_tu, state.tu_probe_failed_count), (512, 0));
        assert!(state.prepare_upward_probe(start + 500_000_001));
        assert_eq!(state.tu_probe_size, 858);
    }
}

// Locate a boundary through an accepted probe's completed loss outcome. The
// fixture starts with a known floor so the tests isolate revalidation, not search.
fn boundary_fixture() -> (ConnectionStateConnected, SendQueues, u64) {
    let (mut state, mut queues, start) = parked_fixture();
    state.apply_effective_tu(1068, start);
    state.tu_probe_size = 1076;
    state.tu_probe_obsolete = false;
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, start, 1076);
    state.finish_upward_probe(false, start, start + 20_000_000);
    assert_eq!(state.upward_probe_deadline(start), start + 5_020_000_000);
    (state, queues, start)
}

#[test]
fn boundary_refused_probe_keeps_exact_ciphertext_nonce_and_outcome_clock() {
    let (mut state, mut queues, start) = boundary_fixture();
    let (cipher, _) = super::wire_v2_tests::ciphers();
    state.cipher = Some(cipher);
    for delay in [10_000_000_000, 20_000_000_000, 30_000_000_000, 30_000_000_000] {
        let due = state.upward_probe_deadline(start);
        assert!(!state.prepare_upward_probe(due - 1));
        assert!(state.prepare_upward_probe(due));
        assert_eq!(state.tu_probe_size, 1076);
        let nonce = state.send_sequence_number;
        let last = state.last_sent_tu_probe_time_ns;
        let failures = state.tu_probe_failed_count;
        let mut ciphertext = vec![0; 1076];
        let n = seal_connected_packet(&mut state.cipher, 42, nonce, &[0xff; 1046],
            &mut ciphertext, due).unwrap();
        assert_eq!(n, 1076);
        assert_eq!(load_u64(&ciphertext[2..10]), nonce);
        assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
            None, due, &ciphertext, &[], Dscp::BestEffort, 42, None));
        // Refusal, timer reads, generic clocks and 30s evidence expiry cannot
        // count a failed attempt or rewrite the already sealed target.
        for now in [due, due + 1, due + 31_000_000_000] {
            assert_eq!(state.upward_probe_deadline(now), due);
            assert_eq!((state.send_sequence_number, state.last_sent_tu_probe_time_ns,
                state.tu_probe_failed_count), (nonce, last, failures));
            assert_eq!(state.tu_probe_sequence_number, u64::MAX);
            assert_eq!(state.recovery.sent_bytes(nonce), None);
            assert!(state.take_positive_receipt(nonce).is_none());
            let pending = state.pending_send.as_ref().unwrap();
            assert_eq!(pending.bytes, ciphertext);
            assert_eq!(pending.kind, PendingSendKind::MtuProbe);
            assert!(needs_active_retry(&state, false));
            assert_eq!(next_service_deadline(now, due), now + 150_000);
        }
        let accepted = due + 31_000_000_000;
        let pending = state.pending_send.take().unwrap();
        assert!(finish_connected_send(&mut state, &mut queues, pending.kind, Some(accepted),
            accepted, &pending.bytes, &pending.plaintext, pending.dscp, 42, None));
        assert_eq!(state.last_sent_tu_probe_time_ns, accepted);
        assert_eq!(state.tu_probe_sequence_number, nonce);
        assert_eq!(state.recovery.sent_bytes(nonce), Some(1076));
        assert_eq!(state.tu_probe_failed_count, failures, "acceptance alone is not failure");
        let outcome = accepted + 20_000_000;
        state.finish_upward_probe(false, accepted, outcome);
        assert_eq!(state.tu_probe_failed_count, failures + 1);
        assert_eq!(state.upward_probe_deadline(outcome), outcome + delay);
        assert_eq!(state.current_tu, 1068);
    }
}

#[test]
fn boundary_fresh_receipt_clears_only_after_pending_copy_effective_promotion() {
    for copy in [false, true] {
        let (mut state, mut queues, start) = boundary_fixture();
        let due = state.upward_probe_deadline(start);
        assert!(state.prepare_upward_probe(due));
        let probe = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, due, 1076);
        let mut plaintext = vec![0xff; 1054];
        plaintext[..4].copy_from_slice(&[1, 1, 0, 7]);
        if copy {
            plaintext[0] |= TARGET_DUP_ORIGINAL;
            queues.fec_prepare_packet(state.send_sequence_number);
            queues.target_duplicate = Some((state.send_sequence_number, Dscp::BestEffort, plaintext.clone()));
            assert!(finish_connected_send(&mut state, &mut queues, PendingSendKind::Data,
                Some(due + 1), due + 1, &[8; 1068], &plaintext, Dscp::BestEffort, 0, None));
            queues.fec_prepare_packet(state.send_sequence_number);
            let mut prepared_copy = vec![0; plaintext.len()];
            assert_eq!(queues.take_target_copy(&mut prepared_copy), plaintext.len());
            assert_eq!(&prepared_copy[1..], &plaintext[1..]);
            assert!(target_is_copy(&prepared_copy));
            plaintext = prepared_copy;
        }
        assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::Data,
            None, due + 1, &[9; 1068], &plaintext, Dscp::BestEffort, 0, None));
        assert!(state.decode_peer_ack(&sample_ack(probe, 1068).encode()).is_none());
        let ack = state.decode_peer_ack(&sample_ack(probe, 1076).encode()).unwrap();
        assert_eq!(ack.sample_seq, probe);
        assert_eq!(state.take_positive_receipt(probe), Some(PositiveReceipt::PendingProbe));
        state.finish_upward_probe(true, due, due + 20_000_000);
        assert!(state.take_positive_receipt(probe).is_none(), "duplicate cannot promote twice");
        assert_eq!((state.current_tu, state.deferred_tu), (1068, Some(1076)));
        assert_eq!(state.upward_probe_deadline(due + 20_000_000), due + 500_000_000,
            "old boundary is retained until its floor actually changes");
        let pending = state.pending_send.take().unwrap();
        assert_eq!(pending.bytes, vec![9; 1068]);
        commit_connected_send(&mut state, &mut queues, pending.kind, due + 30_000_000,
            pending.bytes.len(), &pending.plaintext, 0, None);
        // The bound survives proof and refusal; only acceptance of this exact
        // pending datagram (the copy in the second case) makes growth effective.
        assert_eq!((state.current_tu, state.deferred_tu), (1076, None));
        assert!(state.prepare_upward_probe(due + 500_000_000));
        assert_eq!(state.tu_probe_size, 1452, "cleared ceiling opens coarse discovery");
    }
}

#[test]
fn boundary_partial_lift_reopens_binary_search_and_stale_proof_cannot_unlock() {
    let (mut state, mut queues, start) = boundary_fixture();
    let due = state.upward_probe_deadline(start);
    assert!(state.prepare_upward_probe(due));
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, due, 1076);
    state.finish_upward_probe(true, due, due + 2_000_000_001);
    assert_eq!(state.current_tu, 1068);
    assert_eq!(state.upward_probe_deadline(due + 2_000_000_001), due + 500_000_000);
    let mut now = due + 3_000_000_000;
    let mut attempts = Vec::new();
    for _ in 0..24 {
        now = now.max(state.upward_probe_deadline(now));
        assert!(state.prepare_upward_probe(now));
        let size = state.tu_probe_size;
        attempts.push(size);
        let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, size as usize);
        if size <= 1200 {
            assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
        }
        state.finish_upward_probe(size <= 1200, now, now + 20_000_000);
        now += 20_000_000;
        if state.upward_probe_deadline(now) > now + 2_000_000_000 { break; }
    }
    assert_eq!(&attempts[..2], &[1076, 1452]);
    assert!((1192..=1200).contains(&state.current_tu), "{attempts:?}");
}

#[test]
fn upward_policy_stale_positive_does_not_mutate_search_or_floor() {
    let (mut state, _, start) = parked_fixture();
    assert!(state.prepare_upward_probe(start));
    let before = state.upward_probe_deadline(start);
    state.finish_upward_probe(true, start, start + 2_000_000_001);
    assert_eq!(state.current_tu, 1204);
    assert_eq!(state.tu_probe_failed_count, 0);
    assert_eq!(state.upward_probe_deadline(start), before);
    assert!(state.prepare_upward_probe(start));
    assert_eq!(state.tu_probe_size, 1452);
}

#[test]
fn upward_policy_valid_loss_after_generic_freshness_still_refines() {
    let (mut state, mut queues, start) = parked_fixture();
    state.loss_timer.observe(1_000_000_000); // Ordinary jitter, independent of generic B.
    let timeout = state.loss_timer.timeout_ns(20_000_000, 0, &crate::ship::CC);
    assert_eq!(timeout, 3_000_000_000);
    assert!(state.prepare_upward_probe(start));
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, start, 1452);
    let now = start + timeout + 1;
    assert!(!state.recovery.upward_fresh(start, now));
    state.finish_upward_probe(false, start, now);
    assert_eq!(state.current_tu, 1204);
    assert_eq!(state.tu_probe_failed_count, 1);
    assert!(state.prepare_upward_probe(now));
    assert_eq!(state.tu_probe_size, 1328, "valid aged loss must not loop on 1452");
}

fn repeated_probe_fixture() -> (ConnectionStateConnected, SendQueues, u64, [u64; 2], [u64; 2]) {
    let (mut state, mut queues, start) = parked_fixture();
    let large = [
        recovery_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent, start + 1, 1204),
        recovery_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent, start + 500_000_001, 1204),
    ];
    let small = [
        recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, start + 600_000_000, 512),
        recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, start + 1_100_000_000, 512),
    ];
    (state, queues, start, large, small)
}

#[test]
fn outage_proof_ledger_retains_exact_pending_probe_through_2500ms_generic_churn() {
    let (mut state, mut queues, start) = parked_fixture();
    enter_outage(&mut state, &mut queues, start, 0, None);
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::Outage, start + 1, 1204);
    let mut old_slots = [(u64::MAX, 0); 8];
    old_slots[probe as usize % 8] = (probe, start + 1);
    for tick in 1..=10 {
        let sent = start + tick * crate::mtu_recovery::PERIOD;
        let kind = if tick % 2 == 0 { PendingSendKind::ReachabilityCurrent }
            else { PendingSendKind::Reachability };
        let bytes = if tick % 2 == 0 { 1204 } else { 512 };
        let seq = recovery_send(&mut state, &mut queues, kind, sent, bytes);
        old_slots[seq as usize % 8] = (seq, sent);
    }
    let now = start + 2_500_000_001;
    let ack = state.decode_peer_ack(&sample_ack(probe, 1204).encode()).unwrap();
    assert_ne!(old_slots[probe as usize % 8].0, probe, "legacy proof tuple was overwritten");
    assert!(probe >= state.packets_waiting_ack_tail);
    assert_ne!(state.packets_waiting_ack_field[0] & (1 << probe), 0);
    assert!(state.send_time(probe) != 0 && now.saturating_sub(state.send_time(probe)) < 3_000_000_000);
    println!("OUTAGE_LEDGER_MEMORY outage_state={} connected_state={} reservation={}",
        std::mem::size_of::<OutageState>(), std::mem::size_of::<ConnectionStateConnected>(),
        RECEIVE_CONNECTION_BYTES);
    assert!(recent_outage_probe_acked(&state, &ack, now),
        "a still-outstanding exact 2.5-second-old outage proof must survive generic churn");
    assert_eq!(state.take_positive_receipt(probe), Some(PositiveReceipt::PendingData));
    assert!(!recent_outage_probe_acked(&state, &ack, now + 1), "first positive consumes proof");
}

#[test]
fn outage_proof_ledger_preserves_age_epoch_pending_and_exact_identity_gates() {
    let (mut state, mut queues, start) = parked_fixture();
    state.RTT_mean = 1000;
    enter_outage(&mut state, &mut queues, start, 0, None);
    assert_eq!(state.outage.max_probe_age_ns, 4_000_000_000);
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::Outage, start + 1, 1204);
    let ack = sample_ack(probe, 1204);
    assert!(recent_outage_probe_acked(&state, &ack, start + 4_000_000_001));
    assert!(!recent_outage_probe_acked(&state, &ack, start + 4_000_000_002));
    assert!(!recent_outage_probe_acked(&state, &ack, start), "future send time");
    assert!(state.decode_peer_ack(&sample_ack(probe, 512).encode()).is_none());
    let small = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, start + 2, 512);
    let mut bitmap_ack = sample_ack(small, 512);
    bitmap_ack.bitmap[0] = 1 << probe;
    let bitmap_ack = state.decode_peer_ack(&bitmap_ack.encode()).unwrap();
    assert!(recent_outage_probe_acked(&state, &bitmap_ack, start + 10),
        "a retained proof may be in the bitmap rather than the size sample");
    let bit = probe % PACKETS_WAITING_ACK_CAPACITY;
    state.packets_waiting_ack_field[(bit / 64) as usize] &= !(1 << (bit % 64));
    assert!(!recent_outage_probe_acked(&state, &ack, start + 10), "not pending");
    state.packets_waiting_ack_field[(bit / 64) as usize] |= 1 << (bit % 64);
    state.packets_waiting_ack_tail = probe + 1;
    assert!(!recent_outage_probe_acked(&state, &ack, start + 10), "retired before tail");
    state.packets_waiting_ack_tail = probe;
    let future = state.send_sequence_number;
    state.outage.record_probe(future, start + 2);
    assert!(!recent_outage_probe_acked(&state, &sample_ack(future, 1204), start + 10),
        "only accepted emitted nonces are plausible");
    state.outage.enter(start + 20, 100_000_000);
    assert!(state.outage.probes.iter().all(|&tuple| tuple == (0, 0)));
    assert_eq!(state.outage.probe_cursor, 0);
    assert!(!recent_outage_probe_acked(&state, &ack, start + 30), "new outage clears old proof");
    state.outage.record_probe(probe, start + 1);
    assert!(!recent_outage_probe_acked(&state, &ack, start + 30), "epoch send-time gate");
    state.outage.enter(start + 40, 100_000_000);
    for i in 0..=OUTAGE_PROBE_RECORDS {
        state.outage.record_probe(i as u64, start + 41 + i as u64);
    }
    assert!(!state.outage.probes.iter().any(|&(seq, _)| seq == 0));
    assert!(!recent_outage_probe_acked(&state, &ack, start + 100), "chronological eviction");
}

#[test]
fn outage_proof_ledger_encrypted_replay_cannot_reuse_a_consumed_positive() {
    let (mut state, mut queues, start) = parked_fixture();
    enter_outage(&mut state, &mut queues, start, 0, None);
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::Outage, start + 1, 1204);
    let (sender, mut receiver) = super::wire_v2_tests::ciphers();
    let mut sender = Some(sender);
    let nonce = crate::sequence::ACK_SPACE;
    let mut packet = [0; 182];
    let n = seal_connected_packet(&mut sender, 42, nonce, &sample_ack(probe, 1204).encode(),
        &mut packet, start + 2).unwrap();
    let mut plaintext = [0; 182];
    for replay in [false, true] {
        let len = receiver.open(nonce, load_u32(&packet[10..14]), &packet[..14],
            &packet[14..n], &mut plaintext, start + 10).unwrap();
        let fresh = state.receive_sequences.commit(nonce);
        assert_eq!(fresh, !replay);
        if fresh {
            let ack = state.decode_peer_ack(&plaintext[..len]).unwrap();
            assert!(recent_outage_probe_acked(&state, &ack, start + 10));
            assert!(state.take_positive_receipt(probe).is_some());
            assert!(!recent_outage_probe_acked(&state, &ack, start + 11));
        }
    }
}

#[test]
fn outage_proof_ledger_memory_delta_fits_existing_connection_reservation() {
    let added = (OUTAGE_PROBE_RECORDS - 8) * std::mem::size_of::<(u64, u64)>()
        + std::mem::size_of::<usize>();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Independently measured be71bf4: Outage232, Recovery56; research
        // Connected already carried a pre-existing 40-byte feature delta.
        let baseline = if cfg!(feature = "research_target_validation") { 44384 } else { 44344 };
        assert_eq!(added, 392);
        assert_eq!(std::mem::size_of::<OutageState>(), 232 + added);
        let recovery_state_added = std::mem::size_of::<crate::mtu_recovery::Recovery>() - 56;
        assert_eq!(recovery_state_added, 24 + 16 + 16,
            "raw RTT/count, recent search upper/expiry, independent boundary clock/backoff");
        // Preserve the 416-byte outage/RTT delta; bracket and boundary state
        // add 32 and replace the old 8-byte additive-search step.
        assert_eq!(std::mem::size_of::<ConnectionStateConnected>(),
            baseline + added + recovery_state_added - 8);
    }
    assert!(std::mem::size_of::<ConnectionStateConnected>() < 512 << 10);
    assert_eq!(RECEIVE_CONNECTION_BYTES, (512 << 10) + crate::mtu_recovery::HISTORY_BYTES);
    println!("OUTAGE_LEDGER_MEMORY added={added} state={} connected={} reservation={}",
        std::mem::size_of::<OutageState>(), std::mem::size_of::<ConnectionStateConnected>(),
        RECEIVE_CONNECTION_BYTES);
}

fn sample_ack(sequence: u64, bytes: u16) -> crate::ack::BitmapAck {
    crate::ack::BitmapAck { highest: sequence, receipt_base: 0, sample_seq: sequence,
        sample_udp_payload_bytes: bytes, delay_us: 0, ce_count: 0, bitmap: [0; 15] }
}

// Encrypted ACK-stage regression, not a full socket-injection fixture. This
// executes the production AEAD/replay/decode gates in their receive-loop order.
#[test]
fn profile_four_ack_encrypted_wrong_size_spends_nonce_without_feedback_effects() {
    let (mut state, mut queues, start) = parked_fixture();
    let (sender, receiver) = super::wire_v2_tests::ciphers();
    let mut sender = Some(sender);
    state.cipher = Some(receiver);
    assert!(state.prepare_upward_probe(start));
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, start, 1452);
    assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::Data,
        None, start + 1, &[9; 1204], &[], Dscp::BestEffort, 0, None));
    state.promote_tu(1366, start + 1);
    let before = (state.packets_waiting_ack_field, state.peer_ce_count, state.current_tu,
        state.deferred_tu, state.last_ack_received_time, state.tu_probe_sequence_number);
    let pending_bytes = state.pending_send.as_ref().unwrap().bytes.clone();
    let mut encrypted = [0; 182];
    let mut plaintext = [0; 182];
    for (step, bytes) in [(0, 512), (1, 1452)] {
        let nonce = crate::sequence::ACK_SPACE + step;
        let mut ack = sample_ack(probe, bytes);
        ack.ce_count = 1;
        let n = seal_connected_packet(&mut sender, 42, nonce, &ack.encode(),
            &mut encrypted, start + 2 + step).unwrap();
        assert_eq!(n, 182);
        let epoch = load_u32(&encrypted[10..14]);
        let len = state.cipher.as_mut().unwrap().open(nonce, epoch, &encrypted[..14],
            &encrypted[14..n], &mut plaintext, start + 10 + step).unwrap();
        assert_eq!(len, crate::ack::ACK_PAYLOAD_LEN);
        assert!(crate::sequence::is_ack_space(nonce));
        assert!(state.receive_sequences.commit(nonce));
        let decoded = state.decode_peer_ack(&plaintext[..len]);
        if step == 0 {
            assert!(decoded.is_none());
            assert_eq!((state.packets_waiting_ack_field, state.peer_ce_count, state.current_tu,
                state.deferred_tu, state.last_ack_received_time, state.tu_probe_sequence_number), before);
            assert_eq!(state.pending_send.as_ref().unwrap().bytes, pending_bytes);
            // The authenticated packet remains decryptable, but its replay
            // commit cannot be undone by failure of the later semantic gate.
            state.cipher.as_mut().unwrap().open(nonce, epoch, &encrypted[..14],
                &encrypted[14..n], &mut plaintext, start + 20).unwrap();
            assert!(!state.receive_sequences.commit(nonce));
        } else {
            let decoded = decoded.unwrap();
            assert_eq!(decoded.sample_udp_payload_bytes, 1452);
            assert_eq!(state.take_positive_receipt(probe), Some(PositiveReceipt::PendingProbe));
            state.on_positive_receipt(probe, start + 30);
            state.finish_upward_probe(true, start, start + 30);
            assert_eq!(state.current_tu, 1204, "pending ciphertext still defers promotion");
            assert_eq!(state.deferred_tu, Some(1452));
            assert_eq!(state.pending_send.as_ref().unwrap().bytes, pending_bytes);
        }
    }
}

#[test]
fn profile_four_ack_sample_size_rejects_mismatch_before_receipt_ce_or_tu_changes() {
    let (mut state, mut queues, start, large, small) = repeated_probe_fixture();
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
        start + 1_200_000_000, 1472);
    state.tu_probe_size = 1472;
    let before = (state.packets_waiting_ack_field, state.peer_ce_count, state.current_tu,
        state.last_ack_received_time, state.tu_probe_sequence_number);
    for (sequence, size) in [(large[0], 512), (small[0], 1204), (probe, 1204)] {
        let mut ack = sample_ack(sequence, size);
        ack.ce_count = 1;
        ack.bitmap[0] = (1 << small[0]) | (1 << small[1]) | (1 << probe);
        assert!(state.decode_peer_ack(&ack.encode()).is_none());
        assert_eq!((state.packets_waiting_ack_field, state.peer_ce_count, state.current_tu,
            state.last_ack_received_time, state.tu_probe_sequence_number), before);
    }
    let good = sample_ack(probe, 1472).encode();
    assert!(state.decode_peer_ack(&good).is_some());
    for (offset, value) in [(28, 0), (29, 1), (30, 0), (31, 0)] {
        let mut malformed = good;
        if offset >= 30 { malformed[30..32].fill(0); }
        else { malformed[offset] = value; }
        assert!(state.decode_peer_ack(&malformed).is_none());
    }
    assert_eq!(good.len(), 152);
    for magic in [CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s,
        CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b] {
        assert_eq!(good.len() + total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(magic).unwrap(), 182);
    }
}

#[test]
fn profile_four_ack_size_belongs_to_sample_not_highest_or_other_bitmap_receipts() {
    let (mut state, mut queues, start, _, small) = repeated_probe_fixture();
    let large = recovery_send(&mut state, &mut queues, PendingSendKind::Data,
        start + 1_200_000_000, 1204);
    let mut ack = sample_ack(small[1], 512);
    ack.bitmap[0] = (1 << large) | (1 << small[0]);
    let decoded = state.decode_peer_ack(&ack.encode()).unwrap();
    assert_eq!(decoded.highest, large);
    assert_eq!(decoded.sample_seq, small[1]);
    let sequences = decoded.acknowledged().collect::<Vec<_>>();
    assert!(!recovery_ack(&mut state, &sequences, start + 1_500_000_001));
    assert_eq!(state.current_tu, 1204, "mixed larger progress vetoes fallback");
    assert!(state.decode_peer_ack(&ack.encode()).is_some(), "duplicate validation is not admission");
    assert!(!recovery_ack(&mut state, &sequences, start + 1_500_000_002));
}

#[test]
fn profile_four_ack_size_uses_protected_generic_and_exact_outstanding_probe_metadata() {
    let (mut state, mut queues, start) = parked_fixture();
    let generic = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability,
        start + 1, 512);
    for i in 0..5000 {
        recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 2 + i, 1204);
    }
    assert_eq!(state.recovery.sent_bytes(generic), Some(512));
    assert!(state.decode_peer_ack(&sample_ack(generic, 1204).encode()).is_none());
    assert!(state.decode_peer_ack(&sample_ack(generic, 512).encode()).is_some());
    let probe = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
        start + 6000, 1472);
    state.tu_probe_size = 1472;
    for i in 0..5000 {
        recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 6001 + i, 1204);
    }
    assert_eq!(state.recovery.sent_bytes(probe), None);
    assert!(state.decode_peer_ack(&sample_ack(probe, 1204).encode()).is_none());
    assert!(state.decode_peer_ack(&sample_ack(probe, 1472).encode()).is_some());
    // Unknown ordinary history remains unknown, never inferred from a high-water mark.
    assert!(state.decode_peer_ack(&sample_ack(1, 512).encode()).is_some());
}

#[test]
fn recovery_single_loss_or_single_small_positive_or_upward_failure_cannot_shrink() {
    for scenario in 0..4 {
        let (mut state, mut queues, start, large, small) = repeated_probe_fixture();
        match scenario {
            0 => { // One failed current-TU probe, the other has positive proof.
                assert!(!recovery_ack(&mut state, &[large[1]], start + 600_000_001));
            }
            1 => { // Only one exact small receipt; duplicates cannot add evidence.
                assert!(!recovery_ack(&mut state, &[small[0]], start + 1_500_000_001));
                assert!(!recovery_ack(&mut state, &[small[0]], start + 1_600_000_001));
                continue;
            }
            2 => { // Failures at an old TU must not classify a promoted TU.
                state.current_tu = 1472;
                for tick in 0..2 {
                    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
                        start + 1 + tick, 1500);
                }
            }
            _ => { // The same differential history cannot resize a512TU.
                state.current_tu = 512;
            }
        }
        assert!(!recovery_ack(&mut state, &small, start + 1_500_000_001));
    }
}

#[test]
fn recovery_mixed_reordered_and_delayed_ack_progress_vetoes_entire_decision() {
    for kind in [PendingSendKind::Data, PendingSendKind::ReachabilityCurrent] {
        for large_first in [false, true] {
            let (mut state, mut queues, start, _, small) = repeated_probe_fixture();
            let good = recovery_send(&mut state, &mut queues, kind, start + 1_200_000_000, 1204);
            assert!(!recovery_ack(&mut state, &[small[0]], start + 1_300_000_000));
            let ack = if large_first { [good, small[1]] } else { [small[1], good] };
            assert!(!recovery_ack(&mut state, &ack, start + 1_500_000_001));
            assert_eq!(state.current_tu, 1204);
            let small_later = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability,
                start + 2_600_000_000, 512);
            assert!(!recovery_ack(&mut state, &[small_later], start + 2_700_000_000),
                "old failed probes must stay cancelled after the one-second veto");
        }
    }
    let (mut state, _, start, _, small) = repeated_probe_fixture();
    // Delayed receipts beyond two seconds are not fresh small evidence.
    assert!(!recovery_ack(&mut state, &small, start + 3_100_000_001));
}

#[test]
fn recovery_current_probe_refusal_keeps_ciphertext_schedule_and_deferred_tu() {
    let (mut state, mut queues, start) = parked_fixture();
    let before = state.recovery.next_probe;
    let ciphertext = vec![17; 1204];
    assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent,
        None, start, &ciphertext, &[], Dscp::BestEffort, 0, None));
    assert_eq!(state.recovery.next_probe, before);
    state.promote_tu(1472, start);
    assert_eq!(state.current_tu, 1204);
    assert_eq!(state.deferred_tu, Some(1472));
    let pending = state.pending_send.take().unwrap();
    assert_eq!(pending.bytes, ciphertext);
    commit_connected_send(&mut state, &mut queues, pending.kind, start + 1,
        pending.bytes.len(), &pending.plaintext, 0, None);
    assert_eq!(state.current_tu, 1472);
    assert_eq!(state.recovery.next_probe, start + 1 + crate::mtu_recovery::PERIOD);
    assert_eq!(state.recovery.probe_size(state.current_tu), 512);
    assert!(!needs_active_retry(&state, false));
}

#[test]
fn recovery_unknown_positive_vetoes_mixed_ack_after_ordinary_metadata_overwrite() {
    for unknown_first in [false, true] {
        let (mut state, mut queues, start) = parked_fixture();
        let good = recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 1, 1204);
        for _ in 0..5000 {
            recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 2, 1204);
        }
        let mut small = Vec::new();
        for (kind, sent, bytes) in [
            (PendingSendKind::ReachabilityCurrent, start + 10, 1204),
            (PendingSendKind::ReachabilityCurrent, start + 500_000_010, 1204),
            (PendingSendKind::Reachability, start + 600_000_000, 512),
            (PendingSendKind::Reachability, start + 1_100_000_000, 512),
        ] {
            let seq = recovery_send(&mut state, &mut queues, kind, sent, bytes);
            if bytes == 512 { small.push(seq); }
        }
        assert!(!recovery_ack(&mut state, &small[..1], start + 1_300_000_000));
        let ack = if unknown_first { [good, small[1]] } else { [small[1], good] };
        assert!(!recovery_ack(&mut state, &ack, start + 1_500_000_010));
        assert_eq!(state.current_tu, 1204);
    }
}

#[test]
fn recovery_skipped_slots_allow_recent_repeated_failures_but_not_stale_history() {
    for failed_age in [2_500_000_000, 3_000_000_001] {
        let (mut state, mut queues, start) = parked_fixture();
        recovery_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent, start + 1, 1204);
        recovery_send(&mut state, &mut queues, PendingSendKind::ReachabilityCurrent,
            start + 1_000_000_001, 1204);
        let first = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability,
            start + 1_600_000_000, 512);
        assert!(!recovery_ack(&mut state, &[first], start + 1_700_000_000));
        // Keep both exact generic RTT samples at100ms; a deliberately delayed
        // ACK would legitimately widen the adaptive failure window instead.
        let second = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability,
            start + 1 + failed_age - 100_000_000, 512);
        assert_eq!(recovery_ack(&mut state, &[second], start + 1 + failed_age),
            failed_age <= 3_000_000_000);
    }
}

#[test]
fn recovery_overwritten_old_generic_receipt_is_unknown_veto_not_fresh_proof() {
    let (mut state, mut queues, start) = parked_fixture();
    let old = recovery_send(&mut state, &mut queues, PendingSendKind::Reachability, start + 1, 512);
    for tick in 1..=300 {
        recovery_send(&mut state, &mut queues, PendingSendKind::Reachability,
            start + tick * crate::mtu_recovery::PERIOD, 512);
    }
    for _ in 0..5000 {
        recovery_send(&mut state, &mut queues, PendingSendKind::Data, start + 75_000_000_001, 1204);
    }
    assert!(!state.recovery.is_generic(old));
    assert!(!recovery_ack(&mut state, &[old], start + 75_100_000_000));
    assert_eq!(state.last_pacing_ack_received_time, start + 75_100_000_000);
    assert!(!state.recovery.large_stalled(start + 75_100_000_001));
}

#[test]
fn recovery_native_healthy_idle_with_old_data_loss_then_idle_size_blackhole() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    relay.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let blackhole = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(Mutex::new(BTreeSet::new()));
    let (st, bh, dr) = (stop.clone(), blackhole.clone(), dropped.clone());
    let forwarder = std::thread::spawn(move || {
        let mut peer = None;
        let mut bytes = [0u8; 10000];
        while !st.load(Ordering::Acquire) {
            match relay.recv_from(&mut bytes) {
                Ok((len, src)) => {
                    let target = if src == server_addr { peer }
                        else { peer = Some(src); Some(server_addr) };
                    let limit = if bh.load(Ordering::Acquire) { 512 } else { 1204 };
                    if len <= limit {
                        if let Some(target) = target { relay.send_to(&bytes[..len], target).unwrap(); }
                    } else if src != server_addr {
                        dr.lock().unwrap().insert(bytes[..len].to_vec());
                    }
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => panic!("relay: {e}"),
            }
        }
    });
    let magic = CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s;
    let keypair = new_keypair_from_connect_magic1(magic).unwrap();
    let address = STPAddress {
        ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(), port: relay_port,
        magic1: magic, key: keypair.public.clone(),
    };
    let peer = address.connection_key();
    let log = Arc::new(Mutex::new(Vec::new()));
    use crate::pump::port::lockfree::Event;
    let (server_pump, mut server) = new_pump_with_options(vec![keypair], port, Some(2000),
        (1_000_000, 1 << 20, 1 << 20), 1 << 20, NetworkThreadOptions::default());
    let (client_pump, mut client) = new_pump_with_options(vec![new_keypair_from_connect_magic1(magic).unwrap()], 0,
        Some(2000), (1_000_000, 1 << 20, 1 << 20), 1 << 20,
        NetworkThreadOptions { datagram_log: Some(log.clone()), ..Default::default() });
    let server_worker = Worker::start(server_pump);
    let client_worker = Worker::start(client_pump);
    assert!(client.try_connect(address));
    let (mut outgoing, mut incoming) = (false, false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !outgoing || !incoming {
        while let Some(event) = client.try_recv() {
            assert!(matches!(event, Event::Connected { peer: p, .. } if p == peer));
            outgoing = true;
        }
        while let Some(event) = server.try_recv() {
            assert!(matches!(event, Event::Connected { .. }));
            incoming = true;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    // Lose ordinary DATA briefly, then restore a healthy path before any aged
    // differential evidence exists. The application then drains and stays idle.
    blackhole.store(true, Ordering::Release);
    for i in 0..32 {
        let mut payload = vec![i; 80];
        assert!(client.try_send(peer, 0, Dscp::BestEffort, &mut payload));
    }
    std::thread::sleep(Duration::from_millis(150));
    blackhole.store(false, Ordering::Release);
    assert!(log.lock().unwrap().iter().any(|p| p.kind == "data" && dropped.lock().unwrap().contains(&p.bytes)),
        "fixture must actually retain an unconfirmed ordinary DATA history");
    // Neither endpoint receives further application send work during these idle
    // periods. Generic current-TU success must defeat old DATA loss indefinitely.
    std::thread::sleep(Duration::from_millis(3100));
    let healthy = pump_stats(&client);
    assert_eq!(healthy.connection_stats[0].1.udp_payload_tu, 1204);
    blackhole.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(3100));
    let recovered = pump_stats(&client);
    assert!(client.try_recv().is_none(), "idle recovery must not reconnect or disconnect");
    assert_eq!(recovered.connection_stats[0].1.udp_payload_tu, 512,
        "a real size blackhole must recover without application sends");
    let log = log.lock().unwrap();
    assert!(log.iter().any(|p| p.kind == "reachability_current" && p.bytes.len() == 1204));
    assert!(log.iter().any(|p| p.kind == "reachability" && p.bytes.len() == 512));
    drop(log);
    drop(client_worker);
    drop(server_worker);
    stop.store(true, Ordering::Release);
    forwarder.join().unwrap();
}
