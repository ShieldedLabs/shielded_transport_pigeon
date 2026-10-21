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

// RESEARCH adaptive units/v2: the constructor now starts at SMALL with an
// unresolved 1204 trial. Tests whose PRECONDITION is the old settled 1204
// connection state it explicitly; their functional expectations are unchanged.
fn settled_1204_fixture() -> (ConnectionStateConnected, SendQueues, u64) {
    let (mut state, queues, start) = parked_fixture();
    state.current_tu = 1204;
    state.recovery = crate::mtu_recovery::Recovery::new(start);
    state.tu_assessment_settled = true;
    (state, queues, start)
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
        let (mut state, mut queues, start) = settled_1204_fixture();
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
    let (mut state, mut queues, start) = settled_1204_fixture();
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
        let (mut state, mut queues, mut now) = settled_1204_fixture();
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
            let (mut state, mut queues, start) = settled_1204_fixture();
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
        let (mut state, mut queues, start) = settled_1204_fixture();
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
    let (mut state, _, start) = settled_1204_fixture();
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
    let (mut state, mut queues, start) = settled_1204_fixture();
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
    let (mut state, mut queues, start) = settled_1204_fixture();
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
        // FreshHold: +48 bytes for ConnectionStateConnected::fresh_hold
        // (FreshHold, align 16 via its i128 coordinate). Pre-FreshHold exact sizes were
        // default 44784 / research 44824. FreshHold raises Connected's alignment from 8 to
        // 16, so the total rounds up to a multiple of 16: default 44832 (+0 pad), research
        // 44872 -> 44880 (+8 alignment padding).
        let fresh_hold_added = 48;
        assert_eq!(std::mem::size_of::<FreshHold>(), fresh_hold_added);
        assert_eq!(std::mem::align_of::<FreshHold>(), 16);
        assert_eq!(std::mem::align_of::<ConnectionStateConnected>(), 16);
        let pre_fresh_hold = baseline + added + recovery_state_added - 8;
        assert_eq!(pre_fresh_hold,
            if cfg!(feature = "research_target_validation") { 44824 } else { 44784 });
        let align_pad = if cfg!(feature = "research_target_validation") { 8 } else { 0 };
        assert_eq!((pre_fresh_hold + fresh_hold_added + 15) / 16 * 16,
            pre_fresh_hold + fresh_hold_added + align_pad);
        assert_eq!(std::mem::size_of::<ConnectionStateConnected>(),
            pre_fresh_hold + fresh_hold_added + align_pad);
        assert_eq!(std::mem::size_of::<ConnectionStateConnected>(),
            if cfg!(feature = "research_target_validation") { 44880 } else { 44832 });
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
    let (mut state, mut queues, start) = settled_1204_fixture();
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
    let (mut state, mut queues, start) = settled_1204_fixture();
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
        let (mut state, mut queues, start) = settled_1204_fixture();
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
        let (mut state, mut queues, start) = settled_1204_fixture();
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

// ---- RESEARCH v2 (cache-only): startup-only 1204 candidate + one prompt 1452 ----

fn startup_v2_fresh() -> (ConnectionStateConnected, SendQueues, u64) {
    let now = 8_000_000_000;
    let ConnectionState::Connected(state) = new_connection_state_connected(
        None, CONNECT_MAGIC1_PLAIN_TEXT, MAGIC2_APP_CROSSLINK, now) else { panic!() };
    let queues = SendQueues::baseline_for_test(1, (1_000_000, 1 << 20, 1 << 20));
    (state, queues, now)
}
use crate::mtu_recovery::Startup;
fn startup_v2_reach_prompt(state: &mut ConnectionStateConnected, queues: &mut SendQueues, now: u64) -> u64 {
    assert!(state.prepare_upward_probe(now));
    assert_eq!(state.tu_probe_size, 1204);
    let seq = recovery_send(state, queues, PendingSendKind::MtuProbe, now, 1204);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, now, now + 20_000_000);
    assert_eq!((state.current_tu, state.recovery.startup_state()), (1204, Startup::Prompt));
    now + 20_000_000
}

#[test]
fn startup_v2_fresh_1204_then_one_prompt_1452_then_unchanged_floor() {
    let (mut state, mut queues, now) = startup_v2_fresh();
    assert_eq!((state.current_tu, state.recovery.startup_state()), (512, Startup::Candidate));
    // Deadline reads and not-due prepares never advance state.
    state.recovery.upward_after = now + 1;
    for _ in 0..3 {
        assert_eq!(state.upward_probe_deadline(now), now + 1);
        assert!(!state.prepare_upward_probe(now));
        assert_eq!(state.recovery.startup_state(), Startup::Candidate);
    }
    state.recovery.upward_after = 0;
    assert!(state.upward_probe_deadline(now) <= now);
    assert!(state.prepare_upward_probe(now));
    assert_eq!((state.tu_probe_size, state.recovery.startup_state()), (1204, Startup::Issued));
    let t1 = now + 1_000;
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, t1, 1204);
    assert_eq!(state.last_sent_tu_probe_time_ns, t1, "actual accepted timestamp");
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    let o1 = t1 + 20_000_000;
    state.finish_upward_probe(true, t1, o1);
    assert_eq!((state.current_tu, state.recovery.startup_state()), (1204, Startup::Prompt));
    assert_eq!(state.last_sent_tu_probe_time_ns, t1);
    // One prompt: due at the accepted time, not t1 + 500 ms.
    assert_eq!(state.upward_probe_deadline(o1), t1);
    assert_eq!(state.recovery.startup_state(), Startup::Prompt);
    // The hold still applies to the prompt.
    state.recovery.upward_after = o1 + 5;
    assert_eq!(state.upward_probe_deadline(o1), o1 + 5);
    assert!(!state.prepare_upward_probe(o1));
    assert_eq!(state.recovery.startup_state(), Startup::Prompt);
    state.recovery.upward_after = 0;
    assert!(state.prepare_upward_probe(o1));
    assert_eq!((state.tu_probe_size, state.recovery.startup_state()), (1452, Startup::Done));
    let t2 = o1 + 1_000;
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, t2, 1452);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, t2, t2 + 20_000_000);
    assert_eq!(state.current_tu, 1452);
    assert_eq!(state.upward_probe_deadline(t2), t2 + 500_000_000);
    assert!(!state.prepare_upward_probe(t2 + 499_999_999));
    assert!(state.prepare_upward_probe(t2 + 500_000_000));
    assert_eq!(state.tu_probe_size, 1472);
    assert_eq!(state.recovery.startup_state(), Startup::Done);
}

#[test]
fn startup_v2_failed_1204_no_prompt_existing_refinement_at_floor() {
    let (mut state, mut queues, mut now) = startup_v2_fresh();
    assert!(state.prepare_upward_probe(now));
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204);
    state.finish_upward_probe(false, now, now + 20_000_000);
    assert_eq!((state.current_tu, state.tu_probe_failed_count), (512, 1));
    assert_eq!(state.recovery.startup_state(), Startup::Done);
    let mut attempted = vec![1204];
    for _ in 0..20 {
        let due = state.upward_probe_deadline(now);
        if due > now + 2_000_000_000 { break; }
        assert!(due >= state.last_sent_tu_probe_time_ns + 500_000_000, "no floor exemption");
        now = now.max(due);
        assert!(state.prepare_upward_probe(now));
        let c = state.tu_probe_size;
        attempted.push(c);
        let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, c as usize);
        let ok = c <= 700;
        if ok { assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe)); }
        state.finish_upward_probe(ok, now, now + 20_000_000);
        now += 20_000_000;
        assert_eq!(state.recovery.startup_state(), Startup::Done);
    }
    assert_eq!(&attempted[..3], &[1204, 858, 685]);
    assert_eq!(attempted.iter().filter(|&&c| c == 1204).count(), 1, "{attempted:?}");
    assert!(state.current_tu <= 700 && 700 - state.current_tu <= 8, "{attempted:?}");
}

#[test]
fn startup_v2_stale_or_obsolete_1204_success_arms_no_prompt() {
    // Stale: accepted send long before the proof.
    let (mut state, mut queues, now) = startup_v2_fresh();
    assert!(state.prepare_upward_probe(now));
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    let late = now + 61_000_000_000;
    state.finish_upward_probe(true, now, late);
    assert_eq!((state.current_tu, state.recovery.startup_state()), (512, Startup::Done));
    assert_eq!(state.upward_probe_deadline(late), now + 500_000_000);
    assert!(state.prepare_upward_probe(late));
    assert_eq!(state.tu_probe_size, 1452, "ordinary plan, candidate not re-armed");
    // Obsolete: effective shrink invalidates the attempt.
    let (mut state, mut queues, now) = startup_v2_fresh();
    assert!(state.prepare_upward_probe(now));
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204);
    state.tu_probe_obsolete = true;
    state.finish_upward_probe(true, now, now + 1);
    assert_eq!((state.current_tu, state.recovery.startup_state()), (512, Startup::Done));
}

#[test]
fn startup_v2_deferred_promotion_remembers_prompt_but_bypasses_only_once_effective() {
    let (mut state, mut queues, now) = startup_v2_fresh();
    assert!(state.prepare_upward_probe(now));
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204);
    assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::Data,
        None, now + 1, &[9; 512], &[], Dscp::BestEffort, 0, None));
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, now, now + 20_000_000);
    assert_eq!((state.current_tu, state.deferred_tu), (512, Some(1204)));
    assert_eq!(state.recovery.startup_state(), Startup::Prompt);
    // Not effective yet: ordinary cadence only.
    assert_eq!(state.upward_probe_deadline(now + 20_000_000), now + 500_000_000);
    assert!(!state.prepare_upward_probe(now + 20_000_000));
    assert_eq!(state.recovery.startup_state(), Startup::Prompt);
    let pending = state.pending_send.take().unwrap();
    assert_eq!(pending.bytes, vec![9; 512], "deferred copy ciphertext immutable");
    commit_connected_send(&mut state, &mut queues, pending.kind, now + 21_000_000,
        pending.bytes.len(), &pending.plaintext, 0, None);
    assert_eq!((state.current_tu, state.deferred_tu), (1204, None));
    assert_eq!(state.upward_probe_deadline(now + 21_000_000), now);
    assert!(state.prepare_upward_probe(now + 21_000_000));
    assert_eq!((state.tu_probe_size, state.recovery.startup_state()), (1452, Startup::Done));
}

#[test]
fn startup_v2_refused_and_unsent_issuance_keep_tuple_and_never_leak_or_rearm() {
    for accept_after in [5_000_000u64, 31_000_000_000] {
        let (cipher, _) = super::wire_v2_tests::ciphers();
        let (mut state, mut queues, now) = startup_v2_fresh();
        state.cipher = Some(cipher);
        let due = state.upward_probe_deadline(now);
        assert!(state.prepare_upward_probe(now));
        assert_eq!((state.tu_probe_size, state.recovery.startup_state()), (1204, Startup::Issued));
        let nonce = state.send_sequence_number;
        let mut ciphertext = vec![0; 1204];
        let n = seal_connected_packet(&mut state.cipher, 42, nonce, &[0xff; 1174],
            &mut ciphertext, now).unwrap();
        assert_eq!(n, 1204);
        assert!(!finish_connected_send(&mut state, &mut queues, PendingSendKind::MtuProbe,
            None, now, &ciphertext, &[], Dscp::BestEffort, 42, None));
        for t in [now, now + 1, now + accept_after] {
            assert_eq!(state.upward_probe_deadline(t), due);
            assert_eq!((state.send_sequence_number, state.last_sent_tu_probe_time_ns,
                state.tu_probe_failed_count, state.tu_probe_sequence_number), (nonce, 0, 0, u64::MAX));
            assert_eq!(state.recovery.startup_state(), Startup::Issued);
            assert_eq!(state.pending_send.as_ref().unwrap().bytes, ciphertext);
        }
        let accepted = now + accept_after;
        let pending = state.pending_send.take().unwrap();
        assert!(finish_connected_send(&mut state, &mut queues, pending.kind, Some(accepted),
            accepted, &pending.bytes, &pending.plaintext, pending.dscp, 42, None));
        assert_eq!((state.last_sent_tu_probe_time_ns, state.tu_probe_sequence_number), (accepted, nonce));
        assert_eq!(state.recovery.sent_bytes(nonce), Some(1204));
        assert_eq!(state.take_positive_receipt(nonce), Some(PositiveReceipt::PendingProbe));
        state.finish_upward_probe(true, accepted, accepted + 20_000_000);
        assert_eq!((state.current_tu, state.recovery.startup_state()), (1204, Startup::Prompt));
        assert_eq!(state.upward_probe_deadline(accepted + 20_000_000), accepted);
    }
    // Repeated unsent issuance (e.g. seal not sent): second issuance is ordinary,
    // and even a later success of it cannot arm Prompt or re-arm Candidate.
    let (mut state, mut queues, now) = startup_v2_fresh();
    assert!(state.prepare_upward_probe(now));
    assert_eq!(state.tu_probe_size, 1204);
    assert!(state.prepare_upward_probe(now));
    assert_eq!((state.tu_probe_size, state.recovery.startup_state()), (1452, Startup::Done));
    assert!(state.prepare_upward_probe(now));
    assert_eq!(state.tu_probe_size, 1452);
    let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1452);
    assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
    state.finish_upward_probe(true, now, now + 1);
    assert_eq!((state.current_tu, state.recovery.startup_state()), (1452, Startup::Done));
    assert_eq!(state.upward_probe_deadline(now), now + 500_000_000);
}

#[test]
fn startup_v2_outage_entry_cancels_each_state_and_late_proof_cannot_arm_prompt() {
    for stage in 0..3 {
        let (mut state, mut queues, now) = startup_v2_fresh();
        let mut seq = None;
        let mut t = now;
        if stage >= 1 {
            assert!(state.prepare_upward_probe(now));
            seq = Some(recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204));
        }
        if stage == 2 {
            assert_eq!(state.take_positive_receipt(seq.unwrap()), Some(PositiveReceipt::PendingProbe));
            state.finish_upward_probe(true, now, now + 20_000_000);
            assert_eq!(state.recovery.startup_state(), Startup::Prompt);
            t = now + 20_000_000;
        }
        enter_outage(&mut state, &mut queues, t, 0, None);
        assert_eq!(state.recovery.startup_state(), Startup::Done, "stage {stage}");
        assert_eq!(state.tu_probe_sequence_number, u64::MAX);
        if stage == 1 {
            // A late outcome of the cleared probe (even if delivered) cannot arm Prompt.
            state.finish_upward_probe(true, now, now + 20_000_000);
            assert_eq!(state.recovery.startup_state(), Startup::Done);
        }
        match state.recovery.upward_plan(state.current_tu, state.last_sent_tu_probe_time_ns,
            state.tu_probe_failed_count, t) {
            Some((size, due)) => {
                assert_ne!((state.current_tu, size), (512, 1204), "stage {stage}: candidate re-armed");
                if state.last_sent_tu_probe_time_ns != 0 {
                    assert!(due >= state.last_sent_tu_probe_time_ns + 500_000_000, "stage {stage}: prompt leaked");
                }
            }
            None => panic!(),
        }
    }
}

#[test]
fn startup_v2_shrink_reset_with_upper_at_or_above_1204_never_rearms_special() {
    for target in [1204u64, 1452] {
        let (mut state, mut queues, now) = startup_v2_fresh();
        let mut t = startup_v2_reach_prompt(&mut state, &mut queues, now);
        if target == 1452 {
            assert!(state.prepare_upward_probe(t));
            let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, t, 1452);
            assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
            state.finish_upward_probe(true, t, t + 20_000_000);
            t += 20_000_000;
        }
        assert_eq!(state.current_tu, target);
        state.recovery.downshifted(t);
        state.downshift_for_recovery(false, t);
        assert_eq!((state.current_tu, state.recovery.startup_state()), (512, Startup::Done));
        let mut now = t;
        let mut attempted = Vec::new();
        for _ in 0..24 {
            let due = state.upward_probe_deadline(now);
            if due > now + 12_000_000_000 { break; }
            assert!(due >= t + 10_000_000_000 || due >= state.last_sent_tu_probe_time_ns + 500_000_000);
            assert!(due >= state.last_sent_tu_probe_time_ns + 500_000_000, "no prompt cadence after shrink");
            now = now.max(due);
            assert!(state.prepare_upward_probe(now));
            let c = state.tu_probe_size;
            attempted.push(c);
            let seq = recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, c as usize);
            let ok = c <= 1320;
            if ok { assert_eq!(state.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe)); }
            state.finish_upward_probe(ok, now, now + 20_000_000);
            now += 20_000_000;
            assert_eq!(state.recovery.startup_state(), Startup::Done);
        }
        // The control's ordinary post-shrink plan (Recovery::new semantics) starts the same way.
        assert_eq!(attempted[0], if target == 1204 { 858 } else { 982 }, "{attempted:?}");
        println!("STARTUP_V2_POSTSHRINK target={target} attempts={attempted:?} floor={}", state.current_tu);
    }
}

#[test]
fn adaptive_units_prefix_then_growth_preserves_exact_bytes_and_first_layout() {
    let original: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let mut s = SendQueues::baseline_for_test(1, (1_000_000, 4 << 20, 4 << 20));
    s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0));
    s.set_tu_unresolved(true);
    s.submit_messages(0, vec![original.clone()]);
    s.fec_prepare_packet(0);
    assert!(s.fill_packet(&mut vec![0; 482]) > 0);
    let q = &mut s.queues[0];
    let first = q.fec_send_slot.as_ref().unwrap();
    let prefix = first.message.clone();
    let extent = first.segment.unwrap();
    let old_id = q.send_package_id;
    assert_eq!(first.block_bytes, 445);
    assert!(first.k <= 256);
    assert_eq!(prefix.len(), adaptive_unit_len(original.len(), ADAPTIVE_PREFIX_CAP));
    assert_eq!(prefix.as_slice(), &original[..prefix.len()]);
    assert_eq!(extent.offset, 0);
    q.fec_send_slot.as_mut().unwrap().next_id = q.fec_send_slot.as_ref().unwrap().n;
    s.set_tu_unresolved(false);
    s.fec_prepare_packet(1);
    s.fill_packet(&mut vec![0; 1422]);
    let q = &s.queues[0];
    let next = q.fec_send_slot.as_ref().unwrap();
    assert_eq!(next.segment.unwrap().root, extent.root);
    assert_eq!(next.segment.unwrap().offset as usize, prefix.len());
    assert_eq!(next.block_bytes, 1385);
    assert_eq!(next.message.as_slice(), &original[prefix.len()..]);
    assert_ne!(q.send_package_id, old_id);
    assert!(q.segmented_send.is_none());
    let retained = &q.fec_retained[&old_id].slot;
    assert!(Arc::ptr_eq(&retained.message, &prefix));
    assert_eq!(retained.block_bytes, 445);
    assert_eq!(retained.segment.unwrap().offset, extent.offset);
    assert_eq!(retained.next_id, retained.n);
}

#[test]
fn adaptive_units_ledger_overlap_restart_prefix_and_atomic_capacity_refusal() {
    let mut root = ReassemblySlot::new();
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let range = |offset| FecSegment { root: 19, total: 180_000, offset };
    let layout = crate::fec::MessageLayout::new(60_000, 1000).unwrap();
    assert!(root.admit_segment(range(60_000), layout, 0, 1000, 1, &budget));
    let charge = budget.used();
    for (offset, len) in [(60_000, 70_000), (50_000, 60_000), (100_000, 60_000)] {
        let bad = crate::fec::MessageLayout::new(len, 1000).unwrap();
        assert!(!root.admit_segment(range(offset), bad, 0, 1000, 2, &budget));
        assert_eq!(budget.used(), charge);
        assert_eq!(root.segment_extents, vec![(60_000, 60_000)]);
    }
    assert!(root.admit_segment(range(60_000), layout, 0, 1000, 3, &budget));
    assert!(root.finish_charged(range(60_000), vec![2; 60_000], &budget).is_none());
    assert!(root.admit_segment(range(0), layout, 0, 1000, 4, &budget));
    assert!(root.finish_charged(range(0), vec![1; 60_000], &budget).is_none());
    assert_eq!(root.buf.len(), 120_000);
    assert!(root.segment_covered(range(60_000), 60_000));
    let charge = budget.used();
    assert!(root.admit_segment(range(60_000), layout, 0, 1000, 5, &budget));
    assert!(root.finish_charged(range(60_000), vec![2; 60_000], &budget).is_none());
    assert_eq!(budget.used(), charge);
    assert!(root.admit_segment(range(120_000), layout, 0, 1000, 6, &budget));
    let (message, reservation) = root.finish_charged(range(120_000), vec![3; 60_000], &budget).unwrap();
    assert_eq!(message, [vec![1; 60_000], vec![2; 60_000], vec![3; 60_000]].concat());
    assert!(root.completed);
    assert!(root.finish_charged(range(120_000), vec![3; 60_000], &budget).is_none());
    drop(reservation);
    assert_eq!(budget.used(), 0);
    let charge = SEGMENT_ROOT_METADATA + 4 * std::mem::size_of::<(u32, u32)>() + 4 * std::mem::size_of::<(u32, Vec<u8>)>();
    let tight = crate::receive_memory::ReceiveMemoryBudget::new(360_000);
    let _other_owner = tight.reserve(360_000 - charge).unwrap();
    let mut root = ReassemblySlot::new();
    for i in 0..4 {
        assert!(root.admit_segment(FecSegment { root: 20, total: 360_000, offset: i * 60_000 }, layout, 0, 1000, 10 + i as u64, &tight));
    }
    let before = root.segment_extents.clone();
    assert!(!root.admit_segment(FecSegment { root: 20, total: 360_000, offset: 240_000 }, layout, 0, 1000, 99, &tight));
    assert_eq!(root.segment_extents, before);
    assert_eq!(root.last_segment_ns, 13);
    assert_eq!(tight.used(), 360_000);
}

#[test]
fn adaptive_units_completed_active_owner_drops_lease_but_outstanding_owner_survives() {
    for complete in [false, true] {
        let mut s = SendQueues::baseline_for_test(1, (1_000_000, 4 << 20, 4 << 20));
        s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0));
        s.set_tu_unresolved(true);
        s.submit_messages(0, vec![vec![7; 1 << 20]]);
        s.fec_prepare_packet(0);
        assert!(s.fill_packet(&mut vec![0; 482]) > 0);
        let q = &mut s.queues[0];
        let id = q.send_package_id;
        let mut f = q.fec_send_slot.take().unwrap();
        f.next_id = f.n;
        f.finalized_symbols = if complete { f.next_id } else { f.next_id - 1 };
        let weak = Arc::downgrade(f.package_lease.as_ref().unwrap());
        q.package_lease = None;
        q.retain_fec(f, id);
        assert_eq!(q.fec_retained.contains_key(&id), !complete);
        assert_eq!(weak.upgrade().is_some(), !complete);
        assert!(q.segmented_send.is_some());
    }
}

#[test]
fn adaptive_units_initial_assessment_latches_after_failure_without_rearming() {
    let (mut state, mut queues, now) = startup_v2_fresh();
    prepare_connected_send_tick(&mut state, &mut queues, now);
    assert!(!state.tu_assessment_settled);
    assert!(queues.queues[0].tu_unresolved);
    assert!(state.prepare_upward_probe(now));
    recovery_send(&mut state, &mut queues, PendingSendKind::MtuProbe, now, 1204);
    state.finish_upward_probe(false, now, now + 100_000_000);
    prepare_connected_send_tick(&mut state, &mut queues, now + 100_000_000);
    assert!(state.tu_assessment_settled);
    assert!(!queues.queues[0].tu_unresolved);
    assert_eq!(queues.queues[0].adaptive_unit_cap(1422, 1 << 20), FEC_SEGMENT_BYTES);
    for i in 1..5 {
        let t = now + i * 20_000_000_000;
        state.recovery.downshifted(t);
        prepare_connected_send_tick(&mut state, &mut queues, t);
        assert!(state.tu_assessment_settled);
        assert!(!queues.queues[0].tu_unresolved);
    }
}

// Source-faithful honest adaptive partition: 110 unresolved prefix units of
// ADAPTIVE_PREFIX_CAP, then 8 balanced body units. 118 extents => ledger and
// part-table capacity 128. The last body unit (index 110) completes LAST while
// its decoded Vec and lease are charged throughout.
const OWNED_TOTAL: usize = 29_163_520;
const OWNED_PREFIX_UNITS: usize = 110;
const OWNED_BODY: usize = 2_079_040;
fn owned_partition() -> Vec<(u32, usize)> {
    let mut units = Vec::new();
    let mut offset = 0;
    for i in 0..OWNED_PREFIX_UNITS + 8 {
        let len = if i < OWNED_PREFIX_UNITS { ADAPTIVE_PREFIX_CAP } else { OWNED_BODY };
        units.push((offset as u32, len)); offset += len;
    }
    assert_eq!(offset, OWNED_TOTAL); assert_eq!(OWNED_TOTAL, 256 * ADAPTIVE_PREFIX_CAP);
    units
}
fn owned_unit_bytes(index: usize, len: usize) -> Vec<u8> { vec![(index % 251) as u8 + 1; len] }

#[test]
fn adaptive_owned_completion_fits_derived_root_allowance() {
    let total = OWNED_TOTAL;
    let cap = receive_connection_memory_limit(total, 1).unwrap();
    assert_eq!(cap, 164_193_904);
    assert_eq!(segment_reassembly_peak(total), 45_843_584);
    let process = crate::receive_memory::ReceiveMemoryBudget::new(cap);
    let peer = crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&process, cap);
    let overhead = peer.reserve(cap - segment_reassembly_peak(total)).unwrap();
    assert_eq!(peer.used(), 118_350_320);
    let units = owned_partition();
    let mut root = ReassemblySlot::new();
    let mut order: Vec<usize> = (0..OWNED_PREFIX_UNITS).collect();
    order.extend(OWNED_PREFIX_UNITS + 1..units.len());
    order.push(OWNED_PREFIX_UNITS);
    let mut delivered = None;
    for (n, &i) in order.iter().enumerate() {
        let (offset, len) = units[i];
        let segment = FecSegment { root: 31, total: total as u32, offset };
        let layout = wire_fec_layout(len, FEC_MIN_BLOCK_BYTES).unwrap();
        assert!(root.admit_segment(segment, layout, 0, FEC_MIN_BLOCK_BYTES, 1, &peer), "unit {i}");
        if n + 1 == order.len() {
            // Completion clears the ledger: check its bound before the last unit.
            assert_eq!(root.segment_extents.capacity(), 128);
            assert_eq!(root.segment_parts.as_ref().unwrap().capacity(), 128);
        }
        let donor = peer.reserve(len).expect("decoded unit lease");
        let message = owned_unit_bytes(i, len);
        assert_eq!(message.capacity(), len);
        let result = root.finish_segment(segment, message, donor);
        if n + 1 < order.len() { assert!(result.is_none()); } else { delivered = result; }
        assert!(peer.used() <= cap);
    }
    let (message, reservation) = delivered.expect("final body unit must complete within the derived root allowance");
    assert_eq!(message.len(), total);
    for (i, &(offset, len)) in units.iter().enumerate() {
        assert!(message[offset as usize..offset as usize + len].iter().all(|&b| b == (i % 251) as u8 + 1));
    }
    assert!(peer.peak() <= cap);
    drop(message); drop(reservation); drop(overhead);
    assert_eq!(process.used(), 0);
}

fn owned_layout() -> crate::fec::MessageLayout { crate::fec::MessageLayout::new(60_000, 1000).unwrap() }
fn owned_root_metadata(cap: usize) -> usize {
    SEGMENT_ROOT_METADATA + cap * (std::mem::size_of::<(u32, u32)>() + std::mem::size_of::<(u32, Vec<u8>)>())
}

#[test]
fn owned_prepaid_table_growth_refusal_binds_nothing_then_retries() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(1 << 20);
    let range = |i: u32| FecSegment { root: 40, total: 600_000, offset: i * 60_000 };
    let mut root = ReassemblySlot::new();
    for i in 0..4 { assert!(root.admit_segment(range(i), owned_layout(), 0, 1000, 10 + i as u64, &budget)); }
    assert_eq!(budget.used(), owned_root_metadata(4));
    assert_eq!((root.segment_extents.capacity(), root.segment_parts.as_ref().unwrap().capacity()), (4, 4));
    // The paired ledger+table growth to 8 needs 8*40 more than base: deny it.
    let other = budget.reserve((1 << 20) - owned_root_metadata(8) + 1).unwrap();
    let before = root.segment_extents.clone();
    assert!(!root.admit_segment(range(4), owned_layout(), 0, 1000, 99, &budget));
    // Unbound (caller: no ACK, no decoder), nothing grown, no time refresh.
    assert_eq!(root.segment_extents, before);
    assert_eq!((root.segment_extents.capacity(), root.segment_parts.as_ref().unwrap().capacity()), (4, 4));
    assert!(root.segment_parts.as_ref().unwrap().is_empty());
    assert_eq!(root.last_segment_ns, 13);
    assert_eq!(budget.used(), (1 << 20) + 1 - owned_root_metadata(8) + owned_root_metadata(4));
    assert!(!root.segment_covered(range(4), 60_000));
    drop(other);
    assert!(root.admit_segment(range(4), owned_layout(), 0, 1000, 100, &budget));
    assert_eq!((root.segment_extents.capacity(), root.segment_parts.as_ref().unwrap().capacity()), (8, 8));
    assert_eq!(budget.used(), owned_root_metadata(8));
    assert_eq!(root.last_segment_ns, 100);
    drop(root); assert_eq!(budget.used(), 0);
}

#[test]
fn owned_handoff_moves_vec_and_lease_without_gap_and_refuses_foreign_lease() {
    let process = crate::receive_memory::ReceiveMemoryBudget::new(4 << 20);
    let peer = crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&process, 2 << 20);
    let range = |i: u32| FecSegment { root: 41, total: 180_000, offset: i * 60_000 };
    let mut root = ReassemblySlot::new();
    for i in [2, 0] { assert!(root.admit_segment(range(i), owned_layout(), 0, 1000, 1, &peer)); }
    // Sparse handoff: same allocation, the charge just moves (no gap, no peak).
    let sparse = vec![3u8; 60_000];
    let pointer = sparse.as_ptr();
    let donor = peer.reserve(sparse.capacity()).unwrap();
    let (used, peak, process_used) = (peer.used(), peer.peak(), process.used());
    assert!(root.finish_segment(range(2), sparse, donor).is_none());
    assert_eq!((peer.used(), peer.peak(), process.used()), (used, peak, process_used));
    assert_eq!(peer.used(), owned_root_metadata(4) + 60_000);
    assert_eq!(root.segment_parts.as_ref().unwrap()[0].1.as_ptr(), pointer);
    // First prefix part becomes the destination itself.
    let first = vec![1u8; 60_000];
    let pointer = first.as_ptr();
    assert!(root.finish_charged(range(0), first, &peer).is_none());
    assert_eq!(root.buf.as_ptr(), pointer);
    assert_eq!(peer.used(), owned_root_metadata(4) + 120_000);
    // A lease on another budget is refused: Vec then lease dropped, root intact.
    assert!(root.admit_segment(range(1), owned_layout(), 0, 1000, 2, &peer));
    let other = crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&process, 1 << 20);
    let charge = peer.used();
    assert!(root.finish_segment(range(1), vec![2; 60_000], other.reserve(60_000).unwrap()).is_none());
    assert_eq!((peer.used(), other.used(), root.bytes_received()), (charge, 0, 120_000));
    // An undercharged lease is refused too.
    assert!(root.finish_segment(range(1), vec![2; 60_000], peer.reserve(59_999).unwrap()).is_none());
    assert_eq!(peer.used(), charge);
    let (message, reservation) = root.finish_charged(range(1), vec![2; 60_000], &peer).unwrap();
    assert_eq!(message, [vec![1; 60_000], vec![2; 60_000], vec![3; 60_000]].concat());
    assert_eq!(peer.used(), message.capacity() + 256);
    assert_eq!(reservation.bytes(), message.capacity() + 256);
    drop(message); drop(reservation); drop(root);
    assert_eq!((peer.used(), process.used()), (0, 0));
}

// Four 60,000 B units: 0,1 join (prefix cap 120,000), 3 sparse, then 2.
// Joining 2 needs geometric 416+240,000+120,000 or exact 416+180,000+120,000.
fn owned_blocked_root(budget: &Arc<crate::receive_memory::ReceiveMemoryBudget>, id: u64, deliver_last: bool)
    -> (ReassemblySlot, Option<(Vec<u8>, crate::receive_memory::Reservation)>) {
    let range = |i: u32| FecSegment { root: id, total: 240_000, offset: i * 60_000 };
    let mut root = ReassemblySlot::new();
    let mut result = None;
    for (n, i) in [0u32, 1, 3, 2].into_iter().enumerate() {
        if !deliver_last && i == 2 { break; }
        assert!(root.admit_segment(range(i), owned_layout(), 0, 1000, 5, budget));
        result = root.finish_charged(range(i), vec![i as u8 + 1; 60_000], budget);
        if n < 3 { assert!(result.is_none()); }
    }
    (root, result)
}
fn owned_check(message: &[u8]) {
    assert_eq!(message.len(), 240_000);
    for (i, part) in message.chunks(60_000).enumerate() { assert!(part.iter().all(|&b| b == i as u8 + 1)); }
}

#[test]
fn owned_join_falls_back_to_exact_end_when_geometric_is_denied() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(1 << 20);
    let _other = budget.reserve((1 << 20) - 320_000).unwrap();
    let (root, result) = owned_blocked_root(&budget, 42, true);
    let (message, reservation) = result.expect("exact-end fallback completes");
    owned_check(&message);
    assert_eq!(message.capacity(), 240_000);
    assert!(budget.peak() <= 1 << 20);
    drop(message); drop(reservation); drop(root);
    assert_eq!(budget.used(), (1 << 20) - 320_000);
}

#[test]
fn owned_denied_join_retains_parts_and_lease_then_existing_sweep_delivers_once() {
    let process = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let budget = crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&process, 1 << 20);
    let mut roots = ReassemblySlot::new_ring(4);
    // An unrelated incomplete root (missing unit 2) is NOT joinable.
    let (stalled, _) = owned_blocked_root(&budget, 44, false);
    roots[2] = stalled;
    let stalled_charge = owned_root_metadata(4) + 120_000 + 60_000;
    assert_eq!(budget.used(), stalled_charge);
    // 260,000 B left: the handoff (240,416) fits, exact join (300,416) does not.
    let other = budget.reserve((1 << 20) - stalled_charge - 260_000).unwrap();
    let (blocked, result) = owned_blocked_root(&budget, 43, true);
    assert!(result.is_none(), "both growth steps must be denied");
    roots[1] = blocked;
    // Retained: prefix, both sparse parts and the whole charge stay owned.
    assert_eq!(roots[1].buf.len(), 120_000);
    assert_eq!(roots[1].bytes_received(), 240_000);
    assert_eq!(roots[1].segment_parts.as_ref().unwrap().len(), 2);
    let retained = owned_root_metadata(4) + 120_000 + 120_000;
    assert_eq!(budget.used(), other.bytes() + retained + stalled_charge);
    // Still denied: a sweep inside grace delivers nothing and keeps everything.
    let grace = fec_inactive_grace_ns(0, false);
    let mut delivered = Vec::new();
    assert_eq!(sweep_segment_roots(&mut roots, 5 + grace, grace, |m, r| delivered.push((m, r))), 0);
    assert_eq!(budget.used(), other.bytes() + retained + stalled_charge);
    // Memory frees; the existing sweep (no new packet) completes the root even
    // when its inactivity grace has elapsed, and retires only the stalled root.
    drop(other);
    assert_eq!(sweep_segment_roots(&mut roots, 6 + grace, grace, |m, r| delivered.push((m, r))), 1);
    assert_eq!(delivered.len(), 1);
    owned_check(&delivered[0].0);
    assert!(roots[1].completed);
    assert!(roots[2].segment_parts.is_none() && roots[2].reservation.is_none());
    assert_eq!(budget.used(), delivered[0].0.capacity() + 256);
    // Exactly once: later sweeps and a duplicate late unit deliver nothing.
    assert_eq!(sweep_segment_roots(&mut roots, 7 + grace, grace, |m, r| delivered.push((m, r))), 0);
    let late = FecSegment { root: 43, total: 240_000, offset: 120_000 };
    assert!(roots[1].segment_covered(late, 60_000));
    assert!(roots[1].finish_charged(late, vec![3; 60_000], &budget).is_none());
    assert_eq!(delivered.len(), 1);
    drop(delivered); drop(roots);
    assert_eq!((budget.used(), process.used()), (0, 0));
}

#[test]
fn owned_sweep_resumes_one_root_per_budget_without_premature_expiry() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let mut roots = ReassemblySlot::new_ring(4);
    for (i, slot) in roots.iter_mut().take(3).enumerate() {
        let hog = budget.reserve(budget.limit() - budget.used() - 260_000).unwrap();
        let (blocked, result) = owned_blocked_root(&budget, 70 + i as u64, true);
        assert!(result.is_none());
        *slot = blocked;
        drop(hog);
    }
    let (stalled, _) = owned_blocked_root(&budget, 73, false);
    roots[3] = stalled;
    let grace = fec_inactive_grace_ns(0, false);
    let mut cursor = 0;
    let mut delivered = Vec::new();
    for tick in 0..4 {
        let mut remaining = 1;
        let (count, done) = sweep_segment_roots_bounded(&mut roots, &mut cursor,
            6 + grace, grace,
            || { if remaining == 0 { true } else { remaining -= 1; false } },
            |m, r| delivered.push((m, r)));
        assert_eq!(cursor, tick + 1, "one root per caller budget");
        assert_eq!(count, u64::from(tick < 3));
        assert_eq!(done, tick == 3);
        assert_eq!(delivered.len(), (tick + 1).min(3));
        if tick < 3 {
            assert!(roots[3].reservation.is_some(), "unexamined root cannot expire");
            for root in &roots[tick + 1..3] {
                assert_eq!(root.bytes_received(), 240_000, "pending owners survive pause");
            }
        }
    }
    assert!(roots[3].reservation.is_none(), "blocked root expires after its own retry");
    assert!(roots[..3].iter().all(|root| root.completed));
    for (message, _) in &delivered { owned_check(message); }
    // A finished cursor and a new sweep both preserve exactly-once delivery.
    assert_eq!(sweep_segment_roots_bounded(&mut roots, &mut cursor, 7 + grace, grace,
        || false, |_, _| panic!("duplicate delivery")), (0, true));
    cursor = 0;
    assert_eq!(sweep_segment_roots_bounded(&mut roots, &mut cursor, 7 + grace, grace,
        || false, |_, _| panic!("duplicate delivery")), (0, true));
    drop(delivered); drop(roots);
    assert_eq!(budget.used(), 0);
}

// One pump call's FEC sweep loop, step for step as in the pump (missing or
// non-connected keys are None), driven by a real Deadline whose caller
// deadline passed during calibration: only the owed unit may run.
fn owned_sweep_expired_call(keys: &mut std::collections::VecDeque<Option<Vec<ReassemblySlot>>>,
    cursor: &mut usize, retired: &mut usize, now_ns: u64, grace: u64,
    delivered: &mut Vec<(Vec<u8>, crate::receive_memory::Reservation)>) {
    let mut budget = crate::pump::Deadline::entered_then_passed(u64::MAX / 2);
    assert!(!budget.expired() && budget.unit_owed());
    owned_sweep_call_with_clock(keys, cursor, retired, now_ns, grace, &mut budget,
        monotonic_clock_ns, |m, r| delivered.push((m, r)));
}

fn owned_sweep_call_with_clock(keys: &mut std::collections::VecDeque<Option<Vec<ReassemblySlot>>>,
    cursor: &mut usize, retired: &mut usize, now_ns: u64, grace: u64,
    budget: &mut crate::pump::Deadline, mut clock: impl FnMut() -> u64,
    mut deliver: impl FnMut(Vec<u8>, crate::receive_memory::Reservation)) {
    while let Some(entry) = keys.front_mut() {
        if budget.sampled(clock()) { return; }
        budget.progressed();
        if let Some(slots) = entry {
            if *cursor == 0 { *retired += 1; }
            let (_, done) = sweep_segment_roots_bounded(slots, cursor, now_ns, grace,
                sweep_entry_root_checkpoint_with_clock(budget, &mut clock), &mut deliver);
            if !done { return; }
        }
        keys.pop_front();
        *cursor = 0;
    }
}

#[test]
fn owned_sweep_samples_clock_across_connections_with_missing_and_empty_keys() {
    let memory = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let mut entries = Vec::new();
    for i in 0..3 {
        let hog = memory.reserve(memory.limit() - memory.used() - 260_000).unwrap();
        let (root, result) = owned_blocked_root(&memory, 110 + i, true);
        assert!(result.is_none());
        entries.push(Some(vec![root]));
        drop(hog);
    }
    let mut keys: std::collections::VecDeque<_> =
        [None, Some(Vec::new()), entries.remove(0), None, Some(Vec::new()),
         entries.remove(0), entries.remove(0)].into();
    let grace = fec_inactive_grace_ns(0, false);
    let (mut cursor, mut retired, mut delivered) = (0, 0, Vec::new());
    for (call, (keys_left, retirements)) in [(4, 2), (1, 4), (0, 5)].into_iter().enumerate() {
        let clock = std::cell::Cell::new(0);
        let mut budget = crate::pump::Deadline::entered_then_passed(clock.get());
        owned_sweep_call_with_clock(&mut keys, &mut cursor, &mut retired, 6 + grace, grace,
            &mut budget, || clock.get(), |message, reservation| {
                delivered.push((message, reservation));
                clock.set(u64::MAX / 2); // one heavy final root overran its deadline
            });
        assert_eq!(delivered.len(), call + 1, "one heavy flush across entry boundaries per call");
        assert_eq!(keys.len(), keys_left, "stop before consuming the next queue head");
        assert_eq!(cursor, 0, "finished final roots reset the cursor exactly once");
        assert_eq!(retired, retirements);
        for roots in keys.iter().flatten() {
            for root in roots {
                assert_eq!(root.bytes_received(), 240_000);
                assert!(!root.completed, "unvisited connections retain their roots");
            }
        }
    }
    assert!(keys.is_empty());
    for (message, _) in &delivered { owned_check(message); }
    drop(delivered);
    assert_eq!(memory.used(), 0);
}

#[test]
fn owned_sweep_samples_clock_between_heavy_roots_and_resumes_once() {
    let memory = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let mut roots = ReassemblySlot::new_ring(4);
    for (i, slot) in roots.iter_mut().enumerate() {
        let hog = memory.reserve(memory.limit() - memory.used() - 260_000).unwrap();
        let (blocked, result) = owned_blocked_root(&memory, 100 + i as u64, true);
        assert!(result.is_none());
        *slot = blocked;
        drop(hog);
    }
    let mut keys: std::collections::VecDeque<_> = [roots].into();
    let grace = fec_inactive_grace_ns(0, false);
    let (mut cursor, mut retired, mut delivered) = (0, 0, Vec::new());
    let completed = std::cell::Cell::new(0);
    let samples = std::cell::RefCell::new(Vec::new());
    for call in 0..4 {
        // The real Deadline caches a pre-deadline raw sample. Each actual join
        // deterministically advances the injected clock past the deadline.
        let clock = std::cell::Cell::new(0);
        let mut budget = crate::pump::Deadline::entered_then_passed(clock.get());
        assert!(budget.unit_owed() && !budget.expired());
        assert!(!budget.sampled(clock.get())); // production outer-entry checkpoint
        budget.progressed();
        if cursor == 0 { retired += 1; }
        let (count, done) = sweep_segment_roots_bounded(keys.front_mut().unwrap(), &mut cursor,
            6 + grace, grace,
            sweep_entry_root_checkpoint_with_clock(&mut budget, || {
                assert!(completed.get() > call, "never sample before the prepaid root");
                samples.borrow_mut().push(completed.get());
                clock.get()
            }),
            |message, reservation| {
                delivered.push((message, reservation));
                completed.set(completed.get() + 1);
                clock.set(u64::MAX / 2);
            });
        assert_eq!(count, 1, "only one heavy root may overrun in call {call}");
        assert_eq!(cursor, call + 1, "resume from the first untouched root");
        assert_eq!(done, call == 3);
        assert_eq!(retired, 1, "worker retirement must not repeat at a paused cursor");
        assert_eq!(completed.get(), call + 1);
        for root in &keys.front().unwrap()[call + 1..] {
            assert_eq!(root.bytes_received(), 240_000, "later owners survive the pause");
            assert!(!root.completed);
        }
        if done { keys.pop_front(); cursor = 0; }
    }
    assert!(keys.is_empty());
    assert_eq!(cursor, 0);
    assert_eq!(*samples.borrow(), [1, 2, 3], "fresh samples only BETWEEN work units");
    assert_eq!(delivered.len(), 4);
    for (message, _) in &delivered { owned_check(message); }
    drop(delivered);
    assert_eq!(memory.used(), 0);
}

#[test]
fn owned_sweep_repeated_expired_calls_advance_one_root_or_key_each() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let hog = budget.reserve(budget.limit() - budget.used() - 260_000).unwrap();
    let (blocked, result) = owned_blocked_root(&budget, 90, true);
    assert!(result.is_none());
    drop(hog);
    let mut first = ReassemblySlot::new_ring(3);
    first[0] = blocked;
    let mut keys: std::collections::VecDeque<_> =
        [None, None, Some(first), Some(Vec::new()), Some(ReassemblySlot::new_ring(2))].into();
    let grace = fec_inactive_grace_ns(0, false);
    let (mut cursor, mut retired, mut delivered) = (0, 0, Vec::new());
    // (keys left, cursor, worker retirements, deliveries) after each call.
    let expect = [(4, 0, 0, 0), (3, 0, 0, 0), (3, 1, 1, 1), (3, 2, 1, 1), (2, 0, 1, 1),
                  (1, 0, 2, 1), (1, 1, 3, 1), (0, 0, 3, 1)];
    for (call, &want) in expect.iter().enumerate() {
        owned_sweep_expired_call(&mut keys, &mut cursor, &mut retired, 6 + grace, grace, &mut delivered);
        assert_eq!((keys.len(), cursor, retired, delivered.len()), want, "after expired call {call}");
    }
    owned_check(&delivered[0].0);
    drop(delivered); drop(keys);
    assert_eq!(budget.used(), 0);
}

#[test]
fn owned_sweep_expires_only_examined_root_after_refused_retry() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(2 << 20);
    let mut roots = ReassemblySlot::new_ring(2);
    for (i, slot) in roots.iter_mut().enumerate() {
        let hog = budget.reserve(budget.limit() - budget.used() - 260_000).unwrap();
        let (blocked, result) = owned_blocked_root(&budget, 80 + i as u64, true);
        assert!(result.is_none());
        *slot = blocked;
        drop(hog);
    }
    let hog = budget.reserve(budget.limit() - budget.used()).unwrap();
    let grace = fec_inactive_grace_ns(0, false);
    let mut cursor = 0;
    let mut remaining = 1;
    assert_eq!(sweep_segment_roots_bounded(&mut roots, &mut cursor, 6 + grace, grace,
        || { if remaining == 0 { true } else { remaining -= 1; false } },
        |_, _| panic!("both growth attempts must be refused")), (0, false));
    assert_eq!(cursor, 1);
    assert!(roots[0].reservation.is_none(), "examined root expired after failed retry");
    assert_eq!(roots[1].bytes_received(), 240_000, "later owner was not examined");
    assert!(roots[1].reservation.is_some());
    // Expiring root 0 released enough memory for root 1's retry to succeed;
    // despite expired inactivity, completion must precede root retirement.
    let mut delivered = Vec::new();
    assert_eq!(sweep_segment_roots_bounded(&mut roots, &mut cursor, 6 + grace, grace,
        || false, |m, r| delivered.push((m, r))), (1, true));
    assert!(roots[1].completed);
    assert_eq!(delivered.len(), 1);
    owned_check(&delivered[0].0);
    drop(delivered); drop(roots); drop(hog);
    assert_eq!(budget.used(), 0);
}

#[test]
fn owned_stale_completion_after_root_replacement_is_discarded() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(1 << 20);
    let old = FecSegment { root: 50, total: 180_000, offset: 60_000 };
    let new = FecSegment { root: 51, total: 180_000, offset: 60_000 };
    let mut root = ReassemblySlot::new();
    assert!(root.admit_segment(old, owned_layout(), 0, 1000, 1, &budget));
    assert!(root.admit_segment(new, owned_layout(), 0, 1000, 2, &budget)); // newer root evicts
    assert_eq!(root.package_id, 51);
    let charge = budget.used();
    assert_eq!(charge, owned_root_metadata(4));
    // Same offset/length/total but the previous generation's root id.
    assert!(root.finish_charged(old, vec![9; 60_000], &budget).is_none());
    assert_eq!(budget.used(), charge);
    assert!(root.segment_parts.as_ref().unwrap().is_empty());
    // Same id but a different total is not this generation either.
    assert!(root.finish_charged(FecSegment { total: 240_000, ..new }, vec![9; 60_000], &budget).is_none());
    assert_eq!(budget.used(), charge);
    assert!(root.finish_charged(new, vec![2; 60_000], &budget).is_none());
    assert_eq!(budget.used(), charge + 60_000);
    assert_eq!(root.bytes_received(), 60_000);
    drop(root); assert_eq!(budget.used(), 0);
}

// ---- worker21: floor-aware immutable units and O(log n) bookkeeping ----
fn adaptive_greedy_units(total: usize, cap: usize) -> Vec<usize> {
    let (mut rem, mut units) = (total, Vec::new());
    while rem > 0 { let len = adaptive_unit_len(rem, cap); units.push(len); rem -= len; }
    units
}
fn adaptive_check_partition(total: usize, cap: usize) {
    let units = adaptive_greedy_units(total, cap);
    let (count, short, (long, longs)) = balanced_parts(total, cap);
    assert_eq!(count, total.div_ceil(cap).min(total / ADAPTIVE_MIN_UNIT_LEN).max(1), "total={total} cap={cap}");
    let mut expected = vec![long; longs];
    expected.extend(vec![short; count - longs]);
    assert_eq!(units, expected, "start_segment steps must equal the estimate: total={total} cap={cap}");
    for &len in &units {
        assert!(len >= ADAPTIVE_MIN_UNIT_LEN, "total={total} cap={cap} len={len}");
        for width in [445, 446, 891, 1385, 0x3fff] {
            let w = segment_width(len, width);
            assert!(w >= FEC_MIN_BLOCK_BYTES && w < len && w <= width);
            assert!(segment_unit_k(len, width) >= 2);
            assert_eq!(crate::fec::MessageLayout::new(len, w).unwrap().k, segment_unit_k(len, width));
        }
    }
}

#[test]
fn adaptive_floor_partition_matches_start_steps_and_keeps_k_at_least_two() {
    for cap in [1, 100, 445, 446, 447, 891, 892, 893, 1335, 4096, ADAPTIVE_PREFIX_CAP, FEC_SEGMENT_BYTES] {
        for total in 892..4_000 { adaptive_check_partition(total, cap); }
        for total in (4_000..30_000_000).step_by(104_729) { adaptive_check_partition(total, cap); }
    }
    // Boundaries: 891 never splits, 892 is exactly two floor units.
    assert_eq!(balanced_parts(891, 1).0, 1);
    assert_eq!(balanced_parts(892, 1), (2, 446, (447, 0)));
    assert_eq!(balanced_parts(1337, 1).0, 2);
    assert_eq!(balanced_parts(1338, 1).0, 3);
    // Ordinary large caps keep the old ceil(R/cap) partition exactly.
    assert_eq!(balanced_parts(1 << 20, ADAPTIVE_PREFIX_CAP).0, (1usize << 20).div_ceil(ADAPTIVE_PREFIX_CAP));
    assert_eq!(segment_width(446, 1385), 445);
    assert_eq!(segment_width(1_000, 1385), 999);
    assert_eq!(segment_width(2_000, 1385), 1385);
    // The estimated train/horizon use the same clamp: a 446-byte unit is K=2, never K=1.
    assert_eq!(p4_new_train(892, 0, 482, Some(1)).0, 4);
    assert_eq!(p4_new_train(2_000, 0, 1422, Some(1)).0, segment_unit_k(500, 1385) as u32 * 4);
}

#[test]
fn adaptive_unit_plan_cached_totals_match_bruteforce_under_restarts() {
    let mut x: u64 = 0x9e37_79b9;
    let mut rnd = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let plan = UnitPlan::new(1);
    let mut plan = plan.lock().unwrap();
    let mut brute: Vec<(u32, u32, u64)> = Vec::new();
    let mut end = 0u32;
    for step in 0..3_000 {
        if brute.is_empty() || rnd() % 3 != 0 {
            let (len, k) = (446 + (rnd() % 4_000) as u32, rnd() % 300 + 2);
            plan.record(end, len, k);
            brute.push((end, len, k));
            end += len;
        } else {
            let i = if rnd() % 2 == 0 { brute.len() - 1 } else { rnd() as usize % brute.len() };
            let k = rnd() % 300 + 2; // restart may shrink or grow K
            plan.record(brute[i].0, brute[i].1, k);
            brute[i].2 = k;
        }
        if step % 29 == 0 || step > 2_950 {
            assert_eq!(plan.started_k(), brute.iter().map(|u| u.2).sum::<u64>());
            assert_eq!(plan.end(), end as usize);
            for q in [0, rnd() as usize % brute.len(), brute.len() - 1] {
                let offset = brute[q].0;
                assert_eq!(plan.prefix_k(offset), brute.iter().filter(|u| u.0 < offset).map(|u| u.2).sum::<u64>());
            }
            assert_eq!(plan.prefix_k(u32::MAX), plan.started_k());
        }
    }
}

#[test]
fn adaptive_unit_plan_refuses_resized_restart_and_gaps() {
    let resized = std::panic::catch_unwind(|| {
        let p = UnitPlan::new(1); let mut p = p.lock().unwrap();
        p.record(0, 500, 2); p.record(500, 600, 2); p.record(0, 501, 3);
    });
    assert!(resized.is_err());
    let gap = std::panic::catch_unwind(|| {
        let p = UnitPlan::new(1); let mut p = p.lock().unwrap();
        p.record(0, 500, 2); p.record(501, 600, 2);
    });
    assert!(gap.is_err());
}

#[test]
fn adaptive_unit_wire_floor_applies_to_every_unit_including_last() {
    let s = |offset, total| FecSegment { root: 1, total, offset };
    assert!(s(0, 892).valid(446));
    assert!(s(446, 892).valid(446));
    assert!(!s(0, 891).valid(445));
    assert!(!s(446, 891).valid(445)); // final unit below the floor
    assert!(!s(0, 892).valid(445)); // nonfinal unit below the floor
    assert!(!s(0, 892).valid(892)); // a whole root is not a unit
    assert!(s(0, 60_000).valid(1_000) && s(59_000, 60_000).valid(1_000));
}

#[test]
fn adaptive_receiver_parts_reverse_overlap_duplicate_cached_sums() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(64 << 20);
    let lens: Vec<usize> = (0..40).map(|i| 446 + (i * 37) % 900).collect();
    let total: usize = lens.iter().sum();
    let offsets: Vec<usize> = lens.iter().scan(0, |a, &l| { let o = *a; *a += l; Some(o) }).collect();
    let mut x: u64 = 7;
    let mut rnd = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for trial in 0..60 {
        let mut order: Vec<usize> = (0..lens.len()).collect();
        match trial { 0 => order.reverse(), 1 => { order.remove(0); order.push(0); }, _ => for i in (1..order.len()).rev() { order.swap(i, rnd() as usize % (i + 1)); } }
        let mut root = ReassemblySlot::new();
        let mut done = None;
        for (n, &i) in order.iter().enumerate() {
            let seg = FecSegment { root: 9, total: total as u32, offset: offsets[i] as u32 };
            let layout = wire_fec_layout(lens[i], segment_width(lens[i], 1385)).unwrap();
            // A range overlapping an already-bound neighbour never binds or charges.
            if let Some(&(bo, bl)) = root.segment_extents.first() {
                let used = budget.used();
                let bad = FecSegment { root: 9, total: total as u32, offset: bo + 1 };
                let bad_layout = wire_fec_layout(bl as usize, segment_width(bl as usize, 1385)).unwrap();
                if bo as usize + 1 + bl as usize <= total { assert!(!root.admit_segment(bad, bad_layout, 0, segment_width(bl as usize, 1385), 1, &budget)); }
                assert_eq!(budget.used(), used);
            }
            assert!(root.admit_segment(seg, layout, 0, segment_width(lens[i], 1385), 2, &budget));
            assert!(root.admit_segment(seg, layout, 0, segment_width(lens[i], 1385), 3, &budget), "exact restart rebinds the same range");
            let result = root.finish_charged(seg, vec![i as u8 + 1; lens[i]], &budget);
            // Exact duplicate (fresh id) is accepted as coverage or dropped, never double charged.
            let used = budget.used();
            if result.is_none() {
                assert!(root.finish_charged(seg, vec![i as u8 + 1; lens[i]], &budget).is_none());
                assert_eq!(budget.used(), used);
                let parts = root.segment_parts.as_ref().unwrap();
                assert_eq!(parts.bytes, parts.iter().map(|p| p.1.len()).sum::<usize>());
                assert_eq!(parts.part_capacity, parts.iter().map(|p| p.1.capacity()).sum::<usize>());
                assert!(parts.windows(2).all(|w| w[0].0 > w[1].0));
                assert!(parts.last().map_or(true, |p| p.0 as usize > root.buf.len()), "joinable parts were flushed");
                assert_eq!(root.bytes_received(), (root.buf.len() + parts.bytes) as u64);
                assert_eq!(root.reservation.as_ref().unwrap().bytes(), root.segment_charge(root.segment_extents.capacity(), None, 0));
            } else { assert_eq!(n + 1, order.len()); done = result; }
        }
        let (message, reservation) = done.expect("root completes");
        for (i, &o) in offsets.iter().enumerate() { assert!(message[o..o + lens[i]].iter().all(|&b| b == i as u8 + 1)); }
        drop(message); drop(reservation); drop(root);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn adaptive_floor_metadata_fits_old_root_allowance_with_measured_sizes() {
    let (extent, part) = (std::mem::size_of::<(u32, u32)>(), std::mem::size_of::<(u32, Vec<u8>)>());
    assert_eq!((extent, part), (8, 32));
    eprintln!("measured: ReassemblySlot={}B Option<SegmentParts>={}B (ring slots are fixed, not charged)",
        std::mem::size_of::<ReassemblySlot>(), std::mem::size_of::<Option<SegmentParts>>());
    let table_cap = |n: usize| { let mut c = 4; while c < n { c *= 2; } c };
    for total in (892..200_000).chain((200_000..=crate::stp::MAX_JUMBOGRAM_LEN).step_by(99_991)) {
        let n = total / ADAPTIVE_MIN_UNIT_LEN;
        let metadata = SEGMENT_ROOT_METADATA + table_cap(n) * (extent + part);
        assert!(metadata <= total.div_ceil(2) + 256 + total.div_ceil(FEC_SEGMENT_BYTES) * 64, "total={total}");
    }
}

#[test]
fn adaptive_min_floor_root_completes_within_derived_allowance() {
    // 4096 floor units (K=2 at width 445), the head unit arrives LAST so every
    // other unit is held sparse; then a reverse-order root.
    let n = 4_096;
    let total = n * ADAPTIVE_MIN_UNIT_LEN;
    let cap = receive_connection_memory_limit(total, 1).unwrap();
    for reverse in [false, true] {
        let process = crate::receive_memory::ReceiveMemoryBudget::new(cap);
        let peer = crate::receive_memory::ReceiveMemoryBudget::connection_with_limit(&process, cap);
        let overhead = peer.reserve(cap - segment_reassembly_peak(total)).unwrap();
        let mut order: Vec<usize> = (1..n).collect();
        if reverse { order.reverse(); }
        order.push(0);
        let mut root = ReassemblySlot::new();
        let mut delivered = None;
        for (step, &i) in order.iter().enumerate() {
            let segment = FecSegment { root: 33, total: total as u32, offset: (i * ADAPTIVE_MIN_UNIT_LEN) as u32 };
            let layout = wire_fec_layout(ADAPTIVE_MIN_UNIT_LEN, segment_width(ADAPTIVE_MIN_UNIT_LEN, 1385)).unwrap();
            assert_eq!(layout.k, 2);
            assert!(root.admit_segment(segment, layout, 0, FEC_MIN_BLOCK_BYTES, 1, &peer), "unit {i}");
            if step + 1 == order.len() {
                assert!(root.segment_extents.capacity() <= 2 * n && root.segment_parts.as_ref().unwrap().capacity() <= 2 * n);
            }
            let donor = peer.reserve(ADAPTIVE_MIN_UNIT_LEN).expect("decoded unit lease");
            let result = root.finish_segment(segment, owned_unit_bytes(i, ADAPTIVE_MIN_UNIT_LEN), donor);
            if step + 1 < order.len() { assert!(result.is_none()); } else { delivered = result; }
            assert!(peer.used() <= cap);
        }
        let (message, reservation) = delivered.expect("floor root completes within the derived allowance");
        assert_eq!(message.len(), total);
        for i in 0..n { let o = i * ADAPTIVE_MIN_UNIT_LEN; assert!(message[o..o + ADAPTIVE_MIN_UNIT_LEN].iter().all(|&b| b == (i % 251) as u8 + 1)); }
        assert!(peer.peak() <= cap);
        drop(message); drop(reservation); drop(overhead);
        assert_eq!(process.used(), 0);
    }
}

#[test]
fn adaptive_receiver_part_cache_survives_refusal_and_resets_on_eviction() {
    let budget = crate::receive_memory::ReceiveMemoryBudget::new(16 << 20);
    let unit = ADAPTIVE_MIN_UNIT_LEN;
    let total = 8 * unit;
    let layout = wire_fec_layout(unit, FEC_MIN_BLOCK_BYTES).unwrap();
    let seg = |root, i: usize| FecSegment { root, total: total as u32, offset: (i * unit) as u32 };
    let mut root = ReassemblySlot::new();
    for i in [5, 3, 7] {
        assert!(root.admit_segment(seg(40, i), layout, 0, FEC_MIN_BLOCK_BYTES, 1, &budget));
        assert!(root.finish_charged(seg(40, i), vec![i as u8; unit], &budget).is_none());
    }
    let snapshot = |r: &ReassemblySlot| { let p = r.segment_parts.as_ref().unwrap();
        (p.iter().map(|q| q.0).collect::<Vec<_>>(), p.bytes, p.part_capacity) };
    let before = (snapshot(&root), budget.used());
    assert_eq!(before.0, (vec![7 * unit as u32, 5 * unit as u32, 3 * unit as u32], 3 * unit, 3 * unit));
    // Refused: unbound range, exact duplicate, wrong total, stale root id.
    assert!(root.finish_charged(seg(40, 1), vec![1; unit], &budget).is_none());
    assert!(root.finish_charged(seg(40, 5), vec![5; unit], &budget).is_none());
    assert!(root.finish_charged(FecSegment { root: 40, total: total as u32 + 1, offset: 0 }, vec![0; unit], &budget).is_none());
    assert!(root.finish_charged(seg(39, 0), vec![0; unit], &budget).is_none());
    assert!(!root.admit_segment(FecSegment { root: 40, total: total as u32, offset: (3 * unit + 1) as u32 }, layout, 0, FEC_MIN_BLOCK_BYTES, 2, &budget));
    assert_eq!((snapshot(&root), budget.used()), before);
    // A newer root evicts: parts, cached sums and their charge all go.
    assert!(root.admit_segment(seg(41, 0), layout, 0, FEC_MIN_BLOCK_BYTES, 3, &budget));
    assert_eq!(snapshot(&root), (vec![], 0, 0));
    assert_eq!(budget.used(), root.reservation.as_ref().unwrap().bytes());
    assert_eq!(root.bytes_received(), 0);
    drop(root);
    assert_eq!(budget.used(), 0);
}

// ---- worker21: one-flight exposure cap (frozen constants) and its wiring ----
#[test]
fn adaptive_exposure_cap_table_is_monotone_wide_and_frozen() {
    let p4 = |k: u32| Some(u64::from(k) + u64::from(k.min(2)));
    let snap = |rate_upps, rtt_ns, queues, unresolved| ExposureSnapshot { rate_upps, rtt_ns, queues, unresolved };
    let e0 = snap(0, None, 1, 0);
    assert_eq!(adaptive_exposure_cap(e0, 445, p4), 1335, "E=0 at W=445: k0=3 floor, a 1000-byte root stays ordinary K=3");
    assert_eq!(adaptive_exposure_cap(e0, 446, p4), 892);
    assert_eq!(adaptive_exposure_cap(e0, 1385, p4), 2770);
    // Valid RTT: B0 = ceil(R*T/(1e15*Q)). 100 pps * 100 ms = 10 packets -> k+2 <= 10.
    assert_eq!(adaptive_exposure_cap(snap(100_000_000, Some(100_000_000), 1, 0), 445, p4), 8 * 445);
    assert_eq!(adaptive_exposure_cap(snap(100_000_000, Some(100_000_000), 3, 0), 445, p4), 3 * 445, "ceil(10/3)=4 < U(k0)=5");
    assert_eq!(adaptive_exposure_cap(snap(100_000_000, Some(100_000_000), 0, 0), 445, p4), 8 * 445, "Q=0 means 1");
    // A valid RTT ignores E; no RTT uses E only.
    assert_eq!(adaptive_exposure_cap(snap(100_000_000, Some(100_000_000), 1, 1_000_000), 445, p4), 8 * 445);
    assert_eq!(adaptive_exposure_cap(snap(u64::MAX, None, 1, 1_000), 445, p4), ADAPTIVE_PREFIX_CAP);
    assert_eq!(adaptive_exposure_cap(snap(0, None, 2, 11), 445, p4), 4 * 445, "ceil(11/2)=6");
    assert_eq!(adaptive_exposure_cap(snap(0, Some(1_000_000_000), 1, 0), 445, p4), 1335, "rate 0 before the first CC pass: minimum train");
    // Wide arithmetic: extremes saturate at the 113920 ceiling without overflow.
    assert_eq!(adaptive_exposure_cap(snap(u64::MAX, Some(u64::MAX), u64::MAX, u64::MAX), 445, p4), ADAPTIVE_PREFIX_CAP, "ceil(2^64/1e15) packets");
    assert_eq!(adaptive_exposure_cap(snap(u64::MAX, Some(u64::MAX), 1, 0), 445, p4), ADAPTIVE_PREFIX_CAP);
    // Unknown upper: minimum cap; a bounded upper limits k.
    assert_eq!(adaptive_exposure_cap(snap(0, None, 1, 1_000), 445, |_| None), 1335);
    assert_eq!(adaptive_exposure_cap(snap(0, None, 1, 1_000), 445, |k| (k <= 10).then_some(u64::from(k))), 10 * 445);
    // Exhaustive: cap is a multiple of W in [max(892,k0 W), max(k0 W, 113920)], monotone in budget.
    for w in [445usize, 446, 600, 891, 892, 1385, 8_000] {
        let mut last = 0;
        for e in 0..400u64 {
            let c = adaptive_exposure_cap(snap(0, None, 1, e), w, p4);
            assert_eq!(c % w, 0);
            assert!(c >= ADAPTIVE_EXPOSURE_MIN_CAP && c >= adaptive_exposure_k0(w) * w);
            assert!(c <= ADAPTIVE_PREFIX_CAP.max(adaptive_exposure_k0(w) * w));
            assert!(c >= last); last = c;
            let k = (c / w) as u32;
            assert!(p4(k).unwrap() <= e.max(p4(adaptive_exposure_k0(w) as u32).unwrap()), "chosen unit's initial train fits the budget");
            if c < ADAPTIVE_PREFIX_CAP.max(adaptive_exposure_k0(w) * w) && c / w < ADAPTIVE_PREFIX_CAP / w {
                assert!(p4(k + 1).unwrap() > e.max(p4(adaptive_exposure_k0(w) as u32).unwrap()), "largest such k");
            }
        }
    }
}

#[test]
fn adaptive_exposure_snapshot_uses_measured_rtt_queue_work_and_committed_data_only() {
    let mut s = SendQueues::baseline_for_test(3, (1_000_000, 4 << 20, 4 << 20));
    assert_eq!(s.exposure_snapshot(7, u16::MAX), ExposureSnapshot { rate_upps: 7, rtt_ns: None, queues: 1, unresolved: 0 }, "u16::MAX is the unknown sentinel");
    assert_eq!(s.exposure_snapshot(7, 0).rtt_ns, None);
    assert_eq!(s.exposure_snapshot(7, 1_000).rtt_ns, Some(100_000_000));
    s.submit_messages(0, vec![vec![1; 100]]);
    s.submit_messages(2, vec![vec![2; 100]]);
    assert_eq!(s.exposure_snapshot(0, 1).queues, 2);
    // E is the span ledger's committed-unresolved DATA: commits add, ordered outcomes retire.
    let ConnectionState::Connected(mut state) = new_connection_state_connected(None, 0, 0, 0) else { unreachable!() };
    s.fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0));
    for kind in [PendingSendKind::MtuProbe, PendingSendKind::Ack, PendingSendKind::Reachability, PendingSendKind::Keepalive] {
        commit_connected_send(&mut state, &mut s, kind, 1, 512, &[], 0, None);
    }
    assert_eq!(s.exposure_snapshot(0, 1).unresolved, 0, "probes/ACK/generic never count");
    for seq in 0..5 { commit_connected_send(&mut state, &mut s, PendingSendKind::Data, 1 + seq, 512, &[], 0, None); }
    assert_eq!(s.exposure_snapshot(0, 1).unresolved, 5);
    // The tick copies one snapshot into every queue.
    prepare_connected_send_tick(&mut state, &mut s, 1_000);
    let expect = s.exposure_snapshot(state.stats.cc_rate_upps, state.RTT_mean);
    assert!(expect.rtt_ns.is_none(), "a fresh connection has no measured RTT");
    assert!(s.queues.iter().all(|q| q.exposure == expect));
}

fn adaptive_exposure_queues() -> SendQueues {
    let mut s = SendQueues::baseline_for_test(1, (1_000_000, 4 << 20, 4 << 20));
    let mut a = crate::fec_adapt::FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0);
    a.set_cost_smooth_for_test(); // budget base active, target selector 0
    assert!(a.budget_base_active() && a.target_selector() == 0);
    s.fec_adaptive = Some(a);
    s.set_tu_unresolved(true);
    s.set_exposure(ExposureSnapshot { rate_upps: 0, rtt_ns: None, queues: 1, unresolved: 0 });
    s
}
fn adaptive_exposure_roots(s: &SendQueues) -> (u64, u64) {
    (s.queues[0].budget_sink.lock().unwrap().roots, s.queues[0].target_root_sequence)
}
fn adaptive_finish_current_unit(s: &mut SendQueues) {
    let slot = s.queues[0].fec_send_slot.as_mut().unwrap();
    slot.next_id = slot.n;
}

#[test]
fn adaptive_exposure_root_freezes_once_and_units_follow_current_width_and_snapshot() {
    let message: Vec<u8> = (0..5_000).map(|i| (i % 251) as u8).collect();
    let mut s = adaptive_exposure_queues();
    s.submit_messages(0, vec![message.clone()]);
    s.fec_prepare_packet(0);
    assert!(s.fill_packet(&mut vec![0; 482]) > 0);
    let q = &s.queues[0];
    let first = q.fec_send_slot.as_ref().unwrap();
    let root = q.budget_root.clone().unwrap();
    assert_eq!(adaptive_exposure_roots(&s), (1, 1), "one root/draw/ordinal frozen before the split decision");
    assert_eq!(root.lock().unwrap().target_app_tag, message[..8]);
    assert_eq!(first.segment.unwrap().offset, 0);
    assert_eq!(first.message.len(), adaptive_unit_len(5_000, 1335));
    assert_eq!(first.message.len(), 1_250);
    assert_eq!((first.block_bytes, first.k), (445, 3));
    // Larger exposure + promoted TU: the next NEW unit uses the current snapshot and width.
    adaptive_finish_current_unit(&mut s);
    s.set_exposure(ExposureSnapshot { rate_upps: 100_000_000, rtt_ns: Some(100_000_000), queues: 1, unresolved: 0 });
    s.fec_prepare_packet(1);
    s.fill_packet(&mut vec![0; 1422]);
    let q = &s.queues[0];
    let next = q.fec_send_slot.as_ref().unwrap();
    assert!(Arc::ptr_eq(q.budget_root.as_ref().unwrap(), &root), "later units reuse the frozen root");
    assert_eq!(adaptive_exposure_roots(&s), (1, 1));
    assert_eq!(next.segment.unwrap().offset, 1_250);
    assert_eq!(next.message.len(), 3_750, "cap 8*1385 >= remainder: one final unit");
    assert_eq!(next.block_bytes, 1385);
    assert!(q.segmented_send.is_none());
    assert_eq!(next.message.as_slice(), &message[1_250..]);
}

#[test]
fn adaptive_exposure_small_unsplit_and_settled_roots_keep_one_admission() {
    // Below the smallest possible cap: no early root, ordinary whole FEC, one root.
    let mut s = adaptive_exposure_queues();
    s.queues[0].fec_adaptive = s.fec_adaptive.take(); // lent as during a packet
    assert!(!s.queues[0].may_segment(1_335, 482) && s.queues[0].may_segment(1_336, 482));
    assert!(!s.queues[0].may_segment(1_336, 1422) && s.queues[0].may_segment(2_771, 1422));
    s.fec_adaptive = s.queues[0].fec_adaptive.take();
    s.submit_messages(0, vec![vec![3; 1_200]]);
    s.fec_prepare_packet(0);
    assert!(s.fill_packet(&mut vec![0; 482]) > 0);
    assert!(s.queues[0].fec_send_slot.as_ref().unwrap().segment.is_none());
    assert_eq!(adaptive_exposure_roots(&s), (1, 1));
    // May split, but the exposure allows the whole root: the early root is the one start_fec_group uses.
    let mut s = adaptive_exposure_queues();
    s.set_exposure(ExposureSnapshot { rate_upps: 0, rtt_ns: None, queues: 1, unresolved: 1_000 });
    s.submit_messages(0, vec![vec![4; 5_000]]);
    s.fec_prepare_packet(0);
    assert!(s.fill_packet(&mut vec![0; 482]) > 0);
    let q = &s.queues[0];
    assert!(q.fec_send_slot.as_ref().unwrap().segment.is_none());
    assert_eq!(adaptive_exposure_roots(&s), (1, 1));
    assert_eq!(q.budget_root.as_ref().unwrap().lock().unwrap().target_ordinal, 1);
    // Just above the minimum cap: floor-aware split into two K>=2 units, still one root.
    let mut s = adaptive_exposure_queues();
    s.submit_messages(0, vec![vec![5; 1_400], vec![6; 900]]);
    s.fec_prepare_packet(0);
    assert!(s.fill_packet(&mut vec![0; 482]) > 0);
    let first = s.queues[0].fec_send_slot.as_ref().unwrap();
    assert_eq!((first.message.len(), first.k), (700, 2));
    adaptive_finish_current_unit(&mut s);
    s.fec_prepare_packet(1);
    s.fill_packet(&mut vec![0; 482]);
    let second = s.queues[0].fec_send_slot.as_ref().unwrap();
    assert_eq!((second.segment.unwrap().offset, second.message.len(), second.k), (700, 700, 2));
    assert_eq!(adaptive_exposure_roots(&s), (1, 1));
    // Next message gets its own single root (no lingering root).
    adaptive_finish_current_unit(&mut s);
    s.fec_prepare_packet(2);
    s.fill_packet(&mut vec![0; 482]);
    assert_eq!(adaptive_exposure_roots(&s), (2, 2));
    assert_eq!(s.queues[0].budget_root.as_ref().unwrap().lock().unwrap().target_ordinal, 2);
    // Settled: 2 MiB cap, the 5000-byte root is not split.
    let mut s = adaptive_exposure_queues();
    s.set_tu_unresolved(false);
    s.queues[0].fec_adaptive = s.fec_adaptive.take();
    assert!(!s.queues[0].may_segment(5_000, 482));
    assert_eq!(s.queues[0].adaptive_unit_cap(482, 5_000), FEC_SEGMENT_BYTES);
    // Budget base inactive keeps the legacy fixed prefix cap.
    let mut s = adaptive_exposure_queues();
    s.queues[0].fec_adaptive = Some(crate::fec_adapt::FecAdaptiveState::baseline_for_test(crate::ship::FEC, 0));
    s.set_tu_unresolved(true);
    assert_eq!(s.queues[0].adaptive_unit_cap(482, 1 << 20), ADAPTIVE_PREFIX_CAP);
    assert!(!s.queues[0].may_segment(ADAPTIVE_PREFIX_CAP, 482) && s.queues[0].may_segment(ADAPTIVE_PREFIX_CAP + 1, 482));
}

// ---- Profile-5 unresolved exposure: integrated adaptive-unit regressions ----
// Deterministic in-process link. Sender: real prepare_connected_send_tick,
// fec_prepare_packet, fill_packet and commit_connected_send at the connection's
// current TU. Receiver: real read_frame, wire_fec_layout/valid_fec_symbol,
// ReassemblySlot::admit_segment/segment_covered/finish_segment and
// fec_receive_block (inline decoder, K <= FEC_INLINE_MAX_BLOCKS here).
// Feedback: the connected ACK loop's ordered tail-finalization sequence
// (fec_adaptive.on_sequence_finalized, rand_finalize_packet,
// drain_accepted_cc_events, fec_on_packet_finalized) plus apply_ecn_congestion
// and accept_cc_event for CE. Not modeled: bitmap ACK decoding, RTT samples,
// loss timers and real sockets; the impairment is chosen by the test.

/// Frozen identity of one adaptive coded unit: owner, range, width, K and the
/// exact source Arc its equations are generated from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P5Unit { package: u64, root: u64, offset: u32, len: usize, block_bytes: usize, k: u32, source: usize }

fn p5_unit(package: u64, f: &FecSendSlot) -> P5Unit {
    let seg = f.segment.expect("profile-5 adaptive unit is segmented");
    P5Unit { package, root: seg.root, offset: seg.offset, len: f.message.len(), block_bytes: f.block_bytes,
        k: f.k, source: Arc::as_ptr(&f.message) as usize }
}

/// Every coded unit the sender still owns: active (or rescued), suspended and retained.
fn p5_open_slots(q: &UnreliableSendBuffer) -> Vec<(u64, &FecSendSlot)> {
    let mut out = Vec::new();
    if let Some(f) = &q.fec_send_slot { out.push((q.fec_rescue_package.unwrap_or(q.send_package_id), f)); }
    if let Some(f) = &q.fec_suspended { out.push((q.send_package_id, f)); }
    for r in q.fec_retained.values() { out.push((r.package, &r.slot)); }
    out
}

struct P5Rx {
    root: ReassemblySlot,
    slots: BTreeMap<u64, FecRecvSlot>,
    budget: Arc<crate::receive_memory::ReceiveMemoryBudget>,
    done: std::sync::mpsc::Sender<FecCompletion>,
    _done_rx: std::sync::mpsc::Receiver<FecCompletion>,
    workers: Arc<AtomicUsize>,
    /// (package, segment, len, block_bytes) per decoded unit, in decode order.
    decoded: Vec<(u64, FecSegment, usize, usize)>,
    delivered: Vec<Vec<u8>>,
    covered: usize,
}

impl P5Rx {
    fn new() -> Self {
        let (done, _done_rx) = std::sync::mpsc::channel();
        Self { root: ReassemblySlot::new(), slots: BTreeMap::new(),
            budget: crate::receive_memory::ReceiveMemoryBudget::new(1 << 30), done, _done_rx,
            workers: Arc::new(AtomicUsize::new(0)), decoded: Vec::new(), delivered: Vec::new(), covered: 0 }
    }
    fn receive(&mut self, payload: &[u8], ts: u64) {
        let mut off = 0;
        // 255 pads the rest of the packet (read_frame -> None), as on the receive path.
        while let Some((frame, used)) = read_frame(&payload[off..]) {
            off += used;
            let WireFrame::Fec { id, block_id, message_len, block_bytes, segment, data, .. } = frame else {
                panic!("profile-5 adaptive DATA carries segment FEC frames only");
            };
            let seg = segment.expect("adaptive unit symbols carry their root range");
            let layout = wire_fec_layout(message_len, block_bytes).expect("unit layout");
            assert!(valid_fec_symbol(layout, block_id, data.len()));
            assert!(seg.valid(message_len) && seg.root != id);
            assert!(self.root.admit_segment(seg, layout, block_id, data.len(), ts, &self.budget));
            if self.root.segment_covered(seg, message_len) { self.covered += 1; continue; }
            let slot = self.slots.entry(id).or_default();
            slot.package_id = id;
            slot.segment = Some(seg);
            if let Some((message, mut lease)) = fec_receive_block(slot, ConnectionKey::default(), id, message_len,
                block_bytes, block_id, data, &self.done, &self.workers, &self.budget) {
                lease.shrink(message.capacity());
                self.decoded.push((id, seg, message_len, block_bytes));
                if let Some((full, _lease)) = self.root.finish_segment(seg, message, lease) { self.delivered.push(full); }
            }
        }
    }
}

struct P5Link {
    s: ConnectionStateConnected,
    q: SendQueues,
    now: u64,
    rx: P5Rx,
    rx_cipher: ConnectionCipherTriplet,
    /// First observation of every unit, by package.
    units: BTreeMap<u64, P5Unit>,
    root: Option<Arc<Mutex<BudgetRoot>>>,
    sources: u64,
    repairs: u64,
    /// Committed (source, repair) symbols per unit package.
    per_unit: BTreeMap<u64, (u64, u64)>,
}

impl P5Link {
    /// Fresh Noise-encrypted 512-byte Candidate connection (assessment
    /// unresolved, 512-30=482 payload, 445-byte unit symbols) with the
    /// budget-active P4 fixture of adaptive_exposure_queues.
    fn fresh() -> Self {
        let now = 8_000_000_000;
        let (tx, rx_cipher) = super::wire_v2_tests::ciphers();
        let ConnectionState::Connected(s) = new_connection_state_connected(
            Some(tx), CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, MAGIC2_APP_CROSSLINK, now) else { panic!() };
        assert_eq!((s.current_tu, s.recovery.startup_state()), (512, Startup::Candidate));
        let mut q = adaptive_exposure_queues();
        q.set_tu_unresolved(false); // the prepare tick, not the fixture, must enter unresolved mode
        q.set_exposure(ExposureSnapshot::default());
        Self { s, q, now, rx: P5Rx::new(), rx_cipher, units: BTreeMap::new(), root: None, sources: 0, repairs: 0,
            per_unit: BTreeMap::new() }
    }
    fn payload_len(&self) -> usize {
        self.s.current_tu as usize - total_packet_payload_overhead_from_connect_magic1_inside_udp_payload(self.s.magic1).unwrap()
    }
    /// The DATA site of the send loop up to the socket: prepare tick,
    /// fec_prepare_packet, fill at current_tu, seal under nonce = sequence.
    /// Returns (sequence, sealed datagram, full plaintext buffer).
    fn fill_seal(&mut self) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        self.now += 100_000;
        prepare_connected_send_tick(&mut self.s, &mut self.q, self.now);
        let seq = self.s.send_sequence_number;
        self.q.fec_prepare_packet(seq);
        let mut p = vec![0u8; self.payload_len()];
        let n = self.q.fill_packet(&mut p);
        if n == 0 { return None; }
        let mut out = vec![0u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE];
        let len = seal_connected_packet(&mut self.s.cipher, 0, seq, &p[..n], &mut out, self.now).expect("sealed");
        assert!(len <= self.s.current_tu as usize);
        out.truncate(len);
        Some((seq, out, p))
    }
    /// finish_connected_send for a DATA datagram; `sent: None` is a local refusal.
    fn finish(&mut self, sent: Option<u64>, packet: &[u8], plaintext: &[u8]) -> bool {
        let dscp = self.q.last_dscp;
        finish_connected_send(&mut self.s, &mut self.q, PendingSendKind::Data, sent, self.now, packet, plaintext, dscp, 0, None)
    }
    /// One accepted DATA send; returns (sequence, sealed datagram).
    fn send(&mut self) -> Option<(u64, Vec<u8>)> {
        let (seq, packet, plaintext) = self.fill_seal()?;
        let now = self.now;
        assert!(self.finish(Some(now), &packet, &plaintext));
        assert_eq!(self.s.send_sequence_number, seq + 1, "DATA commit consumed exactly one sequence");
        self.count_symbols(&plaintext);
        self.check_units();
        Some((seq, packet))
    }
    /// Receiver: authenticate/open the datagram with the peer cipher, then the
    /// real frame/FEC/reassembly path.
    fn deliver(&mut self, packet: &[u8], ts: u64) {
        let nonce = load_u64(&packet[2..10]);
        let epoch = load_u32(&packet[10..14]);
        let mut plain = vec![0u8; packet.len()];
        let n = self.rx_cipher.open(nonce, epoch, &packet[..CONNECTED_HEADER_SIZE], &packet[CONNECTED_HEADER_SIZE..], &mut plain, ts)
            .expect("authentic DATA");
        self.rx.receive(&plain[..n], ts);
    }
    fn count_symbols(&mut self, p: &[u8]) {
        let mut off = 0;
        while let Some((frame, used)) = read_frame(&p[off..]) {
            off += used;
            if let WireFrame::Fec { id, block_id, message_len, block_bytes, .. } = frame {
                let repair = (block_id as usize) >= wire_fec_layout(message_len, block_bytes).unwrap().k;
                if repair { self.repairs += 1 } else { self.sources += 1 }
                let e = self.per_unit.entry(id).or_default();
                if repair { e.1 += 1 } else { e.0 += 1 }
            }
        }
    }
    /// Open units keep their first-observed owner/range/width/K/source; every
    /// unit draws on the one frozen message root and stays inside its allowance.
    fn check_units(&mut self) {
        let q = &self.q.queues[0];
        for (package, f) in p5_open_slots(q) {
            let unit = p5_unit(package, f);
            assert_eq!(*self.units.entry(package).or_insert(unit), unit, "open unit {package} changed identity");
            assert!(f.next_id <= f.n && f.k <= f.n, "{unit:?} next {} n {}", f.next_id, f.n);
            let budget = f.repair_accounting.budget.as_ref().expect("budget-active unit owns a segment allowance");
            let b = budget.lock().unwrap();
            assert!(b.emitted <= u64::from(b.reserved) && b.reserved <= b.limit, "{unit:?} {} {} {}", b.emitted, b.reserved, b.limit);
            let root = self.root.get_or_insert_with(|| b.root.clone());
            assert!(Arc::ptr_eq(root, &b.root), "every unit of the message shares one frozen root");
        }
    }
    /// Ordered tail finalization up to `upto` (exclusive), `lost` declared lost.
    fn finalize(&mut self, upto: u64, lost: &BTreeSet<u64>) {
        assert!(upto <= self.s.send_sequence_number);
        self.now += 100_000;
        while self.s.packets_waiting_ack_tail < upto {
            let seq = self.s.packets_waiting_ack_tail;
            let bit = seq % PACKETS_WAITING_ACK_CAPACITY;
            let (word, mask) = ((bit / 64) as usize, 1u64 << (bit % 64));
            // A clear bit is an already positively received packet (e.g. a probe
            // via take_positive_receipt); the ACK handler clears the rest here.
            let waiting = self.s.packets_waiting_ack_field[word] & mask != 0;
            let is_lost = lost.contains(&seq);
            assert!(waiting || !is_lost, "seq {seq} cannot be lost after a positive receipt");
            if waiting { self.s.packets_in_flight = self.s.packets_in_flight.checked_sub(1).unwrap(); }
            if is_lost { self.s.declared_lost_field[word] |= mask } else { self.s.declared_lost_field[word] &= !mask }
            self.s.packets_waiting_ack_field[word] &= !mask;
            if let Some(a) = &mut self.q.fec_adaptive { a.on_sequence_finalized(seq, is_lost, self.now); }
            rand_finalize_packet(&mut self.s, seq, is_lost);
            drain_accepted_cc_events(&mut self.s, &mut self.q);
            self.q.fec_on_packet_finalized(seq, is_lost);
            self.s.packets_waiting_ack_tail += 1;
        }
        self.check_units();
    }
    /// Committed-unresolved DATA E as the next prepare tick copies it.
    fn unresolved(&mut self) -> u64 {
        prepare_connected_send_tick(&mut self.s, &mut self.q, self.now);
        self.q.queues[0].exposure.unresolved
    }
    /// Accepted CE whose evidence is an already committed DATA packet.
    fn accept_ce(&mut self, evidence_seq: u64, evidence_sent_ns: u64) {
        self.now += 100_000;
        prepare_connected_send_tick(&mut self.s, &mut self.q, self.now);
        self.s.congestion_event_time_ns = 0;
        self.s.ecn_congestion_received = true;
        self.s.ecn_oldest_seq = evidence_seq;
        self.s.ecn_oldest_send_time = evidence_sent_ns;
        assert!(apply_ecn_congestion(&mut self.s, self.now, &crate::ship::CC, None));
        accept_cc_event(&mut self.s, &mut self.q, AcceptedCcEvent { kind: CC_EVENT_CE, evidence_seq, evidence_sent_ns, feedback_ns: self.now });
        self.check_units();
    }
}

fn p5_message(len: usize) -> Vec<u8> { (0..len).map(|i| (i * 7 % 251) as u8).collect() }

/// The prepare tick of a fresh Candidate connection, not a fixture flag, puts
/// the queue in budget-active unresolved exposure sizing.
fn p5_assert_unresolved_exposure(link: &P5Link) {
    let q = &link.q.queues[0];
    assert!(!link.s.tu_assessment_settled && link.s.recovery.assessment_unresolved());
    // fec_adaptive is lent to the queue only inside fill (exposure_sized); here
    // it sits on SendQueues.
    assert!(q.tu_unresolved && link.q.fec_adaptive.as_ref().unwrap().budget_base_active(), "queue in unresolved exposure mode");
}

#[test]
fn p5_unresolved_units_recover_dropped_reordered_symbols_through_known_loss_feedback() {
    let message = p5_message(6_000);
    let mut link = P5Link::fresh();
    link.q.submit_messages(0, vec![message.clone()]);
    // Phase 1: one held flight of 10 DATA packets; three of the first unit's
    // five initial symbols are dropped, the rest arrive pairwise reordered.
    let mut flight = Vec::new();
    for _ in 0..10 {
        let sent = link.send().expect("DATA available");
        p5_assert_unresolved_exposure(&link);
        flight.push((sent.0, sent.1, link.now));
    }
    let base = flight[0].0;
    let first = *link.units.values().next().unwrap();
    assert_eq!((first.offset, first.block_bytes, first.k), (0, 445, 3), "E=0 first unit is k0*445 bounded");
    assert_eq!(link.per_unit[&first.package], (3, 2), "initial P4 train K+2");
    let dropped: BTreeSet<u64> = [base + 1, base + 2, base + 3].into();
    let mut order: Vec<usize> = (0..flight.len()).collect();
    for pair in order.chunks_mut(2) { pair.reverse(); }
    for &i in &order {
        if !dropped.contains(&flight[i].0) { link.deliver(&flight[i].1, flight[i].2); }
    }
    assert!(link.rx.decoded.iter().all(|d| d.0 != first.package), "2 of K=3 cannot decode before feedback");
    assert!(link.rx.delivered.is_empty());
    // Accepted CE on committed evidence: counted, no grant at the shipping q=0,
    // and no open unit changes range/width (check_units).
    let ce_before = link.q.queues[0].event_repair.accepted_ce;
    link.accept_ce(flight[4].0, flight[4].2);
    assert_eq!(link.q.queues[0].event_repair.accepted_ce, ce_before + 1);
    assert_eq!(link.q.queues[0].event_repair.roots_granted, 0);
    // Committed unresolved DATA retires exactly on ordered ACK/loss outcomes.
    assert_eq!(link.unresolved(), 10);
    link.finalize(base + 5, &dropped);
    assert_eq!(link.unresolved(), 5);
    link.finalize(base + 10, &dropped);
    assert_eq!(link.unresolved(), 0);
    let unit0_n = p5_open_slots(&link.q.queues[0]).into_iter().find(|(p, _)| *p == first.package)
        .map(|(_, f)| f.n).expect("lossy unit retained for known-loss repair");
    assert!(unit0_n > 5, "known losses extend the retained unit's plan (n={unit0_n})");
    // Phase 2: prompt delivery, one more drop in a later unit, feedback every 6.
    let late_drop = base + 14;
    let mut lost = dropped.clone();
    let mut idle = 0;
    for _ in 0..1_000 {
        match link.send() {
            Some((seq, p)) => {
                idle = 0;
                p5_assert_unresolved_exposure(&link);
                if seq == late_drop { lost.insert(seq); } else { link.deliver(&p, link.now); }
                if (seq + 1 - base) % 6 == 0 { link.finalize(seq + 1, &lost); }
            }
            None => {
                let upto = link.s.send_sequence_number;
                link.finalize(upto, &lost);
                idle += 1;
                if idle == 3 { break; }
            }
        }
    }
    assert_eq!(idle, 3, "sender quiesced");
    assert_eq!(link.rx.delivered, vec![message.clone()], "full bytes completed exactly once");
    assert!(link.per_unit[&first.package].1 > 2, "feedback-driven repairs of the lossy unit were sent");
    // Units: several, contiguous, immutable, each decoded once with its sender identity.
    let mut units: Vec<P5Unit> = link.units.values().copied().collect();
    units.sort_by_key(|u| u.offset);
    assert!(units.len() >= 3, "multiple adaptive units: {units:?}");
    let mut next = 0usize;
    for u in &units {
        assert_eq!(u.offset as usize, next, "contiguous ranges {units:?}");
        assert!(u.len <= ADAPTIVE_PREFIX_CAP && u.block_bytes == segment_width(u.len, 445));
        next += u.len;
    }
    assert_eq!(next, message.len());
    let mut decoded: Vec<_> = link.rx.decoded.iter().map(|d| (d.0, d.1.offset, d.2, d.3)).collect();
    decoded.sort_by_key(|d| d.1);
    let expect: Vec<_> = units.iter().map(|u| (u.package, u.offset, u.len, u.block_bytes)).collect();
    assert_eq!(decoded, expect, "each unit decoded exactly once under its sender identity");
    // Root/repair budget: one root; sink counters equal the committed wire symbols.
    let sink = link.q.queues[0].budget_sink.lock().unwrap().clone();
    assert_eq!(sink.roots, 1);
    assert_eq!(sink.source_symbols, units.iter().map(|u| u64::from(u.k)).sum::<u64>());
    assert_eq!((sink.sources_emitted, sink.repairs_emitted), (link.sources, link.repairs), "{sink:?}");
    assert!(sink.repairs_emitted <= sink.planned_repairs, "{sink:?}");
    assert_eq!(link.unresolved(), 0);
}

#[test]
fn p5_unresolved_many_small_units_back_pressure_on_bounded_package_allocator() {
    let message = p5_message(40_000);
    let mut link = P5Link::fresh();
    // Occupy the bounded live-package table so only two identities remain:
    // the message root plus one live unit at a time.
    let ids = link.q.queues[0].package_allocator.clone().expect("connection package allocator");
    let mut held = Vec::new();
    while *ids.live.lock().unwrap() < 1022 { held.push(ids.allocate().unwrap()); }
    link.q.submit_messages(0, vec![message.clone()]);
    let base = link.s.send_sequence_number;
    let lost: BTreeSet<u64> = [base + 7].into();
    let (mut stalls, mut idle, mut max_live) = (0, 0, 0);
    for _ in 0..5_000 {
        match link.send() {
            Some((seq, p)) => {
                idle = 0;
                p5_assert_unresolved_exposure(&link);
                max_live = max_live.max(*ids.live.lock().unwrap());
                if !lost.contains(&seq) { link.deliver(&p, link.now); }
                if (seq + 1 - base) % 6 == 0 { link.finalize(seq + 1, &lost); }
            }
            None => {
                if link.q.has_unsent_data() { stalls += 1; }
                let upto = link.s.send_sequence_number;
                link.finalize(upto, &lost);
                idle += 1;
                if idle == 3 { break; }
            }
        }
    }
    assert_eq!(idle, 3, "sender quiesced");
    assert_eq!(max_live, 1024, "the live table actually saturated");
    assert!(stalls > 0, "allocator exhaustion back-pressured unit starts instead of discarding retained units");
    assert_eq!(link.rx.delivered, vec![message.clone()], "full bytes completed exactly once");
    let mut units: Vec<P5Unit> = link.units.values().copied().collect();
    units.sort_by_key(|u| u.offset);
    assert!(units.len() >= 20, "many small adaptive units: {}", units.len());
    let mut next = 0usize;
    for u in &units {
        assert_eq!(u.offset as usize, next);
        assert!(u.len <= ADAPTIVE_PREFIX_CAP && u.block_bytes == segment_width(u.len, 445));
        next += u.len;
    }
    assert_eq!(next, message.len());
    assert_eq!(link.rx.decoded.len(), units.len(), "each unit decoded once");
    let sink = link.q.queues[0].budget_sink.lock().unwrap().clone();
    assert_eq!(sink.roots, 1);
    assert_eq!(sink.source_symbols, units.iter().map(|u| u64::from(u.k)).sum::<u64>());
    assert_eq!((sink.sources_emitted, sink.repairs_emitted), (link.sources, link.repairs), "{sink:?}");
    assert_eq!(link.unresolved(), 0);
    assert!(p5_open_slots(&link.q.queues[0]).is_empty(), "all units retired after final outcomes");
    assert_eq!(*ids.live.lock().unwrap(), 1022, "root and unit leases released");
    drop(held);
    assert_eq!(*ids.live.lock().unwrap(), 0);
}

impl P5Link {
    /// Issue the due upward probe exactly as the send loop does (sealed 0xff
    /// payload at tu_probe_size, MtuProbe commit); returns its sequence.
    fn probe(&mut self, size: u64) -> u64 {
        self.now += 100_000;
        prepare_connected_send_tick(&mut self.s, &mut self.q, self.now);
        assert!(self.s.prepare_upward_probe(self.now));
        assert_eq!(self.s.tu_probe_size, size);
        let seq = self.s.send_sequence_number;
        let body = vec![0xffu8; size as usize - 30];
        let mut out = vec![0u8; size as usize];
        let n = seal_connected_packet(&mut self.s.cipher, 0, seq, &body, &mut out, self.now).unwrap();
        assert_eq!(n, size as usize);
        let now = self.now;
        assert!(finish_connected_send(&mut self.s, &mut self.q, PendingSendKind::MtuProbe, Some(now), now, &out, &[],
            Dscp::BestEffort, 0, None));
        seq
    }
    /// Authenticated receipt of the probe (positive ACK of that exact datagram).
    fn probe_acked(&mut self, seq: u64) {
        self.now += 100_000;
        assert_eq!(self.s.take_positive_receipt(seq), Some(PositiveReceipt::PendingProbe));
        let sent = self.now - 200_000;
        let now = self.now;
        self.s.finish_upward_probe(true, sent, now);
    }
    fn active_unit(&self) -> (P5Unit, u32, u32) {
        let q = &self.q.queues[0];
        let f = q.fec_send_slot.as_ref().expect("an open unit");
        (p5_unit(q.fec_rescue_package.unwrap_or(q.send_package_id), f), f.next_id, f.n)
    }
}

#[test]
fn p5_refused_data_in_open_unit_survives_deferred_1204_and_prompt_1452_without_recode() {
    let message = p5_message(6_000);
    let mut link = P5Link::fresh();
    link.q.submit_messages(0, vec![message.clone()]);
    assert_eq!(link.payload_len(), 482);
    // Unit 0 at the safe 512 TU: 445-byte symbols, K=3.
    let (_, s0) = link.send().unwrap();
    link.deliver(&s0, link.now);
    let (unit0, next0, n0) = link.active_unit();
    assert_eq!((unit0.offset, unit0.len, unit0.block_bytes, unit0.k, next0), (0, 1_200, 445, 3, 1));
    assert!(n0 > 3, "unit 0 plans repairs beyond K");
    let (dropped_source_1, _) = link.send().unwrap();
    let probe_1204 = link.probe(1204);
    // Source 2 of the open unit: filled, sealed, locally refused.
    let (refused_seq, refused_packet, refused_plain) = link.fill_seal().unwrap();
    assert!(!link.finish(None, &refused_packet, &refused_plain));
    assert_eq!(link.s.send_sequence_number, refused_seq, "a refusal consumes no sequence");
    assert_eq!(load_u64(&refused_packet[2..10]), refused_seq);
    let pending_identity = |s: &ConnectionStateConnected| {
        let p = s.pending_send.as_ref().expect("pending DATA copy");
        (p.kind, p.bytes.clone(), p.plaintext.clone(), s.send_sequence_number)
    };
    let refused = (PendingSendKind::Data, refused_packet.clone(), refused_plain.clone(), refused_seq);
    assert_eq!(pending_identity(&link.s), refused);
    assert_eq!(link.active_unit(), (unit0, 3, n0), "symbol 2 is tagged to the pending copy");
    // Authenticated exact-1204 proof while the copy is pending: deferred promotion.
    link.probe_acked(probe_1204);
    assert_eq!((link.s.current_tu, link.s.deferred_tu), (512, Some(1204)));
    assert_eq!(link.s.recovery.startup_state(), Startup::Prompt);
    assert!(!link.s.recovery.assessment_unresolved(), "the trial itself finished");
    for _ in 0..3 {
        prepare_connected_send_tick(&mut link.s, &mut link.q, link.now);
        assert!(!link.s.tu_assessment_settled && link.q.queues[0].tu_unresolved, "unresolved until effective");
        assert_eq!(pending_identity(&link.s), refused, "pending ciphertext, plaintext and nonce unchanged");
        assert_eq!(link.active_unit(), (unit0, 3, n0));
        link.now += 1_000_000;
    }
    assert_eq!(link.unresolved(), 2, "E counts the two committed DATA: not the probe, not the refused copy");
    // The send loop's pending retry: same bytes, now accepted; promotion effective.
    link.now += 100_000;
    prepare_connected_send_tick(&mut link.s, &mut link.q, link.now);
    let pending = link.s.pending_send.take().unwrap();
    let now = link.now;
    commit_connected_send(&mut link.s, &mut link.q, pending.kind, now, pending.bytes.len(), &pending.plaintext, 0, None);
    assert_eq!(link.s.send_sequence_number, refused_seq + 1, "the copy committed under its original nonce");
    assert_eq!((link.s.current_tu, link.s.deferred_tu), (1204, None));
    link.count_symbols(&pending.plaintext);
    link.deliver(&pending.bytes, link.now);
    prepare_connected_send_tick(&mut link.s, &mut link.q, link.now);
    assert!(link.s.tu_assessment_settled && !link.q.queues[0].tu_unresolved, "settles exactly at effective promotion");
    assert_eq!(link.payload_len(), 1_174, "1204 alone would give 1137-byte symbols, not 1385");
    assert_eq!(link.active_unit(), (unit0, 3, n0), "no restart/recode at 1204");
    // The one prompt 1452 issuance, acknowledged: effective at once (no pending copy).
    let probe_1452 = link.probe(1452);
    link.probe_acked(probe_1452);
    assert_eq!((link.s.current_tu, link.s.deferred_tu), (1452, None));
    assert_eq!(link.payload_len(), 1_422);
    assert_eq!(link.active_unit(), (unit0, 3, n0), "growth neither completes nor recodes the open unit");
    assert!(link.rx.decoded.is_empty(), "receiver holds 2 of K=3: no premature completion");
    // Unit 0's remaining repairs at TU 1452 still carry 445-byte symbols of the
    // same equations; the receiver decodes unit 0 only from them.
    while link.q.queues[0].fec_send_slot.as_ref().is_some_and(|f| f.next_id < f.n) {
        assert_eq!(link.active_unit().0, unit0);
        let (_, r) = link.send().unwrap();
        link.deliver(&r, link.now);
    }
    // Planned repairs may only extend (exposure refresh), never recode.
    assert!(link.q.queues[0].fec_send_slot.is_none(), "a fully sent unit leaves the active slot");
    let (still0, next_final, n_final) = p5_open_slots(&link.q.queues[0]).into_iter()
        .find(|(p, _)| *p == unit0.package).map(|(p, f)| (p5_unit(p, f), f.next_id, f.n)).expect("unit 0 retained");
    assert_eq!((still0, next_final), (unit0, n_final));
    assert!(n_final >= n0);
    assert_eq!(link.per_unit[&unit0.package], (3, u64::from(n_final) - 3), "exactly the planned train, no recode symbols");
    assert_eq!(link.rx.decoded.len(), 1);
    assert_eq!(link.rx.decoded[0], (unit0.package, FecSegment { root: unit0.root, total: 6_000, offset: 0 }, 1_200, 445));
    // The next new unit starts at the exact next offset at the 1452 width,
    // settled-sized (whole 4800-byte remainder, under 2 MiB).
    let (_, p) = link.send().unwrap();
    link.deliver(&p, link.now);
    assert!(p.len() <= 1452);
    let (unit1, next1, _) = link.active_unit();
    assert_eq!(next1, 1);
    assert_ne!(unit1.package, unit0.package);
    assert_eq!((unit1.root, unit1.offset, unit1.len, unit1.block_bytes), (unit0.root, 1_200, 4_800, 1_385));
    // Finish the message with real commits and ordered outcomes.
    let mut idle = 0;
    for _ in 0..200 {
        match link.send() {
            Some((_, p)) => { idle = 0; link.deliver(&p, link.now); }
            None => {
                let upto = link.s.send_sequence_number;
                link.finalize(upto, &[dropped_source_1].into());
                idle += 1;
                if idle == 3 { break; }
            }
        }
    }
    assert_eq!(idle, 3);
    assert_eq!(link.rx.delivered, vec![message], "full bytes exactly once");
    assert_eq!(link.units.len(), 2);
    assert_eq!(link.units[&unit0.package], unit0);
    assert_eq!(link.unresolved(), 0);
}
