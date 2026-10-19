use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
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
        state.downshift_for_recovery(queues.target_copy_pending());
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
            PendingSendKind::Reachability,
            sent,
            512,
            &[],
            0,
            None,
        );
        assert_eq!(state.outage.next_probe_ns, due);
        assert_eq!(state.outage.probe_interval_ns, interval);
        assert_eq!(
            state.outage.probes[(sequence % 8) as usize],
            (sequence, sent)
        );
        assert!(state.outage.probe_due(sent));
        let ack = crate::ack::BitmapAck {
            highest: sequence,
            receipt_base: sequence,
            sample_seq: sequence,
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
fn profile_three_small_data_is_admitted_in_both_directions_and_cipher_modes() {
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
            PendingSendKind::Reachability,
            sent,
            512,
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
    // This caller-owned driver intentionally uses the PUBLIC ring pump, not the
    // synchronous reference adapter used by codec/capture fixtures above.
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
                .filter(|d| d.kind == "reachability")
                .count();
            // No application command/service call: both retained native schedulers
            // must park and wake solely for generic send and receipt deadlines.
            std::thread::sleep(Duration::from_millis(1100));
            let after = log
                .lock()
                .unwrap()
                .iter()
                .filter(|d| d.kind == "reachability")
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
                assert!(captured.iter().filter(|d| d.kind == "reachability").count() >= after + 4);
            }
        }
        assert_eq!(received.len(), rounds as usize * count as usize);
    }
}
