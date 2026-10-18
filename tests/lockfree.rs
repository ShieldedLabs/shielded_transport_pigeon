use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
#[path = "../examples/support/lockfree_common.rs"]
mod common;
use common::*;
use std::time::{Duration, Instant};

#[test]
fn stopped_pump_backpressure_and_zero_copy_reclaim() {
    let (pump, _, _) = setup();
    drop(pump);
    let (pump, reference) = new_pump(
        vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()],
        0,
        None,
        (1_000_000, 4 << 20, 4 << 20),
        100,
    );
    let mut ep = reference.into_lockfree(2);
    let payload = vec![7; 100];
    let ptr = payload.as_ptr();
    assert!(
        ep.try_send(Command::Send {
            peer: ConnectionKey::default(),
            queue: 0,
            class: Dscp::BestEffort,
            payload
        })
        .is_ok()
    );
    assert!(ep.try_send(Command::Refresh).is_ok());
    let returned = ep.try_send(Command::Stats).err().unwrap();
    assert_eq!(returned.kind, SendErrorKind::Full);
    assert!(ep.try_recv().is_none());
    assert_eq!(
        ep.try_send(Command::Send {
            peer: ConnectionKey::default(),
            queue: 0,
            class: Dscp::BestEffort,
            payload: vec![0; 101]
        })
        .err()
        .unwrap()
        .kind,
        SendErrorKind::Oversized
    );
    ep.close();
    assert_eq!(
        ep.try_send(Command::Refresh).err().unwrap().kind,
        SendErrorKind::Closed
    );
    assert!(ep.try_reclaim().is_none());
    drop(pump);
    if let Some(Command::Send { payload, .. }) = ep.try_reclaim() {
        assert_eq!(payload.as_ptr(), ptr);
    } else {
        panic!("missing payload");
    }
    assert!(matches!(ep.try_reclaim(), Some(Command::Refresh)));
    assert!(ep.try_reclaim().is_none());
}

#[test]
fn event_ring_full_preserves_all_results_and_payload_allocations() {
    let (mut pump, reference) = new_pump(
        vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()],
        0,
        None,
        (1_000_000, 4 << 20, 4 << 20),
        100,
    );
    let mut ep = reference.into_lockfree(2);
    let mut pointers = Vec::new();
    for n in 0..2 {
        let payload = vec![n; 100];
        pointers.push(payload.as_ptr());
        assert!(
            ep.try_send(Command::Send {
                peer: ConnectionKey::default(),
                queue: 0,
                class: Dscp::BestEffort,
                payload
            })
            .is_ok()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut command = Command::Stats;
    loop {
        pump.run_for(Duration::from_millis(1));
        match ep.try_send(command) {
            Ok(()) => break,
            Err(error) => {
                assert_eq!(error.kind, SendErrorKind::Full);
                command = error.command;
            }
        }
        assert!(Instant::now() < deadline);
    }
    // Give the pump many chances to fill output and backpressure Stats. A short
    // run budget is not a promise of progress if the OS preempts that call.
    for _ in 0..10 {
        pump.run_for(Duration::from_millis(1));
    }
    for ptr in pointers {
        let event = loop {
            if let Some(event @ Event::Submitted { .. }) = ep.try_recv() {
                break event;
            }
            pump.run_for(Duration::from_millis(1));
            assert!(Instant::now() < deadline);
        };
        if let Event::Submitted {
            rejected: Some((_, _, _, payload)),
            ..
        } = event
        {
            assert_eq!(payload.as_ptr(), ptr);
        } else {
            panic!("missing rejected ownership event");
        }
    }
    loop {
        if let Some(event) = ep.try_recv() {
            assert!(matches!(event, Event::Update(_)));
            break;
        }
        pump.run_for(Duration::from_millis(1));
        assert!(Instant::now() < deadline);
    }
}

#[test]
fn encrypted_connect_accept_and_bidirectional_roundtrip_on_caller_threads() {
    let (pa, mut a, aa) = setup();
    let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa);
    let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, vec![17; 1_000_000]);
    let inbound = receive(&mut b, 1);
    assert_eq!(inbound[0].1, vec![17; 1_000_000]);
    assert_eq!(inbound[0].0, aa.connection_key());
    send(&mut b, inbound[0].0, b"reply".to_vec());
    assert_eq!(receive(&mut a, 1)[0].1, b"reply");
    drain(&mut a);
    drain(&mut b);
}

#[test]
fn stats_and_explicit_local_disconnect() {
    let (pa, mut a, _) = setup();
    let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa);
    let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, b"before disconnect".to_vec());
    receive(&mut b, 1);
    drain(&mut a);
    enqueue(&mut a, Command::Stats);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(Event::Update(update)) = a.try_recv() {
            if !update.connection_stats.is_empty() {
                assert!(update.thread_stats.loop_iterations > 0);
                break;
            }
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    enqueue(&mut a, Command::Disconnect(peer));
    loop {
        if let Some(Event::Update(update)) = a.try_recv() {
            if update.current_connections.is_empty() {
                break;
            }
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn multi_peer_isolation_and_incoming_accept() {
    let (pa, mut a, _) = setup();
    let (pb, mut b, ab) = setup();
    let (pc, mut c, ac) = setup();
    let _wa = Worker::start(pa);
    let _wb = Worker::start(pb);
    let _wc = Worker::start(pc);
    let kb = connect(&mut a, &mut b, ab);
    let kc = connect(&mut a, &mut c, ac);
    send(&mut a, kb, b"only b".to_vec());
    send(&mut a, kc, b"only c".to_vec());
    assert_eq!(receive(&mut b, 1)[0].1, b"only b");
    assert_eq!(receive(&mut c, 1)[0].1, b"only c");
    assert!(drain(&mut a).is_empty());
}

#[test]
fn cancel_flag_loop_exits_and_park_observes_shutdown() {
    let (pump, mut ep, _) = setup();
    let mut worker = Worker::start(pump);
    // Consume the initial edge and then exercise a real futex park until drop.
    while ep.try_recv().is_some() {}
    let ready = ep.readiness();
    let mut seen = 0;
    ready.wait(&mut seen);
    worker.stop();
    ready.wait(&mut seen);
    assert!(ep.is_finished());
    assert!(!ep.park_until_ready() || ep.try_recv().is_some());
}

#[test]
fn park_until_ready_delivers_without_polling() {
    let (pa, mut a, _) = setup();
    let (pb, mut b, ab) = setup();
    let _wa = Worker::start(pa);
    let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, ab);
    send(&mut a, peer, b"parked".to_vec());
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(Event::Update(update)) = b.try_recv() {
            if let Some((_, payload)) = update.received_unreliable_messages.front() {
                assert_eq!(payload, b"parked");
                break;
            }
        } else {
            assert!(b.park_until_ready());
        }
        assert!(Instant::now() < end);
    }
}

#[test]
fn game_frames_one_ms_budget_every_sixteen_ms_deliver() {
    let (mut pa, mut a, _) = setup();
    let (mut pb, mut b, ab) = setup();
    let peer = ab.connection_key();
    assert!(a.try_send(Command::Connect(ab)).is_ok());
    let mut connected = false;
    let mut accepted = false;
    let mut sent = false;
    let mut got = false;
    for _ in 0..400 {
        let frame = Instant::now();
        pa.run_until(frame + Duration::from_millis(1));
        pb.run_until(Instant::now() + Duration::from_millis(1));
        while let Some(event) = a.try_recv() {
            match event {
                Event::Update(u) => connected |= !u.current_connections.is_empty(),
                Event::Submitted { rejected, .. } => assert!(rejected.is_none()),
            }
        }
        while let Some(event) = b.try_recv() {
            if let Event::Update(u) = event {
                accepted |= !u.current_connections.is_empty();
                for (_, payload) in u.received_unreliable_messages {
                    assert_eq!(payload, b"frame");
                    got = true;
                }
            }
        }
        if connected && accepted && !sent {
            send(&mut a, peer, b"frame".to_vec());
            sent = true;
        }
        if got {
            break;
        }
        std::thread::sleep(
            (frame + Duration::from_millis(16)).saturating_duration_since(Instant::now()),
        );
    }
    assert!(connected && accepted && sent && got);
}
