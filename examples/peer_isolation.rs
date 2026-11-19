//! Cross-peer send isolation probe (public API only, localhost, ephemeral ports).
//!
//! One source pump talks to a "fast" and a "slow" peer. The source is configured
//! with a tiny per-queue send buffer and a very low packet rate, so a large
//! message to the slow peer cannot drain quickly: the next large message to that
//! peer cannot be admitted into its protocol queue. A small marked message for
//! the fast peer is enqueued *behind* them and must still be delivered.
//!
//!   cargo run --release --example peer_isolation                  # expects isolation
//!   cargo run --release --example peer_isolation -- --expect-blocked
//!
//! Default mode: the fast message must arrive while the slow peer still has an
//! unsent backlog (exit 0), otherwise it fails (exit 1). `--expect-blocked`
//! (single shared send-ring FIFO baseline): the fast message must NOT arrive for
//! a full observation window while `send_head_blocked` grows, and must arrive
//! after the slow peer is disconnected (exit 0); isolation there is a failure.
use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const SLOW_MESSAGES: usize = 2; // 1 MB head (admitted into an empty queue), then 100 B that cannot fit
const SLOW_BYTES: usize = 1_000_000;
const FAST_MARK: &[u8] = b"FAST-MARKED-PAYLOAD";
const SOURCE_PPS: u64 = 1; // shared packet-rate cap on the source pump
const SEND_BUFFER: (u32, u32, u32) = (1_000_000, 1, 1); // smaller than any message
const WARMUP_LIMIT: Duration = Duration::from_secs(10);
/// Observation window: the fast message gets this long to arrive in each mode.
const WINDOW: Duration = Duration::from_millis(2500);
/// After disconnecting the slow peer, the fast message must arrive within this.
const RECOVERY_LIMIT: Duration = Duration::from_secs(5);

struct Node {
    pump: Option<Pump>,
    ep: LockfreeEndpoint,
    address: STPAddress,
}
struct Worker {
    cancel: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    fn start(mut pump: Pump) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let join = std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                pump.run_for(Duration::from_millis(20));
            }
        });
        Self {
            cancel,
            join: Some(join),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn node(pps: Option<u64>, bounds: (u32, u32, u32)) -> Node {
    let probe = std::net::UdpSocket::bind("[::1]:0").expect("bind probe");
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let key =
        new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2b).unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
    let (pump, ep) = new_pump_with_options(
        vec![key],
        port,
        pps,
        bounds,
        2_000_000,
        NetworkThreadOptions::default(),
    );
    Node {
        pump: Some(pump),
        ep,
        address,
    }
}

fn payload(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
        .collect()
}

/// Poll an endpoint until `done` accepts the events seen, or `limit` elapses.
fn poll<T>(
    ep: &mut LockfreeEndpoint,
    limit: Duration,
    mut step: impl FnMut(&mut LockfreeEndpoint, Event) -> Option<T>,
) -> Option<T> {
    let end = Instant::now() + limit;
    loop {
        while let Some(event) = ep.try_recv() {
            if let Some(v) = step(ep, event) {
                return Some(v);
            }
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

fn main() {
    let expect_blocked = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--expect-blocked") => true,
        Some(other) => fail(&format!("unknown argument {other}; use --expect-blocked")),
    };
    // The watchdog bounds every failure path, including a wedged pump.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        eprintln!("FAIL: watchdog expired");
        std::process::exit(2);
    });

    let mut source = node(Some(SOURCE_PPS), SEND_BUFFER);
    let mut fast = node(None, (1_000_000, 32 << 20, 32 << 20));
    let mut slow = node(None, (1_000_000, 32 << 20, 32 << 20));
    let (fast_key, slow_key) = (fast.address.connection_key(), slow.address.connection_key());
    let _w_source = Worker::start(source.pump.take().unwrap());
    let _w_fast = Worker::start(fast.pump.take().unwrap());
    let _w_slow = Worker::start(slow.pump.take().unwrap());

    assert!(source.ep.try_connect(fast.address));
    assert!(source.ep.try_connect(slow.address));
    let (mut out_fast, mut out_slow) = (false, false);
    let ok = poll(&mut source.ep, Duration::from_secs(10), |_, e| {
        match e {
            Event::Connected { peer, .. } if peer == fast_key => out_fast = true,
            Event::Connected { peer, .. } if peer == slow_key => out_slow = true,
            Event::ConnectFailed { .. } => fail("source connect failed"),
            _ => {}
        }
        (out_fast && out_slow).then_some(())
    });
    if ok.is_none() {
        fail("source->fast/slow connect timed out");
    }
    // Accepting sides announce the inbound association too.
    let mut inbound = Vec::new();
    for n in [&mut fast.ep, &mut slow.ep] {
        let peer = poll(n, Duration::from_secs(5), |_, e| match e {
            Event::Connected { peer, .. } => Some(peer),
            _ => None,
        });
        match peer {
            Some(p) => inbound.push(p),
            None => fail("inbound connect not seen"),
        }
    }
    let fast_in = inbound[0];

    // Healthy-fast-connection check before any pressure: admission true, delivery intact.
    let mut warm = payload(0xA1, 100);
    let warm_copy = warm.clone();
    assert!(
        source.ep.try_send(fast_key, 0, Dscp::BestEffort, &mut warm),
        "warmup admission refused"
    );
    let got = poll(&mut fast.ep, WARMUP_LIMIT, |_, e| match e {
        Event::Message { peer, data } => Some((peer, data)),
        _ => None,
    });
    match got {
        Some((p, d)) if p == fast_in && d == warm_copy => {}
        Some(_) => fail("warmup message to fast peer corrupted or from wrong peer"),
        None => fail("fast connection not healthy: warmup message never arrived"),
    }

    // Pressure: several large messages to the slow peer, then one small marked
    // message to the fast peer. Every try_send must be admitted into the ring.
    let slow_payloads: Vec<Vec<u8>> = (0..SLOW_MESSAGES)
        .map(|i| payload(i as u8, if i == 0 { SLOW_BYTES } else { 100 }))
        .collect();
    let before = source.ep.stats();
    for p in &slow_payloads {
        let mut m = p.clone();
        assert!(
            source.ep.try_send(slow_key, 0, Dscp::BestEffort, &mut m),
            "slow admission refused"
        );
    }
    let mut marked = FAST_MARK.to_vec();
    assert!(
        source
            .ep
            .try_send(fast_key, 0, Dscp::BestEffort, &mut marked),
        "fast admission refused"
    );
    let started = Instant::now();

    // Observe the window. Fast delivery inside it means isolation.
    let mut fast_msgs: Vec<(ConnectionKey, Vec<u8>)> = Vec::new();
    let mut slow_msgs = 0usize;
    let drain_fast = |n: &mut LockfreeEndpoint, v: &mut Vec<(ConnectionKey, Vec<u8>)>| {
        while let Some(e) = n.try_recv() {
            if let Event::Message { peer, data } = e {
                v.push((peer, data));
            }
        }
    };
    let mut isolated_at = None;
    while started.elapsed() < WINDOW {
        drain_fast(&mut fast.ep, &mut fast_msgs);
        while let Some(e) = slow.ep.try_recv() {
            if matches!(e, Event::Message { .. }) {
                slow_msgs += 1;
            }
        }
        if !fast_msgs.is_empty() && isolated_at.is_none() {
            isolated_at = Some(started.elapsed());
            if !expect_blocked {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mid = source.ep.stats();
    let slow_backlog = source.ep.queued_send_bytes(slow_key, 0);
    let fast_backlog = source.ep.queued_send_bytes(fast_key, 0);
    let blocked_attempts = mid.send_head_blocked - before.send_head_blocked;
    println!(
        "window {:?}: fast_delivered={} at={:?} slow_complete={} send_head_blocked+={} \
         sent+={}/{} slow_queued_bytes={} fast_queued_bytes={}",
        started.elapsed(),
        fast_msgs.len(),
        isolated_at,
        slow_msgs,
        blocked_attempts,
        mid.sent - before.sent,
        SLOW_MESSAGES + 1,
        slow_backlog,
        fast_backlog
    );

    // The slow peer must still hold a backlog in both modes (otherwise the
    // scenario proved nothing), and must not have completed all its messages.
    if slow_backlog == 0 || slow_msgs >= SLOW_MESSAGES {
        fail("slow peer backlog drained; scenario did not create pressure");
    }
    if expect_blocked {
        if isolated_at.is_some() {
            fail("expected head-of-line blocking, but fast message arrived (isolation present)");
        }
        if blocked_attempts == 0
            || fast_backlog == 0
            || mid.sent - before.sent >= (SLOW_MESSAGES + 1) as u64
        {
            fail(
                "no head-of-line evidence: send_head_blocked/queued counters did not show a stuck head",
            );
        }
        println!("OBSERVED: fast message blocked behind slow head for the full window");
    } else {
        if isolated_at.is_none() {
            fail(&format!(
                "fast message not delivered within {WINDOW:?} while slow peer backlog held \
                 (send_head_blocked+={blocked_attempts}): cross-peer head-of-line blocking"
            ));
        }
        println!("OBSERVED: fast message delivered during slow peer backlog");
    }

    // Disconnect the slow peer; the fast message must now be (or already be) delivered.
    assert!(source.ep.try_disconnect(slow_key), "disconnect refused");
    let gone = poll(&mut source.ep, Duration::from_secs(5), |_, e| match e {
        Event::Disconnected { peer, .. } if peer == slow_key => Some(()),
        _ => None,
    });
    if gone.is_none() {
        fail("slow peer Disconnected event not observed");
    }
    let end = Instant::now() + RECOVERY_LIMIT;
    while fast_msgs.is_empty() && Instant::now() < end {
        drain_fast(&mut fast.ep, &mut fast_msgs);
        std::thread::sleep(Duration::from_millis(5));
    }
    if fast_msgs.len() != 1 {
        fail(&format!(
            "after slow disconnect expected exactly 1 fast message, got {}",
            fast_msgs.len()
        ));
    }
    let (peer, data) = &fast_msgs[0];
    if *peer != fast_in || data != FAST_MARK {
        fail("fast payload corrupted or attributed to wrong peer");
    }
    // Let any duplicate straggle in, then confirm the final counters.
    std::thread::sleep(Duration::from_millis(300));
    drain_fast(&mut fast.ep, &mut fast_msgs);
    if fast_msgs.len() != 1 {
        fail("duplicate fast delivery");
    }
    let end_stats = source.ep.stats();
    // Undelivered slow-peer messages are dropped as "unknown peer" once it is gone.
    if end_stats.send_dropped_unknown > SLOW_MESSAGES as u64
        || end_stats.send_dropped_oversized != 0
        || end_stats.send_dropped_invalid_queue != 0
    {
        fail(&format!("unexpected send drops: {end_stats:?}"));
    }
    if source.ep.queued_send_bytes(fast_key, 0) != 0 {
        fail("fast queue still charged after delivery");
    }
    println!(
        "PASS ({}): recovered after slow disconnect; final stats {:?}",
        if expect_blocked {
            "expect-blocked"
        } else {
            "isolation"
        },
        end_stats
    );
}
