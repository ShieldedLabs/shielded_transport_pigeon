#![allow(dead_code)]
use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub fn setup() -> (Pump, LockfreeEndpoint, STPAddress) {
    let probe = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let key =
        new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
    let (pump, endpoint) = new_pump(
        vec![key],
        port,
        None,
        (1_000_000, 32 << 20, 32 << 20),
        2_000_000,
    );
    (pump, endpoint.into_lockfree(128), address)
}
pub struct Worker {
    cancel: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    pub fn start(mut pump: Pump) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let join = std::thread::spawn(move || {
            // run_for parks on socket/command readiness internally; no busy loop.
            while !stop.load(Ordering::Acquire) {
                pump.run_for(Duration::from_millis(20));
            }
        });
        Self {
            cancel,
            join: Some(join),
        }
    }
    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(j) = self.join.take() {
            j.join().unwrap();
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}
pub fn enqueue(ep: &mut LockfreeEndpoint, mut command: Command) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match ep.try_send(command) {
            Ok(()) => return,
            Err(e) => {
                assert_eq!(e.kind, SendErrorKind::Full);
                command = e.command;
                drain(ep);
                std::thread::yield_now();
                assert!(Instant::now() < deadline);
            }
        }
    }
}
pub fn drain(ep: &mut LockfreeEndpoint) -> Vec<(ConnectionKey, Vec<u8>)> {
    let mut received = Vec::new();
    while let Some(event) = ep.try_recv() {
        match event {
            Event::Submitted {
                rejected,
                oversized,
                invalid_queue,
            } => {
                assert!(rejected.is_none(), "protocol send queue rejected message");
                assert!(oversized.is_none());
                assert!(invalid_queue.is_none());
            }
            Event::Update(mut update) => {
                received.extend(update.received_unreliable_messages.drain(..))
            }
        }
    }
    received
}
pub fn connect(
    a: &mut LockfreeEndpoint,
    b: &mut LockfreeEndpoint,
    address: STPAddress,
) -> ConnectionKey {
    let target = address.connection_key();
    enqueue(a, Command::Connect(address));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut outgoing = false;
    let mut incoming = false;
    while !outgoing || !incoming {
        while let Some(event) = a.try_recv() {
            if let Event::Update(update) = event {
                outgoing |= update
                    .current_connections
                    .iter()
                    .any(|(addr, _)| addr.connection_key() == target);
            }
        }
        while let Some(event) = b.try_recv() {
            if let Event::Update(update) = event {
                incoming |= !update.current_connections.is_empty();
            }
        }
        assert!(Instant::now() < deadline, "connect/accept timed out");
        std::thread::yield_now();
    }
    target
}
pub fn send(ep: &mut LockfreeEndpoint, peer: ConnectionKey, bytes: Vec<u8>) {
    enqueue(
        ep,
        Command::Send {
            peer,
            queue: 0,
            class: Dscp::BestEffort,
            payload: bytes,
        },
    );
}
pub fn receive(ep: &mut LockfreeEndpoint, count: usize) -> Vec<(ConnectionKey, Vec<u8>)> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut messages = Vec::new();
    while messages.len() < count {
        messages.extend(drain(ep));
        assert!(
            Instant::now() < deadline,
            "receive timed out: {}/{}",
            messages.len(),
            count
        );
        if messages.len() < count {
            assert!(ep.park_until_ready(), "endpoint stopped while receiving");
        }
    }
    messages
}
