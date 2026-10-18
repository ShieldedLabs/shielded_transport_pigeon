#![allow(dead_code)]
use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
pub fn setup() -> (Pump, LockfreeEndpoint, STPAddress) { setup_with(RingConfig::default(), 2_000_000) }
pub fn setup_with(rings: RingConfig, maximum: usize) -> (Pump, LockfreeEndpoint, STPAddress) {
    let probe = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let port = probe.local_addr().unwrap().port(); drop(probe);
    let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
    let (pump, endpoint) = new_pump(vec![key], port, None, (1_000_000, 32 << 20, 32 << 20), maximum);
    (pump, endpoint.into_rings(rings), address)
}
pub struct Worker { cancel: Arc<AtomicBool>, join: Option<std::thread::JoinHandle<()>> }
impl Worker {
    pub fn start(mut pump: Pump) -> Self {
        let cancel = Arc::new(AtomicBool::new(false)); let stop = cancel.clone();
        let join = std::thread::spawn(move || { while !stop.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(100)); } });
        Self { cancel, join: Some(join) }
    }
    pub fn stop(&mut self) { self.cancel.store(true, Ordering::Release); if let Some(j) = self.join.take() { j.join().unwrap(); } }
}
impl Drop for Worker { fn drop(&mut self) { self.stop(); } }
pub fn drain(ep: &mut LockfreeEndpoint) -> Vec<(ConnectionKey, Vec<u8>)> {
    let mut messages = Vec::new();
    while let Some(event) = ep.try_recv() { if let Event::Message { peer, data } = event { messages.push((peer, data)); } }
    messages
}
pub fn connect(a: &mut LockfreeEndpoint, b: &mut LockfreeEndpoint, address: STPAddress) -> ConnectionKey {
    let target = address.connection_key(); assert!(a.try_connect(address));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut outgoing = false; let mut incoming = false;
    while !outgoing || !incoming {
        while let Some(event) = a.try_recv() { if let Event::Connected { peer, .. } = event { outgoing |= peer == target; } }
        while let Some(event) = b.try_recv() { if let Event::Connected { .. } = event { incoming = true; } }
        assert!(Instant::now() < deadline, "connect/accept timed out"); std::thread::yield_now();
    }
    target
}
pub fn send(ep: &mut LockfreeEndpoint, peer: ConnectionKey, mut bytes: Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ep.try_send(peer, 0, Dscp::BestEffort, &mut bytes) { assert!(Instant::now() < deadline); std::thread::yield_now(); }
}
pub fn receive(ep: &mut LockfreeEndpoint, count: usize) -> Vec<(ConnectionKey, Vec<u8>)> {
    let deadline = Instant::now() + Duration::from_secs(20); let mut messages = Vec::new();
    while messages.len() < count {
        messages.extend(drain(ep));
        assert!(Instant::now() < deadline, "receive timed out: {}/{}", messages.len(), count);
        if messages.len() < count { assert!(ep.park_until_ready()); }
    }
    messages
}
