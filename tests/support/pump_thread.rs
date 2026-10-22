// Caller-owned thread adapter used only by the research binaries. The library
// owns no threads. This legacy batch-shaped helper is NOT a public library API:
// it is implemented entirely on the public three-ring endpoint.
use stp_core::stp::*;
use stp_core::pump::{Event, LockfreeEndpoint};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
struct App { endpoint: LockfreeEndpoint, peers: Vec<(STPAddress, [u8; 64])> }
pub struct NetworkThreadHandle { app: Mutex<App>, cancel: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl NetworkThreadHandle {
    pub fn shutdown(mut self) { self.stop(); }
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release); self.app.lock().unwrap().endpoint.close();
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}
impl Drop for NetworkThreadHandle { fn drop(&mut self) { self.stop(); } }
pub fn new_network_thread(keys: Vec<IdentityKeyPair>, port: u16, pps: Option<u64>, bounds: (u32,u32,u32), maximum: usize) -> NetworkThreadHandle {
    new_network_thread_with_options(keys, port, pps, bounds, maximum, Default::default())
}
pub fn new_network_thread_with_options(keys: Vec<IdentityKeyPair>, port: u16, pps: Option<u64>, bounds: (u32,u32,u32), maximum: usize, options: NetworkThreadOptions) -> NetworkThreadHandle {
    let (mut pump, endpoint) = new_pump_with_options(keys, port, pps, bounds, maximum, options);
    let cancel = Arc::new(AtomicBool::new(false)); let stopping = cancel.clone();
    let thread = std::thread::spawn(move || { while !stopping.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(100)); } });
    NetworkThreadHandle { app: Mutex::new(App { endpoint, peers: Vec::new() }), cancel, thread: Some(thread) }
}
fn drain(app: &mut App, response: &mut NetworkThreadPull) {
    while let Some(event) = app.endpoint.try_recv() {
        match event {
            Event::Connected { address, handshake_hash, .. } => app.peers.push((address, handshake_hash)),
            Event::Disconnected { peer, .. } => app.peers.retain(|(address, _)| address.connection_key() != peer),
            Event::Message { peer, data } => response.received_unreliable_messages.push_back((peer, data)),
            Event::ConnectFailed { .. } => {},
        }
    }
}
pub fn service_connections(handle: &NetworkThreadHandle, request: NetworkThreadPush) -> Option<NetworkThreadPull> {
    let mut app = handle.app.lock().unwrap(); let mut response = NetworkThreadPull::default();
    if app.endpoint.is_finished() { return None; }
    let deadline = Instant::now() + Duration::from_secs(5);
    for address in request.initiate_connections {
        while !app.endpoint.try_connect(address.clone()) {
            drain(&mut app, &mut response); if Instant::now() >= deadline { return None; }
            std::thread::sleep(Duration::from_micros(25));
        }
    }
    drain(&mut app, &mut response);
    response.send_unreliable_rejected = reject_suffix(request.send_unreliable, |peer, queue, class, payload| {
        app.endpoint.try_send(peer, queue, class, payload)
    });
    app.endpoint.request_protocol_stats();
    loop {
        drain(&mut app, &mut response);
        if let Some(mut stats) = app.endpoint.try_protocol_stats() {
            stats.current_connections = app.peers.clone();
            stats.received_unreliable_messages = response.received_unreliable_messages;
            stats.send_unreliable_rejected = response.send_unreliable_rejected;
            return Some(stats);
        }
        if app.endpoint.is_finished() || Instant::now() >= deadline { return None; }
        std::thread::sleep(Duration::from_micros(25));
    }
}

// The legacy cohort ledger requires dense admission: after the first refusal,
// return the entire remaining suffix, even if a concurrent pump frees space.
fn reject_suffix(
    messages: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>,
    mut send: impl FnMut(ConnectionKey, usize, Dscp, &mut Vec<u8>) -> bool,
) -> Vec<(ConnectionKey, usize, Dscp, Vec<u8>)> {
    let mut rejected = Vec::new();
    let mut blocked = false;
    for (peer, queue, class, mut payload) in messages {
        if blocked || !send(peer, queue, class, &mut payload) {
            blocked = true;
            rejected.push((peer, queue, class, payload));
        }
    }
    rejected
}
