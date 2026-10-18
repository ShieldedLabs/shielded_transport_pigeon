// Caller-owned thread adapter, shared by tests and binaries. Not library code.
use stp_core::stp::*;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

pub struct NetworkThreadHandle {
    endpoint: Endpoint,
    cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl std::ops::Deref for NetworkThreadHandle {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint { &self.endpoint }
}
impl NetworkThreadHandle {
    pub fn shutdown(mut self) { self.stop(); }
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.endpoint.close();
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}
impl Drop for NetworkThreadHandle { fn drop(&mut self) { self.stop(); } }
pub fn new_network_thread(keys: Vec<IdentityKeyPair>, port: u16, pps: Option<u64>, bounds: (u32,u32,u32), max_message_size: usize) -> NetworkThreadHandle {
    new_network_thread_with_options(keys, port, pps, bounds, max_message_size, Default::default())
}
pub fn new_network_thread_with_options(keys: Vec<IdentityKeyPair>, port: u16, pps: Option<u64>, bounds: (u32,u32,u32), max_message_size: usize, options: NetworkThreadOptions) -> NetworkThreadHandle {
    let (mut pump, endpoint) = new_pump_with_options(keys, port, pps, bounds, max_message_size, options);
    let cancel = Arc::new(AtomicBool::new(false));
    let stopping = cancel.clone();
    let thread = std::thread::spawn(move || {
        while !stopping.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(100)); }
    });
    NetworkThreadHandle { endpoint, cancel, thread: Some(thread) }
}
