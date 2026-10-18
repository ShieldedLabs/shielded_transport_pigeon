//! Replaceable application/core boundary for the API experiments.
//!
//! One bounded exchange slot carries a complete reference-API command batch and
//! its result. `submit` only transfers ownership; `try_take` only observes results.
//! Neither runs transport work. All protocol state belongs exclusively to Pump.
//! Commands signal the pump's eventfd, and publication increments Ready's durable
//! generation. No user callback runs in the pump. Future endpoint designs replace
//! this module without changing packet, pacing, or FEC policy.
use crate::native_sockets::NetworkWake;
use crate::stp::{NetworkThreadPull, NetworkThreadPush};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct Ready {
    generation: Mutex<u64>,
    changed: Condvar,
    pub(crate) enabled: AtomicBool,
    pub(crate) send_space: AtomicBool,
}
impl Default for Ready {
    fn default() -> Self { Self { generation: Mutex::new(1), changed: Condvar::new(), enabled: AtomicBool::new(false), send_space: AtomicBool::new(false) } }
}
impl Ready {
    pub(crate) fn notify(&self) {
        let mut generation = self.generation.lock().unwrap();
        *generation = generation.wrapping_add(1);
        self.changed.notify_all();
    }
    /// Wait for a durable publication edge; initialize `observed` to zero.
    pub fn wait(&self, observed: &mut u64) {
        let generation = self.generation.lock().unwrap();
        let generation = self.changed.wait_while(generation, |g| *g == *observed).unwrap();
        *observed = *generation;
    }
}
#[derive(Default)]
struct Slot { outstanding: bool, request: Option<NetworkThreadPush>, response: Option<NetworkThreadPull> }
pub(crate) struct Port {
    slot: Mutex<Slot>,
    /// Serializes the optional blocking compatibility exchange, not protocol work.
    pub(crate) exchange: Mutex<()>,
    pub(crate) stop: AtomicBool,
    pub(crate) exited: AtomicBool,
    pub(crate) wake: Arc<NetworkWake>,
    pub(crate) ready: Arc<Ready>,
}
impl Port {
    pub(crate) fn new() -> Arc<Self> { Arc::new(Self {
        slot: Mutex::new(Slot::default()), exchange: Mutex::new(()),
        stop: AtomicBool::new(false), exited: AtomicBool::new(false),
        wake: Arc::new(NetworkWake::new().expect("create pump command wakeup")),
        ready: Arc::new(Ready::default()),
    }) }
    pub(crate) fn take_request(&self) -> Option<NetworkThreadPush> { self.slot.lock().unwrap().request.take() }
    pub(crate) fn has_request(&self) -> bool { self.slot.lock().unwrap().request.is_some() }
    pub(crate) fn publish(&self, response: NetworkThreadPull) {
        self.slot.lock().unwrap().response = Some(response);
        self.ready.notify();
    }
}
/// Thread-safe application handle. Dropping it cancels (does not flush) the pump.
/// One command batch/result may be outstanding. Concurrent producers may call
/// `submit`, receiving their untouched command back when the slot is occupied.
pub struct Endpoint { pub(crate) inner: Arc<Port> }
impl Endpoint {
    pub fn submit(&self, request: NetworkThreadPush) -> Result<(), NetworkThreadPush> {
        let mut slot = self.inner.slot.lock().unwrap();
        if slot.outstanding || self.is_finished() || self.inner.stop.load(Ordering::Acquire) { return Err(request); }
        slot.outstanding = true;
        slot.request = Some(request);
        drop(slot);
        self.inner.wake.notify();
        Ok(())
    }
    pub fn try_take(&self) -> Option<NetworkThreadPull> {
        let mut slot = self.inner.slot.lock().unwrap();
        let response = slot.response.take()?;
        slot.outstanding = false;
        Some(response)
    }
    pub fn close(&self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake.notify();
        self.inner.ready.notify();
    }
    pub fn is_finished(&self) -> bool { self.inner.exited.load(Ordering::Acquire) }
    /// Subscribe to connection, delivery, result and interested send-space edges.
    pub fn readiness(&self) -> Arc<Ready> {
        self.inner.ready.enabled.store(true, Ordering::Release);
        self.inner.wake.notify();
        self.inner.ready.clone()
    }
}
impl Drop for Endpoint { fn drop(&mut self) { self.close(); } }
