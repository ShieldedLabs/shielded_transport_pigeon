//! Pump-owned bounded ownership queues. The reference exchange is retained only
//! for internal protocol regression/research adapters; applications use three rings.
use crate::native_sockets::NetworkWake;
use crate::stp::{NetworkThreadPull, NetworkThreadPush};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
#[path = "lockfree.rs"]
pub mod lockfree;
#[path = "ring.rs"]
mod ring;
use lockfree::{Control, Event, LockfreeEndpoint, RingConfig, SendMessage, Counters};
use ring::Ring;

/// Futex generation notifier; no pump-side mutex or user callback.
#[derive(Debug)]
pub struct Ready { generation: AtomicU32, waiters: AtomicU32, pub(crate) enabled: AtomicBool, pub(crate) send_space: AtomicBool }
impl Default for Ready {
    fn default() -> Self { Self { generation: AtomicU32::new(1), waiters: AtomicU32::new(0), enabled: AtomicBool::new(false), send_space: AtomicBool::new(false) } }
}
impl Ready {
    pub(crate) fn notify(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if self.waiters.load(Ordering::SeqCst) != 0 {
            #[cfg(target_os = "linux")]
            crate::platform::sys::futex_wake_all(&self.generation);
        }
    }
    /// Initialize observed to zero. Spurious wakeups and 2^32 generation wrap apply.
    pub fn wait(&self, observed: &mut u64) {
        let wanted = *observed as u32;
        self.waiters.fetch_add(1, Ordering::SeqCst);
        loop {
            let current = self.generation.load(Ordering::SeqCst);
            if current != wanted { *observed = current as u64; break; }
            #[cfg(target_os = "linux")]
            crate::platform::sys::futex_wait(&self.generation, wanted);
            #[cfg(not(target_os = "linux"))]
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(crate) struct NativePort {
    pub send: Ring<SendMessage>, pub control: Ring<Control>, pub events: Ring<Event>,
    pub counters: Counters, pub send_full: AtomicBool, pub control_full: AtomicBool,
    pub stats_requested: AtomicBool, stats_active: AtomicBool, pub stats_result: AtomicPtr<NetworkThreadPull>,
}
impl NativePort {
    pub(crate) fn input_drained(&self, ready: &Ready, control: bool) {
        std::sync::atomic::fence(Ordering::SeqCst);
        let full = if control { &self.control_full } else { &self.send_full };
        // Keep the flag set until the producer retries: park can recognize space
        // even when the publication precedes its generation snapshot.
        if full.load(Ordering::SeqCst) { ready.notify(); }
    }
    pub(crate) fn emit(&self, ready: &Ready, event: Event) -> Result<(), Event> {
        unsafe { self.events.push(event) }?;
        ready.notify();
        Ok(())
    }
}
struct ReferencePort { requests: Ring<NetworkThreadPush>, responses: Ring<NetworkThreadPull> }
pub(crate) struct Port {
    reference: OnceLock<ReferencePort>, outstanding: AtomicBool,
    app: Mutex<()>, pub(crate) exchange: Mutex<()>,
    pub(crate) stop: AtomicBool, pub(crate) exited: AtomicBool,
    pub(crate) wake: Arc<NetworkWake>, pub(crate) ready: Arc<Ready>,
    pub(crate) native: OnceLock<NativePort>, max_payload: usize, send_queues: usize,
}
impl Port {
    pub(crate) fn new(max_payload: usize, send_queues: usize) -> Arc<Self> {
        Arc::new(Self { reference: OnceLock::new(), outstanding: AtomicBool::new(false), app: Mutex::new(()), exchange: Mutex::new(()), stop: AtomicBool::new(false), exited: AtomicBool::new(false), wake: Arc::new(NetworkWake::new().expect("create pump command wakeup")), ready: Arc::new(Ready::default()), native: OnceLock::new(), max_payload, send_queues })
    }
    pub(crate) fn is_reference(&self) -> bool { self.native.get().is_none() }
    pub(crate) fn wants_snapshot(&self) -> bool { self.is_reference() }
    pub(crate) fn wants_stats(&self) -> bool { self.native.get().is_none_or(|n| n.stats_active.load(Ordering::Relaxed)) }
    pub(crate) fn send_space_ready(&self, used: usize, previous: usize) -> bool { used < previous && self.ready.send_space.swap(false, Ordering::AcqRel) }
    pub(crate) fn transport_ready(&self) { self.ready.notify(); }
    pub(crate) fn take_request(&self) -> Option<(NetworkThreadPush, Option<crate::stp::ConnectionKey>)> {
        if let Some(n) = self.native.get() {
            if n.stats_result.load(Ordering::Acquire).is_null() && n.stats_requested.load(Ordering::Acquire) {
                n.stats_active.store(true, Ordering::Relaxed);
                n.stats_requested.store(false, Ordering::Release);
                return Some((NetworkThreadPush::default(), None));
            }
            None
        } else { self.reference.get().and_then(|r| unsafe { r.requests.pop() }.map(|r| (r, None))) }
    }
    pub(crate) fn has_request(&self) -> bool {
        if let Some(n) = self.native.get() { n.send.has_value() || n.control.has_value() || n.stats_requested.load(Ordering::Acquire) } else { self.reference.get().is_some_and(|r| r.requests.has_value()) }
    }
    pub(crate) fn publish(&self, response: NetworkThreadPull) {
        if let Some(n) = self.native.get() {
            let response = Box::into_raw(Box::new(response));
            assert!(n.stats_result.compare_exchange(std::ptr::null_mut(), response, Ordering::Release, Ordering::Relaxed).is_ok());
            n.stats_active.store(false, Ordering::Release);
        } else { assert!(unsafe { self.reference.get().unwrap().responses.push(response) }.is_ok()); }
        self.ready.notify();
    }
}
/// Setup handle; convert to the single-owner application API before running Pump.
pub(crate) struct Endpoint { pub(crate) inner: Arc<Port> }
impl Endpoint {
    pub(crate) fn submit(&self, request: NetworkThreadPush) -> Result<(), NetworkThreadPush> {
        let _app = self.inner.app.lock().unwrap();
        if self.inner.outstanding.load(Ordering::Acquire) || self.is_finished() || self.inner.stop.load(Ordering::Acquire) { return Err(request); }
        self.inner.outstanding.store(true, Ordering::Release);
        let reference = self.inner.reference.get_or_init(|| ReferencePort { requests: Ring::new(1), responses: Ring::new(1) });
        assert!(unsafe { reference.requests.push(request) }.is_ok());
        self.inner.wake.notify(); Ok(())
    }
    pub(crate) fn try_take(&self) -> Option<NetworkThreadPull> {
        let _app = self.inner.app.lock().unwrap();
        let response = unsafe { self.inner.reference.get()?.responses.pop() }?;
        self.inner.outstanding.store(false, Ordering::Release); Some(response)
    }
    pub fn into_rings(self, config: RingConfig) -> LockfreeEndpoint {
        assert!(!self.inner.outstanding.load(Ordering::Acquire));
        assert!(self.inner.native.set(NativePort { send: Ring::new(config.send), control: Ring::new(config.control), events: Ring::new(config.receive), counters: Counters::default(), send_full: AtomicBool::new(false), control_full: AtomicBool::new(false), stats_requested: AtomicBool::new(false), stats_active: AtomicBool::new(false), stats_result: AtomicPtr::new(std::ptr::null_mut()) }).is_ok());
        self.inner.ready.enabled.store(true, Ordering::Release);
        self.inner.wake.notify(); LockfreeEndpoint::new(self)
    }
    pub fn close(&self) { self.inner.stop.store(true, Ordering::Release); self.inner.wake.notify(); self.inner.ready.notify(); }
    pub fn is_finished(&self) -> bool { self.inner.exited.load(Ordering::Acquire) }
    pub fn readiness(&self) -> Arc<Ready> { self.inner.ready.enabled.store(true, Ordering::Release); self.inner.wake.notify(); self.inner.ready.clone() }
}
impl Drop for Endpoint { fn drop(&mut self) { self.close(); } }

impl Drop for NativePort {
    fn drop(&mut self) {
        let result = *self.stats_result.get_mut();
        if !result.is_null() { unsafe { drop(Box::from_raw(result)); } }
    }
}
