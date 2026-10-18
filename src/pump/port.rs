//! Pump-owned bounded ownership queues. The reference exchange is retained only
//! for internal protocol regression/research adapters; applications use three rings.
use crate::native_sockets::NetworkWake;
use crate::stp::{NetworkThreadPull, NetworkThreadPush};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
            unsafe { libc::syscall(libc::SYS_futex, self.generation.as_ptr(), libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, i32::MAX); }
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
            unsafe { libc::syscall(libc::SYS_futex, self.generation.as_ptr(), libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, wanted, std::ptr::null::<libc::timespec>()); }
            #[cfg(not(target_os = "linux"))]
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(crate) struct NativePort {
    pub send: Ring<SendMessage>, pub control: Ring<Control>, pub events: Ring<Event>,
    pub counters: Counters, pub send_full: AtomicBool, pub control_full: AtomicBool,
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
pub(crate) struct Port {
    requests: Ring<NetworkThreadPush>, responses: Ring<NetworkThreadPull>, outstanding: AtomicBool,
    app: Mutex<()>, pub(crate) exchange: Mutex<()>,
    pub(crate) stop: AtomicBool, pub(crate) exited: AtomicBool,
    pub(crate) wake: Arc<NetworkWake>, pub(crate) ready: Arc<Ready>,
    pub(crate) native: OnceLock<NativePort>, max_payload: usize,
}
impl Port {
    pub(crate) fn new(max_payload: usize) -> Arc<Self> {
        Arc::new(Self { requests: Ring::new(1), responses: Ring::new(1), outstanding: AtomicBool::new(false), app: Mutex::new(()), exchange: Mutex::new(()), stop: AtomicBool::new(false), exited: AtomicBool::new(false), wake: Arc::new(NetworkWake::new().expect("create pump command wakeup")), ready: Arc::new(Ready::default()), native: OnceLock::new(), max_payload })
    }
    pub(crate) fn is_reference(&self) -> bool { self.native.get().is_none() }
    pub(crate) fn wants_snapshot(&self) -> bool { self.is_reference() }
    pub(crate) fn wants_stats(&self) -> bool { self.is_reference() }
    pub(crate) fn send_space_ready(&self, used: usize, previous: usize) -> bool { used < previous && self.ready.send_space.swap(false, Ordering::AcqRel) }
    pub(crate) fn transport_ready(&self) { self.ready.notify(); }
    pub(crate) fn take_request(&self) -> Option<(NetworkThreadPush, Option<crate::stp::ConnectionKey>)> {
        if self.is_reference() { unsafe { self.requests.pop() }.map(|r| (r, None)) } else { None }
    }
    pub(crate) fn has_request(&self) -> bool {
        if let Some(n) = self.native.get() { n.send.has_value() || n.control.has_value() } else { self.requests.has_value() }
    }
    pub(crate) fn publish(&self, response: NetworkThreadPull) {
        assert!(unsafe { self.responses.push(response) }.is_ok());
        self.ready.notify();
    }
}
/// Setup handle; convert to the single-owner application API before running Pump.
pub struct Endpoint { pub(crate) inner: Arc<Port> }
impl Endpoint {
    pub fn submit(&self, request: NetworkThreadPush) -> Result<(), NetworkThreadPush> {
        let _app = self.inner.app.lock().unwrap();
        if self.inner.outstanding.load(Ordering::Acquire) || self.is_finished() || self.inner.stop.load(Ordering::Acquire) { return Err(request); }
        self.inner.outstanding.store(true, Ordering::Release);
        assert!(unsafe { self.inner.requests.push(request) }.is_ok());
        self.inner.wake.notify(); Ok(())
    }
    pub fn try_take(&self) -> Option<NetworkThreadPull> {
        let _app = self.inner.app.lock().unwrap();
        let response = unsafe { self.inner.responses.pop() }?;
        self.inner.outstanding.store(false, Ordering::Release); Some(response)
    }
    pub fn into_rings(self, config: RingConfig) -> LockfreeEndpoint {
        assert!(!self.inner.outstanding.load(Ordering::Acquire));
        assert!(self.inner.native.set(NativePort { send: Ring::new(config.send), control: Ring::new(config.control), events: Ring::new(config.receive), counters: Counters::default(), send_full: AtomicBool::new(false), control_full: AtomicBool::new(false) }).is_ok());
        self.inner.ready.enabled.store(true, Ordering::Release);
        self.inner.wake.notify(); LockfreeEndpoint::new(self)
    }
    pub fn close(&self) { self.inner.stop.store(true, Ordering::Release); self.inner.wake.notify(); self.inner.ready.notify(); }
    pub fn is_finished(&self) -> bool { self.inner.exited.load(Ordering::Acquire) }
    pub fn readiness(&self) -> Arc<Ready> { self.inner.ready.enabled.store(true, Ordering::Release); self.inner.wake.notify(); self.inner.ready.clone() }
}
impl Drop for Endpoint { fn drop(&mut self) { self.close(); } }
