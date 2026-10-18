//! Bounded ownership queues between the application and its caller-owned pump.
//!
//! [`Endpoint`] preserves the one-outstanding-batch reference API. Convert it
//! with [`Endpoint::into_lockfree`] for the fine-grained SPSC API. No port hook
//! explicitly acquires a mutex on the pump. Allocation/deallocation may use the
//! global allocator's locks; the frozen protocol/FEC internals and explicit Stats
//! snapshot still use their existing locks. The reference facade serializes only
//! its application-side callers.
use crate::native_sockets::NetworkWake;
use crate::stp::{NetworkThreadPull, NetworkThreadPush};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
#[path = "lockfree.rs"]
pub mod lockfree;
#[path = "ring.rs"]
mod ring;
use lockfree::{Command, Event, LockfreeEndpoint};
use ring::Ring;

/// Atomic generation notifier. The pump only increments an atomic and, when
/// somebody is parked, performs FUTEX_WAKE. No mutex or user code is involved.
#[derive(Debug)]
pub struct Ready {
    generation: AtomicU32,
    waiters: AtomicU32,
    pub(crate) enabled: AtomicBool,
    pub(crate) send_space: AtomicBool,
}
impl Default for Ready {
    fn default() -> Self {
        Self {
            generation: AtomicU32::new(1),
            waiters: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            send_space: AtomicBool::new(false),
        }
    }
}
impl Ready {
    pub(crate) fn notify(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if self.waiters.load(Ordering::SeqCst) != 0 {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.generation.as_ptr(),
                    libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                    i32::MAX,
                );
            }
        }
    }
    /// Wait for a durable publication edge; initialize `observed` to zero.
    /// Multiple application waiters are supported. Like all finite-generation
    /// notifiers, a waiter must not miss an entire 2^32-edge wrap.
    pub fn wait(&self, observed: &mut u64) {
        let wanted = *observed as u32;
        self.waiters.fetch_add(1, Ordering::SeqCst);
        loop {
            let current = self.generation.load(Ordering::SeqCst);
            if current != wanted {
                *observed = current as u64;
                break;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.generation.as_ptr(),
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    wanted,
                    std::ptr::null::<libc::timespec>(),
                );
            }
            #[cfg(not(target_os = "linux"))]
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(super) struct NativePort {
    commands: Ring<Command>,
    events: Ring<Event>,
    dirty: AtomicBool,
    /// Pump-owned count of exchanges since the last forced protocol pass.
    exchanges: AtomicU8,
    active: AtomicU8,
    max_payload: usize,
}
pub(crate) struct Port {
    requests: Ring<NetworkThreadPush>,
    responses: Ring<NetworkThreadPull>,
    outstanding: AtomicBool,
    /// Only application callers acquire these locks, never Pump.
    app: Mutex<()>,
    pub(crate) exchange: Mutex<()>,
    pub(crate) stop: AtomicBool,
    pub(crate) exited: AtomicBool,
    pub(crate) wake: Arc<NetworkWake>,
    pub(crate) ready: Arc<Ready>,
    native: OnceLock<NativePort>,
    max_payload: usize,
}
impl Port {
    pub(crate) fn new(max_payload: usize) -> Arc<Self> {
        Arc::new(Self {
            requests: Ring::new(1),
            responses: Ring::new(1),
            outstanding: AtomicBool::new(false),
            app: Mutex::new(()),
            exchange: Mutex::new(()),
            stop: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            wake: Arc::new(NetworkWake::new().expect("create pump command wakeup")),
            ready: Arc::new(Ready::default()),
            native: OnceLock::new(),
            max_payload,
        })
    }
    pub(crate) fn is_reference(&self) -> bool {
        self.native.get().is_none()
    }
    pub(crate) fn wants_snapshot(&self) -> bool {
        self.native
            .get()
            .is_none_or(|n| n.active.load(Ordering::Relaxed) != 1)
    }
    pub(crate) fn wants_stats(&self) -> bool {
        self.native
            .get()
            .is_none_or(|n| n.active.load(Ordering::Relaxed) == 3)
    }
    /// A rejection arms one edge, consumed only after queued bytes fall.
    pub(crate) fn send_space_ready(&self, used: usize, previous: usize) -> bool {
        used < previous && self.ready.send_space.swap(false, Ordering::AcqRel)
    }
    pub(crate) fn transport_ready(&self) {
        if let Some(n) = self.native.get() {
            n.dirty.store(true, Ordering::Release);
            // Pair with the application's post-pop fence: publishing dirty and
            // testing event space must not both miss the concurrent pop/check.
            std::sync::atomic::fence(Ordering::SeqCst);
        }
        self.ready.notify();
    }
    pub(crate) fn take_request(
        &self,
    ) -> Option<(NetworkThreadPush, Option<crate::stp::ConnectionKey>)> {
        let Some(n) = self.native.get() else {
            return unsafe { self.requests.pop() }.map(|r| (r, None));
        };
        // Admit a bounded burst so queued tiny sends can share the next protocol
        // pass. Forcing a pass after every Send defeats transport aggregation.
        // The pump still checks its deadline before every command exchange.
        if n.exchanges.load(Ordering::Relaxed) == 32 {
            n.exchanges.store(0, Ordering::Relaxed);
            return None;
        }
        // Only Pump produces events. Reserving room by observing it is enough:
        // the concurrent application can only make more room, never less.
        if !n.events.has_space() {
            return None;
        }
        // Alternate ready receive updates with commands under sustained load;
        // neither a full-duplex receive stream nor producers may starve the other.
        if (n.active.load(Ordering::Relaxed) != 2 || !n.commands.has_value())
            && n.dirty.swap(false, Ordering::AcqRel)
        {
            n.active.store(2, Ordering::Relaxed);
            return Some((NetworkThreadPush::default(), None));
        }
        let command = unsafe { n.commands.pop() };
        if command.is_some() {
            self.ready.notify();
        } // command-space edge
        let mut req = NetworkThreadPush::default();
        match command {
            Some(Command::Send {
                peer,
                queue,
                class,
                payload,
            }) => {
                n.active.store(1, Ordering::Relaxed);
                req.send_unreliable.push((peer, queue, class, payload));
            }
            Some(Command::Connect(address)) => {
                n.active.store(2, Ordering::Relaxed);
                req.initiate_connections.push(address);
            }
            Some(Command::Disconnect(peer)) => {
                n.active.store(2, Ordering::Relaxed);
                return Some((req, Some(peer)));
            }
            Some(Command::Stats) => {
                n.active.store(3, Ordering::Relaxed);
            }
            Some(Command::Refresh) => {
                n.active.store(2, Ordering::Relaxed);
            }
            None => return None,
        }
        Some((req, None))
    }
    pub(crate) fn has_request(&self) -> bool {
        match self.native.get() {
            Some(n) => {
                n.events.has_space() && (n.commands.has_value() || n.dirty.load(Ordering::Acquire))
            }
            None => self.requests.has_value(),
        }
    }
    pub(crate) fn publish(&self, response: NetworkThreadPull) {
        if let Some(n) = self.native.get() {
            if !response.send_unreliable_rejected.is_empty() {
                self.ready.send_space.store(true, Ordering::Release);
            }
            let event = if n.active.load(Ordering::Relaxed) == 1 {
                debug_assert!(
                    response.send_unreliable_rejected.len()
                        + response.send_unreliable_oversized.len()
                        + response.send_unreliable_invalid_queue.len()
                        <= 1
                );
                Event::Submitted {
                    rejected: response.send_unreliable_rejected.into_iter().next(),
                    oversized: response.send_unreliable_oversized.into_iter().next(),
                    invalid_queue: response.send_unreliable_invalid_queue.into_iter().next(),
                }
            } else {
                n.dirty.store(false, Ordering::Relaxed);
                Event::Update(response)
            };
            assert!(
                unsafe { n.events.push(event) }.is_ok(),
                "reserved event slot"
            );
            n.exchanges.fetch_add(1, Ordering::Relaxed);
        } else {
            assert!(
                unsafe { self.responses.push(response) }.is_ok(),
                "reference response slot"
            );
        }
        self.ready.notify();
    }
}
/// Thread-safe reference handle. One batch/result may be outstanding. Submission
/// and taking results serialize on the application side only; Pump never locks.
/// Drop/close cancel rather than flush. Unprocessed payloads are eventually
/// dropped with the pump/endpoint; submission after cancellation returns ownership.
pub struct Endpoint {
    pub(crate) inner: Arc<Port>,
}
impl Endpoint {
    pub fn submit(&self, request: NetworkThreadPush) -> Result<(), NetworkThreadPush> {
        let _app = self.inner.app.lock().unwrap();
        if self.inner.outstanding.load(Ordering::Acquire)
            || self.is_finished()
            || self.inner.stop.load(Ordering::Acquire)
        {
            return Err(request);
        }
        self.inner.outstanding.store(true, Ordering::Release);
        assert!(unsafe { self.inner.requests.push(request) }.is_ok());
        self.inner.wake.notify();
        Ok(())
    }
    pub fn try_take(&self) -> Option<NetworkThreadPull> {
        let _app = self.inner.app.lock().unwrap();
        let response = unsafe { self.inner.responses.pop() }?;
        self.inner.outstanding.store(false, Ordering::Release);
        Some(response)
    }
    /// Convert an unused reference endpoint into a bounded single-owner API.
    /// Panics unless capacity is a power of two in 1..=65_536, or if a reference
    /// exchange is outstanding.
    /// Each ring holds `capacity` items; each Send payload is at most the local
    /// configured maximum. The protocol's separate receive/send budgets remain.
    pub fn into_lockfree(self, capacity: usize) -> LockfreeEndpoint {
        assert!(
            !self.inner.outstanding.load(Ordering::Acquire),
            "drain reference exchange before conversion"
        );
        assert!(
            self.inner
                .native
                .set(NativePort {
                    commands: Ring::new(capacity),
                    events: Ring::new(capacity),
                    dirty: AtomicBool::new(true),
                    exchanges: AtomicU8::new(0),
                    active: AtomicU8::new(0),
                    max_payload: self.inner.max_payload
                })
                .is_ok()
        );
        self.inner.ready.enabled.store(true, Ordering::Release);
        self.inner.wake.notify();
        LockfreeEndpoint::new(self)
    }
    pub fn close(&self) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake.notify();
        self.inner.ready.notify();
    }
    pub fn is_finished(&self) -> bool {
        self.inner.exited.load(Ordering::Acquire)
    }
    pub fn readiness(&self) -> Arc<Ready> {
        self.inner.ready.enabled.store(true, Ordering::Release);
        self.inner.wake.notify();
        self.inner.ready.clone()
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stp::{ConnectionKey, Dscp};
    #[test]
    fn rejected_sender_park_wakes_on_drain_without_other_traffic() {
        use std::sync::mpsc;
        use std::time::Duration;
        let port = Port::new(100);
        let mut endpoint = Endpoint {
            inner: port.clone(),
        }
        .into_lockfree(2);
        // Consume the automatic snapshot, then submit one rejected Send.
        assert!(port.take_request().is_some());
        port.publish(NetworkThreadPull::default());
        assert!(endpoint.try_recv().is_some());
        assert!(port.take_request().is_none());
        assert!(
            endpoint
                .try_send(Command::Send {
                    peer: ConnectionKey::default(),
                    queue: 0,
                    class: Dscp::BestEffort,
                    payload: vec![7; 100],
                })
                .is_ok()
        );
        let (request, _) = port.take_request().unwrap();
        let mut response = NetworkThreadPull::default();
        response.send_unreliable_rejected = request.send_unreliable;
        port.publish(response);
        assert!(matches!(
            endpoint.try_recv(),
            Some(Event::Submitted {
                rejected: Some(_),
                ..
            })
        ));
        assert!(endpoint.try_recv().is_none());
        assert!(!port.send_space_ready(100, 100)); // no drain yet; stays armed
        let (enter_tx, enter_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            enter_tx.send(()).unwrap();
            let ready = endpoint.park_until_ready();
            done_tx.send(ready).unwrap();
        });
        enter_rx.recv().unwrap();
        // Observe actual waiter registration, not just thread startup: a delayed
        // thread must not snapshot the generation after our simulated drain.
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while port.ready.waiters.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < until, "waiter did not park");
            std::thread::yield_now();
        }
        // No stale-generation first return and no unrelated command/event edge.
        let early = done_rx.recv_timeout(Duration::from_millis(30));
        assert!(port.send_space_ready(99, 100));
        assert!(!port.send_space_ready(98, 99)); // one-shot, not every drain
        port.transport_ready();
        let woke = if let Ok(value) = early {
            Ok(value)
        } else {
            done_rx.recv_timeout(Duration::from_secs(2))
        };
        if woke.is_err() {
            port.stop.store(true, Ordering::Release);
            port.ready.notify();
        }
        waiter.join().unwrap();
        assert!(early.is_err(), "park returned before the drain edge");
        assert_eq!(woke.unwrap(), true);
    }
    #[test]
    fn command_bursts_coalesce_but_force_a_protocol_pass_within_32_exchanges() {
        let port = Port::new(100);
        let mut endpoint = Endpoint {
            inner: port.clone(),
        }
        .into_lockfree(64);
        // Drain initial connection snapshot before measuring the send burst.
        assert!(port.take_request().is_some());
        port.publish(NetworkThreadPull::default());
        endpoint.try_recv();
        assert!(port.take_request().is_none());
        for sequence in 0..64u8 {
            assert!(
                endpoint
                    .try_send(Command::Send {
                        peer: ConnectionKey::default(),
                        queue: 0,
                        class: Dscp::BestEffort,
                        payload: vec![sequence],
                    })
                    .is_ok()
            );
        }
        let mut admitted = 0usize;
        let mut rounds = 0;
        let mut burst = 0;
        while admitted < 64 {
            if let Some((request, _)) = port.take_request() {
                assert_eq!(request.send_unreliable[0].3, vec![admitted as u8]);
                admitted += 1;
                burst += 1;
                assert!(burst <= 32, "command stream starved protocol work");
                port.publish(NetworkThreadPull::default());
                assert!(matches!(endpoint.try_recv(), Some(Event::Submitted { .. })));
            } else {
                assert!(
                    burst >= 31,
                    "single-command protocol passes prevent aggregation"
                );
                rounds += 1;
                burst = 0;
                // Even a pending receive must not delay the protocol round. Once
                // yielded, its update takes precedence over the next send burst.
                port.transport_ready();
                assert!(port.take_request().unwrap().0.send_unreliable.is_empty());
                port.publish(NetworkThreadPull::default());
                assert!(matches!(endpoint.try_recv(), Some(Event::Update(_))));
            }
        }
        assert_eq!(rounds, 2);
    }
    #[test]
    fn pending_receive_and_commands_alternate_without_starvation() {
        let port = Port::new(100);
        let mut endpoint = Endpoint {
            inner: port.clone(),
        }
        .into_lockfree(8);
        for _ in 0..8 {
            assert!(
                endpoint
                    .try_send(Command::Send {
                        peer: ConnectionKey::default(),
                        queue: 0,
                        class: Dscp::BestEffort,
                        payload: vec![0; 1]
                    })
                    .is_ok()
            );
        }
        // Initial automatic snapshot then eight alternating sends/updates, with
        // continuously pending application input and transport receive readiness.
        assert!(port.take_request().unwrap().0.send_unreliable.is_empty());
        port.publish(NetworkThreadPull::default());
        endpoint.try_recv();
        for _ in 0..8 {
            port.transport_ready();
            assert_eq!(port.take_request().unwrap().0.send_unreliable.len(), 1);
            port.publish(NetworkThreadPull::default());
            endpoint.try_recv();
            port.transport_ready();
            assert!(port.take_request().unwrap().0.send_unreliable.is_empty());
            port.publish(NetworkThreadPull::default());
            endpoint.try_recv();
        }
    }
}
