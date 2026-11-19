//! Single-owner bounded, isolated send lanes. No library threads are spawned.
//!
//! `try_send` moves the Vec allocation only on success; false leaves it untouched. Each association and logical queue
//! has its own FIFO: a core-credit stall does not block another lane. Accepted sends have no completion event.
//! Unknown/disconnected peers, invalid queues and oversized sends are consumed, dropped and counted. Full receive
//! rings drop data, not lifecycle events. Disconnect is local cancellation, not a wire close; a remote peer may
//! reconnect. Byte limits and `queued_send_bytes` count payload lengths through the last planned send attempt,
//! excluding spare Vec capacity, FEC allocations and protocol overhead; they are not process-memory limits.
use super::{Endpoint, Port, Ready, ring::Ring};
use crate::stp::{ConnectionKey, Dscp, STPAddress};
use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
#[derive(Debug, Clone, Copy)]
pub struct RingConfig {
    pub send: usize,
    pub control: usize,
    pub receive: usize,
}
impl Default for RingConfig {
    fn default() -> Self {
        Self {
            send: 128,
            control: 32,
            receive: 128,
        }
    }
}
/// Limits for accepted application sends, including work already admitted to the protocol core.
/// Bytes are payload lengths, not allocation capacities or a process/RSS bound. An explicit cap below
/// `max_message_size` is valid: a larger payload always returns false, unchanged.
#[derive(Debug, Clone)]
pub struct SendQueueConfig {
    /// None derives max(4 MiB, max_message_size) per (association, logical queue).
    pub per_queue_bytes: Option<u64>,
    /// Optional overrides by logical queue index; omitted/None entries inherit the default.
    pub queue_bytes: Vec<Option<u64>>,
    /// None derives max(64 MiB, four times the largest effective per-queue limit).
    pub global_bytes: Option<u64>,
    /// Lazy lanes retained until their association closes, including lanes still owned by the core.
    /// Must be 1..=65536. Receive-only peers do not allocate lanes.
    pub max_active_queues: usize,
    /// Aggregate outstanding messages, including empty messages, lane rings and core work.
    /// Must be 1..=16777216.
    pub max_queued_messages: usize,
}
impl Default for SendQueueConfig {
    fn default() -> Self {
        Self {
            per_queue_bytes: None,
            queue_bytes: Vec::new(),
            global_bytes: None,
            max_active_queues: 1024,
            max_queued_messages: 65536,
        }
    }
}
#[derive(Debug)]
pub(crate) struct SendBudget {
    pub limits: Box<[u64]>,
    pub global_limit: u64,
    pub bytes: AtomicU64,
    pub messages: AtomicUsize,
    pub lanes: AtomicUsize,
    pub pending: AtomicUsize,
    pub epoch: AtomicU64,
    pub max_lanes: usize,
    pub max_messages: usize,
    pub ready: Arc<Ready>,
}
impl SendBudget {
    pub(crate) fn new(
        config: SendQueueConfig,
        maximum: usize,
        queues: usize,
        ready: Arc<Ready>,
    ) -> Arc<Self> {
        assert!(
            config.queue_bytes.len() <= queues,
            "too many send queue byte overrides"
        );
        assert!((1..=65536).contains(&config.max_active_queues));
        assert!((1..=16777216).contains(&config.max_queued_messages));
        let default = config
            .per_queue_bytes
            .unwrap_or((maximum as u64).max(4 * 1024 * 1024));
        let limits: Box<[_]> = (0..queues)
            .map(|q| {
                config
                    .queue_bytes
                    .get(q)
                    .copied()
                    .flatten()
                    .unwrap_or(default)
            })
            .collect();
        assert!(default != 0 && default <= u64::MAX / 4);
        assert!(limits.iter().all(|&n| n != 0 && n <= u64::MAX / 4));
        let global_limit = config
            .global_bytes
            .unwrap_or((64 * 1024 * 1024).max(4 * limits.iter().copied().max().unwrap()));
        assert!(global_limit != 0);
        Arc::new(Self {
            limits,
            global_limit,
            bytes: AtomicU64::new(0),
            messages: AtomicUsize::new(0),
            lanes: AtomicUsize::new(0),
            pending: AtomicUsize::new(0),
            epoch: AtomicU64::new(0),
            max_lanes: config.max_active_queues,
            max_messages: config.max_queued_messages,
            ready,
        })
    }
    pub(crate) fn released(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.ready.notify();
    }
}
#[derive(Debug)]
pub(crate) struct Account {
    pub bytes: AtomicU64,
    pub budget: Arc<SendBudget>,
}
impl Account {
    pub(crate) fn release(&self, bytes: u64, messages: usize) {
        self.bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.budget.bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.budget.messages.fetch_sub(messages, Ordering::Relaxed);
        self.budget.released();
    }
}
impl Drop for Account {
    fn drop(&mut self) {
        self.budget.lanes.fetch_sub(1, Ordering::Relaxed);
        self.budget.released();
    }
}
pub(crate) struct SendLane {
    pub ring: Ring<SendMessage>,
    pub account: Arc<Account>,
}
pub(crate) struct PeerSend {
    // Bit 0: producer in critical section; bit 1: permanently closed. Close never waits.
    state: AtomicUsize,
    pub queues: Box<[OnceLock<SendLane>]>,
    pub budget: Arc<SendBudget>,
    pub slots: usize,
}
impl PeerSend {
    pub(crate) fn new(budget: Arc<SendBudget>, slots: usize) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicUsize::new(0),
            queues: (0..budget.limits.len()).map(|_| OnceLock::new()).collect(),
            budget,
            slots,
        })
    }
    fn enter(&self) -> bool {
        self.state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn leave(&self) {
        if self
            .state
            .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // close observed an active producer and handed exclusive consumption to us.
            // The pump will never access this association's rings again. Keep bit 0 set
            // until draining completes, then publish the permanently closed state.
            self.drain();
            self.state.store(2, Ordering::SeqCst);
        }
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & 2 != 0
    }
    fn drain(&self) {
        for lane in self.queues.iter().filter_map(OnceLock::get) {
            while let Some(message) = unsafe { lane.ring.pop() } {
                self.budget.pending.fetch_sub(1, Ordering::Relaxed);
                drop(message);
            }
        }
        self.budget.released();
    }
    /// Only the pump calls close. It never waits for the producer: an in-progress
    /// producer inherits exclusive drain ownership on leaving its critical section.
    /// The pump must remove this association from its admission scan before consuming again.
    pub(crate) fn close(&self) {
        if self.state.fetch_or(2, Ordering::SeqCst) == 0 {
            self.drain();
        }
    }
}

pub(crate) struct NativeEvent {
    pub event: Event,
    pub association: Option<Arc<PeerSend>>,
}
impl From<Event> for NativeEvent {
    fn from(event: Event) -> Self {
        Self {
            event,
            association: None,
        }
    }
}
pub(crate) struct SendMessage {
    pub class: Dscp,
    pub payload: Vec<u8>,
    pub charge: Charge,
}
pub(crate) struct Charge {
    cell: Option<Arc<Account>>,
    bytes: u64,
}
impl Charge {
    pub(crate) fn transfer(mut self) -> (Arc<Account>, u64) {
        (self.cell.take().unwrap(), self.bytes)
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(cell) = &self.cell {
            cell.release(self.bytes, 1);
        }
    }
}
pub enum Control {
    Connect(STPAddress),
    Disconnect(ConnectionKey),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    Local,
    TimedOut,
    /// A confirmed fresh handshake replaced this association at the same endpoint.
    Replaced,
    /// A local source-address observation changed; a fresh association is being attempted.
    NetworkChanged,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    TimedOut,
    InvalidAddress,
}
pub enum Event {
    Connected {
        peer: ConnectionKey,
        address: STPAddress,
        handshake_hash: [u8; 64],
    },
    ConnectFailed {
        address: STPAddress,
        reason: ConnectFailure,
    },
    Disconnected {
        peer: ConnectionKey,
        reason: DisconnectReason,
    },
    Message {
        peer: ConnectionKey,
        data: Vec<u8>,
    },
}
#[derive(Default)]
pub(crate) struct Counters {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub send_dropped_unknown: AtomicU64,
    pub send_dropped_oversized: AtomicU64,
    pub send_dropped_invalid_queue: AtomicU64,
    pub receive_dropped_full: AtomicU64,
    pub inbound_refused_full: AtomicU64,
    pub send_head_blocked: AtomicU64,
}
#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub send_dropped_unknown: u64,
    pub send_dropped_oversized: u64,
    pub send_dropped_invalid_queue: u64,
    pub receive_dropped_full: u64,
    pub inbound_refused_full: u64,
    pub send_head_blocked: u64,
}
pub struct LockfreeEndpoint {
    owner: Endpoint,
    _single_owner: PhantomData<Cell<()>>,
    peers: HashMap<ConnectionKey, Arc<PeerSend>>,
    blocked_epoch: Option<u64>,
}
#[inline]
fn admit<T>(inner: &Port, ring: &Ring<T>, full: &AtomicBool, make: impl FnOnce() -> T) -> bool {
    if inner.stop.load(Ordering::Acquire) || inner.exited.load(Ordering::Acquire) {
        return false;
    }
    if !ring.has_space() {
        full.store(true, Ordering::SeqCst);
        if !ring.has_space() {
            return false;
        }
        full.store(false, Ordering::SeqCst);
    }
    full.store(false, Ordering::SeqCst);
    assert!(unsafe { ring.push(make()) }.is_ok());
    inner.wake.notify();
    true
}
impl LockfreeEndpoint {
    pub(crate) fn new(owner: Endpoint) -> Self {
        Self {
            owner,
            _single_owner: PhantomData,
            peers: HashMap::new(),
            blocked_epoch: None,
        }
    }
    /// Move a payload into its association/queue FIFO. False preserves its allocation and contents.
    /// Backpressure may be lane slots, lane bytes, aggregate bytes/messages, or active-lane capacity.
    /// Unknown peers (including before consuming Connected), invalid queues and oversized payloads
    /// are consumed and synchronously counted as drops, not buffered for a future association.
    pub fn try_send(
        &mut self,
        peer: ConnectionKey,
        queue: usize,
        class: Dscp,
        payload: &mut Vec<u8>,
    ) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        self.blocked_epoch = Some(n.budget.epoch.load(Ordering::SeqCst));
        if inner.stop.load(Ordering::Acquire) || inner.exited.load(Ordering::Acquire) {
            return false;
        }
        let drop_counter = if payload.len() > inner.max_payload {
            Some(&n.counters.send_dropped_oversized)
        } else if queue >= inner.send_queues {
            Some(&n.counters.send_dropped_invalid_queue)
        } else if self.peers.get(&peer).is_none_or(|p| p.is_closed()) {
            Some(&n.counters.send_dropped_unknown)
        } else {
            None
        };
        if let Some(counter) = drop_counter {
            counter.fetch_add(1, Ordering::Relaxed);
            drop(std::mem::take(payload));
            self.blocked_epoch = None;
            return true;
        }
        let association = self.peers.get(&peer).unwrap();
        if !association.enter() {
            n.counters
                .send_dropped_unknown
                .fetch_add(1, Ordering::Relaxed);
            drop(std::mem::take(payload));
            self.blocked_epoch = None;
            return true;
        }
        struct Producer<'a>(&'a PeerSend);
        impl Drop for Producer<'_> {
            fn drop(&mut self) {
                self.0.leave();
            }
        }
        let _producer = Producer(association);
        let bytes = payload.len() as u64;
        let budget = &n.budget;
        // The endpoint is the only producer of reservations; the pump only releases them.
        if bytes > budget.limits[queue]
            || bytes
                > budget
                    .global_limit
                    .saturating_sub(budget.bytes.load(Ordering::Acquire))
            || budget.messages.load(Ordering::Acquire) >= budget.max_messages
        {
            return false;
        }
        if association.queues[queue].get().is_none() {
            if budget.lanes.load(Ordering::Acquire) >= budget.max_lanes {
                return false;
            }
            budget.lanes.fetch_add(1, Ordering::Relaxed);
            assert!(
                association.queues[queue]
                    .set(SendLane {
                        ring: Ring::new(association.slots),
                        account: Arc::new(Account {
                            bytes: AtomicU64::new(0),
                            budget: budget.clone()
                        }),
                    })
                    .is_ok()
            );
        }
        let lane = association.queues[queue].get().unwrap();
        if !lane.ring.has_space()
            || bytes
                > budget.limits[queue].saturating_sub(lane.account.bytes.load(Ordering::Acquire))
        {
            return false;
        }
        lane.account.bytes.fetch_add(bytes, Ordering::Relaxed);
        budget.bytes.fetch_add(bytes, Ordering::Relaxed);
        budget.messages.fetch_add(1, Ordering::Relaxed);
        budget.pending.fetch_add(1, Ordering::Release);
        assert!(
            unsafe {
                lane.ring.push(SendMessage {
                    class,
                    payload: std::mem::take(payload),
                    charge: Charge {
                        cell: Some(lane.account.clone()),
                        bytes,
                    },
                })
            }
            .is_ok()
        );
        self.blocked_epoch = None;
        inner.wake.notify();
        true
    }
    pub fn queued_send_bytes(&self, peer: ConnectionKey, queue: usize) -> u64 {
        if self.owner.inner.stop.load(Ordering::Acquire) || self.is_finished() {
            return 0;
        }
        self.peers
            .get(&peer)
            .filter(|p| !p.is_closed())
            .and_then(|p| p.queues.get(queue))
            .and_then(OnceLock::get)
            .map_or(0, |lane| lane.account.bytes.load(Ordering::Relaxed))
    }
    pub fn try_control(&mut self, control: Control) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        admit(inner, &n.control, &n.control_full, || control)
    }
    pub fn try_connect(&mut self, address: STPAddress) -> bool {
        self.try_control(Control::Connect(address))
    }
    pub fn try_disconnect(&mut self, peer: ConnectionKey) -> bool {
        self.try_control(Control::Disconnect(peer))
    }
    pub fn try_recv(&mut self) -> Option<Event> {
        let n = self.owner.inner.native.get().unwrap();
        let envelope = unsafe { n.events.pop() }?;
        self.owner.inner.wake.notify();
        match &envelope.event {
            Event::Connected { peer, .. } => {
                self.peers
                    .insert(*peer, envelope.association.expect("Connected association"));
            }
            Event::Disconnected { peer, .. } => {
                if self.peers.get(peer).is_some_and(|current| {
                    envelope
                        .association
                        .as_ref()
                        .is_some_and(|old| Arc::ptr_eq(old, current))
                }) {
                    self.peers.remove(peer);
                }
            }
            _ => {}
        }
        Some(envelope.event)
    }
    pub fn stats(&self) -> Stats {
        let c = &self.owner.inner.native.get().unwrap().counters;
        Stats {
            sent: c.sent.load(Ordering::Relaxed),
            received: c.received.load(Ordering::Relaxed),
            send_dropped_unknown: c.send_dropped_unknown.load(Ordering::Relaxed),
            send_dropped_oversized: c.send_dropped_oversized.load(Ordering::Relaxed),
            send_dropped_invalid_queue: c.send_dropped_invalid_queue.load(Ordering::Relaxed),
            receive_dropped_full: c.receive_dropped_full.load(Ordering::Relaxed),
            inbound_refused_full: c.inbound_refused_full.load(Ordering::Relaxed),
            send_head_blocked: c.send_head_blocked.load(Ordering::Relaxed),
        }
    }
    pub fn park_until_ready(&mut self) -> bool {
        let ready = &self.owner.inner.ready;
        let mut observed = ready.generation.load(Ordering::SeqCst) as u64;
        let n = self.owner.inner.native.get().unwrap();
        if n.events.has_value()
            || !n.stats_result.load(Ordering::Acquire).is_null()
            || self
                .blocked_epoch
                .is_some_and(|epoch| epoch != n.budget.epoch.load(Ordering::SeqCst))
            || (n.control_full.load(Ordering::SeqCst) && n.control.has_space())
        {
            return true;
        }
        if self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire) {
            return false;
        }
        ready.wait(&mut observed);
        n.events.has_value()
            || !(self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire))
    }
    pub fn request_protocol_stats(&self) {
        self.owner
            .inner
            .native
            .get()
            .unwrap()
            .stats_requested
            .store(true, Ordering::Release);
        self.owner.inner.wake.notify();
    }
    pub fn try_protocol_stats(&self) -> Option<crate::stp::NetworkThreadPull> {
        let ptr = self
            .owner
            .inner
            .native
            .get()
            .unwrap()
            .stats_result
            .swap(std::ptr::null_mut(), Ordering::AcqRel);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { *Box::from_raw(ptr) })
        }
    }
    pub fn readiness(&self) -> Arc<Ready> {
        self.owner.readiness()
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub fn is_finished(&self) -> bool {
        self.owner.is_finished()
    }
}

#[cfg(test)]
#[path = "send_lane_lifecycle_tests.rs"]
mod lifecycle_tests;
