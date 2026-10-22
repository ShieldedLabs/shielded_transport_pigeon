//! Single-owner three-ring application boundary. No library threads are spawned.
//!
//! `try_send` moves the Vec allocation only on success; false leaves it untouched.
//! Accepted sends have no completion/admission event. A full core send queue holds
//! the FIFO head in the send ring (including head-of-line blocking other peers).
//! Unknown/disconnected peers, invalid queues and oversized sends are dropped and
//! counted. Full receive rings drop data, not lifecycle events. Disconnect is local
//! cancellation, not a wire close; a remote peer may reconnect.
//! `queued_send_bytes` reads a per-(peer, queue) payload backlog kept by atomic
//! counters: the pump updates them without locks and the application never waits.
use super::{Endpoint, Port, Ready, ring::Ring};
use crate::stp::{ConnectionKey, Dscp, STPAddress};
use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};

/// Each capacity must be a power of two in 1..=65_536.
#[derive(Debug, Clone, Copy)]
pub struct RingConfig { pub send: usize, pub control: usize, pub receive: usize }
impl Default for RingConfig { fn default() -> Self { Self { send: 128, control: 32, receive: 128 } } }
pub(crate) struct SendMessage { pub peer: ConnectionKey, pub queue: usize, pub class: Dscp, pub payload: Vec<u8>, pub charge: Option<Charge> }
/// Payload bytes counted for one (peer, queue). Dropping the charge (a pump drop,
/// or ring teardown) uncounts them; `transfer` hands them to a core queue ledger
/// without touching the counter, so admission never shows a gap or a double count.
pub(crate) struct Charge { cell: Option<Arc<AtomicU64>>, bytes: u64 }
impl Charge {
    pub(crate) fn transfer(mut self) -> (Arc<AtomicU64>, u64) { (self.cell.take().unwrap(), self.bytes) }
}
impl Drop for Charge {
    fn drop(&mut self) { if let Some(cell) = &self.cell { cell.fetch_sub(self.bytes, Ordering::Relaxed); } }
}
pub enum Control { Connect(STPAddress), Disconnect(ConnectionKey) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason { Local, TimedOut }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure { TimedOut, AlreadyConnected, InvalidAddress, Cancelled }
pub enum Event {
    Connected { peer: ConnectionKey, address: STPAddress, handshake_hash: [u8; 64] },
    ConnectFailed { address: STPAddress, reason: ConnectFailure },
    Disconnected { peer: ConnectionKey, reason: DisconnectReason },
    Message { peer: ConnectionKey, data: Vec<u8> },
}
#[derive(Default)]
pub(crate) struct Counters {
    pub sent: AtomicU64, pub received: AtomicU64, pub send_dropped_unknown: AtomicU64,
    pub send_dropped_oversized: AtomicU64, pub send_dropped_invalid_queue: AtomicU64,
    pub receive_dropped_full: AtomicU64, pub inbound_refused_full: AtomicU64,
    pub send_head_blocked: AtomicU64,
}
#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub sent: u64, pub received: u64, pub send_dropped_unknown: u64,
    pub send_dropped_oversized: u64, pub send_dropped_invalid_queue: u64,
    pub receive_dropped_full: u64, pub inbound_refused_full: u64,
    /// Pump admission attempts stopped by the FIFO head (not distinct messages).
    pub send_head_blocked: u64,
}
// Smallest table size that triggers a sweep of idle queued-bytes counters.
const QUEUED_PRUNE_MIN: usize = 64;
pub struct LockfreeEndpoint {
    owner: Endpoint, _single_owner: PhantomData<Cell<()>>,
    // Application-thread-only counter table; the pump reaches a counter through
    // a message's Charge or its core queue ledger, never through this map.
    queued: HashMap<(ConnectionKey, usize), Arc<AtomicU64>>, queued_prune_at: usize,
}
// Only the endpoint's unique producer calls this for its send/control rings.
#[inline]
fn admit<T>(inner: &Port, ring: &Ring<T>, full: &AtomicBool, make: impl FnOnce() -> T) -> bool {
        if inner.stop.load(Ordering::Acquire) || inner.exited.load(Ordering::Acquire) { return false; }
        if !ring.has_space() {
            full.store(true, Ordering::SeqCst);
            // Pair with consumer's post-pop fence: do not miss a concurrent drain.
            if !ring.has_space() { return false; }
            full.store(false, Ordering::SeqCst);
        }
        full.store(false, Ordering::SeqCst);
        assert!(unsafe { ring.push(make()) }.is_ok());
        inner.wake.notify();
        true
}
// A counter may be removed only when no message or core ledger holds it (then it
// is zero): a later send recreates it, so identity never splits a live backlog.
fn queued_idle(cell: &Arc<AtomicU64>) -> bool { Arc::strong_count(cell) == 1 && cell.load(Ordering::Relaxed) == 0 }
impl LockfreeEndpoint {
    pub(crate) fn new(owner: Endpoint) -> Self {
        Self { owner, _single_owner: PhantomData, queued: HashMap::new(), queued_prune_at: QUEUED_PRUNE_MIN }
    }
    /// Ownership transfer without copying the payload; false also means closed,
    /// and preserves payload. On success a nonempty payload for a valid queue and
    /// size is counted by `queued_send_bytes` before the pump can see it. That
    /// bookkeeping is amortized O(1): the first send to a new (peer, queue) pair
    /// allocates its counter and may sweep idle counters, O(table size), when the
    /// table has doubled since the last sweep.
    pub fn try_send(&mut self, peer: ConnectionKey, queue: usize, class: Dscp, payload: &mut Vec<u8>) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        let (queued, prune_at) = (&mut self.queued, &mut self.queued_prune_at);
        admit(inner, &n.send, &n.send_full, || {
            let bytes = payload.len();
            let charge = (bytes != 0 && bytes <= inner.max_payload && queue < inner.send_queues).then(|| {
                let cell = match queued.get(&(peer, queue)) {
                    Some(cell) => cell.clone(),
                    None => {
                        // Amortized O(1): sweep only when the table doubles past its survivors.
                        if queued.len() >= *prune_at {
                            queued.retain(|_, cell| !queued_idle(cell));
                            *prune_at = (queued.len() * 2).max(QUEUED_PRUNE_MIN);
                        }
                        queued.entry((peer, queue)).or_default().clone()
                    }
                };
                // Counted before the ring publishes the message to the pump.
                cell.fetch_add(bytes as u64, Ordering::Relaxed);
                Charge { cell: Some(cell), bytes: bytes as u64 }
            });
            SendMessage { peer, queue, class, payload: std::mem::take(payload), charge }
        })
    }
    /// Payload bytes of valid submissions accepted by `try_send` for this peer and
    /// queue that are still waiting in the send ring or the protocol send queue.
    /// Empty, oversized (above `max_message_size`) and `queue >= send_queue_count`
    /// payloads are never counted. Bytes leave the count when the pump drops the
    /// message (unknown or disconnected peer), when the association holding them is
    /// disconnected, times out or is replaced, or when a whole message (for a
    /// segmented giant message, each coded extent) has been framed and the UDP
    /// socket has accepted the DATA datagram carrying its last bytes. Retained FEC
    /// repair and retransmission after that point are not counted, nor are
    /// headers, and nothing here implies delivery. Returns 0 for a pair with
    /// nothing queued and after `close()` or exit. One hash lookup and an atomic
    /// load: no lock, no allocation.
    pub fn queued_send_bytes(&self, peer: ConnectionKey, queue: usize) -> u64 {
        if self.owner.inner.stop.load(Ordering::Acquire) || self.is_finished() { return 0; }
        self.queued.get(&(peer, queue)).map_or(0, |cell| cell.load(Ordering::Relaxed))
    }
    pub fn try_control(&mut self, control: Control) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        admit(inner, &n.control, &n.control_full, || control)
    }
    pub fn try_connect(&mut self, address: STPAddress) -> bool { self.try_control(Control::Connect(address)) }
    pub fn try_disconnect(&mut self, peer: ConnectionKey) -> bool { self.try_control(Control::Disconnect(peer)) }
    pub fn try_recv(&mut self) -> Option<Event> {
        let n = self.owner.inner.native.get().unwrap();
        let event = unsafe { n.events.pop() }?;
        // Lifecycle transitions may be waiting for space, even without network traffic.
        self.owner.inner.wake.notify();
        if let Event::Disconnected { peer, .. } = &event {
            for queue in 0..self.owner.inner.send_queues {
                if self.queued.get(&(*peer, queue)).is_some_and(queued_idle) { self.queued.remove(&(*peer, queue)); }
            }
        }
        Some(event)
    }
    /// Independent, relaxed cumulative counters, not an atomic multi-counter snapshot.
    pub fn stats(&self) -> Stats {
        let c = &self.owner.inner.native.get().unwrap().counters;
        Stats { sent: c.sent.load(Ordering::Relaxed), received: c.received.load(Ordering::Relaxed),
            send_dropped_unknown: c.send_dropped_unknown.load(Ordering::Relaxed),
            send_dropped_oversized: c.send_dropped_oversized.load(Ordering::Relaxed),
            send_dropped_invalid_queue: c.send_dropped_invalid_queue.load(Ordering::Relaxed),
            receive_dropped_full: c.receive_dropped_full.load(Ordering::Relaxed),
            inbound_refused_full: c.inbound_refused_full.load(Ordering::Relaxed),
            send_head_blocked: c.send_head_blocked.load(Ordering::Relaxed) }
    }
    /// Wake on output, previously-full input space, or close. Always retry after
    /// return (spurious wakes allowed). False means closed and output drained.
    pub fn park_until_ready(&mut self) -> bool {
        let ready = &self.owner.inner.ready;
        let mut observed = ready.generation.load(Ordering::SeqCst) as u64;
        let n = self.owner.inner.native.get().unwrap();
        if n.events.has_value() || !n.stats_result.load(Ordering::Acquire).is_null() || (n.send_full.load(Ordering::SeqCst) && n.send.has_space())
            || (n.control_full.load(Ordering::SeqCst) && n.control.has_space()) { return true; }
        if self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire) { return false; }
        ready.wait(&mut observed);
        n.events.has_value() || !(self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire))
    }
    /// Explicit expensive frozen-core telemetry. Coalesces repeated requests;
    /// the pump never waits for the application. Unlike stats(), collecting this
    /// snapshot allocates and takes the protocol's existing budget_sink mutex.
    pub fn request_protocol_stats(&self) {
        self.owner.inner.native.get().unwrap().stats_requested.store(true, Ordering::Release);
        self.owner.inner.wake.notify();
    }
    /// Ownership transfer of a requested telemetry snapshot. No application messages
    /// or lifecycle state are carried here: those are exclusively receive-ring events.
    pub fn try_protocol_stats(&self) -> Option<crate::stp::NetworkThreadPull> {
        let ptr = self.owner.inner.native.get().unwrap().stats_result.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if ptr.is_null() { None } else { Some(unsafe { *Box::from_raw(ptr) }) }
    }
    pub fn readiness(&self) -> Arc<Ready> { self.owner.readiness() }
    pub fn close(&self) { self.owner.close(); }
    pub fn is_finished(&self) -> bool { self.owner.is_finished() }
}
