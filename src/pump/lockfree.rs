//! Single-owner three-ring application boundary. No library threads are spawned.
//!
//! `try_send` moves the Vec allocation only on success; false leaves it untouched.
//! Accepted sends have no completion/admission event. A full core send queue holds
//! the FIFO head in the send ring (including head-of-line blocking other peers).
//! Unknown/disconnected peers, invalid queues and oversized sends are dropped and
//! counted. Full receive rings drop data, not lifecycle events. Disconnect is local
//! cancellation, not a wire close; a remote peer may reconnect.
use super::{Endpoint, Ready};
use crate::stp::{ConnectionKey, Dscp, STPAddress};
use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

/// Each capacity must be a power of two in 1..=65_536.
#[derive(Debug, Clone, Copy)]
pub struct RingConfig { pub send: usize, pub control: usize, pub receive: usize }
impl Default for RingConfig { fn default() -> Self { Self { send: 128, control: 32, receive: 128 } } }
pub(crate) struct SendMessage { pub peer: ConnectionKey, pub queue: usize, pub class: Dscp, pub payload: Vec<u8> }
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
pub struct LockfreeEndpoint { owner: Endpoint, _single_owner: PhantomData<Cell<()>> }
impl LockfreeEndpoint {
    pub(crate) fn new(owner: Endpoint) -> Self { Self { owner, _single_owner: PhantomData } }
    /// Constant-time ownership transfer; false also means closed, and preserves payload.
    pub fn try_send(&mut self, peer: ConnectionKey, queue: usize, class: Dscp, payload: &mut Vec<u8>) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        if inner.stop.load(Ordering::Acquire) || self.is_finished() { return false; }
        if !n.send.has_space() {
            n.send_full.store(true, Ordering::SeqCst);
            // Pair with consumer's post-pop fence: do not miss a concurrent drain.
            if !n.send.has_space() { return false; }
            n.send_full.store(false, Ordering::SeqCst);
        }
        n.send_full.store(false, Ordering::SeqCst);
        let message = SendMessage { peer, queue, class, payload: std::mem::take(payload) };
        assert!(unsafe { n.send.push(message) }.is_ok());
        inner.wake.notify();
        true
    }
    pub fn try_control(&mut self, control: Control) -> bool {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        if inner.stop.load(Ordering::Acquire) || self.is_finished() { return false; }
        if !n.control.has_space() {
            n.control_full.store(true, Ordering::SeqCst);
            if !n.control.has_space() { return false; }
            n.control_full.store(false, Ordering::SeqCst);
        }
        n.control_full.store(false, Ordering::SeqCst);
        assert!(unsafe { n.control.push(control) }.is_ok());
        inner.wake.notify();
        true
    }
    pub fn try_connect(&mut self, address: STPAddress) -> bool { self.try_control(Control::Connect(address)) }
    pub fn try_disconnect(&mut self, peer: ConnectionKey) -> bool { self.try_control(Control::Disconnect(peer)) }
    pub fn try_recv(&mut self) -> Option<Event> {
        let n = self.owner.inner.native.get().unwrap();
        let event = unsafe { n.events.pop() }?;
        // Lifecycle transitions may be waiting for space, even without network traffic.
        self.owner.inner.wake.notify();
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
        if n.events.has_value() || (n.send_full.load(Ordering::SeqCst) && n.send.has_space())
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
