//! Lowest-overhead single-application-owner endpoint.
//!
//! Two preallocated bounded SPSC rings move commands and events by ownership.
//! The handle is Send but deliberately !Sync: move it between threads, do not
//! share it between concurrent producers/consumers. Pump is the sole command
//! consumer/event producer. Ring operations are wait-free; neither try_send nor
//! try_recv allocates, copies payloads or explicitly locks. Pump adaptation still
//! allocates/frees temporary vectors, so overall progress depends on the global
//! allocator. Explicit Stats also takes the frozen protocol's telemetry mutex.
//! Each call performs constant queue work; the unchanged native eventfd wake
//! signals a sleeping pump. Linux optional application parking uses an atomic
//! generation and futex (other platforms use a 1 ms sleeping fallback).
//!
//! Sends return an admission event, NOT a delivery guarantee. A successful queue
//! insertion is not protocol acceptance: Submitted returns rejected payloads
//! untouched. Connections are initiated with Connect; incoming peers are accepted
//! automatically and reported by Update. Native peers are retained until explicit
//! Disconnect or endpoint shutdown (reference wanted_connections expiry is not used).
//! Disconnect drops local state immediately, without flushing or a wire close; a
//! remote peer can reconnect under the frozen incoming-accept policy. Refresh asks
//! for connections/messages; Stats additionally asks for the expensive full
//! counters snapshot. Receive/connection changes also generate coalesced Updates
//! automatically. There is no per-message callback or library-owned thread.
//!
//! A full event ring backpressures command consumption, not socket servicing.
//! Receive pressure then follows the frozen transport receive-budget/drop policy.
//! Drain events while sending. Commands/payload bytes are explicitly bounded by
//! ring capacity and the configured maximum message size. Close/drop cancels,
//! does not flush; queued unsent commands may be reclaimed with try_reclaim after
//! dropping Pump (close alone is not sufficient). Remaining values are dropped
//! with their owners. The boundary is lock-free except for the global allocator;
//! explicit Stats additionally takes the frozen `budget_sink` mutex.
use super::{Endpoint, Ready};
use crate::stp::{ConnectionKey, Dscp, NetworkThreadPull, STPAddress};
use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::{Arc, atomic::Ordering};

pub type ReturnedMessage = (ConnectionKey, usize, Dscp, Vec<u8>);
pub enum Command {
    Send {
        peer: ConnectionKey,
        queue: usize,
        class: Dscp,
        payload: Vec<u8>,
    },
    Connect(STPAddress),
    Disconnect(ConnectionKey),
    Refresh,
    Stats,
}
pub enum Event {
    /// Exactly one Submitted per Send; all fields None means accepted by STP.
    Submitted {
        rejected: Option<ReturnedMessage>,
        oversized: Option<ReturnedMessage>,
        invalid_queue: Option<ReturnedMessage>,
    },
    /// Current peers (including newly accepted incoming connections), messages,
    /// and optionally requested stats. Multiple readiness edges may coalesce.
    Update(NetworkThreadPull),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendErrorKind {
    Full,
    Closed,
    Oversized,
}
pub struct TrySendError {
    pub kind: SendErrorKind,
    pub command: Command,
}

pub struct LockfreeEndpoint {
    owner: Endpoint,
    _single_owner: PhantomData<Cell<()>>,
}
impl LockfreeEndpoint {
    pub(super) fn new(owner: Endpoint) -> Self {
        Self {
            owner,
            _single_owner: PhantomData,
        }
    }
    /// Queue without waiting or executing protocol work, even with Pump stopped.
    /// On failure the original command and its payload allocation are returned.
    pub fn try_send(&mut self, command: Command) -> Result<(), TrySendError> {
        let inner = &self.owner.inner;
        let n = inner.native.get().unwrap();
        let kind = if inner.stop.load(Ordering::Acquire) || self.is_finished() {
            Some(SendErrorKind::Closed)
        } else if matches!(&command, Command::Send { payload, .. } if payload.len() > n.max_payload)
        {
            Some(SendErrorKind::Oversized)
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err(TrySendError { kind, command });
        }
        unsafe { n.commands.push(command) }.map_err(|command| TrySendError {
            kind: SendErrorKind::Full,
            command,
        })?;
        inner.wake.notify();
        Ok(())
    }
    /// Move one event out. No allocation, payload copy or lock. A newly freed
    /// slot wakes the pump when command/update work may have been backpressured.
    pub fn try_recv(&mut self) -> Option<Event> {
        let n = self.owner.inner.native.get().unwrap();
        let was_full = !n.events.has_space();
        let event = unsafe { n.events.pop() }?;
        // Pair with transport_ready: head publication must precede the dirty
        // check even on architectures permitting store/load reordering.
        std::sync::atomic::fence(Ordering::SeqCst);
        // A producer may fill the ring between was_full and pop. Rechecking
        // pending work after reclamation closes that missed-full wake race.
        if was_full || n.commands.has_value() || n.dirty.load(Ordering::Acquire) {
            self.owner.inner.wake.notify();
        }
        Some(event)
    }
    /// Optional park-until-ready edge. Always retry the operation after return;
    /// command space, shutdown and spurious wakes are also readiness. Returns
    /// false once closed/finished and no events remain. The generation recheck
    /// before FUTEX_WAIT prevents the check/park lost-wakeup race.
    pub fn park_until_ready(&mut self) -> bool {
        let ready = &self.owner.inner.ready;
        let mut observed = ready.generation.load(Ordering::SeqCst) as u64;
        let n = self.owner.inner.native.get().unwrap();
        if n.events.has_value() {
            return true;
        }
        if self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire) {
            return false;
        }
        ready.wait(&mut observed);
        n.events.has_value()
            || !(self.is_finished() || self.owner.inner.stop.load(Ordering::Acquire))
    }
    /// Obtain a notifier for integrating a single owner with an external wait.
    pub fn readiness(&self) -> Arc<Ready> {
        self.owner.readiness()
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub fn is_finished(&self) -> bool {
        self.owner.is_finished()
    }
    /// Recover commands not consumed before cancellation. Only legal after
    /// dropping Pump (not merely closing this endpoint or stopping calls to
    /// run_until), so there cannot be two command-ring consumers.
    pub fn try_reclaim(&mut self) -> Option<Command> {
        if !self.is_finished() {
            return None;
        }
        unsafe { self.owner.inner.native.get().unwrap().commands.pop() }
    }
}
