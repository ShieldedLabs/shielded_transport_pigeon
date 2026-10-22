//! RESEARCH-ONLY, observation-only telemetry for the size-sweep-cohort harness (Cargo feature
//! `research_cohort_observer`, off by default). Nothing here changes what is sent, when, or what any
//! function returns: counters are incremented next to existing outcomes and the snapshot is a
//! read of existing state, built on the network thread after `free_bytes()` reclamation.
//!
//! Counters are THREAD-LOCAL: the network thread is the only caller of the native UDP send and
//! of the send-buffer fragment builder, and it also builds the snapshot, so each network thread
//! reads exactly its own counts (several network threads in one process do not mix).
use std::cell::Cell;

/// Errnos the Linux native send tolerates by returning `Some(timestamp)` without having sent.
pub const TOLERATED_ERRNO_NAMES: [&str; 7] = ["EMSGSIZE", "ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "ECONNREFUSED", "EHOSTDOWN", "EAFNOSUPPORT"];

/// Commit kinds, in `PendingSendKind` order.
pub const KIND_NAMES: [&str; 5] = ["ack", "data", "keepalive", "mtu_probe", "outage"];
pub const KIND_DATA: usize = 1;

const OUTCOME_NONE: u8 = 0;
const OUTCOME_FULL: u8 = 1;
const OUTCOME_BACKPRESSURE: u8 = 2;
const OUTCOME_TOLERATED: u8 = 3;

/// The calling thread's most recent native send attempt: a fixed-size record, overwritten by
/// every attempt and consumed by at most one commit.
#[derive(Clone, Copy)]
struct Attempt { token: u64, outcome: u8, errno: i32, len: usize, head: [u8; 16] }

fn head_of(payload: &[u8]) -> [u8; 16] {
    let mut h = [0u8; 16];
    let n = payload.len().min(16);
    h[..n].copy_from_slice(&payload[..n]);
    h
}

thread_local! {
    static UDP_SEND_FULL: Cell<u64> = const { Cell::new(0) };
    static UDP_SEND_FULL_BYTES: Cell<u64> = const { Cell::new(0) };
    static UDP_SEND_TOLERATED: [Cell<u64>; 7] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static UDP_SEND_BACKPRESSURE: Cell<u64> = const { Cell::new(0) };
    static NEXT_TOKEN: Cell<u64> = const { Cell::new(1) };
    static LAST_ATTEMPT: Cell<Attempt> = const { Cell::new(Attempt { token: 0, outcome: OUTCOME_NONE, errno: 0, len: 0, head: [0; 16] }) };
    static CONSUMED_TOKEN: Cell<u64> = const { Cell::new(0) };
    static COMMIT_KERNEL_FULL: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static COMMIT_TOLERATED_ERROR: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static COMMIT_UNMATCHED: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static SERVICE_SEQ: Cell<u64> = const { Cell::new(0) };
    static COUNTER_OVERFLOW: Cell<bool> = const { Cell::new(false) };
    static FEC_ENCODER_FAILED: Cell<u64> = const { Cell::new(0) };
    static FEC_REPAIR_SKIP_EVENTS: Cell<u64> = const { Cell::new(0) };
    static FEC_REPAIR_SKIPPED_SYMBOLS: Cell<u64> = const { Cell::new(0) };
}

/// Saturating add; a saturation latches COUNTER_OVERFLOW, which invalidates any observation
/// window that reads it (never wraps, never panics).
fn bump(c: &Cell<u64>, by: u64) {
    match c.get().checked_add(by) {
        Some(v) => c.set(v),
        None => { c.set(u64::MAX); COUNTER_OVERFLOW.with(|o| o.set(true)); }
    }
}

fn record(payload: &[u8], outcome: u8, errno: i32) {
    let token = NEXT_TOKEN.with(|t| { let v = t.get(); bump(t, 1); v });
    LAST_ATTEMPT.with(|a| a.set(Attempt { token, outcome, errno, len: payload.len(), head: head_of(payload) }));
}

/// Native send: sendmsg returned n == payload.len().
pub fn udp_send_full(payload: &[u8]) {
    UDP_SEND_FULL.with(|c| bump(c, 1));
    UDP_SEND_FULL_BYTES.with(|c| bump(c, payload.len() as u64));
    record(payload, OUTCOME_FULL, 0);
}
/// Native send: sendmsg failed with `errno`, which the native send reports as `Some(timestamp)`.
pub fn udp_send_tolerated(payload: &[u8], errno: i32) {
    let i = tolerated_index(errno);
    UDP_SEND_TOLERATED.with(|a| bump(&a[i], 1));
    record(payload, OUTCOME_TOLERATED, errno);
}
/// Native send: local backpressure (`None`: the caller retains the datagram).
pub fn udp_send_backpressure(payload: &[u8]) {
    UDP_SEND_BACKPRESSURE.with(|c| bump(c, 1));
    record(payload, OUTCOME_BACKPRESSURE, 0);
}

/// A connected send of `kind` (index into KIND_NAMES) is being committed as sent with these
/// exact ciphertext bytes. Classifies it against the thread's most recent native attempt:
/// fresh (not yet consumed) + same length + same first 16 bytes + full kernel send => kernel_full;
/// same but a tolerated errno => tolerated_error; anything else (no native attempt at all, e.g.
/// a synthetic test drop, a stale/consumed token, a backpressure outcome, or different bytes)
/// => unmatched. Consumes the attempt token. Observation only.
pub fn observe_commit(kind: usize, bytes: &[u8]) {
    let kind = kind.min(4);
    let a = LAST_ATTEMPT.with(|a| a.get());
    let fresh = CONSUMED_TOKEN.with(|c| a.token != 0 && a.token > c.get());
    let same = fresh && a.len == bytes.len() && a.head == head_of(bytes);
    let slot = match (same, a.outcome) {
        (true, OUTCOME_FULL) => &COMMIT_KERNEL_FULL,
        (true, OUTCOME_TOLERATED) => &COMMIT_TOLERATED_ERROR,
        _ => &COMMIT_UNMATCHED,
    };
    #[cfg(feature = "research_budget_diagnostic")]
    crate::budget_diagnostic::commit_proof(kind, match (same, a.outcome) { (true, OUTCOME_FULL) => 1, (true, OUTCOME_TOLERATED) => 2, _ => 3 });
    slot.with(|s| bump(&s[kind], 1));
    if fresh { CONSUMED_TOKEN.with(|c| c.set(a.token)); }
    let _ = a.errno;
}
/// Next snapshot sequence number of this thread (first is 1).
/// Saturates at u64::MAX (latching COUNTER_OVERFLOW): a repeated value is then visible as stale.
pub fn next_service_seq() -> u64 { SERVICE_SEQ.with(|c| { bump(c, 1); c.get() }) }
/// An asynchronous FEC encoder resolved to `Failed` (no encoder, or the worker disconnected).
pub fn fec_encoder_failed() { FEC_ENCODER_FAILED.with(|c| bump(c, 1)); }
/// No repair symbol could be produced; `skipped` planned symbols (next_id..n) are abandoned.
pub fn fec_repair_skipped(skipped: u64) {
    FEC_REPAIR_SKIP_EVENTS.with(|c| bump(c, 1));
    FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| bump(c, skipped));
}

/// Index into TOLERATED_ERRNO_NAMES. Unknown errnos cannot reach here (the native send panics
/// on them); they map to the last slot defensively rather than being dropped.
pub fn tolerated_index(errno: i32) -> usize {
    // On Windows, sys::E* are the Winsock codes (WSAEMSGSIZE 10040, ...) for the same categories.
    #[cfg(any(unix, windows))]
    {
        [crate::platform::sys::EMSGSIZE, crate::platform::sys::ENETUNREACH, crate::platform::sys::EHOSTUNREACH, crate::platform::sys::ENETDOWN, crate::platform::sys::ECONNREFUSED, crate::platform::sys::EHOSTDOWN, crate::platform::sys::EAFNOSUPPORT]
            .iter().position(|e| *e == errno).unwrap_or(6)
    }
    #[cfg(not(any(unix, windows)))]
    { let _ = errno; 6 }
}

/// Cumulative counters of the calling thread (for the snapshot: the network thread).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadSendCounters {
    pub udp_counters_supported: bool,
    /// All native attempts, every packet kind (handshake, ACK, probe, data...): diagnostic.
    pub udp_send_full: u64,
    pub udp_send_full_bytes: u64,
    pub udp_send_tolerated_by_errno: [u64; 7],
    pub udp_send_backpressure: u64,
    /// Connected commits per kind (KIND_NAMES order), classified against the native attempt.
    pub commit_kernel_full: [u64; 5],
    pub commit_tolerated_error: [u64; 5],
    pub commit_unmatched: [u64; 5],
    /// Any counter, the attempt token or the service sequence saturated: the window is invalid.
    pub counter_overflow: bool,
    pub fec_encoder_failed: u64,
    pub fec_repair_skip_events: u64,
    pub fec_repair_skipped_symbols: u64,
}
impl ThreadSendCounters {
    pub fn read() -> Self {
        let arr5 = |k: &'static std::thread::LocalKey<[Cell<u64>; 5]>| k.with(|a| std::array::from_fn(|i| a[i].get()));
        Self {
            udp_counters_supported: cfg!(target_os = "linux"),
            udp_send_full: UDP_SEND_FULL.with(|c| c.get()),
            udp_send_full_bytes: UDP_SEND_FULL_BYTES.with(|c| c.get()),
            udp_send_tolerated_by_errno: UDP_SEND_TOLERATED.with(|a| std::array::from_fn(|i| a[i].get())),
            udp_send_backpressure: UDP_SEND_BACKPRESSURE.with(|c| c.get()),
            commit_kernel_full: arr5(&COMMIT_KERNEL_FULL),
            commit_tolerated_error: arr5(&COMMIT_TOLERATED_ERROR),
            commit_unmatched: arr5(&COMMIT_UNMATCHED),
            counter_overflow: COUNTER_OVERFLOW.with(|c| c.get()),
            fec_encoder_failed: FEC_ENCODER_FAILED.with(|c| c.get()),
            fec_repair_skip_events: FEC_REPAIR_SKIP_EVENTS.with(|c| c.get()),
            fec_repair_skipped_symbols: FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| c.get()),
        }
    }
    pub fn udp_send_tolerated_total(&self) -> u64 { self.udp_send_tolerated_by_errno.iter().sum() }
}

/// Read-only view of one application send queue (`UnreliableSendBuffer`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueObservation {
    pub queue_bytes_filled: u64,
    pub message_queue_len: u64,
    pub partial_send_slot: bool,
    pub fec_send_slot: bool,
    pub fec_suspended: bool,
    pub segmented_send: bool,
    pub interleave_parked_len: u64,
    pub rescue_ready_count: u64,
    pub rescue_ready_len: u64,
    pub p4_open: bool,
    pub p4_closing: bool,
    pub p4_tail_refreshed: bool,
    pub fec_rescue_package: bool,
    /// Retained codecs (post-message, awaiting feedback) could still emit rescue repairs:
    /// required empty for this MessageBound/P4 campaign.
    pub fec_retained_len: u64,
}
impl QueueObservation {
    /// Strict: no queued, partial, coded, suspended, segmented, parked, rescue-ready or open-P4 work.
    pub fn idle(&self) -> bool {
        self.queue_bytes_filled == 0 && self.message_queue_len == 0 && !self.partial_send_slot && !self.fec_send_slot &&
            !self.fec_suspended && !self.segmented_send && self.interleave_parked_len == 0 && self.rescue_ready_count == 0 && self.rescue_ready_len == 0 && self.fec_retained_len == 0 &&
            !self.p4_open && !self.p4_closing && !self.p4_tail_refreshed && !self.fec_rescue_package
    }
}

/// One connection, observed in a service response after `free_bytes()` reclamation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CohortObservation {
    pub connected: bool,
    /// First 8 bytes of the handshake hash (little-endian): a change means a new session.
    pub handshake_prefix: u64,
    pub pending_send: bool,
    /// KIND_NAMES index of the pending refused datagram, if any.
    pub pending_send_kind: Option<u8>,
    pub locally_blocked: bool,
    pub send_sequence_number: u64,
    pub last_sent_data_packet: u64,
    pub test_dropped: u64,
    /// STP_TEST_DROP_PPM / STP_TEST_DROP_SCHEDULE active on this network thread.
    pub test_drop_configured: bool,
    /// Per-thread snapshot sequence (strictly increasing; rejects stale observations).
    pub service_seq: u64,
    pub queues: Vec<QueueObservation>,
    pub thread: ThreadSendCounters,
    /// native_sockets::monotonic_clock_ns() (Linux: CLOCK_MONOTONIC_RAW, the clock of the native
    /// send timestamps), read AFTER every field above was read.
    pub observed_ns: u64,
}
impl CohortObservation {
    /// Connected, no pending ciphertext and every queue strictly idle.
    pub fn all_idle(&self) -> bool { self.connected && !self.pending_send && self.queues.iter().all(|q| q.idle()) }
}

/// Test-only: preload a counter (and the service sequence) near u64::MAX to exercise saturation.
#[cfg(test)]
pub fn preload_near_max_for_test() {
    UDP_SEND_FULL.with(|c| c.set(u64::MAX - 1));
    SERVICE_SEQ.with(|c| c.set(u64::MAX - 1));
}
