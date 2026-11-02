use std::cell::Cell;
pub const TOLERATED_ERRNO_NAMES: [&str; 7] = [
    "EMSGSIZE",
    "ENETUNREACH",
    "EHOSTUNREACH",
    "ENETDOWN",
    "ECONNREFUSED",
    "EHOSTDOWN",
    "EAFNOSUPPORT",
];
pub const KIND_NAMES: [&str; 5] = ["ack", "data", "keepalive", "mtu_probe", "outage"];
pub const KIND_DATA: usize = 1;
const OUTCOME_NONE: u8 = 0;
const OUTCOME_FULL: u8 = 1;
const OUTCOME_TOLERATED: u8 = 3;
#[derive(Clone, Copy)]
struct Attempt {
    token: u64,
    outcome: u8,
    errno: i32,
    len: usize,
    head: [u8; 16],
}
fn head_of(payload: &[u8]) -> [u8; 16] {
    let mut h = [0u8; 16];
    let n = payload.len().min(16);
    h[..n].copy_from_slice(&payload[..n]);
    h
}
thread_local! { static UDP_SEND_FULL: Cell<u64> = const { Cell::new(0) };
static UDP_SEND_FULL_BYTES: Cell<u64> = const { Cell::new(0) };
static UDP_SEND_TOLERATED: [Cell<u64>; 7] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
static UDP_SEND_BACKPRESSURE: Cell<u64> = const { Cell::new(0) };
static UDP_SEND_OTHER_ERRORS: Cell<u64> = const { Cell::new(0) };
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
static FEC_REPAIR_SKIPPED_SYMBOLS: Cell<u64> = const { Cell::new(0) }; }
fn bump(c: &Cell<u64>, by: u64) {
    match c.get().checked_add(by) {
        Some(v) => c.set(v),
        None => {
            c.set(u64::MAX);
            COUNTER_OVERFLOW.with(|o| o.set(true));
        }
    }
}
fn record(payload: &[u8], outcome: u8, errno: i32) {
    let token = NEXT_TOKEN.with(|t| {
        let v = t.get();
        bump(t, 1);
        v
    });
    LAST_ATTEMPT.with(|a| {
        a.set(Attempt {
            token,
            outcome,
            errno,
            len: payload.len(),
            head: head_of(payload),
        })
    });
}
pub fn udp_send_full(payload: &[u8]) {
    UDP_SEND_FULL.with(|c| bump(c, 1));
    UDP_SEND_FULL_BYTES.with(|c| bump(c, payload.len() as u64));
    record(payload, OUTCOME_FULL, 0);
}
/// All errors are consumed local drops. Keep the historical error buckets as
/// diagnostics only; they no longer select send/retry behavior.
pub fn udp_send_error(payload: &[u8], errno: i32) {
    if let Some(i) = tolerated_index(errno) {
        UDP_SEND_TOLERATED.with(|a| bump(&a[i], 1));
    } else if buffer_refusal(errno) {
        UDP_SEND_BACKPRESSURE.with(|c| bump(c, 1));
    } else {
        UDP_SEND_OTHER_ERRORS.with(|c| bump(c, 1));
    }
    record(payload, OUTCOME_TOLERATED, errno);
}
fn buffer_refusal(errno: i32) -> bool {
    #[cfg(windows)]
    {
        errno == crate::platform::sys::WSAEWOULDBLOCK || errno == crate::platform::sys::WSAENOBUFS
    }
    #[cfg(not(windows))]
    {
        errno == crate::platform::sys::EAGAIN
            || errno == crate::platform::sys::EWOULDBLOCK
            || errno == crate::platform::sys::ENOBUFS
    }
}
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
    crate::budget_diagnostic::commit_proof(
        kind,
        match (same, a.outcome) {
            (true, OUTCOME_FULL) => 1,
            (true, OUTCOME_TOLERATED) => 2,
            _ => 3,
        },
    );
    slot.with(|s| bump(&s[kind], 1));
    if fresh {
        CONSUMED_TOKEN.with(|c| c.set(a.token));
    }
    let _ = a.errno;
}
pub fn next_service_seq() -> u64 {
    SERVICE_SEQ.with(|c| {
        bump(c, 1);
        c.get()
    })
}
pub fn fec_encoder_failed() {
    FEC_ENCODER_FAILED.with(|c| bump(c, 1));
}
pub fn fec_repair_skipped(skipped: u64) {
    FEC_REPAIR_SKIP_EVENTS.with(|c| bump(c, 1));
    FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| bump(c, skipped));
}
fn tolerated_index(errno: i32) -> Option<usize> {
    #[cfg(any(unix, windows))]
    {
        [
            crate::platform::sys::EMSGSIZE,
            crate::platform::sys::ENETUNREACH,
            crate::platform::sys::EHOSTUNREACH,
            crate::platform::sys::ENETDOWN,
            crate::platform::sys::ECONNREFUSED,
            crate::platform::sys::EHOSTDOWN,
            crate::platform::sys::EAFNOSUPPORT,
        ]
        .iter()
        .position(|e| *e == errno)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = errno;
        None
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadSendCounters {
    pub udp_counters_supported: bool,
    pub udp_send_full: u64,
    pub udp_send_full_bytes: u64,
    pub udp_send_tolerated_by_errno: [u64; 7],
    /// Historical name: counts consumed EAGAIN/EWOULDBLOCK/ENOBUFS drops, not retries.
    pub udp_send_backpressure: u64,
    pub udp_send_other_errors: u64,
    pub commit_kernel_full: [u64; 5],
    pub commit_tolerated_error: [u64; 5],
    pub commit_unmatched: [u64; 5],
    pub counter_overflow: bool,
    pub fec_encoder_failed: u64,
    pub fec_repair_skip_events: u64,
    pub fec_repair_skipped_symbols: u64,
}
impl ThreadSendCounters {
    pub fn read() -> Self {
        let arr5 = |k: &'static std::thread::LocalKey<[Cell<u64>; 5]>| {
            k.with(|a| std::array::from_fn(|i| a[i].get()))
        };
        Self {
            udp_counters_supported: true,
            udp_send_full: UDP_SEND_FULL.with(|c| c.get()),
            udp_send_full_bytes: UDP_SEND_FULL_BYTES.with(|c| c.get()),
            udp_send_tolerated_by_errno: UDP_SEND_TOLERATED
                .with(|a| std::array::from_fn(|i| a[i].get())),
            udp_send_backpressure: UDP_SEND_BACKPRESSURE.with(|c| c.get()),
            udp_send_other_errors: UDP_SEND_OTHER_ERRORS.with(|c| c.get()),
            commit_kernel_full: arr5(&COMMIT_KERNEL_FULL),
            commit_tolerated_error: arr5(&COMMIT_TOLERATED_ERROR),
            commit_unmatched: arr5(&COMMIT_UNMATCHED),
            counter_overflow: COUNTER_OVERFLOW.with(|c| c.get()),
            fec_encoder_failed: FEC_ENCODER_FAILED.with(|c| c.get()),
            fec_repair_skip_events: FEC_REPAIR_SKIP_EVENTS.with(|c| c.get()),
            fec_repair_skipped_symbols: FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| c.get()),
        }
    }
    pub fn udp_send_tolerated_total(&self) -> u64 {
        self.udp_send_tolerated_by_errno.iter().sum()
    }
}
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
    pub fec_retained_len: u64,
}
impl QueueObservation {
    pub fn idle(&self) -> bool {
        self.queue_bytes_filled == 0
            && self.message_queue_len == 0
            && !self.partial_send_slot
            && !self.fec_send_slot
            && !self.fec_suspended
            && !self.segmented_send
            && self.interleave_parked_len == 0
            && self.rescue_ready_count == 0
            && self.rescue_ready_len == 0
            && self.fec_retained_len == 0
            && !self.p4_open
            && !self.p4_closing
            && !self.p4_tail_refreshed
            && !self.fec_rescue_package
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CohortObservation {
    pub connected: bool,
    pub handshake_prefix: u64,
    /// Only an intentional whole-packet duplication copy can remain pending.
    pub pending_send: bool,
    pub pending_send_kind: Option<u8>,
    pub send_sequence_number: u64,
    pub last_sent_data_packet: u64,
    pub test_dropped: u64,
    pub test_drop_configured: bool,
    pub service_seq: u64,
    pub queues: Vec<QueueObservation>,
    pub thread: ThreadSendCounters,
    pub observed_ns: u64,
}
impl CohortObservation {
    pub fn all_idle(&self) -> bool {
        self.connected && !self.pending_send && self.queues.iter().all(|q| q.idle())
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;

    #[test]
    fn errors_keep_local_drop_proof_distinct_from_kernel_acceptance() {
        let payload = [7; 512];
        let before = ThreadSendCounters::read();
        udp_send_error(&payload, i32::MAX);
        observe_commit(KIND_DATA, &payload);
        #[cfg(windows)]
        let buffer_error = crate::platform::sys::WSAEWOULDBLOCK;
        #[cfg(not(windows))]
        let buffer_error = crate::platform::sys::EAGAIN;
        udp_send_error(&payload, buffer_error);
        observe_commit(KIND_DATA, &payload);
        udp_send_full(&payload);
        observe_commit(KIND_DATA, &payload);
        let after = ThreadSendCounters::read();
        assert!(after.udp_counters_supported);
        assert_eq!(
            after.udp_send_other_errors,
            before.udp_send_other_errors + 1
        );
        assert_eq!(
            after.udp_send_backpressure,
            before.udp_send_backpressure + 1
        );
        assert_eq!(after.udp_send_full, before.udp_send_full + 1);
        assert_eq!(
            after.udp_send_tolerated_by_errno,
            before.udp_send_tolerated_by_errno
        );
        assert_eq!(
            after.commit_tolerated_error[KIND_DATA],
            before.commit_tolerated_error[KIND_DATA] + 2
        );
        assert_eq!(
            after.commit_kernel_full[KIND_DATA],
            before.commit_kernel_full[KIND_DATA] + 1
        );
        assert_eq!(after.commit_unmatched, before.commit_unmatched);
    }
}
