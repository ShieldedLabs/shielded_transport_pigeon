use std::cell::Cell;
pub const TOLERATED_ERRNO_NAMES: [&str; 7] = ["EMSGSIZE", "ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "ECONNREFUSED", "EHOSTDOWN", "EAFNOSUPPORT"];
pub const KIND_NAMES: [&str; 5] = ["ack", "data", "keepalive", "mtu_probe", "outage"]; pub const KIND_DATA: usize = 1;
const OUTCOME_NONE: u8 = 0; const OUTCOME_FULL: u8 = 1; const OUTCOME_BACKPRESSURE: u8 = 2; const OUTCOME_TOLERATED: u8 = 3;
#[derive(Clone, Copy)] struct Attempt { token: u64, outcome: u8, errno: i32, len: usize, head: [u8; 16] }
fn head_of(payload: &[u8]) -> [u8; 16] {
    let mut h = [0u8; 16]; let n = payload.len().min(16); h[..n].copy_from_slice(&payload[..n]);
    h }
thread_local! {
    static UDP_SEND_FULL: Cell<u64> = const { Cell::new(0) }; static UDP_SEND_FULL_BYTES: Cell<u64> = const { Cell::new(0) };
    static UDP_SEND_TOLERATED: [Cell<u64>; 7] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static UDP_SEND_BACKPRESSURE: Cell<u64> = const { Cell::new(0) }; static NEXT_TOKEN: Cell<u64> = const { Cell::new(1) };
    static LAST_ATTEMPT: Cell<Attempt> = const { Cell::new(Attempt { token: 0, outcome: OUTCOME_NONE, errno: 0, len: 0, head: [0; 16] }) };
    static CONSUMED_TOKEN: Cell<u64> = const { Cell::new(0) };
    static COMMIT_KERNEL_FULL: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static COMMIT_TOLERATED_ERROR: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static COMMIT_UNMATCHED: [Cell<u64>; 5] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
    static SERVICE_SEQ: Cell<u64> = const { Cell::new(0) }; static COUNTER_OVERFLOW: Cell<bool> = const { Cell::new(false) };
    static FEC_ENCODER_FAILED: Cell<u64> = const { Cell::new(0) };
    static FEC_REPAIR_SKIP_EVENTS: Cell<u64> = const { Cell::new(0) };
    static FEC_REPAIR_SKIPPED_SYMBOLS: Cell<u64> = const { Cell::new(0) }; }
fn bump(c: &Cell<u64>, by: u64) {
    match c.get().checked_add(by) { Some(v) => c.set(v), None => { c.set(u64::MAX); COUNTER_OVERFLOW.with(|o| o.set(true)); } } }
fn record(payload: &[u8], outcome: u8, errno: i32) {
    let token = NEXT_TOKEN.with(|t| { let v = t.get(); bump(t, 1); v });
    LAST_ATTEMPT.with(|a| a.set(Attempt { token, outcome, errno, len: payload.len(), head: head_of(payload) })); }
pub fn udp_send_full(payload: &[u8]) {
    UDP_SEND_FULL.with(|c| bump(c, 1)); UDP_SEND_FULL_BYTES.with(|c| bump(c, payload.len() as u64));
    record(payload, OUTCOME_FULL, 0); }
pub fn udp_send_tolerated(payload: &[u8], errno: i32) {
    let i = tolerated_index(errno); UDP_SEND_TOLERATED.with(|a| bump(&a[i], 1));
    record(payload, OUTCOME_TOLERATED, errno); }
pub fn udp_send_backpressure(payload: &[u8]) {
    UDP_SEND_BACKPRESSURE.with(|c| bump(c, 1));
    record(payload, OUTCOME_BACKPRESSURE, 0); }
pub fn observe_commit(kind: usize, bytes: &[u8]) {
    let kind = kind.min(4); let a = LAST_ATTEMPT.with(|a| a.get());
    let fresh = CONSUMED_TOKEN.with(|c| a.token != 0 && a.token > c.get());
    let same = fresh && a.len == bytes.len() && a.head == head_of(bytes);
    let slot = match (same, a.outcome) {
        (true, OUTCOME_FULL) => &COMMIT_KERNEL_FULL,
        (true, OUTCOME_TOLERATED) => &COMMIT_TOLERATED_ERROR,
        _ => &COMMIT_UNMATCHED, };
    #[cfg(feature = "research_budget_diagnostic")]
    crate::budget_diagnostic::commit_proof(kind, match (same, a.outcome) { (true, OUTCOME_FULL) => 1, (true, OUTCOME_TOLERATED) => 2, _ => 3 });
    slot.with(|s| bump(&s[kind], 1));
    if fresh { CONSUMED_TOKEN.with(|c| c.set(a.token)); }
    let _ = a.errno; }
pub fn next_service_seq() -> u64 { SERVICE_SEQ.with(|c| { bump(c, 1); c.get() }) }
pub fn fec_encoder_failed() { FEC_ENCODER_FAILED.with(|c| bump(c, 1)); }
pub fn fec_repair_skipped(skipped: u64) {
    FEC_REPAIR_SKIP_EVENTS.with(|c| bump(c, 1));
    FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| bump(c, skipped)); }
pub fn tolerated_index(errno: i32) -> usize {
    #[cfg(any(unix, windows))] {
        [crate::platform::sys::EMSGSIZE, crate::platform::sys::ENETUNREACH, crate::platform::sys::EHOSTUNREACH, crate::platform::sys::ENETDOWN, crate::platform::sys::ECONNREFUSED, crate::platform::sys::EHOSTDOWN, crate::platform::sys::EAFNOSUPPORT]
            .iter().position(|e| *e == errno).unwrap_or(6) }
    #[cfg(not(any(unix, windows)))] { let _ = errno; 6 } }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)] pub struct ThreadSendCounters {
    pub udp_counters_supported: bool, pub udp_send_full: u64, pub udp_send_full_bytes: u64,
    pub udp_send_tolerated_by_errno: [u64; 7], pub udp_send_backpressure: u64, pub commit_kernel_full: [u64; 5],
    pub commit_tolerated_error: [u64; 5], pub commit_unmatched: [u64; 5], pub counter_overflow: bool,
    pub fec_encoder_failed: u64, pub fec_repair_skip_events: u64,
    pub fec_repair_skipped_symbols: u64, }
impl ThreadSendCounters {
    pub fn read() -> Self {
        let arr5 = |k: &'static std::thread::LocalKey<[Cell<u64>; 5]>| k.with(|a| std::array::from_fn(|i| a[i].get()));
        Self {
            udp_counters_supported: cfg!(target_os = "linux"), udp_send_full: UDP_SEND_FULL.with(|c| c.get()),
            udp_send_full_bytes: UDP_SEND_FULL_BYTES.with(|c| c.get()),
            udp_send_tolerated_by_errno: UDP_SEND_TOLERATED.with(|a| std::array::from_fn(|i| a[i].get())),
            udp_send_backpressure: UDP_SEND_BACKPRESSURE.with(|c| c.get()),
            commit_kernel_full: arr5(&COMMIT_KERNEL_FULL), commit_tolerated_error: arr5(&COMMIT_TOLERATED_ERROR),
            commit_unmatched: arr5(&COMMIT_UNMATCHED), counter_overflow: COUNTER_OVERFLOW.with(|c| c.get()),
            fec_encoder_failed: FEC_ENCODER_FAILED.with(|c| c.get()),
            fec_repair_skip_events: FEC_REPAIR_SKIP_EVENTS.with(|c| c.get()),
            fec_repair_skipped_symbols: FEC_REPAIR_SKIPPED_SYMBOLS.with(|c| c.get()), } }
    pub fn udp_send_tolerated_total(&self) -> u64 { self.udp_send_tolerated_by_errno.iter().sum() } }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)] pub struct QueueObservation {
    pub queue_bytes_filled: u64, pub message_queue_len: u64, pub partial_send_slot: bool, pub fec_send_slot: bool,
    pub fec_suspended: bool, pub segmented_send: bool, pub interleave_parked_len: u64, pub rescue_ready_count: u64,
    pub rescue_ready_len: u64, pub p4_open: bool, pub p4_closing: bool, pub p4_tail_refreshed: bool, pub fec_rescue_package: bool,
    pub fec_retained_len: u64, }
impl QueueObservation {
    pub fn idle(&self) -> bool {
        self.queue_bytes_filled == 0 && self.message_queue_len == 0 && !self.partial_send_slot && !self.fec_send_slot &&
            !self.fec_suspended && !self.segmented_send && self.interleave_parked_len == 0 && self.rescue_ready_count == 0 && self.rescue_ready_len == 0 && self.fec_retained_len == 0 &&
            !self.p4_open && !self.p4_closing && !self.p4_tail_refreshed && !self.fec_rescue_package } }
#[derive(Debug, Clone, Default, PartialEq, Eq)] pub struct CohortObservation {
    pub connected: bool, pub handshake_prefix: u64, pub pending_send: bool, pub pending_send_kind: Option<u8>,
    pub locally_blocked: bool, pub send_sequence_number: u64, pub last_sent_data_packet: u64, pub test_dropped: u64,
    pub test_drop_configured: bool, pub service_seq: u64, pub queues: Vec<QueueObservation>, pub thread: ThreadSendCounters,
    pub observed_ns: u64, }
impl CohortObservation {
    pub fn all_idle(&self) -> bool { self.connected && !self.pending_send && self.queues.iter().all(|q| q.idle()) } }
