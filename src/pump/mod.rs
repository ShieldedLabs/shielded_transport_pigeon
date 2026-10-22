pub mod port; pub(crate) use port::Endpoint;
pub use port::lockfree::{LockfreeEndpoint, RingConfig, Control, Event, Stats, ConnectFailure, DisconnectReason};
use std::time::{Duration, Instant};
/// Exclusive socket/protocol owner. Move this value to a thread, or call it in
/// frame slack. Application operations live on LockfreeEndpoint, never on Pump.
///
/// Protocol clock samples remain at packet boundaries. Traversals with no fresh
/// sample check every eight bookkeeping units. Native admissions form bursts of
/// at most 32 commands per protocol pass, checking the caller deadline before
/// each command except the first owed admission. HOL-blocked sends stay queued.
/// A native Wirehair encode/decode/recovery call cannot be preempted. OS
/// scheduling and allocator latency are not hard real-time bounded. Logical
/// messages up to 1 GiB use native codec units no larger than 2 MiB. Explicit
/// protocol telemetry also incurs work proportional to connections/queues.
/// Dropping Pump closes the UDP socket and publishes endpoint termination.
///
/// Forward progress: a `run_until` call entered before its deadline admits one
/// eligible pending command and completes one unit (one received datagram, one
/// data send, one FEC completion/sweep entry, one connection send step or eight
/// bookkeeping units; an idle pass counts), even if the deadline passes during
/// calibration/preemption. The cooperative overshoot bound is one admission
/// plus one such unit. An unfinished 150 us active retry quantum is never
/// shortened: only the owed command may be admitted inside it, and the owed
/// unit waits for a call after it ends. Calls entered at/after their deadline
/// return immediately without work.
pub struct Pump {
    pub(crate) run: Box<dyn FnMut(Deadline) -> Option<Instant> + Send>,
    pub(crate) wakeup: Option<Instant>, }
pub(crate) struct Deadline {
    pub(crate) instant: Instant, raw_ns: u64, now_ns: u64, unsampled: u8, command_owed: bool,
    unit_owed: bool, }
impl Deadline {
    fn new(instant: Instant, now: Instant, raw_now: u64) -> Self {
        Self { instant, raw_ns: raw_now.saturating_add(instant.saturating_duration_since(now).as_nanos().min(u64::MAX as u128) as u64), now_ns: raw_now, unsampled: 0, command_owed: true, unit_owed: true }
    }
    pub(crate) fn sampled(&mut self, now_ns: u64) -> bool {
        self.now_ns = self.now_ns.max(now_ns); self.unsampled = 0;
        self.expired() }
    pub(crate) fn expired(&self) -> bool { !self.unit_owed && self.now_ns >= self.raw_ns }
    pub(crate) fn checkpoint(&mut self) -> bool {
        self.unsampled += 1;
        if self.unsampled == 8 { self.sampled(crate::native_sockets::monotonic_clock_ns()); self.unit_owed = false; }
        self.expired() }
    pub(crate) fn progressed(&mut self) { self.unit_owed = false; }
    pub(crate) fn unit_owed(&self) -> bool { self.unit_owed }
    pub(crate) fn command_owed(&self) -> bool { self.command_owed }
    pub(crate) fn admitted(&mut self) { self.command_owed = false; } }
impl Pump {
    pub fn run_until(&mut self, deadline: Instant) {
        let now = Instant::now();
        if now < deadline {
            let raw_now = crate::native_sockets::monotonic_clock_ns();
            self.wakeup = (self.run)(Deadline::new(deadline, now, raw_now)); } }
    pub fn run_for(&mut self, duration: Duration) { self.run_until(Instant::now() + duration); }
    pub fn next_wakeup(&self) -> Option<Instant> { self.wakeup } }
