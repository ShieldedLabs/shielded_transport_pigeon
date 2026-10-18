//! Caller-scheduled STP core. No library-owned threads or executor are required.
pub mod port;
pub(crate) use port::Endpoint;
pub use port::lockfree::{LockfreeEndpoint, RingConfig, Control, Event, Stats, ConnectFailure, DisconnectReason};
use std::time::{Duration, Instant};

/// Exclusive socket/protocol owner. Move this value to a thread, or call it in
/// frame slack. Application operations live on Endpoint, never on Pump.
///
/// The core reuses protocol clock samples at packet boundaries. Traversals with
/// no fresh sample check every eight bookkeeping units. The cooperative bound is
/// one packet/FEC unit or eight bookkeeping units, plus at most one reference
/// exchange (cost proportional to its command and connection-snapshot size).
/// A native Wirehair encode/decode/recovery call cannot be preempted. OS
/// scheduling and allocator latency are not hard real-time bounded. Logical
/// messages up to 1 GiB use native codec units no larger than 2 MiB.
/// Dropping Pump closes the UDP socket and publishes endpoint termination.
///
/// Forward progress: a `run_until` call entered before its deadline always
/// admits the pending command exchange (if one is pending when it is checked)
/// and completes one unit (one received datagram, one data send, one FEC
/// completion/sweep entry, one connection send step or eight bookkeeping units;
/// an idle pass counts), even if the deadline passes meanwhile, e.g. during
/// clock calibration or OS preemption. Overshoot past the deadline is therefore
/// bounded by one command admission (measured ~30-70 us for small batches;
/// proportional to batch/connection-snapshot size) plus one unit. An unfinished
/// 150 us active retry quantum is never shortened: only the owed command may be
/// admitted inside it, and the owed unit waits for a call after it ends. A call
/// entered at or after its deadline returns immediately without work.
pub struct Pump {
    pub(crate) run: Box<dyn FnMut(Deadline) -> Option<Instant> + Send>,
    pub(crate) wakeup: Option<Instant>,
}
/// MONOTONIC_RAW and Instant have different origins and may slew relative to
/// each other. Calibrate once per call, never compare their absolute values.
/// At the maximum 500 ppm NTP slew, a 100 ms call has <=50 us clock drift
/// (plus calibration read/scheduling latency). Longer calls scale accordingly.
/// This conversion is only for scheduling: protocol samples/pacing are unchanged.
pub(crate) struct Deadline {
    pub(crate) instant: Instant,
    raw_ns: u64,
    now_ns: u64,
    unsampled: u8,
    /// Forward-progress exemptions: the first command admission and the first
    /// unit of each call ignore the deadline.
    command_owed: bool,
    unit_owed: bool,
}
impl Deadline {
    fn new(instant: Instant, now: Instant, raw_now: u64) -> Self {
        Self { instant, raw_ns: raw_now.saturating_add(instant.saturating_duration_since(now).as_nanos().min(u64::MAX as u128) as u64), now_ns: raw_now, unsampled: 0, command_owed: true, unit_owed: true }
    }
    pub(crate) fn sampled(&mut self, now_ns: u64) -> bool {
        self.now_ns = self.now_ns.max(now_ns);
        self.unsampled = 0;
        self.expired()
    }
    /// Never true before this call's first unit has completed.
    pub(crate) fn expired(&self) -> bool { !self.unit_owed && self.now_ns >= self.raw_ns }
    /// Only bookkeeping loops without an existing fresh protocol clock use this.
    /// Eight bookkeeping units complete the owed unit.
    pub(crate) fn checkpoint(&mut self) -> bool {
        self.unsampled += 1;
        if self.unsampled == 8 { self.sampled(crate::native_sockets::monotonic_clock_ns()); self.unit_owed = false; }
        self.expired()
    }
    /// A unit has started that completes before the next deadline check.
    pub(crate) fn progressed(&mut self) { self.unit_owed = false; }
    pub(crate) fn unit_owed(&self) -> bool { self.unit_owed }
    /// The first command take of a call is exempt from the admission deadline.
    pub(crate) fn command_owed(&self) -> bool { self.command_owed }
    pub(crate) fn admitted(&mut self) { self.command_owed = false; }
}
impl Pump {
    pub fn run_until(&mut self, deadline: Instant) {
        let now = Instant::now();
        if now < deadline {
            let raw_now = crate::native_sockets::monotonic_clock_ns();
            self.wakeup = (self.run)(Deadline::new(deadline, now, raw_now));
        }
    }
    pub fn run_for(&mut self, duration: Duration) { self.run_until(Instant::now() + duration); }
    /// Earliest scheduled core work as of the last run. Commands/socket readiness
    /// can make work ready earlier. None means stopped, not an infinite timer.
    pub fn next_wakeup(&self) -> Option<Instant> { self.wakeup }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_deadline_uses_duration_not_clock_origin() {
        let now = Instant::now();
        let mut deadline = Deadline::new(now + Duration::from_micros(100), now, 123);
        deadline.progressed();
        assert!(!deadline.sampled(100_122));
        assert!(deadline.sampled(100_123));
        // Resuming a retained datagram must not move scheduling time backwards.
        assert!(deadline.sampled(123));
    }
    #[test]
    fn unsampled_bookkeeping_refreshes_on_eighth_unit() {
        let now = Instant::now();
        let raw = crate::native_sockets::monotonic_clock_ns();
        let mut deadline = Deadline::new(now + Duration::from_nanos(1), now, raw.saturating_sub(1_000_000));
        for _ in 0..7 { assert!(!deadline.checkpoint()); }
        assert!(deadline.checkpoint());
    }
    #[test]
    fn first_unit_and_command_ignore_passed_deadline() {
        let now = Instant::now();
        let mut deadline = Deadline::new(now + Duration::from_nanos(1), now, 123);
        assert!(!deadline.sampled(u64::MAX) && !deadline.expired());
        assert!(deadline.command_owed());
        deadline.admitted();
        assert!(!deadline.command_owed() && !deadline.expired());
        deadline.progressed();
        assert!(deadline.expired());
    }
    #[test]
    fn call_whose_deadline_passes_after_entry_admits_queued_commands() {
        use crate::stp::*;
        let (mut pump, endpoint) = new_reference_pump(vec![new_keypair_from_connect_magic1(CONNECT_MAGIC1_PLAIN_TEXT).unwrap()], 0,
            None, (1_000_000, 4 << 20, 4 << 20), 2_000_000);
        pump.run_for(Duration::from_millis(1)); // setup and first sweep
        // Two queued commands (one slot: the second waits for the first result).
        for i in 0..2 {
            endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
            // Entered/calibrated 1 ms ago with a 1 us budget: a deterministic
            // stand-in for calibration latency or preemption after entry.
            let entered = Instant::now() - Duration::from_millis(1);
            let raw_entered = crate::native_sockets::monotonic_clock_ns() - 1_000_000;
            (pump.run)(Deadline::new(entered + Duration::from_micros(1), entered, raw_entered));
            assert!(endpoint.try_take().is_some(), "command {i} was not admitted");
        }
        // Entered at/after the deadline: still no work.
        endpoint.submit(NetworkThreadPush::default()).ok().unwrap();
        pump.run_until(Instant::now());
        assert!(endpoint.try_take().is_none());
    }
}
