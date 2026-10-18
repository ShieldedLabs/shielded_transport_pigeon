//! Caller-scheduled STP core. No library-owned threads or executor are required.
pub mod port;
pub use port::Endpoint;
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
}
impl Deadline {
    fn new(instant: Instant, now: Instant, raw_now: u64) -> Self {
        Self { instant, raw_ns: raw_now.saturating_add(instant.saturating_duration_since(now).as_nanos().min(u64::MAX as u128) as u64), now_ns: raw_now, unsampled: 0 }
    }
    pub(crate) fn sampled(&mut self, now_ns: u64) -> bool {
        self.now_ns = self.now_ns.max(now_ns);
        self.unsampled = 0;
        self.expired()
    }
    pub(crate) fn expired(&self) -> bool { self.now_ns >= self.raw_ns }
    /// Only bookkeeping loops without an existing fresh protocol clock use this.
    pub(crate) fn checkpoint(&mut self) -> bool {
        self.unsampled += 1;
        if self.unsampled == 8 { self.sampled(crate::native_sockets::monotonic_clock_ns()); }
        self.expired()
    }
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
}
