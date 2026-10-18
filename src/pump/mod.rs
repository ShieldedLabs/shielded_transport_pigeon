//! Caller-scheduled STP core. No library-owned threads or executor are required.
pub mod port;
pub use port::Endpoint;
use std::time::{Duration, Instant};

/// Exclusive socket/protocol owner. Move this value to a thread, or call it in
/// frame slack. Application operations live on Endpoint, never on Pump.
///
/// The core checks its deadline at packet boundaries. A native Wirehair
/// encode/decode/recovery call cannot be preempted and is one indivisible work
/// unit; OS scheduling and allocator latency are not hard real-time bounded.
/// Dropping Pump closes the UDP socket and publishes endpoint termination.
pub struct Pump {
    pub(crate) run: Box<dyn FnMut(Instant) -> Option<Instant> + Send>,
    pub(crate) wakeup: Option<Instant>,
}
impl Pump {
    pub fn run_until(&mut self, deadline: Instant) {
        if Instant::now() < deadline { self.wakeup = (self.run)(deadline); }
    }
    pub fn run_for(&mut self, duration: Duration) { self.run_until(Instant::now() + duration); }
    /// Earliest scheduled core work as of the last run. Commands/socket readiness
    /// can make work ready earlier. None means stopped, not an infinite timer.
    pub fn next_wakeup(&self) -> Option<Instant> { self.wakeup }
}
