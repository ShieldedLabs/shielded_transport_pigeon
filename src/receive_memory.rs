//! Shared receive allocation admission. Reservations follow ownership, not packet ACKs.
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[derive(Debug)]
pub struct ReceiveMemoryBudget { limit: usize, used: AtomicUsize, peak: AtomicUsize, parent: Option<Arc<Self>>,
    workers: AtomicUsize, worker_peak: AtomicUsize, worker_limit: usize }
impl ReceiveMemoryBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { limit, ..Default::default() })
    }
    /// The application-derived peer cap covers workers, roots and completed
    /// application-queue entries. Every child charge also belongs to the process.
    pub(crate) fn connection_with_limit(parent: &Arc<Self>, limit: usize) -> Arc<Self> {
        assert!(limit <= parent.limit, "connection receive cap exceeds process budget");
        Arc::new(Self { limit, parent: Some(parent.clone()), ..Default::default() })
    }
    pub(crate) fn with_worker_limit(mut self: Arc<Self>, limit: usize) -> Arc<Self> {
        assert!(limit <= crate::stp::MAX_FEC_DECODE_WORKERS);
        Arc::get_mut(&mut self).expect("configure worker limit before sharing budget").worker_limit = limit;
        self
    }
    pub(crate) fn acquire_worker(&self) -> bool {
        if let Ok(old) = self.workers.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| (n < self.worker_limit).then_some(n + 1)) {
            self.worker_peak.fetch_max(old + 1, Ordering::Relaxed); true
        } else { false }
    }
    pub(crate) fn worker_peak(&self) -> usize { self.worker_peak.load(Ordering::Relaxed) }
    pub(crate) fn release_worker(&self) { self.workers.fetch_sub(1, Ordering::AcqRel); }
    pub(crate) fn worker_limit_reached(&self) -> bool { self.workers.load(Ordering::Acquire) >= self.worker_limit }

    pub fn limit(&self) -> usize { self.limit }
    pub fn used(&self) -> usize { self.used.load(Ordering::Acquire) }
    pub fn peak(&self) -> usize { self.peak.load(Ordering::Acquire) }
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        self.acquire(bytes).then(|| Reservation { budget: self.clone(), bytes })
    }
    fn acquire(&self, bytes: usize) -> bool {
        if self.parent.as_ref().is_some_and(|p| !p.acquire(bytes)) { return false; }
        if let Ok(old) = self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| used.checked_add(bytes).filter(|&n| n <= self.limit)) {
            self.peak.fetch_max(old + bytes, Ordering::Relaxed); true
        } else { if let Some(p) = &self.parent { p.release(bytes); } false }
    }
    fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
        if let Some(p) = &self.parent { p.release(bytes); }
    }
}
impl Default for ReceiveMemoryBudget {
    fn default() -> Self { Self { limit: 4 << 30, used: AtomicUsize::new(0), peak: AtomicUsize::new(0), parent: None,
        workers: AtomicUsize::new(0), worker_peak: AtomicUsize::new(0), worker_limit: crate::stp::MAX_FEC_DECODE_WORKERS } }
}
#[derive(Debug)]
pub(crate) struct Reservation { budget: Arc<ReceiveMemoryBudget>, bytes: usize }
impl Reservation {
    pub(crate) fn shrink(&mut self, bytes: usize) {
        assert!(bytes <= self.bytes);
        self.budget.release(self.bytes - bytes);
        self.bytes = bytes;
    }
    pub(crate) fn grow(&mut self, bytes: usize) -> bool {
        if bytes <= self.bytes { return true; }
        if !self.budget.acquire(bytes - self.bytes) { return false; }
        self.bytes = bytes; true
    }
    pub(crate) fn bytes(&self) -> usize { self.bytes }
    /// Take over a donor lease on the SAME budget without release/reacquire:
    /// the combined charge never has a gap and needs no new admission. A
    /// different budget or an overflowing sum refuses and returns the donor intact.
    pub(crate) fn absorb(&mut self, mut donor: Reservation) -> Result<(), Reservation> {
        if !Arc::ptr_eq(&self.budget, &donor.budget) { return Err(donor); }
        let Some(bytes) = self.bytes.checked_add(donor.bytes) else { return Err(donor); };
        self.bytes = bytes;
        donor.bytes = 0; // its Drop releases nothing
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) { self.budget.release(self.bytes); }
}
