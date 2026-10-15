//! Shared receive allocation admission. Reservations follow ownership, not packet ACKs.
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[derive(Debug)]
pub struct ReceiveMemoryBudget { limit: usize, used: AtomicUsize, peak: AtomicUsize, parent: Option<Arc<Self>> }
impl ReceiveMemoryBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { limit, used: AtomicUsize::new(0), peak: AtomicUsize::new(0), parent: None })
    }
    /// A peer cannot occupy more than its share, even across workers and completed
    /// application-queue entries. Every child charge also belongs to the process.
    /// Half the default 4 GiB process budget fits the public 1 GiB message limit,
    /// including geometric prefix capacity, sparse parts and bounded FEC workers.
    pub(crate) fn connection_share(parent: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self { limit: parent.limit / 2, used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0), parent: Some(parent.clone()) })
    }
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
    fn default() -> Self { Self { limit: 4 << 30, used: AtomicUsize::new(0), peak: AtomicUsize::new(0), parent: None } }
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
}
impl Drop for Reservation {
    fn drop(&mut self) { self.budget.release(self.bytes); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_atomic_admission_and_ownership() {
        let b = ReceiveMemoryBudget::new(100);
        let mut a = b.reserve(40).unwrap(); let c = b.reserve(60).unwrap();
        assert!(b.reserve(1).is_none()); assert!(!a.grow(41));
        assert!(b.reserve(usize::MAX).is_none()); drop(c);
        assert!(a.grow(100)); assert_eq!(b.peak(),100); drop(a); assert_eq!(b.used(),0);
    }
    #[test]
    fn peer_share_charges_parent_and_rolls_back_refused_growth() {
        let process = ReceiveMemoryBudget::new(200);
        let peer = ReceiveMemoryBudget::connection_share(&process);
        let mut r = peer.reserve(80).unwrap();
        assert_eq!(process.used(), 80);
        assert!(peer.reserve(21).is_none());
        assert!(!r.grow(101));
        assert_eq!(process.used(), 80);
        r.shrink(20); assert_eq!(process.used(), 20);
        assert!(r.grow(100)); assert_eq!(process.used(), 100);
        drop(r); assert_eq!(peer.used(), 0); assert_eq!(process.used(), 0);
        let global = process.reserve(150).unwrap();
        assert!(peer.reserve(51).is_none()); assert_eq!(peer.used(), 0);
        drop(global);
    }
    #[test]
    fn shared_budget_never_overcommits() {
        let b = ReceiveMemoryBudget::new(4096);
        std::thread::scope(|s| { for _ in 0..8 { let b = b.clone(); s.spawn(move || {
            for _ in 0..1000 { if let Some(r) = b.reserve(1024) { assert!(b.used() <= b.limit()); drop(r); } }
        }); } });
        assert_eq!(b.used(), 0); assert!(b.peak() <= 4096);
    }
}
