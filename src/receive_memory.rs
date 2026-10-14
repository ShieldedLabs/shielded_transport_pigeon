//! Shared receive allocation admission. Reservations follow ownership, not packet ACKs.
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[derive(Debug)]
pub struct ReceiveMemoryBudget { limit: usize, used: AtomicUsize, peak: AtomicUsize }
impl ReceiveMemoryBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { limit, used: AtomicUsize::new(0), peak: AtomicUsize::new(0) })
    }
    pub fn limit(&self) -> usize { self.limit }
    pub fn used(&self) -> usize { self.used.load(Ordering::Acquire) }
    pub fn peak(&self) -> usize { self.peak.load(Ordering::Acquire) }
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        self.acquire(bytes).then(|| Reservation { budget: self.clone(), bytes })
    }
    fn acquire(&self, bytes: usize) -> bool {
        if let Ok(old) = self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| used.checked_add(bytes).filter(|&n| n <= self.limit)) {
            self.peak.fetch_max(old + bytes, Ordering::Relaxed); true
        } else { false }
    }
}
impl Default for ReceiveMemoryBudget {
    fn default() -> Self { Self { limit: 4 << 30, used: AtomicUsize::new(0), peak: AtomicUsize::new(0) } }
}
#[derive(Debug)]
pub(crate) struct Reservation { budget: Arc<ReceiveMemoryBudget>, bytes: usize }
impl Reservation {
    pub(crate) fn shrink(&mut self, bytes: usize) {
        assert!(bytes <= self.bytes);
        self.budget.used.fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        self.bytes = bytes;
    }
    pub(crate) fn grow(&mut self, bytes: usize) -> bool {
        if bytes <= self.bytes { return true; }
        if !self.budget.acquire(bytes - self.bytes) { return false; }
        self.bytes = bytes; true
    }
}
impl Drop for Reservation {
    fn drop(&mut self) { self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel); }
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
    fn shared_budget_never_overcommits() {
        let b = ReceiveMemoryBudget::new(4096);
        std::thread::scope(|s| { for _ in 0..8 { let b = b.clone(); s.spawn(move || {
            for _ in 0..1000 { if let Some(r) = b.reserve(1024) { assert!(b.used() <= b.limit()); drop(r); } }
        }); } });
        assert_eq!(b.used(), 0); assert!(b.peak() <= 4096);
    }
}
