//! Single-producer/single-consumer bounded ownership queue.
//!
//! Each cursor has exactly one writer. A producer writes a previously reclaimed
//! slot before publishing tail (Release); the consumer observes tail (Acquire)
//! before reading it. The consumer moves the value out before releasing head;
//! producer acquires head before reusing that slot. Thus no slot is concurrently
//! accessed, including across usize wrap. Capacity <= isize::MAX keeps wrapping
//! subtraction unambiguous. Operations have no retry loops, allocations or locks.
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(align(64))]
struct Cursor(AtomicUsize);
pub(crate) struct Ring<T> {
    head: Cursor,
    tail: Cursor,
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
}
// SAFETY: callers must uphold the one-producer/one-consumer contract below.
unsafe impl<T: Send> Send for Ring<T> {}
unsafe impl<T: Send> Sync for Ring<T> {}
impl<T> Ring<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two() && capacity <= 65_536);
        Self {
            head: Cursor(AtomicUsize::new(0)),
            tail: Cursor(AtomicUsize::new(0)),
            slots: (0..capacity)
                .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
                .collect(),
            mask: capacity - 1,
        }
    }
    pub(crate) fn has_space(&self) -> bool {
        self.tail
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.0.load(Ordering::Acquire))
            < self.slots.len()
    }
    pub(crate) fn has_value(&self) -> bool {
        self.tail.0.load(Ordering::Acquire) != self.head.0.load(Ordering::Acquire)
    }
    /// SAFETY: only the unique producer may call push; calls may not overlap.
    pub(crate) unsafe fn push(&self, value: T) -> Result<(), T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.head.0.load(Ordering::Acquire)) == self.slots.len() {
            return Err(value);
        }
        unsafe {
            (*self.slots[tail & self.mask].get()).write(value);
        }
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }
    /// SAFETY: only the unique consumer may peek, and must end the borrow before pop.
    pub(crate) unsafe fn peek(&self) -> Option<&T> {
        let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) { return None; }
        Some(unsafe { (*self.slots[head & self.mask].get()).assume_init_ref() })
    }
    /// SAFETY: only the unique consumer may call pop; calls may not overlap.
    pub(crate) unsafe fn pop(&self) -> Option<T> {
        let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) {
            return None;
        }
        let value = unsafe { (*self.slots[head & self.mask].get()).assume_init_read() };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}
impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        while unsafe { self.pop() }.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicUsize};
    #[test]
    fn million_owned_values_cross_threads_in_order_exactly_once() {
        struct Item {
            sequence: usize,
            drops: Arc<AtomicUsize>,
            bytes: Vec<u8>,
        }
        impl Drop for Item {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        let ring = Arc::new(Ring::new(8));
        let drops = Arc::new(AtomicUsize::new(0));
        let producer_ring = ring.clone();
        let producer_drops = drops.clone();
        let producer = std::thread::spawn(move || {
            for sequence in 0..1_000_000 {
                let mut item = Item {
                    sequence,
                    drops: producer_drops.clone(),
                    bytes: vec![(sequence % 251) as u8; 19],
                };
                loop {
                    match unsafe { producer_ring.push(item) } {
                        Ok(()) => break,
                        Err(v) => {
                            item = v;
                            std::thread::yield_now();
                        }
                    }
                }
            }
        });
        for expected in 0..1_000_000 {
            let item = loop {
                if let Some(v) = unsafe { ring.pop() } {
                    break v;
                }
                std::thread::yield_now();
            };
            assert_eq!(item.sequence, expected);
            assert_eq!(item.bytes, vec![(expected % 251) as u8; 19]);
        }
        producer.join().unwrap();
        assert!(!ring.has_value());
        assert_eq!(drops.load(Ordering::Relaxed), 1_000_000);
    }
    #[test]
    fn wrap_full_and_drop_queued_values() {
        let mut ring = Ring::new(2);
        ring.head.0.store(usize::MAX - 1, Ordering::Relaxed);
        ring.tail.0.store(usize::MAX - 1, Ordering::Relaxed);
        for n in 0..20 {
            unsafe {
                ring.push(n).unwrap();
            }
            assert_eq!(unsafe { ring.pop() }, Some(n));
        }
        let drops = Arc::new(AtomicUsize::new(0));
        struct Count(Arc<AtomicUsize>);
        impl Drop for Count {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let ring = Ring::new(2);
        assert!(unsafe { ring.push(Count(drops.clone())) }.is_ok());
        assert!(unsafe { ring.push(Count(drops.clone())) }.is_ok());
        assert!(!ring.has_space());
        assert!(unsafe { ring.push(Count(drops.clone())) }.is_err());
        drop(ring);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }
}
