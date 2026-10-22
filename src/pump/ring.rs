use std::cell::UnsafeCell; use std::mem::MaybeUninit; use std::sync::atomic::{AtomicUsize, Ordering};
#[repr(align(64))] struct Cursor(AtomicUsize);
pub(crate) struct Ring<T> { head: Cursor, tail: Cursor, slots: Box<[UnsafeCell<MaybeUninit<T>>]>, mask: usize, }
// SAFETY: callers must uphold the one-producer/one-consumer contract below.
unsafe impl<T: Send> Send for Ring<T> {}
unsafe impl<T: Send> Sync for Ring<T> {}
impl<T> Ring<T> {
    pub(crate) fn new(capacity: usize) -> Self { assert!(capacity.is_power_of_two() && capacity <= 65_536);
        Self {
            head: Cursor(AtomicUsize::new(0)), tail: Cursor(AtomicUsize::new(0)),
            slots: (0..capacity).map(|_| UnsafeCell::new(MaybeUninit::uninit())).collect(),
            mask: capacity - 1, } }
    pub(crate) fn has_space(&self) -> bool {
        self.tail.0.load(Ordering::Acquire).wrapping_sub(self.head.0.load(Ordering::Acquire)) < self.slots.len() }
    pub(crate) fn has_value(&self) -> bool {
        self.tail.0.load(Ordering::Acquire) != self.head.0.load(Ordering::Acquire) }
    /// SAFETY: only the unique producer may call push; calls may not overlap.
    pub(crate) unsafe fn push(&self, value: T) -> Result<(), T> { let tail = self.tail.0.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.head.0.load(Ordering::Acquire)) == self.slots.len() { return Err(value); }
        unsafe { (*self.slots[tail & self.mask].get()).write(value); }
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(()) }
    /// SAFETY: only the unique consumer may peek, and must end the borrow before pop.
    pub(crate) unsafe fn peek(&self) -> Option<&T> { let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) { return None; }
        Some(unsafe { (*self.slots[head & self.mask].get()).assume_init_ref() }) }
    /// SAFETY: only the unique consumer may call pop; calls may not overlap.
    pub(crate) unsafe fn pop(&self) -> Option<T> { let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) { return None; }
        let value = unsafe { (*self.slots[head & self.mask].get()).assume_init_read() };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(value) } }
impl<T> Drop for Ring<T> { fn drop(&mut self) { while unsafe { self.pop() }.is_some() {} } }
