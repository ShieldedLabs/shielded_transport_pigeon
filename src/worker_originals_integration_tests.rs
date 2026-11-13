//! Exercise the real synchronous worker job, leases, clocks and completions.
use super::*;
use crate::receive_memory::ReceiveMemoryBudget;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

struct Harness {
    layout: crate::fec::MessageLayout,
    bytes: Vec<u8>,
    charge: usize,
    process: Arc<ReceiveMemoryBudget>,
    budget: Arc<ReceiveMemoryBudget>,
    workers: Arc<AtomicUsize>,
    slot: FecRecvSlot,
    tx: mpsc::Sender<FecCompletion>,
    rx: mpsc::Receiver<FecCompletion>,
}
impl Harness {
    fn new(limit_adjust: isize, worker_limit: usize) -> Self {
        let layout = wire_fec_layout(257 * FEC_MIN_BLOCK_BYTES - 17, FEC_MIN_BLOCK_BYTES).unwrap();
        let charge =
            crate::fec::receive_memory_charge(layout, true, fec_ingress_bytes(layout)).unwrap();
        let process = ReceiveMemoryBudget::new(4 * charge);
        let budget = ReceiveMemoryBudget::connection_with_limit(
            &process,
            (2 * charge).checked_add_signed(limit_adjust).unwrap(),
        )
        .with_worker_limit(worker_limit);
        let (tx, rx) = mpsc::channel();
        Self {
            layout,
            bytes: (0..layout.len).map(|i| (i ^ (i / 241)) as u8).collect(),
            charge,
            process,
            budget,
            workers: Arc::new(AtomicUsize::new(0)),
            slot: FecRecvSlot {
                package_id: 17,
                ..Default::default()
            },
            tx,
            rx,
        }
    }
    fn add(&mut self, id: usize, conflict: bool) {
        let start = id * self.layout.block_bytes;
        let mut bytes =
            self.bytes[start..(start + self.layout.block_bytes).min(self.layout.len)].to_vec();
        if conflict {
            bytes[0] ^= 1;
        }
        assert!(
            fec_receive_block_waking(
                &mut self.slot,
                ConnectionKey::default(),
                17,
                self.layout.len,
                self.layout.block_bytes,
                id as u32,
                &bytes,
                &self.tx,
                &self.workers,
                &self.budget,
                None
            )
            .is_none()
        );
    }
    fn assert_released(&self) {
        assert_eq!(self.budget.used(), 0);
        assert_eq!(self.process.used(), 0);
        assert_eq!(self.workers.load(Ordering::Acquire), 0);
        assert!(!self.budget.worker_limit_reached());
    }
}
#[test]
fn worker_originals_real_job_completion_and_stale_generation() {
    assert!(
        std::mem::size_of::<FecDecodeJob>() < 4096,
        "bitmap/job metadata fits existing per-codec allowance"
    );
    let mut h = Harness::new(0, 1);
    h.add(0, false);
    assert_eq!(
        h.budget.used(),
        h.charge,
        "retain pessimistic native charge even before decoding"
    );
    assert_eq!(h.workers.load(Ordering::Acquire), 1);
    assert!(h.budget.worker_limit_reached());
    for conflict in [false, true] {
        h.slot.last_block_ns = 1;
        h.add(0, conflict);
        assert!(
            h.slot.last_block_ns > 1,
            "accepted worker ingress refreshes clock even for duplicate/conflict"
        );
        assert_eq!(h.budget.used(), h.charge);
        assert!(h.rx.try_recv().is_err());
    }
    for id in 1..h.layout.k {
        h.add(id, false);
    }
    let completion = h.rx.try_recv().unwrap();
    assert_eq!(completion.message, h.bytes);
    assert_eq!(completion.connection_key, ConnectionKey::default());
    assert!(completion.owns(&h.slot, &h.budget));
    assert_eq!(h.workers.load(Ordering::Acquire), 0);
    assert!(!h.budget.worker_limit_reached());
    assert_eq!(
        h.budget.used(),
        h.charge,
        "completion retains full lease until consumer"
    );
    assert!(h.rx.try_recv().is_err(), "one completion only");
    let other = ReceiveMemoryBudget::connection_with_limit(&h.process, h.charge);
    assert!(
        !completion.owns(&h.slot, &other),
        "same decoder identity, different connection budget"
    );
    h.slot.state = FecRecvState::Empty;
    h.add(0, false);
    assert!(
        !completion.owns(&h.slot, &h.budget),
        "same package id, new decoder generation"
    );
    assert_eq!(h.budget.used(), 2 * h.charge);
    drop(completion);
    h.slot.state = FecRecvState::Done;
    h.assert_released();
}
#[test]
fn worker_originals_refusal_expiry_preemption_and_queued_cancel() {
    let mut h = Harness::new(0, 1);
    let held = h.budget.reserve(h.charge + 1).unwrap();
    h.add(0, false);
    assert!(h.slot.admission_refused);
    assert!(matches!(h.slot.state, FecRecvState::Empty));
    assert_eq!(h.budget.used(), h.charge + 1);
    assert_eq!(h.workers.load(Ordering::Acquire), 0);
    drop(held);
    h.assert_released();
    let parent_held = h.process.reserve(h.process.limit() - h.charge + 1).unwrap();
    h.add(0, false);
    assert!(matches!(h.slot.state, FecRecvState::Empty));
    assert_eq!(
        h.budget.used(),
        0,
        "parent refusal must not acquire child charge"
    );
    assert_eq!(h.process.used(), h.process.limit() - h.charge + 1);
    assert_eq!(h.workers.load(Ordering::Acquire), 0);
    drop(parent_held);
    h.assert_released();
    h.workers.store(MAX_FEC_DECODE_WORKERS, Ordering::Release);
    h.add(0, false);
    assert!(h.slot.worker_limit_refused);
    assert_eq!(h.budget.used(), 0);
    h.workers.store(0, Ordering::Release);
    for oldest_only in [false, true] {
        h.add(0, false);
        if let FecRecvState::Worker { tx, .. } = &h.slot.state {
            tx.try_send((1, vec![0; h.layout.block_bytes])).unwrap();
        } else {
            panic!("worker not admitted");
        }
        h.slot.last_block_ns = 1;
        h.slot.recovery_resume_ns = None;
        assert_eq!(
            retire_inactive_fec_workers(std::slice::from_mut(&mut h.slot), 10, 1, oldest_only),
            1
        );
        assert!(matches!(h.slot.state, FecRecvState::Done));
        assert!(h.rx.try_recv().is_err());
        h.assert_released();
        h.slot.state = FecRecvState::Empty;
    }
    let mut zero_workers = Harness::new(0, 0);
    zero_workers.add(0, false);
    assert!(zero_workers.slot.worker_limit_refused);
    assert_eq!(zero_workers.budget.used(), 0);
    assert_eq!(zero_workers.process.used(), 0);
    assert_eq!(zero_workers.workers.load(Ordering::Acquire), 0);
}
