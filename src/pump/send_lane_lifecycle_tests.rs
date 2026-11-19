use super::*;
use std::time::{Duration, Instant};

#[test]
fn send_lane_close_does_not_wait_for_preempted_producer_and_repeated_close_is_safe() {
    let budget = SendBudget::new(
        SendQueueConfig::default(),
        100,
        1,
        Arc::new(Ready::default()),
    );
    let association = PeerSend::new(budget.clone(), 2);
    let producer = association.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        assert!(producer.enter());
        // Pause in the exact critical section used by lazy ring allocation and publication.
        entered_tx.send(()).unwrap();
        let _ = resume_rx.recv_timeout(Duration::from_secs(2));
        producer.budget.lanes.fetch_add(1, Ordering::Relaxed);
        let account = Arc::new(Account {
            bytes: AtomicU64::new(5),
            budget: producer.budget.clone(),
        });
        producer.budget.bytes.fetch_add(5, Ordering::Relaxed);
        producer.budget.messages.fetch_add(1, Ordering::Relaxed);
        producer.budget.pending.fetch_add(1, Ordering::Relaxed);
        assert!(
            producer.queues[0]
                .set(SendLane {
                    ring: Ring::new(2),
                    account: account.clone()
                })
                .is_ok()
        );
        assert!(
            unsafe {
                producer.queues[0].get().unwrap().ring.push(SendMessage {
                    payload: vec![7; 5],
                    class: Dscp::BestEffort,
                    charge: Charge {
                        cell: Some(account),
                        bytes: 5,
                    },
                })
            }
            .is_ok()
        );
        producer.leave(); // becomes the unique consumer and drains the accepted payload
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let start = Instant::now();
    association.close();
    association.close();
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "close waited for the producer"
    );
    assert!(!association.enter());
    resume_tx.send(()).unwrap();
    thread.join().unwrap();
    association.close();
    assert_eq!(budget.pending.load(Ordering::Relaxed), 0);
    assert_eq!(budget.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(budget.messages.load(Ordering::Relaxed), 0);
    drop(association);
    assert_eq!(budget.lanes.load(Ordering::Relaxed), 0);
}
