use shielded_transport_pigeon::pump::port::lockfree::*;
#[path = "support/lockfree_common.rs"] mod common;
use common::*;
fn main() { let (pa, mut a, _) = setup(); let (pb, mut b, address) = setup(); let mut worker_a = Worker::start(pa);
    let mut worker_b = Worker::start(pb); let peer = connect(&mut a, &mut b, address);
    send(&mut a, peer, b"owned rings, caller-owned threads".to_vec()); let messages = receive(&mut b, 1);
    println!("{}", String::from_utf8_lossy(&messages[0].1)); a.close(); b.close(); worker_a.stop(); worker_b.stop();
    assert!(a.is_finished() && b.is_finished()); }
