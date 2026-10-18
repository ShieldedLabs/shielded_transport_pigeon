//! Single-thread frame loop: no application operation executes transport work.
use shielded_transport_pigeon::pump::port::lockfree::*;
#[path = "support/lockfree_common.rs"]
mod common;
use common::*;
use std::time::{Duration, Instant};
fn main() {
    let (mut pa, mut a, _) = setup();
    let (mut pb, mut b, address) = setup();
    let peer = address.connection_key();
    assert!(a.try_send(Command::Connect(address)).is_ok());
    let mut sent = false;
    for frame_number in 0..400 {
        let frame = Instant::now();
        // Each simulated endpoint gets its own 1 ms frame-slack budget.
        pa.run_until(frame + Duration::from_millis(1));
        pb.run_until(Instant::now() + Duration::from_millis(1));
        while let Some(event) = a.try_recv() {
            if let Event::Update(update) = event {
                if !sent && !update.current_connections.is_empty() {
                    assert!(
                        a.try_send(Command::Send {
                            peer,
                            queue: 0,
                            class: shielded_transport_pigeon::stp::Dscp::BestEffort,
                            payload: b"message between frames".to_vec()
                        })
                        .is_ok()
                    );
                    sent = true;
                }
            }
        }
        while let Some(event) = b.try_recv() {
            if let Event::Update(update) = event {
                for (_, payload) in update.received_unreliable_messages {
                    println!(
                        "frame {frame_number}: {}",
                        String::from_utf8_lossy(&payload)
                    );
                    return;
                }
            }
        }
        std::thread::sleep(
            (frame + Duration::from_millis(16)).saturating_duration_since(Instant::now()),
        );
    }
    panic!("frame-loop delivery timed out");
}
