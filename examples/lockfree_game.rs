use shielded_transport_pigeon::pump::Event;
#[path = "support/lockfree_common.rs"]
mod common;
use common::*;
use std::time::{Duration, Instant};
fn main() {
    let (mut pa, mut a, _) = setup();
    let (mut pb, mut b, address) = setup();
    let peer = address.connection_key();
    assert!(a.try_connect(address));
    let mut sent = false;
    for frame_number in 0..400 {
        let frame = Instant::now();
        pa.run_until(frame + Duration::from_millis(1));
        pb.run_for(Duration::from_millis(1));
        while let Some(event) = a.try_recv() {
            if matches!(event, Event::Connected { .. }) && !sent {
                send(&mut a, peer, b"message between frames".to_vec());
                sent = true;
            }
        }
        while let Some(event) = b.try_recv() {
            if let Event::Message { data, .. } = event {
                println!("frame {frame_number}: {}", String::from_utf8_lossy(&data));
                return;
            }
        }
        std::thread::sleep(
            (frame + Duration::from_millis(16)).saturating_duration_since(Instant::now()),
        );
    }
    panic!("frame-loop delivery timed out");
}
