//! Paired idle CPU + post-idle application-send-to-delivery latency measurement.
mod api_support;
use api_support::*;
use shielded_transport_pigeon::api::Event;
use std::time::{Duration, Instant};
fn cpu() -> f64 {
    let mut r = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()) },
        0
    );
    let r = unsafe { r.assume_init() };
    (r.ru_utime.tv_sec + r.ru_stime.tv_sec) as f64
        + (r.ru_utime.tv_usec + r.ru_stime.tv_usec) as f64 / 1e6
}
fn main() {
    println!("kind,trial,style,cap_ms,samples,idle_cpu_percent,p50_us,p99_us");
    for trial in 1..=3 {
        for cap_ms in [1, 2, 8] {
            for style in STYLES {
                if matches!(style, Style::Core) && cap_ms != 1 {
                    continue;
                }
                let (mut a, mut b, to, _, _, _) =
                    pair_with_idle_cap(style, 1_000_000, false, Duration::from_millis(cap_ms));
                let start = Instant::now();
                let cpu0 = cpu();
                std::thread::sleep(Duration::from_secs(1));
                let idle_cpu = (cpu() - cpu0) / start.elapsed().as_secs_f64() * 100.0;
                let mut latencies = Vec::with_capacity(100);
                for i in 0..100 {
                    // Deterministic idle jitter avoids phase-locking to the service cadence.
                    std::thread::sleep(Duration::from_micros(25_000 + (i * 7919) % 10_000));
                    let start = Instant::now();
                    a.send_timeout(to, vec![7; 100], Duration::from_secs(5))
                        .unwrap();
                    loop {
                        if let Event::Message { data, .. } = b.recv(Duration::from_secs(5)).unwrap()
                        {
                            assert_eq!(data, vec![7; 100]);
                            break;
                        }
                    }
                    latencies.push(start.elapsed().as_secs_f64() * 1e6);
                }
                latencies.sort_by(f64::total_cmp);
                println!(
                    "latency,{trial},{style:?},{cap_ms},100,{idle_cpu:.4},{:.2},{:.2}",
                    latencies[49], latencies[98]
                );
                a.close();
                b.close();
            }
        }
    }
}
