//! Encrypted IPv6 loopback, decimal MB, process-wide CPU and peak RSS.
//! Run three independent processes; report medians of the CSV metric values.
#[path = "support/lockfree_common.rs"]
mod common;
use common::*;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
// Frozen core emits handshake diagnostics on stdout. Suppress only this
// process's diagnostics while measuring so the benchmark emits valid CSV.
struct QuietStdout(i32);
impl QuietStdout {
    fn new() -> Self {
        std::io::stdout().flush().unwrap();
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0);
        assert!(unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } >= 0);
        Self(saved)
    }
}
impl Drop for QuietStdout {
    fn drop(&mut self) {
        std::io::stdout().flush().unwrap();
        unsafe {
            libc::dup2(self.0, libc::STDOUT_FILENO);
            libc::close(self.0);
        }
    }
}
/// Process CPU time with ns resolution (the tick counter has 10 ms granularity).
fn cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) }, 0);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}
fn main() {
    let quiet = QuietStdout::new();
    let (pa, mut a, _) = setup();
    let (pb, mut b, address) = setup();
    let _wa = Worker::start(pa);
    let _wb = Worker::start(pb);
    let peer = connect(&mut a, &mut b, address);
    let start = Instant::now();
    for sequence in 0..100 {
        send(&mut a, peer, vec![sequence as u8; 1_000_000]);
        let messages = receive(&mut b, 1);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].1, vec![sequence as u8; 1_000_000]);
        drain(&mut a);
    }
    let mbps = 100.0 / start.elapsed().as_secs_f64();
    let start = Instant::now();
    let mut sent = 0usize;
    let mut received = 0usize;
    let mut seen = vec![false; 4096];
    while received < 4096 {
        while sent < 4096 && sent - received < 32 {
            let mut bytes = vec![0; 100];
            bytes[..8].copy_from_slice(&(sent as u64).to_le_bytes());
            send(&mut a, peer, bytes);
            sent += 1;
        }
        // Match the sibling benchmarks: block for at least one message, then
        // drain the ready batch. A timed polling sleep caps small-message rate.
        for (_, payload) in receive(&mut b, 1) {
            assert_eq!(payload.len(), 100);
            let id = u64::from_le_bytes(payload[..8].try_into().unwrap()) as usize;
            assert!(id < 4096 && !seen[id]);
            seen[id] = true;
            received += 1;
        }
        drain(&mut a);
        assert!(start.elapsed() < Duration::from_secs(30));
    }
    let msgps = 4096.0 / start.elapsed().as_secs_f64();
    // Let congestion/ACK work settle before measuring two connected idle pumps.
    std::thread::sleep(Duration::from_secs(1));
    drain(&mut a);
    drain(&mut b);
    let ticks = cpu_ticks();
    let ns = cpu_ns();
    let idle_start = Instant::now();
    std::thread::sleep(Duration::from_secs(10));
    let idle_seconds = idle_start.elapsed().as_secs_f64();
    let idle_ns = cpu_ns() - ns;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let idle_cpu = (cpu_ticks() - ticks) as f64 / hz;
    let mut latency_us = Vec::new();
    for n in 0..100 {
        // Each sample is post-idle, not a hot burst after the one 10 s pause.
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        send(&mut a, peer, vec![n; 100]);
        assert_eq!(receive(&mut b, 1)[0].1, vec![n; 100]);
        latency_us.push(start.elapsed().as_secs_f64() * 1e6);
        drain(&mut a);
    }
    latency_us.sort_by(f64::total_cmp);
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let rss_kib: u64 = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    drop(quiet);
    println!("metric,value,unit");
    println!("stop_wait_100x1MB,{mbps:.3},MB/s");
    println!("window32_4096x100B,{msgps:.3},msg/s");
    println!("idle_cpu_10s,{idle_cpu:.6},CPU-s");
    println!(
        "idle_cpu_percent,{:.3},percent",
        idle_cpu / idle_seconds * 100.0
    );
    println!("idle_cpu_percent_ns,{:.4},percent", idle_ns as f64 / 1e9 / idle_seconds * 100.0);
    println!("post_idle_p50,{:.3},us", latency_us[49]);
    println!("post_idle_p99,{:.3},us", latency_us[98]);
    println!("post_idle_max,{:.3},us", latency_us[99]);
    println!("peak_rss,{rss_kib},KiB");
}
