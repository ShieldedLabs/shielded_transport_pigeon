//! Loopback microbenchmark. Run release mode under the repository's network locks.
//! Stop-and-wait intentionally isolates API wakeup/dispatch latency from saturation.
mod api_support;
use api_support::*;
use shielded_transport_pigeon::api::Event;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
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
fn counts() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}
fn main() {
    println!(
        "kind,trial,style,size,count,wall_s,cpu_s,msg_s,MB_s,allocs_per_msg,allocated_bytes_per_msg"
    );
    for trial in 1..=3 {
        for style in STYLES {
            let (mut a, mut b, to, _, _, _) = pair(style, 1_000_000, false);
            let cpu0 = cpu();
            let wall = Instant::now();
            std::thread::sleep(Duration::from_millis(500));
            println!(
                "idle,{trial},{style:?},0,0,{:.6},{:.6},0,0,0,0",
                wall.elapsed().as_secs_f64(),
                cpu() - cpu0
            );
            for (size, count) in [(100, 200), (10_000, 100), (1_000_000, 8)] {
                let expected = blake3::hash(&payload(size, 0));
                let (alloc0, bytes0) = counts();
                let cpu0 = cpu();
                let start = Instant::now();
                for _ in 0..count {
                    a.send_timeout(to, payload(size, 0), Duration::from_secs(30))
                        .unwrap();
                    loop {
                        if let Event::Message { data, .. } =
                            b.recv(Duration::from_secs(30)).unwrap()
                        {
                            assert_eq!(data.len(), size);
                            assert_eq!(blake3::hash(&data), expected);
                            break;
                        }
                    }
                }
                let seconds = start.elapsed().as_secs_f64();
                let used_cpu = cpu() - cpu0;
                let (alloc1, bytes1) = counts();
                println!(
                    "transfer,{trial},{style:?},{size},{count},{seconds:.6},{used_cpu:.6},{:.3},{:.3},{:.2},{:.2}",
                    count as f64 / seconds,
                    count as f64 * size as f64 / seconds / 1e6,
                    (alloc1 - alloc0) as f64 / count as f64,
                    (bytes1 - bytes0) as f64 / count as f64
                );
            }
            a.close();
            b.close();
        }
    }
}
