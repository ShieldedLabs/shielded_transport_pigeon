//! Loopback throughput/latency matrix with every role on its own named thread:
//! pump-a (sender's Pump), pump-b (receiver's Pump), app-send, app-recv.
//! CSV on stdout: metric,payload,mode,value,unit. Progress on stderr.
//!
//! Usage: throughput_matrix [--only <cell>] [--min-secs S] [--max-secs S]
//!   cell names: msg-16B-w32 msg-100B-deep bulk-1MiB-pipe bulk-16MiB-saw ...
//!   (--only skips idle/latency; use it to profile one cell for longer).
//!
//! Porting: everything API-specific lives in `mod api` directly below. The
//! harness only uses: Ep, Peer, AppEvent, setup(), connect(), try_send(),
//! poll(), park(), request_stats().
//!
//! Linux-only: reads /proc and uses Linux libc ABI values (CLOCK_PROCESS_CPUTIME_ID 2,
//! gettid, /proc/self/task/*/schedstat). Other targets build a stub that exits 2; the portable
//! benchmark is `portable_smoke`. The body is not re-indented inside `mod linux`.
#[cfg(target_os = "linux")]
mod linux {
use std::collections::VecDeque;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::time::{Duration, Instant};

// ======================= API ADAPTER (port only this) =======================
mod api {
    use shielded_transport_pigeon::{pump::port::lockfree::*, stp::*};
    use std::time::{Duration, Instant};
    pub use shielded_transport_pigeon::stp::Pump;
    pub type Ep = LockfreeEndpoint;
    pub type Peer = ConnectionKey;
    pub const RING_CAPACITY: usize = 8192;
    pub const SEND_BUFFER: (u32, u32, u32) = (1_000_000, 32 << 20, 32 << 20);
    pub const MAX_MESSAGE: usize = 32 << 20;

    #[derive(Default, Clone, Copy, Debug)]
    pub struct Stats {
        pub cc_rate_pps: f64,
        pub packets_sent: u64,
        pub bytes_sent: u64,
        pub rtt_us: u64,
        pub kernel_rx_drops: u64,
        pub recv_queue_dropped: u64,
        pub pump_cpu_us: u64,
    }
    pub enum AppEvent {
        Message(Vec<u8>),
        /// Protocol send queue refused it; payload returned for retry.
        Rejected(Vec<u8>),
        Stats(Stats),
    }
    pub fn setup() -> (Pump, Ep, STPAddress) {
        let probe = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
        let address = STPAddress::from(std::net::Ipv6Addr::LOCALHOST, port, &key);
        let (pump, endpoint) = new_pump_with_options(vec![key], port, None, SEND_BUFFER, MAX_MESSAGE,
            NetworkThreadOptions { rings: RingConfig { send: RING_CAPACITY, control: RING_CAPACITY, receive: RING_CAPACITY }, ..Default::default() });
        (pump, endpoint, address)
    }
    /// Pumps must already be running on their threads.
    pub fn connect(a: &mut Ep, b: &mut Ep, address: STPAddress) -> Peer {
        let target = address.connection_key();
        while !a.try_connect(address.clone()) { std::thread::yield_now(); }
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut outgoing, mut incoming) = (false, false);
        while !outgoing || !incoming {
            while let Some(event) = a.try_recv() { if let Event::Connected { peer, .. } = event { outgoing |= peer == target; } }
            while let Some(event) = b.try_recv() { if let Event::Connected { .. } = event { incoming = true; } }
            assert!(Instant::now() < deadline, "connect/accept timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
        target
    }
    #[inline]
    pub fn try_send(ep: &mut Ep, peer: Peer, payload: &mut Vec<u8>) -> bool {
        ep.try_send(peer, 0, Dscp::BestEffort, payload)
    }
    pub fn request_stats(ep: &mut Ep) -> bool { ep.request_protocol_stats(); true }
    #[inline]
    pub fn poll(ep: &mut Ep, f: &mut impl FnMut(AppEvent)) -> usize {
        let mut n = 0;
        while let Some(event) = ep.try_recv() {
            n += 1;
            if let Event::Message { data, .. } = event { f(AppEvent::Message(data)); }
        }
        if let Some(u) = ep.try_protocol_stats() {
            n += 1;
            if let Some((_, s)) = u.connection_stats.first() {
                f(AppEvent::Stats(Stats {
                    cc_rate_pps: s.cc_rate_upps as f64 / 1e6,
                    packets_sent: s.packets_sent, bytes_sent: s.bytes_sent, rtt_us: s.rtt_us,
                    kernel_rx_drops: u.thread_stats.kernel_rx_drops.unwrap_or(0),
                    recv_queue_dropped: u.thread_stats.recv_queue_dropped_messages + ep.stats().receive_dropped_full,
                    pump_cpu_us: s.network_cpu_user_us + s.network_cpu_sys_us,
                }));
            }
        }
        n
    }
    /// Block until this endpoint may have new events or command space.
    pub fn park(ep: &mut Ep) { ep.park_until_ready(); }
}
// ============================ END API ADAPTER ===============================
use api::{AppEvent, Ep, Peer, Stats};

#[allow(non_camel_case_types, dead_code)]
mod libc {
    use std::os::raw::{c_int, c_long};
    pub const STDOUT_FILENO: c_int = 1;
    pub const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
    pub type time_t = c_long;
    #[repr(C)] pub struct timespec { pub tv_sec: time_t, pub tv_nsec: c_long }
    unsafe extern "C" {
        pub fn dup(fd: c_int) -> c_int;
        pub fn dup2(old: c_int, new: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn clock_gettime(clk: c_int, ts: *mut timespec) -> c_int;
        pub fn gettid() -> c_int;
    }
}
struct QuietStdout(i32);
impl QuietStdout {
    fn new() -> Self {
        std::io::stdout().flush().unwrap();
        let null = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0);
        assert!(unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } >= 0);
        Self(saved)
    }
}
impl Drop for QuietStdout {
    fn drop(&mut self) {
        std::io::stdout().flush().unwrap();
        unsafe { libc::dup2(self.0, libc::STDOUT_FILENO); libc::close(self.0); }
    }
}

fn epoch() -> Instant { static E: OnceLock<Instant> = OnceLock::new(); *E.get_or_init(Instant::now) }
fn now_ns() -> u64 { epoch().elapsed().as_nanos() as u64 }
fn gettid() -> i32 { unsafe { libc::gettid() } }
/// Thread run time in ns from schedstat (ns resolution).
fn thread_cpu_ns(tid: i32) -> u64 {
    std::fs::read_to_string(format!("/proc/self/task/{tid}/schedstat"))
        .ok().and_then(|s| s.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}
fn process_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) }, 0);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

const SENTINEL: u64 = u64::MAX;
/// Payload: [0..8] id, [8..16] send time ns, then PATTERN[id%251 ..].
struct Pattern(Vec<u8>);
impl Pattern {
    fn new(max: usize) -> Self { Self((0..max + 251).map(|i| (i % 251) as u8).collect()) }
    fn body(&self, id: u64, len: usize) -> &[u8] { let o = (id % 251) as usize; &self.0[o + 16..o + len] }
    fn make(&self, id: u64, len: usize, timestamp_ns: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&timestamp_ns.to_le_bytes());
        v.extend_from_slice(self.body(id, len));
        v
    }
}

struct PumpThread { cancel: Arc<AtomicBool>, join: Option<std::thread::JoinHandle<()>>, tid: i32 }
impl PumpThread {
    fn start(mut pump: api::Pump, name: &str) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let tid = Arc::new(AtomicI32::new(0));
        let t2 = tid.clone();
        let join = std::thread::Builder::new().name(name.into()).spawn(move || {
            t2.store(gettid(), Ordering::Release);
            while !stop.load(Ordering::Acquire) { pump.run_for(Duration::from_millis(100)); }
        }).unwrap();
        while tid.load(Ordering::Acquire) == 0 { std::thread::yield_now(); }
        Self { cancel, join: Some(join), tid: tid.load(Ordering::Acquire) }
    }
}
impl Drop for PumpThread {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(j) = self.join.take() { j.join().unwrap(); }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind { Msg, Bulk, Latency }
#[derive(Clone)]
struct Cell { name: String, kind: Kind, size: usize, window: usize, mode: &'static str, label: String,
    min_secs: f64, max_secs: f64, min_bytes: u64, fixed_count: Option<u64>, gap: Duration }

#[derive(Default)]
struct Shared {
    received: AtomicU64,
    received_bytes: AtomicU64,
    sender_waiting: AtomicBool,
    receiver_done: AtomicBool,
    t0_ns: AtomicU64,
    last_recv_ns: AtomicU64,
}
struct SendOut { issued: u64, rejected: u64, stats: Vec<(u64, Stats)>, mid: Option<usize>, stop_idx: Option<usize> }
struct RecvOut { received: u64, bytes: u64, bad: u64, dup: u64, latencies_us: Vec<f64>, stats: Vec<Stats> }

fn sender(mut ep: Ep, peer: Peer, cell: Cell, sh: Arc<Shared>, pat: Arc<Pattern>, start: Arc<Barrier>) -> (Ep, SendOut) {
    start.wait();
    let t0 = Instant::now();
    sh.t0_ns.store(now_ns(), Ordering::Release);
    let mut out = SendOut { issued: 0, rejected: 0, stats: Vec::new(), mid: None, stop_idx: None };
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut slot: Vec<u8> = Vec::new(); // payload awaiting ring space
    let mut issued_bytes = 0u64;
    let mut stopping = false;
    let mut mid_requested = false;
    let mut stop_requested_stats = false;
    let mut stats_requests = 0usize;
    if api::request_stats(&mut ep) { stats_requests += 1; }
    let mut last_progress = (0u64, Instant::now());
    loop {
        let mut rejected_now = false;
        api::poll(&mut ep, &mut |ev| match ev {
            AppEvent::Rejected(p) => { pending.push_back(p); out.rejected += 1; rejected_now = true; }
            AppEvent::Stats(s) => out.stats.push((now_ns(), s)),
            AppEvent::Message(_) => {}
        });
        let batch_now = Instant::now();
        let elapsed = batch_now.duration_since(t0).as_secs_f64();
        if !mid_requested && elapsed >= cell.min_secs / 2.0 && cell.kind != Kind::Latency {
            mid_requested = api::request_stats(&mut ep);
            if mid_requested { stats_requests += 1; out.mid = Some(stats_requests); }
        }
        if !stopping {
            stopping = match cell.fixed_count {
                Some(n) => out.issued >= n,
                None => (elapsed >= cell.min_secs && issued_bytes >= cell.min_bytes) || elapsed >= cell.max_secs,
            };
        }
        if stopping && !stop_requested_stats && cell.kind != Kind::Latency {
            stop_requested_stats = api::request_stats(&mut ep);
            if stop_requested_stats { stats_requests += 1; out.stop_idx = Some(stats_requests); }
        }
        let received = sh.received.load(Ordering::Acquire);
        if received != last_progress.0 { last_progress = (received, batch_now); }
        if stopping && slot.is_empty() && pending.is_empty() && received >= out.issued { break; }
        if batch_now.duration_since(last_progress.1) > Duration::from_secs(10) {
            eprintln!("  {}: no progress for 10 s, issued {} received {}", cell.name, out.issued, received);
            break;
        }
        if rejected_now { std::thread::park_timeout(Duration::from_millis(1)); }
        // Amortize application clock/progress bookkeeping over 64 sends.
        // Throughput payloads need no timestamp; only latency samples read the
        // clock per message, after their deliberate quiet period.
        let mut sent_any = false;
        for _ in 0..64 {
            let received = sh.received.load(Ordering::Acquire);
            if slot.is_empty() {
                if let Some(p) = pending.pop_front() { slot = p; }
                else if !stopping && out.issued - received < cell.window as u64
                    && cell.fixed_count.is_none_or(|n| out.issued < n) {
                    let stamp = if cell.kind == Kind::Latency { std::thread::sleep(cell.gap); now_ns() } else { 0 };
                    slot = pat.make(out.issued, cell.size, stamp);
                    out.issued += 1;
                    issued_bytes += cell.size as u64;
                }
            }
            if slot.is_empty() { break; }
            if !api::try_send(&mut ep, peer, &mut slot) { api::park(&mut ep); break; }
            sent_any = true;
        }
        if sent_any || !slot.is_empty() { continue; }
        // Window full (or draining): wait for the receiver.
        sh.sender_waiting.store(true, Ordering::SeqCst);
        if sh.received.load(Ordering::SeqCst) == received {
            std::thread::park_timeout(Duration::from_millis(5));
        }
        sh.sender_waiting.store(false, Ordering::SeqCst);
    }
    // Ask the receiver to exit; repeat in case a sentinel is lost.
    while !sh.receiver_done.load(Ordering::Acquire) {
        let mut s = pat.make(SENTINEL, 16, 0);
        while !api::try_send(&mut ep, peer, &mut s) { api::poll(&mut ep, &mut |_| {}); std::thread::yield_now(); }
        for _ in 0..50 {
            api::poll(&mut ep, &mut |ev| if let AppEvent::Stats(s) = ev { out.stats.push((now_ns(), s)) });
            if sh.receiver_done.load(Ordering::Acquire) { break; }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // Make sure the requested stats responses arrived.
    let want = stats_requests;
    let until = Instant::now() + Duration::from_secs(3);
    while out.stats.len() < want && Instant::now() < until {
        api::poll(&mut ep, &mut |ev| if let AppEvent::Stats(s) = ev { out.stats.push((now_ns(), s)) });
        std::thread::sleep(Duration::from_millis(1));
    }
    (ep, out)
}

fn receiver(mut ep: Ep, cell: Cell, sh: Arc<Shared>, pat: Arc<Pattern>, start: Arc<Barrier>, send_thread: std::thread::Thread) -> (Ep, RecvOut) {
    let mut out = RecvOut { received: 0, bytes: 0, bad: 0, dup: 0, latencies_us: Vec::new(), stats: Vec::new() };
    let mut seen: Vec<u64> = Vec::new();
    start.wait();
    api::request_stats(&mut ep);
    let mut done = false;
    while !done {
        let before = out.received;
        let n = api::poll(&mut ep, &mut |ev| match ev {
            AppEvent::Message(m) => {
                let t = if cell.kind == Kind::Latency { now_ns() } else { 0 };
                if m.len() < 16 { out.bad += 1; return; }
                let id = u64::from_le_bytes(m[..8].try_into().unwrap());
                if id == SENTINEL { sh.last_recv_ns.store(now_ns(), Ordering::Relaxed); done = true; return; }
                if m.len() != cell.size || m[16..] != *pat.body(id, cell.size) { out.bad += 1; return; }
                let (w, b) = ((id / 64) as usize, 1u64 << (id % 64));
                if seen.len() <= w { seen.resize(w + 1024, 0); }
                if seen[w] & b != 0 { out.dup += 1; return; }
                seen[w] |= b;
                if cell.kind == Kind::Latency {
                    let sent = u64::from_le_bytes(m[8..16].try_into().unwrap());
                    out.latencies_us.push(t.saturating_sub(sent) as f64 / 1e3);
                }
                out.received += 1;
                out.bytes += m.len() as u64;

            }
            AppEvent::Stats(s) => out.stats.push(s),
            AppEvent::Rejected(_) => {}
        });
        if out.received != before {
            sh.received_bytes.store(out.bytes, Ordering::Release);
            sh.received.store(out.received, Ordering::SeqCst);
            if sh.sender_waiting.load(Ordering::SeqCst) { send_thread.unpark(); }
        }
        if n == 0 && !done { api::park(&mut ep); }
    }
    sh.receiver_done.store(true, Ordering::Release);
    api::request_stats(&mut ep);
    let until = Instant::now() + Duration::from_secs(3);
    while out.stats.len() < 2 && Instant::now() < until {
        api::poll(&mut ep, &mut |ev| if let AppEvent::Stats(s) = ev { out.stats.push(s) });
        std::thread::sleep(Duration::from_millis(1));
    }
    (ep, out)
}

struct Csv(Vec<String>);
impl Csv {
    fn row(&mut self, metric: &str, payload: &str, mode: &str, value: f64, unit: &str) {
        let line = format!("{metric},{payload},{mode},{value:.3},{unit}");
        eprintln!("  {line}");
        self.0.push(line);
    }
}

fn run_cell(cell: &Cell, a: Ep, b: Ep, peer: Peer, pumps: (i32, i32), pat: &Arc<Pattern>, csv: &mut Csv) -> (Ep, Ep, Vec<f64>) {
    eprintln!("cell {}", cell.name);
    let sh = Arc::new(Shared::default());
    let start = Arc::new(Barrier::new(3));
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let gate = Arc::new(Barrier::new(3)); // end of measured phase
    let release = Arc::new(Barrier::new(3)); // threads may exit
    let (c1, s1, p1, st1, tx1, g1, r1) = (cell.clone(), sh.clone(), pat.clone(), start.clone(), tid_tx.clone(), gate.clone(), release.clone());
    let send = std::thread::Builder::new().name("app-send".into()).spawn(move || {
        tx1.send(("send", gettid())).unwrap();
        let r = sender(a, peer, c1, s1, p1, st1);
        g1.wait(); r1.wait(); r
    }).unwrap();
    let send_thread = send.thread().clone();
    let (c2, s2, p2, st2, g2, r2) = (cell.clone(), sh.clone(), pat.clone(), start.clone(), gate.clone(), release.clone());
    let recv = std::thread::Builder::new().name("app-recv".into()).spawn(move || {
        tid_tx.send(("recv", gettid())).unwrap();
        let r = receiver(b, c2, s2, p2, st2, send_thread);
        g2.wait(); r2.wait(); r
    }).unwrap();
    let mut tids = vec![("pump_a", pumps.0), ("pump_b", pumps.1)];
    for _ in 0..2 { let (n, t) = tid_rx.recv().unwrap(); tids.push((if n == "send" { "app_send" } else { "app_recv" }, t)); }
    let cpu0: Vec<u64> = tids.iter().map(|t| thread_cpu_ns(t.1)).collect();
    let pcpu0 = process_cpu_ns();
    start.wait();
    let w0 = Instant::now();
    gate.wait();
    let wall = w0.elapsed().as_secs_f64();
    let cpu1: Vec<u64> = tids.iter().map(|t| thread_cpu_ns(t.1)).collect();
    let pcpu1 = process_cpu_ns();
    release.wait();
    let (a, so) = send.join().unwrap();
    let (b, ro) = recv.join().unwrap();

    let (p, m) = (cell.label.as_str(), cell.mode);
    let span = (sh.last_recv_ns.load(Ordering::Relaxed).saturating_sub(sh.t0_ns.load(Ordering::Relaxed))) as f64 / 1e9;
    match cell.kind {
        Kind::Msg => csv.row("msg_rate", p, m, ro.received as f64 / span, "msg/s"),
        Kind::Bulk => csv.row("bulk_rate", p, m, ro.bytes as f64 / span / 1e6, "MB/s"),
        Kind::Latency => {}
    }
    if cell.kind != Kind::Latency {
        csv.row("messages", p, m, ro.received as f64, "count");
        csv.row("bytes", p, m, ro.bytes as f64, "B");
        csv.row("span", p, m, span, "s");
    }
    csv.row("lost", p, m, (so.issued - ro.received) as f64, "count");
    csv.row("bad_payload", p, m, ro.bad as f64, "count");
    csv.row("duplicates", p, m, ro.dup as f64, "count");
    csv.row("send_rejected", p, m, so.rejected as f64, "count");
    for (i, (name, _)) in tids.iter().enumerate() {
        csv.row(&format!("cpu_{name}"), p, m, (cpu1[i] - cpu0[i]) as f64 / 1e9 / wall * 100.0, "percent");
    }
    csv.row("cpu_process", p, m, (pcpu1 - pcpu0) as f64 / 1e9 / wall * 100.0, "percent");
    // CC: target at mid and at stop; achieved data-packet rate start->mid.
    let st = &so.stats;
    if let (Some(first), Some(mi)) = (st.first(), so.mid.and_then(|i| st.get(i - 1))) {
        let dt = (mi.0 - first.0) as f64 / 1e9;
        csv.row("cc_target_mid", p, m, mi.1.cc_rate_pps, "pkt/s");
        csv.row("achieved_pps", p, m, (mi.1.packets_sent - first.1.packets_sent) as f64 / dt, "pkt/s");
        csv.row("wire_MBps", p, m, (mi.1.bytes_sent - first.1.bytes_sent) as f64 / dt / 1e6, "MB/s");
        csv.row("rtt_mid", p, m, mi.1.rtt_us as f64, "us");
    }
    if let Some(s) = so.stop_idx.and_then(|i| st.get(i - 1)) { csv.row("cc_target_stop", p, m, s.1.cc_rate_pps, "pkt/s"); }
    if let (Some(f), Some(l)) = (st.first(), st.last()) {
        csv.row("sender_kernel_rx_drops", p, m, (l.1.kernel_rx_drops - f.1.kernel_rx_drops) as f64, "count");
    }
    if ro.stats.len() >= 2 {
        let (f, l) = (ro.stats[0], *ro.stats.last().unwrap());
        csv.row("recv_kernel_rx_drops", p, m, (l.kernel_rx_drops - f.kernel_rx_drops) as f64, "count");
        csv.row("recv_queue_dropped", p, m, (l.recv_queue_dropped - f.recv_queue_dropped) as f64, "count");
    }
    (a, b, ro.latencies_us)
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| args.iter().position(|a| a == k).map(|i| args[i + 1].clone());
    let only = arg("--only");
    let min_secs: f64 = arg("--min-secs").map_or(2.0, |s| s.parse().unwrap());
    let max_secs: f64 = arg("--max-secs").map_or(25.0, |s| s.parse().unwrap());
    epoch();
    let mut cells = Vec::new();
    for (size, label) in [(16usize, "16B"), (100, "100B"), (1000, "1KB")] {
        for (window, mode) in [(32usize, "w32"), (api::RING_CAPACITY, "deep")] {
            cells.push(Cell { name: format!("msg-{label}-{mode}"), kind: Kind::Msg, size, window, mode, label: label.into(),
                min_secs: min_secs + 0.5, max_secs, min_bytes: 0, fixed_count: None, gap: Duration::ZERO });
        }
    }
    for (size, label) in [(64usize << 10, "64KiB"), (1 << 20, "1MiB"), (16 << 20, "16MiB")] {
        let pipe = 8.min(((api::SEND_BUFFER.2 as usize) / size).max(1));
        for (window, mode) in [(pipe, "pipe"), (1, "saw")] {
            cells.push(Cell { name: format!("bulk-{label}-{mode}"), kind: Kind::Bulk, size, window, mode, label: label.into(),
                min_secs, max_secs, min_bytes: 200_000_000, fixed_count: None, gap: Duration::ZERO });
        }
    }
    if let Some(o) = &only {
        cells.retain(|c| &c.name == o);
        assert!(!cells.is_empty(), "unknown cell {o}");
    }
    let max_size = cells.iter().map(|c| c.size).max().unwrap().max(100);
    let pat = Arc::new(Pattern::new(max_size));

    let quiet = QuietStdout::new();
    let (pa, mut a, _) = api::setup();
    let (pb, mut b, address) = api::setup();
    let wa = PumpThread::start(pa, "pump-a");
    let wb = PumpThread::start(pb, "pump-b");
    let peer = api::connect(&mut a, &mut b, address);
    let mut csv = Csv(Vec::new());
    for cell in &cells {
        if cell.kind == Kind::Bulk { csv.row("window", &cell.label, cell.mode, cell.window as f64, "messages"); }
        let (na, nb, _) = run_cell(cell, a, b, peer, (wa.tid, wb.tid), &pat, &mut csv);
        a = na; b = nb;
    }
    if only.is_none() {
        // Idle: two connected endpoints, nothing draining or sending.
        std::thread::sleep(Duration::from_secs(1));
        api::poll(&mut a, &mut |_| {});
        api::poll(&mut b, &mut |_| {});
        let (c0, ta, tb) = (process_cpu_ns(), thread_cpu_ns(wa.tid), thread_cpu_ns(wb.tid));
        let t = Instant::now();
        std::thread::sleep(Duration::from_secs(10));
        let s = t.elapsed().as_secs_f64();
        csv.row("idle_cpu", "-", "idle10s", (process_cpu_ns() - c0) as f64 / 1e9 / s * 100.0, "percent");
        csv.row("idle_cpu_pump_a", "-", "idle10s", (thread_cpu_ns(wa.tid) - ta) as f64 / 1e9 / s * 100.0, "percent");
        csv.row("idle_cpu_pump_b", "-", "idle10s", (thread_cpu_ns(wb.tid) - tb) as f64 / 1e9 / s * 100.0, "percent");
        let lat = Cell { name: "latency".into(), kind: Kind::Latency, size: 100, window: 1, mode: "post_idle", label: "100B".into(),
            min_secs: 0.0, max_secs: 1e9, min_bytes: 0, fixed_count: Some(100), gap: Duration::from_millis(100) };
        let (na, nb, mut l) = run_cell(&lat, a, b, peer, (wa.tid, wb.tid), &pat, &mut csv);
        a = na; b = nb;
        l.sort_by(f64::total_cmp);
        assert_eq!(l.len(), 100, "latency samples lost");
        csv.row("latency_p50", "100B", "post_idle", l[49], "us");
        csv.row("latency_p99", "100B", "post_idle", l[98], "us");
        csv.row("latency_max", "100B", "post_idle", l[99], "us");
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let hwm: f64 = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    csv.row("peak_rss", "-", "-", hwm, "KiB");
    drop(wa); drop(wb); drop(a); drop(b);
    drop(quiet);
    println!("metric,payload,mode,value,unit");
    for l in &csv.0 { println!("{l}"); }
}
} // mod linux

#[cfg(target_os = "linux")]
fn main() { linux::main() }

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this benchmark is Linux-only (/proc, /dev/null, Linux clock ids); use the portable_smoke example on this target");
    std::process::exit(2);
}
