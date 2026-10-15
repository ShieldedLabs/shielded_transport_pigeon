//! STP throughput / latency benchmark over the unreliable message channel (Linux).
//!
//!   stp_bench serve --port P [--bind IP] [--advertise IP] [--seed-key HEX64]
//!   stp_bench send  --to STPADDR [--seed N] [--count N] [--min 100] [--max 50000000]
//!                   [--timeout 600] [--idle 10] [--out report.json]
//!                   [--giant 256M|1G] (one whole framed message, binary units)
//!                   [--giant-warmup S] (wait up to S seconds for TU stabilization; giant default 5)
//! Report: udp_payload_tu, fec_block_bytes_by_id, receiver_fec_decode_last_tail_ms.
//! Decode tail uses the receiver clock: last accepted FEC block to delivery, excludes surplus repairs.
//! Giant demo: send --to STPADDR --giant 1G --timeout 600 --idle 30.
//! Both endpoints must support extended FEC kind 2 for messages above 64000 source blocks.
//!                   [--loss-trace events.csv] (S/F/L/A sender event CSV; see loss_trace.rs)
//!
//! Both: [--queue-us 1000000] [--queue-min 4194304] [--queue-max 67108864] [--max-pps N]
//! (the pre-existing send_buffer_params and max_pps resource limits).
//! Transport policy is fixed: slow110 loss/ECN packet-rate control, precise pacing,
//! adaptive bitmap ACKs and grouped Wirehair span-tail FEC with closed-loop top-up.
//! There are no CC, ACK, FEC or pacer tuning flags.
//! --queues N: fixed sender magazines; ordinary data ids map to id % N.
//! --traffic-classes be,af11,af21,ef: one class or one per queue.
//! --workload bulk|bulk-small|dueling --duration S: saturated 50 MiB trains;
//! bulk-small adds independent 1000 B Poisson arrivals (--small-rate 20, --small-class ef).
//! With one queue they share its FIFO, with >=2 queues small messages use queue 1.
//! dueling saturates every configured queue (--bulk-size B can shorten trains).
//! These modes stop producing at S, then drain accepted messages up to --timeout seconds.
//! Reports include per-queue completion goodput/last-byte p50,p99, plus fixed-window goodput.
//! --duration S: saturated measurement for S seconds; requests receiver status while sending.
//! --send-on-ms N --send-off-ms N: application submission duty cycle (queued packets drain normally).
//! --loss-episodes 1: record loss episode diagnostics without changing control behaviour.
//! estimator_series: [seconds, FEC estimate, sample, sent, lost, UDP bytes, RTT us, CC pps, app-limited entries].
//! --mix classes [--classes "SIZE:COUNT,..."] sends fixed counts per size class (default
//! 1000:200,65536:200,1048576:50,5242880:20,52428800:5), shuffled by --seed; the report then
//! groups by class instead of size bucket. Per class: delivery, mean redundancy actually sent.
//! Test loss injection: STP_TEST_DROP_PPM=n in the environment drops n per million outgoing
//! data packets in that process's network thread; STP_TEST_DROP_SCHEDULE="0:0.5,20:4,24:0.5,@60"
//! (seconds:percent from network thread start, optional @period repeat) varies it over time, and
//! STP_TEST_DROP_BURST=n makes drops come in runs of n packets.
//!
//! Every message, data or control, is framed [id u32 LE][total len u32 LE][blake3(payload) 32B][payload].
//! Data ids are 0..count; ids from CTRL_BASE up are control messages:
//!   PING        sender -> server  payload [sender_ns u64]
//!   PONG        server -> sender  payload [sender_ns u64][server_ns u64]
//!   STATUS_REQ  sender -> server  payload [expected count u32]
//!   STATUS      server -> sender  payload [n u32] then n x [id u32][ok u8][server_recv_ns u64]
//!                                 then [m u32] then m x u64 receiver counters (see RxReport)
//! The sender polls STATUS_REQ every second once all data is queued, and stops when the
//! server has an entry for every id, at --timeout, or when its send queue has drained and the
//! server's count has not grown for --idle seconds. The unreliable channel does not retransmit:
//! one lost UDP fragment loses the whole message, so a drained queue plus silence means lost. Control messages that are lost are
//! simply asked for again.

use shielded_transport_pigeon::stp::*;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use rand::{Rng, RngCore, SeedableRng};
use rand::seq::SliceRandom;

const HEADER: usize = 40;
const CTRL_BASE: u32 = 0xFFFF_FF00;
const PING: u32 = CTRL_BASE;
const PONG: u32 = CTRL_BASE + 1;
const STATUS_REQ: u32 = CTRL_BASE + 2;
const STATUS: u32 = CTRL_BASE + 3;

fn frame(id: u32, payload_len: usize, fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let total = HEADER + payload_len;
    let mut buf = vec![0u8; total];
    fill(&mut buf[HEADER..]);
    let hash = blake3::hash(&buf[HEADER..]);
    buf[0..4].copy_from_slice(&id.to_le_bytes());
    buf[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    buf[8..40].copy_from_slice(hash.as_bytes());
    buf
}

fn ctrl(id: u32, payload: &[u8]) -> Vec<u8> { frame(id, payload.len(), |b| b.copy_from_slice(payload)) }

enum Parsed<'a> { Ok(u32, &'a [u8]), Corrupt(u32), Malformed }

fn parse(data: &[u8]) -> Parsed<'_> {
    if data.len() < HEADER { return Parsed::Malformed; }
    let id = u32_at(data, 0);
    let len = u32_at(data, 4) as usize;
    if len != data.len() { return Parsed::Corrupt(id); }
    if blake3::hash(&data[HEADER..]).as_bytes() != &data[8..40] { return Parsed::Corrupt(id); }
    Parsed::Ok(id, &data[HEADER..])
}

fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }

struct Args(HashMap<String, String>);
impl Args {
    fn allowed(k: &str) -> bool {
        matches!(k, "port" | "bind" | "advertise" | "seed-key" | "to" | "seed" |
            "count" | "min" | "max" | "timeout" | "idle" | "out" | "giant" |
            "giant-warmup" | "queue-us" | "queue-min" | "queue-max" | "max-pps" |
            "duration" | "send-on-ms" | "send-off-ms" | "mix" | "classes" |
            "max-message-size" | "loss-trace" | "loss-episodes" | "queues" | "workload" | "bulk-size" | "small-rate" | "small-size" | "traffic-classes" | "small-class")
    }
    fn parse(it: impl Iterator<Item = String>) -> Args {
        let mut m = HashMap::new();
        let v: Vec<String> = it.collect();
        let mut i = 0;
        while i < v.len() {
            let Some(k) = v[i].strip_prefix("--") else { die(&format!("unexpected argument {}", v[i])) };
            if !Self::allowed(k) { die(&format!("unknown flag --{k}; transport tuning is not supported")); }
            let Some(val) = v.get(i + 1) else { die(&format!("--{k} needs a value")) };
            m.insert(k.to_string(), val.clone());
            i += 2;
        }
        Args(m)
    }
    fn str(&self, k: &str) -> Option<&str> { self.0.get(k).map(|s| s.as_str()) }
    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> T {
        match self.0.get(k) { None => default, Some(s) => s.parse().unwrap_or_else(|_| die(&format!("bad --{k} {s}"))) }
    }
}

fn bench_receive_budget(max_message_size: usize, queues: usize) -> std::sync::Arc<shielded_transport_pigeon::receive_memory::ReceiveMemoryBudget> {
    let cap = receive_connection_memory_limit(max_message_size, queues).unwrap_or_else(|| die("invalid queue/message-size configuration"));
    // Bench is the application: explicitly provision unusually large queue counts,
    // rather than asking the library to silently accept an impossible configuration.
    let process = (4usize << 30).max(cap + (1 << 20));
    println!("application max_message_size={max_message_size} queues={queues} per_connection_receive_cap={cap} process_receive_budget={process}");
    shielded_transport_pigeon::receive_memory::ReceiveMemoryBudget::new(process)
}

fn service_connections(handle: &NetworkThreadHandle, request: NetworkThreadPush) -> Option<NetworkThreadPull> {
    let response = shielded_transport_pigeon::stp::service_connections(handle, request)?;
    if let Some((_, _, _, message)) = response.send_unreliable_oversized.first() {
        die(&format!("{}-byte submission exceeds application max_message_size; increase --max-message-size", message.len()));
    }
    Some(response)
}

/// Server-side ground truth sent in every STATUS reply: that connection's receiver counters,
/// the server network thread's counters and the server process CPU time.
#[derive(Clone, Copy, Debug, Default)]
struct RxReport { st: ConnectionStats, th: NetworkThreadStats, cpu_user_us: u64, cpu_sys_us: u64 }
impl RxReport {
    fn to_words(&self) -> Vec<u64> {
        let (s, t) = (&self.st, &self.th);
        let mut v = vec![s.rx_packets, s.rx_seq_span, s.rx_lost, s.rx_reordered, s.rx_late_beyond_window, s.rx_duplicates, s.rx_bursts];
        v.extend_from_slice(&s.rx_burst_hist);
        v.extend_from_slice(&[t.kernel_rx_drops.unwrap_or(u64::MAX), t.max_loop_gap_ns, t.loop_gaps_over_1ms, t.loop_gaps_over_10ms, t.loop_gaps_over_100ms,
            t.loop_iterations, t.recv_queue_dropped_messages, self.cpu_user_us, self.cpu_sys_us,
            s.rx_messages_completed, s.rx_partial_evicted, s.rx_partial_evicted_bytes, s.rx_insert_failures, s.rx_stale_fragments]);
        v.extend_from_slice(&[s.fec_decode_last_tail_ns, s.fec_decode_max_tail_ns, s.fec_ingress_dropped_blocks, s.udp_payload_tu]);
        v.extend_from_slice(&[s.ack_packets_sent, s.ack_bytes_sent, s.ack_packets_received, s.ack_delay_us_max as u64, s.rtt_samples]);
        v.extend_from_slice(&[s.fec_decode_admission_refusals, s.fec_decode_timeouts, s.fec_decode_preemptions, s.fec_worker_limit_events, s.fec_decode_peak_workers, s.rx_plain_admission_refusals]);
        v
    }
    // Preserve the aggregate wire counter; partition its two disjoint causes
    // for reports without changing the backwards-compatible STATUS prefix.
    fn worker_limit_json(&self) -> String {
        let retired = self.st.fec_decode_preemptions;
        let refused = self.st.fec_worker_limit_events.saturating_sub(retired);
        format!(",\"receiver_fec_worker_refusals\":{refused},\"receiver_fec_worker_pressure_retirements\":{retired}")
    }
    const WORDS: usize = 43;
    fn from_words(w: &[u64]) -> Option<RxReport> {
        if w.len() < 37 { return None; }
        let mut st = ConnectionStats { rx_packets: w[0], rx_seq_span: w[1], rx_lost: w[2], rx_reordered: w[3], rx_late_beyond_window: w[4], rx_duplicates: w[5], rx_bursts: w[6], ..Default::default() };
        st.rx_burst_hist.copy_from_slice(&w[7..14]);
        st.fec_decode_last_tail_ns = w.get(28).copied().unwrap_or(0);
        st.fec_decode_max_tail_ns = w.get(29).copied().unwrap_or(0);
        st.fec_ingress_dropped_blocks = w.get(30).copied().unwrap_or(0);
        st.udp_payload_tu = w.get(31).copied().unwrap_or(0);
        (st.rx_messages_completed, st.rx_partial_evicted, st.rx_partial_evicted_bytes, st.rx_insert_failures, st.rx_stale_fragments) = (w[23], w[24], w[25], w[26], w[27]);
        let th = NetworkThreadStats { kernel_rx_drops: if w[14] == u64::MAX { None } else { Some(w[14]) }, max_loop_gap_ns: w[15], loop_gaps_over_1ms: w[16],
            loop_gaps_over_10ms: w[17], loop_gaps_over_100ms: w[18], loop_iterations: w[19], recv_queue_dropped_messages: w[20] };
        (st.ack_packets_sent, st.ack_bytes_sent, st.ack_packets_received, st.ack_delay_us_max, st.rtt_samples) = (w[32], w[33], w[34], w[35] as u32, w[36]);
        st.fec_decode_admission_refusals = w.get(37).copied().unwrap_or(0);
        st.fec_decode_timeouts = w.get(38).copied().unwrap_or(0);
        st.fec_decode_preemptions = w.get(39).copied().unwrap_or(0);
        st.fec_worker_limit_events = w.get(40).copied().unwrap_or(0);
        st.fec_decode_peak_workers = w.get(41).copied().unwrap_or(0);
        st.rx_plain_admission_refusals = w.get(42).copied().unwrap_or(0);
        Some(RxReport { st, th, cpu_user_us: w[21], cpu_sys_us: w[22] })
    }
}

/// (user, system) CPU microseconds of this process.
fn cpu_us() -> (u64, u64) {
    #[allow(unsafe_code)]
    let ru = unsafe { let mut ru: libc::rusage = std::mem::zeroed(); libc::getrusage(libc::RUSAGE_SELF, &mut ru); ru };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    (us(ru.ru_utime), us(ru.ru_stime))
}

fn die(msg: &str) -> ! { eprintln!("stp_bench: {msg}"); std::process::exit(2) }

fn send_buffer_params(a: &Args) -> (u32, u32, u32) {
    (a.num("queue-us", 1_000_000), a.num("queue-min", 4 << 20), a.num("queue-max", 64 << 20))
}

fn max_pps(a: &Args) -> Option<u64> { a.str("max-pps").map(|s| s.parse().unwrap_or_else(|_| die("bad --max-pps"))) }

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace()
        .take(3).collect::<Vec<_>>().join(",")
}

fn to_v6(ip: std::net::IpAddr) -> std::net::Ipv6Addr {
    match ip { std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(), std::net::IpAddr::V6(v6) => v6 }
}

fn main() {
    if let Err(error) = shielded_transport_pigeon::fec_adapt::initialize_research_policy() { die(&error); }
    let mut argv = std::env::args().skip(1);
    let mode = argv.next().unwrap_or_default();
    let args = Args::parse(argv);
    match mode.as_str() {
        "serve" => serve(&args),
        "send" => if args.str("workload").is_some() { send_magazines(&args) } else { send(&args) },
        _ => die("usage: stp_bench serve --port P [--bind IP] [--advertise IP] [--seed-key HEX64] | stp_bench send --to STPADDR [--seed N] [--count N] [--min B] [--max B] [--timeout S] [--idle S] [--out FILE]"),
    }
}

// ---------------------------------------------------------------------------------------------
// serve

#[derive(Default)]
struct PeerLog {
    recs: HashMap<u32, (bool, u64)>, // id -> (verified ok, server receive ns)
    ok_bytes: u64,
    corrupt: u64,
    malformed: u64,
    expected: Option<u32>,
    first_ns: Option<u64>,
    last_ns: u64,
    reported_complete: bool,
}

fn serve(a: &Args) {
    let port: u16 = a.num("port", 0);
    if port == 0 { die("serve needs --port"); }
    let bind: Option<std::net::IpAddr> = a.str("bind").map(|s| s.parse().unwrap_or_else(|_| die("bad --bind")));
    let advertise: std::net::IpAddr = match a.str("advertise") {
        Some(s) => s.parse().unwrap_or_else(|_| die("bad --advertise")),
        None => bind.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    };
    let seed: [u8; 32] = match a.str("seed-key") {
        Some(h) => {
            if h.len() != 64 { die("--seed-key must be 64 hex chars"); }
            let mut s = [0u8; 32];
            for i in 0..32 { s[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die("bad --seed-key hex")); }
            s
        }
        None => *blake3::hash(b"stp_bench default server key").as_bytes(),
    };
    let kp = new_keypair_from_connect_magic1_with_seed(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s, seed).unwrap();
    let addr = STPAddress::from(to_v6(advertise), port, &kp);

    // General-purpose bench endpoint: explicitly accept the largest supported
    // workload unless the operator supplies a narrower application limit.
    let max_message_size = a.num("max-message-size", MAX_JUMBOGRAM_LEN).min(MAX_JUMBOGRAM_LEN);
    let queues = a.num("queues", 1);
    let handle = new_network_thread_with_options(vec![kp], port, max_pps(a), send_buffer_params(a), max_message_size, NetworkThreadOptions { receive_memory: Some(bench_receive_budget(max_message_size, queues)), bind_ip: bind, send_queue_count: queues, ..Default::default() });
    println!("stp_bench serve: bound {}:{port}", bind.map(|b| b.to_string()).unwrap_or("[::]".into()));
    println!("STP address: {:?}", addr);

    let epoch = Instant::now();
    let mut wanted = Vec::new();
    let mut outbox: Vec<(ConnectionKey, usize, Dscp, Vec<u8>)> = Vec::new();
    let mut peers: HashMap<ConnectionKey, PeerLog> = HashMap::new();
    let mut last_progress = Instant::now();
    let mut progress_dirty = false;
    loop {
        // Keep every current connection wanted, or the network thread retires it after 30 s.
        let push = NetworkThreadPush { wanted_connections: wanted.clone(), send_unreliable: std::mem::take(&mut outbox), ..Default::default() };
        let Some(pull) = service_connections(&handle, push) else { die("network thread not answering") };
        wanted = pull.current_connections;
        outbox = pull.send_unreliable_rejected; // replies retried until queued
        let now_ns = epoch.elapsed().as_nanos() as u64;
        let thread_stats = pull.thread_stats;
        let conn_stats = pull.connection_stats;
        for (key, data) in pull.received_unreliable_messages {
            let p = peers.entry(key).or_default();
            match parse(&data) {
                Parsed::Malformed => p.malformed += 1,
                Parsed::Corrupt(id) => {
                    p.corrupt += 1;
                    if id < CTRL_BASE { p.recs.entry(id).or_insert((false, now_ns)); }
                }
                Parsed::Ok(PING, pl) if pl.len() == 8 => {
                    let mut r = pl.to_vec();
                    r.extend_from_slice(&now_ns.to_le_bytes());
                    outbox.push((key, 0, Dscp::BestEffort, ctrl(PONG, &r)));
                }
                Parsed::Ok(STATUS_REQ, pl) if pl.len() == 4 => {
                    p.expected = Some(u32_at(pl, 0));
                    let mut r = Vec::with_capacity(4 + 13 * p.recs.len());
                    r.extend_from_slice(&(p.recs.len() as u32).to_le_bytes());
                    for (id, (ok, t)) in &p.recs {
                        r.extend_from_slice(&id.to_le_bytes());
                        r.push(*ok as u8);
                        r.extend_from_slice(&t.to_le_bytes());
                    }
                    let (cpu_user_us, cpu_sys_us) = cpu_us();
                    let st = conn_stats.iter().find(|(k, _)| *k == key).map(|x| x.1).unwrap_or_default();
                    let words = RxReport { st, th: thread_stats, cpu_user_us, cpu_sys_us }.to_words();
                    r.extend_from_slice(&(words.len() as u32).to_le_bytes());
                    for w in words { r.extend_from_slice(&w.to_le_bytes()); }
                    outbox.push((key, 0, Dscp::BestEffort, ctrl(STATUS, &r)));
                    if !p.reported_complete && p.recs.len() as u32 >= u32_at(pl, 0) {
                        p.reported_complete = true;
                        print_peer(&key, p);
                    }
                }
                Parsed::Ok(id, _) if id >= CTRL_BASE => p.malformed += 1,
                Parsed::Ok(id, _) => {
                    p.first_ns.get_or_insert(now_ns);
                    p.last_ns = now_ns;
                    let e = p.recs.entry(id).or_insert((false, now_ns));
                    if !e.0 { *e = (true, now_ns); p.ok_bytes += data.len() as u64; }
                    progress_dirty = true;
                }
            }
        }
        if progress_dirty && last_progress.elapsed() > Duration::from_secs(5) {
            for (k, p) in &peers { println!("progress [{}]:{}: {} messages, {:.1} MB verified", k.ip, k.port, p.recs.len(), p.ok_bytes as f64 / 1e6); }
            last_progress = Instant::now();
            progress_dirty = false;
        }
        std::thread::sleep(Duration::from_micros(300));
    }
}

fn print_peer(key: &ConnectionKey, p: &PeerLog) {
    let ok = p.recs.values().filter(|r| r.0).count();
    let span = (p.last_ns.saturating_sub(p.first_ns.unwrap_or(p.last_ns))) as f64 / 1e9;
    println!("=== peer [{}]:{} complete: {} expected, {} verified ({:.1} MB), {} corrupt, {} malformed, first->last receive {:.3} s ({:.1} MB/s)",
        key.ip, key.port, p.expected.unwrap_or(0), ok, p.ok_bytes as f64 / 1e6, p.corrupt, p.malformed, span,
        if span > 0.0 { p.ok_bytes as f64 / 1e6 / span } else { 0.0 });
}

// ---------------------------------------------------------------------------------------------
// send

fn bucket_of(size: usize) -> usize {
    const B: [usize; 5] = [1 << 10, 64 << 10, 1 << 20, 10 << 20, 50 << 20];
    B.iter().position(|&b| size <= b).unwrap_or(B.len())
}
const BUCKET_NAMES: [&str; 6] = ["<=1KiB", "<=64KiB", "<=1MiB", "<=10MiB", "<=50MiB", ">50MiB"];

fn pct(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() { return None; }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    Some(sorted[rank.min(sorted.len()) - 1])
}

fn jnum(v: Option<f64>) -> String { v.map(|x| format!("{x:.3}")).unwrap_or("null".into()) }

/// Demo sizes are whole framed messages, not an extra 40-byte header on top.
fn giant_size(s: &str) -> Option<usize> {
    let (number, scale) = match s.strip_suffix('G').or_else(|| s.strip_suffix("GiB")) {
        Some(n) => (n, 1usize << 30),
        None => match s.strip_suffix('M').or_else(|| s.strip_suffix("MiB")) {
            Some(n) => (n, 1usize << 20),
            None => (s, 1),
        },
    };
    let bytes = number.parse::<usize>().ok()?.checked_mul(scale)?;
    (HEADER..=MAX_JUMBOGRAM_LEN).contains(&bytes).then_some(bytes)
}

type Outbox = Vec<(ConnectionKey, usize, Dscp, Vec<u8>)>;
type Wanted = Vec<(STPAddress, [u8; 64])>;

fn poll(handle: &NetworkThreadHandle, outbox: &mut Outbox, wanted: &mut Wanted) -> NetworkThreadPull {
    let p = service_connections(handle, NetworkThreadPush { wanted_connections: wanted.clone(), send_unreliable: std::mem::take(outbox), ..Default::default() })
        .unwrap_or_else(|| die("network thread not answering; submitted messages may be lost"));
    *wanted = p.current_connections.clone();
    p
}

fn mean_transmitted_redundancy(sum_repair_ratios: f64, sent_messages: u64) -> f64 {
    if sent_messages == 0 { 0.0 } else { 100.0 * sum_repair_ratios / sent_messages as f64 }
}

#[test]
fn redundancy_is_not_diluted_by_unsent_workload() {
    // 10 sent K=12,N=24 messages in a nominal 1000-message timeout workload.
    assert_eq!(mean_transmitted_redundancy(10.0, 10), 100.0);
    assert_eq!(mean_transmitted_redundancy(0.0, 0), 0.0);
    // Cumulative rescue raises N to30, i.e.18 actually sent repair symbols.
    assert_eq!(mean_transmitted_redundancy(18.0 / 12.0, 1), 150.0);
}

fn send_duty_off(elapsed_ns: u64, on_ns: u64, off_ns: u64) -> bool {
    off_ns != 0 && elapsed_ns % (on_ns + off_ns) >= on_ns
}

#[test]
fn send_duty_boundaries() {
    assert!(!send_duty_off(0, 2000, 2000));
    assert!(!send_duty_off(1999, 2000, 2000));
    assert!(send_duty_off(2000, 2000, 2000));
    assert!(send_duty_off(3999, 2000, 2000));
    assert!(!send_duty_off(4000, 2000, 2000));
    assert!(!send_duty_off(u64::MAX, 2000, 0));
}

#[test]
fn integrated_rx_report_roundtrip() {
    let r = RxReport { st: ConnectionStats { fec_decode_last_tail_ns: 11, fec_decode_max_tail_ns: 12, fec_ingress_dropped_blocks: 13, udp_payload_tu: 1472, ack_packets_sent: 21, ack_bytes_sent: 22, ack_packets_received: 23, ack_delay_us_max: 24, rtt_samples: 25, fec_decode_admission_refusals: 31, fec_decode_timeouts: 32, fec_decode_preemptions: 33, fec_worker_limit_events: 34, fec_decode_peak_workers: 35, rx_plain_admission_refusals: 36, ..Default::default() }, ..Default::default() };
    let words = r.to_words();
    assert_eq!(words.len(), RxReport::WORDS);
    let decoded = RxReport::from_words(&words).unwrap();
    assert_eq!(decoded.to_words(), words);
    assert_eq!(&words[28..32], &[11, 12, 13, 1472]);
    assert_eq!(&words[32..37], &[21, 22, 23, 24, 25]);
    assert_eq!(&words[37..40], &[31, 32, 33]);
    assert_eq!(decoded.worker_limit_json(), ",\"receiver_fec_worker_refusals\":1,\"receiver_fec_worker_pressure_retirements\":33");
    assert_eq!(RxReport::default().worker_limit_json(), ",\"receiver_fec_worker_refusals\":0,\"receiver_fec_worker_pressure_retirements\":0");
    // Old receivers still report the original prefix without the new counters.
    let old = RxReport::from_words(&words[..37]).unwrap();
    assert_eq!(old.st.fec_decode_admission_refusals, 0);
}

// Research-only sidecar: disk stream, not an unbounded in-memory result list.
struct FecTrace(Option<std::io::BufWriter<std::fs::File>>);
impl FecTrace {
    fn open(a: &Args) -> Self {
        use std::io::Write;
        Self(a.str("loss-trace").map(|p| {
            let mut w = std::io::BufWriter::new(std::fs::File::create(std::path::Path::new(p).with_extension("fec.csv")).unwrap());
            writeln!(w, "time_ns,package_id,root_id,offset,tag,message_len,block_bytes,k,n_planned,n_sent,lost,rescue_rounds,rescue_symbols").unwrap();
            w
        }))
    }
    fn record(&mut self, time_ns: u64, rows: &[(ConnectionKey, shielded_transport_pigeon::fec_adapt::FecMessageInfo)]) {
        use std::io::Write;
        if let Some(w) = &mut self.0 {
            for (_, m) in rows {
                writeln!(w, "{},{},{},{},{},{},{},{},{},{},{},{},{}", time_ns, m.package_id, m.root_id,
                    m.segment_offset, m.tag, m.message_len, m.block_bytes, m.k, m.n_planned, m.n_sent,
                    m.lost_during_send, m.rescue_rounds, m.rescue_symbols).unwrap();
            }
        }
    }
    fn flush(&mut self) { use std::io::Write; if let Some(w) = &mut self.0 { w.flush().unwrap(); } }
}

fn send(a: &Args) {
    let mut fec_trace = FecTrace::open(a);
    let to = STPAddress::parse(a.str("to").unwrap_or_else(|| die("send needs --to STPADDR"))).unwrap_or_else(|| die("bad --to address"));
    let seed: u64 = a.num("seed", 1);
    let giant = a.str("giant").map(|s| giant_size(s).unwrap_or_else(|| die("--giant needs a byte count, 256M or 1G (binary units, whole framed message)")));
    let count: u32 = if giant.is_some() { 1 } else { a.num("count", 60) };
    let mut min: usize = giant.unwrap_or_else(|| a.num("min", 100));
    let max: usize = giant.unwrap_or_else(|| a.num("max", 50_000_000));
    let timeout = Duration::from_secs(a.num("duration", a.num("timeout", 600)));
    let idle = Duration::from_secs(a.num("idle", 10));
    let on_ns = a.num::<u64>("send-on-ms", 2000).saturating_mul(1_000_000);
    let off_ns = a.num::<u64>("send-off-ms", 0).saturating_mul(1_000_000);
    if on_ns == 0 || on_ns.checked_add(off_ns).is_none() { die("invalid send duty cycle"); }
    let out = a.str("out").unwrap_or("stp_bench_report.json").to_string();
    let fec_mode = "adaptive:span";
    if min < HEADER { eprintln!("--min raised to the {HEADER}-byte header size"); min = HEADER; }
    if max < min || max > MAX_JUMBOGRAM_LEN { die(&format!("need --min <= --max <= {MAX_JUMBOGRAM_LEN}")); }
    if count == 0 || count >= CTRL_BASE { die("bad --count"); }

    // Sizes are log-uniform in [min, max] (whole framed message), deterministic from the seed;
    // the send order is a seeded shuffle of the ids.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let classes: Option<Vec<(usize, u32)>> = match if giant.is_some() { "giant" } else { a.str("mix").unwrap_or("loguniform") } {
        "giant" => Some(vec![(giant.unwrap(), 1)]),
        "loguniform" => None,
        "classes" => Some(a.str("classes").unwrap_or("1000:200,65536:200,1048576:50,5242880:20,52428800:5").split(',').map(|c| {
            let (sz, n) = c.split_once(':').unwrap_or_else(|| die("bad --classes"));
            (sz.trim().parse::<usize>().unwrap_or_else(|_| die("bad --classes size")).clamp(HEADER, MAX_JUMBOGRAM_LEN), n.trim().parse::<u32>().unwrap_or_else(|_| die("bad --classes count")))
        }).collect()),
        _ => die("--mix must be loguniform or classes"),
    };
    let count: u32 = match &classes { Some(c) => c.iter().map(|x| x.1).sum(), None => count };
    if count == 0 || count >= CTRL_BASE { die("bad class counts"); }
    let (lmin, lmax) = ((min as f64).ln(), (max as f64).ln());
    let sizes: Vec<usize> = match &classes {
        Some(c) => c.iter().flat_map(|&(sz, n)| std::iter::repeat(sz).take(n as usize)).collect(),
        None => (0..count).map(|_| ((rng.random::<f64>() * (lmax - lmin) + lmin).exp().round() as usize).clamp(min, max)).collect(),
    };
    // Report groups: size classes, or the fixed size buckets.
    let group_names: Vec<String> = match &classes { Some(c) => c.iter().map(|x| x.0.to_string()).collect(), None => BUCKET_NAMES.iter().map(|s| s.to_string()).collect() };
    let group_of = |size: usize| -> usize { match &classes { Some(c) => c.iter().position(|x| x.0 == size).unwrap(), None => bucket_of(size) } };
    let ngroups = group_names.len();
    let mut order: Vec<u32> = (0..count).collect();
    order.shuffle(&mut rng);
    let total_bytes: u64 = sizes.iter().map(|&s| s as u64).sum();

    // Payloads are generated on a producer thread just ahead of the sender so memory stays
    // bounded (a few messages) for any --count. Each payload is seeded by (seed, id). Time the
    // sender spends blocked on it after the first submission is reported.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(4);
    {
        let sizes = sizes.clone();
        let order = order.clone();
        std::thread::spawn(move || {
            for id in order {
                let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(seed ^ (id as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let m = frame(id, sizes[id as usize] - HEADER, |b| r.fill_bytes(b));
                if tx.send(m).is_err() { return; }
            }
        });
    }

    let kp = new_keypair_from_connect_magic1(to.magic1).unwrap_or_else(|| die("unsupported crypto in --to"));
    // The receiver also accepts complete STATUS replies, not just data messages.
    let workload_max = sizes.iter().copied().max().unwrap().max(HEADER + 8 + 13 * count as usize + 8 * RxReport::default().to_words().len());
    let max_message_size = a.num("max-message-size", workload_max).min(MAX_JUMBOGRAM_LEN);
    if max_message_size < workload_max { die("--max-message-size is smaller than workload data/status messages"); }
    let queues = a.num("queues", 1);
    let handle = new_network_thread_with_options(vec![kp], 0, max_pps(a), send_buffer_params(a), max_message_size, NetworkThreadOptions { receive_memory: Some(bench_receive_budget(max_message_size, queues)), send_queue_count: queues, bind_ip: None, record_loss_episodes: a.num::<u8>("loss-episodes", 0) != 0, record_fec_messages: true, loss_trace: a.str("loss-trace").map(std::path::PathBuf::from), ..Default::default() });
    // Per data id: (k, blocks sent, blocks planned, loss estimate) of its FEC coding, if coded.
    let mut fec_info: HashMap<u32, (u32, u32, u32, f64)> = HashMap::new();
    // One sample per second, with the CC command and queue-empty transition count.
    let mut series: Vec<(f64, f64, f64, u64, u64, u64, u64, f64, u64)> = Vec::new();
    let key = to.to_connection_key();
    let unix_epoch_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let load_start = load_average();
    let epoch = Instant::now();
    let ns = || epoch.elapsed().as_nanos() as u64;

    println!("stp_bench send: {count} messages, {:.1} MB total, sizes {min}..{max} B log-uniform, seed {seed}", total_bytes as f64 / 1e6);
    let mut outbox: Outbox = Vec::new();
    let pull = service_connections(&handle, NetworkThreadPush { initiate_connections: vec![to.clone()], ..Default::default() }).unwrap_or_default();
    let mut wanted: Wanted = pull.current_connections;
    let connect_deadline = Instant::now() + Duration::from_secs(30);
    while !wanted.iter().any(|(a, _)| a.connection_key() == key) {
        if Instant::now() > connect_deadline { die("could not connect within 30 s"); }
        std::thread::sleep(Duration::from_millis(20));
        poll(&handle, &mut outbox, &mut wanted);
    }
    println!("connected to {:?}", to);

    // Clock offset and RTT: 10 pings on the idle connection. For the ping with the smallest RTT,
    // offset = server_ns - (send_ns + recv_ns) / 2, assuming a symmetric path; the error is at
    // most RTT/2 (each side also adds up to one poll interval, ~0.3-1 ms). Server receive times
    // are mapped into the sender clock as server_ns - offset, and a message's latency is that
    // minus the sender time it was first handed to service_connections. (The sender only hands
    // over what the queue reports room for, so first submission is, in practice, acceptance.)
    // One ping at a time, each waiting up to 3 s for its reply: at STP's starting rate of about
    // 1 packet/s, back-to-back pings mostly queue behind each other and give lopsided samples.
    let mut pings: Vec<(u64, i128)> = Vec::new(); // (rtt ns, offset ns)
    let ping_phase = Instant::now();
    let mut sent_pings = 0;
    while pings.len() < 10 && ping_phase.elapsed() < Duration::from_secs(40) {
        sent_pings += 1;
        let before = pings.len();
        outbox.push((key, 0, Dscp::BestEffort, ctrl(PING, &ns().to_le_bytes())));
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until && pings.len() == before {
            let p = poll(&handle, &mut outbox, &mut wanted);
            outbox.extend(p.send_unreliable_rejected);
            for (_, d) in p.received_unreliable_messages {
                if let Parsed::Ok(PONG, pl) = parse(&d) && pl.len() == 16 {
                    let (t0, ts, t1) = (u64_at(pl, 0), u64_at(pl, 8), ns());
                    pings.push((t1 - t0, ts as i128 - (t0 as i128 + t1 as i128) / 2));
                }
            }
            std::thread::sleep(Duration::from_micros(300));
        }
    }
    pings.sort();
    let (rtt_min_ns, offset) = pings.first().copied().unwrap_or_else(|| die("no ping replies"));
    let rtt_median_ns = pings[pings.len() / 2].0;
    println!("idle RTT: min {:.3} ms, median {:.3} ms ({} of {} pings answered)", rtt_min_ns as f64 / 1e6, rtt_median_ns as f64 / 1e6, pings.len(), sent_pings);

    // A giant fixes its symbol size for the entire transfer. Observe TU stabilization
    // before encoding so cold 1200B symbols do not cap per-packet throughput on a 1472B path.
    let warmup_s: f64 = a.num("giant-warmup", if giant.is_some() { 5.0 } else { 0.0 });
    if !warmup_s.is_finite() || !(0.0..=60.0).contains(&warmup_s) { die("--giant-warmup must be in 0..=60 seconds"); }
    let warm_start = Instant::now();
    let mut tu_changed = warm_start;
    let mut observed_tu = 0;
    let stable_for = Duration::from_nanos((3 * rtt_median_ns).max(500_000_000));
    while warm_start.elapsed() < Duration::from_secs_f64(warmup_s) {
        let p = poll(&handle, &mut outbox, &mut wanted);
        if let Some((_, st)) = p.connection_stats.iter().find(|(k, _)| *k == key) {
            if st.udp_payload_tu != observed_tu { observed_tu = st.udp_payload_tu; tu_changed = Instant::now(); }
        }
        if warm_start.elapsed() >= Duration::from_secs(1) && tu_changed.elapsed() >= stable_for { break; }
        std::thread::sleep(Duration::from_millis(1));
    }
    let warmup_elapsed_s = warm_start.elapsed().as_secs_f64();
    if warmup_s > 0.0 { println!("TU warm-up: {warmup_elapsed_s:.3}s, UDP payload TU {observed_tu}B"); }

    // Back-pressured send loop: hand over only what the connection's queue reports room for
    // (one message when it is empty, whatever its size); anything rejected goes back in front.
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut produced = 0u32;
    let mut first_submit_ns: Vec<Option<u64>> = vec![None; count as usize];
    let nqueues = a.num::<usize>("queues", 1);
    if !(1..=64).contains(&nqueues) { die("--queues must be 1..=64"); }
    let traffic = traffic_classes(a, nqueues);
    let mut free = vec![u64::MAX; nqueues];
    let mut start_ns: Option<u64> = None;
    let mut all_queued = false;
    let mut last_status_req: Option<Instant> = None;
    let mut status: Option<Vec<(u32, bool, u64)>> = None;
    let mut stop_reason = "complete";
    let mut last_change = Instant::now();
    let mut last_drained: Option<Instant> = None;
    let mut stats = shielded_transport_pigeon::stp::ConnectionStats::default();
    let mut generator_wait_ns = 0u64;
    let mut rejected_total = 0u64;
    let mut rx_report: Option<RxReport> = None;
    let mut sender_thread = NetworkThreadStats::default();
    loop {
        while pending.len() < 2 && produced < count {
            match rx.try_recv() { Ok(m) => { pending.push_back(m); produced += 1; } Err(_) => break }
        }
        if pending.is_empty() && produced < count {
            let t = ns();
            pending.push_back(rx.recv().unwrap());
            produced += 1;
            if start_ns.is_some() { generator_wait_ns += ns() - t; }
        }
        let in_off_period = start_ns.is_some_and(|s| send_duty_off(ns() - s, on_ns, off_ns));
        let mut budget = if in_off_period { vec![0; nqueues] } else { free.clone() };
        let mut send_now: Outbox = Vec::new();
        let mut index = 0;
        let mut blocked = vec![false; nqueues];
        let mut sent_empty = vec![false; nqueues];
        while index < pending.len() {
            let m = &pending[index];
            let id = u32_at(m, 0) as usize;
            let q = id % nqueues;
            let len = m.len() as u64;
            if blocked[q] || (budget[q] == u64::MAX && sent_empty[q]) || (budget[q] != u64::MAX && len > budget[q]) {
                blocked[q] = true; index += 1; continue;
            }
            if budget[q] == u64::MAX { sent_empty[q] = true; } else { budget[q] -= len; }
            let m = pending.remove(index).unwrap();
            let t = ns();
            start_ns.get_or_insert(t);
            first_submit_ns[id].get_or_insert(t);
            send_now.push((key, q, traffic[q], m));
        }
        let mut sent_status = false;
        if (all_queued || a.str("duration").is_some()) && last_status_req.is_none_or(|t| t.elapsed() > Duration::from_secs(1)) {
            outbox.push((key, 0, Dscp::BestEffort, ctrl(STATUS_REQ, &count.to_le_bytes())));
            last_status_req = Some(Instant::now());
            sent_status = true;
        }
        outbox.extend(send_now);
        let p = poll(&handle, &mut outbox, &mut wanted);
        for (_, _, _, m) in p.send_unreliable_rejected.into_iter().rev() {
            if u32_at(&m, 0) >= CTRL_BASE {
                if sent_status { last_status_req = None; } // retry next tick
                continue;
            }
            rejected_total += 1;
            pending.push_front(m);
        }
        for &(k, q, bytes) in &p.unreliable_send_free_bytes { if k == key { free[q] = bytes; } }
        if let Some((_, st)) = p.connection_stats.iter().find(|(k, _)| *k == key) { stats = *st; }
        sender_thread = p.thread_stats;
        fec_trace.record(ns(), &p.fec_messages);
        for (k, m) in &p.fec_messages {
            let id = m.tag as u32;
            if *k == key && id < count && m.message_len == sizes[id as usize] { fec_info.insert(id, (m.k, m.n_sent, m.n_planned, m.loss_estimate)); }
        }
        if let Some(s0) = start_ns {
            let t = (ns() - s0) as f64 / 1e9;
            if series.last().is_none_or(|x| t - x.0 >= 1.0) { series.push((t, stats.fec_loss_estimate, stats.fec_last_loss_sample, stats.packets_sent, stats.packets_lost, stats.bytes_sent, stats.rtt_us, stats.cc_rate_upps as f64 / 1e6, stats.cc_app_limited_entries)); }
        }
        if produced == count && pending.is_empty() { all_queued = true; }
        for (_, d) in p.received_unreliable_messages {
            if let Parsed::Ok(STATUS, pl) = parse(&d) && pl.len() >= 4 {
                let n = u32_at(pl, 0) as usize;
                let o = 4 + 13 * n;
                if pl.len() < o + 4 { continue; }
                let m = u32_at(pl, o) as usize;
                if pl.len() != o + 4 + 8 * m { continue; }
                let v: Vec<(u32, bool, u64)> = (0..n).map(|i| { let o = 4 + 13 * i; (u32_at(pl, o), pl[o + 4] != 0, u64_at(pl, o + 5)) }).collect();
                let words: Vec<u64> = (0..m).map(|i| u64_at(pl, o + 4 + 8 * i)).collect();
                if let Some(r) = RxReport::from_words(&words) { rx_report = Some(r); }
                let prev = status.as_ref().map_or(0, |s| s.len());
                if v.len() > prev { last_change = Instant::now(); }
                if v.len() >= prev { status = Some(v); }
            }
        }
        if status.as_ref().is_some_and(|s| s.len() as u32 >= count) { break; }
        if start_ns.is_some_and(|s| ns() - s > timeout.as_nanos() as u64) { stop_reason = "timeout"; break; }
        // Idle stop: once every message has been queued and the queue has been seen empty, all
        // data is on the wire (nothing but the 1 s status request is queued after that). From that
        // first drain, stop after --idle s in which the server reported nothing new.
        if all_queued && free.iter().all(|b| *b == u64::MAX) && last_drained.is_none() {
            last_drained = Some(Instant::now());
            last_change = Instant::now();
        }
        if last_drained.is_some() && last_change.elapsed() > idle { stop_reason = "idle (send queue drained, nothing new at server)"; break; }
        if !wanted.iter().any(|(a, _)| a.connection_key() == key) && !p.unreliable_send_free_bytes.iter().any(|(k, _, _)| *k == key) {
            eprintln!("connection lost; reporting what the server last confirmed");
            stop_reason = "connection lost";
            break;
        }
        std::thread::sleep(Duration::from_micros(300));
    }
    let done_ns = ns();
    let (sender_cpu_user_us, sender_cpu_sys_us) = cpu_us();
    let start_ns = start_ns.unwrap();

    // Report.
    let recs: HashMap<u32, (bool, u64)> = status.unwrap_or_default().into_iter().map(|(i, ok, t)| (i, (ok, t))).collect();
    let to_sender = |server_ns: u64| (server_ns as i128 - offset) as f64;
    let (mut delivered, mut delivered_bytes, mut corrupt, mut lost) = (0u64, 0u64, 0u64, 0u64);
    let mut last_recv = start_ns as f64;
    let (mut b_count, mut b_deliv, mut b_bytes) = (vec![0u64; ngroups], vec![0u64; ngroups], vec![0u64; ngroups]);
    let mut b_lat: Vec<Vec<f64>> = vec![Vec::new(); ngroups];
    // Cumulative on-wire repair snapshots, including late rescue. Never dilute a saturated
    // run's FEC ratio with workload messages that were not transmitted before its timeout.
    let (mut b_red, mut b_red_plan, mut b_coded) = (vec![0f64; ngroups], vec![0f64; ngroups], vec![0u64; ngroups]);
    let (mut b_sent, mut b_repairs) = (vec![0u64; ngroups], vec![0u64; ngroups]);
    let mut all_lat = Vec::new();
    for id in 0..count {
        let size = sizes[id as usize];
        let b = group_of(size);
        b_count[b] += 1; b_bytes[b] += size as u64;
        if let Some(&(k, n, np, _)) = fec_info.get(&id) {
            b_sent[b] += 1;
            b_coded[b] += u64::from(k > 1);
            let repairs = n.saturating_sub(k);
            b_repairs[b] += repairs as u64;
            b_red[b] += repairs as f64 / k as f64;
            b_red_plan[b] += np.saturating_sub(k) as f64 / k as f64;
        }
        match recs.get(&id) {
            Some(&(true, t)) => {
                delivered += 1; delivered_bytes += size as u64; b_deliv[b] += 1;
                let r = to_sender(t);
                last_recv = last_recv.max(r);
                if let Some(s) = first_submit_ns[id as usize] {
                    let lat_ms = (r - s as f64) / 1e6;
                    b_lat[b].push(lat_ms); all_lat.push(lat_ms);
                }
            }
            Some(&(false, _)) => corrupt += 1,
            None => lost += 1,
        }
    }
    // Wall clock: first submission to the (offset-mapped) server receive of the last message;
    // on timeout or connection loss, first submission to the stop.
    let timed_out = stop_reason == "timeout" || stop_reason == "connection lost";
    let wall_s = if timed_out || delivered == 0 { (done_ns - start_ns) as f64 / 1e9 } else { (last_recv - start_ns as f64) / 1e9 };
    let confirm_s = (done_ns - start_ns) as f64 / 1e9;
    let goodput_mbs = delivered_bytes as f64 / 1e6 / wall_s;

    println!("\n=== stp_bench report ===");
    println!("messages: {count} ({:.3} MB) | delivered+verified: {delivered} ({:.3} MB) | corrupt: {corrupt} | lost: {lost}{}",
        total_bytes as f64 / 1e6, delivered_bytes as f64 / 1e6, format!(" | stopped: {stop_reason}"));
    println!("FEC: adaptive span-tail, closed-loop fountain top-up, real-trace floor");
    println!("wall clock: {wall_s:.3} s (status confirmed at {confirm_s:.3} s) | goodput: {goodput_mbs:.2} MB/s = {:.2} Mbit/s", goodput_mbs * 8.0);
    println!("idle RTT: min {:.3} ms, median {:.3} ms | rejected submissions (back pressure): {rejected_total} | sender waited on generator: {:.3} s",
        rtt_min_ns as f64 / 1e6, rtt_median_ns as f64 / 1e6, generator_wait_ns as f64 / 1e9);
    let loss_pct = if stats.packets_sent > 0 { 100.0 * stats.packets_lost as f64 / stats.packets_sent as f64 } else { 0.0 };
    let wire_overhead = if delivered_bytes > 0 { stats.bytes_sent as f64 / delivered_bytes as f64 } else { 0.0 };
    println!("sender packets: {} sent, {} declared lost ({loss_pct:.3}%) | UDP payload bytes sent: {:.3} MB = {wire_overhead:.3}x delivered bytes",
        stats.packets_sent, stats.packets_lost, stats.bytes_sent as f64 / 1e6);
    // Ground truth: what the receiver saw of our sequence numbers, and what our declarations were worth.
    let spurious_pct = if stats.packets_lost > 0 { 100.0 * stats.spurious_losses as f64 / stats.packets_lost as f64 } else { 0.0 };
    let net_declared_pct = if stats.packets_sent > 0 { 100.0 * stats.packets_lost.saturating_sub(stats.spurious_losses) as f64 / stats.packets_sent as f64 } else { 0.0 };
    println!("sender: {} declared lost, {} of them spurious (acked later, {spurious_pct:.1}%) -> net declared {net_declared_pct:.3}% | test-dropped {} | TU probes lost {} | seq numbers used {}",
        stats.packets_lost, stats.spurious_losses, stats.test_dropped, stats.tu_probes_lost, stats.seq_numbers_used);
    println!("sender thread: kernel rx drops {} | max loop gap {:.3} ms | loop gaps >1ms {} >10ms {} >100ms {}",
        sender_thread.kernel_rx_drops.map(|d| d.to_string()).unwrap_or("n/a".into()), sender_thread.max_loop_gap_ns as f64 / 1e6,
        sender_thread.loop_gaps_over_1ms, sender_thread.loop_gaps_over_10ms, sender_thread.loop_gaps_over_100ms);
    let rx = rx_report.unwrap_or_default();
    let rx_loss_pct = if rx.st.rx_seq_span > 0 { 100.0 * rx.st.rx_lost as f64 / rx.st.rx_seq_span as f64 } else { 0.0 };
    let hist_txt = RX_BURST_CLASS_NAMES.iter().zip(rx.st.rx_burst_hist.iter()).map(|(n, c)| format!("{n}:{c}")).collect::<Vec<_>>().join(" ");
    let mean_burst = if rx.st.rx_bursts > 0 { rx.st.rx_lost as f64 / rx.st.rx_bursts as f64 } else { 0.0 };
    match rx_report {
        None => println!("receiver ground truth: none (no STATUS reply carried it)"),
        Some(_) => {
            println!("receiver: {} received of seq span {} -> path loss {} ({rx_loss_pct:.3}%) | reordered {} (beyond window {}) | duplicates {}",
                rx.st.rx_packets, rx.st.rx_seq_span, rx.st.rx_lost, rx.st.rx_reordered, rx.st.rx_late_beyond_window, rx.st.rx_duplicates);
            println!("receiver loss bursts: {} (mean {mean_burst:.2} pkts) by length {hist_txt}", rx.st.rx_bursts);
            println!("receiver reassembly: {} messages completed | partials evicted {} ({} B held) | insert failures {} | stale fragments {}",
                rx.st.rx_messages_completed, rx.st.rx_partial_evicted, rx.st.rx_partial_evicted_bytes, rx.st.rx_insert_failures, rx.st.rx_stale_fragments);
            println!("receiver thread: kernel rx drops {} | max loop gap {:.3} ms | loop gaps >1ms {} >10ms {} >100ms {} | recv-queue dropped msgs {} | server CPU {:.3} s user + {:.3} s sys",
                rx.th.kernel_rx_drops.map(|d| d.to_string()).unwrap_or("n/a".into()), rx.th.max_loop_gap_ns as f64 / 1e6,
                rx.th.loop_gaps_over_1ms, rx.th.loop_gaps_over_10ms, rx.th.loop_gaps_over_100ms, rx.th.recv_queue_dropped_messages,
                rx.cpu_user_us as f64 / 1e6, rx.cpu_sys_us as f64 / 1e6);
        }
    }
    println!("{:<9} {:>6} {:>9} {:>8} {:>12} {:>12} {:>7} {:>9} {:>9}", "group", "count", "delivered", "rate", "p50 ms", "p99 ms", "coded", "red% sent", "red% plan");
    let mut bucket_json = Vec::new();
    for b in 0..ngroups {
        if b_count[b] == 0 { continue; }
        let red = mean_transmitted_redundancy(b_red[b], b_sent[b]);
        let red_plan = mean_transmitted_redundancy(b_red_plan[b], b_sent[b]);
        b_lat[b].sort_by(|x, y| x.partial_cmp(y).unwrap());
        let rate = if b_count[b] > 0 { Some(b_deliv[b] as f64 / b_count[b] as f64) } else { None };
        let (p50, p99) = (pct(&b_lat[b], 50.0), pct(&b_lat[b], 99.0));
        println!("{:<9} {:>6} {:>9} {:>8} {:>12} {:>12} {:>7} {:>9.2} {:>9.2}", group_names[b], b_count[b], b_deliv[b],
            rate.map(|r| format!("{:.1}%", r * 100.0)).unwrap_or("-".into()), jnum(p50), jnum(p99), b_coded[b], red, red_plan);
        bucket_json.push(format!("{{\"bucket\":\"{}\",\"count\":{},\"bytes\":{},\"delivered\":{},\"delivery_rate\":{},\"latency_ms_p50\":{},\"latency_ms_p99\":{},\"fec_coded\":{},\"sent_messages\":{},\"repair_blocks_sent\":{},\"mean_redundancy_pct\":{:.4},\"mean_planned_redundancy_pct\":{:.4}}}",
            group_names[b], b_count[b], b_bytes[b], b_deliv[b], jnum(rate), jnum(p50), jnum(p99), b_coded[b], b_sent[b], b_repairs[b], red, red_plan));
    }
    all_lat.sort_by(|x, y| x.partial_cmp(y).unwrap());
    println!("all       latency p50 {} ms, p99 {} ms", jnum(pct(&all_lat, 50.0)), jnum(pct(&all_lat, 99.0)));

    let sbp = send_buffer_params(a);
    let (sender_cpu_user_us, sender_cpu_sys_us) = cpu_us();
    let mut json = format!(concat!("{{\"to\":\"{:?}\",\"seed\":{},\"min\":{},\"max\":{},\"send_buffer_params\":[{},{},{}],\"fec_pct\":null,\"fec_mode\":\"{}\",\"fec_adaptive\":\"{}\",\"drop_schedule\":\"{}\",",
        "\"total_messages\":{},\"total_bytes\":{},\"delivered\":{},\"delivered_bytes\":{},\"corrupt\":{},\"lost\":{},\"stop_reason\":\"{}\",",
        "\"data_start_unix_seconds\":{:.6},\"wall_seconds\":{:.6},\"status_confirmed_seconds\":{:.6},\"goodput_MBps\":{:.3},\"goodput_Mbitps\":{:.3},",
        "\"rtt_ms_min\":{:.3},\"rtt_ms_median\":{:.3},\"rejected_submissions\":{},\"generator_wait_seconds\":{:.6},",
        "\"latency_ms_p50\":{},\"latency_ms_p99\":{},",
        "\"packets_sent\":{},\"packets_lost\":{},\"packet_loss_pct\":{:.4},\"udp_payload_bytes_sent\":{},\"wire_bytes_per_delivered_byte\":{:.4},",
        "\"latency_method\":\"server receive time mapped to sender clock via min-RTT ping offset (error <= RTT/2) minus first submission\",",
        "\"spurious_losses\":{},\"net_declared_loss_pct\":{:.4},\"test_dropped\":{},\"tu_probes_lost\":{},\"seq_numbers_used\":{},",
        "\"max_rtt_loss_pct\":{:.4},\"max_rtt_loss_window_packets\":{},",
        "\"sender_kernel_rx_drops\":{},\"sender_max_loop_gap_ms\":{:.3},\"sender_loop_gaps_over_10ms\":{},",
        "\"receiver\":{{\"reported\":{},\"rx_packets\":{},\"rx_seq_span\":{},\"rx_lost\":{},\"path_loss_pct\":{:.4},\"rx_reordered\":{},\"rx_late_beyond_window\":{},\"rx_duplicates\":{},",
        "\"bursts\":{},\"mean_burst_len\":{:.3},\"burst_hist\":{{{}}},\"kernel_rx_drops\":{},\"max_loop_gap_ms\":{:.3},\"loop_gaps_over_1ms\":{},\"loop_gaps_over_10ms\":{},\"loop_gaps_over_100ms\":{},",
        "\"recv_queue_dropped_messages\":{},\"server_cpu_user_s\":{:.3},\"server_cpu_sys_s\":{:.3},",
        "\"messages_completed\":{},\"partials_evicted\":{},\"partials_evicted_bytes\":{},\"insert_failures\":{},\"stale_fragments\":{}}},",
        "\"buckets\":[{}],\"estimator_series\":[{}],\"congestion_control\":\"{}\",",
        "\"ack_options\":\"{}\",\"ack_packets_sent\":{},\"ack_bytes_sent\":{},\"ack_packets_received\":{},\"ack_delay_us_max\":{},\"rtt_samples\":{},",
        "\"receiver_ack_packets_sent\":{},\"receiver_ack_bytes_sent\":{},\"receiver_ack_delay_us_max\":{},\"sender_cpu_user_s\":{:.6},\"sender_cpu_sys_s\":{:.6},\"sender_rtt_us\":{},",
        "\"sender_pacing\":{{\"mode\":\"{}\",\"diagnostics\":{},\"burst_budget_ms\":{},\"batches\":{},\"packets\":{},\"max_burst\":{},\"burst_hist\":[{}],",
        "\"commanded_packets\":{},\"error_samples\":{},\"error_abs_sum_ns\":{},\"error_max_ns\":{},\"history_records\":{},",
        "\"network_cpu_user_us\":{},\"network_cpu_sys_us\":{},\"process_cpu_user_us\":{},\"process_cpu_sys_us\":{},\"load_start\":[{}],\"load_end\":[{}]}}}}\n"),
        to, seed, min, max, sbp.0, sbp.1, sbp.2, fec_mode, "span-tail+closed-loop+real-floor",
        std::env::var("STP_TEST_DROP_SCHEDULE").unwrap_or_else(|_| std::env::var("STP_TEST_DROP_PPM").map(|v| format!("ppm={v}")).unwrap_or_default()),
        count, total_bytes, delivered, delivered_bytes, corrupt, lost, stop_reason,
        unix_epoch_s + start_ns as f64 / 1e9, wall_s, confirm_s, goodput_mbs, goodput_mbs * 8.0,
        rtt_min_ns as f64 / 1e6, rtt_median_ns as f64 / 1e6, rejected_total, generator_wait_ns as f64 / 1e9,
        jnum(pct(&all_lat, 50.0)), jnum(pct(&all_lat, 99.0)),
        stats.packets_sent, stats.packets_lost, loss_pct, stats.bytes_sent, wire_overhead,
        stats.spurious_losses, net_declared_pct, stats.test_dropped, stats.tu_probes_lost, stats.seq_numbers_used,
        stats.max_rtt_loss_ppm as f64 / 10_000.0, stats.max_rtt_loss_window_packets,
        sender_thread.kernel_rx_drops.map(|d| d.to_string()).unwrap_or("null".into()), sender_thread.max_loop_gap_ns as f64 / 1e6, sender_thread.loop_gaps_over_10ms,
        rx_report.is_some(), rx.st.rx_packets, rx.st.rx_seq_span, rx.st.rx_lost, rx_loss_pct, rx.st.rx_reordered, rx.st.rx_late_beyond_window, rx.st.rx_duplicates,
        rx.st.rx_bursts, mean_burst, RX_BURST_CLASS_NAMES.iter().zip(rx.st.rx_burst_hist.iter()).map(|(n, c)| format!("\"{n}\":{c}")).collect::<Vec<_>>().join(","),
        rx.th.kernel_rx_drops.map(|d| d.to_string()).unwrap_or("null".into()), rx.th.max_loop_gap_ns as f64 / 1e6, rx.th.loop_gaps_over_1ms, rx.th.loop_gaps_over_10ms, rx.th.loop_gaps_over_100ms,
        rx.th.recv_queue_dropped_messages, rx.cpu_user_us as f64 / 1e6, rx.cpu_sys_us as f64 / 1e6,
        rx.st.rx_messages_completed, rx.st.rx_partial_evicted, rx.st.rx_partial_evicted_bytes, rx.st.rx_insert_failures, rx.st.rx_stale_fragments,
        bucket_json.join(","),
        series.iter().map(|x| format!("[{:.1},{:.5},{:.5},{},{},{},{},{:.3},{}]", x.0, x.1, x.2, x.3, x.4, x.5, x.6, x.7, x.8)).collect::<Vec<_>>().join(","), "slow110",
        "adaptive bitmap", stats.ack_packets_sent, stats.ack_bytes_sent, stats.ack_packets_received, stats.ack_delay_us_max, stats.rtt_samples,
        rx.st.ack_packets_sent, rx.st.ack_bytes_sent, rx.st.ack_delay_us_max, sender_cpu_user_us as f64 / 1e6, sender_cpu_sys_us as f64 / 1e6, stats.rtt_us,
        "Precise", false, "null", stats.pacing_batches, stats.pacing_packets, stats.pacing_max_burst,
        stats.pacing_burst_hist.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
        stats.pacing_commanded_packets, stats.pacing_error_samples, stats.pacing_error_abs_sum_ns, stats.pacing_error_max_ns, stats.pacing_history_records,
        stats.network_cpu_user_us, stats.network_cpu_sys_us, sender_cpu_user_us, sender_cpu_sys_us, load_start, load_average());
    let queues = queue_report(nqueues, &sizes, &(0..count).map(|id| id as usize % nqueues).collect::<Vec<_>>(), &first_submit_ns, &recs, offset, wall_s, None);
    json.insert_str(json.len() - 2, &format!(",\"max_message_size\":{max_message_size},\"queues\":[{}]", queues.join(",")));
    let block_sizes = fec_info.iter().map(|(&id, &(k, _, _, _))| format!("\"{id}\":{}", sizes[id as usize].div_ceil(k as usize))).collect::<Vec<_>>().join(",");
    json.insert_str(json.len() - 2, &format!(",\"udp_payload_tu\":{},\"fec_block_bytes_by_id\":{{{block_sizes}}},\"tu_warmup_seconds\":{warmup_elapsed_s:.6},\"receiver_fec_decode_last_tail_ms\":{:.3},\"receiver_fec_decode_max_tail_ms\":{:.3},\"receiver_fec_ingress_dropped_blocks\":{}",
        stats.udp_payload_tu, rx.st.fec_decode_last_tail_ns as f64 / 1e6, rx.st.fec_decode_max_tail_ns as f64 / 1e6, rx.st.fec_ingress_dropped_blocks));
    json.insert_str(json.len() - 2, &format!(",\"receiver_fec_decode_admission_refusals\":{},\"receiver_fec_decode_timeouts\":{},\"receiver_fec_decode_preemptions\":{},\"receiver_fec_worker_limit_events\":{},\"receiver_fec_decode_peak_workers\":{},\"receiver_plain_admission_refusals\":{}",
        rx.st.fec_decode_admission_refusals, rx.st.fec_decode_timeouts, rx.st.fec_decode_preemptions, rx.st.fec_worker_limit_events, rx.st.fec_decode_peak_workers, rx.st.rx_plain_admission_refusals));
    json.insert_str(json.len() - 2, &rx.worker_limit_json());
    println!("UDP TU {}B | FEC blocks {{{block_sizes}}}B | receiver FEC last/max decode tail {:.3}/{:.3}ms | ingress erased {} blocks",
        stats.udp_payload_tu, rx.st.fec_decode_last_tail_ns as f64 / 1e6, rx.st.fec_decode_max_tail_ns as f64 / 1e6, rx.st.fec_ingress_dropped_blocks);
    std::fs::write(&out, json).unwrap_or_else(|e| die(&format!("writing {out}: {e}")));
    println!("report written to {out}");
    fec_trace.flush();
    drop(handle); // A traced run joins the network thread and flushes its event CSV.
    std::process::exit(if delivered == count as u64 { 0 } else { 1 });
}

fn traffic_classes(a: &Args, queues: usize) -> Vec<Dscp> {
    let v: Vec<Dscp> = a.str("traffic-classes").unwrap_or("be").split(',').map(|c| match c {
        "be" => Dscp::BestEffort, "af11" => Dscp::Af11, "af21" => Dscp::Af21, "ef" => Dscp::Ef,
        _ => die("--traffic-classes needs be,af11,af21,ef (one or one per queue)"),
    }).collect();
    if v.len() == 1 { vec![v[0]; queues] } else if v.len() == queues { v } else { die("wrong number of traffic classes") }
}

fn queue_report(n: usize, sizes: &[usize], queue_ids: &[usize], submitted: &[Option<u64>], recs: &HashMap<u32, (bool, u64)>, offset: i128, wall: f64, cutoff: Option<f64>) -> Vec<String> {
    (0..n).map(|q| {
        let mut lat = Vec::new(); let mut bytes = 0u64; let mut count = 0;
        for (id, &size) in sizes.iter().enumerate().filter(|(id, _)| queue_ids[*id] == q) {
            if let Some(&(true, t)) = recs.get(&(id as u32)) {
                let recv = (t as i128 - offset) as f64;
                if cutoff.is_some_and(|c| recv > c) { continue; }
                count += 1; bytes += size as u64;
                if let Some(s) = submitted[id] { lat.push((recv - s as f64) / 1e6); }
            }
        }
        lat.sort_by(f64::total_cmp);
        let gp = bytes as f64 * 8.0 / 1e6 / wall;
        println!("queue {q}: {count} delivered, {gp:.3} Mbit/s, last-byte latency p50 {} ms p99 {} ms", jnum(pct(&lat, 50.0)), jnum(pct(&lat, 99.0)));
        format!("{{\"queue\":{q},\"delivered\":{count},\"delivered_bytes\":{bytes},\"goodput_Mbitps\":{gp:.6},\"latency_ms_p50\":{},\"latency_ms_p99\":{}}}", jnum(pct(&lat, 50.0)), jnum(pct(&lat, 99.0)))
    }).collect()
}

/// Saturated magazines: bulk queues have at most one pending producer message each; tiny
/// arrivals are generated independently, so the producer itself cannot hide sender HOL.
/// Small latencies start at Poisson arrival, including app backpressure in the single-queue case.
fn send_magazines(a: &Args) {
    let mut fec_trace = FecTrace::open(a);
    let mode = a.str("workload").unwrap();
    if !matches!(mode, "bulk" | "bulk-small" | "dueling") { die("--workload must be bulk, bulk-small or dueling"); }
    let n = a.num::<usize>("queues", if mode == "dueling" { 2 } else { 1 });
    if !(1..=64).contains(&n) || mode == "dueling" && n < 2 { die("invalid queue count"); }
    let traffic = traffic_classes(a, n);
    let duration = a.num::<f64>("duration", 40.0);
    let small_rate = a.num::<f64>("small-rate", 20.0);
    if !(0.0..=600.0).contains(&duration) || duration == 0.0 || !small_rate.is_finite() || small_rate <= 0.0 { die("invalid workload duration/rate"); }
    let small_size = a.num::<usize>("small-size", 1000).clamp(HEADER, MAX_JUMBOGRAM_LEN);
    let bulk_size = a.num::<usize>("bulk-size", 50<<20).clamp(HEADER, MAX_JUMBOGRAM_LEN);
    let to = STPAddress::parse(a.str("to").unwrap_or_else(|| die("send needs --to"))).unwrap_or_else(|| die("bad --to"));
    let key = to.to_connection_key();
    let kp = new_keypair_from_connect_magic1(to.magic1).unwrap();
    let max_message_size = a.num("max-message-size", bulk_size.max(small_size)).min(MAX_JUMBOGRAM_LEN);
    if max_message_size < bulk_size.max(small_size) { die("--max-message-size is smaller than workload messages"); }
    let handle = new_network_thread_with_options(vec![kp], 0, max_pps(a), send_buffer_params(a), max_message_size, NetworkThreadOptions { receive_memory: Some(bench_receive_budget(max_message_size, n)), send_queue_count: n, record_fec_messages: true, record_loss_episodes: a.num::<u8>("loss-episodes", 0) != 0, loss_trace: a.str("loss-trace").map(std::path::PathBuf::from), ..Default::default() });
    let mut wanted = service_connections(&handle, NetworkThreadPush { initiate_connections: vec![to], ..Default::default() }).unwrap().current_connections;
    let mut outbox = Vec::new();
    let epoch = Instant::now(); let ns = || epoch.elapsed().as_nanos() as u64;
    let mut pings = Vec::new();
    let mut sent_ping = 0;
    let mut last_ping = Instant::now() - Duration::from_secs(1);
    while pings.len() < 10 {
        if epoch.elapsed() > Duration::from_secs(40) { die("no connection/ping replies"); }
        if wanted.iter().any(|(a, _)| a.connection_key() == key) && last_ping.elapsed() >= Duration::from_millis(100) && sent_ping < 10 {
            outbox.push((key, 0, Dscp::BestEffort, ctrl(PING, &ns().to_le_bytes())));
            last_ping = Instant::now(); sent_ping += 1;
        }
        let p = poll(&handle, &mut outbox, &mut wanted);
        outbox.extend(p.send_unreliable_rejected);
        for (_, data) in p.received_unreliable_messages {
            if let Parsed::Ok(PONG, pl) = parse(&data) && pl.len() == 16 {
                let (t0, ts, t1) = (u64_at(pl, 0), u64_at(pl, 8), ns());
                pings.push((t1-t0, ts as i128 - (t0 as i128 + t1 as i128)/2));
            }
        }
        std::thread::sleep(Duration::from_micros(300));
    }
    pings.sort(); let offset = pings[0].1;
    // Reuse bulk payload/hash; IDs are outside the hashed payload. Generation is not measured.
    let template = frame(0, bulk_size-HEADER, |p| p.fill(0x55));
    let start = ns(); let cutoff = start as f64 + duration * 1e9;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(a.num("seed", 1));
    let mut next_small = -rng.random::<f64>().max(f64::MIN_POSITIVE).ln() / small_rate;
    let bulk_queues = if mode == "dueling" { n } else { 1 };
    let small_queue = if n > 1 { 1 } else { 0 };
    let small_class = match a.str("small-class") { None => traffic[small_queue], Some("be") => Dscp::BestEffort, Some("af11") => Dscp::Af11, Some("af21") => Dscp::Af21, Some("ef") => Dscp::Ef, _ => die("bad --small-class") };
    let control_queue = if n > 1 && mode != "dueling" { 1 } else { 0 };
    let mut pending: Vec<VecDeque<(u32, Vec<u8>)>> = (0..n).map(|_| VecDeque::new()).collect();
    let mut sizes = Vec::new(); let mut ids = Vec::new(); let mut submitted = Vec::new(); let mut small_ids = Vec::new();
    let mut recs = HashMap::new(); let mut stats = ConnectionStats::default(); let mut receiver = RxReport::default();
    let mut free = vec![u64::MAX; n]; let mut last_status = Instant::now()-Duration::from_secs(1);
    let mut drained = false; let mut last_growth = Instant::now(); let mut last_delivery = start as f64;
    let drain_limit = a.num::<u64>("timeout", 180);
    loop {
        let elapsed = (ns()-start) as f64/1e9;
        if elapsed < duration {
            if mode == "bulk-small" {
                while next_small <= elapsed && next_small < duration {
                    let id = sizes.len() as u32;
                    let m = frame(id, small_size-HEADER, |p| p.fill(0x77));
                    sizes.push(small_size); ids.push(small_queue); submitted.push(Some(start+(next_small*1e9) as u64)); small_ids.push(id);
                    pending[small_queue].push_back((id, m));
                    next_small += -rng.random::<f64>().max(f64::MIN_POSITIVE).ln()/small_rate;
                }
            }
            for q in 0..bulk_queues {
                // Keep one whole bulk train standing in the transport, not two 50 MiB trains.
                if pending[q].is_empty() && free[q] == u64::MAX {
                    let id = sizes.len() as u32; let mut m = template.clone();
                    m[..4].copy_from_slice(&id.to_le_bytes());
                    sizes.push(bulk_size); ids.push(q); submitted.push(None);
                    pending[q].push_back((id, m));
                }
            }
        }
        for q in 0..n {
            let mut budget = free[q];
            let mut sent_empty = false;
            while let Some((id, m)) = pending[q].front() {
                if budget == u64::MAX { if sent_empty { break; } sent_empty = true; }
                else if m.len() as u64 > budget { break; } else { budget -= m.len() as u64; }
                submitted[*id as usize].get_or_insert_with(&ns);
                let (_, m) = pending[q].pop_front().unwrap();
                let class = if small_ids.binary_search(&u32_at(&m, 0)).is_ok() { small_class } else { traffic[q] };
                outbox.push((key, q, class, m));
            }
        }
        if last_status.elapsed() >= Duration::from_secs(1) {
            outbox.push((key, control_queue, traffic[control_queue], ctrl(STATUS_REQ, &(sizes.len() as u32).to_le_bytes())));
            last_status = Instant::now();
        }
        let p = poll(&handle, &mut outbox, &mut wanted);
        for (_, q, _c, m) in p.send_unreliable_rejected.into_iter().rev() {
            let id = u32_at(&m, 0);
            if id < CTRL_BASE { pending[q].push_front((id, m)); }
        }
        fec_trace.record(ns(), &p.fec_messages);
        for &(k, q, b) in &p.unreliable_send_free_bytes { if k == key { free[q] = b; } }
        if let Some((_, st)) = p.connection_stats.iter().find(|(k, _)| *k == key) { stats = *st; }
        for (_, d) in p.received_unreliable_messages {
            if let Parsed::Ok(STATUS, pl) = parse(&d) && pl.len() >= 4 {
                let count = u32_at(pl, 0) as usize;
                if pl.len() < 4+13*count+4 { continue; }
                let at = 4+13*count;
                let words = u32_at(pl, at) as usize;
                if pl.len() == at+4+8*words {
                    let v: Vec<u64> = (0..words).map(|i| u64_at(pl, at+4+8*i)).collect();
                    if let Some(r) = RxReport::from_words(&v) { receiver = r; }
                }
                for i in 0..count {
                    let at = 4+13*i; let id = u32_at(pl, at); let ok = pl[at+4] != 0; let t = u64_at(pl, at+5);
                    if recs.insert(id, (ok, t)).is_none() { last_growth = Instant::now(); }
                    if ok { last_delivery = last_delivery.max((t as i128-offset) as f64); }
                }
            }
        }
        if elapsed >= duration {
            if !drained && pending.iter().all(VecDeque::is_empty) && free.iter().all(|&b| b == u64::MAX) {
                drained = true;
                last_growth = Instant::now(); // status may have been backpressured for the entire bulk train
            }
            if recs.len() == sizes.len() || drained && last_growth.elapsed() > Duration::from_secs(a.num("idle", 10)) || elapsed > duration+drain_limit as f64 { break; }
        }
        std::thread::sleep(Duration::from_micros(300));
    }
    let wall = if last_delivery > start as f64 { (last_delivery-start as f64)/1e9 } else { (ns()-start) as f64/1e9 }.max(1e-9);
    let queues = queue_report(n, &sizes, &ids, &submitted, &recs, offset, wall, None);
    let window = queue_report(n, &sizes, &ids, &submitted, &recs, offset, duration, Some(cutoff));
    let small_sizes: Vec<_> = small_ids.iter().map(|_| 1000).collect();
    let small_times: Vec<_> = small_ids.iter().map(|&i| submitted[i as usize]).collect();
    let small_recs: HashMap<_, _> = small_ids.iter().enumerate().filter_map(|(i, id)| recs.get(id).map(|r| (i as u32, *r))).collect();
    let small = queue_report(1, &small_sizes, &vec![0; small_ids.len()], &small_times, &small_recs, offset, wall, None);
    let delivered = recs.values().filter(|r| r.0).count();
    let bytes: u64 = recs.iter().filter(|(_, r)| r.0).map(|(id, _)| sizes[*id as usize] as u64).sum();
    let gp = bytes as f64*8.0/1e6/wall;
    let json = format!("{{\"workload\":\"{mode}\",\"num_queues\":{n},\"duration_seconds\":{duration},\"wall_seconds\":{wall:.6},\"total_messages\":{},\"delivered\":{delivered},\"goodput_Mbitps\":{gp:.6},\"wire_bytes_per_delivered_byte\":{:.6},\"queues\":[{}],\"window_queues\":[{}],\"small\":{},\"rtt_ms_min\":{:.3},\"latency_method\":\"last-byte delivery minus first bulk submission or scheduled Poisson small arrival; ping offset error <= RTT/2\"}}\n", sizes.len(), stats.bytes_sent as f64/bytes.max(1) as f64, queues.join(","), window.join(","), small[0], pings[0].0 as f64/1e6);
    println!("{delivered}/{} delivered, total goodput {gp:.3} Mbit/s", sizes.len());
    let mut json = json;
    json.insert_str(json.len()-2, &format!(",\"packets_sent\":{},\"packets_lost\":{},\"spurious_losses\":{},\"receiver_rx_lost\":{},\"receiver_rx_reordered\":{},\"receiver_rx_late_beyond_window\":{},\"cc_rate_pps\":{:.3}", stats.packets_sent, stats.packets_lost, stats.spurious_losses, receiver.st.rx_lost, receiver.st.rx_reordered, receiver.st.rx_late_beyond_window, stats.cc_rate_upps as f64/1e6));
    json.insert_str(json.len()-2, &format!(",\"max_message_size\":{max_message_size},\"receiver_fec_worker_limit_events\":{},\"receiver_stale_fragments\":{},\"receiver_partials_evicted\":{},\"receiver_insert_failures\":{}", receiver.st.fec_worker_limit_events, receiver.st.rx_stale_fragments, receiver.st.rx_partial_evicted, receiver.st.rx_insert_failures));
    json.insert_str(json.len()-2, &format!(",\"receiver_fec_decode_peak_workers\":{},\"receiver_plain_admission_refusals\":{},\"receiver_fec_decode_admission_refusals\":{},\"receiver_fec_ingress_dropped_blocks\":{},\"receiver_recv_queue_dropped_messages\":{},\"receiver_kernel_rx_drops\":{}", receiver.st.fec_decode_peak_workers, receiver.st.rx_plain_admission_refusals, receiver.st.fec_decode_admission_refusals, receiver.st.fec_ingress_dropped_blocks, receiver.th.recv_queue_dropped_messages, receiver.th.kernel_rx_drops.map_or("null".into(), |n| n.to_string())));
    json.insert_str(json.len() - 2, &receiver.worker_limit_json());
    std::fs::write(a.str("out").unwrap_or("stp_bench_report.json"), json).unwrap();
    fec_trace.flush();
    drop(handle);
    if delivered != sizes.len() { std::process::exit(1); }
}
