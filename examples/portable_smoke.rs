use shielded_transport_pigeon::{pump::Event, stp::*};
#[path = "support/lockfree_common.rs"] mod common;
use common::*; use std::time::{Duration, Instant}; const RESPONSE_BYTES: usize = 20_000_000;
const REQUEST: [u8; 128] = [0x39; 128];
fn pattern(i: usize) -> u8 { (i as u64).wrapping_mul(73).wrapping_add((i / 257) as u64) as u8 }
fn exchange(family: u8) {
    let response: Vec<u8> = (0..RESPONSE_BYTES).map(pattern).collect();
    let (server_pump, mut server, mut address) = setup_with(Default::default(), RESPONSE_BYTES);
    if family == 4 { address.ip = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(); }
    let server_worker = Worker::start(server_pump);
    let server_app = std::thread::spawn(move || {
        let _worker = server_worker; let deadline = Instant::now() + Duration::from_secs(120); let mut response = response;
        loop {
            if let Some(event) = server.try_recv() {
                match event {
                    Event::Message { peer, data } => {
                        assert_eq!(data.as_slice(), REQUEST, "invalid request");
                        while !server.try_send(peer, 0, Dscp::BestEffort, &mut response) {
                            assert!(Instant::now() < deadline, "response admission timeout");
                            std::thread::yield_now(); }
                        while !server.is_finished() && Instant::now() < deadline {
                            if let Some(Event::Message { data, .. }) = server.try_recv() {
                                assert_eq!(data.as_slice(), b"verified"); server.close();
                                return; }
                            std::thread::sleep(Duration::from_micros(100)); }
                        panic!("completion receipt timeout"); }
                    Event::ConnectFailed { .. } | Event::Disconnected { .. } => panic!("server connection failed"),
                    _ => {} } }
            assert!(Instant::now() < deadline, "request timeout");
            std::thread::sleep(Duration::from_micros(100)); } });
    let started = Instant::now(); let (client_pump, mut client, _) = setup_with(Default::default(), RESPONSE_BYTES);
    let mut client_worker = Worker::start(client_pump); let peer = address.connection_key();
    assert!(client.try_connect(address)); let deadline = started + Duration::from_secs(120); let mut request = REQUEST.to_vec();
    let elapsed = 'receiving: loop {
        while let Some(event) = client.try_recv() {
            match event {
                Event::Connected { .. } => { assert!(client.try_send(peer, 0, Dscp::BestEffort, &mut request)); }
                Event::Message { peer: source, data } => {
                    assert_eq!(source, peer); assert_eq!(data.len(), RESPONSE_BYTES);
                    assert!(data.iter().enumerate().all(|(i, &byte)| byte == pattern(i)), "response corruption");
                    break 'receiving started.elapsed(); }
                Event::ConnectFailed { .. } | Event::Disconnected { .. } => panic!("client connection failed"), } }
        assert!(Instant::now() < deadline, "response timeout");
        std::thread::sleep(Duration::from_micros(100)); };
    send(&mut client, peer, b"verified".to_vec()); server_app.join().unwrap(); client.close(); client_worker.stop();
    println!("PORTABLE_SMOKE_OK ipv{family} response_bytes={RESPONSE_BYTES} cold_sequence_s={:.6}", elapsed.as_secs_f64()); }
fn main() {
    match std::env::args().nth(1).as_deref() {
        None => { exchange(4); exchange(6); }
        Some("4") => exchange(4),
        Some("6") => exchange(6),
        _ => panic!("usage: portable_smoke [4|6]"), } }
