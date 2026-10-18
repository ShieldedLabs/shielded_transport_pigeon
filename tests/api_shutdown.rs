extern crate shielded_transport_pigeon as stp_core;
#[path = "support/pump_thread.rs"]
mod pump_thread;
use pump_thread::*;
// Regression for the minimal core hook needed by all application facades.
#[cfg(target_os = "linux")]
#[test]
fn shutdown_releases_bound_udp_port() {
    use shielded_transport_pigeon::stp::*;
    use std::net::UdpSocket;
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port(); drop(probe);
    let key = new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap();
    let core = new_network_thread_with_options(vec![key], port, None, (1_000_000, 1 << 20, 1 << 20), 1_000_000,
        NetworkThreadOptions { bind_ip: Some("127.0.0.1".parse().unwrap()), ..Default::default() });
    core.shutdown();
    let _rebound = UdpSocket::bind(("127.0.0.1", port)).unwrap();
}
