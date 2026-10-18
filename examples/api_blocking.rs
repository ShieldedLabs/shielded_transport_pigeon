//! Run: cargo run --example api_blocking (under the repository's network locks).
mod api_support;
use shielded_transport_pigeon::{
    api::{Event, blocking::Endpoint},
    stp::STPAddress,
};
use std::time::Duration;
fn main() {
    let server_config = api_support::config(1_000_000); // explicit, never defaulted
    let address = STPAddress::from(
        "127.0.0.1"
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .to_ipv6_mapped(),
        server_config.bind.port(),
        &server_config.keys[0],
    );
    let mut server = Endpoint::open(server_config).unwrap();
    let mut client = Endpoint::open(api_support::config(1_000_000)).unwrap();
    client.connect(address).unwrap();
    let peer = loop {
        if let Event::Connected(p) = client.recv_timeout(Duration::from_secs(5)).unwrap() {
            break p;
        }
    };
    client
        .send_timeout(
            peer.key(),
            b"whole encrypted message".to_vec(),
            Duration::from_secs(5),
        )
        .unwrap();
    loop {
        if let Event::Message { peer, data } = server.recv_timeout(Duration::from_secs(5)).unwrap()
        {
            println!("{} bytes from {:?}", data.len(), peer.address);
            break;
        }
    }
    client.close();
    server.close();
}
