//! Level readiness, caller-owned token/event buffer, nonblocking event draining.
mod api_support;
use shielded_transport_pigeon::{
    api::{
        Event,
        readiness::{Endpoint, Interest},
    },
    stp::STPAddress,
};
use std::time::Duration;
fn main() {
    let c = api_support::config(1_000_000);
    let address = STPAddress::from(
        "127.0.0.1"
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .to_ipv6_mapped(),
        c.bind.port(),
        &c.keys[0],
    );
    let mut server = Endpoint::open(c).unwrap();
    let mut client = Endpoint::open(api_support::config(1_000_000)).unwrap();
    client.register(None, 1, Interest::READABLE);
    server.register(None, 2, Interest::READABLE);
    client.connect(address).unwrap();
    let mut ready = Vec::with_capacity(1);
    let peer = loop {
        client.poll(&mut ready, Duration::from_secs(5));
        if let Ok(Event::Connected(p)) = client.try_recv() {
            break p;
        }
    };
    client
        .try_send(peer.key(), b"whole encrypted message".to_vec())
        .unwrap();
    let mut received = false;
    while !received {
        server.poll(&mut ready, Duration::from_secs(5));
        for event in &ready {
            assert_eq!(event.token, 2);
        }
        while let Ok(event) = server.try_recv() {
            if let Event::Message { peer, data } = event {
                println!("{} bytes from {:?}", data.len(), peer.address);
                received = true;
            }
        }
    }
    client.close();
    server.close();
}
