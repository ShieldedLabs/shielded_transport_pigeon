//! Per-peer cloneable senders and single-consumer receivers, no forwarding thread.
mod api_support;
use shielded_transport_pigeon::{
    api::{Event, channel::Endpoint},
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
    client.connect(address).unwrap();
    let outgoing = client.accept_timeout(Duration::from_secs(5)).unwrap();
    let mut incoming = server.accept_timeout(Duration::from_secs(5)).unwrap();
    let sender = outgoing.sender.clone();
    std::thread::spawn(move || {
        sender
            .send_timeout(b"whole encrypted message".to_vec(), Duration::from_secs(5))
            .unwrap()
    })
    .join()
    .unwrap();
    if let Event::Message { peer, data } = incoming
        .receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
    {
        println!("{} bytes from {:?}", data.len(), peer.address);
    }
    client.close();
    server.close();
}
