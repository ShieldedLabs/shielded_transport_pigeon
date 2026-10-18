//! Runtime-independent Futures, using a tiny parking executor only for this example.
mod api_support;
use shielded_transport_pigeon::{
    api::{Event, asynchronous::Endpoint},
    stp::STPAddress,
};
use std::time::Duration;
fn main() {
    let server_config = api_support::config(1_000_000);
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
    api_support::block_on_timeout(
        async {
            let peer = loop {
                if let Event::Connected(p) = client.recv().await.unwrap() {
                    break p;
                }
            };
            client
                .send(peer.key(), b"whole encrypted message".to_vec())
                .await
                .unwrap();
            loop {
                if let Event::Message { peer, data } = server.recv().await.unwrap() {
                    println!("{} bytes from {:?}", data.len(), peer.address);
                    break;
                }
            }
        },
        Duration::from_secs(10),
    )
    .expect("loopback deadline");
    client.close();
    server.close();
}
