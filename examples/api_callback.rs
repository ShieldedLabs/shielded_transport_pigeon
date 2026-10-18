//! Handler callbacks execute on this application's dispatch thread, not the worker.
mod api_support;
use shielded_transport_pigeon::{
    api::{
        Peer,
        callback::{Context, Endpoint, Handler},
    },
    stp::{ConnectionKey, STPAddress},
};
use std::time::Duration;
#[derive(Default)]
struct Application {
    peer: Option<ConnectionKey>,
    received: bool,
}
impl Handler for Application {
    fn on_connect(&mut self, _: &Context, peer: Peer) {
        self.peer = Some(peer.key());
    }
    fn on_message(&mut self, _: &Context, peer: Peer, data: Vec<u8>) {
        println!("{} bytes from {:?}", data.len(), peer.address);
        self.received = true;
    }
    fn on_backpressure(&mut self, peer: ConnectionKey) {
        eprintln!("local admission full: {peer:?}");
    }
}
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
    let mut server = Endpoint::open(c, Application::default()).unwrap();
    let mut client =
        Endpoint::open(api_support::config(1_000_000), Application::default()).unwrap();
    client.context().connect(address).unwrap();
    while client.handler().peer.is_none() {
        client.dispatch(Duration::from_secs(5)).unwrap();
    }
    client
        .context()
        .try_send(
            client.handler().peer.unwrap(),
            b"whole encrypted message".to_vec(),
        )
        .unwrap();
    while !server.handler().received {
        server.dispatch(Duration::from_secs(5)).unwrap();
    }
    client.close();
    server.close();
    while server.dispatch(Duration::ZERO).is_ok() {} // deliver disconnect + close callbacks
}
