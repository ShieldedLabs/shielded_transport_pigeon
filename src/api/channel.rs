//! Per-peer channels: cloneable send side, single-owner receive side, one shared
//! bounded endpoint mailbox (no forwarding thread or payload copy per connection).
//! The endpoint owns lifetime: dropping it closes all channel handles.
use super::{
    driver::{Owner, Shared},
    *,
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct Endpoint {
    owner: Owner,
}
impl Endpoint {
    pub fn open(config: Config) -> io::Result<Self> {
        Ok(Self {
            owner: Owner::open(config)?,
        })
    }
    pub fn connect(&self, address: STPAddress) -> io::Result<ConnectionKey> {
        self.owner.shared.connect(address)
    }
    /// Returns a sender/receiver pair for the next authenticated inbound OR outbound
    /// connection. Outbound users match `Connection::peer.key()` with connect's key.
    pub fn accept_timeout(&mut self, timeout: Duration) -> Result<Connection, ReceiveError> {
        match self.owner.shared.recv_timeout(None, true, timeout)? {
            Event::Connected(peer) => {
                let sender = Sender {
                    shared: self.owner.shared.clone(),
                    peer: peer.key(),
                };
                let receiver = Receiver {
                    shared: self.owner.shared.clone(),
                    peer: peer.key(),
                };
                Ok(Connection {
                    peer,
                    sender,
                    receiver,
                })
            }
            _ => unreachable!(),
        }
    }
    pub fn stats(&self) -> Stats {
        self.owner.shared.stats()
    }
    pub fn close(&mut self) {
        self.owner.close();
    }
}
pub struct Connection {
    pub peer: Peer,
    pub sender: Sender,
    pub receiver: Receiver,
}
#[derive(Clone)]
pub struct Sender {
    shared: Arc<Shared>,
    peer: ConnectionKey,
}
impl Sender {
    pub fn try_send(&self, data: Vec<u8>) -> Result<(), SendError> {
        self.shared.try_send(self.peer, data)
    }
    pub fn send_timeout(&self, data: Vec<u8>, timeout: Duration) -> Result<(), SendError> {
        self.shared.send_timeout(self.peer, data, timeout)
    }
    pub fn peer(&self) -> ConnectionKey {
        self.peer
    }
    pub fn stats(&self) -> Stats {
        self.shared.stats()
    }
}
/// Not Clone: one consumer per peer. Other peers' messages remain in the mailbox.
pub struct Receiver {
    shared: Arc<Shared>,
    peer: ConnectionKey,
}
impl Receiver {
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Event, ReceiveError> {
        self.shared.recv_timeout(Some(self.peer), false, timeout)
    }
    pub fn try_recv(&mut self) -> Result<Event, ReceiveError> {
        self.recv_timeout(Duration::ZERO)
    }
}
