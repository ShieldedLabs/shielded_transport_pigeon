//! Blocking endpoint: one receiver, condvar-backed deadlines, no application polling.
use super::{driver::Owner, *};
use std::{io, time::Duration};

pub struct Endpoint {
    pub(super) owner: Owner,
}
impl Endpoint {
    pub fn open(config: Config) -> io::Result<Self> {
        Ok(Self {
            owner: Owner::open(config)?,
        })
    }
    /// Initiates asynchronously. `Connected` is the authenticated connect/accept result.
    pub fn connect(&self, address: STPAddress) -> io::Result<ConnectionKey> {
        self.owner.shared.connect(address)
    }
    /// Admission to a bounded adapter queue, NOT a delivery acknowledgement.
    pub fn try_send(&self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        self.owner.shared.try_send(peer, data)
    }
    /// Waits for local queue space. Timeout returns the original buffer.
    pub fn send_timeout(
        &self,
        peer: ConnectionKey,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SendError> {
        self.owner.shared.send_timeout(peer, data, timeout)
    }
    /// Includes inbound `Connected` (automatic acceptance), messages, and lifecycle events.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Event, ReceiveError> {
        self.owner.shared.recv_timeout(None, false, timeout)
    }
    pub fn stats(&self) -> Stats {
        self.owner.shared.stats()
    }
    /// Immediate local shutdown; no flush or delivery guarantee. Joins both threads.
    pub fn close(&mut self) {
        self.owner.close();
    }
}
