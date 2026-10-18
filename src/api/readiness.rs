//! Level-triggered, runtime-free readiness for a game loop or external reactor.
//! `poll` reports readiness without consuming messages; drain with `try_recv`.
//! This is not an OS fd and cannot be registered in mio/epoll directly.
use super::{driver::Owner, *};
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}
impl Interest {
    pub const READABLE: Self = Self {
        readable: true,
        writable: false,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct Ready {
    pub token: usize,
    pub readable: bool,
    pub writable: bool,
    pub closed: bool,
}
struct Registration {
    peer: Option<ConnectionKey>,
    token: usize,
    interest: Interest,
}
pub struct Endpoint {
    owner: Owner,
    registrations: Vec<Registration>,
}
impl Endpoint {
    pub fn open(config: Config) -> io::Result<Self> {
        Ok(Self {
            owner: Owner::open(config)?,
            registrations: Vec::new(),
        })
    }
    /// `None` observes every peer and endpoint lifecycle. Reusing a token replaces it.
    pub fn register(&mut self, peer: Option<ConnectionKey>, token: usize, interest: Interest) {
        self.deregister(token);
        self.registrations.push(Registration {
            peer,
            token,
            interest,
        });
    }
    pub fn deregister(&mut self, token: usize) {
        self.registrations.retain(|r| r.token != token);
    }
    pub fn connect(&self, address: STPAddress) -> io::Result<ConnectionKey> {
        self.owner.shared.connect(address)
    }
    pub fn try_send(&self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        self.owner.shared.try_send(peer, data)
    }
    pub fn try_recv(&mut self) -> Result<Event, ReceiveError> {
        self.owner.shared.recv_timeout(None, false, Duration::ZERO)
    }
    /// Reuses the caller's Vec. Timeout is a maximum wait; zero is a snapshot.
    /// Writable means some bounded adapter space, not that an arbitrary size fits.
    pub fn poll(&mut self, events: &mut Vec<Ready>, timeout: Duration) {
        events.clear();
        let deadline = Instant::now().checked_add(timeout);
        let mut s = self.owner.shared.lock();
        loop {
            for r in &self.registrations {
                let readable = r.interest.readable
                    && s.events.iter().any(|e| {
                        r.peer.is_none() || e.peer_key() == r.peer || matches!(e, Event::Closed)
                    });
                let writable = r.interest.writable && self.owner.shared.writable(&s, r.peer);
                if readable || writable || s.closed {
                    events.push(Ready {
                        token: r.token,
                        readable,
                        writable,
                        closed: s.closed,
                    });
                }
            }
            if !events.is_empty() || s.closed {
                return;
            }
            let left = deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return;
            }
            s = self
                .owner
                .shared
                .changed
                .wait_timeout(s, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
    pub fn stats(&self) -> Stats {
        self.owner.shared.stats()
    }
    pub fn close(&mut self) {
        self.owner.close();
    }
}
