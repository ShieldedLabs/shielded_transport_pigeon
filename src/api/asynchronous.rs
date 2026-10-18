//! Runtime-independent Futures. No runtime dependency, helper thread per Future,
//! timer in `poll`, or self-waking busy loop. One receiver is enforced by `&mut`.
//! Dropping a pending Send cancels it before admission; dropping Recv consumes nothing.
use super::{
    driver::{Owner, Shared},
    *,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
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
    pub fn try_send(&self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        self.owner.shared.try_send(peer, data)
    }
    pub fn send(&self, peer: ConnectionKey, data: Vec<u8>) -> Send {
        Send {
            shared: self.owner.shared.clone(),
            id: self.owner.shared.waiter(),
            peer,
            data: Some(data),
        }
    }
    pub fn recv(&mut self) -> Recv<'_> {
        Recv {
            shared: self.owner.shared.clone(),
            id: self.owner.shared.waiter(),
            _borrow: std::marker::PhantomData,
        }
    }
    pub fn stats(&self) -> Stats {
        self.owner.shared.stats()
    }
    /// Synchronous, deterministic shutdown. Normally a sub-millisecond join;
    /// do this outside a latency-sensitive executor worker.
    pub fn close(&mut self) {
        self.owner.close();
    }
}

#[must_use = "a Future does nothing until polled"]
pub struct Send {
    shared: Arc<Shared>,
    id: u64,
    peer: ConnectionKey,
    data: Option<Vec<u8>>,
}
impl Future for Send {
    type Output = Result<(), SendError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut s = this.shared.lock();
        let data = this.data.take().expect("Send polled after completion");
        match this.shared.admit(&mut s, this.peer, data) {
            Ok(()) => {
                s.waiters.remove(&this.id);
                drop(s);
                this.shared.signal();
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind == SendErrorKind::Full => {
                this.data = Some(e.data);
                s.waiters.insert(this.id, cx.waker().clone());
                Poll::Pending
            }
            Err(e) => {
                s.waiters.remove(&this.id);
                Poll::Ready(Err(e))
            }
        }
    }
}
impl Drop for Send {
    fn drop(&mut self) {
        self.shared.lock().waiters.remove(&self.id);
    }
}

#[must_use = "a Future does nothing until polled"]
pub struct Recv<'a> {
    shared: Arc<Shared>,
    id: u64,
    _borrow: std::marker::PhantomData<&'a mut Endpoint>,
}
impl Future for Recv<'_> {
    type Output = Result<Event, ReceiveError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut s = this.shared.lock();
        if let Some(e) = this.shared.pop(&mut s, None, false) {
            s.waiters.remove(&this.id);
            return Poll::Ready(Ok(e));
        }
        if s.closed {
            s.waiters.remove(&this.id);
            return Poll::Ready(Err(ReceiveError::Closed));
        }
        s.waiters.insert(this.id, cx.waker().clone());
        Poll::Pending
    }
}
impl Drop for Recv<'_> {
    fn drop(&mut self) {
        self.shared.lock().waiters.remove(&self.id);
    }
}
