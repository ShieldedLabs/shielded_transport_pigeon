//! Caller-driven callbacks: handlers run on YOUR thread, never the network worker.
//! A callback can submit with `Context::try_send` without reentrant mutex locking.
use super::{
    driver::{Owner, Shared},
    *,
};
use std::{io, sync::Arc, time::Duration};

pub trait Handler {
    fn on_connect(&mut self, _cx: &Context, _peer: Peer) {}
    fn on_message(&mut self, cx: &Context, peer: Peer, data: Vec<u8>);
    fn on_disconnect(&mut self, _cx: &Context, _peer: Peer) {}
    /// Called after a callback's `try_send` observes a full adapter queue.
    fn on_backpressure(&mut self, _peer: ConnectionKey) {}
    fn on_send_failed(&mut self, _peer: ConnectionKey, _data: Vec<u8>) {}
    fn on_close(&mut self) {}
}
/// Lightweight cloneable command handle; keeping it alive does not keep the endpoint open.
#[derive(Clone)]
pub struct Context {
    shared: Arc<Shared>,
    backpressure: Arc<std::sync::Mutex<Vec<ConnectionKey>>>,
}
impl Context {
    pub fn try_send(&self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        let r = self.shared.try_send(peer, data);
        if r.as_ref().is_err_and(|e| e.kind == SendErrorKind::Full) {
            let mut pending = self.backpressure.lock().unwrap();
            if !pending.contains(&peer) {
                pending.push(peer);
            }
        }
        r
    }
    pub fn connect(&self, address: STPAddress) -> io::Result<ConnectionKey> {
        self.shared.connect(address)
    }
    pub fn stats(&self) -> Stats {
        self.shared.stats()
    }
}
pub struct Endpoint<H: Handler> {
    owner: Owner,
    handler: H,
    context: Context,
}
impl<H: Handler> Endpoint<H> {
    pub fn open(config: Config, handler: H) -> io::Result<Self> {
        let owner = Owner::open(config)?;
        let context = Context {
            shared: owner.shared.clone(),
            backpressure: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        Ok(Self {
            owner,
            handler,
            context,
        })
    }
    pub fn context(&self) -> Context {
        self.context.clone()
    }
    pub fn handler(&self) -> &H {
        &self.handler
    }
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }
    /// Dispatch one event, waiting at most timeout. Bounds callback work per tick.
    pub fn dispatch(&mut self, timeout: Duration) -> Result<(), ReceiveError> {
        let pressures = std::mem::take(&mut *self.context.backpressure.lock().unwrap());
        for peer in pressures {
            self.handler.on_backpressure(peer);
        }
        match self.owner.shared.recv_timeout(None, false, timeout)? {
            Event::Connected(p) => self.handler.on_connect(&self.context, p),
            Event::Message { peer, data } => self.handler.on_message(&self.context, peer, data),
            Event::Disconnected(p) => self.handler.on_disconnect(&self.context, p),
            Event::SendFailed { peer, data } => self.handler.on_send_failed(peer, data),
            Event::Closed => self.handler.on_close(),
        }
        Ok(())
    }
    pub fn stats(&self) -> Stats {
        self.owner.shared.stats()
    }
    /// Closes transport. Dispatch remaining events to deliver on_disconnect/on_close.
    pub fn close(&mut self) {
        self.owner.close();
    }
}
