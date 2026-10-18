//! Single owner of the legacy handle. No facade ever calls the unsafe-to-share
//! core exchange concurrently. Replace `wait_for_core_or_command` when the core
//! gains receive/queue-space notification; facade and Future code need not change.
use super::*;
use crate::native_sockets::Dscp;
use crate::stp::{self, NetworkThreadOptions, NetworkThreadPush};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    task::Waker,
    thread::{self, JoinHandle},
    time::Instant,
};

type Pending = (ConnectionKey, usize, Dscp, Vec<u8>);
pub(super) struct State {
    pub events: VecDeque<Event>,
    pub peers: HashMap<ConnectionKey, Peer>,
    pending: Vec<Pending>,
    connects: Vec<STPAddress>,
    pub closed: bool,
    pub stopping: bool,
    pub stats: Stats,
    stats_requested: u64,
    stats_completed: u64,
    receive_bytes: usize,
    pub waiters: BTreeMap<u64, Waker>,
    next_waiter: u64,
}
pub(super) struct Shared {
    pub state: Mutex<State>,
    pub changed: Condvar,
    core_ready: std::sync::OnceLock<Arc<stp::CoreReady>>,
    max_message_size: usize,
    send_slots: usize,
    send_bytes: usize,
    receive_slots: usize,
    receive_limit: usize,
}
pub(super) struct Owner {
    pub shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl Owner {
    pub fn open(c: Config) -> io::Result<Self> {
        if c.bind.port() == 0
            || c.keys.is_empty()
            || c.keys
                .iter()
                .any(|k| k.public.len() < 2 || k.private.is_empty())
            || !(1..=stp::MAX_JUMBOGRAM_LEN).contains(&c.max_message_size)
            || c.send_slots == 0
            || c.send_bytes == 0
            || c.receive_slots == 0
            || c.receive_bytes == 0
            || c.core_send_buffer.1 > c.core_send_buffer.2
            || c.service_interval.is_zero()
            || c.idle_service_interval < c.service_interval
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid explicit STP API configuration (nonzero port and message limit required)",
            ));
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                events: VecDeque::new(),
                peers: HashMap::new(),
                pending: Vec::new(),
                connects: Vec::new(),
                closed: false,
                stopping: false,
                stats: Stats::default(),
                stats_requested: 0,
                stats_completed: 0,
                receive_bytes: 0,
                waiters: BTreeMap::new(),
                next_waiter: 0,
            }),
            changed: Condvar::new(),
            core_ready: std::sync::OnceLock::new(),
            max_message_size: c.max_message_size,
            send_slots: c.send_slots,
            send_bytes: c.send_bytes,
            receive_slots: c.receive_slots,
            receive_limit: c.receive_bytes,
        });
        // The core binds synchronously. Keep startup on the caller's thread so
        // failures cannot strand a live-looking facade with a dead worker.
        let core = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut options = NetworkThreadOptions::default();
            options.bind_ip = Some(c.bind.ip());
            stp::new_network_thread_with_options(
                c.keys,
                c.bind.port(),
                c.max_pps,
                c.core_send_buffer,
                c.max_message_size,
                options,
            )
        }))
        .map_err(|_| {
            io::Error::other("STP core initialization failed (see core panic diagnostic)")
        })?;
        shared.core_ready.set(core.readiness()).unwrap();
        let worker = shared.clone();
        let thread = thread::Builder::new()
            .name("stp-api".into())
            .spawn(move || run(worker, core))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }
    pub fn close(&mut self) {
        {
            let mut s = self.shared.lock();
            s.stopping = true;
        }
        self.shared.signal();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}

impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Wake arbitrary application code only AFTER releasing the state lock.
    pub fn signal(&self) {
        if let Some(ready) = self.core_ready.get() { ready.notify(); }
        self.publish();
    }
    fn publish(&self) {
        let waiters = { std::mem::take(&mut self.lock().waiters) };
        self.changed.notify_all();
        for (_, w) in waiters {
            w.wake();
        }
    }
    pub fn waiter(&self) -> u64 {
        let mut s = self.lock();
        let id = s.next_waiter;
        s.next_waiter += 1;
        id
    }
    pub fn connect(&self, address: STPAddress) -> io::Result<ConnectionKey> {
        if address.key.len() < 2 || address.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid peer address",
            ));
        }
        let key = address.connection_key();
        let mut s = self.lock();
        if s.closed || s.stopping {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if s.connects.len() >= self.send_slots {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        s.connects.push(address);
        drop(s);
        self.signal();
        Ok(key)
    }
    pub fn writable(&self, s: &State, peer: Option<ConnectionKey>) -> bool {
        !s.closed
            && !s.stopping
            && s.stats.queued_sends < self.send_slots
            && s.stats.queued_send_bytes < self.send_bytes
            && peer.map_or(!s.peers.is_empty(), |p| s.peers.contains_key(&p))
    }
    pub fn try_send(&self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        let mut s = self.lock();
        let result = self.admit(&mut s, peer, data);
        drop(s);
        if result.is_ok() {
            self.signal();
        }
        result
    }
    pub fn admit(
        &self,
        s: &mut State,
        peer: ConnectionKey,
        data: Vec<u8>,
    ) -> Result<(), SendError> {
        let kind = if s.closed || s.stopping {
            Some(SendErrorKind::Closed)
        } else if data.len() > self.max_message_size || data.capacity() > self.send_bytes {
            Some(SendErrorKind::TooLarge)
        } else if !s.peers.contains_key(&peer) {
            Some(SendErrorKind::NotConnected)
        } else if s.stats.queued_sends >= self.send_slots
            || data.capacity() > self.send_bytes.saturating_sub(s.stats.queued_send_bytes)
        {
            Some(SendErrorKind::Full)
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err(SendError { kind, data });
        }
        s.stats.queued_sends += 1;
        s.stats.queued_send_bytes += data.capacity();
        s.pending.push((peer, 0, Dscp::BestEffort, data));
        Ok(())
    }
    pub fn send_timeout(
        &self,
        peer: ConnectionKey,
        mut data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SendError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut s = self.lock();
        loop {
            match self.admit(&mut s, peer, data) {
                Ok(()) => {
                    drop(s);
                    self.signal();
                    return Ok(());
                }
                Err(e) if e.kind == SendErrorKind::Full => {
                    data = e.data;
                }
                Err(e) => return Err(e),
            }
            let left = deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return Err(SendError {
                    kind: SendErrorKind::TimedOut,
                    data,
                });
            }
            s = self
                .changed
                .wait_timeout(s, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
    pub fn pop(
        &self,
        s: &mut State,
        peer: Option<ConnectionKey>,
        connections_only: bool,
    ) -> Option<Event> {
        let index = s.events.iter().position(|e| {
            (!connections_only || matches!(e, Event::Connected(_)))
                && peer.is_none_or(|p| e.peer_key() == Some(p) || matches!(e, Event::Closed))
        })?;
        let e = s.events.remove(index)?;
        s.receive_bytes = s.receive_bytes.saturating_sub(event_bytes(&e));
        Some(e)
    }
    pub fn recv_timeout(
        &self,
        peer: Option<ConnectionKey>,
        connections_only: bool,
        timeout: Duration,
    ) -> Result<Event, ReceiveError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut s = self.lock();
        loop {
            if let Some(e) = self.pop(&mut s, peer, connections_only) {
                return Ok(e);
            }
            if s.closed {
                return Err(ReceiveError::Closed);
            }
            let left = deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return Err(ReceiveError::TimedOut);
            }
            s = self
                .changed
                .wait_timeout(s, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
    fn push(&self, s: &mut State, e: Event) {
        let n = event_bytes(&e);
        if n > self.receive_limit {
            s.stats.dropped_receive_messages += 1;
            return;
        }
        while s.events.len() >= self.receive_slots || s.receive_bytes + n > self.receive_limit {
            if let Some(old) = s.events.pop_front() {
                s.receive_bytes -= event_bytes(&old);
                s.stats.dropped_events += 1;
                if matches!(old, Event::Message { .. }) {
                    s.stats.dropped_receive_messages += 1;
                }
            } else {
                break;
            }
        }
        s.receive_bytes += n;
        s.events.push_back(e);
    }
    pub fn stats(&self) -> Stats {
        let mut s = self.lock();
        if let Some(ready) = self.core_ready.get().filter(|_| !s.closed && !s.stopping) {
            s.stats_requested += 1;
            let requested = s.stats_requested;
            ready.notify();
            s = self.changed.wait_while(s, |s| s.stats_completed < requested && !s.closed && !s.stopping)
                .unwrap_or_else(|e| e.into_inner());
        }
        s.stats.clone()
    }
}
fn event_bytes(e: &Event) -> usize {
    match e {
        Event::Message { data, .. } | Event::SendFailed { data, .. } => data.capacity(),
        _ => 0,
    }
}

/// Generation and command admission share one coalescing event. The generation
/// is consumed BEFORE each exchange, so an edge during the exchange is retained.
fn run(shared: Arc<Shared>, core: stp::NetworkThreadHandle) {
    let ready = shared.core_ready.get().unwrap();
    let mut observed = 0;
    let mut wanted = Vec::new();
    let mut retry = Vec::new();
    let mut current = HashMap::new();
    loop {
        ready.wait(&mut observed);
        if core.is_finished() { break; }
        let (connects, mut pending, stats_request) = {
            let mut s = shared.lock();
            if s.stopping {
                break;
            }
            (
                std::mem::take(&mut s.connects),
                std::mem::take(&mut s.pending),
                s.stats_requested,
            )
        };
        retry.append(&mut pending);
        // Arm before submitting, never after the rejection: capacity may be
        // reclaimed as soon as the core completes the exchange.
        ready.send_space.store(!retry.is_empty(), std::sync::atomic::Ordering::Release);
        let submitted_slots = retry.len();
        let submitted_bytes: usize = retry.iter().map(|p| p.3.capacity()).sum();
        let Some(pull) = stp::service_connections(
            &core,
            NetworkThreadPush {
                wanted_connections: wanted,
                initiate_connections: connects,
                send_unreliable: std::mem::take(&mut retry),
                ..Default::default()
            },
        ) else {
            break;
        };
        wanted = pull.current_connections;
        let mut s = shared.lock();
        let mut activity = !pull.received_unreliable_messages.is_empty()
            || !pull.send_unreliable_oversized.is_empty()
            || !pull.send_unreliable_invalid_queue.is_empty();
        current.clear();
        for (a, session) in &wanted {
            let key = a.connection_key();
            let p = match s.peers.get(&key).filter(|p| p.session == *session) {
                Some(p) => p.clone(),
                None => {
                    activity = true;
                    let p = Peer {
                        address: Arc::new(a.clone()),
                        session: *session,
                    };
                    shared.push(&mut s, Event::Connected(p.clone()));
                    p
                }
            };
            current.insert(key, p);
        }
        let disconnected: Vec<_> = s
            .peers
            .iter()
            .filter(|(k, _)| !current.contains_key(k))
            .map(|(_, p)| p.clone())
            .collect();
        activity |= !disconnected.is_empty();
        for p in disconnected {
            shared.push(&mut s, Event::Disconnected(p));
        }
        std::mem::swap(&mut s.peers, &mut current);
        s.stats.connections = pull.connection_stats;
        for (k, data) in pull.received_unreliable_messages {
            if let Some(peer) = s.peers.get(&k).cloned() {
                s.stats.received_messages += 1;
                shared.push(&mut s, Event::Message { peer, data });
            }
        }
        s.stats.core_rejections += pull.send_unreliable_rejected.len() as u64;
        for item in pull.send_unreliable_rejected {
            if s.peers.contains_key(&item.0) {
                retry.push(item);
            } else {
                shared.push(
                    &mut s,
                    Event::SendFailed {
                        peer: item.0,
                        data: item.3,
                    },
                );
            }
        }
        for item in pull
            .send_unreliable_oversized
            .into_iter()
            .chain(pull.send_unreliable_invalid_queue)
        {
            shared.push(
                &mut s,
                Event::SendFailed {
                    peer: item.0,
                    data: item.3,
                },
            );
        }
        s.stats.queued_sends -= submitted_slots - retry.len();
        s.stats.queued_send_bytes -=
            submitted_bytes - retry.iter().map(|p| p.3.capacity()).sum::<usize>();
        activity |= submitted_slots != retry.len();
        ready.send_space.store(!retry.is_empty(), std::sync::atomic::Ordering::Release);
        s.stats_completed = stats_request;
        drop(s);
        shared.changed.notify_all();
        if activity {
            shared.publish();
        }
    }
    // Joins the actual socket owner, not just this adapter worker.
    core.shutdown();
    let mut s = shared.lock();
    s.closed = true;
    let peers: Vec<_> = s.peers.drain().map(|(_, p)| p).collect();
    for p in peers {
        shared.push(&mut s, Event::Disconnected(p));
    }
    s.pending.clear();
    s.stats.queued_sends = 0;
    s.stats.queued_send_bytes = 0;
    shared.push(&mut s, Event::Closed);
    drop(s);
    shared.signal();
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shared() -> Shared {
        let address = STPAddress {
            key: vec![1; 32],
            ..Default::default()
        };
        let peer = Peer {
            address: Arc::new(address),
            session: [0; 64],
        };
        Shared {
            state: Mutex::new(State {
                peers: [(peer.key(), peer)].into(),
                events: VecDeque::new(),
                pending: Vec::new(),
                connects: Vec::new(),
                closed: false,
                stopping: false,
                stats: Stats::default(),
                stats_requested: 0,
                stats_completed: 0,
                receive_bytes: 0,
                waiters: BTreeMap::new(),
                next_waiter: 0,
            }),
            changed: Condvar::new(),
            core_ready: std::sync::OnceLock::new(),
            max_message_size: 100,
            send_slots: 1,
            send_bytes: 100,
            receive_slots: 2,
            receive_limit: 100,
        }
    }
    #[test]
    fn stats_requests_and_waits_for_a_fresh_idle_exchange() {
        let shared = Arc::new(shared());
        let ready = Arc::new(stp::CoreReady::default());
        let mut observed = 0;
        ready.wait(&mut observed);
        shared.core_ready.set(ready.clone()).unwrap();
        let worker = shared.clone();
        let thread = thread::spawn(move || {
            ready.wait(&mut observed);
            let mut s = worker.lock();
            assert_eq!(s.stats_requested, 1);
            s.stats.received_messages = 42;
            s.stats_completed = s.stats_requested;
            drop(s);
            worker.changed.notify_all();
        });
        assert_eq!(shared.stats().received_messages, 42);
        thread.join().unwrap();
    }

    #[test]
    fn admission_moves_payload_without_copying_and_counts_capacity() {
        let shared = shared();
        let key = *shared.lock().peers.keys().next().unwrap();
        let mut data = Vec::with_capacity(100);
        data.extend_from_slice(b"hello");
        let ptr = data.as_ptr();
        shared.try_send(key, data).unwrap();
        assert_eq!(shared.lock().pending[0].3.as_ptr(), ptr);
        assert_eq!(shared.stats().queued_send_bytes, 100);
        let data = vec![7];
        let ptr = data.as_ptr();
        let err = shared.try_send(key, data).unwrap_err();
        assert_eq!(err.kind, SendErrorKind::Full);
        assert_eq!(err.data.as_ptr(), ptr);
    }
    #[test]
    fn receive_mailbox_is_bounded_in_slots_and_capacity() {
        let shared = shared();
        let mut s = shared.lock();
        let peer = s.peers.values().next().unwrap().clone();
        for _ in 0..3 {
            shared.push(
                &mut s,
                Event::Message {
                    peer: peer.clone(),
                    data: vec![1; 60],
                },
            );
        }
        assert_eq!(s.events.len(), 1);
        assert_eq!(s.receive_bytes, 60);
        assert_eq!(s.stats.dropped_receive_messages, 2);
        for _ in 0..3 {
            shared.push(&mut s, Event::Connected(peer.clone()));
        }
        assert_eq!(s.events.len(), 2);
        assert_eq!(s.receive_bytes, 0);
        assert_eq!(s.stats.dropped_events, 4);
    }
}
