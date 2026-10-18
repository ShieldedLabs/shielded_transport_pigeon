//! Shared executable harness, not part of the library API.
#![allow(dead_code)]
use shielded_transport_pigeon::{
    api::{self, *},
    stp::*,
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    net::UdpSocket,
    pin::pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, Wake, Waker},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub enum Style {
    Core,
    Blocking,
    Async,
    Callback,
    Readiness,
    Channel,
}
pub const STYLES: [Style; 6] = [
    Style::Core,
    Style::Blocking,
    Style::Async,
    Style::Callback,
    Style::Readiness,
    Style::Channel,
];
struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}
/// Tiny parking executor, used to exercise actual wakeups without a dependency.
pub fn block_on_timeout<F: Future>(future: F, timeout: Duration) -> Option<F::Output> {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = TaskContext::from_waker(&waker);
    let mut future = pin!(future);
    let deadline = Instant::now() + timeout;
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return Some(v);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        std::thread::park_timeout(left);
    }
}
#[derive(Default)]
pub struct Capture {
    events: VecDeque<Event>,
    pub backpressures: usize,
}
impl api::callback::Handler for Capture {
    fn on_connect(&mut self, _: &api::callback::Context, p: Peer) {
        self.events.push_back(Event::Connected(p));
    }
    fn on_message(&mut self, _: &api::callback::Context, peer: Peer, data: Vec<u8>) {
        self.events.push_back(Event::Message { peer, data });
    }
    fn on_disconnect(&mut self, _: &api::callback::Context, p: Peer) {
        self.events.push_back(Event::Disconnected(p));
    }
    fn on_backpressure(&mut self, _: ConnectionKey) {
        self.backpressures += 1;
    }
    fn on_send_failed(&mut self, peer: ConnectionKey, data: Vec<u8>) {
        self.events.push_back(Event::SendFailed { peer, data });
    }
    fn on_close(&mut self) {
        self.events.push_back(Event::Closed);
    }
}
pub struct Direct {
    core: Option<NetworkThreadHandle>,
    wanted: Vec<(STPAddress, [u8; 64])>,
    peers: HashMap<ConnectionKey, Peer>,
    events: VecDeque<Event>,
    stats: Stats,
}
impl Direct {
    fn service(
        &mut self,
        initiate_connections: Vec<STPAddress>,
        send_unreliable: Vec<(
            ConnectionKey,
            usize,
            shielded_transport_pigeon::native_sockets::Dscp,
            Vec<u8>,
        )>,
    ) -> NetworkThreadPull {
        let mut p = service_connections(
            self.core.as_ref().unwrap(),
            NetworkThreadPush {
                wanted_connections: std::mem::take(&mut self.wanted),
                initiate_connections,
                send_unreliable,
                ..Default::default()
            },
        )
        .unwrap();
        self.wanted = std::mem::take(&mut p.current_connections);
        for (a, session) in &self.wanted {
            let key = a.connection_key();
            if !self.peers.contains_key(&key) {
                let peer = Peer {
                    address: Arc::new(a.clone()),
                    session: *session,
                };
                self.events.push_back(Event::Connected(peer.clone()));
                self.peers.insert(key, peer);
            }
        }
        for (k, data) in p.received_unreliable_messages.drain(..) {
            self.events.push_back(Event::Message {
                peer: self.peers[&k].clone(),
                data,
            });
        }
        self.stats.connections = std::mem::take(&mut p.connection_stats);
        p
    }
}
pub enum App {
    Core(Direct),
    Blocking(api::blocking::Endpoint),
    Async(api::asynchronous::Endpoint),
    Callback(api::callback::Endpoint<Capture>),
    Readiness(api::readiness::Endpoint, Vec<api::readiness::Ready>),
    Channel(
        api::channel::Endpoint,
        HashMap<ConnectionKey, api::channel::Connection>,
    ),
}
impl App {
    pub fn open(style: Style, c: Config) -> Self {
        match style {
            Style::Core => Self::Core(Direct {
                core: Some(new_network_thread_with_options(
                    c.keys,
                    c.bind.port(),
                    c.max_pps,
                    c.core_send_buffer,
                    c.max_message_size,
                    NetworkThreadOptions {
                        bind_ip: Some(c.bind.ip()),
                        ..Default::default()
                    },
                )),
                wanted: Vec::new(),
                peers: HashMap::new(),
                events: VecDeque::new(),
                stats: Stats::default(),
            }),
            Style::Blocking => Self::Blocking(api::blocking::Endpoint::open(c).unwrap()),
            Style::Async => Self::Async(api::asynchronous::Endpoint::open(c).unwrap()),
            Style::Callback => {
                Self::Callback(api::callback::Endpoint::open(c, Capture::default()).unwrap())
            }
            Style::Readiness => {
                let mut ep = api::readiness::Endpoint::open(c).unwrap();
                ep.register(None, 7, api::readiness::Interest::READABLE);
                Self::Readiness(ep, Vec::with_capacity(1))
            }
            Style::Channel => {
                Self::Channel(api::channel::Endpoint::open(c).unwrap(), HashMap::new())
            }
        }
    }
    pub fn connect(&mut self, a: STPAddress) -> ConnectionKey {
        match self {
            Self::Core(d) => {
                let key = a.connection_key();
                d.service(vec![a], vec![]);
                key
            }
            Self::Blocking(e) => e.connect(a).unwrap(),
            Self::Async(e) => e.connect(a).unwrap(),
            Self::Callback(e) => e.context().connect(a).unwrap(),
            Self::Readiness(e, _) => e.connect(a).unwrap(),
            Self::Channel(e, _) => e.connect(a).unwrap(),
        }
    }
    pub fn try_send(&mut self, peer: ConnectionKey, data: Vec<u8>) -> Result<(), SendError> {
        match self {
            Self::Core(d) => {
                let p = d.service(
                    vec![],
                    vec![(
                        peer,
                        0,
                        shielded_transport_pigeon::native_sockets::Dscp::BestEffort,
                        data,
                    )],
                );
                if let Some(item) = p.send_unreliable_rejected.into_iter().next() {
                    Err(SendError {
                        kind: SendErrorKind::Full,
                        data: item.3,
                    })
                } else if let Some(item) = p.send_unreliable_oversized.into_iter().next() {
                    Err(SendError {
                        kind: SendErrorKind::TooLarge,
                        data: item.3,
                    })
                } else {
                    Ok(())
                }
            }
            Self::Blocking(e) => e.try_send(peer, data),
            Self::Async(e) => e.try_send(peer, data),
            Self::Callback(e) => e.context().try_send(peer, data),
            Self::Readiness(e, _) => e.try_send(peer, data),
            Self::Channel(_, peers) => peers.get(&peer).unwrap().sender.try_send(data),
        }
    }
    pub fn send_timeout(
        &mut self,
        peer: ConnectionKey,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SendError> {
        match self {
            Self::Blocking(e) => e.send_timeout(peer, data, timeout),
            Self::Async(e) => {
                block_on_timeout(e.send(peer, data), timeout).expect("send Future timeout")
            }
            Self::Channel(_, peers) => peers.get(&peer).unwrap().sender.send_timeout(data, timeout),
            _ => self.try_send(peer, data),
        }
    }
    pub fn recv(&mut self, timeout: Duration) -> Result<Event, ReceiveError> {
        match self {
            Self::Core(d) => {
                let deadline = Instant::now() + timeout;
                loop {
                    if let Some(e) = d.events.pop_front() {
                        return Ok(e);
                    }
                    if d.core.is_none() {
                        return Err(ReceiveError::Closed);
                    }
                    d.service(vec![], vec![]);
                    if let Some(e) = d.events.pop_front() {
                        return Ok(e);
                    }
                    if Instant::now() >= deadline {
                        return Err(ReceiveError::TimedOut);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Self::Blocking(e) => e.recv_timeout(timeout),
            Self::Async(e) => {
                block_on_timeout(e.recv(), timeout).unwrap_or(Err(ReceiveError::TimedOut))
            }
            Self::Callback(e) => {
                if let Some(ev) = e.handler_mut().events.pop_front() {
                    return Ok(ev);
                }
                e.dispatch(timeout)?;
                e.handler_mut()
                    .events
                    .pop_front()
                    .ok_or(ReceiveError::TimedOut)
            }
            Self::Readiness(e, events) => {
                e.poll(events, timeout);
                if !events.is_empty() {
                    assert_eq!(events[0].token, 7);
                }
                e.try_recv()
            }
            Self::Channel(e, peers) => {
                if peers.is_empty() {
                    let connection = e.accept_timeout(timeout)?;
                    let peer = connection.peer.clone();
                    peers.insert(peer.key(), connection);
                    Ok(Event::Connected(peer))
                } else {
                    peers
                        .values_mut()
                        .next()
                        .unwrap()
                        .receiver
                        .recv_timeout(timeout)
                }
            }
        }
    }
    pub fn stats(&self) -> Stats {
        match self {
            Self::Core(d) => d.stats.clone(),
            Self::Blocking(e) => e.stats(),
            Self::Async(e) => e.stats(),
            Self::Callback(e) => e.stats(),
            Self::Readiness(e, _) => e.stats(),
            Self::Channel(e, _) => e.stats(),
        }
    }
    pub fn close(&mut self) {
        match self {
            Self::Core(d) => {
                if let Some(c) = d.core.take() {
                    c.shutdown();
                }
            }
            Self::Blocking(e) => e.close(),
            Self::Async(e) => e.close(),
            Self::Callback(e) => e.close(),
            Self::Readiness(e, _) => e.close(),
            Self::Channel(e, _) => e.close(),
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.close();
    }
}
pub fn keypair() -> IdentityKeyPair {
    new_keypair_from_connect_magic1(CONNECT_MAGIC1_Noise_IK_25519_ChaChaPoly_BLAKE2s).unwrap()
}
pub fn config(max: usize) -> Config {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    Config::new(socket.local_addr().unwrap(), vec![keypair()], max)
}
pub fn pair(
    style: Style,
    max: usize,
    pressure: bool,
) -> (App, App, ConnectionKey, ConnectionKey, u16, u16) {
    pair_with_idle_cap(style, max, pressure, Duration::from_millis(2))
}
pub fn pair_with_idle_cap(
    style: Style,
    max: usize,
    pressure: bool,
    cap: Duration,
) -> (App, App, ConnectionKey, ConnectionKey, u16, u16) {
    let mut ca = config(max);
    let mut cb = config(max);
    while cb.bind.port() == ca.bind.port() {
        cb = config(max);
    }
    ca.idle_service_interval = cap;
    cb.idle_service_interval = cap;
    if pressure {
        ca.send_slots = 1;
        ca.send_bytes = max;
        ca.core_send_buffer = (1_000_000, 1, 1);
        ca.max_pps = Some(1);
    }
    let (pa, pb) = (ca.bind.port(), cb.bind.port());
    let aa = STPAddress::from(
        "127.0.0.1"
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .to_ipv6_mapped(),
        pa,
        &ca.keys[0],
    );
    let ab = STPAddress::from(aa.ip, pb, &cb.keys[0]);
    let mut a = App::open(style, ca);
    let mut b = App::open(style, cb);
    std::thread::sleep(Duration::from_millis(20)); // legacy asynchronous bind startup
    a.connect(ab.clone());
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ak = None;
    let mut bk = None;
    while ak.is_none() || bk.is_none() {
        if ak.is_none() {
            if let Ok(Event::Connected(p)) = a.recv(Duration::from_millis(1)) {
                assert_eq!(*p.address, ab);
                ak = Some(p.key());
            }
        }
        if bk.is_none() {
            if let Ok(Event::Connected(p)) = b.recv(Duration::from_millis(1)) {
                assert_eq!(*p.address, aa);
                bk = Some(p.key());
            }
        }
        assert!(Instant::now() < deadline, "{style:?}: connect deadline");
    }
    (a, b, ak.unwrap(), bk.unwrap(), pa, pb)
}
pub fn payload(size: usize, index: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(17).wrapping_add(index * 31) % 251) as u8)
        .collect()
}
pub fn demo(style: Style) {
    let (mut a, mut b, to, _, _, _) = pair(style, 1_000_000, false);
    a.send_timeout(
        to,
        b"whole encrypted message".to_vec(),
        Duration::from_secs(5),
    )
    .unwrap();
    loop {
        if let Event::Message { peer, data } = b.recv(Duration::from_secs(5)).unwrap() {
            println!("{style:?}: {} bytes from {:?}", data.len(), peer.address);
            break;
        }
    }
    a.close();
    b.close();
}
