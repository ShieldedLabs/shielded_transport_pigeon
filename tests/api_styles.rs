//! Loopback-only integration contract shared by all five application interfaces.
#[path = "../examples/api_support/mod.rs"]
mod support;
use shielded_transport_pigeon::api::*;
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use support::*;

fn contract(style: Style) {
    let (mut a, mut b, to, from, pa, pb) = pair(style, 1_000_000, false);
    assert_eq!(b.recv(Duration::ZERO).unwrap_err(), ReceiveError::TimedOut);
    for (i, size) in [100, 10_000, 1_000_000].into_iter().enumerate() {
        let data = payload(size, i);
        let expected = blake3::hash(&data);
        a.send_timeout(to, data, Duration::from_secs(10)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Event::Message { peer, data } = b.recv(Duration::from_secs(10)).unwrap() {
                assert_eq!(peer.key(), from);
                assert_eq!(data.len(), size);
                assert_eq!(blake3::hash(&data), expected);
                break;
            }
            assert!(Instant::now() < deadline);
        }
    }
    let too_big = vec![1; 1_000_001];
    let ptr = too_big.as_ptr();
    let err = a.try_send(to, too_big).unwrap_err();
    assert_eq!(err.kind, SendErrorKind::TooLarge);
    assert_eq!(err.data.as_ptr(), ptr);
    assert!(!a.stats().connections.is_empty());
    a.close();
    b.close();
    // The actual socket threads have joined: no sleeping/retrying to reclaim ports.
    let _a = UdpSocket::bind(("127.0.0.1", pa)).unwrap();
    let _b = UdpSocket::bind(("127.0.0.1", pb)).unwrap();
    assert_eq!(
        a.try_send(to, vec![0]).unwrap_err().kind,
        SendErrorKind::Closed
    );
    let mut disconnected = false;
    let mut closed = false;
    for _ in 0..5 {
        match b.recv(Duration::ZERO) {
            Ok(Event::Disconnected(p)) => {
                assert_eq!(p.key(), from);
                disconnected = true;
            }
            Ok(Event::Closed) => closed = true,
            Err(ReceiveError::Closed) => break,
            other => panic!("unexpected close result: {other:?}"),
        }
    }
    // A channel receives its peer's disconnect and then endpoint Closed as well.
    assert!(disconnected && closed);
}
fn pressure(style: Style) {
    let (mut a, mut b, to, _, _, _) = pair(style, 1_000_000, true);
    let mut full = None;
    for i in 0..64 {
        let data = payload(10_000, i);
        let ptr = data.as_ptr();
        match a.try_send(to, data) {
            Ok(()) => (),
            Err(e) => {
                assert_eq!(e.kind, SendErrorKind::Full);
                assert_eq!(e.data.as_ptr(), ptr);
                full = Some(e.data);
                break;
            }
        }
    }
    assert!(full.is_some(), "{style:?}: bounded admission never filled");
    if matches!(style, Style::Blocking | Style::Channel) {
        let err = a
            .send_timeout(to, full.unwrap(), Duration::ZERO)
            .unwrap_err();
        assert_eq!(err.kind, SendErrorKind::TimedOut);
    }
    a.close();
    b.close();
}
macro_rules! style_tests {
    ($name:ident, $style:expr) => {
        #[test]
        fn $name() {
            contract($style);
            pressure($style);
        }
    };
}
style_tests!(blocking_contract, Style::Blocking);
style_tests!(async_contract, Style::Async);
style_tests!(callback_contract, Style::Callback);
style_tests!(readiness_contract, Style::Readiness);
style_tests!(channel_contract, Style::Channel);

#[test]
fn explicit_limit_is_validated() {
    assert!(blocking::Endpoint::open(config(0)).is_err());
    let mut c = config(100);
    c.bind.set_port(0);
    assert!(blocking::Endpoint::open(c).is_err());
}

#[test]
fn async_pending_receive_does_not_self_wake_and_cancels() {
    use std::{
        future::Future,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut ep = asynchronous::Endpoint::open(config(100)).unwrap();
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut future = pin!(ep.recv());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }
    ep.close();
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        0,
        "cancelled future retained a waker"
    );
}

#[test]
fn async_full_send_wakes_on_close_and_returns_original_buffer() {
    use std::{
        future::Future,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let (mut a, mut b, to, _, _, _) = pair(Style::Async, 1_000_000, true);
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.stats().core_rejections == 0 {
        let _ = a.try_send(to, vec![3; 10_000]);
        std::thread::sleep(Duration::from_millis(2));
        assert!(Instant::now() < deadline);
    }
    let support::App::Async(endpoint) = &mut a else {
        unreachable!()
    };
    let data = vec![9; 100];
    let ptr = data.as_ptr();
    let mut future = pin!(endpoint.send(to, data));
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    endpoint.close();
    assert!(count.0.load(Ordering::Relaxed) > 0);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(Err(e)) => {
            assert_eq!(e.kind, SendErrorKind::Closed);
            assert_eq!(e.data.as_ptr(), ptr);
        }
        other => panic!("unexpected pending-send close result: {other:?}"),
    }
    b.close();
}

#[test]
fn channel_shutdown_delivers_lifecycle_before_terminal_error() {
    let c = config(100);
    let address = shielded_transport_pigeon::stp::STPAddress::from(
        "127.0.0.1"
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .to_ipv6_mapped(),
        c.bind.port(),
        &c.keys[0],
    );
    let mut server = channel::Endpoint::open(c).unwrap();
    let mut client = channel::Endpoint::open(config(100)).unwrap();
    client.connect(address).unwrap();
    let _outgoing = client.accept_timeout(Duration::from_secs(5)).unwrap();
    let mut incoming = server.accept_timeout(Duration::from_secs(5)).unwrap();
    let consumer = std::thread::spawn(move || {
        assert!(matches!(
            incoming.receiver.recv_timeout(Duration::from_secs(5)),
            Ok(Event::Disconnected(_))
        ));
        assert!(matches!(
            incoming.receiver.recv_timeout(Duration::from_secs(5)),
            Ok(Event::Closed)
        ));
        assert_eq!(
            incoming.receiver.recv_timeout(Duration::ZERO).unwrap_err(),
            ReceiveError::Closed
        );
    });
    server.close();
    consumer.join().unwrap();
    client.close();
}
