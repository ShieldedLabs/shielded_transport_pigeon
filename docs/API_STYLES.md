# Five application APIs over STP

The application **must choose its maximum message size**. None of these APIs
implements `Default` for endpoint configuration or supplies a message-size
fallback. `Config::new(bind, keys, max_message_size)` requires that choice and
`open` rejects zero and values above 1 GiB. All examples choose 1,000,000 bytes;
that is an example application limit, not a transport default.

These are adapters, not five transports. They use the same `service_connections`,
same single FIFO sender queue per peer, same owned `Vec<u8>` payloads, and same
frozen Noise/framing/FEC/congestion implementation. No reliable-delivery mode,
new acknowledgement, retransmission policy, packet header, parity knob, or CC
knob is introduced. The core's `send_unreliable` name is not interpreted as a
promise to deliver or not deliver: STP still delivers complete unordered messages
or nothing. Applications needing stronger reliability still implement their
application acknowledgement/retry semantics themselves.

## Existing API and its problems

The public low-level API remains available in `stp`:

1. Generate or load `IdentityKeyPair` values, typically with
   `new_keypair_from_connect_magic1`. `STPAddress` contains IP, port, crypto selector,
   and full public key; `ConnectionKey` is a compact routing key, not a full identity.
2. `new_network_thread[_with_options]` takes keys, a port, optional pps cap, sender
   queue bounds, and the required maximum message size. `NetworkThreadOptions`
   selects bind IP, queue count, receive budget, and measurement options.
3. Repeatedly call `service_connections(handle, NetworkThreadPush { ... })`.
   Put new addresses in `initiate_connections`, echo the previous authenticated
   `current_connections` into `wanted_connections`, and pass owned payloads in
   `send_unreliable` as `(key, queue, DSCP, Vec<u8>)`.
4. Process `NetworkThreadPull`: authenticated connections/session hashes, whole
   messages, untouched rejected/oversized/invalid-queue buffers, free send bytes,
   and per-connection/thread statistics. Retain/retry rejected buffers yourself.
5. Internally/publicly, `SendQueues::submit_messages` accepts a FIFO prefix and
   returns the untouched suffix, including the oversized-alone queue-capacity
   exception. `ReceiveQueue::take` transfers a whole batch; allocation reservations
   end when ownership passes to the application. `ConnectionState` exposes core
   handshake/connected state; application code normally sees only pull snapshots.

`src/bin/stp_bench.rs` demonstrates complete request/rejection/snapshot bookkeeping;
`src/bin/stp_memory.rs` demonstrates explicit receive budgets and stalled consumers.
Both are useful core examples, but considerably more machinery than most apps need.

Problems for applications:

- The handle is documented as unsafe to exchange from two threads concurrently,
  despite `service_connections` taking `&Handle`. The adapters serialize ownership
  in one worker and never expose that handle.
- The app must pump both connection management and receive delivery, preserve
  `wanted_connections`, inspect several rejection vectors, and poll for changes.
- The core exchange can block up to five seconds and uses a 25 us sleep-poll;
  the network thread uses a 150 us idle sleep. Neither is an executor-ready Future
  or a readiness handle. The adapters cannot remove those costs themselves.
- Snapshot comparison is required for lifecycle events. Compact routing keys can
  easily be confused with cryptographic identity.
- The core does not return the bound ephemeral port and panics on bind failure.
  These adapters require a nonzero port. They initialize the core synchronously
  and convert constructor panics to `io::Error` under unwind builds (the legacy
  panic diagnostic is still printed). `panic=abort` cannot recover.
- Previously stopping/joining the core still leaked the raw UDP descriptor:
  `SockHandle` is Copy and had no destructor. The minimal cleanup hook below fixes
  that, with an immediate Linux port-rebind regression test.

## Shared contract and ownership

Each endpoint owns one small adapter worker in addition to the core network
thread. All five facades use the same driver and bounded mutex/condvar mailbox.
The callback and channel styles do **not** add another worker per peer or handler.
No new dependencies, Cargo features, runtime, or Tokio adapter are necessary.
The async Futures can be awaited directly on Tokio or any conforming executor.

### Sending and backpressure

- `try_send` transfers an owned buffer into the adapter or returns `SendError`
  containing the **same allocation**, untouched. `Full` means adapter slots or
  retained payload-buffer capacity are exhausted. `TooLarge` means payload length
  exceeds the explicit message limit, or buffer capacity exceeds the adapter byte
  bound. `NotConnected` and `Closed` are distinct permanent admission failures.
- `send_slots` and `send_bytes` include sends currently in the driver's core
  exchange and rejected sends waiting for another core admission attempt. Bytes
  count `Vec::capacity`, not just its length. Core-owned accepted data has its own
  existing bounded queues. The limits are endpoint-wide, not per peer.
- `Ok(())` means **bounded local ownership admission**, not core queue admission,
  wire transmission, remote receipt, or eventual delivery. The worker retries only
  messages the core returned as unaccepted. It never resubmits a core-accepted
  message. FIFO order is preserved on each connection.
- Blocking/channel `send_timeout` waits for adapter space and returns the original
  buffer on timeout. Async `send` waits through a registered Waker. Callback and
  readiness styles deliberately use only immediate `try_send`; the application
  chooses when/whether to retry. Callback `on_backpressure` reports observed Full
  results at the next dispatch; it is not a remote-congestion notification.
- Cancellation of a pending async Send discards its still-future-owned buffer and
  unregisters its Waker; no send was admitted. Dropping a pending Recv consumes no
  event. Admission and Waker registration share one lock, avoiding lost wakeups.
  Future-owned pending buffers and caller-retained received buffers are application
  memory, not part of the adapter admission limits.

### Receiving, accepting and closing

`Connected(Peer)` is the authenticated connect **or automatic inbound accept**
result. It contains an `Arc<STPAddress>` (full public identity) and the Noise session
hash. `Message { peer, data }` includes that identity without cloning public-key
bytes for every message. There is no new on-wire accept/reject handshake.

Each facade exposes connection lifecycle events, `stats`, and explicit `close`.
Closing or dropping the endpoint stops and joins both workers and releases the
socket. Close is immediate cancellation, **not** a flush; accepted-but-unsent
messages may be discarded. No close packet is invented: remote peers observe the
core's existing liveness timeout. Local consumers can drain `Disconnected` and
`Closed` events after explicit close. Keeping a channel sender or callback Context
alive does not keep its endpoint open; subsequent sends return Closed.

The unread event mailbox is bounded by `receive_slots` (all events, including
lifecycle) and `receive_bytes` (payload capacities). Oldest events are evicted
whole on overflow; an incoming buffer larger than the byte bound is discarded
whole instead. Inspect `Stats::dropped_events` and `dropped_receive_messages`.
Lifecycle history can therefore be lost if an application stops consuming events;
these are not durable logs. Core receive-memory budgets and incomplete-message
admission remain unchanged. Application-owned received buffers are outside the
transport budget, just as with the low-level `ReceiveQueue::take`.

### One replaceable wakeup boundary

`api/driver.rs::wait_for_core_or_command` is the only adapter polling fallback.
Commands notify its condvar immediately. Idle waits start at
`Config::service_interval` (1 ms), double after idle snapshots, and stop at
`Config::idle_service_interval` (2 ms as shipped; configurable). Commands, observed messages/lifecycle,
and pending adapter sends reset the active cadence. The cap is an explicit
receive-discovery latency/CPU choice; it bounds the normal wait, not OS scheduling
or a failed core exchange. Set both intervals to 1 ms to retain the initial fixed
cadence. The driver reuses peer-map allocations across snapshots.

Future polling itself contains no sleep, timer or self-wake; idle snapshots do
not wake application Futures. A real core receive/queue-space notifier can replace
this one wait function and signal the existing condvar without changing any
facade. Until then, async and readiness are application interfaces over a periodic
driver, not a claim that the legacy transport is internally event-driven.

### Core notifier needed by the CPU pass

Add one optional, coalescing application-readiness notifier on the core handle,
installed before the adapter begins waiting. The **network thread** should notify
the **adapter worker** after (1) a whole message enters `ReceiveQueue`, including
FEC worker results once admitted by the network thread, (2) an authenticated
connection appears/disappears or changes session, and (3) send capacity increases
while the adapter has armed an interest after a rejected admission. Hook points
are the core receive-queue insertion, connection lifecycle transitions, and
sender-space reclamation; do not wake once per idle loop or change packet work.
Use a generation counter plus condvar/eventfd to coalesce edges and avoid lost
wakeups: arm interest, recheck the generation/predicate, then wait. No application
handler or Waker should execute in the core's transport-critical path.

The adapter remains the sole caller of `service_connections`; on notification it
publishes mailbox/space changes, then wakes application condvars/Wakers outside
its state mutex. Commands already wake it immediately. Once all three readiness
sources exist, replace `wait_for_core_or_command` with an untimed event wait and
remove the idle cap entirely. Separately, the CPU pass should replace the core's
150 us sleep and the exchange's 25 us polling with socket/deadline/command waits
and a response-completion notification. None of those notifications encodes a
wire acknowledgement, changes parity/CC policy, or adds an application retry.

## 1. Blocking synchronous (`api::blocking`)

Use for small services and simple thread-oriented applications. `recv_timeout`
returns the next event; `send_timeout` parks on queue-space changes. The facade
keeps one receive consumer (`&mut self`) and exposes immediate `try_send` as well.
There is no per-call helper thread. This is the recommended starting interface
when the application has no existing event model.

```rust,ignore
let mut endpoint = blocking::Endpoint::open(config)?;
endpoint.connect(address)?;
let peer = loop {
    if let Event::Connected(peer) = endpoint.recv_timeout(timeout)? { break peer; }
};
endpoint.send_timeout(peer.key(), buffer, timeout)?;
let event = endpoint.recv_timeout(timeout)?;
endpoint.close();
```

Complete two-endpoint example: `examples/api_blocking.rs`.

## 2. Async/await (`api::asynchronous`)

Use inside an existing executor. `Send` and `Recv` implement `std::future::Future`,
register/replace Wakers atomically with their predicates, and unregister on Drop.
Only blocked operations hold Waker/map entries. No boxed Future or runtime dependency
is required. Multiple pending sends are supported; one receiving Future is enforced
by borrowing the endpoint mutably. `open` and deterministic `close` are synchronous
and can join a legacy exchange; keep them off latency-sensitive executor workers.
Runtime timeout combinators can wrap a Future without changing this API.

```rust,ignore
let mut endpoint = asynchronous::Endpoint::open(config)?;
endpoint.connect(address)?;
let peer = loop {
    if let Event::Connected(peer) = endpoint.recv().await? { break peer; }
};
endpoint.send(peer.key(), buffer).await?;
let event = endpoint.recv().await?;
endpoint.close();
```

Complete example with a dependency-free parking executor: `examples/api_async.rs`.

## 3. Callback / handler (`api::callback`)

Use for an application with an existing mutable state machine. Implement `Handler`;
call `dispatch(timeout)` on the application thread. It invokes at most one transport
event per call, so the game/service controls callback budget and thread affinity.
Callbacks receive owned messages and a cloneable Context for reentrant-safe sends
and connects. No application callback runs while the driver mutex is held.
`on_connect`, `on_disconnect`, `on_backpressure`, `on_send_failed` and `on_close`
have defaults; `on_message` is required. Panics in a handler unwind the caller,
not the network worker. Dispatch remaining lifecycle events after explicit close
if those callbacks are needed; Drop itself never invokes application callbacks.

```rust,ignore
impl Handler for Application {
    fn on_message(&mut self, cx: &Context, peer: Peer, data: Vec<u8>) {
        // Full returns data untouched; retain it or explicitly discard it.
        if let Err(error) = cx.try_send(peer.key(), data) { self.pending.push(error); }
    }
}
let mut endpoint = callback::Endpoint::open(config, application)?;
endpoint.context().connect(address)?;
endpoint.dispatch(timeout)?;
```

Complete example: `examples/api_callback.rs`.

## 4. Poll / readiness (`api::readiness`)

Use in a game loop or a custom reactor that wants explicit tokens, interests and
nonblocking drain operations. Register endpoint-wide (`None`) or peer-specific
read/write interests. `poll(&mut Vec<Ready>, timeout)` reuses the caller's vector,
returns level readiness without consuming messages, and `try_recv` drains the
endpoint's unified event queue. `poll(..., Duration::ZERO)` is a frame-tick snapshot.
Writable means some adapter capacity, not that every possible buffer fits.
Register writable only when needed: level writable readiness otherwise returns
immediately. Deregistration/re-registration is explicit. This is an application
reactor, **not an fd** directly registerable with mio/epoll; a future core notifier
can support that without redesigning message ownership.

```rust,ignore
let mut endpoint = readiness::Endpoint::open(config)?;
endpoint.register(None, 7, Interest::READABLE);
endpoint.connect(address)?;
endpoint.poll(&mut ready, Duration::ZERO);
while let Ok(event) = endpoint.try_recv() { application.handle(event); }
// endpoint.try_send(peer.key(), owned_buffer) never blocks on the core.
```

Complete example: `examples/api_readiness.rs`.

## 5. Per-peer channels (`api::channel`)

Use when producers live on different application threads. `accept_timeout` returns
a `Connection { peer, sender, receiver }` for either an inbound or completed outbound
connection. Sender is cloneable and behaves as a bounded multi-producer channel;
Receiver is not Clone and carries message/disconnect events for that peer. The
endpoint owns lifetime. Byte/slot bounds are shared globally, avoiding a capacity
allocation per peer. Receivers filter the shared mailbox; this costs a linear scan
in unread event count instead of one queue and forwarding task per peer. It is
usually appropriate for modest peer counts, not a promise of O(1) demultiplexing
for thousands of independently backlogged peers.

```rust,ignore
let mut endpoint = channel::Endpoint::open(config)?;
endpoint.connect(address)?;
let mut connection = endpoint.accept_timeout(timeout)?;
let producer = connection.sender.clone();
producer.send_timeout(buffer, timeout)?;
let event = connection.receiver.recv_timeout(timeout)?;
endpoint.close();
```

Complete cross-thread example: `examples/api_channel.rs`.

## Measured comparison

Observed on Linux 6.18.39-1-MANJARO x86_64, AMD Ryzen 5 5500U, rustc 1.94.0,
release profile. `examples/api_bench.rs` runs **three fresh endpoint-pair trials**
for the core and every facade, 200 x 100 B, 100 x 10 kB, and 8 x 1 MB messages.
Each message is content-verified with BLAKE3. Values below are coordinate-wise
medians of the three trials; MB is decimal. Connection setup is excluded.

This is a **stop-and-wait API wakeup/dispatch microbenchmark**, not maximum STP
throughput. The direct baseline uses `service_connections` itself, moving request
vectors, retaining authenticated peer metadata, and a 1 ms receive-pump wait.
Facades use adaptive 1 ms → 2 ms service waiting and real condvar/Waker wakes.
The main table is the final shipped-cap-2 run, not the exploratory cap-8 run.
Different pump timing changes latency, allocations and when the frozen core is
serviced; negative elapsed-time deltas do **not** establish that an API inherently
speeds up encryption or networking. Host scheduling varies substantially for
100 B messages. No statistical confidence intervals or high-rate saturation
claims are made.

CPU is process-wide user + system time from `getrusage(RUSAGE_SELF)`, including both
socket threads, both adapter workers where present, payload creation, hashing,
and the tiny harness. Allocation calls/bytes are also **whole process**, counted
with a System global-allocator wrapper (realloc counts as an allocation). They
include core/FEC metadata and both sender and receiver payloads, not isolated
facade-only counts. C/C++ Wirehair allocator calls are not intercepted. The 1 MB
rows stay near two payload allocations' byte volume, not a third full-size copy.
Unit tests additionally verify pointer-preserving successful adapter admission
and pointer-preserving rejection; identity metadata uses Arc clones.

Time delta = `(core messages/s / facade messages/s - 1) * 100`.

| Style | Message B | Messages/s | MB/s | CPU us/message | Time delta vs core | Alloc calls/message | Allocated B/message |
|---|---:|---:|---:|---:|---:|---:|---:|
| Core | 100 | 473.2 | 0.047 | 397.4 | +0.0% | 31.9 | 11990 |
| Blocking | 100 | 394.2 | 0.039 | 562.0 | +20.1% | 34.6 | 13099 |
| Async | 100 | 390.7 | 0.039 | 531.4 | +21.1% | 37.7 | 13458 |
| Callback | 100 | 483.2 | 0.048 | 510.8 | -2.1% | 31.3 | 11681 |
| Readiness | 100 | 369.8 | 0.037 | 635.6 | +28.0% | 34.3 | 12966 |
| Channel | 100 | 381.9 | 0.038 | 614.4 | +23.9% | 34.6 | 13070 |
| Core | 10000 | 602.5 | 6.025 | 598.1 | +0.0% | 39.2 | 80976 |
| Blocking | 10000 | 644.9 | 6.449 | 717.7 | -6.6% | 36.7 | 79876 |
| Async | 10000 | 614.9 | 6.149 | 642.1 | -2.0% | 40.2 | 80384 |
| Callback | 10000 | 642.4 | 6.424 | 539.4 | -6.2% | 36.9 | 79936 |
| Readiness | 10000 | 645.0 | 6.450 | 693.3 | -6.6% | 36.5 | 79787 |
| Channel | 10000 | 703.4 | 7.034 | 525.8 | -14.3% | 36.7 | 79847 |
| Core | 1000000 | 106.5 | 106.477 | 9497.5 | +0.0% | 185.2 | 2034666 |
| Blocking | 1000000 | 109.2 | 109.185 | 9406.0 | -2.5% | 199.2 | 2040302 |
| Async | 1000000 | 109.5 | 109.498 | 9498.5 | -2.8% | 202.6 | 2041337 |
| Callback | 1000000 | 112.4 | 112.353 | 9364.6 | -5.2% | 199.2 | 2040256 |
| Readiness | 1000000 | 107.9 | 107.884 | 9557.0 | -1.3% | 200.5 | 2041302 |
| Channel | 1000000 | 104.7 | 104.720 | 10680.5 | +1.7% | 200.5 | 2041452 |

### Idle optimization: before/after and latency trade-off

The initial fixed 1 ms implementation added 4.94–6.40 percentage points of idle
CPU over direct core. Adaptive waiting and reusing the driver's peer-map storage
reduced that cost; it did not eliminate it. Below are 500 ms idle samples (medians
of three trials) from the initial run and the exploratory 8 ms-cap run. Percentages
are process-wide percentages of **one CPU core**, for two connected endpoints.

| Style | Initial fixed 1 ms CPU % | Adaptive cap 8 ms CPU % | Initial delta vs core, pp | Cap 8 delta vs core, pp |
|---|---:|---:|---:|---:|
| Core | 12.41 | 11.75 | 0.00 | 0.00 |
| Blocking | 18.12 | 12.96 | 5.71 | 1.21 |
| Async | 18.79 | 12.61 | 6.38 | 0.85 |
| Callback | 18.81 | 13.50 | 6.40 | 1.75 |
| Readiness | 18.11 | 12.82 | 5.70 | 1.07 |
| Channel | 17.35 | 12.97 | 4.94 | 1.22 |

`examples/api_latency.rs` measures the caps explicitly. Each of three fresh-pair
trials measures CPU over 1 s idle, then 100 send-to-delivery latencies for 100 B
messages, each following deterministic 25–35 ms idle jitter (avoiding phase-lock
to the service cadence). Time begins before peer send admission and ends when
the receiving facade delivers the whole message; it includes the frozen core's
pacing and wakeups, not only adapter discovery delay. p50/p99 use order statistics
50/99 of 100; table entries are medians of the three per-trial statistics.

| Style | Idle cap ms | Idle CPU % | Delta vs core, pp | Post-idle p50 ms | Post-idle p99 ms |
|---|---:|---:|---:|---:|---:|
| Core | n/a | 11.07 | 0.00 | 3.023 | 6.550 |
| Blocking | 1 | 18.12 | 7.05 | 3.425 | 6.808 |
| Blocking | 2 | 15.42 | 4.35 | 4.202 | 7.386 |
| Blocking | 8 | 13.09 | 2.02 | 7.255 | 12.832 |
| Async | 1 | 17.87 | 6.80 | 3.612 | 6.603 |
| Async | 2 | 15.91 | 4.84 | 4.185 | 7.062 |
| Async | 8 | 13.32 | 2.25 | 7.462 | 12.619 |
| Callback | 1 | 17.90 | 6.83 | 3.361 | 6.668 |
| Callback | 2 | 15.55 | 4.48 | 4.220 | 7.342 |
| Callback | 8 | 12.99 | 1.92 | 6.960 | 12.811 |
| Readiness | 1 | 17.71 | 6.64 | 3.328 | 6.398 |
| Readiness | 2 | 15.41 | 4.34 | 3.647 | 7.510 |
| Readiness | 8 | 13.09 | 2.02 | 7.467 | 12.821 |
| Channel | 1 | 17.62 | 6.55 | 3.441 | 6.725 |
| Channel | 2 | 15.69 | 4.62 | 4.154 | 7.399 |
| Channel | 8 | 13.31 | 2.24 | 7.044 | 12.562 |

CPU samples vary: the three direct-core 1 s values were 12.91%, 10.63%, 11.07%.
The 8 ms cap **did not consistently meet a +1 pp idle target**: the longer study
shows +1.92–2.25 pp. It also added several milliseconds of post-idle latency and
hurt stop-and-wait throughput. The shipped choice is **2 ms**, prioritizing
latency over the remaining idle overhead while the real core notifier is pending.
No 16/32 ms configurations were measured or selected. Cap values are application
latency/CPU choices, not congestion-control or parity settings.

The throughput penalty was visible as well, not just the latency percentiles:

| Style | Initial fixed 1 ms, 1 MB MB/s | Exploratory adaptive cap 8 ms, 1 MB MB/s |
|---|---:|---:|
| Core | 102.031 | 101.306 |
| Blocking | 117.964 | 69.980 |
| Async | 121.321 | 75.464 |
| Callback | 116.443 | 64.438 |
| Readiness | 112.796 | 59.098 |
| Channel | 113.677 | 65.623 |

These runs have the same frozen transport but different application-service
cadences and host scheduling. The cap 8 result is a reason **not** to hide a long
idle wait behind an async or readiness API. The shipped cap 2 measurements are
reported in the main throughput table above.

## Verification and reproduction

`tests/api_styles.rs` exercises every facade on two real encrypted UDP endpoints
on 127.0.0.1, verifies 100 B / 10 kB / 1 MB with BLAKE3 and full peer identity,
checks Full/TooLarge buffer return, stats, local disconnect/close, and immediate
socket port reuse. It also tests explicit-limit rejection and cancelled idle
async receive behavior. `api::driver::tests` checks allocation-preserving admission
and receive byte/slot bounds. `tests/api_shutdown.rs` independently tests Linux
socket cleanup without any adapter.

Every build/test/example/benchmark invocation must use both shared network locks:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/stp-research-build/api-target"
export TMPDIR="$HOME/.cache/stp-research-build/p4-cc-calm-tmp"
export CARGO_INCREMENTAL=0
flock /tmp/stp_anyrun.lock flock /tmp/stp_highrate.lock cargo test -- --test-threads=1
flock /tmp/stp_anyrun.lock flock /tmp/stp_highrate.lock cargo run --release --example api_bench
# Likewise api_blocking, api_async, api_callback, api_readiness, api_channel.
```

The executable emits CSV rows (filter `kind,`, `idle,`, and `transfer,` prefixes;
the unchanged core also prints connection diagnostics). Add the same locked
`cargo run --release --example api_latency` command for the cap sweep. Raw output
lives under `$HOME/.cache/stp-research-build/`:

- `api-bench-final.log`: initial fixed-1ms baseline.
- `api-bench-adaptive.log`: exploratory adaptive cap 8 ms.
- `api-idle-caps.log`: three-trial cap 1/2/8 ms idle + latency sweep.
- `api-bench-shipped-cap2.log`: final shipped 2 ms throughput/allocation run.
- `api-final-cap2-validation.log`: final build, full suite and all five examples.

Final observed validation: `cargo build --all-targets` passed; `cargo test --
--test-threads=1` passed 245 library tests (2 ignored microbenchmarks), 4 bench-bin
tests, 1 socket-shutdown test, and 9 API integration tests. All five standalone
examples also ran successfully in release mode. Final cap-2 500 ms idle medians
were core 11.67%, blocking 16.17%, async 17.08%, callback 15.91%, readiness 15.75%,
channel 17.00%: +4.08–5.41 pp remains. This is not a claim of meeting +1 pp.

## Core hooks, recommendation and remaining boundaries

Existing files changed only as follows:

- `src/lib.rs`: `pub mod api;`.
- `src/stp.rs`: `NetworkThreadHandle::shutdown(self)` sets the existing stop flag,
  unparks and joins the existing thread. A tiny socket-owner guard closes its
  raw handle on thread exit, including unwind. Neither change emits a packet or
  touches send scheduling, CC, FEC, wire framing, receive admission, or crypto.
- `src/native_sockets.rs`: crate-private unsafe `SockHandle::close` for Linux,
  Windows and macOS, called solely by that owner guard. Only Linux was executed;
  Windows/macOS cleanup compilation and behavior are not verified here.

Choose **blocking** for a new simple service, **async** for an existing async app,
**callback** for an existing state-machine framework, **readiness** for frame-driven
work, and **channels** for threaded producers with per-peer consumers. Keep the
low-level API for transport research and applications needing explicit queue/DSCP
management. A C ABI or a lending-buffer interface was deliberately not added:
five distinct ownership/scheduling models already cover the Rust use cases, and
lending across the legacy worker boundary would add complexity without eliminating
the core's encryption/reassembly allocations.

Remaining boundaries: no port-0 discovery, OS readiness fd, admission-veto accept,
per-peer immediate on-wire close, guaranteed delivery/draining close, durable
lifecycle queue, facade-only allocation profiler, large-peer-count channel scaling
study, or cross-platform runtime verification. These are stated limitations, not
hidden transport changes. No version bump, publication, push, or main-branch edit
is part of this work.
