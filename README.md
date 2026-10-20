# Shielded Transport Pigeon (STP)

**Encrypted UDP messages, with scheduling owned by your application.**

STP combines Noise IK authentication, ChaCha20-Poly1305 encryption, message
packing and fragmentation, Wirehair forward error correction, and packet-rate
congestion control. It needs no TLS, certificates, relay service or peer-discovery
infrastructure. Applications supply peer addresses and keys.

STP provides **unordered, best-effort messages**, not reliable byte streams.
Proactive repair symbols and loss top-up improve delivery, but a sender forgets a
message once its planned send work is finished. Delivery is not guaranteed.

## Documentation

- [Wire protocol specification](PROTOCOL.md): packet layouts, handshake,
  authenticated fields, ACKs, nonce/key epochs, framing and FEC interoperability.
- [Application API guide](docs/rings-api.html): self-contained HTML documentation
  with examples, ownership rules, backpressure and configuration.
- [Dedicated-thread example](examples/lockfree_thread.rs) and
  [game-loop example](examples/lockfree_game.rs).

## Build and run

```sh
cargo add shielded_transport_pigeon@0.3
cargo run --release --example lockfree_thread
cargo run --release --example lockfree_game
```

Building requires Rust with edition 2024 support, a C++11 compiler and a native
C/C++ toolchain: the crate builds the vendored Wirehair codec. Wirehair's
BSD-3-Clause license is included in `third_party/wirehair/LICENSE`; STP is MIT.
Linux is the platform exercised by the release tests and benchmarks. Other
platform branches exist but are not release-tested here.

## Compatibility

Version **0.3.0** replaces the 0.2 application API with a caller-driven pump and
three SPSC rings. This is a breaking API release. The library does not start
network or FEC threads. Move the pump to an application-owned thread if desired.
The package version and wire-profile version are separate. Current main uses
**wire profile 4**, incompatible with profiles 2 and 3, including the published
0.3.0 version-2 profile. Both peers must be updated together: mismatched
handshake declarations are rejected. Profile 4 retains the bitmap ACK and
445-byte minimum FEC symbol for 512-byte MTU recovery, and adds the exact sampled
UDP payload size inside the unchanged 152-byte ACK. Known size mismatches are
rejected before receipt, congestion or MTU feedback is admitted. This is not a
new package release.

## Application API

`NetworkThreadOptions` and `NetworkThreadStats` retain historical names; they do
not imply library-owned threads. The supported application surface is the pump,
ring endpoint, configuration, address/key types and the events described here.
Low-level protocol modules are exposed for inspection but are not an additional
application service interface.

The library creates **no threads**. `stp::new_pump(...)` or
`stp::new_pump_with_options(..., NetworkThreadOptions { rings: RingConfig {
    send: 128, control: 32, receive: 128
}, ..Default::default() })` returns `(Pump, LockfreeEndpoint)`. Every capacity
is independently configurable and must be a power of two from 1 to 65,536.
Move the pump to your own thread and loop `run_for(Duration::from_millis(100))`,
or drive it with `run_until(frame_deadline)` between frames. The pump and app
handle are `Send`; the single-owner app handle is deliberately **not Sync**.

- `try_send(peer, queue, class, &mut payload) -> bool` moves the Vec allocation
  on true; false (full or closed) leaves the caller's Vec untouched. No send
  admission/completion events exist. Core send-buffer pressure keeps the FIFO
  head in the send ring: **one blocked peer head-of-line blocks other peers**.
  Oversized messages, invalid queue indices and sends to unknown/disconnected
  peers are dropped and counted in `stats()`, not reported individually.
- `try_connect(address) -> bool`, `try_disconnect(peer) -> bool`, and
  `try_control(Control) -> bool` use a separate control ring. Disconnect cancels
  local state without flushing or sending a wire close. Connecting an already
  present/handshaking peer produces `ConnectFailure::AlreadyConnected`.
- `try_recv() -> Option<Event>` drains one ordered receive stream:
  `Connected { peer, address, handshake_hash }`, `Message { peer, data }`,
  `ConnectFailed { address, reason }`, `Disconnected { peer, reason }`.
  `Connected` precedes a peer's messages; a disconnected association produces
  one `Disconnected`, with no later messages from that association. A new
  association can reconnect under the same peer key and produces a new
  `Connected`. Every processed connect has one outcome, including duplicate,
  invalid and cancelled requests. Frozen handshake timeout is 30 seconds.
- A full receive ring drops/counts **data**, so a stalled app cannot prevent
  ACK/socket servicing. It also refuses inbound handshakes: neither new hello
  state nor handshake completion is admitted without a slot for `Connected`;
  frozen peer retry logic can retry once space returns. Must-deliver lifecycle
  events are held pump-side pending (bounded by live/pending associations),
  blocking further control consumption while pending. Messages for a removed
  peer are suppressed immediately, even before its disconnect event fits.
- `stats() -> Stats` reads relaxed atomic boundary counters without locking.
  `request_protocol_stats()` / `try_protocol_stats()` explicitly request expensive
  frozen-core telemetry (including per-peer CC/FEC counters and queue credit).
  Telemetry allocates and takes the core's existing per-queue `budget_sink`
  mutex; ordinary ring operations do neither. It carries no messages or peer
  lifecycle snapshots, and repeated requests coalesce. Results use an atomic
  ownership slot, not another queue/ring.
- `park_until_ready()` uses futex generation handshakes on Linux. It wakes for
  receive events, previously-full input-ring space, telemetry, or close. Always
  retry after waking. Non-Linux parking falls back to 1 ms polling and has not
  been release-tested here. `close()` and dropping either owner **cancel**, not flush:
  queued work can be discarded and cancellation does not promise lifecycle
  events for every queued request/association. Pump never waits for app space.

`examples/lockfree_thread.rs` and `examples/lockfree_game.rs` show both driving
styles. The historical batch exchange is crate-private, kept solely for frozen
protocol regression tests. Research binaries use an application-side adapter
implemented on the same public rings; it is not another library API.

## Transport and security boundaries

- The default production policy is fixed: rate-based congestion control in
  packets/second and message-bound P4 repair. Research features are not ordinary
  application configuration; leave them disabled in deployments.
- Peer discovery, authorization and deciding which public keys to trust belong
  to the application. The supported authenticated profiles use Noise IK and
  require the responder's static public key. Developer plaintext is not secure.
- Directional UDP transmission units start at 1204 bytes. Default-on recovery
  alternates generic 512-byte and current-TU best-effort padding probes on a
  250 ms schedule, independent of application message sizes or queued work.
  Recent repeated current-TU failures alongside repeated fresh small-packet
  receipts can lower the TU to 512, with a ten-second hold at the failed size. Healthy
  current-TU progress cancels this evidence; old unconfirmed data alone cannot
  cause an idle/drain fallback. At TU 512 every slot sends a small probe.
  Proof ages adapt to exact generic-probe raw RTT, retaining the original
  one/two/three-second windows on a stable 20 ms path. A protected 256-probe
  history survives ordinary-send churn; outage proof uses a separate
  chronological 32-entry ledger without weakening outstanding/replay checks.
  Upward search tries coarse rungs 1452, 1472, 2048, 4096, 8192 and 9216 bytes.
  A recent failed size bounds binary refinement above the confirmed TU; accepted
  attempts stay at least 500 ms apart. Within eight bytes, search rechecks the
  exact failed boundary after max(5 seconds, B), capped at 30 seconds. Failed
  boundary rechecks back off independently to 10, 20 and 30 seconds on a low-RTT
  path; interior outcomes do not restart that clock. An expired settled bound
  remains a target, not promotion proof. Fresh authenticated success releases
  the bound only when the larger TU becomes effective, then coarse search resumes.
  An effective shrink seeds the bound from the old TU, permitting interior
  refinement during the ten-second failed-size hold. These are issuance deadlines
  once locally eligible, not ACK-arrival guarantees.
  Recovery does not promise delivery or support paths below 512 bytes. It adds
  a bounded 96 KiB packet-history allocation per connected peer on Linux x64.
  See `PROTOCOL.md` for proof, retry and FEC identity rules.
- Receive resources are bounded. Incoming data may be dropped under local
  memory or ring pressure, even when its network packet was acknowledged.
- Cryptographic authentication is not a claim of a security audit, anonymity,
  traffic-flow confidentiality, DoS resistance or reliable delivery. The wire
  specification describes the implementation's security limits explicitly.

## Validation and performance

The 0.3.0 release passed the default and research-feature test suites,
including encrypted loopback, lifecycle/backpressure and pump-deadline tests.
The deterministic FEC planning golden hash is unchanged. Tests are not an
independent interoperability or security audit.

On a Ryzen 5 5500U Linux host using HPET, three interleaved loopback runs measured
about **309,000 100-byte messages/s** with 8192 in flight and **246 MB/s** for
1 MiB messages with eight in flight. Each endpoint's pump ran on its own thread.
These are machine-specific application-payload rates, not WAN guarantees; bulk
throughput saturated one sender core. The API guide includes benchmark context.
