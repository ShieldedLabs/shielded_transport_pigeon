# Shielded Transport Pigeon (STP)

**Encrypted UDP messages, with scheduling owned by your application and isolated per-peer send lanes.**

STP combines Noise IK authentication, ChaCha20-Poly1305 encryption, message
packing and fragmentation, Wirehair forward error correction, and packet-rate
congestion control. It needs no TLS, certificates, relay service or peer-discovery
infrastructure. Applications supply peer addresses and keys.

STP provides **unordered, best-effort messages**, not reliable byte streams.
Proactive repair symbols and loss top-up improve delivery, but a sender forgets a
message once its planned send work is finished. Delivery is not guaranteed.

- **No library threads.** You drive a `Pump` from a thread of your own
  (`run_for`) or between frames (`run_until`).
- **Isolated send lanes.** Each (peer, logical queue) pair has its own bounded
  lock-free send ring; the pump admits from lanes in fair round-robin order and
  skips blocked ones, so one slow peer does not stall the rest. Shared control and
  receive rings complete the connection to a single-owner `LockfreeEndpoint`.
  Sending moves the `Vec<u8>` allocation.
- **Pure Rust.** No build script, no C++ compiler. Wirehair is a Rust port.

## Quick start

```sh
cargo add shielded_transport_pigeon
cargo run --release --example lockfree_thread
cargo run --release --example lockfree_game
cargo run --release --example peer_isolation
```

Requires Rust with edition 2024 support. The first two examples show the supported
driving styles, and `peer_isolation` is the regression example that shows fast-peer
delivery while another peer is slow; the [API guide](docs/rings-api.html) covers ownership,
backpressure and configuration.

```rust
use shielded_transport_pigeon::pump::port::lockfree::*;
// setup(): new_keypair_from_connect_magic1(..), STPAddress::from(..),
//          new_pump_with_options(..) -> (Pump, LockfreeEndpoint)
let (pa, mut a, _) = setup();
let (pb, mut b, address) = setup();
let mut worker_a = Worker::start(pa); // your own pump threads
let mut worker_b = Worker::start(pb);
let peer = connect(&mut a, &mut b, address);
send(&mut a, peer, b"owned rings, caller-owned threads".to_vec());
```

The complete, compiling version is [examples/lockfree_thread.rs](examples/lockfree_thread.rs)
with helpers in `examples/support/lockfree_common.rs`.

## Documentation

- [Application API guide](docs/rings-api.html): self-contained HTML with examples,
  ownership rules, backpressure and configuration.
- [Wire protocol specification](PROTOCOL.md): packet layouts, handshake,
  authenticated fields, ACKs, nonce/key epochs, framing and FEC interoperability.

## Application API

`stp::new_pump(...)` or `stp::new_pump_with_options(..., NetworkThreadOptions {
rings: RingConfig { send: 128, control: 32, receive: 128 }, ..Default::default() })`
returns `(Pump, LockfreeEndpoint)`. Each ring capacity (`send` applies per lane) is a
power of two from 1 to 65,536; queue counts stay 1..=64. The pump and endpoint are `Send`; the endpoint is deliberately not `Sync`.
`NetworkThreadOptions` and `NetworkThreadStats` keep their names; they do not
imply library-owned threads.

- `try_send(peer, queue, class, &mut payload) -> bool` moves the allocation on
  `true`; `false` (lane slots, a byte cap, the global message or active-lane cap, a
  cap smaller than the message, or closed) leaves your `Vec` untouched. Lanes are
  created lazily per queue on the connected association; the first send to a queue
  may allocate, and an ordinary push onto an established lane copies no payload.
  Oversized messages, invalid queue indices and sends to unknown or
  still-handshaking peers are accepted, then dropped and counted in `stats()`
  synchronously, without allocating a lane. A peer without send credit blocks only
  its own lanes; admission is fair round-robin, not a strict latency guarantee.
  Shared global caps can still make `try_send` fail across lanes.
- `queued_send_bytes(peer, queue)` reports accepted bytes (in the lane and the
  protocol queue) until send work retires, meaning the last DATA attempt (a local
  UDP send error counts) or a drop/disconnect. It is not a delivery acknowledgement
  or total memory use: spare `Vec` capacity and FEC/parity buffers are excluded.
  `try_send` enforces the byte caps, independent of the low-level
  `send_buffer_params` credit, and `park_until_ready` wakes when capacity returns.
- Backlog limits live in `NetworkThreadOptions.send_queue: SendQueueConfig`:
  `per_queue_bytes` (default max(4 MiB, max message)), `queue_bytes` (per-queue
  overrides), `global_bytes` (default max(64 MiB, 4x the per-queue default)),
  `max_active_queues` (default 1024, 1..=65,536; a lane's permit is held until
  disconnect or replacement) and `max_queued_messages` (default 65,536, counting
  messages already in the core). `RingConfig.send` is slots per lane.
- `try_connect(address)`, `try_disconnect(peer)` and `try_control(Control)` use the
  control ring. Disconnect cancels local state without flushing or sending a wire
  close. Duplicate connects are silent no-ops.
- `try_recv() -> Option<Event>` drains one ordered stream: `Connected`, `Message`,
  `ConnectFailed`, `Disconnected`. `Connected` precedes a peer's messages and each
  association yields at most one `Disconnected`.
- `stats()` reads relaxed atomic counters; `request_protocol_stats()` /
  `try_protocol_stats()` request heavier per-peer telemetry.
- `park_until_ready()` blocks until there is something to do (futex on Linux, 1 ms
  polling elsewhere). `close()` and dropping an owner cancel; they do not flush.

A full receive ring drops data (counted), so a stalled application cannot starve
ACKs; while full, outgoing ACKs request ECN CE to slow the sender. Lifecycle events
are never dropped: the pump holds them until the ring has room.

### Reconnects and network changes

- **Restarted peers.** An encrypted peer that restarts with the same key and IP/port
  can run a fresh handshake while the old session stays live. Once authenticated
  traffic confirms it, you get `Disconnected { reason: Replaced }` and then
  `Connected`. Unconfirmed candidates expire silently after 15 seconds.
- **Source-address changes.** Every `run_until`/`run_for` call probes the host's
  IPv4 and IPv6 source addresses (no payload is sent). If an address changes, old
  associations are dropped with `Disconnected { reason: NetworkChanged }` and fresh
  handshakes are scheduled to remembered peers. The automatic restart has a
  30-second deadline; on expiry you get `ConnectFailed { reason: TimedOut }` and
  STP stops until you reconnect. Explicit disconnects are never resurrected.
- **UDP send errors** are counted as dropped attempts (`local_send_drops`,
  `last_local_send_error`) and consume send attempts; they are not backpressure and
  never block ACKs or recovery.

## Compatibility

Both peers must run this protocol: unknown handshake selectors are rejected.
Constructor message limits are local and are not advertised to the peer, so
coordinate them in your application if they matter. The wire format is specified
in [PROTOCOL.md](PROTOCOL.md).

## Security and transport boundaries

- Only `Noise_IK_25519_ChaChaPoly_BLAKE2b` is supported for encrypted STP. The
  responder's raw X25519 static public key must be known. Developer plaintext is
  for tests and is **not secure**.
- Peer discovery, authorization and deciding which keys to trust belong to the
  application.
- Overhead is 22 bytes per connected packet (6-byte header plus 16-byte tag). The
  UDP transmission unit starts at 512 bytes and is searched upward (1204, 1452,
  1472, 2048, 4096, 8192, 9216) with default-on recovery probing. Paths below 512
  bytes are unsupported. See PROTOCOL.md for the exact rules.
- Receive resources are bounded. Data may be dropped under memory or ring pressure
  even if its packet was acknowledged.
- The default congestion policy is fixed (rate-based, message-bound repair).
  Research features are not application configuration; leave them disabled.
- Authentication is not a claim of a security audit, anonymity, traffic-flow
  confidentiality, DoS resistance or reliable delivery.

Native Linux obtains secrets using blocking `getrandom(2)` and fails closed if it
is unavailable. It never falls back to a clock or deterministic seed.

## Building and portability

Cryptography uses crates.io dependencies: `shielded_labs_snow` (imported as `snow`),
`curve25519-dalek`, `chacha20poly1305`, `blake2` and `blake3` (pure-Rust feature);
some come transitively through Snow. STP's FEC is a Rust port of
[Wirehair FEC](https://wirehairfec.com) by Christopher A. Taylor; its BSD-3-Clause
license is in `src/wirehair/LICENSE`, and notices for retained RNG code are in
`src/crypto/`. STP itself is MIT.

For an Actually Portable Executable, use the separate
[Cargo Cosmo](https://github.com/ShieldedLabs/cargo_cosmo) 10.0.0 toolchain:

```sh
cargo cosmo build --release --example portable_smoke
sh target/cosmo/release/portable_smoke.com
```

The smoke example opens a fresh encrypted connection and validates one 20 MB
response over IPv4 and IPv6. Linux is the primary runtime validation host; macOS
has had targeted testing. Windows and other targets need their own qualification,
and cross-compiling is not a pass.

## Testing and benchmarks

Run `cargo test` and `cargo test --all-features`. Tests are not an independent
interoperability or security audit.

The `lockfree_bench`, `pump_timing` and `throughput_matrix` examples and the
`stp_bench` binary are measurement tools. Throughput depends heavily on the
machine; measure on your own hardware, and do not treat loopback results as WAN
guarantees.
