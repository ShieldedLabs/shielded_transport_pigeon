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
cargo add shielded_transport_pigeon --git https://github.com/ShieldedLabs/shielded_transport_pigeon
cargo run --release --example lockfree_thread
cargo run --release --example lockfree_game
```

Building requires Rust with edition 2024 support. STP remains a single library
crate, with Wirehair, address encoding and platform bindings implemented in Rust.
Cryptography uses crates.io dependencies: `shielded_labs_snow` (imported as
`snow`), `curve25519-dalek`, `chacha20poly1305`, `blake2` and `blake3`; some are
provided transitively through Snow. BLAKE3 uses its pure-Rust build feature.
STP has no build script or C++ compiler requirement. The standard library and
operating-system APIs are still required. Wirehair's BSD-3-Clause license is in
`src/wirehair/LICENSE`; notices for retained local RNG code are beside its source
in `src/crypto/`. STP itself is MIT.

For an Actually Portable Executable, use the separate
[Cargo Cosmo](https://github.com/ShieldedLabs/cargo_cosmo) **10.0.0** toolchain,
which supplies zero-dependency shim injection. Both `cosmo-build` and
`cosmo-compat` 10.0.0 are published; versions through 9.0.1 do not provide this
complete integration:

```sh
cargo cosmo build --release --example portable_smoke
sh target/cosmo/release/portable_smoke.com
```

The smoke example opens a fresh encrypted connection and validates one 20 MB
response over both IPv4 and IPv6. Cargo Cosmo supplies Cosmopolitan Libc and its
ABI shim at the executable link; neither is a Cargo dependency of STP. Applications
using `cosmo-build` can instead configure that tool in their own executable crate,
without adding it to this library. A fat APE contains x86-64 and AArch64 code;
building both architectures is not evidence of runtime testing on every OS.
Linux is the runtime validation host available here. macOS and Windows require
their own runtime qualification; cross-target compilation alone is not a pass.

Native Linux obtains secrets using blocking `getrandom(2)` and fails closed if
it is unavailable or blocked (including kernels older than 3.17). It never
substitutes a clock, deterministic seed, or uninitialized `/dev/urandom` fallback.

## Compatibility

Version **2.0.0** includes the verified source reductions and freshly randomized
Noise/plaintext `magic1` selectors and Crosslink `magic2` application ID. Both
peers must upgrade and update configured addresses; 1.0.0 selectors are rejected.
Congestion control, repair policy, packet layout and the public API are unchanged
from 1.0.0. Package versions advance by majors only.

Version **1.0.0** internalized Wirehair, address encoding and platform bindings,
while using external cryptography crates, and introduced the profile below.
The published **0.3.0** introduced the caller-driven pump and three SPSC rings,
replacing the 0.2 application API. The library does not start network or FEC
threads. Move the pump to an application-owned thread if desired.
The package version and wire-profile version are separate. Versions 1.0.0 and 2.0.0 use
**wire profile 6**, incompatible with profiles 2 through 5,
including the 0.3.0 version-2 profile.
Both peers must be updated together: mismatched handshake
selectors are rejected. Profile 6 keeps profile 5's bitmap ACK and 445-byte
minimum FEC symbol for 512-byte MTU recovery, and the
exact sampled UDP payload size inside the unchanged 152-byte ACK; known size
mismatches are rejected before receipt, congestion or MTU feedback is admitted.
Profile 6 uses a six-byte connected header (prefix + low 31 counter bits +
one key-phase bit), plus the unchanged 16-byte tag: **22 bytes overhead**.
Only `Noise_IK_25519_ChaChaPoly_BLAKE2b` is supported for encrypted STP;
BLAKE2s transport support is removed. The fixed transport declaration is removed:
client offer/server choice payloads are 257/8 bytes, encrypted hellos 359/62 bytes.
The new magic1 selectors imply the profile. Constructor message limits remain
local; the sender no longer learns a peer-specific maximum. Applications must
coordinate that limit separately if needed.
ACKs are 174 encrypted UDP bytes (158 in developer plaintext); ACK/data nonce
spaces stay independent and full nonces never reset at wrap or rekey. Nearest
reconstruction requires bounded per-space gaps: strictly less than 2^30 counter
positions is sufficient, not a connection-lifetime limit. Larger gaps, including
locally burned ACK nonces, can fail closed even while data flows. Updates use
only 600-second age and peer confirmation, not packet/byte budgets; there is no
aggregate per-key usage/forgery limit. See PROTOCOL.md for finite-range/tie rules,
phase resolution, exact exhaustion limits and security assumptions.
It retains profile 5's large-message segmentation: the declared 2 MiB maximum is a per-unit
maximum, and a large message is sent as disjoint immutable coded byte extents
whose boundaries the sender chooses, not a balanced layout (see PROTOCOL.md).
Every extent is at least 446 bytes. While the initial TU assessment is
unresolved, the sender sizes new units from an estimated one-flight exposure
(pacing rate, measured RTT or unresolved DATA, and a repair-inclusive upper train
size), at most 113920 bytes. This is a sizing estimate, not a delivery bound.
Low-level API changes: the BLAKE2s selector constant,
`TRANSPORT_PARAMETERS_LEN` and `build_magic2_client_block_for_limit` are removed,
not emulated. `build_magic2_client_block` and `MAGIC2_BLOCK_SIZE` now describe only
the 257-byte offer. `PROTOCOL_VERSION` remains a descriptive profile label, not
a transmitted field. Public rings and constructor signatures are unchanged.
`sequence::to_wire` and `ReceiveSequences::candidate` preserve legacy full-nonce
identity-helper semantics, not compact wire serialization. Receivers use
`compact_candidate`/`reconstruct`; senders pack low 31 bits plus key phase.
magic1 is the dispatch boundary for a whole future handshake/address-material
interpretation, not just a Noise hash; no generic handshake framework, PQ or
hash-discovery implementation is introduced. See PROTOCOL.md for that boundary.

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
  ACK/socket servicing. While full, every outgoing ACK requests IP ECN CE
  (best-effort OS/path support), and each newly admitted data-class packet adds
  authenticated cumulative CE feedback, coalesced with kernel CE. This signals
  the shared application bottleneck before a large message completes, using the
  existing sender congestion cut/guard; draining stops new overload marks.
  `ConnectionStats::rx_app_overload_ce_marks` counts synthetic packet marks,
  not dropped messages; `ack_app_overload_ce_sent` counts successful ACK sends
  requesting local overload CE, not proof of OS/path preservation. It also
  refuses inbound handshakes: neither new hello
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
styles. The historical batch exchange is crate-private; it was kept for frozen
protocol regression tests, which this source tree no longer ships. Research binaries use an application-side adapter
implemented on the same public rings; it is not another library API.

## Transport and security boundaries

- The default production policy is fixed: rate-based congestion control in
  packets/second and message-bound P4 repair. Research features are not ordinary
  application configuration; leave them disabled in deployments.
- Peer discovery, authorization and deciding which public keys to trust belong
  to the application. The supported authenticated profiles use Noise IK and
  require the responder's raw X25519 static public key. Developer plaintext is not secure.
- Directional UDP transmission units start at 512 bytes in profile 6. The first
  larger trial is 1204; only an exact, fresh, promoted success of that trial
  permits one prompt 1452 trial that skips just the 500 ms floor. Otherwise,
  coarse search follows. Default-on recovery
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
independent interoperability or security audit. These historical results predate profiles 5 and 6 and do not cover them;
external validation of the current source is not an independent audit or a
performance claim.

This source tree ships no test suite: the unit and integration tests were
removed to reduce source size, and validation was run externally against the
baseline revision's tests.

For 0.3.0, on a Ryzen 5 5500U Linux host using HPET, three interleaved loopback runs measured
about **309,000 100-byte messages/s** with 8192 in flight and **246 MB/s** for
1 MiB messages with eight in flight. Each endpoint's pump ran on its own thread.
These are machine-specific application-payload rates, not WAN guarantees; bulk
throughput saturated one sender core. The API guide includes benchmark context.
