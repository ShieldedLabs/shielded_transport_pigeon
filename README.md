# STP - WIP

**"Stop winging your connections"**

STP is a fledgling🐦 transport layer built to support [Zebra](https://z.cash/ecosystem/zebrad/)'s and [Crosslink](https://github.com/ShieldedLabs/zebra-crosslink-staging)'s networking requirements with minimal code size and infrastructure dependencies.

STP is intended to make "small-and-frequent" P2P gossip and "high-bandwidth serial beaming" both viable, even over high-RTT connections (satellite, radio, intercontinental fibre).

## Overview

- **UDP only**.
- Encrypted from the ground up. STP can only connect to STP addresses: `[IP]:port:crypto_specifier:public_key`. Plaintext connections to `[IP]:port:plaintext_mode:0` are explicitly unsupported except as a mock crypto scheme for dev testing.
    - We use the [Noise Protocol](https://noiseprotocol.org/) for our secure and two way authenticated connections. The rust implementation of STP uses the [`snow`](https://github.com/mcginty/snow) crate.
- If you want infrastructure, bring your own. We don't depend on TLS or any PKI, which helps keep the surface area small. We don't depend on or make use of any relay servers. If you want to relay, do it manually.
- Upgrade-only crypto. No downgrade attacks possible.
- STP is P2P ready, without forcing any particular P2P scheme. You bring your own peer discovery scheme or DHT. With STP, implementing a global P2P gossip network is made relatively easy. [TODO: link to example code]
- Option for: Reliable streams [TODO: link to docs]
- Option for: Large datagrams with fragmentation [TODO: link to docs]
- Assumed minimum-maximum-transmissable-unit (mMTU) is slightly different from QUIC.

## Users
- Zebra without Crosslink
    - Requires frequent, overlapping-lifetime, short-lived reliable streams.
    - Optionally requires longer-lived high-bandwidth connections.
- Zebra with Crosslink
    - We have battle tested this with Tenderlink, our Tendermint BFT implementation.
- Application developers who want fine-grained control over their infrastructure

## Benefits

- Low dependency
  - small code size
  - fewer system components

<!--
- (Crypto-capability connection model (with object-capability))
> no reliance on infrastructure
> no reliance on relays
> secure IP connections without intermediate relays/infrastructure
-->

## Current non-goals
- Multiple NICs/network interfaces
- Multiple simultaneous physical locations for the same logical client (e.g. 2 connections with the same NOISE key)
- Opening & closing the same connection frequently, with all the same keys/IP/port (not actively supported, can be handled by application anyway)
- Punch through for Symmetric NATs and other difficult NAT traversal
    - Discovering faster endpoints for peers on more local networks
- Packet Relay for peers with no path

### Why Not QUIC?
- TLS
- Certificates - *boo hiss boo*
    - Centralized authorities
    - Downgrade attacks
    - Overall complexity and code volume / audit surface area
- Made redundant with Noise

### Why Not libp2p?
- Misaligned goals
- Peer discovery
- NAT-poor, relay heavy
- Broadcast-only
- Too modular, can’t make effective use of any of its features
- Large code volume/layers
- Pub-sub is a terrible model for our use case - all our messages are globally relevant to all peers, so we always want to gossip everything
- DHT is unneeded complexity - see point on pub-sub
- Not a Zcash project, so a heavy dependency for a key component of the “supply chain”

### Why not Iroh?
- See "Why not QUIC"
- Relies on peer discovery routing infrastructure

## Medium-term improvements
- "Packlet" framing for small datagrams & streams.

## Long-term improvements
- Opt-in RaptorQ (or similar) lost-packet recovery
- Compression

## Design overview
Normative details, constants and wire formats are in [PROTOCOL.md](PROTOCOL.md).

- **Transport**: Noise-authenticated association, AEAD-sealed UDP datagrams, replay-checked 64-bit packet nonces, separate ACK space with ACK-delay reporting and ECN feedback.
- **Messages**: a message that fits in one datagram is sent as a *whole* frame, and several can be packed into one datagram. Larger messages are fragmented, or coded with Wirehair fountain FEC (large ones in segments). The maximum message size is a required constructor argument with no default.
- **Congestion control**: rate-based (packets per second). After each congestion event the rate follows a fixed recovery/probe curve: beta 0.8, 9-RTT recovery to 0.92 of the anchor rate, then probing toward 1.02 and 2.0 of it. Congestion events are loss, ECN CE, and a *delay* event (queueing delay above clamp(0.5 × min RTT, 5–50 ms) for a whole RTT window). A delay cut is gentle (beta 0.95). Delay cuts stop after 3 ineffective ones so STP is not starved by loss-based flows such as CUBIC. They stay off for 16–256 RTT and come back once the queue drains.
- **Parity**: each coded message gets proactive repair symbols so its planned miss probability is 0.2% at a design loss rate. The base rate is 0.1%, raised by a measured background random-loss estimate (2× its EWMA, at most 5%). When the sender is at its anchor rate and the queue is building, the design loss rises toward 10%. Extra parity covers the last ~3 RTTs of a message. Each known loss is replaced 1:1 while the message is still sending. Nothing is repaired after a message finishes sending.
- **Whole-message duplication**: in high-risk periods every datagram carrying whole messages is sent twice. A flag nibble in the first frame-kind byte marks it, and the receiver deduplicates by canonical nonce.
- **Liveness**: a connection expires after 120 s with neither ACK progress nor any fresh authenticated packet from the peer.

## Release candidate design (frozen)
The release candidate fixes the policy above (P4 message-bound repair, interleave width 1, no slipstream, no post-send repair). Legacy P0–P3 initialization is not supported by this candidate; those experiment arms remain in the research tree. Measured results:

- **Emulated 20 Mbit/s bottleneck, 20 ms and 200 ms RTT, ~1 BDP buffer** (clean link): 100% delivery at every message size from 100 B to 2 MB on both links. Goodput 16.79 / 15.27 Mbit/s.
- **0.3% random loss, same links**: worst size 99.53% / 99.55%; all misses were single-datagram (100 B / 1 kB) messages. At 200 ms RTT goodput falls to 4.18 Mbit/s, because CC still cuts on random loss.
- **Sharing with a long TCP CUBIC flow** (delay cut 0.95, give-up 3, hold 16–256 RTT): at 200 ms STP's share converges to ~53–56%. At 20 ms it is starved to 8–18% for the first ~140–180 s, then recovers to 33–47% (two runs).
- **Real internet, Ethernet sender to three Fly hosts, one run each** (sizes 100 B–2 MB): London 155 Mbit/s, worst 98.78% (2 kB; 40 kB 99.40%). Virginia 70.6 Mbit/s, worst 87.50% at 1 MB (28 of 32 messages); all other sizes 100%. Singapore 33.4 Mbit/s, 100% at every size.

Caveats: these are single research runs (sources: `p4-cc-calm/NIGHT-NOTES.md` and `wifi/eth-rand/*/summary.txt`), not a reliability guarantee. The runs used a per-profile exposure constant H (33.3 or 333.3) rather than the frozen 100/3. H has no effect on planning while the 0.2% target is set, but the frozen value itself was not re-run. The emulated runs predate the liveness change, and the TCP-sharing runs predate the random-loss estimator. The Virginia 1 MB shortfall is not analysed in the notes.
