# STP - WIP

**"Stop winging your connections"**

STP is a fledgling🐦 transport layer built to support [Zebra](https://z.cash/ecosystem/zebrad/)'s and [Crosslink](https://github.com/ShieldedLabs/zebra-crosslink-staging)'s networking requirements with minimal code size and infrastructure dependencies.

STP is intended to make "small-and-frequent" P2P gossip and "high-bandwidth serial beaming" both viable, even over high-RTT connections like the Nym mixnet.

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
- No Nym
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
- TODO.
