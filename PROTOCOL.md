# STP wire protocol, version 2

This document specifies the incompatible version-2 transport implemented by
`shielded_transport_pigeon`. It does not change the crate's package version.
All integers are unsigned little-endian; offsets below are byte offsets. One
UDP payload is one STP packet. There is no compatibility with version 1.

## Scope and delivery

STP is an encrypted, packet-rate-paced UDP transport with unordered application
messages and optional Wirehair fountain-code redundancy. Data-class packet
numbers form a dense sequence; ACK numbers have a separate nonce space. Queue
numbers, DSCP classes, congestion-control rates, and FEC planning policies are
not transmitted inside frames. Each physical packet has one DSCP class.

Delivery is not a reliability promise after the sender forgets a message.
Duplicate packet admission is prevented before frame delivery. Incomplete
reassembly, decoder work, and very old packets may be erased when the declared
receive support or local resource budget is exceeded. Such erasure must never
join different identities. Missing ACK bits are not declarations of loss.

The ordinary-UDP/Noise record profile is specified here, not IPv6 jumbograms or
GSO super-buffers. Each GSO segment would need its own complete packet, nonce,
header, and authentication tag. Native implementation UDP payloads are capped
at 9216 bytes. Noise ciphertext records are capped at 65535 bytes (plaintext
65519), independently of the native socket limit.

## Handshake

The crypto selector is a six-byte little-endian `magic1` with bit zero set:

| Selector | Value | Crypto |
|---|---|---|
| Noise IK, BLAKE2s | `0x7193c304f8d5` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` |
| Noise IK, BLAKE2b | `0xbe53b3641ce1` | `Noise_IK_25519_ChaChaPoly_BLAKE2b` |
| Developer plaintext | `0x5bb22856ae53` | test-only, no authentication |

The Noise prologue is the exact six-byte selector. The initiator knows the
responder's static key; both use 32-byte X25519 static public keys. Noise IK's
first encrypted handshake payload is the client application offer plus its
transport parameters, and the second is the server application choice plus its
transport parameters. Thus both parameter declarations and version are bound
to the authenticated handshake transcript. The plaintext developer variant
uses the same parameter validation but offers no security.

Client application offer: one-byte count (1..32), then 32 u64 application IDs,
then the 32-byte transport parameter declaration below. Unused IDs must be
zero. This is 289 payload bytes. The server chooses the first offered ID it
supports. This implementation offers/supports `0x5d747212563144d9` (Crosslink).
The server payload is its chosen u64 ID followed by its 32-byte declaration,
40 bytes total. A client rejects a choice it did not offer.

A Noise client datagram is `magic1[6] || Noise IK message 1` (391 bytes for this
profile). A Noise server datagram is `reply_prefix[6] || Noise IK message 2`
(94 bytes). `reply_prefix` is `0xffffffff0000 | sender_prefix`, where
`sender_prefix = low_u16(static_public_key) << 1` (truncated to u16).
Developer plaintext client packets are selector[6], public key[32], client
payload[289], total 327 bytes; server packets are reply prefix[6], public
key[32], server payload[40], total 78 bytes. Handshake packets are dispatched
before ordinary size-based ACK classification. Retransmissions reuse the
original handshake bytes, not a new Noise transcript.

### Transport declaration (32 bytes)

| Offset | Width | Field | This implementation sends |
|---|---:|---|---|
| 0 | 2 | protocol version | 2 |
| 2 | 2 | declaration length, including these four bytes | 32 |
| 4 | 4 | maximum coded unit / balanced segmentation layout | 2097152 (2 MiB) |
| 8 | 4 | Wirehair grouped-codec maximum source blocks per group | 32000 |
| 12 | 2 | minimum full repair-symbol bytes | 1136 |
| 14 | 2 | maximum Noise ciphertext record bytes | 65535 |
| 16 | 4 | maximum scheduled ACK delay, microseconds | implementation ACK policy (10000) |
| 20 | 4 | receiver maximum application-message bytes | required constructor argument, capped at 1 GiB |
| 24 | 4 | maximum previous-key retention, microseconds | 10000000 |
| 28 | 4 | per-space replay/receipt support capacity, packets | 262144 |

Version 2 of this implementation requires exact agreement on every declared
field except maximum application-message size, which may differ and must be
in 1..1073741824. In particular it rejects, rather than silently reinterprets,
a different coded-unit or grouped-codec layout. These are declared profile
parameters, not tuning knobs hidden from the peer. A future implementation can
support additional profiles by explicit validation/selection; it must not use
its own layout constants to reinterpret a peer's different declaration.
The length makes the declaration boundary explicit. Unknown versions or
lengths are rejected, not guessed. Future compatible frame extensions do not
require expanding this fixed handshake declaration.

A sender obeys both its local maximum and the peer's declared maximum. An
oversized submission is returned in `send_unreliable_oversized`; submissions
before handshake completion remain retryable. The receiver independently
checks whole lengths, fragment extents, coded-unit lengths and segmented totals
before allocation. Local receive/worker quotas are allowed to be stricter than
wire maxima. The declaration does not promise unlimited history or memory.

## Ordinary connected packet

| Offset | Width | Field |
|---|---:|---|
| 0 | 2 | sender prefix (as above; bit zero clear) |
| 2 | 8 | complete Noise nonce, including the space bit |
| 10 | 4 | directional key epoch |
| 14 | variable | Noise ciphertext, including its 16-byte tag |

All **14 header bytes** are AEAD associated data. The full u64 nonce is also
supplied as the Noise transport nonce. No truncated-counter extension,
nearest-cycle inference, synchronization packet, or reset on rekey exists.
Untrusted counters or epochs do not advance replay/key state before successful
authentication. Developer plaintext uses this header with epoch zero and no tag.

### Nonces and replay

Data/probe/keepalive nonces are `0 .. 2^63-1`; ACK nonces are
`2^63 .. 2^64-2`. `2^64-1` is reserved by Noise and is never used. Each direction
allocates its own monotonically increasing counter within each space. A fresh
handshake is required before exhaustion; counters never wrap, reset at rekey,
or reuse a nonce for different plaintext under a key.

The two anti-replay histories are independent and persist across rekeys.
The full transmitted nonce authenticates correctly after arbitrarily large
forward gaps. Admission of late packets is separately bounded by receive
history and retained key epochs; being too old causes safe discard, never
nonce reconstruction in another generation. This implementation retains
262144 packet positions in each replay space and in data receipt history.
This is resource capacity, not a fundamental 262144-packet format horizon.

ACK plaintext is recognized **only by its exact size, 152 bytes**. This
classification must agree with the nonce's high bit; otherwise the packet is
rejected. Data/probe/keepalive plaintext must never be 152 bytes. No packet-type
byte replaces the size test. Ordinary sender data packets and idle/outage
keepalives fill exactly the current transmission unit (TU); MTU probes fill
exactly their probed TU. Handshakes are the explicitly separate exception.

## Frame stream

Non-ACK plaintext contains frames followed, if needed, by authenticated
padding. There is no per-packet message-ID base and no queue ID on wire.

Every non-padding frame is `kind:u8 || body_length:u16 || body[body_length]`.
The length covers **all** kind-specific metadata plus application/symbol bytes,
not just data. Checked parsing must establish the full frame extent before
reading metadata. Unknown kinds are skipped by exactly `3 + body_length`
bytes, including unknown kinds with longer metadata than today's frames.
Truncated/undersized known frames terminate processing of that packet's
remaining frames without allocation. A receiver may reject the entire packet
instead. Already admitted earlier frames need not be rolled back.

Kind **255** is padding: it consumes the entire remaining tail and terminates
parsing in constant time. Senders fill that tail with `0xff` bytes. A padding
byte is recognized only at a frame boundary; it never conflicts with any
length, identity, or data value. Other unknown kinds, including zero, remain
length-delimited. Zero-length unknown bodies consume three bytes and cannot
cause an infinite parsing loop.

| Kind | Frame | Body fields before data | Header bytes, incl. kind/length |
|---:|---|---|---:|
| 1 | whole plain message | none | 3 |
| 2 | non-final plain fragment | message_id:u64, offset:u32 | 15 |
| 3 | final plain fragment | message_id:u64, offset:u32 | 15 |
| 4 | ordinary Wirehair symbol | unit_id:u64, block_id:u32, unit_len:u32, block_bytes:u16 | 21 |
| 5 | grouped Wirehair symbol | same as kind 4 | 21 |
| 6 | segmented Wirehair symbol | kind-4 fields, root_id:u64, total:u32, unit_offset:u32 | 37 |

All remaining body bytes are data. A whole frame, even a zero-byte message, is
one complete application message; its identity is its containing packet nonce
and frame position. Packet replay admission suffices for its duplicate
suppression, so whole messages carry **zero identity bytes**. In particular a
16383-byte whole message is valid framing; the old `length=16383,id=65535`
all-ones collision does not exist.

Plain fragmented messages and coded units have connection-direction-scoped
u64 identities, allocated from one nonwrapping namespace across all sender
queues, roots and units. Roots and their units have distinct identities. A
sender never reuses an identity in a connection, including after its local
lease expires or it restarts a unit with a smaller symbol layout. u64::MAX is
reserved to force a new handshake rather than wrap. Receiver table indices
are never message identities. This implementation maps full IDs to bounded
storage; on pressure it permanently retires oldest identities and safely
erases older arrivals. It does not use `id % 1024` as identity or infer a
16-bit generation.

A message fitting one packet is not split simply because the current tail is
too small. Whole FIFO-head fillers are preferred. The existing fill exception
allows chopping a small message across at most **two packets** to use a tail,
provided its remainder fits a fresh packet with the 15-byte fragment header.
Both pieces then carry the same full message ID. A continuation cannot be
chopped into a third piece as another tail filler. No small plain message is
retransmitted/FEC-rescued by this rule.

For plain fragments, checked `offset + data_len` must fit u32 and not exceed
the local receiver application maximum. A final fragment declares the total
extent. Completion requires conflict-free coverage from zero through that
extent. The implementation bounds plain-message reassembly to 2 MiB, using
coded segmentation for larger original messages.

### Wirehair symbol and segmentation validation

The codec is the bundled Wirehair construction, systematic source IDs first,
with immutable grouped-symbol mapping for the declared group maximum. K is
`ceil(unit_len / block_bytes)`; Wirehair supports K in 2..64000 per codec.
Up to K=64000 there is one codec (ordinary kind 4). Above that threshold,
grouped kind 5 uses G=ceil(K/32000) balanced codecs. Set B=floor(K/G) and
E=K mod G. Group g has K_g=B+(g<E) source blocks, starts at global source
index S_g=g*B+min(g,E), and codes bytes starting at S_g*block_bytes, length
min(K_g*block_bytes, unit_len-S_g*block_bytes). A source block_id<K selects
the unique group with S_g<=block_id<S_g+K_g and local ID block_id-S_g. A
repair block_id>=K selects g=(block_id-K) mod G and local Wirehair ID
K_g+floor((block_id-K)/G). Thus the equation selected by an ID does not depend
on send order. The sender interleaves systematic sources round-robin across
groups, then repair rounds; this ordering is not required for decoding.
Block IDs are u32, must select valid source/repair positions, and must never
wrap to represent a different equation in the same unit. Repairs are full
`block_bytes` bytes. A final systematic source can be shorter, exactly the
remaining source bytes. Invalid symbol lengths/IDs are discarded before
creating any decoder or resource reservation.

The receiving ordinary profile requires `block_bytes >= 1136`, a unit at most
2 MiB, and a bounded source-block count (at most ceil(2 MiB/1136)). Thus grouped
kind 5 is structurally parseable and round-trip tested, but cannot be needed
by a valid current-profile production unit; tiny-symbol or oversized-unit
uses are rejected. Kind 6 requires the unit itself to have one codec.
A layout's length, width, and segment metadata cannot change under an ID.

Version 2 declares the current balanced segmentation layout explicitly. For
`total > max_unit`, let `groups = ceil(total / max_unit)` and
`unit_span = ceil(total / groups)`. Unit offsets must be multiples of
`unit_span`, below total; `unit_len = min(unit_span, total - unit_offset)`.
`total <= receiver maximum <= 1 GiB`. The transmitted unit length and offset
are validated against this **declared** layout, not an undeclared receiver
constant. Completion requires the entire contiguous root message, once, and
nonconflicting total/root metadata. A sender's restarted unit uses a fresh
unit ID, preserving the root and byte range. Changing this layout is a new
negotiated profile/version, not a local tuning change.

## Fixed-size arbitrary-window ACK

ACK plaintext remains **152 bytes**. The encrypted UDP size is therefore
**182 bytes** (14 header + 152 plaintext + 16 tag); the developer plaintext
size is 166 bytes. No other connected traffic uses that size.

| Offset | Width | Field |
|---|---:|---|
| 0 | 8 | receipt_base |
| 8 | 8 | sample_seq (also positively acknowledged) |
| 16 | 8 | cumulative unique CE-marked data-class packet count |
| 24 | 4 | delay_us for sample_seq only |
| 28 | 1 | receipt encoding (0 = bitmap) |
| 29 | 3 | reserved zero |
| 32 | 120 | 960 receipt bits, least significant bit first in each byte |

Bit i means positive receipt of `receipt_base + i`. The base is absolute and
may address **any** old or new window; it is not inferred from a highest
packet. `sample_seq` is independently acknowledged even outside the bitmap.
All positive receipts and the sample must be in data nonce space and below
the sender's next allocated data nonce. Additions are checked. Unknown ACK
encodings or nonzero reserved bytes are rejected safely. A highest receipt,
when needed internally, is derived from set bits and the sample; it is not a
separate wire field.

Zero bits, omitted windows, and reordered ACK bases never declare losses.
Multiple ACKs can cover an arbitrarily deep sequence window; finite local
history may safely erase older receipts. This implementation queues affected
960-position pages and transmits each three times in round-robin order,
refreshing a page on new receipts, and schedules residual feedback even when
new traffic stops. Pages outside retained history are discarded. The timing
sample remains the latest unique admitted packet; duplicates do not change
its origin. ACK losses do not erase the underlying receipt history.

Delay uses microseconds, saturates at u32::MAX, and applies only to the timing
sample, not every bitmap receipt. CE is a monotone u64 cumulative count of
unique admitted data/probe/keepalive packets; old/repeated counts do not move
the sender's remembered count backwards. Exhaustion requires a fresh
handshake; it must never wrap. CE feedback is idempotent under ACK loss,
duplication and reordering.

## Key epochs and operational rotation

Epochs are directional u32 counters starting at zero. Epoch zero's keys are
the Noise IK split transport keys after **one Noise REKEY** per direction
(the pre-existing post-handshake key separation). Epoch n+1 is one additional
Noise REKEY of epoch n's directional key. ACK and data share the directional
key but have distinct, persistent nonce spaces.

Before encryption, rotate when the current directional key has already
performed 2^24 encryptions, when the next ciphertext would exceed 2^40 bytes,
or after 600 seconds since its first encryption, whichever occurs first.
Both ACK and data-class encryptions count, including locally refused sends.
These are conservative **operational budgets, not a claimed hard
ChaChaPoly packet limit or a formal security proof**. Noise's reserved nonce
and record-size rules still apply. A different cryptographic budget/profile
requires review; nonce width alone is not a security-advantage bound.

The sender writes the chosen epoch in the authenticated packet header.
Locally blocked data sends retain/retry the exact ciphertext; they do not
re-encrypt a different snapshot under its nonce. A refused time-sensitive ACK
burns its nonce before generating a later snapshot.

A receiver holds current, previous and one prederived next incoming key.
Only a valid tag for **exactly current+1** advances its incoming epoch; a forged
or far-future epoch causes no derivation loop or state mutation. The previous
epoch is accepted for at most ten seconds after advancement and only while
its packet is within replay support. Packets older than one key epoch are
safely discarded even within that ten-second time bound: this is a bounded
implementation capability, not a promise to cover ten seconds across an
arbitrary number of high-rate updates. Replay state is never reset at rekey.

There are no update control messages whose loss would strand a single key
change; any authenticated packet in the next epoch proves the transition.
A receiver missing **more than one complete epoch** cannot catch up in this
bounded-ratchet profile and requires a fresh handshake. u32 epoch exhaustion
also requires a new handshake. Invalid tags do not result in ACKs or frame
allocation. Verification-attempt throttling/formal multi-user cryptographic
bounds are not claimed by this implementation.

## Minimum TU and byte costs

Minimum UDP TU is **1204 bytes**, raised from 1184. The largest symbol header
leaves `1204 - 14 - 16 - 37 = 1137` bytes, satisfying the 1136-byte repair
minimum with one byte spare. Current-TU data, fixed-size ACK, and explicit MTU
probe sizes remain the only encrypted connected UDP sizes emitted. Raising
the minimum TU is an intentional interoperability change; paths that cannot
carry it are not supported by this profile.

The table excludes IP/UDP headers, padding and coding redundancy; these are
encoding overhead bytes, not a claim about measured wire/app ratio. The
packet overhead includes the AEAD tag. Whole headers are per packed message.

| Item | Old bytes | Version 2 bytes | Change |
|---|---:|---:|---:|
| Data packet outer header + tag | 22 | 30 | +8 |
| 80 B whole message frame | 4 | 3 | -1 (84 -> 83 with data) |
| 1000 B whole message frame | 4 | 3 | -1 (1004 -> 1003 with data) |
| Chopped small message, each of its two frames | 8 | 15 | +7 per piece |
| Bulk plain fragment frame | 8 | 15 | +7 |
| Bulk ordinary/grouped FEC symbol frame | 16 | 21 | +5 |
| Bulk segmented FEC symbol frame | 26 | 37 | +11 |
| One ordinary FEC symbol, packet + frame | 38 | 51 | +13 |
| One segmented FEC symbol, packet + frame | 48 | 67 | +19 |
| ACK plaintext | 152 | 152 | 0 (1024 -> 960 bitmap bits) |
| ACK encrypted UDP | 174 | 182 | +8 |

At TU 1472, seventeen 80 B whole messages fit both formats: old unpadded cost
`22 + 17*84 = 1450`, new `30 + 17*83 = 1441`. Both physical datagrams are
1472 bytes; free tail/padding changes. An isolated 1000 B message has logical
encoding overhead 26 -> 33 bytes, but its actual current-TU data datagram is
still uniformly padded. Packed whole IDs are deliberately omitted instead
of paying eight bytes per message; u64 IDs on fragmented/coded frames keep
parsing cheap, bounded and generation-free. The overhead increase on a
1136-byte segmented repair is 48 -> 67 bytes before uniform padding.

## Implementation and verification boundaries

FEC worker counts, slot counts, sender retention, congestion/loss estimators,
ACK batching cadence and native socket limits are implementation policies,
not new identity widths or implicit wire generations. The declaration makes
current support explicit and rejects incompatible interpretations.

Tests cover every frame kind, unknown-kind skipping, the former all-ones
padding collision, full nonces across enormous gaps, arbitrary ACK bases and
repeated deep-window feedback, rekey budget boundaries/reordering, parameter
mismatches, malformed-input bounds, and encrypted UDP size capture. Tests are
implementation evidence, not a cryptographic proof or cross-implementation
interoperability result. Performance at 1 Tbit/s is not claimed.
