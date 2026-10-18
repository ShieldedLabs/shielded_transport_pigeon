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

### Handshake confirmation and simultaneous initiation

The states in each endpoint are ClientHello-sending, ServerHello-sending
(awaiting confirmation), Connected, and Closed. A valid ClientHello selects
an application/profile and creates the responder's ServerHello-sending state.
A valid ServerHello finishes the initiator's Noise IK exchange and enters
Connected. Noise completion alone does **not** tell the responder that its
reply arrived: the initiator MUST send an ordinary, authenticated data-class
packet within five seconds of accepting ServerHello, even if the application
is idle. An all-padding current-TU keepalive suffices. It MUST keep sending
ACK-eliciting keepalives as specified below until the responder is confirmed.
The responder enters Connected on the first successfully authenticated
ordinary packet under the split/rekeyed keys, then processes that packet
normally, including positive receipt feedback. There is no third Noise flight.
It does not send ordinary application traffic before confirmation. The
plaintext developer variant follows the transitions without authentication.

If both peers initiate concurrently with the same identities and selector,
compare the complete 32-byte static public keys lexicographically as byte
strings: the smaller remains initiator; the larger abandons its pending client
flight and answers as responder. Self-connections are not initiated. A hello
for an existing Connected association does not reset it or its counters.
A fresh association requires discarding the old state and a fresh Noise
handshake; endpoints must not reinterpret a new hello as a connected rekey.

Handshake retransmissions reuse the exact saved flight. This implementation
expires a client attempt after 30 seconds from creation and a responder
attempt after 15 seconds. Its first successful send is followed after about
10 ms, then at 2.5-second intervals; local refusal does not advance that
schedule. An interoperating peer MUST tolerate duplicate flights and provide
confirmation within the responder lifetime. Precise retry pacing is local
policy, not a dependency of key or packet identity.

### Connected liveness and outage

Every Connected endpoint, including an application-idle or ACK-only endpoint,
MUST emit an ACK-eliciting data-class packet at least once per five seconds
when locally able to send; ordinary data substitutes for an idle keepalive.
Keepalives are all-padding current-TU packets with fresh data-space nonces.
A receiver sends normal fixed-size positive receipt feedback for them; ACKs
themselves never elicit ACKs. This supplies round-trip liveness and confirms
key updates in otherwise receive-only directions without an ACK-of-ACK.

This implementation enters outage after two seconds without positive ACK
progress while a data-class packet is outstanding (measured from the later
of the first outstanding send and last progress). It stops application sends
and MTU discovery but continues receive/ACK processing. It immediately sends
an all-padding current-TU outage probe, then probes after 250 ms, 500 ms,
1 s, 2 s, and at most every 4 s. Probes use fresh data nonces; ACKs/probes are
subject to the same local-refusal and cryptographic-budget rules as data.
Only an authenticated ACK positively receipting a still-outstanding recorded
outage probe younger than max(4 s, twice the pre-outage RTT) resumes sending.
Old withheld/replayed feedback cannot prove recovery. Recovery retains TU,
nonce/epoch histories and message identities, resets pacing credit and RTT
sampling, and resumes startup at no more than the pre-outage/initial rate.
Local bounded FEC retention may pause over a real outage; it cannot resurrect
already-expired sources or change identities. This is a recovery policy, not
a reliability promise.

Peer expiry (release candidate): the association closes when 120 seconds
have elapsed since the later of (a) the last new positive ACK progress and
(b) the last *fresh authenticated peer packet*, even if local sends have all
been refused. (b) is refreshed by any inbound packet that has passed AEAD,
nonce-space/type, replay and minimum-size admission: a well-formed fresh
ACK (even one that receipts nothing new and cannot end an outage) or any
data-class packet. Local sends never refresh it. This changes only
connection expiry: congestion control, outage resumption and RTT sampling
still require positive ACK progress as described above. The initial deadline
is 120 s after the connection's start timestamp. A new association uses a
fresh handshake, never reset transport keys/counters.
Other implementations may choose different local outage pacing/timeouts;
they MUST maintain periodic ACK-eliciting traffic and MUST NOT treat mere
inbound traffic or ACK-of-ACK as round-trip confirmation.

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
rejected. This implementation also rejects non-ACK plaintext shorter than
517 bytes; conforming current-TU/probe packets are larger. Data/probe/keepalive
plaintext must never be 152 bytes. No packet-type
byte replaces the size test. Ordinary sender data packets and idle/outage
keepalives fill exactly the current transmission unit (TU); MTU probes fill
exactly their probed TU. Handshakes are the explicitly separate exception.
TU is the effective sender transmission unit: if an MTU-probe ACK arrives
while a locally refused current-TU ciphertext is pending, its discovered
larger TU is recorded but promotion is deferred until that immutable datagram
is accepted. Every retry is therefore still exactly the effective current TU.
Promote before framing the next datagram; never reseal changed plaintext under
the pending nonce. MTU probes retain their explicit probe-size exception.

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

#### Whole-message duplication flags (release candidate)

The **first** frame-kind byte of a data-class plaintext MAY carry one
duplication flag in its high nibble: `0x10` marks an *original* datagram,
`0x20` marks its *copy*. A flagged byte is valid only when its low nibble
`kind & 0x0f` is a base kind 1..6 and its high nibble is exactly `0x10` or
`0x20`; base kinds 1..6 use neither bit, so the flags cost zero bytes. The
flag only appears on the first frame of the datagram; later frames are
unflagged. The receiver parses the first frame as its base kind. Unflagged
datagrams behave exactly as above and never touch the duplication history.

Sender rules:

- A datagram that carries at least one whole frame and is assembled while
  the sender's duplication decision is high (see "Release candidate sender
  policy") is sent twice. Every whole frame in it is protected; this is not
  a random fraction. Packed wholes share one duplicated datagram, and a
  high-risk small message is not split to fill the tail of a datagram.
- The copy has the same plaintext apart from the flag nibble. It is sealed
  under a fresh data-space nonce that MUST be exactly the original's nonce
  + 1, and it uses the original's DSCP. It takes its own pacing, flight and
  congestion-control slot. ACK-space nonces are unaffected.
- A pending copy is sent before any other data-space packet (data, MTU probe,
  keepalive). If an outage begins before it is sent, the copy itself is the
  first outage probe. On local send refusal the exact ciphertext is retained.
  If the nonce cannot be allocated, no copy is sent (the fallback is counted).

Receiver rules:

- The *canonical nonce* is the packet nonce for an original and the packet
  nonce − 1 for a copy (a copy with nonce 0 has no canonical nonce and its
  wholes are not delivered). Canonical nonces
  are tracked in a second replay-style history with the same 262144-position
  support as packet replay (allocated lazily, 64 KiB). Below its watermark
  canonical identities are permanently stale, never reopened.
- If the canonical nonce has already been committed, the whole frames of the
  packet are skipped. Fragment and Wirehair frames in the packet are still
  processed with their own identity deduplication, so the second arrival can
  still supply a symbol.
- Otherwise receive memory for all of the packet's whole frames is reserved
  first. Only when all reservations succeed are the wholes delivered and the
  canonical nonce committed. If memory is refused the packet counts as
  memory-erased and the canonical nonce stays fresh, so the other copy can
  still be delivered.
- Each physical packet keeps its own nonce and its own ACK/CE accounting.
  On the sender, a coded symbol carried in a duplicated pair counts as one
  lost FEC symbol only when both copies are lost. Congestion control still
  sees every physical loss.

Both peers must implement these flags. This is an incompatible framing
extension within version 2's frame-kind byte; it adds no header bytes.

Plain fragmented messages and coded units have connection-direction-scoped
u64 identities, allocated from one nonwrapping namespace across all sender
queues, roots and units. Roots and their units have distinct identities. A
sender never reuses an identity in a connection, including after its local
lease expires or it restarts a unit with a smaller symbol layout. u64::MAX is
reserved to force a new handshake rather than wrap. Receiver table indices
are never message identities. This implementation maps full IDs to fixed
1024-entry storage, with assembly/decoder bytes additionally charged to the
connection receive budget. On table pressure it permanently retires a completed
or already-erased identity older than the arriving ID first, otherwise the
least recently active older identity inactive for more than max(4*RTT, 2s).
If all entries are live/recent it refuses the new ID and withholds that packet's
ACK; it does not evict already-ACKed active state. Inline FEC decoders expire
on the same inactivity grace as workers (the outage sweep retains its existing
longer grace). The retirement watermark only erases unretained older arrivals:
retained active roots/units/plain messages remain usable below it. A frame for
an unretained ID (or segmented root) below the watermark is stale: ignore it
without allocating or reopening the ID, but acknowledge the physical packet.
In particular surplus repair symbols for an evicted completed unit are network
receipts, not new admission refusals or congestion evidence. Thus neither
completed-message churn nor a flood of concurrent incomplete messages can
evict a recently active assembly or grow the table.
It does not use `id % 1024` as identity or infer a 16-bit generation.

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

The normative codec/reference is the exact `third_party/wirehair` source tree
at STP commit `4bdea0bde6a8794ee0f7606bdb62f657bc2a36a9`, Git tree object
`3d8e99a30a94ac1d0fd66762baef5eeb3d791a45`. Its coefficient/seed generation,
GF(256) arithmetic, peel/dense/heavy construction and repair-ID interpretation
are part of the codec, not implementation-selected random choices. This pins
the complete reference, including the bundled fixup tables; merely agreeing
on the name Wirehair is insufficient. Source IDs are systematic first, with
immutable grouped-symbol mapping for the declared group maximum. K is
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
An admitted ID has one immutable role (plain fragmented message, FEC unit,
or segmented root). A unit's length, width, and full segment tuple and a
root's total cannot change under an ID. Conflicting frames are discarded,
never used to reset/rebind an existing decoder or completed identity.
Resource retirement may erase content, but not reopen the ID for another
role/layout. Asynchronous completion is delivered only for its exact still-live
decoder instance and connection generation, once; a Done slot is not live.

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
handshake; it must never wrap. Counts decreasing or greater than the sender's
total sent data-class packets MUST NOT change its remembered CE baseline.
A lower delayed count is harmless and does not invalidate its other positive
receipts. CE feedback is idempotent under ACK loss, duplication and reordering.
An authenticated receiver is still trusted to report CE honestly: plausibility
is not proof that any particular packet really experienced congestion.

## Key epochs and operational rotation

Epochs are directional u32 counters starting at zero. Epoch zero's keys are
the Noise IK split transport keys after **one Noise REKEY** per direction
(the pre-existing post-handshake key separation). Epoch n+1 is one additional
Noise REKEY of epoch n's directional key. ACK and data share the directional
key but have distinct, persistent nonce spaces.

Before encryption, rotate after at most **2^48 encryptions** or before the
next ciphertext would exceed **2^60 bytes** under that directional key.
ACK and data-class encryptions both count, including locally refused sends.
Also attempt an age-based update 600 seconds after the first encryption.
Age is an operational hygiene target, not an AEAD exhaustion limit, and is
deferred while the current update is unconfirmed.

Budget rationale: the actual AEAD is the IETF ChaCha20-Poly1305 construction
used by Noise ChaChaPoly (64-bit Noise nonces in its 96-bit nonce field).
[RFC 8439 sections 2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439#section-4)
requires unique nonces and limits an invocation to fewer than 2^32 64-byte
blocks; our 65535-byte record cap is far below this. For records of this size,
[RFC 9001 section 6.6](https://www.rfc-editor.org/rfc/rfc9001#section-6.6)
documents a ChaCha20-Poly1305 confidentiality limit greater than 2^62 packets.
The 2^48 encryption budget leaves at least a 2^14 packet margin to that bound;
the 2^60 byte budget is an additional conservative volume guard, not an
invented ChaChaPoly hard byte limit. In contrast, 2^24 packets would rotate
about every 0.2 seconds at 1 Tbit/s and TU1472 for no documented AEAD reason.
The new packet budget alone covers about 38 days at that rate; ordinarily the
600-second target rotates much sooner. These are fixed protocol rules, not
user knobs. Nonce exhaustion and Noise's reserved nonce/record rules still
apply independently. This is not a new formal multi-user security proof.
RFC 9001 also identifies an integrity limit of 2^36 **failed verifications**;
STP does not presently enforce a per-key failed-verification limit or claim
that bound against an unlimited active forger. Failed attempts are silent,
make no state changes except expired-key erasure, and do not cause a cheap
attacker-driven rekey/close. Global verification throttling/attempt accounting
is separate unimplemented hardening; encryption budgets do not bound forgeries.

### Confirmed, loss-tolerant key updates

Epoch zero starts confirmed. After rotating to epoch e+1, the sender MUST NOT
rotate again until an authenticated, plausible positive ACK receipts a
data-class nonce actually emitted in e+1. Because nonces never reset and
outgoing epochs never decrease, remembering the first data nonce sealed in
the current epoch and comparing a validated highest positive receipt suffices;
a receipt for an allocated-but-not-yet-accepted pending send is not plausible.
This also works for updates first used by an ACK: the next periodic keepalive
(or ordinary data/probe) provides a receiptable nonce in the new epoch.
ACK-only and idle directions therefore do not depend on application traffic.

Without confirmation, age alone MUST NOT rotate again or close the
association; continue sending in e+1 within its hard safety budgets. If either
hard encryption budget is reached before confirmation, stop encryption and
close, requiring a fresh handshake. Do not exceed the budget or send e+2.
Consequently loss of **all** e+1 packets cannot strand a conforming receiver
at e with an endless stream of undecryptable e+2 packets: the sender retries
e+1, receives confirmation, or cleanly closes at its safety/liveness boundary.
No reliable key-update control flight, ACK-of-ACK, new wire field or unbounded
catch-up derivation is required. A malicious authenticated receiver can lie
about receipts and harm its own association, as with ordinary ACK feedback.

The sender writes its chosen epoch in the authenticated packet header.
Locally blocked data sends retain/retry exact ciphertext at the effective TU;
they do not re-encrypt a different snapshot under its nonce. A refused
time-sensitive ACK burns its nonce before generating a later snapshot.

A receiver holds current, optional previous, and one prederived next incoming
key. Only a valid tag for **exactly current+1** advances its incoming epoch.
Each packet selects at most one AEAD key; successful advancement performs one
REKEY. A forged/far-future epoch causes no derivation loop or advance. The
previous epoch is accepted for at most ten seconds after advancement, and
only within replay support. Its stored keys are overwritten and dropped on
expiry (including from the idle send timer), or earlier on another advance.
This is logical key retirement plus best-effort overwrite of live stored keys,
not a guarantee of compiler-resistant erasure of all process-memory copies.
Packets older than one epoch are safely discarded even within ten seconds;
this bounded retention is not a promise to retain arbitrary high-rate old
epochs. Replay state never resets at rekey. Deterministic Noise REKEY protects
past erased epoch keys against compromise of a later key; it does **not**
provide post-compromise recovery or hide future keys from a transport-key
compromise. A fresh authenticated handshake is needed for fresh DH entropy.

Before nonce, u32 epoch or u64 identity exhaustion, implementations MUST
stop sealing and close or arrange a fresh handshake, never wrap or abort the
process. This implementation closes cleanly and reports the association gone;
the caller may request reconnection. It conservatively reserves the last
data nonce rather than trying to allocate beyond it. No old worker completion
may deliver into a replacement connection with the same endpoint lookup key.
Invalid tags elicit neither ACKs nor frame allocation.

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

## Security and traffic-analysis boundaries

ClientHello authentication requires Noise IK DH work before return routability
is known. Anyone knowing the responder's public key can generate a valid
hello, and matching-selector garbage still incurs responder DH attempts.
Half-open state is memory-bounded and expires after 15 seconds, but CPU cost
is not rate-limited. The initial 391-byte request/94-byte response is not
large-response reflection; retransmitted responses before confirmation can
exceed the original request cumulatively. A future **handshake version** will
put a stateless return-routability retry cookie before expensive DH/allocation,
with an aggregate pre-confirmation response budget. That cookie is not part
of version 2 and no current anti-spoofing/strict anti-amplification guarantee
is claimed.

Uniform current-TU padding hides application message sizes, fragment shape
and packing boundaries, not all metadata. The clear full nonce reveals packet
counts, gaps and rate; the clear epoch reveals update cadence, including the
600-second target. The static-key-derived 15-bit sender prefix permits
cross-address correlation and leaks those key bits. ACKs are intentionally
identifiable by their fixed size, and their cadence exposes receive timing.
Probe sizes, handshake sizes, DSCP, outage/idle timing and IP/UDP endpoints
are also observable. Version 2 does not provide traffic-flow confidentiality,
constant-rate cover traffic, unlinkable connection identifiers or epoch-age
jitter. These residual surfaces are deployment threat-model considerations,
not removed by encrypting/padding message frames.

## Implementation and verification boundaries

FEC worker counts, slot counts, sender retention, congestion/loss estimators,
ACK batching cadence and native socket limits are implementation policies,
not new identity widths or implicit wire generations. The declaration makes
current support explicit and rejects incompatible interpretations.

### Release candidate sender policy (frozen)

Nothing in this section is transmitted except the duplication flags above;
it is sender policy. Peers need not agree on it. Rates are in packets per
second (pps); internally micro-packets/s. "RTT" below is the smoothed CC RTT
unless stated. A *delay-corrected RTT sample* is raw ACK RTT minus the
peer-reported ACK delay, floored at 0.1 ms. The *connection min RTT* is the
minimum of all such samples. Legacy P0–P3 initialization is rejected by this
candidate; those experiment arms remain in the research tree. The
`research_target_validation` feature permits policy overrides, with
`STP_POLICY_FROZEN=0` restoring raw environment-only research configuration
(no frozen-value fallback); production builds ignore all these overrides.

#### Congestion control

Rate-based curve with the frozen parameters (`ship::CC`):

| Parameter | Value | Parameter | Value |
|---|---:|---|---:|
| beta | 0.8 | recovery_rtts | 9 |
| rate_rp | 0.92 | rate_pg | 1.02 |
| rate_gs | 2.0 | time_pg | 6.0 |
| time_gs | 10.0 | loss_threshold | 2 |
| loss_timeout_rtts | 2.0 | event_guard_rtts | 0.5 |
| rate_floor | 100 pps | initial_rate | 100 pps |
| min_growth | 25 pps/s | max_growth | 1000 pps/s |
| relative_growth_per_rtt | 0.015 | startup_multiplier | 1.05 |
| startup_backoff_rtts | 1.0 | | |

After a congestion event at anchor rate A (the *discovered* rate), with
k = recovery_rtts × RTT: phase R recovers quadratically from beta·A to
rate_rp·A over k; phase P rises linearly to rate_pg·A by time_pg·k; phase G
rises quadratically to rate_gs·A by time_gs·k; phase S then ramps steeply.
Every phase adds min_growth·t and is capped by the absolute envelope
beta·A + (min_growth + max_growth)·t and the relative envelope
beta·A·exp(relative_growth_per_rtt·t/RTT) + min_growth·t.

Congestion events (all respect a guard: evidence must have been *sent* more
than event_guard_rtts × RTT after the previous accepted event):

- **Loss**: loss_threshold (2) eligible packet losses inside one 1-RTT
  counting window.
- **ECN CE** feedback.
- **Delay** (below). An accepted delay event uses the CE path exactly
  (same guard, anchor discovery, startup exit and accepted-event record).

On a loss or ECN event the next recovery starts at beta = 0.8. On an accepted
delay event the recovery starts at **beta_delay = 0.95** instead, and the
R-phase end point is lifted to max(rate_rp, 0.95) = 0.95 so there is no
backward step at R→P. Anchor, epoch and guard are unchanged; a later loss or
ECN event restores beta = 0.8.

#### Delay congestion event

Constants (`STP_CC_DELAY_*`): K = 0.5, MIN = 5 ms, MAX = 50 ms,
INTERVAL = 1 RTT, GIVEUP = 3, HOLD = 16 RTT, HOLD_MAX = 256 RTT,
BETA = 0.95.

- Threshold: `T = clamp(0.5 × min_rtt, 5 ms, 50 ms)`.
- Window: the first sample opens a window with deadline
  `now + max(1 × RTT, 20 ms)` (the first ever sample seeds RTT). The window
  keeps the minimum delay-corrected sample and the latest sample's packet
  number and send time as evidence. It closes at the first sample at/after the
  deadline (before that sample is added, so the sample starts the next window)
  or on a send tick at/after the deadline. A closed window immediately starts
  the next deadline. Empty windows do nothing: no synthetic samples.
- A closed non-empty window is **high** if `window_min − min_rtt > T`,
  otherwise **low**. A high window raises a delay event (unless suspended).

Give-up and suspension (CUBIC coexistence). State: `ineffective`,
`suspended`, `pending` (time of the last accepted delay cut),
`consecutive_suspensions`, `hold_until`, `clean_until`.

1. On each close, if not suspended and `now ≥ clean_until`, reset
   `consecutive_suspensions = 0`.
2. **Low window**: if suspended and `now < hold_until`, the rearm is blocked
   (nothing else changes). Otherwise, if suspended, it is a *rearm* and
   `clean_until = now + 256 × RTT`; in all cases set `suspended = false`,
   `pending = none`, `ineffective = 0`, `hold_until = none`.
3. **High window**: if `pending` is set and `now > pending + 0.5 × RTT`,
   clear `pending` and increment `ineffective` (the cut did not drain the
   queue below T). When `ineffective ≥ 3` and not suspended: set
   `suspended = true`, increment `consecutive_suspensions` to c, and set
   `hold_until = now + min(16 × 2^(c−1), 256) × RTT`. While suspended, high
   windows raise no event (loss and ECN events are unaffected).
4. Otherwise the high window raises a delay event. If accepted (guard), set
   beta_delay as above and `pending = now`. A delay event rejected by the
   guard adds no strike.

#### Proactive coded parity (P4 target policy)

Race policy P4 (message-bound repair), interleave width 1, no slipstream,
no event-triggered repair, no medium-duration bonus (0) and no repair after a
message finishes sending: P4 seals and forgets an owner when its planned
send work is done. Messages that fit in one datagram are whole frames and
get no coded parity (only duplication, below).

For a coded logical message with K source symbols (K ≤ 32000 per plan) the
sender picks the smallest proactive repair count r with
`1 − delivery(K, r, p_eff) ≤ ε`, where `delivery(K, r, p)` is the binomial
probability of at most r losses among K + r packets at independent loss p.
Target miss ε = **EPS = 0.002**. (Without EPS the target would be
`p/(1 + (K/H)^E)` with P = 0.001, E = 1, H = 100/3. H and E are frozen
configuration but are not used for planning while EPS is set.)

Selector 2 mixes adjacent integers: with hi = r, lo = r − 1,
`w = clamp((1 − ε − delivery(K,lo,p)) / (delivery(K,hi,p) − delivery(K,lo,p)), 0, 1)`,
`threshold = floor(w × 2^64)`; use hi if `w = 1` or `draw < threshold`,
else lo. `draw` is SplitMix64 of `MIX_SEED + seq × 0x9e3779b97f4a7c15`
(MIX_SEED = 0x5354505f544d0001, seq = admission sequence of the root). It
does not depend on timing or outcomes.

The risk admission (p_eff, ε) is evaluated **once** at a logical root's first
admission and frozen for all its groups, segments and replans.

Loss top-up: while an owner is still sending, its planned repairs are
`proactive + tail_added + one replacement per known lost own DATA packet`
(exactly 1:1). Losses learned after the owner is sealed add nothing.

#### Design loss and risk

Base floor: `p_base = min(max(RAND_MULT × p̂, P), RAND_MAX)` with P = 0.001
(see RAND). Effective design loss:

    phi' = max(PHI, p_base),  PHI = 0.1
    p_eff = p_base + (phi' − p_base) × risk

Raw risk uses SRC = 4 (both signals must be high):

    ramp(x, lo, hi) = clamp((x − lo)/(hi − lo), 0, 1)
    cc    = ramp(rate / anchor, 0.98, 1.02)        (anchor unknown → 1)
    queue = ramp(qd / qd_ref, 0.5, 0.7)            (qd_ref unknown → cc)
    raw   = min(cc, queue)

rate is the current CC rate and anchor the last discovered event rate.
`qd = latest delay-corrected sample − connection min RTT`. `qd_ref` is the
qd measured at the last accepted congestion event of any kind; an event that
measures qd = 0 keeps the previous reference. Each event also updates the
anchor. Before the first congestion event both are unknown, so raw risk is 1.

STEP = 2: coded-parity admission and the tail use the continuous `raw`.
Duplication uses a stepped value: 1 if `raw ≥ 1` or a latch is active,
else 0. Latch (HOLD = 1 RTT, HOLD_MAX = 10 RTT): when no latch is active and
`raw ≥ 1`, latch at now. An active latch expires, once smoothed RTT is
known, at 1 × RTT after the latest accepted congestion event that came
after the latch time, or, if there is none, at 10 × RTT after latching. Low
raw risk cannot cut a latch short. A still-high raw risk re-latches at once.

#### End-of-message tail parity

TAIL = 3.0 RTTs. Once per logical root, when the last source symbol of the
final segment is emitted (before sealing):

    kt       = min(K, ceil(rate_pps × RTT_s × 3.0))
    reserve  = proactive count for kt from the rule above, using a fresh
               risk admission with phi' = max(PHI, root p_base) and draw
               SplitMix64(root_draw XOR 0x5441494c5f525356)   ("TAIL_RSV")
    added    = max(0, reserve − repairs still planned but not yet sent)

`added` repairs are added to the owner's plan (kt = 0 gives 0). The 1:1
loss top-up continues to apply afterwards.

#### Whole-message duplication

When the stepped risk is 1, every datagram containing whole frames is
duplicated as described in "Whole-message duplication flags".

#### RAND: background random-loss estimator

Constants: RAND_MULT = 2, RAND_HALF = 4000 packets, RAND_MAX = 0.05.

- Each DATA packet (including copies) is classified as *background* when
  sent: not in outage, `now > guard_until`, and the estimator's raw risk is
  exactly 0. Estimator risk is SRC 4 with missing signals treated as absent:
  if one ramp is unknown the other is used, if both are unknown risk is 0.
  The latch is ignored.
- `guard_until = max(guard_until, now + RTT × max(0.5, 9))`, i.e. 9 RTT,
  on every accepted queue-signal event (ECN CE or delay); with no RTT yet the
  guard is unbounded. Loss-only events
  set no guard.
- When the outcome of a background packet is final (one sample per physical
  packet): `p̂ += α × (lost − p̂)` with `α = 1 − exp(−ln 2 / 4000)`. Later
  spurious-loss corrections are ignored.
- `p_base` is computed at each root admission and frozen with it. On a clean
  link it stays at P = 0.001.

Tests cover every frame kind, unknown-kind skipping, the former all-ones
padding collision, full nonces across enormous gaps, arbitrary ACK bases and
repeated deep-window feedback, rekey budget boundaries/reordering, parameter
mismatches, malformed-input bounds, and encrypted UDP size capture. Tests are
implementation evidence, not a cryptographic proof or cross-implementation
interoperability result. Performance at 1 Tbit/s is not claimed.
