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
a reliability promise. After 120 seconds without new positive ACK progress
the association closes, even if local sends have all been refused. A new
association uses a fresh handshake, never reset transport keys/counters.
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

Tests cover every frame kind, unknown-kind skipping, the former all-ones
padding collision, full nonces across enormous gaps, arbitrary ACK bases and
repeated deep-window feedback, rekey budget boundaries/reordering, parameter
mismatches, malformed-input bounds, and encrypted UDP size capture. Tests are
implementation evidence, not a cryptographic proof or cross-implementation
interoperability result. Performance at 1 Tbit/s is not claimed.
