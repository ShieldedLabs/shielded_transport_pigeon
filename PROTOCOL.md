# STP wire protocol, version 5 (research, unreleased)

This document specifies the incompatible version-5 transport (immutable
adaptive coded-unit extents) of `shielded_transport_pigeon`. It does not change
the crate's package version. Status: unreleased research profile; this document
states no test, interoperability or performance result.
All STP framing integers are unsigned little-endian; offsets below are byte
offsets. Public keys and Noise messages are byte strings with the encodings
specified by Noise, not little-endian STP integers. One UDP payload is one STP
packet. There is no compatibility with versions 1 through 4.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** specify
requirements for this interoperable wire profile. Statements explicitly labelled
"this implementation", "local", or "sender policy" describe the shipped Rust
implementation, not additional peer-negotiated requirements. Wire version 5 is
independent of the crate version and the application API. It retains version 3's
445-byte minimum FEC symbol, bitmap ACK and whole-duplication framing, and
version 4's 152-byte ACK carrying its sampled nonce's exact UDP payload size.
Version 5 changes only segmented roots: the declared maximum coded unit is a
per-unit maximum, not a balanced layout, and kind 6 units are validated as
immutable extents ("Wirehair symbol and segmentation validation"). The
declaration stays 32 bytes. Both endpoints MUST reject a mismatched profile;
they cannot silently reinterpret the old ACK or segmentation encodings.

An independent implementation needs this document, the Noise specification for
the selected suite, and the exact vendored Wirehair codec pinned below. No Rust
object layout, thread model, queue index, or public API type is serialized.

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
key[32], server payload[40], total 78 bytes. ClientHello dispatch uses bit zero of byte 0 (set); the selector is matched
exactly. An even prefix selects an existing association by source IP address,
source UDP port, and sender prefix. A pending initiator recognizes ServerHello
by bytes 2..5 all being `ff`; a connected endpoint instead attempts ordinary
AEAD admission. Handshake packets are dispatched before ordinary size-based ACK
classification. Retransmissions reuse the original handshake bytes, not a new
Noise transcript. An unknown selector, unknown association, failed handshake
authentication, invalid application offer/choice, or incompatible declaration
produces no wire error response.

Complete encrypted-profile handshake layouts (ranges are half-open):

| Datagram | Range | Contents |
|---|---|---|
| ClientHello (391 bytes) | 0..6 | little-endian six-byte selector / Noise prologue |
| | 6..38 | Noise initiator ephemeral public key `e` (32 bytes) |
| | 38..86 | Noise-encrypted initiator static key `s` (32 bytes + tag) |
| | 86..391 | Noise-encrypted client payload (289 bytes + tag) |
| ServerHello (94 bytes) | 0..6 | little-endian reply prefix, **not** a second prologue |
| | 6..38 | Noise responder ephemeral public key `e` (32 bytes) |
| | 38..94 | Noise-encrypted server payload (40 bytes + tag) |

The client payload offsets are count at 0, 32 application-ID slots at 1..257,
and declaration at 257..289. The server payload offsets are chosen application
ID at 0..8 and declaration at 8..40. The Noise IK pre-message is the responder
static key; the flights follow `-> e, es, s, ss` and `<- e, ee, se`. Handshake
hashes, cipher state, DH order and handshake nonces follow Noise, not the STP
connected-packet counters. After the second flight, Noise Split gives the
initiator-to-responder and responder-to-initiator keys; apply the one REKEY per
direction described under "Key epochs" before any connected packet.

For developer plaintext the corresponding byte ranges are selector/prefix
0..6, sender static key 6..38, then the unencrypted payload 38..327 (client)
or 38..78 (server). The implementation accepts a plaintext ClientHello with
trailing bytes but sends exactly 327 bytes; interoperable senders MUST use the
specified lengths. This mode MUST NOT be treated as an authenticated profile.

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
This implementation enters Connected on the first successfully authenticated
ordinary packet under the split/rekeyed keys, **before** checking packet type,
replay, minimum size or ACK semantics. It then processes that packet normally;
positive receipt feedback is generated only if subsequent data admission allows
it. Thus AEAD success confirms receipt of the responder's Noise flight, not
validity or application delivery of the confirming packet. There is no third
Noise flight. It does not send ordinary application traffic before this
transition. In developer plaintext even this authentication gate is absent.

| State | Input/action | Next state |
|---|---|---|
| Absent | local connect request: generate and save ClientHello | ClientHello-sending |
| Absent | valid ClientHello and local admission succeeds: save ServerHello and split keys | ServerHello-sending |
| ClientHello-sending | timer: resend saved ClientHello | unchanged |
| ClientHello-sending | valid compatible ServerHello: split/rekey keys; schedule data/keepalive | Connected |
| ClientHello-sending | simultaneous ClientHello from smaller public key: answer it | ServerHello-sending |
| ServerHello-sending | timer: resend saved ServerHello | unchanged |
| ServerHello-sending | ordinary packet with valid transport AEAD | Connected, then ordinary admission |
| Connected | fresh admitted data or ACK | Connected; process as below |
| Connected | ClientHello for the existing association | unchanged; do not reset |
| Any live state | local disconnect, deadline, or safety exhaustion | Closed (remove local association) |

Closed is conceptual: there is **no close frame, reset packet, reliable stream
control, or wire disconnect reason**. Reconnection creates fresh handshake and
transport state. Endpoint lookup is by source address/port plus the 15-bit
prefix, not a cryptographic connection ID; this implementation does not support
address migration or concurrent identities that collide in that lookup key.
Admission may also refuse a handshake when lifecycle-event or memory capacity
is unavailable; that refusal does not negotiate a different wire profile.

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
when locally able to send; ordinary data or a periodic 512-byte reachability
probe substitutes for an idle keepalive. Current-TU keepalives are all-padding
packets with fresh data-space nonces; the default 250 ms reachability schedule
normally supplies idle liveness before the five-second keepalive becomes due.
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
The sender retains 32 accepted outage/generic probe tuples in chronological
order, not nonce-modulo slots; generic traffic cannot overwrite a 2.5-second
proof after only eight sends. Each new outage clears this ledger. A candidate
must have been sent during the current outage, still be pending and at/after
the pending tail, and satisfy the unchanged age bound above. The lookup scans
at most 32 tuples and checks bitmap/sample membership, not every ACK bit per
tuple. Retired, consumed, pre-outage or replayed proof cannot resume sending.
Old withheld/replayed feedback cannot prove recovery. Outage resumption retains the
current TU (which the independent size-recovery policy below may lower),
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
| 0 | 2 | protocol version | 5 |
| 2 | 2 | declaration length, including these four bytes | 32 |
| 4 | 4 | maximum coded-unit bytes (a per-unit maximum, not a segmentation layout) | 2097152 (2 MiB) |
| 8 | 4 | Wirehair grouped-codec maximum source blocks per group | 32000 |
| 12 | 2 | minimum full repair-symbol bytes | 445 |
| 14 | 2 | maximum Noise ciphertext record bytes | 65535 |
| 16 | 4 | maximum scheduled ACK delay, microseconds | implementation ACK policy (10000) |
| 20 | 4 | receiver maximum application-message bytes | required constructor argument, capped at 1 GiB |
| 24 | 4 | maximum previous-key retention, microseconds | 10000000 |
| 28 | 4 | per-space replay/receipt support capacity, packets | 262144 |

Version 5 of this implementation requires exact agreement on every declared
field except maximum application-message size, which may differ and must be
in 1..1073741824. In particular it rejects, rather than silently reinterprets,
a different maximum coded unit or grouped-codec parameter. These are declared profile
parameters, not tuning knobs hidden from the peer. A future implementation can
support additional profiles by explicit validation/selection; it must not use
its own layout constants to reinterpret a peer's different declaration.
The length makes the declaration boundary explicit. Unknown versions or
lengths are rejected, not guessed. Future compatible frame extensions do not
require expanding this fixed handshake declaration.

A sender MUST obey the peer's declared maximum and may impose a smaller local
maximum. The receiver independently checks whole lengths, fragment extents,
coded-unit lengths and segmented totals. Local receive/decoder quotas may be
stricter than wire maxima. The declaration does not promise unlimited history
or memory. The public rings API's admission, dropping and counter behavior is
local API policy (see README), not an on-wire error or delivery receipt; in
particular accepting a send into a ring does not promise peer delivery.

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

Data/probe/keepalive nonce space is `0 .. 2^63-1` inclusive; ACK nonce space is
`2^63 .. 2^64-2` inclusive. `2^64-1` is reserved by Noise and MUST NOT be used.
This implementation also reserves data nonce `2^63-1`, closing before sealing
it, so its highest emitted data nonce is `2^63-2`. Initial outgoing nonces are
zero for data and `2^63` for ACKs in each direction. Counters are independent,
monotonically increase within each space, and MUST NOT wrap or reset at rekey.
A fresh handshake is required before exhaustion. A `(direction, key, nonce)`
MUST NOT seal different plaintext or associated data. Retrying an already
sealed locally blocked datagram reuses its exact bytes, not an encryption.

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
482 bytes (= 512 minus the maximum 30-byte transport/AEAD overhead). Data/probe/keepalive
plaintext must never be 152 bytes. No packet-type
byte replaces the size test. Ordinary sender data packets and idle/outage
keepalives fill exactly the current transmission unit (TU); upward MTU probes fill
exactly their probed TU. Periodic reachability probes alternate 512 UDP bytes
and the current TU.
Handshakes are the explicitly separate exception.
TU is the effective sender transmission unit: if an MTU-probe ACK arrives
while a locally refused current-TU ciphertext is pending, its discovered
larger TU is recorded but promotion is deferred until that immutable datagram
is accepted. Downshift is also deferred across a pending whole-duplication copy:
accepting its original cannot shrink the TU before the planned copy is accepted.
Apply the deferred TU before framing any subsequent packet, including within a
multi-packet send pass; run normal pacing finalization when the prepared width
becomes stale. Never reseal changed plaintext under the pending nonce. Explicit
probe-size exceptions are preserved verbatim through local-refusal retries.

### Receive admission and rejection order

The shipped receiver follows this order; malformed authenticated input is not
an atomic transaction and state changes are not rolled back.

1. Demultiplex by source address/port and prefix; require the 14-byte header.
2. Select only the key for the supplied epoch and verify AEAD with the entire
   header as associated data. A valid current+1 tag advances the incoming epoch
   and starts previous-key retention **at this point**, even if later checks
   reject the packet. An invalid tag cannot advance epochs or replay history.
3. Classify ACK by plaintext length 152 and require agreement with nonce space.
4. Commit packet replay admission. Duplicate/too-old packets stop here and do
   not regenerate ACK feedback. This replay commit precedes minimum-size,
   ACK semantic, frame and resource checks: a later rejected nonce stays spent.
5. Reject data plaintext shorter than 482. For ACKs, decode the fixed format
   and validate that the highest positive receipt is below the next **sent**
   data nonce (locally pending data have not advanced that counter). Reject the
   entire ACK if its sampled UDP size conflicts with retained exact emitted-size
   metadata, before activity, key confirmation, CE, receipt or TU effects. This
   semantic rejection does not undo replay admission. Valid ACKs
   refresh peer activity and may confirm outgoing keys; only new positive
   receipts progress delivery/loss state. ACK packets never elicit ACKs.
6. For data, refresh peer activity, apply whole-duplication admission and parse
   frames in order. A frame can complete/deliver before a later frame fails.
   Unknown frames are skipped. Truncated known frames stop parsing; this alone
   does not withhold receipt feedback for the physical packet.
7. If any receive-memory/table/decoder-ingress admission was refused, withhold
   the entire packet's positive receipt; otherwise record its nonce and ECN CE
   in the ACK receiver. This can acknowledge packets whose invalid/stale frames
   were skipped, and can withhold an ACK after another frame already delivered.

Further local distinctions: an oversized whole frame stops packet processing
without an ACK but does not close the connection. An over-limit FEC unit/root,
a plain extent exceeding the declared maximum, or plain u32 extent overflow
removes the association (the current API labels this `TimedOut`; there is no
wire reason). Other invalid FEC layouts, symbol lengths or role conflicts are
skipped. A plain extent above 2 MiB but within the declared maximum fails
reassembly admission and withholds the ACK. A kind 6 unit that violates the
extent rules, or overlaps a different already-admitted extent of its root, is
likewise refused before receipt and withholds the ACK. These choices are implementation
error policy, not messages a peer must send. Compliant senders MUST respect
all declared bounds and the consistency rules below.

A positive STP ACK is therefore packet feedback, **not** a reliable application
receipt. In particular the public receive ring may drop a completed message
when full while normal ACK processing continues. Neither replay admission nor
whole-duplication suppression is rolled back on such an application-side drop.

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

Complete frame layouts (offsets relative to the frame's first kind byte;
`L` is body_length, and each frame ends at `3+L`):

| Kind | Byte ranges and contents | Minimum L |
|---|---|---:|
| 1 | kind[0], L[1..3], message[3..3+L] | 0 |
| 2, 3 | kind[0], L[1..3], message_id[3..11], offset[11..15], data[15..3+L] | 12 |
| 4, 5 | kind[0], L[1..3], unit_id[3..11], block_id[11..15], unit_len[15..19], block_bytes[19..21], symbol[21..3+L] | 18 |
| 6 | kind[0], L[1..3], unit_id[3..11], block_id[11..15], unit_len[15..19], block_bytes[19..21], root_id[21..29], total[29..33], unit_offset[33..37], symbol[37..3+L] | 34 |
| 255 | kind[0], ignored tail[1..end of plaintext]; **no L field** | n/a |

A sender MUST NOT place duplication flags on later frame-kind bytes. For
robustness the current parser strips a recognized flag nibble on any frame;
only the **first** byte controls whole-message duplicate suppression. Unknown
high-nibble combinations are ordinary unknown TLV kinds, not a reason to infer
another flag format. Padding terminates parsing without inspecting the tail;
conforming senders fill the complete padding tail with `ff`.

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

Local duplication-selection policy (not required to match the peer): a sender
may send no flagged pairs at all. The frozen sender does the following.

- A datagram that carries at least one whole frame and is assembled while
  the sender's duplication decision is high (see "Release candidate sender
  policy") is sent twice. Every whole frame in it is protected; this is not
  a random fraction. Packed wholes share one duplicated datagram, and a
  high-risk small message is not split to fill the tail of a datagram.
- A flagged copy MUST carry the same frames and application bytes as its
  original, apart from the first-kind flag nibble. If the sender's TU grows
  between pair members, the copy may append additional `ff` padding to fill
  the new TU; exact plaintext length equality is not required. The copy MUST
  use a fresh data-space nonce exactly the original's nonce + 1. This sender
  also retains the original DSCP and takes a separate pacing, flight and
  congestion-control slot. ACK-space nonces are unaffected. Copies need not
  share the original's key epoch if a permitted rotation occurs between them.
- A pending copy is sent before any other data-space packet (data, MTU probe,
  keepalive, periodic reachability probe). If an outage begins before it is sent, the copy itself is the
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
- Otherwise this implementation scans parseable frames and reserves receive
  memory for all whole frames first, then commits the canonical nonce before
  processing/delivering individual frames. If reservation is refused the packet
  counts as memory-erased and the canonical nonce stays fresh, so the other
  copy can still be delivered. This is atomic memory admission, **not** atomic
  validation/delivery of a malformed frame stream or guaranteed admission into
  the public application receive ring.
- Each physical packet keeps its own nonce and its own ACK/CE accounting.
  On the sender, a coded symbol carried in a duplicated pair counts as one
  lost FEC symbol only when both copies are lost. Congestion control still
  sees every physical loss.

Both peers must implement these flags. This is an incompatible framing
extension introduced within version 2's frame-kind byte and retained in versions 4 and 5;
it adds no header bytes.

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
on the same inactivity grace as larger decoder jobs (the outage sweep uses a
longer grace). The retirement watermark only erases unretained older arrivals:
retained active roots/units/plain messages remain usable below it. A frame for
an unretained ID (or segmented root) below the watermark is stale: ignore it
without allocating or reopening the ID, but acknowledge the physical packet.
In particular surplus repair symbols for an evicted completed unit are network
receipts, not new admission refusals or congestion evidence. Thus neither
completed-message churn nor a flood of concurrent incomplete messages can
evict a recently active assembly or grow the table.
It does not use `id % 1024` as identity or infer a 16-bit generation.

Local sender packing policy: a message fitting one packet is not split simply
because the current tail is too small. Whole FIFO-head fillers are preferred.
The fill exception allows chopping a small message across at most **two
packets** to use a tail, provided its remainder fits a fresh packet with the
15-byte fragment header. Both pieces carry the same full message ID. A
continuation cannot be chopped into a third piece as another tail filler. No
small plain message is retransmitted/FEC-rescued by this rule. These sender
choices do not limit a receiver to two fragments per message.

For plain fragments, `offset + data_len` MUST fit u32, the receiver's declared
application maximum, and this profile's 2 MiB plain-reassembly bound. The final
fragment declares that sum as the total extent. A compliant sender MUST keep
that total fixed and MUST send identical bytes in any overlapping ranges for
the same ID. Completion requires coverage of `[0,total)` and a final fragment;
equal overlaps and duplicate fragments add no new bytes. Empty fragments are
legal subject to the same extent checks. Coded segmentation is used for larger
original messages.

**Current receiver conflict policy:** conflicting overlap, a changed final
extent, or bytes beyond a previously declared total fail insertion. Unlike
FEC layout conflicts, the implementation then discards the incomplete plain
assembly and retries the incoming fragment under the **same** ID; it does not
freeze or permanently reject that ID's byte contents. Completed plain IDs do
not redeliver. Thus immutable byte-content binding against an authenticated
malicious/buggy plain sender is not guaranteed. Resetting does not join
*different* IDs, and network loss/reordering of a compliant sender's consistent
fragments cannot itself create these conflicts. An independent receiver MAY
instead discard conflicting fragments or permanently erase that incomplete ID.

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

The receiving ordinary profile requires `block_bytes >= 445`, a unit at most
2 MiB, and a bounded source-block count (at most ceil(2 MiB/445) = 4713). Thus grouped
kind 5 is structurally parseable and round-trip tested, but cannot be needed
by a valid current-profile production unit; tiny-symbol or oversized-unit
uses are rejected. Kind 5 is therefore rejected by the current transport's
layout/kind check, not an alternate way to encode an ordinary unit. Kind 6
requires the unit itself to have one codec. For this profile K MUST be in
2..4713 and `445 <= block_bytes <= 65535`, additionally constrained by the
frame's u16 body length and the actual packet extent. All u32 block IDs are
source or repair equation IDs according to the mapping; no separate repair
flag is transmitted. Decoding may require more than K distinct equations:
Wirehair is a fountain code, not a guarantee that every K-symbol subset solves.

A sender MUST NOT change an ID's role (plain fragmented message, FEC unit, or
segmented root). A unit's length, width, and full segment tuple and a root's
total MUST NOT change under an ID. The receiver binds these role/layout fields
and discards conflicts rather than resetting a decoder or completed identity.
This does not guarantee rejection of every inconsistent coded equation from
an authenticated malicious sender, nor does it freeze plain byte contents
(see the plain conflict policy above). Resource retirement may erase content,
but cannot rebind a retained ID to another role/layout. Deferred completion is
delivered only for its exact still-live decoder instance and connection
generation, once; a Done slot is not live.

Version 5 replaces version 4's balanced offset rule with immutable extents. The
former requirement that kind 6 offsets be multiples of
`unit_span = ceil(total / ceil(total / max_unit))` with
`unit_len = min(unit_span, total - unit_offset)` is **no longer normative**, and
a receiver MUST NOT enforce a global uniform span. A segmented root of `total`
bytes (`total <= receiver maximum <= 1 GiB`) is covered by disjoint **extents**
`[offset, offset + len)`, one coded unit each; `unit_offset` is the offset and
the unit's length `len` is its FEC message length. Every extent MUST satisfy
(all arithmetic checked):

- `446 <= len < total`. The 446-byte minimum (one byte above the 445-byte
  minimum symbol) applies to **every** extent, including the one ending at
  `total`. A root therefore has at most `floor(total / 446)` extents, and only a
  root of at least 892 bytes can be split. A root that needs no split is an
  ordinary kind 4 unit.
- `offset + len <= total`.
- `len <= 2097152`, the declared per-unit maximum (and the unit remains one
  codec, so at most 4713 source blocks).

Extents of one root are immutable and pairwise disjoint; boundaries are chosen
by the sender (policy below) and are not derived from the declaration. The
receiver keeps a per-root ledger of admitted extents:

- An extent identical in `(offset, len)` to an admitted one is accepted (a
  restart under a fresh unit ID, or a duplicate).
- Any other overlap with an admitted extent, including the same offset with a
  different length, is refused before receipt: the packet's positive receipt is
  withheld and nothing is bound. Conflicting total/root metadata is discarded
  as above.
- The ledger persists, completed extents included, until the root is done. It
  is charged to the receiver's existing memory accounting and grows only after
  the larger charge is granted, within the unchanged hard caps; a refused
  charge binds nothing. The 446-byte minimum bounds the ledger to
  `floor(total / 446)` entries. This document specifies no exact maximum
  metadata size.
- Completion requires every byte of `[0, total)` to be covered by completed
  extents, once, with nonconflicting total/root metadata. A completed root is
  not redelivered.

A sender's restarted unit uses a fresh unit ID, preserving its root, offset and
length. Changing these extent rules is a new negotiated profile/version, not a
local tuning change.

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
| 28 | 1 | receipt encoding (1 = bitmap with sampled UDP payload size) |
| 29 | 1 | reserved zero |
| 30 | 2 | sample_udp_payload_bytes (nonzero, for sample_seq only) |
| 32 | 120 | 960 receipt bits, least significant bit first in each byte |

Bit i means positive receipt of `receipt_base + i`. The base is absolute and
may address **any** old or new window; it is not inferred from a highest
packet. `sample_seq` is independently acknowledged even outside the bitmap.
All positive receipts and the sample MUST be in data nonce space and below
the sender's next emitted data nonce; an allocated/sealed but still locally
pending datagram cannot yet be receipted. `receipt_base` itself must be in data
space even if its bitmap is empty; zero-bit positions need not be below the
next emitted nonce. There is no "no sample" sentinel: sample_seq always
positively receipts a packet, even with an empty bitmap. Additions are checked.
Unknown ACK encodings (including the old encoding 0), nonzero reserved bytes,
and a zero sampled size are rejected safely. The sample size is the exact
received UDP payload length, including STP framing and any AEAD tag but excluding
UDP/IP headers; it is not decrypted plaintext size or a largest-ever counter.
The receiver retains it with the latest unique admitted sample; duplicates and
old rejected packets cannot replace it. Before admitting receipt, CE or MTU
feedback, this implementation rejects the entire ACK if its sampled size
conflicts with retained exact emitted-size metadata, including protected generic
history or the outstanding upward probe. Missing history remains unknown and
cannot itself reject feedback. This field describes only sample_seq, never all
bitmap receipts, and size alone is not positive receipt or loss evidence. A highest receipt,
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
sample, not every bitmap receipt. It measures from that sample's receive time
to generation of this ACK snapshot. The declared 10000 us is the maximum
**scheduled** ACK delay, not a clamp on delay_us or a real-time execution
guarantee: a caller that does not drive Pump, local socket refusal or retained
feedback pages can make the actual sample age larger. CE is a monotone u64
cumulative count of
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
data nonce rather than trying to allocate beyond it. No old decoder completion
may deliver into a replacement connection with the same endpoint lookup key.
Invalid tags elicit neither ACKs nor frame allocation.

## Minimum TU and byte costs

The minimum supported recovered UDP TU is **512 bytes**. Its largest symbol
header leaves `512 - 14 - 16 - 37 = 445` bytes, exactly the declared repair
minimum. At TU 1204 that width is 1137 bytes; a profile-5 sender starts at TU 512
(width 445). Receiver
source-block and memory admission bounds derive from the 445-byte floor, not
from the initial TU; the maximum 2 MiB unit has at most 4713 source blocks.

TU is directional and measured in **UDP payload bytes**, excluding UDP/IP
headers. A profile-5 sender starts at 512 (versions 2-4 started at 1204); there
is no explicit MTU frame or negotiated common TU. All data receivers MUST accept valid current-profile packets independently
of their own send TU. The implementation admits non-ACK plaintext down to 482
bytes and never emits trimmed ordinary data. Local upward discovery searches up
to 9216 bytes using best-effort (BE) all-`ff` padding probes. Only an exact new
positive receipt of the recorded probe, at most `B + 1 s` old (B defined below),
can promote TU. Its full accepted timestamp is paired with its recorded nonce.
The probe's own delayed ACK cannot expand B to justify its freshness. With no
live failed-size bound, search chooses the first rung above the confirmed TU
from **1452, 1472, 2048, 4096, 8192, 9216**, identically for both IP families.
A failed candidate above current TU establishes a temporary exclusive upper
bound (the smaller of it and any live bound), expiring 30 seconds after that
failure. While the gap exceeds eight bytes, search tries the integer midpoint
between confirmed TU and the bound, with a **500 ms accepted-attempt floor**.
Success moves only the confirmed floor; it does not erase a useful upper bound.
Further interior failures renew the 30-second bound. When an outcome first
settles the gap to at most eight bytes, an independent clock schedules a recheck
of the **exact remembered upper**, not a coarse rung. Its delay is
`min(30 s, max(5 s, B) * 2^min(boundary_failures, 3))`, with B snapshotted when
that deadline is armed. Only completed failures of accepted exact-boundary
attempts increment this separate counter: low-RTT waits are initially 5 s, then
10, 20 and 30 s. Intermediate floor gains and interior failures neither restart
an already armed clock nor increment its counter. An expired settled upper stays
a revalidation target, not fresh evidence or a promotion/hold exception. Fresh
authenticated success at that exact upper clears it only upon effective TU
promotion, allowing normal coarse discovery after the accepted-attempt floor;
a partial path increase is therefore not trapped below the old boundary. With
an unsettled expired bound, coarse search retains
`max(500 ms, min(30 s, failures² * 250 ms))` backoff; it never slows interior
refinement. These are issuance deadlines once locally eligible, not ACK-arrival
guarantees. Both issuance and pump wakeups use the same candidate/deadline plan,
independent of CC/application occupancy. Outside the one-time startup exception
specified below, success never bypasses the last accepted attempt's 500 ms floor.
Only an **effective** shrink resets the failure count and seeds a bound from
the old effective TU, not from an unrelated upward probe. During the ten-second
post-recovery hold, strictly interior candidates below that live failed-size
bound may issue and promote; candidates at or above it remain excluded. An
obsolete pre-shrink attempt retains its exact size, nonce and pending ciphertext,
but its later ACK or failure cannot undo the reset search. A valid loss declaration
may narrow the bracket even if its ordinary loss timer exceeds B+1 seconds;
only positive promotion proof is subject to that freshness limit.

Default-on local size-recovery policy:

- Alternate generic **512-byte and current-TU BE** all-padding data-space probes
  on **250 ms** slots when locally able: two probes per second of each size,
  with no increase in the total four-probe-per-second schedule. At TU 512 every
  slot sends a small probe. The schedule depends on time and accepted generic
  attempts, never on application availability, queue occupancy or message length;
  ordinary 512-byte data does not move this clock. A pending ciphertext or
  whole-packet copy takes priority; send-ring capacity still applies. Pump wake
  deadlines include the generic probe and the upward hold. No thread is created.
- Feed only native authenticated, exact first-positive receipts into a bounded
  4096-entry nonce/size/send-time allocation: 3840 nonce-indexed metadata entries
  and a protected chronological 256-generic-probe ledger (64 seconds at four
  probes/s). Ordinary-send churn cannot erase recent generic evidence. Exact
  first-positive generic receipts train a separate raw RTT EWMA from their full
  accepted send times, before freshness/classification; ordinary and upward
  probes do not train it. First sample initializes SRTT=raw and variance=raw/2;
  subsequent samples use 1/8 SRTT and 1/4 absolute-error variance updates.
  Define `B = min(30 s, max(1 s, SRTT + 4*variance, 2*SRTT + ACK_delay_cap))`.
  Samples older than the absolute 31-second supported freshness ceiling are
  marked received but cannot train the estimate or prove recovery. With unknown
  RTT or a stable 20 ms path, B remains one second: original windows are unchanged.
  A fresh exact small receipt can lower the effective TU to 512 only after at
  least **B without fresh larger ordinary or exact-current-TU generic progress**,
  with **at least two unconfirmed exact-current-TU generic probes aged B to B+2 s**
  and **at least two positive generic 512-byte receipts whose sends are at most
  B+1 s old**. All counted sends must follow the last such larger progress.
  Upward-probe failures and old ordinary losses supply no failure evidence;
  old-TU failures cannot classify a newly promoted TU. Fresh larger progress
  anywhere in the same ACK vetoes the decision regardless of receipt order.
  The complete predicate is rechecked after the whole ACK using its final RTT
  budget: a later sample cannot leave earlier, now-immature failure proof valid.
  A native first-positive receipt with overwritten metadata can only veto,
  never establish evidence. ACK-highest, aggregate counts and duplicate
  receipts supply no proof. Normal larger receipts take constant-time lookup;
  unknown metadata uses binary search of the rotated chronological generic ring,
  not a linear 256-entry scan. Only eligible fresh small proofs scan that ledger.
  A downshift clears both history rings, their cursor and valid count, while
  retaining the independently learned raw RTT estimate.
- Hold discovery/promotion at or above the failed TU for ten seconds after a
  decision; strictly interior bracket refinement is allowed as above. Pending
  ciphertext and planned duplication copies retain their exact bytes and nonce;
  effective shrink waits for their acceptance. Restart a still-active FEC unit
  from its full shared source under a fresh unit ID if its symbol no longer fits;
  preserve segmented root/offset, and never reopen a sealed root or mutate an
  existing unit's layout. Already-forgotten messages are not made reliable.
- Startup trial and initial unit assessment (profile-5 sender policy; nothing
  here is transmitted). A new connection starts at TU 512. Its first generic
  larger-size trial is 1204, issued at the ordinary first-issuance deadline with
  no extra delay (startup state Candidate, then Issued when that attempt is
  issued). Only a fresh, accepted success of that exact 1204 attempt that is
  promoted allows **one** prompt 1452 attempt once 1204 is effective; it bypasses
  only the 500 ms accepted-attempt floor (hold, failed-size bounds and every
  other eligibility rule still apply). Afterwards, and in every other case,
  ordinary coarse search applies. The initial *assessment* is **unresolved**
  while the state is Candidate or Issued. It settles once, when the 1204 trial
  reaches an outcome and any promotion it caused is effective (no larger TU still
  deferred behind a pending ciphertext or duplication copy); a failed trial, a
  cancellation, outage entry, or an effective shrink also ends it. Nothing
  re-arms the assessment for the connection.
- During outage, either generic probe class also records an outage probe, so its
  fresh positive receipt can satisfy the existing outage-resumption rule without
  postponing independently backed-off current-TU outage probes.

This is a conservative classifier, not proof of a path failure. Old unconfirmed
ordinary sends alone cannot trigger idle/drain fallback, but recent repeated
size-selective loss can. Sustained occasional positive progress at the larger
size can delay or prevent downshift even under severe size-selective loss.
A successful size proof does not guarantee future delivery at that size. The
one-second minimum B is an evidence-aging floor, not a fallback deadline:
repeated current-TU attempts must each mature, and the decision still waits for
a fresh small receipt. A change in size-selective delivery can therefore cause
an interval of application loss after a valid promotion; starting at 512 does
not prevent that later failure. Shrink does not retransmit already-forgotten
unreliable messages. History overwrite and local backpressure may further delay
recovery; paths below 512 bytes are unsupported. The
history uses 96 KiB per connected peer on Linux x64, charged in the 608 KiB
connection-bookkeeping reservation separately from the derived receive-data cap.
The 32-entry outage ledger and generic RTT/count state add 416 inline bytes on
Linux x64 within that existing reservation, with no extra history allocation.
The upward bracket and independent boundary clock use another 32 inline bytes,
replacing the old eight-byte additive-search step; history and reservation sizes
are unchanged.
Adaptive classifier windows do not promise native 5–10-second RTT support: the
ordinary compact send-time history still has an approximately 4.295-second
horizon and the CC RTT mean is capped at 6.5535 seconds. Packet-rate congestion
control and FEC planning policy are unchanged. These schedules/search limits
are local sender policy, not additional wire fields.

The table excludes IP/UDP headers, padding and coding redundancy; these are
encoding overhead bytes, not a claim about measured wire/app ratio. The
packet overhead includes the AEAD tag. Whole headers are per packed message.

| Item | Pre-version-2 bytes | Version 2/3 bytes | Change |
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
exceed the original request cumulatively. Stateless return-routability retry
cookies and an aggregate pre-confirmation response budget are **not** part of
versions 4 or 5. No current anti-spoofing/strict anti-amplification guarantee is
claimed; adding such a handshake exchange requires a separately specified
compatible mechanism or a new profile/version.

Uniform current-TU padding hides application message sizes, fragment shape
and packing boundaries, not all metadata. The clear full nonce reveals packet
counts, gaps and rate; the clear epoch reveals update cadence, including the
600-second target. The static-key-derived 15-bit sender prefix permits
cross-address correlation and leaks those key bits. ACKs are intentionally
identifiable by their fixed size, and their cadence exposes receive timing.
Probe sizes, handshake sizes, DSCP, outage/idle timing and IP/UDP endpoints
are also observable. Version 5 does not provide traffic-flow confidentiality,
constant-rate cover traffic, unlinkable connection identifiers or epoch-age
jitter. These residual surfaces are deployment threat-model considerations,
not removed by encrypting/padding message frames.

## Implementation and verification boundaries

Receiver admission and assembly remain subject to the unchanged memory caps.
An extent that cannot be charged is refused and its receipt withheld. Completed
unit buffers transfer into root assembly together with their memory charges;
assembly does not make a second unit copy. If a contiguous join cannot grow its
destination buffer, its charged parts remain owned for a later retry. Periodic
maintenance retries a root before applying that root's inactivity expiry and
checks the caller's work budget between roots: the first root of each
maintenance entry is prepaid, so a deadline that already passed still advances
one root, and every later root first takes a fresh monotonic clock sample.
Erased incomplete work is never reported complete, and a completed root is never
redelivered. A single root join remains an indivisible work item; no hard
wall-clock latency bound is claimed.

The receive budget counts charged allocations (decoders, unit buffers, root
ledgers and part tables), not process RSS. Each connection's fixed 1024-slot
reassembly ring is allocated outside that dynamic budget; profile 5's cached
per-root part sums add about 16 KiB to it on 64-bit targets. Extent and part
lookups are binary searches; finding and removing the next contiguous part is
O(1), excluding the copy of its bytes. Inserting a unit in the middle of a
root's ledger or part table shifts a vector. A peer that
sends a large root's units in an adversarial order can therefore force O(n²)
element moves for n <= `floor(total / 446)` extents, within the memory caps. The
sender's per-root unit plan is updated in O(log n) per unit.

FEC job quotas, slot counts, sender retention, congestion/loss estimators,
ACK batching cadence and native socket limits are implementation policies,
not new identity widths or implicit wire generations. The declaration makes
current support explicit and rejects incompatible interpretations. The library
creates no worker threads: the caller drives a Pump; encoder construction and
persistent decoder work run on that caller's thread. Historical internal
"Worker" names and worker counters now denote admitted decoder jobs, not
library-owned threads. Worker-capable connections may admit up to the unchanged
process-wide ceiling of eight decoder jobs, subject to full per-job byte leases
and the unchanged connection/process receive-memory caps; inline-only connections
admit no worker jobs. The configured worst-case worker dimension still sizes the
connection byte cap, not its runtime job count. Job generations prevent stale
completions from reaching a different decoder or replacement association.

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

#### Segmented unit selection (profile-5 sender policy)

Local policy; the wire requires only the extent rules above. A root that fits
the unit cap C is one ordinary kind 4 unit and is not segmented. Let W be the
current segment symbol width (current TU payload minus the 37-byte kind 6
header, at least 445). C is:

- **2097152** once the initial TU assessment has settled;
- **113920** (= 445 * 256) while it is unresolved and the P4 budget base is
  inactive (no frozen root risk exists);
- otherwise, while unresolved, the **exposure cap** below.

Exposure cap. Each send tick copies one connection snapshot to every queue: R,
the last allowed congestion-control pacing rate (0 before the first CC pass);
T, the mean of ACK-measured RTT samples, absent while none is valid; Q =
max(1, queues holding unsent work); and E, the committed but unresolved DATA
packets in the repair span ledger. With

    k0 = max(2, ceil(892 / W)),   k_max = max(k0, floor(113920 / W))
    B0 = ceil(R × T / Q)  packets  (T valid),   else  B0 = ceil(E / Q)
    B  = max(B0, U(k0))

C = k × W for the largest k in [k0, k_max] with U(k) <= B; if U(k0) is
unavailable, C = k0 × W. U(k) is an upper bound on a new unit's initial packet
train: K = k source packets plus its repairs. With target validation off it is
`k + min(k, 2)`. With target validation on it is k plus the smallest reserve r
whose modeled binomial miss probability for K = k at the root's frozen p_eff is
at most the smallest possible unit share, ε_root × 446 / total (frozen EPS, or
ε_root from K_up below). No admission, draw or zero band is applied; it is meant to
be no smaller than a unit's actual initial train. U(k) is unavailable if the frozen risk is
missing or the computation fails, and such a k does not fit. The search assumes
U is non-decreasing in k. 113920 remains the largest cap of the unresolved phase.
B is a one-flight estimate from a mean RTT and the current rate, not a strict
all-path RTT bound, and U(k) sizes units; neither is a delivery or miss bound.
A root of at least 892 bytes that may exceed the smallest cap k0 × W freezes its
single root risk admission, draw and ordinal before the split decision; every
unit, restart and whole-root start of that message reuses it.

C is recomputed from the current snapshot and width whenever a new unit starts.
With `R` bytes remaining, the next unit has length

    g   = max(1, min(ceil(R / C), floor(R / 446)))
    len = ceil(R / g)                  (balanced, floor-aware partition of R)

so every unit, including the last, is at least 446 bytes. Each unit's symbol
width is `min(W, max(len - 1, 445))`, fixed when the unit starts. This clamp
gives every unit K >= 2; a same-range restart after a TU shrink applies the same
clamp. A unit already admitted is immutable: changes to C affect only the
unstarted remainder. There is no hold or admission timeout waiting for the
assessment, and no upward recode: a started unit is never re-split or re-encoded
at a wider symbol to exploit TU growth (a same-range restart after a TU shrink
remains as described above).

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
else lo. Define `D(x)` as the SplitMix64 finalizer applied to
`MIX_SEED + x × 0x9e3779b97f4a7c15`, with wrapping u64 arithmetic and
MIX_SEED = 0x5354505f544d0001. The finalizer successively applies
`z = (z XOR (z >> 30)) × 0xbf58476d1ce4e5b9`,
`z = (z XOR (z >> 27)) × 0x94d049bb133111eb`, and
`z XOR (z >> 31)`. The admission draw is `D(seq)`, where seq is the root's
admission sequence; it does not depend on timing or outcomes.

The risk admission (p_eff, ε) is evaluated **once** at a logical root's first
admission and frozen for all its groups, segments and replans.

##### Segmented roots (profile 5)

A root sent as several kind 6 units keeps the single frozen root risk admission
and root draw. Each unit extent `[offset, offset + len)` of a root of `total`
bytes receives, when it is first admitted:

    ε_root = EPS                                  (EPS set)
           = p_eff / (1 + (K_up / H)^E)           (EPS off; uncapped, no 32000 limit)
    K_up   = n + floor((total - n) / 445),   n = max(1, floor(total / 446))
    ε_unit = ε_root × len / total
    draw   = D(root_draw XOR (0x554e495400000000 OR offset))

where 0x554e4954 is ASCII "UNIT" and `offset` is the unit's start offset as a
32-bit value. With EPS off, K_up is the largest possible total source-symbol
count over any partition of the root into units of at least 446 bytes at
symbol widths of at least 445 bytes. n such units hold at most
`n + floor((total - n) / 445)` symbols; this grows with n and is attained by
n - 1 minimum units plus the remainder. K_up is therefore independent of layout
and TU (a whole unsplit root uses the same formula with n = 1 when
total < 446). ε is allocated by byte length, so a unit's share does not depend
on its K or width. The unit draw depends only on the root draw and the
immutable offset: not on unit number, TU, timing or outcomes. A unit that is the
whole root (`len = total`) uses the root draw and exactly the pre-unit plan. Each
unit's plan is the Selector 2 plan above for its own K and codec groups at
ε_unit. These shares of any disjoint cover of `[0, total)` sum to ε_root.

Model statement, not a guarantee: *if* every unit meets its modeled share ε_unit,
the union bound gives a modeled probability of at most ε_root that some unit
misses, whatever boundaries were chosen, because shares are allocated by the
byte length of immutable extents. This is conditional on the per-unit model.
Selector 2 is a mixture over an ensemble of draws, not an absolute per-draw
target: a particular draw gets r or r - 1. The draws are deterministic
pseudorandom values and boundaries may depend on outcomes (TU assessment,
feedback); neither proves independence conditional on every history, so they do
**not** establish a physical delivery guarantee. The model also assumes
independent packet loss at p_eff and ideal rank; Wirehair may need more than K
equations and real loss is correlated.

##### TU-shrink replanning

When a still-active unit restarts at a smaller TU its symbol count K grows. The
sender replans for the current K using the same frozen root risk admission,
the same ε_unit share and the same unit draw as above, rather than keeping the
old proactive count. The cumulative repair allowance retains every repair already charged to the
old layout, without refund. The new layout reserves its full proactive plan
again within that same remaining allowance, not merely the difference between
the old and new proactive counts; previously emitted equations are not useful
to its new decoder. The 1:1 loss top-up is preserved only while the owner is
open, the end-of-message tail is applied once at the final tail, and nothing is
added after the owner is sealed.

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
               D(root_draw XOR 0x5441494c5f525356)   ("TAIL_RSV")
    added    = max(0, reserve − repairs still planned but not yet sent)

`added` repairs are added to the owner's plan (kt = 0 gives 0). The 1:1
loss top-up continues to apply afterwards.

K here is the root's source-symbol count in its first admitted layout; a later
same-range restart at a smaller TU does not change it (it is not the then-current
K). For kt <= 32000 the plan is the ordinary one above. For a larger segmented
root kt may exceed 32000. It is bounded by K_up at the 1 GiB maximum root,
4,814,984. The reserve then uses the same pooled binomial model over the one
exposure kt, not chunked per codec, evaluated by a bounded-term CDF that expands
outward from the mode and stops each direction when the omitted-mass bound falls
below EPSILON/4 of the accumulated normalization. Floating-point error is
additional, so this is not a formal probability certificate. The ordinary
per-codec 32000 cap and admission planning are unchanged.

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
interoperability result. Performance at 1 Tbit/s is not claimed. This
profile-5 document reports no test, build or performance result.
