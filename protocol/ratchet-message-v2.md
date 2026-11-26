# Ratchet message version 4: encrypted headers and the post-quantum ratchet

Development protocol; release readiness requires internal verification of the
exact candidate. No independent cryptographic audit is claimed.

Ratchet message version `4` is how an upgraded direct session sends. It adds
two things to the Double Ratchet of [`ratchet-message-v1.md`](ratchet-message-v1.md)
and [`crypto-profile-v1.md`](crypto-profile-v1.md):

- **Header encryption** (§22.3 C4): the session ID, ratchet public key, both
  counters and the suite are sealed under a header key from the root chain, as
  in the header-encryption variant of the Double Ratchet (Signal's
  specification, §4).
- **A sparse post-quantum ratchet** (§22.3 C1): the two sides take turns
  running ML-KEM-768 exchanges inside the session and mix each shared secret
  into the root key together with that step's X25519 output.

Version 4 travels only inside the [recipient-sealed transport](recipient-transport-v1.md)
(`RCP`, outer suite 4), like version 3. Versions 1–3 are unchanged and still
read. The code is `packages/messenger-protocol/session/header.mpl` (wire and key
schedule), `pq_ratchet.mpl` (the post-quantum state machine) and `ratchet.mpl`.

## Negotiation

A session starts as version 3 and upgrades in place; there is no new
handshake and nothing changes for a peer that has not upgraded.

- Every direct inner envelope a current client sends carries optional
  inner-envelope extension **3** (session features), one byte: `1` reads
  version 4 (header encryption), `2` runs the post-quantum ratchet, `4` answers
  session resets ([`session-reset-v1.md`](session-reset-v1.md)), `8` reads
  deniable group messages (inner type 9 and group message 6,
  [`mls-groups-v1.md`](mls-groups-v1.md#deniable-sender-authentication)).
  Mobile sends `15`, the CLI's interop client `3`. Older clients ignore
  optional extensions.
- A receiver records the features of a message only after that message
  authenticated (the extension is inside the ratchet or handshake ciphertext),
  and they only grow (`ratchet_note_peer_features`). An attacker can neither
  add nor strip them.
- A side sends version 4 from its **next sending root step** (the first
  message after it received a new chain from the peer) once the peer has
  advertised `1`. Every message of that chain and every later one is version 4.
- The other side needs nothing recorded to read it: an un-upgraded session also
  tries the upgrade header key (below). Once it has read a version 4 chain, its
  own next chain is version 4 too.
- The post-quantum ratchet starts at a sending root step of a suite `0x0002`
  (hybrid) session whose peer advertised `2`. Classical sessions never run it.

Two current clients reach version 4 on the initiator's second message: the
responder answers on its handshake chain (version 3), which tells the initiator
the responder's features, and the initiator's next message begins a chain.

Once a session encrypts headers it never goes back: `encrypt` (bare version 2)
refuses, and a cleartext header is accepted only for a chain that began before
the upgrade (the current receiving chain if it is still version 3, or a
skipped key). A version 3 message that would begin a new chain, or that claims
the current chain when that chain began encrypted, is `InvalidMessage`.

## Wire format

```text
u8     version = 4
bytes3 "RAT"
u32    header length (113..1,297) || header blob = nonce[12] || AEAD(header)
bytes12 nonce
u32    ciphertext length (16..65,536) || ciphertext
```

The decoder fills no cleartext header fields: suite, session ID, ratchet key
and counters are empty until a session opens the header. A version 4 message
therefore names no session at all, even to whoever opens the recipient seal;
the receiver finds its session by trying each session's header keys
(`ratchet_header_matches`, `Mobile.Healing.locate_header_session`). That costs
a restore and a few AEAD trials a session, and anyone can seal an envelope to a
device's public identity key, so a junk version 4 envelope costs the receiver
that much before it is refused; proof of work on deposits bounds how many
arrive.

Header plaintext (85 bytes plus units):

```text
u16    suite                      1 or 2
bytes32 session ID
bytes32 ratchet public key
u32    previous chain length
u32    message number
u32    post-quantum mix            epoch this chain's root step mixed, 0 for none
u32    post-quantum epoch          0 when the kind is 0
u8     unit kind                   0 none, 1 encapsulation key, 2 ciphertext
u8     first unit                  < 37 (kind 1) or < 34 (kind 2)
u8     unit count                  at most the whole set
bytes  count × 32 unit bytes       units first, first+1, ... wrapping past the last
```

Decoders reject unknown kinds, a kind-0 header with an epoch or units, counts
over the set, and trailing bytes.

Header seal: `key = HKDF-SHA256(HK, salt = "", info = "mesh-msg/v2/header-seal",
32)`, ChaCha20-Poly1305 with a fresh CSPRNG nonce and associated data
`"mesh-msg/v2/ratchet-header"`. Body: the message key from the chain step of
version 1 (`mesh-msg/v1/chain-next`, `mesh-msg/v1/message-key`), ChaCha20-Poly1305
with a fresh nonce and associated data

```text
"mesh-msg/v2/ratchet-message" || u16(4) || u32(len(header blob)) || header blob
  || nonce || caller associated data (the session AAD)
```

so the body authenticates the exact sealed header. The body has no padding of
its own; the transport pads the packet. Largest plaintext: 65,314 bytes, which
seals to exactly 65,536.

## Key schedule

Version 4 root steps use new labels and have three outputs. With `RK` the
root key, `pub` the new ratchet public key, `m` the post-quantum epoch this step
mixes (0 for none) and `session_id` as salt:

```text
old      = HKDF(RK, session_id, "mesh-msg/v2/root-mix" || pub, 32)
IKM      = old || DH                    (m = 0)
IKM      = old || DH || ML-KEM secret   (m > 0)
RK'      = HKDF(IKM, session_id, "mesh-msg/v2/ratchet-root"  || pub || u32(m), 32)
CK       = HKDF(IKM, session_id, "mesh-msg/v2/ratchet-chain" || pub || u32(m), 32)
NHK      = HKDF(IKM, session_id, "mesh-msg/v2/header-key"    || pub || u32(m), 32)
```

`NHK` is the header key of the chain after next in the same direction, exactly
as in the header-encryption variant: a chain's header key is known to both
sides one root step before its ratchet key is.

**Upgrade keys.** When a session's first version 4 chain begins, both sides
hold the same root key `RK` (the upgrading side is the only one that may take a
sending root step). From it:

```text
first  = HKDF(RK, session_id, "mesh-msg/v2/header-key/upgrade/first", 32)
second = HKDF(RK, session_id, "mesh-msg/v2/header-key/upgrade/second", 32)
```

`first` seals the upgrading side's first chain, `second` the other side's next
one. The receiver tries `first` when a header opens under no key it holds and
it has not upgraded yet.

**Roles.** Header keys live in the session's header-key map under the roles
`send`, `next-send`, `receive`, `next-receive`, and, for each earlier
receiving chain that still has skipped message keys, under that chain's ratchet
key. At a sending root step `send := next-send` and `next-send := NHK`. At a
receiving one the key that opened the header becomes `receive`, the old
`receive` moves under the old chain's ratchet key, and `next-receive := NHK`.
An earlier chain's header key is deleted with that chain's last skipped key
(`header_key_owners` in the state lists them; at most eight).

**Decryption order.** `receive` (same chain: skipped key, replay, jump or the
next message), `next-receive` (a new chain), each earlier chain's key (skipped
key or replay), and the upgrade key. Any other header is `InvalidMessage`
without touching the session. Skipped keys, their 64 limit and their aging are
those of version 1 and keep their identifiers (ratchet key and message number).

## The sparse post-quantum ratchet

One ML-KEM-768 exchange an epoch, the sides taking turns as its owner:

| Phase | Side | Sends | Waits for |
|---|---|---|---|
| 1 | owner | its 1,184-byte encapsulation key, 37 units | a ciphertext unit |
| 2 | owner | nothing | the rest of the 1,088-byte ciphertext, 34 units |
| 3 | owner | nothing | its next sending root step, which mixes |
| 4 | other side | nothing | the whole key; then encapsulates |
| 5 | other side | the ciphertext | a received chain whose header says it mixed this epoch |
| 6 | next owner | nothing | its next sending root step, which starts the next epoch |

- **Start.** A side's sending root step with the ratchet allowed and phase 0
  starts epoch 1 as its owner. Every header of that chain says so (kind 1,
  epoch 1, possibly with no units), so the other side learns it before its own
  next sending root step and cannot start one too.
- **Keys.** The owner draws a 32-byte seed; the key pair is
  `ML-KEM-768.KeyGen(HKDF(seed, session_id, "mesh-msg/v2/pq-ratchet-key", 64))`.
  The seed is kept until the ciphertext is decapsulated, then destroyed; the
  shared secret is kept until it is mixed, then destroyed. At most one
  decapsulation key is ever in flight (the risk SPQR's design limits too).
- **Mixing.** Only the owner, holding the secret (phase 3), mixes, at its next
  sending root step, and every header of that chain carries `mix = epoch`. The
  other side mixes the same secret into that chain's root step. A header that
  claims a mix the receiver cannot match (wrong epoch, or no secret held) is
  `InvalidMessage`; a flipped mix field changes the derived keys and fails
  authentication. Both sides then move to the next epoch with roles swapped.
- **Units ride in padding.** A message carries as many units as fit in the
  space its padding bucket would leave anyway, computed from its plaintext
  length and the 69 bytes of transport and 153 of version 4 framing around it.
  A unit never moves a message into a larger bucket, so it costs no bandwidth
  the size buckets reveal. A message that fills its bucket carries none, and the
  exchange simply waits.
- **Loss and reordering.** Units are indexed and idempotent; the sender cycles
  through the set with runs that wrap, so each cycle's runs fall differently and
  losing every second message cannot keep missing the same units. Units of
  another epoch or kind are late copies and are ignored. Nothing is mixed until
  both sides hold the secret, and the side that mixes first says so in
  authenticated headers, so a lost, delayed or reordered unit only delays an
  epoch; it never parts the two roots. A chunk set is complete, or still
  waiting; there is no partial state to disagree on.

With 298-byte messages (a 1,024-byte bucket, 15 units each) and every second
message lost, an epoch completes in about six rounds of conversation
(`ratchet_v4.test.mpl`).

## Snapshot version 3

The ratchet snapshot is version `3` (`session/snapshot.mpl`). Its authenticated
header adds, after version 2's fields: the peer's features, whether sends
encrypt headers, the earlier chains with kept header keys, and the public half
of the post-quantum ratchet (epoch, phase, cursor, epoch mixed by the sending
chain, the key or ciphertext being sent, the one being collected and which of
its units arrived). The sealed parts add the four role header keys (purpose
`4`, each under its own slot; an empty part for a key the session does not hold
yet), the earlier chains' header keys (a `SecretMap`, purpose `12`, slot
`header-keys`) and the post-quantum seed and secret (a `SecretMap`, purpose
`12`, slot `pq`). New parts' storage objects are
`SHA-256("mesh-msg/v2/ratchet-snapshot-object/" || slot || header || u16(purpose))`,
so no two parts share a context; the five version 2 parts keep their objects.

Versions 1 and 2 are read (as not upgraded, with no features recorded and the
ratchet not started; version 1 still without its skipped keys) and every write
is version 3. A build older than this one cannot read a version 3 snapshot.

## What it protects, and what it does not

- **Headers after the identity key is lost.** Someone who records sealed
  envelopes and later obtains the recipient device's X25519 identity key opens
  the `RCP` seal of every one, but for version 4 learns only that it is a
  version 4 ratchet message and its length: no session ID linking the two
  directions, no ratchet key linking a chain's messages, no counters, no suite.
  Version 3 envelopes, and the ones sent before a session upgraded, stay as
  exposed as before.
- **Headers against session compromise.** Header keys come from the root chain,
  so someone who takes a session's state reads the headers of the chains whose
  keys it holds, and of later chains until the ratchet heals, exactly as with
  message keys. Header encryption adds nothing against that.
- **Post-quantum post-compromise security.** After a compromise, the first
  epoch whose ML-KEM key is generated afterwards takes the root back from an
  attacker who can break X25519 from the public ratchet keys it recorded,
  provided the attacker stays passive: an active attacker holding the state can
  impersonate either side, as with any ratchet. How soon depends on traffic,
  since units only use padding.
- **Hybrid.** Each mixing step's input is the previous root's output, the X25519
  result and the ML-KEM secret together: breaking X25519 alone or ML-KEM alone
  recovers no root, chain or header key. Between mixes, and in a session that
  never started the ratchet, confidentiality against a quantum attacker rests on
  the suite `0x0002` handshake's ML-KEM secret, as before.
- **Not covered.** Classical (suite `0x0001`) sessions get header encryption but
  no post-quantum ratchet. The ML-KEM-768 implementation is the runtime's
  unaudited crate (§22.3 C6). Envelope sizes, times and mailbox addresses are as
  visible as before.

## Tests

`packages/messenger-protocol/tests/ratchet_v4.test.mpl`: the key schedule and
header seal against an independent derivation (OpenSSL through Node,
`tests/fixtures/ratchet-v4/kat.mjs`); staying on version 3 without the peer's
features; one-sided and two-sided upgrade and no way back; no session ID or
ratchet key in the encoding; epochs completing with every second message lost
and the rest reordered; units only in padding, the largest message still
fitting; classical sessions never starting the ratchet; garbled, moved and
foreign headers refused with the session unchanged; earlier chains' header
keys opening late messages and going with the last; snapshots mid-epoch, their
authenticated version 3 fields, and version 2 snapshots read and rewritten.
`packages/mobile-core/tests/session_healing.test.mpl` upgrades two mobile
accounts end to end.
