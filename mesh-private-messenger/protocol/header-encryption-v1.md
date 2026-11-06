# Header encryption, document revision 1

This describes the C4/D3 profile adopted in development source and matching native
libraries. Deployment, release and independent cryptographic review remain
separate. Its wire identifiers
are HST/INI version `2`, RAT version `4`, and RST version `3`; the document revision
does not replace those identifiers. The construction is a versioned Morse profile,
not another protocol's wire or KDF interoperability profile.

The existing [recipient seal](recipient-transport-v1.md) remains the outer transport.
Opening a captured RCP with a later-compromised recipient identity key still reveals
the inner packet kind and initial bootstrap metadata. For an established HE message,
that alone does not reveal its session ID, ratchet public key or counters: those
fields require the evolving header key. Arrival timing, mailbox addresses, expiry
and size buckets remain observable.

## Authenticated selection and migration

`DeviceCredential.capabilities` mask `8` advertises HE. It is useful only after
account-signature, bundle, current device-set and transparency validation. The
combined mobile account/link writer advertises `31` (`1|2|4|8|16`); the text-only
Mesh CLI advertises `9` (`1|8`). The CLI does not thereby claim attachment or timed
group readers. Historical C4-only mobile credentials advertised `15`.

Latest mobile writes require HE on the exact authenticated local/peer profiles
and all current selected peer/own-device sets, including linked/self-sync targets.
Admission occurs before new sends and prekey reservation; unsigned flags, a pending
renewal or an account manager's inference do not establish support. Mixed, stale,
changed or unverified sets fail; failure does not trigger a legacy send. A cached
legacy session requires a new authenticated HE handshake before it can send under
the latest policy. Preferred-session selection favors HE at an equal strongest
suite, while preserving suite-downgrade and key-change checks.

RNWv2's signed mask remains exact and monotone. The current-readers request adds
`2|4|8|16` to the prior mask, preserving prior bits. The historical ACH3, attachment,
HE-only and group-only methods retain their exact `old|2`, `old|6`, `old|14` and
`old|22` routes. A changed capability answer requires its stored authenticated
device-signed request and exact requested keys/expiry/mask; an unchanged-capability
renewal can retain its existing route. RNWv1 remains a mask-preserving legacy
request. See [device capabilities](device-capabilities-v1.md) for framing and the
two-phase primary/linked-device process. Matching backend verifiers and client
readers are required before activation.

The protocol library still has explicit legacy construction/read paths for
compatibility. Those are not permission for the latest mobile writer to bypass
the authenticated HE admission policy.

## RAT4 wire and associated data

All integers below are unsigned big-endian. Fields are concatenated exactly; there
are no implicit string terminators, optional fields or trailing bytes.

| Field | Offset | Bytes |
|---|---:|---:|
| Version `4`, then ASCII `RAT` | 0 | 4 |
| Random XChaCha20-Poly1305 header nonce | 4 | 24 |
| Encrypted header, including its tag | 28 | 90 |
| Body AEAD nonce | 118 | 12 |
| Body ciphertext length, u32 | 130 | 4 |
| Body ciphertext, including its tag | 134 | 16–65,333 |

The complete RAT4 is **150–65,467 bytes**. The authenticated header plaintext is
exactly **74 bytes**:

| Field | Offset | Bytes |
|---|---:|---:|
| Negotiated suite (`1` or `2`), u16 | 0 | 2 |
| Session ID | 2 | 32 |
| X25519 ratchet public key | 34 | 32 |
| Previous sending-chain length, u32 | 66 | 4 |
| Message number, u32 | 70 | 4 |

The public decoder does not populate those values from an untrusted clear hint.
Its internal empty/zero placeholders are not a transmitted suite `0` or a routing
identifier. Header authentication recovers and verifies the real suite/session.

Let `P = 04 52 41 54`, and let `C` be the caller's associated data:

```text
header AAD = ASCII("mesh-msg/v2/header-aad") || P || C
body AAD   = ASCII("mesh-msg/v2/body-aad") || C || P
             || header_nonce24 || encrypted_header90 || body_nonce12
```

Header sealing uses `Crypto.xchacha20poly1305_seal` and a fresh random 24-byte
nonce. Body sealing retains the existing 12-byte-nonce `Crypto.aead_seal` cipher
and a separately derived per-message body key. A body cannot be moved to a
different encrypted header, nonce, caller context or wire version. Both header
and body must authenticate before accepting a protocol transition or committing
its stored state. Exact saved outbox bytes can be retried. New encryption attempts
generate fresh random nonces; only an accepted state transition advances the
counter. A failed tentative attempt may be discarded without advancing the
original state.

For normal mobile/CLI messages, `C` is
`SHA256(ASCII("mesh-msg/mobile/ratchet-aad/v1") || session_id32)`. The initial
embedded RAT4 instead uses `ASCII("mesh-msg/v2/he-initial") || session_id32`.

### Writer bounds versus codec bounds

RAT4 adds 134 bytes of framing and a 16-byte body tag. Its M8P kind-2 wrapper
adds 13 bytes, so a **65,317-byte body** produces 65,467 RAT bytes and exactly
65,480 inner packet bytes. RCP adds its four-byte inner length plus 52 bytes of
transport overhead, fitting the existing **65,536-byte maximum bucket**. RCP
still checks canonical minimal buckets and zero padding; the HE change does not
increase that transport ceiling. The 65,317 limit covers the complete ratchet
plaintext, including any inner/presentation framing, not only the displayed text.

An INI2 carries a complete RAT4 as its ciphertext field and retains INI's existing
bootstrap fields. Its old nonce field must be exactly 12 zero bytes. With a
credential length `L` and suite-dependent ML-KEM ciphertext length `Q`, INI's
fixed overhead is 138 bytes, so its encoded length is
`138 + L + Q + (150 + body_length)`.

The transport's existing `InitialPacket.message` writer bound is **48,800 bytes**.
Consequently the HE initiator admits at most `48,512 - L - Q` body bytes:

| Initial profile | `L` | `Q` | HE body writer maximum |
|---|---:|---:|---:|
| Classical credential, suite 1 | 211 | 0 | 48,301 |
| Hybrid credential, suite 2 | 1,395 | 1,088 | 46,029 |

These are new HE *writer* admission bounds. INI's codec retains its separate
65,536-byte envelope limit and validates ciphertext against
`65,398 - L - Q`; INI2's ciphertext must be at least 150 bytes. Legacy codec/read
admission is not reduced to the new writer limit. Valid hybrid/classical pairings
and credential signatures remain required independently of this length arithmetic.

## Handshake binding and key schedule

HE is selected only when both authenticated credentials have mask `8`. The
transcript encoder emits HST2, and the initial message emits INI2. Receive derives
the expected version from the authenticated initiator credential and the selected
responder bundle; it checks version, suite, prekey IDs/keys and transcript hash.
It never retries an INI2 failure as INI1.

Define `HKDF(secret, salt, info)` as the existing opaque-resource HKDF-SHA256 with
32-byte output; `||` below is exact concatenation. Let:

```text
SID = SHA256(ASCII("mesh-msg/v2/handshake-header-encryption") || encode(HST2))
salt = SHA256(ASCII("mesh-msg/v1/handshake") || SID)
bootstrap = HKDF(handshake_IKM, salt, ASCII("mesh-msg/v2/he-bootstrap-root"))
HKA  = HKDF(bootstrap, SID, ASCII("mesh-msg/v2/he-shared-hka"))
NHKB = HKDF(bootstrap, SID, ASCII("mesh-msg/v2/he-shared-nhkb"))
```

`handshake_IKM` is the existing authenticated suite-1/suite-2 handshake material;
suite 2 includes its ML-KEM-768 contribution. The `v1` salt prefix above is
intentional existing code, while the transcript and HE derivation labels are
distinct. No secret is exported into ordinary bytes for this derivation.

For a root transition using the fresh ratchet public key `R` and DH output `DH`:

```text
mix = HKDF(root, SID, ASCII("mesh-msg/v2/he-root-mix") || R32)
combined = Secret.concat(mix, DH)
next_root   = HKDF(combined, SID, ASCII("mesh-msg/v2/he-root") || R32)
body_chain  = HKDF(combined, SID, ASCII("mesh-msg/v2/he-chain") || R32)
next_header = HKDF(combined, SID, ASCII("mesh-msg/v2/he-next-header") || R32)
```

For body message number `n` on ratchet public key `R`:

```text
next_chain = HKDF(chain, SID, ASCII("mesh-msg/v2/he-chain-next") || R32 || u32(n))
message_key = HKDF(chain, SID, ASCII("mesh-msg/v2/he-message-key") || R32 || u32(n))
```

Alice starts with sending header `HKA` and next-receiving header `NHKB`, creates a
fresh ratchet DH pair distinct from the bootstrap ephemeral, and transitions
against Bob's selected one-time-prekey public key. Bob starts with
next-receiving `HKA`, next-sending `NHKB` and that one-time private key. Initial
RAT4 authentication performs Bob's receive/root transition, then generates his
new sending DH pair only after the body authenticates. Successful future
next-receiving-header authentication similarly promotes the next roles and
derives new next header keys through the receive/send DH transitions.

Current sending/receiving and next sending/receiving header secrets are 32-byte
opaque resources. Bootstrap's absent chains use unreachable opaque placeholders
under `mesh-msg/v2/he-unstarted-sending` /
`mesh-msg/v2/he-unstarted-receiving`; no chain
operation is admitted before its header role exists. Header lookup tries current
receiving, next receiving, then retained old receiving keys. The skipped-key name
is `SHA256(ASCII("mesh-msg/v2/he-skipped") || R32 || u32(n))`.

Header secrecy advances by DH/header-key generation, **not per message**. The
current header key is reused with independent random nonces. A compromised active
or retained header key can expose captured headers from that generation. Old
header keys are retained only while eligible skipped message keys need them and
are removed when the final applicable skipped key is consumed or its generation
ages out. The existing **64 skipped-message** capacity and **five-generation**
aging policy are retained. Authentication failure discards tentative resources
instead of replacing the original state.

This is an initial hybrid handshake plus a classical X25519/header ratchet. It
does **not** complete a sparse post-quantum ratchet, establish post-compromise
security from new PQ ratchet contributions, or claim an independent audit.

## Snapshot compatibility

RST3 persists HE state (`RatchetState.version = 2`); legacy state version `1`
continues to seal as RST2. RST3 binds the suite, SID, monotone snapshot version,
public ratchet keys, counters, pending-send flag, receive generation, skipped-key
index and canonical header-role directory to its sealed components. There are
three initial or four established fixed header roles, plus bounded old roles,
with **3–9 canonical names**. Each header secret uses storage purpose `4` and a
role-specific object context incorporating the authenticated snapshot header and
role name. Context also binds account, device, SID and snapshot version. Swapping
roles, accounts, sessions, generations or versions is not a valid migration.

The computed RST3 maximum is **70,007 bytes**, under its **70,100-byte parser
ceiling**. RST1/2 retain the **68,900-byte read ceiling**. RST1 is read with its
historical missing aging/skipped-key state and rewritten through the existing
legacy RST2 path; it is not converted into HE by a format-byte change. RST3 is
not readable by old clients. A legacy-to-HE upgrade needs the fresh authenticated
handshake, with queued old-session state retained for format-specific reads.

Stored source guards compare the original sealed profile, index and relevant
session/prekey/history ciphertexts, including captured absence, before atomic
commit. Appending a newly discovered source cannot bless a changed earlier one.
The HE receive commit includes cursor removal in the same state/history write;
conflicts leave the message unacknowledged. These guards are storage concurrency
rules, not an additional wire version or broader plaintext-label coverage.

Erasure refers to current protocol state and opaque live resources. It does not
claim forensic erasure of old database/WAL pages, journals, backups or exported
sealed snapshots together with their applicable wrapping authority.

## Bounded private routing and acknowledgement

RAT4 has no clear SID or stable routing hint. The routing phase scans at most
**16 indexed sessions per call**, probing only HE states and their authenticated
header keys. Its conservative bound is **7 header-key attempts per candidate,
112 routing probes per batch**. Authentication/decryption of the selected message
is additional work; this is not a bound on all index loading, snapshot restoration,
policy, history, IO or total receive processing.

The **4,096 indexed-session ceiling is new HE writer/admission policy**, counting
existing indexed entries and any extra alias being created. It is not a receive
ceiling and does not delete old sessions. Larger existing indexes remain readable
through repeated 16-session scans. An HE initial admission over capacity fails;
queued legacy initial reads keep their original admission behavior.

A sealed local `header-routing/v1` record contains a u64 service tick and at most
**256 cursor rows**, each exactly **136 bytes**; its plaintext maximum is
**34,824 bytes**. Each row binds envelope ID16, SHA256(RAT packet bytes)32,
SHA256(original sealed profile)32, SHA256(exact sealed session index)32,
count/offset u32 each, and first/progress service ticks u64 each. Partial scans
persist only this work state. A changed packet/profile/index/count restarts from
offset zero while a retained same-ID row keeps its original lease.

Active cursors are not displaced by new arrivals. Reclamation applies at an idle
age of **65,536** service ticks or total age **1,048,576** ticks; these are service
calls, not milliseconds. Reclaiming a cursor neither deletes nor acknowledges its
envelope. Capacity, repeated index churn and mailbox traffic can delay progress;
this bounded policy is not a global availability guarantee.

`header_selection_pending`, `header_selection_capacity` and `account_state_changed`
are unfinished work in inbox classification: **no ACK, no failed-attempt increment
and no ordinary age-out**. The fetch cursor can pass set-aside messages to avoid
blocking later deliveries. On a complete no-match scan, `unknown_session` follows
the existing ordinary retry policy, which gives up only when both 16 failed tries
and 24 hours since the first ordinary try have elapsed. Malformed/permanently
rejected packets retain their own existing classification; an unfinished scan is
not reclassified as one merely because it has been retried many times.

## Format-specific legacy reads

- RCP remains version 1 / outer suite 4. It carries M8P initial kind 1, ratchet
  kind 2, or group packets after recipient opening.
- RAT3 is accepted only inside the recipient seal. RAT1/2 are accepted only
  on their historical bare transport. RAT4 is accepted only sealed; an HE state
  refuses legacy RAT messages instead of retrying a clear-header parser.
- INI1, historical SIP-wrapped initials and old session snapshots remain readable
  through their authenticated historical credential/bundle/prekey paths. An INI
  version must match the HE mode derived from those signed inputs; the receiver
  does not accept a version mismatch as an upgrade or downgrade. Bare initial
  packets remain refused.
- SGP/bare group legacy readers retain their own rules. This document does not
  apply direct-session HE to group headers or replace the group protocol.

Legacy queued metadata is not retroactively hidden. Retained protocol construction
APIs do not override latest mobile/CLI send admission or authorize fallback after
HE failure. Full release, physical-device coverage and independent security review
remain separate gates.

## Counter exhaustion

Development HE writers refuse when `sent_count` is already `2^32 - 1`.
The last valid message index is `2^32 - 2`; its committed next count is
`2^32 - 1`. A noncached receive of index `2^32 - 1` refuses before incrementing.
A next-DH receive also refuses when `receive_generation` is already `2^32 - 1`.
All use the existing `InvalidMessage` result and preserve the original owner.

Cached messages, current-chain messages at the final generation and authenticated
new-chain resets of an exhausted previous count remain supported. These guards
preserve the existing wire/snapshot/error formats. The counter-specific host
checks and legacy/hybrid compatibility checks pass; matching native and release
qualification remain separate.

## Implementation anchors

The normative code for this development profile is in
`packages/messenger-protocol/session/{header_wire,header_ratchet,header_store,handshake,ratchet,snapshot}.mpl`,
`protocol/handshake_wire.mpl`, `prekeys/renewal.mpl` and
`transport/{packet,recipient}.mpl`. Mobile admission/routing/persistence is in
`packages/mobile-core/mobile/{header_capabilities,header_routing,header_routing_state,header_admission,receive_sources,messages,inbox,inbox_state,sessions}.mpl`.
The guarded documentation delivery pins the exact joint-v2 source map and reused
C4 draft; it does not substitute its prose for those source/version checks.
