# Cryptographic Profile A, Version 1

- Profile identifier: `mesh-msg/profile-a/v1`
- Protocol version: `1`
- Suite identifier: `0x0001`

> This is a development profile for the classical encrypted-envelope vertical
> slice. It has not received independent cryptographic review and must not be
> represented as independently audited. Release candidates require internal
> verification of the exact revision and applicable platform evidence.

## Primitive suite

| Purpose | Profile A selection |
|---|---|
| Hash | SHA-256; 32-byte binary digest |
| Message authentication | HMAC-SHA-256; 32-byte tag |
| Key derivation | HKDF-SHA-256 |
| Key agreement | X25519; 32-byte public keys and shared secrets |
| Device and account credentials | Ed25519; 32-byte public keys and 64-byte signatures |
| Authenticated encryption | ChaCha20-Poly1305; 32-byte key, 12-byte nonce, 16-byte tag |
| Randomness | Operating-system CSPRNG only |
| Initial establishment | Classical asynchronous signed-prekey handshake |
| Ongoing session | Double Ratchet; once both sides read it, with encrypted headers (ratchet message `4`, [`ratchet-message-v2.md`](ratchet-message-v2.md)) |

Private keys, root keys, chain keys, message keys, and HKDF/HMAC outputs use
secret or resource types. Ordinary `Bytes` is limited to public keys,
signatures, nonces, associated data, ciphertext, and public protocol fields.
Deterministic providers and secret revelation are test-build-only.

The all-zero X25519 shared result is invalid. AEAD key and nonce lengths are
checked exactly; nonce/key pairs are never reused. Authentication failure
returns no plaintext and leaves committed protocol state unchanged.

## Domain separation

The following ASCII labels are protocol constants and are included exactly in
their corresponding derivations:

```text
mesh-msg/v1/account-credential
mesh-msg/v1/device-credential
mesh-msg/v1/handshake
mesh-msg/v1/root-key
mesh-msg/v1/sending-chain
mesh-msg/v1/receiving-chain
mesh-msg/v1/message-key
mesh-msg/v1/initial-message
mesh-msg/v1/header-key
mesh-msg/v1/attachment-key
mesh-msg/v1/storage-wrap
mesh-msg/v1/transparency-leaf
```

Ratchet message version 4 ([`ratchet-message-v2.md`](ratchet-message-v2.md))
adds:

```text
mesh-msg/v2/root-mix
mesh-msg/v2/ratchet-root
mesh-msg/v2/ratchet-chain
mesh-msg/v2/header-key
mesh-msg/v2/header-key/upgrade/first
mesh-msg/v2/header-key/upgrade/second
mesh-msg/v2/header-seal
mesh-msg/v2/ratchet-header
mesh-msg/v2/ratchet-message
mesh-msg/v2/pq-ratchet-key
mesh-msg/v2/ratchet-snapshot-object/<slot>
```

These exact ASCII bytes are part of the published protocol. A label for one
purpose must never be reused for another purpose.

## Development limits

These limits are part of Profile A and are enforced before expensive work:

| Limit | Value |
|---|---:|
| Padded ciphertext bucket | At most 65,536 bytes |
| Padding buckets | 256, 512, 1,024, 2,048, 4,096, 8,192, 16,384, 32,768, 65,536 bytes |
| Skipped message keys per session | 64, shared by every receiving chain; newer keys push out the oldest |
| Skipped message key lifetime | Until its message arrives, or five further receiving chains have begun |
| Message-number jump | 64 within a chain; into a new chain, what is left of the previous chain and the position in the new one are at most 64 each and 64 together |
| Jump checked for a session reset | At most 16,384 positions ahead, derived without keeping any key |
| Messages sent again after a session reset | The newest 32 after the receiver's newest |
| Post-quantum ratchet | One ML-KEM-768 exchange in flight at a time; 32-byte units only in padding the message has anyway |
| Initial messages consuming one one-time prekey | 1 |
| Initial messages accepted through the reusable last-resort prekey | Unbounded; each transcript accepted once (newest 1,024 remembered) |
| Last-resort prekey lifetime | Replaced a week after it was made; the old secret is destroyed 35 days after the directory confirms the new key |
| Device credential and signed prekey lifetime | One year; renewed once fewer than 275 days remain, by a logged transition |
| ML-KEM-768 prekey lifetime | Replaced with every renewal of its device's credential |
| Replaced signed and ML-KEM prekeys | Kept until 35 days after the verified device set shows their successor; at most sixteen replaced bundles |

A mailbox delivers in the order it received, and a sender never lets one of its
envelopes overtake another for the same mailbox, so a gap comes only from an
envelope that was lost or that its sender gave up on (its mailbox refused it
for good, or it expired unsent after 30 days). A message more than 64 ahead
returns `ExcessiveJump` without changing session state, and that is final: the
receiver acknowledges the envelope unopened, because the messages in between
are never coming, and an envelope left unacknowledged is handed over again
ahead of everything behind it (`delivery-wire-v1.md`).

A device that stays offline until more than 64 consecutive messages from one
sender have expired finds that sender's next message too far ahead, and every
one after it. That session is healed by a **session reset**
([`session-reset-v1.md`](session-reset-v1.md)): once the far message proves
genuine (it opens under the key its position gives, derived without keeping
any key in between), the receiver asks the sender, in the direction that still
works, for a new session; the sender starts one with an ordinary handshake to a
one-time prekey the request carried, and sends again, in it, the newest 32 of
its messages the receiver is missing. Both sides show that the secure session
was reset. A peer that predates resets, and a gap over 16,384 messages, still
leave the session dark. The bound no longer follows from the mailbox's size,
which is now a byte budget that holds thousands of ordinary messages; see
`delivery-wire-v1.md`.

A key kept for a message that has not come is a key that whoever held the
message back could use after taking the device, so none is kept for ever. The
session state lists the keys it keeps, oldest first, with the number of
receiving chains it had seen when each was set aside (ratchet snapshot `2`
stores the list and the count in its authenticated header). A key is forgotten
when its message arrives, when the fifth receiving chain after its own begins,
or when 64 newer keys have pushed it out, whichever is first; a full set never
stops a session. Its message, if it comes after that, is refused for good.
There is no limit by the clock: a session that receives nothing forgets
nothing, and an envelope cannot outlive 31 days in a mailbox anyway. A
version `1` snapshot cannot say which keys it holds, so reading one leaves them
behind.

A device's credential, signed prekey and ML-KEM prekey are renewed together,
through the logged device set, ninety days into their one-year life
(`multi-device-wire-v1.md`, "Renewal"): the device holding the account key
renews itself, and a linked device asks it with a request signed by its own
key. The replaced secrets stay until no first message sealed to them can still
arrive, then are destroyed. A device that is not renewed in time (it stayed
away for nine months, or the device holding the account key never answered)
stops receiving new sessions when its credential runs out, without making the
rest of its account's device set fail to verify, and is renewed when it asks
again and is answered. Earlier revisions of this table stated 1,000-key
limits, a seven-day skipped-key policy, a two-session cap, and a seven-day
signed-prekey lifetime that the implementation never had; until renewal was
built, signed prekeys lived the credential's full year and credentials were
never renewed, so every account stopped verifying a year after it was made.

Content that does not fit the 64 KiB ciphertext bucket uses encrypted
attachments. Decoders also enforce canonical integer widths, bounded vectors
and nesting, no duplicate fields, no trailing bytes, and rejection of unknown
mandatory extensions. Exceeding a ratchet limit returns a typed error and
requires session recovery.

## Authenticated negotiation

Protocol version and suite identifier appear in canonical transcripts and AEAD
associated data. Credentials and prekey bundles advertise supported suites.
Devices remember the strongest suite previously observed for a remote device;
a lower suite then fails as a downgrade instead of silently falling back.
Unsupported higher suites fail explicitly.

## Encrypted headers and the post-quantum ratchet

A session between two current clients upgrades in place to ratchet message
version `4` ([`ratchet-message-v2.md`](ratchet-message-v2.md)) at its next
sending root step, negotiated by the session-features inner-envelope extension
(`3`) each side sends inside its authenticated messages:

- **Header encryption.** Session ID, ratchet key, counters and suite are sealed
  under header keys from the root chain (the Double Ratchet's
  header-encryption variant), so someone who later obtains a recipient's device
  identity key and opens the recipient seal of recorded envelopes learns no
  session, chain or position. A version 4 message names no session; the
  receiver finds it by the keys that open its header.
- **Sparse post-quantum ratchet** (suite `0x0002` sessions only). The sides take
  turns running ML-KEM-768 exchanges, carried in 32-byte units in the padding
  messages have anyway, and mix each secret into the root with that step's
  X25519 output. This gives post-compromise security against an attacker who
  can break X25519, once an epoch whose key was made after the compromise
  completes, provided the attacker stays passive. Breaking X25519 or ML-KEM
  alone recovers no key.

Ratchet snapshots are version `3`; versions 1 and 2 are read and rewritten.

## Deniable group sender authentication

Group messages of version `6` ([mls-groups-v1.md](mls-groups-v1.md#deniable-sender-authentication))
are signed with Ed25519, but not with the device's long-term signing key: each
sending device makes a fresh key pair per group epoch, at its first message
there, and gives the public key to every other member device inside their
pairwise Double Ratchet session (inner message type `9`, a 76-byte `GSA`
frame with no signature). The ratchet's message keys are symmetric, so the
announcement authenticates the key to the receiver and to no one else, and the
receiver, which also holds the epoch's group sender chains, could have made the
announcement, the key and the message itself. The signed input is that of
earlier versions (`mesh-mls/v1/group-message` with the version byte, header,
caller data and ciphertext); version `6` selects the announced key. The private
key is a `SigningPrivateKey` sealed under storage purpose `7` for one epoch.
Commits and welcomes remain signed with the long-term key. A device uses
version `6` only when every other member device advertised session feature `8`
over a session it can send on without a handshake; the first message of an
epoch fixes its mode, and a receiver holding a device's key for an epoch
refuses that device's long-term-signed messages there as a downgrade.

## Outside Profile A

Suite `0x0002` is the experimental hybrid Profile B defined in
[`hybrid-handshake-v1.md`](hybrid-handshake-v1.md). It is implemented for
interoperability and performance testing and is reachable in the application.
The security config's minimum session suite (config version 2) sets a floor for
new sessions: at `2`, no new session starts at suite `0x0001`, in either
direction, while existing classical sessions keep working until renewal moves
their devices to suite `0x0002`.
Release readiness uses the internal criteria in [SECURITY.md](../../SECURITY.md). Independent
cryptographic review has not been recorded and is not a release prerequisite.
