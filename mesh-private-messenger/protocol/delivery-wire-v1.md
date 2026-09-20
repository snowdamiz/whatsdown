# Delivery wire v1

The M8 directory and delivery APIs use canonical binary bodies. All records
begin with version `1` and a three-byte magic value; integers are unsigned and
big-endian, and vectors use a `u32` byte length.

| Record | Magic | Fields | Maximum |
|---|---|---|---:|
| Directory lookup | `DLK` | username vector | 72 bytes |
| Directory entry | `DRE` | username, account identity, prekey bundle, 32-byte mailbox token | 36,006 bytes |
| Mailbox fetch | `FET` (version `2`) | 32-byte mailbox address hash, `u64` cursor, `u64` issued-at ms, 64-byte signature | 116 bytes |
| Delivery batch | `BAT` | `u8` count, then `u64` sequence and envelope vector | 524,949 bytes |
| Mailbox acknowledgement | `ACK` (version `2`) | 32-byte mailbox address hash, `u64` issued-at ms, `u8` count, 16-byte envelope IDs, 64-byte signature | 237 bytes |

## Envelope lifetime

A mailbox holds at most 64 envelopes and anyone may deposit into it. Delivery
therefore refuses (`400`) an envelope that is already expired or that expires
more than 31 days ahead: a client's own 30-day lifetime plus a day of clock
skew. An envelope that never expired would otherwise hold its slot until the
owner next came online, letting any sender keep an offline device's mailbox
full. With the bound, a full mailbox always drains by itself.

## Mailbox authorization

The 32-byte mailbox token in a directory entry is a public **address**. Anyone
who resolves a device can read it, and it authorizes exactly one thing:
depositing an envelope. It never authorizes reading, subscribing to, or
acknowledging a mailbox.

Fetch, stream, and acknowledgement are version-2 statements signed with the
Ed25519 device signing key whose public half is bound into the account-signed
device credential registered for that mailbox. They name the mailbox by
`SHA-256(mailbox token)`. The signed bytes are the exact ASCII label followed
by the frame without its signature:

```text
"mesh-msg/v2/mailbox-fetch" || u8(2) || "FET" || hash[32] || u64(cursor) || u64(issued_at_ms)
"mesh-msg/v2/mailbox-ack"   || u8(2) || "ACK" || hash[32] || u64(issued_at_ms) || u8(count) || ids
```

The delivery service accepts a request only when the signature verifies under
the key of the one active, unrevoked device that owns the mailbox and
`issued_at_ms` is at most 300,000 ms old and at most 60,000 ms ahead of its
clock. This is the same freshness rule clients apply to transparency
checkpoints. Freshness is checked before the database is consulted. Every
authorization failure (unknown, inactive, or revoked mailbox; stale or
premature timestamp; wrong key) returns `403` with no body, so responses do not
reveal which mailboxes exist. A malformed or version-1 frame returns `400`.

The mailbox stream is authorized by the same signed `FET` frame, hex-encoded in
`Authorization: MeshMailbox <232 hex characters>`. A fetch frame is never
accepted as an acknowledgement: the two labels are distinct.

A request captured inside its five-minute window can be replayed only by a
party already inside the TLS session, which can read the mailbox ciphertext
regardless. A replayed acknowledgement re-acknowledges the same envelope IDs
and is idempotent. No server-side nonce cache is therefore kept.

Version-1 `FET` and `ACK` frames carried the raw mailbox token as a bearer
credential. They are rejected as `UnsupportedVersion`; there is no fallback.
The unauthenticated single-device directory (`/v1/directory/register`,
`/v1/directory/resolve`, table `messenger_directory`) is removed; migration
`011` deletes it together with mailboxes that no signed device owns.

CLI and mobile direct messages share the canonical `M8P` client transport
record inside `OuterEnvelope.ciphertext`. It contains byte version `1`, magic
`M8P`, a byte kind, an account-identity vector, and a message vector. Kind `1`
is an initial message and requires a non-empty account identity; kind `2` is a
ratchet message and requires an empty account-identity vector. Both clients
reject truncation, trailing bytes, wrong kind/account combinations, and inputs
over 65,536 bytes. Ratchet encryption binds to the shared session-ID-derived
AAD domain `mesh-msg/mobile/ratchet-aad/v1`.

Directory usernames are 1–64 lowercase ASCII letters, digits, dots,
underscores, or hyphens. Fetch and acknowledgement batches contain at most
eight envelopes. Every delivered envelope is decoded as a canonical
`OuterEnvelope` before it is accepted. Decoders reject unsupported versions,
wrong magic, invalid lengths, oversized input, truncation, and trailing bytes.
The server-visible `u16` suite is `4` for every new envelope: the
[recipient-sealed transport](recipient-transport-v1.md), which hides the
protocol suite and the packet kind. Legacy envelopes used `1` for classical
direct messages, `2` for hybrid direct messages, and `3` for group packets.

For direct suites 1 and 2, mobile batch processing acknowledges an envelope
only after it was durably applied or classified as a permanent rejection.
Permanent rejections are malformed or mismatched direct protocol records,
peer authentication, ratchet replay, invalid peer-controlled profile or sync data,
replay of a consumed one-time prekey, and a message rejected by persisted
blocking policy. Local profile, key-store, database, session, history,
cryptographic-provider failures, and potentially later-applicable ratchet gaps
are retryable; every unrecognized error is retryable by default.

Suite 3 follows the same durable-apply/permanent-rejection rule. For example, a
future-epoch group message remains retryable until its commit arrives. Mobile
batch processing returns empty bytes instead of an `ACK` when every decodable
envelope is retryable, and the client must skip the acknowledgement request in
that case. A mixed batch contains only the IDs that were durably applied or
classified as permanent poison; retryable IDs remain absent for redelivery.
An undecodable outer envelope has no trusted acknowledgement ID and is not
acknowledged.
