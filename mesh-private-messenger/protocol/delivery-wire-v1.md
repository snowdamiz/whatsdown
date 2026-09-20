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

## Mailbox capacity and envelope lifetime

A mailbox is the queue of envelopes waiting for one device. Its address is
public and deposits are anonymous, so it must be bounded or anyone could make
the service keep unlimited data for a device. The bound is on what that costs:
at most **4 MiB** of waiting envelopes, each counted as its padding bucket, and
at most 4,096 of them. Sixty-four envelopes of the largest size fill it; an
ordinary message is a few hundred bytes, so a device that is switched off holds
thousands of them. It used to be a flat 64 envelopes, which a day offline in a
busy group reached. A full mailbox, or one being sent to too fast, answers
`429`; a revoked one, or an address nothing is registered under, answers `410`.
Envelopes sent to a device's public address may use three quarters of the
mailbox; the rest is kept for its [contact address](contact-address-v1.md).

Delivery refuses (`400`) an envelope that is already expired or that expires
more than 31 days ahead: a client's own 30-day lifetime plus a day of clock
skew. An envelope that never expired would otherwise hold its space until the
owner next came online, letting any sender keep an offline device's mailbox
full. With the bound, a full mailbox always drains by itself.

## What a sender does with each answer

A client sends its queued envelopes in the order it queued them, and never lets
one overtake another for the same mailbox.

| Answer | Meaning | The client |
|---|---|---|
| `202`, `200` | Accepted, or already held | removes the envelope; its message counts as having reached that device |
| `410` | That mailbox was revoked, or nothing is registered under that address | removes it, counts it against its message, and stops using the address if it was a contact address: nothing sent there can ever arrive |
| `400`, and the envelope's own expiry has passed | It waited more than 30 days | the same |
| `429` | That mailbox cannot take it now | leaves it, and everything queued behind it for that mailbox, and carries on with other mailboxes |
| any other `400`, `5xx`, `502`, no connection | Not about this envelope | stops and retries later, discarding nothing |

An unexplained `400` stops everything rather than discarding, because it may
mean the service refuses whatever this build or this clock produces, and
discarding on that would empty the outbox for good.

## What a receiver does with what it cannot open

A fetch returns the eight oldest unacknowledged envelopes after a position, and
a device acknowledges an envelope once it is durably applied or rejected for
good. One it cannot open *yet*, because what it depends on has not arrived, is
left unacknowledged. Left at that, eight such envelopes at the head of a
mailbox would be all the device ever received until they expired, and anyone
can send them. So:

- A pass asks past what it has set aside. After a batch in which something was
  set aside, the next fetch starts after that batch's highest sequence; the
  empty batch that ends a pass starts the next pass from the beginning, so
  whatever was set aside is tried again then.
- An envelope is not set aside for ever. It is acknowledged unopened once it
  has been tried sixteen times and the first of those tries is a day old. Both,
  because what stops it being opened may be the device's own trouble, a full
  disk or a directory it cannot reach, and sixteen tries can go by in a minute;
  a message is not lost to that. Nothing waits behind it meanwhile, and the
  mailbox drops it within 31 days whatever the device does.
- A failure that cannot change is final at once: a message numbered more than
  64 ahead, a replay, a message that fails authentication, a malformed packet.

A pass that set anything aside reports that processing is pending, after taking
everything it could, so the caller comes back later.

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
