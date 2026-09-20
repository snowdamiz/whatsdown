# Recipient-sealed transport, version 1

Development protocol; release readiness requires internal verification of the
exact candidate. No independent cryptographic audit is claimed.

Every packet a client deposits is sealed to the recipient device, so the
delivery service and its database store one indistinguishable shape: a mailbox
address, a size bucket, an expiry, and opaque bytes. This supersedes the
per-kind wrappers of [client privacy revision 2](client-privacy-v2.md) (`SIP`)
and [group schedule revision 2](group-schedule-v2.md#recipient-transport)
(`SGP`), and closes the gap they left: direct ratchet packets travelled bare.

## What the bare format leaked

A version-1 or version-2 ratchet message carries its 32-byte session ID, ratchet
public key, and message counters in the clear inside `M8P`. Both peers of a
session use the same session ID, so anyone able to read envelopes for two
mailboxes could join them on it and recover who converses with whom, how often,
and in which direction, without decrypting anything. The outer suite (`1`, `2`,
`3`) and the wrapper magic additionally revealed whether an envelope started a
conversation, continued one, or belonged to a group.

## Format

```text
RecipientPacket ("RCP"):
  u8 version = 1
  bytes[3] magic = "RCP"
  bytes hpke_ciphertext          32-byte encapsulation || AEAD ciphertext

OuterEnvelope.suite = 4
```

The HPKE plaintext is the padded inner packet, exactly one of:

| Inner packet | First bytes | Meaning |
|---|---|---|
| `M8P` kind `1` | `01 4d 38 50 01` | Initial message with the initiator's account identity |
| `M8P` kind `2` | `01 4d 38 50 02` | Ratchet message |
| `GRP` | `01 47 52 50` | Group commit, welcome, or application message |

Sealing uses Mesh's RFC 9180 base-mode HPKE (X25519, HKDF-SHA256,
ChaCha20-Poly1305) to the recipient's account-signed X25519 device identity
key, with info `mesh-msg/v1/recipient-packet` and the recipient's 32-byte public
key as associated data. The label is distinct from `mesh-msg/v1/recipient-initial`
and `mesh-msg/v1/recipient-group`, so a packet cannot be moved between the
legacy and current wrappers.

Before sealing, the inner packet becomes `length:u32be || packet || zeroes`,
padded so the complete `RCP` packet is the smallest of 256, 512, 1,024, 2,048,
4,096, 8,192, 16,384, 32,768, or 65,536 bytes. Transport overhead is 52 bytes
(4 header, 32 encapsulation, 16 tag); the inner packet is at most 65,480 bytes.
Receivers verify the length, the minimal bucket, and all-zero padding.

Outer suite `4` names the transport only. The protocol suite stays inside the
seal, where the handshake transcript and the ratchet associated data already
authenticate it. A suite-`4` envelope whose body is not an `RCP` packet, and an
`RCP` packet under any other suite, are rejected as `invalid_recipient_packet`:
neither is reinterpreted.

## Ratchet message version 3

A ratchet message inside the seal is version `3`: identical to version `2`
except that its plaintext carries no padding of its own, because the transport
pads the whole packet. Padding twice would double every message's bucket. The
version is part of the authenticated associated data, and the transport binding
is enforced: version `3` is accepted only from a sealed envelope, and versions
`1` and `2` only from a bare one. Maximum plaintext is 65,357 bytes.

Group application messages inside the seal keep version `4`, which already
omits inner padding.

## What delivery still sees

The destination mailbox address, arrival time, size bucket, expiry, and the
source connection of whoever deposits or fetches. Initial packets (which carry
a credential and, for hybrid sessions, an ML-KEM ciphertext) and group welcomes
occupy larger buckets than short ratchet messages; the bucket is the only
remaining signal of packet kind. This transport does not provide sender
anonymity against a global observer, and it does not hide that two mailboxes
receive traffic at correlated times.

The seal uses a long-lived classical key. It claims neither forward secrecy nor
post-quantum protection for the *metadata* it hides: later compromise of a
recipient's device identity key exposes the headers of envelopes captured
earlier. Message content is governed by the inner handshake and ratchet, not by
this layer. Signal's sealed sender has the same property.

## Compatibility

New sends are always sealed. Receivers still read, for envelopes queued before
the sender upgraded: bare `M8P` ratchet packets at versions `1`-`2` under outer
suites `1`-`2`, `SIP`-wrapped initial packets, and `SGP`-wrapped or bare group
packets under outer suite `3`. Their exposed metadata is not retroactively
hidden. A bare initial packet is never accepted. Clients that predate this
transport cannot open sealed envelopes; update mobile, desktop, and CLI
together. Migration `012` admits outer suite `4` in the delivery database.

`recipient_transport.test.mpl` reproduces the leak on a bare packet and shows
the sealed packet contains neither the session ID nor the ratchet key, that
resealing shares no bytes, that the kind is readable only after opening, and
that the transport binding rejects a moved message. `cli_mobile.test.mpl`
asserts the shared session ID appears in neither direction of a live exchange.
