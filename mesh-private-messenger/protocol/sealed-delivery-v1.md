# Sealed delivery v1

Sealed delivery separates the source connection from the mailbox capability.
The mobile core encrypts a canonical `OuterEnvelope` to the delivery core's
pinned static X25519 public key. The privacy edge validates anonymous work and
forwards the sealed record without learning the mailbox token, envelope ID,
expiry, or ciphertext.

## Cryptography

For every submission the sender generates an ephemeral X25519 key pair and a
random 12-byte nonce. The shared secret is passed to HKDF-SHA256 with:

- salt: `SHA-256("mesh-msg/v1/sealed-delivery-salt")`
- info: `"mesh-msg/v1/sealed-delivery" || ephemeral_public_key || delivery_public_key`
- output length: 32 bytes

ChaCha20-Poly1305 seals the exact canonical outer-envelope bytes. The HKDF info
is also the AEAD associated data. The delivery core rejects authentication
failure and noncanonical plaintext.

## Canonical records

All integers are unsigned big-endian and vectors have a `u32` byte length.

`SealedDelivery` (`SED`, maximum 65,674 bytes):

```text
u8 version = 1
bytes[3] magic = "SED"
bytes[32] ephemeral_public_key
bytes[12] nonce
vector ciphertext (16..65,622 bytes)
```

`PrivacySubmission` (`PRV`, maximum 65,694 bytes):

```text
u8 version = 1
bytes[3] magic = "PRV"
u64 expires_at_ms
u32 work_nonce
vector canonical_sealed_delivery
```

The anonymous abuse proof is locally mined; no issuance account or stable
identifier exists. It is valid when this digest has the configured number of
leading zero bits:

```text
SHA-256(
  "mesh-msg/v1/anonymous-abuse-token" ||
  expires_at_ms ||
  work_nonce ||
  SHA-256(canonical_sealed_delivery)
)
```

The edge accepts difficulty 1..24 and an expiry between its current clock and
five minutes in the future. Deployments tune `MESSENGER_ABUSE_DIFFICULTY`; the
production default is 16 and acceptance proofs use 8. Replaying the exact
proof can only replay the exact envelope, whose mailbox/envelope key is
idempotent. Add a short-lived edge replay cache if measured replay traffic
becomes material.

## Service boundary

- Public mobile sends use the privacy edge `POST /v1/envelopes/batch`.
- The edge forwards only `SED` bytes to delivery
  `POST /internal/v1/envelopes/sealed`.
- The direct delivery `POST /v1/envelopes/batch` is absent by default. It is
  registered only when `MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled`; that
  compatibility flag is forbidden in production.
- The internal sealed route requires the privacy edge's exact
  `Authorization: Bearer` credential, compared in constant time, in addition
  to network policy restricting the route to the edge.
- Neither service logs request bodies, mailbox tokens, envelope IDs, token
  nonces, hashes, or shared request identifiers.

OHTTP is not used for persistent message delivery because it does not replace a
long-lived connection. It remains a future option for stateless directory,
prekey, transparency-proof, or token-redemption requests.
