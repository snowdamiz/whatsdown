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

## Stamped directory requests

Device registration, device lookup and prekey claim are anonymous. The backend
never sees a network address, because the Worker forwards no client headers,
and a limit keyed on the name being registered or looked up would let anyone
lock a victim out of their own name. These three requests therefore cost the
caller work instead. Signed requests (prekey publication, mailbox fetch and
acknowledgement, revocation, push binding) are already attributable to a device
and carry no stamp.

`StampedRequest` (`PWR`, at most the inner body plus 20 bytes):

```text
u8 version = 1
bytes[3] magic = "PWR"
u64 expires_at_ms
u32 work_nonce
vector inner_request
```

The stamp is valid when this digest has the configured number of leading zero
bits. All integers are big-endian:

```text
SHA-256(
  label ||
  expires_at_ms ||
  work_nonce ||
  SHA-256(inner_request)
)
```

| Endpoint | Label | Largest inner request |
|---|---|---:|
| `PUT /v1/devices/register` | `mesh-msg/v1/work/register` | 36,006 |
| `POST /v1/devices/resolve` | `mesh-msg/v1/work/resolve` | 76 |
| `POST /v1/prekeys/bundle` | `mesh-msg/v1/work/prekey-claim` | 100 |

The label makes work done for one endpoint worthless at another, the payload
hash ties it to one request, and the expiry stops it being stockpiled. The
directory accepts an expiry between its clock and five minutes ahead; clients
mint four minutes ahead, leaving a minute for a fast device clock. The
difficulty is the same `MESSENGER_ABUSE_DIFFICULTY` the edge uses, which devices
read from their signed native configuration, so one setting governs both.

Unlike a sealed delivery, replaying a lookup is not idempotent work for the
service: it is a free read. The directory therefore records each stamp's digest
as spent and admits it once. The work is checked before the database is
touched, so a caller who has done none cannot cause a write. A malformed frame
returns `400`; missing, insufficient, expired or spent work returns `429`, and
the client mints a fresh stamp. Spent stamps are purged after a day, long after
they expire.

This raises the cost of draining prekey pools, filling the transparency log and
scraping the directory; it does not make them impossible. A determined attacker
with hardware still gets through at the configured rate, which is why a drained
pool falls back to the last-resort prekey and a full log fails safe.

## Service boundary

The separation is real only when the edge and the delivery core are separate
deployments: the edge sees the source connection and must never hold the
delivery core's static private key; the delivery core holds that key and must
never see the source connection. The production build therefore deploys the
edge on its own with a single secret (its bearer credential), and the backend
without any edge. A combined deployment, used for local development, provides
no such separation. One operator controlling both deployments, or the platform
terminating TLS for both, can still correlate them by timing; see the
[Cloudflare guide](../ops/cloudflare/README.md#separate-privacy-edge-deployment).

- Public mobile sends use the privacy edge `POST /v1/envelopes/batch`.
- The edge forwards only `SED` bytes and its bearer credential to delivery
  `POST /internal/v1/envelopes/sealed`, reached across deployments as the
  backend's `POST /v1/ingress/sealed`. No client-supplied header is forwarded.
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
