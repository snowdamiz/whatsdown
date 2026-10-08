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
identifier exists. It is valid when this digest has the envelope's number of
leading zero bits, four fewer than the configured difficulty (see
"Per-endpoint difficulty"):

```text
SHA-256(
  "mesh-msg/v1/anonymous-abuse-token" ||
  expires_at_ms ||
  work_nonce ||
  SHA-256(canonical_sealed_delivery)
)
```

The edge accepts a configured difficulty of 1..24 and an expiry between its
current clock and five minutes in the future. Deployments tune
`MESSENGER_ABUSE_DIFFICULTY`; the production default is 16 and acceptance
proofs use 8. Replaying the exact
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

The stamp is valid when this digest has its endpoint's number of leading zero
bits (see "Per-endpoint difficulty"). All integers are big-endian:

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
| `POST /v1/devices/resolve` | `mesh-msg/v1/work/resolve` | 80 (a version 2 lookup) |
| `POST /v1/prekeys/bundle` | `mesh-msg/v1/work/prekey-claim` | 100 |

The label makes work done for one endpoint worthless at another, the payload
hash ties it to one request, and the expiry stops it being stockpiled. The
directory accepts an expiry between its clock and five minutes ahead; clients
mint four minutes ahead, leaving a minute for a fast device clock. Every
endpoint's difficulty is a fixed step from the same `MESSENGER_ABUSE_DIFFICULTY`
the edge uses, which devices read from their signed native configuration, so
one setting governs both.

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

## Per-endpoint difficulty

The configured difficulty `d` (`MESSENGER_ABUSE_DIFFICULTY` on the directory and
the edge, line 3 of the signed native configuration on devices) is a base. Each
endpoint asks for a fixed step from it, clamped to 1..24:

| Endpoint | Label | Bits | At `d` = 16 |
|---|---|---|---:|
| Device registration | `mesh-msg/v1/work/register` | `d` | 16 |
| Device lookup | `mesh-msg/v1/work/resolve` | `d - 2` | 14 |
| Prekey claim | `mesh-msg/v1/work/prekey-claim` | `d - 2` | 14 |
| Envelope submission | `mesh-msg/v1/anonymous-abuse-token` | `d - 4` | 12 |

The steps live in the protocol code (`abuse_endpoint_difficulty` in
`Privacy.Edge`), and minting and checking both apply them, so devices, the
directory, the edge and the CLI agree whenever they agree on `d`, and the signed
configuration still pins a single number. Changing a step is a protocol change
that ships to devices and services together. No step is above the base, so a
directory or edge that knows the steps accepts every stamp an older build mints
at `d` everywhere; deploy the services first, then the builds that mint less.

The steps come from measuring the miner the phones run. A benchmark
(`tools/pow-bench`) calls `mint_request_stamp`, the function the mobile core
uses, and counts the attempts it makes (the digest is SHA-256 over 68 to 77 bytes).
Release builds (EAS, CI's Android archives, the desktop workflow) link the
release profile of the Mesh runtime and compile the core at optimization level
2; development builds (`./run.sh`, and `build-mobile-native.sh` or
`npm run native` without `--release`) link the debug runtime at level 0, and
the steps were first chosen from their numbers. Each column is the benchmark
built that way, on an Apple M4, both as a native macOS process and inside the
iOS 26.5 simulator (which runs on the same CPU), with the machine otherwise
under heavy load:

| Bits | Mean attempts | Release build | Development build |
|---:|---:|---:|---:|
| 8 | 256 | 0.2 ms | 4 ms |
| 10 | 1,024 | 0.6–1 ms | 15 ms |
| 12 | 4,096 | 3–4 ms | 60 ms |
| 14 | 16,384 | 10–16 ms | 0.25 s |
| 16 | 65,536 | 40–65 ms | 0.9–1.0 s |
| 18 | 262,144 | 0.16–0.26 s | 3.1–3.7 s |
| 20 | 1,048,576 | 0.65–1.05 s | 10–15 s |

A release build makes 1.0 to 1.7 million attempts a second, about 1.4 million
typically, and 0.6 million with the machine at its busiest; a development build
50,000 to 115,000. The runtime is most of the
difference: the release runtime with the core at level 0 still makes 0.95 to
1.3 million, the debug runtime with the core at level 2 only 75,000 to 140,000.
No Android device or emulator was available; an emulator on this Mac would run
on the same CPU anyway. Mid-range and older phones have single cores several
times slower, so budget for three to six times these times.

The default `d` = 16 was sized with development-build numbers: a release build
pays a fifteenth to a twentieth of those times, and `d` = 20 would restore them.
Devices mint at the `d` in their signed configuration, and a stamp with more
zero bits than asked meets the lower requirement, so raise `d` by shipping
builds that pin the new value before raising it on the directory and the edge.

A device sends an envelope for every recipient device, its own linked devices
and every receipt, so a message can cost several stamps: at 12 bits each is
about 3 ms here in a release build (60 ms in a development build). Lookups come with every contact added and device-set refresh,
retried while witnesses sign; prekey claims with every new session, one per
device. Registration happens once per device and at each renewal, so it keeps
the full base.

None of this stops a determined attacker. Native code does 4.5 million
SHA-256 digests of this size a second on one of the same cores (OpenSSL), about
three times the release miner (60 times the development one): at `d` = 16 that is a lookup for under 4 ms and an
envelope for under 1 ms, and a GPU is a thousand times faster again. Proof of
work paces abuse; the per-mailbox deposit limits and the stranger share bound
what envelopes can do to one person, the last-resort key what draining a prekey
pool can, and credits (`credits-v1.md`) are the paid path.

## Service boundary

The separation is real only when the edge and the delivery core are separate
deployments: the edge sees the source connection and must never hold the
delivery core's static private key; the delivery core holds that key and must
never see the source connection. The production build therefore deploys the
edge on its own with a single secret (its bearer credential, plus its client
certificate once one is configured), and the backend without any edge. A combined deployment, used for local development, provides
no such separation. One operator controlling both deployments, or the platform
terminating TLS for both, can still correlate them by timing; see the
[Cloudflare guide](../ops/cloudflare/README.md#separate-privacy-edge-deployment).

- Public mobile sends use the privacy edge `POST /v1/envelopes/batch`. A send
  may carry credits in a `CRD` frame beside or instead of the proof of work; the
  edge redeems them at the core first and then forwards `HLD(redemption, SED)`
  ([credits-v1.md](credits-v1.md)). `PRV` stays the free path. Longer storage
  (`POST /v1/mailbox/retention`, `CRD ‖ MRT`) goes the same way: redeemed at
  the core, then `HLD(redemption, MRT)` to `POST /internal/v1/mailbox/retention`.
  Credit quotes (`POST /v1/credits/quote`) carry a `PWR` stamp with the label
  `mesh-msg/v1/work/credit-quote` at the full base.
- Registration's difficulty rises with the sign-up rate, and 20 credits skip
  the rise ([credits-v1.md](credits-v1.md), "Priority sign-up"): a `429` for a
  registration carries `WRK` (the difficulty now), and
  `GET /v1/devices/register/work` answers it.
- The edge forwards only `SED` bytes and its bearer credential to delivery
  `POST /internal/v1/envelopes/sealed`, reached across deployments as the
  backend's `POST /v1/ingress/sealed`. No client-supplied header is forwarded.
- The edge is also the Oblivious HTTP relay ([ohttp-v1.md](ohttp-v1.md)): it
  takes `POST /v1/ohttp` (`message/ohttp-req`) and forwards the encapsulated
  bytes alone, with its bearer, to the core's gateway
  `POST /internal/v1/ohttp`, reached across deployments as the backend's
  `POST /v1/ingress/ohttp`. That route has the same guards as the sealed
  ingress (bearer, and the signature or client certificate below once pinned).
- The direct delivery `POST /v1/envelopes/batch` is absent by default. It is
  registered only when `MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled`; that
  compatibility flag is forbidden in production.
- The internal sealed route requires the privacy edge's exact
  `Authorization: Bearer` credential, compared in constant time by the backend
  Worker and again by the delivery core. `POST /v1/ingress/sealed` is publicly
  routable.
- The build can also require, beyond the bearer, a credential that only the
  edge deployment holds, in either or both of two forms. Each is enforced once
  the operator pins it on the backend. A request either form refuses answers
  `403` and never reaches the delivery core; only after both pass is the bearer
  checked (`401`).
  - An Ed25519 signature on every request, made with a key that exists only as
    the edge's Worker secret; the backend pins the public key
    ([Edge request signatures](#edge-request-signatures)).
  - A TLS client certificate (mTLS): the connection must present a certificate
    that the backend's zone verified, that isn't revoked, and that has a pinned
    SHA-256 fingerprint (and the pinned issuer, if one is set). Cloudflare
    currently refuses a Worker that presents a client certificate to a hostname
    Cloudflare serves, so this form can't be used while the edge and the backend
    both run as Cloudflare Workers.
- Pinning is a deployment step
  ([Cloudflare guide](../ops/cloudflare/README.md#sealed-ingress-edge-credential-22-m2))
  that hasn't been done. Until it is, the bearer credential is the route's only
  guard.
- Neither service logs request bodies, mailbox tokens, envelope IDs, token
  nonces, hashes, or shared request identifiers.

### Edge request signatures

The edge signs each request it sends to `POST /v1/ingress/sealed` (and to the
other ingress routes, `/v1/ingress/credits/redeem`,
`/v1/ingress/mailbox/retention` and `/v1/ingress/ohttp`, the same way, each
with its own path) with an
Ed25519 key (RFC 8032, pure Ed25519) held only by the edge deployment, as three
headers:

- `Morse-Ingress-Timestamp`: Unix time in seconds, decimal ASCII, no sign and
  no leading zeros.
- `Morse-Ingress-Nonce`: 16 fresh random bytes per request, as 32 lowercase hex
  digits.
- `Morse-Ingress-Signature`: the 64-byte signature as 128 lowercase hex digits.

The signed message is the UTF-8 bytes of seven fields joined by LF (`0x0A`),
with no trailing LF:

1. `morse-ingress-v1`
2. the method, `POST`
3. the request URL's host, lowercase, with `:port` only for a non-default port
4. the path, `/v1/ingress/sealed` (the query string isn't signed, and the route
   ignores it)
5. the timestamp, exactly as sent in its header
6. the nonce, exactly as sent in its header
7. SHA-256 of the exact body bytes, as 64 lowercase hex digits

For example, host `api.morse.test`, timestamp `1790000000`, nonce
`00112233445566778899aabbccddeeff` and body hash `H` sign
`morse-ingress-v1\nPOST\napi.morse.test\n/v1/ingress/sealed\n1790000000\n00112233445566778899aabbccddeeff\nH`.
Binding the host means a request signed for one backend (the canary, say) is
refused by another.

Once public keys are pinned (64 lowercase hex each, comma-separated while
rotating), the backend checks, in order, after the client certificate when
that is pinned too:

1. All three headers are present and well formed, else `403`.
2. The timestamp is within 60 seconds of the backend's clock, else `403`.
3. The signature verifies under one of the pinned keys over the message
   rebuilt from the request as received, else `403`.
4. The nonce hasn't been accepted before, else `403`. Accepted nonces are kept
   until their timestamp is 61 seconds old, past the window, and a nonce is
   recorded only after its signature verifies.
5. Then the bearer (`401`), then the delivery core, which receives the verified
   body without the signature headers.

A malformed pin or a missing nonce store answers `503`, and a body over 1 MiB
`413` (the delivery core's own limits are smaller). Keys rotate by pinning the
old and new public keys, switching the edge's key, then removing the old pin.

Oblivious HTTP ([ohttp-v1.md](ohttp-v1.md)) now carries the stateless
requests (lookups, prekey claims, transparency proofs, the credit issuer's
keys) and the signed mailbox fetch and acknowledgement through the edge, so the
backend sees the edge rather than the phone for them too. It does not replace
the long-lived mailbox stream, which stays a direct connection, nor this
sealed submission path, which already hides the sender's connection from the
core.
