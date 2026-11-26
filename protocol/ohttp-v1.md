# Oblivious HTTP v1

Status: development contract (plan §22 M3, decision D17). Oblivious HTTP
([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)) carries the requests a
phone makes that need no connection of their own to the backend: directory
lookups, prekey claims, transparency proofs, the credit issuer's keys, and the
device-signed mailbox fetch and acknowledgement. The privacy edge is the
**relay**, the directory-delivery core is the **gateway** and the target, so

- the backend sees the edge's connection, never the phone's address;
- the edge sees the phone's address and the size and timing of sealed bytes,
  never the request or the answer, which are encrypted end to end between the
  phone and the gateway.

Envelope submission keeps its own sealing ([sealed-delivery-v1.md](sealed-delivery-v1.md)).
The mailbox stream (`GET /v1/mailbox/stream`, a WebSocket) stays a direct
connection; see "What stays direct".

## Suite and key configuration

One HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) suite, the one
Mesh implements: `DHKEM(X25519, HKDF-SHA256)` (KEM `0x0020`), `HKDF-SHA256`
(KDF `0x0001`), `ChaCha20-Poly1305` (AEAD `0x0003`). RFC 9458 allows any
registered suite; this is a conforming choice, not a deviation.

The gateway's key configuration is RFC 9458 §3.1, with exactly one symmetric
pair (41 bytes):

```text
u8  key_id
u16 kem_id = 0x0020
32  X25519 public key
u16 length = 4
u16 kdf_id = 0x0001
u16 aead_id = 0x0003
```

`GET /v1/ohttp/keys` on the backend serves the configured keys as
`application/ohttp-keys` (§3.2: each configuration with a `u16` length), the
current key first. Phones never fetch it: they **pin** the key (below). The
route is for operators and the smoke check, to confirm that what builds pin is
what the gateway holds.

### Pinning

The key is pinned in the build's security config
([witness-network-v1.md](witness-network-v1.md), config v2) as an optional
last line after the minimum suite:

```text
<key configuration, 82 lowercase hex> <relay origin>
```

- The key configuration must decode as above and be canonical (re-encoding it
  gives the same bytes); a configuration that doesn't offer this suite is
  refused.
- The relay origin is the privacy edge: `https://` with no path, userinfo,
  query or fragment, or, for development builds, `http://` on `localhost`,
  `[::1]` or a loopback or private IPv4 address (with an optional port).
- Without the line the frame pins no gateway. A frame with the line has one
  more line than before; frames without it are unchanged, so every existing
  frame and its `set_id` stay the same.

Build variables (`apps/mobile/plugins/security-config.cjs`):
`MESSENGER_OHTTP_KEY` = `<key id 0-255>:<public key, 64 lowercase hex>` and
`MESSENGER_OHTTP_RELAY` = the edge origin, set together. Release builds
(mobile `check-release-config.mjs`, desktop `config.mjs`) require both, with
the relay equal to `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL`'s origin.

Pinning follows the plan's invariant that releases pin trust (I3): a
malicious edge or network can't hand a phone another key, and there is no
key-fetch request to fingerprint or to fail. A transparency-logged key
(like the credit issuer's) was the alternative; it adds a fetch, a proof and a
failure mode to every cold start for no gain while the gateway and the log are
the same operator's.

### Rotation

The gateway holds up to two keys, told apart by `key_id`:

| Variable | Holds |
|---|---|
| `MESSENGER_OHTTP_GATEWAY_KEY_ID`, `MESSENGER_OHTTP_GATEWAY_SEED_HEX` | the current key (id 0–255, X25519 private key as 64 hex) |
| `MESSENGER_OHTTP_GATEWAY_PREVIOUS_KEY_ID`, `MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX` | the key being retired |

Rotate by generating a key with a new id, moving the current pair to the
previous one, shipping builds that pin the new key, and deleting the previous
pair once no supported build pins it. Deleting a key is what gives requests
sent under it forward secrecy (RFC 9458 §6.6). The directory refuses to start
when a configured id's seed doesn't load; without a current id the gateway is
off and answers `503`.

## Messages

### Request (client)

RFC 9458 §4.3, unchanged:

```text
hdr         = key_id ‖ kem_id ‖ kdf_id ‖ aead_id        (7 bytes)
info        = "message/bhttp request" ‖ 0x00 ‖ hdr
enc, sctxt  = SetupBaseS(pkR, info)                     (a fresh context every request)
ct          = sctxt.Seal("", request)
enc_request = hdr ‖ enc ‖ ct
```

### Response (gateway)

RFC 9458 §4.4, unchanged, with `max(Nn, Nk) = 32`:

```text
secret         = context.Export("message/bhttp response", 32)
response_nonce = random(32)
prk            = Extract(enc ‖ response_nonce, secret)
key            = Expand(prk, "key", 32)
nonce          = Expand(prk, "nonce", 12)
enc_response   = response_nonce ‖ Seal(key, nonce, "", response)
```

### Inner messages

Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292)), known-length
form (`Privacy.Bhttp`):

- **Request:** framing `0`, method `GET` or `POST`, scheme `https`, an empty
  authority, the path with its query (for example
  `/v1/credits/issuer-keys?previous_tree_size=7`), no header fields, the body
  as content. No trailers.
- **Response:** framing `1`, the status, no header fields, the body as
  content. Informational responses before it are skipped when read.
- **Padding** (§3.8): requests are zero-padded to at least 256 bytes and a
  power of two; responses to at least 1 KiB, a power of two up to 64 KiB, then
  the next multiple of 64 KiB. So a lookup doesn't show the username's length
  to the edge, and a mailbox batch shows its size only in 64 KiB steps.
- **Limits:** a request is at most 64 KiB (the HPKE plaintext bound); a
  response at most 1 MiB (a full mailbox batch is 524,949 bytes, a lookup's
  evidence 570,274).
- Decoders refuse indeterminate-length framing, non-zero padding, a section
  running past the end, pseudo-fields and uppercase or non-token field names,
  and field values HTTP/2 calls malformed.

Media types: `message/ohttp-req` and `message/ohttp-res`.

## HTTP

| Hop | Request | Answer |
|---|---|---|
| Phone → edge | `POST {relay}/v1/ohttp`, `Content-Type: message/ohttp-req`, the encapsulated request | `200 message/ohttp-res` with the encapsulated response, or the gateway's bare status |
| Edge → backend (isolated) | `POST {backend}/v1/ingress/ohttp`: the same body, `Content-Type: message/ohttp-req`, the edge's bearer, and its request signature or client certificate once pinned ([sealed-delivery-v1.md](sealed-delivery-v1.md#edge-request-signatures)); no client header | as below |
| Backend → core | `POST /internal/v1/ohttp`, bearer checked again | `200` with `message/ohttp-res`; bare `400` (too short), `401`, `422` (unknown key id, another suite, or a ciphertext that doesn't open, RFC 9458 §6.4), `503` (no gateway key) |

The combined development Worker and a local stack (`./run.sh`) run the same
route through the in-process edge. The edge refuses a body shorter than
`7 + 32 + 16` or longer than `7 + 32 + 65,536 + 16` bytes (`400`) before
anything leaves it, and answers `502` when the backend doesn't.

Every answer the gateway gives after opening a request is encapsulated
(RFC 9458 §5.2): the route's own status and body, `404` for a route it doesn't
serve, `400` for a malformed inner message, and `409` for a replay. The
backend's status inside tells the phone what the direct route would have.

### Routes the gateway serves

Everything else is `404`, so the gateway can't be used to reach any other
resource (RFC 9458 §6.3):

| Inner request | Answered by | Guard kept |
|---|---|---|
| `POST /v1/devices/resolve` | the lookup | its `PWR` stamp, spent once |
| `POST /v1/prekeys/bundle` | the claim (`OTQ` 1 or 2) | its `PWR` stamp, spent once |
| `POST /v1/transparency/consistency` | `KTS` → `KTC` | public data |
| `POST /v1/transparency/leaf` | `KTP` → `KTL` | public data |
| `GET /v1/credits/issuer-keys?previous_tree_size=N` | the issuer-key listing | public data |
| `POST /v1/mailbox/fetch` | `FET` → `BAT` | the device signature and its freshness |
| `POST /v1/mailbox/ack` | `ACK` | the device signature and its freshness |

The direct routes stay for builds that predate this and for development
builds without a pinned gateway.

## Replays

The relay can replay an encapsulated request (RFC 9458 §6.5). The gateway
keeps a strike register of the `enc` of every request it opened in the last
ten to twenty minutes and answers a second one with an encapsulated `409`,
so a replayed mailbox fetch never returns the mailbox's current batch to be
sized. The register lives in the directory process's memory, bounded to
200,000 requests a window (past that it refuses, rather than grow), and a
restart forgets it; a signed fetch or acknowledgement stays valid at most six
minutes (five back, one ahead), inside the window. What a replay could still
do after a restart is bounded by each request's own guard: a stamped lookup or
claim is spent once, public data is public, and a fetch older than six minutes
is refused by its signature's freshness.

Clients send no `Date` field: the gateway doesn't use it (RFC 9458 §6.5.1 lets
a client with that knowledge omit it), which also keeps the phone's clock out
of the request (§6.8).

## Clients

- **Mobile core** (`Mobile.Oblivious`, `packages/messenger-ohttp`). For the
  requests the app makes, `mesh_messenger_oblivious_encapsulate` takes
  `vector(method) ‖ vector(path) ‖ vector(body)` and answers empty (no pinned
  gateway) or `vector(relay origin) ‖ vector(encapsulated request) ‖
  vector(sealed response key)`; `mesh_messenger_oblivious_decapsulate` takes
  `vector(sealed response key) ‖ vector(encapsulated response)` and answers
  `u16 status ‖ body`. The response key is `enc` and the exported secret sealed
  under the platform storage key (purpose `5`, label
  `ohttp-response-key/v1/<hex enc>`), so no key reaches TypeScript. The core's
  own requests (prekey claims, the issuer's keys) go through the relay in
  `oblivious_exchange`.
- **App** (`src/network.ts`): lookups, anchor and gossip consistency and leaf
  proofs, and the mailbox fetch and acknowledgement go through
  `obliviousRequest`. A development build without a pinned gateway sends them
  directly; a release build without one refuses (`oblivious_http_unconfigured`).
- **Desktop** (`src-tauri/src/request.rs`): allows `POST {pinned relay}/v1/ohttp`
  with `message/ohttp-req` and nothing else on that origin's path.
- **CLI** (`clients/mesh-cli`): with `MESSENGER_SECURITY_CONFIG` pinning a
  gateway, its lookups, claims, fetches and acknowledgements take the relay.

## What each party sees

| Party | Sees | Doesn't see |
|---|---|---|
| Edge (relay) | the phone's address and connection timing, the key id and suite, the padded size of each request and answer | the path, the body, the answer, the status inside |
| Backend (gateway and target) | the request and its answer, as the direct route would, and the edge's connection | the phone's address |
| Network observer | TLS to the edge | which route, which answer |

The two still correlate by timing if one operator runs both (see
[privacy-contract.md](privacy-contract.md#paths-and-correlation)). Sizes are
bucketed, not hidden: a mailbox batch of many envelopes still looks larger than
an empty one.

## What stays direct

- The mailbox stream: a long-lived WebSocket that tells the phone new mail has
  arrived. OHTTP has no long-lived exchange, and relaying the socket through
  the edge would hand the edge the mailbox's signed authorization beside the
  phone's address, which is exactly what the split keeps apart. While the app
  is in the foreground, the backend therefore still sees the phone's address
  with its mailbox on the stream.
- Registration, prekey publication, revocation, account deletion and leaving,
  push binding, the mailbox policy, and object uploads and downloads. They are
  device-signed or capability-bearing writes or large transfers, not the
  stateless reads this covers.
- Envelope submission, which already goes through the edge sealed.

## Mesh runtime

Mesh's HPKE was single-shot, with no exporter, and its AEAD took plaintexts of
at most 64 KiB, so OHTTP's response could not be built in Mesh. The runtime
gains four functions (development compiler until the next Mesh release):

- `Crypto.hpke_seal_export(public_key, info, aad, plaintext, exporter_context)`
  → `(enc ‖ ct, SecretBytes)` and `Crypto.hpke_open_export(private_key, info,
  aad, sealed, exporter_context)` → `(plaintext, SecretBytes)`: the base-mode
  seal and open, plus a 32-byte `Export` (RFC 9180 §5.3) from the same
  context. The runtime checks both against RFC 9180 A.2.1's exported values.
- `Crypto.hkdf_aead_seal(secret, salt, aad, plaintext)` and
  `Crypto.hkdf_aead_open(...)`: ChaCha20-Poly1305 under the key and nonce
  HKDF-SHA256 derives from the secret and salt with the labels `key` and
  `nonce`, for messages up to 1 MiB: RFC 9458 §4.4 steps 3–6. The nonce never
  leaves the runtime.

`packages/messenger-protocol` (`Privacy.Bhttp`, `Privacy.OhttpWire`) holds the
formats and builds with the published Mesh release; the encapsulation is
`packages/messenger-ohttp` (`Privacy.Ohttp`), which only the core, the
directory and the CLI link.

## Test vectors

RFC 9458 Appendix A uses AES-128-GCM, which Mesh doesn't have. An independent
HPKE and OHTTP in Node (`ops/cloudflare/ohttp.mjs`, OpenSSL) reproduces
RFC 9180 A.2.1 and RFC 9458 Appendix A exactly, then gives these answers for
the same keys and messages with ChaCha20-Poly1305, which the Mesh gateway and
client reproduce (`packages/messenger-ohttp/tests/ohttp.test.mpl`):

```text
gateway secret key     3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a
key configuration      01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003
ephemeral secret key   bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73
request (BHTTP)        00034745540568747470730b6578616d706c652e636f6d012f
encapsulated request   010020000100034b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472
                       c956d3d9bc7cb56a25766a5ad36c4d5c3f40480e331005e514b03bd29c38e1dc74753d6e1c310fdd7f
response nonce         c789e7151fcba46158ca84b04464910dc789e7151fcba46158ca84b04464910d
response (BHTTP)       0140c8
encapsulated response  c789e7151fcba46158ca84b04464910dc789e7151fcba46158ca84b04464910d
                       682d0cfaf89cd461faeca9b2451f504fc3d432
```

Binary HTTP is checked against RFC 9292's known-length examples (Figures 8
and 13).

## Deviations from the RFCs

None in any format on the wire. Narrowings: one suite; known-length Binary
HTTP only; inner header fields are neither sent nor used; no `Date` field (see
"Replays").
