# OHTTP gateway and relay

Development implementation; the feature defaults off. Host tests exercise the
Mesh relay and gateway with real encrypted requests. Matching native artifacts,
independent ingress enforcement and production activation remain separate gates.
The current Cloudflare outbound mTLS limitation in [INGRESS_MTLS.md](INGRESS_MTLS.md)
still applies. No production cutover is claimed.

## Route and configuration

Only the isolated edge/backend topology exposes these Worker routes:

1. The client posts `message/ohttp-req` to the edge's `/v1/ohttp`.
2. The Mesh edge forwards the opaque bytes to
   `http://delivery.internal/internal/v1/ohttp` using its own configured bearer.
3. The edge's outbound Worker maps that fixed target to the core's
   `/v1/ingress/ohttp`. The backend applies the same certificate gate as sealed
   ingress and sends the request to the Mesh core's `/internal/v1/ohttp`.
4. The core authenticates the internal bearer, decrypts the request, admits only
   the fixed supported inner operations and encrypts the response.

The edge sees source connections, ciphertext sizes and timing. The core sees
the admitted lookup/prekey request and the edge connection. Neither operator
independence nor resistance to timing correlation follows from local tests.

| Setting | Owner and meaning |
| --- | --- |
| `MORSE_OHTTP` | Explicit `on` on both deployments to enable routes; unset or `off` disables them. Other values refuse build/startup validation. |
| `MESSENGER_OHTTP_CORE_ORIGIN` | Core only: exact canonical HTTPS origin authorized inside encrypted requests, with no trailing slash/path/query. |
| `MESSENGER_OHTTP_KEY_CONFIG_HEX` | Core public configuration: lowercase hex of the canonical RFC 9458 key collection, one or two distinct key IDs. The current profile is X25519/HKDF-SHA256/ChaCha20-Poly1305. |
| `MESSENGER_OHTTP_PRIVATE_KEY_0_HEX` | Core deployment secret: 32-byte X25519 seed encoded as 64 hex characters, matching the first public key record. |
| `MESSENGER_OHTTP_PRIVATE_KEY_1_HEX` | Core deployment secret: matching seed for the second public record when present. |
| `MESSENGER_DELIVERY_INTERNAL_TOKEN` | Existing coordinated edge/core credential; caller authorization is never its source. |
| `MORSE_DELIVERY_URL` | Edge Worker only: fixed external core HTTPS origin, subject to ingress topology checks. |

Public pins are persisted in the backend build configuration. Private seeds must
be provisioned through the core's deployment secret store. The edge environment
allowlist excludes both seeds and the public gateway configuration. The Mesh
core loads seeds through `Env.get_secret_hex` into protected key handles and
checks every advertised public/private pair before starting, including an unused
second slot. Request selection is by the exact configured key ID; a failed
decryption does not try another key.

The client has a separate bounded, release-pinned OHTTP configuration bound to
its exact network and security parent frames. Enabling server routes does not
update or activate those client pins. Required-mode native source refuses direct
fallback. Explicit off mode retains the existing direct path.

## Rotation and limits

During rotation, configure both old and new public key records and their matching
seeds. Slot numbers follow collection order; moving a public record requires
moving its seed with it. Keep the old record while supported, unexpired client
pins can still select it. Distribute and qualify new client pins before removing
the old record. Removal makes the old ID fail with an empty outer `400`; it never
silently selects another key. No rotation or client rollout has been performed.

Outer requests are bounded to 55 bytes through 1 MiB; encrypted responses to
48 bytes through 1 MiB. Request/response media types are exact, compressed bodies
and redirects are refused, and responses carry `Cache-Control: no-store`. Caller
cookies, identity, forwarding and trace headers are discarded. Outer errors have
empty bodies; successful outer responses contain only ciphertext. Fixed inner
errors stay encrypted, including an unavailable versioned transparency log.
The Mesh HTTP server refuses bodies above 1 MiB before handler dispatch; the
Worker boundary returns `413` for that limit.

The Mesh relay's local test-only `MESSENGER_OHTTP_DEVELOPMENT=on` permits a
canonical loopback HTTP target. Cloudflare does not pass this setting to its
containers. The combined `npm run dev` Worker does not expose OHTTP routes; use
the separate Mesh services for a loopback integration fixture. Mailbox, object,
push and other non-allowlisted operations are outside this gateway.
