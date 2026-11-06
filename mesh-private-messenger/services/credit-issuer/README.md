# Credit issuer

This Mesh service owns purchase quotes, finalized Solana payments, Lightning
hold-invoice settlement and blind issuance. Its PostgreSQL database contains no redemption nullifiers, mailboxes,
core hold IDs or user-account identifiers. Apply the SQL files in `migrations/` in lexical order to
its own database before starting the executable.

`GET /health` is unauthenticated. `POST /internal/v1/credits/quote` and
`POST /internal/v1/credits/issue` accept the canonical binary CQR/CIQ frames and
require the purchase bearer token. Success is HTTP 200 with signed CSQ/CIS; 425 means
payment is not finalized, 409 means an immutable purchase conflict, 400 rejects
malformed requests, and 503 means issuance or a dependency is unavailable.
Responses are binary and `Cache-Control: no-store`; errors have empty bodies.
The privacy edge exposes `/v1/credits/quote`, `/v1/credits/issue`, and
`/v1/credits/issuer`. It never forwards caller cookies, account/device identifiers
or IP headers to this service.

Optional Lightning routes use `/internal/v1/credits/lightning/{quote,issue}` and
the same purchase authority. Their public edge paths are
`/v1/credits/lightning/{quote,issue}`. They bind a signed BOLT11 invoice to the
ordered blind batch and release credits only after authenticated settlement.
See [Lightning operations](../../ops/credit-lightning/OPERATIONS.md) for the
separate configuration, durable recovery, local proof and remaining release gates.

Required configuration:

| Variable | Meaning |
| --- | --- |
| `MORSE_CREDITS_MODE` | `off` (default), `test`, or `live` |
| `MESSENGER_CREDITS_PURPOSE` | `test` or `live`; must match an enabled mode |
| `MESSENGER_ISSUER_DATABASE_URL` | Separate issuer PostgreSQL database |
| `MESSENGER_ISSUER_SECURITY_CONFIG` | Canonical v3+ native security configuration text, with RFC 6962 log and pinned service/witness policy |
| `MESSENGER_CREDIT_STORAGE_DIR` | Absolute private persistent directory for `StorageKey.file` |
| `MESSENGER_ISSUER_PORT` | HTTP port; default 18096 |
| `MESSENGER_CREDIT_USDC_MINT` | Operator-pinned SPL USDC mint in base58 |
| `MESSENGER_CREDIT_SOLANA_RPC_URL` | Finalized transaction/account RPC endpoint |
| `MESSENGER_CREDIT_SOL_PRICE_ACCOUNT` | Optional pinned Pyth SOL/USD account; SOL quotes refuse when absent |
| `MESSENGER_DELIVERY_INTERNAL_URL` | Directory core HTTPS origin for issuer publication/admission |
| `MESSENGER_CREDIT_ADMIN_TRANSPORT` | `direct` (default) for private core routes; `ingress` for the explicitly enabled backend Worker admission proxy |
| `MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN` | Core issuer-administration credential |
| `MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN` | Separate privacy-edge purchase credential |

Production URLs require HTTPS. Test mode additionally permits explicit
`http://127.0.0.1:port` or `http://localhost:port` endpoints. Security configuration
and mint/price-account pins are operator configuration, never request fields.
The edge needs the purchase token and `MESSENGER_CREDIT_ISSUER_INTERNAL_URL`; it
must not receive the issuer-administration credential.

The key worker generates one immutable RSA/Ed25519 key pair per 30-day epoch, seals it, announces
it to the core, obtains independently verified witnessed evidence, and admits
the key in both databases. A failed core admission leaves local quote issuance
disabled. The worker retries after witness lag and schedules the next epoch
after success. Current and previous keys remain verifiable; no key replacement
is inferred from an HTTP failure.

Quotes commit the client's ordered blinded batch before payment. Their CSQ
responses authenticate every CQT field with the separate Ed25519 quote key in
the witnessed v2 issuer leaf. A privacy edge cannot replace the deposit address.
Migration002 leaves old unsigned development keys/quotes intact but inactive;
it does not re-sign old quotes or change an existing witnessed epoch key. Retrying a
commitment returns the original deposit and expiry. Issuance verifies a signed
wire transaction and finalized RPC execution metadata before acquiring the
issuance row lock. It persists payment ownership and the entire blind-signature
response in one transaction. An exact issued retry returns that response even
after epoch expiry, during RPC outage, or with mode `off`; new quotes and new
issuance are disabled in that mode.

Persistent-host Compose and TLS examples are in
[`ops/credit-issuer`](../../ops/credit-issuer/README.md).

The public file storage backend requires a local filesystem, a 0700 directory
and 0600 key/lock files. Keep this directory outside database rollback/restore
procedures: restoring both an old wrapping key and its old counter is unsafe.
See [the public Mesh storage contract](../../../../mesh-lang/docs/security/storage-key-file.md).

SOL pricing reads the pinned account at finalized commitment. It checks the
current Pyth receiver owner `rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp`,
`PriceUpdateV2`, full verification and the SOL/USD feed ID, age at most 60
seconds, confidence at most 1%, and positive bounded price/slot fields. USD
micros are rounded down and payment lamports up using integer arithmetic.
Sources: [Pyth account ownership/freshness requirements](https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/solana),
[receiver layout](https://github.com/pyth-network/pyth-crosschain/blob/main/target_chains/solana/pyth_solana_receiver_sdk/src/price_update.rs),
and [current program IDs](https://github.com/pyth-network/pyth-crosschain/blob/main/target_chains/solana/pyth_solana_receiver_sdk/src/lib.rs).
The RPC chain view remains a trust assumption shared with payment verification.

The Cloudflare backend may explicitly enable
`MORSE_CREDIT_ISSUER_INGRESS=on`. With issuer transport `ingress`, the key worker
uses only `/v1/ingress/credits/issuers/{announce,evidence,admit,cursor}`. The
backend strips nonessential headers, bounds each body, and forwards to the
same core routes with the issuer-administration bearer. The core remains the
authentication authority. Neither this credential nor these routes are exposed
to the privacy-edge container.

Run `python3 scripts/prove-credit-issuer.py` from the product for isolated
PostgreSQL ledger/config/oracle tests, and the payment transport proof in
`payment/verify.test.mjs`. `python3 scripts/prove-credit-issuer-http.py` runs the
actual service, forced restart/recovery, failed-admission gate and real Solana
program execution fixtures. `bash scripts/prove-credits.sh` combines those with
the protocol, edge and central-redemption proofs. These are local implementation checks. Publishing
Mesh, independent crypto review, treasury conversion and live purchase/redemption
acceptance remain release prerequisites. The implemented refund/sweep custody
and local execution evidence are documented in
[treasury operations](../../ops/credit-treasury/OPERATIONS.md).
