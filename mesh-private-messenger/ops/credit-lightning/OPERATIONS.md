# Lightning credit issuer

Status: local implementation and regtest evidence. This is not a production
activation or a completed Phase 4b exit. New purchases default off.

The Mesh issuer uses LND hold invoices, one invoice per committed blind batch.
A payment hash and an opaque `HashPreimage` sealed under the issuer storage key
are committed before creating the invoice. Retries look up that same hash.
The signed quote binds the complete verified BOLT11 invoice, network, node,
amount, expiry, issuer key and ordered blind batch. The native client must
verify the witnessed quote key before handing an invoice to a wallet.

For an accepted payment, the issuer verifies the fixed amount and the exact
one-percent tolerance. It commits the exact blind response and its Ed25519
integrity signature before restoring and revealing the preimage. Only an
authenticated `SETTLED` lookup commits revenue and releases the saved response.
A successful settle POST alone is insufficient. Invalid held amounts are
canceled before collection. An unexpected already-settled mismatch requires
operator reconciliation and cannot issue credits.

## Configuration

Keep the ordinary issuer database, storage directory, RFC6962 security pins,
purchase credential and admission worker configured. Migration `007_lightning`
adds an independent invoice ledger; `008_lightning_recovery` adds bounded retry
leases; `009_lightning_cancellation` stores authenticated terminal certificates.
Do not put nullifiers or account/device IDs in this ledger.

| Variable | Meaning |
| --- | --- |
| `MORSE_LIGHTNING_MODE` | `off` by default; `test` or `live` must match the issuer purpose |
| `MESSENGER_CREDIT_LIGHTNING_ORIGIN` | Exact LND REST origin; HTTPS in live mode; explicit `http://127.0.0.1:port` allowed only in test mode |
| `MESSENGER_CREDIT_LIGHTNING_NETWORK` | `mainnet` in live mode; `testnet`, `regtest`, `signet` or `simnet` in test mode |
| `MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY` | Pinned compressed 33-byte node public key, hex |
| `MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX` | Restricted LND credential, lowercase hex; supply through the deployment's secret environment |
| `MESSENGER_CREDIT_BTC_PRICE_ACCOUNT` | Pinned Solana Pyth PriceUpdateV2 account for BTC/USD |
| `MESSENGER_CREDIT_SOLANA_RPC_URL` | Existing finalized-account RPC, also used for the pinned BTC price |

Use a dedicated restricted credential permitting only GetInfo, LookupInvoice,
AddHoldInvoice, SettleInvoice and CancelInvoice. The test harness uses an admin
macaroon only inside its disposable regtest node. Production must not use that
fixture credential pattern. LND's TLS certificate must validate through the
runtime's trusted roots, directly or through the operator's trusted TLS ingress.
Redirects are disabled. The backend's returned identity and Bitcoin network
must match the configured pins on each operation.

The BTC feed is
`e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43`.
The common Pyth reader verifies receiver owner, discriminator, Full verification,
feed, slot, positive integer price, at most 60 seconds of age, and at most one
percent confidence. Quote arithmetic uses integer USD micros and millisatoshis,
rounding the requested payment up. Updating a quote never changes its price.

## Routes and recovery

The authenticated issuer routes are
`POST /internal/v1/credits/lightning/quote` and
`POST /internal/v1/credits/lightning/issue`. Their public privacy-edge counterparts
are `/v1/credits/lightning/quote` and `/v1/credits/lightning/issue`. They carry
binary protocol messages and return no internal diagnostics or upstream headers.
The edge carries its separate purchase credential; it forwards no caller cookies,
account IDs or IP metadata.

Invoice records use states 0 reserved, 1 invoice ready, 2 response prepared,
3 settled and issued, 4 canceled, and 5 reserved for blocked reconciliation.
State 2 is not a successful purchase. Keep the database, sealed preimages,
issuer storage key and LND node together through backup/recovery. Replacing a
backend origin, node, network or service identity for an existing record fails
closed. Rotating the restricted macaroon does not change its backend identity.

A fresh authenticated `CANCELED` lookup commits a signed `LCN` response and
state4 atomically. It is bound to the original quote, payment hash, batch and
witnessed issuer key. Cached certificates are verified before replay; legacy
canceled rows without certificates require another authenticated node lookup.
The native journal retires the pending blind batch only after verifying this
certificate. It saves the canceled purchase in local history without adding
credits and permits a fresh purchase. Expiry or an unsigned HTTP error cannot
release the pending purchase. See [the wire contract](../../protocol/credits-lightning-v1.md).

Completed responses remain replayable when new purchases are disabled and after
quote expiry. The original batch cannot be replaced. A cross-rail retry cannot
create both a Solana quote and a Lightning invoice for one issuer/batch binding.

The recovery worker starts immediately and runs every 30 seconds, claiming at
most eight prepared records with 60-second retry leases. It reauthenticates the
saved response before any preimage disclosure. It completes accepted or settled
payments without another client request, including with `MORSE_CREDITS_MODE=off`.
Keep `MORSE_LIGHTNING_MODE` configured to retain this recovery service. A backend
outage or corrupt saved record is retried without holding a database transaction
across network calls; other due records can advance on subsequent cycles.

Revenue is recorded as actual BTC millisatoshis. No USDC funding receipt is
created by this path. BTC sweeping/conversion and final rewards funding need a
separate custody and reconciliation implementation before production use.

## Local verification and remaining work

The native app pins `MESSENGER_CREDIT_PURPOSE`,
`MESSENGER_CREDIT_ISSUER_ORIGIN`, RFC6962 security resources and optionally
`MESSENGER_CREDIT_LIGHTNING_NETWORK` at build time. An absent Lightning pin
hides that payment option. JavaScript cannot select its network or issuer URL.
Discovery, purchase, retention, signup and reconciliation HTTP now run in Mesh;
the UI supplies a local journal identity and typed action. Native wallet launch
checks the saved signed quote and commits the Lightning claim before returning
the invoice to the platform launcher. A failed launch preserves that claim.

`python3 scripts/prove-credit-lightning.py` owns disposable Bitcoin Core, two LND
nodes, a private channel, PostgreSQL, native Mesh client and production HTTP issuer.
Set `BITCOIND` and `LND` to verified test binaries, or provide the tools directory
used by `scripts/lightning_regtest.py`. No live funds or existing node is used.
The Pyth-account response is an explicit local RPC fixture, not guardian proof.

The current proof covers normal payment, lost creation and settlement replies,
server restarts, exact response replay, automatic recovery with new purchases
disabled, rollback before preimage disclosure, and a tampered prepared-response
signature that prevents settlement until the authentic saved data is restored.
Four paid cases finalize and verify 400 blind credits. A fifth canceled-invoice
case verifies cancellation-commit rollback, disabled-purchase recovery, exact
certificate replay without another node lookup, corrupt-certificate refusal and
legacy canceled-row reconciliation. It creates no credits or revenue.
With `MORSE_LIGHTNING_IOS_PROOF=1`, an additional owned iOS Simulator app drives
the compiled production journal with the real LND invoice. It rejects forged
quotes and credit signatures, survives termination after handoff and after
finalization, and stores exactly 100 delayed credits. This brings the local
proof to 500 verified credits. A second native invoice is canceled after handoff;
forged and cross-purchase certificates are refused, the valid certificate survives
actual process restarts, the previous credit balance stays unchanged, and a fresh
blinded purchase becomes possible. Separate Mesh tests refuse future-dated
certificates and attempts to relabel a sealed canceled purchase as completed or
pending. The Python coordinator relays the issuer's HTTP
responses for that case; native TLS transport and launching a separate wallet
application are separate outstanding checks. The simulator app is removed on
completion, and no user's app data or wallet is used.
Additional public BOLT11 vectors, integer pricing, wrong-node/network, malformed
receipt, concurrent reservation, cross-rail and edge-routing tests are separate.
Evidence is under `.morse/witness-proof/lightning-*` in the workspace root.
`lightning-cancellation-native-ios-regtest.log` and `lightning-issuance-local.json`
record the full 500-credit run and native cancellation/restart cases. The isolated
iOS archive and its 403-source snapshot are recorded separately; this does not
claim that every installed platform archive already includes this later change.
Use `MORSE_LIGHTNING_CASES=canceled` for the focused server case; subset runs write
`lightning-issuance-selected-local.json` and cannot replace full-run evidence.

Still open: broader concurrent/failure integration, external wallet launch, BTC treasury
conversion, public language release/review, and live acceptance. The plan remains
the authority for release gates.

Sources: [LND hold-invoice API](https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/lnrpc/invoicesrpc/invoices.proto),
[BOLT11](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/11-payment-encoding.md),
[Pyth BTC/USD feed](https://docs.pyth.network/price-feeds/core/fetch-price-updates).

Direct native HTTPS dogfood is available with `MORSE_LIGHTNING_IOS_TLS_PROOF=1`
and `MORSE_LIGHTNING_ANDROID_TLS_PROOF=1` on
`scripts/prove-credit-lightning.py`. The isolated module selected by
`MORSE_LIGHTNING_IOS_MODULE` must include the public `Http.trust_root_pem`
runtime and native issuer-root resource reader. The proof owns a short-lived
CA and exact-origin HTTPS ingress, rejects missing trust before HTTP, completes
a local LND purchase, injects forged and dropped responses, restarts the native
app, and recovers signed cancellation with new purchases disabled. No external
wallet app or live funds are used. See `packages/mobile-core/ISSUER_TLS.md` for
the immutable build resource; JavaScript cannot choose a CA or origin. Local
evidence is `.morse/witness-proof/credit-native-https-evidence.json` at the repo
root. `MORSE_LIGHTNING_CASES=canceled` runs the focused cancellation and native
HTTPS cases without overwriting the full issuance evidence.

The subsequent 162-export compiler-adoption proof passes on both iOS Simulator
and Android emulator. Each stores 100 delayed test credits, preserves an exact
claim across a dropped HTTPS response and process restart, rejects forged
responses, and recovers an authenticated cancellation with new purchases off.
The complete scoped archive is
`.morse/witness-proof/seal-errors162-checkpoint/manifest.json`, SHA-256
`52d17c16de505c857353e0673d7b71e152377572a9420eef9b0034f47b3ea529`.
Its HTTP backend deliberately uses frozen pre-policy-2 issuer sources and the
preceding compiler; the new compiler is exercised in the native libraries.
It does not qualify later issuer policy changes or external wallet launching.

Use `MORSE_LIGHTNING_PROOF_DIR` to preserve a new run independently, and
`MORSE_LIGHTNING_SERVICE_SOURCE` to select an explicitly frozen service and its
migrations. Each completed platform result and public proof package is saved
immediately, even if a later platform fails. The driver preserves the exact
compiled issuer/client executables, reports and reported module source bodies.
The Android harness normalizes the generated JNI application-error wrapper and
retains the raw error. A quote rejected at its not-before boundary may be retried
once after 1.1 seconds only if the journal still holds the exact stage-0 request;
all other quote failures propagate. Instrumentation startup may retry once only
when attachment failed before consuming the command and no response exists.
Neither rule relaxes production verification or replays an unknown native result.
