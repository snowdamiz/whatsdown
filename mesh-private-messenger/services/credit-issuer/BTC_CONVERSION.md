# BTC treasury conversion

The default-off Kraken adapter converts one closed Lightning revenue week's
witness or burn allocation into independently observed USDC. It preserves the
original millisatoshi allocation, policy, membership and 20/30/50 split. Normal
issuer startup does not schedule conversion work.

The issuer exposes these explicit, bounded commands:

```text
btc-conversion reserve BATCH witness|burn
btc-conversion status BATCH witness|burn
btc-conversion run-once BATCH witness|burn
btc-conversion refresh BATCH witness|burn
btc-conversion reconcile-order BATCH witness|burn KNOWN_ORDER_ID
```

`reserve` persists the source and conversion budget. `run-once` advances one
bounded stage; it can make provider or Lightning requests when explicitly
configured. `refresh` replaces only an unsent order or withdrawal draft, retaining
the previous drafts. `reconcile-order` authenticates an operator-supplied exact
order ID against its original client ID. `status` reports the durable state and
residual accounting. Operations allocations are not eligible.

## Configuration

`MORSE_BTC_CONVERSION_MODE` defaults to `off`. `test` requires the issuer's test
purpose and owned loopback provider endpoints; `live` requires its live purpose
and the exact `https://api.kraken.com` origin. A dedicated conversion account is
required. Configuration is loaded only for an explicit conversion command.

`payment/btc_conversion_config.mpl` defines and validates the complete environment
contract. Its profile binds the existing treasury configuration hash and chain,
the original LND backend, dedicated account and API-key identities, Kraken's
Lightning payee, saved funding method/network/address, native USDC mint and
treasury owner/associated token account, three canonical read origins and the
conversion limits. The treasury hash must match the issuer's existing treasury
configuration; an independently supplied matching balance is insufficient.

The API secret is read through Mesh `Env.get_secret_hex` as `SecretBytes` and
borrowed by `Crypto.hmac_sha512_tag`. It is never stored in the public profile or
request journal. Provider account acceptance, API permissions and funding method
availability must be established before activation. No account or credentials
are provisioned by this implementation.

## Recovery and accounting

Migration `014_btc_conversion.sql` adds immutable request/draft/output records,
checked state transitions, a monotonic nonce lease per API key and exclusive
output-use reservations. Requests and their unknown state commit before the
external effect. An unknown invoice, order or withdrawal acknowledgement never
authorizes another effect. Lightning recovery tracks the original payment hash.
Kraken client IDs are not treated as permanent provider idempotency keys.

The adapter requires a fresh independent BTC reference price and enforces the
full 1% conversion budget across routing, trading and withdrawal fees. A draft
refresh cannot lower the original net floor. Expired unsent drafts can be
replaced; submitted or unknown requests remain frozen. Tiny or uneconomic
allocations stay deferred, without drawing on unrelated balances or silently
pooling later weeks.

Known withdrawal recovery matches the exact provider ID through persisted cursor
pages. Each invocation reads at most four pages; malformed or repeated cursors
refuse. A subsequent process resumes the scan. An exhausted pending scan can
start a new observation to discover later success. The journal's request bound
is an explicit stop, not permission to resubmit a withdrawal.

An output requires a successful signed transaction, matching finalized metadata,
exact mint/owner/custody and positive received balance delta, matching incoming
classic SPL instructions and two matching observations from three configured
origins. Address-lookup-table transactions are currently refused. Provider
balances and webhooks do not establish arrival.

The immutable 340-byte MCB2 receipt binds the original intent/profile, selected
draft, withdrawal, transaction, slot and actual received amount. Original
millisatoshis are never rewritten as USDC. Unused routing headroom and dust at
LND, unused BTC fee reserve at Kraken and sub-micro-USDC remainder remain
separate same-bucket liabilities. Status therefore reports
`source_discharge_proven: false`. Lightning payment success establishes delivery
to the pinned invoice, not independent proof of provider ledger credit posting.

Only the actual USDC output can be reserved once for a downstream operation.
Burn reservations can be released only after the existing authenticated permanent
unfunded-expiry proof; funded output cannot be reused. The combined BTC/SOL burn
path is locally qualified through actual funding, replay and permanent expiry
in a fresh owned bank. The separate explicit witness funding operator in
`ops/btc-witness-funding` is also qualified through actual `fund_once`, duplicate
and epoch-rollover replay, mutation refusal and restart recovery. Its permanent
bucket-0 output reservation cannot be released. It prints an unsigned funding
intent; this adapter does not schedule rewards, settle claims or sign treasury
transactions.

## Qualification boundary

The local adapter archive is
`.morse/witness-proof/btc-conversion-adapter/manifest.json` at repository root.
It records genuine regtest LND payments, authenticated owned Kraken protocol
fixtures, PostgreSQL concurrency/restart checks and actual classic SPL transfer
execution. These prove local implementation behavior, not Kraken acceptance,
public-chain finality, independent operators or production liquidity.

The combined storage regression is recorded in
`.morse/witness-proof/treasury-conversions-current-tree-qualified/manifest.json`
(17 files/29 cases, through migration 014). The fresh common-bank execution is
`.morse/witness-proof/treasury-conversions-common-bank-final/manifest.json`
(47 expected outcomes on the HTTP-fixed Mesh runtime). Its fixture source is
`ops/common-conversion-bank`. These proofs retain original source denominations
and distinguish actual conversion output from ordinary treasury coverage.

The witness bridge's current-tree proof is
`.morse/witness-proof/btc-witness-funding-current-qualified/manifest.json`.
Current-tree adoption and the optimized standalone operator build are recorded
in `.morse/witness-proof/btc-witness-funding-adopted/manifest.json`.
Use its documented explicit `http10-fixed` compiler/runtime profile. The bridge
preserves the existing program-identity/two-source reader contract; it does not
add current-pool or executable-release authentication. Its README records those
trust boundaries and the external policy qualification still required.

Reviewed public Mesh publication and exact deployment pins, real USDC and
provider configuration, independent RPC policy, deployment and live acceptance
remain separate gates. Conversion is disabled unless explicitly configured.
