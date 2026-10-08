# credit-issuer

Sells Morse credits ([protocol/credits-v1.md](../../protocol/credits-v1.md)):
quotes a pack, checks its payment on Solana (USDC or SOL) or Lightning,
blind-signs the buyer's batch with this epoch's key, announces its keys in the
transparency log, sweeps paid deposits to the treasury, and gives operators
refund and re-issue commands and the weekly settlement numbers. It stores
quotes and payments in its own database and never a redemption: it never sees
a token.

Status: development. It builds only with a Mesh compiler that has
`Crypto.BlindRsa` (the development compiler until a Mesh release ships it) and
is not deployed anywhere yet.

## Build and test

```sh
MESHC=/Volumes/SSK-SSD/mesh-lang/target/debug/meshc   # needs Crypto.BlindRsa
$MESHC build services/credit-issuer

createdb credit_issuer_test && for f in services/credit-issuer/migrations/*.sql; do psql -d credit_issuer_test -f "$f"; done
set -a; source services/credit-issuer/tests/test-keys.env; set +a
CREDIT_ISSUER_TEST_DATABASE_URL=postgres://…/credit_issuer_test $MESHC test services/credit-issuer/tests
node --test services/credit-issuer/tests/linkability.test.mjs
```

The tests run against fake Solana RPC, Pyth, LND and directory servers
(`tests/world.mpl`); `tests/test-keys.env` holds test-only RSA keys and a test
key-wrapping seed. Never deploy them.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MORSE_CREDITS_MODE` | `off` | `off`: refuses quotes and signs nothing (still answers resubmissions from stored signatures); `test`: signs with `test` keys; `live`: with `live` keys |
| `MORSE_CREDIT_ASSETS` | `usdc,sol` | Rails offered; `btc` (Lightning) also needs `MORSE_CREDIT_LND_URL`. Removing one stops new quotes for it |
| `MORSE_CREDIT_ISSUER_NAME` | | The issuer origin's host, exactly as the release's security config pins `https://<host>` (the tokens' challenge names it) |
| `MORSE_CREDIT_DATABASE_URL` | local dev database | Its own Postgres database, migrated with `migrations/*.sql` in order |
| `MORSE_CREDIT_PORT` | `18092` | HTTP port |
| `MORSE_CREDIT_KEY_WRAPPING_SEED_HEX` | | 32-byte X25519 seed that opens the sealed signing keys (secret) |
| `MORSE_CREDIT_DEPOSIT_SEED_HEX` | | 16–64-byte SLIP-0010 seed (e.g. a BIP-39 seed) the deposit addresses are derived from (secret) |
| `MORSE_CREDIT_SOLANA_RPC_URL` | | Solana JSON-RPC endpoint (mainnet for `live`, devnet or local for `test`) |
| `MORSE_CREDIT_USDC_MINT` | mainnet USDC | The USDC mint; devnet `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` |
| `MORSE_CREDIT_ORACLE_URL` | `https://hermes.pyth.network` | Pyth Hermes; SOL/USD and BTC/USD at most 60 s old |
| `MORSE_CREDIT_LND_URL`, `MORSE_CREDIT_LND_MACAROON_HEX` | | LND REST node and an invoice-only macaroon; unset turns Lightning off. The URL needs a publicly trusted certificate (put LND's REST port behind a TLS proxy) or a private network |
| `MORSE_CREDIT_DIRECTORY_URL`, `MORSE_CREDIT_ISSUER_INTERNAL_TOKEN` | | Where keys are announced: the directory's `POST /internal/v1/credits/issuer-keys`, and the bearer the directory holds as `MORSE_CREDIT_ISSUER_INTERNAL_TOKEN` (32+ characters) |
| `MORSE_CREDIT_TREASURY_ADDRESS`, `MORSE_CREDIT_TREASURY_USDC_ACCOUNT` | | Sweep destinations: the treasury (a multisig; its key is never on this server) and its USDC token account. Unset: no sweeps |
| `MORSE_CREDIT_SWEEP` | `on` | `off` stops the sweeper |
| `MORSE_CREDIT_SWEEP_MIN_DELAY_S`, `_MAX_DELAY_S` | `3600`, `86400` | Each deposit is swept after a random delay in this range |
| `MORSE_CREDIT_SETTLEMENT_SPLIT` | `20/80` | `20/80` (pool / operations) before the token, `20/30/50` (pool / buy-and-burn / operations) after |
| `MESSENGER_ABUSE_DIFFICULTY` | `16` | The pinned proof-of-work base a quote's stamp must meet (label `mesh-msg/v1/work/credit-quote`, no per-endpoint step) |
| `MORSE_CREDIT_MAX_OPEN_QUOTES` | `1000` | Open, unexpired quotes allowed at once; past it quotes answer `429` until some expire |

The privacy edge reaches this service through `MORSE_CREDIT_ISSUER_URL` (in the
isolated edge deployment, the edge Worker's `MORSE_CREDIT_ISSUER_URL` var, which
must be this service's HTTPS origin). Clients never call the issuer directly:
its Worker admits the purchase routes only with the edge's bearer
(`MORSE_CREDIT_EDGE_TOKEN`). Deployment (`npm run deploy:credit-issuer`, its own
Worker, database and secrets, migrations with `node migrate.mjs --credit-issuer`)
is in [ops/cloudflare/README.md](../../ops/cloudflare/README.md), "Separate
credit-issuer deployment".

## Routes

| Route | |
|---|---|
| `POST /v1/credits/quote` | `PWR(CQR)` → `201 CQT`; `429` unpaid, replayed or too many open quotes (see credits-v1.md for every status) |
| `POST /v1/credits/issue` | `CIR` → `200 CIS` |
| `GET /health` | JSON: `mode`, `purpose`, `epoch`, `current_key`, `next_key_provisioned`, `open_quotes`, `unswept_deposits`. `503` unless credits are off or this epoch's key is announced. Alert when `next_key_provisioned` is false a week before the epoch ends (plan §12: issuer errors page Morse) |

## Keys

One RSA-2048 key per purpose (`live`/`test`) and 30-day epoch (epoch `e` starts
at `e × 30` days of Unix time; `date +%s` / 2592000 is the current one). Keys
are made offline and provisioned in advance; the issuer announces each one into
the transparency log and signs with the current epoch's key only once it is
announced. Every minute the issuer announces the current and the next epoch's
key if they are provisioned and not yet announced, so rotation is automatic as
long as keys are provisioned ahead.

Mesh has no durable storage key on a server (`StorageKey.platform()` needs a
phone's secure store, `ephemeral()` dies with the process), so
`BlindRsaSecretKey.seal_for_storage` cannot keep a key across restarts. Keys are
therefore HPKE-sealed to the issuer's key-wrapping key and stored sealed in its
database; the issuer opens one straight into `SecretBytes` when it signs. A key
is never ordinary `Bytes` in either process. When Mesh gains a server storage
key, keys can be generated in the issuer and sealed with `seal_for_storage`
instead.

Provisioning a key (e.g. the next twelve epochs at once):

```sh
# once: the wrapping key's public half, from the issuer's environment
credit-issuer wrapping-public-key            # prints 64 hex

# per key, on an operator machine that can reach the issuer's database
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
MORSE_CREDIT_PROVISION_KEY_HEX=$(openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER | xxd -p | tr -d '\n') \
MORSE_CREDIT_KEY_WRAPPING_PUBLIC_KEY_HEX=<the 64 hex above> \
MORSE_CREDIT_DATABASE_URL=… \
  credit-issuer provision-key live <epoch>
shred -u key.pem
```

`credit-issuer announce` announces due keys at once instead of waiting for the
minute tick.

## Deposits and payments

Each Solana quote pays to its own address, `m/44'/501'/q'/0'` of the deposit
seed for quote index q (SLIP-0010 hardened Ed25519, the account path every
Solana wallet uses; `tests/derivation.test.mpl` checks it against
`packages/wallet-core`'s vectors). The fee payer is `m/44'/501'/2147483645'/0'`:
fund it with SOL (it pays every sweep and refund fee, and collects the rent of
the emptied USDC deposit accounts). Keep its balance above 0.05 SOL. Because
the seed restores in any Solana wallet, deposits can be recovered by hand if
the service is gone.

Mesh has no secret HMAC-SHA-512, so the derivation runs over ordinary `Bytes`:
the deposit seed and deposit keys are not zeroized in this process. They only
control deposits, which the sweeper empties; the treasury's key is never here.

A payment is read at `finalized` from the transaction's balances; one
transaction or invoice pays one quote. USDC and Lightning must pay the full
amount, SOL at least 99% of it. Less, or paid after the quote expired, issues
nothing: the quote becomes `underpaid` or `late` and waits for a refund.

## Sweeps

Every minute the sweeper confirms earlier sweeps (a finalized one marks its
deposits swept; a failed one, or one unknown after three minutes, is released
to be swept again) and sends at most one SOL batch (8 deposits) and one USDC
batch (4 deposits, each account closed) of issued deposits whose random delay
has passed, in random order. Underpaid and late deposits are never swept.
`credit-issuer sweep` runs one pass by hand (`--now` ignores the delays).
Sweeps are public transfers.

## Refunds

Only on a payer's request, only for `underpaid` or `late` quotes, and only with
an explicit operator step:

```sh
credit-issuer refund <quote-id-hex>                              # prints the plan: from, to, amount
credit-issuer refund <quote-id-hex> --confirm <quote-id-hex>    # sends it
```

The whole deposit goes back to the payer (SOL: the paying transaction's fee
payer; USDC: the token account it paid from). The quote becomes `refunded`.
Lightning cannot underpay (LND settles only the full amount).

## Re-issues

A client killed mid-exchange cannot open the signatures stored for its quote
(its blinding states are gone), and its next batch gets `409`; the app then
shows the purchase reference (the quote ID) and asks the payer to contact
Morse. Ask for the payment proof (the transaction signature, or the Lightning
invoice), compare it with the `payment` the plan prints, then re-open the quote:

```sh
credit-issuer reissue <quote-id-hex>                                                  # prints state, payment, issue time, whether re-issued
credit-issuer reissue <quote-id-hex> --confirm <quote-id-hex> --note "proof checked"   # re-opens it once
```

The next batch the app sends for that quote (the same count, blinded for the
current key) is signed, and the quote closes again. Only an `issued`, paid
quote can be re-issued, and only once, ever: a purchase yields at most one
extra batch, only by this step, and only to whoever holds the quote ID, which
is why the proof matters. Each re-issue is recorded in `reissues` (quote ID,
time, the note, when its batch was signed); keep client details out of the
note.

## Weekly settlement

```sh
credit-issuer settlement 2026-09-28        # a Monday (UTC)
```

prints the week's issued packs, revenue by asset (pack prices, in micro-USD =
USDC base units) and the split. Pass `pool_usdc_base_units` to
`node ops/drills/fund-pool.mjs --amount …`, which builds (never signs) the
`fund_pool` transaction for the treasury's signers. Nothing here moves money.

## Test and live

| Environment | `MORSE_CREDITS_MODE` | Keys | Chain |
|---|---|---|---|
| Local | `test` | `test` | local validator, local USDC mint |
| Staging | `test` | `test` | devnet, devnet USDC |
| Production | `live` (plus a separate `test` issuer if wanted) | `live` | mainnet |

Release builds accept only `live` keys; a production core redeems only `live`
tokens. A `test` issuer's tokens are worthless in production.

## Incidents

- **Signing key compromised.** Set `MORSE_CREDITS_MODE=off` (quotes and signing
  stop). Run `credit-issuer revoke-key <purpose> <epoch>`: it publishes the
  revocation leaf and the core refuses that key's tokens at once. Provision and
  `announce` a replacement for the same epoch, then turn the mode back on.
  Buyers holding tokens of the revoked key resubmit their quote with a newly
  blinded batch and are issued again against their purchase.
- **Key-wrapping seed lost.** Stored keys cannot be opened: provision new keys
  (with a new wrapping key) for the current and next epochs; tokens already
  issued stay valid, since redemption needs only public keys.
- **Deposit seed exposed.** Stop quotes (`off`), sweep everything at once
  (`credit-issuer sweep --now`, repeated until `unswept_deposits` is 0), let open
  quotes expire, then start again with a new seed.
- **Spent-set loss (core).** The core refuses redemptions until it is restored;
  nothing to do here.
