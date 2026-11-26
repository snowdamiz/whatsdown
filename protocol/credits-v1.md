# Credits v1

Status: implemented in development, not deployed. The frames and checks below
exist in `packages/messenger-protocol/credits` and `privacy/credit_edge.mpl`
(bytes only), `packages/messenger-credits` (the blind RSA parts), the
directory-delivery core (spent set, holds, issuer keys), the privacy edge,
`services/credit-issuer` and the phone and desktop client ("Client" below),
with tests. Code that signs or verifies tokens needs
a Mesh release with `Crypto.BlindRsa` (profile BR1); until one is published it
builds only with the development compiler. What each credit buys (postage,
storage, sign-up priority, files over 16 MiB) is in "Extras" below.

Credits are optional. Messaging never needs a credit, a wallet or the token:
proof of work (`PRV`/`PWR`) stays the free path for every request that has it
today (plan invariant I6).

## Parties and what each one sees

| Party | Sees | Never sees |
|---|---|---|
| Phone | its quotes, its payments, its tokens (sealed under the storage key) | |
| Privacy edge | the source connection of a quote, an issue request and a credited request; token bytes in transit | the payer's address (inside a quote only as the deposit address it pays to), a nullifier's history, which account spends |
| Credit issuer | quotes (pack, asset, amount, deposit address or invoice, time), the on-chain payment and its payer, blinded messages and its blind signatures | a token, a token input or a nullifier (blinding hides them); where or when a token is spent; the buyer's network address (quotes come through the edge) |
| Directory-delivery core | issuer public keys; each spent token's nullifier, key epoch and spend time; each hold's action, binding and count; weekly spend totals by action; a mailbox's signed price and its paid storage (so which mailbox bought storage, and when) | a quote, a payment, a deposit, a blinded message; which purchase a token came from; who paid a message request's postage |
| Solana / Lightning | the purchase (payer, deposit address, amount, time) and later sweeps and refunds, publicly | anything about the tokens or Morse accounts |

The issuer's database and the core's spent set share no column that could join
them (asserted on both migrations by
`services/credit-issuer/tests/linkability.test.mjs`). What still links a buyer
to a spender is timing, and the client controls it: packs come in fixed sizes,
every token of an epoch carries the same challenge and key, and clients spend
tokens in random order, no sooner than 10 minutes after a purchase. A purchase
is as public as any on-chain payment; the app says so where it sells credits.

## Tokens

Morse credits are Privacy Pass tokens of type `0x0002` (RFC 9577, RFC 9578):
blind RSA, RSABSSA-SHA384-PSS-Deterministic (RFC 9474), 2,048-bit keys,
exponent 65,537. One token is one credit, so every token has the same value.

**Challenge.** A TokenChallenge (RFC 9577 §2.1):

```text
u16  token_type = 0x0002
u16  length ‖ issuer_name      the issuer origin's host, e.g. "credits.morseapp.io"
u8   length ‖ redemption_context   always empty (length 0)
u16  length ‖ origin_info      "morseapp.io"
```

The issuer origin is the security config's `<credit issuer origin>` line
(`https://<host>`, nothing else); its host is the issuer name. Tokens are
fetched ahead of use, so the redemption context is empty and every token of an
issuer carries the same challenge digest. `credits_challenge` builds it;
`credits_challenge("credits.morseapp.io")` is
`0002 0013 "credits.morseapp.io" 00 000b "morseapp.io"`.

**Token input** (98 bytes, what the issuer blind-signs):
`u16 0x0002 ‖ nonce32 (random) ‖ SHA-256(challenge) ‖ token_key_id32`, where
`token_key_id = SHA-256(the key's 342-byte RFC 9578 SPKI)`.

**Token** (354 bytes): the token input followed by the 256-byte authenticator,
exactly RFC 9577's Token for type 2. The RFC 9578 Appendix A.2 vectors decode to
this layout and verify (`tests/credits_token.test.mpl`,
`messenger-credits/tests/credits_crypto.test.mpl`; the vectors are
`tests/fixtures/credits/rfc9578-type2.json`, copied from mesh-lang).

**Nullifier**: `SHA-256(token input)`. It is what the core records as spent.

**Verification** (`credits_verify_token(key, token)`): the token decodes as
type 2; its key ID is the logged key's; its challenge digest is the Morse
challenge of the key's issuer name; `Crypto.blind_rsa_verify` accepts the
authenticator over the token input. Whether the key is logged, unrevoked, of the
right purpose and inside its window is the redeemer's check (below).

## Issuer keys in the transparency log

A phone accepts a credit key only when its leaf is in the log it verified, so
the issuer cannot give one user a key of its own to tag their tokens.

**Epochs.** Epoch `e` starts at `e × 30 days` of Unix time (2,592,000,000 ms).
One key per purpose and epoch; the key of epoch `e` is valid from its start for
two epochs: it is the current key during `e` and the previous one during
`e + 1`. Redeemers accept exactly the keys whose window holds the moment of
redemption.

**`issuer-key-v1` leaf (`IKY`):**

```text
u8   version = 1
"IKY"
u8   purpose: 1 live | 2 test
vector32 issuer_name     1-253 bytes, the issuer origin's host
u32  epoch
u64  not_before_ms       = epoch × 2,592,000,000
u64  not_after_ms        = not_before_ms + 2 × 2,592,000,000
342  spki                the RFC 9578 SPKI (RSASSA-PSS, SHA-384)
```

**Revocation leaf (`IKR`):**

```text
u8   version = 1
"IKR"
u8   purpose
vector32 issuer_name
u32  epoch
32   token_key_id        the revoked key
u64  revoked_at_ms
```

Both are canonical: one encoding per value, no trailing bytes, windows exactly
as above. A leaf's kind is its first four bytes (`01 "DVS"` a device set, `01
"IKY"`, `01 "IKR"`). The directory stores them as ordinary log leaves under
commitments no account has (`SHA-256("morse-credits/v1/issuer-key" ‖ key_id)`,
`SHA-256("morse-credits/v1/issuer-key-revocation" ‖ key_id)`), keeping their
bytes: log pruning supersedes an entry only by a newer one under the same
commitment, so these leaves are never pruned. A key already announced may be
announced again (the same leaf answers `200`); a second unrevoked key for the
same purpose and epoch, or another leaf for a known key, is refused (`409`).
After a revocation a replacement key for the same epoch may be announced.

**Listing (`CIK`):** `GET /v1/credits/issuer-keys[?previous_tree_size=N]`
answers

```text
u8 1 ‖ "CIK" ‖ u8 count (0-8) ‖ count × vector32(KTE v2)
```

one [KTE v2](key-transparency-v1.md) per unrevoked key of either purpose whose
window holds now, all on one fresh checkpoint, each proving the key's leaf into
the witnessed log with consistency from `previous_tree_size` (default 0). A
phone verifies each with `transparency_verify_evidence_v2` under its pinned
service key and witnesses, decodes the entry as `IKY`, and keeps only keys of
the purpose its build uses (release builds: `live`). A key that disappears from
the listing (revoked, or past its window) is no longer spent.

## Issuance

Through the privacy edge, which forwards the body alone (no client header) to
the issuer, so the issuer never sees a buyer's address:

| Edge route | Issuer route | Request | Answer |
|---|---|---|---|
| `POST /v1/credits/quote` | `POST /v1/credits/quote` | `PWR(CQR)` | `201` `CQT`; `429` missing, stale, short or spent work, or too many open quotes; `503` credits off or no announced key this epoch; `422` asset not offered; `400` malformed; `502` oracle or Lightning node failure |
| `POST /v1/credits/issue` | `POST /v1/credits/issue` | `CIR` | `200` `CIS`; `202` payment not final yet (retry); `402` not a payment to this quote, underpaid, or paid after expiry; `404` unknown quote; `409` another batch for an issued quote, or a payment used by another quote; `410` expired unpaid; `412` blinded for a key that is not the current one (re-blind); `503` not signing (credits off, no key) |

The edge answers `404` for both when `MORSE_CREDIT_ISSUER_URL` is not set.

**Quote request (`CQR`):** `u8 1 ‖ "CQR" ‖ u8 pack ‖ u8 asset`, sent inside a
`PWR` stamp ([sealed-delivery-v1.md](sealed-delivery-v1.md), "Stamped directory
requests") with the label `mesh-msg/v1/work/credit-quote`, at the full pinned
difficulty (the label has no per-endpoint step). The edge checks the work and
forwards the stamped frame; the issuer checks it again, spends the stamp once,
and refuses (`429`) while `MORSE_CREDIT_MAX_OPEN_QUOTES` (default 1,000) quotes
are open and unexpired. An expired quote stops counting; its deposit address
stays reserved for a late payment. Every quote therefore costs work and a
quote can never be asked for twice with one stamp. Packs: 1 = 100
credits ($5), 2 = 500 ($25), 3 = 2,000 ($100); $0.05 a credit. Assets: 1 USDC,
2 SOL, 3 BTC over Lightning.

**Quote (`CQT`):**

```text
u8 1 ‖ "CQT"
32   quote_id            random; whoever holds it can collect the pack, so it
                         stays with the buyer
u8   pack
u8   asset
u16  batch               = the pack size: tokens to blind
u64  amount              base units: USDC micro-units, lamports, or satoshis
u64  expires_at_ms       15 minutes after the quote
32   token_key_id        the key to blind for (this epoch's)
vector32 payment_request UTF-8, ≤ 4,096 bytes
```

For USDC and SOL the payment request is a Solana Pay URL to a fresh deposit
address: `solana:<deposit>?amount=<decimal>[&spl-token=<USDC mint>]&reference=<base58
reference>&label=Morse&message=<batch>%20Morse%20credits`, where the reference
is `SHA-256("morse-credits/v1/solana-pay-reference" ‖ quote_id)`: a Solana Pay
reference is public on-chain, and the quote ID must not be, since an issue
request needs only the quote ID and the first batch presented for a paid quote
is the one signed. The deposit address is
the issuer's `m/44'/501'/q'/0'` for a new quote index q (SLIP-0010, the
derivation `packages/wallet-core` uses). The wallet pays it with a plain
transfer (and creates the deposit's USDC account if needed). USDC costs the pack
price exactly; SOL is priced from a Pyth SOL/USD price at most 60 s old whose
confidence is within 1%, rounded up to the lamport, and may arrive up to 1%
short. For BTC the payment request is a BOLT11 invoice for the pack price at the
Pyth BTC/USD price, from the issuer's LND node, expiring with the quote.

**Issue request (`CIR`):**

```text
u8 1 ‖ "CIR"
32   quote_id
vector32 payment         ≤ 128 bytes: the paying transaction's base58 signature,
                         or empty (the issuer finds the payment to the deposit
                         itself, as for a Solana Pay payment from another wallet;
                         always empty for Lightning)
32   token_key_id
u16  count               = the quote's batch (100, 500 or 2,000)
count × 256              blinded messages, RSABSSA blinded token inputs
```

**Issue response (`CIS`):** `u8 1 ‖ "CIS" ‖ quote_id32 ‖ token_key_id32 ‖ u16
count ‖ count × 256` blind signatures, in request order.

Rules the issuer applies:

- A payment is read at `finalized` commitment, from the transaction's balances:
  lamports gained by the deposit address, or USDC (the configured mint) gained
  by token accounts the deposit address owns. A failed transaction pays nothing.
- One transaction (or invoice) pays one quote. A payment that lands after the
  quote expired, or pays less than the quote (SOL: less than 99%), issues
  nothing; the quote is marked `late` or `underpaid` and is refundable on the
  payer's request. Overpayment is kept.
- The batch is signed with this epoch's key, announced and unrevoked. A request
  blinded for another key gets `412`.
- The issuer stores a hash of the blinded batch
  (`SHA-256("morse-credits/v1/blinded-batch" ‖ token_key_id ‖ blinded…)`, the
  payment excluded) and the signatures. The same batch again gets the same
  signatures; another batch gets `409`. If the key that signed a quote is later
  revoked, the quote may be issued once more for a batch blinded for the
  current key (re-issue against the purchase).
- Credits off (`MORSE_CREDITS_MODE=off`) signs nothing, and still answers a
  resubmission from what it stored.

The client blinds each token input (`Crypto.blind_rsa_blind`), keeps every
blinding state until the answer arrives, then finalizes each signature
(`Crypto.blind_rsa_finalize`, which verifies it) and seals the 354-byte tokens
under the storage key. Blinding states are affine resources: no list or record
can hold them, and they cannot be persisted, so the whole exchange happens in
one Mesh call (`credits_blind_batch` holds them on the stack and makes the one
exchange through a callback). The callback retries the same batch on a lost
answer or a `202`: a resubmission is answered from what the issuer stored. A
client that loses its blinding states (the app is killed mid-exchange) cannot
finalize the stored signatures, and a new batch for an issued quote gets `409`;
that purchase needs the operator (a refund is not possible once issued).

**Operator re-issue.** `credit-issuer reissue <quote> --confirm <quote>`
re-opens an `issued` quote that a payment paid, once: the next `CIR` for it
with a new batch (the same count, blinded for the current key) is signed, and
the quote closes again; later batches get `409` as before. The quote keeps its
issue time (its settlement week). A second re-issue of the same quote, or one
of a quote that is open, expired, underpaid, late or refunded, is refused. The
issuer records each re-issue (quote ID, time, the operator's note, when its
batch was signed) and nothing about who asked. The bound: a purchase yields at
most one extra batch, only after an operator's action, and only to the holder
of the quote ID (the purchase reference the app shows). The operator asks for
the payment proof (the transaction or invoice that paid it, which
`credit-issuer reissue <quote>` prints to compare) before confirming; the
reference alone is not enough, since anyone who saw it could ask.

## Spending: the `CRD` frame

A request that uses an extra carries a `CRD` frame in front of the body the
route takes anyway:

```text
u8   version = 1
"CRD"
32   binding             SHA-256 of the rest of the request (everything after the frame)
u8   count               1-64 tokens
count × 354              tokens, no token twice
```

The request is `CRD ‖ body`. The frame is canonical and self-delimiting (its
length is `37 + 354 × count`); `credits_detach` splits it off and refuses a
binding that is not `SHA-256(body)`, repeated tokens, a count of 0 or above 64,
and truncation. A body that does not start with `01 "CRD"` is an ordinary
request. The binding stops a frame being moved onto another request before it
is spent.

### Privacy edge

`POST /v1/envelopes/batch` takes one of:

| Body | Meaning |
|---|---|
| `PRV` | proof of work, unchanged: the free path |
| `CRD ‖ PRV` | credits beside the work: the work must verify too |
| `CRD ‖ SED` | credits instead of the work |

The edge checks the binding and any work before anything reaches the core
(`400` malformed or wrong binding, `429` missing or stale work). It then posts
`RDQ(action 1, frame)` to the core's redeem route with its bearer and, only on
`201`, forwards `HLD(redemption_id, SED)` to the core's sealed route. The core's
refusals pass through: `422` not a credit, `403` credits off, `409` a token
already spent (a replay); anything else, or no answer, is `503` and nothing is
delivered. The edge never logs or keeps token bytes. In the isolated
deployment the edge Worker carries the redeem call to the backend's
`POST /v1/ingress/credits/redeem`, guarded like `POST /v1/ingress/sealed` (bearer, and
the edge request signature once `MORSE_EDGE_INGRESS_PUBLIC_KEY` is set).

### Core redeem route

`POST /internal/v1/credits/redeem`, bearer: the delivery internal token (the
edge) or `MESSENGER_OBJECT_INTERNAL_TOKEN` (the object store).

```text
RDQ: u8 1 ‖ "RDQ" ‖ u8 action ‖ vector32(CRD frame)
RDR: u8 1 ‖ "RDR" ‖ redemption_id16 ‖ u8 credits
```

Actions: 1 envelope (edge: postage and admission), 2 storage, 3 priority
sign-up, 4 large file. The core does not interpret the action; it records it
with the hold.

In one transaction the core finds the accepted keys (logged, unrevoked, of the
purpose it redeems, window holding now), verifies every token against its key,
inserts every nullifier into `credit_spent` and writes one hold. Any token that
is not a credit refuses the frame (`422`) before anything is written; any
nullifier already present refuses the whole frame (`409`) and nothing of it is
spent; a spent set that cannot be read or written refuses it (`503`, fail
closed). Two services redeeming the same token at the same moment spend it
once: the nullifier is the primary key, and the loser's transaction rolls back.
`403` when this core redeems no credits.

**Holds.** A redemption writes `credit_holds(redemption_id, action, binding,
credits)`. The action that the credits pay for takes the hold once, inside its
own transaction (`credits_take_hold_on_connection`), within an hour; a taken or
unknown hold cannot be taken again. For an envelope, the core's sealed route
receives

```text
HLD: u8 1 ‖ "HLD" ‖ redemption_id16 ‖ vector32(SED)
```

and stores the envelope in the transaction that takes the envelope hold (`409`
when there is no hold to take). A route inside the core (priority sign-up,
storage) can instead call `credits_redeem_on_connection` in its own
transaction, spending the tokens and performing the action atomically. A
service outside the core's database (the object store) treats `201` as its
entitlement. Spent tokens stay spent even when the action then fails (a mailbox
that is full, say): the credits are not returned.

**Retention.** A token is accepted only inside its key's two-epoch window, so a
spent-set row is useless after it; rows go 7 days later (`key_epoch ≤
(now − 7 days) / epoch − 2`), holds after a day, from the directory's scheduled
job. Issuer-key leaves are never pruned.

## Modes and flags

| Flag | Where | Values |
|---|---|---|
| `MORSE_CREDITS_MODE` | issuer, core | `off` (default), `test`, `live`. The issuer signs keys of its purpose (`live` in live, else `test`) and refuses quotes when off. The core redeems tokens of keys whose purpose is its mode; switching to `off` keeps redeeming the previous purpose for 7 days from the change (recorded in `credit_mode` at startup), then refuses (`403`) |
| `MORSE_CREDIT_ASSETS` | issuer | `usdc,sol` by default; `btc` also needs `MORSE_CREDIT_LND_URL` |
| `MORSE_CREDIT_ISSUER_URL` | edge | where quote and issue requests go; unset: `404` |
| `MORSE_CREDIT_ISSUER_INTERNAL_TOKEN` | core, issuer | the issuer's bearer for `POST /internal/v1/credits/issuer-keys` |

Release builds use `live` keys only; staging and local runs use `test` keys. A
production core runs `live` and never accepts a `test` token.

## Extras

What credits buy (plan §6.10).

### Postage: a price on your inbox

A device may ask 0, 1, 5 or 25 credits for every envelope that reaches its
**public** address. Envelopes to its [contact address](contact-address-v1.md)
never pay, so a price only touches message requests from strangers; postage
goes to the network, never to the recipient (plan D12).

**Where the price lives.** Not in the transparency-logged device set: a price
change would then be a new log entry and a new device-set version for a setting
that changes often and that nobody needs to audit. It is instead a policy the
device signs and the directory only stores and serves:

```text
MBP: u8 1 ‖ "MBP" ‖ mailbox_hash32 ‖ u64 sequence ‖ u8 postage (0|1|5|25) ‖ sig64
signed by the device's Ed25519 signing key over
"mesh-msg/v1/mailbox-policy" ‖ the frame without its signature
```

`mailbox_hash` is SHA-256 of the device's public mailbox token. The directory
cannot sign one, so it cannot raise a price or invent one; a sender verifies the
signature with the device key from the device set it verified against the
transparency log. A policy replaces the stored one only with a higher sequence
(the device uses its clock in milliseconds), so an old one cannot be brought
back by resubmitting it. What the directory can still do is serve an older,
genuinely signed policy instead of the newest (a device that lowered its price
from 25 to 1 could be shown 25): it can overcharge up to a price the device once
set, never beyond, and never pays the recipient either way.

| Route | Request | Answer |
|---|---|---|
| `PUT /v1/mailbox/policy` (directory; device-signed, no proof of work) | `MBP` | `201` stored, `200` the same again, `409` not newer than the stored one, `403` not signed by the mailbox's active device, `400` malformed |
| `POST /v1/prekeys/bundle` with `OTQ` **version 2** (same fields, same stamp) | `PWR(OTQ v2)` | `200` `PKC`: `u8 1 ‖ "PKC" ‖ vector32(PKB) ‖ vector32(MBP or empty)`; other statuses as version 1 |

A sender learns the price when it claims the recipient device's prekey bundle
to start a session, before its first message. An envelope to a priced public
address that carries no hold, or a hold of fewer credits than the price, is
refused with **`402`** and the signed `MBP` as the body (the edge passes both
through): the client shows "this person charges N credits for message requests"
and may send again with a `CRD` of at least N tokens. The credits of a refused
envelope are spent (the edge redeemed them first), so a client attaches the
price it verified. Clients whose device sets a price must hand their contact
address to the members of their groups too (group messages from non-contacts
arrive at the public address, and would otherwise pay).

### Longer storage

10 credits per mailbox per extra 30 days, up to 180 days (5 periods). A
purchase is a device-signed request carried through the edge with its credits:

```text
MRT: u8 1 ‖ "MRT" ‖ mailbox_hash32 ‖ u8 periods (1–5) ‖ u64 issued_at_ms ‖ sig64
signed over "mesh-msg/v1/mailbox-retention" ‖ the frame without its signature
MRA: u8 1 ‖ "MRA" ‖ u16 retention_days ‖ u64 entitled_until_ms
```

| Route | Request | Answer |
|---|---|---|
| `POST /v1/mailbox/retention` (edge) | `CRD ‖ MRT` (at least 10 × periods tokens, action 2) | `201` `MRA`; `402` no CRD frame, or fewer credits than the periods cost (the hold is left untaken; its tokens are spent); `403` not signed by the mailbox's device, or `issued_at` outside the 5-minute window; `409` no hold to take; `422`/`409`/`403`/`503` as the redeem route |
| `POST /internal/v1/mailbox/retention` (core, bearer) | `HLD(storage hold, MRT)` | as above |

An entitled mailbox (`entitled_until` in the future) has `retention_days` =
30 + 30 × periods, and the entitlement lasts that long from the purchase. A new
purchase never shortens an entitlement: it keeps the larger retention while the
current one lasts, and the later end. While entitled:

- delivery accepts an envelope whose expiry is at most `retention_days` plus a
  day ahead (instead of 31 days), and refuses (`400`) anything later;
- every envelope that arrives is kept at least `retention_days` from its arrival
  (a shorter expiry is raised to that), so senders need not know about it;
- the purge honours the stored expiry. Once the entitlement ends, new envelopes
  are treated as before; envelopes already stored keep their expiry.

The mailbox's capacity is unchanged (4 MiB and 4,096 envelopes).

### Priority sign-up

Registration (`PUT /v1/devices/register`) gets harder under load, never below
the pinned base. The signal is the number of devices registered in the last 10
minutes against `MORSE_SIGNUP_SURGE_TARGET` (default 300; 0 turns the surge
off): every doubling above the target adds one bit, at most 8, never past 24.
With per-endpoint difficulty ([sealed-delivery-v1.md](sealed-delivery-v1.md),
"Per-endpoint difficulty") registration's step is 0, so the required
difficulty is the base plus the surge bits.

```text
WRK: u8 1 ‖ "WRK" ‖ u8 difficulty ‖ u8 credits (20)
```

- A registration whose stamp falls short answers `429` with `WRK`: the
  difficulty required now and the sign-up price. `GET /v1/devices/register/work`
  answers the same `WRK` (`200`), so a device can mint once for the right
  difficulty.
- `CRD ‖ PWR(DRE)` with at least 20 tokens (action 3) needs work only at the
  pinned base. The tokens are spent in the registration's own transaction, so
  a registration that fails (a taken name, an invalid entry) spends nothing:
  `402` fewer than 20 credits, `422` tokens that are not usable (invalid or
  already spent), `403` credits off; otherwise the ordinary registration
  answers.

### Large files

Attachments up to 16 MiB are free. Above that, up to 512 MiB, a file costs 1
credit for every 16 MiB of its padded size beyond the first
([attachment-wire-v1.md](attachment-wire-v1.md#large-files-over-16-mib)): the
price follows the size bucket the object store sees anyway, 1 credit from
20 MiB through 32 MiB, 2 for 40 and 48 MiB, and so on to 31 for 512 MiB.

The object grant carries the credits: `CRD ‖ OGR` with the price in tokens,
bound to the `OGR` ([opaque-object-wire-v1.md](opaque-object-wire-v1.md#large-objects)).
The object store checks the binding and the grant's work, posts
`RDQ(action 4, CRD)` to the core's redeem route with
`MESSENGER_OBJECT_INTERNAL_TOKEN` (`MESSENGER_DELIVERY_INTERNAL_URL` names the
core; the Cloudflare deployment routes `delivery.internal` from the store to
the core's redeem route and nothing else), and grants only on `201`, whose
redemption must hold at least the price. The store's database is not the
core's, so it takes no hold: the `201` is its entitlement, and the hold lapses
after a day. What the store answers:

- `402` no frame, or fewer tokens than the price: nothing reaches the core and
  nothing is spent;
- `409` the core found a token spent (a replay), `422` a token that is not a
  credit, `403` credits off: as the redeem route, nothing new spent;
- `503` the core could not be asked; the tokens may or may not be spent;
- an exact replay of a granted request answers `200` from the store and
  redeems nothing.

The core records action 4 with the redemption and counts it under `file` in
the spend totals; it learns that some object was paid for, never which one:
the redemption carries no object identifier, and the store keeps no token,
nullifier or redemption.

A client takes the price from the device's credits at the moment it sends, so
a purchase and a large file are separated by at least the 10-minute cooldown
like any other spend. It shows the price before the file is staged ("Sending
this 40 MB video uses 2 credits") and, when the device holds too few, says so
instead of sending. Tokens the store answered `201` (or `409`/`422`) for are
gone; after `402`, `403` or a malformed request they were never redeemed and go
back; after `503` or no answer they are suspect.

### Spend totals

The core adds every redemption's credits to a per-week, per-action total
(`credit_spend_totals`: UTC Monday, action, credits) in the redemption's
transaction. `GET /internal/v1/credits/totals?week=YYYY-MM-DD` (bearer)
answers `{"week_start","postage","storage","signup","file"}` in credits. Credit
revenue is split when credits are bought (the issuer's weekly settlement sends
20% of it to the witness pool); these totals say what the credits were spent
on, including how much went to postage, and hold nothing per sender.

## Client

What a phone or desktop does, in `packages/mobile-core` (`mobile/credits_*.mpl`)
and the app (`apps/mobile/src/credits.ts`, `credits-model.ts`,
`CreditsScreen.tsx`). The core does every step that touches a token or a
blinding state; tokens leave it only inside the requests it builds, except the
raw tokens it hands the attachment path, whose own export frames them
(`Mobile.Attachments`, "Large files" above). Only `Mobile.CreditsIssue` needs
`Crypto.BlindRsa`; with a Mesh release that lacks it, mobile-core fails to build
there and in `packages/messenger-credits` alone.

### Which keys a build takes

`mesh_messenger_credits_refresh_keys` fetches `CIK` from the directory with
`previous_tree_size` set to the size of the checkpoint the device last
verified, and keeps a key only when its `KTE` v2 verifies under the pinned
service key and witnesses (`transparency_verify_evidence_v2`, consistent with
the device's checkpoint and fresh), its entry is an `IKY` for the pinned
issuer's host, its window holds now, and its purpose is the build's. The
build's purpose follows from the issuer origin it pins, which only a release
changes: `https://credits.morseapp.io` takes `live` keys only, every other
origin (local, staging) `test` keys only. So a release build never accepts a
test key, even one the production log lists. A key that leaves the listing
before its window ends is taken as revoked: its tokens are no longer spent, but
are kept until the window ends, so a listing that merely left it out cannot
destroy them (they count again once it is listed), and the purchases it signed
become `reissue`. Collecting one of those again while the issuer still stands by
the first batch (`409`) leaves it `issued` (outcome 9, "current"). Keys are
fetched when Credits opens and before a quote if the last fetch is over six
hours old.

### Buying

A purchase is a record the core keeps sealed ("credits/v1/purchases", the
newest 24 and every unfinished one):

| State | Meaning |
|---|---|
| 1 quoted | `mesh_messenger_credits_quote` minted `PWR(CQR)` at the full pinned difficulty, posted it to the edge and checked the `CQT` (pack, asset, batch, not expired, a key this device accepted) |
| 2 paid | the wallet's transaction signature is recorded |
| 3 issuing | a blinded batch was sent and its answer is not stored yet |
| 4 issued | the tokens are stored, spendable 10 minutes later |
| 5 expired | `410`/`404`: the quote ran out unpaid |
| 6 unpaid | `402`: short, late or not this quote's payment; Morse refunds on request, with the purchase reference (the quote ID, shown only in this state and the next) |
| 7 reissue | the key that signed it left the listing (revoked): collect again |
| 8 operator | see below |

Paying: USDC and SOL from the in-app wallet (the Solana Pay URL is parsed by
wallet op 6, checked to be for exactly the quoted amount in the quoted asset,
signed by op 5 and sent; `solana.ts` waits for `finalized`), from another wallet
(the URL as a QR code and a copyable link), or over Lightning (the BOLT11 invoice
as a QR code and copyable text).

`mesh_messenger_credits_issue` collects: it picks this epoch's accepted key (the
issuer signs with no other; else the quote's), marks the purchase `issuing`
before anything leaves, makes fresh token inputs, and in one call blinds them,
posts `CIR` through the edge, finalizes every signature (which verifies it) and
seals the tokens under the storage key. No answer, or a `500`/`502`/`504`, is
retried twice in the same call with the same batch (the issuer answers a
resubmission from what it stored); the call waits a minute for a large batch.
A `202` stores nothing on the issuer's side, so the call returns at once
(outcome `pending`) and the app asks again later with a new batch: every 5 s,
growing to 20 s, while the payment screen is open, for an external wallet or
Lightning; after the in-app wallet's payment is final, once, then the same
way. `412` asks for fresh keys and one more try.

**If the app dies mid-exchange.** Blinding states cannot be stored, so once a
batch has left, only this call can open its signatures. A purchase found
`issuing` (the app stopped, or every retry went unanswered) is collected again
with a new batch: if the issuer never saw the first, it signs this one; if it
did, it answers `409` and the purchase becomes `operator`. The payment is not
lost, but the signatures the issuer stored can't be opened on the device, so
Morse has to finish the purchase from the purchase reference. The payment
screen says so ("Keep Morse open while credits are collected"), and the app asks
again about `paid`, `issuing` and `reissue` purchases when Credits opens and at
most every five minutes before the outbox drains.

### The token store

Tokens sit in sealed shelves of at most 150 ("credits/v1/shelf/<n>"), each of
one key and one time they became spendable, under an index ("credits/v1/shelves").
Every spend takes its tokens uniformly at random from all spendable ones (so
the order says nothing about when they were bought), never within 10 minutes
of their purchase, and only under keys accepted now. A token past its key's
window is worthless: Credits shows how many expire first, and when.

A spend is a reservation ("credits/v1/reservation/<id>") of the tokens sent with
one request; the app hands the answer's status to `mesh_messenger_credits_settle`:

| Answer | What becomes of the tokens |
|---|---|
| `2xx`; `402` for postage and storage (the edge redeemed them) | spent |
| `400`, `429` (refused before any redemption); any refusal of a sign-up (it spends only on success) | back, as they were |
| `403`, and anything else the core can't read | back, **suspect** |
| `422` (not a credit) | back, suspect, and the app refreshes issuer keys |
| no answer, `5xx` | kept: a retry of the same request (same purpose) sends the same tokens; unanswered for an hour, they go back suspect |
| `409` (a token already spent) | on a retry, the first attempt spent them all; on a first attempt the suspect ones were the spent ones: they go, the clean ones come back |

Suspect tokens are only sent when there are not enough clean ones, so a `409`
names which were spent. Retrying a request with its own tokens is also what
keeps two requests from sharing a token.

### What credits pay for

- **Postage.** Prekey claims are sent as `OTQ` v2 (a directory that refuses them
  with any error is asked with v1); the `PKC` answer's `MBP` is verified under
  the claimed device's key and kept. Before a first message the app asks the
  core which of the peer's devices ask a price and have handed over no contact
  address (`mesh_messenger_credits_postage_quote`) and asks the person ("@x
  charges N credits for message requests"); a no stops the send. When the edge
  answers an envelope `402` with an `MBP`, `mesh_messenger_credits_postage`
  verifies it under that device's key (from the claim, or from a session with
  it), and, once the person agreed to that price, returns `CRD ‖ SED` with that
  many tokens; the app posts it to `/v1/envelopes/batch` and settles. A `409`
  is tried once more with fresh tokens. A background pass that has nobody to
  ask leaves the envelope queued.
- **Inbox price.** Settings → Privacy → Message requests from strangers: Free,
  1, 5 or 25. `mesh_messenger_credits_inbox_policy` signs the `MBP` for this
  device's own mailbox (sequence: its clock, always above the last) and the
  app `PUT`s it to `/v1/mailbox/policy`. Each device signs for its own mailbox:
  the directory accepts a policy only from the mailbox's device.
- **Group members.** While its price is above zero, a device hands its contact
  address to every member device of its groups that doesn't have it, in a group
  packet of kind 4 sealed to each member (`GRP` kind 4, `mesh_messenger_credits_group_handover`):

  ```text
  GCH: u8 1 ‖ "GCH" ‖ group_id32 ‖ account_id32 ‖ device_id16 ‖ contact_address32 ‖ u64 issued_at_ms ‖ sig64
  signed by the device's key over "mesh-msg/v1/group-contact-address" ‖ the frame without its signature
  ```

  A member keeps it, exactly like an address handed over in a direct message,
  when the signature verifies under the key the group holds for that member;
  group fan-out then addresses that device's envelopes to it, so they never meet
  the price. Older builds refuse kind 4 as an invalid group packet and drop it
  unshown. A new contact address (blocking rotates it) is handed over again.
- **Longer storage.** `mesh_messenger_credits_retention` signs `MRT` for this
  device's mailbox with 10 credits a period; the app posts `CRD ‖ MRT` to the
  edge's `/v1/mailbox/retention` and the `MRA` it gets back is kept for the
  Credits screen. Each device buys for its own mailbox: `MRT` must be signed by
  the mailbox's device within 5 minutes, and tokens stay on the device that
  bought them.
- **A busy sign-up.** When registration answers `429` with `WRK`, the app
  offers to skip the wait (`mesh_messenger_credits_signup`: `CRD ‖ PWR(DRE)`
  with 20 credits at the pinned base) if the device holds 20 spendable
  credits; otherwise, or if the person prefers, it sends the same entry worked
  at the difficulty `WRK` names (`mesh_messenger_credits_register_at`).
- **Large files.** The attachment path takes its tokens from
  `mesh_messenger_credits_spend` (action 4) through `setCreditSource` and
  settles through the same store.

`mesh_messenger_credits_status` answers the Credits screen: whether this build
sells credits and which purpose, the spendable balance, what is cooling down
and until when, what expires first, when keys were fetched, the inbox price,
paid storage, and the purchases, newest first. Purchase history never leaves the
device.

## Monitoring

Plan §12 pages Morse on issuer errors, spent-set write failures and a
redemption p95 above 500 ms. The issuer's `GET /health` reports its mode, key
readiness and unswept deposits (see its README). The core's
`GET /v1/credits/health` (not routed publicly) answers JSON with the mode, the
number of `live` and `test` keys accepted now, and, for the running process,
`redemptions`, `spent_set_failures` (redemptions answered `503`) and
`redeem_p95_ms` over the last 256. Counts and durations only.

## Incidents

- **Issuer key compromise.** `MORSE_CREDITS_MODE=off` on the issuer; `credit-issuer
  revoke-key <purpose> <epoch>` publishes the revocation leaf and the core
  refuses that key's tokens at once; provision and announce a replacement for
  the epoch; turn the issuer back on. Buyers whose tokens were under the revoked
  key resubmit their quote with a new batch and are issued again.
- **Spent-set loss.** The core refuses every redemption while the spent set is
  unavailable (fail closed) until it is restored from its replicated store.

See [the issuer's README](../services/credit-issuer/README.md) for keys,
rotation, sweeps, refunds and settlement.
