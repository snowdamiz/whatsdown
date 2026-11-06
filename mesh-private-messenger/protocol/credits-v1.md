# Anonymous credits v1

The Mesh `Credits` modules define credit tokens, issuer-key admission, request
binding, prices and encrypted local snapshots. The issuer service, payment
verification, shared redemption transaction, entitlement handlers and app UI
must integrate these modules before credits can be activated. Passing a codec
or signature check alone does not authorize a paid action.

## Cryptographic and wire profile

One credit is one [RFC 9578 Type 2 token](https://www.rfc-editor.org/rfc/rfc9578.html#section-6),
using public Mesh BR1. The runtime owns all RSA, PSS and secret arithmetic.
Morse uses only the public Mesh API. No amount, purchase reference or wallet
address enters the signed token input.

All integers below use network byte order. Parsers require the exact length and
reject unknown versions and types, truncated fields and trailing bytes.

| Value | Canonical bytes | Length |
|---|---|---:|
| Token input | `u16(2), nonce[32], challenge_digest[32], token_key_id[32]` | 98 |
| Token | token input, authenticator[256] | 354 |
| Issuance request | `u16(2), last_byte(token_key_id), blinded_message[256]` | 259 |
| Issuer-key leaf | `02 IKY, epoch:u64, purpose:u8, canonical_spki[342], quote_ed25519_public[32]` | 387 |
| Redemption frame | `01 CRD, body_sha256[32], count:u16, count × token` | 38 + 354 × count |
| Quote request | `01 CQR, count:u16, asset:u8, purpose:u8, issuer_key_id[32], batch_hash[32]` | 72 |
| Quote content | `01 CQT, quote_id[32], deposit_owner[32], destination[32], mint[32], asset:u8, amount:u64, purpose:u8, count:u16, issued_at:u64, expires_at:u64, issuer_key_id[32], batch_hash[32]` | 224 |
| Authenticated quote | `01 CSQ, canonical_quote[224], ed25519_signature[64]` | 292 |
| Issue request | `01 CIQ, quote_id[32], transaction_signature[64], count:u16, count × token_request` | 102 + 259 × count |
| Issue response | `01 CIS, quote_id[32], batch_hash[32], count:u16, count × signature[256]` | 70 + 256 × count |

Lightning uses separate invoice and claim formats described in
[Lightning credits v1](credits-lightning-v1.md). It shares the `CIS` success
response and bearer token format, but never reinterprets a Solana quote or
transaction signature as a Lightning payment.

The token key ID is SHA-256 of the canonical SPKI. The challenge digest hashes
the following opaque, service-wide challenge:

```
UTF8("morse-credit-v1") || 00 || pinned_service_public_key[32] || purpose:u8
```

Purpose 0 is live and 1 is test. This challenge is shared by every buyer of a
service/purpose; it contains no user identifier or per-purchase value. Keys must
not be reused between purposes or epochs. Tokens are bearer credentials.

`CreditFrame.binding` is SHA-256 of the exact request body with the CRD frame
removed. It must match the body whose action is authorized, including any PWR
frame that remains in that body. The transport/handler must identify the CRD
frame unambiguously. The hash is a request association, not a signature or proof
of ownership of a token.

A frame contains 1–64 tokens and must pay exactly the handler's computed price.
The largest launch price is 50 credits. Larger purchases are kept in the local
balance and spent across requests. Duplicate SHA-256(token input) values reject
the whole frame, even if their authenticator bytes differ.

## Issuer trust and key lifetime

Epochs are fixed 30-day intervals from the Unix epoch, using Unix seconds:
`epoch = floor(now / 2592000)`. Accept only the current and previous epochs.
Clients admit an issuer through a fresh witnessed version-2 transparency
checkpoint, inclusion of the exact issuer-key leaf and consistency with their
previous checkpoint. Existing checkpoint freshness permits at most five minutes
old or one minute ahead. Credits require at least one pinned witness.

The local key cache retains at most two accepted epochs and rejects replacement
of a key already authenticated for an epoch/purpose. A raw SPKI, a response from
the issuer, or a successful token signature verification does not admit a key.
The directory integration must enforce one immutable key per epoch/purpose and
global key-ID uniqueness; monitors must detect conflicting issuer announcements.
Those server constraints are still integration work.

## Local recovery and storage

`PendingCredit` is affine because it contains `BlindRsaBlindingState`. Before
posting an issuance batch, persist every pending token with
`seal_pending_credit`. The inner state seal uses Mesh storage purpose 19. An
outer purpose-14 seal hides and authenticates the token input, blinded request
and state ciphertext together. The caller supplies a storage context bound to
its account, device, unique purchase/token record and snapshot version.

The sealed pending format is `01 CPN`, the 98-byte input, the 259-byte request,
a u32 state-ciphertext length and that ciphertext. The parser bounds the inner
ciphertext to 4096 bytes. The runtime, not this codec, validates its private
resource format. Pending data and completed tokens have different magic values.
A completed token is stored as `01 CTK || token` inside a purpose-14 seal.

The client admits an issuer, blinds the entire fixed pack and persists its
pending state before requesting a quote. Its commitment is
`SHA256(01 CIB || count:u16 || ordered canonical token_requests)`. Duplicate
blinded requests or mixed truncated key IDs are rejected. The quote immutably
binds that commitment and issuer key before payment; otherwise an observer of
the public quote reference and payment signature could race the buyer with a
different blinded batch. The client checks the returned commitment before paying.

Recovery opens the same pending snapshot and retries the same blinded request.
The issuer retains the exact responses. Reopening the inverse and finalizing that response again yields the
same token input/nullifier, not additional value. The client must atomically
replace pending snapshots with completed tokens before deleting recovery state.

Client spending starts at least 600 seconds after purchase and selects tokens
in random order. The purchase timestamp remains client-local; enforcing this
delay must not introduce a purchase/redemption join into the server databases.

Asset 0 is USDC and 1 is SOL. USDC amounts equal the fixed pack price in six
decimal units; its destination is the canonical associated token account of
the fresh deposit owner and pinned mint. SOL uses a zero mint field and the
deposit owner itself as destination. A quote expires exactly 900 seconds after
creation. A confirmed payment must have a chain timestamp in the half-open
interval `[issued_at, expires_at)`. Historical verification can finish later.
Each key/batch commitment has at most one quote, and a transaction signature
can fund at most one quote. A lost quote response returns the same deposit and
expiry. Reusing an expired commitment does not silently create another bill.

## Redemption and pricing

`verify_credit_frame` checks every signature against admitted issuer keys and
returns each nullifier, issuer epoch and absolute retention deadline. The shared
core must insert all nullifiers and create the action or its hold in one
transaction. One conflict rolls back the entire frame. Edges and object stores
must forward to that shared ledger and cannot maintain independent spent sets.
Retain an epoch-E nullifier until `(E + 2) × 2592000 + 604800` seconds, seven
days after that key's acceptance period ends. Core records never contain quote
IDs or payment addresses; the issuer database never contains redemptions.

| Item | Integer price |
|---|---:|
| 100-credit pack | 5,000,000 USD micro-units |
| 500-credit pack | 25,000,000 USD micro-units |
| 2000-credit pack | 100,000,000 USD micro-units |
| Attachment, 1–512 MiB | `floor((plaintext_bytes - 1) / 16777216)` credits |
| Retention, 1–31 days | 0 credits |
| Retention, 32–180 days | `10 × ceil((days - 31) / 30)` credits |
| Recipient postage | 0, 1, 5 or 25 credits |
| Priority signup | 20 credits only above the configured base PoW difficulty |

The free PWR path remains available. Prices are computed from validated action
parameters, never from a client-supplied count alone. Payment asset conversion,
quote expiry, finalized-chain payment verification and revenue settlement are
separate issuer/operations responsibilities.

Paid attachment authorization uses the exact LAG/CAP request and signed LAR/CAR
completion in [paid-attachment-v1.md](paid-attachment-v1.md). Its central
object-to-hold binding and receipt survive an uncertain local object-store
commit; exact retry never charges another frame. Creation defaults off pending
the corresponding host streaming and native recovery integration.

## Qualification

The protocol tests cover fixed encoding, all five published RFC 9578 Type 2
tokens, malformed bounds, duplicate/nullifier handling, prices and time limits,
fresh witnessed key admission, public-Mesh issuance/finalization, sealed restart
recovery and cross-purpose/service rejection. Release evidence must separately
record the exact Mesh version, BR1 crypto gates, physical target execution,
shared-ledger concurrency and full payment-to-entitlement dogfood. This document
does not claim those integration or release gates are complete.


### External wallet transfer request

`Credits.Payment.solana_pay_url` constructs the official Solana Pay transfer
request from the native client's durably stored quote and native mint/purpose
pins. It rejects expiry and a wrong SPL destination. The recipient is the
quote's deposit **owner**, with `spl-token` naming the pinned mint for USDC;
the external wallet derives the canonical ATA. SOL omits `spl-token`. Amounts
use exact integer-derived decimal strings (six USDC or nine SOL places), and
the only transfer reference is the random quote ID. No account, device,
issuer-key ID or blinded batch appears in the URL. Opening the URL neither
proves payment nor grants tokens; finalized verification and exact pending
batch recovery still apply. The buy screen must show that the payment is
public and must obtain the user's action before opening an external wallet.
See the [Solana Pay transfer-request specification](https://docs.solanapay.com/spec).


### Issuer-authenticated quotes

The witnessed `02 IKY` leaf binds an independent Ed25519 quote key to the BR1
SPKI, epoch and purpose. The RFC token key ID remains SHA-256 of the canonical
SPKI. Admission and cache retention reject a changed quote key for the same
issuer epoch, including idempotent retries. Unsigned legacy issuer leaves do
not authorize purchases.

The issuer returns CSQ, never a bare CQT, from quote HTTP routes. Its Ed25519
signature covers ASCII `morse-credit-quote-v1` followed by the entire 224-byte
canonical CQT. Clients authenticate that signature with their witnessed quote
key and check the pending batch, pack, asset, purpose, key ID, epoch and expiry
before accepting a deposit address. The signature is stored with the pending
purchase and rechecked on recovery. Native wallet signing obtains the quote
from this verified journal; JavaScript cannot submit an arbitrary unsigned
quote as a purchase instruction.

The quote key is separate because a blind-RSA signing oracle accepts blinded
messages whose meaning the issuer cannot inspect. Reusing the token RSA key to
authenticate quotes would allow a buyer to obtain a quote forgery through the
blind-signing flow. Quote-key custody uses the existing sealed Ed25519 resource
with a distinct domain-bound storage context. Each stored response is immutable.
Migration002 preserves old development rows as unauthenticated, with nullable
new columns; it never silently creates or substitutes a witnessed quote signer.
Such rows fail closed. No live issuer migration is claimed.

### Priority signup and action recovery

PSU is `01 50 53 55`, operation nonce32, expiry-u64, entry-length-u32 and the
canonical directory entry (at most36,006 bytes). Its kind4 action targets the
entry's account, uses quantity0 and hashes the entire PSU. The signed CAR's
SGR result is `01 53 47 52`, account32 and SHA-256(entry)32. Native completion
checks the pinned signature, exact reserved CAP, account/entry and application
time within the action's authorization window.

SPY is an 88-byte signed price policy: `01 53 50 59`, purpose-u8,
enabled-u8, base-difficulty-u8, current-difficulty-u8, issued-u64,
expires-u64 and Ed25519-signature64. Expiry is exactly issued+60 seconds.
The signature covers `morse-credit-signup-policy-v1` followed by the first24
bytes. Native custody requires a current policy under its pinned core key,
matching purpose and enabled paid signup, before reserving20 credits at raised
difficulty. Base difficulty requires no credit payment.

CCR is `01 43 43 52`, operation-ID32, SHA-256(action)32, SHA-256(CRD)32,
cancelled-at-u64 and signature64, exactly172 bytes. Its Ed25519 domain is
`morse-credit-cancellation-v1` followed by the first108 bytes. Cancellation
time must be at least the bound action's expiry. The core serializes this
decision with redemption/effect consumption and returns an original CAR if
already completed. For a never-submitted expired action, cancellation time is
its expiry, giving a deterministic stateless response. An existing hold is
atomically replaced by a durable cancellation fence when its tokens are freed.
Clients retain a terminal cancelled reservation and verify the exact signed
CCR before making its tokens available. Neither time nor an unsigned failure
is sufficient evidence. These server/native contracts do not imply complete
onboarding UI or live paid-action rollout.
