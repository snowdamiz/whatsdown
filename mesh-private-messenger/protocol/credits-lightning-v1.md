# Lightning credits v1

Status: local implementation and regtest evidence; production activation and
review remain open. This extends [anonymous credits v1](credits-v1.md) without
changing Solana quote/signature formats or the bearer token profile.

## Wire formats

Integers are unsigned and big-endian. Parsers require exact lengths, canonical
BOLT11, recognized versions and no trailing bytes. All four 32-byte identifiers
in a cancellation must be nonzero. Purpose is 0 live or 1 test. Network is
0 mainnet, 1 testnet, 2 regtest, 3 signet or 4 simnet; live requires mainnet and
test excludes mainnet. Packs remain 100, 500 or 2000 credits.

| Value | Canonical bytes | Length |
|---|---|---:|
| Quote request | `01 LQR, credits:u16, network:u8, purpose:u8, issuer_key_id[32], batch_hash[32]` | 72 |
| Quote | `01 LQT, quote_id[32], network:u8, purpose:u8, credits:u16, amount_msat:u64, issued_at:u64, expires_at:u64, issuer_key_id[32], batch_hash[32], payment_hash[32], payee[33], invoice_length:u16, invoice_utf8` | 195 + invoice length, at most 7284 |
| Signed quote | `01 LQS, canonical_quote, signature[64]` | 264–7352 |
| Issue request | `01 LIR, quote_id[32], payment_hash[32], count:u16, count × token_request[259]` | 70 + 259 × count |
| Issued credits | Existing `01 CIS` response | 70 + 256 × count |
| Canceled invoice | `01 LCN, quote_id[32], payment_hash[32], batch_hash[32], issuer_key_id[32], purpose:u8, canceled_at:u64, signature[64]` | 205 |

The quote signature is Ed25519 over
`UTF8("morse-lightning-credit-quote-v1") || canonical_quote`, using the witnessed
issuer quote key. The invoice is independently verified by the public Mesh
BOLT11 primitive. Its amount, payment hash, node public key, network, issue time,
900-second expiry and description hash for `Morse credits` must match the quote.
On-chain fallback addresses are refused. The signed quote binds the exact
ordered blinded batch before payment.

The cancellation signature uses the same witnessed quote key, over
`UTF8("morse-lightning-credit-cancellation-v1") || cancellation[0..141)`.
The timestamp is Unix seconds, is positive, and cannot precede the original
quote issue time. The client also rejects a future cancellation timestamp when
first accepting it. Every identifier, purpose and full issuer key ID must match
the original authenticated quote. Cancellation recovery can outlive the minting
epoch: it authorizes no token issuance and retains its originally admitted key.

## Settlement and recovery

The issuer commits a unique payment hash and sealed opaque preimage before
creating its LND hold invoice. Retries query that same hash. After an accepted
payment, it commits the exact blind response and its integrity signature before
revealing the preimage. Only an authenticated `SETTLED` lookup can commit revenue
and return `CIS`. An ambiguous HTTP outcome is retried with the same batch.

Only an authenticated `CANCELED` lookup can create `LCN`. The issuer atomically
stores the signed cancellation and terminal ledger state before returning it.
Cached certificates are authenticated again before replay. A legacy canceled
row without a certificate requires another authenticated node lookup. Recovery
remains available when new purchases are disabled. No credit token or revenue
is created by cancellation, including for a previously prepared blind response.
Expiry, HTTP409/503, wallet-launch failure and missing node responses are not
cancellation proofs.

The privacy edge accepts `CIS` or `LCN` on the Lightning issue route. It binds a
cancellation to the request's quote ID, payment hash and ordered batch; the
native client authenticates its issuer signature. The native journal seals the
complete `LCN` with the saved quote and retires pending blinding state in one
wallet commit. Native purchase stage4 means canceled, stage3 means completed.
Their distinct sealed terminal forms prevent one being relabeled as the other.
Duplicate certificates preserve the revision; different terminal responses are
refused. A new blinded purchase may start after authenticated cancellation.

The local app asset selector uses value2 for Lightning. This does not extend the
Solana `CQR` asset field. Native build resources pin both the issuer origin and
allowed Lightning network; JavaScript supplies neither authority.

See [operations and evidence](../ops/credit-lightning/OPERATIONS.md) for backend
configuration, recovery worker behavior and remaining release gates.
