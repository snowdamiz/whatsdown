# Native wallet payment submission

The UI selects the encrypted local database and durable purchase ID. It cannot
select an RPC URL, supply a quote/blockhash/payer, sign a raw message, or provide
a payment-success Boolean. This path is local implementation evidence; it does
not activate production purchases or authorize live fund movement.

The foreground native host privately reads SDK operation 2 (payment address),
then calls `credit_wallet_prepare` with counted `[database, purchase_id, payer]`.
Mesh authenticates the stored signed quote against its admitted issuer, native
purpose/mint, and the original sealed blind-batch commitment. Endpoints come
from `configured_anchor_pins(native_security_config())`, using the existing
validated direct-provider configuration. Versions without pinned chain sources
fail closed. These direct public chain calls contain the signed public payment;
issuer quote/issuance requests continue through the configured privacy edge.
The payer is never added to a core/edge request or retained in issuer token data.

A kind-7 encrypted wallet record reserves the authenticated quote and payer
before the first provider call. A confirmed `getLatestBlockhash` response
reserves the exact hash, context slot and unsigned `lastValidBlockHeight` before
the native confirmation prompt. Resuming an unsigned plan checks confirmed
`getBlockHeight`. Only a height beyond its reserved lifetime permits a new hash,
with a CAS requiring the same still-unsigned old plan. A stale outstanding
prompt then fails commit against the new hash. Signed plans never perform a
height/hash refresh. There are at most three provider attempts,
each bounded to three seconds and 2,048 response bytes, with no redirects.
JSON-RPC IDs and unsigned integer types are checked. Providers are trusted for
chain availability; this is not a Solana light client.

The host consumes the private `MWP` plan and calls the SDK's constrained signer
outside the Mesh runtime lock. Its foreground prompt shows the exact quote,
payer, destination, reference, amount and expiry. Mesh `credit_wallet_commit`
independently verifies the complete Ed25519-signed wire, sole reserved payer,
reserved blockhash, exact amount and every account/program privilege. Only a
legacy System transfer or ATA CreateIdempotent plus SPL TransferChecked is
accepted. Reference/program/mint/payer aliases, extras, changed recipients and
lookup tables are rejected. Quote expiry is checked again immediately before
committing the signed packet. A single bounded pinned-height read also rejects a
hash that expired while the prompt was open, leaving the unsigned plan available
for refresh. RPC failure cannot promote that packet to a submitted state.

The signed wire is immutable and durably committed with SQLite FULL synchronous
mode and the existing encrypted-wallet CAS before submission. The issuance
request containing that exact signature is also committed before the first
`sendTransaction`. A crash between those commits is repaired from the signed
packet. Concurrent CAS losers cannot submit an alternate packet. Native
`credit_wallet_submit` never calls the signer. It sends only the stored bytes,
with base64 encoding, preflight enabled at confirmed commitment, zero provider
retries and the reserved minimum context slot. Returned signatures must equal
the authenticated packet's first signature. An acknowledgment is not finality.

Timeouts, resets, RPC errors, wrong IDs and changed returned signatures leave
the durable packet intact. Recovery before expiry can replay only those exact
bytes. At or after quote expiry **no submission occurs**, even for an identical
packet: the first send may have been interrupted before reaching a provider.
The original signature remains attached so issuer finality/replay can recover
an earlier in-window payment. The issuer remains responsible for finalized
chain execution, block time, amount and single-use payment claims. Neither
negative RPC observations nor blockhash expiry authorizes a fresh signature
for the same purchase. Signed unresolved purchases block implicit replacement.

Record metadata is one byte: 0 reserved/fetching, 1 prepared unsigned,
2 signed/uncertain, 3 RPC acknowledged. The sealed payload contains six bounded
parts: raw authenticated CQT224, hash (empty only in state 0), context slot U64BE,
last-valid height U64BE, signed wire (empty before state 2), and payer32.
Unsigned expired plans can be left in history when the user explicitly starts
a distinct purchase. States 2/3 remain recoverable and block Buy again.

Private prepare output is counted `[014d5750, purchase_id, status, quote224,
hash32, signature]`, with status 0 requiring native signing and 1 reusing a
committed packet. Commit/submit return safe counted `[014d5752, purchase_id,
status, signature64]`, where status 0 means journaled/unknown and 1 means an RPC
acknowledged the signature. Only that safe result reaches JavaScript. Public
host operations are Pay (5) and Recover (6), each taking `[database,purchase_id]`;
Recover does not require the seed or SDK address to remain accessible.

`packages/wallet-core/tests/network.test.mjs` compiles actual Mesh, restarts its
process for every operation using a persistent private StorageKey.file and
SQLite journal, signs with the real SDK, and executes System/SPL/ATA SBF in
LiteSVM. It checks durable state before the fake RPC sees a packet, accepted
but disconnected sends, wrong IDs/signatures, concurrent commits and retries,
changed signed fields and payer, unsigned stale-hash refresh/stale-prompt
rejection, no signed refresh or post-expiry broadcast, same-bank duplicate
rejection, and post-expiry finalization of 200 credits from earlier payments.
This test uses public fixture seeds and owned loopback providers only. The
separate HTTP proof exercises the production issuer service, database, key
lifecycle and hard restart with real blind issuance.
