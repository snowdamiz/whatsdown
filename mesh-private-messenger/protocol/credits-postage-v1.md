# Account postage and opaque delivery batches

Postage buys one message request to one recipient account, covering its complete
ordered active device set (one to eight devices). The server enqueues every
envelope and consumes one exact credit frame in a single transaction. A current
secret contact address remains free. A public or retired address observes the
recipient's published level: 0, 1, 5 or 25 credits. Nonzero postage is opt-in via
`MORSE_PAID_INBOX_POSTAGE`; the default is disabled.

This extension requires a newer client to send a paid public message request.
Ordinary delivery returns 402 before enqueueing when payment is required. It
does not spend credits, prompt automatically, or grant a reusable sender pass.

## Recipient policy

`PPY` is 141 bytes, all integers unsigned big-endian:

| Field | Bytes |
| --- | ---: |
| `01 50 50 59` | 4 |
| Account ID / publishing device ID | 32 / 16 |
| Monotonic policy revision / expected device-set revision | 8 / 8 |
| Level / issue time in milliseconds | 1 / 8 |
| Account authorization signature | 64 |

The account authorization key signs
`morse-credit-postage-policy-v1 || PPY-with-zero-signature`. The core authenticates
the immutable registered account and active publisher, serializes publication,
and rejects stale timestamps, revision gaps and conflicting retries. An exact
historical retry remains identifiable after later changes. Successful publication
mirrors the same independently signed extension 3 into every active bundle and
appends the new device set to transparency. Registration strips untrusted caller
extension 3 and restores the stored policy; bundle extensions 1 and 2 survive.

`POST /v1/credits/postage-policy` accepts raw PPY and returns an eight-byte
device-set revision (201 new, 200 exact retry). This acknowledgement is not
witnessed admission. Clients continue showing the admitted policy until a fresh
quorum-witnessed device set verifies it. Linked devices without the account key
have read-only policy access. Publication is limited to eight new revisions per
account per hour; exact retries do not consume that allowance.

Native publication persists the exact signed PPY in an authenticated local
`postage-policy-intent/v1` record before transport. Reopening the same pending
change returns the original signature and issue time. A conflicting level on
the same witnessed revision is refused; a later witnessed device-set state can
resolve or supersede the intent. The record uses atomic compare-and-swap and
binds account, publisher, service key and issuer origin. Erasing the account
removes it with the other local records.

The counted native `MPV` v2 view (`02 4d 50 56`) contains account ID, admitted
policy revision, admitted device-set revision, admitted level, and an optional
counted `MPP` pending plan. The UI restores that plan after restart while still
displaying the admitted level. A plan is pending only against the same witnessed
device-set revision. The typed native publication call accepts the app database,
expected policy revision, expected device-set revision and selected level. It
loads the saved signed PPY; JavaScript supplies no URL or HTTP body. If fresh
witnessed state already includes the requested level at that revision or later,
publication returns locally without another HTTP attempt.

## Request and response privacy

`PSB` is `01 50 53 42 || count:u8 || (SED-length:u32 || SED)* || PCB`.
It contains one to eight existing canonical SED frames and one fixed 16,436-byte
credit box. Maximum PSB size is 541,865 bytes. Existing chat and HPKE bounds do
not change. The public AEAD plaintext limit is independently 128 KiB, allowing
the complete canonical 65,606-byte outer frame to become a 65,674-byte SED.

The batch digest is SHA-256 of `morse-credit-postage-batch-v1`, count, and each
ordered SED length and SHA-256. Duplicate envelopes are rejected. PCB is
`01 50 43 42 || HPKE`; its 16,384-byte plaintext contains `01 50 43 50`, a u16
CAP length, the exact CAP and canonical zero padding. HPKE info is
`morse-credit-postage-box-v1`; AAD is the pinned core transport public key and
batch digest. The edge learns no CAP, recipient policy, token or reply key.

The CAP body is PST188 (`01 50 53 54`): nonce32, recipient account32,
policy revision8, device-set revision8, device-set SHA-25632, batch digest32,
reply public key32 and action expiry8. The kind-3 action binds its exact bytes.
The core authenticates the current full snapshot, account price, complete
canonical device fanout, each actual envelope and credit signature. Any stale
snapshot, spent token, duplicate enqueue or failed final insert rolls back all
tokens and all devices. The fixed signed PDR86 result binds the same account,
digest, revisions, enqueued count and charged count.

`PCR` is exactly 564 bytes: `01 50 43 52 || HPKE`. Its 512-byte plaintext contains
`01 50 52 50`, a u16 length, canonical CAR or CCR, and zero padding. HPKE info is
`morse-credit-postage-reply-v1`; AAD is the saved reply public key and batch
digest. HPKE base mode alone does not authenticate the core: native completion
must verify the inner pinned-core signature and exact saved action/frame/result.
The core always takes the reply key from the CRD-bound saved request.

Public `POST /v1/credits/postage` and `/v1/credits/postage/reconcile` carry PWR
with distinct work labels `mesh-msg/v1/work/postage` and
`mesh-msg/v1/work/postage/reconcile`. Both return only opaque PCR on success
(201 new effect, 200 retry/recovery). The edge strips PWR before its authenticated
private core hop. Private paths are `/internal/credits/postage` and
`/internal/credits/postage/reconcile`. Diagnostics contain no decrypted CAP or
receipt. Generic plaintext credit recovery refuses postage on the native boundary.

## Durable native ownership

Native candidate selection links the refused envelope to one persisted outgoing
logical message and recipient conversation. Fresh witnessed device state selects
its exact ordered fanout; mixed, ambiguous or incomplete fanout fails before
reservation. Native code stores the original ciphertexts, snapshot, reply-key
handle and exact batch before returning network bytes. Unknown outcomes retain
that state. Ordinary outbox paging suppresses owned envelopes across restarts.
A pinned CAR acknowledges exactly those envelopes; only a pinned CCR releases
them back to ordinary delivery. Generic HTTP success never completes a spend.

Native preview is read-only and supplies the price, purpose, balance, IDs and an
opaque nonce. New nonces contain issue-time8 plus 192 random bits. Missing-material
prepare rejects a preview older than fifteen minutes; exact persisted retries,
including legacy nonces, bypass that age check. A durable clock floor prevents
retired, pruned intents from reopening after clock rollback. An expired preview
requires a fresh preview and explicit confirmation, never an automatic new spend.

At most sixteen unresolved postage batches retain their ciphertexts. Terminal
material compacts after acknowledgement or cancellation, preserving the exact
request, reply handle and receipt through the shared retention policy. Inventory
shows unresolved rows and at most 128 recent terminal rows; omitted history can
still recover by its saved nonce during that window. Shared cleanup examines at
most 64 token/reservation records per pass and never evicts unresolved spends.

`credit_postage_continue` accepts only the app database and saved nonce. Mesh
recovers the journal, selects normal or expired reconciliation, makes a bounded
native HTTPS request to the immutable issuer origin, and verifies the encrypted
reply before applying it. Redirects are disabled, the response is bounded to
564 bytes, and account/configuration fences run before applying the reply.
Terminal retries remain local. Policy publication uses the same transport with
an eight-byte acknowledgement bound. Optional issuer CA trust follows the
immutable exact-origin resource in `packages/mobile-core/ISSUER_TLS.md`.

Run `scripts/prove-postage-native-https.py` for the owned HTTPS peer plus real
Mesh journals, policy signing, hostile replies, exact batch retries, and
receipt-commit/outbox-ack recovery. Rendered tests disable JavaScript postage
HTTP and cover both paid-message and policy recovery across a UI restart.

Local two-core PostgreSQL tests prove the shared-token race, rollback on a failed
eighth enqueue, exact retry after policy changes and opaque reconciliation, with
core A reached through an actual compiled privacy edge. Native tests additionally
cover the maximum outer frame, receipt-commit/outbox-ack crash, fixed encrypted
replies, cancellation ownership, bounded history and clock rollback. These are
local protocol proofs, not a production deployment or external security review.
