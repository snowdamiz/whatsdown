# Core credit redemption

Migration `018_credits.sql` adds the shared spent set, immutable action holds and
issuer admission records. Issuance quotes, payments and deposit addresses belong
in the separate issuer database and are not stored here.

`POST /internal/credits/redeem` uses `MESSENGER_DELIVERY_INTERNAL_TOKEN` and accepts
JSON with `schema_version: 1` plus lowercase hex `action`, `request_body` and
`frame`. The action is the canonical 117-byte `Credits.Action` descriptor; the
body is at most 65,536 bytes and the frame at most 22,694 bytes. The core derives
the exact price from bounded action parameters and trusted mailbox/difficulty
state. Caller-supplied issuer keys or prices grant no authority.

The descriptor binds a 32-byte operation nonce, target, kind, expiry, quantity and
SHA-256 of the exact request body. New actions must expire within 15 minutes.
Keep the exact descriptor, body and CRD frame until the outcome is known. A new
hold returns 201; an exact retry returns 200 and the same hold, including its
`held`, `expired` or `consumed` state. Reusing the operation identity with another
descriptor or payment frame returns 409. Redemption verifies all tokens and
inserts all nullifiers plus the hold in one transaction. One spent token rolls
back every fresh token and the hold.

## Issuer authority

`POST /v1/credits/issuer` is an account-free public discovery route. Its body is
the canonical 13-byte `Credits.Discovery` query: `01 43 49 4b`, purpose byte
(`0` live or `1` test), and the client's previous global v2 tree size as u64
big-endian. Purpose must match this core's configured credit purpose. A ready
response is raw canonical `TransparencyEvidence`, `application/octet-stream`,
with `Cache-Control: no-store`. Clients must independently verify their pinned
service key, witnesses, consistency cursor and issuer admission before purchase.

Discovery chooses only the current epoch's durably admitted key. It reads the
latest fresh stored checkpoint with a pinned-witness majority that includes that
key's leaf, verifies the service signature and each counted witness (including
C2SP's signed timestamp), and constructs exact inclusion and prefix-consistency
proofs from retained nodes. It never signs a checkpoint or manufactures a
witness. A newer checkpoint awaiting witnesses does not hide a still-fresh ready
checkpoint. Malformed or wrong-purpose requests return 400; a previous tree size
ahead of the ready checkpoint returns 409; missing current admission or fresh
quorum returns 503. Errors do not return a substitute key or mutate admission.

Publication and admission use the separate
`MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN`. An absent or invalid configured token
fails closed. This credential must not be given to redeeming services.

- `POST /internal/credits/issuers/announce` accepts `{ "leaf": "<hex>" }`. It
  publishes a canonical current/previous epoch issuer leaf to the active
  version-2 transparency log. Epoch/purpose and global key identity are immutable
  before append, so an identical retry cannot add another issuer leaf.
  The canonical 387-byte version-2 `IKY` leaf pins both the blind RSA SPKI and a
  separate Ed25519 quote-signing public key. Raw leaf bytes remain immutable;
  keeping the same RSA key cannot replace the quote signer on retry or admission.
  Legacy unsigned version-1 issuer leaves are rejected.
- `POST /internal/credits/issuers/admit` accepts `{ "evidence": "<hex>" }`.
  Evidence must include that exact published leaf, a fresh core-signed checkpoint,
  consistency from the core admission cursor, and a strict majority of the
  server registry's pinned witnesses. Only then can the key verify redemptions.
- `POST /internal/credits/issuers/evidence` accepts the same raw `CIK` query as
  public discovery, but may return proof for the current announced key before
  admission. It still requires a fresh stored witness quorum, and never changes
  admission or the cursor. This is an issuer lifecycle endpoint, not a public
  purchase endpoint.
- `GET /internal/credits/issuers/cursor` returns the raw encoded core admission
  checkpoint, or an empty 200 response before the first admission. Fetch its tree
  size and request consistency from that exact size; the query's `previous_size`
  is never overloaded. Concurrent admissions may require a fresh cursor and
  evidence retry. Both endpoints require the distinct issuer credential and
  return binary `no-store` responses.

`MESSENGER_CREDITS_PURPOSE` is `live` by default or explicitly `test`. A witness
signature attests log consistency; it does not authorize an issuer to mint.
Publication authorization and the server-owned pinned registry provide those
separate boundaries. Redemption never trusts a client's key directory.

## Completing an action

A successful redemption reserves a hold; it does not deliver an extra.
`Storage.Credits.consume_credit_hold_on_connection` must run inside the same
`Repo.transaction` as the real database action, or insertion of a durable service
effect record that can be recovered after a lost response. It locks the hold,
checks the exact descriptor and a nonzero 32-byte effect ID, and returns
`HoldApplied` or `HoldAlreadyApplied`. Execute the effect only for `HoldApplied`;
recover its stored result for `HoldAlreadyApplied`. A failed action must roll back
the transaction. A different effect ID cannot consume the same hold.

Adapters must also authenticate the target and compare actual inputs with the
descriptor: in particular, actual attachment size must match the charged size.
There is no one-shot HTTP consume endpoint. Each concrete adapter must apply
its effect and signed completion in that same transaction.

`POST /v1/credits/retention` implements the mailbox parking adapter. It accepts
canonical `Credits.ActionWire` CAP bytes containing the exact action, a
device-signed `Credits.Retention` RET body, and the CRD frame. Only the active,
unrevoked device registered for that mailbox can authorize a new grant. The
request signs its mailbox hash, unique operation nonce, requested total days,
action expiry and freshness timestamp. Days must be 32–180; the server derives
the price, 10 credits per started extra 30 days beyond the free 31 days.

Migration 025 adds a separate paid storage deadline. One transaction authenticates
the owner, redeems the entire frame, consumes its hold, extends the live parking
deadline, and stores an immutable core-signed CAR completion receipt. A failure
at any point rolls back the spends, hold and effect together. The deadline is
`max(existing_paid_until, applied_at * 1000 + requested_days * 86400000)`, bounded
by 180 days from the trusted application time. Live unacknowledged envelopes and
future deposits use the greater of that paid deadline and their original TTL.
Expired envelopes are never resurrected; acknowledgements retain their existing
short deletion policy. The original outer expiration and ciphertext are never
rewritten by a grant. The hold and receipt survive through the paid horizon plus
seven recovery days, or the original token retention deadline if later.

The response is raw CAR: 201 for a new completed effect, 200 for the exact cached
receipt. The core signature binds the exact action hash, CRD frame hash, operation
ID, stable effect ID, application time and RTE result. A repeated request recovers
the same bytes even after expiry or owner revocation; a changed intent or frame
conflicts. Clients must verify their pinned core key and exact durably reserved
submission before completing token custody. An edge's ordinary 200 is no proof.

`MORSE_PAID_RETENTION` defaults to `off`. The route remains disabled until joint
client tests prove signed receipt completion, acceptance of retained original
envelopes, and custody of replaced decryption bundles through the paid horizon.
Enabling server storage alone would leave old first messages undecryptable after
the free path's 35-day bundle grace period.

## Retention and proof

`POST /v1/credits/signup` accepts CAP with a canonical PSU registration body.
It charges 20 credits only when the server's current signup difficulty exceeds
its configured base. `MESSENGER_SIGNUP_DIFFICULTY` falls back to
`MESSENGER_ABUSE_DIFFICULTY`; the dedicated value applies only to registration,
its signed policy and this price, preserving lookup and prekey work. `MORSE_PAID_SIGNUP` defaults to `off`. One transaction
redeems the tokens, registers the actual device/credentials, appends its
transparency entry and saves a signed CAR containing the account and exact
entry hash. The account lock rejects renewals, already registered accounts and
racing free registrations without charging. A failed effect rolls everything
back; an exact completed retry returns the original receipt even after a price
change or expiry. The existing free registration path remains available.

`POST /v1/credits/signup-policy` accepts an empty body and returns an 88-byte
core-signed SPY policy with purpose, enabled state, base/current difficulty and
a 60-second validity window. It remains available when paid signup is disabled.
The native wallet verifies this policy before reserving signup credits; an
edge-supplied amount or difficulty cannot authorize a charge.

`POST /v1/credits/reconcile` accepts the exact saved CAP and remains available
when new paid actions are disabled. It returns the original CAR if completed,
or 425 while an incomplete action is unexpired. After expiry it can return a
172-byte signed CCR cancellation bound to the operation, exact action and CRD.
A transaction advisory lock shared with redemption and consumption makes it
wait for any pre-expiry effect. It never releases a consumed hold whose receipt
is missing, and rejects tokens spent by another action. Recovery verifies the
bearer frame against admitted keys without applying today's price.

For an existing unconsumed hold, the same transaction deletes its nullifiers
and hold and saves an immutable cancellation fence (migration027). Changed
intent/frame reuse conflicts. A never-submitted expired action receives a
deterministic stateless proof, preventing a bearer from filling the database
with invented expired nonces. Native custody retains the cancelled reservation
as terminal status2 and restores only tokens still reserved by that operation;
stale cancellation/completion responses cannot affect their next use. A plain
HTTP error, elapsed clock or unknown network outcome never releases tokens.

`python3 scripts/prove-credit-signup.py` runs these paths against real HTTP
cores and an owned PostgreSQL cluster. It proves price gating, rollback,
concurrent completion, recovery while a real registration effect is delayed
past expiry, released-token reuse and bounded cancellation retention. Native
signup/cancellation and edge proofs are separate; onboarding activation and
complete payment-to-signup UI dogfood remain to be connected.

`POST /internal/credits/prune`, authenticated with the issuer administrator
credential, accepts `{ "limit": 1..1000 }`. Each call deletes at most that many
expired nullifiers, unreferenced expired holds and cancellation fences. It uses the trusted
database clock, waits until each absolute `retain_until`, and never deletes
unexpired spends. The existing durable directory job and local retention worker
also prune at most 128 spends and 128 holds per run. A new redemption registers
its durable wakeup inside the spending transaction; registration failure rolls
the whole redemption back. Startup restores pending deadlines. A backlog stays
due until drained, and the next wakeup follows the earliest absolute retention
deadline. Issuer announcements and public raw issuer leaves remain retained.

The live proof starts and removes its own temporary PostgreSQL cluster, applies
the real migrations, and runs two independent core processes. It never resets a
shared database. Build the real service first, then run:

```sh
meshc build services/directory-delivery
CREDIT_TEST_PG_BIN=/path/to/postgres/bin node --test services/directory-delivery/tests/credits-live.test.mjs
```

`MESHC` and `CREDIT_CORE_BIN` can override the compiler and core executable. The
explicit live proof also runs `security/credits-effect.test.mpl`; it cannot be
silently skipped without PostgreSQL. It checks forced concurrent spend overlap,
all-token rollback, exact retries, server-owned prices, separate issuer authority,
witness admission and public discovery, independently compiled client evidence
verification, atomic effect recovery, raw leaf preservation, durable wakeup
registration before commit, scheduling-outage rollback and bounded automatic
retention. Existing retention/reset contracts run against another owned database
in the same disposable cluster. Its fresh tokens use proof-only generated RSA keys and published
Ed25519 test material, never deployment credentials.
