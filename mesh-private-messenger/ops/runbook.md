# Directory and Delivery Runbook

The service is development-only until every release gate in the implementation plan is satisfied.

## Start and verify

1. Set `MESSENGER_DATABASE_URL`, `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, `MESSENGER_DELIVERY_SEALING_SEED_HEX`, and a high-entropy `MESSENGER_DELIVERY_INTERNAL_TOKEN` through the deployment secret store. Provision the same token on the privacy edge.
2. Apply `services/directory-delivery/migrations/*.sql` in numeric order with `psql -v ON_ERROR_STOP=1`.
3. Build and start `services/directory-delivery`; route HTTP traffic to `MESSENGER_PORT` and WebSocket upgrades for `/v1/mailbox/stream` to `MESSENGER_STREAM_PORT` (default 18090). Terminate TLS at the trusted proxy and preserve the `Authorization` header without logging it.
4. Require `GET /health` to return success before routing traffic.
5. Run `scripts/prove-m9.sh` against an isolated PostgreSQL instance before promotion.

Never place signing seeds, mailbox capabilities, envelope IDs, account IDs, device IDs, or message data in command lines, logs, metrics, or incident tickets.

## Foreground mailbox stream

The native client supplies a device-signed version-2 `FET` request as hex in
the upgrade header `Authorization: MeshMailbox <frame>` (244 characters). The
service verifies the Ed25519 signature against the signing key in the active,
unrevoked device credential registered for that mailbox, requires the signed
timestamp to be at most five minutes old and one minute ahead, and only then
limits upgrades to 60 per mailbox per minute. Rejected attempts never spend
the owner's budget. The published mailbox address is not a credential: it
authorizes deposits only. Credentials never go in the URL.

After joining its mailbox room, the client receives the text control event
`ready`, then `encrypted-wakeup` from committed outbox events. These events
contain no IDs or messages. Clients fetch and acknowledge canonical binary
batches over HTTP, drain all pending batches, and catch up on every reconnect.
The Mesh runtime supplies ping/pong liveness checks and closes failed room
writes. Configure proxy idle timeouts above its 30-second heartbeat interval.

Run one delivery process until Mesh node clustering is configured: room
broadcasts reach other processes only when those nodes are connected. Outbox
leases alone do not distribute notifications to every service replica.

The live regression uses an isolated migrated database and a service with
`MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled`, HTTP port 18986 and stream
port 18990. Build `clients/mesh-cli` first: the test registers real devices and
obtains signed frames through its `stream-fixture` role instead of
reimplementing protocol codecs. Run
`node --test services/directory-delivery/tests/stream-live.test.mjs` from
`mesh-private-messenger`. Override `MESSENGER_STREAM_TEST_HTTP`,
`MESSENGER_STREAM_TEST_WS`, and `MESSENGER_CLI` for different proof ports or
binaries. Never run this fixture against a production service.

The public direct-delivery route is disabled unless `MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled`; never set that compatibility flag in production. Network policy must also restrict `/internal/v1/envelopes/sealed` to the privacy edge. The bearer token is required even on a private network and must be rotated as one coordinated edge/core secret.

## Push delivery adapter

Push is disabled by default. Use `MESSENGER_PUSH_MODE=local-fake` only for integration tests; set `MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE=false` to simulate a retryable provider outage. Production deployments use `MESSENGER_PUSH_MODE=broker` with `MESSENGER_PUSH_BROKER_URL` and the matching `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`. Operate the broker as documented in [`../services/push-broker/README.md`](../services/push-broker/README.md), and distribute only the public key derived from its secret X25519 seed to mobile clients.

The broker sends a data-only wake with `contentAvailable=true`, `priority=normal`, and `data.kind=encrypted-wakeup`. The local fake adapter retains its generic test payload. Do not add usernames, mailbox identifiers, envelope identifiers, senders, or message content. Clients decrypt locally to format ordinary and mention alerts. Install the native background-task client before switching the broker payload; older clients cannot display data-only wakes. Keep the broker endpoint private and treat a `204` response as durable queue acceptance, not provider delivery.

## Transparency log capacity

`PUT /v1/devices/register` and `POST /v1/devices/revoke` answer `507` when the
transparency log has no room for the transition; nothing is committed. New
accounts are refused from 3,584 entries and every transition from 4,096 (see
[key transparency](../protocol/key-transparency-v1.md#proof-representation-and-its-ceiling)).
Lookups, mailbox access, and messaging are unaffected. Alert on the entry count
well before 3,584: reaching it closes registration for the deployment, and the
reserved 512 entries are what let existing accounts keep revoking devices.

## Anonymous request cost

- `PUT /v1/devices/register`, `POST /v1/devices/resolve` and `POST /v1/prekeys/bundle` require proof of work (`PWR`, see `protocol/sealed-delivery-v1.md`). `MESSENGER_ABUSE_DIFFICULTY` (1 to 24, default 16) now governs `directory-delivery` as well as `privacy-edge`; the service refuses to start outside that range. It must equal the difficulty in the signed native configuration shipped to devices: a device configured lower is refused with `429`, one configured higher simply does more work than needed. Change both together.
- `400` means a malformed frame (a client older than this change). A sustained `429` rate on these routes means clients and service disagree on the difficulty, or clocks have drifted more than the one-minute allowance.
- `messenger_rate_limits` also records each spent stamp. The scheduled job purges rows older than a day, 128 per run. Before this change the table was never purged; the first runs after upgrade clear that backlog.

## One-time prekey pools

- Devices publish canonical, device-signed batches with `POST /v1/prekeys/one-time/batch`. A new batch returns `201`, an exact replay or empty recovery query returns `200`, an invalid signature returns `403`, an ID/key conflict returns `409`, and exceeding the 64 available-key cap returns `429`. Every `200`/`201` body is the canonical `OTA` list of exactly the server's active IDs after the transaction.
- Clients claim with a canonical 100-byte `POST /v1/prekeys/bundle` body bound to the SHA-256 hash of the verified base bundle and a random 16-byte Mesh-persisted reservation ID. The response is `Cache-Control: no-store`; retrying the same reservation returns the exact same one-time key without consuming another. Success returns a canonical prekey bundle. A missing, revoked, or stale target returns `404`. An exhausted pool returns the device's reusable last-resort key in the one-time slot, so exhaustion no longer blocks new sessions; `409` remains only for a device that never published one (a client older than `OTB` version 2).
- Every `OTB` publication repeats the device's current last-resort key. A higher identifier retires the previous key; a lower one, or a changed key under a known identifier, returns `409`. The key never appears in an `OTA` list and does not count against the 64-key cap.
- Never retry a `409` exhaustion in a tight loop. Back off, preserve the verified base bundle, and let the target replenish its pool. Alert only on aggregate last-resort claim and replenishment rates: a sustained last-resort rate means pools are being drained faster than devices refill them. Account, device, and prekey IDs must not be metric labels.
- Registration extracts its submitted one-time prekey into the pool atomically. Publication is idempotent, but consumed IDs are permanent tombstones and must never be republished with different key bytes. Revocation deletes the device's entire pool.
- Mobile clients reconcile each `OTA` body before generating replacements. They retain at most 64 non-active secrets for delayed initial messages and at most 64 active secrets. If the retired bound is full, replenishment evicts the oldest retired secrets atomically; more than 64 claimed-but-undelivered initial messages can therefore become undecryptable and require incident investigation.
- During upgrade, a legacy singleton secret is opened with its historical context, resealed under its per-ID context, and held provisionally active until `OTA` reports whether the server still has it. An already-consumed singleton becomes retired without permitting its ID to be reused.
- Investigate sustained `429` responses before changing limits. The 64-key cap is a protocol and abuse-control boundary, not a deployment tuning knob.

## Operate

- Treat PostgreSQL as the durability boundary. Do not acknowledge a submission before its transaction commits.
- Alert on health-check failure, sustained mailbox/rate-limit rejection, exhausted outbox retries, expired outbox leases, and database pool exhaustion. Labels must stay aggregate and must not contain delivery identifiers.
- Scale workers only within the configured limits. Lease ownership and expiry provide crash recovery; do not manually edit active leases.
- Retention deletes expired envelopes in bounded batches. Investigate a growing expired backlog before increasing batch sizes.
- Back up PostgreSQL with encryption and tested point-in-time recovery. Restore into isolation, run migrations, then execute the M8 and M9 proofs before accepting traffic.

## Incident response

1. Stop the affected ingress path when confidentiality, integrity, or authentication may be compromised; preserve encrypted database and service-log evidence.
2. Record UTC times, deployed revisions, affected components, and aggregate impact. Keep user content and stable delivery identifiers out of the incident record.
3. Rotate exposed service credentials and signing material through the deployment secret store. A compromised user/device key follows the signed revocation flow; it is not repaired by a server-side database edit.
4. Patch on a review branch, run the relevant milestone proofs, obtain independent retest for cryptographic/protocol findings, and deploy with rollback protection.
5. Notify affected users and publish a security advisory when disclosure is safe. Record follow-up tests and retention-safe evidence.

## Shutdown and rollback

Send the normal termination signal and wait for the HTTP server, workers, and database pool to close. A rollback may use only a revision compatible with the persisted versions listed in [`../protocol/compatibility-matrix.md`](../protocol/compatibility-matrix.md); otherwise restore forward with a new migration. Never roll back transparency checkpoints or snapshot counters.
