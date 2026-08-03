# Directory and Delivery Runbook

The service is development-only until every release gate in the implementation plan is satisfied.

## Start and verify

1. Set `MESSENGER_DATABASE_URL`, `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, and `MESSENGER_DELIVERY_SEALING_SEED_HEX` through the deployment secret store.
2. Apply `services/directory-delivery/migrations/*.sql` in numeric order with `psql -v ON_ERROR_STOP=1`.
3. Build and start `services/directory-delivery`; expose only its configured HTTP port.
4. Require `GET /health` to return success before routing traffic.
5. Run `scripts/prove-m9.sh` against an isolated PostgreSQL instance before promotion.

Never place signing seeds, mailbox capabilities, envelope IDs, account IDs, device IDs, or message data in command lines, logs, metrics, or incident tickets.

## Push delivery adapter

Push wake-up delivery currently uses a local fake adapter for integration testing. It does not register with or send to APNs, FCM, or another production provider. Set `MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE=false` to simulate a retryable provider outage; the default is available.

Every fake push contains only the generic body `New encrypted activity` and the data field `kind=encrypted-wakeup`. Do not add usernames, mailbox identifiers, envelope identifiers, senders, or message content. Production provider registration and adapters require a later implementation slice before release.

## One-time prekey pools

- Devices publish canonical, device-signed batches with `POST /v1/prekeys/one-time/batch`. A new batch returns `201`, an exact replay returns `200`, an invalid signature returns `403`, an ID/key conflict returns `409`, and exceeding the 64 available-key cap returns `429`.
- Clients claim with `GET /v1/prekeys/bundle?request=<hex>`, where `request` is the canonical 84-byte query bound to the SHA-256 hash of the verified base bundle. Success returns a canonical prekey bundle. A missing, revoked, or stale target returns `404`; an exhausted pool returns `409`.
- Never retry exhaustion in a tight loop. Back off, preserve the verified base bundle, and let the target replenish its pool. Alert only on aggregate exhaustion and replenishment rates; account, device, and prekey IDs must not be metric labels.
- Registration extracts its submitted one-time prekey into the pool atomically. Publication is idempotent, but consumed IDs are permanent tombstones and must never be republished with different key bytes. Revocation deletes the device's entire pool.
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
