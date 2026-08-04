# Directory and Delivery Runbook

The service is development-only until every release gate in the implementation plan is satisfied.

## Start and verify

1. Set `MESSENGER_DATABASE_URL`, `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, `MESSENGER_DELIVERY_SEALING_SEED_HEX`, and a high-entropy `MESSENGER_DELIVERY_INTERNAL_TOKEN` through the deployment secret store. Provision the same token on the privacy edge.
2. Apply `services/directory-delivery/migrations/*.sql` in numeric order with `psql -v ON_ERROR_STOP=1`.
3. Build and start `services/directory-delivery`; expose only its configured HTTP port.
4. Require `GET /health` to return success before routing traffic.
5. Run `scripts/prove-m9.sh` against an isolated PostgreSQL instance before promotion.

Never place signing seeds, mailbox capabilities, envelope IDs, account IDs, device IDs, or message data in command lines, logs, metrics, or incident tickets.

The public direct-delivery route is disabled unless `MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled`; never set that compatibility flag in production. Network policy must also restrict `/internal/v1/envelopes/sealed` to the privacy edge. The bearer token is required even on a private network and must be rotated as one coordinated edge/core secret.

## Push delivery adapter

Push is disabled by default. Use `MESSENGER_PUSH_MODE=local-fake` only for integration tests; set `MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE=false` to simulate a retryable provider outage. Production deployments use `MESSENGER_PUSH_MODE=broker` with `MESSENGER_PUSH_BROKER_URL` and the matching `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`. Operate the broker as documented in [`../services/push-broker/README.md`](../services/push-broker/README.md), and distribute only the public key derived from its secret X25519 seed to mobile clients.

Both adapters send only the generic body `New encrypted activity` and the data field `kind=encrypted-wakeup`. Do not add usernames, mailbox identifiers, envelope identifiers, senders, or message content. Keep the broker endpoint private and treat a `204` response as durable queue acceptance, not provider delivery.

## One-time prekey pools

- Devices publish canonical, device-signed batches with `POST /v1/prekeys/one-time/batch`. A new batch returns `201`, an exact replay or empty recovery query returns `200`, an invalid signature returns `403`, an ID/key conflict returns `409`, and exceeding the 64 available-key cap returns `429`. Every `200`/`201` body is the canonical `OTA` list of exactly the server's active IDs after the transaction.
- Clients claim with a canonical 100-byte `POST /v1/prekeys/bundle` body bound to the SHA-256 hash of the verified base bundle and a random 16-byte Mesh-persisted reservation ID. The response is `Cache-Control: no-store`; retrying the same reservation returns the exact same one-time key without consuming another. Success returns a canonical prekey bundle. A missing, revoked, or stale target returns `404`; an exhausted pool returns `409`.
- Never retry exhaustion in a tight loop. Back off, preserve the verified base bundle, and let the target replenish its pool. Alert only on aggregate exhaustion and replenishment rates; account, device, and prekey IDs must not be metric labels.
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
