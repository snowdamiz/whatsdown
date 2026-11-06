# Consumed prekey retention

With cleanup explicitly enabled, migration 030 and `Storage.Prekeys.prune_consumed_prekeys` remove session-timing and claim-correlation fields after the exact response is no longer usable. This policy does not introduce a shorter retry TTL.

A claim's inclusive retry boundary is the earlier of the signed PKB `expires_at` and its account-signed device credential's `expires_at`. The server retains and replays the exact response through that millisecond, including a saved older base after renewal. Once that boundary has passed, the exact old OTQ returns 404; an expired current base cannot allocate another key. The 5-minute request-work validity and 8-second HTTP timeout are not reservation lifetimes. A fresh work stamp can wrap the same durable OTQ after a transport failure.

Current mobile-generated credentials initially last 365 days. There is no universal maximum signed lifetime in the protocol, so there is no universal numeric retention TTL. A valid custom future expiry can retain claim material longer. A checked malformed, missing or unverifiable historical response remains unpruned because no authenticated deletion boundary is available.

Cleanup moves the exact `(account_id, device_id, prekey_id, public_key, last_resort)` into `messenger_retired_prekeys`, then deletes the original consumed row in the same transaction. The retired table contains no creation/consumption/cleanup timestamp, claim/reservation hash, base-bundle hash, response or expiry. Identical signed OTB replay still returns an unchanged active set; different bytes for a retired ID still conflict, and no retired key becomes active. Arbitrary gaps in IDs remain valid; no monotonic floor is imposed. Retired last-resort IDs retain their equality and ordering behavior. Device revocation deletes both tables, and physical device removal cascades through their foreign keys.

The exact retired-ID/key mapping remains linked to the device and can grow until device removal. This is not total metadata erasure or a bounded total row count. Arbitrary published IDs and required exact key-equality conflict behavior cannot be represented faithfully by a simple maximum ID or a bounded set of ranges. Expired reservation hashes are removed, so an expired reservation is no longer globally reserved against a different future OTQ; the unchanged expired OTQ can never consume again.

Deletion happens on a successful eligible sweep; a backlog, busy device or stopped worker can extend retention. Database backups/WAL and operating-system copies require their own retention controls.

The worker verifies/backfills or retires at most 128 rows per transaction. It obtains the same device lock used by publication, while claims hold a share lock. Busy devices are skipped. Legacy 009 base markers are reconstructed and verified before using their signed horizon; checked failures are left unpruned without an immediate rescheduling loop. Rows predating claim identifiers, and superseded reusable keys, contain no recoverable exact-claim material and can be moved directly to timestamp-free retired records.

A singleton nondecreasing floor records only the greatest retired signed horizon plus 1 ms, never the wall-clock cleanup time. It advances in the retirement transaction. Claims and cleanup use the later of the database clock and this floor, preventing a backward clock from resurrecting a retired base. Maximum-U64 expiry cannot enter the strictly-expired retirement branch. The scheduler maps work already due under the floor to the current wall clock, and caps future wakeups to one hour without shortening the signed retention boundary.

When cleanup is enabled, new consumption and reusable-key retirement register durable directory wakeups before commit. Registration failure rolls the database mutation back; the same OTQ can then retry exactly. Existing scheduled maintenance and the local retention loop run the bounded cleanup, and startup re-registers pending deadlines.

Cleanup activation is **off by default**. `MESSENGER_PREKEY_RETENTION` accepts only `off` or `on`; absence means `off`, while an empty or malformed explicit value fails configuration validation. With cleanup off, claims/publications do not register cleanup-only jobs, the scheduler omits prekey deadlines, and bounded cleanup returns zero without backfilling or deleting. Claims still enforce signed expiry and any already-persisted rollback floor; retired-ID publication protections remain active.

For rollout, first apply migration 030 and deploy the new server code with cleanup off. Drain **every old writer** before setting `MESSENGER_PREKEY_RETENTION=on` on the cleanup-capable processes. An old writer knows neither the retired table nor the expired-base/rollback guards: replaying an old signed OTB after retirement can reinsert the old key. Mixed old/new writers are therefore unsupported after activation. Reverting the flag to off does not make old writers safe again; rollback to an old writer requires backporting these protections. No live activation is performed by the proof scripts.

The Cloudflare Directory container forwards the Worker binding
`MESSENGER_PREKEY_RETENTION` unchanged, defaulting to `off` when absent. Configure
that binding for the backend deployment; changing only a local shell variable
does not change a deployed Worker. The Mesh service rejects empty or malformed
values. Activate the new server instances together after draining the old
writers so new claims also register durable cleanup wakeups. Neither migration
030 nor the ordinary build command activates cleanup.

Qualification is local PostgreSQL and an owned HTTP scheduler fixture, with synthetic accounts only. No live deployment, credential, provider, native app artifact or public protocol wire changes are required. Apply all migrations through 030 before running this service version. Historical archives and migration 029 remain unchanged.

Reproduce against a clean checkout with PostgreSQL 17 tools (`PG_BIN` overrides their installation directory) and explicitly selected qualified Mesh artifacts:

```sh
python3 scripts/prove-prekey-retention.py \
  --compiler /absolute/path/to/meshc \
  --runtime /absolute/path/to/libmesh_rt.a \
  --test-runtime /absolute/path/to/libmesh_test_rt.a \
  --output /absolute/path/to/new-evidence-directory
```

The runner freezes declared source dependencies, applies migrations to fresh owned loopback databases, runs focused tests sequentially, builds the scheduler fixture outside the service source, and executes its exact-replay stage in a separate process. It stops and removes every temporary database on success or failure. `--test` can select additional directory test files; `--jobs-only` runs only the wakeup/restart fixture. Output directories must be new, so earlier failed attempts are preserved.

The retention-positive runner explicitly sets `MESSENGER_PREKEY_RETENTION=on` only in its owned child processes. To check the default-off rollout separately:

```sh
python3 scripts/prove-prekey-rollout.py \
  --compiler /absolute/path/to/meshc \
  --runtime /absolute/path/to/libmesh_rt.a \
  --test-runtime /absolute/path/to/libmesh_test_rt.a \
  --output /absolute/path/to/new-rollout-evidence
```

That fixture supplies an owned scheduler which always returns 503; absent/off cleanup must still allow claims and publications and make zero scheduler requests. It restarts with explicit activation, verifies bounded retirement and exact modern replay, and refuses malformed explicit values. Optional `--legacy-prekeys PATH --legacy-prekeys-sha256 SHA --legacy-workers PATH --legacy-workers-sha256 SHA` inputs exercise the captured old storage implementation over the same current protocol closure before and after activation. They are never default dependencies and do not claim an entire historical service build. The expected old-writer resurrection after activation demonstrates why the deployment prerequisite cannot be waived.

CI runs both proof scripts against the compiler and runtime archives built in
that job. The general M9 directory test command also enables cleanup for its
positive retention cases; this setting is scoped to that command and does not
activate the service started later by M9 or any deployment. The dedicated rollout
proof checks absent/off behavior independently.
