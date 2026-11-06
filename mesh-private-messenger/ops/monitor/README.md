# Public log monitor

The Mesh CLI runs the same authenticated reader and fork verifiers as the
phone. It needs public release pins, a directory origin and durable local
storage. It has no service signing key, wallet, chain-writing authority or
account data. Local proofs cover its behavior; the published Mesh release,
reviewed deployment and live observation gates remain pending.

## Run

Build with the exact Mesh revision verified for the Morse release:

```sh
meshc build mesh-private-messenger/clients/mesh-cli --output ./mesh-cli
export MESSENGER_SECURITY_CONFIG="$(cat /path/to/security-config-v4.txt)"
export MESSENGER_BASE_URL=https://directory.example
export MORSE_MONITOR_STATE_PATH=/path/to/durable/monitor.sqlite
./mesh-cli monitor --log morse-main
```

Use the actual directory origin and release frame for the monitored log. The
frame pins its program, ring, log name, service key, witnesses and three to
eight distinct HTTPS RPC origins. Every poll randomly samples three and
requires two matching finalized responses. A registry response cannot install
trust. Do not set any signing-key or wallet environment variable for this
process.

The status page defaults to port 18100; `--port` changes it. `--once` performs
one bounded pass, prints a JSON report and exits 0 if healthy, 2 if degraded,
or 1 for a command/configuration/storage error. Repeated passes catch up in
batches of at most 32 anchors. The persistent service polls again fifteen
seconds after each completed pass. SIGTERM and SIGINT request graceful shutdown.

`MORSE_MONITOR_LOG_VERSION` defaults to `2` (RFC 6962). Set `1` to monitor a
separate legacy log using the legacy witness policy in the v4 frame. The
frame's program/ring/name must identify that legacy log. Versions and public
log identities have different state; they never reuse another log's cursor.

During an approved witness rotation, `MORSE_MONITOR_POLICY_FILES` may contain
up to fifteen additional v4 frame paths, separated by newlines. All must pin
the same public log and service. At least one complete policy must reach its
threshold; votes from different policies are never pooled. Restart to load
an approved change. A registry key change remains a warning until its original
baseline is restored or an explicitly installed policy approves the new key.

The existing services image includes `/app/mesh-cli`. `compose.yaml` builds
that image from the repository with `MORSE_REVISION` and `MESH_LANG_REVISION`
set to the exact verified commits. It runs as UID 65532, retains a named state
volume and exposes the page on host loopback. Supply the public environment
above and run `docker compose -f mesh-private-messenger/ops/monitor/compose.yaml up --build -d`.
Set `MORSE_MONITOR_LOG_NAME` for a different log. Additional policy files need
explicit read-only bind mounts at the paths listed in the environment. A TLS
reverse proxy can publish the status page; status requests only read the cache.

## Status and evidence

`GET /status` returns HTTP 200 only for a healthy report no older than two
minutes. It returns 503 while starting, degraded, stale or when the local clock
precedes the cached check. Responses are not cached. `/` renders that report.
`GET /evidence.frk` downloads the first verified fork; `/evidence-context`
downloads its canonical ACV3 observation context. Both return 404 before
evidence exists. Neither endpoint performs network reads or signing.

The cursor follows posting order, including rollbacks. An unresolved candidate
is saved before requesting proofs and cannot be replaced or cleared until
that exact posting is accepted. A missing retained cursor or hidden candidate
keeps the monitor degraded. The first fork and its observation context remain
immutable across restarts, policy changes and later healthy replies.

For WITNESS §4.3 acceptance, require a fresh healthy status with no issues and
complete catch-up from the retained observation baseline. The consistency
requirement covers every consecutive pair in posting order, matching §6.8;
verified prefix links establish consistency across the chain. It does not
require a separate proof request for every non-adjacent pair. A newly created
database starts at the oldest visible ring entry and cannot attest to earlier,
overwritten history. Establish its baseline before the observation window and
preserve it throughout that window. A replacement database cannot repair a
history gap or erase a prior incident for acceptance purposes.

F1 and F3 use authenticated anchor comparisons. For F2, a failed consistency
check starts a rotating scan of at most sixteen common-prefix leaves per pass.
The scan advances durably and requires two valid inclusion paths with different
leaves. Missing or malformed responses never become evidence. A directory that
withholds those paths can prevent proof completion; the inconsistency remains
visible. A fork halts cursor advancement and remains a permanent alert.

Cosign checks have their own durable queue, so a late cosign does not stall
consistency checks. Each pass rotates through up to 32 pending postings using
their original witness generations. The reservation is durable before reads;
unavailable old entries cannot repeatedly monopolize the batch. A threshold observed on-chain becomes `met`.
Below threshold after the inclusive 1,500-slot window becomes `missed`; an
overwritten entry whose threshold was never observed becomes `lost`. These
terminal counts persist. Pending, missed and lost observations are distinct
status issues. No pooling, implicit trust in registered keys or silent history
reset can make the monitor green.

Back up the SQLite database using SQLite's online backup API or stop the
monitor before copying the database and its WAL. Keep the original database
and downloaded evidence for incident review. Deleting the database loses
observed history; creating a new database is not a resolution of an incident.
ACV3 records an RPC observation, not a portable chain proof. A relay must
independently authenticate the referenced account/generation before filing.
The monitor currently emits service evidence without adding private-side
witness attestations and does not file a transaction or route external alerts.
Operators can alert on the cached HTTP status and retained issue codes.

## Local proof

```sh
meshc test mesh-private-messenger/clients/mesh-cli/tests
MESHC=/path/to/meshc node --test mesh-private-messenger/scripts/monitor-command.test.mjs
meshc lint mesh-private-messenger
```

Mesh tests use three local RPC servers and a signed directory fixture for both
log versions, including late cosigns, missed thresholds, registry replacement,
hidden unresolved comparisons, rotating retries and retained F1/F2/F3. A
contradiction beyond the first sixteen leaves verifies probe resumption. The command test builds
the native executable and exercises configuration rejection, exit codes,
outage caching, restart, HTTP routes and graceful shutdown. CI runs these
checks. They establish neither public RPC consensus nor the 30-day live gate.
