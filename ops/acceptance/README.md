# Acceptance, alerting and the status page

The witness network's production checks ([plan](../../../WITNESS_NETWORK_PLAN.md)
§4.3, §11.3), its alerting (§12) and the public status page. Everything runs
from [`.github/workflows/acceptance.yml`](../../../.github/workflows/acceptance.yml)
against production with only Morse's witnesses, and by hand from a workstation.

| File | Does |
|---|---|
| `run.mjs` | Runs checks (`--checks 1,3,4,5`), picks this week's drill witness (`--drill-witness`), registers the canary accounts once (`--create-canaries`) |
| `checks.mjs` | The eight checks, each returning `{id, name, status: ok \| fail \| skip, detail, evidence: [{label, url}]}` |
| `canary-device/` | The canary device: a Mesh program on the real mobile core (`packages/mobile-core`), run with `meshc test` |
| `canary.mjs` | Starts the canary device and reads the JSON lines it writes as it goes |
| `witness-outage.mjs` | The weekly outage drill, and `stop`/`start` for a witness by hand |
| `credits-drill.mjs` | The weekly credits purchase: quote, payment, blind issuance, finished tokens, then each extra on the drill device |
| `alerts.mjs` | Collects the §12 signals, evaluates the thresholds, notifies (dependency-free) |
| `status-page.mjs` | Renders the public status page (`index.html` and `status.json`) |
| `config.mjs` | Reads the security config release builds pin |

## The checks

A check skips only while what it checks is not live, and says why. A failure
pages Morse's on-call through the alerts (below).

| # | Check | Schedule | Passes when | Skips while |
|---|---|---|---|---|
| 1 | Lookup | hourly | A fresh canary device looks up `morse-canary-1…3` and the real mobile core verifies each answer under the pinned set (`k` of `n`, the release's security config) | never: it fails instead |
| 2 | Outage tolerance | weekly, Tue 10:20 UTC | One Morse witness stopped for 15 minutes: a canary device's lookup verifies every minute (each round also proves the log consistent with the last), the directory's threshold holds, and within 10 minutes of starting again the witness signs the current checkpoint and its host reports no halt or evidence | the pinned set has no spare witness (`n − k = 0`, before B1) |
| 3 | Anchoring | hourly | Every anchor of the last 2 hours reached the ring within 70 s of its checkpoint (the plan's 60 s plus the transaction's confirmation), no gap between anchors over 65 minutes, and the directory's `anchor_lag_seconds` is at most 60 | `MORSE_ANCHOR_MODE=off` (from `status.json`) |
| 4 | Phone check | hourly | The canary device's anchor check (mobile-core's `mesh_messenger_anchor_check`, driven as the app drives it) ends `ok` with two different RPC providers answering | no anchor pinned in the security config |
| 5 | Monitor | hourly | The monitor's `/status.json` reports zero inconsistencies and its last cycle ended within 10 minutes (or `morse-monitor --once` exits 0) | anchoring off |
| 6 | Fork drill | monthly, the 3rd, 11:00 UTC | `ops/drills/canary-fork.mjs` on the canary log: two conflicting checkpoints, T3 cosigns both, the relay files the `FRK`, the judge slashes T3 and the canary directory, the finder's share is paid | not enabled (`MORSE_FORK_DRILL=on`): it moves canary bond money |
| 7 | Rewards | weekly, Thu 01:40 UTC | `settle_epoch` ran for the last finished epoch within an hour of its boundary, paid no excluded or inactive witness, and with no payable witness carried the whole budget over | no rewards program configured, or anchoring off |
| 8 | Credits | weekly, Wed 12:30 UTC | A pack bought with the canary buyer wallet is issued, every token finishes and verifies, and postage, longer storage and (during a surge) priority sign-up each answer as specified; large files skip until deployed | "credits not live": no issuer in the pinned config, or the issuer's `/health` mode is not `live`; or the purchase is not enabled (`MORSE_CREDITS_DRILL=on`) |

**Today** (release config v1 values, `MORSE_ANCHOR_MODE=off`): check 1 runs for
real; 2 skips (two witnesses, `k = 2`); 3, 4, 5 and 7 skip (anchoring off); 6
and 8 skip. **As features go live** nothing changes in the code: pinning a third
witness turns 2 on, `MESSENGER_ANCHOR` plus `MORSE_ANCHOR_MODE` turn 3, 4 and 5
on, `MORSE_REWARDS_PROGRAM` turns 7 on, and credits in `live` with an issuer in
the config turn 8 on.

### The canary device

`canary-device/canary.test.mpl` is a phone without a person: the mobile core,
an in-memory secure store and the security config frame release builds pin,
compiled and run by `meshc test` with the newest published Mesh release (the
workflow installs it). It talks to the directory as the app does (proof of
work, the app's retry schedule while witnesses sign a new checkpoint) and
appends one JSON line per result to a file `canary.mjs` reads. Since
mobile-core depends on `packages/messenger-credits`, it builds only with a Mesh
compiler that has `Crypto.BlindRsa`: until a published release has it, run
it with the development compiler (`MESHC`), and the workflow's canary checks
fail to compile. Roles:

- `check`: lookups of every canary account, then the anchor check when an anchor is pinned;
- `watch`: one lookup a minute until told to stop (check 2);
- `create`: registers the canary accounts;
- `extras`: the credits drill's own device (check 8, below).

### The canary accounts, once

`morse-canary-1…3` are the only synthetic leaves in `morse-main` (§11.3).
Create them once, from a workstation, against production:

```sh
cd mesh-private-messenger
npm ci --omit=dev --prefix ops/cloudflare
MORSE_DIRECTORY_URL=https://<backend> MESHC=<meshc of the newest release> \
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=… MESSENGER_DELIVERY_PUBLIC_KEY_HEX=… MESSENGER_ABUSE_DIFFICULTY=16 \
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX=… MESSENGER_WITNESS_B_PUBLIC_KEY_HEX=… \
  node ops/acceptance/run.mjs --create-canaries
```

Each account's keys live only in that run's memory and are gone when it ends,
on purpose: nobody can later move, renew or delete a canary account, and none
can send. Lookups keep verifying after their devices' one-year credentials
lapse, since a lapsed device is listed as expired and does not fail its set
(`packages/mobile-core/mobile/device_set.mpl`). A `409` means the name is
already registered.

## Running by hand

```sh
cd mesh-private-messenger
npm ci --omit=dev --prefix ops/cloudflare      # the chain client (@solana/kit)
npm ci --prefix ops/relay                      # only for check 6
export MORSE_DIRECTORY_URL=https://<backend> MESHC=<meshc>
export MESSENGER_…=…                           # the release's security config, as the release workflows set it
node ops/acceptance/run.mjs --checks 1,3,4,5 --out results.json
node ops/acceptance/alerts.mjs --state alert-state.json --results results.json --dry-run
node ops/acceptance/status-page.mjs --out site --results results.json
```

`run.mjs` exits 1 when a check failed. Never point it at production from a test:
the tests (`node --test ops/acceptance/*.test.mjs`) fake every network, chain and process.

### Configuration

Variables (non-secret) and secrets as the workflow passes them. An empty value
counts as unset.

| Name | Kind | For | |
|---|---|---|---|
| `MORSE_BACKEND_URL` (as `MORSE_DIRECTORY_URL`) | var | all | The backend's public origin |
| `MESSENGER_*` | var | all | The security config release builds pin (`apps/mobile/plugins/security-config.cjs`); or `MORSE_SECURITY_CONFIG` / `MORSE_SECURITY_CONFIG_FILE` by hand |
| `MORSE_ACCEPTANCE_RPC` | secret | 3, 7 | Solana RPC to read the ring and rewards with (default: the config's first RPC URL) |
| `MORSE_MONITOR_STATUS_URL` | var | 5, alerts, page | Morse's monitor's `/status.json`; by hand `MORSE_MONITOR_BIN` + `MORSE_MONITOR_STATE` run `--once` instead |
| `MORSE_REWARDS_PROGRAM` | var | 7, alerts | The `morse-rewards` program ID |
| `MORSE_DRILL_WITNESSES` | var | 2 | JSON: witness ID → drill target (below) |
| `MORSE_DRILL_CLOUDFLARE_API_TOKEN` | secret | 2 | Cloudflare token with *Workers Scripts: Edit* on the witness accounts only |
| `MORSE_DRILL_SSH_KEY`, `MORSE_DRILL_SSH_KNOWN_HOSTS` | secret, var | 2 | For pull-mode targets reached over SSH |
| `MORSE_FORK_DRILL` | var | 6 | `on` to run the monthly drill |
| `MORSE_CANARY_RPC` | secret | 6 | RPC of the canary log's cluster |
| `MORSE_CANARY_JUDGE`, `MORSE_CANARY_LOG`, `MORSE_CANARY_CLUSTER`, `MORSE_CANARY_RELAY`, `MORSE_CANARY_WITNESS` | var | 6 | Judge ID (default: the pinned one), log (`morse-canary`), `devnet` for explorer links, relay origin, T3's ID |
| `MORSE_CANARY_SERVICE_SEED_HEX`, `MORSE_CANARY_WITNESS_SEED_HEX`, `MORSE_CANARY_ANCHOR_KEYPAIR`, `MORSE_CANARY_PAYER_KEYPAIR` | secret | 6 | The canary service key and T3's key (64 hex), the canary anchor authority and a fee payer (solana-keygen JSON) |
| `MORSE_CREDITS_DRILL` | var | 8 | `on` to buy a pack each week |
| `MORSE_CREDIT_ISSUER_HEALTH_URL` | var | 8, alerts | The issuer's `/health` |
| `MORSE_EDGE_URL` (as `MORSE_CREDITS_EDGE_URL`) | var | 8 | The privacy edge, where quotes and issuance go |
| `MORSE_CREDITS_BUYER_KEYPAIR`, `MORSE_CREDITS_RPC` | secret | 8 | The canary buyer wallet (holds USDC and a little SOL) and its RPC |
| `MORSE_ALERT_WEBHOOK`, `MORSE_ALERT_FORMAT`, `MORSE_ALERT_ROUTING_KEY` | secret, var, secret | alerts | Morse's on-call destination (below) |
| `MORSE_ALERT_CONTACTS_JSON` | secret | alerts | Operator and relay contacts (below) |
| `MORSE_ACCEPTANCE_DATABASE_URL` | secret | alerts | A read-only role on the directory database, for its size |
| `MORSE_STATUS_PAGE`, `MORSE_STATUS_PAGE_URL`, `MORSE_STATUS_R2_BUCKET`, `MORSE_STATUS_R2_API_TOKEN` | var, var, var, secret | page | Where the status page goes (below) |

### Check 2: the outage drill

`MORSE_DRILL_WITNESSES` names how to stop and start each Morse witness:

```json
{"witness-a": {"cloudflare": {"account": "<account id>", "script": "morse-witness-a"}},
 "witness-b": {"cloudflare": {"account": "<account id>", "script": "morse-witness-b"}},
 "witness-c": {"stop": "ssh morse@witness-c.example sudo systemctl stop morse-witness",
               "start": "ssh morse@witness-c.example sudo systemctl start morse-witness",
               "status": "ssh morse@witness-c.example 'test ! -e /var/lib/morse-witness/checkpoint.halted && ! ls /var/lib/morse-witness/evidence-*.json'"}}
```

A Cloudflare witness is stopped by switching its `workers.dev` route off
(`POST /accounts/{account}/workers/scripts/{script}/subdomain`, `enabled:
false`) and started by switching it back on; the jobs Worker's `/attest`
calls fail meanwhile, so it signs nothing. Its store keeps its history, so
starting it is catching up: it signs the next checkpoint only if that extends
the last one it signed. A deploy switches the route back on too. The drill
rotates through the pinned Morse witnesses with a target, one a week, and
refuses to start unless every pinned witness signs and stopping one leaves `k`.

While a witness is down the backend's public `/health` answers 503 (the
witness job fails and retries). The drill job announces the window
(`drill.json`, in the Actions cache) and the alert runs stay quiet about that
witness and about `/health` until it ends. If a drill is cut short, put the
witness back by hand:

```sh
MORSE_DRILL_WITNESSES='…' CLOUDFLARE_API_TOKEN=… node ops/acceptance/witness-outage.mjs start witness-a
```

### Check 6: the fork drill

Runs `canaryForkDrill` from [`ops/drills`](../drills/README.md) with the canary
keys; a relay (`MORSE_CANARY_RELAY`) files the proof. A slashed canary directory
bond is final, so each drill ends with the canary log to re-provision (a new
log name and service key, T1-T3 registered and admitted, `MORSE_CANARY_LOG`
and the canary backend pointed at it); until then the next month's check fails
saying so. Before Phase 4 the finder field is zero and the relay keeps the
share.

### Check 8: the credits purchase

`credits-drill.mjs` does what the app will: `POST /v1/credits/quote` (`PWR(CQR)`,
pack 1, USDC, the work minted at the pinned difficulty) through the privacy
edge; checks the quote's key is a `live` key of the pinned issuer in
`GET /v1/credits/issuer-keys`; pays the Solana Pay request from the buyer
wallet (the deposit's USDC account created if needed, the reference on the
transfer); blinds 100 token inputs (RFC 9474 RSABSSA-SHA384-PSS-Deterministic,
tested against RFC 9578's vectors), sends `CIR` until the payment is final,
finishes and verifies every signature. Then the canary device's `extras` role
spends 31 of the tokens on each extra in `EXTRAS`:

| Extra | Tokens | The drill device | Passes when |
|---|---|---|---|
| Priority sign-up | 20 | Registers a fresh drill account (`morse-drill-<hex>`): `CRD ‖ PWR(DRE)` while `GET /v1/devices/register/work` asks more than the pinned base (a surge), a plain registration otherwise | During a surge `201`; otherwise nothing is spent and the work route must answer `200` |
| Postage | 1 | Prices the drill account's inbox at 1 credit (`PUT /v1/mailbox/policy`, `MBP` signed by its device key), then sends a stranger's envelope to its public address through the edge, first without credits, then as `CRD ‖ PRV` | `402` carrying that `MBP`, then `202` |
| Longer storage | 10 | `CRD ‖ MRT` (one 30-day period, signed by the device key) to the edge's `POST /v1/mailbox/retention` | `201` with an `MRA` of 60 days |
| Large files | 0 | Nothing yet | Skips with "large-file extra not deployed". Its workstream replaces the `large-file` entry with the object-store grant request (`CRD` above 16 MiB) once the object store serves it |

The canary accounts' keys are gone, so the drill needs a device of its own. It
makes one per run and deletes it at the end (`POST /v1/accounts/delete`; a
leftover fails the check). Each weekly drill therefore adds one leaf to
`morse-main` beside the three canary accounts, and deletion frees its name and
mailbox but, like every deletion, leaves its leaf hash. The envelope it sends
itself is random bytes nobody reads. The redemption statuses and latencies go
to the alerts (spent-set failures, p95 latency) and count until the next drill.

The smallest pack is 100 credits for $5 (`protocol/credits-v1.md`), so the
weekly purchase costs $5, not the plan's $1; the 69 unspent tokens are dropped
with the run. Keep about $25 of USDC and 0.05 SOL on the buyer wallet.

## Scheduling

| Cron (UTC) | Runs |
|---|---|
| `*/5 * * * *` | Alerts |
| `7 * * * *` | Checks 1, 3, 4, 5, the alerts, the status page |
| `20 10 * * 2` | Check 2 |
| `30 12 * * 3` | Check 8 |
| `40 1 * * 4` | Check 7 (settlement may run from 00:15; it is late after 01:00) |
| `0 11 3 * *` | Check 6 |

`workflow_dispatch` runs any checks by hand. Only `snowdamiz/whatsdown` runs it,
and it has no `push` or `pull_request` trigger. Each check set has its own
concurrency group, so the 30-minute outage drill never holds up the alerts.
GitHub starts scheduled runs late under load (often minutes) and disables
schedules after 60 days without a commit; for alerts on time, also run
`alerts.mjs` on a timer on a Morse host (below).

## Alerting

`alerts.mjs` collects the signals, evaluates, notifies and keeps a small state
file (first-seen times, what was sent, the last result of each check, database
size samples). In the workflow the state lives in the Actions cache.

| §12 signal | Source | Fires | Severity → recipients |
|---|---|---|---|
| Threshold not met for the current checkpoint | directory `GET /v1/transparency/health` (`threshold_met`) | 2 minutes | page → Morse |
| A witness silent | directory health, `last_signature_age_seconds` of each pinned or shadow witness (never signed: from first seen) | 10 minutes; 30 minutes adds Morse | page → its operator, then also Morse |
| Anchor gap | `status.json` `last_public_checkpoint.time` (else the directory's `last_anchor_age_seconds`), or `operations.pages` holding `anchor_gap`; jobs line `PAGE anchor_gap` | 60 minutes, while anchoring is on | page → Morse |
| Fee payer balance | `status.json` `operations.fee_payer.lamports`; jobs lines `fee_payer_*` | below 0.2 SOL / below 0.05 SOL | warn / page → Morse |
| Monitor inconsistency | the monitor's `/status.json` (`ok`, `inconsistencies`, P0 findings); monitor `P0` lines | at once | P0 → Morse and every operator |
| Fork evidence received by a relay | relay line `P0 fork_evidence_received` | at once, once per proof | P0 → Morse and every operator |
| Credits: issuer errors, spent-set failures, redemption p95 > 500 ms | the issuer's `/health` (unreachable, 503, or no key for the next epoch: warn); check 8's redemption statuses (a 503) and latencies | at once | page → Morse |
| Burn slippage > 1% or a failed chunk | jobs lines `WARN burn_slippage`, `WARN burn_chunk_failed` | at once | warn → Morse |
| `settle_epoch` not run within an hour of the boundary | `status.json` `operations.settled_epoch` (with `MORSE_REWARDS_PROGRAM`); jobs line `WARN settle_epoch_late` | an hour after the boundary | warn → Morse |
| Bond counter snapshot older than 5 minutes, or its providers disagree | `status.json` `generated_at` / `stale`, `status: unavailable` with `reason` | at once | warn → Morse |
| A landed proof paid another address than the evidence a relay received | relay line `P0 relay_finder_mismatch` | at once, once per proof | P0 → that relay's operator and Morse (to unpin it next release) |
| Pruning skipped or failed for 2 days; database growth over 20% in a month | directory health `last_pruning_day`; `pg_database_size` samples | 2 days; 20% against a sample 28+ days old | warn → Morse |
| Log size over 8 million leaves | directory health `tree_size` | at once | warn → Morse |
| An acceptance check failed (§4.3: any failure pages) | `results.json` | until that check passes again | page → Morse |
| Backend or directory unreachable; backend `/health` 503 | `GET /health`, directory health | 2 minutes; 503: 5 minutes | page; warn → Morse |

A condition is sent when it first fires, again when it escalates (a higher
severity or more recipients), every hour while a page lasts (every 30 minutes
for P0, daily for a warning), and once more as resolved when it clears. A log
line is an event: sent once, never resolved.

**Destinations.** Morse's on-call is `MORSE_ALERT_WEBHOOK` with
`MORSE_ALERT_FORMAT` (`slack`, `discord`, `json`, or `pagerduty` with
`MORSE_ALERT_ROUTING_KEY`), plus the `morse` list of the contacts file.
Operators and relays come from `MORSE_ALERT_CONTACTS_JSON`:

```json
{"morse": [{"format": "pagerduty", "routing_key": "…"}],
 "operators": {"witness-c": [{"format": "discord", "url": "https://discord.com/api/webhooks/…"}],
               "acme-1": [{"format": "slack", "url": "https://hooks.slack.com/services/…"}]},
 "relays": {"https://relay.morseapp.io": [{"format": "json", "url": "https://ops.example/hook"}]}}
```

An operator or relay with no contact is paged through Morse's destinations,
saying so. Morse's own witnesses need no entry: Morse is their operator.

**Relay lines and tighter timing.** GitHub cannot read a relay's log. On each
relay host (and on the monitor host, for `P0` lines and alerts on the minute),
run the evaluator on a timer with only the log source, so it does not repeat
what the workflow sends:

```ini
# /etc/systemd/system/morse-alerts.service
[Service]
Type=oneshot
EnvironmentFile=/etc/morse-alerts/env   # MORSE_ALERT_WEBHOOK=…, MORSE_ALERT_FORMAT=…
ExecStart=/bin/sh -c 'docker logs --since 6m morse-relay > /run/morse-alerts/relay.log 2>&1; \
  exec node /opt/morse/ops/acceptance/alerts.mjs --state /var/lib/morse-alerts/state.json \
  --log /run/morse-alerts/relay.log@relay:https://relay.morseapp.io --contacts /etc/morse-alerts/contacts.json'

# /etc/systemd/system/morse-alerts.timer
[Timer]
OnCalendar=*:0/5
[Install]
WantedBy=timers.target
```

The jobs Worker's own lines can be fed the same way from
`npx wrangler tail morse-backend --format pretty` saved to a file.

## The status page

`status-page.mjs` renders the current profile ("Bootstrap: all 3 witnesses are
run by Morse", §4.4), the pinned set with registry statuses and shadow
witnesses, attendance per witness per epoch (from the monitor), the last public
checkpoint, bonds, slashes, burns (every number links to the explorer) and the
latest result of each acceptance check. It reads the previous page's
`status.json` and keeps every slash, burn and epoch it ever saw, so the history
survives a source forgetting it (§6.17).

The hourly run publishes it by `MORSE_STATUS_PAGE`:

- `pages`: GitHub Pages. Operator step once: Settings → Pages → Source: GitHub
  Actions, then set `MORSE_STATUS_PAGE=pages` and `MORSE_STATUS_PAGE_URL` to the
  page's URL (so the next run reads the history back).
- `r2`: an R2 bucket served on a domain (`MORSE_STATUS_R2_BUCKET`, a token with
  *R2 Edit* on that bucket as `MORSE_STATUS_R2_API_TOKEN`), with
  `MORSE_STATUS_PAGE_URL` its public URL.
- unset: the site is only uploaded as the run's `status-page` artifact (history
  then starts over each run).

The landing page's `witnesses.html` can link to it once it is published.

## Tests

```sh
cd mesh-private-messenger
npm ci --omit=dev --prefix ops/cloudflare
node --test ops/acceptance/*.test.mjs
```

The canary device and check 2 were also run against a local directory and
local witnesses: `--create-canaries`; check 1 (lookups verified under 2-of-2 and
2-of-3 sets); the anchor check running to its outcome; lookups failing once
both witnesses of a 2-of-2 set stopped and the tree changed; and check 2 with
`MORSE_OUTAGE_MINUTES=5` and a command target pausing witness-c (every lookup
verified, the threshold held, witness-c caught up 90 s after starting).
