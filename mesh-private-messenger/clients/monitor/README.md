# morse-monitor

`morse-monitor` watches a Morse key-transparency log from the outside. It
follows the log's anchor ring on Solana, checks every anchored checkpoint
against the one before it, against the directory's own records and against
what the directory serves, checks that each anchor carries a threshold of
witness cosignatures, and watches the directory's witness registry. When two
checkpoints signed by the log contradict each other it builds a fork proof
(`FRK` v1) and files it with every relay, where it slashes the directory's bond
and the bond of every witness that signed both.

Morse runs one, and **every witness operator is asked to run one** (plan
§6.8, §9). It needs no keys and no account: it only reads public data, and
anyone can run it.

The plan calls this `mesh-cli monitor`. It ships as its own package
(`clients/monitor`, binary `morse-monitor`) because `clients/mesh-cli` is the
protocol interop test harness.

Contents: [What it checks](#what-it-checks) · [Findings](#findings) ·
[Build](#build) · [Flags](#flags) · [Running it](#running-it) ·
[State](#state) · [Status page](#status-page) ·
[What it needs from the directory](#what-it-needs-from-the-directory) ·
[Limits](#limits) · [Tests](#tests)

## What it checks

Every `--interval` seconds (default 30) the monitor runs one cycle.

**1. Reading the chain.** Every account is read with `getAccountInfo`
(`encoding: base64`, `commitment: finalized`, `dataSlice` for the part it
needs). A read counts only when **two providers return the same owner and the
same bytes**; it asks the `--rpc` URLs in order until two agree, and retries
once. The owner must be the judge program (`--judge`) for the Log account and
the ring alike, and the Log's `log_id` must be the `--log` name zero-padded to
32 bytes (`protocol/morse-judge-v1.md` §3). When no two providers agree,
nothing is judged that cycle: the status page says `rpc_disagree` (or
`rpc_unavailable`) and the next cycle tries again. Ring entries are compared
without their cosign bitmap (bytes 96–97), which cosign transactions keep
setting for 1,500 slots after an anchor lands; bitmaps are compared exactly
once the cosign window has closed (check 5).

**2. Following the ring.** The monitor reads the Log account (offsets per
`morse-judge-v1.md` §4.2) and the ring header (§4.3), then every entry written
since its last position, oldest first, in slices of at most 512 entries that
split at the end of the 4,096-entry ring. A first run reads the whole ring. It
remembers the last entry it read; if that ring slot now holds another entry,
the ring lapped the monitor, it reports a `ring_gap` and re-reads the whole
ring (entries it already checked are skipped by sequence). It never pretends
the missed entries were checked.

**3. Anchor pairs.** Each anchor (evidence flag 0) is checked against the
previous one:

- if the two contradict each other on their face (same tree size with
  different roots; sequence order and size order disagreeing; the same
  sequence with another checkpoint), that is a fork (`FRK` kind 1 or 3);
- otherwise the monitor asks the directory for a consistency proof between the
  two tree sizes (`POST /v1/transparency/consistency`, `KTS` v2, Morse tree)
  and verifies it against the two **anchored** roots;
- if the proof does not verify, it looks for a leaf index the two trees read
  differently, using its own copy of the log for the older tree and the
  directory's `KTP` v2 leaf proof (`POST /v1/transparency/leaf`) for the newer
  one, each checked against its anchored root. That is `FRK` kind 2.

An entry the ring stores as evidence (flag 1 or 3: `post_anchor` found it
contradicts the tip) is checked against the anchor before it the same way.
It is always reported, with a proof when one can be built.

For every anchor the monitor also fetches the directory's record of it
(`GET /v1/transparency/anchor/{sequence}`, when the directory still has it)
and checks it names the same checkpoint hash and tree size. A record naming
another checkpoint is a fork when the other checkpoint is signed (proved from
the record's `checkpoint` field or a checkpoint the monitor saw served), and
an unproven inconsistency otherwise.

**4. The directory's current checkpoint.** Each cycle the monitor fetches
`GET /v1/transparency/checkpoint` and the attestations served for it
(`GET /v1/transparency/witnesses`, `Accept: application/x-morse-attestation-v2`),
keeps both (they are the signed side of any later proof), and checks the
checkpoint against the newest anchor exactly as in check 3: the same test a
phone runs daily (plan §6.7), run continuously.

**5. Cosignature thresholds.** When an anchor's cosign window has closed (the
older of the two agreeing providers' finalized slots is more than 1,500 slots
past the slot it was posted in), the monitor reads its final bitmap (two
providers agreeing exactly) and requires, for **at least one supported set**
(each `--config`), at least that set's `k` of its witnesses cosigned. A set's
witness counts through the Log list entry with its witness ID **and** its
pinned key, and only if that entry was filled at or before the anchor's slot
(the list entry's since slot, so a reused slot never inherits old bits). It
also reports a pinned witness missing from the Log's list, or listed under
another key.

**6. The witness registry.** `GET /v1/transparency/registry` is compared with
the previous cycle's copy and with the pinned sets. A witness ID whose key
changed is always reported (rotation always means a new ID); so is a pinned
witness missing from the registry or registered under another key than the one
pinned.

**7. Evidence and filing.** A fork proof names the anchored side by ring
reference (`C2` form 1) and carries the other side's signed checkpoint inline.
That checkpoint comes from what the directory served (check 4, or the anchor
record) or, for a ring entry, from the chain itself: the `post_anchor`
transaction's data holds the `KTK`, found with `getSignaturesForAddress` on the
ring and `getTransaction` (one provider is enough here, because the `KTK` must
hash to the agreed ring entry). Witness attestations on the inline side come
from the directory's attestation list and from the Ed25519 instructions of the
ring's `cosign` transactions; only attestations that verify under the Log
list's key for that witness are carried, since the judge refuses a proof
holding an unverifiable one (`morse-judge-v1.md` §7.1 rule 5). The implicated
witnesses are those with an attestation on the inline side and a bitmap bit on
the anchored side.

Every proof is encoded and then checked with `Transparency.Fork.fork_verify`
against the Log's key and witness list before anything is filed. A verified
proof is:

- kept in the state and written next to it as `<state>.<proof hash>.frk`
  (ready for `morse-relay submit <file> --wallet <keypair>`);
- logged as a `P0` line (see [Findings](#findings));
- `POST`ed to every relay's `/v1/fork-evidence`, retried each cycle (at most 50
  times) until the relay answers for good (2xx, or a 4xx other than 408 and
  429).

The finder address in the proof is zero unless `--finder` names one; with a
zero address the relay that lands the proof keeps the finder's share
(`ops/relay/README.md`).

**What is never a verdict.** A directory that is down, slow, stale, or refuses
a consistency or leaf request only leaves a note ("pending") and the check is
retried next cycle; the pair queue waits for it in ring order. Providers that
do not agree leave a note. Nothing is filed without a proof that verifies.

## Findings

Each finding is recorded once (keyed by what it is about), logged once as
`<severity> morse-monitor <log> <kind>: <detail>`, and listed on the status
page. `P0` lines are the ones to alert on (plan §12: "Monitor inconsistency:
page Morse and every operator immediately").

| Kind | Severity | Meaning |
|---|---|---|
| `fork_kind_1`, `fork_kind_2`, `fork_kind_3` | P0 | Two log-signed checkpoints contradict each other. The line ends with `proof_hash=… frk=<file>`; the proof was filed with the relays |
| `inconsistency_unproven` | P0 | An inconsistency the monitor could not turn into a proof: a consistency proof between two anchors that does not verify with no leaf contradiction available, an anchor record naming an unsigned or unknown checkpoint, or a ring evidence entry whose tip is no longer in view. Evidence is kept in the state; plan §14 "Monitor inconsistency without a proof" |
| `below_threshold` | P1 | An anchor closed its cosign window without a threshold for any supported set |
| `registry_key_changed` | P1 | The registry changed a witness's key under the same ID |
| `pinned_witness_missing` | P1 | A pinned witness is not in the registry |
| `pinned_key_differs` | P1 | The registry holds another key than the pinned one |
| `list_key_differs` | P1 | The Log's witness list holds another key than the pinned one |
| `pinned_not_listed` | warn | A pinned witness is not in the Log's witness list, so its cosignatures cannot count |
| `ring_gap` | warn | The ring lapped the monitor; some anchor pairs went unchecked |
| `leaves_mismatch` | warn | The directory's leaf hashes do not hash to an anchored root; the monitor's copy of the log was discarded and is rebuilt |

## Build

With the Mesh compiler the messenger uses (`meshc` 0.1.8 or later):

```sh
meshc build mesh-private-messenger/clients/monitor --opt-level 2 \
  --output mesh-private-messenger/clients/monitor/morse-monitor
```

The binary needs only glibc (Mesh's HTTP client carries its own TLS roots).

## Flags

| Flag | Default | |
|---|---|---|
| `--log morse-main\|morse-canary` | required | The log to watch; its Log account must carry this name as `log_id` |
| `--directory URL` | required | The directory's base URL, e.g. `https://api.morseapp.io` |
| `--config PATH` | at least one | A supported security config frame (v1 or v2, one trailing newline allowed). Repeat for every set phones may hold (the current release and the previous one during a rotation) |
| `--judge ADDRESS` | from a config's anchor line | The judge program ID |
| `--log-account ADDRESS` | from a config's anchor line | The Log account |
| `--rpc URL` | from a config's RPC list | Solana RPC URL; repeat, **at least two** different providers. Use providers independent of Morse and of each other |
| `--relay URL` | from a config's relay list | Relay origin to file proofs with; repeat |
| `--state PATH` | required | The state file (SQLite), created if missing |
| `--listen PORT` | `0` (off) | Serve the status page on this port (all interfaces) |
| `--interval SECONDS` | `30` | Time between cycles (1–3600) |
| `--finder ADDRESS` | zero | A Solana address to name as the finder in proofs (it receives 10% of each slashed bond) |
| `--once` | off | Run one cycle and exit: `0` no P0 finding in the state, `2` at least one, `1` error |

A config that pins an anchor must pin the same judge and Log account as the
flags. Without `--once` the monitor runs until SIGINT or SIGTERM and exits `0`;
a bad flag or an unreadable state exits `1`.

Example:

```sh
morse-monitor --log morse-main \
  --directory https://api.morseapp.io \
  --config /etc/morse-monitor/security-config-current.txt \
  --config /etc/morse-monitor/security-config-previous.txt \
  --rpc https://rpc.provider-one.example \
  --rpc https://rpc.provider-two.example \
  --rpc https://rpc.provider-three.example \
  --state /var/lib/morse-monitor/morse-main.sqlite \
  --listen 8480
```

## Running it

Give it disk for the log copy (32 bytes per log entry: 320 MB at 10 million
entries), outbound HTTPS to the directory, the RPC
providers and the relays, and an inbound port only if you publish the status
page. The first cycle reads the whole ring (up to 4,096 anchors) and copies
the log's leaf hashes (one request per 1,024 entries), so it takes minutes;
later cycles make a handful of requests.

Alert on `P0` lines, on the process exiting, and on the status page's
`updated_at_ms` falling behind (a stuck cycle). `pending_entries` growing
means the directory is not answering consistency requests.

### systemd

```ini
# /etc/systemd/system/morse-monitor.service
[Unit]
Description=Morse transparency monitor (morse-main)
Wants=network-online.target
After=network-online.target

[Service]
User=morse-monitor
ExecStart=/usr/local/bin/morse-monitor --log morse-main \
  --directory https://api.morseapp.io \
  --config /etc/morse-monitor/security-config.txt \
  --rpc https://rpc.provider-one.example --rpc https://rpc.provider-two.example \
  --rpc https://rpc.provider-three.example \
  --state /var/lib/morse-monitor/morse-main.sqlite --listen 8480
Restart=always
RestartSec=10
StateDirectory=morse-monitor
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home morse-monitor
sudo systemctl enable --now morse-monitor
journalctl -u morse-monitor -f | grep --line-buffered '^P0 '
```

### Docker

Build the Linux binary as above, then:

```dockerfile
FROM ubuntu:24.04
COPY morse-monitor /usr/local/bin/morse-monitor
COPY security-config.txt /etc/morse-monitor/security-config.txt
VOLUME /var/lib/morse-monitor
EXPOSE 8480
ENTRYPOINT ["/usr/local/bin/morse-monitor"]
```

```sh
docker build -t morse-monitor .
docker run -d --name morse-monitor --restart unless-stopped \
  -v morse-monitor:/var/lib/morse-monitor -p 8480:8480 morse-monitor \
  --log morse-main --directory https://api.morseapp.io \
  --config /etc/morse-monitor/security-config.txt \
  --rpc https://rpc.provider-one.example --rpc https://rpc.provider-two.example \
  --rpc https://rpc.provider-three.example \
  --state /var/lib/morse-monitor/morse-main.sqlite --listen 8480
```

To watch the canary log as well, run a second instance with `--log
morse-canary`, the canary's config and its own state file.

## State

The state is one SQLite file (`--state`): the ring position, the queue of
entries still to check, the last verified pair, findings with their evidence
(JSON with every checkpoint, root, proof and `FRK` involved, hex), relay
filings, the checkpoints and attestations the directory served (kept 28 days,
the proof window), the copy of the log's leaf hashes, the previous registry
and the latest status document.

Every step commits atomically (SQLite rollback journal, `synchronous=FULL`), so
a crash or power loss leaves the state as it was after the last whole step,
and a restart continues from there without re-checking what was done. The
release Mesh compiler has no `File.rename` or `File.sync`, so a plain state
file could not be replaced atomically; SQLite is the atomic primitive it does
have. Back the file up like any SQLite database (`sqlite3 … .backup`); losing
it only costs a fresh first run.

## Status page

With `--listen`, `GET /` is a small HTML page and `GET /status.json` the
document it renders, rewritten at the end of every cycle:

| Field | |
|---|---|
| `log`, `judge`, `log_account`, `directory` | What is watched |
| `updated_at_ms` | End of the last cycle |
| `ok`, `inconsistencies` | `false` / the count once any P0 finding exists |
| `service_slashed` | The Log's `service_slashed` flag |
| `ring` | Header as last agreed: `head`, `count`, `last_sequence`, `last_tree_size`, `last_slot`, `finalized_slot` (null when the providers did not agree) |
| `position` | The newest entry read: `ring_index`, `sequence`, `tree_size`, `slot`, `timestamp_ms`, `evidence` |
| `last_verified_pair` | `old_sequence`, `old_tree_size`, `new_sequence`, `new_tree_size`, `verified_at_ms` |
| `pending_entries` | Entries read but not yet checked |
| `mirror` | The log copy: `size`, `verified_size` (leaves hashed to an anchored root) |
| `epochs` | This epoch and the last (604,800 s, as the judge counts): `anchors` judged, `below_threshold`, and per Log witness `cosigned` |
| `sets` | The supported sets: `set_id`, `threshold`, `witnesses` |
| `relays` | Where proofs are filed |
| `findings` | Newest first (at most 200): `key`, `severity`, `kind`, `detail`, `found_at_ms`, `proof_hash`, `filed` (`relay`, `status`, `attempts`) |
| `notes` | Why parts of the last cycle did not finish (a provider or the directory not answering) |

## What it needs from the directory

Public routes only (INTERFACES §7): `GET /v1/transparency/checkpoint`,
`GET /v1/transparency/witnesses` (v2 with the Accept header above; v1 also
read), `GET /v1/transparency/registry`,
`GET /v1/transparency/anchor/{sequence}`, `POST /v1/transparency/consistency`
(`KTS` v2 between two **historical** sizes, not only up to the current tree),
`POST /v1/transparency/leaf` (`KTP` v2 at a historical size) and
`GET /v1/transparency/leaves?start=S&count=C` (in order, up to 1,024 per
request). When the anchor record also carries `"checkpoint"` (the anchored
`KTK`, hex), a record naming another checkpoint becomes a proof rather than an
unproven inconsistency.

## Limits

- The leaf search for a kind-2 proof reads the log copy and the directory's
  leaves linearly (one request per 1,024 entries); only done on an
  inconsistency.
- Reading a checkpoint back from the chain looks at the ring's newest 50,000
  transactions; an older anchor's checkpoint must have been seen served by the
  directory.
- A kind-2 proof needs the log copy to cover the older tree. After downtime
  with several new anchors, the copy catches up anchor by anchor; a copy the
  directory cannot serve (no `leaves` route) leaves such inconsistencies
  unproven.
- The monitor sees what the directory shows it. A split view aimed only at one
  phone shows up here once it is anchored; before that, the phone's own check
  and checkpoint gossip are what catch it.

## Tests

```sh
mesh-lang/target/debug/meshc test mesh-private-messenger/clients/monitor/tests
```

The tests run a stub directory, stub RPC providers and a stub relay inside the
test process (`tests/support.mpl`), and cover an honest progression, a
rewritten history (kind 2 proof filed with the relay and accepted by
`fork_verify`), a same-size fork proven from `post_anchor` and `cosign`
transaction data, providers that disagree (no verdict until two agree), the
ring wrapping and lapping the monitor, cosignatures below threshold, registry
key changes, a restart resuming from the state file, and an anchor record
naming another checkpoint (kind 3 proof).
