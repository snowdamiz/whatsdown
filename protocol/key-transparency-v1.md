# Key Transparency v1

Status: implemented development profile. The two witness keys currently share
an operator/account; they do not provide independent trust against that
operator. Internal verification is required for release. Outside review is
additional scrutiny, not an activation prerequisite.

## Commitments

Each canonical account/device-set transition is hashed as:

```text
SHA-256("mesh-msg/v1/transparency-leaf" || canonical transition bytes)
```

The balanced Merkle tree hashes internal nodes with
`mesh-msg/v1/transparency-node`. Checkpoints bind the tree size and root,
monotonic checkpoint sequence, previous signed-checkpoint hash, timestamp, and
the service signing public key under `mesh-key-transparency-v1`.

## Client rules

Clients reject a directory response unless all of these hold:

- the returned device-set commitment has a valid inclusion proof;
- the service checkpoint signature matches the pinned service key;
- the new tree is consistent with the cached checkpoint;
- the configured threshold of distinct, pinned witnesses signed the exact
  checkpoint hash;
- account and device-set sequence rules still pass independently.

Two valid service-signed checkpoints at the same sequence and tree size with
different roots are a publishable conflict. The three provable kinds of fork
and their evidence format, `FRK` v1, are in
[witness-network-v1.md](witness-network-v1.md). Witness IDs are not
authorities by themselves; each ID is pinned to an expected public key.

## Compact proofs (wire version 2)

Proofs follow RFC 9162 exactly, with Morse's hashes in place of RFC 6962's:
the inclusion path PATH(m, D[n]) and its verification (section 2.1.3), and the
consistency proof PROOF(m, D[n]) and its verification (section 2.1.4). A
consistency proof from size 0 is empty and valid only when the old root is the
empty root `SHA-256("mesh-msg/v1/transparency-empty")`; equal sizes need an
empty proof and equal roots. A path has at most 64 hashes and a consistency
proof at most 128, so a proof for a billion-leaf log is about 1 KB.

A server builds proofs from a node oracle: the hash of the complete subtree at
(level, index), covering leaves `[index * 2^level, (index + 1) * 2^level)`, with
level 0 the leaf hashes. Partial subtrees on the right edge are hashed from
their complete children, so a proof costs O(log n) oracle reads and no leaf
list. `Transparency.Tree` implements generation over any oracle (and a
list-backed one for tests), and verification, for both trees the directory
keeps: tree 1 hashes as above; tree 2 is the RFC 6962 view described in
[witness-network-v1.md](witness-network-v1.md), "C2SP view".

Version 2 frames (all integers big-endian, `vector32(x)` = `u32 length || x`):

```text
KTI  u8 2 || "KTI" || u64 leaf_index || u64 tree_size || u8 p (0-64) || p x 32
KTC  u8 2 || "KTC" || u64 old_size || u64 new_size || u8 p (0-128) || p x 32
KTQ  u8 2 || "KTQ" || vector32(username) || u64 previous_tree_size
KTA  u8 2 || "KTA" || account_id32 || u64 previous_tree_size          (44 bytes)
KTS  u8 2 || "KTS" || u64 old_size || u64 new_size (0 = current) || u8 tree (1 | 2)
KTP  u8 2 || "KTP" || u64 leaf_index || u64 tree_size || u8 tree (1 | 2)
KTL  u8 2 || "KTL" || leaf_hash32 || vector32(KTI v2)
KTW  u8 2 || "KTW" || u16 count (<= 16) || count x entry
       entry = u8 kind || vector32(witness_id, 1-64 bytes) || body
       kind 1 (Morse statement):     checkpoint_hash32 || signature64
       kind 2 (C2SP cosignature/v1): u64 timestamp_seconds || signature64
KTE  u8 2 || "KTE" || vector32(entry) || vector32(KTI v2) || vector32(KTC v2)
       || vector32(KTK) || vector32(KTW v2) || vector32(c2sp_view)
       c2sp_view = empty, or root6962_32 || u8 p (0-64) || p x 32
```

`KTS` answers with a `KTC` over the chosen tree; `KTP` answers with `KTL`,
whose `leaf_hash` is the Morse leaf hash in both trees (for tree 2 the path is
in the RFC 6962 tree). A `KTE`'s inclusion and consistency proofs must both end
at the checkpoint's tree size, and its C2SP view must be present whenever a
kind-2 attestation is. Decoders refuse unknown versions, kinds and trees,
oversized counts, sizes of 2^62 or more, truncation and trailing bytes.

The client check for version 2 (`transparency_verify_evidence_v2`) is the list
above, with two changes. Each pinned witness counts once, through either a
kind-1 attestation or a kind-2 one; a kind-2 attestation counts only through
the dual inclusion rule of the C2SP view. And the caller passes the pinned C2SP
origin (`-` means kind-2 attestations never count) and the current time, since
a C2SP cosignature carries its own timestamp and must be inside the same
freshness window as the checkpoint.

A server answers a version 1 request with version 1 frames and a version 2
request with version 2 frames (`transparency_frame_version` reads the first
byte). Version 1 frames stay decodable, unchanged, for one release; they carry
every leaf commitment and so only work while the log holds at most 4,096
entries.

## Phones

`Mobile.Transparency` in mobile-core. Phones send only version 2 lookups and
accept only version 2 evidence.

**Lookup.** `KTQ` or `KTA` version 2, with `previous_tree_size` the size of
the checkpoint this phone last verified (0 before its first). The answer is a
`KTE` version 2, checked with `transparency_verify_evidence_v2` against the
pinned service key, the pinned witnesses and their `k` from the security
config ([witness-network-v1.md](witness-network-v1.md), "Security config v2"),
the config's C2SP origin, the previous checkpoint and the phone's clock; then
the five-minute freshness rule and the account or username the lookup named.

**What a phone keeps.**

- The newest checkpoint it verified (`KTK`).
- A view: `u8 2 || "KTV" || service_key32 || set_id32 || KTK || u16 n || n x hash32`,
  `n <= 512`: the hashes of older checkpoints known to be prefixes of the
  view's. Every checkpoint the phone verifies is added (the evidence proved it
  consistent with the one before), and so is every anchor whose consistency
  proof it verified. The oldest hashes drop out first; an anchor that dropped
  out is proven again when something needs it.
- Each verified device set with the checkpoint and the witness `set_id` it was
  verified under.

**A new witness set.** When the pinned `set_id` changes, every cached device
set verified under the old set is looked up again before use
(`device_set_transparency_unverified`). Continuity is kept: the previous
checkpoint still anchors the next consistency proof, whichever set signs, so a
new set can neither restart nor roll back the log. Known prefix hashes stay: they
are facts about the log, not about its witnesses. A different service key is a
different log and stays refused (`transparency_trust_mismatch`).

**Anchors.** Groups carry checkpoints this phone may never have verified: a
group's baseline, another device's key package. A checkpoint is *in view* when
it is the view's checkpoint, its hash is known, or it has the view's size and
root (or size 0 and the empty root). It is never in view when it is newer than
the view, a different checkpoint at the view's sequence, not signed by the
pinned service key, or a different root at the view's size. Anything else
needs a proof. Consistency is transitive along the phone's own verified chain,
so one proof to any checkpoint the phone verified settles an anchor for every
later view.

For each anchor that needs one, the core records a 397-byte request
(`KTS` version 2 with `old_size` the anchor's size, `new_size` the view's and
tree 1, then the anchor `KTK`, then the view `KTK`) and fails the operation
with `transparency_anchor_proof_needed:<hex of that KTS>`. At most 16 requests
are pending. The app lists them (`mesh_messenger_transparency_anchor_requests`),
POSTs each `KTS` to `/v1/transparency/consistency` and hands the `KTC` version
2 answer to `mesh_messenger_transparency_anchor_proof` (database path,
request, answer). The core accepts it when the view checkpoint named in the
request is still known, the anchor is signed by the pinned service key, both
sizes match the request, and the RFC 9162 consistency proof connects the
anchor's root to the view checkpoint's root; it then remembers the anchor's
hash. Anything else is `transparency_anchor_proof_invalid`, which also settles
the request. The app then retries the original operation once; a mailbox pass
that set envelopes aside (a welcome waiting on its baseline) is followed by one
more pass after the proofs are in.

**Changed while away.** Before replacing the cached set of this device's own
account, the core compares it with the new one. When the new sequence is more
than one past the cached one and the new checkpoint is more than 90 days after
the cached one, transitions this device never saw may have been pruned
(the directory prunes superseded entries after 90 days): the core stores the new
set and fails once with `account_changed_while_away`. The app says "Your
account changed while this device was away.", opens Linked devices and looks
the account up again.

## The phone's check against the public record

`Mobile.Anchor` in mobile-core (plan §6.7). The directory posts its checkpoints
to the judge program's anchor ring on Solana (`morse-judge-v1.md` §4.3); the
phone checks that the version it was shown is part of that public history.
Nothing is reported to Morse and every state stays on the device.

**When.** Daily, after a contact's keys change (at most hourly), and when
Settings → Network opens with a reading older than five minutes. A check that
could not reach an answer (providers unreachable or disagreeing, directory
down) is tried again after an hour. With no anchor pinned (security config v2
anchor line `-`) the check is OFF and reads nothing.

**Driven by the core, carried by the app.** mobile-core does no networking.
`mesh_messenger_anchor_check` takes `vector32(database path) ||
vector32(u16 count || count x exchange)` and returns a step: `u8 1 || "ACS" ||
u8 done || u16 count || count x vector32(request)`. A request is `u8 kind ||
vector32(tag) || vector32(target) || vector32(body)`:

| kind | the app does |
|---|---|
| 1 rpc | POST the JSON-RPC body to `target`, one of the pinned RPC URLs, as `application/json` |
| 2 directory | POST the body to the messenger service at `target` (`/v1/transparency/consistency`, `/v1/transparency/leaf`) |
| 3 relay | POST the FRK to `target`, a pinned relay's `/v1/fork-evidence` |
| 4 finder | answer a fresh one-time finder address (32 bytes) when the person collects fork bounties, or nothing |

An exchange is `vector32(request) || u16 status || vector32(answer)`, status 0
when nothing answered. The app calls again with every exchange of the run so
far until `done`; the core replays the run from them, so a run holds no state
between calls. The desktop host allows exactly the pinned RPC URLs and the
pinned relays' `/v1/fork-evidence` beyond the messenger's own routes.

**RPC agreement.** Every chain read (`getAccountInfo` with a data slice,
`getMultipleAccounts`, `getProgramAccounts` with filters, `getBlockTime`, all
at `finalized`) counts only when two providers return the same projection:
the account owner plus the bytes the phone uses (for the Log account, all but
the anchor counts at 216..280, which every anchor changes). The first two
providers are picked at random from the pinned list and serve the whole run; a
provider that fails is replaced by another, and after a disagreement one more
is asked. Three answers with no two alike is `rpc_disagree`, fewer than two
answers `rpc_unavailable`: warnings, never a pass. Every judge account must be
owned by the pinned judge program, token vaults by the SPL Token program.

**The check.**

1. Read the pinned Log account (`morse-judge-v1.md` §4.2). Its service key
   must be the pinned one (else `chain_invalid`). If `service_slashed` is set,
   raise a `service_slashed` trust alarm: the service key is refused for new
   lookups from now on (below).
2. Read the ring header (its log id must be the Log's) and, together, the
   time of `last_slot` (`getBlockTime`), the newest ring entry that is not
   evidence (walking back past at most 8 evidence entries), and the bond
   counter.
3. The public record is STALE when there is no anchor or the newest is more
   than two hours old: a quiet notice, nothing blocked. The comparison still
   runs.
4. Compare the phone's view checkpoint `L` with the entry `E`. Same size with
   another root is a fork (kind 1); sequence and size in opposite order, or one
   sequence with two checkpoint hashes, is a fork (kind 3). Same size and root
   is consistent. Otherwise POST `KTS` v2 (old = the smaller size, new = the
   larger, both explicit, tree 1) to `/v1/transparency/consistency` and verify
   the `KTC` v2 against the two roots. A 200 with a proof that verifies is OK;
   a 4xx or a proof that does not verify is a MISMATCH; no answer, 408, 429 or
   5xx is `directory_unavailable` (try again later). The plan's "newest entry
   with tree_size ≥ the cached size" is the newest normal entry; when the
   phone's checkpoint is newer than the last anchor the proof runs the other
   way (entry → phone).
5. On MISMATCH: raise an `anchor_mismatch` trust alarm at once, keep the
   evidence, build FRK proofs and file them (below).
6. A later check that proves the view consistent clears an `anchor_mismatch`
   alarm (both versions are then prefixes of one history, which a real fork
   never is); the record stays.

Outcomes, kept as `anchor-check/v1`: 1 ok, 2 stale, 3 rpc_disagree,
4 rpc_unavailable, 5 mismatch, 6 service_slashed, 7 off, 8
directory_unavailable, 9 chain_invalid, with the check time, the newest
anchor's time, slot and tree size, and the bond counter.

**Fork evidence.** The phone keeps, for its last 8 lookups
(`transparency-lookup-proofs/v1`), the checkpoint verified, the Morse (kind 1)
attestations on it that verified under the pinned keys, and the looked-up
leaf with its audit path. For a kind 1 or 3 fork the proof is the phone's
checkpoint with its attestations against a ring reference to `E`. For a
refused or invalid consistency proof it is a contradiction (kind 2): for each
kept lookup whose leaf index is inside `E`, the phone asks the directory for
that leaf in `E`'s tree (`KTP` v2 → `KTL` v2) and checks it against `E`'s root.
A different leaf makes a complete proof, which the phone checks with
`fork_verify` exactly as the judge would; the same leaf is not the fork and is
dropped; a refused or wrong answer leaves the public side empty (zero leaf, no
path) for the relays to complete from their own copy of the log. At most 8
proofs; each asks for its own finder address.

**Trust alarms** (`Mobile.TrustAlarm`, sealed as `trust-alarms/v1`): kinds 1
`anchor_mismatch`, 2 `service_slashed`, 3 `contact_fork` (checkpoint gossip,
[checkpoint-gossip-v1.md](checkpoint-gossip-v1.md)). While an alarm for the
pinned service key is active:

- a lookup that would add keys fails with `trust_alarm_active`: an account the
  phone never verified, another account identity, or a device the account did
  not have. A device set it already holds still refreshes, including
  renewals and removals of devices it knows;
- a new session (a device with no session yet) fails with `trust_alarm_active`;
- existing sessions keep sending and receiving.

Each alarm keeps both versions (sequence, size, root) and its proofs. Every
proof of an active alarm is filed with every pinned relay: 200/202 is sent
(with the proof hash the relay reports, which differs when it completed the
proof), another 4xx is refused, anything else stays pending and is retried on
the next run. For a proof some relay took, the phone reads the judge's
pay-once record (`getProgramAccounts`: Proof accounts of the pinned log with
that proof hash) and keeps whether it landed and which address was paid.
`mesh_messenger_trust_alarm_details` returns `u8 1 || "TAD" || u8 count ||
count x vector32(alarm)`, alarm = `u8 kind || u8 active || u64 raised_at_ms ||
summary || summary || u8 n || n x vector32(vector32(FRK) || proof_hash32 ||
u8 complete || u8 landed || paid_to32 || u64 slot || u8 r || r x
(vector32(relay URL) || u8 status 0 pending | 1 sent | 2 refused ||
reported_hash32))`, summary = `u8 present || u64 sequence || u64 tree_size ||
root32`.

Checkpoint gossip raises its alarm with `trust_alarm_raise(database_path,
trust_alarm_for_fork(own KTK, contact's KTK, [FRK bytes]))`; the gossip run
that raised it (`mesh_messenger_gossip_check`, the same steps) files the
proofs at once, and the next check here tries any relay that did not answer.

**What the app shows** (plan §10): Settings → Network adds the bond counter
("$50,000 bonded. Slashed: never. Last public checkpoint: 40 seconds ago." —
bond lines only once the bonds exist on chain), the last check's result, each
pinned witness's bond, and "Details" (the two versions, each proof, the relays
it went to, where a landed proof's bounty went, and an export of the proof as
`evidence.frk` for `morse-relay submit`). Every chat list shows "Public record
is behind" (quiet) after two hours without an anchor, and a blocking banner for
an active alarm: "Morse's key log doesn't match the public record.",
"Morse's key log was caught signing two versions." or "A contact's phone was
shown a different key log." Network status (`NST`) sections: tag 2 the last
check (`u8 outcome || u64 checked_at_ms || u64 anchor_time_ms || u64 slot ||
u64 tree_size`), tag 3 the bond counter
([witness-network-v1.md](witness-network-v1.md), "Bond counter"), tag 4 the
blocking alarm (`u8 kind || u64 raised_at_ms`). Sections 2-4 appear once the
build pins an anchor or relays, or a check has run.

## The 4,096-entry ceiling

The protocol no longer has one: version 2 frames carry u64 sizes, proofs grow
with log n, and a checkpoint can be signed over a root computed from stored
nodes (`transparency_sign_checkpoint_root`) instead of a leaf list. Tree sizes
are bounded only below 2^62.

The directory has no append limit either. It keeps the tree's nodes and builds
every proof from them (below, "Directory storage"), so appends, checkpoints and
proofs cost O(log n) whatever the log's size; registration is limited by proof
of work, as before. The old limits (no append past 4,096 entries, no new
account past 3,584, `507` when refused) are gone. A version 1 lookup or `KTS`
still gets version 1 frames while the log holds at most 4,096 entries; above
that it gets `426` and nothing else, because no full list fits a proof.
`transparency_capacity.test.mpl` grows the log to 1,000,000 entries and shows
registration, compact lookups and consistency proofs still answer. Renewal
spends entries steadily: every device renews its credential through the log
(`multi-device-wire-v1.md`, "Renewal"), about four entries a year for the
device holding an account key and eight for each linked device.

Phones keep no leaf list: they prove a group anchor with one fetched
consistency proof ("Phones", below).

Witnesses and optional blockchain anchors receive checkpoint commitments only,
never usernames, device records, mailbox capabilities, account identifiers, or
message data.

The client rejects directory evidence more than five minutes old or more than
one minute ahead of its clock. Receipt time does not renew a replayed checkpoint.
Witnesses refuse to sign a checkpoint stamped more than 60 s from their own
clock or not later than the last one they signed, and at the next sequence one
whose previous-checkpoint hash is not that of the last one they signed, so a
directory can't get a future-dated checkpoint cosigned in advance
([witness-network-v1.md](witness-network-v1.md), "Witness software").
The directory refreshes an unchanged tree on demand after four minutes, advancing
the signed checkpoint sequence and retaining the same tree root. New witnesses
must sign that new checkpoint before clients can authorize it. Migration 010
allows several checkpoint sequences for the same tree size. A failed or pending
witness check remains an error; it does not permit unchecked encryption.

Freshness currently applies to evidence ingestion and cached device-set
requirements used by fanout and identity operations. Extending it to every group
send and updating group recipient discovery remain implementation work; these
paragraphs do not claim those paths complete.

## Directory storage

Migrations 019 and 020 give the log this layout (plan section 6.15, G1-G4):

- **Leaf positions.** `transparency_entries.leaf_index` is dense, 0 to n - 1,
  assigned under the log's append lock. The BIGSERIAL `sequence` can skip a
  value for every rolled-back append; a leaf index never does. The log's size is
  one past the highest leaf index.
- **Nodes.** `transparency_nodes (tree, level, node_index, hash)` holds the hash
  of every complete subtree of both trees: tree 1 with Morse's hashing (what
  checkpoints sign), tree 2 with RFC 6962's over the Morse leaf hashes (the C2SP
  view). Level 0 is the leaves. The append that completes a subtree stores its
  node, in the same transaction, reading only the old tree's right edge. Nodes
  never change, so they can later move to object storage as tiles without
  changing a proof.
- **Roots and proofs.** A checkpoint's root is computed from the right-edge
  nodes of its size (one per set bit of the size), never from the leaves. A
  proof reads, in one query, the nodes it can need: for an inclusion path of
  leaf i at size n, every complete ancestor of i and its sibling, plus n's right
  edge; for a consistency proof from m to n, the same for leaf m - 1. Those sets
  are exactly what the RFC 9162 generators ask for.
- **Device records.** Each device record (one device's `DRE` bytes inside a
  device set) is stored once in `transparency_device_records`, keyed by its
  SHA-256. An entry keeps its device set's header (up to and including the
  device count), the ordered hashes of its records and its revocation trailer.
  The canonical entry bytes are rebuilt from those for lookups and checked
  against the stored leaf hash before they are served; leaf hashes and wire
  formats are unchanged. Migration 020 moved existing entries over, replacing an
  entry's old bytes only once the rebuilt bytes hashed to its leaf hash; an
  entry that failed keeps its bytes and is reported.
- **Pruning.** A scheduled job, at most once a UTC day and up to a daily cap per
  kind (`MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP`, default 10,000), removes:
  - an entry's bytes once the same account's next entry has existed for 90
    days. It never touches an account's current entry, anything younger than 90
    days, or any hash: `leaf_hash`, `account_commitment`, the leaf position and
    every node stay, and `pruned_at` records when the bytes went. Device records
    that no remaining entry lists go with them;
  - checkpoints older than 35 days, with their witness signatures, except the
    newest checkpoint and every checkpoint anchored on-chain
    (`transparency_anchors`).
  `MESSENGER_TRANSPARENCY_PRUNING` is `on` (the default), `dry-run` (count and
  record what would go, change nothing) or `off`. Each run is recorded in
  `transparency_pruning_runs`. A deleted account's entries and device records
  are dropped at deletion, as before.

Nothing a proof needs is ever pruned: inclusion, consistency and fork proofs
need only hashes. A device offline for more than 90 days can find its account's
sequence moved through transitions whose bytes are gone; it must then treat its
account as changed while it was away rather than accept the change silently.

The log also holds the credit issuer's keys: `issuer-key-v1` (`IKY`) and
revocation (`IKR`) leaves, appended through `POST /internal/v1/credits/issuer-keys`
and proved to phones by `GET /v1/credits/issuer-keys` ([credits-v1.md](credits-v1.md)).
They keep their bytes and are never pruned, and account lookups never return
them.

## Directory API

Lookups (`POST /v1/devices/resolve`, under proof of work, payload up to 80
bytes) take `KTQ` or `KTA` in either version and answer `KTE` in the same
version: version 2 carries compact proofs, both kinds of attestation for the
checkpoint, and the C2SP view of the same leaf whenever a kind-2 attestation is
included. `426` answers a version 1 lookup once the log is past 4,096 entries;
`400` a previous tree size past the checkpoint. `POST /v1/transparency/inclusion`
answers the inclusion proof of the same lookup (`KTI` in its version).

| Route | Request | Response |
|---|---|---|
| `POST /v1/transparency/consistency` | `KTS` v1, or `KTS` v2 (new size 0 = the current checkpoint, refreshed as a lookup would) | `KTC` v1 (`426` past 4,096 entries), or `KTC` v2 over the named tree; `400` for a size the log has not reached |
| `POST /v1/transparency/leaf` | `KTP` v2 | `KTL` v2; `400` for an index or size the log has not reached |
| `GET /v1/transparency/leaves?start=S&count=C` | C from 1 to 1,024 | up to C Morse leaf hashes from leaf S, 32 bytes each, fewer past the end |
| `GET /v1/transparency/checkpoint` | | `KTK` of the latest checkpoint; `404` before the first |
| `GET /v1/transparency/checkpoint.note` | | the latest checkpoint as a C2SP signed note (`text/plain; charset=utf-8`), signed with the service key under the log origin `MESSENGER_TRANSPARENCY_LOG_ORIGIN` (default `morseapp.io/log/main`); `404` before the first checkpoint |
| `GET /v1/transparency/witnesses` | | `KTW` v1: the Morse statements on the latest checkpoint. With `Accept: application/x-morse-attestation-v2`, `KTW` v2 with both kinds. At most 16, pinned witnesses first, then shadow ones, newest first; never a retired one |
| `GET /v1/transparency/witnesses/{sequence}` | canonical decimal sequence | `KTW` v2 (both kinds, the same selection and order) for that checkpoint, whether or not it is the latest: the cosign crank reads an anchored checkpoint's attestations here after the log has moved on. `404` when the directory does not hold that checkpoint (never issued, or pruned after 35 days; anchored ones are kept), `400` for a non-canonical number |
| `POST /v1/transparency/witnesses` | one Morse statement (`KTW` v1, or `KTW` v2 with exactly one kind-1 entry), or with `Content-Type: text/x-c2sp-cosignature` one or more `— <key name> <base64>` cosignature lines on the latest checkpoint's note | `201` stored, `200` already stored, `409` a different attestation is stored for that witness and checkpoint (a later C2SP cosignature replaces an earlier one), `400` anything else: not for the latest checkpoint, from an unknown or retired witness, a Morse statement from C2SP software or the reverse, a cosignature more than 60 s in the future, or a line under a registered key that fails to verify |
| `GET /v1/transparency/registry` | | `{"witnesses":[{"witness_id","public_key" (hex),"operator","status","software","morse_run","c2sp_name" (or null)}]}`, every entry including retired ones |
| `GET /v1/transparency/anchor/{sequence}` | canonical decimal sequence | `{"sequence","tree_size","checkpoint_hash" (hex),"ring_index","tx_signature","slot","checkpoint" (the anchored KTK, hex)}`; `404` if not anchored, `400` for a non-canonical number |
| `POST /internal/v1/transparency/anchors` | bearer (the delivery internal token); the same JSON as above | `201` stored, `200` already stored, `404` no such checkpoint, `409` the size or hash is not that checkpoint's, or another record is stored for it, `400` malformed (ring index 0-4,095, a base58 signature of 32-128 characters) |
| `GET /internal/v1/transparency/push-witnesses` | bearer | the registry JSON of every shadow and pinned entry, each with `"push_url"` added (the C2SP `add-checkpoint` endpoint, or null). The jobs Worker asks the Morse-run Mesh entries it has an `/attest` URL for to sign (the legacy-seeded `witness-a`/`witness-b` included) and pushes checkpoints to C2SP entries with a `push_url`; an empty list is normal |
| `GET /health`, and publicly `GET /v1/transparency/health` | | JSON: `checkpoint_sequence`, `tree_size` (null before the first checkpoint), `pinned`, `threshold` (k = pinned / 2 + 1), `threshold_met` (at least k pinned registry entries attested the latest checkpoint), per-witness `signed_current` and `last_signature_age_seconds` (null when none is kept), `anchor_lag_seconds` (null while nothing was ever anchored; else how long the oldest checkpoint past the newest anchored size has waited), `last_anchor_age_seconds`, `last_pruning_day`. `503` when the database does not answer |

The registry (`transparency_witness_registry`, migration 017) lists every
witness: ID, key, operator label, status `shadow` / `pinned` / `retired`,
software `mesh` (signs Morse statements) or `c2sp` (cosigns notes under its
`c2sp_name`), an optional C2SP `push_url`, and whether Morse runs it. A key
stays with its ID for good, and a retired witness never returns. At startup the
directory upserts `MESSENGER_WITNESS_REGISTRY` (a JSON array of entries with
the fields above plus `push_url`; `morse_run` defaults to operator `Morse`) and
the legacy `MESSENGER_WITNESS_{A,B}_PUBLIC_KEY_HEX`, which seed `witness-a` and
`witness-b` as pinned Morse witnesses, unless `MORSE_REGISTRY_WRITES` is `off`.
A seed that contradicts the registry stops the directory from starting. Only
the directory's own witnesses in the registry, no C2SP witness and no anchor
are all normal states.
