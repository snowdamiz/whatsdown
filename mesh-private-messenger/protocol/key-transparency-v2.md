# Key transparency v2: RFC 6962 log

Status: the Mesh protocol primitives, authenticated native transition, resumable
directory cutover, operator commands and C2SP registry/jobs are implemented and
locally tested. Versioned proof endpoints include exact historical checkpoints
and compact leaf proofs. Release pinning and production activation remain open.

The log version is authenticated by the checkpoint signature. `KTK` v1 uses
Morse's original hash domains. `KTK` v2 uses [RFC 6962 section 2.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1):
empty root `SHA256(empty)`, leaf `SHA256(0x00 || entry)`, and parent
`SHA256(0x01 || left || right)`. Existing roots are never reinterpreted.

Both checkpoints retain the 188-byte wire layout. The signing statement retains
`mesh-key-transparency-v1` as its domain and includes the actual checkpoint
version as a big-endian u16. The checkpoint digest therefore binds the version
as well as the signature. A version byte cannot be changed without invalidating
the signature. New log sequences and leaf positions start independently.

`KTI`/`KTC` v1 and v2 apply only to the legacy hash profile. Proof v3 is the
compact path encoding with RFC 6962 hashes. `KTE` uses its checkpoint's version
and requires matching proof versions. Ordinary evidence verification rejects
different versions of cached and incoming checkpoints. A cached v2 checkpoint
cannot be downgraded, including through the migration verifier.

## Authenticated transition

The new log's leaf at index zero is exactly `1 || KTM || legacy_KTK`, 192 bytes.
It commits to the complete signed legacy checkpoint at which the old log is
sealed. Its RFC leaf hash is computed over all 192 bytes. Legacy history is
retained under its original version and hash profile. It is not rehashed or
silently replaced with a fresh trust state.

`Transparency.Migration.verify_migrated_evidence` requires:

- a valid previously cached v1 checkpoint and a valid v1 seal under the pinned
  service key;
- nondecreasing legacy sequence, size and timestamp; identical checkpoint
  hashes when the sequence is equal;
- a compact legacy consistency proof from the cached size to the seal;
- a strict majority of distinct pinned legacy witness keys on the seal;
- normal v2 evidence verification, including a strict majority of current pins;
- inclusion of the exact bridge leaf at index zero of the new checkpoint;
- a new checkpoint timestamp no earlier than the legacy seal.

Both witness policies come from native configuration. The response cannot
choose them. Existing account binding and checkpoint freshness rules still
apply. A new install has no cached legacy history to migrate and uses normal
v2 verification under its native pins. Keeping the final legacy checkpoint,
its quorum, and legacy nodes permits clients returning after a long absence
to prove the transition.

`KTB` carries the bridge evidence, bounded to 4,942 bytes:

| Field | Encoding |
|---|---|
| Header | version u8 `1`, magic `KTB` |
| Legacy seal | `KTK` v1, 188 bytes |
| Legacy witnesses | u32 length, `KTW`, at most 2,630 bytes |
| Legacy consistency | u32 length, `KTC` v2, at most 1,070 bytes |
| New-log inclusion | u32 length, `KTI` v3, at most 1,038 bytes |

Integers are big-endian. The decoder requires complete input and canonical
re-encoding. The inclusion index must be zero, and the consistency target size
must equal the seal's size. Cryptographic verification is separate from decode.

## Native transition policy

Native security config v3 carries the migration trust explicitly. It uses the
same canonical LF-separated fields as config v2, with header `3`, followed by
`2` (preferred log version), legacy threshold, legacy witness count, and that
many `id public-key-hex operator-label` lines. The current and legacy sets are
validated independently: 1–16 sorted distinct IDs/keys, and exactly
`floor(n/2)+1` required signatures. Config v3 is bounded to 8,192 bytes; formats
v1/v2 retain their original 4,096-byte limit and authorize only the legacy log.
Changing legacy pins does not change the current witness set ID.

Config v4 retains every v3 migration field and appends the base58 judge program
address and log name, with header `4` and the same 8,192-byte limit. Enabled
anchors require both, a canonical 1–32 character lowercase/digit/hyphen log
name, and a ring equal to the PDA derived from that program and name. Disabled
anchors require `-` for all three identity fields. Versions 1–3 remain readable;
their ring-only fields cannot activate a phone reader without a program/log pin.
Current and legacy witness policy selection and migration rules are identical
under v3, v4 and v5.

`MESSENGER_ANCHOR_PROGRAM_ADDRESS` and `MESSENGER_ANCHOR_LOG_NAME` select v4 and
require all v3 migration settings. Production mobile/desktop writers permit only
`morse-main`. An explicit development build can pin `morse-canary`; the mobile
release checker always applies production validation. These identities stay in
the signed native resources and public `client.env`, never an OTA response.

Config v5 retains all v4 fields, changes the header to `5`, and appends the
canonical base58 slash mint (or `-`), a canonical decimal relay count, and that
many HTTPS relay origins. The count is 0–8; origins must be distinct, use their
canonical spelling, and contain no path, query, fragment or credentials. Phones
append `/v1/fork-evidence` to each origin. The complete frame remains bounded to
8,192 bytes. Nonempty relay lists require enabled judge/log/ring pins and a
nonzero 32-byte mint. A pinned mint with an empty list permits receipt reading
without automatic submission. Earlier versions always decode with no relays and
mint `-`; appending v5 fields to an older version is rejected.

`MESSENGER_RELAY_URLS` (a JSON array) or `MESSENGER_SLASH_MINT_ADDRESS` selects v5
and requires the v4 identity and v3 migration settings. Both are public release
pins. Native iOS/Android resources, desktop configuration and `client.env`
preserve them. This extends the plan's original “v2.1” proposal after the v3/v4
migration and anchor formats; it does not reinterpret those formats. The mint
must match the deployed judge's custody mint before a receipt can be trusted.
The config extension alone does not enable filing: the durable mobile worker,
receipt watch and Details presentation are separate implementation work.

Config v6 wraps one canonical v1–v5 frame with a new-session suite minimum:

```text
6
<minimum session suite: 1 or 2>
<complete canonical v1–v5 frame>
```

The entire envelope is at most 8,192 bytes, uses LF separators and has no
trailing newline. Nested v6 envelopes, noncanonical numbers and extra fields
are rejected. `SecurityConfig.wire_version` is 6; `version` remains the
embedded feature profile, so the wrapper grants no additional witness, anchor
or relay authority. Bare v1–v5 frames retain their exact bytes and decode with
minimum 1. Parent-bound companion configurations hash the complete envelope.

The native/public configuration producer emits this wrapper only when
`MESSENGER_MINIMUM_SESSION_SUITE` is explicitly `1` or `2`. It requires complete
security pins; absent configuration cannot acquire authority from a floor.
The default remains unchanged. Mobile admission captures the exact canonical
native frame before cryptography and rechecks it alongside the original
account/session sources in the final writer. A changed frame retries without
publishing the stale result. Both CLI roles enforce the minimum parsed from
their supplied security frame; a malformed frame has no default fallback.
These paths and the minimum-taking protocol APIs pass scoped host checks.
Matching native artifacts and release qualification remain pending. Suite 2
activation requires the renewal rollout and 90-day adoption condition in the
witness plan, rather than elapsed time since this implementation was written.

The native writers select v3 only when all three explicit build settings are
present: `MESSENGER_TRANSPARENCY_LOG_VERSION=2`,
`MESSENGER_LEGACY_WITNESS_THRESHOLD`, and
`MESSENGER_LEGACY_WITNESS_SET_JSON`. The ordinary witness settings continue to
name the current policy. The public `client.env` exporter preserves both sets;
no private signing material is exported. Mesh parses and re-encodes the same
format and exposes the appropriate policy for each log.

A migration-capable native release must function before cutover: legacy
responses use its explicit historical policy until it has persisted an RFC
checkpoint. Thereafter, legacy responses cannot roll it back. Failed RFC
verification is never grounds for a fallback. Mesh supplies the app a bounded
list of stamped resolution requests: RFC then legacy before transition, RFC
only afterward. The transport uses the legacy request only for an explicit
404 `transparency_v2_not_active` response. A missing account, network failure,
or failed verification cannot select that fallback.

Mobile core fetches the bridge and atomically persists the new checkpoint,
account evidence, witness policy and verified bridge. Historical group anchors
remain verifiable through that bridge. Reinstalling an older native policy
cannot erase the RFC history. The CLI is stateless: its explicit v3 policy
selects only the RFC resolution endpoint.

Morse witnesses accept the same operator-installed `MESSENGER_SECURITY_CONFIG`
frame, whose service key must match their existing pin. A cached legacy witness
verifies current checkpoint freshness and the old quorum/bridge before its
first RFC signature. It persists the RFC checkpoint with the existing durable
compare-and-swap before publishing, including when publication must retry.
Its RFC polling may fall back on 404 only before the durable transition. An
older policy, a legacy response on the RFC route or a missing RFC checkpoint
afterward cannot roll it back. Native release and operator rollout remain gates.

## Durable directory transition

Migrations 021 and 022 create separate RFC nodes, checkpoints and witness
signatures, plus versioned account-entry positions. Installing them leaves the
legacy log active. Account entry bytes keep their signed account sequence and
share the existing content-addressed device records across versions.

Migration 024 adds RFC anchor references. Checkpoint retention uses one daily
budget across both logs, preserving each log's latest checkpoint, its own
anchored checkpoints, and the 35-day boundary. The accepted legacy seal and
quorum remain stored independently of checkpoint pruning. Tree nodes and leaf
hashes are retained in both profiles.

The explicit Mesh storage transition holds the same transaction advisory lock
as appends, deletion and retention:

1. **Sealing:** persist the exact final legacy checkpoint. Registration and
   device mutations return `transparency_migration_in_progress`; their entire
   transaction rolls back. Legacy checkpoint reads keep returning the seal,
   even after its freshness window expires. They never refresh it or change
   the response to a v2 checkpoint.
2. **Copying:** authenticate a legacy majority against trusted operator pins,
   retain its canonical witnesses with the seal, and append the bridge at RFC
   index zero. Copy at most 100 current account snapshots per transaction,
   retaining a durable source-sequence cursor. No RFC checkpoint is published
   while copying. Deletion remains serialized with copying and removes content
   in both versions; it cannot cause fallback to an older account snapshot.
3. **Active:** commit completion and the first RFC checkpoint together. New
   appends use RFC hashes and positions. There is no application operation to
   reopen the legacy log. Retries and fresh database connections resume from
   committed state; failed batches roll back content, nodes and cursor together.

The legacy seal and its witnesses survive independently of later registry
changes or historical checkpoint pruning. Legacy nodes and leaf hashes remain
unchanged. Copying current account entries is an explicit maintenance window;
capable native clients and operational witness migration must ship before a
production operator starts it.

The directory exposes `/v2/transparency/checkpoint`, `/consistency`, `/inclusion`
and `/witnesses` with the same request shapes as v1, and
`/v2/devices/resolve` with the existing proof-of-work admission. All v1 endpoints
continue to address only the legacy profile. Both
`/v1/transparency/checkpoint.note` and `/v2/transparency/checkpoint.note` expose
the RFC note; neither exposes a legacy root as RFC 6962. Before activation,
the latest RFC checkpoint and note endpoints return 404.

`POST /v1/transparency/checkpoint` and `POST /v2/transparency/checkpoint`
retrieve exact retained history. The body is exactly one nonzero big-endian u64
checkpoint sequence; the URL selects the log version. A successful response is
the original 188-byte `KTK`. Missing/pruned sequences (including values beyond
the database's signed integer range) return 404, malformed bodies return 400,
and storage failures return 500. These reads never poll, sign, create or refresh
a checkpoint, and never substitute the latest record. Responses carry
`Cache-Control: no-store`. They expose no account identifier. The phone still
verifies the signature and every committed field against its authenticated
anchor; a directory response cannot confer anchor trust.

`POST /v1/transparency/leaf` and `POST /v2/transparency/leaf` return a leaf hash
and compact inclusion path at an exact historical size. The 12-byte body is
`1 || KTQ || leaf_index:u32 || tree_size:u32`; size is 1–2^32−1 and index is
strictly smaller. The URL selects the log. The response is
`1 || KTL || leaf_hash:32 || inclusion:KTI`, with compact proof v2 for legacy
or v3 for RFC, at most 1,074 bytes. Full-tree proof v1 is not permitted here.
Missing future sizes return 404, malformed queries return 400, and storage
failures return 500. Responses use `Cache-Control: no-store`.

This read uses immutable stored nodes, so later growth and entry/checkpoint
pruning do not change the requested path. Neither request nor response contains
an account identifier or account record. A consumer must check the returned
index, exact size, proof version and root against its authenticated checkpoint;
decoding alone grants no trust. Together with a retained private inclusion path,
this supplies the public half of a possible F2 contradiction proof. The phone now retains its latest verified private path, builds F2 when the
public path proves a different hash, and retains the rejected candidate for
retries. Retained evidence now uses the native [phone filing worker](phone-filing-v1.md)
when this release pins a judge, receipt mint and relay origins.

`POST /v2/transparency/legacy-bridge` takes exactly twelve bytes: `1 || KBQ ||
legacy_size:u32 || rfc_size:u32`, with big-endian integers. The legacy size is
0–2^32−1 and the RFC size is 1–2^32−1. These sizes are independent; a long legacy
history can migrate to a smaller new tree. The response is `KTB` and proves the
requested legacy prefix to the seal and bridge inclusion at the exact requested
RFC size. No account identifier appears in this request or response.

Focused storage tests exercise quorum refusal, repeated operations, bounded
batches, connection replacement, rollback of an interrupted batch, deleted
copied/not-yet-copied accounts, expired-seal polling, versioned API responses and
verification of the directory's signed C2SP note.

## C2SP and fork evidence

The C2SP origin for the new log is `morseapp.io/log/main/v2`. Only v2 roots may
be advertised there. The note extension `morse-checkpoint <base64 KTK>` binds
the complete v2 checkpoint. Initial interoperability uses Ed25519 signatures
and Ed25519 cosignatures that authenticate extension lines. Other signature
types must not be counted unless they authenticate the complete Morse
checkpoint under the supported profile.

Fork verification requires both checkpoints to have the same log version.
An authenticated ring entry must supply its log version as well as its key,
size and root. Inclusion contradictions select the hash profile from the
signed checkpoint. A valid legacy checkpoint and valid v2 checkpoint are
different logs and cannot alone prove equivocation.
