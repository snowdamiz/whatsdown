# Anchor ring account layout v1

This is the Phase 1 judge/reader contract under implementation. The local judge
subset, Mesh decoder, native RPC quorum reader, durable scheduler, chain-time
freshness check, authenticated fork construction and scheduled transaction
writer are implemented. Deployment and native release remain open. A decoded ring entry
alone must not create a fork pause or authorize a lookup.

The phone and monitor now share `Transparency.AnchorChain` and `AnchorRpc`
for authenticated reads, plus `AnchorHttp`, `AnchorConsistency`,
`AnchorContinuity` and `AnchorContradiction` for proof comparison. These Mesh
modules live in the protocol package; the phone retains its sealed scheduling
and state in mobile-core. `read_anchor_batch` reads at most 32 consecutive
postings in oldest-to-newest order through one or two account slices and
rereads the header before returning, including across ring wrap. The Mesh CLI
now runs this polling loop and serves cached status and retained evidence;
see the [monitor runbook](../ops/monitor/README.md). It persists an unresolved
candidate before proof I/O, separates late cosign checks from the consistency
cursor, and retains the first verified F1/F2/F3 frame with its ACV3 context.
Legacy and RFC logs use separate identities and their respective release
policies. Operational deployment and live monitoring gates remain open.

## Account bytes

All account integers use unsigned little endian, preserving the complete u64
range. Checkpoint wire frames and signed statements retain their existing big
endian encodings. The ring has 4,096 entries and occupies 426,048 bytes.

The 64-byte header is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `MRG` followed by layout version 1 |
| 4 | 32 | SHA-256 of the UTF-8 registry log ID, e.g. `morse-main` |
| 36 | 2 | Head: index of the most recently posted entry |
| 38 | 2 | Count, 0 through 4,096 |
| 40 | 8 | Last posted checkpoint sequence |
| 48 | 8 | Last posted checkpoint size |
| 56 | 8 | Slot of the most recent post |

An empty ring has head, sequence, size and slot zero. Before filling, head is
`count - 1`; a full ring wraps. Entry `i` begins at `64 + 104 * i`. Reading an
unfilled entry is an error. Distance zero means the head; increasing distances
walk backward through posting order, wrapping at index zero.

Each 104-byte entry is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | Checkpoint sequence |
| 8 | 8 | Tree size |
| 16 | 32 | Root |
| 48 | 32 | Morse checkpoint hash, including the service signature |
| 80 | 8 | Checkpoint timestamp, milliseconds since Unix epoch |
| 88 | 8 | Slot posted |
| 96 | 2 | Cosign bitmap |
| 98 | 1 | Transparency log version: 1 legacy or 2 RFC 6962 |
| 99 | 1 | Flags: bit 0 marks a rollback; all other bits zero |
| 100 | 2 | Native cosign bitmap, a subset of the cosign bitmap |
| 102 | 2 | Immutable witness-set generation |

The final six bytes refine the plan's reserved padding. Log version prevents
cross-profile comparisons. Native signatures bind the entire Morse checkpoint
hash; C2SP type 4 signatures bind its canonical text. The separate native bitmap
preserves FRK2 attribution rules. Bit positions refer to an immutable historical
witness-set generation; a rotation must create a new generation, never relabel
past bits. The judge must reject generation overflow rather than reuse an ID.
Generation zero means no witness set and requires both bitmaps zero.

## Log and configuration accounts

The singleton config PDA uses `["config"]`. Its 40 bytes contain `MCF` + version
1, the governance address (32 bytes), and four zero reserved bytes. Initializing
it requires the actual loader-v3 upgrade authority signer, the executable
program account, and its canonical loader-owned ProgramData PDA. The program
and ProgramData metadata must agree. A first caller cannot claim the config,
and initialized config cannot be replaced. Before the judge becomes immutable,
deployment review must confirm the pinned authority is the required Squads
3-of-5 authority with the required outside signers.

Each Log PDA uses `["log", UTF-8 log name]`; its ring uses `["ring", log name]`.
Names contain 1–32 lowercase ASCII letters, digits or hyphens. The 352-byte Log
record is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `MLG` + layout version 1 |
| 4 | 1 | Log version (1 or 2) |
| 5 | 1 | `service_slashed`, 0 or 1 |
| 6 | 1 | Name length |
| 7 | 1 | One-way attendance-enabled flag, 0 or 1; see `attendance-v1.md` |
| 8 | 32 | Name, zero-padded |
| 40 | 32 | SHA-256 of the name |
| 72 | 32 | Service signing key |
| 104 | 32 | Separate anchor authority |
| 136 | 32 | Ring PDA address |
| 168 | 32 | Directory bond vault (currently zero; custody pending) |
| 200 | 8 | Nonnegative signed i64 ready time, Unix seconds |
| 208 | 2 | Current witness-set generation (initially zero) |
| 210 | 2 | C2SP origin length |
| 212 | 128 | C2SP origin, zero-padded |
| 340 | 12 | Zero reserved bytes |

Version 1 has an empty origin. Version 2 has a nonempty origin of at most 128
printable ASCII bytes without spaces or `+`. Service and anchor keys must be nonzero.
Registration fixes the name, service key, log version, origin, ring and anchor
authority; no instruction currently changes them. The ready time is the chain
clock at registration plus 14 days. Both Rust posting checks and the Mesh
account reader retain the slash flag; the instruction that establishes a slash
is still pending.

## Witness identity and generation accounts

A witness ID is 1–64 lowercase ASCII letters, digits or hyphens. Its immutable
record identity is SHA-256 of `morse-witness-record-v1`, its one-byte ID length,
the ID and its 32-byte signing key, concatenated in that order. The Witness PDA
uses `["witness", log-name hash, record identity]`. Hashing accommodates IDs
longer than Solana's 32-byte seed limit. A new key for the same ID creates a
separate record; it never overwrites the historical key or transfers its bond.
IDs alone confer no ownership or client trust. Admission to an on-chain set
requires governance; admission to a phone trust policy requires a native release.

The 320-byte Witness record is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `MWI` + layout version 1 |
| 4 | 1 | ID length |
| 5 | 1 | Status: Registered 0, Active 1, Unbonding 2, Slashed 3, Withdrawn 4 |
| 6 | 1 | Excluded from rewards, 0 or 1 |
| 7 | 1 | Reserved zero |
| 8 | 64 | ID, zero-padded |
| 72 | 32 | Witness signing key |
| 104 | 32 | Operator wallet |
| 136 | 32 | Payout wallet |
| 168 | 32 | Operator's claimed affiliation hash; not proof of independence |
| 200 | 32 | Log-name hash |
| 232 | 32 | Bond vault, currently zero |
| 264 | 8 | Unbond time, currently zero |
| 272 | 48 | Reserved zeros |

Registration starts at Registered, with exclusion false. Only registration is
implemented; bonding, status changes, unbonding and payouts are still pending.
The signing key must differ from both operator and payout wallets. The operator
must sign the transaction, and an earlier exact Ed25519 instruction must prove
control over `morse-witness-register-v1 || ID || operator || payout`.

A generation PDA uses `["witness-set", log-name hash, generation u16 LE]`.
Its 2,752 bytes have a 64-byte header: `MWS` + version 1 at 0, log-name hash at
4, generation u16 at 36, witness count u8 at 38, reserved zero at 39,
nonnegative i64 ready time at 40, and 16 reserved zeros at 48. It contains 16
168-byte slots beginning at 64. Each occupied slot stores Witness PDA (32),
ID length (1), reserved zeros (7), zero-padded ID (64), key (32), payout (32).
Unused slots are entirely zero. Occupied slots are strictly sorted by ID with
unique keys; only Registered or Active records may enter a new generation.

Governance prepares exactly the next generation, with ready time equal to the
chain clock plus 14 days. The account is immutable immediately. After the delay,
anyone can activate it by advancing the Log pointer. Preparing cannot replace a
pending generation, and activation cannot skip, reverse or wrap a generation.
There is currently no cancellation instruction. Posting uses the active pointer;
cosigning uses the generation stored in the ring entry, including after rotation.

## Implemented instruction subset

Instruction tags are one byte. Integer fields below are little endian except
the unchanged KTK checkpoint frame, which is big endian. Extra payload bytes
or account metas are refused. `W` means writable and `S` means signer.

| Tag | Payload | Ordered accounts |
| --- | --- | --- |
| 0, initialize config | Governance address, 32 bytes | Upgrade authority S, payer WS, config W, executable program, ProgramData, System Program |
| 1, register log | Name length u8, name, log version u8, service key 32, anchor authority 32, origin length u8, origin | Governance S, payer WS, config, Log W, ring W, System Program |
| 2, grow ring | Empty | Log, ring W |
| 3, post anchor | Ed25519 instruction index u16, KTK 188 | Log, ring W, anchor authority S, Instructions sysvar |
| 4, register witness | Ed25519 index u16, ID length u8, ID, signing key 32, payout 32, operator hash 32, signature 64 | Operator S, payer WS, Log, Witness W, System Program, Instructions sysvar |
| 5, prepare set | Generation u16 | Governance S, payer WS, config, Log, generation W, System Program, 1–16 Witness accounts in ID order |
| 6, activate set | Empty | Log W, generation |
| 7, native cosign | Ring index u16, Ed25519 index u16, witness index u8, signature 64 | Log, ring W, generation, Instructions sysvar |
| 8, C2SP cosign | Ring index u16, Ed25519 index u16, witness index u8, timestamp u64 BE, signature 64, KTK 188 | Log, ring W, generation, Instructions sysvar |
| 9, compact native cosign | Ring index u16, Ed25519 index u16, witness index u8 | Log, ring W, generation, Instructions sysvar |
| 30, compact C2SP cosign | Ring index u16, Ed25519 index u16, witness index u8, timestamp u64 BE, KTK 188 | Log, ring W, generation, Instructions sysvar |

Enabled logs append the accounts specified in [weekly attendance](attendance-v1.md).
That contract defines tags 25–29, durable counters and activation. Tag 30 reuses
the precompile's signature with the same exact statement checks as tag 8.

Tag 9 retains the signature in the earlier self-contained Ed25519 instruction
and omits its redundant copy in tag 7. The judge reconstructs the exact native
statement from the authenticated entry and historical witness slot, checks the
actual Instructions sysvar, earlier instruction index, Ed25519 program ID,
canonical offsets, witness key and message, and relies on that precompile's
successful signature verification. Tag 7 remains supported. The same historical
generation and inclusive 1,500-slot window apply to both tags.

The payer funds the Log and the ring's full eventual rent at registration. The
ring initially allocates 64 bytes, then grows by at most 10,240 bytes per call
until exactly 426,048 bytes. Anyone may pay transaction fees for growth. No
posting is allowed before full allocation or before the ready time. Creation
uses System allocation and assignment after topping up rent, so pre-funding
a PDA cannot block setup. There is no rent withdrawal or account reset path.

Posting verifies the pinned service key and log version, the separate anchor
authority signer, and the exact earlier Ed25519 precompile statement. Every
account owner and PDA is checked. The chain Clock supplies the posting slot.
Reposting the exact latest checkpoint is idempotent and does not refresh that
slot or erase cosignatures. A sequence/size regression or differing checkpoint
at the same sequence is retained with the flag set. Posting order alone is not
cryptographic fork evidence; only the FRK relation checks may establish that.

Cosigning accepts only a filled ring position and its canonical, program-owned
generation account. The chain slot must be from the posting slot through posting
slot + 1,500 inclusive. Anyone may pay the transaction; a wallet signer is not
substituted for the witness key's exact Ed25519 proof. Native signatures cover
`mesh-msg/v1/transparency-witness || ID || checkpoint hash`. C2SP reconstructs
the canonical Ed25519 cosignature text using the Log's fixed origin, signed time,
tree size/root and `morse-checkpoint` extension. It requires version 2, size at
most u32::MAX, the canonical empty RFC root at size zero, and a KTK hash matching
the ring entry. The KTK key/version must match the Log. There is no separate
freshness requirement on C2SP's signed timestamp when recording; the authenticated
posting slot controls the deadline. Phone authorization freshness is separate.
The encoding follows [C2SP Ed25519 cosignatures](https://c2sp.org/tlog-cosignature@v1.1.0)
and [checkpoint text](https://c2sp.org/tlog-checkpoint@v1.1.0).

Both signatures OR their bit into the cosign bitmap. Only native signatures
also set the native bitmap. Retries cannot add attendance twice or erase bits;
enabled logs also update durable weekly counters. Reward settlement remains
unimplemented. Recording does not
claim that the witness is bonded, trusted by a release, or eligible for payment.

## RPC agreement

The caller supplies release-pinned ring address, program owner, log ID and at
least three provider URLs. It takes an unbiased random sample of three without
replacement. Distinct URL paths at the same origin do not constitute separate
providers. Release configuration requires HTTPS. The low-level reader permits
loopback HTTP for local validators and tests.

Each read uses finalized `getAccountInfo`, base64, an exact bounded `dataSlice`,
and `minContextSlot`. Replies must have the requested ID, expected owner,
non-executable account, nonzero lamports, exact slice length and sufficient
context. The reader follows no redirects, limits replies to 8,192 bytes, and
times out each request after three seconds.

The first two providers must return identical account bytes. If they fail or
disagree, the third may form a matching pair with either. Different finalized
context slots do not invalidate matching bytes. The lower slot of the agreeing
pair becomes the next minimum, so one lying provider cannot force future reads
to an arbitrary slot. Fewer than two usable responses yields
`anchor_rpc_unavailable`; two or more usable but nonmatching responses yields
`anchor_rpc_disagree`. Neither is fork evidence.

Header log ID must match the native pin and its last slot cannot exceed the
agreed context. Entry reads use that context as their minimum. The head entry
must match the header's sequence, size and posting slot; every historical entry
must have been posted no later than the header. After reading an entry, the
reader rereads the header at or after the entry's agreed context. A changed
header yields `anchor_snapshot_changed` so the caller can restart safely.

Provider origin separation does not prove independent ownership. Selecting
independently operated providers remains a native release review requirement.
Two colluding providers can forge the same response; this is the plan's
explicit RPC quorum trust assumption, not a Solana light-client proof.

The native Log reader similarly requires two matching 352-byte slices and
binds the decoded record to the pinned log ID, service key, log version and
ring address. The scheduled reader retains an authenticated slash and pauses
new sessions and key changes through the shared transparency safety guard.
The witness-set reader similarly fetches exactly 2,752 bytes and binds the decoded
record to the expected log and historical generation. Mesh derives the canonical
generation PDA from program, log-name hash and generation locally through the
public `Solana.Address` package. Log reads likewise derive their PDA locally;
every reader verifies the pinned ring against the derived ring and binds the log
name to its hash. Native config v4 carries the program/log pins; v1–v3 cannot
enable the reader. The Mesh decoder rejects duplicate
keys/IDs/addresses, out-of-range bits, a different generation and noncanonical
padding. Attribution preserves native versus C2SP semantics and does not replace
release-pinned witness policy.

`read_anchor_freshness` reads `getBlockTime` for the finalized header's posting
slot from the same sampled origins. Two matching nonnegative integer timestamps
are required; a third provider breaks a disagreement or replaces an unavailable
provider. Requests have a three-second timeout, a 1,024-byte response cap and no
redirects. Null, malformed time, wrong response IDs and transport errors never
become timestamps. Local time before chain time reports `anchor_clock_skew`;
an empty ring has no freshness verdict. Age strictly over 7,200 seconds is stale.
The calculation checks ordering before subtraction, including at the signed
integer limit. Service checkpoint timestamps and estimated slot durations are
never used. Staleness and clock/RPC problems are notices, not fork evidence or
grounds to block existing messaging.

## Durable schedule and native observation

`Mobile.AnchorSchedule` seals `ASC1` state under `anchor-schedule/v1`: a 32-byte
configuration identity, four big-endian u64 millisecond times (next daily check,
next permitted attempt, last start, last completion), a u32-length-prefixed
0/16-byte active token and a u32-length-prefixed result of at most 4,096 bytes.
Maximum size is 4,188 bytes. The absent-record insert and subsequent updates
use a SQLite compare-and-swap transaction; a failed comparison cannot write
companion records. Readers and writers wait at most one second for contention. Other errors
propagate, and corrupt ciphertext never resets the schedule.

A check reserves the next hour before network I/O. Successful account/time
observations schedule 24 hours from the attempt; verified changed or new device
sets can request an earlier check, still at most hourly. Empty/stale rings,
clock and RPC failures retry after the reserved hour. A crash consumes that
hour; a unique attempt token prevents an old completion from overwriting its
replacement. Backward time cannot authorize an extra attempt.
In-flight reservations hold new trust changes until the result commits, so a
concurrent caller cannot bypass a slash response or a failed completion write.
Saved RPC/clock notices clear that temporary hold; a crashed reservation is
recoverable at the next permitted attempt. Existing ratchet messaging continues.
This is an
on-device due check at foreground refresh and verified contact-key changes,
not a guarantee of execution while the operating system suspends the app.

The identity is SHA-256 of `morse-anchor-observation-v1`, program bytes, ring
bytes, log-name hash, service key and one-byte log version. RPC rotation and
witness-policy updates do not erase a slash or reset the same identity's limit.
The `ACO1` result contains a status byte and four big-endian u64 fields: checked
time in milliseconds, finalized header context slot, posted slot and block time
in seconds. Status codes in order are pending, observed, stale, RPC unavailable,
RPC disagreement, clock unavailable, empty, service slashed, consistent,
mismatch, proof unavailable. Existing numeric codes are unchanged. An empty result
means pending. The check preserves its finalized context as the minimum for
later reads. Log slash checks precede freshness checks, including empty rings.
An authenticated slash is latched for this identity and cannot be cleared by a
later healthy reply or outage. Same-device-set checkpoint refreshes and existing
ratchet messaging remain allowed.

The `mesh_messenger_anchor_check` ABI accepts only the app database path. Mesh
loads native pins, chooses providers, owns the clock/rate limits and returns five
bounded UTF-8 vectors (status plus the four decimal u64 values), using the normal
output-list codec. `off` indicates absent v4 pins. Settings presents notices;
a slash or mismatch adds a persistent pause banner. `observed` explicitly does
**not** claim consistency: it is used when the device has no usable checkpoint
for this log version/key. No production program, native release or relay
deployment is claimed.

## Checkpoint comparison and evidence

After authenticating a fresh account, the check reads the newest ring entry and
rereads its header to detect overwrite. When the device is behind the public
tree, this is the newest qualifying entry from the plan. When it is ahead of
the writer, the implementation verifies the reverse consistency path (public
tree to local tree). This additionally checks the public prefix without scanning
4,096 old positions or treating ordinary writer lag as a mismatch. Signed
sequence/size contradictions are checked in either direction before fetching.
Key-change ingestion supplies the already authenticated candidate checkpoint
and directory origin before accepting it; foreground checks use the sealed cache.
The latest verified lookup atomically retains a compact leaf hash/inclusion path
under `transparency-leaf/v1`, without another copy of the account record. Legacy
full-tree evidence is verified and reduced to the equivalent compact path.
The legacy-to-RFC bridge remains responsible for transitions between log versions.

Mesh retrieves the exact historical checkpoint by sequence, with a 188-byte
response cap. It verifies the service signature, version, sequence, size, root,
timestamp and checkpoint hash against the authenticated entry. Unequal sizes
require a bounded 1,070-byte compact consistency proof for the exact two sizes
and hash profile. Equal sizes still require the exact checkpoint commitment.
Requests contain no account or contact identifier, use a three-second timeout,
and follow no redirects. HTTPS origins and local loopback test origins only
are accepted.

An invalid successful response or explicit refusal produces `mismatch`, pausing
new sessions and key changes. Transport failures, server errors, HTTP 408 and
429 produce `proof_unavailable`. Those notices alone do not pause trust. Once
a mismatch is saved, an outage, stale account or absent cache cannot clear it:
only a completed successful comparison can. A rejected candidate is not in the
ordinary cache, so retries use the private view saved with the mismatch. An older
benign cache or another contact cannot clear that pause. If a different incoming
key-change candidate also needs comparison, both checks run under the same claim
and must succeed. A changed public anchor must prove an exact compact extension
of the earlier saved public tree, with advancing sequence and nondecreasing size;
otherwise the original evidence and pause remain. This prevents the public log
from concealing a fork by later switching to the private branch. A newly proven
fork is retained regardless of this optional continuity response. Retry attempts
share the hourly reservation. Existing ratchets and unchanged-device-set refreshes remain usable.

Refusal and invalid proofs are **not** cryptographic fork proofs. Same-size
different roots and signed sequence/size rollbacks produce a verified `FRK`
with an anchor reference, even if the directory is unreachable. These
checks also preserve a validly signed historical response that contradicts
either the anchor or the local checkpoint; an invalid signature cannot create
such evidence. A contradiction with the local checkpoint alone retains both
signed checkpoints instead of using an anchor reference. Anchored proofs retain
at most one valid private signature per release-pinned key, including signatures
whose public cosigns have not arrived yet. The historical generation named by
the entry is read at its canonical PDA through the same finalized quorum; the
current Log generation cannot relabel an old bit. Attribution intersects valid
private signatures, exact release-pinned IDs/keys, and public historical cosigners.
C2SP signatures support root contradictions; rollback attribution requires native
signatures on both sides. A failed generation read still retains the service fork
and private signatures, allowing a relay to resolve the set later. Finder addresses
and relay filing remain separate work. The zero finder means no bounty destination
is selected.

When consistency is unavailable or fails and a retained private leaf lies within
the public tree, Mesh requests `POST /v1|v2/transparency/leaf` for that index and
exact anchored size. The bounded 1,074-byte answer must have the same index, exact
size and hash profile, and its inclusion path must verify against the authenticated
anchor root. A different leaf hash, with both paths verified, produces canonical
F2 evidence and the same atomic permanent pause and witness attribution as F1.
Malformed/refused leaf proofs produce a mismatch, never fabricated FRK evidence.
A valid unchanged leaf does not establish consistency of the whole log and cannot
release an existing mismatch. Discovery covers the retained lookup's leaf; it does
not claim exhaustive search over private leaves the phone never received.

The sealed `anchor-evidence/v1` record retains `ACV3`, the 32-byte configuration
identity, checked time and finalized context slot (u64 big-endian), the exact
64-byte header, ring index (u32 big-endian), exact 104-byte entry, 188-byte local
checkpoint, then u32-length-prefixed origin, served checkpoint bytes, consistency
response bytes, FRK bytes, original private KTW witness bytes, and the exact
historical witness-set account bytes (or empty if unavailable), private compact
`KTL` bytes and the served leaf response. The native
key-change path passes candidate signatures before accepting or caching the
candidate, including its private inclusion path; foreground checks read the sealed
witness and leaf caches. The bounded context
codec caps the origin at 2,048 bytes, served checkpoint at 188, consistency at
1,070, FRK at 8,009, KTW at 2,774, historical account at exactly 2,752 or zero,
and each leaf vector at 1,074 bytes; the complete frame is at most 19,433 bytes.
It rejects trailing/truncated input and still reads `ACV1` (no witness/account
or leaf vectors) and `ACV2` (no leaf vectors). No response is fetched without its
body cap.
Evidence and the observation commit in one fenced SQLite transaction. A failed
write leaves the active claim and temporary trust hold intact. When a new valid
fork is found, its first FRK and matching context additionally commit under
`transparency-fork/v1` and `transparency-fork-anchor/v1`; later checks cannot
replace that first proof or its context. A retained fork keeps the existing
permanent fork pause even after a subsequent consistent comparison.

This local context records a quorum-authenticated observation, not a standalone
Solana light-client proof. A relay must independently resolve the referenced
entry before trusting it; a reference whose ring position has since been
overwritten needs the original signed public checkpoint to remain fileable.

## Directory transaction receipts

The Mesh directory implements the receipt store and discovery API used by the
scheduled writer. A receipt is public lookup metadata, not evidence of chain
finality or a signature verification result. Readers must authenticate the
configured judge, log, ring, entry and historical witness set themselves.

After confirming the transaction at finalized commitment and reading back the
exact entry, the internal writer posts a 128-byte `KTA` to
`/internal/v1/transparency/anchors` with the directory's internal bearer token.
The gateway never exposes this write route. All integers in the frame are big
endian:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `01` followed by ASCII `KTA` |
| 4 | 2 | Log version, 1 or 2 |
| 6 | 8 | Nonzero checkpoint sequence |
| 14 | 8 | Tree size, 1 through 2³²−1 |
| 22 | 32 | Canonical Morse checkpoint hash |
| 54 | 2 | Ring index, 0 through 4,095 |
| 56 | 64 | Transaction signature bytes |
| 120 | 8 | The ring entry's original posted slot |

The directory selects the corresponding legacy/RFC table, locks the exact
checkpoint against concurrent pruning, and checks its size and hash before
inserting. Creation returns 201; replay of the same anchor coordinates returns
200, retaining the first transaction signature and `posted_at`. A second
idempotent transaction may have a different signature; it must still report the
entry's original slot. A conflicting size, hash, index or slot returns 409;
missing retained history returns 404. Malformed frames or coordinates exceeding
PostgreSQL's signed bigint range return 400, and storage failures return 503.
Concurrent writers serialize on the checkpoint row. The foreign key protects
the anchored checkpoint after commit. No receipt can create or refresh a KTK.

`GET /v1/transparency/anchor/{sequence}` and its `/v2/` counterpart return the
saved receipt as JSON with `Cache-Control: no-store`. Sequences in paths are
canonical positive decimal u64 values. Missing receipts return 404; the endpoint
never substitutes a newer receipt. `checkpoint_sequence`, `tree_size` and `slot`
are decimal **strings** to preserve integers above JavaScript's exact-number
range. `log_version` and `ring_index` are numbers, `checkpoint_hash` is lowercase
hex, and `tx_signature` is base58. Equal sequences in different log versions
remain independent. These APIs disclose no account, contact or message data.

## Writer instruction preparation

The directory exposes two internal bearer-authenticated preparation routes.
`GET /internal/v1/transparency/anchor-candidate/{version}` reads the latest
available checkpoint from the selected log, respecting the legacy seal and
inactive RFC log. It verifies the service signature before returning the KTK,
hash, root, key, version, decimal-string sequence/size/time, and the canonical
Ed25519 and tag-3 instruction bytes as lowercase hex. It does not mint a new
checkpoint. The chain writer must match the key and version to its authenticated
Log account before using the result.

`POST /internal/v1/transparency/anchor-cosigns` takes exactly 2,768 bytes:
`01 || AWQ || log_version:u16BE || sequence:u64BE || ring_index:u16BE || set:2752`.
The writer must first authenticate that immutable historical set's owner, PDA,
log and generation against the target entry. Mesh decodes it canonically, reads
the exact checkpoint, and selects stored signatures by each historical ID **and
key**, independently of later registry changes. Only cryptographically valid
signatures produce instruction pairs. The response includes the checkpoint
fields, log hash, generation, ring index and at most 16 `cosigns`, each with
`witness_index`, `ed25519` and `instruction`. Missing signatures produce an empty
list; they are never replaced by signatures on a newer checkpoint. Each pair
initially refers to Ed25519 instruction zero. Responses use `no-store`.

Mesh's `Transparency.AnchorWrite` owns signature verification and instruction
preparation. `ops/cloudflare/anchor-transactions.mjs` uses pinned Solana Kit
8.4.0 to construct and sign v0 transactions, with a separate fee payer and
anchor authority. It fixes the program/account list, adjusts each earlier
Ed25519 index to its actual batch position, and measures the compiled packet
before signing. Batches contain at most four cosigns and never exceed 1,232
bytes. The tested nine-character native IDs fit four compact pairs in 1,136
bytes; the maximal-timestamp C2SP fixture fits one pair in 1,100 bytes. Longer
IDs and larger C2SP statements can require smaller batches.

`scripts/prove-anchor-writer.sh` rebuilds the judge and introspection probe,
runs the Rust suite, exports instruction bytes from Mesh, signs them with Kit,
and executes the exact signed transactions in LiteSVM with the real SBF and
Ed25519 precompile. It checks posting, idempotent reposting, native/C2SP bitmaps,
altered signatures, valid precompiles for the wrong key or message, and tag-7
compatibility. It also confirms a base fee of 15,000 lamports per anchor post
(two wallet signatures plus one service precompile verification) and 10,000
for a single-witness cosign. These exclude priority fees. See the
[Solana fee model](https://solana.com/docs/core/fees/fee-structure).
Local test accounts stand in for reviewed deployment setup.

## Writer recovery boundary

`ops/cloudflare/anchor-outbox.mjs` journals the exact fully signed wire,
signature, last valid block height and public intent in Durable Object SQLite
before broadcasting. One immutable scope must name the cluster genesis,
program, log and wallet identities. A changed scope is refused. One pending
post and up to sixteen cosign packets fit. A drain defaults to four operations;
the production cycle makes two passes of at most five, prioritizing the post
and the least recently checked cosigns. Concurrent
wakeups on the same instance share one drain. The scheduler must own a single
instance and save its recovery alarm before invoking it.

Lost responses retain the original wire and a persisted 30-second resend
backoff. A finalized readback is saved before the directory receipt request;
a failed receipt write retries that exact receipt without another broadcast.
Completion, finalized failure and expiry remain durable until acknowledged.
The scheduler must atomically save its cadence/cursor update with that
acknowledgement. These outcomes do not themselves authorize signing a replacement.

`anchor-rpc.mjs` uses pinned Kit 8.4.0's public JSON-RPC and bigint codecs with
a 3-second timeout, 32-KiB response cap, no redirects and an expected genesis
hash. It preserves full-width integers in both request and response directions.
Processed or confirmed transactions, including provisional errors, remain
pending. Finalized success requires a caller-supplied authenticated entry
readback at or after the transaction slot. Expiry requires a finalized block
height strictly beyond the saved lifetime, then another historical signature
lookup whose context has not regressed. A transaction landing during that
check takes precedence. RPC failure never becomes expiry or a receipt.

The fee helper warns at or below 0.2 SOL, marks at or below 0.05 SOL critical,
and flags more than 1 SOL as overfunded. It reports integer lamports. Operator
funding is capped at 1 SOL; unsolicited excess deposits do not stop the writer.
The scheduler refuses new spending below 25,000 lamports and delivers durable
alerts through an explicitly configured HTTPS receiver. Miniflare tests restart
the actual SQLite Durable Object after lost replies and failed receipt writes,
exercise all sixteen cosign slots, and reject a changed identity. RPC tests
cover finality, expiry races, malformed replies, timeouts and integers above
JavaScript's exact-number range.

## Writer account readback and configuration

`anchor-accounts.mjs` derives the Log and ring addresses from the configured
program and log name. It requires exact finalized owner, executable flag,
nonzero lamports, full account space and slice length, with a nondecreasing
context slot. It binds the Log's service key, anchor authority, version, name,
hash, ring and origin to configuration; slash and timelock values remain visible
to the scheduler. All integers preserve their u64 width. These reads follow the
[Solana account-info contract](https://solana.com/docs/rpc/http/getaccountinfo).

Ring reads group requested entries into slices of at most 128 entries, with at
most four requests in flight. A second header read at the highest observed
context must match the original. Unfilled slots, invalid bitmap relations,
future posting slots and a head inconsistent with its header are rejected.
Ordinary post readback checks the head first; recovery can search the entire
retained ring through bounded slices. A cosign readback reads its exact index
and requires the expected version, sequence, size, checkpoint hash, posting
slot, generation and every requested witness bit.

Historical set reads derive the generation PDA, reject noncanonical padding,
duplicate or unsorted identities, and derive every member's own Witness PDA
from its ID and key. The Log's current generation never relabels an older entry.
The writer trusts its configured RPC's finalized chain reporting. This does
not replace the phone's independent quorum reader or make a receipt a chain
proof. SBF tests exercise this reader against real post/cosign accounts and
compare its resulting directory receipt with Mesh-generated codec bytes.

`anchor-config.mjs` is off by default. Enabled modes `devnet` and `mainnet` pin
the corresponding [Solana SDK genesis hash](https://github.com/solana-labs/solana/blob/master/sdk/src/genesis_config.rs).
Configuration carries the program, log name/version, service key, origin and
HTTPS RPC URL. Separate fee-payer and anchor-authority secrets import as
non-extractable Kit signing resources; temporary import buffers are cleared.
Both wallets must differ from the service key. The durable identity includes
the cluster, program, log, version, service, origin and wallet addresses, while
RPC rotation preserves it. No configuration check starts a deployment or funds
a wallet.

`anchor-directory.mjs` uses only the internal bearer-authenticated preparation
and receipt routes, bounded responses, ten-second deadlines and no redirects.
Historical preparation responses must match the exact entry, historical
generation and log hash; a current checkpoint cannot substitute for an old one.
HTTP 200/201 acknowledges an idempotent receipt, while failures retain journaled
work.

## Scheduled writer

`anchor-job.mjs` uses these production adapters; `anchor-cycle.mjs` owns cadence,
historical selection and atomic journal acknowledgement. The independent
`anchor` JobScheduler instance persists its recovery alarm before I/O and
normally wakes every fifteen seconds. The backend minute cron bootstraps it
only when `MORSE_ANCHOR_MODE` is enabled. Witness jobs have a different alarm
and cannot delay it. Disabling the mode stops the next run without deleting
saved transactions.

A new checkpoint hash and increasing sequence are required to post. Both a
persisted local minute fence and the latest public entry's finalized block time
enforce the cadence. Changed roots/sizes trigger a post; unchanged roots become
due at 59 minutes to leave time for finality before the hourly target. The
scheduler cannot mint a service checkpoint. If the directory keeps returning
the same signed checkpoint, it reports a missing heartbeat. A local clock
behind finalized chain time, log timelock, service slash or insufficient fee
reserve prevents new signing/broadcast, while finalized receipts still settle.

Cosign selection starts with 32 newest entries and grows bounded reads only
while the oldest is within 1,500 slots. The inclusive slot window is checked
for new and already-signed work. Each turn prepares one incomplete checkpoint
under its immutable generation and persists a round-robin cursor. Complete
C2SP attendance does not require redundant native signatures. Pending and
just-completed bits prevent duplicate preparation from an older snapshot.
`MORSE_COSIGN_CRANK=off` stops preparation/broadcast while retaining finality
reconciliation. Zero-witness logs still post normally.

Alerts persist an event ID and body before HTTP delivery, coalesce unchanged
health, retry after thirty seconds and report recovery. Missing alert routing
retains pending state without blocking transactions. Cached `/health` exposes
bounded progress and fee state; observations older than two minutes are not
healthy and a probe never invokes the signer. The runbook documents the alert
receiver contract and operational funding cap.

The full proof executes the production job with actual Mesh preparation and
receipt fixtures, Kit signatures, SQLite journal and SBF account readback.
Its controlled RPC reports finality for locally executed transactions; it does
not simulate consensus or establish a live network latency gate. Miniflare
also checks the complete production Worker bundle, separate alarm lifecycle,
non-extractable signing resources, restart recovery and disabled mode.
