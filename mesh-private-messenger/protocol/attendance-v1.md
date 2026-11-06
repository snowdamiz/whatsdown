# Weekly witness attendance v1

The judge retains attendance independently of its 4,096-entry anchor ring.
At the maximum writer cadence that ring wraps in about 2.8 days, before a
seven-day settlement. These judge-owned accounts preserve the weekly denominator
without trusting a keeper or service-signed checkpoint timestamps. Reward
settlement and eligibility remain separate work.

All account integers are little endian. Epochs are nonnegative chain
`Clock.unix_timestamp / 604800`. Activation's partial epoch is recorded; the
first full eligible epoch is always the next one. No history is backfilled.

## Activation and accounts

Log byte 7 is `attendance_enabled`, 0 or 1. Governance enables it once; no
instruction disables, resets, replaces or closes attendance accounts. Existing
disabled logs retain their four-account interface. Enabled logs require two
additional accounts on every post and cosign. Update readers and writers before
activation. This implementation does not activate a live log.

The clock PDA `["attendance", log_id]` has 65,616 bytes: an 80-byte header and
4,096 16-byte records aligned with the unchanged anchor ring. `log_id` is the
SHA-256 of the registry name, unlike the ring's existing name seed. Initialize
allocates 80 bytes and funds full rent; growth adds at most 10,240 bytes per call.
Enabling requires full allocation.

| Offset | Bytes | Header field |
| --- | --- | --- |
| 0 | 4 | `MAC` followed by version 1 |
| 4 | 32 | Log ID |
| 36 | 8 | Activation Unix seconds, positive i64; zero before activation |
| 44 | 8 | Activation slot |
| 52 | 8 | First full epoch |
| 60 | 8 | Latest posting epoch; activation epoch before the first post |
| 68 | 12 | Zero reserved bytes |

Record `i` at `80 + i * 16` stores posting epoch **plus one**, then posting slot.
A zero record denotes an untracked pre-activation entry and is accepted only
for a ring entry posted no later than activation. Missing metadata for a later
post or a mismatched slot after wrap is an error. A tracked post in the
activation slot counts normally.

The epoch PDA `["attendance-epoch", log_id, epoch:u64]` has 2,640 bytes:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `MAE` followed by version 1 |
| 4 | 32 | Log ID |
| 36 | 8 | Epoch |
| 44 | 8 | Number of new ring entries posted during this epoch |
| 52 | 8 | Latest posting slot; zero for an empty epoch |
| 60 | 2 | Occupied witness rows, 0–64 |
| 62 | 1 | Sealed flag, 0 or 1 |
| 63 | 17 | Zero reserved bytes |
| 80 | 2,560 | 64 rows: Witness PDA (32 bytes), signed count (u64) |

Rows are strictly sorted by raw PDA bytes. Occupied keys and counts are nonzero;
counts never exceed posts. Unused rows are zero. The authenticated historical
witness-set row supplies the address. Sixty-four rows exceed the two 16-member
generations that can overlap a week under the sequential 14-day generation
timelock. Overflow fails rather than dropping data.

Epoch accounts survive ring wrap, consuming about 137 KB per log per 52 weeks
plus the fixed clock. Operations must budget their rent; this version has no
rent reclamation path.

## Instructions and accounting

`S` marks signer and `W` writable. All accounts have owner, canonical address,
size and identity checks. Initialization handles pre-funded PDAs.

| Tag | Payload | Ordered accounts |
| --- | --- | --- |
| 25 | Empty | Governance S, payer WS, config, Log, clock W, System Program |
| 26 | Empty | Log, clock W |
| 27 | Empty | Governance S, config, Log W, clock W |
| 28 | Epoch u64 | Payer WS, Log, clock, epoch W, System Program |
| 29 | Empty | Log, epoch W |

Tag 28 is permissionless and idempotent, accepting epochs from activation
through the current chain epoch. Existing records, including sealed ones,
remain unchanged. Empty past epochs may be created and sealed: a missing account
cannot conceal recorded posts because every tracked post requires that account.

Enabled tag 3 appends `clock W, current epoch W`. Each new ring entry increments
the denominator and stores its posting epoch and slot. Reposting the identical
latest checkpoint changes neither. Accounting failure rolls back the ring too.

Enabled tags 7, 8, 9 and 30 append `clock, posting epoch W`. Only the first
combined cosign bit increments the witness count. A native signature after
C2SP may add the native bit but earns no second count. A late cosign across a
week boundary updates the original week. Pre-activation entries may finish
cosigning without a count; their final account is unused and need not exist.

Tag 29 seals after both the epoch boundary and the final posting slot plus
1,500 slots. At the inclusive last signing slot, sealing is refused. Sealed
records cannot gain posts or first cosigns.

## Mesh and writer integration

`Transparency.Attendance` decodes header slices, posting records and epochs,
and derives canonical PDAs. Decoding does not authenticate RPC responses.
`AnchorLog` exposes the one-way flag. The writer authenticates the Clock sysvar
for new-post epochs and retained posting metadata for cosigns. It opens the
current epoch idempotently before the service precompile and post in one
transaction, adjusting the precompile index. Boundary races fail atomically
and enter its existing durable retry path.

Compact C2SP tag 30 carries ring index u16, Ed25519 index u16, witness index u8,
signed seconds u64 BE and KTK188. Like native tag 9, it reuses the signature in
the earlier canonical Ed25519 instruction. The judge still reconstructs and
checks the exact statement, witness key, checkpoint hash and generation. Tag 8
remains supported. Mesh generates tag 30 by default; maximum origin length,
signed time and tree size fit 1,232 bytes with attendance accounts.
Deploy a judge supporting tag 30 before the updated directory/writer. The
reader/writer update must precede one-way attendance activation.

`scripts/prove-anchor-writer.sh` builds fresh SBF, runs judge adversarial tests,
and executes Mesh-prepared, Kit-signed production writer transactions with
attendance disabled and enabled. Unit tests also cover 4,100 posts across wrap.
This is local evidence, not deployment, independent review or funded settlement.

The selected first-year floor policy is $300/month multiplied by the attendance
factor: zero at 80%, full at 95%, linear between. Settlement still must enforce
eligibility, duration and pool funding; attendance accounts transfer no rewards.
