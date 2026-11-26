# Morse Judge v1 (on-chain programs)

Status: implemented and tested locally; not deployed. The two Solana programs
live in `programs/` (`morse-judge`, `morse-rewards`), with LiteSVM tests,
a local-validator smoke test and the `morse-admin` runbook tool
(`programs/README.md`). This document is what chain writers (anchor poster,
cosign crank, relay, burn crank), phones and monitors implement against. The
plan is `WITNESS_NETWORK_PLAN.md` §5.2, §5.3, §5.8, §6.3, §6.5, §6.6, §6.12;
wire formats are `witness-network-v1.md` and INTERFACES §1, §5.

- **`morse-judge`** anchors checkpoints of one or more transparency logs,
  records witness cosignatures (attendance), holds the directory's and the
  witnesses' bonds, and slashes them on proof of a fork. It becomes
  immutable after review: windows and shares are constants.
- **`morse-rewards`** pays witnesses from a USDC pool by the attendance the
  judge records, and burns Morse tokens sent to its burn account. It is
  upgradeable behind governance and only ever *reads* judge accounts.

Nothing here can grant trust (invariant I2): phones read `service_slashed`
and witness status only to refuse.

## 1. Conventions

- Integers in account data and instruction data are **little-endian**.
  `KTK`, `FRK` and the statements inside instruction data keep their Morse
  **big-endian** encoding byte for byte.
- Every judge account is owned by the judge program; phones and monitors
  must check `owner == pinned judge program id` for every account they read
  (INTERFACES §8). Bond vaults and the locked vault are SPL Token accounts
  (owner = the SPL Token program) whose token authority is a judge PDA.
- Byte 0 of every judge account except the ring is a type tag, byte 1 the
  layout version (1). Tags: 1 Config, 2 Log, 3 Witness, 4 Stage, 5 Proof.
- Only the classic SPL Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
  is supported. Token-2022 mints are refused.
- `‖` is concatenation. `sha256(x)` is SHA-256. Addresses are 32 bytes.
- Instruction data byte 0 is the discriminator; the "data" column below
  lists the bytes after it.

### Program IDs and configuration

The program IDs are the addresses of the deploy keypairs
(`programs/target/deploy/morse_judge-keypair.json` for local work; separate,
offline-held keypairs for devnet and mainnet, §12). Nothing is hard-coded in
either program: PDAs derive from the executing program's own ID, and
`morse-rewards` stores the judge's ID in its Config.

- **Phones** pin `<judge program id> <log account>` in security config v2's
  anchor line. Every other address they need (ring, directory vault, witness
  accounts) is read from the Log account.
- **Chain writers** take the same pair (judge program ID, Log account) from
  their configuration, plus their own signing keys, and derive or read
  everything else as below. The relay also needs Config (derived) for the
  mints.

## 2. Rules compiled into the judge

| Constant | Value |
|---|---|
| Epoch | 604,800 s; epoch `e` = `floor(unix_timestamp / 604800)` (starts Thursday 00:00 UTC) |
| Cosign window | 1,500 slots after the slot the anchor was posted |
| Proof window | 28 days (2,419,200,000 ms) from the older checkpoint's `timestamp_ms` |
| Unbonding delay | 30 days (2,592,000 s) from `request_unbond` |
| Parameter timelock | 14 days (1,209,600 s) between `propose` and `apply` |
| Finder's share | `amount / 10` (10%, rounded down) of each slashed vault; the rest is locked (USDC) or burned (token) |
| Witness list | 16 entries per log; bit `i` of every cosign bitmap is list entry `i` |
| Ring | 4,096 entries × 104 bytes + 64-byte header = 426,048 bytes |
| Largest `FRK` | 8,192 bytes |

## 3. Addresses

| Account | Seeds (judge program) | Notes |
|---|---|---|
| Config | `["config"]` | one per deployment |
| Log | `["log", log_id]` | `log_id` is 32 bytes; convention: the ASCII name zero-padded (`morse-main`, `morse-canary`) |
| AnchorRing | `["ring", log_id]` | address also stored in Log |
| Directory bond vault | `["bond", log_id, "directory"]` | SPL token account, authority = itself |
| Witness | `["witness", log_id, sha256(witness_id)]` | |
| Witness bond vault | `["bond", log_id, sha256(witness_id)]` | SPL token account, authority = itself |
| Locked vault | `["locked", log_id]` | USDC token account, authority = itself; no instruction ever signs for it |
| Stage | `["stage", submitter, nonce u64 LE]` | |
| Proof (pay-once) | `["proof", proof_hash]` | `proof_hash` per INTERFACES §5 |
| ProgramData | `[program_id]` under `BPFLoaderUpgradeab1e11111111111111111111111` | read by `initialize` |

Rewards program: Config `["config"]`, pool authority `["pool"]`, burn
authority `["burn"]`, Epoch `["epoch", epoch u64 LE]`. The **pool vault** is
the USDC associated token account of the `["pool"]` PDA.

Seeds use `sha256(witness_id)` rather than the ID itself: a seed is at most
32 bytes, and variable-length seeds would let a witness named `directory`
collide with the directory vault.

## 4. Judge accounts

### 4.1 Config (192 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 1 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | pending change kind (0 = none; kinds in §6.1) |
| 4 | 4 | zero |
| 8 | 32 | governance authority (the Squads vault) |
| 40 | 32 | USDC mint |
| 72 | 32 | Morse token mint (zeros = not set) |
| 104 | 32 | rewards program ID (zeros = not set; informational, for clients) |
| 136 | 8 | minimum for new USDC bonds (base units) |
| 144 | 8 | minimum for new token bonds (base units) |
| 152 | 8 | pending change applies at (unix seconds, i64) |
| 160 | 32 | pending value (address, or u64 LE in the first 8 bytes) |

### 4.2 Log (2,584 bytes) — pinned by phones

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 2 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | `service_slashed` (0 or 1) |
| 4 | 1 | witness count (0–16, entries in use) |
| 5 | 1 | directory bond status (§4.4 statuses) |
| 6 | 1 | log kind: 0 main (never closable), 1 canary (closable after a slash, §6.2) |
| 7 | 1 | directory vault bump |
| 8 | 8 | slashed at (unix seconds, i64; set when the directory bond is slashed) |
| 16 | 32 | log_id |
| 48 | 32 | service public key (Ed25519) |
| 80 | 32 | anchor authority (the only signer of `post_anchor`) |
| 112 | 32 | ring address |
| 144 | 32 | directory bond vault address |
| 176 | 32 | locked vault address |
| 208 | 8 | directory withdrawable at (unix seconds, i64; set by `request_unbond`) |
| 216 | 64 | anchor counts: 4 × {u64 epoch, u64 count}, slot = epoch mod 4 |
| 280 | 2,304 | witness list: 16 entries × 144 bytes |

List entry `i` at `280 + 144·i`:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | witness_id length (1–64) |
| 1 | 64 | witness_id (UTF-8 `[a-z0-9-]`, zero-padded) |
| 65 | 7 | zero |
| 72 | 32 | witness signing key (Ed25519) |
| 104 | 32 | Witness account address |
| 136 | 8 | since slot (u64): the slot the entry was (re)filled; bitmap bit `i` of a ring entry posted before it does not count |

An anchor count is incremented by `post_anchor` for every non-evidence entry,
in the epoch of the posting time. A counter slot whose epoch differs from the
one asked for means 0.

### 4.3 AnchorRing (426,048 bytes, no tag)

Header:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | log_id |
| 32 | 4 | head (u32): index the next entry is written to |
| 36 | 4 | count (u32): entries written, at most 4,096 |
| 40 | 8 | last sequence (of the newest non-evidence entry) |
| 48 | 8 | last tree size (same entry) |
| 56 | 8 | last slot (same entry): "last public checkpoint" for the bond counter |

Entry `i` (0–4,095) at `64 + 104·i`:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | sequence |
| 8 | 8 | tree size |
| 16 | 32 | root |
| 48 | 32 | checkpoint hash = `SHA-256("mesh-msg/v1/transparency-checkpoint" ‖ statement146 ‖ sig64)` |
| 80 | 8 | checkpoint timestamp (ms) |
| 88 | 8 | slot posted |
| 96 | 2 | cosign bitmap (u16; bit `i` = list entry `i`) |
| 98 | 1 | evidence: 0 normal, 1 same size as the tip with another root (F1), 3 sequence/size order disagrees with the tip, or same sequence with other content (F3) |
| 99 | 1 | zero |
| 100 | 4 | epoch of the posting time (u32) |

Entries `0..count` are valid; once `count` is 4,096 every index is valid and
`head` wraps. A ring index names a physical slot, so an index held for a long
time may by then hold a newer entry: check its content before relying on it.
Phones read the header and single entries with `getAccountInfo` +
`dataSlice` (`offset = 64 + 104·i`, `length = 104`).

### 4.4 Witness (336 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 3 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | status: 0 Registered, 1 Active, 2 Unbonding, 3 Slashed, 4 Withdrawn |
| 4 | 1 | excluded (1 = never paid; one-way) |
| 5 | 1 | list index (0–15), 255 = not in the log's list |
| 6 | 1 | bond vault bump |
| 7 | 1 | witness_id length |
| 8 | 64 | witness_id (zero-padded) |
| 72 | 32 | Log account address |
| 104 | 32 | witness signing key |
| 136 | 32 | operator wallet (owns the bond, signs bond/unbond/withdraw) |
| 168 | 32 | payout address (rewards pay to a USDC account it owns) |
| 200 | 32 | operator hash (opaque, from registration) |
| 232 | 32 | bond vault address |
| 264 | 8 | withdrawable at (unix seconds, i64; set by `request_unbond`) |
| 272 | 64 | cosign counts: 4 × {u64 epoch, u64 count}, slot = epoch mod 4, counted in the anchor's epoch |

The directory bond uses the same statuses (Log offset 5). `service_slashed`
is 1 exactly when the directory status is Slashed.

### 4.5 Stage (96 + length bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 4 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | zero |
| 4 | 4 | verification marks (u32, §7.2) |
| 8 | 32 | submitter |
| 40 | 32 | Log account address |
| 72 | 8 | nonce |
| 80 | 2 | total length (1–8,192) |
| 82 | 2 | bytes written |
| 84 | 12 | zero |
| 96 | n | staged `FRK` bytes |

### 4.6 Proof (112 bytes) — one per proof hash, forever

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 5 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | fork kind (1, 2, 3) |
| 4 | 4 | zero |
| 8 | 32 | Log account address |
| 40 | 32 | proof hash |
| 72 | 32 | paid to: the finder address named in the proof, or the submitter |
| 104 | 8 | slot |

A phone that filed a proof reads `["proof", proof_hash]`: if `paid to` is not
its one-time address, someone else's proof of the same fork landed first
(plan §6.9).

## 5. Ed25519 checks (instruction introspection)

The judge never verifies Ed25519 itself. The transaction carries a native
Ed25519 program instruction (`Ed25519SigVerify111111111111111111111111111`);
the runtime verifies every signature listed in it before any instruction
runs, and fails the whole transaction if one is wrong. The judge instruction
names that instruction by its index in the transaction (`ed_ix`, u8) and the
judge then checks, through the instructions sysvar
(`Sysvar1nstructions1111111111111111111111111`, address checked), that the
named instruction:

1. exists in **this** transaction and belongs to the Ed25519 program;
2. holds an entry whose three instruction indexes are all `0xFFFF` ("this
   instruction"), so the verified bytes are its own data; entries pointing
   into other instructions are ignored;
3. at that entry's offsets holds exactly the expected public key (32 bytes),
   message (exact length and bytes) and, where the table says so, signature.

Ed25519 instruction data (the layout `@solana/web3.js`
`Ed25519Program.createInstructionWithPublicKey` produces, one entry per
signature):

```
u8  count            number of entries (≥ 1)
u8  0                padding
count × 14 bytes     offsets, u16 LE each:
    signature_offset, signature_instruction_index = 0xFFFF,
    public_key_offset, public_key_instruction_index = 0xFFFF,
    message_offset, message_size, message_instruction_index = 0xFFFF
payload              the public keys, signatures and messages the offsets point at
```

Offsets are from the start of the Ed25519 instruction's data. One Ed25519
instruction may carry several entries; the judge accepts the check if any
entry matches, so one Ed25519 instruction can serve several judge
instructions (or several marks) in the same transaction.

| Check | Public key | Message | Signature compared |
|---|---|---|---|
| `post_anchor` | Log service key | the 146-byte statement rebuilt from the KTK: `"mesh-key-transparency-v1" ‖ u16 BE 1 ‖ KTK[4..124]` | yes: KTK bytes 124..188 (the checkpoint hash covers them) |
| `cosign` | list entry's signing key | `"mesh-msg/v1/transparency-witness" ‖ witness_id ‖ ring entry checkpoint_hash` | no |
| `register_witness` | the signing key in the data | `"morse-witness-register-v1" ‖ witness_id ‖ operator wallet (32) ‖ payout address (32)` | no |
| mark bit 0 | Log service key | statement of the proof's C1 | yes: C1's signature |
| mark bit 1 | Log service key | statement of the proof's inline C2 | yes: C2's signature |
| mark bit 2 + j | signing key of the listed witness whose ID is attestation `j`'s | `"mesh-msg/v1/transparency-witness" ‖ id ‖ hash` from attestation `j` | yes: attestation `j`'s signature |

Entry sizes: a checkpoint check is 14 + 32 + 64 + 146 = 256 bytes; a witness
statement is 14 + 32 + 64 + 64 + id length.

## 6. Judge instructions

"s" = signer, "w" = writable. Accounts beyond those listed are ignored.

| # | Instruction | Data after the discriminator |
|---|---|---|
| 0 | `initialize` | authority32 ‖ usdc_mint32 ‖ token_mint32 ‖ rewards_program32 ‖ u64 min_bond_usdc ‖ u64 min_bond_token |
| 1 | `propose` | u8 kind ‖ value32 |
| 2 | `apply` | — |
| 3 | `register_log` | log_id32 ‖ service_key32 ‖ anchor_authority32 ‖ u8 kind (optional: 0 main, 1 canary; 96 bytes = main) |
| 4 | `set_anchor_authority` | new_authority32 |
| 5 | `grow_ring` | — |
| 6 | `post_anchor` | u8 ed_ix ‖ KTK188 |
| 7 | `cosign` | u32 ring_index ‖ u8 list_index ‖ u8 ed_ix |
| 8 | `register_witness` | signing_key32 ‖ payout32 ‖ operator_hash32 ‖ u8 excluded ‖ u8 ed_ix ‖ u8 id_len ‖ id |
| 9 | `bond_directory` | u64 amount |
| 10 | `bond` | u64 amount |
| 11 | `request_unbond` | u8 target (0 directory, 1 witness) |
| 12 | `withdraw` | u8 target (0 directory, 1 witness) |
| 13 | `stage_init` | u64 nonce ‖ u16 total_length |
| 14 | `stage_write` | u16 offset ‖ bytes |
| 15 | `stage_verify` | u8 ed_ix |
| 16 | `stage_close` | — |
| 17 | `prove_same_size` | u8 mode (0 inline ‖ u8 ed_ix ‖ FRK, or 1 staged) |
| 18 | `prove_contradiction` | same |
| 19 | `prove_rollback` | same |
| 20 | `admit_witness` | u8 replace (0xFF append, else list index) ‖ u8 excluded |
| 21 | `close_log` | — |

### 6.1 Governance

**`initialize`** — once, by the program's upgrade authority (so nobody can
front-run the deployer).

| # | Account | |
|---|---|---|
| 0 | deployer = upgrade authority | s, w (pays) |
| 1 | Config | w |
| 2 | judge ProgramData | |
| 3 | System program | |

Refused: signer is not ProgramData's upgrade authority (`Unauthorized`),
zero USDC mint (`InvalidParameter`), Config exists.

**`propose`** — the authority starts the 14-day timelock for one change; a
new proposal replaces the pending one; kind 0 cancels.

| # | Account | |
|---|---|---|
| 0 | authority | s |
| 1 | Config | w |

Kinds: 1 authority (address), 2 token mint (address; only while unset,
never equal to the USDC mint), 3 rewards program (address), 4 minimum for
new USDC bonds (u64), 5 minimum for new token bonds (u64).

**`apply`** — anyone, once `now ≥ pending_after`. Accounts: 0 Config (w).
Refused: `NoPendingChange`, `TimelockActive`, `InvalidParameter`.

**`register_log`** — immediate (it cannot touch existing logs).

| # | Account | |
|---|---|---|
| 0 | authority | s |
| 1 | payer | s, w (Log and locked-vault rent; the vault itself in a Squads transaction) |
| 2 | Config | |
| 3 | Log `["log", log_id]` | w (created) |
| 4 | locked vault `["locked", log_id]` | w (created, USDC) |
| 5 | USDC mint (= Config) | |
| 6 | System program | |
| 7 | SPL Token program | |

The directory status starts Registered and the kind is stored at Log offset
6 (`morse-main` is kind 0; drill logs such as `morse-canary` are kind 1).
The ring must then be grown (§6.2).

**`set_anchor_authority`** — immediate key rotation of a log's hot anchor
key. Accounts: 0 authority (s), 1 Config, 2 Log (w).

Governance has no instruction that moves a vault or changes a window or
share.

### 6.2 Ring and anchoring

**`grow_ring`** — anyone. The first call creates the ring at 10,240 bytes;
each further call adds 10,240 bytes (the per-instruction realloc limit) and
tops up rent from the payer, until 426,048 bytes (42 calls; up to 8 per
transaction). A ring shorter than that refuses anchors (`RingNotReady`).

| # | Account | |
|---|---|---|
| 0 | payer | s, w |
| 1 | Log | |
| 2 | ring | w |
| 3 | System program | |

**`post_anchor`** — the anchor authority posts a service-signed checkpoint.

| # | Account | |
|---|---|---|
| 0 | anchor authority | s |
| 1 | Log | w (anchor counts) |
| 2 | ring | w |
| 3 | instructions sysvar | |

Checks: signer = Log anchor authority; not a slashed canary log (its ring is
frozen, `InvalidStatus`); KTK version 1 and magic `KTK`; KTK key = Log
service key; Ed25519 check (§5); ring full size. Then, against the
tip (the newest entry with evidence 0):

| New checkpoint vs tip | Result |
|---|---|
| no tip yet | stored, normal |
| same sequence, same checkpoint hash | refused `DuplicateAnchor` (a retry that already landed) |
| same sequence, other hash | stored with evidence 3 |
| newer sequence and smaller tree, or older sequence and larger tree | stored with evidence 3 |
| same tree size, other root | stored with evidence 1 |
| newer sequence, tree not smaller (same root if same size) | stored, normal |
| older sequence, tree not larger | refused `StaleAnchor` |

Evidence entries are public, cosignable and usable as the ring reference of a
fork proof, but do not move the header's last sequence/size/slot and are not
counted as anchors.

**`cosign`** — anyone pays; typically the crank.

| # | Account | |
|---|---|---|
| 0 | Log | |
| 1 | ring | w |
| 2 | Witness at list entry `list_index` | w (attendance) |
| 3 | instructions sysvar | |

Checks: `list_index < witness count` and the Witness account is that entry's;
`ring_index < count`; the entry was posted at or after the list entry's
since slot; `current slot ≤ slot posted + 1,500` (`CosignWindowClosed`);
Ed25519 check (§5); witness status Registered, Active or Unbonding. Sets the
bitmap bit and, for a normal entry, adds one to the witness's cosign count
for the entry's epoch. Cosigning an entry whose bit is already set succeeds
and changes nothing, so cranks may retry.

**`close_log`** — governance reclaims a finished canary log's ring rent.

| # | Account | |
|---|---|---|
| 0 | authority | s |
| 1 | Config | |
| 2 | Log | |
| 3 | ring (Log's) | w (closed) |
| 4 | destination named by governance | w (receives the ring's lamports) |
| 5… | optional pairs: a Stage made for this log (w), its submitter (w) | the stage is closed and its rent returned to its submitter |

Allowed only for a canary-kind log whose directory bond is slashed, and only
28 days (the proof window) after the slash (`NotClosable`, `CloseTooEarly`).
A slashed canary log accepts no anchors, so every entry in its ring was
posted before the slash. Main-kind logs are never closable: their public
evidence stays for good. The Log, Witness and Proof accounts and every vault
are untouched; after closing, ring references to this log fail
(`RingNotReady`) while inline proofs still work.

### 6.3 Witnesses and bonds

**`register_witness`** — the operator's wallet registers, proving control of
the witness key. The witness is not in the list yet (it cannot cosign and is
never implicated) until governance admits it.

| # | Account | |
|---|---|---|
| 0 | operator wallet | s, w (pays; becomes the bond owner) |
| 1 | Log | |
| 2 | Witness `["witness", log_id, sha256(id)]` | w (created) |
| 3 | instructions sysvar | |
| 4 | System program | |

`excluded` 1 declares a Morse-run witness (never paid). IDs are
`[a-z0-9-]{1,64}` and unique per log for good (the PDA exists forever).

**`admit_witness`** — governance puts a registered witness into the list.

| # | Account | |
|---|---|---|
| 0 | authority | s |
| 1 | Config | |
| 2 | Log | w |
| 3 | Witness | w |
| 4 | replaced Witness (the account at list entry `replace`) | w when replacing; any account when appending (pass the judge program ID) |

Checks: witness belongs to this log, is not listed, and is Registered or
Active; append needs fewer than 16 entries (`WitnessListFull`); replacing
needs the slot's current witness to be Slashed or Withdrawn
(`SlotNotReusable`); no other listed entry has the same signing key
(`DuplicateSigningKey`). Sets the entry's since slot to the current slot,
the witness's list index, and `excluded |= excluded`. The replaced witness's
list index becomes 255.

**`bond`** — the operator posts or tops up its bond.

| # | Account | |
|---|---|---|
| 0 | operator wallet | s, w (pays vault rent on the first bond) |
| 1 | Config | |
| 2 | Log | |
| 3 | Witness | w |
| 4 | bond vault | w (created on first bond with this mint) |
| 5 | mint (USDC, or the token once set) | |
| 6 | source token account (authority = operator) | w |
| 7 | System program | |
| 8 | SPL Token program | |

Status must be Registered or Active. While Registered, the vault balance
after the deposit must reach the Config minimum for that mint
(`BondBelowMinimum`); the status becomes Active. A vault keeps the mint of
its first bond.

**`bond_directory`** — governance posts or tops up the directory bond.

| # | Account | |
|---|---|---|
| 0 | authority | s, w (pays vault rent) |
| 1 | Config | |
| 2 | Log | w |
| 3 | directory vault | w |
| 4 | mint | |
| 5 | source token account (authority = authority) | w |
| 6 | System program | |
| 7 | SPL Token program | |

Directory status must be Registered or Active; it becomes Active.

**`request_unbond`** — status Registered/Active → Unbonding; withdrawable
30 days later.

| # | Account | |
|---|---|---|
| 0 | owner: the authority (directory) or the operator (witness) | s |
| 1 | Config | |
| 2 | Log | w |
| 3 | Witness (target 1) or any account (target 0; pass the Log) | w |

**`withdraw`** — the whole vault to a token account the owner owns, at or
after the withdrawable time, only from Unbonding (so never after a slash).
Status becomes Withdrawn; the vault stays (empty).

| # | Account | |
|---|---|---|
| 0 | owner | s |
| 1 | Config | |
| 2 | Log | w |
| 3 | Witness (target 1) or any account (target 0) | w |
| 4 | bond vault (directory or witness) | w |
| 5 | destination token account (its owner must be the signer) | w |
| 6 | SPL Token program | |

Money leaves a vault only here and in a slash (§7). The locked vault has no
instruction at all.

### 6.4 Staging

Proofs are usually larger than one transaction (1,232 bytes).

**`stage_init`** — accounts: 0 submitter (s, w; pays), 1 Log, 2 Stage
`["stage", submitter, nonce]` (w, created), 3 System program.

**`stage_write`** — append only: `offset` must equal the bytes written so
far and the total may not exceed the declared length. Accounts: 0 submitter
(s), 1 Stage (w). About 1,000 bytes fit per transaction. A complete stage
accepts no more writes, so verified bytes never change.

**`stage_verify`** — anyone; the stage must be complete and made for this
Log. Parses the staged `FRK` and ORs into the stage's marks every signature
the Ed25519 instruction at `ed_ix` verifies (§5, §7.2). Accounts: 0 Stage
(w), 1 Log, 2 instructions sysvar. Repeat with further Ed25519 instructions
until every needed mark is set (about three checkpoint signatures or five
witness signatures per transaction).

**`stage_close`** — the submitter abandons a stage and gets its rent back.
Accounts: 0 submitter (s, w), 1 Stage (w). A successful staged proof closes
its stage the same way.

### 6.5 Proofs: `prove_same_size`, `prove_contradiction`, `prove_rollback`

The `FRK` kind byte must match the instruction (`KindMismatch`). Mode 0 takes
the `FRK` inline after `ed_ix`, with its Ed25519 entries in the same
transaction; mode 1 takes it from a complete stage whose submitter signs.

| # | Account | |
|---|---|---|
| 0 | submitter | s, w (pays the Proof account's rent) |
| 1 | Config | |
| 2 | Log | w |
| 3 | ring (Log's; always passed) | |
| 4 | Proof `["proof", proof_hash]` | w (created) |
| 5 | Stage (mode 1) | w; mode 0: any account, read-only (pass the judge program ID) |
| 6 | instructions sysvar | |
| 7 | System program | |
| 8 | SPL Token program | |
| 9 | locked vault (Log's) | w |
| 10 | token mint | w when Config has a token mint (pass it); otherwise any account, e.g. the USDC mint, read-only |
| 11 | finder USDC account (§7.4) | w |
| 12 | finder token account (§7.4) | w; when no token-bonded vault is slashed, repeat account 11 |
| 13 | directory vault (Log's) | w |
| 14… | for every implicated witness, in ascending list index: Witness (w), its bond vault (w) | |

The submitter computes the implicated set exactly as §7.3 does (from the
`FRK`, the Log's list and, for a ring reference, the entry's bitmap);
anything else is refused (`ImplicatedAccountsMismatch`).

## 7. Fork proofs and slashing

### 7.1 Acceptance

The judge decodes `FRK` v1 strictly (INTERFACES §5: version 1, `"FRK"`, kind
1–3, C2 form 0 or 1, at most 16 attestations with ID lengths 1–64, kind 2
paths of at most 64 hashes, no trailing bytes, at most 8,192 bytes;
otherwise `FrkMalformed`) and then requires, in order:

1. the kind matches the instruction;
2. the proof's log service key equals the Log's (`WrongLogKey`), and C1's
   service signature is verified (mark bit 0), as is inline C2's (bit 1);
   a ring-referenced C2 must be a written entry (`RingIndexInvalid`) and
   counts as service-signed, since `post_anchor` verified it;
3. the fork rule (`NotAFork`), with C2 from the ring entry when referenced:
   - F1: equal tree sizes, different roots;
   - F2: `i < min(size1, size2)`, `leaf1 ≠ leaf2`, and both RFC 9162 §2.1.3.2
     inclusion paths verify with Morse node hashing
     (`SHA-256("mesh-msg/v1/transparency-node" ‖ l ‖ r)`, leaves given as
     leaf hashes);
   - F3: sequence order and size order disagree, or equal sequences with
     different checkpoint hashes;
4. `now_ms ≤ min(C1.timestamp_ms, C2.timestamp_ms) + 28 days`
   (`ProofWindowClosed`);
5. every attestation whose ID is in the Log's list and whose hash is C1's or
   C2's checkpoint hash is verified (`AttestationNotVerified`).
   Attestations by other IDs, or on other hashes, are ignored.

Rule 5 makes the proof's bytes alone decide who is slashed: nobody can land
a proof that leaves out a verification to shield a witness, because the
pay-once record would then block the complete proof of the same bytes.

### 7.2 Marks

A proof's verified signatures are a u32 bitmap: bit 0 C1's service
signature, bit 1 inline C2's, bit `2 + j` attestation `j` (by the listed
witness whose ID it names, under that entry's key). Inline proofs compute
the marks from the named Ed25519 instruction; staged proofs accumulate them
with `stage_verify`.

### 7.3 Implicated witnesses

For each list entry `i < witness count`: signed C1 if a verified attestation
with the entry's ID names C1's hash; signed C2 if one names C2's hash, or if
C2 is a ring reference whose bitmap has bit `i` set and whose slot posted is
at or after the entry's since slot. Implicated = signed both.

### 7.4 Slashing and the finder

After acceptance the judge creates the Proof account `["proof", proof_hash]`
(existing: `AlreadyProven`) and slashes:

- the directory bond, unless its status is Slashed or Withdrawn: status
  Slashed, `service_slashed = 1`;
- each implicated witness, unless Slashed or Withdrawn: status Slashed.

Each slashed party's vault, if it exists and holds tokens, is emptied:
`amount / 10` to the finder account for that vault's mint, the rest to the
locked vault (USDC) or burned (the token mint in Config). If no party
changes status the proof is refused (`NothingToSlash`) and no Proof account
is created. A Registered witness or directory with no bond still becomes
Slashed (trust is taken away even with nothing to take).

The payee is the `FRK` finder address when nonzero, otherwise the submitter.
The finder account used for a mint must be an initialized SPL token account
of that mint whose owner is the payee, and, when the proof names a finder,
the payee's **associated token account** for that mint
(`FinderAccountMismatch`). The relay creates it beforehand in the same
transaction with the ATA program's `CreateIdempotent` (data `[1]`; accounts
payer s w, ATA w, owner, mint, System, SPL Token).

Because the proof hash excludes the finder address, the same fork pays once
whatever address is named; a different encoding of the same fork finds
everyone already Slashed.

## 8. Judge errors (`custom program error: <code>`)

| Code | Name | Meaning |
|---|---|---|
| 6000 | WrongAccount | an account is not the one required (address, owner, tag, length, relationship) |
| 6001 | Unauthorized | the required signer is not the expected key |
| 6002 | InvalidData | malformed instruction data |
| 6003 | TimelockActive | `apply` before the 14 days are over |
| 6004 | NoPendingChange | `apply` with nothing pending |
| 6005 | InvalidParameter | zero authority/mint, token mint already set or equal to USDC |
| 6006 | RingNotReady | ring not fully grown |
| 6007 | RingAlreadyGrown | `grow_ring` on a full ring |
| 6008 | InvalidCheckpoint | KTK malformed or not under the Log's service key |
| 6009 | SignatureNotVerified | no matching Ed25519 entry (§5), or a required mark is missing |
| 6010 | DuplicateAnchor | the tip was already posted |
| 6011 | StaleAnchor | older than the tip and not a contradiction |
| 6012 | RingIndexInvalid | ring index not written, or older than the list entry |
| 6013 | CosignWindowClosed | more than 1,500 slots after posting |
| 6014 | InvalidStatus | bond status does not allow the action |
| 6015 | WitnessListFull | 16 entries in use |
| 6016 | SlotNotReusable | the slot's witness is not Slashed or Withdrawn |
| 6017 | DuplicateSigningKey | the key is already listed |
| 6018 | InvalidWitnessId | not `[a-z0-9-]{1,64}` |
| 6019 | MintNotAllowed | not the USDC or configured token mint, or not the vault's mint |
| 6020 | BondBelowMinimum | first bond below the minimum for new bonds |
| 6021 | UnbondingNotElapsed | withdraw before the 30 days |
| 6022 | StageInvalid | bad length, out-of-order or overflowing write, incomplete or already complete stage |
| 6023 | FrkMalformed | `FRK` does not decode |
| 6024 | WrongLogKey | the proof names another service key |
| 6025 | NotAFork | the pair does not satisfy the kind's rule |
| 6026 | ProofWindowClosed | older checkpoint more than 28 days old |
| 6027 | AttestationNotVerified | a listed witness's attestation on C1/C2 lacks a verified signature |
| 6028 | AlreadyProven | this proof hash was already paid |
| 6029 | ImplicatedAccountsMismatch | witness/vault pairs are not exactly the implicated set |
| 6030 | FinderAccountMismatch | finder account is not the payee's (associated) account for the mint |
| 6031 | NothingToSlash | every party already Slashed or Withdrawn |
| 6032 | KindMismatch | `FRK` kind differs from the instruction |
| 6033 | AmountZero | zero bond amount |
| 6034 | WrongDestination | withdraw destination not owned by the bond owner |
| 6035 | NotClosable | `close_log` on a main-kind or unslashed log |
| 6036 | CloseTooEarly | `close_log` less than 28 days after the slash |

Generic runtime errors also occur: `NotEnoughAccountKeys`,
`InvalidInstructionData` (unknown discriminator), `MissingRequiredSignature`,
and SPL Token errors from a failed transfer (codes below 100).

## 9. What each writer does

- **Anchor poster** (every root change, at most one per minute, plus an
  hourly heartbeat): transaction = [Ed25519 instruction with the service
  signature entry, `post_anchor` with `ed_ix = 0`], signed by the fee payer
  and the anchor authority. `DuplicateAnchor` means an earlier attempt
  landed: treat it as success. The ring index of the new entry is the
  header's `head` read before posting (or `head − 1 mod 4096` after).
- **Cosign crank**: for each witness signature on an anchored checkpoint
  hash, within 1,500 slots of posting. Four cosigns fit one legacy
  transaction: one Ed25519 instruction with four entries at index 0, then
  four `cosign` instructions with `ed_ix = 0` (tested at ≤ 1,232 bytes).
- **Relay**: verify the `FRK` off-chain; compute the proof hash and check
  `["proof", hash]` does not exist; stage it (`stage_init`, `stage_write`
  chunks, `stage_verify` with Ed25519 entries for C1, inline C2 and every
  listed witness's attestation on C1/C2); then one transaction with
  `CreateIdempotent` for the finder's ATA (named finder) and the `prove_*`
  instruction. A relay paying its own fees fits nine implicated witnesses in
  a legacy transaction; more need an address lookup table. The worst case
  (16 witnesses implicated through the ring bitmap, 17 vaults emptied) uses
  about 70,000 compute units; request 400,000.
- **Burn crank**: send bought tokens to a token account owned by the
  rewards `["burn"]` PDA, then call rewards `burn` (§10).

Measured compute: `post_anchor` about 1,200 CU, `cosign` about 1,100 CU,
worst-case proof about 70,000 CU.

Implementations: the anchor poster, cosign crank, weekly `settle_epoch`, burn
crank and bond counter run in the backend Worker (`ops/cloudflare`: `anchor.mjs`,
`burn.mjs`, `bond-counter.mjs`, `network.mjs`); the relay is `ops/relay`; the
monthly canary and weekly rewards drills are `ops/drills`. All use the JavaScript
client of this document, `ops/relay/judge.mjs`, which
`ops/drills/local-validator.test.mjs` checks against the built programs on a
local validator.

## 10. `morse-rewards`

### 10.1 Accounts

Config `["config"]` (904 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 1 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | pool authority bump |
| 4 | 1 | burn authority bump |
| 5 | 3 | zero |
| 8 | 32 | authority (the time-locked governance vault) |
| 40 | 32 | judge program ID |
| 72 | 32 | judge Log account paid for (`morse-main`) |
| 104 | 32 | USDC mint |
| 136 | 32 | Morse token mint (zeros = not set) |
| 168 | 32 | price oracle program (owner of the feed) |
| 200 | 32 | price feed account |
| 232 | 8 | floor per payable witness per epoch (USDC base units) |
| 240 | 8 | floor until (unix seconds, i64) |
| 248 | 8 | token-bond target (USDC base units, e.g. 10,000,000,000 for $10,000) |
| 256 | 8 | reserved: allocated and not yet claimed |
| 264 | 640 | token-bond watch: 16 × {Witness address32, i64 below_since}, by list index |

Epoch `["epoch", epoch u64 LE]` (1,320 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | tag = 2 |
| 1 | 1 | version = 1 |
| 2 | 1 | bump |
| 3 | 1 | allocation count |
| 4 | 4 | zero |
| 8 | 8 | epoch |
| 16 | 8 | budget: pool balance minus reserved at settlement |
| 24 | 8 | allocated |
| 32 | 8 | anchors counted for the epoch |
| 40 | 1,280 | 16 × {Witness address32, payout address32, u64 amount, u8 claimed, 7 zero} |

### 10.2 Instructions

| # | Instruction | Data | Accounts |
|---|---|---|---|
| 0 | `initialize` | authority32 ‖ judge32 ‖ log32 ‖ usdc32 ‖ u64 floor ‖ i64 floor_until | 0 deployer = upgrade authority (s, w), 1 Config (w), 2 rewards ProgramData, 3 System |
| 1 | `set_param` | u8 kind ‖ value32 | 0 authority (s), 1 Config (w) |
| 2 | `fund_pool` | u64 amount | 0 funder (s), 1 source (w), 2 pool vault (w), 3 Config, 4 SPL Token |
| 3 | `settle_epoch` | u64 epoch | 0 payer (s, w), 1 Config (w), 2 judge Log, 3 pool vault, 4 Epoch (w, created), 5 System, 6 price feed (any account when unset), 7… (Witness, bond vault) for every list entry, in list order |
| 4 | `claim_reward` | u64 epoch ‖ u8 index | 0 Config (w), 1 Epoch (w), 2 pool vault (w), 3 pool authority `["pool"]`, 4 destination (w), 5 SPL Token |
| 5 | `burn` | — | 0 Config, 1 burn authority `["burn"]`, 2 token account owned by it (w), 3 token mint (w), 4 SPL Token |
| 6 | `check_bond` | — | 0 Config (w), 1 judge Log, 2 price feed, 3 Witness, 4 its bond vault |

`set_param` kinds: 1 authority, 2 token mint, 3 oracle program, 4 price
feed, 5 floor per epoch (u64), 6 floor until (i64), 7 token-bond target
(u64); integers in the first 8 bytes. Changes take effect immediately: the
authority is a Squads vault with a 14-day time lock, which also holds the
upgrade authority (§12).

`fund_pool` is a convenience: a plain SPL transfer to the pool vault funds
it equally.

### 10.3 Settlement

`settle_epoch(e)` runs once per epoch (the Epoch PDA), by anyone, at or after
`(e + 1) · 604,800 + 900` seconds (the last cosigns must have landed). The
witness accounts must be exactly the Log's list, in order
(`WitnessAccountsMismatch`), so nobody can be left out. With `anchors` = the
Log's anchor count for `e` and `cosigns` = the witness's count for `e`:

- attendance = `min(cosigns / anchors, 1)` (0 when there were no anchors);
- pay factor = `clamp((attendance − 0.80) / 0.15, 0, 1)` in parts per
  million: full at ≥ 95%, none at ≤ 80%;
- payable = status Active, not excluded, token bond eligible (§10.4);
- share = `budget / payable count`, raised to the floor while `now <
  floor_until`; pay = `share × factor`;
- if the pays add up to more than the budget they are scaled down to it;
- the rest carries over: nothing is moved, only `reserved` grows by the
  allocations.

Only witnesses with a nonzero pay get an allocation. Morse's witnesses
(excluded) are never paid (I8). A Morse-only or empty registry settles with
no allocations and the whole pool carries over. The judge keeps four epochs
of counters, so settle within three weeks of an epoch's end.

`claim_reward` pays an allocation once to a USDC token account owned by the
payout address registered with the judge (`WrongDestination`,
`AlreadyClaimed`); anyone may call it.

### 10.4 Token bonds (Phase 5)

A bond vault in the Morse token is valued at the feed's price; USDC bonds
are always eligible. When the value is below 80% of the target, the watch
records when that started (`settle_epoch` and the permissionless
`check_bond` both refresh it); after 7 days below, the witness is not
payable until the value recovers. The witness is never slashed for this and
its bond is untouched. A stale or invalid feed leaves the watch unchanged.

**Price feed account** (generic; an adapter program publishes it):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | price (i64 LE, > 0): the 7-day TWAP, USD per whole token = `price × 10^exponent` |
| 8 | 4 | exponent (i32 LE, −18…18) |
| 12 | 8 | publish time (unix seconds, i64 LE) |

The account's owner must be Config's oracle program and its address Config's
price feed. It counts when `publish_time ≤ now + 60` and `now −
publish_time ≤ 86,400`. With both mints at 6 decimals, value in USDC base
units = `amount × price × 10^exponent`.

### 10.5 Burn

`burn` burns the whole balance of a token account of the configured token
mint whose owner is the `["burn"]` PDA (the burn crank creates it as that
PDA's associated token account and sends bought tokens there). Anyone may
call it; burns are visible as SPL `Burn` instructions.

### 10.6 Errors

7000 WrongAccount, 7001 Unauthorized, 7002 InvalidData, 7003 EpochNotOver,
7004 AlreadySettled, 7005 AlreadyClaimed, 7006 WrongDestination,
7007 WitnessAccountsMismatch, 7008 NoTokenMint.

## 11. Reading the chain (phones, monitors, bond counter)

- **Phone anchor check** (plan §6.7): Log (owner check; `service_slashed` at
  offset 3; witness list), ring header (offsets 32–64), and the entries it
  needs (§4.3). A slashed service or a Slashed witness is a reason to refuse,
  never to trust.
- **Bond counter** (§6.17): `morse-main` directory vault balance (Log offset
  144 → token account amount at offset 64), `service_slashed`, the count of
  listed witnesses in status Slashed, each pinned witness's vault balance,
  and the ring's last slot. The canary log is never counted.
- **Monitor**: watch for ring entries with evidence ≠ 0 and file proofs.

## 12. Deployment runbook

Tools: Solana CLI 4.1, `cargo-build-sbf`, Squads v4, and `morse-admin`
(`programs/tests/src/bin/morse-admin.rs`; run from `programs/` as
`cargo run -q -p morse-program-tests --bin morse-admin -- …`; `gov`
subcommands print the instructions as JSON plus a base58 message with the
vault as fee payer, for a Squads vault transaction).

**Governance keys.** Two Squads v4 multisigs, 3 of 5 members, at least 2
outside Morse:

- *judge governance* vault, time lock 0: it is the judge Config authority.
  Parameter changes wait the judge's own 14 days; registrations, witness
  admission, directory bonds and anchor-key rotation take effect when
  approved.
- *rewards governance* vault, time lock 14 days: the rewards Config authority
  and the rewards program's upgrade authority.

Fund each vault with a little SOL (it pays rent for logs and vaults it
creates) and USDC (directory bonds).

**Steps (devnet first, then mainnet with the same steps):**

1. Build and record hashes:
   `cargo-build-sbf --manifest-path morse-judge/Cargo.toml`, same for
   `morse-rewards`; `shasum -a 256 target/deploy/*.so`. For the review, build
   verifiably (`solana-verify build`) from a tagged commit.
2. Program keypairs: `solana-keygen new -o judge-program.json` and
   `rewards-program.json`, held offline. Their addresses are the program IDs
   phones and writers pin.
3. Deploy with a temporary deployer key as upgrade authority:
   `solana program deploy target/deploy/morse_judge.so --program-id judge-program.json --upgrade-authority deployer.json -u <cluster>`
   (same for rewards).
4. Initialize the judge (deployer signs):
   `morse-admin init-judge --url <rpc> --judge <JUDGE> --deployer deployer.json --authority <JUDGE_VAULT> --usdc <USDC> --rewards <REWARDS> --min-bond-usdc <N> --min-bond-token 0`.
   Mainnet USDC is `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`; on devnet
   use a test mint. The minimum is one value for all logs, so it must allow
   the canary's $100 bonds (`100000000`); the §7 amounts ($10,000 per
   witness, $50,000 directory) are what a release requires before pinning,
   and the bond counter shows each actual bond.
5. Register the logs (governance):
   `morse-admin gov register-log morse-main --judge <JUDGE> --authority <JUDGE_VAULT> --service-key <hex> --anchor <ANCHOR_PUBKEY> --usdc <USDC>`,
   then the same for `morse-canary` with the canary service key, the canary
   anchor key and `--canary` (kind 1; only canary logs can later be closed).
   Approve and execute each in Squads.
6. Grow both rings (anyone, about 2.2 SOL of rent each at today's rate;
   `solana rent 426048`):
   `morse-admin grow-ring --url <rpc> --judge <JUDGE> --payer payer.json --log morse-main`
   (and `morse-canary`). It sends the 42 reallocs, 8 per transaction.
7. Start the anchor poster and cosign crank with the judge ID and each Log
   address. Check with `morse-admin show --log morse-main`.
8. Witnesses: each operator has its witness key sign
   `morse-admin register-message --log morse-main --id <id> --operator <wallet> --payout <address>`
   (hex; the HSM signs these bytes), then runs
   `morse-admin register-witness … --witness-key <hex> --signature <hex>`
   (add `--excluded` for Morse-run witnesses). Governance admits it:
   `morse-admin gov admit-witness morse-main --id <id> --authority <JUDGE_VAULT>`
   (add `--excluded` to force I8 for a Morse witness registered without the
   flag). Operators bond with `morse-admin bond … --mint <USDC> --amount <N>`.
   Canary witnesses T1–T3 register in `morse-canary`.
9. Directory bonds (governance):
   `morse-admin gov bond-directory morse-main --mint <USDC> --amount 50000000000 --authority <JUDGE_VAULT>`
   and `100000000` for the canary.
10. Rewards:
    `morse-admin init-rewards --rewards <REWARDS> --judge <JUDGE> --deployer deployer.json --authority <REWARDS_VAULT> --log morse-main --usdc <USDC> --floor <per-epoch base units> --floor-until <unix>`
    (it also creates the pool vault). Then move the rewards upgrade
    authority to the rewards vault:
    `solana program set-upgrade-authority <REWARDS> --new-upgrade-authority <REWARDS_VAULT> --skip-new-upgrade-authority-signer-check`.
11. After the outside review, make the judge immutable:
    `solana program set-upgrade-authority <JUDGE> --final` (check the
    deployed hash equals the reviewed build first:
    `solana program dump <JUDGE> judge.so && shasum -a 256 judge.so`).
    Until then, move the judge's upgrade authority from the deployer key to
    the rewards governance vault (14-day time lock) right after step 4, never
    to the judge vault (no time lock). No bonds are posted before the review
    (Phase 3).
12. Publish the program IDs, Log addresses and the build hash; ship the
    security config release with the anchor line.

**Parameter changes** (judge): `morse-admin gov propose <kind> --value <v>`
through Squads, wait 14 days, then anyone runs `morse-admin apply`. Setting
the token mint in Phase 5 is `gov propose token-mint --value <MINT>`; the
rewards side is `gov rewards-param token-mint|oracle|price-feed|target`.

**Anchor key compromise**: `morse-admin gov set-anchor-authority morse-main --anchor <NEW>`.

**Monthly canary drill** (plan §11.3): sign two conflicting canary
checkpoints, have T3 cosign both, file the `FRK` through a relay against
`morse-canary`; then re-bond. Canary witnesses whose slot must be reused are
re-registered under a new ID and admitted with `--replace <index>
--replaced-id <old id>`. A slashed directory bond is final, so each drill
re-provisions a fresh canary log (`gov register-log <new name> --canary`,
`grow-ring`, `gov bond-directory`, register and admit T1–T3). Its ring rent
is not lost: 28 days after the slash, governance closes the old ring with
`morse-admin gov close-log <old name> --destination <account> --authority
<JUDGE_VAULT>` (add `--stages STAGE:SUBMITTER,...` for stages left behind),
which returns the ring's rent (about 2.2 SOL) to the destination.

## 13. Local-validator quickstart

```
cd mesh-private-messenger/programs
./scripts/smoke.sh
```

It builds both programs, starts a throwaway `solana-test-validator` on port
18899 with both programs deployed as upgradeable (upgrade authority = a fresh
deployer key), and runs the smoke binary: initialize, register `morse-main`,
grow the ring, register/admit/bond a witness, bond the directory, anchor and
cosign, stage and prove a same-size fork against the ring paying a named
finder (whose ATA is created in the same transaction), then the rewards
drill; finally `morse-admin show` and one `gov` printout. It stops only the
validator it started. For manual work, start the validator the same way and
use `morse-admin` against `http://127.0.0.1:18899`.

## 14. Differences from the plan and INTERFACES

- Witness PDAs and vaults use `sha256(witness_id)` as the seed, not the ID
  (§3).
- Registration is two steps: the operator's `register_witness` (key proof)
  and governance's `admit_witness` into the 16-entry list. Without the gate,
  anyone could fill a log's 16 slots for good; with it, governance never
  needs an operator's signature inside a Squads transaction. Admission can
  also force the excluded flag.
- A list slot is reusable once its witness is Slashed or Withdrawn; the
  entry's since slot keeps old bitmap bits from implicating the newcomer.
  List entries therefore carry 7 padding bytes and the since slot after the
  INTERFACES fields.
- `post_anchor` stores contradicting checkpoints as evidence (F3, and F1
  against the tip), refuses exact duplicates and stale checkpoints, and
  counts anchors for attendance (so `cosign` only counts the witness side).
  The ring header has no padding (u32 head and count fill 64 bytes); entry
  bytes 98–103, padding in the plan, hold the evidence flag and the epoch.
- The directory bond exits like a witness bond (governance
  `request_unbond`, 30 days, `withdraw` to a governance token account, never
  after a slash). Governance can also rotate a log's anchor authority.
- `cosign` data carries no signature (it is in the Ed25519 instruction and is
  not stored), so four cosigns fit one transaction.
- One minimum bond per mint for all logs (§12 step 4).
- Logs have a kind (Log offset 6, formerly padding) and a slash time (offset
  8, formerly padding). `close_log` (21) reclaims a slashed canary log's ring
  rent 28 days after the slash; a slashed canary log refuses anchors so that
  window covers every entry. Proof records are kept (they are the pay-once
  guarantee); stages go back to their submitters, not to governance.
- `morse-rewards` parameter changes rely on the Squads vault's 14-day time
  lock rather than an in-program timelock; its pool vault is the `["pool"]`
  PDA's USDC associated token account, and the burn account is any token
  account the `["burn"]` PDA owns.
- F3 with equal sequences compares checkpoint hashes, as INTERFACES §5 says.
  Ed25519 signing is deterministic and the precompile rejects malleable
  signatures, so equal statements under one key give equal hashes.

## 15. Tests

`programs/tests` (LiteSVM against the built `.so` files, with the Ed25519
precompile, SPL Token and ATA programs): every instruction's success and
refusals; Ed25519 introspection attacks (instruction missing, in another
transaction, entry pointing into another instruction while its own data
holds a forged statement, entry pointing at other data, another program's
instruction laid out like an Ed25519 one, a fake sysvar, other
message/key/signature, prefix message); cosign window; ring wrap; duplicate,
stale and evidence anchors; list reuse; bond, unbond, withdraw and the
directory bond; staging abuse; every proof kind inline and staged, against
inline and ring checkpoints; finder rules and the pay-once record; double
slash; slash during unbonding and refused after withdrawal; canary/main
isolation; closing a slashed canary log (rent to the destination, stages
to their submitters, vaults untouched; refused for unslashed, main-kind or
too-recent logs); token burns on slash; compute and transaction-size bounds;
rewards settlement, floor, carry-over, excluded and Bootstrap/empty
registries, claims, token-bond eligibility with a mock feed, and burns. The
Mesh `FRK` vectors (`tests/fixtures/frk/*.json`) are replayed on-chain: valid
ones slash exactly the directory and the implicated witnesses and match the
proof hash; invalid ones are refused and change nothing.
