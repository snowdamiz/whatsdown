# Permanent unfunded burn-week expiry

This additive wire extends the local MORSE token program with instruction15.
Existing MTW1/MTW2 funding, MTC1/MTC2 closed weeks, MCY1 carry and MBC1 close
receipts retain their layouts and interpretation. No funded or closed week can
be converted into an unfunded expiry. This is local implementation evidence,
not a deployment, live finality or operational approval.

## Instruction15

Data is tag `0f` followed by epoch as eight little-endian unsigned bytes.
The epoch start is `epoch*604800`; expiry is allowed inclusively at
`epoch*604800+25200`, the first of24 seven-hour chunk boundaries. Arithmetic
must fit a positive signed64-bit chain timestamp. A schedule that missed its
funding window cannot be funded later; creating the permanent records makes
that fact survive later clock movement.

Accounts, in order:

| Role | Access |
| --- | --- |
| Rent payer | Signer, writable |
| Canonical token Config | Read |
| Canonical MORSE mint | Read |
| Immutable swap profile, `['swap']` | Read |
| Week, `['burn-week', epochLE8]` | Writable |
| Receipt, `['burn-carry-epoch', epochLE8]` | Writable |
| System program | Read, executable |

Config, mint and profile authentication is identical to the burn boundary. The
initial Week and Receipt must both be exactly canonical, System owned, empty,
nonexecutable accounts. Donated rent lamports are accepted; initialized,
foreign-owned or partially created records are rejected. Both account
creations and writes are atomic. A failure creating either account leaves
neither initialized. The transaction fee is still charged by the chain.

The payer funds only rent. No token, DEX, price source or recipient account is
accepted, and no transfer or withdrawal occurs. Any signer may pay this rent;
the fixed issuer operator request uses its separately held treasury owner.

## Permanent records

All integers are unsigned little endian. Every reserved byte is zero. Both
records are program owned, nonexecutable and never closed or reused.

| MBX1 Week192 bytes | Offset | Length |
| --- | ---: | ---: |
| Magic `4d425801` | 0 | 4 |
| Swap profile | 4 | 32 |
| Config | 36 | 32 |
| USDC mint | 68 | 32 |
| Treasury owner | 100 | 32 |
| Epoch | 132 | 8 |
| Funding deadline | 140 | 8 |
| Chain expiry timestamp | 148 | 8 |
| SHA256 of exact immutable profile bytes | 156 | 32 |
| Reserved | 188 | 4 |

| MBU1 Receipt256 bytes | Offset | Length |
| --- | ---: | ---: |
| Magic `4d425501` | 0 | 4 |
| Swap profile | 4 | 32 |
| Week PDA | 36 | 32 |
| Config | 68 | 32 |
| USDC mint | 100 | 32 |
| Treasury owner | 132 | 32 |
| Epoch | 164 | 8 |
| Funding deadline | 172 | 8 |
| Chain expiry timestamp | 180 | 8 |
| SHA256 of exact immutable profile bytes | 188 | 32 |
| SHA256 of exact MBX1 bytes | 220 | 32 |
| Reserved | 252 | 4 |

An exact duplicate validates both full records and returns without changing
them, even after a clock rollback or funding/carry activity in later epochs.
Existing funding instructions9 and14 reject MBX1 forever. Record identity is
per epoch and profile, independent of a particular offchain cash allocation.

## Finalized release boundary

The Mesh reader authenticates one finalized nine-account bank in this exact
order: Config, MORSE mint, swap profile, USDC mint, Clock, Week, Receipt,
executable token program, loader-v3 ProgramData. It verifies canonical PDAs,
owners, full spaces, bounded slices, lamports, executable flags, mint profile,
pinned governance/treasury/factory, ProgramData release slot, context/Clock
slot consistency and the exact pair hashes. Clock must reach the deadline;
record timestamp cannot exceed Clock. The two independently configured RPC
origins must each return a valid bank with matching immutable footprint.
Advancing clock/head and donated rent do not change that footprint.

A pair of canonical absent accounts permits preparation only. Elapsed local
time, one provider, a missing receipt, disagreement, malformed data, timeout or
an unknown funding outcome never releases a reservation. Raw decoding alone
is not a chain proof. The pinned provider and deployed program trust boundary
remains explicit; these local proofs do not establish live consensus or real
world provider independence.

The issuer persists the exact MBX1/MBU1 bytes and positive finalized slot when
moving a pending intent to terminal state2. Under the shared burn journal
transaction lock it releases only that intent's member reservations; the
liabilities themselves remain pending. Every historical member row remains
immutable except its one-way released marker. A later intent may reserve
those liabilities with a new epoch and new fixed randomized schedule. An old
expiry retry compares its stored proof and has no effect on the later intent,
its liabilities, carry, cash or funding receipt.
