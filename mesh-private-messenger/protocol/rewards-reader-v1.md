# Authenticated rewards reads

```sh
morse rewards --program PROGRAM --mint MINT --log LOG_NAME --epoch EPOCH
```

Program and mint are explicit operator-selected read pins. Selecting them does
not add native release trust, establish token value, identify a real-world
operator, or qualify governance custody. The exact log must match
`MESSENGER_SECURITY_CONFIG`, which supplies the judge program, service key, log
version, ring and RPC provider set. `EPOCH` is a canonical unsigned decimal
seven-day Unix-time epoch. `MORSE_REWARDS_MIN_CONTEXT_SLOT` optionally requires a
canonical decimal minimum finalized context, defaulting to `0`.

`Transparency.RewardsRead` derives the ordered account list locally:

1. rewards Pool;
2. rewards Epoch;
3. pool vault ATA;
4. selected classic SPL mint;
5. judge Log;
6. judge AttendanceClock;
7. judge AttendanceEpoch;
8. judge Economics;
9. selected rewards executable.

Each provider receives one `getMultipleAccounts` request, finalized commitment,
the minimum context and an 8,416-byte prefix slice. The whole response is capped
at 64 KiB. The clock's full space must still be 65,616 bytes. Pool, Epoch, vault,
mint, Log, attendance epoch, Economics and executable must have their exact
full spaces of 304, 8,416, 165, 82, 352, 2,640, 192 and 36 bytes, respectively.
The program must be an executable loader-v3 Program account with the canonical
ProgramData link. This check does not attest to its upgrade authority or code
review status.

The reader checks account owners, nonzero lamports, executable flags, canonical
addresses, native Log identity and the pool's immutable judge/log/mint/network
start/first-full-epoch relationship. The mint must be initialized with six
decimals. The vault must be its canonical ATA with the Pool as token authority,
initialized, nonnative, and free of delegate and close authority. Its actual
balance must cover the accounted amount; direct donations remain explicit
surplus. The public codecs check record layout, padding, counters, unsigned
weights, row ordering, claim bits and conservation.

Two independently configured provider origins must agree on the entire ordered
batch, including absence, owners, full spaces, token balances and account bytes.
Contexts must be numeric fields in actual JSON objects and satisfy the minimum.
The result uses the lower agreeing context. Wrong, unavailable or conflicting
providers produce an error without a JSON report.

Reports use schema version 1 and mark `program_pin` as `operator_selected`.
Every u64 amount/epoch/slot and u128 weight is a decimal JSON string.

- `absent`: Pool is absent or an empty prefunded System PDA. Unknown pool
  accounting remains null.
- `awaiting`: an initialized pool awaits the requested Epoch or Economics.
  `awaiting` names the missing prerequisite. Missing Economics is allowed before
  settlement and never becomes a fabricated zero revision.
- `open`: the Epoch is open and its explicitly classified revenue is known.
- `collecting`: the Epoch contains a staged attendance snapshot. Its attendance
  hash, prefix rows and pool relationship are authenticated. `revision_matches`
  reports whether current Economics still matches that stage. No wall-clock
  expiry or permission to finalize is inferred.
- `finalized`: allocation and claimed bits are fixed in the canonical Epoch.
  The current pool must cover the unclaimed amount. An already earned allocation
  remains readable after eligibility or governance changes, and is not checked
  against current Member or Bond status.

Finalized rows expose canonical Witness, stored payout-wallet and Bond addresses,
raw weight, floor, amount and claimed flag. They do not assert operator
independence or token fiat value. Historical finalization does not establish
that an unclaimed row has been paid.

## Operator helpers and funding recovery

`read_rewards_account_slices(pins, addresses, slice_length, minimum_slot)` exposes
the same bounded whole-batch transport for additional operator reads. It accepts
1–64 accounts and prefix lengths 1–8,416. Callers must authenticate each returned
owner, canonical address, full space and schema; provider agreement alone does
not interpret an account.

`read_reward_funding(pins, service_key, version, program, mint, epoch, funder,
operation_id, minimum_slot)` adds the operation's canonical FundingReceipt as a
tenth account in the same bank. It returns `missing` or `funded` and the complete
typed rewards snapshot. A present receipt must have exact program ownership,
192-byte space, nonzero funding, the selected pool/mint/epoch, requested funder
and operation ID, and the funder's canonical classic ATA as source. The caller
compares kind and amount with its durable intent. A later epoch, claim or current
eligibility revision does not erase an authenticated receipt. The reader does
not submit transactions or classify a missing receipt as permission to fund an
expired intent.

## Local verification

```sh
../mesh-lang/target/debug/meshc test packages/messenger-protocol/tests/rewards_read.test.mpl
../mesh-lang/target/debug/meshc test clients/mesh-cli/tests/rewards.test.mpl
node --test scripts/rewards-command.test.mjs
MORSE_REWARDS_FIXTURES_PATH=../.morse/witness-proof/rewards-program-fixtures.json \
  ../mesh-lang/target/debug/meshc test packages/messenger-protocol/security/rewards-read.test.mpl
```

The normal tests use synthetic account fixtures and local HTTP providers. The
mandatory security proof replays freshly generated real-SBF settlement and claim
accounts through local RPC servers, including the original full clock allocation.
No test uses live providers or establishes deployment/funding readiness.
