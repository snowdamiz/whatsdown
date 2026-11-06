# Judge custody v1

This is the implemented USDC escrow and read contract. Fork verdicts and payouts
are documented in `judge-adjudication-v1.md`; rewards and deployment remain
pending. The program remains local and upgradeable pending the rest of the
judge and outside review.

The judge accepts a configured classic SPL Token mint with six decimals. The
configuration pins the mint and directory bond owner once for each Log. Neither
has an update instruction. Readers additionally pin the mint themselves: an
arbitrary six-decimal token must never be described as USDC or dollars.

## Addresses and ownership

- Economics: `["economics", log_id]`, owned by the judge.
- Witness bond: `["bond", log_id, identity]`, owned by the judge, where identity
  is SHA-256 of `"morse-witness-record-v1" || id_length_u8 || id || signing_key`.
  This is the identity used by the immutable Witness registration. Hashing it
  accommodates 64-byte IDs and keeps successive signing keys in separate bonds.
- Directory bond: `["bond", log_id, "directory"]`, owned by the judge. A witness
  whose ID is `directory` has a distinct hashed identity and cannot collide.
- Each vault is the classic SPL associated token account for its Bond PDA and
  configured mint. The Bond PDA is its token authority. Only judge instructions
  can sign for that authority. No approve, close, generic transfer, or admin
  withdrawal instruction is exposed.

The registered operator wallet, rather than the signing key or reward payout
wallet, authorizes witness deposits, unbond requests and withdrawals. Directory
deposits additionally require governance. Withdrawals can only reach the
original owner's associated token account for the configured mint. Accounts and
vaults remain allocated after withdrawal; staging-rent refunds are unrelated.

## Accounting and lifecycle

Initial configuration and proposals for new minimums each wait 14 days. Anyone
may activate a ready proposal. Proposing again starts a fresh full delay. An
active bond can be topped up without restarting its bond age or meeting a later
raised minimum; a withdrawn bond must meet the current minimum to rebond.

Economics tracks deposited principal, excluding unsolicited token donations.
The directory's principal must cover aggregate witness principal, including
unbonding witnesses. New witness deposits require an Active directory bond.
The directory cannot withdraw until witness principal is zero. These rules also
apply to canaries: three $100 witness bonds require at least $300 of directory
principal. Donation transfers cannot inflate entry collateral or principal
counters; an eligible withdrawal transfers the whole actual vault balance.

`request_unbond` changes Active to Unbonding and records the request's on-chain
Unix seconds. Repeating it preserves the original deadline. Withdrawals require
at least 30 full days, measured by Clock, and change Unbonding to Withdrawn.
Unbonding or Slashed bonds cannot receive a new deposit through the judge.
Economics carries a monotonically increasing witness eligibility revision.
Initial bonding, rebonding, the first unbond request, withdrawal and witness
slashing advance it with checked arithmetic. Active top-ups preserve it because
they change neither status nor bond age. Rewards settlement pins this revision
across staged account reads; a change invalidates the draft before allocation.
This requires the updated judge and readers before rewards activation. Legacy
Economics accounts start at revision zero in their former reserved bytes.

The Slashed encoding is reserved for adjudication; custody instructions do not
produce it. No test of custody alone proves that a fork can be paid out.

All transfers use actual `TransferChecked` CPI. Token program, mint, exact ATA,
token owner, initialized state and vault authority are checked. A vault with a
delegate, close authority, frozen state or native-token reserve is refused.
Failed transfers roll back newly created accounts and principal counters.
PDA and ATA creation tolerate valid pre-funded system accounts.

## Account layouts

All integers are little-endian. Times are nonnegative signed 64-bit seconds.
Balances are full unsigned 64-bit base units. Reserved bytes are zero.

Economics is 192 bytes:

| Offset | Field |
|---|---|
| 0 | `MEC\x01` |
| 4 | log ID, 32 bytes |
| 36 | immutable mint, 32 bytes |
| 68 | immutable directory owner, 32 bytes |
| 100, 108 | witness and directory minimums, u64 each |
| 116 | initial ready-at, i64 |
| 124, 132, 140 | pending witness minimum, directory minimum, ready-at |
| 148, 156 | aggregate witness and directory principal, u64 each |
| 164 | directory status: 0 unbonded, 1 active, 2 unbonding, 3 slashed, 4 withdrawn |
| 165 | three reserved bytes |
| 168 | witness eligibility revision, u64 |
| 176 | 16 reserved bytes |

Bond is 208 bytes:

| Offset | Field |
|---|---|
| 0 | `MBD\x01` |
| 4, 5 | status (1–4), kind (0 directory, 1 witness) |
| 6 | two reserved bytes |
| 8 | log ID, 32 bytes |
| 40 | Witness PDA, or zero for directory, 32 bytes |
| 72, 104, 136 | immutable owner, mint, vault, 32 bytes each |
| 168 | deposited principal, u64 |
| 176, 184, 192 | bonded-at, unbond-requested-at, slashed-at, i64 each |
| 200 | eight reserved bytes |

The existing Witness mirrors status at byte 5, vault at 232 and unbond request
at 264. Log mirrors the directory vault at 168. The reader validates these
relationships as well as each derived account address and owner.

## Instruction contract

Tags 0–14 retain their previous meaning. Payload widths exclude the tag.
`S` means signer, `W` writable; all other accounts are read-only.

| Tag | Instruction and payload | Ordered accounts |
|---|---|---|
| 15 | Configure: minimum witness u64, minimum directory u64, directory owner 32 bytes | governance S, payer SW, Config, Log, Economics W, mint, System |
| 16 | Propose minimums: two u64s | governance S, Config, Log, Economics W |
| 17 | Activate minimums: empty | Log, Economics W |
| 18 | Witness deposit: positive amount u64 | operator SW, Log, Economics W, Witness W, Bond W, vault W, source W, mint, Token, ATA, System |
| 19 | Directory deposit: positive amount u64 | governance S, operator SW, Config, Log W, Economics W, Bond W, vault W, source W, mint, Token, ATA, System |
| 20 | Request unbond: kind u8 | kind 1: owner S, Log, Witness W, Bond W, Economics W; kind 0: owner S, Log, Economics W, Bond W |
| 21 | Withdraw: kind u8 | owner S, Log, Economics W, Witness W (only kind 1), Bond W, vault W, destination W, mint, Token |

## Authenticated reads and local verification

`Transparency.AnchorCustody` derives every address in Mesh, using public
`Solana.Address` and `Solana.Read`. It requires agreement from two distinct
configured RPC origins on the entire finalized `getMultipleAccounts` response,
using the lower agreeing context slot. It first discovers optional Economics,
then reads Log, Economics, mint, directory custody and up to sixteen pinned
witnesses together (at most 53 accounts). The second read preserves a minimum
context and must retain the first read's configuration. A concurrent change
returns `anchor_snapshot_changed`; incomplete or disagreeing responses never
become a zero-dollar balance. Missing and pre-funded uninitialized state remain
explicitly unconfigured/unregistered, rather than bonded.

`morse bonds --log LOG_NAME` reads this state using `MESSENGER_SECURITY_CONFIG`
and required `MORSE_BOND_MINT`. Optional `MORSE_BOND_LOG_VERSION` chooses a legacy
log; `MORSE_BOND_MIN_CONTEXT_SLOT` requires a canonical unsigned decimal slot.
The log must match the pinned frame. JSON amounts and slots are decimal strings.
The report distinguishes deposited principal, actual vault balance and currently
bonded balance, with mint and six-decimal precision explicit. It exits nonzero
and emits no balance report on authentication or availability failure.

Run `scripts/prove-custody.sh` with `MESHC` and `CARGO_BUILD_SBF` pointing to the
local tools. The proof builds the real judge and introspection probe, executes
the judge with LiteSVM's real SPL Token and ATA programs, and replays the resulting
accounts through Mesh codecs and live local HTTP quorum fixtures. It covers
timelock/withdrawal boundaries, immutable owner, failed-transfer atomicity,
rotation, donations, pre-funding, malformed state and RPC substitutions. CI
transfers these generated account fixtures with checksums alongside the exact
tested SBF. These are local verification results, not funded deployment evidence.
Set `MORSE_CUSTODY_FIXTURES_PATH` to an explicit output file to retain the generated
account fixtures; otherwise they are temporary and removed after the proof.
