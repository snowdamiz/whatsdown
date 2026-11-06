# Bounded public record discovery

The optional `history` configuration discovers funded burn frames (`MTW`/`MTC`),
registered witness identities (`MWI`) and proof receipts (`MPR`) for explicitly
pinned programs/profile/log. Default exports remain selected-only. The landing
page still loads the existing bootstrap artifact until an operator deliberately
writes and reviews a separate report; nothing in this slice publishes it.

```json
"history": { "schema_version": 1, "maximum_records": 128, "page_size": 16 }
```

The maximum is 1–128 returned records **per family**, and page size is 1–16.
Explicit history permits an empty selected-epoch list. Each source receives one
complete filtered `getProgramAccounts` request with finalized context, followed
by authenticated context accounts at the exact same slot. Mesh rechecks account
owner, funding, executable flag, full space/body, filter, known version and PDA,
then compares the entire sorted list plus bank/context digest. At least two of
three configured origins must agree. Different origins do not establish
independent operators. A list/body overflow, timeout or malformed response is a
refusal, never a silently shortened list or an empty index.

The filters are fixed: burn `MT` prefix plus swap-profile address at offset4;
witness `MWI` plus log ID at offset200; proof `MPR` plus log ID at offset8.
Close receipts (`MBC`) are read through funded-frame values, not misclassified
as funded weeks. Every indexed identifier appears once. Status0 witness rows
are registry-only; no zero bond, eligibility or operator independence is inferred.
Unknown versions/families are explicitly unvalidated observations: owner/filter
agreement does not authenticate their canonical identities. Known wrong owners,
PDAs and layouts refuse the source instead of downgrading it to an unknown row.

Values use the existing selected readers in bounded pages. Each page records
its own authenticated slot/time/code status and must be at or after the index.
Burn values have one bank per record; collateral values have one bank per page.
No sum across banks or assets is emitted. An unavailable value remains an
explicit indexed identifier with incomplete values. Expected program release
pins and code-change warnings remain visible. The viewer checks every index and
value bank for age/code changes and validates exact page coverage before showing
amounts. Navigation is static and makes no RPC requests.

`complete-returned-filtered-family-at-index-bank` describes the provider-agreed
returned set. It is **not a cryptographic proof that providers omitted no
matching account**, complete program/global history, or proof that no records
appeared later. This report cannot supply a globally summed historical balance.
The per-request HTTP cap is512KiB and5seconds, without redirects; the host adds a
180second history deadline and8MiB output cap. A large/slow allowed configuration
can exceed that deadline and produce no artifact. Limits are refusals, not
pagination of a silently truncated RPC list.

The default v2 context retains MPRv1 identifiers without rendering their values.
An explicit, mutually exclusive `legacy_collateral` context provides versioned
MEC1/MBD1/MPR1 discovery and values without requiring a token/rewards v2 binding:

```json
"legacy_collateral": {
  "schema_version": 1,
  "judge": "EXPLICIT_PROGRAM_ADDRESS",
  "judge_slot": "EXPLICIT_DEPLOYMENT_SLOT",
  "governance": "EXPLICIT_CONFIG_AUTHORITY",
  "anchor_authority": "EXPLICIT_LOG_AUTHORITY",
  "log_name": "CONFIGURED_LOG_NAME",
  "log_version": 2,
  "service_public_key": "EXPLICIT_32_BYTE_HEX_KEY",
  "mint": "EXPLICIT_CLASSIC_SPL_MINT"
}
```

This context requires `history` and an empty `epochs` list. Supplying `pins` or
`collateral` as well is an error. A v2 context failure never activates legacy
mode. The mint must be initialized classic SPL with six decimals; the report
names only its configured mint address, without assigning USDC/MORSE/fiat identity.
Burns are explicitly **not configured**, rather than an empty or zero burn history.

Legacy discovery and each value page authenticate canonical log/economics/config,
mint, Clock, executable and ProgramData. Each index context must be the same bank
as its complete returned list; each value page is a separate whole-batch 2-of-3
observation at or above that index slot. Expected code release and freshness remain
visible for both. Pending-v2 layouts and MEC2 are refused in a v1 value context.
Future proof versions are unvalidated identifiers, never reinterpreted as v1 or
as authenticated v2 receipts. An authentic empty proof set in an active legacy
bank is shown independently from its funded directory/witness values.

The explicitly versioned v1 values retain principal, actual vault balance,
donation surplus and settled receipt amounts. V1 has no v2 pending-liability field,
so that field is unavailable, not zero. Receipt signature masks and their bit counts
are separate. A v1 receipt records witness account addresses and public keys but
has no witness-ID seed: the report cannot independently reconstruct those row PDAs.
Receipt decoding is not independent re-verification of the original fork evidence.
Neither version emits cross-bank, cross-asset or global historical totals. Mixed
migration contexts not represented by these exact schemas remain unsupported.

## Reproduce locally

Run from a checkout with the declared Mesh dependencies present:

```sh
python3 ops/public-chain/prove-history.py \
  --meshc /absolute/pinned/meshc \
  --runtime-dir /absolute/pinned/runtime-directory \
  --output /absolute/fresh-proof-directory \
  --browser-executable /absolute/chromium \
  --playwright-module /absolute/playwright/index.mjs
```

Both browser arguments may be omitted for compiler/HTTP-only qualification;
that does not qualify browser navigation. The driver uses committed public
complete-bank fixtures, verifies their provenance hashes, preserves source bodies
and tool pins before execution, runs the original selected readers plus new
history cases, and refuses source drift. It does not default to untracked
`.morse` inputs, install services, or use public RPC. Browser assertions do not
capture screens.

Fixture provenance includes three fresh real SBF cases: funded close/carry,
current collateral migration, and six legacy fork settlements. The optional
`MORSE_PUBLIC_HISTORY_{TOKEN,JUDGE,LEGACY}_EXPORT` test hooks export all actual
owned accounts from the selected final bank. An optional matching `_LATER`
variable exports a genuine cloned bank with controlled Clock/slot +7. Original
bank state and default env-unset assertions are unchanged. These are owned local
state observations, not production finalized ledger or live independent-provider
evidence. The corresponding exact SBF inputs/runners/ELFs/results are separately
sealed by the manifests recorded in `fixtures/history-provenance.json`.

The optional `MORSE_PUBLIC_HISTORY_LEGACY_ACTIVE_EXPORT` hook snapshots the genuine
pre-settlement bank from the existing legacy settlement SBF case. A matching
`_LATER` path exports its controlled later clone. Default env-unset execution and
all original program assertions remain unchanged. The four active/settled fixtures
and their separate SBF provenance are recorded in `history-legacy-provenance.json`.
The shared Mesh source validator counts normalized origins, so different paths,
default ports or host spelling cannot manufacture multiple quorum origins. The
Node shell performs the same independent boundary check; neither claims actual
provider independence.
