# Relay MPR2 interface

`relay-mpr2 --pins operator.json --input evidence.frk --request request.json`
reads operator configuration, raw FRK evidence, and an unsigned request. It
prints one JSON report. A refusal prints `status:"refused"` and exits with code 1.
The executable does not sign or submit transactions.

The pins file uses the collateral-v2 configuration schema, plus `submitter`,
`fee_payer`, and `witnesses:[{witness_id,public_key}]`. Witness public keys are
32-byte lowercase hex. An explicit `morse_mint` must match the token program's
derived mint. Configurations and requests are bounded to 65,536 and 32,768 bytes.
Raw evidence is bounded to 8,009 bytes. Request amounts and slots are canonical
decimal strings.

A request has this shape:

```json
{
  "schema_version": 2,
  "method": "admit",
  "min_context_slot": "0",
  "lookup": {"creation_slot": "100000", "addresses": ["PUBLIC_KEY"]}
}
```

`lookup` is optional. An effect request also contains `effect`, the opaque token
from a previous operation. All reads require finalized provider agreement and
honor `min_context_slot`. Errors never become absence or permission to retry.

| Method | Result |
| --- | --- |
| `admit` | Next MPR2 operation, or permanent settled receipt |
| `resume` | Permanent receipt first, then authenticated legacy or MPR2 admission according to current collateral activation |
| `receipt` | `missing`, `prepared`, or `settled`, with authenticated context |
| `stage` | Existing upload status, byte progress, and verified signature ordinals |
| `effect` | `{schema_version:2,state:"present"\|"absent",slot:"..."}` for an old operation |
| `close` | Stage close instruction, requiring a permanent settled receipt |
| `lookup-plan` | Lookup lifecycle; an explicit retained lookup bypasses current collateral admission |
| `lookup` | Existing `RelayLookupState` report |
| `lookup-close` | Existing lookup cooldown report, including authenticated remaining blocks |
| `legacy-admit` | Original schema 1 admission through the existing verifier |
| `legacy-stage` | Original stage report |
| `legacy-destinations` | Original individual USDC destination report, without mutable economics |
| `legacy-receipt` | Same permanent reader as `receipt`, including MPR2 records |

Ready schema 2 reports contain `program`, `log`, `submitter`, `fee_payer`,
`usdc_mint`, `morse_mint`, `proof_hex`, `proof_hash`, `finder`, `receipt`,
`context_slot`, `stage:{address,full_hash}`, `digest`, `selection`,
`compute_budget`, `operation`, and `lookup`.

`operation` contains `reason`, standard Solana instruction reports,
`rent_allocations:[{address,space}]`, and an opaque `effect` token. Reasons come
from the existing collateral-v2 planner: initialize, append, seal, verify,
permissionless legacy-bond migration, prepare, payout accounts, and settle. The writer preserves instruction order.
Signature verification has Ed25519 at index zero immediately before judge13.
The separate 1,400,000-unit `compute_budget` instruction can precede preparation
and settlement. It must not move a signature pair from index zero.

`receipt` is the proof PDA string in admission reports. Settled admission has
`operation:null` and `settled_receipt` with the immutable payout. Receipt reads
instead contain `receipt:null` or the immutable receipt object. MPR2 objects
include both assets, checkpoint hashes, finder, submitter, stage, deadline,
subject identities, bond lifetimes, and per-asset amounts. Prepared records are
unpaid. MPR1 objects retain the original schema 1 `slash_receipt_report` shape.
A competing receipt can name a different finder from the submitted evidence.
Admission of a prepared winner reconstructs its canonical finder and submitter
intent, binds it to the receipt's exact stage, and reuses the existing collateral
reader and planner. The caller's pinned wallet remains the fee payer. Ready
reports keep the original accepted wire, finder, submitter and cleanup stage;
`payout_finder` names the authenticated winner used for payout account ownership.
Prepared lookup candidates use the actual settlement metas. Existing compatible
tables remain eligible through the ordinary coverage and retirement checks.
Permanent reads depend on the pinned judge loader, immutable log identity, and
derived proof PDA. They do not read current sources, bonds, or witness registries.

Lookup contents are the ordered union of canonical preparation and settlement
metas, excluding signers. A replan retains a compatible existing superset.
Incompatible contents produce a fresh candidate; the journal retires its old
owned table before adopting that candidate. An authenticated missing table
whose creation slot is more than 512 slots old also produces a fresh candidate.
Lookup reads and effects use the retained creation slot and ordered addresses.

The writer stores `operation.effect` unchanged. Lookup effects instead use the
old descriptor `{kind,stepId,lookup,instructions}` for create, extend, deactivate,
and close. Mesh checks that descriptor against the canonical lookup lifecycle
before reading the table. Old effects and destination reads do not require
readmission through current economics or the evidence deadline.
Payout effects first authenticate the permanent receipt to select the winner,
then reauthenticate it with that winner's destinations in one finalized batch
at the learned slot floor. A changed winner rejects reconciliation. Stage reads
and close instructions continue to target the original submitter and wire.

## Local verification

The compiler family requires matching `MESH_RT_LIB_PATH` and
`MESH_TEST_RT_LIB_PATH`. The qualified development family is recorded in the
parent qualification artifacts. The sibling `mesh-lang` symlink resolves the
repository's existing public package dependencies.

`proof_read.mpl` adds `legacy_subjects` from the same authenticated account batch.
The relay schedules the existing permissionless tag33 migration before the
shared proof planner when a selected bond still uses MBD1. Migration effects
authenticate the permanent receipt and the exact subject bond without current
economics or source dependencies. The shared proof planner is unchanged.

`tests/fixture.py` selects the pinned actual MPR2 receipt records and the retained
MPR1 receipt bytes. The MPR1 unit fixture constructs its account envelope around
those bytes. It does not claim a fresh SBF bank or a cross-record bank capture.
`meshc test tests --opt-level 2` covers permanent receipts and table revision.
`tests/receipt_rpc.mjs` drives the actual executable over three loopback RPCs.
Its required environment variables are listed at the top of that file. It covers
expired permanent receipts, source changes, prepared status, competing finders,
legacy recovery, owner rejection, and stale-slot rejection. The parent relay's
separate SBF qualification executes fresh instruction packets and custody CPIs.
