# Bounded collateral/proof planning

This Mesh package prepares **unsigned local instructions** for judge tags31–45 and the staged fork workflow10–14. It does not sign, submit, run periodically, choose a conversion, or hold private keys. Onchain execution authenticates all accounts and remains the authority. A plan is not authorization or proof of eventual execution.

`TokenCollateralWrite` derives the canonical log/config/binding, subject bond/pending record and both asset vaults. `TokenProofWrite` strictly decodes permanent MPRv2 receipts and derives bounded staged proof, signature, payout and mixed-asset settlement instructions. Existing AnchorWrite/TokenWrite APIs are unchanged.

## Run

Build `main.mpl` with the qualified compiler, then run:

```
collateral-v2 --pins pins.json --input request.json
```

Each JSON file is bounded to32768bytes. Config schema1 requires three distinct canonical HTTPS origins (only `http://127.0.0.1:PORT` is allowed for owned tests), judge/token/rewards program identities, governance, optional token_governance (defaults to governance), log name/version/service public key, USDC mint, network start, all three executable deployment slots, oracle receiver/source/feed/revision. See `request.mpl` for the typed exact field names. U64 values are canonical decimal **strings**, byte strings canonical lowercase hex. No price, current slot or current time supplied by the request becomes authority.

Collateral requests specify action `collateral`, tag, fee_payer, operator, subject `{kind:"directory"}` or `{kind:"witness",witness_id,public_key}`, asset0USDC/1MORSE, amount, witness_minimum, directory_minimum, min_context_slot. Proof requests specify action `proof`, fee_payer, submitter, wire_hex, witnesses (max16), explicit close Boolean and min_context_slot. Proof wire bound8009bytes. Unused collateral numeric fields must still be supplied; they do not create policy.

The JSON report contains ready/waiting/complete, selected snapshot digest/slot, exact instruction reports, fee payer, rent payers, required instruction/transaction signers, governance requirement and any onchain wait deadline. Tag32 uses the actually SBF-qualified permissionless activation metas; the requested fee payer still signs the transaction. Every other operation retains its handler authority requirements. The legacy oversigned tag32 builder remains available for compatibility vectors.

## Authentication and dependency limits

Each accepted snapshot requires two of three responses to agree on the **entire selected state and same finalized bank slot**, including ownership, full account space, rent epoch, data and executable release metadata. Missing, partial, malformed, code-changed, too-old, future, mismatched or redirected responses fail. Snapshot age is rechecked after provider I/O (maximum300seconds). The planner is bounded selected-record reporting, not discovery or complete history. Public raw codecs and typed states alone do not authenticate arbitrary caller-created values.

The ordinary strict reader additionally requires the configured current oracle source and binding revision. The action-aware reader still authenticates canonical immutable identities, executable releases, owned oracle shape and all balances, but exposes **no usable price** if source or binding revisions differ. Price-dependent steps refuse that state; owner exits and proof settlement use their actual oracle-free onchain dependencies. Deposit/activation/assessment still require the releases committed by their binding. There is no substituted price or discretionary source fallback.

Binding and minimum changes preserve their existing fourteen-day waits. Migration explicitly preserves units. Pending collateral is a liability separate from active principal and donations. MORSE uses only the authenticated full seven-day TWAP; recorded grace is never inferred from a new price. Owner exits retain the actual thirty-day wait and directory coverage/exit checks. All arithmetic uses U64/U128, never floating point or asset-unit sums.

A proof read uses at most97main accounts (27base +4×16selectedwitnesses +stage/receipt/fourpayouts). Anchored proofs make three additional bounded reads per origin:64-byte ring header,104-byte selected entry,2752-byte historical witness set. All must have the **same slot** as the main batch. Up to12RPCcalls, no cross-context total. Full account prefixes are bounded9216bytes; response caps and deadlines are fixed. Both current and historical witness identities, signatures/bitmaps, fork semantics, stage bytes, permanent receipt binding and collateral lifetimes are checked. Permanent settled receipts remain complete after later status changes.

The planner emits one next step. A signature step is exactly Ed25519 at instruction index0 immediately followed by judge13. Assembly must preserve adjacency/index or rebuild that pair. Large max16-target settlement needs an actual address lookup table; the report flags conservatively when more than30unique transaction keys require one. This package does not create/extend an ALT, fetch a blockhash, estimate fees, sign or submit. Reread after each completed step. Deposits are not idempotent: never retry a signed/submitted deposit blindly after an unknown result. Stage close is an explicit caller request, not automatic deletion.

## Qualification

`fixture_subset.py` selects SDK packets and account observations from actual disposable LiteSVM execution of the pinned judge/token/rewards SBFs. It invents no accepted account data. `qualify.py --vectors ACTUAL_SUBSET --output NEW_DIRECTORY` requires pinned MESH_COMPILER_BIN/MESH_RT_LIB_PATH/MESH_TEST_RT_LIB_PATH, freezes sources/toolchain, runs at most two compiles in parallel, exact SDK comparisons, lifecycle/negative/planning tests, fresh local three-origin HTTP replay, CLI build, formatting and lint. Missing fixture inputs fail; no skipped gates count as passes.

Actual SBF replay is separate: set MORSE_COLLATERAL_OPERATOR_FIXTURES_PATH to a fresh output, MORSE_COLLATERAL_OPERATOR_REPLAY_PATH to emitted mesh-instructions.json and MORSE_COLLATERAL_OPERATOR_EXTRA_KEYS_PATH to the same capture query file, then execute the owned token_custody_svm integration. Hooks replace a packet only when its complete expected SDK instruction list **and exact pre-bank digest** match. The unchanged transaction signatures, Ed25519 adjacency, real ALT/v0 serialization,1232-byte and compute checks remain active. Verify every requested packet replayed with the expected success/refusal; merely passing the integration does not prove coverage.

The opt-in fixture adds all three signed/anchored fork kinds and real timelocked source rotation with assessment refusal versus owner exit. Test-only canonical empty-ring initialization is explicit; checkpoints and historical cosignatures are admitted by the real handlers. Oracle publications are disposable owned fixtures, not a claim of live oracle authenticity. All recorded chain evidence is local SBF execution/replay; local HTTP replay is not a fresh external chain observation. Release independence, live execution, financial policy and service activation are outside this package.

## Owner cleanup

`action:"close"` requires only fee_payer, submitter, full_hash (32-byte lowercase hex), schema_version and min_context_slot. It has a separate seven-account finalized read: judge config/log/Clock/executable/ProgramData, canonical stage and refund owner. It checks the current configured judge release, immutable log/service binding, owner/digest/PDA, exact bounded MST header, clock freshness, refund arithmetic and same-bank quorum. It does **not** read token prices, binding activation, collateral, witness membership or old proof signatures, and deliberately does not parse old staged proof bytes. The full hash comes from the saved upload intent; it is not a new authority. Onchain owner authorization still applies. Existing proof requests with `close:true` use this same independent path.

The owner-close SBF regression stages an unsupported format, proves sealing is refused, genuinely withdraws the witness after forty days (oracle stale and binding still inactive), rejects the distinct governance/fee payer's attempt to close the owner's stage, and executes the exact Mesh owner-close packet. Repeated missing-stage planning is complete with no instructions/signers. The additional close corpus is mandatory: use `qualify.py --vectors ACTUAL_SUBSET --close-vectors ACTUAL_CLOSE_SUBSET --output NEW_DIRECTORY`. `close_fixture_subset.py` selects it from the separate actual owned SBF regression output. Both HTTP fixtures are local historical-state replay; neither is a live chain freshness claim.

Origins must equal the public URL parser's canonical origin exactly; case/default-port aliases, credentials, fragments, paths and queries are refused. Three strings pointing at one origin do not form a quorum. Distinct origins still do not establish independent operators.

`assessment_read.mpl` exposes bounded groups for the v2 rewards keeper. Groups
reuse this package's exact collateral decoder, retain a single finalized bank
per group, and authenticate independent Judge and token governance pins. The
reward keeper scans the directory and all attendance witnesses before each
settlement step. `collateral_grace_update_needed` compares only active principal
against the recorded lifetime target, so no-op checks can continue collection.
This API prepares unsigned tag45 assessment; it does not apply pending collateral.
