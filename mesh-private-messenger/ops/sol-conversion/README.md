# Explicit SOL conversion

This operator converts the immutable SOL witness or burn allocation of one
weekly issuer batch into separately recorded USDC. It is off unless an operator
explicitly supplies a configuration file and invokes a command. It does not run
inside issuer startup, install a service, or possess a treasury private key.

The original policy version, policy hash, membership, lamport amounts and carry
remain unchanged. A quote, RPC acknowledgement, oracle multiplication, or elapsed
time cannot create usable USDC. Only the exact finalized signed transaction and
its authenticated custody deltas can create one output row. Output-backed
witness funding uses a separate permanent receipt; burn output joins the single
existing burn reservation and preserves its permanent tombstone/close rules.

## Configuration and external signing

Configuration schema1 is an operator JSON file, bounded16KiB. It requires
`database_url`, two `providers`, their canonical `providers_hash`, `cluster`,
`owner`, `payer`, `usdc`, `nonce_authority`, `nonce_address`, `rewards_program`,
`rewards_pool`, `treasury_config`, `pool`, `amm_config`, `authority`, `input_vault`,
`output_vault`, `observation`, `oracle`, `amm_hash`, `raydium_code`, `token_code`,
`rent`, `maximum_fee`, and `owned_loopback_test`.

Addresses are canonical base58; hashes and the existing treasury-chain byte
fields are32-byte hex. Integer rent/fee fields are decimal strings. Configuration
hashing uses the existing treasury-chain schema and the full conversion profile.
No key, arbitrary route or signer URL belongs in this file. Both providers must
be distinct canonical bare HTTPS origins. `owned_loopback_test=true` is accepted
only for two explicit `http://127.0.0.1:<port>` origins; it cannot bypass a remote
clock check. No public provider, USDC mint, oracle or deployment pin is supplied
by default.

`raydium_code` and `token_code` hash the complete loader ProgramData account,
including its metadata. `amm_hash` hashes the complete admitted AMM account.
The route is the fixed Raydium CP program, classic SPL token program and WSOL
mint. Its pool/vault/authority/observation PDA graph must match the pinned mints.
The pinned SOL/USD feed is independent of pool pricing, fully verified, no more
than60seconds old, never future-dated, with confidence at most1%. The integer
minimum is rounded upward and permits at most100basis points below that price.
Commit and every network attempt recheck fresh native-time oracle/profile/code.
USDC is the USD accounting unit specified by the revenue policy. This floor
does not divide by a separate USDC/USD depeg feed. Actual finalized USDC custody
and its receipt, rather than that accounting assumption or the quote, determine
the amount available to funding.

Build with explicitly selected Mesh compiler/runtime paths. The executable
accepts only these bounded, individually requested commands:

```text
sol-conversion CONFIG prepare BATCH BUCKET OUTPUT_MESSAGE_BASE64
sol-conversion CONFIG commit ID ORDINAL SIGNED_PACKET_BASE64_FILE
sol-conversion CONFIG submit ID
sol-conversion CONFIG reconcile ID
sol-conversion CONFIG status ID
sol-conversion CONFIG refresh-unsigned ID OUTPUT_MESSAGE_BASE64
```

Bucket0 is witness, bucket1 is burn. The latter requires the existing pending
original burn liability. `prepare` persists a request before returning its exact
message. An external treasury-owner and fee-payer signer must review and sign
that message. The issuer has no signing endpoint. `commit` accepts only two valid
signatures over the exact canonical seven-instruction message: bounded CU limit,
per-intent WSOL escrow creation/initialization, exact native principal transfer,
sync, pinned exact-in swap, and escrow close returning rent to the payer. Owner
cost is the exact principal; payer cost is a capped fee. Unknown signed packets
remain immutable and reconciliation-only even after their blockhash expires.

`refresh-unsigned` is explicit, only for a still-unsigned request. Both providers
must report the old hash invalid and height beyond its stored lifetime at the
same authenticated finalized context, plus a valid new hash. The old request is
retained. A different signed packet is permitted only after authenticated
finalized failure; an absent transaction or timeout never authorizes it.

The library's `Runtime.SolConversionFunding.prepare_sol_witness_output` and
`reconcile_sol_witness_output` implement a one-off output accounting handoff.
`Storage.SolConversionFunding.sol_witness_funding_instruction` supplies the
existing canonical fund-once instruction to an external signing coordinator.
They do not sign, submit, schedule, append members, claim, or operate a rewards
keeper. No durable rewards-keeper behavior is part of this package.

## Fresh owned proof

The proof driver requires explicit compiler, host/test runtimes, pinned DEX
directory, rewards ELF, Cargo target directory, PostgreSQL binary directory, and
a fresh output directory. It copies the declared source closure before building,
uses one compiler at a time and Cargo jobs1, and seals before/after hashes. The
two owned RPC ports24494/24495 must be free. No remote endpoint is contacted.

```text
python3 ops/sol-conversion/prove.py \
  --compiler /absolute/path/to/meshc \
  --runtime /absolute/path/to/libmesh_rt.a \
  --test-runtime /absolute/path/to/libmesh_test_rt.a \
  --dex-dir /absolute/path/to/pinned-dex-elf-directory \
  --token-elf /absolute/path/to/spl_token-3.5.0.so \
  --rewards-elf /absolute/path/to/morse_rewards.so \
  --cargo-target /absolute/path/to/owned-cargo-target \
  --pg-bin /absolute/path/to/postgresql/bin \
  --carry-fixture ops/credit-burn-handoff/fixtures/carry-accounts.json \
  --expiry-fixture ops/token-expiry/fixtures/tombstone.json \
  --output /absolute/path/to/fresh-proof
```

The actual SBF fixture validates every Mesh instruction/account privilege before
ephemeral owned keys sign it. It couples real swap execution to separate CLI
processes and verifies the exact packet is in PostgreSQL before the first send.
It covers an unknown response, restart reconciliation, actual minimum failure
then explicit successful retry, and actual-USDC fund-once with fresh-hash
duplicate-intent refusals to transfer twice. Focused fixtures additionally cover
concurrent commits/reconciliation/burn composition, stale oracle at submission,
changed code/profile, exact-context disagreements, aliases, unsigned expiry and
stale signer callbacks. Original burn accounting/expiry regressions use their
genuine preexisting SBF account exports.

Scope limits: LiteSVM Clock, slot, height and HTTP finalized flags are controlled
test observations, not production consensus. The Pyth account's verification bit
is a fixture, not a guardian proof. Two-source agreement does not prove provider
independence. The fixture mint is not public USDC. Witness funding uses the
pinned rewards ELF and canonical judge-owned log/clock fixtures; it does not
qualify judge custody, attendance or keeper execution. The new SOL output's burn
reservation is accounting/canonical-instruction coverage; existing burn program
execution remains a separate qualification. No actual funds or deployment are
qualified.
