# Morse judge implementation

This crate is the beginning of the plan's Pinocchio judge, not a deployable
production program. Rust here is the plan's on-chain program exception: phone,
directory, witness and monitor protocol behavior remains in Mesh.

Implemented:

- Exact 188-byte KTK parsing for legacy and RFC 6962 log versions, preserving
  unsigned 64-bit values.
- The 146-byte service statement and checkpoint hash, checked against the
  existing independent OpenSSL fork fixtures and new fixtures shared with Mesh.
- Ed25519 introspection through Pinocchio's authenticated Instructions sysvar
  view. It requires an earlier instruction in the same transaction, the actual
  precompile ID, zero account metas, one signature, canonical self-contained
  offsets, and exact public key, signature and message bytes.
- A test-only SBF probe executing that same helper inside LiteSVM with actual
  Ed25519 precompiles enabled. The probe has no state or deployment role.
- Singleton configuration bootstrapped only by the actual loader-v3 upgrade
  authority. Its immutable governance address authorizes log registration.
- Immutable log identities and a 14-day registration delay, full rent funding
  followed by permissionless 10 KiB ring growth, and signed checkpoint posting.
  Pre-funded PDAs can initialize; initialized accounts cannot reset.
- Log/ring owner, address, identity and authority checks. Posting rejects
  incomplete rings, a marked-slashed service, wrong log versions, foreign
  service keys and missing signatures. Exact latest retries preserve the old
  slot; non-monotonic posts are retained for comparison. Ring wrap clears old
  cosignatures.

- Operator-signed witness registration with a separate signing-key proof, and
  immutable identity records across key rotations. Governance stages sorted,
  unique witness-set generations with a 14-day delay; activation is permissionless.
- Native and C2SP Ed25519 cosigning against historical generations, with an
  inclusive 1,500-slot deadline, exact message reconstruction and idempotent
  bitmaps. Only native signatures set the native bitmap.

- Canonical FRK v1/v2/v3 parsing, allocation-free Merkle relations, and staged
  proof upload/sealing with exact Ed25519 verification of up to 34 signatures.
  Sealed stages retain immutable witness keys; the submitter can recover stage
  rent. A stage is not a verdict. See `protocol/judge-stage-v1.md`.
- Six-decimal SPL Token custody through real Token/ATA CPIs: immutable per-log
  mint and directory owner, 14-day minimum changes, explicit principal accounting,
  directory collateral coverage, separate witness-key bonds, and 30-day owner-only
  unbonding/withdrawals. See `protocol/judge-custody-v1.md` for tags 15–21.
- Atomic fork adjudication, the 28-day proof window, historical anchor admission,
  full bond slashes, per-vault finder payments and locked-vault transfers.
  Tags 22–24 create a finder-independent pay-once receipt. Full sixteen-witness
  settlement fits one transaction after staging; Mesh authenticates the
  resulting receipts. See `protocol/judge-adjudication-v1.md`.

Pending: rewards, later token support,
and verification of the actual Squads 3-of-5 deployment configuration.
The configured governance signer must be the reviewed
Squads authority in production; test wallets are not a governance deployment.
Do not deploy this unfinished program or treat these checks as a complete
judge review. See `protocol/anchor-ring-v1.md` for account/instruction contracts.

## Verification

The workspace at `programs/Cargo.toml` has one dependency lock for
the judge library, thin `morse-judge-program` entrypoint and SBF probe. Install
the pinned builder:

```sh
cargo install --locked --version 4.4.0 cargo-build-sbf
bash scripts/prove-judge.sh
bash scripts/prove-custody.sh
bash scripts/prove-adjudication.sh
node --test scripts/judge-checkpoint.test.mjs
```

Run from `mesh-private-messenger`. `CARGO_BUILD_SBF` may identify a local copy
of the same pinned builder; `MESHC` may identify the local Mesh compiler. The
script checks formatting and Clippy, compiles the program and probe with platform-tools
v1.57 and SBF v0, then runs all judge tests with the `svm` feature. Missing SBF
output fails the tests; there is no silently skipped virtual-machine lane.
SBF builds use a fresh temporary target and reject printed compiler errors,
including stack-frame diagnostics that otherwise exit successfully.
CI runs this proof in the Judge job, and the Mesh job runs the OpenSSL/Mesh
fixture oracle. `scripts/verify-security.mjs` also includes that oracle.

The virtual-machine proof covers both log versions, real signature failures,
missing or future precompiles, another transaction's signature, a fake sysvar,
a valid signature over a different statement, and offsets redirected into
another instruction. The redirected instruction succeeds on Solana by itself
but fails the judge's exact self-contained matching rule. Host tests mutate
every instruction byte and every truncated length.

The account test executes real System Program allocation/assignment, every
growth step to the 426,048-byte ring, and the actual 14-day boundary with the VM
clock. It exercises bootstrap hijacks, pre-funding, insufficient rent, missing
or foreign authority, valid foreign service signatures, wrong owners, copied
accounts at different addresses, read-only rings, duplicate initialization,
idempotent retries and rollback retention. Host tests exercise all 4,096 ring
positions and wraparound, with full u64 values.

The same VM flow registers witnesses, rejects stolen/missing proofs and duplicate
keys/IDs, exercises the set activation deadline and rotation, preserves old key
attribution, checks both signature kinds and cross-log C2SP rejection, and proves
the slot deadline and highest bitmap bit with a full 16-witness set. Wrong owners,
copied generation accounts, unfilled positions and generation overflow fail.
The Mesh phone reader exercises matching RPC slices for the immutable generation.

Custody tests execute real Token/ATA CPIs and the on-chain 14-day and 30-day
boundaries. They export configured, active, unbonding and withdrawn account
snapshots for the Mesh quorum reader. Substitution, donations, pre-funding,
failed-transfer atomicity, long IDs, key rotation and directory coverage are
checked without any real wallets or funds. `prove-custody.sh` includes this
cross-language replay and the optimized CLI command checks. The protocol files
live under `mesh-private-messenger/protocol`, relative to the repository root.

The new shared fixture is
`tests/fixtures/fork-v1/anchor-checkpoints.json`. Regenerate it deliberately with
`node scripts/judge-checkpoint.test.mjs --write-fixture`; the test independently
reproduces its OpenSSL signatures/hashes and verifies that Mesh rejects an
altered expected hash or cosignature. The fixtures also share canonical native
and C2SP witness statements/signatures with Mesh and Rust, including a u64::MAX
C2SP timestamp. Fixture signing seeds are public test data.
