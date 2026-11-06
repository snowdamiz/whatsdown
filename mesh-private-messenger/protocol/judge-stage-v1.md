# Judge proof staging v1

This is the implemented local ABI for bounded uploads and signature verification.
Staging alone does not adjudicate a fork or pay a finder. The separate atomic
instructions in `judge-adjudication-v1.md` enforce fork relations, the 28-day
window, collectible bonds and payout receipts.

## Identity and account data

A stage is a judge-owned PDA with seeds:

```text
["stage", submitter_wallet_32, SHA256(full_canonical_FRK_bytes)]
```

The full hash includes the finder. The pay-once proof identity uses
`Transparency.Fork.fork_hash`, which excludes the finder; these hashes serve
different purposes. A relayer cannot change a finder, checkpoint, attestation
order, or path inside an existing stage.

The account is 1,152 header bytes followed by exactly the declared proof length.
The maximum proof length is 8,009 bytes and the maximum account length is 9,161,
so initialization fits a single permitted account allocation. Integers in the
stage account and instruction payloads are **little-endian**. FRK and checkpoint
bytes retain their own big-endian wire format.

| Offset | Length | Value |
|---:|---:|---|
| 0 | 4 | `MST` then version byte `1` |
| 4 | 1 | Sealed flag, 0 or 1 |
| 5 | 3 | Reserved, zero |
| 8 | 2 | Total proof byte count, 1–8,009 |
| 10 | 2 | Received contiguous prefix byte count |
| 12 | 4 | Reserved, zero |
| 16 | 32 | Submitter wallet |
| 48 | 32 | Registered Log ID |
| 80 | 32 | SHA-256 of the complete proof including finder |
| 112 | 8 | Verified signature bitmap |
| 120 | 1,024 | 32 witness signing keys, one slot per attestation |
| 1,144 | 8 | Reserved, zero |
| 1,152 | total | Uploaded FRK bytes |

Bitmap ordinals 0 and 1 name the first and second service checkpoints. Ordinals
2–33 name attestation positions 0–31. An anchor reference has no second service
checkpoint to verify; ordinal 1 is refused. The adjudicator instead
authenticate the referenced ring entry and historical witness generation.

For attestation `i`, key slot `i` is meaningful only when bit `i + 2` is set.
It records the exact signing key whose registered Witness account and executed
precompile were verified. Re-verification cannot substitute another key under
the same textual witness ID. Unset bits never establish a signature, even when
the proof contains a plausibly encoded signature.

## Instructions

The discriminator is one byte. Payload lengths and account counts are exact.
`S` denotes signer and `W` writable; other accounts are read-only.

| Tag | Instruction and payload after tag | Accounts, in order |
|---:|---|---|
| 10 | Initialize: `u16 total`, `32 full_hash` | submitter S/W, Log, Stage W, System program |
| 11 | Append: `u16 offset`, 1–900 bytes | submitter S, Stage W |
| 12 | Seal: no payload | submitter S, Log, Stage W |
| 13 | Verify: `u8 ordinal`, `u16 ed25519_instruction_index` | Log, Stage W, Instructions sysvar; Witness and original submitter S only for ordinal ≥2 |
| 14 | Close: no payload | submitter S/W, Stage W |

Initialize validates the registered Log and derives the Stage address locally.
The submitter funds rent. Pre-funding the PDA does not block initialization;
the program tops up rent, allocates and assigns using its PDA seeds. Repeated
initialization of an existing account is refused; callers read its state to
resume an interrupted upload.

Append requires the original submitter. New bytes must start at the received
prefix length and fit the declared total. A retry wholly inside the received
prefix succeeds only when every byte matches. Gaps, overwrites, overlaps that
extend the prefix, empty chunks and chunks over 900 bytes are refused. Appending
after sealing is refused, including exact retries.

Seal requires the complete upload, the original submitter, the same registered
Log, the full hash, canonical FRK v1/v2/v3 framing, and the registered service key
and log version for each supplied checkpoint. Repeated sealing is idempotent.
It does not treat framing or a checkpoint-shaped byte array as a valid signature.
It also does not interpret a bare anchor index as trusted chain evidence.

Service verification is permissionless after sealing. Optional witness
verification requires the original submitter's signature: outsiders cannot
add an unfunded or withdrawn identity to a Stage's required settlement accounts.
The instruction reconstructs the exact service or witness statement from the
sealed proof. Witness verification first
loads an authenticated judge-owned Witness PDA for the same Log and exact ID;
its signing key is used for the precompile comparison and retained in the
stage. The attestation hash must match a checkpoint actually present in the
proof. A native statement binds the ID and checkpoint hash. C2SP statements
bind the registered origin, exact checkpoint note and original timestamp.
Historic signatures do not acquire a new timestamp when staged. C2SP-only
attestations cannot set witness verification bits for kind-3 metadata claims.

The Ed25519 instruction must be earlier in the same transaction, use the actual
precompile ID, have no account metas, and contain a self-contained single
signature with the exact key, signature and message. Missing, future, prior-
transaction, altered-offset, foreign-origin or otherwise mismatched precompiles
cannot set a bit. The real Instructions sysvar is required. A successful verify
adds one bit and its witness key without modifying the sealed proof. An already
verified signature can be retried with the same executed precompile.

Close requires the original submitter and transfers the Stage's entire lamport
balance to that submitter before closing it. Another wallet cannot choose a
refund recipient or consume a stage. Closing an incomplete upload is allowed.
The stage has no token vault or authority over bonds or rewards.

## Local evidence

`programs/morse-judge/tests/fork.rs` replays independently generated Node/OpenSSL
fixtures shared with Mesh for all framing versions, finder-independent hashes,
fork relations and exact Merkle paths. It checks every truncated prefix.
`stage_svm.rs` executes the compiled SBF program and real Ed25519 precompiles in
LiteSVM, with each transaction asserted to fit Solana's 1,232-byte packet cap.
Tests cover 34 separate verified signatures, maximum 8,009-byte uploads,
interrupted/retried uploads, sealing, refund authorization, malformed frames,
wrong keys/messages/origins/timestamps, missing/future/prior-transaction
precompiles, fake sysvars, read-only substitution and anchor-reference ordinals.

The app's `Transparency.RelayStage` constructs these instruction bytes in Mesh.
Its plan retains the exact proof, resolves the Stage PDA from the uploader and
full hash, emits append chunks of at most 900 bytes, and skips invalid optional
annotations without changing their positions in the proof. Only selected
witness identities are verified. Their settlement order follows first verified
first-checkpoint appearance, independently of RPC ordering. Each prepared
verification pair has an Ed25519 instruction index of zero; a transaction
assembler must patch that index to the actual earlier precompile position.

`scripts/prove-relay-stage.sh` generates fresh plans in Mesh and replays all
their bytes against the SBF judge with actual Ed25519 execution in LiteSVM.
It covers both profiles, native/C2SP, signed/anchor targets, sixteen witnesses,
34-signature stages, repeated appends, bad precompile rollback, close, and the
1,232-byte packet cap. The explicit Rust test requires the generated fixture;
the ordinary Rust-only suite labels it ignored instead of claiming it ran.
CI carries its compiled test executable and SBF artifact into the Mesh job.

Stage plans are a local preparation boundary. They do not establish proof age,
vault custody, funding policy, chain finality or a completed relay submission.
The separate [relay admission boundary](relay-admission-v1.md) authenticates
observed age, custody and destinations and prepares settlement instructions.
The judge still rechecks those conditions atomically during execution.

Run `scripts/prove-judge.sh` with the pinned SBF toolchain. This also runs the
existing registration, historical generation, anchor, ring and introspection
checks. These local tests do not establish deployment, external review,
immutability, funded custody, economic safety or live chain finality.
