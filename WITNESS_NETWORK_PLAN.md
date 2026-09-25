# Witness Network: Implementation Plan

Status: plan, written 2026-09-25. Nothing in it is built. The design it
implements is [protocol/witness-network-v1.md](mesh-private-messenger/protocol/witness-network-v1.md)
(status: proposed). This file says how to build it, in what order, with what
numbers, and how each step is tested.

All dollar figures assume SOL at $150 and are starting points to revisit at each
phase gate, not commitments.

## 1. What this delivers

Today a phone trusts a key because the directory's log says so and two witnesses
countersigned that version of the log. Both witnesses are run by Morse, so a
lying directory is checked only by itself. When this plan is done:

1. Every version of the key log is **posted to a public chain** (Solana), so a
   version shown privately to one person contradicts the public record.
2. **Independent operators run most of the witnesses**, pinned by each app
   release, with a strict-majority threshold.
3. Each witness, and the directory itself, **stakes a bond** that is slashed by
   an on-chain proof whenever it signs two versions of the log that can't both
   be true.
4. Witnesses are **paid** for being present, first from a Morse-funded floor,
   then from a share of anonymous credit sales.
5. Later, the **Morse token** becomes the bond and is burned by credit purchases.

Three rules hold in every phase:

- **The phone verifies.** Security never depends on the chain being up or the
  token having value. The chain can take trust away (a slashed key stops being
  trusted); it can never grant it.
- **Releases pin trust.** The witness keys a phone accepts, and the threshold,
  ship in the app's native security config. On-chain status decides who may
  bond, who gets paid and who gets slashed, never who is trusted.
- **Privacy is unchanged.** Witnesses, the chain, monitors and relays see
  checkpoints and proofs only: no usernames, devices, mailboxes, wallets or
  messages. Messaging never needs a wallet, credits or the token.

## 2. Where things stand today (verified in code)

| Area | Today | Where |
|---|---|---|
| Checkpoint | 188-byte `KTK` wire form. The service signs a 146-byte statement: `"mesh-key-transparency-v1"`, version u16, sequence u64, tree size u64, root, previous checkpoint hash, timestamp u64, service key. `checkpoint_hash = SHA-256("mesh-msg/v1/transparency-checkpoint" ‖ statement ‖ signature)` | `packages/messenger-protocol/transparency/merkle.mpl:182`, `wire.mpl:416` |
| Witness signature | Ed25519 over `"mesh-msg/v1/transparency-witness" ‖ witness_id ‖ checkpoint_hash`; ID at most 64 bytes, pinned to one key | `merkle.mpl:276` |
| Witness logic | Run-once job: fetch checkpoint, verify the service signature, refuse rollback, refuse a same-sequence conflict, require a consistency proof from its last signed checkpoint, persist, then sign and post | `services/transparency-witness/main.mpl:89,140` |
| Witness hosting | Two Cloudflare Workers, same operator. Delivery's scheduled job calls each one's `/attest` with a bearer token Morse holds. State lives in a Durable Object with compare-and-swap writes; continuity is carried over with `WITNESS_INITIAL_CHECKPOINT_HEX` | `ops/cloudflare/witness.mjs`, `jobs.mjs:77` |
| Phone threshold | Exactly witnesses A and B, **threshold 2 of 2**: either one offline stops new lookups | `packages/mobile-core/mobile/transparency.mpl:529-541` |
| Phone pinning | Witness keys come from the native security config, baked in at build; an OTA update can't change them | `mobile-core/mobile/platform.mpl:248`, `ops/cloudflare/README.md` |
| Groups | Group policy hard-codes `witness_threshold: 2` and checks `witness_count == 2` | `mobile-core/mobile/groups.mpl:133,476` |
| Limits | `verify_witnesses` accepts at most 16 pinned keys and 16 attestations | `merkle.mpl:388` |
| Proof size | Proofs carry the full leaf list. The log stops at 4,096 entries (3,584 for new accounts) | `merkle.mpl:171`, `key-transparency-v1.md` |
| Freshness | Phones reject evidence more than 5 minutes old; the directory re-signs an unchanged tree after 4 minutes | `transparency/client.mpl`, `directory-delivery/storage/transparency.mpl:211` |
| Conflict detection | Only same sequence, same size, different root | `merkle.mpl:397` |
| Missing entirely | No public record, no monitors, no fork-proof format, and no comparison of a phone's view with anyone else's | |

## 3. Design decisions

### 3.1 Threshold is a strict majority

Phones require `k > n/2` of the `n` pinned witnesses. Then any two conflicting
versions that both reach the threshold share at least `2k − n ≥ 1` witness who
signed both, so every successful split view leaves a provable, slashable
double-signer as soon as both versions are seen.

### 3.2 What counts as a lie (fork evidence)

A fork proof is self-contained and checkable on-chain. Three kinds:

| Kind | Evidence | Who is slashed |
|---|---|---|
| **F1 same size** | Two service-signed checkpoints with equal tree size and different roots | The directory, plus every witness that cosigned both |
| **F2 contradiction** | Two service-signed checkpoints C1 (size n1) and C2 (size n2), an index `i < min(n1, n2)`, and compact inclusion proofs showing different leaf hashes at `i` in each | Same. This covers forks that never share a tree size, which F1 misses. |
| **F3 rollback** | Two service-signed checkpoints whose sequence order and tree-size order disagree, or equal sequence with different content | The directory, plus any witness that cosigned both |

F1 reveals only two roots. F2 reveals which leaf index was forked, which can
hint at the targeted account, so relays prefer F1 whenever both are available.

Morse never receives slashed funds, since that would reward framing witnesses.
**10% goes to whoever submitted the proof. The other 90% is locked forever
(USDC) or burned (token).** Because the finder's share is below 100%, reporting
yourself always loses money.

### 3.3 Chain: Solana (confirmed 2026-09-25)

- It has a native Ed25519 program, so service and witness signatures can be
  verified on-chain without new cryptography, and a `sol_sha256` syscall for
  Merkle paths.
- Base fees are 5,000 lamports per signature, so anchoring every checkpoint is
  cheap.
- USDC is native there, for the bond phase before the token.
- Its known pitfall is Ed25519 verification through instruction introspection:
  the program must check that the Ed25519 instruction is in the same
  transaction and that its offsets point at exactly the expected key, message
  and signature bytes. This is tested explicitly (§6).

### 3.4 Languages (approved 2026-09-25, an exception to Mesh-first like the wallet core)

- **On-chain programs: Rust.** Mesh has no SBF target. Use Pinocchio for the
  immutable part (§5 Phase 3), because it has no framework macros to review.
- **Chain writers (anchor poster, reward crank): JavaScript in `ops/cloudflare`**,
  using `@solana/kit`, next to the existing ops code.
- **Everything phones and witnesses run: Mesh.** Phones only *read* the chain,
  through plain JSON-RPC over HTTP, and verify with the Ed25519 and SHA-256
  functions Mesh already has.

### 3.5 Implementation diversity

If every witness runs the same Mesh binary, one bug, a compiler backdoor or a bad
Morse release breaks the whole threshold at once. So:

- The directory also publishes each checkpoint in the C2SP signed-note format and
  accepts C2SP cosignatures (`tlog-checkpoint`, `tlog-cosignature`,
  `tlog-witness`). Existing third-party witness software can then cosign the
  Morse log unchanged. Check the exact C2SP wire details at implementation time.
- At least one pinned witness must run software not written by Morse before the
  threshold relies on outside witnesses (Phase 2 exit).
- The Mesh witness ships as a reproducible build (pinned `meshc`,
  `SHA256SUMS`), so operators can rebuild it and compare.

### 3.6 Phones check the public record themselves

Phones read the chain from public RPC providers, never through Morse
infrastructure, because a Morse-run proxy could hand a victim a forged "public"
record. Solana has no practical light client, so phones require **two
independent providers to agree**. The cost: those providers learn the phone's IP
address and that it reads Morse's anchor account, about once a day. This goes
into the privacy contract (§8).

## 4. Numbers

| Parameter | Value | Why |
|---|---|---|
| Pinned witnesses at Phase 2 launch | **5, threshold 3** (Morse runs 1) | Up to 2 can be offline. A split view needs the directory plus 3 witnesses, so Morse would have to recruit 2 outsiders |
| Target pinned set | **9, threshold 5** (Morse runs 1) | Up to 4 can be offline; collusion needs 4 outside operators. The code limit is 16 |
| Witness poll interval | 15 s | A new checkpoint must collect a threshold of signatures well inside the 5-minute freshness window |
| Witness signing deadline | 60 s after a new checkpoint | Leaves time for phones inside the 5-minute window |
| Anchor cadence | Every root change, at most **1 per minute**, plus an **hourly heartbeat** | The heartbeat lets phones and monitors tell a stalled anchor from a quiet log |
| Anchor ring | 4,096 entries × 104 B (sequence, size, root, checkpoint hash, timestamp, slot, cosign bitmap, padding) ≈ 426 KB | That's **about 3 SOL of rent, refundable**. It covers 2.8 days at the worst-case rate and several weeks at typical rates; older anchors stay in transaction history |
| Cosign window | **1,500 slots (about 10 minutes)** after the anchor's slot | A cosignature only counts as attendance if it was on time |
| Anchor fees | Worst case 1,440 × 5,000 lamports = 0.0072 SOL/day (about **$33/month**); typical (about 100/day) **$2/month** | |
| Witness self-cosign fees | The same per witness if it self-submits. Morse's crank submits for everyone by default, batched 4 per transaction | |
| Phone check | Every **24 h**, plus when a contact's key changes (at most **1 per hour**). Reads use `getAccountInfo` with `dataSlice`, a few hundred bytes from 2 providers | |
| Anchor lag tolerated by phones | **2 h** before a "public record is stale" warning. It never blocks messaging | Solana outages must not take Morse down |
| Epoch | **7 days** | Attendance is counted and rewards settle once per epoch |
| Attendance | Share of the epoch's anchors that carry the witness's on-time cosignature | Pay factor = clamp((attendance − 0.80) / 0.15, 0, 1): full pay at ≥ 95%, none at ≤ 80% |
| Removal | Attendance below 95% for 2 epochs in a row means unpinned in the next release. Any fork proof means unpinned in a hotfix | |
| Pay floor (bootstrap) | **$300/month** per outside witness, from the Morse treasury, for the first 12 months | $14,400/year for 4 operators. There's no credit revenue yet |
| Pay after credits exist | Witness pool = **20% of credit revenue**, split by pay factor, never below the floor while the floor lasts | About $400/month each at 10,000 buyers spending $2/month across 10 witnesses |
| Witness bond | **$10,000 USDC at Phase 3.** Later: `max($10,000, 24 × the witness's average monthly pay)` | Lying always costs at least two years of income, plus $10k |
| Directory bond | **$50,000 USDC at Phase 3**, rising to **$250,000**, and never below the sum of all witness bonds | The directory has to sign every fork, so its bond is on the line in every attack |
| Money at risk to fork one person | Launch: 3 × $10k + $50k = **$80k**. Target: 5 × $25k + $250k = **$375k**, plus public exposure | This deters commercial attackers, not states. Detection and safety numbers cover those |
| Finder's share | **10%** of everything the proof slashes | |
| Proof window | **28 days** after the older checkpoint's timestamp | Covers phones that check daily, with slack |
| Unbonding delay | **30 days**, longer than the proof window | A witness can't sign a lie and then withdraw its bond before it's caught |
| Parameter changes | 3-of-5 multisig with at least 2 non-Morse signers, plus a **14-day timelock** | Slashing and custody code is immutable (§5 Phase 3) |
| Token bond (Phase 5) | The USD target converted at a 7-day TWAP. Below 80% of target, the witness has 7 days to top up or becomes ineligible (not slashed) | A falling token price mustn't quietly weaken security |
| Credit revenue split (Phase 5) | 20% witness pool, 30% buy-and-burn, 50% operations | Before the token: 20% pool, 80% operations |
| Operator costs | $10–40/month for the server (active/passive pair for 99.5% uptime), plus fees above | |
| Program security review | **$40,000–80,000**, before any bond is on mainnet | |

## 5. Phases

| Phase | What | Rough time | Depends on |
|---|---|---|---|
| 0 | Foundations: compact proofs, N-of-M witnesses, pull-mode witness, fork evidence, C2SP | 8–12 weeks | nothing |
| 1 | Public checkpoints: anchor program, poster, phone check, monitor, relays | 4–6 weeks | 0.1, 0.4 |
| 2 | Independent witnesses, paid from the floor | 4–8 weeks (recruit during 0–1) | 0.2, 0.3, 1 |
| 3 | Bonds and slashing (USDC) | 6–10 weeks incl. review | 1, 2 |
| 4 | Anonymous credits (separate plan); feeds the witness pool | 6–8 weeks | 3 for pool payouts |
| 5 | The token as bond and burn | 6–8 weeks | 3, 4 |

### Phase 0: Foundations (no chain)

**0.1 Compact proofs and lifting the 4,096 ceiling.** Needed for scale, for
C2SP witnesses (which verify RFC 6962 consistency proofs) and for F2 proofs
on-chain. `key-transparency-v1.md` already lists this as unfinished.

- `transparency/merkle.mpl`: RFC 6962 audit paths and consistency proofs. The
  tree shape and the domain-separated leaf and node hashes are unchanged, so
  roots, checkpoints and witness signatures are unaffected.
- `transparency/wire.mpl`: new proof encodings with a version bump. Old
  full-list proofs stay accepted for one release (`compatibility-matrix.md`).
- `directory-delivery/storage/transparency.mpl`: store interior node hashes and
  build proofs from them, instead of loading every leaf.
- `mobile-core/mobile/transparency.mpl`: redesign `transparency_checkpoint_in_view`
  to fetch and cache one proof per group anchor through the group flows.
- Tests: RFC 6962 vectors; a property test that the consistency proof of every
  (old, new) prefix pair verifies and a mutated one fails;
  `transparency_capacity.test.mpl` raised to one million entries.
- Exit: the log grows past 4,096 entries; proof size is O(log n).

**0.2 N-of-M witness sets.**

- Security config v2: up to 16 `(witness_id, public_key)` entries, a threshold,
  and `set_id = SHA-256(canonical list ‖ threshold)`. Parser in
  `mobile-core/mobile/platform.mpl`; writers for Kotlin, Swift and the desktop
  `config.json`; generation of `.morse/cloudflare/client.env`.
- `mobile-core/mobile/transparency.mpl`: replace the `witness_a/b` fields with
  the set, and invalidate the cached view when `set_id` changes (it already does
  this for key changes, at :524).
- `mobile-core/mobile/groups.mpl`: the group policy carries `set_id` and the
  threshold, and rejects any threshold that isn't a strict majority. Remove
  `witness_count == 2`. This bumps the group welcome wire version.
- `clients/mesh-cli/main.mpl:214`, `ops/cloudflare/witness.mjs` (`attestWitnesses`
  iterates a `WITNESSES` list), and the directory's `validate_transparency_config`.
- Tests: threshold boundary (k−1 fails, k passes); duplicate and unknown IDs
  ignored; a non-majority threshold refused; group welcomes across a set
  rotation; migration from today's 2-of-2 config.

**0.3 Pull-mode witnesses for outside operators.** Today Morse holds each
witness's bearer token and triggers it. Outside operators shouldn't expose an
endpoint for Morse to call.

- The witness polls `GET /v1/transparency/checkpoint` every 15 s and posts to
  `POST /v1/transparency/witnesses` (both routes already exist in
  `directory-delivery/api/router.mpl`). `/attest` stays for Morse's own witness.
- Local state is a file with fsync and compare-and-swap semantics, replacing the
  Durable Object for operators outside Cloudflare. Continuity transfer keeps its
  existing rule: new identity, or an explicit last checkpoint.
- Packaging: an OCI image built reproducibly from a pinned `meshc`, published
  `SHA256SUMS`, and an operator runbook covering keys, backups, upgrades and
  monitoring.
- Exit: a witness on an ordinary VPS stays in sync for 7 days, and a restored
  stale backup refuses to sign instead of forking.

**0.4 Fork evidence in the protocol.**

- A new `Transparency.Fork` module with `fork_same_size`, `fork_contradiction`
  and `fork_rollback`, each returning which service and witness keys are
  implicated.
- An `FRK` v1 wire encoding: both checkpoints, the proofs, and the attestations
  involved.
- Witnesses persist evidence when `verify_history` fails, instead of only
  logging it.
- Tests: each kind accepts a real fork, rejects honest pairs, rejects mixed
  service keys, and rejects a proof with any byte changed. These vectors are
  later replayed against the on-chain program (Phase 3).

**0.5 C2SP compatibility.**

- The directory serves each checkpoint as a C2SP signed note and accepts
  `cosignature/v1` from pinned keys.
- Phones accept either a Mesh-native attestation or a C2SP cosignature from a
  pinned key; each witness counts once.
- Exit: one third-party witness implementation cosigns the development log.

### Phase 1: Public checkpoints

**1.1 The anchor part of the judge program** (Rust, Pinocchio, devnet first).

- Accounts: `Config` (service key, anchor authority, parameters, `service_slashed`
  flag) and `AnchorRing` (4,096 × 104 B, grown in 10 KB reallocs at setup).
- `post_anchor(checkpoint)`: the transaction must carry an Ed25519 instruction
  verifying the service signature over the 146-byte statement, which the program
  rebuilds from the checkpoint and compares byte for byte. It enforces
  non-decreasing sequence and size against the previous anchor; a violation is
  stored as F3 evidence. It then records the entry.
- `cosign(anchor_index, witness_id, signature)`: verifies the witness statement
  over the anchored `checkpoint_hash` through the Ed25519 instruction, only
  within 1,500 slots of the anchor, and sets that witness's bit. Anyone may pay
  the fee. The bit, and later the pay, belong to the witness.
- Before Phase 3 there are no bonds, so a violation only emits an event.

**1.2 Anchor poster** (`ops/cloudflare`, JavaScript).

- Runs in the jobs Durable Object right after each new checkpoint and hourly.
- Keys: a fee-payer hot wallet holding at most 1 SOL (alert at 0.2 SOL) and a
  separate anchor authority. A stolen authority key can only post genuinely
  signed checkpoints, because the program checks the service signature.
- It also cranks witnesses' cosignatures collected by the directory. Witnesses
  can self-submit with a small standalone tool if they think they're being
  censored.

**1.3 Phone check** (`mobile-core`, Mesh, a new `Mobile.Anchor` module).

- Read the ring header, then the needed entries, from 2 of at least 3 pinned
  public RPC URLs in the security config. Both must agree.
- Take the newest anchor whose tree size is at least the phone's cached
  checkpoint's, fetch a consistency proof from the directory, and verify it
  against the anchored root. Also read `Config.service_slashed` and the witness
  statuses.
- Outcomes:
  - **ok**
  - **stale** (anchors more than 2 h behind): a quiet warning, messaging
    unaffected.
  - **mismatch or refused proof**: fail closed for new sessions and key changes,
    exactly like a failed witness check today. Show "Morse's key log doesn't
    match the public record", keep the evidence, and send `FRK` to relays.
  - **slashed**: stop accepting that key at once.
- Tests: fake RPC servers that agree, disagree or lag; a forked directory
  fixture; the failure states surfaced to the UI through the existing error
  paths.

**1.4 Monitor** (Mesh, a `monitor` subcommand in `clients/mesh-cli`).

- Follows every anchor, checks consistency between consecutive anchors, checks
  cosign bitmaps against the pinned set, and builds `FRK` proofs.
- Exposes a status page. Morse runs one, and every witness operator is asked to
  run one.

**1.5 Relays for phone evidence.** Phones have no SOL, so they post `FRK`
evidence to every relay in a pinned list. Witness operators and monitors run the
relays, not only Morse, because Morse can't be trusted to submit proof against
itself. From Phase 3, the relay that lands a proof on-chain keeps the finder's
share, which gives outsiders a reason to run relays.

- Exit: 30 days of mainnet anchors with no gap over 1 hour, and the phone check
  shipped.

### Phase 2: Independent witnesses

- **Recruit 4 outside operators** (start in Phase 0): two from existing
  transparency-witness operators via C2SP, one or two Solana validators, and one
  privacy organisation or university. Requirements: separate legal entities, at
  least 2 jurisdictions, nothing shared with Morse's cloud accounts, a named
  contact, and 99.5% uptime.
- **Key ceremony.** Each operator generates its key on its own hardware (an HSM
  or a KMS with Ed25519 support where possible); Morse never sees it. The
  operator signs a pinning statement. Publish `protocol/witnesses.md` listing ID,
  key, operator, jurisdiction and software.
- **Release.** Pin 5 with threshold 3: Morse's witness A plus 4 outside
  operators. Keep witness B pinned for one release during the transition, as 6
  with threshold 4, then drop it.
- **Pay.** $300/month in USDC from the multisig, using the Phase 1 on-chain
  attendance. No program changes are needed yet.
- Exit: 30 days with the threshold met on at least 99.9% of checkpoints, and at
  least one witness running software not written by Morse. Only after this may
  any Morse copy call the witnesses independent.

### Phase 3: Bonds and slashing (USDC)

Split the on-chain code in two:

- **`morse-judge`** (Pinocchio, made immutable after review): anchors, cosigns,
  bond vaults, unbonding, fork proofs and slashing.
- **`morse-rewards`** (upgradeable behind the multisig and timelock): epochs,
  attendance, pool and payouts.

Instructions:

- `register_witness(witness_id, signing_key, payout_address)`, `bond`,
  `request_unbond`, `withdraw` (30 days later), `bond_directory`.
- `prove_same_size`: two checkpoints, with Ed25519 instructions covering the two
  service signatures and each accused witness's two cosignatures. Staged across
  transactions when it doesn't fit in the 1,232-byte limit.
- `stage_proof` then `prove_contradiction`: a staging account holds both
  checkpoints and two audit paths (at most 2 × 32 × 32 B); finalizing
  recomputes both roots with `sol_sha256` using Morse's domain labels. Staging
  rent returns to the submitter.
- `prove_rollback`.
- Slashing takes 100% of each implicated bond: 10% to the submitter, 90% locked
  in a vault with no withdraw path. It sets `Slashed` (permanent) or
  `service_slashed`. The same proof can't be paid twice.
- `settle_epoch` and `claim_reward` in `morse-rewards`.

Bonds: witnesses $10,000 USDC, the directory $50,000 USDC from treasury. A
witness must be `Active` (bonded) for one full epoch before a release may pin it.

Tests (LiteSVM or Mollusk unit tests; a local validator for integration):

- Every instruction's happy path and refusals.
- Ed25519 introspection attacks: the instruction missing, in another
  transaction, offsets pointing at other bytes, or a different message.
- A cosignature outside the window; double slashing; slashing during unbonding
  (succeeds) and after withdrawal (fails).
- Staging abuse: someone else's staging account, or a partial proof.
- The Phase 0.4 fork vectors replayed through the program, checked against the
  Mesh implementation, the same interop pattern as the ML-KEM/OpenSSL
  cross-check.
- Review: an outside security review of `morse-judge` before mainnet bonds, then
  upgrade authority removed. A bug bounty for the programs.
- Exit: a devnet game day. Fork a staging directory on purpose, watch phones
  fail closed and relay, and see the witness and directory bonds slashed on-chain
  with the relay paid.

### Phase 4: Anonymous credits (witness-relevant parts only)

Credits get their own plan: Privacy Pass issuance (RFC 9578, blind RSA from RFC
9474), issuer keys logged in the transparency log, and spending at the privacy
edge beside proof of work. For witnesses, 20% of credit revenue flows into the
`morse-rewards` pool each epoch, and the $300 floor tapers off once the pool
exceeds it for three epochs in a row.

### Phase 5: The token

- Bonds may be posted in the token at the USD targets above (7-day TWAP, top-up
  rule). USDC bonds are still accepted during the transition.
- The slashed token portion is burned. Credit purchases swap and burn per the
  split in §4.
- No token governance over anything security-relevant: pinning stays in
  releases, and parameters stay behind the multisig and timelock.

## 6. What a cheating witness host can do, and what stops it

| Attempt | Effect | Stopped by | Phase |
|---|---|---|---|
| Change the witness code, `meshc` or the runtime | Equivalent to signing anything; affects only their own witness | The phone checks signatures, not code. See the rows below | — |
| Sign a fake version alone | Nothing: it also needs the directory's signature and a majority | Strict-majority threshold | 0.2 |
| Sign without checking (lazy) | Harmless alone; if it ever signs a fork it's slashed like a liar | Fork proofs punish the outcome, so laziness never needs proving | 3 |
| Collude with the directory to fork one person | The real attack | Phone check against the public record; majority threshold guarantees a double-signer; bonds; safety numbers | 1, 3 |
| Fork at sizes that never overlap | Escapes F1 | F2 contradiction proofs | 0.4, 3 |
| Farm the finder's reward | Impossible: needs the directory's signature on two versions | Proof requires two service signatures; finder's share below 100% | 3 |
| Go offline or sign late | Lookups fail if more than `n − k` are down | Spare witnesses, pay factor, removal rules | 2 |
| Lose state and re-sign from an old backup | Could accidentally double-sign | Continuity rule refuses to start without a trusted last checkpoint | 0.3 |
| Get its key stolen | The attacker can double-sign; the operator's bond is still slashed | Operator key custody (HSM), unpinning by hotfix, 30-day unbonding | 2, 3 |
| One bug or backdoor shared by every witness (including a bad Morse release) | Could break the threshold at once | C2SP diversity, reproducible builds | 0.5, 2 |
| Sybil: one entity runs several witnesses | Fewer distinct parties to collude | Vetting and published operator list, releases pin by operator, at most 1 per legal entity | 2 |
| Attack the slashing program | Slash honest witnesses or drain bonds | Minimal immutable judge, outside review, timelocked multisig, bug bounty | 3 |
| Touch user data | Nothing to touch | Witnesses receive checkpoints only | — |

## 7. Incidents

- **Witness offline.** No action below `n − k` down. Operator paged at 10
  minutes. If attendance drops, the pay factor falls, then removal.
- **Witness key compromised or lost.** The operator reports it, and a hotfix
  release unpins that ID. Rotation always means a new witness ID pinned by a
  release; the old one stays bonded until unbonding ends.
- **Fork proof lands.** The implicated witness is unpinned by hotfix. If the
  service key is implicated, phones stop trusting it on their next check and
  fail closed for new key lookups; existing sessions keep working. Morse
  publishes a post-mortem, then ships a new service key and log, carrying
  continuity evidence so users can check nothing else changed.
- **Solana outage or censorship.** Anchoring pauses; phones show "stale" after 2
  hours and messaging carries on. A backlog is anchored when the chain recovers.
- **RPC providers disagree.** Retry with the others. Persistent disagreement is a
  warning, never a silent pass.

## 8. Documents and the landing page

- Update `protocol/key-transparency-v1.md` (N-of-M, majority, compact proofs,
  anchors), `privacy-contract.md` (RPC providers see a phone's IP and its daily
  read of the anchor account), `threat-model.md` (collusion model, chain
  assumptions), `witness-network-v1.md` (status per phase), `compatibility-matrix.md`,
  `ops/cloudflare/README.md`, and the landing page's `how-it-works.html` (outside
  witnesses and a chain node).
- The landing page describes the network in the present tense. Its "Launching in
  stages" pill stays until the Phase 3 exit, because until then bonded
  independent witnesses don't exist. The token copy isn't true until Phase 5.
- `node check.mjs` in `apps/landing` keeps banning return language.

## 9. Budget (first 12 months)

| Item | Cost |
|---|---|
| Directory bond (locked, not spent) | $50,000 USDC |
| Morse's own witness bond (locked) | $10,000 USDC |
| Pay floor, 4 outside witnesses × $300 × 12 | $14,400 |
| Program security review | $40,000–80,000 |
| Chain fees and rent | under $1,000 (anchor rent of about 3 SOL is refundable) |

## 10. Decisions (2026-09-25)

1. **Languages:** Rust for the on-chain programs and JavaScript for the chain
   writers are approved, as an exception to Mesh-first like the wallet core.
2. **Chain:** Solana.
3. **Funding:** the bonds, the pay floor and the program review in §9 are
   approved at the amounts shown.
4. **Morse's own witness:** Morse keeps exactly one pinned witness for good. It
   counts toward the pinned set like any other, and is bonded and slashable like
   any other. The thresholds in §4 are chosen so it can never reach a majority
   on its own or with the directory.
