# Local outage qualification on 2026-11-06

The local integration prerequisite for WITNESS §4.3 check 2 passed on compiled
source `a66889ae36a281de586a864e50544adb876763a2`, based on
`661a585d69e5da8aacfadd349b5b002ac433c5c1`. This qualifies that source and its
retained artifacts. Parent `c49561a` contains different Core sources and requires
its own fresh composed-source control. This result is not B1 or production
acceptance.

## Observed process and native behavior

Three unchanged standalone witness executables ran their actual pull loops with
distinct synthetic keys and state directories. Native resources pinned all
three keys at threshold two, selected RFC log v2, disabled anchors and RPC
sources, and served RPC TLS resource bytes `01 00`. The loopback directory was
a synthetic persisted Mesh log, not the production directory service.

Witness C's original PID `54229` exited cleanly and was reaped before timing
started at `2026-11-06T20:37:02.856692Z`. The restart was requested at
`2026-11-06T20:52:02.914387Z`. The conservative measured absence was
`900.056500333` monotonic seconds and `900.057696` UTC wall seconds.

During the outage, the actual compiled `mesh_messenger_directory_resolve` ABI
succeeded 155 times over 30 new checkpoints, tree sizes 2 through 31. The largest
observed gap was `20.091857333` seconds. Every success required the expected
canary device set, current verified checkpoint and origin, and an audit of the
view, consistency, witnesses and leaf cache records. A/B supplied actual verified
attestations for every new checkpoint. C supplied none during its absence.

C retained checkpoint 1 unchanged throughout the outage. Its state SHA256 before
stop and before restart was
`f056ca3fe0a29deff92c5254d73525dd1de34a8673c66878488c0e300714fb87`.
Restart PID `11448` used the same key and state path, without an initial
checkpoint/reset input. The actual service requested consistency range 1 to 31,
verified the Mesh proof, persisted checkpoint 31, and released its verified
signature for that fresh checkpoint. No history/timing rejection record appeared.
The returned state SHA256 was
`8f7275e45d543c279de09160ece93351b92feb8bc7cc23bf93611cacebf8ddee`.
A final actual native lookup passed after recovery. All three witness processes
and both native ABI host processes exited with code zero.

The final short run used the same binary hashes. It observed
`60.094800958` monotonic seconds of absence, 11 native successes, two new
checkpoints and the same verified retained-state recovery contract.

## Controls and review

The native boundary first rejected evidence with zero witness attestations.
Starting the actual witness processes made that same native lookup succeed.
It also rejected each of these responses while preserving the prior verified
cache:

- One genuine pinned witness signature, below the two-of-three threshold.
- A checkpoint with a corrupted service signature.
- Valid checkpoint/proofs with two pinned witness IDs and one corrupted witness
  signature.

Independent source review found and then cleared a partial-line ABI deadline
bug, incomplete cache binding and missing forged-witness coverage. The retained
transport regression failed before the deadline fix and passes afterward.
The real process proof uses observed HTTP/publication barriers and PID exit
checks. Poll scheduling waits do not establish success or elapsed duration.

Final independent review R3 reran the retained-evidence audit and returned
`PASS` with no blockers for this exact source. It separately confirmed hashes,
process ownership, both clocks, native coverage, threshold controls, retained
state recovery, and absent PIDs after clean exits. Its disposition is retained
in `audit/reviews.json`.

## Exact inputs, artifacts and evidence

The qualified Mesh source is
`8256d5d30e79f3c1de9d8507f8607f8efbee756a`. The compiler, runtime and test runtime
pins are recorded in `build.json` and match the reviewed bootstrap family.
The native artifacts have these SHA256 values:

| Artifact | SHA256 |
| --- | --- |
| Native library | `d7d9a864edd7478ebf3c2fcb9f32ba88fab930376f0ded2ae8efd36d92dc767c` |
| C ABI bridge | `e5d7166b0b025ba9b27af6a2e6a109c078dce0a3a81eb67fe38887ba7f823cb7` |
| Actual witness executable | `121fac3b565dbde25779f1ba8e87fda69627636faf4af77b93ea41fe10b399fe` |

Evidence is retained in this worktree at
`.morse/witness-outage-20261106/`. The closed 900-second receipt and logs are
under `measured-900/`. The receipt includes every public configuration/state/log
hash. `events.jsonl` includes signed checkpoint bytes, actual witness submissions,
durable state bytes, consistency queries/proofs, native outcomes, PIDs and clocks.

| Retained record | SHA256 |
| --- | --- |
| `measured-900/receipt.json` | `e94248c9e09c3461a5607d9a7b6d3f0c1afb06def74f3fed99786a02c9adb1b3` |
| `measured-900/events.jsonl` | `8c8f4edc04c80b97416a81c087ac37c7a77892c76a61e4f23df4fa1545f4c65f` |
| `measured-900/build.json` | `3db640b97984d5b7d94acb7264655001de1eccd4870dbac6ae9923cd9ba7f2a6` |
| `short/receipt.json` | `0bc777a5f1267e697ee66241e14bd111a2d8dc08afc53e919853bc74f930ae05` |

The independent retained-evidence audit is `audit/check.py`, with its result in
`audit/result.json`. It checked the closed hashes, source copies, pinned toolchain,
artifact bytes, process stop/restart identities, both elapsed clocks, all four
negative controls, native freshness and checkpoint coverage, exact recovery
range and clean process exits. The native artifacts and frozen product/Mesh
package sources remain available for parent review.

The exact 900-second command was:

```sh
python3 -B mesh-private-messenger/ops/bootstrap/witness-outage/prove.py \
  --compiler /Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts/bin/meshc \
  --mesh-source /Users/andreyyurlov/Documents/dev/mesh-lang \
  --build-dir .morse/witness-outage-20261106/build \
  --evidence-dir .morse/witness-outage-20261106/measured-900 \
  --outage-seconds 900
```

No witness service, Core, protocol, shared bootstrap/TLS fixture, packaging,
inventory or WITNESS plan source changed. No push, PR, deployment, external RPC,
paid network, host configuration, secret/user-account or production-state access
was used. This does not qualify independent operators/software, remote
placement, Linux images, native phones, anchors, TLS, seven-day observation or
any live production check.

## Retention after parent coordination

After the receipt closed and R3 passed, the parent authorized removal of only
the copied compiler and runtime archives. Cleanup removed `284732544` logical
bytes from this proof's `build/toolchain/`. The shared qualified Mesh family
was untouched. Native library, bridge and witness executable hashes were
checked again after cleanup and remain unchanged.

`cleanup.json` records the removed file hashes, original shared paths,
authorization and retained artifact hashes. Its SHA256 is
`caba008695c5381cede835fe06b5e7812ca66a89b66687404ea36e92e9426c53`.
All frozen product sources, external Mesh package sources, fixture/resources,
public synthetic state, event logs and receipts remain available. The full
`audit/check.py` result and R3 hash checks were obtained before archive removal;
rerunning that exact pre-cleanup audit requires restaging the copied archives
and checking out the recorded source revision. The fixture runner can still
reuse the retained binaries or rebuild with the shared qualified family.
