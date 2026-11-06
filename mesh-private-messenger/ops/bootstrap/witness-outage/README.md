# Local witness outage prerequisite

This runner qualifies the **local integration prerequisite** for WITNESS §4.3
check 2. It does not qualify B1, a native phone, live production, seven days of
observation, independent software/operators, remote placement, anchors or TLS.
It uses no external services, accounts or production state.

The directory is a loopback fixture, not the production directory service.
Its compiled Mesh exports create a public synthetic canary using the actual
MobileCore account/directory-entry ABI, grow a persisted RFC tree, and produce
signed checkpoints, inclusion proofs and exact-range consistency proofs with
the public production Mesh APIs. It never signs witness attestations. Three
unchanged `services/transparency-witness` executables own distinct public
synthetic seeds and separate state directories. Each run generates new fixture
identities so separate runs cannot reset one signing identity's history.
The executables run the current 15-second
pull loop, verify history, persist state, and submit their own signatures.

The client is a separate native process calling the actual compiled
`mesh_messenger_directory_resolve` ABI. Success requires the expected canary
device set and publication of all five verified cache records, including the
exact current checkpoint and directory origin. A further Mesh audit uses Core's
public view loader and compares the cached consistency, witness and leaf records
to the exact successful response. No raw lookup encoder replaces
the resolver. Its native security resource pins three distinct keys at threshold
two, prefers RFC log v2, and explicitly disables anchors and RPC sources. The
native resource host serves **exact bytes `01 00`** for
`messenger/rpc-tls-roots/v1`, including before a Core loader consumes that resource.
OHTTP is explicitly off in this loopback fixture.

## Run

Run from the repository root with the qualified clean Mesh source and compiler
family. No installation or dependency download is performed. The compiler,
runtime and test runtime hashes must match the bootstrap family's reviewed pins.
The runner copies its source inputs and toolchain to one owned build directory;
it never modifies a shared compiler or build target.

```sh
python3 -B mesh-private-messenger/ops/bootstrap/witness-outage/prove.py \
  --compiler /Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts/bin/meshc \
  --mesh-source /Users/andreyyurlov/Documents/dev/mesh-lang \
  --build-dir .morse/witness-outage-20261106/build \
  --evidence-dir .morse/witness-outage-20261106/short \
  --outage-seconds 60

python3 -B mesh-private-messenger/ops/bootstrap/witness-outage/prove.py \
  --compiler /Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts/bin/meshc \
  --mesh-source /Users/andreyyurlov/Documents/dev/mesh-lang \
  --build-dir .morse/witness-outage-20261106/build \
  --evidence-dir .morse/witness-outage-20261106/measured-900 \
  --outage-seconds 900
```

Evidence directories must be new. A retained build is reused only after checking
all input, copied-source and artifact hashes. `--build-only` builds without
running the outage. Short mode is a regression qualification, never the required
15-minute proof. The read-only `ops/bootstrap/prove.py` dependency supplies only
its stable SHA256/source-manifest utilities and reviewed compiler pins; no TLS
owner fixture or in-flight TLS branch is needed or edited.

## Observable gates

1. Native delivery with zero witness signatures fails. After the actual three
   processes publish signatures, identical native delivery succeeds. Returning
   just one valid signature, corrupting the service checkpoint signature, or
   returning a valid checkpoint with two pinned IDs and one corrupt witness
   signature must fail at native delivery and leave the prior cache unchanged.
2. Readiness uses an HTTP response, process startup handshakes, and observed
   cryptographically verified publications. At each accepted submission, the
   durable witness checkpoint must already equal the signed checkpoint.
3. Exactly witness C receives SIGTERM. Its PID is waited/reaped and checked
   absent before starting the measured interval. A and B must stay alive and C's
   retained state must remain byte-for-byte unchanged. Checkpoints grow every
   30 seconds; quorum publication has a 22-second deadline. Successful native
   lookups target a five-second cadence, with a required maximum observed gap
   of 45 seconds, including quorum waits. The 900-second run crosses the native
   five-minute checkpoint freshness window several times.
4. C restarts only after both real monotonic and UTC elapsed time meet the
   requested duration, on the same state path and key, with no `new-identity`
   reset/transfer input. It must request the exact retained-to-current consistency
   range, persist the current checkpoint and produce a verified fresh signature.
   No history/timing rejection evidence may appear. A final native lookup must
   publish the current checkpoint again.

The partial-line ABI transport regression is run with
`python3 -B mesh-private-messenger/tests/bootstrap-witness-outage-native/test_acceptance.py`.
It proves a partial native output line cannot bypass the response deadline.

All service network origins are fixed to loopback. Child environments contain
only PATH and fixture-specific resources/public synthetic keys. Network requests
have response limits/timeouts; ABI calls, readiness, publication, shutdown and
the overall process run have bounded deadlines. Scheduling waits are not proof:
the receipt records actual monotonic nanoseconds and UTC wall timestamps.
SIGINT, SIGTERM, and failures tear down the owned processes.

## Retention and cleanup

`receipt.json` distinguishes `PASS_SHORT_ONLY`, `PASS_LOCAL_900S`, and `FAIL`.
`build.json` retains exact source revisions, every source-copy hash, compiler and
runtime pins, commands and artifact hashes. `events.jsonl` retains clock samples,
PIDs, checkpoint bytes, actual witness submissions, durable checkpoints,
consistency requests/proofs, negative results and native cache observations.
`local/` retains the synthetic directory database, signed checkpoint history,
native databases/resources and witness state/logs. These contain public canaries
and fixture keys only; they are not user account exports.

Coordinate parent reuse before deleting the owned build directory (copied
toolchain and compiled artifacts). Keep build manifests/logs, receipts, event
logs and necessary public state for review. Deleting artifacts after hashing
does not prove binary reproducibility; rebuilding and rerunning remain separate
work. No image packaging, Linux service qualification, release, deployment,
network independence or production acceptance follows from this local result.
