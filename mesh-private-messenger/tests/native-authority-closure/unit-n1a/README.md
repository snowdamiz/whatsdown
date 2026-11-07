# N1a: observed ProcessOwner loss

This unit connects the actual macOS `MDProcessOwner` to the accepted synchronous
Mesh effect-authority runtime. It covers observed path loss and explicit close.
It does not complete WITNESS_NETWORK_PLAN or activate a protected application.

The owner holds a retained state object containing its original directory FD,
lock FD, mutex, and optional immutable retirement link from acquisition. Native
construction of a protected owner requires a fresh link. The link takes the
generation's owning C reference, clears the caller's pointer on transfer, and
can be claimed by one registration only. Bind callers retain the wrapper while
borrowing its generation; there is no generation retain or rebind API.

The link resolves only the three exact frozen runtime symbols at construction.
Those targets never change. Retirement calls only the captured
`mesh_authority_retire_v2` target. Resolution, reference release, filesystem work,
and cleanup scheduling are outside retirement. The native embedding must load
one coherent runtime family and keep that image loaded until all native handles
are released. Missing symbols refuse link construction. Existing unbound V1
owners still compile without Mesh, close synchronously, and make no runtime
retirement or settlement calls. The implementation fragment is included once by
`ProcessOwner.m`; Cargo tracks both new support files for incremental rebuilds.

Every original stat, metadata, identity, anchor, flock and duplicate predicate
remains. False observations retire and latch the original bound registration
before returning, without disposing its descriptors. Restoring a name cannot
revive that registration. A successful sample still has the original residual
external-rename interval; neither FDs nor flock pin the namespace.

Explicit close retires and sets logical close before attempting the descriptor
mutex. The last conjunct of both currentness checks reads loss/close again.
One cleanup scheduling bit selects the inline or asynchronous disposal path.
The retained state owns the original descriptors throughout; cleanup never
retains a dying facade or transfers raw FDs from it. After retirement, a real
zero local-settlement observation allows disposal. Fields become `-1` before
either close syscall. Nonzero settlement or a busy mutex rearms cleanup on a
native serial queue without holding locks between attempts. HTTP and root-call
completion do not control this lifetime. Zero is an observation about previously
accepted r1 local operations, never native effect permission. This unit adds no
native SDK accounting; all other resource/account fences stay in place.

## Reproduce

From the repository root, choose a fresh output directory:

```sh
python3 mesh-private-messenger/tests/native-authority-closure/unit-n1a/prove.py \
  --phase baseline --output /tmp/n1a-baseline-unique
python3 mesh-private-messenger/tests/native-authority-closure/unit-n1a/prove.py \
  --phase green --output /tmp/n1a-green-unique
```

The runner compiles only small native drivers. It never rebuilds or copies a
Mesh compiler/runtime family. It verifies all 19 pinned committed source files,
all 44 retained artifacts and the frozen authority header before execution.
Concurrent edits in the live Mesh checkout are recorded as unused drift; the
only runtime used is the hash-pinned retained generated library. Tests use one
runtime per subprocess, unique synthetic directories, an in-memory anchor, real
owned loopback HTTP, real SQLite, and native Host callbacks. No Keychain claim.

The ten baseline RED cases compile `ProcessOwner` unchanged from
`e036a6240be799e172dfea53faf80581c91ed996`. Both rename variants and both actual
observation paths return false before HTTP release, yet the next SQLite write
or HTTP send proceeds. Restore revives old currentness. Explicit close releases
flock inside an admitted SQLite commit hook. The unchanged-owner control and the
original `process_owner_closure.m` 2/2 controls pass.

Green has 25 cases: the 11 original runtime scenarios; separate instrumented
commit/HTTP disposal observations; and 12 ownership/lifetime cases. These include
held actual secure-store writes, close before admission, owner deallocation,
removal of the caller's link while cleanup is its sole owner, stat/close overlap
and post-dup overlap, zero-inflight close, caller-owned duplicates, repeat close,
forced FD-number reuse, failed acquisition, one-use binding, and a successor
which remains current and performs a real generated effect after old cleanup.
Original Host retain/release and owning-generation release counts are checked.
The two existing ProcessOwner controls also pass without linking Mesh.

The syscall observer performs the real calls and preserves their results. It
parks after the actual stat inside `currentLocked`; close completion is observed
after the actual close syscall using semaphores. No runtime counter is mocked.
Two scratch-source negative controls remove only the final loss/close conjunct
and must fail at these same overlap barriers. Deadlines fail the test; none are
treated as settlement. An admitted commit may complete one durable row while the
outer scoped call returns refusal; this is the expected finite-effect contract.

## Evidence and limits

`receipts/qualification.json` indexes the retained baseline and green receipts,
source/tool/header/library/driver hashes, DB before/after hashes and exit codes.
The complete local build products and failed harness attempts remain under the
ignored `artifacts/` directory. The baseline-r4 driver sources are retained there
unchanged. The initial harness failures (worker dispatch, Objective-C selector
instrumentation, Darwin close alias, autorelease ownership, nil receiver return)
are not counted as semantic RED. The unbound-link failure in green-r9 is a real
compatibility RED; construction-time fixed symbol resolution fixes it in green.

PASS is limited to source correctness and this local native/runtime composition.
NOT RUN: product macOS/Keychain/UI integration; N1b off-Main owner closure;
N2 framework writers and mobile lifecycle; R2 scheduler/fresh-owner progress;
N3 SDK/JSI/WK final consumption/publication; S1 vendor SDK sinks; P1 account and
application composition, generated application artifact qualification, hosted CI,
release or activation. No CALL_LOCK, Core mutex, native resource/account barrier,
protocol or capability bit changed. Only the test embedding requests mask 1.
