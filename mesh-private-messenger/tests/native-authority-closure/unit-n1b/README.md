# N1b: original native lifetime retirement before Main cleanup

Bounded source and macOS native proof from app parent `0d6826b`. The application
remains unbound. No capability, protected-mode, compiler, runtime, serializer,
framework, native policy, account/session, or publication implementation changes.
The retained generated library advertises mask **1**. This unit does not activate
the product and does not qualify UIKit/Expo owner or sentinel destruction.

`MeshMessengerNativeRetirementDomain` opens an explicit native-selected image.
Every frozen function is resolved from that handle and checked to belong to that
same image, including its canonical path. No `RTLD_DEFAULT` lookup, replaceable
function table, user callback, permission callback, or latest-owner lookup exists.
The internal native pointers are for the trusted embedding, never request bytes.

Each root, sentinel registration, and committed owner lease has its own immutable
node. Captures and leases retain the original root and sentinel nodes as well as
the lease's owner node; the native driver binds all three in the same domain.
The retirement method calls only that node's frozen `mesh_authority_retire_v2`
function. Resolution, allocation, reference release, `dlclose`, and Main dispatch
are outside that method. The original `onMain` overload remains unchanged; the
new overload retires first, then performs that same exact cleanup dispatch.
UIKit owner and sentinel deinitializers call the new overload with their original
stored lease/node, before scheduling cleanup.

Installation and ownership:

- The optional domain is fixed when `RootBindings` is constructed. Production
  `MeshMessengerDataProtection.rootBindings` supplies no domain. There is no
  mutable install-later/rebind slot or fallback to a previously valid owner.
- `registerRoot` already requires Main. It allocates the new immutable root node
  before retiring or replacing any old state. `registerSentinel` allocates a
  distinct immutable node for each new sentinel ID, even on the same root. The
  native sentinel receives that exact node on Main before it is added to the root. The unchanged
  rootID/sentinelID predicates still guard later Main cleanup.
- `prepareCapture` retains the actual owner/root/context/module and surface tuple.
  `commitCapture` keeps all original guards and allocates its node before
  publishing the lease. The original Module caller serializes this commit and
  owner lease assignment under `RootModuleLifecycle.withRegistered` on Main.
  A last owner release cannot race a strong reference held by `Capture`; the
  native test exercises release of the caller's owner while capture remains held,
  commit of the same original lease, then last capture release off Main.
- In the bound path, replacing a sentinel retires its original node and current
  lease before clearing that lease. A pending capture retains the old root and
  sentinel nodes; commit refuses if either registration changed, even if the
  auth epoch did not. New capture uses the new sentinel's node. Same-ID repeated
  registration is idempotent. The unbound path keeps its prior gate/current behavior.
- Retirement precedes replacement/clear at the existing Main lifetime sites.
  A lease replacement retires the old node before storing the new lease. Sentinel
  teardown retains its own sentinel node independently of the current registry.
  Delayed cleanup still checks the original IDs. It does not obtain a successor's
  node by looking up a current owner.
- Node wrapper → domain wrapper → image is a strong ownership chain. Node release
  invokes the original generation release before releasing the domain reference;
  domain release invokes the original domain release before `dlclose`. The test
  driver also retains its fixture (and thus its wrappers/image) until every C
  authority and invocation has finished and been released. Any future scoped-call
  integration must retain this same chain for its authorities/invocations; a raw
  pointer alone is not ownership. This unit adds no product scoped-call API.

Partial initialization and failure ordering:

- Failed `dlopen` adopts nothing. Missing or foreign-image symbols close the
  newly opened handle before throwing; no domain/node exists yet.
- A failed domain/generation ABI result releases any non-null output from that
  same image before throwing. The local image/domain reference remains alive
  through that release. Successful generation creation transfers the sole C
  reference to its immutable wrapper; the frozen ABI has no generation retain.
- Root/lease allocation happens before retirement and before registry mutation.
  A rejected capture keeps the original predicates and state. If the final epoch
  check rejects a newly allocated lease, its unpublished node is retired/released
  normally; no existing owner is selected or replaced.
- Swift/ABI out-of-memory termination is not converted into recoverable success.
  No allocator or runtime was patched to fabricate that path. Loader failure and
  node/domain lifetime paths have executable controls; allocation ordering is
  also reviewed in the actual source.

Reproduce from the repository root (choose new output directories):

```sh
python3 -B mesh-private-messenger/tests/native-authority-closure/unit-n1b/prove.py --phase baseline --output /tmp/n1b-red
python3 -B mesh-private-messenger/tests/native-authority-closure/unit-n1b/prove.py --phase green --output /tmp/n1b-green
```

Only small Swift drivers are compiled. The baseline reads the original
DataProtection file from `0d6826b`; the original Main dispatcher and RootBindings
run unchanged. Its native Foundation lifetime ports have no bound retirement
node, matching the missing bridge. Both owner and sentinel cases fail the same
observable requirement: teardown returns while Main is held, runtime bind still
returns 0, and releasing actual loopback HTTP lets actual generated SQLite commit
the `later` row. The positive current-owner case succeeds.

Green uses the production domain/node/registration/dispatcher implementation.
The native ports' destructors execute on a worker while Main remains undrained.
Bind returns 10 before teardown returns; after HTTP resumes, the old invocation
returns 10 and database bytes remain unchanged. After a fresh root and lease are
registered, draining delayed cleanup preserves all fresh ancestry nodes; their actual
generated call commits its row. Main-thread owner/sentinel controls additionally
require synchronous original gate cleanup. The capture control proves that a
strong original capture delays owner destruction, rather than letting a cached
owner identity stand in for lifetime ownership.

Independent R1 review found a same-root replacement defect in the first N1b
implementation: root and sentinel had shared a node. The retained
`same-root-red` driver reproduces status 10 on the successor after old sentinel
teardown while Main is held. The corrected case keeps that old sentinel alive,
installs a replacement on the same root, and destroys the old sentinel off Main.
Successor bind remains 0 and real SQLite receives a row both before and after
stale cleanup. A second case replaces the sentinel between prepare and commit
without rotating the epoch; the old capture refuses and the fresh capture
reaches both real sinks. This fixes the aliasing rather than delaying retirement
until Main can check identity.

The image lifetime executable is not linked against the runtime. It checks
missing/wrong-image rejection, releases the caller's domain reference while
retaining only its node, calls repeated retirement and the actual frozen bind,
and observes domain deallocation only after node release. These are lifetime
checks, not native permission checks.

Regression scope is the unchanged 31 AppLock groups, 23 default RootBinding
groups plus all seven command-line modes (17 groups), and 3 Retirement groups:
**71 + 3**. This is the affected Foundation policy/identity/lifetime boundary;
no Bounty, view-once, JS, framework, or runtime source was changed. Individual
mode invocations are recorded rather than counting unexecuted tests in the file.
Parent also granted the exact existing unit0 build-list integration: insert the
new helper immediately before DataProtection, preserving DataProtection as the
last entry (used for its negative control) and the first two entries (AppLock).
That runner is replayed once with its Main-dispatch red control, 71 + 3 Swift
groups, and existing actual ProcessOwner controls. This is a test dependency
addition, not a product policy or build-family change.

The runner verifies all 44 retained family members, the 19 committed accepted
runtime sources, generated-library SHA-256
`1d5af0920725bc0449977060a270393192193b09ce896f96049ce3226299bf5d`, and frozen
header `5bbaf429dbd3749924b041847aba40ce40ee33c5a13a5c97f454601d79f87843`.
It neither rebuilds nor copies the Mesh family. Installed app8256 tools stay
untouched. Receipts record exact source, driver and log hashes.

Platform limits: this Mac has Xcode and the iOS simulator SDK. The new support
file typechecks for arm64 iOS simulator 16.4 with the local SDK. The retained
generated image has `LC_BUILD_VERSION platform MACOS`; the granted checkout has
no generated mobile iOS project/Pods or accepted iOS runtime image. No full
UIKit/Expo build, actual UIKit destructor run, simulator app, or device run is
claimed. The native Foundation `Owner`/`Sentinel` test ports exercise production
registration and dispatch, not UIKit/Expo classes. Actual UIKit/Expo integration
is **UNQUALIFIED** until that separate platform integration exists. Framework
writer coverage, weak tuple lifetime coverage, complete effects, native policy,
scheduler progress, SDK/JSI/WK publication, and application activation remain open.
