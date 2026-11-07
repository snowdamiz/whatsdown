# Native admission API obligations

The selected design uses a native-owned synchronous sequencing domain at each
ready runtime effect. Scheduling is separate. This unit does not freeze the API
or install a partial epoch gate in production.

The language owner's provisional direction preserves standalone V1, adds separate
V2 domain and authority handles, retains the exact nine-callback V1 Host table
inside a V2 registration, and requires explicit protected capability activation.
The synchronous generated export establishes the original context for process,
actor, HTTP, and normal-stack descendants. `CALL_LOCK` remains in unit 1.

## Supported hook integration

Owned mutations can retire a generation inside the original short state lock.
The corresponding domain update must precede replacement visibility or loss
acknowledgment. Deferred revoke observers are cleanup and notification hooks.
They are too late to establish retirement ordering.

The required lock order is lifecycle state to domain during retirement, or an
already-owned resource to domain at a ready sink. The domain cannot acquire
lifecycle, Core, SQL, policy, Main, JNI, or provider locks. It cannot call an
application closure. Runtime-private fixed slots consume one immutable effect
under that domain. A returned Boolean cannot authorize later arbitrary work.

The adapter needs monotonic, idempotent retirement, retained tombstones, exact
registration identity, and bounded refusal on contention, overflow, mismatch, or
missing context. Wake callbacks, destruction, UI covering, and resource disposal
run after the domain releases. Resource deadlines require actual monotonic time
at their relevant admission boundary. A delayed timer does not prove expiry.

The provisional maximum of 64 native lifetimes is an unresolved pre-freeze
capacity issue. A workload can retain old handles across pending HTTP, actors,
resource disposal, and owner replacement. Capacity exhaustion must refuse without
evicting live references or reusing an identity that an old handle still names.
The owner must define the bound, ancestry accounting, reclamation, and overflow
behavior before platform integration. This unit neither assumes 64 is sufficient
nor changes that API.

## Native truth that still blocks integration

1. iOS's factory, ReactHost instance and presenter, surface registry, component
   registry, tags, hierarchy, and Expo module membership have framework-owned
   mutations. The current live observer remains required. Public APIs inspected
   here do not retire a native domain before all these changes. An after-reload
   callback or same-window generation cannot replace that truth.
2. iOS notification delegate ownership remains a live native requirement.
   `nativeEnvironmentLost()` latches observed loss synchronously, but this unit
   proves no before-set interception for `UNUserNotificationCenter.delegate`.
3. Main deinit retirement now completes in the caller's turn. Off-Main deinit
   still returns before queued cleanup. A future authority cannot treat queued
   cleanup as an immediate retirement receipt.
4. Android's before-destroy listener is useful, but registry replacement,
   AppContext rebinding, activity identity and flags, and weak-reference loss do
   not all share that hook. Subscription plus a later identity check is not an
   atomic subscribe-and-snapshot operation. The actual application template uses
   a lazy canonical host. A mutable test-host getter is not evidence that product
   code needs a host-swap registry.
5. macOS policy includes live named-path identity and metadata. `flock` is
   advisory and bound to the original inode. Retained descriptors permit access
   to the original object after namespace replacement. Vnode notifications occur
   after changes and can aggregate events. None supplies equivalent synchronous
   ordering with the external actor. `currentLocked()` itself uses independent
   syscalls, not an atomic filesystem snapshot.

For macOS, preserving named-path policy needs proven OS mediation tied to the
effect, or an explicit boundary redesign. A descriptor-capability policy would
be a policy change requiring review. It cannot silently replace the existing
path predicates. The real owner probe supplies counterevidence against that
substitution. No process-owner source changes were made.

## Authority kinds

Ordinary private authority binds the original native receiver and every applicable
native generation. Disabled headless authority is a separate native constructor,
not a missing-scope fallback. Native lifecycle replacement never retargets an old
scope to the newest owner.

An account transition binds one exact existing export and one native transition
ID. It survives only its own tagged epoch rotations. Unrelated module, page,
environment, account, or policy loss still retires it. `account_delete` legitimately
posts a network request before local erasure. Its transition authority cannot ban
all sends or disappear when one local execution quantum ends. A late completion
must match the original transition ID before finalization.

Finite cleanup owns an exact old resource and action. It grants no private read,
general database write, new send, or publication. Existing iOS and desktop cleanup
scopes differ from Android's public protected-file wrapper, which still requires
`moduleScoped` before its cleanup branch. This unit preserves those differences.
Admitted finite local writes need an account/resource settlement fence before
successor activation. Pending HTTP must not hold that fence. Stuck local writes
remain fenced until actual settlement, rather than a timeout assumption.

## Subsequent proof boundaries

Runtime tests must exercise real generated exports, HTTP dispatch, SQLite
mutations and commit, durable nonce reservation, and secure-store writes.
Native tests then need the actual Expo, Tauri, and SDK effect or final-byte handoff.
Returning `Data`, `Vec`, or a framework response object is not that handoff.
Private errors need the same publication authority as successful bytes.

The source-correct preflight and completion checks remain in place. All 176
messenger ABI names, payloads, limits, and audiences remain unchanged. This unit
does not modify language, BountyBridge, operation 8, shared Module dispatch,
`main.rs`, `mesh.rs`, Core exports or protocol, or the parent's plan inventories.
