# Native predicate matrix

This inventory covers native authority reached by private call, owner, and resource
adapters. Protocol, request-format, transport, and Mesh CAS conditions remain
independent. Source base is `f2e872a51457ec5963132ec9cbf4303c31e453ea`, with the
bounded iOS dispatcher correction described in [README.md](README.md).

"Hook" means the app owns a synchronous state transition suitable for later
domain retirement. It does not mean the V2 domain is integrated. "Gap" means
the actual predicate lacks a proved equivalent before-change hook. "Sample"
means existing live revalidation still provides refusal. None authorizes
protected activation by itself.

Proof labels describe this run:

- **R**: production Swift RootBindings, scope, module-lifecycle, startup, and
  account-transition host tests. Identity and platform ports are controlled.
- **L**: production Swift AppLock, 31 host groups. Native policy and UI ports
  are controlled. Barrier tests cover revocation during policy work and bounded
  publication ordering.
- **D**: new production dispatcher with RootBindings and AppLock. Main stays
  undrained until the explicit barrier. Red fails two groups, green passes three.
- **O**: production Objective-C ProcessOwner and actual macOS filesystem calls.
  In-memory anchor only. Both external replacement controls pass.
- **A**: Android source audit plus six passing config-plugin tests. Android
  controller and runtime tests are **NOT RUN** in this unit.
- **S**: source evidence only. No actual boundary run in this unit.

## iOS

Paths below are under `apps/mobile/modules/mesh-messenger/ios/`:

- **I**: `MeshMessengerDataProtection.swift`
- **Lk**: `MeshMessengerAppLock.swift`
- **Mt**: `MeshMessengerCurrentMount.mm`
- **M**: `MeshMessengerModule.swift`
- **N**: `MeshMessengerLockedNotifications.swift`
- **F**: `MeshMessengerProtectedFiles.swift`

| ID | Authoritative truth and check | Synchronous mutation or retirement hook | Ordering, loss semantics, and proof |
|---|---|---|---|
| I1 | Lease ID equals current lease, root UUID and exact root object match. `I:187-203` | `registerRoot`, `detachRoot`, `retireOwner`. `I:94-121,230-239` | Hook on Main. Replacement clears current and rotates gate before returning. Late old IDs cannot revoke a successor. **R, D**. |
| I2 | Exact weak owner, context, module, window, and scene remain alive. `I:26-37,192-196` | Owner window detach and explicit module/root retirement. `I:795-801,M:183-201` | Sample for weak loss. Main deinit now retires synchronously through `I:3-10,768-771,800`. Off-Main remains queued. **D** proves dispatcher/controller behavior, not UIKit deallocation timing. |
| I3 | Module UUID is registered, not retired, and points to the exact module/context. `I:78-92,189-195` | Main register and retire. Module's `OnDestroy` first calls lifecycle `dispose`. `M:24-46,183-201` | Hook for owned dispose. Lifecycle mutex excludes registration/commit; disposal does not wait for Core. Root cleanup can be queued. Actual registry membership remains separate. **R**. |
| I4 | Exact Expo AppContext and live `moduleRegistry.get(...) === self`. `M:28-40,205-208` | Expo registry insertion, replacement, and removal | Gap. `didCreate` runs after insertion. Old retained module need not deallocate at replacement. OnDestroy and cached registered state cannot substitute for the live registry getter. **S**. |
| I5 | View context equals module context; owner is the actual root descendant in the same window. `I:134-145,680-691,740-745` | Owner `didMoveToWindow`, root sentinel `didMoveToWindow`, native root binding | Hook for observed detach/root replacement. Gap for every hierarchy mutation before it becomes visible. Main capture and live validation remain required. **R** tests identity ports, **S** for UIKit timing. |
| I6 | AppDelegate's current factory equals captured factory; current root factory ReactHost equals captured host. `I:511-513,683-684,Mt:66-73,83-86` | Actual root customization and bind. `I:696-717` | Gap for same-root factory/host mutation. Weak references pin no authority. Current-factory resolver and live native chain remain required. **R** port tests, **S** actual framework. |
| I7 | Captured host's current surface presenter equals captured presenter. `Mt:68,85` | ReactHost replaces its RCTInstance/presenter during reload | Gap. Host identity alone is insufficient. Pinned `RCTHost.mm:628-647` invalidates old instance, constructs new instance, then resets attached surfaces. No app before-mutation domain hook is present. **R** port refusal only. |
| I8 | Root surface identity and rootTag match; presenter's rootTag registry resolves that exact surface. `Mt:69,75-76,85-87` | React surface reset, register/unregister, and stop | Gap. Pinned presenter registers and unregisters the surface directly. Main snapshot is live truth, not an immutable lifetime capability. **R** port refusal only. |
| I9 | Owner tag is positive, fits React Tag, and is unchanged; presenter's canonical component registry resolves that tag to the exact owner. `Mt:69,75-80,87` | Fabric component enqueue/dequeue and recycling | Gap. Pinned `RCTComponentViewRegistry.mm:50-69` inserts/erases entries and resets tags on Main. Window equality and a watcher miss same-window replacement. **R** port refusal only. |
| I10 | Lease epoch and account generation equal gate; supplied expected epoch equals original captured epoch. `I:71-76,261-268` | `rotateEpochLocked`, lock, accountChanging, authentication, environment loss. `Lk:121-128,236-299,395,425-443` | Hook inside recursive state mutex. Revoke listeners run later, outside that mutex. Domain retirement must join the original transition. **L, R**. |
| I11 | Boot ready, readable policy, no boot/error phase; disabled-unrestricted or enabled-unlocked with active owner. `Lk:301-309` | Bootstrap/failure; foreground; policy settlement; authentication completion/failure | Hook for in-memory authority. Durable policy work stays outside state lock and uses readback. Current `requireEpoch` also calls live environment validation, so it is not a pure sink callback. **L**. |
| I12 | Exact window/scene object and persistent scene ID, with actual foreground-active scene for owner validation. `I:195-202,224-227,689-691` | Root sentinel observation and native scene/application notifications. `I:719-732,Lk:507-542` | Hook for observed events. Foreground rotation is synchronous before the handler returns. Prompt inactivity differs from root detach. Actual OS notification timing is **NOT RUN**. **L, R** for controller behavior. |
| I13 | Actual UNUserNotificationCenter delegate equals installed wrapper; startup services/protection exist. `I:470-495,563-592,N:44-46,209-224` | Owned startup install; `nativeEnvironmentLost()` latches observed loss synchronously | Gap for arbitrary delegate setter replacement. Restoring the delegate cannot clear latched failure. The deferred revoke/UI callback is not retirement. **L, R** prove observed loss and failed startup. Setter timing **S**. |
| I14 | Scope and call are not closed; disabled admission has a live module and unrestricted policy. `I:254-268,313-341` | `close()` under scope/call locks; native module lifecycle dispose | Hook for the local close bit only. Locks release before native validation and work. Pre/post checks do not serialize a later effect. Owner and disabled constructors remain distinct. **R**. |
| I15 | Account mutation pending state, exact active transition ID, exact export ticket, once-only consumption. `I:373-422` | `perform` sets active/pending, rotates account, then finalizes matching ID after body | Hook for existing synchronous call lifetime. Revoke observers run outside Core. Future scheduling needs a retained logical transition surviving only its own rotations. Four allowed exports include account deletion and its network. **R**, four transition groups. |
| I16 | Exact native resource epoch, profile account/device/generation, live handle, expiry, and exclusive per-resource operation. `F:153,365,412-486` | Resource insertion/discard/revoke and per-resource lock | Hook for owned resource state. Profile callback, selection context, and native documents/provider truth remain live checks. Expiry uses monotonic time, not queued notification. Resource-specific tests **NOT RUN** here. **S**. |
| I17 | Exact native selection context, request identity, account generation, deadline, once-only completion, captured cleanup target. `I:521-537,F:562-587,642-762,835-850` | Picker registration/cancellation and completion; captured cleanup | Separate finite cleanup authority. No stale handle adopts a successor's resource. Picker metadata may survive an epoch when same-account rules permit it, but new use needs private admission. **S**. |
| I18 | Notice authority matches epoch/account/record/owner, valid unused ID, and bounded registration. `Lk:175-234` | Native issue/consume/forget and epoch rotation | Hook under state mutex. Bounded native presentation callback shares that mutex; native add/final reply still needs its actual sink. `N:113-138` uses live ownership and epoch checks. **L** covers controller behavior, **S** full OS delivery. |

I1-I18 enumerate the conjunctions reached by `validate`, `validateIdentity`,
`NativeOwnerScope.check`, disabled `NativeCall.check`, startup environment
validation, and native resources. Public auth metadata intentionally uses native
identity after its own auth epoch rotation. It is not a private-data grant.

## Android

Paths below are under `apps/mobile/modules/mesh-messenger/android/src/main/java/expo/modules/meshmessenger/`:

- **M**: `MeshMessengerModule.kt`
- **Lk**: `MeshMessengerAppLock.kt`
- **P**: `MeshMessengerAppLockPolicy.kt`
- **F**: `MeshMessengerProtectedFiles.kt`
- **W**: `MeshMessengerWalletStore.kt`
- **N**: `MeshMessengerLockedNotifications.kt`

All Android runtime rows have proof status **A**. Source correctness and existing
test targets are evidence of implementation shape, not executed lifecycle proof.

| ID | Authoritative truth and check | Synchronous mutation or retirement hook | Ordering and remaining gap |
|---|---|---|---|
| A1 | `registrationReady`, not destroyed, and process currentModule equals this. `M:340-345` | OnCreate, replacement, setup failure, OnDestroy. `M:53-120,282-304` | Hook under moduleLifecycle. Ordinary moduleScoped does not hold that monitor through work. |
| A2 | Registered Expo context equals appContext and RuntimeOwner.nativeContext. `M:324,343-344` | Owned registration and teardown; Expo registry can rebind module AppContext | Gap for Expo before-rebind. |
| A3 | Registry's MeshMessenger entry is this module. `M:325` | Expo ModuleRegistry.register and cleanUp | Gap. Mutation precedes this module's OnCreate. |
| A4 | Expo context's React context equals captured React context. `M:326` | Construction and ReactHost teardown | Weak context loss has no synchronous callback. Before-destroy is useful but does not cover every loss source. |
| A5 | ReactContext's application equals captured application. `M:327` | Captured during native owner construction. `M:314-320` | Construction provenance. No normal application replacement source was found. |
| A6 | Application's canonical reactHost equals captured host. `M:328` | Application getter | Inspected product template uses lazy val. No arbitrary before-getter-change hook. Mutable test getter is not product evidence. |
| A7 | Host currentReactContext equals captured context. `M:328` | ReactHost before-destroy listener before context reset | Hook runs inline on UI executor before reset/destruction, after teardown initiation and surface shutdown. Subscription lacks atomic snapshot semantics. |
| A8 | RuntimeOwner exists and is not retired. `M:323-345` | Exact-owner before-destroy and removeRuntimeOwner. `M:82-95,331-337` | Hook. Sticky retirement and exact module/context/owner checks protect successors from old callbacks. |
| A9 | Module activity equals app-lock activity. `M:349-353` | React/Expo currentActivity updates and application lifecycle callbacks | Gap. Framework updates currentActivity before dispatching lifecycle listeners. Snapshot equality cannot record an unobserved replacement. |
| A10 | Native owner exists, is resumed, and is neither destroyed nor finishing. `Lk:272` | Resume, pause, destroy. `Lk:91-139` | Own state uses stateLock. Resume overwrites owner without independently rotating epoch. Activity flags are framework truth. |
| A11 | Effective owned foreground, including native cover and wallet prompt. `Lk:95,102,291,W:263-266` | Focus callbacks, cover and prompt focus. `Lk:100-106,308-311,381-393` | Boolean changes synchronously. Ordinary focus invalidation is posted and can be skipped after regain. Full old-scope loss semantics remain open. |
| A12 | Exact epoch, completed boot, no revocation underway, readable non-error state. `Lk:288-295` | Boot commit/error and revoke begin/end. `Lk:147-172,253-257,330-350` | Hook under stateLock. New admission waits for revoke hooks via revoking counter. |
| A13 | Restricted/policy state permits private admission. `Lk:271,291` | Manual lock, auth admission/result/failure, bootstrap. `Lk:353,410-420,458-496` | Hook. Disabled policy intentionally allows fresh headless work. |
| A14 | Exact durable installation, sequence, and policy record. `P:24,33-68` | Validated transition, atomic save, readback. `P:71-110,Lk:443,457-467,506-507` | Policy I/O outside stateLock under auth operation lock. No before-hook for arbitrary external file/Keystore mutation. |
| A15 | Exact challenge, native approval, owner/account, deadline, foreground. `Lk:510-517` | Native prompt/result, cancellation, revoke. `Lk:519-587` | Hook for owned challenge state. Pause can preserve challenge while rotating epoch. Completion rechecks actual authority. |
| A16 | Account generation and restrictive-event identity. `Lk:70,356-362` | accountChanging before four account exports. `M:398` | Hook. Current call remains serialized with Core. Scheduler-safe logical transition ownership is not implemented here. |
| A17 | Activated epoch and exact native cover identity. `Lk:364-394` | Activate, epoch rotation, cover replace/dismiss | Hook on Main and stateLock. Queued dismiss rechecks exact cover and epoch. |
| A18 | Notice disabled/unrestricted state, epoch/account/record/owner, unused ID. `Lk:180-256` | Native issue/consume/forget and epoch rotation | Hook under stateLock. Private notification post shares this lock. Consumption additionally requires focused resumed live owner. |
| A19 | Exact protected-file profile binding and identity. `F:112-125,153-158` | Atomic binding replacement and exact CAS release | Hook for binding pointer. Live profile loading and module identity remain separate checks. |
| A20 | Resource epoch, open state, account generation, expiry, exclusive operation. `F:76-103,160-181` | remember, discard, revoke, resource busy lock | Owned retirement marks/removes before queued provider disposal. Actual provider I/O does not share the authority lock. |
| A21 | Choice/request identity and context, expiry, picker owner/code, once-only callback. `F:225-254,284-330,419-468` | Native request and picker registration/cancel/result CAS | Exact metadata can survive pause in the same account. Fresh resource use still needs new private admission. |
| A22 | Cleanup targets supplied epoch/handle only. `F:256-267` | discard/revoke and queued disposal | Dispatch cleanup is non-authorizing. Public protectedFile still runs moduleScoped before all branches. `M:150-152`. No stale-public-cleanup exemption is invented here. |
| A23 | Captured call epoch plus module pre/post checks. `M:356-367,Lk:297-316` | Thread-local install/restore, call entry/exit | Checks are not continuing effect grants. Postchecks can erase bytes, not undo external effects. |
| A24 | Exact observer, push state, protected binding/listener, JNI registration resources. `M:93-108,168-223,282-311,645-676,Lk:266,280-282` | Copy-on-write observer changes, push serial queue/pushLock, JNI callback mutex | Separate registration lifetimes. No generic effect/retirement ordering is established by their locks. |

Clipboard already holds stateLock over `setPrimaryClip` at `Lk:321-327`.
Private-notice issuance holds it over native post at `Lk:194-206,N:98-104`.
Those app-lock critical sections still do not cover every module or framework
predicate. `publication()` releases the stateLock before returning. External
wallet launch and provider writes cannot retain permission from that return.

Pinned local framework evidence came from the parent's same-HEAD node_modules.
The lockfile matches and versions are React Native 0.88.0, Expo 58.0.16, and
Expo Modules Core 58.0.23. The decisive files are:

- `ReactHostImpl.kt:1356-1371,1519-1537` for inline before-destroy and context reset.
- `ReactHostImpl.kt:834-839` for listener insertion without atomic subscribe/snapshot.
- `ReactHostImpl.kt:249-253` and `ReactContext.java:281-287,309-315` for activity updates before listeners.
- Expo `ModuleRegistry.kt:24-40,86-92,127-129` for context/registry changes and later create events.
- Expo `AppContext.kt:274-287` for destroy notification before registry cleanup.
- Expo `ReactActivityDelegateWrapper.kt:176-241,463-470` for coroutine/mutex forwarding with loadAppReady waits.

Source-derived follow-ups remain unproven: preview recreation after cleanup at
`F:134,179,384-386`, focus loss/regain before posted invalidation, owner B resumed
before owner A pauses, and a retained module's notification racing registry
replacement before OnCreate. No correction was made without a runtime red.

## Desktop on macOS

Paths below are under `apps/desktop/src-tauri/src/desktop_lock/`:

- **C**: `controller.rs`
- **Rcv**: `receiver_scope.rs`
- **Np**: `native_policy.rs`
- **Pb**: `native/PolicyBridge.m`
- **Owr**: `native/ProcessOwner.m`

| ID | Authoritative truth and check | Synchronous mutation or retirement hook | Ordering, loss semantics, and proof |
|---|---|---|---|
| D1 | Actual native receiver equals current page owner, original token matches. `Rcv:133-138` | Native page installation/replacement | Hook under page mutex. Header/token narrows native receiving owner; it cannot select another owner. **S**. |
| D2 | Captured Page.open remains true. `Rcv:155-162` | install, close, abandon, release, observed owner loss. `Rcv:81-111,128-131,178-180` | Old page closes before fallible replacement preparation. Atomic bit does not span a later effect. **S**. |
| D3 | Controller epoch space is not exhausted. `C:305-315,378-382` | rotate | Hook under state mutex. Overflow clears readiness and restricts. **S**. |
| D4 | Exact controller owner equals captured lease owner. `C:383-385` | replace_owner or matching Destroyed. `C:475-497` | Hook under state. Old owner events do not retire a successor. **S**. |
| D5 | Exact boot and epoch generation match. `C:386-388` | rotate through lifecycle, lock, auth, policy and account events | Hook. State changes precede later publish/resource retirement callbacks. **S**. |
| D6 | Exact account generation matches full lease. `C:80-85,397-413` | account_changed. `C:500-509` | Hook increments account, rotates epoch, cancels challenge, retires resources. **S**. |
| D7 | Policy authority is Verified Disabled or Enabled, never Pending/Unavailable. `C:150-188,389-395` | bootstrap, refresh, begin_checked, settle_policy, finish | Hook for in-memory state. Durable uncertainty clears known authority before write. Policy I/O stays outside state mutex. **S**. |
| D8 | Captured policy sequence matches. `C:397-413` | Policy transition/refresh and epoch rotation | Hook for captured sequence. Lease does not carry installation UUID. Native process-owner currentness does not reload the durable policy record. **S**. |
| D9 | Controller is Activated and ready. `C:351-375,390-395` | activate and any rotate | Hook under state lock. Prior phase, policy, owner, epoch, and activity all gate activation. **S**. |
| D10 | Enabled private capture requires activity; verified Disabled permits background capture. `C:390-394` | lifecycle. `C:428-485` | Hook for observed lifecycle state. UI uncover always needs activity; notification privacy has a different projection. Native event handlers cover before Rust event callbacks. OS timing **NOT RUN**. |
| D11 | Both process-owner descriptors remain open. `Owr:81-90` | Explicit close/dealloc. `Owr:114-120` | Hook under native owner gate. No callback or latched loss on current()==false. **O** proves synchronous close refusal. |
| D12 | Held directory fstat is directory, effective UID, mode 0700, captured dev/inode. `Owr:9-10,84-85` | External metadata/namespace operations; explicit close | Gap for external changes. Descriptor retains original object, not metadata policy. **O** demonstrates retained capability after namespace loss. |
| D13 | lstat named directory independently matches metadata and captured dev/inode. `Owr:86-87` | External rename/replacement | Gap. No app-owned atomic hook. **O** demonstrates successful replacement while original flock remains held, followed by actual refusal. |
| D14 | Held lock fstat is regular, effective UID, nlink 1, mode 0600, size 0, captured dev/inode. `Owr:12-14,88` | External metadata/link/write operations; explicit close | Gap for external changes. Exclusive advisory flock does not prevent uncooperative changes. **O** proves original inode remains locked across namespace replacement. |
| D15 | fstatat named lock, no symlink following, independently matches held identity and all lock metadata. `Owr:89-90` | External rename/unlink/replacement | Gap. **O** proves replacement inode can be locked independently while current owner refuses. Original anchor refuses successor acquisition. |

Controller `rotate` callers include refresh policy (`C:325-340`), restrictive
lifecycle (`C:428-485`), owner/account replacement (`C:487-509`), unavailable and
lock (`C:513-552`), auth admission (`C:602-607`), success (`C:823-832`), and
failure/cancellation/expiry (`C:840-888`). A future domain must retire inside
those transitions, before the later `retire()` observers at `C:317-323`.

`PrivateScope.check` samples page/policy, checks the lease under state, then
samples page/policy again (`Rcv:207`). `execute_checked` checks before and after
work and wipes stale success/error bytes (`Rcv:219-226`). Neither holds those
locks through an external effect. Native pasteboard checks at
`native/ProtectionBridge.m:161-184` do not extend the owner or controller locks
over the final write.

Controller policy work orders policy_io before brief state locking. Native owner
currentness independently uses `_gate`; native policy work uses its own writer.
The owner gate releases between samples and policy work (`Pb:55-83`). Independent
fstat/lstat/fstatat calls are not an atomic namespace snapshot. An async vnode
watcher cannot create the missing shared ordering with an external actor.

Desktop controller/receiver Rust tests were **NOT RUN** here. The checked-in
native-boundary suite has narrower controls for owner replacement, retirement
during file I/O, and worker-result suppression. Some account-transition tests
create/delete Keychain credentials, so the full suite is excluded from this
no-Keychain host packet. The new **O** probe links only production ProcessOwner
and Foundation, not PolicyBridge or system policy storage.

## Narrow authorities and resource registration

| Kind | Actual predicate and owner | Required distinction and remaining proof |
|---|---|---|
| Desktop choice | Page open plus controller owner/account, with page pointer equality when matched to a fresh private scope. `Rcv:58-68,C:404-406` | Deliberately survives ordinary lock/unlock. It does not admit private reads. **S**. |
| Desktop finite cleanup | Captured page and account generation. `Rcv:230-245` | Exact old legacy removal only. No Core read, new send, or publication. **S**. |
| Android finite cleanup | Exact epoch/handle inside F dispatch, with outer moduleScoped | Public entry still rejects stale module scopes before cleanup. No authority broadening in this unit. **A**. |
| iOS finite cleanup | Captured selection/resource cancellation and dispose closure | Cleanup cannot reacquire a fresh native owner or erase a successor. App-lifetime settlement differs from process-death recovery. **S**. |
| Account transition | iOS exact ticket and logical ID; Android four pre-export accountChanging hooks; desktop existing account-transition controller path | Each platform's current semantics remain intact. Runtime integration must survive only its own tagged rotation, allow the exact export's network, and order finite local writers before successor activation. **R** for iOS host; **A/S** elsewhere. |
| Host services | Original native registration/callback resources plus current applicable registration truth | Retained V2 Host registration can solve callback lifetime. It does not freeze permission or substitute profile/frame equality for live native truth. Actual registration replacement must retire the applicable generation. V2 API and wiring remain provisional. **S**. |

The matrix leaves all unproved rows open. [HANDOFF.md](HANDOFF.md) records the
specific API and policy decisions required before protected integration.
