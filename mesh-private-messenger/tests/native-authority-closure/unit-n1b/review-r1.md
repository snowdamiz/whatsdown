# N1b independent implementation review

REQUEST_CHANGES — one reproduced successor-isolation defect. Review is against baseline `0d6826b` plus the shared N1b changes; no production or test source was edited by this reviewer.

Reviewed production SHA-256:

- `MeshMessengerDataProtection.swift`: `fdd74fc1b77feb6f50d0224cb5f8cfcb7dc8405ffb1ced35769cc520c26d953a`
- `MeshMessengerNativeRetirement.swift`: `79004e1e8938d3bc922164f64da65ac7bd0af3dd36135423567b3f134833c237`

## P2 — A replacement sentinel on the same root shares the old sentinel's retirement node

Source: `apps/mobile/modules/mesh-messenger/ios/MeshMessengerDataProtection.swift:738` and `:800`; supporting registration path `:106–118`, sentinel replacement `:728–741`, and existing cleanup identity guard `:752–755`.

`registerRoot` returns the existing registration when the root object is unchanged. `bindReactNativeRoot` can nevertheless install a new sentinel for that registration when the previous sentinel no longer has this root as its superview. Both sentinels then retain the same `rootRetirement(id)` node. A retained old sentinel can subsequently deinitialize off-Main and retire that shared node at line 800, before the sentinel-ID check in deferred `retireSentinel` can reject the obsolete cleanup. This revokes the new sentinel's root authority, including a fresh owner lease captured in a fresh epoch. Native successor validation can still succeed while generated authority binding now refuses.

This is a distinct path from the passing test's replacement of the root object. `Fixture.successor()` always allocates `root = Object()`, which necessarily obtains a different root node and misses same-root sentinel replacement.

I reproduced the aliasing with the actual production RootBindings, gate, retirement wrapper, existing Foundation Sentinel port, and accepted generated ABI. The probe ran through `xcrun swift -swift-version 5 -` from an in-memory concatenation of the production sources and fixture classes; it created no test-source file. Sequence:

1. Retain the old sentinel independently using `Unmanaged.passRetained`.
2. Apply the existing replacement path's inactive foreground transition, then call `registerRoot` with the same root object.
3. Install a new Sentinel with that root ID; call `rootWindowDidChange`, restore active foreground, and capture a fresh owner lease at the new epoch.
4. Bind the new lease's root and owner nodes through `mesh_authority_bind_v2`.
5. Release the retained old sentinel on a worker while Main waits on a semaphore, then bind those same successor nodes again.

Observed output:

```text
same root registration: true
fresh owner lease: true
fresh epoch: true
replacement authority before old teardown: 0
Main undrained: true
replacement authority after old teardown: 10
native successor still validates: true
```

The port's cleanup cannot explain this result: Main remains undrained throughout. The unconditional retirement of the aliased node is sufficient. This is Foundation/production-source evidence, not a claim that UIKit was executed.

Give each replacement sentinel lifetime a fresh immutable registration/node before exposing it, while preserving idempotence when the existing attached sentinel is reused. The previous sentinel must retain only its old node. Add a bound control that keeps the old sentinel alive, installs a replacement on the same root, captures the successor, then destroys the old sentinel off-Main with Main held. The successor must still reach the real generated sink before and after stale Main cleanup. Do not move identity lookup, Main dispatch, or a lock into the atomic retirement operation.

## Verification and non-findings

- Read AGENTS.md, the requested seven design packet documents, final-contract-review-r2, n1-final-review-r3, and R3_DISPOSITIONS.
- Verified all 44 files in the retained `final-family.json` by SHA-256; used its existing library, with no Mesh/runtime rebuild or new family. Header remains `5bbaf429…7843`, library `1d5af092…bf5d`, capability mask 1.
- Independently replayed baseline-r2 control/owner/sentinel: control reaches SQLite; each teardown case returns before Main cleanup, still binds with status 0, writes the later row, then fails the expected assertion.
- Independently replayed green-r2 control, owner, sentinel, owner-main, and sentinel-main against the retained driver. All pass: old generated calls refuse with status 10 and no later row, and different-root successors reach the actual SQLite sink after stale cleanup.
- Independently ran all 71 existing Swift groups: AppLock 31, default RootBinding 23, and its seven extra modes totaling 17. Independently ran all 3 retirement groups. All pass.
- Independently replayed green-r3 capture-owner and image-lifetime. Both pass. Capture retains the original owner until release; the wrapper retains its domain/image after the caller drops the domain; missing and wrong-symbol images refuse initialization.
- Allocation occurs before retiring/replacing existing RootBindings state. The post-allocation epoch guard is preserved; a failed new lease releases its own node. No changed native identity guard was removed. Owner replacement and different-root cleanup use immutable original nodes. The fixed retirement call contains no lookup, lock, queue, user callback, or release; generation/domain/image destruction is outside it.
- One image object resolves all five ABI symbols and validates a common image base/path. Nodes retain their domain, which retains that image through generation and domain release. No additional lifetime defect found by source review or the replayed lifetime control. Runtime allocation-error injection was not performed.

The parent was editing proof/docs concurrently. Green-r3 production sources, native_lifetime.swift, check.py, and image_lifetime.swift matched that receipt at inspection; prove.py had subsequently changed. Earlier receipt source drift is historical evidence, not a production-source pass for those earlier versions. This review does not adopt later source changes automatically.

UIKit/Expo execution and the existing native-policy, scheduler, publication, and activation gates remain outside this bounded verdict. Their absence is not an additional finding. No push, PR, deployment, inventory, plan, or runtime/auth/session work was performed.
