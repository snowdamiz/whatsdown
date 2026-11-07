# Native predicate closure, unit 0

Source base: `f2e872a51457ec5963132ec9cbf4303c31e453ea`.

The bounded production correction retires iOS root and owner authority inline
when deinit already runs on Main. Off-Main teardown still queues exact-identity
cleanup. The shared dispatcher preserves that distinction at both deinit hooks.

The native host regression reproduces the old dispatcher behavior with the Main
queue held. Both Main cases fail before the correction. All three groups pass
after it. The test runs the production dispatcher, `MeshMessengerRootBindings`,
and `MeshMessengerAppLock`. Its identity ports do not reproduce UIKit deallocation,
Expo, or Fabric scheduling.

The production macOS `MDProcessOwner` probe demonstrates that a held descriptor
and exclusive `flock` do not retain named-path authority. Another worker replaces
the lock or directory between barriers. The original descriptor and lock survive,
the replacement lock can be locked independently, and production currentness
refuses. The original anchor also refuses successor acquisition. Only the anchor
storage is in memory. No Keychain service is constructed.

[PREDICATES.md](PREDICATES.md) contains the finite predicate matrix and the exact
open design obligations. [HANDOFF.md](HANDOFF.md) describes the runtime API needs.
The synchronous runtime domain remains provisional and is not connected here.
No protected activation or serializer removal is qualified by this unit.

## Replay the host proof

Run from the repository root on macOS with Xcode selected:

```sh
python3 mesh-private-messenger/tests/native-effect-authority-unit0/prove.py \
  --output .morse/native-effect-unit0/replay
```

The script compiles small Swift and Objective-C host executables sequentially.
It creates an always-deferred negative control in the output directory and expects
that executable to fail both Main cases. Production source remains untouched.
It then runs the corrected dispatcher, the existing root-binding modes, the
app-lock controller tests, and the actual process-owner probe.

`receipt.json` records commands, exit codes, source hashes, binary hashes, and log
hashes. [receipts.json](receipts.json) retains the results of this implementation
run. The two short [red](retirement-red.log) and [green](retirement-green.log)
logs retain the accepted failure and correction. The [process-owner log](process-owner.log)
records the real filesystem controls.

## Qualification limits

The replay passed 71 existing Swift host groups, three new retirement groups,
and two Objective-C process-owner controls. Its negative control failed as
expected. Android's config-plugin audit passed six tests with the pinned local
dependencies. Android runtime tests did not run because the generated Gradle
app project and artifact cache are absent.

UIKit deinit, actual React reloads, Expo final reply delivery, native Android
lifecycle scheduling, Tauri delivery, and physical devices remain unqualified.
The known macOS signing-profile failure, Keychain status `-34018`, remains a
separate product blocker. This unit does not retry or alter signing, certificates,
trust, profiles, or user accounts. No product UI success is claimed.
