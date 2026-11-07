# N1b independent implementation review, round 2

**PASS_WITH_GATES — no actionable findings in the authorized bounded N1b scope.** R1's same-root sentinel aliasing defect is closed in the reviewed source. This approves the dormant source and bounded Foundation/macOS proof, not UIKit/Expo integration, native-policy completeness, or activation.

Reviewed baseline/HEAD: `0d6826b5d02e3439d93568ecc1d6fa996135a505`, plus the shared uncommitted N1b changes. Read AGENTS/TDD, all seven requested design documents, final-contract-review-r2, n1-final-review-r3, R3_DISPOSITIONS, and review-r1. Only this review file was added by this reviewer; production/test sources and retained receipts were not edited. Existing executables were replayed; no new driver/runtime build or Mesh family was created. The existing support-only iOS simulator typecheck was also rerun.

## R1 disposition and source review

- `MeshMessengerDataProtection.swift:126–134` allocates a distinct immutable sentinel registration before retiring the prior sentinel and clearing the bound current lease. Same-root replacement therefore preserves the root node while replacing the sentinel node. Same-ID registration returns before allocation or mutation. The existing attached-sentinel early return at `:760` remains.
- `Capture` freezes the original root/sentinel node references (`:162–188`). Bound commit compares those exact references before returning an existing lease or creating a new one (`:194–213`). Replacement cannot silently refresh a pending capture, including when the auth epoch is unchanged. A committed lease retains all three original ancestry nodes.
- The actual UIKit sentinel stores its own immutable node and retires it before the original Main dispatcher (`:816–829`). Deferred cleanup retains the original DataProtection sentinel-ID guard (`:781–784`) and now also checks that ID inside RootBindings (`:154–158`). Old cleanup cannot detach a replacement sentinel on the same root. The owner likewise retires its stored original lease before deferred cleanup (`:862–863`); owner replacement and detach retire before clearing their stored lease.
- Compared the complete production diff with the baseline. No original native identity, mount, scene/window, module/context, account/epoch, retired-owner, ambiguity, Main-thread, or cleanup predicate was removed. The Module's existing Main queue and `RootModuleLifecycle.withRegistered` serialization around commit/owner assignment remain unchanged. Strong `Capture` references prevent last owner release while capture is held. Sentinel replacement is serialized on Main; off-Main retirement uses only the original retained node.
- Production RootBindings still omits the optional domain (`:732`). Unbound sentinel registration does not clear current or change the gate; the existing Main dispatcher overload is unchanged. No app binding/activation was introduced. The existing podspec source glob already includes the added Swift file; no build integration change was made.
- Root, sentinel, and lease node allocation precede their respective retirement/registry mutations. The post-allocation epoch check remains before publishing a new lease. An unpublished rejected node tears down through its own wrapper. The UIKit wrapper's preexisting foreground/factory updates are not claimed to be transactional with the new allocations; its failure catch remains fail-closed. Failed image initialization balances its handle, and non-null failed ABI outputs are released using that same retained image. Recoverable allocation-error injection was not performed; OOM termination is not represented as recoverable success.
- `MeshMessengerNativeRetirement.swift:84` calls only the immutable original retire function with the immutable original node. The pinned runtime implementation is the atomic `retired.store(true, SeqCst)`; it performs no Main dispatch, queue, lock, callback, lookup, or destruction. Generation release and image teardown occur outside that method. All five ABI symbols resolve through one retained handle and are checked for the same canonical image path/base. Node → domain → image references preserve the release order. The driver keeps its fixture alive until C authorities/invocations are finished. Future product scoped-call integration must preserve that ownership chain; raw handles alone do not do so.

## Independently replayed evidence

Verified all 44 retained `final-family.json` members and all 19 accepted runtime sources from commit `9b844dbab34e61f6de575af2b25b0ed0f321059e`. Verified every current source entry, driver hash, and log hash in `artifacts/final-green-r2/receipt.json`; all matched. Rechecked source hashes after the executions. Retained executable replay is distinguished here from a fresh compilation: this reviewer did not recompile the native or regression binaries.

Commands were the existing `command` arrays in `final-green-r2/receipt.json` and `final-red-r2/receipt.json`, excluding compile entries; the green `ios-support-typecheck` command was separately replayed. The R1 red used:

```sh
python3 -B mesh-private-messenger/tests/native-authority-closure/unit-n1b/check.py \
  /Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/native-effect-authority/generated-abi-1794012766838904000/libauthority.dylib \
  mesh-private-messenger/tests/native-authority-closure/unit-n1b/artifacts/same-root-red/native-lifetime.dylib \
  same-root-sentinel
```

Results:

- Baseline control succeeds. Baseline owner/sentinel each reproduce bind `0`, status `0`, and a real SQLite `later` row after off-Main teardown with Main undrained; both exit `1` at the expected missing-retirement assertion.
- Historical R1 same-root driver reproduces bind/status `10` and no successor row, exiting `1` at `obsolete same-root sentinel retired successor before Main cleanup`. Its driver and retained log hashes match its receipt.
- Current green **8/8 cases pass**: control, owner, sentinel, owner-main, sentinel-main, capture-owner, same-root-sentinel, same-root-stale-capture. Retired old owner/sentinel calls bind/refuse with `10` before held HTTP is released and leave the original database hash unchanged. Different-root successors reach the real generated SQLite sink after stale cleanup. Same-root successors bind with `0` and write real rows both before and after stale cleanup. Same-epoch replacement rejects the old capture while a fresh capture succeeds. Repeated same-ID registration's node-identity assertion executes during fixture setup.
- The capture-owner case binds successfully while the strong capture retains the owner, commits the same original lease, and then refuses only after the last capture release on a worker. No Main/HTTP join is needed for retirement.
- All **71 existing Swift groups + 3 retirement groups pass**: AppLock 31, default RootBinding 23, all seven extra RootBinding modes totaling 17, retirement 3.
- Standalone image-lifetime passes missing/wrong-symbol image refusal, retained domain after caller reference release, repeated retirement, actual ABI refusal, and domain deallocation after node release. `otool -L` confirms neither green driver nor standalone image-lifetime executable has a runtime link dependency. Image unload/release ordering is additionally supported by source inspection; this is not an allocator/destructor fault-injection proof.
- Support-only arm64 iOS simulator 16.4 typecheck exits `0`. `vtool -show-build` confirms the accepted generated dylib is **MACOS**. `git diff --check 0d6826b` passes.

## Exact SHA-256 pins

Paths below are relative to this unit unless otherwise named. These are the reviewed current bytes, not R1 source pins.

| Artifact | SHA-256 |
|---|---|
| Production `MeshMessengerDataProtection.swift` | `cd5410f2f3c58bb6338c8048a068bb2bb06de515696b121ea54e95a54918ed9a` |
| Production `MeshMessengerNativeRetirement.swift` | `79004e1e8938d3bc922164f64da65ac7bd0af3dd36135423567b3f134833c237` |
| `native_lifetime.swift` | `a63486431479bb5f4ba0cc33c6b17b64d1ef0fe853be6a0da896efe3fd6a723e` |
| `image_lifetime.swift` | `8b71f8152e60483a04e972b681e25d00817e5425db62c3a369dabe510322c1bb` |
| `check.py` | `0b3c9459d16cb04bc61e1ac83ec5641e075922e9ff905436709af7085dca4e18` |
| `prove.py` | `8e721462778265a635d522099c80f3d9f9be7f34af97225f8e388f48ecf4756e` |
| `README.md` | `3709e135cff5d7539f6f8b65368e72e3c4c1d3b4bdfc7ef6b2701ed8a6158dde` |
| `artifacts/final-green-r2/receipt.json` | `eb43268a525a6571817796188d0314af8f4b14dd1db8e14f3ccafd96d9f3a853` |
| `artifacts/final-green-r2/native-lifetime.dylib` | `474e44d9e9da84f8d6ed75d8318120f219dd85f030b07e446d7376cb049b8874` |
| `artifacts/final-green-r2/image-lifetime` | `41e2fa17b4cf15647f2690cb5c1ebf0876faceb13199b30b9c3377757ee03150` |
| `artifacts/final-green-r2/MeshMessengerAppLockTests` | `842ea9d68ec5a83087d0e397b3c3593d7ad84705ff0ccf06b3ad926c9a5ce96c` |
| `artifacts/final-green-r2/MeshMessengerRootBindingTests` | `57b1259bfedb574188a2d8bc0aa02adfc780ea908992af44f574e164c9018d97` |
| `artifacts/final-green-r2/MeshMessengerRetirementTests` | `5e5cbd5c407491c873b8d655bf8273e5f196bebf6bdc526f0d47cc62008c4b50` |
| Accepted `final-family.json` | `652b8475fec8e4391c7f178b26923661e109c18b73c0008d4b84718e03cbbb59` |
| Accepted generated `libauthority.dylib` | `1d5af0920725bc0449977060a270393192193b09ce896f96049ce3226299bf5d` |
| Frozen `library_authority.h` | `5bbaf429dbd3749924b041847aba40ce40ee33c5a13a5c97f454601d79f87843` |

## Remaining gates

The owner/sentinel executables use Foundation lifetime ports with production RootBindings/retirement code and the accepted generated HTTP/SQLite sinks. They do **not** execute the actual UIKit/Expo classes. No complete iOS build, UIKit destructor run, simulator application, or device qualification was performed. The support-file typecheck does not close those gates, and the retained MACOS runtime image cannot establish iOS runtime integration.

Framework writer/structural lifetime coverage, complete effects, service provenance, native policy, scheduler progress, SDK/JSI/WK publication, and product activation remain unqualified. Mask remains **1**. Those known boundaries are separate from this bounded pass. No runtime/auth/session work, installed app8256 changes, push, PR, merge, deployment, inventory, or plan edits were performed.

At the final status check, a concurrent modification to `tests/native-effect-authority-unit0/prove.py` appeared. This reviewer did not create, inspect, or include that unrelated change in the verdict. All reviewed N1b source hashes still matched the pins above.
