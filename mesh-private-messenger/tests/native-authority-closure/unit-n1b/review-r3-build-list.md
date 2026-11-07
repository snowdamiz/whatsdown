# N1b R3: unit0 source-list integration review

**PASS_WITH_GATES — no actionable finding in the newly authorized one-line integration.** This verdict covers only the insertion in `tests/native-effect-authority-unit0/prove.py` and its retained unit0 replay evidence. R2's production acceptance remains a separate `PASS_WITH_GATES`; both production files still match its exact pins. This review does not reopen or broaden that acceptance.

Baseline/HEAD: `0d6826b5d02e3439d93568ecc1d6fa996135a505`. Read `review-r1.md`, `review-r2.md`, and `review-scope-addendum.md`. Independently inspected the current runner, baseline bytes, receipt commands, source/binary hashes, and retained logs. No compiler, proof runner, or retained executable was invoked. Only this review file was written.

The runner's reviewed SHA-256 is **`f6cca1cdb463fdfdf5abc20ed4f790bab7a67b041717bd499fa18accabac7bc0`**.

- A byte comparison against `git show 0d6826b:mesh-private-messenger/tests/native-effect-authority-unit0/prove.py` confirms exactly one insertion: `MeshMessengerNativeRetirement.swift` immediately before `MeshMessengerDataProtection.swift` at current line 26. Every other runner byte is unchanged.
- The common list remains AppLockPolicy, AppLock, ProtectedFiles, LockedNotifications, then the new NativeRetirement dependency, then DataProtection. `common[-1]` at line 49 still reads DataProtection for the negative-control mutation. `common[:-1]` at line 56 includes NativeRetirement while replacing only DataProtection with the mutated copy. The retained red source exactly equals current DataProtection with the runner's single Main-dispatch replacement; the mutation target occurs once.
- The complete common list reaches the retirement and RootBinding compilations at lines 60 and 63. AppLock's `common[:2]` at line 68 is unchanged and still includes only AppLockPolicy and AppLock. All four recorded Swift compile command arrays match these source lists exactly. The ProcessOwner compile command and every recorded execution command also match the runner.

`receipts/unit0/receipt.json` has SHA-256 **`6b8df5e946bb57c28d8c973341f28f714279585b302e2bb864d8c45751de8b7e`** and is byte-identical to `artifacts/unit0-replay/receipt.json`. Independently verified all 14 source entries against current files, all 5 retained binary hashes, and all 17 log hashes. Each copied log is also byte-identical to its artifact log. The receipt records the current baseline HEAD and the reviewed runner hash.

The 17 records comprise 5 successful compilations and 12 executions, including the expected failing control. Every recorded exit equals its expected exit; only `retirement-red-control` expects and records exit 1. Its log contains exactly two `FAIL Main ` entries, for owner and root retirement being deferred past return, one passing off-Main control, and `RESULT 1/3`. The positive retirement log reports 3/3. AppLock reports 31 groups with zero failures; default RootBinding reports 23/23, and its seven additional modes report 17/17 combined, preserving all 71 existing Swift groups. ProcessOwner reports both namespace-replacement controls passing, 2/2. These are independently hash-verified records of the implementation's replay, not a fresh R3 execution.

The current production pins equal R2 and the unit0 receipt:

- `MeshMessengerDataProtection.swift`: `cd5410f2f3c58bb6338c8048a068bb2bb06de515696b121ea54e95a54918ed9a`.
- `MeshMessengerNativeRetirement.swift`: `79004e1e8938d3bc922164f64da65ac7bd0af3dd36135423567b3f134833c237`.

R2 owns the prior production-source and generated-sink acceptance, including closure of R1's same-root sentinel finding. R3 establishes that this exact runner integration preserves its source slicing and has matching retained regression evidence. It adds no runtime-family, ABI, lifecycle, or product qualification.

UIKit/Expo remains **UNQUALIFIED** pending accepted iOS runtime/integration and actual class execution. The bounded Foundation/macOS scope and mask **1** remain; native-policy, scheduler, publication, activation, and all other R2 gates remain open. No product binding is authorized or established by this verdict.
