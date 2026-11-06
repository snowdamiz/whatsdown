# Isolated ACH3 native proof

These tools build and execute a separate proof app on an iOS simulator and an
Android emulator. They do not install production libraries. The original
`AttachmentProof.swift` / `AttachmentProof.kt` evidence describes the earlier
ABI; their four-field free upload and five-field paid prepare calls are
superseded by this ticket-aware proof. Retained old results are not claims about
the new ABI.

Default inputs are the immutable `87085bbd…` ACH3 closure, compiler `2e701ef6…`
and matching `347da0ed…` host/runtime family under `.morse/witness-proof`.
Run from this product root:

```sh
python3 ops/attachment-ach3-native/build.py --work /absolute/new-proof-directory
python3 ops/attachment-ach3-native/prepare.py --work /absolute/new-proof-directory
python3 ops/attachment-ach3-native/run.py ios --work /absolute/new-proof-directory --run-id final
python3 ops/attachment-ach3-native/run.py android --work /absolute/new-proof-directory --run-id final
python3 ops/attachment-ach3-native/seal.py --work /absolute/new-proof-directory --run-id final
```

Coordinate simulator/emulator access with any other native proof before the
last two commands. The custom bundles are `app.morse.ach3.proof.ios` and
`app.morse.ach3.proof.android`; the runners remove only their own apps. Commands
use file/terminal transport. No screenshots, recordings or computer-use service
are required. Set `MORSE_MAILBOX_IOS_DEVICE` / `MORSE_ATTACHMENT_ANDROID_SERIAL`
for the supported harness device overrides (see their constructors).

Build verification requires every selected production ABI entry to be identical (historical default 162; explicit padded successor 163), and every production module source hash and plaintext site to match the selected canonical report. The only replacement is proof `Main`, with its exact source
hash and zero plaintext sites. Six proof-only exports produce authenticated
ciphertext or signed evidence. Total reviewed plaintext sites must exactly match
the selected canonical report (22 for the default historical checkpoint).
Successor builds can select `--closure`, `--toolchain`, `--baseline-report` and
`--baseline-abi`; changing the expected count alone cannot admit a changed
production module or a disclosure in a proof helper. The verifier regressions
run with `python3 ops/attachment-ach3-native/build.test.py`.
Use `--opt-level 2 --jobs 1` for an optimized successor with one compiler at a
time. New builds record an explicit optimization level (default `0`).
Verification preserves the original executed command and refuses a different
requested optimization level; it cannot relabel an earlier debug artifact.

Fixture service/witness keys are publicly known synthetic seeds. Native release
resources pin their public keys; the fixture constructs account-signed device
credentials, service-signed RFC log checkpoints and witness signatures, then
passes them through the production transparency verifier and recipient gate.
There are no test-host token overrides or verification bypasses.

Coverage includes forged evidence, authenticated legacy primary/linked devices,
new request framing, recipient ticket tamper/path/account/native-pin binding,
actual free upload over owned HTTP, new free and paid ACH3 chunk writers,
restart-stable paid ciphertext, EAM replacement rejection, and legacy ACH1/ACH2
reads over owned HTTP/TLS. Android pin mutation reinstalls the same signed
isolated app without clearing its real OS custody/database. The simulator
relocates its data container on reinstall, so its pin-only test changes and
re-signs only the owned installed app's native metadata in place. A separate
reinstall case proves the old path-bound ticket is refused and a new ticket
from the same authenticated profile/device set recovers normally.

The paid writer case intentionally has no credits: production preparation
persists material-only status3, then correctly refuses token reservation. The
proof exercises the actual part writer/recovery for that material. It does not
claim a funded paid grant or production object-store transfer. Simulator and
emulator execution do not establish physical-device behavior or authorize live
funds, deployment or activation.


## Explicit padded successor

Historical commands and unlabelled historical evidence retain profile3/162. Padded proof selection requires both `--wire-profile 4 --expected-production-exports 163` on the new build. Pass the same flags to prepare/run/seal for an explicit invocation, or let those later stages inherit the exact recorded settings. Mixed pairs, an incomplete selection, a caller/record mismatch, duplicate ABI symbols and wrong rehashed ABI counts fail before host preparation. Verify-only preserves the recorded optimization/profile and cannot relabel an old result.

The profile4 material library retains all 163 selected production exports and exactly 6 proof-only exports (169 total). Binding equality across the two OS targets, every canonical production module/site, exact proof Main/legacy hashes and zero proof disclosure sites remain mandatory. `prepare.py` checks the recorded native artifacts before copies/CMake, then records the selected profile, exact settings/qualification bytes and host inputs. It does not configure recipient capabilities through host flags.

Profile4 uses a distinct material result status (`passed_isolated_native_attachment_profile4`, sealed `passed_frozen_isolated_native_attachment_profile4`) plus explicit profile/count fields. The runner expects16groups/79calls on iOS and 15 groups/76 calls on Android. These counts include authentic mask3-only primary and linked-device cases: the ordinary ACH3 recovery ticket remains valid, while both new padded writers refuse before HTTP or reservation changes. The actual sealed outcomes must retain unchanged inventory, no network effects and the precise upgrade refusal.

Swift/Kotlin keep final plaintext input at one byte. Mesh must emit a 65,576-byte ACH4 final ciphertext and return exactly that original byte when opened. New free, paid and one-byte uploads assert fixed 514-byte EAM4 envelopes; source size and padding are never manufactured in the host. The original independent ACH1/ACH2 read corpus and fixture helper stay unchanged. Profile4 adds an ACH3 read/restart case with its genuine short41-byte final frame. No extra production or proof export is added for these cases.

The focused orchestration checks below use owned temporary files and mocked native build boundaries; they do not qualify Swift/JNI execution, OS custody, crypto or the new driver. Run from the product root:

```sh
python3 ops/attachment-ach3-native/build.test.py
python3 ops/attachment-ach3-native/prepare.test.py
python3 ops/attachment-ach3-native/profile.test.py
python3 ops/attachment-ach3-native/seal.test.py
python3 ops/attachment-paid-native/build.test.py
python3 ops/attachment-paid-native/qualification.test.py
python3 ops/attachment-paid-native/callback.test.py
```

A fresh combined source/native build and both actual material runs are still required before describing these added native outcomes as passed. Preserve all prior sealed archives.
