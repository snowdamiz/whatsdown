# Plaintext types v1

Status: implementation and application migration in progress. This document
defines the intended guarantee and its evidence. It does not claim that the
complete Morse app has passed the release gate. The current scoped checkpoints
and remaining work are recorded in §2 of `WITNESS_NETWORK_PLAN.md`.

## Checked boundary

`Plaintext<T>` identifies private message content and values derived from it.
The required sources include message bodies and captions, attachment names and
MIME types, contact names, and profile text. Labels must start at the actual
input or decryption boundary and survive storage, parsing, framing, aggregation
and forwarding. Labeling only the final network call is insufficient.

The Mesh checker follows values and content-dependent control flow. Hashing,
slicing, concatenating or wrapping private bytes does not make their contents
public. A public primitive's documented fixed output size can be public while
its bytes remain private. Error payloads and success/error selection must retain
their actual dependencies; successful encryption does not authorize revealing
a failure selected by private input length.

The app migration must cover both direct and group messages, linked-device
sync, history, attachments, contact/profile presentation and host input frames.
Passing a scoped helper or a partially labeled build does not establish complete
source coverage.

## Allowed exits

| Exit | Required behavior |
|---|---|
| Authenticated encryption | Private content is accepted only as plaintext input. Keys, nonces and associated data are not arbitrary disclosure exits. |
| Sealed local storage | History and private journals remain under the platform-bound storage key and authenticated context. |
| Reviewed `@display` export | Only the named export's result crosses into the audited UI observer. Internal network, log and other effects remain checked. |
| `declassify(value, reason)` | The exact disclosed value and a nonempty reason appear in the compiler report and reviewed inventory. |
| `declassify_discriminant(result, reason)` | Only success/error selection is reviewed. Both payloads, prior and caller control, and ownership retain their original restrictions; this has a distinct report kind. |

HTTP and WebSocket URLs, headers and bodies; logs, panics and diagnostic output;
push payloads; public serialization; and actor messages outside the checked core
are refused exits unless an explicit reviewed policy authorizes the particular
disclosure. An opaque helper, generic container or error return must not hide
the flow from the checker.

Morse's bounded helper policies are documented in
[`ops/plaintext/BOUNDED_HELPERS.md`](../ops/plaintext/BOUNDED_HELPERS.md). They
describe deliberate admission, size and presentation disclosures, including
their limits. They do not authorize declassifying arbitrary message bytes or
error strings to make a build pass.

A result-tag review must happen at the intended boundary before the caller
matches or propagates the private result. It cannot undo control dependencies
already introduced by `case`, `?`, or a helper that branches internally. Testing
a labeled result therefore uses a separate helper to compute a known synthetic
equality or outcome, then explicitly observes only that Boolean. Test-only
observers are excluded from the production disclosure inventory.

## UI and native networking

A display export gives private content to the UI. The Mesh checker alone cannot
control what JavaScript or a third-party native module does with that value.
The application therefore routes production network operations through reviewed
native Mesh entry points and installs immutable JavaScript networking
restrictions before application and background-task initialization.

The native dependency inventory records modules, source/build inputs and the
desktop host boundary. `npm run check:native-network --prefix apps/mobile`
checks it from the product root. A dependency or source change requires review
of the changed capability; updating a hash is not evidence of that review.
The inventory is an application control, not a network sandbox for native code.
Local notifications, display, attachment saving and an explicitly requested
external-wallet launch remain separately reviewed OS capabilities.

## Build evidence and release gate

The compiler emits a `plaintext-v1` report containing each checked module's
source hash and every display/declassification site, including its reason and
source location. `ops/plaintext/report.mjs` compares that list exactly with the
reviewed inventory. Added, removed, moved or changed sites fail the comparison.
The evidence records the report, review, compiler and artifact hashes. The
review must identify the exact value disclosed and why; there is no numeric
quota that makes a disclosure acceptable.

Release qualification requires all of the following:

- Complete source labels and a successful checked application build.
- Review of every display and declassification site, with the exact inventory
  published in the release notes.
- Retained compiler/runtime/application source and artifact identities, including
  native target builds and the dependencies actually used.
- Refusal tests for private data and control flows, plus positive native
  execution and failure/restart recovery of the affected application paths.
- Verified JavaScript restrictions, native connection inventory and the plan's
  performance and release checks.

The native build entry points enforce the current
[development disclosure inventory](plaintext-disclosures.md), including its
exact source spans and reasons. This controls changes to the existing exits.
Full source coverage and release approval remain pending; the development
baseline must not be presented as a completed application migration.

Release evidence packaging is implemented by
[`ops/plaintext/release-evidence.mjs`](../ops/plaintext/release-evidence.mjs) and
the [release adapter](../scripts/plaintext-release.mjs). Bundles bind the complete
reviewed site list and per-target source reports to compiler/native hashes,
source and Mesh revisions, a build identity, and actual final package hashes.
They preserve pre-sign and post-sign native identities separately. Desktop
release notes retain the inventory and downloadable evidence; configured EAS
workers export evidence which is retrieved and checked for the exact build ID
and application package. A legacy unconfigured worker is explicitly pending,
not a verified mobile disclosure release. Local packaging checks do not execute
or approve a release, establish full source labels, or prove installed bytes.

## Claim limits

Any eventual claim must name the checked source revision and build evidence.
This work does not prove that a downloaded app is that build; the plan excludes
build transparency. Rust, OS glue and third-party native code are outside the
Mesh proof and require their own review. It does not stop a compromised device
or hide all message lengths, timing, acceptance, storage footprint or deliberate
disclosures. Local test fixtures do not establish production deployment or an
independent security review.
