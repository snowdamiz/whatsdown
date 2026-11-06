# Plaintext disclosure evidence

`report.mjs` checks a successful public Mesh build report against the reviewed
disclosure inventory, then records hashes of the frozen build inputs.

```sh
node --test ops/plaintext/report.test.mjs
node ops/plaintext/report.mjs \
  --report build/libmesh_messenger_core.a.plaintext.json \
  --review protocol/plaintext-disclosures.json \
  --compiler /path/to/pinned/meshc \
  --artifact build/libmesh_messenger_core.a \
  --output build/plaintext-evidence.json
```

The reviewed inventory has schema version 1, policy `plaintext-v1`, and a `sites`
array. Each entry includes `module`, `file`, `kind`, `reason`, `start`, `end`,
`line`, and `column`, matching the source report. Every addition, removal, moved
site, and changed reason requires the reviewed inventory to change. There is no
numeric ceiling on disclosures.

The verifier distinguishes whole-value `declassify`, `display`, and the Mesh
`declassify_discriminant` result-tag boundary. Changing between these kinds
requires a matching review even when the reason and source span stay the same.
Accepting a report kind does not add a disclosure to the application's inventory.

The build pipeline supplies the frozen compiler and artifact used for that
report. Evidence includes their streamed SHA-256 hashes, the exact report and
review hashes, and the compiler-reported Mesh source hashes. The output is
replaced atomically after validation. A caller must check the command's exit
status before publishing evidence.

The current development inventory is
[`protocol/plaintext-disclosures.json`](../../protocol/plaintext-disclosures.json).
Its [review notes](../../protocol/plaintext-disclosures.md) identify twenty
finite value releases, five result-tag reviews and seven display
observers. Both native build entry
points enforce it before replacing installed libraries and retain the report
and evidence. Missing or mismatched reports are fatal; there is no silent
inventory regeneration. The Android CI archive build also runs this check for
each architecture before accepting its artifact and records the evidence next
to the archive.

Complete field labeling, application/compiler source pins, independent review,
native-module inventory and UI network closure remain separate release gates.
The development baseline is not release approval. When the compiler input is a
wrapper, its hash identifies that entry point; retain the underlying compiler
and runtime identities separately.

Check the actual attachment and presentation getter boundaries with:

```sh
python3 ops/plaintext/prove_display_sources.py \
  --compiler /absolute/path/to/pinned/meshc \
  --output /absolute/path/to/new/evidence-directory
```

This runner snapshots the full declared Mesh path dependency closure, refuses
seven actual getter/wrapper-to-HTTP flows, proves that removing the five result
labels admits those flows, and builds the protected production core. It never
runs the probe or changes live labels. `MESH_RT_LIB_PATH`, when supplied, is
recorded by hash. Getter coverage does not establish complete source labeling.

Check the labeled manifest fields, encrypted positive paths, private metadata
refusals and exhaustive error policy with:

```sh
python3 ops/plaintext/prove_attachment_metadata.py \
  --compiler /absolute/path/to/pinned/meshc \
  --output /absolute/path/to/new/evidence-directory
```

This runner uses actual protocol and classifier sources, tests label-removal
mutations and a future error variant, and records source/toolchain identities.
It never executes the forbidden network probes. It qualifies manifest fields,
not every native input or the whole application.

## Release disclosure bundles

`release-evidence.mjs` packages the exact reviewed inventory, source report,
existing build evidence, compiler and native bytes, and final package hashes.
Files are stored by SHA-256, so equal reports or compilers across targets are
retained once per bundle. `verifyReleaseBundle` requires an independently
supplied release identity, target set, and actual package files. A missing or
changed report, review, evidence, compiler, native artifact, package or build
association fails. The bundle includes `DISCLOSURES.md` with every reviewed site,
reason and source location; no complete-labeling or build-transparency claim is
inferred from packaging.
This tool does not add an ABI qualification claim; ABI compatibility remains a
separate native build/release check.

Run the self-contained local checks without compiling or releasing an app:

```sh
node --test ops/plaintext/report.test.mjs ops/plaintext/release-evidence.test.mjs scripts/plaintext-release.test.mjs
python3 ops/plaintext/extract-release-evidence.test.py
```

`scripts/plaintext-release.mjs` captures native inputs before platform signing,
then associates those compiler-produced bytes, the bytes supplied to packaging
after signing, and the actual installer/update archive hashes. These are
separate identities: an old compiler report is never silently rebound to a
signed library. The package association is a record from the build workflow,
not a proof of installer contents or of the bytes installed on a device.
Desktop builds retain one compressed bundle per target; the release job checks
all three bundles against its downloaded packages before attaching them and
the full inventory to the existing release notes. The generated notes retain
the source revision, Mesh revision, build/run identity and package hashes.

For EAS, the worker hook captures native/compiler inputs in
the pre-install hook, then runs `worker-success` to bind the final IPA/APK/AAB. Archive discovery
resolves EAS profile/platform inheritance and `applicationArchivePath`, using
the documented platform defaults when it is absent. Missing, ambiguous or
outside-project packages fail; simulator directory archives need a separate
association policy. Owned fixtures cover default/custom paths and the
directory-shaped gzip TAR exported by the pinned public EAS formatter.
Expo's documented [`buildArtifactPaths`](https://docs.expo.dev/eas/json/)
exports the `plaintext-release` directory after the
[`eas-build-on-success` hook](https://docs.expo.dev/build-reference/npm-hooks/).
Using the directory itself avoids overlapping directory/file glob entries.
The pinned [EAS CLI 24.7.0 build fields](https://github.com/expo/eas-cli/blob/v24.7.0/packages/eas-cli/src/graphql/types/Build.ts)
include the build ID, source commit, project, profile and both artifact URLs.
The workflow queries `eas build:view` for that exact ID and downloads raw
application and custom artifact bytes. It does not select a latest build or
substitute a local fixture for a remote report.

Retrieval checks the finished build, project, platform, profile, source/Mesh
revisions, exact target set and the one application package hash. It retains
only the verified bundle, application package and sanitized build association;
temporary signed URLs and unrelated custom artifacts are excluded. Extraction
rejects traversal, links, special files, duplicate members, more than 4096
entries, and over 2 GiB of declared content. Downloads are bounded to 2 GiB.

The worker hook and production/staging configuration enable this export.
An older unconfigured branch keeps its existing release behavior and records
`pending_worker_evidence_configuration`, with no reviewed-inventory claim for
that build. Partial configuration fails. Configured builds with missing remote
evidence or a mismatch fail before the TestFlight submission step. Verified inventory is included in
the build summary, with a retained artifact link in build/TestFlight notes.
GitHub workflow artifacts currently retain this mobile evidence for 90 days;
this is not a claim of permanent public hosting. Hosted EAS transfer and actual
signed release execution remain external qualification gates; the local tests
exercise owned package/archive fixtures only.
