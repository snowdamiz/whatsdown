# Pull witness operations

This implementation is under local verification. No witness C host, published
image, native B1 release, or seven-day production acceptance run is claimed.
The planned bootstrap placement is a Hetzner VPS in Germany, separate from the
Cloudflare account. It needs outbound HTTPS and accurate UTC time; it exposes
no signing or administration HTTP endpoint.

The versioned RFC transition is implemented separately and remains an explicit
release/operator action. See [the cutover runbook](cutover.md) for the native v3
policy, durable witness transition, C2SP registry and operator commands.

## Build and verify

The witness uses the public Mesh `File.sync` and `File.rename` APIs. Publish and
pin a Mesh release containing them before building a production service image.
Use the same reviewed Morse/ Mesh revisions as the backend verification job;
the service image must contain both revision labels. `prepare-build.mjs` adds
the Morse revision in release jobs through `GITHUB_SHA`.

The wrapper packages an **immutable, already verified** Linux service image.
It performs no package installation and no source download. Set
`MORSE_SERVICES_IMAGE` to its full `repository@sha256:…` reference,
`MORSE_REVISION` and `MESH_LANG_REVISION` to their full commit SHAs, and
`SOURCE_DATE_EPOCH` to the Morse commit's Unix timestamp. Then run:

```sh
node mesh-private-messenger/ops/witness/package.mjs .morse/witness-package
```

Use a Buildx builder with the `docker-container` driver and a Docker client/server
supporting `image inspect --platform`. The command verifies the Linux x86-64
base image's revision labels, exports `witness.oci.tar` and `relay.tar`, records the inputs
and Buildx version in `inputs.json`, and writes `SHA256SUMS`. Rebuild in a second
empty directory with identical inputs and the same Buildx version, then compare
checksums before publishing. Packaging argument/provenance tests are included;
a real release-image reproducibility comparison remains a release gate.
Timestamp normalization follows Docker's [reproducible build settings](https://docs.docker.com/build/ci/github-actions/reproducible-builds/)
and [OCI exporter](https://docs.docker.com/build/exporters/oci-docker/).

## Relay tool included in the package

`relay.tar` contains the standalone JavaScript relay, its exact npm lockfile,
configuration example, runbook and the Linux x86-64 `morse-fork-verifier` binary.
Both the source and binary are extracted from the same verified service image;
the packager never substitutes a local checkout. Archive creation runs only GNU
tar with networking disabled and no wallet mounts, normalizing timestamps and
ownership. An older image missing the relay fails packaging before `SHA256SUMS`
is written. Include this archive when distributing the witness package, even
when a particular witness operator chooses not to fund a relay.

Verify `SHA256SUMS`, extract the archive into an operator-owned installation
directory, and run `npm ci --ignore-scripts` inside its `morse-relay` directory
with supported Node (Node 24 in CI). Set the relay configuration's
`verifierBinary` to the absolute extracted `morse-fork-verifier` path. Follow
`morse-relay/RUNBOOK.md` for the private funded wallet, persistent journal,
cluster/security pins, HTTPS edge, limits and upgrades. The relay wallet is
separate from witness checkpoint signing material. The witness container itself
does not run the relay or receive its wallet. Other platforms need a native Mesh
verifier built and qualified for that platform.

The Docker archive proof builds the actual `relay-sources` stage, checks that
local secret files and tests are excluded, compares two timestamp-normalized
archives, and loads the unpacked CLI after a locked dependency install. It uses
a deliberately fake native binary, so it proves packaging and JavaScript module
completeness, not a production Linux verifier or release-image reproducibility.
A complete published bundle still needs the reviewed service image, exact Mesh
release, native ABI validation and the second release rebuild comparison.

## Configure and start

Generate the signing seed on the operator's host using the release's supported
key-generation tooling. Keep it off Morse's systems. Give Morse only the ID,
public key, operator label and software type for the registry. Registry
membership does not grant phone trust; only a native release can pin a key.

1. Create `/etc/morse-witness` owned by root with mode 0700. Copy
   `config.env.example` to `config.env`, replace every placeholder, and set mode
   0600. Use the actual HTTPS directory origin and the release-pinned service key.
2. Create `/var/lib/morse-witness`, owned by UID/GID 65532, mode 0700, on a
   persistent local filesystem supporting atomic rename and directory sync.
3. Write `MORSE_WITNESS_IMAGE=repository@sha256:…` in
   `/etc/morse-witness/image.env`. Install `morse-witness.service` and start it.
   The container publishes no ports and writes only its state volume and `/tmp`.
4. For a genuinely new signing identity, the first start uses
   `WITNESS_INITIAL_CHECKPOINT_HEX=new-identity`. After its first checkpoint is
   durable, remove that line and restart. Missing history then refuses signing.
5. For an existing identity, transfer its latest independently verified 188-byte
   checkpoint as 376 lowercase hex characters in that variable. Never reset an
   existing signing identity to `new-identity`. Existing local history always
   takes precedence over this bootstrap input.

The process polls every 15 seconds after each attempt. Network failures retry;
SIGTERM stops polling promptly. A repeated checkpoint may be retried only while
fresh enough to sign. An unchanged checkpoint older than 60 seconds is refused
until the directory's four-minute refresh. This can log a clock-skew rejection
even with correct clocks; distinguish it from a new checkpoint outside the
60-second window. Polling the directory refreshes an idle tree without requiring
a user's lookup, preserving its root and linking to the prior checkpoint.

## State and incident handling

`checkpoint` contains canonical base64 of the signed checkpoint. A SQLite
`checkpoint.lock` sidecar serializes processes while Mesh compares the exact
previous checkpoint, writes `checkpoint.pending`, syncs it, renames it, and
syncs the parent directory. A crash before rename leaves the old state; a
failed sync or compare releases no signature. The next run reads the durable
state before retrying publication. Never unlink lock files while a process is
running, or put the state volume on a filesystem whose locks are unreliable.

The first signed timing rejection and first history rejection are retained in
`checkpoint.evidence-timing.json` and `checkpoint.evidence-history.json` (at most
2 KiB each), with their own lock sidecars. These contain only public signed
checkpoints and a reason. The HTTP state store used by Cloudflare has equivalent
private `/evidence/timing` and `/evidence/history` slots. A timing rejection
cannot overwrite a history record. Export and investigate a record before
removing its slot. Captured failures are not automatically slashable fork proofs;
FRK conversion and relay filing are separate phases.

A stale concurrent writer is refused. Restoring an entire older machine or
state volume cannot reveal history that was also lost from that backup: stop
signing and reconcile it with independently retained checkpoints before recovery.
Never operate two independent state volumes for one signing key. Back up a
stopped, reconciled state volume and keep public checkpoints independently.

## Directory registration and rollout

Apply migration `017_witness_registry.sql` before starting the new directory.
On an empty registry only, startup seeds the existing A/B public keys as Morse
pins. It never overwrites a populated registry. For isolated Workers,
`WITNESS_A_URL` and `WITNESS_B_URL` seed their `/attest` endpoints. The `.internal`
bootstrap URLs serve only the older local-binding mode; explicitly update them
when switching an existing registry to isolated Workers.

Add a new operator row as `shadow`, `software='mesh'`, with `push_url=NULL` for
pull mode. Set `morse_run=true` for witness C and `false` for outside operators.
The database requires a unique ID/key, printable operator label, and an explicit
retirement timestamp for retired entries. Administrative registry changes use
the existing authenticated database operations path, never a public write API.

`GET /v1/transparency/registry` publishes ID, key, operator, status and software.
Attestations from active rows are verified against their registered key; retired
keys cannot submit or appear in current evidence. At most 16 signatures are
returned, pinned first and then the most recently added shadow entries.

The jobs Worker reads the authenticated push registry. Arbitrary Morse-run push
IDs use `MESSENGER_WITNESS_PUSH_TOKENS`, a JSON object from ID to 64-character hex
invocation token. Existing A/B secret names remain supported during migration.
Pull-only registries make no push calls. An unavailable minority does not fail a
job when registered pinned witnesses still meet the current checkpoint's strict
majority. The public health JSON reports that threshold, signature ages and
anchor lag from the job's cached observation. Missing anchors/observations are
`null`; expired health observations cannot remain green indefinitely.

Before B1 rollout: shadow witness C, verify continuity, publish the native 2-of-3
config, update the registry's pinned status, and run the seven-day acceptance
window plus the 15-minute outage drill. Keep Bootstrap labeling throughout.
No outside independence, bond, anchor or payment claims follow from this phase.
