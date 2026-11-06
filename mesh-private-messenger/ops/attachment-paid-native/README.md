# Owned funded native ACH3 proof

This slice closes the gap between the material-only native ACH3 writer proof and
an actual purchased credit spend. It uses explicit pinned protocol/source,
native library, ABI/report, material qualification and compiler/runtime inputs,
with no extra native exports. Core, privacy edge and
object-store are built from a frozen copy of current service sources. A narrow
proof-only Core router creates/cosigns the normal log cutover and issuer
admission; native accounts and their device credentials are registered through
the normal directory API.

Build once into a new work directory, then coordinate both OS test windows:

```sh
python3 ops/attachment-paid-native/build.test.py
python3 ops/attachment-paid-native/qualification.test.py
python3 ops/attachment-paid-native/build.py --work /absolute/new-paid-proof --qualification /absolute/pinned-qualification.json --jobs 1
PATH=/opt/homebrew/opt/rustup/bin:$PATH python3 ops/attachment-paid-native/prove.py --work /absolute/new-paid-proof --run-id first
```

Work and qualification paths are required. Build refuses an existing work
directory; prove refuses an existing run ID; seal refuses an existing final
manifest. Prior archives, including `attachment-paid-native87085`, remain
immutable. Preserve failed work/run directories and choose fresh ones for retry.
Sealed source inputs may be read-only. The builder makes only its new source
copies writable before rebasing dependency paths and inserting fixture routes;
the original source files and their permissions remain unchanged.

The qualification JSON has schema_version1 and records `closure`,
`source_manifest`, `native_manifest`, `material_qualification`,
`canonical_report`, `expected_abi`, `compiler`, `runtime`, `expected`,
`issuer_root` and `issuer_files`. Every named file input is an absolute
`{"path":"...","sha256":"..."}` pin. `expected` explicitly fixes
`exports`, `modules` and `sites`; `issuer_files` pins the complete relative
source map of the deliberately reused issuer. An optional `prior_funded_archive`
file pin rechecks the immutable prior checkpoint.

An optional `source_packages` map selects the relative directories for
`mesh-binary`, `mesh-solana`, `mesh-lightning` and `messenger-protocol` inside
the pinned closure. This supports a combined checkout checkpoint without
rearranging its qualified inputs. Absolute paths, parent traversal, symlink
escapes and mismatched package names are refused. Omission preserves the
historical flattened layout. The owned service snapshot gets its public-package
aliases before compilation; copied dependencies must resolve inside that
snapshot. Original source bodies and manifests remain unchanged.

Source manifests use the full `files: {absolute_path: {sha256: ...}}` mapping.
The manifest must describe the entire selected closure: changed, missing and
extra Mesh/manifest/migration source files fail. Full checkpoints may also pin
native hosts or other non-Mesh files; their recorded bytes are checked too.
Every native target artifact hash, full canonical
source/site inventory and complete ABI are rechecked; the ABI may differ only
in its target. The material qualification must bind the same source manifest,
compiler, canonical report, production exports and disclosure-site count.
Neither a matching count alone nor a rehashed changed native report is accepted.
Build, prove and seal revalidate the same immutable qualification.json copied
into the work directory, its hash, services, native bodies and toolchain.

The metadata27 run selects the explicitly adopted483-file source manifest,
246production modules,27reviewed metadata sites,162production exports and the
frozen compiler SHA-256
`25a8e3f78695e3c190bc2fc153c5294336451c3b120564ceca6f0e33c6333ef1`.
Its explicit configuration and qualification regression logs are under
`.morse/witness-proof/attachment-paid-native-metadata27-preflight`;
the fresh build/run/seal destination is
`.morse/witness-proof/attachment-paid-native-metadata27`.
These records do not rewrite or requalify a prior archive.

After a successful run, archive and independently verify its exact input bodies
and artifacts with `python3 ops/attachment-paid-native/seal.py --work
/absolute/new-paid-proof --run-id first`.

Both native wallets use real Keychain/Keystore callbacks, durable blinding state
and the actual local Mesh issuer/LND regtest flow. Each buys100 credits and waits
at least600 real seconds. A fresh genuine service/witness checkpoint is then
produced. Production native recipient preflight resolves the real signed device
sets and emits the authorization ticket before credit reservation.

For each OS, the native host invokes the real per-part Mesh writer257 times for
a16MiB+1 attachment. An incomplete file cannot reach the grant endpoint. The
actual object store forwards the credit authorization to the consuming Core,
which records one spent token/effect and signs its immutable receipt. Tampered
and dropped replies leave the original local reservation and ciphertext intact
through process restart; replay repairs the same operation. The native client
uploads the manifest and257 durable ACH3 parts, completes with bounded progress,
and downloads/decrypts the first/last parts. A dropped committed PUT is retried
using the same saved bytes; a forged ciphertext is rejected.

A distinct fully staged operation receives an injected pre-upstream503. The
reservation stays held through another real 600-second action expiry. A forged
cancellation cannot release it. Only an authenticated Core non-consumption proof
restores the credit; terminal recovery performs no HTTP and cannot grant the
cancelled operation. PostgreSQL checks enforce two completed effects/objects,
516 stored parts and no extra spent credits across the two native wallets.
The two elapsed windows are measured separately with monotonic time and both
must be at least600seconds before seal accepts the evidence. Three temporary
PostgreSQL clusters are initialized on private ephemeral ports;55438 and61546
are explicitly excluded. Service binaries and module reports must still match the
frozen service closure, and the exact build/proof/helper bodies are archived
by hash alongside native artifacts and results.

The owned HTTPS gateway forwards to real services and injects only transport or
response failures. It never fabricates an accepted grant, credit, device set or
receipt. No bearer frames, wallet databases, signer secrets, TLS private keys or
native seed material should be archived. Keep exact source bodies, binaries,
public native trust resources, request/response digests and final assertions.

All funds and nodes are local Bitcoin/LND regtest fixtures. The price account is
an explicit RPC fixture, not a Pyth guardian proof. This is simulator/emulator
ABI and OS-custody evidence, not physical-device or rendered confirmation UI
acceptance, production deployment, activation or live funds authorization.
The fixture's signed witness is owned test material; it does not establish a
real independent operator or a live network qualification period.


## Padded profile4 qualification

The qualification JSON explicitly selects `"wire_profile": 4` with `"expected": {"exports": 163, ...}`. Its pinned material manifest must be the new profile4 material status with matching explicit profile/count, exact source/compiler/report pins, and the same selected native artifacts. Omitting the profile or supplying an ACH3 material result cannot relabel a163-export successor. Historical qualification JSON without this field remains profile3/162 only.

Build, prepared host, runtime result and seal all retain the same selection. Swift/Kotlin receive the selected fixture wire version solely to validate every staged frame; the plaintext final input remains one byte. For profile4, all 257 chunks must be65,576 bytes, the encrypted manifest514 bytes, and the final download exactly one byte. Python validates the same public framing and records the observed shapes. The real 600-second maturity and separate 600-second cancellation expiry, actual issuer/Core/object-store effects, receipt/replay checks and exact selected native source/ABI/site checks are unchanged. No budget, clock bypass, funding authority or default toolchain pin is added.

Python orchestration/unit success does not establish the new native behavior. A fresh profile4 material seal and actual funded run/seal are prerequisites. Earlier profile3 proofs and their captured source remain immutable.


The focused funded callback regression is `python3 ops/attachment-paid-native/callback.test.py`. It executes the actual callback entry up to an intercepted database boundary without opening a service or native app. It also validates exact unique cancellation-inventory selection. This protects the profile capture from local inventory-name shadowing; it does not replace the actual funded execution gate.
