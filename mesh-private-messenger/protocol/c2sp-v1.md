# C2SP checkpoint profile

The Mesh protocol implements the v1.1.0 [signed-note](https://c2sp.org/signed-note@v1.1.0),
[checkpoint](https://c2sp.org/tlog-checkpoint@v1.1.0) and
[Ed25519 cosignature](https://c2sp.org/tlog-cosignature@v1.1.0) formats.
The directory now serves the signed RFC note through the versioned routes in
[key-transparency-v2.md](key-transparency-v2.md). Registry admission and push
jobs are implemented in Mesh and verified against an independent witness.
Native and operational rollout remain gates; no production cutover is claimed.

The main-log note text has exactly four LF-terminated lines:

```text
morseapp.io/log/main/v2
<canonical decimal tree size>
<canonical padded base64 RFC 6962 root>
morse-checkpoint <canonical padded base64 KTK v2>
```

An empty line separates this text from signature lines. A log signature uses
the origin as its key name and Ed25519 signature type `0x01`. A witness uses
its registered C2SP name and type `0x04`; its payload is an eight-byte unsigned
big-endian POSIX timestamp in seconds followed by the 64-byte signature. Its
signed message prepends `cosignature/v1\ntime <seconds>\n` to the exact note
text, including the Morse extension. Unsupported signature algorithms cannot
count as witnesses. In particular, an algorithm that authenticates only the
first three lines does not authenticate the complete Morse checkpoint.

`Transparency.C2sp` signs notes, parses notes and signature-only responses,
verifies pinned service keys, and resolves a witness signature against its
exact trusted name, Ed25519 algorithm and public key. Unknown keys are ignored;
a matching key with a bad signature is rejected. Duplicate name/ID pairs,
noncanonical base64, extra body lines, inconsistent size/root/KTK fields, CRLF,
missing final newlines and more than 16 signatures are rejected. Input is
bounded to 196,608 bytes before parsing; unknown signature payloads are bounded
to 8,192 bytes each. The bound accommodates 16 large unknown signatures without
allowing them to count toward a quorum.

Migration 023 adds the operator-provisioned C2SP `note_name` and a verified
cosignature timestamp used by current-log health. The push registry includes
active C2SP endpoints regardless of operator ownership. `jobs.mjs` invokes
the authenticated Mesh push handler; Mesh constructs the request, validates
one canonical 409 size retry, fetches its stored-node consistency proof, and
admits the returned signature. Admission re-reads the active registry row under
lock, so a retirement or key/name change during the network request takes
effect before storage. Re-signing the same checkpoint with a later timestamp
can refresh its cosignature; an older timestamp cannot replace it.
An outside witness can also POST one standard signature line to
`/v2/transparency/witnesses`. Mesh matches its name and type-4 key identifier
against the active registry, then verifies it against the current RFC
checkpoint. The caller cannot supply a checkpoint or a replacement public key.
Duplicate lines, stale signatures and legacy-route submissions are rejected.
The active RFC job retains a 15-second durable deadline to refresh an idle log.
`MORSE_C2SP_PUSH=off` (the default) stops C2SP pushes at both the job and Mesh
handler boundaries; enabling it requires an explicit operator setting.

`Transparency.C2spText` handles the canonical body and cryptographic cosignature
verification without a clock dependency. Authorization separately checks the
signed cosignature timestamp: at most five minutes old or one minute ahead.
This separation preserves later fork-evidence verification. Callers must also
verify the KTK's service signature and the normal account/freshness rules.

## Morse attestations and accountability

After admission verifies the registered name and key, Morse identifies the
witness by its native pinned ID/key. `WitnessAttestation.signature` contains
64 bytes for a native attestation or the 72-byte timestamped Ed25519 C2SP
payload. Native signatures bind the ID and checkpoint hash; C2SP signatures
bind the fixed log origin and full canonical note. C2SP signatures never count
for a legacy hash-profile checkpoint.

`KTW` v1 remains byte-for-byte unchanged for all-native lists. Lists containing
a C2SP signature use v2: each entry adds an algorithm byte after its checkpoint
hash, `0` for a 64-byte native signature or `4` for a 72-byte cosignature. IDs,
lengths and the 16-entry limit are unchanged. The maximum frame is 2,774 bytes.
The decoder requires the version chosen by canonical re-encoding. Mixed
quorums are allowed; repeated IDs count once, and invalid copies cannot conceal
a later valid signature. Native pins continue to require distinct keys.

Mobile and CLI authorization apply the cosigner's freshness window as well as
the checkpoint's. Mobile persists attestations atomically with the verified
checkpoint and rechecks them before using a cached v2 view. A checkpoint with
a later timestamp cannot extend an expired witness authorization.

Generic C2SP witnesses promise tree consistency and do not interpret the KTK
extension's sequence, previous-hash or timestamp semantics. They can therefore
be implicated by equal-size root forks and contradictory inclusion proofs,
but not by a kind-3 Morse metadata fork. Such a proof still implicates the
directory and native witnesses signing both views. An authenticated ring
reader must identify which cosigners used native signatures before a kind-3
proof can attribute them. It cannot infer that from a key alone.

## Independent interoperability

Run `node --test mesh-private-messenger/scripts/c2sp-interop.test.mjs` from the
repository root. It needs Go 1.26 and the locally built Mesh compiler (`MESHC`
can override its path). The Go harness imports the unmodified public
`transparency-dev/witness` implementation at commit
`b4c9458d9b14e5789285c5b68a7535d152c98de9`, pinned in `tests/c2sp-interop/go.mod`
with checksums in `go.sum`. It only supplies test keys, configuration and a
localhost HTTP listener; all witness behavior remains in that dependency.

The Mesh test signs a three-leaf checkpoint, receives and verifies the external
cosignature, advances to seven leaves with a compact proof, handles the standard
409 size response, and checks that bad proofs and same-size forks receive 422.
Keys are deterministic public fixtures. The harness has no production state,
binds only loopback, and is terminated after the test. This interoperability
proof passes; the application/service rollout remains a separate step.

With `MESSENGER_STORAGE_TEST_DATABASE_URL` naming a disposable `_test` database,
the same command also runs the directory integration. It applies every migration
to a new child database, seals and migrates a legacy tree, pushes the new tree,
advances it with a stored consistency proof, and verifies its admitted quorum.
The test drops that database afterward. The explicit operator commands and
release sequence are in [the cutover runbook](../ops/witness/cutover.md).
