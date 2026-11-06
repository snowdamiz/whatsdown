# Local bootstrap native boundary

This is a reproducible **local synthetic fixture**, bounded to one public canary,
`morse-canary-1`. It does not qualify a native phone, independent RPC providers,
or production acceptance. All eight WITNESS §4.3 production checks remain pending.

The current unit is **blocked**, and its acceptance command exits **1**. Current
native release configuration requires HTTPS anchor RPCs, but the current
`Transparency.AnchorRpc` request builder has no input for an owned local CA.
The native anchor result is `rpc_unavailable`, never mapped to success.
Production source, release pins, generated app bindings and WITNESS plans are
unchanged. Coordinate a generic origin-bound trust-root input with the parent
and the AnchorRpc owner before changing that production path.

Run from the repository root on macOS with Python 3, OpenSSL and the C compiler:

```sh
python3 mesh-private-messenger/ops/bootstrap/prove.py \
  --compiler /path/to/qualified-8256/release-artifacts/bin/meshc \
  --mesh-source /path/to/mesh-lang \
  --evidence-dir /path/to/new-local-evidence
```

Use the clean Mesh source `8256d5d30e79f3c1de9d8507f8607f8efbee756a`.
The runner requires the exact qualified compiler/runtime/test-runtime hashes
from that family and copies all three into its own temporary directory. The
runtime archives must be in `../lib` relative to the compiler. It snapshots
MobileCore and protocol sources, changes only copied dependency paths, and
builds an optimized native library. It compiles `abi_host.c` against that build's
generated C header. Actual exported Core calls go through this C bridge.

`--keep-work` retains disposable databases, custody, certificates and artifacts
for debugging. Otherwise the runner retains hashes and receipts, then removes
its own temporary directory, including synthetic private keys. It never removes
a shared target. `--build-only` compiles without acceptance and reports
`BUILT_NOT_RUN`; this is not a pass. Use a new evidence directory per run.

The boundary checks run as follows:

1. Create a disposable canary through `mesh_messenger_create_account` and read
   its actual directory entry. Mesh generates the signed RFC-log evidence,
   two witness signatures, explicit configuration and anchor account fixtures.
2. Start one HTTP directory peer and three HTTPS RPC peers, each bound to
   `127.0.0.1` on an allocated port. Mesh validates lookup proof of work and
   decodes the request in a separate fixture process. Python forwards bytes
   and adapts the synthetic RPC account responses; it does not sign evidence,
   verify messenger proofs, or populate the verified cache.
3. Exercise `mesh_messenger_directory_resolve` with the native platform-key
   callbacks and an initially empty cache. Compare the returned device set to
   the Mesh-generated fixture and read the committed checkpoint, view,
   witnesses, leaf proof and origin through read-only Mesh helpers.
4. Serve a well-framed corrupted directory signature. Require the native
   application error `transparency_verification_failed` and byte-identical
   prior cache. Restart the client process, repeat the real lookup and require
   the request's persisted `previous_tree_size=1` continuity basis.
5. Call `mesh_messenger_anchor_check`, inspect its structured result and
   encrypted schedule through Mesh, restart again and require the exact
   retained result, completed claim and no additional request during the
   reserved interval. This currently persists an **unavailable result**, not a
   successful daily check.
6. Prove all three HTTPS peers are ready using Mesh's existing explicit
   request-root primitive. Prove the native configuration refuses HTTP RPCs.
   The actual anchor path reaches none of the peers' HTTP handlers; the
   acceptance gate requiring `consistent` fails.

OHTTP is explicitly **off**, bound to the exact native network/security frames.
This chooses the smallest current integrated direct-origin path; it still
executes native OHTTP policy capture, signed lookup admission, verification,
cache commit and continuity. Required-mode transport is a separate qualification
and is not inferred from this run.

Pending local controls: a valid `consistent` anchor, missing-cache `observed`
control, incorrect/stale/forged anchor, quorum disagreement/unavailability after
successful transport, and advancement across a daily boundary. Three canaries
are also deferred. Even if a future transport change yields `consistent`, this
runner reports `INCOMPLETE_LOCAL` and exits 1 until those required controls are
implemented. The three loopback origins never count as independent providers.

`receipt.json` records exact source/compiler/artifact/result hashes;
`sources.json` contains the source manifest; `local-result.json` contains the
bounded public observations. None of these artifacts is production evidence.
