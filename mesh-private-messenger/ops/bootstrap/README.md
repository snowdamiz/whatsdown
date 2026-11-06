# Local bootstrap native boundary

This is a reproducible **local synthetic fixture**, bounded to one public canary,
`morse-canary-1`. It does not qualify a native phone, independent RPC providers,
or production acceptance. All eight WITNESS §4.3 production checks remain pending.

The scoped RPC TLS milestone now passes locally. The recorded fresh run exits
**0** with `PASS_LOCAL_RPC_TLS`: 37 checks exercise actual Core functions inside
the bootstrap fixture library. Native `messenger/rpc-tls-roots/v1` resources
bind exact origins and roots to the security frame and captured operation;
`Transparency.RpcTransport` carries that authority through the shared readers.
The original `rpc_unavailable`/zero-HTTP failure remains in the older receipts.
See the [current qualification](evidence/20261106/rpc-tls-core/README.md) and
[implementation receipt](evidence/20261106/rpc-tls-implementation.json).

The fixture ABI contains 176 production symbols and nine fixture symbols. It is
not the exact product Main artifact or a signed/native-phone qualification.

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
5. Call `mesh_messenger_anchor_check`, require `consistent`, inspect its structured result and
   encrypted schedule through Mesh, restart again and require the exact
   retained result, completed claim and no additional request during the
   reserved interval. Root-only rotation must retain the public-log identity,
   budget, slot floor and authenticated slash/mismatch refusal.
6. Exercise exact-origin/frame/CA/PEM refusals, explicit WebPKI versus custom
   roots, two-of-three agreement, redirect refusal and root-pool isolation.
   Pause real TLS requests, replace the captured resource or account, then
   release successful and failed HTTP completions. All four old operations
   must refuse without replacing the verified cache. Fresh capture accepts
   the new immutable resource.

OHTTP is explicitly **off**, bound to the exact native network/security frames.
This chooses the smallest current integrated direct-origin path; it still
executes native OHTTP policy capture, signed lookup admission, verification,
cache commit and continuity. Required-mode transport is a separate qualification
and is not inferred from this run.

This runner's pass covers the scoped TLS milestone, not the full bootstrap
suite. Three canaries, broader missing-cache/invalid-anchor controls, phone/UI
and production acceptance remain separate. The next-due check uses injected
time through the public Mesh checker; the production C ABI next-day clock and
retained-mismatch retry under real wall time remain unqualified. Bounded native
capture has separate focused tests. Exact internal pre-dispatch/post-receive
pause points are not claimed. The three loopback origins never count as
independent providers.

Source, fixture or runner drift fails the command and its receipt. The retained
classification-red run exited 1 despite an old erroneous raw pass label; its
supplement records the failure, and the runner now overwrites status on an
exception. Always inspect the process exit status as well as the receipt.

`receipt.json` records exact source/compiler/artifact/result hashes;
`sources.json` contains the source manifest; `local-result.json` contains the
bounded public observations. None of these artifacts is production evidence.
