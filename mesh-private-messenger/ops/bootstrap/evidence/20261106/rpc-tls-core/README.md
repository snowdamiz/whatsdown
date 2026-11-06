# Compiled-Core local RPC TLS qualification

The final run at `3293d90dc3a21dbb72098b407c3fa1cbdfcaa233` passed all 37 local
checks with process exit 0. Both compilation and acceptance were fresh. The
qualified Mesh source is `8256d5d30e79f3c1de9d8507f8607f8efbee756a`.

The actual MobileCore C ABI creates an account, resolves a signed directory
entry, commits verified checkpoint, view, witness, leaf, and origin records,
and returns `consistent` from `mesh_messenger_anchor_check`. The primary path
records ten finalized RPC HTTP requests, including header, log, entry, time,
and header reread, plus the directory checkpoint-proof request. The complete
run records 81 RPC HTTP requests across its cases.

The generated ABI and header contain all 176 production exports and nine
fixture exports. The source declaration set equals the production ABI set.
The runner records each artifact hash in `receipt.json`.

The local controls cover signature corruption with unchanged cache, a real
process restart with `previous_tree_size=1`, retained result and reservation,
three independent CA roots, wrong origin, port and suffix, failed CA trust,
malformed frame and PEM, exact absence, mixed WebPki policy, quorum tolerance,
redirect refusal, and runtime root-pool isolation. Four actual TLS response
barriers replace the companion or account on success and transport-error
branches. Each barrier records exactly one RPC before refusal and no cache
completion. The dedicated redirect target receives zero TLS connections.

Root rotation preserves the public-log schedule, slash refusal, and mismatch
refusal. The next-due slot-floor proof uses explicit time on the public Mesh
checker. The production C ABI wall clock remains an unrun boundary.

`verification.json` records the independent hash and source checks. All 199
public fixture files, generated header, ABI, compiled artifacts, and current
production, fixture, Mesh-package, and runner source hashes matched. The
package source closure excludes `tests` directories and `.test.mpl` files.
Full `meshc lint mesh-private-messenger` produced no output and exited 0.

`rpc-tls-local-20261106.json` contains the complete fresh-or-reused run matrix,
original bootstrap red, check rows, artifact hashes, and unrun boundaries.
All eight production checks remain `pending`. Native platform packages,
phone UI, funded or external RPC, bounded native context qualification, and
production deployment are outside this local result.

The retained build family is:

```text
.morse/rpc-tls/green/final-r4/bootstrap-native-bc_ocwa8
```

The full raw evidence remains in `.morse/rpc-tls/green/final-r4`. To verify the
committed public copies against that retained family and current source, run
from the repository root:

```sh
python3 mesh-private-messenger/ops/bootstrap/evidence/20261106/rpc-tls-core/verify-receipt.py
```

`SHA256.json` hashes the committed public files. The retained family includes
the compiled library and disposable private fixture resources. Those private
resources are not in this evidence directory. Earlier diagnostic build,
custody, and PKI directories were removed after their hashes were verified.
The parent owns the retained baseline red and final-family cleanup.

The reporting regression is preserved under `classification-red`. That run
passed its local behavior checks, then exited 1 with `AssertionError: runner
drift`. Its original receipt incorrectly retained `PASS_LOCAL_RPC_TLS`.
`classification-red/verification.json` records the actual `FAIL` without
rewriting the raw receipt. Commit `3293d90` resets the receipt to `FAIL` on any
exception. The final fresh run uses that correction.
