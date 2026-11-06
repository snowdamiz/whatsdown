# Local compiled-Core RPC TLS acceptance

`ops/bootstrap/prove.py` builds this fixture with the qualified Mesh compiler and
both pinned runtime archives. The fixture imports the production MobileCore
exports unchanged. Its C bridge dispatches to those exports using the generated
ABI header. A separate process supplies platform resource bytes and disposable
key custody through the public host callbacks.

`acceptance.py` owns a direct HTTP directory and three HTTPS RPC peers. Each RPC
peer has a different disposable CA. The directory signer and evidence generator
run inside compiled Mesh. Python serves their encoded responses and records the
requests. The CA files never enter a system trust store.

The native resource callback serves `messenger/rpc-tls-roots/v1` as raw bytes.
Physical absence produces exactly `01 00`. Present resources use the complete,
sorted origin set and SHA-256 of the canonical security frame. Only RPC requests
receive these roots. The owned directory retains explicit direct mode.

Run from the repository root with a fresh evidence directory:

```sh
python3 mesh-private-messenger/ops/bootstrap/prove.py \
  --compiler /Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts/bin/meshc \
  --mesh-source /Users/andreyyurlov/Documents/dev/mesh-lang \
  --evidence-dir .morse/rpc-tls/green/unique-run \
  --keep-work
```

The runner records source hashes, the exact compiler family, build commands,
artifact hashes, and the local result. Source drift fails the run. The local
result includes hashes for the public fixture, resource callback trace, and
HTTP event trace. Disposable custody, databases, and private CA keys remain in
the private work directory and are never committed as evidence.

The result classes have distinct exit statuses:

| Result | Exit status | Meaning |
| --- | --- | --- |
| `PASS_LOCAL_RPC_TLS` | 0 | Every declared local acceptance assertion passed. |
| `BUILT_NOT_RUN` | 0 | Compilation succeeded with `--build-only`. No behavioral qualification. |
| `FAIL` | 1 | A build, assertion, source check, or runner failed. |
| `INCOMPLETE_LOCAL` | 2 | A local result explicitly reports incomplete coverage. |
| `BLOCKED_NATIVE_RPC_TLS` | 3 | A local result explicitly identifies the missing native RPC TLS path. |

Every production check remains `pending`, including after a local pass. The
historic red runner used exit status 1 for its blocker.

Primary acceptance uses actual `mesh_messenger_create_account`,
`mesh_messenger_directory_resolve`, and `mesh_messenger_anchor_check` calls. A
successful result must be `consistent` and have matching checkpoint, view,
witness, leaf, and origin cache records. The HTTP trace must show finalized
header, log, entry, time, header reread, and directory checkpoint-proof paths.
The process restart check terminates process A, starts process B with the same
database and custody, and verifies `previous_tree_size=1` plus the retained
result and reservation.

The remaining cases exercise malformed and mismatched resources, failed CA
trust, quorum tolerance, redirects, signature corruption, slash refusal, and
resource or account replacement while an actual TLS response is blocked. The
failed-response barrier closes the accepted TLS connection before response
headers, so it exercises the `Http.send` error branch. Events release barriers;
fixed sleeps do not select the race.

`bootstrap_schedule_snapshot` reads the persisted state using the existing
public-log identity. It constructs a WebPki transport only to derive that
identity and never sends it. This observer remains usable with malformed roots.
`bootstrap_batch` and `bootstrap_tls_pool` are supplementary shared-reader and
runtime proofs in the same compiled library. They do not replace native C ABI
acceptance. `bootstrap_anchor_due` uses explicit time on the public Mesh checker
and cannot qualify the production C ABI's wall clock.

`local-result.json` lists unexecuted boundaries. This fixture does not qualify
native platform packages, phone UI, production RPC services, funded accounts,
or deployment.
