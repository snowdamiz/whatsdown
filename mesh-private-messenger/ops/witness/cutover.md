# RFC log cutover

The local implementation and proofs are complete for the main-log transition.
No production activation, new witness host, image publication or native rollout
is implied. Finish the release gates before running these commands against a
production database. Canary logs and chain integration are separate phases.

## Prepare the release

1. Publish the reviewed Mesh revision and build the service image from that exact
   revision. The image includes `/app/transparency-cutover`; it shares the
   directory's Mesh storage operations. For local development, build it with
   `meshc build mesh-private-messenger/tools/transparency-cutover --output transparency-cutover`.
2. Apply all directory migrations through `024_rfc_retention.sql`. The migration
   runner includes digits in migration names. Installation alone never activates
   or seals a log.
3. Ship the native v3 security policy, with separate current and legacy witness
   sets. Install its canonical `MESSENGER_SECURITY_CONFIG` on Morse witnesses.
   Their existing service-key pin must match it. The app and witnesses continue
   using legacy evidence before activation, then persist a one-way transition.
4. Configure C2SP registry rows with `software='c2sp'`, the witness's exact
   signed-note `note_name`, Ed25519 public key, and HTTPS `push_url` ending in the
   implementation's add-checkpoint route. Start outside witnesses in shadow
   status. Setting `morse_run=false` does not disable C2SP pushes. The registry
   never supplies phone trust.
   Set `MORSE_C2SP_PUSH=on` on the jobs Worker and directory container to enable
   pushes; its default `off` is enforced at both boundaries.

Use the public v3 frame produced by the native configuration writer; do not
reconstruct a witness set from a directory response. Keep the final legacy
policy available independently of later registry changes. The operator tool
requires `MESSENGER_DATABASE_URL`. Mutations require the v3
`MESSENGER_SECURITY_CONFIG`; prepare/resume also require the directory's existing
`MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX` through the ordinary secret-injection
path. The seed is never an argument or command output. Status needs no signer.

## Run the transition

Run one command at a time using the reviewed executable and provisioned
configuration:

```sh
transparency-cutover status
transparency-cutover prepare
transparency-cutover accept
transparency-cutover resume 100
transparency-cutover status
```

`prepare` seals the exact signed legacy checkpoint and enters `sealing`.
Registrations, renewal, revocation and device departure return the temporary
migration error while the log is being copied. Account deletion remains
available and removes copied and uncopied account material. The legacy
checkpoint endpoint continues returning the seal, allowing its native witnesses
to sign it. Complete quorum acceptance promptly: witnesses enforce their clock
window, and a sealed checkpoint is never refreshed or re-signed with a later
clock just to obtain a quorum.

`accept` verifies the seal against the release's service key and obtains the
required legacy signatures already stored in the database. Each ID and key
comes from the supplied historical release policy; a newer registry cannot
replace it. Missing signatures leave the operation in `sealing`. A verified
quorum is stored with the seal and its bridge becomes RFC leaf zero.

`resume N` commits one batch of at most N current account entries (1–100;
default 100). Repeat until the JSON status reports `phase: "active"`. The
`copied_through` cursor is a database sequence, not a percentage. The final batch
activates the RFC tree and creates its first signed checkpoint in the same
transaction. Repeating a command after success is safe; an interrupted batch
rolls back and the next process resumes from durable state. There is no rollback
command. Investigate a stuck transition without editing its seal or cursor.

Status also returns `rfc_tree_size` and the public `legacy_checkpoint_hex`.
Retain the latter independently for incident review. Keep the legacy nodes and
accepted seal/quorum: returning clients use a bounded consistency/inclusion
bridge to authenticate the new history.

## Verify the active log

- `/v2/transparency/checkpoint` returns KTK v2 and the note endpoint returns the
  fixed `morseapp.io/log/main/v2` origin. The legacy route still returns KTK v1.
- The authenticated jobs path invokes C2SP pushes through Mesh. Mesh produces
  the note and proof, permits one canonical 409 size retry, refuses redirects,
  and rechecks the active registry row before admission. It admits only the
  registered name/key and a fresh type-4 cosignature. Native submission endpoints
  accept only native signatures from Mesh rows.
  An outside witness may submit one standard signature line directly to
  `/v2/transparency/witnesses`; it is verified against the current RFC checkpoint
  and the active registry's exact name/key.
- Health includes `log_version` and `phase`; RFC quorum counts use fresh
  signatures on the current RFC checkpoint. Expired cosignatures, retired keys,
  wrong algorithms and legacy signatures cannot keep that quorum green.
- The RFC job schedules its next durable wakeup after 15 seconds and refreshes
  idle checkpoints under the normal checkpoint policy. C2SP push mode therefore
  does not depend on a native pull witness or a user's account lookup. Migration
  024 extends the existing pruning budget to both checkpoint tables while
  protecting each log's own anchors and latest checkpoint.
- A migrated phone and witness refuse legacy response substitution, an older
  local policy and RFC disappearance. A phone with old group anchors verifies
  them through its retained migration bridge.

Local verification commands (the database URL must name a disposable `_test`
database; the tests create and drop their own child databases):

```sh
node --test mesh-private-messenger/scripts/cutover-command.test.mjs
node --test mesh-private-messenger/scripts/c2sp-interop.test.mjs
```

Set `MESSENGER_STORAGE_TEST_DATABASE_URL` and provide `psql`, Go 1.26 and the
current Mesh compiler (`MESHC` may select it). The C2SP proof uses the unmodified,
commit-pinned `transparency-dev/witness` implementation over loopback. It verifies
both the protocol codec and a real migrated directory tree, including the
standard 409 consistency retry and stored, fresh cosignature quorum.
