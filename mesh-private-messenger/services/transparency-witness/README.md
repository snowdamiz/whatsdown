# Transparency witness

The Morse key-transparency witness. It signs a directory checkpoint only after
checking that the checkpoint extends the last one it signed, and it never
signs two checkpoints that can't both be true. The protocol is in
[`protocol/key-transparency-v1.md`](../../protocol/key-transparency-v1.md) and
[`protocol/witness-network-v1.md`](../../protocol/witness-network-v1.md)
("Witness software"). Operators follow
[`ops/witness/README.md`](../../ops/witness/README.md).

## Compiler

The witness writes its state with `File.rename` and `File.sync`, which Mesh
v0.1.8 (the release CI builds with) does not have. Build and test it with a
compiler that does, currently the development build of `mesh-lang`:

```sh
MESHC=/Volumes/SSK-SSD/mesh-lang/target/debug/meshc
$MESHC test services/transparency-witness/tests
(cd services/transparency-witness && $MESHC build .)
```

`scripts/prove-m13.sh` builds the witness with `WITNESS_MESHC` (default: its
`MESHC`). This code can't merge to `release` until a Mesh release ships both
functions: the Cloudflare image and CI build the witness with the newest
release.

## Modes

`MESSENGER_WITNESS_MODE`:

- `once` (default): one round, then exit. The Cloudflare witnesses run this
  from their `/attest` Worker, which also enforces the start rule below.
- `pull`: a round every `MESSENGER_WITNESS_POLL_MS` (15 s) until SIGTERM. The
  witness polls `GET /v1/transparency/checkpoint` and posts to
  `POST /v1/transparency/witnesses`; it opens no port. A new checkpoint is
  signed within one poll of appearing, well inside the 60 s deadline.
- `restore`: replaces the state with the checkpoint in
  `MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX` and clears a halt. The checkpoint
  must carry the log's signature and be no older than the state or the guard.

A round:

1. Stops if the state has a halt marker (`<state>.halted`).
2. In pull mode, refuses a missing state unless
   `MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX` is `new-identity` (nothing signed
   yet) or the 376-hex checkpoint to continue from (an explicit transfer).
3. Halts ("stale state") if the host's guard (`MESSENGER_WITNESS_GUARD_PATH`)
   holds a newer checkpoint than the state: the state was restored from an
   older copy.
4. Fetches the checkpoint and checks the log's signature.
5. If it signed this checkpoint before, makes sure the directory holds the
   signature (submitting it again if not) and stops.
6. If the directory shows this witness's own signature on a newer checkpoint
   than the state holds, the state came from a backup or was lost: it halts
   ("stale state") and names that checkpoint in the marker.
7. Checks history against the last signed checkpoint: no rollback, no second
   checkpoint at one sequence, the previous-checkpoint hash intact at the next
   sequence, and a `KTC` v2 consistency proof (v1 only if the directory
   refuses the v2 query). Any failure is kept as evidence, halts the witness
   and, when the two checkpoints alone prove a fork, files an `FRK` with the
   relays.
8. Refuses (without halting) a checkpoint stamped more than 60 s from its
   clock or not later than the last one it signed.
9. Writes the checkpoint to the state (compare-and-swap, crash-safe) and the
   guard, then signs and submits. A failed submission is retried next round.

Exit codes: `0` done, `1` error, `3` halted (the witness refuses to sign until
an operator restores continuity; systemd doesn't restart it).

## Environment

| Variable | Meaning |
|---|---|
| `MESSENGER_WITNESS_MODE` | `once` (default), `pull` or `restore` |
| `MESSENGER_BASE_URL` | Directory origin, `https://` (or `http://` inside a private network) |
| `MESSENGER_WITNESS_ID` | Registry ID, `[a-z0-9-]{1,64}` |
| `MESSENGER_WITNESS_SIGNING_SEED_HEX` | Ed25519 seed, 64 hex (secret) |
| `MESSENGER_WITNESS_PUBLIC_KEY_HEX` | The pinned public key; must match the seed |
| `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX` | The log's service key |
| `MESSENGER_WITNESS_CHECKPOINT_PATH` | State file, or an `http(s)` checkpoint store taking `If-Match` (Cloudflare) |
| `MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX` | Pull-mode start (`new-identity` or a checkpoint's hex); `restore` input |
| `MESSENGER_WITNESS_GUARD_PATH` | Copy of the last signed checkpoint on the host's own disk, off the shared volume (empty: none) |
| `MESSENGER_WITNESS_EVIDENCE_DIR` | Existing directory for evidence files (empty: evidence only in the log) |
| `MESSENGER_WITNESS_RELAY_URLS` | Comma-separated relay origins (at most 8) that receive `POST /v1/fork-evidence` |
| `MESSENGER_WITNESS_POLL_MS` | Pull interval, 50–60000 (default 15000) |

## State and evidence

A file state holds the base64 `KTK` of the last checkpoint the witness signed.
It is replaced by writing a temporary file beside it, `File.sync`, and
`File.rename`, after checking that the file still holds what this process
read. Primary and standby may share the file (one shared volume); only one
runs at a time, and whichever runs signs only what extends the file. Each host
also keeps a guard copy on its own disk: if the shared state is ever older
than the guard, the state came from a snapshot and the witness halts. The halt
marker sits beside the state (`<state>.halted`: a reason, then `evidence <path>` or
`checkpoint <hex>`).

Evidence files are `evidence-<witness>-<ms>-<reason>.json` with `reason`,
`detected_at_ms`, `previous_checkpoint` and `current_checkpoint` (`KTK` hex),
`consistency_proof` (the directory's answer, hex), `attestations` (its `KTW`
list, hex) and `fork_evidence` (`FRK` hex, empty when the pair alone proves no
fork).

## Tests

`tests/` runs against a stub directory and relay on 127.0.0.1:18962–18963:
W1 timestamps and links, v2 proofs and the v1 fallback, evidence for each
failure, the stale-backup refusal (directory and guard), the start rule, two
instances on one state, and the pull loop.
