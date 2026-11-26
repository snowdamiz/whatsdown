# Running a Morse witness

A witness signs the key-transparency log's checkpoints after checking that
each one extends the last checkpoint it signed. Phones accept a directory
answer only when a strict majority of the witnesses pinned in the app signed
its checkpoint, so an honest witness makes a split view (one history for you,
another for everyone else) need the collusion of the directory and a majority
of witnesses. A witness receives checkpoints only: tree sizes, roots,
sequence numbers and times. It never sees usernames, keys, devices or
messages.

This runbook covers the Morse witness software (`services/transparency-witness`)
in pull mode. Operators running a C2SP witness (`tlog-witness`, for example
litewitness) follow the same program with that software's own install guide;
the key ceremony, pinning statement, monitoring and leaving steps below apply
to them too. Morse's own bootstrap witness C is deployed with
[`witness-c.md`](witness-c.md).

Contents: [Requirements](#requirements) · [Build and verify](#build-and-verify) ·
[Key ceremony](#key-ceremony) · [Pinning statement](#pinning-statement) ·
[Install](#install) · [Key custody](#key-custody) ·
[Backups and continuity](#backups-and-continuity) · [Failover](#failover) ·
[Upgrades](#upgrades) · [Monitoring](#monitoring) · [Incidents](#incidents) ·
[Leaving](#leaving) · [Contact](#contact)

## Requirements

- One primary host and, for 99.5% uptime, a standby: 1 vCPU, 1 GB RAM and
  10 GB disk each, Linux (Ubuntu 24.04 is what the image is built on).
- One state volume the primary and standby can both mount, one at a time (a
  cloud block volume that attaches to one server at a time is ideal).
- Outbound HTTPS to the directory and the relays, DNS and NTP. No inbound port:
  in pull mode the witness polls the directory and nobody calls it.
- An accurate clock. The witness refuses checkpoints stamped more than 60 s
  from its own clock, so run `chrony` or `systemd-timesyncd` and alert on
  drift.
- Nothing shared with Morse's cloud accounts, and one witness per legal
  entity (plan §9.1).

## Build and verify

The witness ships as a reproducible OCI image and binary. Build it on a
machine with Docker Buildx and at least 25 GB free inside Docker (LLVM and
the Mesh compiler are built in the image); expect 30–60 minutes:

```sh
git clone https://github.com/snowdamiz/whatsdown && cd whatsdown
git checkout <release commit>
MESH_LANG_REVISION=<mesh-lang commit named in the release> \
  mesh-private-messenger/ops/witness/build.sh --platform linux/amd64 --verify
```

`ops/witness/dist/` then holds:

- `transparency-witness-amd64`: the binary (needs only glibc).
- `morse-witness-amd64.oci.tar`: the image (`docker load -i` it).
- `SHA256SUMS-amd64`: both files' SHA-256 and the image's OCI digest.
- `BUILDINFO-amd64`: the Morse and Mesh revisions, platform and
  `SOURCE_DATE_EPOCH`.

`--verify` builds the binary twice without cache and fails if the two differ.
Compare your `SHA256SUMS-amd64` with the one Morse publishes for the release:
equal sums mean you run exactly the reviewed source. Every input is pinned in
the `Dockerfile` (base image digest, Ubuntu snapshot, rustup-init, Rust
toolchain, LLVM SHA-256) and the Mesh compiler by revision.

The witness needs `File.rename` and `File.sync`, which Mesh v0.1.8 and earlier
lack; the release names a Mesh revision that has them. (`MESH_LANG_DIR=<local
checkout>` builds from a local tree for development; `BUILDINFO` then says the
build is unpinned.)

## Key ceremony

Make the witness key on your own hardware. Morse never sees it: you send only
the public key and a statement signed with it.

On an offline or freshly installed machine you control:

```sh
umask 077
openssl genpkey -algorithm ed25519 -out witness.pem
openssl pkey -in witness.pem -outform DER | tail -c 32 | xxd -p -c 64 > witness.seed    # the signing seed
openssl pkey -in witness.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64           # the public key
```

The seed becomes `MESSENGER_WITNESS_SIGNING_SEED_HEX`; the public key goes in
your application, the pinning statement and the registry.

**HSM or KMS.** Plan §9.1 prefers a hardware security module or a KMS with
Ed25519. The Mesh witness holds its key in process memory (it reads the seed
from its environment at start), so an HSM can't sign for it. If your policy
requires hardware custody, run a C2SP witness that signs through one (for
example litewitness, which signs through an `ssh-agent` that can be backed by a
hardware token), and register it as `software: c2sp`. Either way the pinning
statement can be signed by the HSM or KMS (next section).

A key is never rotated in place: a new key is a new witness ID, registered
and pinned like any other, and a leaked key is retired, never reused.

## Pinning statement

Before a release pins your witness, you publish a statement signed by the
witness key (plan §9.2). `pinning-statement.mjs` (Node 20+) formats and signs
it on the machine that holds the key:

```sh
node ops/witness/pinning-statement.mjs sign \
  --witness-id example-witness --operator "Example Witness GmbH" \
  --jurisdiction DE --software "mesh 0.1.9" \
  --payout <Solana address> --key-file witness.pem > pinning-statement.txt
node ops/witness/pinning-statement.mjs verify pinning-statement.txt
```

`--key-file` takes the PEM or the 64-hex seed file. With an HSM or KMS, print
the exact bytes to sign, sign them there (pure Ed25519, no prehash), and
assemble:

```sh
node ops/witness/pinning-statement.mjs message --public-key <hex> <same fields> > message.txt
node ops/witness/pinning-statement.mjs assemble --public-key <hex> <same fields> --signature <128 hex>
```

The statement is:

```text
morse-witness-pin-v1
witness_id: <id, [a-z0-9-]{1,64}>
public_key: <64 hex>
operator: <label, 1-48 printable ASCII, as the app will show it>
jurisdiction: <ISO 3166-1 alpha-2 country>
software: mesh <version> | c2sp <implementation> <version>
payout: <Solana address>
date: <YYYY-MM-DD>
signature: <Ed25519 over the eight lines above, each ending in \n, hex>
```

Attach it to your application (the "Witness application" issue form); Morse
publishes it in `protocol/witnesses.md` with the release that pins you.

## Install

Morse adds your key to the directory's registry as `shadow`: the directory
stores your signatures and phones ignore them until a release pins you.

Two ways to run it; both use the same settings files.

```sh
sudo install -d -m 0755 /etc/morse-witness
sudo install -m 0644 ops/witness/witness.env.example /etc/morse-witness/witness.env    # then edit
sudo sh -c 'umask 077; printf "MESSENGER_WITNESS_SIGNING_SEED_HEX=%s\n" "$(cat witness.seed)" > /etc/morse-witness/seed.env'
```

`witness.env` names the directory origin, your witness ID and public key, the
log's service key (from the security config of the current release), the
relays, and, for the very first start only, `MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX=new-identity`.
Every variable is described in
[`services/transparency-witness/README.md`](../../services/transparency-witness/README.md#environment).

**systemd** (no container runtime on the host):

```sh
sudo useradd --system --uid 65532 --home-dir /var/lib/morse-witness --shell /usr/sbin/nologin morse-witness
sudo install -d -o morse-witness -g morse-witness -m 0700 /var/lib/morse-witness   # the state volume's mount point
sha256sum -c --ignore-missing SHA256SUMS-amd64
sudo install -D -m 0755 transparency-witness-amd64 /opt/morse-witness/transparency-witness
sudo install -m 0644 ops/witness/morse-witness.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now morse-witness
journalctl -u morse-witness -f      # "witness signed checkpoint <hash>" within 15 s of a new checkpoint
```

**Docker Compose**:

```sh
sha256sum -c --ignore-missing SHA256SUMS-amd64
docker load -i morse-witness-amd64.oci.tar            # prints morse-witness:<revision>
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/morse-witness
MORSE_WITNESS_IMAGE=morse-witness:<revision> docker compose -f ops/witness/compose.yaml up -d
docker compose -f ops/witness/compose.yaml logs -f
```

Once the log shows a signed checkpoint, delete the
`MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX` line and restart. From then on a
missing state file is an error, never a fresh start.

**Network.** The witness opens no port. Allow outbound TCP 443 (directory and
relays), DNS and NTP; deny all inbound except your SSH. The Hetzner example is
in `witness-c.md`.

**Shadow week.** Morse pins a witness after 7 days at ≥ 99% attendance with
one planned failover and one restore drill (plan §9.4; the checklist is in
`witness-c.md`).

## Key custody

- `seed.env` is `0600 root`; systemd and Docker read it as root and pass it to
  the witness process only. Keep it off the state volume.
- Keep one offline copy of `witness.pem` (sealed, in a safe) so a dead host
  doesn't end the witness. Never run two hosts with the key at the same time
  outside a failover, and never restore a key onto a host that may still be
  running.
- If the key may have leaked, stop the witness and tell Morse at once
  ([Incidents](#incidents)). A stolen key can sign a fork in your name, and
  your bond pays for it.

## Backups and continuity

The state file (`/var/lib/morse-witness/checkpoint`) holds the last checkpoint
the witness signed. It is the witness's memory: the witness signs only
checkpoints that extend it, which is what keeps it from ever signing a fork.

A backup of it is always older than the witness's real history. If you
restored one and the witness carried on, it could sign a checkpoint that forks
from one it signed after the backup was taken, a double signature that slashes
your bond. So the witness checks, twice:

- Each host keeps a guard copy of the last checkpoint it signed on its own
  disk (`/var/lib/morse-witness-guard`, never on the shared volume). A state
  older than the guard was restored from a snapshot.
- The directory holding this witness's own signature on a checkpoint newer
  than the state means the same, whichever host signed it.

Either way it halts with **stale state**, writes `checkpoint.halted` naming
the newer checkpoint, exits with code 3, and won't sign again until you
restore continuity:

```sh
cat /var/lib/morse-witness/checkpoint.halted     # "stale state: ..." then "checkpoint <hex>"
# Check the named checkpoint against the monitor or the anchor record, then:
sudo systemctl stop morse-witness
sudo -u morse-witness sh -c 'set -a; . /etc/morse-witness/witness.env; set +a
  MESSENGER_WITNESS_MODE=restore MESSENGER_WITNESS_CHECKPOINT_PATH=/var/lib/morse-witness/checkpoint \
  MESSENGER_WITNESS_GUARD_PATH=/var/lib/morse-witness-guard/checkpoint \
  MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX=<hex from the marker> exec /opt/morse-witness/transparency-witness'
sudo systemctl start morse-witness
```

(With Compose: `docker compose run --rm -e MESSENGER_WITNESS_MODE=restore -e
MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX=<hex> witness`.) Restore refuses a
checkpoint older than the state or the guard, or not signed by the log.

What to back up is therefore the configuration and the key, not the state.
Snapshots of the state volume are fine as a record, but restoring one is the
drill above, not a shortcut.

## Failover

The primary and standby share the state volume and the key; only one runs.
Whichever runs reads the state file each round and signs only what extends
it, and each write is a compare-and-swap, so a standby that takes over can't
fork what the primary signed.

1. Stop the primary (`systemctl stop morse-witness`), or make sure it is dead.
2. Move the state volume to the standby (detach, attach, mount at
   `/var/lib/morse-witness`).
3. Start the witness on the standby.
4. Watch for `witness signed checkpoint` within 15 s of the next checkpoint.

Never mount the volume on both hosts or run both witnesses at once. Failing
back is the same procedure in reverse. A quarterly failover drill is part of
the program (plan §9.3).

## Upgrades

Morse announces any breaking witness change at least 14 days ahead in the
operator channel, with the release's `SHA256SUMS`. To upgrade: build and
verify as above, compare sums, replace the binary or image, restart. The state
carries over; the first round after the restart finds nothing new or signs
the next checkpoint. To roll back, reinstall the previous binary the same way.

## Monitoring

The directory's health (`GET /v1/transparency/health` on its public origin)
lists each registry witness:

```sh
curl -fsS <directory>/v1/transparency/health | jq '.witnesses[] | select(.witness_id == "<id>")'
# {"witness_id":"...","status":"shadow","morse_run":false,"signed_current":true,"last_signature_age_seconds":42}
```

Alert on (Morse watches the same numbers):

| Condition | Severity |
|---|---|
| `last_signature_age_seconds` > 600, or the service not running | **Page** (10 minutes of silence) |
| `checkpoint.halted` exists, or exit code 3 | **Page**: see [Incidents](#incidents) |
| An `evidence-*.json` file appears | **Page, P0**: the directory's history broke |
| Log lines `witness refused checkpoint` for more than 2 minutes | Warn: check the clock first |
| `witness round failed` for more than 5 minutes | Warn: network or directory |
| Clock offset > 1 s (`chronyc tracking`) | Warn |

## Incidents

- **Halted with evidence** (`evidence-*.json`, reason `rollback`, `conflict`,
  `inconsistency` or `broken-link`): the directory served a checkpoint that
  doesn't extend the last one you signed. The witness has stopped signing and,
  when the two checkpoints alone prove a fork, has filed an `FRK` with the
  relays in `MESSENGER_WITNESS_RELAY_URLS`. Keep the evidence file, tell Morse
  and the other operators, and don't restore continuity until the incident is
  understood: resuming means choosing which history to sign.
- **Stale state**: see [Backups and continuity](#backups-and-continuity).
- **Key compromised or lost**: stop the witness, tell Morse. The next release
  unpins your ID by hotfix; you re-apply with a new key.
- **Long outage**: nothing to do below the network's tolerance; attendance
  falls, and below 95% for two epochs a witness is unpinned (plan §7).

## Leaving

Tell Morse; the next release unpins your witness and the registry marks it
retired. Once bonds exist (Phase 3) you also call `request_unbond` on the
judge program ([`protocol/morse-judge-v1.md`](../../protocol/morse-judge-v1.md));
the bond returns after the 30-day unbonding period. Keep the key sealed until
then, since a fork proof against your ID can still land during unbonding, and
never reuse it for another witness.

## Contact

- Coordination and upgrade notices: the private operator channel Morse sets up
  when you are accepted.
- Security reports (a fork, a leaked key, a bug in the witness): GitHub's
  **Security → Report a vulnerability** on `snowdamiz/whatsdown`, as
  `SECURITY.md` describes, and the operator channel.
- Morse reaches you through the contact on your application; keep it current.
