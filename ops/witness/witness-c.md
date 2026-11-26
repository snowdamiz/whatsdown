# Witness C: Morse's bootstrap witness on Hetzner

Witness C moves production from two witnesses on one Cloudflare account (B0)
to three, one of them off Cloudflare and in another jurisdiction (plan §4.1
step B1, decision D10). It runs the Morse witness in pull mode on Hetzner
Cloud in Germany: a primary and a standby in Falkenstein (`fsn1`) sharing one
Hetzner Volume, which attaches to one server at a time, so the two can never
sign at once. After a clean shadow week a release pins a, b and c with 2 of 3
required.

The general runbook is [`README.md`](README.md); this file is the exact
sequence for witness C. Replace `<...>` values as you go and keep a log of the
times you record.

## 0. What you need

- A Hetzner Cloud project `morse-witness-c` in an account that holds nothing
  else of Morse's, and an API token for it (`hcloud context create morse-witness-c`).
- `hcloud` CLI, an SSH key, and the admin IP addresses allowed to SSH in.
- A build machine with Docker Buildx and 25 GB free (not the witness hosts).
- An offline machine for the key ceremony.
- Access to the directory's database and release pipeline (for the registry
  entry and the shadow-week queries).

## 1. Build and verify the binary

On the build machine, from the release commit that contains the pull-mode
witness and with the Mesh revision that release names:

```sh
MESH_LANG_REVISION=<mesh-lang commit> mesh-private-messenger/ops/witness/build.sh --platform linux/amd64 --verify
cat mesh-private-messenger/ops/witness/dist/SHA256SUMS-amd64 mesh-private-messenger/ops/witness/dist/BUILDINFO-amd64
```

Record `SHA256SUMS-amd64` in the release notes. Anyone can rebuild and compare.

## 2. Key ceremony

On the offline machine (plan §9.2; Morse's own witness follows the same rule
as outside operators):

```sh
umask 077
openssl genpkey -algorithm ed25519 -out witness-c.pem
openssl pkey -in witness-c.pem -outform DER | tail -c 32 | xxd -p -c 64 > witness-c.seed
openssl pkey -in witness-c.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64 > witness-c.pub
node ops/witness/pinning-statement.mjs sign --witness-id witness-c --operator Morse \
  --jurisdiction DE --software "mesh <Mesh release version>" \
  --payout <Morse treasury Solana address> --key-file witness-c.pem > witness-c.pin.txt
node ops/witness/pinning-statement.mjs verify witness-c.pin.txt
```

Seal `witness-c.pem` offline (two copies, two places). Only `witness-c.seed`
travels to the two hosts, over SSH, in step 5. The label is exactly `Morse`:
that is what makes the security config count C as Morse-run.

## 3. Hetzner resources

```sh
hcloud ssh-key create --name admin --public-key-from-file ~/.ssh/id_ed25519.pub
hcloud placement-group create --name witness-c --type spread

hcloud firewall create --name witness-c
hcloud firewall add-rule witness-c --direction in  --protocol tcp --port 22  --source-ips <admin IP>/32
hcloud firewall add-rule witness-c --direction out --protocol tcp --port 443 --destination-ips 0.0.0.0/0 --destination-ips ::/0
hcloud firewall add-rule witness-c --direction out --protocol udp --port 53  --destination-ips 0.0.0.0/0 --destination-ips ::/0
hcloud firewall add-rule witness-c --direction out --protocol tcp --port 53  --destination-ips 0.0.0.0/0 --destination-ips ::/0
hcloud firewall add-rule witness-c --direction out --protocol udp --port 123 --destination-ips 0.0.0.0/0 --destination-ips ::/0

for host in witness-c-1 witness-c-2; do
  hcloud server create --name "$host" --type cx22 --image ubuntu-24.04 --location fsn1 \
    --ssh-key admin --firewall witness-c --placement-group witness-c
done
hcloud volume create --name witness-c-state --size 10 --location fsn1 --format ext4
hcloud volume attach witness-c-state --server witness-c-1
hcloud volume describe witness-c-state -o format='{{.LinuxDevice}}'    # /dev/disk/by-id/scsi-0HC_Volume_<id>
```

`cx22` is the smallest shared x86 type at the time of writing; any amd64 type
with 2 GB works (`hcloud server-type list`). With outbound rules present, the
Hetzner firewall drops every other outbound packet, so the hosts reach only
HTTPS, DNS and NTP. Inbound is SSH from the admin address only.

## 4. Prepare both hosts

On `witness-c-1` and `witness-c-2` (as root):

```sh
apt-get update && apt-get -y upgrade && apt-get -y install chrony unattended-upgrades
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh
useradd --system --uid 65532 --home-dir /var/lib/morse-witness --shell /usr/sbin/nologin morse-witness
install -d -o morse-witness -g morse-witness -m 0700 /var/lib/morse-witness
echo '/dev/disk/by-id/scsi-0HC_Volume_<id> /var/lib/morse-witness ext4 discard,nofail,defaults 0 0' >> /etc/fstab
install -d -m 0755 /etc/morse-witness
chronyc tracking      # "System time" within a few ms
```

On `witness-c-1` only (the volume is attached there):

```sh
mount /var/lib/morse-witness && chown morse-witness:morse-witness /var/lib/morse-witness && chmod 0700 /var/lib/morse-witness
```

The standby keeps the same fstab line; `nofail` lets it boot without the
volume. Without the volume its `/var/lib/morse-witness` is an empty directory,
and a witness started there refuses to sign (a missing state needs an explicit
start), so a mistaken start can't sign from nothing.

## 5. Install the witness on both hosts

From the build machine and the offline machine:

```sh
for host in witness-c-1 witness-c-2; do
  scp dist/transparency-witness-amd64 dist/SHA256SUMS-amd64 ops/witness/morse-witness.service "root@$host:/root/"
  scp witness-c.seed "root@$host:/root/witness-c.seed"
done
```

On each host:

```sh
cd /root && sha256sum -c --ignore-missing SHA256SUMS-amd64
install -D -m 0755 transparency-witness-amd64 /opt/morse-witness/transparency-witness
umask 077 && printf 'MESSENGER_WITNESS_SIGNING_SEED_HEX=%s\n' "$(cat witness-c.seed)" > /etc/morse-witness/seed.env
shred -u witness-c.seed
cat > /etc/morse-witness/witness.env <<EOF
MESSENGER_BASE_URL=<directory origin, the release's MORSE_BACKEND_URL>
MESSENGER_WITNESS_ID=witness-c
MESSENGER_WITNESS_PUBLIC_KEY_HEX=<contents of witness-c.pub>
MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=<the service key in the current security config>
MESSENGER_WITNESS_RELAY_URLS=<relay origins, once relays run (Phase 1); empty before>
EOF
chmod 0644 /etc/morse-witness/witness.env
install -m 0644 morse-witness.service /etc/systemd/system/ && systemctl daemon-reload
```

Enable the unit on the primary only:

```sh
systemctl enable morse-witness      # witness-c-1
systemctl disable morse-witness     # witness-c-2: started only by a failover
```

## 6. Registry entry (shadow)

Add witness C to the directory's registry as `shadow` through
`MESSENGER_WITNESS_REGISTRY` (JSON array; see `ops/cloudflare/README.md`,
registry) and ship it with a release (release pipeline, not a manual deploy):

```json
[{"witness_id":"witness-c","public_key":"<witness-c.pub>","operator":"Morse","status":"shadow","software":"mesh","morse_run":true}]
```

After the release, `GET /health` lists `witness-c` with `"status":"shadow"`.

## 7. First start

On `witness-c-1`:

```sh
echo 'MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX=new-identity' >> /etc/morse-witness/witness.env
systemctl start morse-witness
journalctl -u morse-witness -f       # "witness witness-c pulling every 15000 ms", then "witness signed checkpoint <hash>"
curl -fsS <directory>/health | jq '.witnesses[] | select(.witness_id == "witness-c")'   # signed_current: true
sed -i '/MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX/d' /etc/morse-witness/witness.env
systemctl restart morse-witness
ls -l /var/lib/morse-witness /var/lib/morse-witness-guard   # checkpoint on the volume, guard on the root disk
```

## 8. Monitoring

Add to Morse's on-call alerting, polled every minute:

- **Page** when `.witnesses[] | select(.witness_id=="witness-c") | .last_signature_age_seconds`
  exceeds 600, or `/health` doesn't answer.
- **Page** when the unit is `failed` or exited with status 3, or
  `/var/lib/morse-witness/checkpoint.halted` or an `evidence-*.json` exists
  (a node-exporter textfile check, or `systemctl is-failed morse-witness` over
  SSH from the monitoring host).
- **Warn** on `chronyc tracking` offset above 1 s.

## Failover (planned or not)

```sh
ssh root@witness-c-1 systemctl stop morse-witness          # skip if the host is dead
hcloud volume detach witness-c-state                         # works for a dead host too
hcloud volume attach witness-c-state --server witness-c-2
ssh root@witness-c-2 'mount /var/lib/morse-witness && systemctl start morse-witness && journalctl -u morse-witness -n 20'
```

Record the time the primary stopped and the standby's first
`witness signed checkpoint`. Fail back the same way. Never attach the volume
to both, and never start the unit on a host without the volume mounted.

## Shadow week (plan §9.4)

Start it after step 7; record the start time (UTC). Queries run against the
directory database.

**1. At least 99% of checkpoints signed within 60 s**

```sql
SELECT count(*) AS checkpoints,
       count(s.witness_id) AS signed,
       round(100.0 * count(*) FILTER (
         WHERE s.observed_at <= to_timestamp((c.timestamp_ms + 60000) / 1000.0)) / count(*), 2) AS on_time_percent
FROM transparency_checkpoints c
LEFT JOIN witness_signatures s ON s.checkpoint_sequence = c.sequence AND s.witness_id = 'witness-c'
WHERE c.created_at >= '<shadow start>';
```

Pass: `on_time_percent >= 99`.

**2. One planned failover: no fork, no missed window over 5 minutes**

Run the failover above. Then every checkpoint issued from 5 minutes after the
primary stopped until the end of the drill must be signed within 60 s:

```sql
SELECT c.sequence, to_timestamp(c.timestamp_ms / 1000.0) AS issued, s.observed_at
FROM transparency_checkpoints c
LEFT JOIN witness_signatures s ON s.checkpoint_sequence = c.sequence AND s.witness_id = 'witness-c'
WHERE c.timestamp_ms BETWEEN extract(epoch FROM timestamptz '<primary stopped>' + interval '5 minutes') * 1000
                         AND extract(epoch FROM timestamptz '<drill end>') * 1000
  AND (s.observed_at IS NULL OR s.observed_at > to_timestamp((c.timestamp_ms + 60000) / 1000.0));
```

Pass: no rows, no `evidence-*.json` and no `checkpoint.halted` on either host.

**3. A restart from backup refuses to sign until continuity is restored**

On the running host:

```sh
cp -p /var/lib/morse-witness/checkpoint /root/checkpoint.drill        # the "backup"
journalctl -u morse-witness -f          # wait for at least one newer "witness signed checkpoint"
systemctl stop morse-witness
install -o morse-witness -g morse-witness -m 0600 /root/checkpoint.drill /var/lib/morse-witness/checkpoint
date -u                                  # record: backup restored
systemctl start morse-witness; sleep 5
systemctl status morse-witness           # inactive, status=3
journalctl -u morse-witness -n 5         # "witness halted: stale state: ..."
cat /var/lib/morse-witness/checkpoint.halted
```

Wait 15 minutes, then restore continuity from the checkpoint the marker names
(after checking it against the monitor or the anchor record):

```sh
sudo -u morse-witness sh -c 'set -a; . /etc/morse-witness/witness.env; set +a
  MESSENGER_WITNESS_MODE=restore MESSENGER_WITNESS_CHECKPOINT_PATH=/var/lib/morse-witness/checkpoint \
  MESSENGER_WITNESS_GUARD_PATH=/var/lib/morse-witness-guard/checkpoint \
  MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX=<hex after "checkpoint " in the marker> exec /opt/morse-witness/transparency-witness'
date -u                                  # record: continuity restored
systemctl start morse-witness
```

```sql
SELECT count(*) FROM witness_signatures
WHERE witness_id = 'witness-c' AND observed_at BETWEEN '<backup restored>' AND '<continuity restored>';
```

Pass: `0`, and signing resumes after the restore.

**4. No inconsistency involving the witness**

The monitor (plan §6.8) reports none for `witness-c`. Until the monitor runs:
no `evidence-*.json` on either host and no `witness halted` in either journal
except the drill in check 3.

**Weekly outage drill** (plan §4.3 check 2, from B1 on): stop witness C for 15
minutes; lookups keep succeeding on 2 of 3; after the restart it signs the
next checkpoint without a halt.

## Pinning (B1)

When the four checks pass, the next release pins the set in security config
v2 (`protocol/witness-network-v1.md`, "Security config v2"). Lines 5 onwards
of the frame (k, n, then the witnesses sorted by ID) become:

```text
2
3
witness-a <witness A key> Morse
witness-b <witness B key> Morse
witness-c <witness-c.pub> Morse
```

The registry entry moves to `"status":"pinned"`, and Morse
publishes `witness-c.pin.txt` in `protocol/witnesses.md`. The profile stays
Bootstrap (all three Morse-run, k = 2), and production survives one witness
outage. Exit for Phase 0.3: B1 in production for 7 days, the stale-backup
refusal shown (check 3), and the weekly outage drill passing.
