# Witness Network v1

Status: proposed, with its protocol layer implemented. The formats and checks
in "Security config v2", "Fork evidence", "C2SP view" and
[checkpoint gossip](checkpoint-gossip-v1.md) exist in
`packages/messenger-protocol` with tests; nothing is deployed, and apps,
services and chain programs do not use them yet. The landing page presents the
network as what comes next, in the order below. Each step stands on its own
without the ones after it.

## Why

[Key transparency](key-transparency-v1.md) is only as strong as witnesses the
directory operator does not control, and today both witnesses share one
operator. This plan opens the witness set to outside operators, backs each
witness's signature with a bond it loses if it signs a fork, and pays for that
with optional, anonymous credits.

## Rules that do not change

- Messaging never needs credits, a wallet or the token. Proof of work (`PWR`)
  stays the free path for every request that needs it today.
- Wallet addresses never reach the privacy edge, the directory or the delivery
  core, and are never linked to an account (see the
  [privacy contract](privacy-contract.md)).
- Nothing per message, per contact or per account is written to a chain. A
  chain sees checkpoint commitments, bonds, fork proofs and credit purchases.
- Each app release pins the witness keys a client trusts and the threshold it
  requires. On-chain state decides who may bond and whose bond is taken, never
  which witnesses a client trusts, so holding tokens cannot change which keys a
  phone accepts.
- Nothing rewards in-app activity. Measuring activity is what the servers are
  built not to do.

## Trust profiles

The network always runs, whoever the witnesses are. With `m` the number of
pinned witnesses Morse runs and `k` the threshold:

- **Bootstrap** (`m ≥ k`): every pinned witness may be Morse's. This is how
  production runs before outside witnesses join. Anchors, phone checks, monitors,
  bonds and fork proofs all work, but no outside signature is required.
- **Transitional** (`1 < m < k`): forking needs at least `k − m` outside
  witnesses.
- **Open** (`m ≤ 1`): Morse runs at most one witness and can't reach a
  majority, alone or with the directory.

Apps and the site state the current profile. Nothing may call the witnesses
independent before the Open profile.

## Steps

1. **Public checkpoints.** The directory posts each checkpoint commitment (tree
   size, root, sequence and the witness cosignatures) to a public chain. The
   chain receives what witnesses already see and nothing more.
2. **Independent witnesses.** Operators outside Morse run the existing witness
   service with their own keys. Releases pin them with a threshold below the
   pinned count, so one operator going offline does not stop lookups.
3. **Anonymous credits.** Privacy Pass issuance (RFC 9578, blind RSA from
   RFC 9474). A client pays on-chain in USDC, SOL or BTC to a one-time address
   and receives blind-signed credits; it spends them at the privacy edge beside
   or instead of `PWR`, and the directory-delivery core keeps the one spent set.
   Issuer keys, one per 30-day epoch, are published in the transparency log so
   the issuer cannot hand one user a unique key to tag their credits
   ([credits-v1.md](credits-v1.md)). Credits buy extras: larger
   attachments, longer mailbox retention, postage a recipient may require on
   message requests, and priority when registration is closed by a flood.
4. **The token.** Witnesses, and the directory's own service key, bond it.
   Buying credits burns it: clients may pay in other assets and the purchase
   swaps before burning. Witnesses are paid for each anchored checkpoint they
   cosigned. Missing a checkpoint forfeits that payment, not the bond.

## Fork proof

Two service-signed checkpoints that can't both be true prove a fork, and every
witness that cosigned both signed it. Three forms are accepted: the same tree
size with different roots; the same leaf index reading differently in two
checkpoints, shown by compact inclusion proofs (this catches forks that never
share a size); and sequence and size moving in opposite directions. Each is
checked on-chain with Ed25519 verifications and SHA-256 path recomputation.
Whoever submits it receives 10% of what it slashes; the rest is locked or
burned, never paid to Morse.

Phones require a strict majority of the pinned witnesses, so two conflicting
checkpoints that both reach the threshold always share at least one witness
that signed both.

The implementation order, parameters and tests are in
[WITNESS_NETWORK_PLAN.md](../../WITNESS_NETWORK_PLAN.md).

A witness that keeps the last checkpoint it signed (the witness service does;
see "Witness software" below) cannot produce a fork proof against itself unless
its key is stolen or its state is lost. Downtime is never slashed.

## Security config v2

Each build pins one frame (`Security.Config`, `security_config_parse`). It is
UTF-8, at most 4,096 bytes, lines separated by `\n`, no trailing newline, and
must equal its own canonical re-encoding:

```text
2
<transparency service key, 64 lowercase hex>
<delivery key, 64 lowercase hex>
<PoW difficulty, 1-24>
<threshold k>
<n, 1-16>
<witness_id> <public key, 64 lowercase hex> <operator label>    n lines, sorted by witness_id
<"<judge program id> <log account>" (base58) | "-">
<r: 3-8 with an anchor, 0 when the anchor is "-">
<https RPC URL>                                                 r lines
<s: 0-8>
<https relay origin>                                            s lines
<credit issuer origin | "-">
<C2SP log origin | "-">
<minimum session suite: 1 or 2>
<OHTTP key configuration, 82 lowercase hex> <relay origin>     optional
```

- `witness_id` is `[a-z0-9-]{1,64}`; IDs are strictly increasing bytewise, so
  unique; public keys are unique.
- The operator label is 1-48 bytes of printable ASCII (0x20-0x7E) with no
  leading or trailing space. A witness is **Morse-run** exactly when its label
  is `Morse`.
- `k` must equal `⌊n/2⌋ + 1` (`security_config_majority`).
- Numbers are canonical decimal: no sign, no leading zero, no spaces.
- Base58 fields decode to 32 bytes and re-encode to the same text.
- URLs are `https://`, printable ASCII, with a host and no `@`, `?` or `#`,
  and none repeats. RPC URLs may have a path; relay and issuer origins may not
  (not even `/`).
- The C2SP origin is 1-255 bytes of printable ASCII without space or `+`. `-`
  means kind-2 attestations never count.
- The delivery key must be a contributory X25519 point, as in v1.
- The optional last line pins the Oblivious HTTP gateway and its relay
  ([ohttp-v1.md](ohttp-v1.md#pinning)): an RFC 9458 key configuration for
  X25519, HKDF-SHA256 and ChaCha20-Poly1305, and the privacy edge's origin
  (`https://`, or `http://` on a local address for development builds). A frame
  without it pins no gateway and is byte for byte what it was before.

`set_id = SHA-256("morse-witness-set-v1" || lines 5 to 6+n joined with "\n")`:
the `k` line, the `n` line and the witness lines exactly as written, so a
change of any witness key, ID or label changes it, and nothing else does.

A v1 frame (`1`, service key, witness A key, witness B key, delivery key,
difficulty; 263-264 bytes; A ≠ B) still parses, into `witness-a` and
`witness-b` labelled `Morse`, `k = 2`, no anchor, RPC, relays, credits or C2SP,
and minimum suite 1. Its `set_id` is computed over the equivalent v2 lines
(`2`, `2`, `witness-a <A> Morse`, `witness-b <B> Morse`), so rewriting a v1 frame
as v2 keeps the cached view. `security_config_encode` always writes the
canonical v2 frame and refuses any config its own parser would refuse. The
build-time writer (`apps/mobile/plugins/security-config.cjs`) produces frames
this parser accepts with the same `set_id`.

`security_config_profile` names the trust profile from `m`
(`security_config_morse_run`) and `k`: `bootstrap` when `m ≥ k`,
`transitional` when `1 < m < k`, `open` when `m ≤ 1`.

## Fork evidence (`FRK` v1)

`Transparency.Fork` encodes, decodes and judges fork proofs. All integers are
big-endian; KTK checkpoints are embedded verbatim.

```text
offset  field
0       u8 version = 1
1..4    "FRK"
4       u8 kind: 1 same size | 2 contradiction | 3 rollback
5..37   finder address: 32 raw bytes of a Solana address, or 32 zero bytes
37..69  log service public key (32)
69..257 C1: KTK (188)
257     u8 C2 form: 0 = inline, then KTK (188); 1 = ring reference, then u32 ring index
then    u8 attestation count a (0-16),
        a x { u8 id length (1-64), id (UTF-8), checkpoint_hash32, signature64 }
kind 2 only, after the attestations:
        u64 leaf index i || u8 p1 (0-64) || p1 x 32 (path of i in C1) || leaf32 in C1
        || u8 p2 (0-64) || p2 x 32 (path of i in C2) || leaf32 in C2
```

No trailing bytes; at most 8,192 bytes (the largest possible proof is 7,193).
Kinds 1 and 3 carry no leaf fields. A decoder refuses every other version,
kind, form, count or length.

A proof is judged against a log: its service key and its witness list in the
order the judge's `Log` account holds it (`ForkLog`). The key the proof names
must be the log's, and every inline checkpoint must verify under it. A ring
reference is resolved by the caller to the ring entry (sequence, tree size,
root, checkpoint hash, cosign bitmap, `ForkRingEntry`); `post_anchor` already
verified its service signature, so it counts as signed.

| Kind | Holds when |
|---|---|
| 1 same size | `size1 == size2 && root1 != root2` |
| 2 contradiction | `i < min(size1, size2)`, both Morse audit paths verify (RFC 9162 section 2.1.3.2 with `mesh-msg/v1/transparency-node`) against their roots, and `leaf1 != leaf2` |
| 3 rollback | `(seq1 < seq2 && size1 > size2) || (seq1 > seq2 && size1 < size2) || (seq1 == seq2 && checkpoint_hash1 != checkpoint_hash2)` |

The **implicated witnesses** are the log's witnesses, in the log's order, that
signed both checkpoints: for an inline checkpoint, a valid Morse statement
(`"mesh-msg/v1/transparency-witness" || id || checkpoint_hash`, Ed25519 under
the log's key for that ID) whose hash matches it; for a ring entry, its cosign
bitmap bit (bit i is witness i). Attestations from unknown IDs, over other
hashes or with bad signatures implicate no one and do not invalidate the
proof: the fork itself rests on the service signatures, and a finder may only
hold some attestations. A fork no witness signed twice is still valid and
implicates only the directory.

`fork_proof_hash = SHA-256("morse-frk-v1/proof" || bytes[0..5] || bytes[37..])`
covers every byte except the finder address, so naming a different address
never makes a second payable proof. It does cover the attestations: two proofs
of one fork with different attestation lists hash differently, so the judge
must also refuse to slash the same directory or witness twice.

`fork_same_size`, `fork_contradiction` and `fork_rollback` each check one
condition and return the implicated IDs or `not_a_fork`; `fork_verify` checks
the kind the proof claims. `fork_kind_between` tells which kind two signed
checkpoints prove on their own: 1 (preferred, since it reveals only two
roots), 3, or 0 when only a consistency proof or a leaf comparison can decide.

Deterministic vectors (fixed seeds, hex fields, service and witness keys,
ring entries, FRK bytes, proof hash, implicated IDs, expected validity) are in
[`tests/fixtures/frk`](../tests/fixtures/frk). `transparency_fork.test.mpl`
regenerates them and fails when a file is stale; run it with
`MESSENGER_FRK_FIXTURE_WRITE=<dir>` to rewrite them. The judge replays the
same files.

## C2SP view

Morse's tree uses domain-separated hashes, so a stock C2SP witness, which
checks RFC 6962 proofs, can't verify it. The directory therefore keeps a
second tree over the same leaves, the **RFC 6962 view**: its leaf data is the
32-byte Morse leaf hash, so

- leaf = `SHA-256(0x00 || morse_leaf_hash32)`, node = `SHA-256(0x01 || l || r)`,
  empty root = `SHA-256("")`;

with the same shape, proofs and oracle (`Transparency.Tree`, tree 2). Leaf `i`
of both trees is always the same entry.

**Checkpoint note** (`Transparency.Note`): a
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body plus one extension
line binding the full Morse checkpoint, signed as a
[signed note](https://c2sp.org/signed-note):

```text
<origin>\n
<tree size, decimal>\n
<base64 RFC 6962 root>\n
morse-checkpoint <base64 KTK, 188 bytes>\n
\n
— <origin> <base64(key ID4 || Ed25519 signature64)>\n
```

- Origin: `morseapp.io/log/main` (canary `morseapp.io/log/canary`). The log's
  key name is the origin.
- The log signs with the transparency service key: signed-note type `0x01`,
  key ID = `SHA-256(origin || 0x0A || 0x01 || public key32)[:4]`, signature
  over the body including its final newline. Its verifier key, as witnesses
  are configured with it, is `<origin>+<hex key ID>+<base64(0x01 || key)>`
  (`note_verifier_key`).
- A witness cosignature ([tlog-cosignature](https://c2sp.org/tlog-cosignature)
  v1, Ed25519, type `0x04`) signs
  `"cosignature/v1\ntime " || decimal(timestamp seconds) || "\n" || body`; its
  line is `— <witness name> base64(key ID4 || u64 timestamp || signature64)`
  with key ID = `SHA-256(name || 0x0A || 0x04 || public key32)[:4]`. The name
  is not signed, so one key must never serve two witness names. The Morse
  statement and the C2SP message start with different bytes, so one witness
  key can safely sign both.
- **Push** ([tlog-witness](https://c2sp.org/tlog-witness) `add-checkpoint`):
  `"old " || decimal(old size) || "\n"`, one base64 line per RFC 6962
  consistency-proof hash (at most 63; none when the old size is 0), `"\n"`,
  then the signed note (`note_add_checkpoint_request`). Answers: 200 with one
  or more cosignature lines, each ending in a newline (`note_read_cosignatures`
  ignores other keys' lines and refuses a failing line from the expected key);
  409 with `Content-Type: text/x.tlog.size` and the witness's size as
  `"<decimal>\n"`; 404 unknown origin; 403 no valid signature from a trusted
  log key; 400 malformed or old size above the new one; 422 a consistency
  proof that fails, a same-size checkpoint with another root, or a size-0
  checkpoint whose root is not the empty root.

**What counts on a phone.** In `KTE` v2 a C2SP cosignature travels as a kind-2
attestation (timestamp and signature; the directory maps its C2SP name to the
registry's witness ID). A phone counts it for pinned witness W only when:

1. the pinned config has a C2SP origin (not `-`) and the `KTE` carries a C2SP
   view (`root6962`, path);
2. the RFC 6962 audit path proves `SHA-256(0x00 || leaf_hash(entry))` at the
   Morse proof's index and the checkpoint's size under `root6962`;
3. the cosignature verifies under W's pinned key over the body the phone
   rebuilds from the pinned origin, the checkpoint's size, `root6962` and the
   checkpoint's own KTK;
4. its timestamp (times 1,000) is fresh by the checkpoint rule: at most five
   minutes old and one minute ahead.

The witness vouches only for the first three lines (the specification says
cosigners assert nothing about extension lines), so the security rests on
rule 2: the entry the phone looked up sits at the same position in the history
the witness checked for append-only growth. The `morse-checkpoint` line only
ties that history to the Morse checkpoint the phone also verifies.

**Checked against the specifications** (C2SP signed-note, tlog-checkpoint,
tlog-cosignature, tlog-witness, editor's copies fetched 2026-09-29). The
formats above match them. Points the specifications add:

- Extension lines are allowed but "NOT RECOMMENDED". Ed25519 cosignatures sign
  them; ML-DSA-44 cosignatures (`subtree/v1`, type `0x06`) do not.
- The specifications now say witnesses SHOULD use ML-DSA-44 cosignatures. Mesh
  has no ML-DSA, so phones count only Ed25519 (`0x04`) cosignatures, and an
  outside C2SP witness must run with an Ed25519 key to count. Its ML-DSA lines
  are ignored as unknown keys.
- At most 63 proof lines per push; a cosignature timestamp is nonzero and
  below 2^63.
- Signed notes contain no control characters other than newline, and the text
  ends at the last blank line. Morse keeps names and origins to printable
  ASCII without space or `+`, a subset of what the specification allows.

**Checked against a real witness.** `scripts/c2sp-interop.sh` builds
FiloSottile's litewitness v0.10.0 (`filippo.io/torchwood`, an implementation
Morse did not write), registers the log with `witnessctl add-key` using the
verifier key Mesh computes, and pushes notes Mesh built. On 2026-09-29 it
passed: litewitness accepted the note with its `morse-checkpoint` line,
verified the log signature and the Mesh-generated RFC 6962 consistency proof
from size 5 to 9, and returned one Ed25519 cosignature per push, which Mesh
verified, both on its own and as a kind-2 attestation through the phone's
`KTE` v2 check. It refused a same-size fork (422), a stale old size (409, body
`9`) and a note signed by another key (403). The script skips when Go is not
installed.

## Witness software

The Morse witness (`services/transparency-witness`, run by operators with
[`ops/witness`](../ops/witness/README.md)) signs in one of two modes. `once` runs one round
and exits (the Cloudflare witnesses, called by the jobs Worker through
`/attest`). `pull` runs a round every 15 s: `GET /v1/transparency/checkpoint`,
then `POST /v1/transparency/witnesses` with a `KTW` holding one attestation.
It opens no port, and signs a new checkpoint within one poll, inside the 60 s
signing deadline.

Before signing a checkpoint it has not signed, a witness checks it against the
last checkpoint it signed, `L`:

1. The log's signature verifies.
2. **Stale state.** If the directory's attestation list for the checkpoint
   holds this witness's own valid signature while `L` is older (or absent), or
   the host's guard copy of its last signed checkpoint is newer than `L`, the
   state came from a backup: the witness halts until an operator restores
   continuity from the newer checkpoint.
3. **History.** A lower sequence or tree size (`rollback`), a different
   checkpoint at `L`'s sequence (`conflict`), a checkpoint at `L`'s sequence + 1
   whose previous-checkpoint hash is not `checkpoint_hash(L)` (`broken-link`),
   or a consistency proof that fails (`inconsistency`) is evidence. The same
   tree size needs no proof (equal roots, or `inconsistency`); otherwise the
   witness sends `KTS` v2 (`old_size` = `L`'s size, `new_size` = the
   checkpoint's size, tree 1) and verifies the `KTC` v2 answer, sending the
   `KTS` v1 query only when the directory refuses v2 with 400. A proof for
   other sizes than asked is an error to retry, not evidence.
4. **W1 timestamps.** The checkpoint's timestamp is within 60 s of the
   witness's clock and later than `L`'s. Otherwise the witness doesn't sign it
   now, and signs a later checkpoint normally.
5. The checkpoint replaces `L` in the state, then the witness signs.

On evidence the witness writes both `KTK`s, the directory's proof bytes and
attestation list, and the time to its evidence directory, stops signing for
good (a halt marker beside its state), and, when the two checkpoints alone
form a fork (`fork_kind_between` is 1 or 3), builds an `FRK` v1 (finder: none,
no attestations) and posts it to each configured relay as
`POST /v1/fork-evidence` with the `FRK` bytes as an `application/octet-stream`
body. A failed consistency proof alone needs a leaf comparison (`FRK` kind 2),
which a witness holding only checkpoints can't build; relays and monitors can.

State is written crash-safely: a temporary file, `File.sync`, then
`File.rename` over the old file, after a compare-and-swap check that the file
still holds what the round read. A primary and a standby share the state file
on one volume and run one at a time; whichever runs signs only what extends
the file. A missing state in pull mode is refused unless the operator starts
the witness as a new identity (`new-identity`) or transfers a checkpoint to
continue from.

## Phone check and bond counter

Status: implemented in mobile-core and the app (Settings → Network, banners,
"Details"); it runs once a release pins an anchor, RPC providers and relays in
the security config. The check itself, its request/answer steps and the trust
alarms are specified in [key-transparency-v1.md](key-transparency-v1.md), "The
phone's check against the public record"; the chain layouts it reads in
[morse-judge-v1.md](morse-judge-v1.md) §4 and §11.

- **Phone check** (plan §6.7): daily and after a contact's key change (at most
  hourly), the phone reads the pinned Log account and anchor ring from two
  agreeing pinned RPC providers, refuses a slashed service key, notes a public
  record more than two hours behind, and proves its own checkpoint consistent
  with the newest anchor through the directory. A refused or invalid proof is
  a mismatch: new chats and key changes stop, existing chats continue, and the
  phone files FRK proofs with every pinned relay, then watches where they
  land. A test build that pins the canary log checks the canary ring the same
  way (plan §11.3).
- **Bond counter** (plan §6.17), read with the same agreeing providers, never
  through Morse. Network status section 3 body: `u8 available || u8 counted ||
  u8 service_slashed || u8 slashed_witnesses || bond(directory) || u8 n ||
  n x (vector32(witness_id) || u8 status || bond)`, one row per pinned witness
  (the judge's status, 255 when the log does not list it); bond = `u8 asset
  (0 none, 1 USDC, 2 Morse token, 3 other) || u64 amount || u8 usd_known ||
  u64 usd_micros`, amounts in base units (6 decimals). It holds the pinned
  log's directory bond vault (Log offset 144), `service_slashed`, the number of
  listed witnesses whose status is Slashed, and each pinned witness's bond
  vault. USDC is told from the token by the judge Config's mints; a token bond
  has a USD value only while the rewards program's price feed (its TWAP,
  `morse-judge-v1.md` §10.4) is at most a day old, otherwise the token amount
  shows. When the providers disagree the counter is `available = 0`: shown as
  unavailable, never as a number. Only a log whose id is `morse-main` is
  counted (`counted = 0` for the canary log), so "Slashed: never" stays
  literally true. The app shows the bond lines once the directory's bond
  exists on chain, and always shows a slash.

## Open questions

- Chain: Solana (decided 2026-09-25). Its native Ed25519 program makes fork
  proofs cheap.
- A credit purchase is public on its chain. Clients should buy in batches and
  spend later to weaken timing correlation.
