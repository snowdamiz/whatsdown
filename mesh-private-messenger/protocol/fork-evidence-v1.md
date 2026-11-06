# Fork evidence v1

`Transparency.Fork` implements portable evidence of a log's inconsistent
history. It checks evidence without consulting the network, the wall clock,
account records or a wallet. The judge's proof window, registered log lookup,
pay-once record and payout rules are separate admission rules.

## Trust and attribution

`fork_same_size`, `fork_contradiction` and `fork_rollback` take a `ForkProof`,
the caller's trusted log `SigningPublicKey`, and up to 16 `WitnessKey` pins.
They return the implicated service key and the witnesses proven to have signed
both conflicting views. They require both checkpoints to have the same signed
log version and verify under that trusted log key. The service key carried in evidence cannot select a new log
for the caller.

- Kind 1: equal tree sizes and different roots. Sequence numbers may differ.
- Kind 2: different leaf hashes at the same index, below both tree sizes, with
  exact compact inclusion paths to both signed roots. The paths use the
  hash profile selected by the signed checkpoint: original Morse hashes for
  v1, RFC 6962 hashes for v2. The evidence carries hashes, not raw entry bytes.
- Kind 3: sequence ordering disagrees with tree-size ordering, or equal
  sequence numbers have different complete checkpoint hashes. An unchanged
  root signed with a different timestamp at the same sequence is equivocation.

An honest extension, an identical checkpoint, an invalid log signature or an
invalid inclusion path cannot prove a fork. Prefer kind 1 whenever available:
kind 2 exposes a leaf position that may reveal which account was targeted.

Witness attribution does not require a quorum. The directory can be implicated
with no witness signatures. Unknown or invalid witness signatures do not
implicate anyone. Repeated signatures cannot add accusations; an invalid
copy cannot conceal a later valid copy. Witness pins require distinct IDs and
keys. A witness that signed only one conflicting view is not implicated.

`fork_at_anchor` also accepts a `ForkAnchor` supplied by an authenticated chain
reader, or by the judge after validating its accounts. This is a **trusted
input boundary**: callers must validate the log, ring ownership/PDA, ring entry
and witness-key mapping before constructing it. The chain's `post_anchor` and
`cosign` verification establish the service signature and cosigners. A bare
RPC response or evidence-supplied ring index is insufficient. The verifier
checks the requested index, log version and key, uses the anchored position, and
intersects its verified cosigners with valid signatures on the first
checkpoint. The signed-checkpoint APIs reject unresolved references.

`ForkAnchor.native_cosigners` identifies the authenticated subset whose
attestations also promise Morse's metadata checks. Kind 3 only attributes keys
with native signatures on both checkpoints (or in that anchored subset).
C2SP signatures authenticate the extension without making those additional
claims; kinds 1 and 2 can attribute either signature type.

The chain reader and the local judge anchor subset are implemented; deployed
chain trust, proof admission and slashing remain subsequent work.

`Transparency.Relay.verify_relay_fork` supplies the off-chain relay preflight.
It rejects invalid signed evidence before network I/O, resolves the Log and
referenced entry through the pinned two-of-three RPC reader, and uses the
entry's historical set for witness attribution. It preserves FRK/finder bytes
exactly. Signed-only attribution currently discovers the active generation;
the result reports that scope and does not claim to resolve every historical
key. A caller's ACV3 context is never a trusted input. The
[native verifier command](../tools/fork-verifier/README.md) exposes this same
Mesh API for the upcoming JavaScript writer. Cryptographic preflight does not
replace the judge's time window, custody or payout checks.

## Canonical bytes

All integers are unsigned big-endian. Frames with at most 16 attestations use
v1 when all signatures are native (maximum **5,145 bytes**), or v2 when any
signature is C2SP (maximum **5,289 bytes**). V2 adds an algorithm byte after
each checkpoint hash: `0` then 64 native signature bytes, or `4` then a 72-byte
C2SP payload. Their encodings are unchanged.

V3 carries **17–32 attestations**, using the same algorithm tags as v2 even
when every signature is native. It allows all 16 pinned witnesses to be
implicated by a pair of signatures, rather than truncating evidence after eight
witnesses. Its maximum is **8,009 bytes**, within the relay's 8 KiB body limit.
A v3 frame with 16 or fewer attestations is noncanonical. Canonical re-encoding
determines the frame version.
Decode checks lengths, versions, complete input and canonical re-encoding
before any signature operation. Decoding alone does not verify a fork.

| Field | Bytes |
|---|---:|
| Version `1`, `2` or `3`, magic `FRK`, kind `1`–`3` | 5 |
| Finder Solana address; all zero means absent | 32 |
| Log service public key | 32 |
| First checkpoint in canonical `KTK` v1 or v2 | 188 |
| Second-target tag: `0` = checkpoint, `1` = ring reference | 1 |
| Tag 0: second `KTK`; tag 1: ring index u32, range 0–4095 | 188 or 4 |
| Attestation count: v1/v2 0–16, v3 17–32 | 1 |
| V1 attestation: u8 UTF-8 ID length 1–64, ID, checkpoint hash, signature | 1 + ID length + 32 + 64 |
| V2/v3 attestation: same, with algorithm byte and variable signature | 1 + ID length + 32 + 1 + (64 or 72) |

Kind 2 then appends:

| Field | Bytes |
|---|---:|
| Leaf index | 8 |
| First audit path count 0–32, then hashes from leaf to root | 1 + count × 32 |
| First leaf hash | 32 |
| Second audit path count 0–32, then hashes from leaf to root | 1 + count × 32 |
| Second leaf hash | 32 |

Other kinds have no extension. The format preserves attestation order; a proof producer
can omit irrelevant attestations before encoding. Relays preserve submitted
canonical bytes, including the named finder. It uses u8 ID
lengths and counts, unlike the existing `KTW` container. A checkpoint target
always has the explicit `0` tag, so neither decoder guesses its representation.

`fork_hash` is SHA-256 over the entire canonical frame **except bytes 5–36**, the
finder address. It does not replace those bytes with zeros and adds no prefix.
Changing the finder preserves the hash. Reordering the two checkpoints or
attestations produces a different encoded proof and may change the hash; the
judge must also enforce its permanent directory/witness slashed state, not rely
solely on proof-hash deduplication for bond safety.

## Verification

`tests/fixtures/fork-v1/vectors.json` is shared input for Mesh and the judge parser. The generator in `scripts/fork-vectors.mjs` independently builds the
wire, roots, paths, Ed25519 signatures and SHA-256 hashes using Node/OpenSSL.
All private seeds there are deterministic public test data.

Run `node --test mesh-private-messenger/scripts/fork-oracle.test.mjs` from the
repository root. It verifies reproducibility, invokes the Mesh public API for
every vector, and proves that altering the expected hash is detected. Native
`tests/fork.test.mpl` additionally exercises truncation at every byte, groupings
of double signers, honest pairs, log pinning and resolved anchors. Full protocol
verification runs `meshc test tests` from `packages/messenger-protocol`.

## Judge staging

The [staging ABI](judge-stage-v1.md) implements uploads, sealing, exact signature
verification and submitter rent refunds. The same FRK framing/hash/relations run
in Rust and Mesh, with independent OpenSSL fixtures. Stage verification uses
real Ed25519 precompiles in LiteSVM. A sealed stage or verified signature bitmap
is **not** a fork verdict or payment receipt: proof-age admission, authenticated
anchor adjudication, custody, slashing and payouts remain unfinished.
