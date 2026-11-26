# morse-relay

A relay lands fork evidence on-chain ([plan §6.9](../../../WITNESS_NETWORK_PLAN.md),
[morse-judge-v1.md §9](../../protocol/morse-judge-v1.md)). Phones post an `FRK`
([witness-network-v1.md](../../protocol/witness-network-v1.md), "Fork evidence") to
every pinned relay; monitors and operators may too. A relay is a chain writer, so it
is JavaScript on `@solana/kit`, standalone, with its own funded wallet.

For each evidence body it:

1. verifies it off-chain first (the judge's rules, §7.1 and §7.3: the proof's
   service key is a served log's, both checkpoints are service-signed, the fork
   rule holds, the 28-day window is open), so spam costs no fees;
2. completes a contradiction proof against a ring reference: a phone holds only its
   own side, so the relay fetches the public version's leaf and audit path from the
   log's directory (`POST /v1/transparency/leaf`, `KTP` v2 → `KTL` v2) and checks it
   against the ring entry's root rather than trusting it;
3. drops attestations the judge would refuse (a listed witness's attestation on C1
   or C2 whose signature fails): they implicate nobody and would block the proof;
4. submits from its own wallet: inline when one transaction fits, else staged
   (`stage_init`, `stage_write` in 1,000-byte chunks, `stage_verify` with as many
   Ed25519 entries per transaction as fit), then `prove_*` with the implicated
   witnesses in list order, and an address lookup table when more than nine are
   implicated;
5. passes a nonzero finder address through unchanged and creates its associated
   token account (`CreateIdempotent`, about 0.002 SOL of rent, paid by the relay);
   with a zero finder address the relay's own wallet is paid;
6. retries until its proof lands or another proof of the same fork does
   (`AlreadyProven` / `NothingToSlash`: the pay-once `["proof", hash]` account).

Completing or trimming the evidence changes its proof hash (the hash covers every
byte except the finder). The response carries the hash of the proof the relay
lands.

## Relay terms

- **Never substitute a finder address.** The address in the evidence is paid, or the
  relay's own wallet when the evidence names none. The code has no option to change
  it. A relay shown to have substituted an address is unpinned in the next release.
- Forwarding costs a few cents per proof and earns nothing (plan §9): a few
  transaction fees, rent for the Proof account and the finder's token account
  (about 0.004 SOL together), and stage rent that comes back when the stage
  closes. Keep the wallet funded.
- Keep the wallet key on the relay host only; it holds SOL for fees and the finder
  shares of zero-address proofs.

## Run

```sh
cd mesh-private-messenger/ops/relay
npm ci
node cli.mjs serve --port 8787 --wallet relay-wallet.json \
  --rpc https://rpc.example --judge <morse-judge program id> \
  --log morse-main=https://<directory origin> [--log morse-canary=https://<canary directory origin>]
```

or with the Docker image (`Dockerfile`; configuration by environment:
`MORSE_RELAY_WALLET`, `MORSE_RELAY_RPC`, `MORSE_JUDGE_PROGRAM_ID`,
`MORSE_RELAY_LOGS` as `name=origin,name=origin`, `MORSE_RELAY_PER_MINUTE`,
`MORSE_RELAY_TRUST_PROXY=1` behind a proxy that sets `X-Forwarded-For`, `PORT`).
Each log is the judge's `["log", name]` account; the relay matches evidence to a log
by the service key in it.

`POST /v1/fork-evidence` takes the raw `FRK` (at most 8,192 bytes) and answers:

| Status | Body | Meaning |
|---|---|---|
| 202 | `{"status":"submitting","proof_hash","completed"}` | valid; landing in the background |
| 200 | `{"status":"landed","proof_hash","paid_to","slot"}` | this proof is already on-chain |
| 400 | `{"error":"frk_malformed"}` | does not decode |
| 413 | `{"error":"too_large"}` | over 8,192 bytes |
| 422 | `{"error":"not_a_fork" \| "wrong_log_key" \| "unknown_log" \| "checkpoint_unsigned" \| "ring_index_invalid" \| "proof_window_closed" \| "completion_invalid"}` | the judge would refuse it |
| 429 | `{"error":"rate_limited"}` | more than `--per-minute` (default 6) posts from one address |
| 503 | `{"error":"completion_unavailable" \| "unavailable"}` | the directory or RPC failed; retry |

`GET /health` answers `{"ok":true}`.

Manual fallback (a phone's "Details" screen exports the evidence file):

```sh
node cli.mjs submit evidence.frk --wallet <keypair.json> --rpc https://… --judge <id> --log morse-main=https://…
```

## Alerts

| Line | Meaning (plan §12) |
|---|---|
| `P0 fork_evidence_received log=<name> kind=<k> proof=<hash>` | valid fork evidence arrived: page Morse and every operator |
| `P0 relay_finder_mismatch proof=<hash> expected=<address> paid=<address>` | a landed proof paid an address other than the one in the evidence this relay received: page the relay's operator. It also happens honestly when a monitor or another phone proved the same fork first |

## Tests

```sh
npm test    # FRK vectors (tests/fixtures/frk), completion, trimming, staging, retries, HTTP, rate limit
node --test ../drills/local-validator.test.mjs   # against a local judge (needs the Solana CLI)
```
