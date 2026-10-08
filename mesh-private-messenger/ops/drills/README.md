# Drills

Scheduled drills of the witness network ([plan](../../../WITNESS_NETWORK_PLAN.md)
§4.3, §11.3), run against the canary log in production, devnet in staging, or a
local validator. They use the relay's client (`../relay/judge.mjs`), so run
`npm ci` in `ops/relay` first.

| Script | Does |
|---|---|
| `canary-fork.mjs` | The monthly fork drill up to the phone step, then the re-bond |
| `rewards.mjs` | The weekly rewards drill: settle with zero payable witnesses, check the carry-over |
| `fund-pool.mjs` | Builds (never signs) the weekly `fund_pool` transaction for the treasury's signers |
| `close-log.mjs` | Builds (never signs) governance's `close_log`, which returns a slashed canary log's ring rent 28 days after the slash |
| `local.mjs` | A local validator with `morse-main` and `morse-canary` set up, for running the drills by hand |
| `local-validator.test.mjs` | The integration test: anchor poster, cosign crank, bond counter, relay and both drills against a local judge |

The weekly outage drill (§4.3 check 2) and the schedule that runs these drills
are in [ops/acceptance](../acceptance/README.md).

## Canary fork drill

```sh
node ops/drills/canary-fork.mjs --rpc <URL> --judge <ID> --log morse-canary \
  --service-key canary-service.hex --witness t3 --witness-key t3.hex \
  --anchor canary-anchor.json --payer payer.json --relay https://<relay origin> \
  [--finder <one-time address>] [--operator t3-operator.json --new-witness-key t3-next.hex] \
  [--governance governance.json | --governance-vault <Squads vault>]
```

1. Signs two checkpoints with the canary service key (a local file: the seed as 64
   hex characters): the same sequence and size, different roots.
2. Anchors one with `post_anchor` (the canary anchor authority) and has T3 cosign it
   on-chain; T3 also signs the other one as an attestation.
3. Builds the `FRK` a phone would build: the version it was shown, inline, against
   the ring reference of the public one, with T3's attestation and the finder
   address (`--finder`, or zeros).
4. Files it through a relay (`--relay`; without it, `--relay-wallet` files it
   in-process with the same code) and waits for the proof account.
5. Checks the slash: `service_slashed`, T3 Slashed, and the finder's 10%.
6. Re-bonds T3 under a new ID (`t3-rYYYYMMDD`) in its list slot: the operator
   registers it with the new witness key, governance admits it (sent with a local
   `--governance` key, or printed as a Squads vault transaction for
   `--governance-vault`), then the operator bonds. Configure the T3 host with the
   new ID and key.

A slashed directory bond is final and a slashed canary log takes no more
anchors: after a drill has slashed the canary directory, the canary log must be
re-provisioned before the next one (a new log name and service key,
`register-log --canary`, `grow-ring`, `bond-directory`, T1-T3 registered and
admitted; the drill prints the steps; [morse-judge-v1.md](../../protocol/morse-judge-v1.md) §12).
Canary logs are registered with kind 1 (`LOG_CANARY`), the only kind `close_log`
accepts: 28 days after the slash, governance reclaims the old ring's rent (about
2.2 SOL) with the message `close-log.mjs` prints:

```sh
node ops/drills/close-log.mjs --judge <ID> --log <old name> --authority <JUDGE_VAULT> --destination <account> [--stage STAGE:SUBMITTER ...]
```

### Where the phone step plugs in

Plan §11.3 step 3 is a canary phone in a test build: it detects the mismatch
against the canary ring and posts the `FRK` to the relays itself, naming a
one-time finder address from `wallet-core` (Phase 4). Until that build exists the
drill stands in for it at step 3 above. To switch over:

- give the canary test build a security config with the canary log's anchor line,
  the canary relays and the canary transparency key;
- run steps 1-2 with the drill, but show the phone the unanchored version (serve
  it from the canary directory, or hand it to the test build) instead of letting the
  drill build the evidence;
- let the phone post to the relays, then run only the checks: the proof account for
  the phone's proof hash, the slash, and `paid_to` equal to the phone's one-time
  address (step 5 of §11.3; before Phase 4 the finder field is zeros and the relay
  keeps the share).

In `canaryForkDrill()` the phone replaces the blocks marked 3 (building the
evidence) and 4 (filing it); the checks from the proof account on stay as they
are, with the phone's proof hash.

## Rewards drill

```sh
node ops/drills/rewards.mjs --rpc <URL> --rewards <ID> --payer payer.json [--epoch N]
```

Settles the last finished epoch (unless the weekly job already did) and fails if
anything was allocated to an excluded or inactive witness, if pool money moved,
or, with no payable witness (Bootstrap), if anything was allocated at all. It
prints the budget, allocations and carry-over.

## By hand, locally

```sh
cd mesh-private-messenger/ops/relay && npm ci && cd ../..
node ops/drills/local.mjs --port 18990 --dir /tmp/morse-drill
```

starts `solana-test-validator` with both programs (built with `cargo-build-sbf`
when missing; programs/README.md), sets up `morse-main` and `morse-canary` with a
local governance key, writes the key files into the directory, and prints the drill
command lines. Start a relay on a port other than the validator's RPC port + 1
(its websocket), e.g. `node ops/relay/cli.mjs serve --port 18999 …`. Stop with
Ctrl-C.

The integration test does the same end to end and skips when the Solana tools are
missing:

```sh
node --test ops/drills/local-validator.test.mjs   # port 18990; MORSE_DRILL_RPC_PORT to change
```
