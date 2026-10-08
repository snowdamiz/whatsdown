#!/usr/bin/env bash
# Local-validator smoke test: builds both programs, starts a throwaway
# solana-test-validator with them deployed (upgradeable, so `initialize` can
# check the upgrade authority), runs tests/src/bin/smoke.rs against it, and
# stops the validator it started.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH" # rustup's cargo, not Homebrew's
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
PORT="${SMOKE_RPC_PORT:-18899}"

cargo-build-sbf --manifest-path morse-judge/Cargo.toml
cargo-build-sbf --manifest-path morse-rewards/Cargo.toml
cargo build -q -p morse-program-tests --bin smoke

WORK="$(mktemp -d)"
solana-keygen new --no-bip39-passphrase --silent --force -o "$WORK/deployer.json" >/dev/null
JUDGE="$(solana address -k target/deploy/morse_judge-keypair.json)"
REWARDS="$(solana address -k target/deploy/morse_rewards-keypair.json)"

solana-test-validator --reset --quiet --ledger "$WORK/ledger" \
  --rpc-port "$PORT" --faucet-port "$((PORT + 1001))" --gossip-port "$((PORT + 1002))" \
  --dynamic-port-range "$((PORT + 1010))-$((PORT + 1040))" \
  --upgradeable-program "$JUDGE" target/deploy/morse_judge.so "$WORK/deployer.json" \
  --upgradeable-program "$REWARDS" target/deploy/morse_rewards.so "$WORK/deployer.json" \
  >"$WORK/validator.log" 2>&1 &
VALIDATOR=$!
# `|| true`: the killed validator's status (143) would otherwise fail the run under set -e.
trap 'kill "$VALIDATOR" 2>/dev/null; wait "$VALIDATOR" 2>/dev/null || true; rm -rf "$WORK"' EXIT

URL="http://127.0.0.1:$PORT"
for _ in $(seq 1 60); do
  if curl -s "$URL" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"'; then
    break
  fi
  sleep 1
done

target/debug/smoke "$URL" "$JUDGE" "$REWARDS" "$WORK/deployer.json"

# The runbook tool against the same validator: read-only status, and one
# governance action printed for Squads.
cargo build -q -p morse-program-tests --bin morse-admin
target/debug/morse-admin show --url "$URL" --judge "$JUDGE" --log morse-main
target/debug/morse-admin gov set-anchor-authority morse-main --judge "$JUDGE" \
  --authority "$(solana address -k "$WORK/deployer.json")" --anchor 11111111111111111111111111111111 >/dev/null
echo "smoke: morse-admin OK"
