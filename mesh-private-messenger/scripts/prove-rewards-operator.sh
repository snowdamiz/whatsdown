#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
proof_dir="${MORSE_REWARDS_PROOF_DIR:-$(dirname "$product")/.morse/witness-proof}"
compiler="${MESHC:-$(dirname "$product")/mesh-lang/target/debug/meshc}"
mkdir -p "$proof_dir"
export MORSE_REWARDS_FIXTURES_PATH="${MORSE_REWARDS_FIXTURES_PATH:-$proof_dir/rewards-program-fixtures.json}"
export MORSE_JUDGE_SBF_PATH="${MORSE_JUDGE_SBF_PATH:-$product/programs/target/deploy/morse_judge.so}"
export MORSE_REWARDS_SBF_PATH="${MORSE_REWARDS_SBF_PATH:-$product/programs/target/deploy/morse_rewards.so}"
for artifact in "$MORSE_REWARDS_FIXTURES_PATH" "$MORSE_JUDGE_SBF_PATH" "$MORSE_REWARDS_SBF_PATH"; do
  [[ -s "$artifact" ]] || { echo 'Run prove-rewards.sh first; required fresh artifacts are missing.' >&2; exit 1; }
done
if [[ -z "${MORSE_REWARDS_SBF_BRIDGE:-}" ]]; then
  cargo build --manifest-path "$product/programs/Cargo.toml" --locked \
    -p morse-rewards --features svm --example rewards_writer_bridge
  export MORSE_REWARDS_SBF_BRIDGE="$product/programs/target/debug/examples/rewards_writer_bridge"
fi
[[ -x "$MORSE_REWARDS_SBF_BRIDGE" ]]
"$compiler" build "$product/tools/rewards-operator" --opt-level 2 --output "$proof_dir/rewards-operator"
"$compiler" build "$product/ops/rewards/fixtures/operator" --opt-level 2 --output "$proof_dir/rewards-test-operator"
export MORSE_REWARDS_TEST_OPERATOR_BIN="$proof_dir/rewards-test-operator"
npm ci --prefix "$product/ops/rewards" --ignore-scripts --no-audit --no-fund
node --test "$product/ops/rewards/transactions.test.mjs" "$product/ops/rewards/journal.test.mjs" \
  "$product/ops/rewards/writer.test.mjs" "$product/ops/rewards/mesh-sbf.test.mjs" \
  "$product/ops/chain-writer/rpc.test.mjs"
"$compiler" test "$product/packages/messenger-protocol/security/rewards-chain.test.mpl"
"$compiler" test "$product/packages/messenger-protocol/security/rewards-read.test.mpl"
MESHC="$compiler" node --test "$product/scripts/rewards-command.test.mjs"
