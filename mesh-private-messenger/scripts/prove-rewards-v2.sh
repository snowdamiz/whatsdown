#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
root="$(dirname "$product")"
proof_dir="${MORSE_REWARDS_V2_PROOF_DIR:-$root/.morse/rewards-v2}"
compiler="${MESHC:-$root/mesh-lang/target/debug/meshc}"
cargo="${CARGO:-cargo}"
builder="${CARGO_BUILD_SBF:-cargo-build-sbf}"
: "${MESH_RT_LIB_PATH:?Set MESH_RT_LIB_PATH to the runtime built with MESHC}"
: "${MORSE_TOKEN_CUSTODY_FIXTURES_PATH:?Set an explicit custody fixture path; this proof records its reused hash}"
[[ -s "$MORSE_TOKEN_CUSTODY_FIXTURES_PATH" && -x "$compiler" && -s "$MESH_RT_LIB_PATH" ]]
mkdir -p "$proof_dir/sbf"
export MORSE_JUDGE_SBF_PATH="$proof_dir/sbf/morse_judge.so"
export MORSE_TOKEN_SBF_PATH="$proof_dir/sbf/morse_token.so"
export MORSE_REWARDS_SBF_PATH="$proof_dir/sbf/morse_rewards.so"
export MORSE_REWARDS_V2_OPERATOR_BIN="$proof_dir/operator"
export MORSE_REWARDS_V2_SBF_BRIDGE="${CARGO_TARGET_DIR:-$product/programs/target}/debug/examples/rewards_v2_bridge"
export MORSE_REWARDS_V2_BRIDGE="$MORSE_REWARDS_V2_SBF_BRIDGE"
build_command=("$builder" --tools-version v1.57 --arch v0)
if [[ -n "${SBF_RUSTC:-}" ]]; then
  build_command=(env "RUSTC=$SBF_RUSTC" "${build_command[@]}" --no-rustup-override)
fi
for name in token judge rewards; do
  "${build_command[@]}" --manifest-path "$product/programs/morse-$name-program/Cargo.toml" \
    --sbf-out-dir "$proof_dir/sbf" -- --locked \
    > "$proof_dir/$name-sbf.txt" 2>&1
done
"$cargo" build --manifest-path "$product/programs/Cargo.toml" --locked \
  -p morse-rewards --features svm --example rewards_v2_bridge > "$proof_dir/bridge-build.txt" 2>&1
"$cargo" test --manifest-path "$product/programs/Cargo.toml" --locked \
  -p morse-rewards --features svm --example rewards_v2_bridge > "$proof_dir/bridge-tests.txt" 2>&1
"$compiler" build "$product/tools/rewards-v2-operator" --opt-level 2 \
  --output "$MORSE_REWARDS_V2_OPERATOR_BIN" > "$proof_dir/build.txt" 2>&1
npm ci --prefix "$product/ops/rewards" --ignore-scripts --no-audit --no-fund
node --test "$product/ops/rewards/transactions.test.mjs" "$product/ops/rewards/journal.test.mjs" \
  "$product/ops/rewards/writer.test.mjs" "$product"/ops/rewards/v2-*.test.mjs \
  "$product/ops/chain-writer/rpc.test.mjs" \
  "$product/programs/morse-rewards/examples/support/rewards_v2_kit.test.mjs" > "$proof_dir/node-tests.txt" 2>&1
for source in "$product/ops/token-v2/reward_operator.mpl" "$product/tools/rewards-v2-operator/main.mpl"; do
  "$compiler" fmt --check "$source"
  "$compiler" lint "$source"
done
python3 "$product/scripts/rewards-v2-receipt.py" "$root" "$proof_dir" "$compiler" "$MESH_RT_LIB_PATH"
echo "PASS: explicit v2 rewards local execution; receipt: $proof_dir/receipt.json"
