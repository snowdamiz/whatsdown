#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
builder="${CARGO_BUILD_SBF:-cargo-build-sbf}"
proof_dir="${MORSE_REWARDS_PROOF_DIR:-$(dirname "$product")/.morse/witness-proof}"
mkdir -p "$proof_dir"
export MORSE_REWARDS_FIXTURES_PATH="${MORSE_REWARDS_FIXTURES_PATH:-$proof_dir/rewards-program-fixtures.json}"
run_proof() {
  version="$("$builder" --version)"
  if [[ "$version" != *'cargo-build-sbf 4.4.0'* ]]; then
    echo 'Install cargo-build-sbf 4.4.0 before this proof.' >&2
    return 1
  fi
  cargo fmt --manifest-path "$product/programs/Cargo.toml" --all -- --check
  cargo clippy --manifest-path "$product/programs/Cargo.toml" --locked \
    -p morse-rewards-math -p morse-rewards -p morse-rewards-program \
    --features morse-rewards/svm --all-targets -- -D warnings
  sbf_work="$(mktemp -d)"
  trap 'rm -rf "$sbf_work"' EXIT
  for manifest in "$product/programs/morse-rewards-program/Cargo.toml" \
    "$product/programs/morse-judge-program/Cargo.toml"; do
    CARGO_TARGET_DIR="$sbf_work/target" "$builder" --manifest-path "$manifest" \
      --arch v0 --tools-version v1.57 --sbf-out-dir "$product/programs/target/deploy" -- --locked \
      2>&1 | tee "$sbf_work/build.log"
    if grep -Eq '(^|[[:space:]])(Error:|error:|error\[)' "$sbf_work/build.log"; then
      echo 'SBF compiler diagnostics rejected rewards; no SBF test was run.' >&2
      return 1
    fi
  done
  export MORSE_JUDGE_SBF_PATH="$product/programs/target/deploy/morse_judge.so"
  export MORSE_REWARDS_SBF_PATH="$product/programs/target/deploy/morse_rewards.so"
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked \
    -p morse-rewards-math -p morse-rewards --features morse-rewards/svm
}
run_proof 2>&1 | tee "$proof_dir/rewards-program.log"
