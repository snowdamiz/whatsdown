#!/usr/bin/env bash
set -euo pipefail
PRODUCT="$(cd "$(dirname "$0")/.." && pwd -P)"
PUBLIC="${MESH_LANG_ROOT:-$PRODUCT/../mesh-lang}"
PROOF="${MORSE_PROOF_DIR:-$(dirname "$PRODUCT")/.morse/witness-proof}"
MESHC="${MESHC:-$PUBLIC/target/debug/meshc}"
BUILDER="${CARGO_BUILD_SBF:-cargo-build-sbf}"
mkdir -p "$PROOF"
export TOKEN_INCLUDE_DEX="${TOKEN_INCLUDE_DEX:-1}"
if [[ "$TOKEN_INCLUDE_DEX" != 1 ]]; then
  echo 'The required token gate includes the actual pinned DEX execution proof.' >&2
  exit 2
fi
export MORSE_TOKEN_DEX_BIN_DIR="${MORSE_TOKEN_DEX_BIN_DIR:-$PROOF/token-dex}"
FEATURES="morse-token/svm"
if [[ "$TOKEN_INCLUDE_DEX" == 1 ]]; then
  python3 "$PRODUCT/ops/token/fetch-dex.py" > "$PROOF/token-dex-fixtures.log" 2>&1
  FEATURES="$FEATURES,morse-token/dex"
fi
export MORSE_TOKEN_FIXTURES_PATH="$PROOF/token-sbf-fixtures.json"
export MORSE_TOKEN_BURN_FIXTURES_PATH="$PROOF/token-burn-fixtures.json"
export MORSE_TOKEN_CUSTODY_FIXTURES_PATH="$PROOF/token-custody-fixtures.json"
export MORSE_TOKEN_CARRY_FIXTURES_PATH="$PROOF/token-carry-fixtures.json"
unset MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH MORSE_TOKEN_CARRY_JOURNAL_PATH MORSE_TOKEN_CARRY_JOURNAL_KEY MORSE_TOKEN_CARRY_JOURNAL_STAGE MORSE_TOKEN_CARRY_RPC
unset MORSE_TOKEN_WRITE_INSTRUCTIONS_PATH
export MORSE_TOKEN_SBF_PATH="$PRODUCT/programs/target/deploy/morse_token.so"
export MORSE_PROOF_DIR="$PROOF"
cd "$PRODUCT"
cargo fmt --manifest-path programs/Cargo.toml --all --check > "$PROOF/token-format.log" 2>&1
cargo clippy --locked --manifest-path programs/Cargo.toml -p morse-token -p morse-token-program -p morse-judge -p morse-judge-program -p morse-rewards -p morse-rewards-program --features "$FEATURES,morse-judge/svm" --all-targets -- -D warnings > "$PROOF/token-clippy.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-rewards-math -p morse-token --lib > "$PROOF/token-math.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-judge --lib token_custody::tests > "$PROOF/token-judge-model.log" 2>&1
python3 ops/token/build-sbf.py "$BUILDER"
cargo test --locked --manifest-path programs/Cargo.toml -p morse-token --features "$FEATURES" --test token_svm -- --nocapture > "$PROOF/token-program.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-judge --features svm --lib --tests -- --nocapture > "$PROOF/token-judge.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-rewards --features svm --test rewards_svm -- --nocapture > "$PROOF/token-rewards-legacy.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" fmt --check ops/token > "$PROOF/token-mesh-format.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" lint ops/token > "$PROOF/token-mesh-lint.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" fmt --check ops/token-v2 > "$PROOF/token-v2-mesh-format.log" 2>&1
: > "$PROOF/token-v2-mesh-lint.log"
for source in token_custody token_rewards token_write token_policy token_chain token_burn token_burn_write token_burn_carry token_burn_carry_write token_burn_read token_burn_carry_read; do
  env -u CARGO_TARGET_DIR "$MESHC" fmt --check "packages/messenger-protocol/transparency/$source.mpl" >> "$PROOF/token-v2-mesh-format.log" 2>&1
  env -u CARGO_TARGET_DIR "$MESHC" lint "packages/messenger-protocol/transparency/$source.mpl" >> "$PROOF/token-v2-mesh-lint.log" 2>&1
done
env -u CARGO_TARGET_DIR "$MESHC" lint ops/token-v2 >> "$PROOF/token-v2-mesh-lint.log" 2>&1
export MORSE_TOKEN_WRITE_INSTRUCTIONS_PATH="$PROOF/token-v2-mesh-instructions.json"
export MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH="$PROOF/token-carry-mesh-instructions.json"
env -u CARGO_TARGET_DIR "$MESHC" test ops/token-v2 > "$PROOF/token-v2-codecs.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-judge --features svm --test token_custody_svm -- --nocapture > "$PROOF/token-v2-write-sbf.log" 2>&1
cargo test --locked --manifest-path programs/Cargo.toml -p morse-token --features "$FEATURES" --test token_svm missed_input_is_closed_once -- --nocapture > "$PROOF/token-carry-write-sbf.log" 2>&1
unset MORSE_TOKEN_WRITE_INSTRUCTIONS_PATH MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH
env -u CARGO_TARGET_DIR MESHC="$MESHC" node --test ops/token/burn_rpc.test.mjs > "$PROOF/token-mesh.log" 2>&1
env -u CARGO_TARGET_DIR MESHC="$MESHC" node --test ops/token-v2/reward_rpc.test.mjs > "$PROOF/token-v2-reward-rpc.log" 2>&1
env -u CARGO_TARGET_DIR MESHC="$MESHC" node --test ops/token-v2/burn_carry_rpc.test.mjs > "$PROOF/token-carry-rpc.log" 2>&1
MESHC="$MESHC" MORSE_PROOF_DIR="$PROOF" python3 ops/token/report.py
printf 'Local token foundation gates passed. Phase5 remaining work is explicit in token-local.json. Evidence: %s\n' "$PROOF"
