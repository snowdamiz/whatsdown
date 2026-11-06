#!/usr/bin/env bash
set -euo pipefail
PRODUCT="$(cd "$(dirname "$0")/.." && pwd -P)"
PUBLIC="${MESH_LANG_ROOT:-$PRODUCT/../mesh-lang}"
PROOF="${MORSE_PROOF_DIR:-$(dirname "$PRODUCT")/.morse/witness-proof}"
MESHC="${MESHC:-$PUBLIC/target/debug/meshc}"
CARGO="${CARGO:-cargo}"
TARGET="${CARGO_TARGET_DIR:-$PRODUCT/programs/target}"
mkdir -p "$PROOF"
export MESHC MESH_LANG_ROOT="$PUBLIC"
export MORSE_JUDGE_SBF_PATH="${MORSE_JUDGE_SBF_PATH:-$PRODUCT/programs/target/deploy/morse_judge.so}"
export MORSE_REWARDS_SBF_PATH="${MORSE_REWARDS_SBF_PATH:-$PRODUCT/programs/target/deploy/morse_rewards.so}"
for artifact in "$MORSE_JUDGE_SBF_PATH" "$MORSE_REWARDS_SBF_PATH"; do
  [[ -s "$artifact" ]] || { echo 'Run prove-rewards.sh first; required SBF artifact is missing.' >&2; exit 1; }
done
CARGO_TARGET_DIR="$TARGET" "$CARGO" build --locked --manifest-path "$PRODUCT/programs/Cargo.toml" -p morse-rewards --features svm --example rewards_writer_bridge --example treasury_payment_fixture > "$PROOF/credits-treasury-sbf-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" "$CARGO" build --locked --manifest-path "$PRODUCT/tools/solana-nonce-proof/Cargo.toml" > "$PROOF/solana-nonce-agave-build.log" 2>&1
export MORSE_REWARDS_SBF_BRIDGE="$TARGET/debug/examples/rewards_writer_bridge"
export MORSE_REWARDS_TEST_OPERATOR_BIN="$PROOF/rewards-test-operator"
env -u CARGO_TARGET_DIR "$MESHC" build "$PRODUCT/ops/rewards/fixtures/operator" --opt-level 2 -o "$MORSE_REWARDS_TEST_OPERATOR_BIN" > "$PROOF/credits-treasury-rewards-planner-build.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" test "$PUBLIC/packages/mesh-solana/tests" > "$PROOF/solana-package-treasury.log" 2>&1
(cd "$PUBLIC" && env -u CARGO_TARGET_DIR "$CARGO" test --locked -p meshc --test e2e_solana_rpc_redirect) > "$PROOF/solana-rpc-redirect.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" test "$PRODUCT/ops/credit-treasury/policy.test.mpl" > "$PROOF/credits-treasury-split.log" 2>&1
env -u CARGO_TARGET_DIR python3 "$PRODUCT/scripts/prove-credit-issuer.py" > "$PROOF/credits-treasury-storage.log" 2>&1
env -u CARGO_TARGET_DIR SOLANA_NONCE_ORACLE="$TARGET/debug/morse-solana-nonce-proof" SOLANA_NONCE_REPORT="$PROOF/solana-nonce-bank.json" node --test "$PRODUCT/tools/solana-nonce-proof/nonce.test.mjs" > "$PROOF/solana-nonce-bank.log" 2>&1
env -u CARGO_TARGET_DIR SOLANA_NONCE_ORACLE="$TARGET/debug/morse-solana-nonce-proof" TREASURY_REPORT="$PROOF/credits-treasury-rpc.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-rpc.log" 2>&1
env -u CARGO_TARGET_DIR SOLANA_NONCE_ORACLE="$TARGET/debug/examples/treasury_payment_fixture" TREASURY_REPORT="$PROOF/credits-treasury-usdc.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-usdc.log" 2>&1
env -u CARGO_TARGET_DIR TREASURY_BATCH_PROOF=1 SOLANA_NONCE_ORACLE="$TARGET/debug/morse-solana-nonce-proof" TREASURY_REPORT="$PROOF/credits-treasury-batch-sol.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-batch-sol.log" 2>&1
env -u CARGO_TARGET_DIR TREASURY_BATCH_PROOF=1 TREASURY_SBF_BUYER_UNITS=9999998 SOLANA_NONCE_ORACLE="$TARGET/debug/examples/treasury_payment_fixture" TREASURY_REPORT="$PROOF/credits-treasury-batch-usdc.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-batch-usdc.log" 2>&1
env -u CARGO_TARGET_DIR TREASURY_BATCH_PROOF=1 TREASURY_BATCH_FAILURE=1 SOLANA_NONCE_ORACLE="$TARGET/debug/morse-solana-nonce-proof" TREASURY_REPORT="$PROOF/credits-treasury-batch-failure.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-batch-failure.log" 2>&1
env -u CARGO_TARGET_DIR TREASURY_PROOF_CASE=funding TREASURY_REPORT="$PROOF/credits-treasury-funding-sbf.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-funding-sbf.log" 2>&1
env -u CARGO_TARGET_DIR TREASURY_PROOF_CASE=service TREASURY_REPORT="$PROOF/credits-treasury-service.json" python3 "$PRODUCT/scripts/prove-credit-treasury.py" > "$PROOF/credits-treasury-service.log" 2>&1
if [[ "${TREASURY_DEFER_CHECKPOINT:-0}" != 1 ]]; then
  MORSE_PROOF_DIR="$PROOF" python3 "$PRODUCT/tools/solana-nonce-proof/treasury-report.py"
fi
printf 'Offline treasury accounting, restart and actual SBF funding gates passed. Evidence: %s\n' "$PROOF"
