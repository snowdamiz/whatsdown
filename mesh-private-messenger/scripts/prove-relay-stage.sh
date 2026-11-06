#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
meshc="${MESHC:-meshc}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export MORSE_RELAY_STAGE_FIXTURES_PATH="${MORSE_RELAY_STAGE_FIXTURES_PATH:-$work/relay-stages.ndjson}"
"$meshc" test "$product/packages/messenger-protocol/tests/relay_stage.test.mpl"
if [[ -n "${MORSE_RELAY_STAGE_PROOF_BINARY:-}" ]]; then
  "$MORSE_RELAY_STAGE_PROOF_BINARY" mesh_prepared_stage_transactions_execute_in_sbf --ignored --exact
else
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge \
    --features svm --test stage_svm mesh_prepared_stage_transactions_execute_in_sbf -- --ignored --exact
fi
