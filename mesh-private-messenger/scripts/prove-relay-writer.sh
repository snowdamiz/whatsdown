#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export MORSE_ADJUDICATION_FIXTURES_PATH="${MORSE_ADJUDICATION_FIXTURES_PATH:-$work/custody.json}"
export MORSE_RELAY_ANCHORED_FIXTURES_PATH="${MORSE_RELAY_ANCHORED_FIXTURES_PATH:-$work/anchored.json}"
export MORSE_RELAY_MAXIMUM_FIXTURES_PATH="${MORSE_RELAY_MAXIMUM_FIXTURES_PATH:-$work/maximum.json}"
export MORSE_RELAY_SETTLEMENT_PLANS_PATH="${MORSE_RELAY_SETTLEMENT_PLANS_PATH:-$work/plans.ndjson}"
export MORSE_RELAY_STAGE_READ_FIXTURES_PATH="${MORSE_RELAY_STAGE_READ_FIXTURES_PATH:-$work/stage-recovery.json}"
export MORSE_RELAY_LOOKUP_READ_FIXTURES_PATH="${MORSE_RELAY_LOOKUP_READ_FIXTURES_PATH:-$work/lookup-recovery.json}"
export MORSE_RELAY_SETTLEMENT_READ_FIXTURES_PATH="${MORSE_RELAY_SETTLEMENT_READ_FIXTURES_PATH:-$work/settlement-recovery.json}"
export MORSE_RELAY_EFFECT_REPORTS_PATH="${MORSE_RELAY_EFFECT_REPORTS_PATH:-$work/effects.ndjson}"
export MORSE_RELAY_PLAN_REVISIONS_PATH="${MORSE_RELAY_PLAN_REVISIONS_PATH:-$work/revisions.ndjson}"
if [[ -z "${MORSE_RELAY_SBF_BRIDGE:-}" ]]; then
  cargo build --manifest-path "$product/programs/Cargo.toml" --locked \
    -p morse-judge --features svm --example relay_writer_bridge
  export MORSE_RELAY_SBF_BRIDGE="$product/programs/target/debug/examples/relay_writer_bridge"
fi
if [[ -z "${MORSE_RELAY_SCHEDULER_PROOF_BINARY:-}" ]]; then
  "${MESHC:-meshc}" build "$product/tools/relay-scheduler-proof" --opt-level 2 --output "$work/scheduler-proof"
  export MORSE_RELAY_SCHEDULER_PROOF_BINARY="$work/scheduler-proof"
fi
bash "$product/scripts/prove-relay-admission.sh"
node --test "$product/ops/relay/transactions.test.mjs" "$product/ops/relay/journal.test.mjs" \
  "$product/ops/relay/verifier.test.mjs" "$product/ops/relay/rpc.test.mjs" \
  "$product/ops/relay/writer.test.mjs" "$product/ops/relay/effects.test.mjs" "$product/ops/relay/progress.test.mjs" \
  "$product/ops/relay/revisions.test.mjs" "$product/ops/relay/scheduler.test.mjs" "$product/ops/relay/retention.test.mjs" \
  "$product/ops/relay/service.test.mjs" "$product/ops/relay/http.test.mjs" \
  "$product/ops/relay/config.test.mjs" "$product/ops/relay/command.test.mjs" \
  "$product/ops/relay/relay-sbf.test.mjs" "$product/ops/relay/scheduler-sbf.test.mjs"
: > "$MORSE_RELAY_EFFECT_REPORTS_PATH"
"${MESHC:-meshc}" test "$product/packages/messenger-protocol/security/relay-stage-read.test.mpl"
"${MESHC:-meshc}" test "$product/packages/messenger-protocol/security/relay-lookup-cooldown.test.mpl"
"${MESHC:-meshc}" test "$product/packages/messenger-protocol/security/relay-settlement-read.test.mpl"
node --test "$product/ops/relay/effects-readback.test.mjs"
