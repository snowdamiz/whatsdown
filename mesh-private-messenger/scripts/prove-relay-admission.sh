#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
meshc="${MESHC:-meshc}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export MORSE_ADJUDICATION_FIXTURES_PATH="${MORSE_ADJUDICATION_FIXTURES_PATH:-$work/custody.json}"
export MORSE_RELAY_SETTLEMENT_PLANS_PATH="${MORSE_RELAY_SETTLEMENT_PLANS_PATH:-$work/plans.ndjson}"
export MORSE_RELAY_PAID_FIXTURES_PATH="${MORSE_RELAY_PAID_FIXTURES_PATH:-$work/paid.json}"
export MORSE_RELAY_ANCHORED_FIXTURES_PATH="${MORSE_RELAY_ANCHORED_FIXTURES_PATH:-$work/anchored.json}"
export MORSE_RELAY_ANCHORED_PAID_FIXTURES_PATH="${MORSE_RELAY_ANCHORED_PAID_FIXTURES_PATH:-$work/anchored-paid.json}"
export MORSE_RELAY_MAXIMUM_FIXTURES_PATH="${MORSE_RELAY_MAXIMUM_FIXTURES_PATH:-$work/maximum.json}"
export MORSE_RELAY_MAXIMUM_PAID_FIXTURES_PATH="${MORSE_RELAY_MAXIMUM_PAID_FIXTURES_PATH:-$work/maximum-paid.json}"
fixture_test=all_three_fork_kinds_atomically_pay_the_named_finder_and_lock_the_rest_for_both_log_profiles
anchor_test=anchored_verdicts_pin_historical_generation_key_and_contents_and_only_native_metadata_accuses_rollback
maximum_test=sixteen_double_signers_settle_in_one_packet_with_real_lookup_tables_and_token_cpis
plan_test=mesh_admitted_settlements_execute_in_sbf
if [[ -n "${MORSE_RELAY_ADMISSION_PROOF_BINARY:-}" ]]; then
  "$MORSE_RELAY_ADMISSION_PROOF_BINARY" "$fixture_test" --exact
  "$MORSE_RELAY_ADMISSION_PROOF_BINARY" "$anchor_test" --exact
  "$MORSE_RELAY_ADMISSION_PROOF_BINARY" "$maximum_test" --exact
else
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge \
    --features svm --test adjudication_svm "$fixture_test" -- --exact
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge \
    --features svm --test adjudication_svm "$anchor_test" -- --exact
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge \
    --features svm --test adjudication_svm "$maximum_test" -- --exact
fi
"$meshc" test "$product/packages/messenger-protocol/security/relay-admission.test.mpl"
"$meshc" test "$product/packages/messenger-protocol/security/relay-anchored-admission.test.mpl"
MORSE_RELAY_MAXIMUM_CASES=1 "$meshc" test "$product/packages/messenger-protocol/security/relay-anchored-admission.test.mpl"
if [[ -n "${MORSE_RELAY_ADMISSION_PROOF_BINARY:-}" ]]; then
  "$MORSE_RELAY_ADMISSION_PROOF_BINARY" "$plan_test" --ignored --exact
else
  cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge \
    --features svm --test adjudication_svm "$plan_test" -- --ignored --exact
fi
MORSE_ADJUDICATION_FIXTURES_PATH="$MORSE_RELAY_PAID_FIXTURES_PATH" \
  "$meshc" test "$product/packages/messenger-protocol/security/slash-receipt.test.mpl"
MORSE_RELAY_ANCHORED_FIXTURES_PATH="$MORSE_RELAY_ANCHORED_PAID_FIXTURES_PATH" \
  MORSE_RELAY_VERIFY_PAID=1 "$meshc" test "$product/packages/messenger-protocol/security/relay-anchored-admission.test.mpl"
MORSE_RELAY_MAXIMUM_FIXTURES_PATH="$MORSE_RELAY_MAXIMUM_PAID_FIXTURES_PATH" \
  MORSE_RELAY_VERIFY_PAID=1 MORSE_RELAY_MAXIMUM_CASES=1 \
  "$meshc" test "$product/packages/messenger-protocol/security/relay-anchored-admission.test.mpl"
