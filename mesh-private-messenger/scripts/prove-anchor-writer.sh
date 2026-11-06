#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
meshc_bin="${MESHC:-$product/../mesh-lang/target/debug/meshc}"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/morse-anchor-writer.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT

"$product/scripts/prove-judge.sh"
cargo build --manifest-path "$product/programs/Cargo.toml" --locked \
  -p morse-judge --features svm --example anchor_writer_bridge
MORSE_ANCHOR_CHECKPOINTS_PATH="$product/tests/fixtures/fork-v1/anchor-checkpoints.json" \
MORSE_ANCHOR_WORK_PATH="$temporary/materials.json" \
  "$meshc_bin" test "$product/packages/messenger-protocol/security/anchor-checkpoints.test.mpl"
MORSE_ANCHOR_WORK_PATH="$temporary/materials.json" \
MORSE_ANCHOR_SBF_BRIDGE="$product/programs/target/debug/examples/anchor_writer_bridge" \
  node --test "$product/ops/cloudflare/anchor-transactions.test.mjs" "$product/ops/cloudflare/anchor-sbf.test.mjs" \
    "$product/ops/cloudflare/anchor-outbox.test.mjs" "$product/ops/cloudflare/anchor-rpc.test.mjs" \
    "$product/ops/cloudflare/anchor-accounts.test.mjs" "$product/ops/cloudflare/anchor-config.test.mjs" \
    "$product/ops/cloudflare/anchor-directory.test.mjs" "$product/ops/cloudflare/anchor-cycle.test.mjs" \
    "$product/ops/cloudflare/anchor-alerts.test.mjs" "$product/ops/cloudflare/anchor-scheduler.test.mjs" \
    "$product/ops/cloudflare/anchor-worker.test.mjs" "$product/ops/cloudflare/anchor-job-sbf.test.mjs"
