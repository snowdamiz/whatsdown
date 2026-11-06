#!/usr/bin/env bash
set -euo pipefail
PRODUCT="$(cd "$(dirname "$0")/.." && pwd)"
PROOF="${MORSE_PROOF_DIR:-$(dirname "$PRODUCT")/.morse/witness-proof}"
PUBLIC="${MESH_LANG_ROOT:-$PRODUCT/../mesh-lang}"
MESHC="${MESHC:-$PUBLIC/target/debug/meshc}"
CARGO="${CARGO:-cargo}"
TARGET="${CARGO_TARGET_DIR:-$PRODUCT/programs/target}"
mkdir -p "$PROOF"
env -u CARGO_TARGET_DIR "$MESHC" test "$PUBLIC/packages/mesh-solana/tests/nonce.test.mpl" > "$PROOF/solana-nonce.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" test "$PUBLIC/packages/mesh-solana/tests/transaction_write.test.mpl" > "$PROOF/solana-transaction-write.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" test "$PUBLIC/packages/mesh-solana/tests/transaction_outcome.test.mpl" > "$PROOF/solana-transaction-outcome.log" 2>&1
env -u CARGO_TARGET_DIR "$MESHC" test "$PRODUCT/ops/credit-treasury/policy.test.mpl" > "$PROOF/credits-treasury-split.log" 2>&1
CARGO_TARGET_DIR="$TARGET" "$CARGO" build --locked --manifest-path "$PRODUCT/tools/solana-nonce-proof/Cargo.toml" > "$PROOF/solana-nonce-agave-build.log" 2>&1
env -u CARGO_TARGET_DIR SOLANA_NONCE_ORACLE="$TARGET/debug/morse-solana-nonce-proof" \
SOLANA_NONCE_REPORT="$PROOF/solana-nonce-bank.json" \
MESH_LANG_ROOT="$PUBLIC" MESHC="$MESHC" \
node --test "$PRODUCT/tools/solana-nonce-proof/nonce.test.mjs" > "$PROOF/solana-nonce-bank.log" 2>&1
printf 'Public Solana nonce and isolated treasury arithmetic proof passed. Evidence: %s\n' "$PROOF"
