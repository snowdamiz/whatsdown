#!/usr/bin/env bash
# Local custody/signing oracle proof; never connects to a live Solana RPC.
set -euo pipefail
product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
public_root="${MESH_LANG_ROOT:-${product}/../mesh-lang}"
export MESH_LANG_ROOT="${public_root}"
export MESHC="${MESHC:-${public_root}/target/debug/meshc}"
cd "${product}"
[[ -x "${MESHC}" ]] || { echo 'Build public meshc and runtime archives, or set MESHC' >&2; exit 1; }
[[ -d ops/rewards/node_modules/@solana/kit ]] || { echo 'Run npm ci --prefix ops/rewards for the independent SDK oracle' >&2; exit 1; }
for source in packages/messenger-protocol/bounty/*.mpl packages/messenger-protocol/tests/bounty_transfer.test.mpl; do
  "$MESHC" fmt --check "$source"
  "$MESHC" lint "$source"
done
"$MESHC" test packages/messenger-protocol/tests/bounty_transfer.test.mpl
for source in packages/mobile-core/tests/bounty*.test.mpl; do
  "$MESHC" fmt --check "$source"
  "$MESHC" lint "$source"
  "$MESHC" test "$source"
done
cargo test --locked --manifest-path packages/wallet-core/Cargo.toml
cargo build --locked --manifest-path packages/wallet-core/Cargo.toml --example wallet_fixture_bridge
cargo build --locked --manifest-path programs/Cargo.toml -p morse-rewards --example credit_payment_fixture
node --test packages/wallet-core/tests/sdk.test.mjs
node --test packages/wallet-core/tests/bounty-transfer.test.mjs
for level in 0 2; do
  BOUNTY_NETWORK_OPT_LEVEL="$level" node --test packages/wallet-core/tests/bounty-network.test.mjs
done
node --test packages/wallet-core/tests/network.test.mjs
# Exercise the production HTTP issuer using this SDK's actual signed packets,
# real blind issuance, concurrent retries and a hard process restart.
export MORSE_HTTP_WALLET_BRIDGE="${WALLET_FIXTURE_BRIDGE:-${product}/packages/wallet-core/target/debug/examples/wallet_fixture_bridge}"
if [[ -n "${WALLET_ISSUER_HTTP_REPORT:-}" ]]; then
  export MORSE_HTTP_REPORT_PATH="${WALLET_ISSUER_HTTP_REPORT}"
else
  unset MORSE_HTTP_REPORT_PATH
fi
python3 scripts/prove-credit-issuer-http.py
