#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compiler="${MESHC:-$(dirname "$product")/mesh-lang/target/debug/meshc}"
cd "$product"
export MESHC="$compiler"
export MESH_LANG_ROOT="${MESH_LANG_ROOT:-$(dirname "$product")/mesh-lang}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Requires the matching public Mesh compiler and host runtime containing BR1.
# This proves local behavior, not a published compiler or release readiness.
for source in "$product"/packages/messenger-protocol/credits/*.mpl; do
  "$compiler" fmt --check "$source"
  "$compiler" lint "$source"
done
for source in "$product"/packages/messenger-protocol/tests/credits_*.test.mpl; do
  "$compiler" fmt --check "$source"
  "$compiler" lint "$source"
  "$compiler" test "$source"
done

for source in "$product"/packages/mobile-core/tests/credits_*.test.mpl; do
  "$compiler" test "$source"
done

"$compiler" test "$product/services/privacy-edge/tests"
"$compiler" build "$product/services/privacy-edge" -o "$work/privacy-edge"
"$compiler" build "$product/services/directory-delivery" -o "$work/directory-delivery"
"$compiler" build "$product/services/credit-issuer" -o "$work/credit-issuer"
export CREDIT_CORE_BIN="$work/directory-delivery"
export CREDIT_ISSUER_BIN="$work/credit-issuer"
node --test "$product/services/directory-delivery/tests/credits-live.test.mjs"
node --test "$product/services/directory-delivery/tests/credits-retention-locking.test.mjs"
node --test "$product/services/directory-delivery/tests/credits-postage-policy-live.test.mjs"
node --test "$product/services/directory-delivery/tests/credits-postage-live.test.mjs"
node --test "$product/services/object-store/tests/paid-attachments-live.test.mjs"
python3 "$product/scripts/prove-credit-signup.py"
python3 "$product/scripts/prove-credit-issuer.py"
node --test "$product/services/credit-issuer/payment/verify.test.mjs"
python3 "$product/scripts/prove-credit-issuer-http.py"
# The credit gate includes the production wallet signer, independent Solana
# codec/SBF checks, and issuer issuance/restart with that signer's real packets.
bash "$product/scripts/prove-wallet-core.sh"
