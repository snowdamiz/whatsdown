#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
meshc="${MESHC:-meshc}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export MORSE_ADJUDICATION_FIXTURES_PATH="${MORSE_ADJUDICATION_FIXTURES_PATH:-$work/adjudication-accounts.json}"
node --test "$product/scripts/prove-judge.test.mjs"
bash "$product/scripts/prove-judge.sh"
"$meshc" test "$product/packages/messenger-protocol/tests/slash_receipt.test.mpl"
"$meshc" test "$product/packages/messenger-protocol/security/slash-receipt.test.mpl"
"$meshc" test "$product/clients/mesh-cli/tests/receipt.test.mpl"
MESHC="$meshc" node --test "$product/scripts/bonds-command.test.mjs"
