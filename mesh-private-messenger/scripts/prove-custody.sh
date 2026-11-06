#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
meshc="${MESHC:-meshc}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export MORSE_CUSTODY_FIXTURES_PATH="${MORSE_CUSTODY_FIXTURES_PATH:-$work/custody-accounts.json}"
bash "$product/scripts/prove-judge.sh"
"$meshc" test "$product/packages/messenger-protocol/security/anchor-custody.test.mpl"
MESHC="$meshc" node --test "$product/scripts/bonds-command.test.mjs"
