#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly protocol_tests="$repo_root/mesh-private-messenger/packages/messenger-protocol/tests"
readonly mobile_tests="$repo_root/mesh-private-messenger/packages/mobile-core/tests"

[[ -x "$meshc_bin" ]] || { printf 'M12 proof failed: Mesh compiler not found at %s\n' "$meshc_bin" >&2; exit 1; }

"$meshc_bin" test "$protocol_tests/device_set.test.mpl"
"$meshc_bin" test "$mobile_tests/device_linking.test.mpl"
"$meshc_bin" test "$mobile_tests/fanout.test.mpl"
"$script_dir/prove-m9.sh"

printf '%s\n' \
  'M12 proof passed: linked-device delivery, encrypted self-sync, visible device-set changes, revocation fanout exclusion, and revoked-device re-registration rejection.'
