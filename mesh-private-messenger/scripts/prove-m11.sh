#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly app_dir="$repo_root/mesh-private-messenger/apps/mobile"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m11.XXXXXX")"
readonly temp_dir

fail() {
  printf 'M11 proof failed: %s\n' "$*" >&2
  return 1
}

cleanup() {
  local status=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    resolved_parent="$(realpath "$temp_parent")"
    resolved_temp="$(realpath "$temp_dir")"
    case "$resolved_temp" in
      "$resolved_parent"/whatsdown-m11.*)
        if [[ "$(find "$resolved_temp" -type l -print -quit)" == '' ]]; then
          find "$resolved_temp" -depth -delete
        fi
        ;;
    esac
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

main() {
  [[ -d "$app_dir/node_modules" ]] || fail "run npm ci in $app_dir"
  "$script_dir/prove-m10.sh"
  npm --prefix "$app_dir" test
  npm --prefix "$app_dir" run typecheck
  (cd "$app_dir" && npx expo-doctor)
  (cd "$app_dir" && npx expo export --platform ios --output-dir "$temp_dir/export")
  [[ "$(find "$temp_dir/export/assets" -type f | wc -l | tr -d ' ')" == 3 ]] || \
    fail "the mobile bundle did not contain exactly the three selected fonts"
  if rg -n '\buseMemo\b' "$app_dir/src" >/dev/null; then
    fail "the React compiler anti-pattern useMemo was introduced"
  fi
  printf 'M11 software proof passed: encrypted restart flow, app parsers, strict generic push, typecheck, Expo diagnostics, and iOS bundle.\n'
}

main "$@"
