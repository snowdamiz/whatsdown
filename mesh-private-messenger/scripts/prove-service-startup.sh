#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly messenger_root="$repo_root/mesh-private-messenger"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/morse-service-startup.XXXXXX")"
readonly temp_dir
edge_pid=""

fail() {
  printf 'Service startup proof failed: %s\n' "$*" >&2
  return 1
}

cleanup() {
  local exit_code=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  set +e
  if [[ -n "$edge_pid" ]] && kill -0 "$edge_pid" 2>/dev/null; then
    kill "$edge_pid"
    wait "$edge_pid" >/dev/null 2>&1
  fi
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]] &&
    resolved_parent="$(cd "$temp_parent" && pwd -P)" &&
    resolved_temp="$(cd "$temp_dir" && pwd -P)"; then
    case "$resolved_temp" in
      "$resolved_parent"/morse-service-startup.*)
        /usr/bin/find "$resolved_temp" -depth -delete
        ;;
    esac
  fi
  exit "$exit_code"
}

trap cleanup EXIT INT TERM

build_service() {
  local name=$1
  "$meshc_bin" build "$messenger_root/services/$name" --output "$temp_dir/$name"
}

expect_missing_config_failure() {
  local name=$1
  local exit_code
  set +e
  env -i PATH="$PATH" "$temp_dir/$name" >"$temp_dir/$name.log" 2>&1
  exit_code=$?
  set -e
  [[ "$exit_code" == 1 ]] || fail "$name accepted missing configuration with status $exit_code"
}

wait_for_edge() {
  local attempt
  for ((attempt = 0; attempt < 50; attempt += 1)); do
    if curl --fail --silent http://127.0.0.1:18996/health >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$edge_pid" 2>/dev/null || fail "privacy-edge stopped before becoming healthy"
    sleep 0.1
  done
  fail "privacy-edge did not become healthy"
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v curl >/dev/null || fail "curl is required"

  local name
  for name in directory-delivery privacy-edge push-broker object-store; do
    build_service "$name"
    expect_missing_config_failure "$name"
  done

  MESSENGER_PRIVACY_EDGE_PORT=18996 \
    MESSENGER_DELIVERY_INTERNAL_URL=http://127.0.0.1:1 \
    MESSENGER_DELIVERY_INTERNAL_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    "$temp_dir/privacy-edge" >"$temp_dir/privacy-edge-first.log" 2>&1 &
  edge_pid=$!
  wait_for_edge

  local bind_exit
  set +e
  MESSENGER_PRIVACY_EDGE_PORT=18996 \
    MESSENGER_DELIVERY_INTERNAL_URL=http://127.0.0.1:1 \
    MESSENGER_DELIVERY_INTERNAL_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    "$temp_dir/privacy-edge" >"$temp_dir/privacy-edge-bind.log" 2>&1
  bind_exit=$?
  set -e
  [[ "$bind_exit" == 1 ]] || fail "privacy-edge bind failure exited with status $bind_exit"
  grep -qF 'privacy-edge HTTP server failed' "$temp_dir/privacy-edge-bind.log" ||
    fail "privacy-edge did not report its bind failure"

  kill "$edge_pid"
  set +e
  wait "$edge_pid"
  local shutdown_exit=$?
  set -e
  edge_pid=""
  [[ "$shutdown_exit" == 0 ]] || fail "privacy-edge graceful shutdown exited with status $shutdown_exit"

  printf 'Service startup proof passed: missing config and bind failures exit nonzero; graceful shutdown exits zero.\n'
}

main "$@"
