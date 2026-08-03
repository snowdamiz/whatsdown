#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly service_dir="$repo_root/mesh-private-messenger/services/directory-delivery"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly database_port=55435
readonly service_port=18089
readonly database_url="postgres://messenger:messenger@127.0.0.1:$database_port/messenger?sslmode=disable"
readonly base_url="http://127.0.0.1:$service_port"
# Deterministic proof-only keys; deployments inject unrelated secrets.
readonly transparency_signing_seed_hex="5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
readonly witness_a_public_key_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
readonly witness_b_public_key_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m9.XXXXXX")"
readonly temp_dir
readonly server_log="$temp_dir/server.log"
readonly compose=(docker compose --project-name whatsdown-m9-proof --file "$service_dir/docker-compose.yml")

service_pid=""

fail() {
  printf 'M9 proof failed: %s\n' "$*" >&2
  return 1
}

compose() {
  MESSENGER_POSTGRES_PORT="$database_port" "${compose[@]}" "$@"
}

psql() {
  compose exec -T postgres psql -v ON_ERROR_STOP=1 -U messenger -d messenger "$@"
}

cleanup() {
  local status=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  set +e
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    kill "$service_pid"
    wait "$service_pid" >/dev/null 2>&1
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1
  if ((status != 0)) && [[ -f "$server_log" ]]; then
    sed -n '1,200p' "$server_log" >&2
  fi
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    resolved_parent="$(realpath "$temp_parent")"
    resolved_temp="$(realpath "$temp_dir")"
    case "$resolved_temp" in
      "$resolved_parent"/whatsdown-m9.*)
        find "$resolved_temp" -depth -delete
        ;;
    esac
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for_health() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if curl --fail --silent --show-error "$base_url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  fail "service did not become healthy"
}

wait_for_worker() {
  local attempt
  local result
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    result="$(psql -Atc "SELECT concat(status, ':', attempts::text) FROM messenger_outbox_events WHERE envelope_id = decode('02020202020202020202020202020202', 'hex');")"
    if [[ "$result" == 'delivered:1' ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail "worker pool did not complete the pending event exactly once"
}

stop_service() {
  local attempt
  local status
  kill "$service_pid"
  for ((attempt = 0; attempt < 50; attempt += 1)); do
    if ! kill -0 "$service_pid" 2>/dev/null; then
      set +e
      wait "$service_pid"
      status=$?
      set -e
      service_pid=""
      [[ "$status" == 0 ]] || fail "service exited with status $status"
      return 0
    fi
    sleep 0.1
  done
  fail "service did not stop within five seconds"
}

assert_database_state() {
  local state
  state="$(psql -Atc "
    SELECT concat(
      (SELECT count(*) FROM messenger_envelopes), ':',
      (SELECT count(*) FROM messenger_outbox_events), ':',
      (SELECT count(*) FROM messenger_outbox_events WHERE status = 'permanent_failure'), ':',
      (SELECT count(*) FROM messenger_outbox_events WHERE status = 'delivered'), ':',
      (SELECT count(*) FROM messenger_envelopes WHERE envelope_id = decode('03030303030303030303030303030303', 'hex')), ':',
      (SELECT count(*) FROM messenger_envelopes WHERE envelope_id = decode('04040404040404040404040404040404', 'hex'))
    );")"
  [[ "$state" == '2:2:1:1:0:0' ]] || fail "unexpected durable state: $state"
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v curl >/dev/null || fail "curl is required"
  command -v docker >/dev/null || fail "Docker is required"

  export MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="$transparency_signing_seed_hex"
  export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="$witness_a_public_key_hex"
  export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="$witness_b_public_key_hex"

  compose down --volumes --remove-orphans >/dev/null 2>&1
  compose up --detach --wait postgres
  (cd "$service_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" "$meshc_bin" test tests)
  (cd "$service_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" "$meshc_bin" test tests/hardening.test.mpl)
  assert_database_state

  psql -c "UPDATE messenger_outbox_events SET status = 'pending', attempts = 0, available_at = now(), completed_at = NULL, lease_owner = NULL, lease_expires_at = NULL, last_error_code = NULL WHERE envelope_id = decode('02020202020202020202020202020202', 'hex');" >/dev/null
  (cd "$service_dir" && "$meshc_bin" build .)
  MESSENGER_DATABASE_URL="$database_url" MESSENGER_PORT="$service_port" \
    "$service_dir/output" >"$server_log" 2>&1 &
  service_pid=$!
  wait_for_health
  wait_for_worker
  stop_service
  grep -qF '[mesh-rt] HTTP server stopped' "$server_log" || fail "HTTP server did not drain"
  printf 'M9 proof passed: atomic outbox, bounded retries, lease recovery, retention, rate limits, worker fencing, and graceful shutdown.\n'
}

main "$@"
