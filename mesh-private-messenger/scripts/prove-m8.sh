#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly service_dir="$repo_root/mesh-private-messenger/services/directory-delivery"
readonly client_dir="$repo_root/mesh-private-messenger/clients/mesh-cli"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly database_port=55433
readonly service_port=18087
readonly database_url="postgres://messenger:messenger@127.0.0.1:$database_port/messenger?sslmode=disable"
readonly base_url="http://127.0.0.1:$service_port"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m8.XXXXXX")"
readonly temp_dir
readonly server_log="$temp_dir/server.log"
readonly device_a_log="$temp_dir/device-a.log"
readonly device_b_log="$temp_dir/device-b.log"
readonly compose=(docker compose --project-name whatsdown-m8-proof --file "$service_dir/docker-compose.yml")

service_pid=""
device_b_pid=""

fail() {
  printf 'M8 proof failed: %s\n' "$*" >&2
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
  trap - EXIT INT TERM
  set +e
  if [[ -n "$device_b_pid" ]] && kill -0 "$device_b_pid" 2>/dev/null; then
    kill "$device_b_pid"
    wait "$device_b_pid" >/dev/null 2>&1
  fi
  if [[ -n "$service_pid" ]] && kill -0 "$service_pid" 2>/dev/null; then
    kill "$service_pid"
    wait "$service_pid" >/dev/null 2>&1
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1
  if ((status != 0)); then
    for log_file in "$server_log" "$device_a_log" "$device_b_log"; do
      if [[ -f "$log_file" ]]; then
        printf '\n== %s ==\n' "$(basename "$log_file")" >&2
        sed -n '1,200p' "$log_file" >&2
      fi
    done
  fi
  case "$temp_dir" in
    "$temp_parent"/whatsdown-m8.*)
      if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
        find "$temp_dir" -depth -delete
      fi
      ;;
  esac
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

start_service() {
  MESSENGER_DATABASE_URL="$database_url" MESSENGER_PORT="$service_port" \
    "$service_dir/output" >>"$server_log" 2>&1 &
  service_pid=$!
  wait_for_health
}

wait_for_process() {
  local pid=$1
  local attempt
  local status
  for ((attempt = 0; attempt < 450; attempt += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e
      wait "$pid"
      status=$?
      set -e
      return "$status"
    fi
    sleep 0.1
  done
  fail "process $pid timed out"
}

wait_for_registration() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if [[ "$(psql -Atc 'SELECT count(*) FROM messenger_directory' 2>/dev/null)" == 1 ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail "Device B did not register"
}

assert_hostile_frames_rejected() {
  local status
  status="$(printf '\x00\x01hostile' | curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/octet-stream' --data-binary @- \
    "$base_url/v1/envelopes/batch")"
  [[ "$status" == 400 ]] || fail "hostile frame returned HTTP $status"

  status="$(dd if=/dev/zero bs=70000 count=1 2>/dev/null | \
    curl --silent --output /dev/null --write-out '%{http_code}' --request POST \
      --header 'Content-Type: application/octet-stream' --data-binary @- \
      "$base_url/v1/envelopes/batch")"
  [[ "$status" == 400 ]] || fail "oversized frame returned HTTP $status"
  curl --fail --silent --show-error "$base_url/health" >/dev/null
}

assert_client_output() {
  local displays
  displays="$(grep '^display:' "$device_b_log")"
  [[ "$displays" == $'display:initial\ndisplay:third\ndisplay:first\ndisplay:second' ]] || \
    fail "unexpected display order"
  [[ "$(grep -cFx 'dedup:suppressed' "$device_b_log")" == 1 ]] || \
    fail "duplicate delivery was not suppressed exactly once"
  grep -qFx 'device-a:ok' "$device_a_log" || fail "Device A failed"
  grep -qFx 'device-b:acked=5' "$device_b_log" || fail "Device B did not acknowledge all envelopes"
  grep -qFx 'device-b:ok' "$device_b_log" || fail "Device B failed"
  if grep -qE 'device-[ab]:(error|invalid)|ratchet-rejected|unexpected-initial' \
    "$device_a_log" "$device_b_log"; then
    fail "client reported a protocol error"
  fi
}

assert_database_private_and_drained() {
  local result
  result="$(psql -Atc "
    SELECT count(*),
      count(*) FILTER (WHERE acknowledged_at IS NOT NULL),
      count(*) FILTER (WHERE position(convert_to('initial', 'UTF8') in ciphertext) > 0
        OR position(convert_to('first', 'UTF8') in ciphertext) > 0
        OR position(convert_to('second', 'UTF8') in ciphertext) > 0
        OR position(convert_to('third', 'UTF8') in ciphertext) > 0),
      (SELECT sum(pending_count) FROM messenger_mailboxes)
    FROM messenger_envelopes;")"
  [[ "$result" == '5|5|0|0' ]] || fail "unexpected database proof result: $result"
  if grep -qE 'initial|first|second|third' "$server_log"; then
    fail "server log contained message plaintext"
  fi
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v curl >/dev/null || fail "curl is required"
  command -v docker >/dev/null || fail "Docker is required"

  (cd "$service_dir" && "$meshc_bin" build .)
  (cd "$client_dir" && "$meshc_bin" build . && "$meshc_bin" test tests/transport.test.mpl)

  compose down --volumes --remove-orphans >/dev/null 2>&1
  compose up --detach --wait postgres
  (cd "$service_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" "$meshc_bin" test tests)
  psql -c 'TRUNCATE messenger_envelopes, messenger_directory, messenger_mailboxes RESTART IDENTITY;' >/dev/null

  start_service
  MESSENGER_ROLE=device-b MESSENGER_BASE_URL="$base_url" MESSENGER_FETCH_DELAY_MS=15000 \
    "$client_dir/output" >"$device_b_log" 2>&1 &
  device_b_pid=$!
  wait_for_registration

  MESSENGER_ROLE=device-a MESSENGER_BASE_URL="$base_url" \
    "$client_dir/output" >"$device_a_log" 2>&1

  kill "$service_pid"
  wait "$service_pid" || true
  service_pid=""
  start_service
  assert_hostile_frames_rejected
  wait_for_process "$device_b_pid"
  device_b_pid=""

  assert_client_output
  assert_database_private_and_drained
  printf 'M8 proof passed: restart persistence, encryption, ordering, deduplication, hostile-frame rejection, and bounded mailboxes.\n'
}

main "$@"
