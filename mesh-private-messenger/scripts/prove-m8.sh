#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly service_dir="$repo_root/mesh-private-messenger/services/directory-delivery"
readonly client_dir="$repo_root/mesh-private-messenger/clients/mesh-cli"
readonly witness_dir="$repo_root/mesh-private-messenger/services/transparency-witness"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly database_port=55433
# Overridable so the proof can run beside a local ./run.sh stack on the default ports.
readonly service_port="${M8_SERVICE_PORT:-18087}"
readonly stream_port="${M8_STREAM_PORT:-18093}"
readonly database_url="postgres://messenger:messenger@127.0.0.1:$database_port/messenger?sslmode=disable"
readonly base_url="http://127.0.0.1:$service_port"
# Deterministic proof-only keys; deployments inject unrelated secrets.
readonly transparency_signing_seed_hex="5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
readonly transparency_public_key_hex="6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b"
readonly witness_a_signing_seed_hex="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
readonly witness_a_public_key_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
readonly witness_b_signing_seed_hex="4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
readonly witness_b_public_key_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
readonly delivery_sealing_seed_hex="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
readonly internal_delivery_token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Register, resolve and prekey claim need proof of work. Every process in the
# proof (directory, edge, clients) must agree on the difficulty; acceptance
# proofs use 8.
export MESSENGER_ABUSE_DIFFICULTY=8
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/morse-m8.XXXXXX")"
readonly temp_dir
readonly server_log="$temp_dir/server.log"
readonly device_a_log="$temp_dir/device-a.log"
readonly device_b_log="$temp_dir/device-b.log"
readonly compose=(docker compose --project-name morse-m8-proof --file "$service_dir/docker-compose.yml")

service_pid=""
device_a_pid=""
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
  if [[ -n "$device_a_pid" ]] && kill -0 "$device_a_pid" 2>/dev/null; then
    kill "$device_a_pid"
    wait "$device_a_pid" >/dev/null 2>&1
  fi
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
    for log_file in "$server_log" "$device_a_log" "$device_b_log" "$temp_dir/witness-a.log" "$temp_dir/witness-b.log"; do
      if [[ -f "$log_file" ]]; then
        printf '\n== %s ==\n' "$(basename "$log_file")" >&2
        sed -n '1,200p' "$log_file" >&2
      fi
    done
  fi
  case "$temp_dir" in
    "$temp_parent"/morse-m8.*)
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
    MESSENGER_STREAM_PORT="$stream_port" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$internal_delivery_token" \
    MESSENGER_DIRECT_DELIVERY_COMPATIBILITY=enabled \
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
    if [[ "$(psql -Atc 'SELECT count(*) FROM messenger_devices' 2>/dev/null)" == 1 ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail "Device B did not register"
}

wait_for_checkpoint() {
  local attempt
  for ((attempt = 0; attempt < 300; attempt += 1)); do
    if [[ "$(psql -Atc 'SELECT count(*) FROM transparency_checkpoints' 2>/dev/null)" -ge 1 ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail "transparency checkpoint timed out"
}

# Device A uses the directory entry only after both pinned witnesses countersign.
run_witness() {
  local witness_id=$1
  local signing_seed=$2
  local public_key=$3
  MESSENGER_BASE_URL="$base_url" \
    MESSENGER_WITNESS_ID="$witness_id" \
    MESSENGER_WITNESS_CHECKPOINT_PATH="$temp_dir/$witness_id-checkpoint" \
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX="$transparency_public_key_hex" \
    MESSENGER_WITNESS_SIGNING_SEED_HEX="$signing_seed" \
    MESSENGER_WITNESS_PUBLIC_KEY_HEX="$public_key" \
    "$witness_dir/output" >"$temp_dir/$witness_id.log" 2>&1
  [[ -s "$temp_dir/$witness_id-checkpoint" ]] || fail "$witness_id did not persist its checkpoint"
}

http_status() {
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --header 'Content-Type: application/octet-stream' "$@"
}

# The public mailbox address is not a credential, and the unauthenticated
# single-device directory no longer exists.
# Register, resolve and prekey claim are anonymous, so they must arrive wrapped
# in proof of work. A well-formed lookup with no stamp is malformed (400); the
# same lookup under an expired stamp is refused (429). An expired stamp, not a
# workless one: a zero-work nonce satisfies difficulty 8 one time in 256.
assert_anonymous_requests_cost_work() {
  local lookup status
  lookup='014b545100000005616c69636500000000'
  status="$(printf '%s' "$lookup" | xxd -r -p | \
    http_status --request POST --data-binary @- "$base_url/v1/devices/resolve")"
  [[ "$status" == 400 ]] || fail "unstamped device lookup returned HTTP $status"
  status="$(printf '01505752%s%s%s%s' '0000000000000001' '00000000' '00000011' "$lookup" | xxd -r -p | \
    http_status --request POST --data-binary @- "$base_url/v1/devices/resolve")"
  [[ "$status" == 429 ]] || fail "device lookup under an expired stamp returned HTTP $status"
  status="$(printf '%s' "$lookup" | xxd -r -p | \
    http_status --request PUT --data-binary @- "$base_url/v1/devices/register")"
  [[ "$status" == 400 ]] || fail "unstamped device registration returned HTTP $status"
}

assert_mailbox_requires_device_signature() {
  local token_hex status
  token_hex="$(psql -Atc "SELECT encode(mailbox_token, 'hex') FROM messenger_devices LIMIT 1")"
  [[ "$token_hex" =~ ^[0-9a-f]{64}$ ]] || fail "registered mailbox address was not found"
  status="$(printf '01464554%s0000000000000000' "$token_hex" | xxd -r -p | \
    http_status --request POST --data-binary @- "$base_url/v1/mailbox/fetch")"
  [[ "$status" == 400 ]] || fail "unsigned mailbox fetch returned HTTP $status"
  status="$(printf '0141434b%s01%s' "$token_hex" '00000000000000000000000000000000' | xxd -r -p | \
    http_status --request POST --data-binary @- "$base_url/v1/mailbox/ack")"
  [[ "$status" == 400 ]] || fail "unsigned mailbox acknowledgement returned HTTP $status"
  status="$(http_status --request PUT --data-binary @/dev/null "$base_url/v1/directory/register")"
  [[ "$status" == 404 ]] || fail "legacy directory registration returned HTTP $status"
  status="$(http_status --request POST --data-binary @/dev/null "$base_url/v1/directory/resolve")"
  [[ "$status" == 404 ]] || fail "legacy directory resolution returned HTTP $status"
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
  # Delivery must not be able to join envelopes into conversations. A bare
  # ratchet packet carried its 32-byte session ID at a fixed offset, identical in
  # every message of a session; sealed packets share no bytes there, and nothing
  # names the protocol suite or the packet kind.
  result="$(psql -Atc "
    SELECT count(*) FILTER (WHERE suite <> 4 OR substring(ciphertext from 1 for 4) <> '\\x01524350'),
      count(*) - count(DISTINCT substring(ciphertext from 20 for 32))
    FROM messenger_envelopes;")"
  [[ "$result" == '0|0' ]] || fail "stored envelopes expose a suite, packet kind, or stable session bytes: $result"
  if grep -qE 'initial|first|second|third' "$server_log"; then
    fail "server log contained message plaintext"
  fi
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v curl >/dev/null || fail "curl is required"
  command -v docker >/dev/null || fail "Docker is required"

  command -v xxd >/dev/null || fail "xxd is required"

  export MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="$transparency_signing_seed_hex"
  export MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX="$transparency_public_key_hex"
  export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="$witness_a_public_key_hex"
  export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="$witness_b_public_key_hex"
  export MESSENGER_DELIVERY_SEALING_SEED_HEX="$delivery_sealing_seed_hex"

  (cd "$service_dir" && "$meshc_bin" build .)
  (cd "$witness_dir" && "$meshc_bin" build .)
  (cd "$client_dir" && "$meshc_bin" build . && "$meshc_bin" test tests/transport.test.mpl)

  compose down --volumes --remove-orphans >/dev/null 2>&1
  compose up --detach --wait postgres
  (cd "$service_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" "$meshc_bin" test tests)
  psql -c 'TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY;' >/dev/null

  start_service
  MESSENGER_ROLE=device-b MESSENGER_BASE_URL="$base_url" MESSENGER_FETCH_DELAY_MS=25000 \
    "$client_dir/output" >"$device_b_log" 2>&1 &
  device_b_pid=$!
  wait_for_registration

  assert_mailbox_requires_device_signature
  assert_anonymous_requests_cost_work

  MESSENGER_ROLE=device-a MESSENGER_BASE_URL="$base_url" \
    "$client_dir/output" >"$device_a_log" 2>&1 &
  device_a_pid=$!
  wait_for_checkpoint
  run_witness witness-a "$witness_a_signing_seed_hex" "$witness_a_public_key_hex"
  run_witness witness-b "$witness_b_signing_seed_hex" "$witness_b_public_key_hex"
  wait_for_process "$device_a_pid"
  device_a_pid=""

  kill "$service_pid"
  wait "$service_pid" || true
  service_pid=""
  start_service
  assert_hostile_frames_rejected
  wait_for_process "$device_b_pid"
  device_b_pid=""

  assert_client_output
  assert_database_private_and_drained
  printf 'M8 proof passed: device-signed mailbox access, witnessed resolution, restart persistence, encryption, ordering, deduplication, hostile-frame rejection, and bounded mailboxes.\n'
}

main "$@"
