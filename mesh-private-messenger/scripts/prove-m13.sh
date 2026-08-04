#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly protocol_dir="$repo_root/mesh-private-messenger/packages/messenger-protocol"
readonly fanout_test="$repo_root/mesh-private-messenger/packages/mobile-core/tests/fanout.test.mpl"
readonly live_dir="$repo_root/mesh-private-messenger/tests/m13-live"
readonly core_dir="$repo_root/mesh-private-messenger/services/directory-delivery"
readonly edge_dir="$repo_root/mesh-private-messenger/services/privacy-edge"
readonly witness_dir="$repo_root/mesh-private-messenger/services/transparency-witness"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly database_port=55436
readonly core_port=18090
readonly edge_port=18091
readonly database_url="postgres://messenger:messenger@127.0.0.1:$database_port/messenger?sslmode=disable"
readonly delivery_seed_hex="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
readonly transparency_seed_hex="5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
readonly transparency_public_key_hex="6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b"
readonly witness_a_signing_seed_hex="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
readonly witness_a_public_key_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
readonly witness_b_signing_seed_hex="4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
readonly witness_b_public_key_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
readonly internal_delivery_token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
readonly proof_plaintext="m13 live private suite-2 message"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m13.XXXXXX")"
readonly temp_dir
readonly core_log="$temp_dir/core.log"
readonly edge_log="$temp_dir/edge.log"
readonly mobile_log="$temp_dir/mobile.log"
readonly postgres_log="$temp_dir/postgres.log"
readonly envelope_dump="$temp_dir/envelopes.bin"
readonly witness_a_log="$temp_dir/witness-a.log"
readonly witness_b_log="$temp_dir/witness-b.log"
readonly witness_a_checkpoint="$temp_dir/witness-a-checkpoint"
readonly witness_b_checkpoint="$temp_dir/witness-b-checkpoint"
readonly alice_database="$temp_dir/alice.db"
readonly bob_database="$temp_dir/bob.db"
readonly compose=(docker compose --project-name "whatsdown-m13-proof-$$" --file "$core_dir/docker-compose.yml")

core_pid=""
edge_pid=""
mobile_pid=""
docker_probe_pid=""
docker_ready=false

fail() {
  printf 'M13 proof failed: %s\n' "$*" >&2
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
  if [[ -n "$docker_probe_pid" ]] && kill -0 "$docker_probe_pid" 2>/dev/null; then
    kill "$docker_probe_pid"
    wait "$docker_probe_pid" >/dev/null 2>&1
  fi
  for pid in "$mobile_pid" "$edge_pid" "$core_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      wait "$pid" >/dev/null 2>&1
    fi
  done
  if [[ "$docker_ready" == true ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1
  fi
  if ((status != 0)); then
    for log_file in "$core_log" "$edge_log" "$mobile_log" "$postgres_log" "$witness_a_log" "$witness_b_log"; do
      if [[ -f "$log_file" ]]; then
        printf '\n== %s ==\n' "$(basename "$log_file")" >&2
        sed -n '1,200p' "$log_file" >&2
      fi
    done
  fi
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    resolved_parent="$(cd "$temp_parent" && pwd -P)"
    resolved_temp="$(cd "$temp_dir" && pwd -P)"
    case "$resolved_temp" in
      "$resolved_parent"/whatsdown-m13.*)
        [[ "$(find "$resolved_temp" -type l | wc -l | tr -d ' ')" == 0 ]] && \
          find "$resolved_temp" -depth -delete
        ;;
    esac
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for_health() {
  local url=$1
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if curl --fail --silent --show-error "$url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  fail "$url did not become healthy"
}

wait_for_docker() {
  local attempt
  docker info >/dev/null 2>&1 &
  docker_probe_pid=$!
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if ! kill -0 "$docker_probe_pid" 2>/dev/null; then
      if wait "$docker_probe_pid"; then
        docker_probe_pid=""
        docker_ready=true
        return 0
      fi
      docker_probe_pid=""
      return 1
    fi
    sleep 0.1
  done
  kill "$docker_probe_pid" >/dev/null 2>&1 || true
  wait "$docker_probe_pid" >/dev/null 2>&1 || true
  docker_probe_pid=""
  return 1
}

wait_for_process() {
  local pid=$1
  local label=$2
  local attempt
  local status
  for ((attempt = 0; attempt < 1200; attempt += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e
      wait "$pid"
      status=$?
      set -e
      [[ "$status" == 0 ]] || fail "$label exited with status $status"
      return 0
    fi
    sleep 0.1
  done
  fail "$label timed out"
}

wait_for_checkpoint() {
  local attempt
  local status
  for ((attempt = 0; attempt < 1200; attempt += 1)); do
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
      "http://127.0.0.1:$core_port/v1/transparency/checkpoint" || true)"
    if [[ "$status" == 200 ]]; then
      return 0
    fi
    if [[ -n "$mobile_pid" ]] && ! kill -0 "$mobile_pid" 2>/dev/null; then
      wait_for_process "$mobile_pid" "Mesh live mobile proof"
      mobile_pid=""
      fail "Mesh live mobile proof exited before creating a checkpoint"
    fi
    sleep 0.1
  done
  fail "live transparency checkpoint timed out"
}

run_witness() {
  local witness_id=$1
  local signing_seed=$2
  local public_key=$3
  local checkpoint_path=$4
  local log_path=$5
  MESSENGER_BASE_URL="http://127.0.0.1:$core_port" \
    MESSENGER_WITNESS_ID="$witness_id" \
    MESSENGER_WITNESS_CHECKPOINT_PATH="$checkpoint_path" \
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX="$transparency_public_key_hex" \
    MESSENGER_WITNESS_SIGNING_SEED_HEX="$signing_seed" \
    MESSENGER_WITNESS_PUBLIC_KEY_HEX="$public_key" \
    "$witness_dir/output" >"$log_path" 2>&1
  [[ -s "$checkpoint_path" ]] || fail "$witness_id did not persist its checkpoint"
}

run_live_mobile_proof() {
  MESSENGER_M13_CORE_URL="http://127.0.0.1:$core_port" \
  MESSENGER_M13_EDGE_URL="http://127.0.0.1:$edge_port" \
  MESSENGER_M13_ALICE_DB_PATH="$alice_database" \
  MESSENGER_M13_BOB_DB_PATH="$bob_database" \
    MESSENGER_M13_PROOF_PLAINTEXT="$proof_plaintext" \
    "$meshc_bin" test "$live_dir" >"$mobile_log" 2>&1 &
  mobile_pid=$!
  wait_for_checkpoint
  run_witness witness-a "$witness_a_signing_seed_hex" "$witness_a_public_key_hex" \
    "$witness_a_checkpoint" "$witness_a_log"
  run_witness witness-b "$witness_b_signing_seed_hex" "$witness_b_public_key_hex" \
    "$witness_b_checkpoint" "$witness_b_log"
  wait_for_process "$mobile_pid" "Mesh live mobile proof"
  mobile_pid=""
}

assert_private_ingress_only() {
  local status
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/octet-stream' --data-binary @/dev/null \
    "http://127.0.0.1:$core_port/v1/envelopes/batch")"
  [[ "$status" == 404 ]] || fail "public direct-delivery route returned HTTP $status"
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/octet-stream' --data-binary @/dev/null \
    "http://127.0.0.1:$core_port/internal/v1/envelopes/sealed")"
  [[ "$status" == 401 ]] || fail "unauthenticated sealed ingress returned HTTP $status"
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/octet-stream' \
    --header 'Authorization: Bearer wrong-internal-token' --data-binary @/dev/null \
    "http://127.0.0.1:$core_port/internal/v1/envelopes/sealed")"
  [[ "$status" == 401 ]] || fail "wrong sealed-ingress bearer returned HTTP $status"
}

assert_live_database_private() {
  local result
  local file
  local -a mobile_files=()
  [[ "$(psql -Atc "SELECT concat((SELECT count(*) FROM messenger_accounts), '|', (SELECT count(*) FROM messenger_devices), '|', (SELECT count(*) FROM messenger_mailboxes));")" == '2|2|2' ]] || \
    fail "live Mesh driver did not register exactly two accounts and devices"
  [[ "$(psql -Atc 'SELECT count(*) FROM transparency_entries;')" == 2 ]] || \
    fail "live directory did not append exactly two transparency entries"
  [[ "$(psql -Atc 'SELECT concat(sequence, '\''|'\'', tree_size) FROM transparency_checkpoints ORDER BY sequence DESC LIMIT 1;')" == '1|2' ]] || \
    fail "live directory did not retain the exact two-entry checkpoint"
  [[ "$(psql -Atc "SELECT concat(count(*), '|', string_agg(witness_id, ',' ORDER BY witness_id)) FROM witness_signatures;")" == '2|witness-a,witness-b' ]] || \
    fail "live directory did not retain both independent witnesses"
  [[ "$(psql -Atc 'SELECT concat(count(*), '\''|'\'', count(*) FILTER (WHERE consumed_at IS NOT NULL)) FROM messenger_one_time_prekeys;')" == '2|1' ]] || \
    fail "live fanout did not consume exactly Bob's claimed one-time prekey"
  result="$(psql -Atc "
    SELECT concat(count(*), '|',
      count(*) FILTER (WHERE envelope.suite = 2), '|',
      count(*) FILTER (WHERE account.username = 'bob'))
    FROM messenger_envelopes AS envelope
    LEFT JOIN messenger_devices AS device
      ON device.mailbox_token_hash = envelope.mailbox_token_hash
    LEFT JOIN messenger_accounts AS account
      ON account.account_id = device.account_id;")"
  [[ "$result" == '1|1|1' ]] || fail "unexpected sealed-delivery database proof: $result"
  psql -qAtc 'COPY (SELECT ciphertext FROM messenger_envelopes) TO STDOUT WITH (FORMAT binary);' >"$envelope_dump"
  if grep -aFq -- "$proof_plaintext" "$envelope_dump"; then
    fail "delivery storage exposed message plaintext"
  fi
  while IFS= read -r -d '' file; do
    mobile_files+=("$file")
  done < <(find "$temp_dir" -maxdepth 1 -type f -name '*.db*' -print0)
  ((${#mobile_files[@]} >= 2)) || fail "live mobile databases are missing"
  if grep -aFq -- "$proof_plaintext" "${mobile_files[@]}"; then
    fail "mobile SQLite storage exposed message plaintext"
  fi
  compose logs --no-color postgres >"$postgres_log"
  if grep -Fq -- "$proof_plaintext" "$core_log" "$edge_log" "$mobile_log" "$postgres_log"; then
    fail "a proof log exposed message plaintext"
  fi
}

assert_logs_are_not_joinable() {
  local shared
  if grep -Eiq '0102030405060708090a0b0c0d0e0f|202122232425262728292a2b2c2d2e2f|mailbox[_ -]?token|envelope[_ -]?id|abuse[_ -]?token' \
    "$core_log" "$edge_log"; then
    fail "a service log exposed a delivery identifier"
  fi
  shared="$(comm -12 \
    <(LC_ALL=C grep -Eio '[0-9a-f]{16,}' "$core_log" | sort -u) \
    <(LC_ALL=C grep -Eio '[0-9a-f]{16,}' "$edge_log" | sort -u) || true)"
  [[ -z "$shared" ]] || fail "privacy edge and delivery logs share a joinable identifier"
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v curl >/dev/null || fail "curl is required"
  command -v docker >/dev/null || fail "Docker is required"
  wait_for_docker || fail "Docker daemon is unavailable"

  export MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="$transparency_seed_hex"
  export MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX="$transparency_public_key_hex"
  export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="$witness_a_public_key_hex"
  export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="$witness_b_public_key_hex"
  export MESSENGER_DELIVERY_SEALING_SEED_HEX="$delivery_seed_hex"

  "$meshc_bin" test "$protocol_dir"
  "$meshc_bin" test "$fanout_test"
  "$meshc_bin" test "$edge_dir/tests/api.test.mpl"
  (cd "$core_dir" && "$meshc_bin" build .)
  (cd "$edge_dir" && "$meshc_bin" build .)
  (cd "$witness_dir" && "$meshc_bin" build .)
  if "$witness_dir/output" >/dev/null 2>&1; then
    fail "transparency witness accepted missing configuration"
  fi

  compose down --volumes --remove-orphans >/dev/null 2>&1
  compose up --detach --wait postgres
  (cd "$core_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" \
    "$meshc_bin" test tests/api.test.mpl)
  (cd "$core_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" \
    "$meshc_bin" test tests/prekey_pool.test.mpl)
  psql -c 'TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_directory, messenger_mailboxes RESTART IDENTITY;' >/dev/null

  MESSENGER_DATABASE_URL="$database_url" MESSENGER_PORT="$core_port" \
    MESSENGER_DIRECT_DELIVERY_COMPATIBILITY="" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$internal_delivery_token" \
    "$core_dir/output" >"$core_log" 2>&1 &
  core_pid=$!
  wait_for_health "http://127.0.0.1:$core_port"
  MESSENGER_PRIVACY_EDGE_PORT="$edge_port" MESSENGER_ABUSE_DIFFICULTY=8 \
    MESSENGER_DELIVERY_INTERNAL_URL="http://127.0.0.1:$core_port" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$internal_delivery_token" \
    "$edge_dir/output" >"$edge_log" 2>&1 &
  edge_pid=$!
  wait_for_health "http://127.0.0.1:$edge_port"

  assert_private_ingress_only
  run_live_mobile_proof
  assert_live_database_private
  [[ "$(psql -Atc "SELECT count(*) FROM information_schema.columns WHERE table_name = 'messenger_envelopes' AND column_name ILIKE '%sender%';")" == 0 ]] || \
    fail "delivery storage contains sender identity"
  assert_logs_are_not_joinable
  printf 'M13 proof passed: two live Mesh accounts, exact transparency caches, two independent witnesses, a claimed prekey, one suite-2 fanout, sealed authenticated ingress, opaque storage, and non-joinable logs.\n'
}

main "$@"
