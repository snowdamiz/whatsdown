#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly protocol_dir="$repo_root/mesh-private-messenger/packages/messenger-protocol"
readonly mobile_dir="$repo_root/mesh-private-messenger/packages/mobile-core"
readonly core_dir="$repo_root/mesh-private-messenger/services/directory-delivery"
readonly edge_dir="$repo_root/mesh-private-messenger/services/privacy-edge"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly database_port=55436
readonly core_port=18090
readonly edge_port=18091
readonly database_url="postgres://messenger:messenger@127.0.0.1:$database_port/messenger?sslmode=disable"
readonly delivery_seed_hex="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
readonly transparency_seed_hex="5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
readonly witness_a_public_key_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
readonly witness_b_public_key_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
readonly mailbox_hash_hex="72dbb7336c76780023f83da4c355f2eeea85733b13d3477697917790c1229084"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m13.XXXXXX")"
readonly temp_dir
readonly core_log="$temp_dir/core.log"
readonly edge_log="$temp_dir/edge.log"
readonly submission="$temp_dir/submission.bin"
readonly compose=(docker compose --project-name whatsdown-m13-proof --file "$core_dir/docker-compose.yml")

core_pid=""
edge_pid=""

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
  for pid in "$edge_pid" "$core_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      wait "$pid" >/dev/null 2>&1
    fi
  done
  compose down --volumes --remove-orphans >/dev/null 2>&1
  if ((status != 0)); then
    for log_file in "$core_log" "$edge_log"; do
      if [[ -f "$log_file" ]]; then
        printf '\n== %s ==\n' "$(basename "$log_file")" >&2
        sed -n '1,200p' "$log_file" >&2
      fi
    done
  fi
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    resolved_parent="$(realpath "$temp_parent")"
    resolved_temp="$(realpath "$temp_dir")"
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

build_mobile_submission() {
  "$meshc_bin" test "$mobile_dir/tests/transparency.test.mpl"
  MESSENGER_M13_SUBMISSION_PATH="$submission" \
    "$meshc_bin" test "$mobile_dir/tests/privacy_submission.test.mpl"
  [[ -s "$submission" ]] || fail "Mesh mobile privacy proof did not produce a submission"
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

  export MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="$transparency_seed_hex"
  export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="$witness_a_public_key_hex"
  export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="$witness_b_public_key_hex"
  export MESSENGER_DELIVERY_SEALING_SEED_HEX="$delivery_seed_hex"

  "$meshc_bin" test "$protocol_dir"
  "$meshc_bin" test "$edge_dir/tests/api.test.mpl"
  (cd "$core_dir" && "$meshc_bin" build .)
  (cd "$edge_dir" && "$meshc_bin" build .)
  build_mobile_submission

  compose down --volumes --remove-orphans >/dev/null 2>&1
  compose up --detach --wait postgres
  (cd "$core_dir" && MESSENGER_TEST_DATABASE_URL="$database_url" \
    "$meshc_bin" test tests/api.test.mpl)
  psql -c 'TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_directory, messenger_mailboxes RESTART IDENTITY;' >/dev/null
  psql -c "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES (decode('$mailbox_hash_hex', 'hex'));" >/dev/null

  MESSENGER_DATABASE_URL="$database_url" MESSENGER_PORT="$core_port" \
    "$core_dir/output" >"$core_log" 2>&1 &
  core_pid=$!
  wait_for_health "http://127.0.0.1:$core_port"
  MESSENGER_PRIVACY_EDGE_PORT="$edge_port" MESSENGER_ABUSE_DIFFICULTY=8 \
    MESSENGER_DELIVERY_INTERNAL_URL="http://127.0.0.1:$core_port" \
    "$edge_dir/output" >"$edge_log" 2>&1 &
  edge_pid=$!
  wait_for_health "http://127.0.0.1:$edge_port"

  [[ "$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/octet-stream' \
    --data-binary "@$submission" "http://127.0.0.1:$edge_port/v1/envelopes/batch")" == 202 ]] || \
    fail "privacy edge did not accept the native sealed submission"
  [[ "$(psql -Atc "SELECT concat(count(*), ':', count(*) FILTER (WHERE octet_length(ciphertext) = 8)) FROM messenger_envelopes;")" == '1:1' ]] || \
    fail "delivery core did not persist exactly one opaque envelope"
  [[ "$(psql -Atc "SELECT count(*) FROM information_schema.columns WHERE table_name = 'messenger_envelopes' AND column_name ILIKE '%sender%';")" == 0 ]] || \
    fail "delivery storage contains sender identity"
  assert_logs_are_not_joinable
  printf 'M13 proof passed: Mesh mobile proof verification, sealed delivery, anonymous abuse work, split edge/core visibility, and non-joinable service logs.\n'
}

main "$@"
