#!/usr/bin/env bash
# Checks Morse's C2SP view of the key log against a real, independently
# written C2SP witness: FiloSottile's litewitness (filippo.io/torchwood).
# Mesh builds the log's signed checkpoint notes and tlog-witness add-checkpoint
# requests (including an RFC 6962 consistency proof), litewitness verifies and
# cosigns them, and Mesh verifies the cosignatures it returns, including
# through the phone's v2 evidence check. Skips when Go is not installed.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly harness="$repo_root/mesh-private-messenger/packages/messenger-protocol/interop/c2sp_interop.test.mpl"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly torchwood_version="${TORCHWOOD_VERSION:-v0.10.0}"
readonly witness_name="interop.morse.test/litewitness"
readonly port="${C2SP_INTEROP_PORT:-17380}"

if ! command -v go >/dev/null 2>&1 && [[ -z "${LITEWITNESS_BIN_DIR:-}" ]]; then
  echo "c2sp-interop: SKIPPED (Go is not installed; set LITEWITNESS_BIN_DIR to prebuilt litewitness and witnessctl)"
  exit 0
fi
for tool in ssh-keygen ssh-agent ssh-add curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "c2sp-interop: $tool is required" >&2; exit 1; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/morse-c2sp.XXXXXX")"
readonly work
# Unix socket paths are limited to about 100 bytes, so the agent gets its own short directory.
socket_dir="$(mktemp -d /tmp/mc2sp.XXXXXX)"
readonly socket_dir
witness_pid=""
agent_pid=""
cleanup() {
  if [[ -n "$witness_pid" ]]; then
    kill "$witness_pid" 2>/dev/null || true
    wait "$witness_pid" 2>/dev/null || true
  fi
  [[ -n "$agent_pid" ]] && kill "$agent_pid" 2>/dev/null || true
  rm -rf "$work" "$socket_dir"
}
trap cleanup EXIT

bin_dir="${LITEWITNESS_BIN_DIR:-$work/bin}"
if [[ -z "${LITEWITNESS_BIN_DIR:-}" ]]; then
  echo "c2sp-interop: building litewitness $torchwood_version"
  GOBIN="$bin_dir" go install \
    "filippo.io/torchwood/cmd/litewitness@$torchwood_version" \
    "filippo.io/torchwood/cmd/witnessctl@$torchwood_version"
fi

run_harness() {
  MESSENGER_C2SP_INTEROP_DIR="$work" MESSENGER_C2SP_INTEROP_PHASE="$1" \
    "$meshc_bin" test "$harness" >"$work/harness-$1.log" 2>&1 || {
    cat "$work/harness-$1.log" >&2
    echo "c2sp-interop: FAILED in the Mesh $1 phase" >&2
    exit 1
  }
}

run_harness prepare

ssh-keygen -q -t ed25519 -N '' -C litewitness -f "$work/witness" >/dev/null
printf '%s' "$witness_name" >"$work/witness.name"
eval "$(ssh-agent -a "$socket_dir/agent.sock" -s)" >/dev/null
agent_pid="$SSH_AGENT_PID"
SSH_AUTH_SOCK="$socket_dir/agent.sock" ssh-add -q "$work/witness"
fingerprint="$(ssh-keygen -l -E sha256 -f "$work/witness.pub" | awk '{print $2}')"

origin="$(cat "$work/origin")"
"$bin_dir/witnessctl" add-log -db "$work/witness.db" -origin "$origin"
"$bin_dir/witnessctl" add-key -db "$work/witness.db" -origin "$origin" -key "$(cat "$work/log.vkey")"

"$bin_dir/litewitness" -db "$work/witness.db" -name "$witness_name" -key "$fingerprint" \
  -ssh-agent "$socket_dir/agent.sock" -listen "127.0.0.1:$port" >"$work/litewitness.log" 2>&1 &
witness_pid=$!
for _ in $(seq 1 50); do
  curl -s -o /dev/null "http://127.0.0.1:$port/" && break
  sleep 0.2
done

# post <request> <expected status> [response file]
post() {
  local status
  status="$(curl -s -o "$work/${3:-last-response.txt}" -w '%{http_code}' \
    --data-binary "@$work/$1" "http://127.0.0.1:$port/add-checkpoint")"
  if [[ "$status" != "$2" ]]; then
    echo "c2sp-interop: $1 returned $status, expected $2" >&2
    cat "$work/${3:-last-response.txt}" >&2 || true
    cat "$work/litewitness.log" >&2
    exit 1
  fi
}

post request-1.txt 200 response-1.txt
post request-2.txt 200 response-2.txt
post request-fork.txt 422
post request-stale.txt 409 response-stale.txt
[[ "$(cat "$work/response-stale.txt")" == "9" ]] || { echo "c2sp-interop: 409 body was not the witness's size" >&2; exit 1; }
post request-foreign.txt 403

run_harness verify
echo "c2sp-interop: PASS (litewitness $torchwood_version cosigned sizes 5 and 9; fork refused 422, stale 409 at 9, foreign key 403; Mesh verified both cosignatures and the dual-inclusion evidence)"
