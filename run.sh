#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
readonly messenger_root="$script_dir/mesh-private-messenger"
readonly mesh_root="${MESH_LANG_DIR:-$script_dir/mesh-lang}"
readonly meshc_bin="$mesh_root/target/debug/meshc"
readonly app_dir="$messenger_root/apps/mobile"
readonly service_root="$messenger_root/services"
readonly compose_file="$service_root/directory-delivery/docker-compose.yml"
readonly compose_project="whatsdown-dev"
readonly state_dir="${WHATSDOWN_STATE_DIR:-$script_dir/.whatsdown}"
readonly log_dir="$state_dir/logs"

child_pids=()
child_names=()

usage() {
  printf '%s\n' \
    "Usage: ./run.sh [run|build]" \
    "" \
    "  run    Build and start PostgreSQL, every service, both witnesses, and Expo (default)." \
    "  build  Build Mesh, every service, the mobile native module, and install app packages." \
    "" \
    "Set MESH_LANG_DIR to a separate Mesh checkout or WHATSDOWN_MOBILE_PLATFORM to ios/android."
}

fail() {
  printf 'whatsdown: %s\n' "$*" >&2
  return 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

validate_key() {
  [[ "$2" =~ ^[0-9a-f]{64}$ ]] || fail "$1 must be 32-byte lowercase hex"
}

configure_environment() {
  # Deterministic development-only keys shared with the repository proofs.
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="${MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX:-5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b}"
  export MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX="${MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX:-6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b}"
  MESSENGER_WITNESS_A_SIGNING_SEED_HEX="${MESSENGER_WITNESS_A_SIGNING_SEED_HEX:-9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60}"
  export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="${MESSENGER_WITNESS_A_PUBLIC_KEY_HEX:-d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a}"
  MESSENGER_WITNESS_B_SIGNING_SEED_HEX="${MESSENGER_WITNESS_B_SIGNING_SEED_HEX:-4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb}"
  export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="${MESSENGER_WITNESS_B_PUBLIC_KEY_HEX:-3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c}"
  MESSENGER_DELIVERY_SEALING_SEED_HEX="${MESSENGER_DELIVERY_SEALING_SEED_HEX:-77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a}"
  export MESSENGER_DELIVERY_PUBLIC_KEY_HEX="${MESSENGER_DELIVERY_PUBLIC_KEY_HEX:-8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a}"
  MESSENGER_PUSH_BROKER_SEED_HEX="${MESSENGER_PUSH_BROKER_SEED_HEX:-5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb}"
  MESSENGER_DELIVERY_INTERNAL_TOKEN="${MESSENGER_DELIVERY_INTERNAL_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
  MESSENGER_PUSH_BROKER_INTERNAL_TOKEN="${MESSENGER_PUSH_BROKER_INTERNAL_TOKEN:-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789}"
  MESSENGER_EXPO_ACCESS_TOKEN="${MESSENGER_EXPO_ACCESS_TOKEN:-}"
  MESSENGER_EXPO_PUSH_URL="${MESSENGER_EXPO_PUSH_URL:-https://exp.host/--/api/v2/push/send}"
  export MESSENGER_POSTGRES_PORT="${MESSENGER_POSTGRES_PORT:-55432}"
  export MESSENGER_PORT="${MESSENGER_PORT:-18086}"
  export MESSENGER_PRIVACY_EDGE_PORT="${MESSENGER_PRIVACY_EDGE_PORT:-18087}"
  export MESSENGER_PUSH_BROKER_PORT="${MESSENGER_PUSH_BROKER_PORT:-18088}"
  export MESSENGER_OBJECT_PORT="${MESSENGER_OBJECT_PORT:-18089}"
  export MESSENGER_ABUSE_DIFFICULTY="${MESSENGER_ABUSE_DIFFICULTY:-8}"
  export MESSENGER_OBJECT_WORK_DIFFICULTY="${MESSENGER_OBJECT_WORK_DIFFICULTY:-8}"
  MESSENGER_DATABASE_URL="${MESSENGER_DATABASE_URL:-postgres://messenger:messenger@127.0.0.1:$MESSENGER_POSTGRES_PORT/messenger?sslmode=disable}"
  MESSENGER_DELIVERY_INTERNAL_URL="${MESSENGER_DELIVERY_INTERNAL_URL:-http://127.0.0.1:$MESSENGER_PORT}"
  MESSENGER_PUSH_MODE="${MESSENGER_PUSH_MODE:-broker}"
  MESSENGER_PUSH_BROKER_URL="${MESSENGER_PUSH_BROKER_URL:-http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT}"
  export EXPO_PUBLIC_MESSENGER_BASE_URL="${EXPO_PUBLIC_MESSENGER_BASE_URL:-http://127.0.0.1:$MESSENGER_PORT}"
  export EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL="${EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL:-http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT}"

  if [[ -n "${MESSENGER_EXPO_PROJECT_ID:-}" ]]; then
    export MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX="${MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX:-de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f}"
  elif [[ -n "${MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX:-}" ]]; then
    fail "MESSENGER_EXPO_PROJECT_ID is required with MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX"
    return 1
  fi

  validate_key MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX "$MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX" || return 1
  validate_key MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX "$MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX" || return 1
  validate_key MESSENGER_WITNESS_A_SIGNING_SEED_HEX "$MESSENGER_WITNESS_A_SIGNING_SEED_HEX" || return 1
  validate_key MESSENGER_WITNESS_A_PUBLIC_KEY_HEX "$MESSENGER_WITNESS_A_PUBLIC_KEY_HEX" || return 1
  validate_key MESSENGER_WITNESS_B_SIGNING_SEED_HEX "$MESSENGER_WITNESS_B_SIGNING_SEED_HEX" || return 1
  validate_key MESSENGER_WITNESS_B_PUBLIC_KEY_HEX "$MESSENGER_WITNESS_B_PUBLIC_KEY_HEX" || return 1
  validate_key MESSENGER_DELIVERY_SEALING_SEED_HEX "$MESSENGER_DELIVERY_SEALING_SEED_HEX" || return 1
  validate_key MESSENGER_DELIVERY_PUBLIC_KEY_HEX "$MESSENGER_DELIVERY_PUBLIC_KEY_HEX" || return 1
  validate_key MESSENGER_PUSH_BROKER_SEED_HEX "$MESSENGER_PUSH_BROKER_SEED_HEX" || return 1
  if [[ -n "${MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX:-}" ]]; then
    validate_key MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX "$MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX" || return 1
  fi

  export -n MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX \
    MESSENGER_WITNESS_A_SIGNING_SEED_HEX MESSENGER_WITNESS_B_SIGNING_SEED_HEX \
    MESSENGER_DELIVERY_SEALING_SEED_HEX MESSENGER_PUSH_BROKER_SEED_HEX \
    MESSENGER_DELIVERY_INTERNAL_TOKEN MESSENGER_PUSH_BROKER_INTERNAL_TOKEN \
    MESSENGER_DATABASE_URL MESSENGER_EXPO_ACCESS_TOKEN
}

mobile_platform() {
  if [[ -n "${WHATSDOWN_MOBILE_PLATFORM:-}" ]]; then
    case "$WHATSDOWN_MOBILE_PLATFORM" in
      ios|android) printf '%s\n' "$WHATSDOWN_MOBILE_PLATFORM" ;;
      *) fail "WHATSDOWN_MOBILE_PLATFORM must be ios or android" ;;
    esac
  elif [[ "$(uname -s)" == Darwin ]]; then
    printf 'ios\n'
  elif [[ -n "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
    printf 'android\n'
  else
    fail "set WHATSDOWN_MOBILE_PLATFORM and install its native toolchain"
  fi
}

build_mesh() {
  [[ -f "$mesh_root/Cargo.toml" ]] || fail "Mesh checkout not found at $mesh_root"
  CARGO_INCREMENTAL=0 cargo build --locked --manifest-path "$mesh_root/Cargo.toml" -p meshc
  CARGO_INCREMENTAL=0 cargo build --locked --manifest-path "$mesh_root/Cargo.toml" -p mesh-rt --lib
}

build_service() {
  local name=$1
  "$meshc_bin" build "$service_root/$name" --output "$service_root/$name/output"
}

build_services() {
  local name
  for name in directory-delivery privacy-edge push-broker object-store transparency-witness; do
    build_service "$name"
  done
}

build_mobile() {
  local ndk
  local ndk_bin
  local platform
  local target
  platform="$(mobile_platform)"
  npm --prefix "$app_dir" ci --ignore-scripts=false
  require_command rustup
  if [[ "$platform" == ios ]]; then
    for target in aarch64-apple-ios aarch64-apple-ios-sim; do
      rustup target add "$target"
      CARGO_INCREMENTAL=0 cargo build --locked --manifest-path "$mesh_root/Cargo.toml" \
        -p mesh-rt --lib --target "$target"
    done
  else
    ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    [[ -d "$ndk" ]] || fail "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must name an installed NDK"
    ndk_bin="$(find "$ndk/toolchains/llvm/prebuilt" -mindepth 2 -maxdepth 2 \
      -type d -name bin -print -quit)"
    [[ -x "$ndk_bin/aarch64-linux-android26-clang" \
      && -x "$ndk_bin/x86_64-linux-android26-clang" \
      && -x "$ndk_bin/llvm-ar" ]] || fail "Android NDK 26 toolchain is unavailable"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android26-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ndk_bin/x86_64-linux-android26-clang"
    export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
    export CC_x86_64_linux_android="$CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
    export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
    export AR_x86_64_linux_android="$ndk_bin/llvm-ar"
    for target in aarch64-linux-android x86_64-linux-android; do
      rustup target add "$target"
      CARGO_INCREMENTAL=0 cargo build --locked --manifest-path "$mesh_root/Cargo.toml" \
        -p mesh-rt --lib --target "$target"
    done
  fi
  MESHC="$meshc_bin" "$messenger_root/scripts/build-mobile-native.sh" "$platform"
}

build_all() {
  require_command cargo
  require_command npm
  build_mesh
  build_services
  build_mobile
}

compose() {
  docker compose --project-name "$compose_project" --file "$compose_file" "$@"
}

start_process() {
  local name=$1
  shift
  "$@" >"$log_dir/$name.log" 2>&1 &
  child_pids+=("$!")
  child_names+=("$name")
}

wait_for_health() {
  local name=$1
  local url=$2
  local attempt
  for ((attempt = 0; attempt < 150; attempt += 1)); do
    if curl --fail --silent --show-error "$url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  tail -n 40 "$log_dir/$name.log" >&2 || true
  fail "$name did not become healthy"
}

witness_loop() {
  local witness_id=$1
  local signing_seed=$2
  local public_key=$3
  local checkpoint=$4
  while true; do
    if MESSENGER_BASE_URL="http://127.0.0.1:$MESSENGER_PORT" \
      MESSENGER_WITNESS_ID="$witness_id" \
      MESSENGER_WITNESS_CHECKPOINT_PATH="$checkpoint" \
      MESSENGER_WITNESS_SIGNING_SEED_HEX="$signing_seed" \
      MESSENGER_WITNESS_PUBLIC_KEY_HEX="$public_key" \
      "$service_root/transparency-witness/output"; then
      sleep 30
    else
      sleep 5
    fi
  done
}

start_services() {
  start_process push-broker env \
    MESSENGER_PUSH_BROKER_PORT="$MESSENGER_PUSH_BROKER_PORT" \
    MESSENGER_PUSH_BROKER_SEED_HEX="$MESSENGER_PUSH_BROKER_SEED_HEX" \
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN="$MESSENGER_PUSH_BROKER_INTERNAL_TOKEN" \
    MESSENGER_PUSH_BROKER_DB_PATH="$state_dir/push-broker.db" \
    MESSENGER_EXPO_PUSH_URL="$MESSENGER_EXPO_PUSH_URL" \
    MESSENGER_EXPO_ACCESS_TOKEN="$MESSENGER_EXPO_ACCESS_TOKEN" \
    "$service_root/push-broker/output"
  wait_for_health push-broker "http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT"

  start_process directory-delivery env \
    MESSENGER_DATABASE_URL="$MESSENGER_DATABASE_URL" \
    MESSENGER_PORT="$MESSENGER_PORT" \
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="$MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX" \
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="$MESSENGER_WITNESS_A_PUBLIC_KEY_HEX" \
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="$MESSENGER_WITNESS_B_PUBLIC_KEY_HEX" \
    MESSENGER_DELIVERY_SEALING_SEED_HEX="$MESSENGER_DELIVERY_SEALING_SEED_HEX" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$MESSENGER_DELIVERY_INTERNAL_TOKEN" \
    MESSENGER_PUSH_MODE="$MESSENGER_PUSH_MODE" \
    MESSENGER_PUSH_BROKER_URL="$MESSENGER_PUSH_BROKER_URL" \
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN="$MESSENGER_PUSH_BROKER_INTERNAL_TOKEN" \
    MESSENGER_DIRECT_DELIVERY_COMPATIBILITY= \
    "$service_root/directory-delivery/output"
  wait_for_health directory-delivery "http://127.0.0.1:$MESSENGER_PORT"

  start_process privacy-edge env \
    MESSENGER_PRIVACY_EDGE_PORT="$MESSENGER_PRIVACY_EDGE_PORT" \
    MESSENGER_ABUSE_DIFFICULTY="$MESSENGER_ABUSE_DIFFICULTY" \
    MESSENGER_DELIVERY_INTERNAL_URL="$MESSENGER_DELIVERY_INTERNAL_URL" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$MESSENGER_DELIVERY_INTERNAL_TOKEN" \
    "$service_root/privacy-edge/output"
  wait_for_health privacy-edge "http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT"

  start_process object-store env \
    MESSENGER_OBJECT_PORT="$MESSENGER_OBJECT_PORT" \
    MESSENGER_OBJECT_WORK_DIFFICULTY="$MESSENGER_OBJECT_WORK_DIFFICULTY" \
    MESSENGER_OBJECT_DATABASE_PATH="$state_dir/object-store.db" \
    MESSENGER_OBJECT_STORAGE_ROOT="$state_dir/objects" \
    "$service_root/object-store/output"
  wait_for_health object-store "http://127.0.0.1:$MESSENGER_OBJECT_PORT"

  start_process witness-a witness_loop witness-a \
    "$MESSENGER_WITNESS_A_SIGNING_SEED_HEX" "$MESSENGER_WITNESS_A_PUBLIC_KEY_HEX" \
    "$state_dir/witness-a.checkpoint"
  start_process witness-b witness_loop witness-b \
    "$MESSENGER_WITNESS_B_SIGNING_SEED_HEX" "$MESSENGER_WITNESS_B_PUBLIC_KEY_HEX" \
    "$state_dir/witness-b.checkpoint"
  start_process mobile npm --prefix "$app_dir" run start
}

wait_for_children() {
  local index
  local status
  while true; do
    for ((index = 0; index < ${#child_pids[@]}; index += 1)); do
      if ! kill -0 "${child_pids[$index]}" 2>/dev/null; then
        set +e
        wait "${child_pids[$index]}"
        status=$?
        set -e
        printf 'whatsdown: %s exited with status %s\n' "${child_names[$index]}" "$status" >&2
        return 1
      fi
    done
    sleep 1
  done
}

cleanup() {
  local status=$?
  local pid
  trap - EXIT INT TERM
  set +e
  for pid in "${child_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1
  done
  for pid in "${child_pids[@]}"; do
    wait "$pid" >/dev/null 2>&1
  done
  compose down --remove-orphans >/dev/null 2>&1
  exit "$status"
}

run_all() {
  require_command curl
  require_command docker
  docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
  mkdir -p "$log_dir" "$state_dir/objects"
  chmod 700 "$state_dir"
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  build_all
  compose up --detach --wait postgres
  start_services
  printf '%s\n' \
    "Whatsdown is running." \
    "  directory  http://127.0.0.1:$MESSENGER_PORT" \
    "  edge       http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT" \
    "  broker     http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT" \
    "  objects    http://127.0.0.1:$MESSENGER_OBJECT_PORT" \
    "  logs       $log_dir" \
    "Press Ctrl-C to stop."
  wait_for_children
}

main() {
  local command=${1:-run}
  if [[ $# -gt 1 ]]; then
    usage >&2
    return 2
  fi
  case "$command" in
    run) configure_environment; run_all ;;
    build) configure_environment; build_all ;;
    -h|--help|help) usage ;;
    *) usage >&2; return 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
