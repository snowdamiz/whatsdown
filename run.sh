#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
readonly messenger_root="$script_dir/mesh-private-messenger"
readonly mesh_root="${MESH_LANG_DIR:-$script_dir/mesh-lang}"
readonly meshc_bin="$mesh_root/target/debug/meshc"
readonly app_dir="$messenger_root/apps/mobile"
readonly desktop_dir="$messenger_root/apps/desktop"
readonly landing_dir="$messenger_root/apps/landing"
readonly service_root="$messenger_root/services"
readonly compose_file="$service_root/directory-delivery/docker-compose.yml"
readonly migrations_dir="$service_root/directory-delivery/migrations"
# Keep the database volume stable across product renames.
readonly compose_project="whatsdown-dev"
readonly state_dir="${MORSE_STATE_DIR:-$script_dir/.morse}"
readonly log_dir="$state_dir/logs"
readonly runner_lock="$state_dir/run.lock"
readonly schema_stamp="$state_dir/postgres-migrations"

child_pids=()
child_names=()
client=desktop
landing_only=false
owns_lock=false

usage() {
  printf '%s\n' \
    "Usage: ./run.sh [run|landing|desktop|mobile|build|reset]" \
    "" \
    "  run      Start the backend, landing page, desktop, and mobile simulator app (default)." \
    "  landing  Serve the landing page only." \
    "  desktop  Start the backend and desktop only." \
    "  mobile   Start the backend and mobile simulator app only." \
    "  build    Build the backend and desktop without starting them." \
    "  reset    Delete the development database so the next run rebuilds it." \
    "" \
    "Set MESH_LANG_DIR to a separate Mesh checkout or MORSE_MOBILE_PLATFORM to ios/android."
}

fail() {
  printf 'morse: %s\n' "$*" >&2
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
  export MESSENGER_STREAM_PORT="${MESSENGER_STREAM_PORT:-18090}"
  export MORSE_LANDING_PORT="${MORSE_LANDING_PORT:-18080}"
  export MESSENGER_ABUSE_DIFFICULTY="${MESSENGER_ABUSE_DIFFICULTY:-8}"
  export MESSENGER_OBJECT_WORK_DIFFICULTY="${MESSENGER_OBJECT_WORK_DIFFICULTY:-8}"
  MESSENGER_DATABASE_URL="${MESSENGER_DATABASE_URL:-postgres://messenger:messenger@127.0.0.1:$MESSENGER_POSTGRES_PORT/messenger?sslmode=disable}"
  MESSENGER_DELIVERY_INTERNAL_URL="${MESSENGER_DELIVERY_INTERNAL_URL:-http://127.0.0.1:$MESSENGER_PORT}"
  MESSENGER_PUSH_MODE="${MESSENGER_PUSH_MODE:-broker}"
  MESSENGER_PUSH_BROKER_URL="${MESSENGER_PUSH_BROKER_URL:-http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT}"
  export EXPO_PUBLIC_MESSENGER_BASE_URL="${EXPO_PUBLIC_MESSENGER_BASE_URL:-http://127.0.0.1:$MESSENGER_PORT}"
  export EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL="${EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL:-http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT}"
  export EXPO_PUBLIC_MESSENGER_STREAM_URL="${EXPO_PUBLIC_MESSENGER_STREAM_URL:-ws://127.0.0.1:$MESSENGER_STREAM_PORT/v1/mailbox/stream}"
  export EXPO_PUBLIC_MESSENGER_OBJECT_URL="${EXPO_PUBLIC_MESSENGER_OBJECT_URL:-http://127.0.0.1:$MESSENGER_OBJECT_PORT}"
  export EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY="${EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY:-$MESSENGER_OBJECT_WORK_DIFFICULTY}"

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
  if [[ -n "${MORSE_MOBILE_PLATFORM:-}" ]]; then
    case "$MORSE_MOBILE_PLATFORM" in
      ios|android) printf '%s\n' "$MORSE_MOBILE_PLATFORM" ;;
      *) fail "MORSE_MOBILE_PLATFORM must be ios or android" ;;
    esac
  elif [[ "$(uname -s)" == Darwin ]]; then
    printf 'ios\n'
  elif [[ -n "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
    printf 'android\n'
  else
    fail "set MORSE_MOBILE_PLATFORM and install its native toolchain"
  fi
}

build_mesh() {
  [[ -f "$mesh_root/Cargo.toml" ]] || { fail "Mesh checkout not found at $mesh_root"; return 1; }
  local dependency_root="$script_dir/mesh-lang"
  local resolved_mesh_root
  resolved_mesh_root="$(cd "$mesh_root" && pwd -P)" || return 1
  if [[ ! -e "$dependency_root" && ! -L "$dependency_root" ]]; then
    ln -s "$resolved_mesh_root" "$dependency_root" || return 1
  fi
  if [[ ! -d "$dependency_root" ]] || \
    [[ "$(cd "$dependency_root" && pwd -P)" != "$resolved_mesh_root" ]]; then
    fail "$dependency_root must resolve to MESH_LANG_DIR ($resolved_mesh_root)"
    return 1
  fi
  (
    cd "$mesh_root"
    CARGO_INCREMENTAL=0 cargo build --locked -p meshc
    CARGO_INCREMENTAL=0 cargo build --locked -p mesh-rt --lib
  )
}

# Replaces a literal string in a file under apps/mobile that npm or Expo
# regenerates, so every launch reapplies it. A file with neither form changed
# upstream: say so now, because the simulator build otherwise fails minutes
# later with an error that does not name the cause.
patch_generated() {
  local file="$app_dir/$1"
  [[ -f "$file" ]] || return 0
  if grep -qF -- "$3" "$file"; then return 0; fi
  if ! grep -qF -- "$2" "$file"; then
    printf 'morse: %s no longer matches its patch in patch_external_checkout\n' "$file" >&2
    return 0
  fi
  OLD=$2 NEW=$3 perl -pi -e 's/\Q$ENV{OLD}\E/$ENV{NEW}/g' "$file"
}

# Lets the simulator build run from a checkout on an external volume, which
# trips React Native and Expo in two ways. Both are unfixed upstream.
# shellcheck disable=SC2016
patch_external_checkout() {
  local template_call quoted_call
  # ExFAT has no extended attributes, so macOS keeps them in binary "._name"
  # files, which Xcode writes beside each Swift interface mid-build. Expo's globs
  # match those too, and its sed stops on one with "illegal byte sequence".
  patch_generated node_modules/expo-modules-jsi/apple/scripts/build-xcframework.sh \
    '.swiftmodule" -' ".swiftmodule\" ! -name '._*' -"
  # A space in the volume name: these split the project path.
  patch_generated node_modules/expo-constants/scripts/get-app-config-ios.sh \
    '$(basename $PROJECT_DIR)' '$(basename "$PROJECT_DIR")'
  patch_generated node_modules/expo-constants/ios/EXConstants.podspec \
    'bash -l -c \"#{env_vars}$PODS_TARGET_SRCROOT/' '#{env_vars}bash -l \"$PODS_TARGET_SRCROOT/'
  patch_generated node_modules/expo-updates/ios/EXUpdates.podspec \
    'bash -l -c "$PODS_TARGET_SRCROOT/' 'bash -l "$PODS_TARGET_SRCROOT/'
  # CocoaPods copied those two commands into any project it installed earlier,
  # and Expo reinstalls pods only when package.json changes.
  patch_generated ios/Pods/Pods.xcodeproj/project.pbxproj \
    'bash -l -c \"$PODS_TARGET_SRCROOT/' 'bash -l \"$PODS_TARGET_SRCROOT/'
  # React Native's app template runs a printed path from bare backticks.
  IFS= read -r template_call <<'EOF'
`\"$NODE_BINARY\" --print \"require('path').dirname(require.resolve('react-native/package.json')) + '/scripts/react-native-xcode.sh'\"`
EOF
  quoted_call="${template_call#?}"
  patch_generated ios/Morse.xcodeproj/project.pbxproj \
    "$template_call" "\\\"\$(${quoted_call%?})\\\""
}

npm_install() {
  local dir=$1
  shift
  if [[ ! -f "$dir/node_modules/.package-lock.json" \
    || "$dir/package-lock.json" -nt "$dir/node_modules/.package-lock.json" ]]; then
    npm --prefix "$dir" ci "$@"
  fi
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
  local vfs_overlay
  platform="$(mobile_platform)"
  npm_install "$app_dir" --ignore-scripts=false
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
  # Expo otherwise generates ios/ while it builds, too late to patch.
  if [[ "$platform" == ios && ! -d "$app_dir/ios" ]]; then
    npm --prefix "$app_dir" exec -- expo prebuild "$app_dir" --platform ios --no-install
  fi
  # pod install writes this checkout's absolute path all through ios/Pods, so
  # after the checkout moves or its volume is renamed, Xcode reads files that
  # are gone. Expo reinstalls pods when the folder is missing.
  vfs_overlay="$app_dir/ios/Pods/React-Core-prebuilt/React-VFS.yaml"
  if [[ -f "$vfs_overlay" ]] && ! grep -qF "$app_dir/ios/Pods/" "$vfs_overlay"; then
    printf 'morse: ios/Pods was installed at another path; reinstalling it\n' >&2
    rm -rf "$app_dir/ios/Pods"
  fi
  patch_external_checkout
  # External macOS volumes create AppleDouble files that Expo mistakes for podspecs.
  # Patching writes more of them, so this stays last.
  find "$app_dir" -type f -name '._*' -delete
}

build_desktop() {
  local dir
  for dir in "$app_dir" "$desktop_dir"; do
    npm_install "$dir"
  done
  MESHC="$meshc_bin" npm --prefix "$desktop_dir" run native -- --development
}

build_all() {
  require_command rustup
  PATH="$(dirname "$(rustup which cargo)"):$PATH"
  require_command cargo
  require_command npm
  if [[ "$(uname -s)" == Darwin ]]; then
    export MACOSX_DEPLOYMENT_TARGET=12.0
  fi
  build_mesh
  build_services
  if [[ "$client" != desktop ]]; then
    build_mobile
  fi
  if [[ "$client" != mobile ]]; then
    if [[ "${1:-run}" == build ]] || ! desktop_running; then
      build_desktop
    fi
  fi
}

compose() {
  docker compose --project-name "$compose_project" --file "$compose_file" "$@"
}

# A stopped Docker Desktop leaves a socket that accepts connections and never
# answers, so an unbounded `docker info` hangs the launcher before it prints
# anything. Bound every probe; the caller owns the overall deadline.
docker_ready() {
  local pid attempt
  docker info >/dev/null 2>&1 &
  pid=$!
  for ((attempt = 0; attempt < 50; attempt += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" && return 0
      return 1
    fi
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

ensure_docker() {
  require_command docker
  docker compose version >/dev/null 2>&1 || { fail "docker compose v2 is required"; return 1; }
  if docker_ready; then return; fi
  [[ "$(uname -s)" == Darwin ]] || { fail "Start your Docker daemon, then rerun ./run.sh"; return 1; }
  printf 'Starting Docker Desktop...\n'
  open -g -a Docker || { fail "no Docker Desktop to open; start your Docker daemon, then rerun ./run.sh"; return 1; }
  local deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    if docker_ready; then return; fi
    sleep 1
  done
  fail "Docker Desktop did not become ready within 120 seconds"
}

# Docker Desktop corrupts its VM when a build fills the disk, and then wedges
# until its backend is killed, so name a shortfall before the build rather than
# ten minutes into it. Both volumes matter: the checkout holds Cargo's target
# directory, the home volume holds Docker's disk image and Xcode's caches.
check_disk_space() {
  local path filesystem free previous=""
  for path in "$script_dir" "$HOME"; do
    read -r filesystem free <<<"$(df -Pk "$path" | awk 'NR == 2 { print $1, $4 }')"
    if [[ "$filesystem" != "$previous" ]]; then
      previous=$filesystem
      if ((free < 15 * 1024 * 1024)); then
        printf 'morse: %s GiB free on %s; a full build needs more room and Docker corrupts its VM when the disk fills.\n' \
          "$((free / 1024 / 1024))" "$filesystem" >&2
      fi
    fi
  done
}

# PostgreSQL seeds migrations/ into a new volume once and never again, so a
# database created before a migration was added keeps a stale schema, and the
# services then fail with errors that do not name the cause. Record the
# migration set whenever this launcher creates the volume, and report drift.
start_database() {
  local applied fresh=false
  applied="$(cd "$migrations_dir" && printf '%s\n' *.sql)"
  docker volume inspect "${compose_project}_messenger-postgres" >/dev/null 2>&1 || fresh=true
  compose up --detach --wait postgres
  if [[ "$fresh" == true || ! -f "$schema_stamp" ]]; then
    printf '%s\n' "$applied" >"$schema_stamp"
  elif [[ "$applied" != "$(cat "$schema_stamp")" ]]; then
    printf '%s\n' \
      "morse: migrations changed since this development database was created." \
      "       Run ./run.sh reset to rebuild it." >&2
  fi
}

reset_database() {
  ensure_docker
  compose down --volumes
  rm -f "$schema_stamp" "$state_dir"/witness-*.checkpoint
  rm -rf "${state_dir:?}/objects"
  printf 'Development database, witness checkpoints and stored objects deleted;\n./run.sh recreates them.\n'
}

start_process() {
  local name=$1
  shift
  "$@" >"$log_dir/$name.log" 2>&1 &
  child_pids+=("$!")
  child_names+=("$name")
}

start_service() {
  local name=$1 url=$2
  shift 2
  if curl --max-time 2 --fail --silent "$url/health" >/dev/null 2>&1; then
    printf 'Reusing %s at %s\n' "$name" "$url"
    return
  fi
  start_process "$name" "$@"
  wait_for_health "$name" "$url"
}

wait_for_health() {
  local name=$1
  local url=$2
  local attempt
  for ((attempt = 0; attempt < 150; attempt += 1)); do
    if curl --max-time 5 --fail --silent --show-error "$url/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  tail -n 40 "$log_dir/$name.log" >&2 || true
  fail "$name did not become healthy"
}

start_landing() {
  require_command python3
  start_process landing python3 -m http.server "$MORSE_LANDING_PORT" \
    --bind 127.0.0.1 --directory "$landing_dir"
  local attempt
  for ((attempt = 0; attempt < 150; attempt += 1)); do
    if curl --max-time 5 --fail --silent --show-error \
      "http://127.0.0.1:$MORSE_LANDING_PORT/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  tail -n 40 "$log_dir/landing.log" >&2 || true
  fail "landing page did not become ready"
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

desktop_running() {
  local executable
  while IFS= read -r executable; do
    # Only the development build (io.morseapp.desktop.dev) counts. It runs from
    # Cargo's target directory, which may sit outside the checkout. An installed
    # Morse.app is the release identity with its own data and runs beside it.
    case "$executable" in
      */debug/Morse) return 0 ;;
    esac
  done < <(ps -axo comm=)
  return 1
}

start_services() {
  start_service push-broker "http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT" env \
    MESSENGER_PUSH_BROKER_PORT="$MESSENGER_PUSH_BROKER_PORT" \
    MESSENGER_PUSH_BROKER_SEED_HEX="$MESSENGER_PUSH_BROKER_SEED_HEX" \
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN="$MESSENGER_PUSH_BROKER_INTERNAL_TOKEN" \
    MESSENGER_PUSH_BROKER_DATABASE_URL="$MESSENGER_DATABASE_URL" \
    MESSENGER_EXPO_PUSH_URL="$MESSENGER_EXPO_PUSH_URL" \
    MESSENGER_EXPO_ACCESS_TOKEN="$MESSENGER_EXPO_ACCESS_TOKEN" \
    "$service_root/push-broker/output"

  start_service directory-delivery "http://127.0.0.1:$MESSENGER_PORT" env \
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

  start_service privacy-edge "http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT" env \
    MESSENGER_PRIVACY_EDGE_PORT="$MESSENGER_PRIVACY_EDGE_PORT" \
    MESSENGER_ABUSE_DIFFICULTY="$MESSENGER_ABUSE_DIFFICULTY" \
    MESSENGER_DELIVERY_INTERNAL_URL="$MESSENGER_DELIVERY_INTERNAL_URL" \
    MESSENGER_DELIVERY_INTERNAL_TOKEN="$MESSENGER_DELIVERY_INTERNAL_TOKEN" \
    "$service_root/privacy-edge/output"

  start_service object-store "http://127.0.0.1:$MESSENGER_OBJECT_PORT" env \
    MESSENGER_OBJECT_PORT="$MESSENGER_OBJECT_PORT" \
    MESSENGER_OBJECT_WORK_DIFFICULTY="$MESSENGER_OBJECT_WORK_DIFFICULTY" \
    MESSENGER_OBJECT_DATABASE_URL="$MESSENGER_DATABASE_URL" \
    MESSENGER_OBJECT_STORAGE_ROOT="$state_dir/objects" \
    "$service_root/object-store/output"

  start_process witness-a witness_loop witness-a \
    "$MESSENGER_WITNESS_A_SIGNING_SEED_HEX" "$MESSENGER_WITNESS_A_PUBLIC_KEY_HEX" \
    "$state_dir/witness-a.checkpoint"
  start_process witness-b witness_loop witness-b \
    "$MESSENGER_WITNESS_B_SIGNING_SEED_HEX" "$MESSENGER_WITNESS_B_PUBLIC_KEY_HEX" \
    "$state_dir/witness-b.checkpoint"
  if [[ "$client" != desktop ]]; then
    start_process mobile npm --prefix "$app_dir" run "$(mobile_platform)"
  fi
  if [[ "$client" != mobile ]]; then
    if desktop_running; then
      printf 'Morse desktop is already running.\n'
    else
      start_process desktop npm --prefix "$desktop_dir" run dev
    fi
  fi
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
        printf 'morse: %s exited with status %s\n' "${child_names[$index]}" "$status" >&2
        tail -n 40 "$log_dir/${child_names[$index]}.log" >&2 || true
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
  if ((${#child_pids[@]} > 0)); then
    for pid in "${child_pids[@]}"; do
      kill -- "-$pid" >/dev/null 2>&1
    done
    for pid in "${child_pids[@]}"; do
      wait "$pid" >/dev/null 2>&1
    done
  fi
  if [[ "$owns_lock" == true ]]; then
    rm -f "$runner_lock/pid"
    rmdir "$runner_lock"
  fi
  exit "$status"
}

run_all() {
  require_command curl
  mkdir -p "$log_dir" "$state_dir/objects"
  chmod 700 "$state_dir"
  if ! mkdir "$runner_lock" 2>/dev/null; then
    local pid
    pid="$(cat "$runner_lock/pid" 2>/dev/null || true)"
    if [[ -z "$pid" ]]; then
      # A concurrent launcher may still be writing its PID after mkdir.
      sleep 1
      pid="$(cat "$runner_lock/pid" 2>/dev/null || true)"
    fi
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
      printf 'Morse launcher is already running (PID %s; logs: %s).\n' "$pid" "$log_dir"
      return
    fi
    printf 'Removing stale launcher lock.\n'
    rm -f "$runner_lock/pid"
    rmdir "$runner_lock"
    mkdir "$runner_lock"
  fi
  owns_lock=true
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  printf '%s\n' "$$" > "$runner_lock/pid"
  # Separate process groups let Ctrl-C stop npm/Cargo and witness descendants too.
  set -m
  if [[ "$landing_only" == true ]]; then
    start_landing
    printf 'Morse landing page is running at http://127.0.0.1:%s.\n' "$MORSE_LANDING_PORT"
    wait_for_children
    return
  fi
  ensure_docker
  check_disk_space
  build_all
  start_database
  start_services
  if [[ "$client" == both ]]; then
    start_landing
  fi
  printf '%s\n' \
    "Morse backend is running; app startup logs are in $log_dir." \
    "  directory  http://127.0.0.1:$MESSENGER_PORT" \
    "  edge       http://127.0.0.1:$MESSENGER_PRIVACY_EDGE_PORT" \
    "  broker     http://127.0.0.1:$MESSENGER_PUSH_BROKER_PORT" \
    "  objects    http://127.0.0.1:$MESSENGER_OBJECT_PORT"
  if [[ "$client" == both ]]; then
    printf '  landing    http://127.0.0.1:%s\n' "$MORSE_LANDING_PORT"
  fi
  printf '%s\n' \
    "  logs       $log_dir" \
    "Press Ctrl-C to stop processes started here. PostgreSQL stays running."
  wait_for_children
}

main() {
  local command=${1:-run}
  if [[ $# -gt 1 ]]; then
    usage >&2
    return 2
  fi
  case "$command" in
    run) client=both; configure_environment; run_all ;;
    landing) landing_only=true; export MORSE_LANDING_PORT="${MORSE_LANDING_PORT:-18080}"; run_all ;;
    desktop) configure_environment; run_all ;;
    mobile) client=mobile; configure_environment; run_all ;;
    build) configure_environment; build_all build ;;
    reset) reset_database ;;
    -h|--help|help) usage ;;
    *) usage >&2; return 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
