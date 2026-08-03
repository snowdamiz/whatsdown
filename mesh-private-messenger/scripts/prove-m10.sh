#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly core_dir="$repo_root/mesh-private-messenger/packages/mobile-core"
readonly module_dir="$repo_root/mesh-private-messenger/apps/mobile/modules/mesh-messenger"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly vector="$repo_root/mesh-private-messenger/tests/fixtures/m1/outer-envelope-v1.hex"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m10.XXXXXX")"
readonly temp_dir
readonly database="$temp_dir/mobile.db"
readonly peer_database="$database.bob"
readonly linked_database="$database.linked"
if [[ "$(uname -s)" == Darwin ]]; then
  readonly library="$temp_dir/libmessenger_mobile.dylib"
  readonly host_system_libs=(-framework Security -framework CoreFoundation)
else
  readonly library="$temp_dir/libmessenger_mobile.so"
  readonly host_system_libs=()
fi

fail() {
  printf 'M10 proof failed: %s\n' "$*" >&2
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
      "$resolved_parent"/whatsdown-m10.*)
        if [[ "$(find "$resolved_temp" -type l | wc -l | tr -d ' ')" == 0 ]]; then
          find "$resolved_temp" -depth -delete
        fi
        ;;
    esac
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

build_ios() {
  local target=$1
  local sdk=$2
  local clang_target=$3
  local archive="$temp_dir/libmessenger_${target}.a"
  local linked="$temp_dir/libmessenger_${target}.dylib"

  IPHONEOS_DEPLOYMENT_TARGET=16.4 "$meshc_bin" build "$core_dir" \
    --artifact staticlib --target "$target" --output "$archive"
  xcrun --sdk "$sdk" clang -target "$clang_target" -dynamiclib \
    -Wl,-force_load,"$archive" -framework Security -framework CoreFoundation -lm -o "$linked"
  xcrun nm -gU "$linked" | grep '_mesh_messenger_validate_outer$' >/dev/null || \
    fail "$target artifact does not export the mobile protocol boundary"
}

prove_bridge() {
  local extension
  local java_home

  for extension in h swift kt jni.c ts; do
    cmp "$temp_dir/libmessenger_mobile.$extension" \
      "$module_dir/generated/libmessenger_mobile.$extension" >/dev/null || \
      fail "checked-in $extension binding is stale"
  done
  grep -q 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly' \
    "$module_dir/ios/MeshMessengerSecureStore.m" || fail "iOS adapter is not device-only Keychain storage"
  grep -q 'AndroidKeyStore' \
    "$module_dir/android/src/main/java/expo/modules/meshmessenger/MeshMessengerSecureStore.kt" || \
    fail "Android adapter does not use Android Keystore"
  grep -q 'AES/GCM/NoPadding' \
    "$module_dir/android/src/main/java/expo/modules/meshmessenger/MeshMessengerSecureStore.kt" || \
    fail "Android adapter does not authenticate encrypted values"
  [[ -f "$module_dir/ios/MeshMessenger.podspec" ]] || fail "iOS module descriptor is missing"
  [[ -f "$module_dir/android/build.gradle" ]] || fail "Android module descriptor is missing"
  [[ -f "$module_dir/android/src/main/cpp/CMakeLists.txt" ]] || fail "Android native build is missing"
  if grep -R -q 'secure_store_' "$module_dir/generated/libmessenger_mobile.ts" "$module_dir/index.ts"; then
    fail "secure-store operations crossed the TypeScript boundary"
  fi

  if [[ "$(uname -s)" == Darwin ]] && command -v xcrun >/dev/null; then
    xcrun clang -fobjc-arc -fmodules -fsyntax-only -I "$module_dir/generated" \
      "$module_dir/ios/MeshMessengerSecureStore.m"
    xcrun swiftc -frontend -parse "$module_dir/generated/libmessenger_mobile.swift" \
      "$module_dir/ios/MeshMessengerModule.swift"
    if java_home="$(/usr/libexec/java_home 2>/dev/null)"; then
      xcrun clang++ -std=c++17 -fsyntax-only -I "$module_dir/generated" \
        -I "$java_home/include" -I "$java_home/include/darwin" \
        "$module_dir/android/src/main/cpp/MeshMessengerHost.cpp"
    fi
  fi
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  command -v cc >/dev/null || fail "a C compiler is required"
  command -v sqlite3 >/dev/null || fail "sqlite3 is required"

  "$meshc_bin" build "$core_dir" --artifact cdylib --output "$library"
  cc "$core_dir/tests/host.c" -I "$temp_dir" -L "$temp_dir" -lmessenger_mobile \
    -Wl,-rpath,"$temp_dir" "${host_system_libs[@]}" -o "$temp_dir/host"
  "$temp_dir/host" "$vector" "$database"

  [[ "$(sqlite3 "$database" "SELECT count(*) = 13 AND min(length(record_hash)) = 64 AND min(length(ciphertext)) > 0 AND min(typeof(ciphertext)) = 'text' FROM encrypted_blobs;")" == 1 ]] || \
    fail "sender SQLite did not contain thirteen encrypted records after fanout"
  [[ "$(sqlite3 "$peer_database" "SELECT count(*) = 11 AND min(length(record_hash)) = 64 AND min(length(ciphertext)) > 0 AND min(typeof(ciphertext)) = 'text' FROM encrypted_blobs;")" == 1 ]] || \
    fail "recipient SQLite did not contain eleven encrypted fanout records"
  [[ "$(sqlite3 "$linked_database" "SELECT count(*) = 10 AND min(length(record_hash)) = 64 AND min(length(ciphertext)) > 0 AND min(typeof(ciphertext)) = 'text' FROM encrypted_blobs;")" == 1 ]] || \
    fail "linked-device SQLite did not contain ten encrypted sync records"
  local leak_pattern='whatsdown-mobile-record-key|account-signing-key|device-signing-key|device-identity-key|signed-prekey|one-time-prekey|post-quantum-prekey|pending-link|profile/v1|device-set/v1|sessions/v1|session/v1|history/v1|hello bob|hello alice|synced hello|all alice devices|blocked message|gone soon'
  local leaks
  leaks="$(LC_ALL=C grep -a -E -o "$leak_pattern" "$database" "$peer_database" "$linked_database" || true)"
  if [[ -n "$leaks" ]]; then
    fail "SQLite leaked a record label or profile value: $leaks"
  fi

  "$meshc_bin" build "$core_dir" --artifact staticlib \
    --output "$temp_dir/libmessenger_mobile.a"
  prove_bridge

  if [[ "$(uname -s)" == Darwin ]] && command -v xcrun >/dev/null && \
      [[ -f "$repo_root/mesh-lang/target/aarch64-apple-ios/debug/libmesh_rt.a" ]] && \
      [[ -f "$repo_root/mesh-lang/target/aarch64-apple-ios-sim/debug/libmesh_rt.a" ]]; then
    build_ios aarch64-apple-ios iphoneos arm64-apple-ios16.4
    build_ios aarch64-apple-ios-sim iphonesimulator arm64-apple-ios16.4-simulator
  fi

  printf 'M10 proof passed: canonical mobile vector, encrypted SQLite, native bridge, host lifecycle, static/dynamic libraries, and available iOS targets.\n'
}

main "$@"
