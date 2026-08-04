#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd -P)"
readonly repo_root
readonly core_dir="$repo_root/mesh-private-messenger/packages/mobile-core"
readonly cli_dir="$repo_root/mesh-private-messenger/clients/mesh-cli"
readonly interop_dir="$repo_root/mesh-private-messenger/tests/interoperability"
readonly shared_transport="$repo_root/mesh-private-messenger/packages/messenger-protocol/transport/packet.mpl"
readonly module_dir="$repo_root/mesh-private-messenger/apps/mobile/modules/mesh-messenger"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
temp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly temp_parent
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m10.XXXXXX")"
readonly temp_dir
readonly database="$temp_dir/mobile.db"
readonly capacity_database="$database.capacity"
readonly legacy_active_database="$database.legacy-active"
readonly legacy_consumed_database="$database.legacy-consumed"
readonly delivery_sealing_seed_hex="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
if [[ "$(uname -s)" == Darwin ]]; then
  readonly library="$temp_dir/libmessenger_mobile.dylib"
else
  readonly library="$temp_dir/libmessenger_mobile.so"
fi

fail() {
  printf 'M10 proof failed: %s\n' "$*" >&2
  return 1
}

encrypted_database_matches() {
  local database_path=$1
  local expected_count=$2
  [[ "$(sqlite3 "$database_path" "SELECT count(*) = $expected_count AND min(length(record_hash)) = 64 AND min(length(ciphertext)) > 0 AND sum(typeof(ciphertext) != 'blob') = 0 FROM encrypted_blobs;")" == 1 ]]
}

encrypted_database_nonempty() {
  local database_path=$1
  [[ "$(sqlite3 "$database_path" "SELECT count(*) > 0 AND min(length(record_hash)) = 64 AND min(length(ciphertext)) > 0 AND sum(typeof(ciphertext) != 'blob') = 0 FROM encrypted_blobs;")" == 1 ]]
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    case "$temp_dir" in
      "$temp_parent"/whatsdown-m10.*)
        if [[ "$(find "$temp_dir" -type l | wc -l | tr -d ' ')" == 0 ]]; then
          find "$temp_dir" -depth -delete
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
  grep -Fq 'stringWithFormat:@"1\n%@\n%@"' \
    "$module_dir/ios/MeshMessengerSecureStore.m" || \
    fail "iOS adapter does not marshal the versioned signed push config frame"
  grep -Fq '"1\n${projectID.orEmpty()}\n${brokerPublicKeyHex.orEmpty()}"' \
    "$module_dir/android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt" || \
    fail "Android adapter does not marshal the versioned signed push config frame"
  [[ -f "$module_dir/ios/MeshMessenger.podspec" ]] || fail "iOS module descriptor is missing"
  [[ -f "$module_dir/android/build.gradle" ]] || fail "Android module descriptor is missing"
  [[ -f "$module_dir/android/src/main/cpp/CMakeLists.txt" ]] || fail "Android native build is missing"
  if grep -R -q 'secure_store_' "$module_dir/generated/libmessenger_mobile.ts" "$module_dir/index.ts"; then
    fail "secure-store operations crossed the TypeScript boundary"
  fi
  local symbol
  for symbol in mesh_messenger_outbox_list mesh_messenger_outbox_ack \
    mesh_messenger_replenish_prekeys mesh_messenger_reconcile_prekeys; do
    grep -q "\"$symbol\"" "$module_dir/ios/MeshMessengerModule.swift" || \
      fail "iOS bridge does not dispatch $symbol"
    grep -q "\"$symbol\"" \
      "$module_dir/android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt" || \
      fail "Android bridge does not dispatch $symbol"
  done
  if ! grep -q 'private let lock = NSLock()' "$module_dir/ios/MeshMessengerModule.swift" || \
      ! grep -q 'self.lock.lock()' "$module_dir/ios/MeshMessengerModule.swift"; then
    fail "iOS bridge does not serialize native invocations"
  fi
  grep -q 'synchronized(lock)' \
    "$module_dir/android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt" || \
    fail "Android bridge does not serialize native invocations"

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
  command -v sqlite3 >/dev/null || fail "sqlite3 is required"

  local mixed_database="$temp_dir/mixed-storage.db"
  sqlite3 "$mixed_database" "CREATE TABLE encrypted_blobs(record_hash TEXT, ciphertext BLOB); INSERT INTO encrypted_blobs VALUES (printf('%064d', 0), X'00'), (printf('%064d', 1), 'text');"
  if encrypted_database_matches "$mixed_database" 2; then
    fail "encrypted SQLite verification accepted a non-BLOB ciphertext"
  fi

  [[ ! -e "$cli_dir/transport/packet.mpl" ]] || \
    fail "the CLI still owns a private transport codec"
  [[ -z "$(find "$core_dir/tests" -type f -name '*.c' -print -quit)" ]] || \
    fail "mobile-core behavior tests must be written in Mesh, not C"
  [[ -f "$shared_transport" ]] || fail "the shared client transport codec is missing"
  if grep -R -q 'from MobileCore' "$cli_dir/interop"; then
    fail "the CLI interoperability module imports the mobile implementation"
  fi
  if grep -qE 'struct Mobile(Profile|InitialPacket|InitialPlaintext|RatchetPacket)|fn (encode_initial_packet|encode_ratchet_packet|ratchet_aad)' \
      "$core_dir/mobile_core.mpl"; then
    fail "the mobile core still owns a duplicate behavioral client codec"
  fi

  "$meshc_bin" build "$cli_dir" --output "$temp_dir/mesh-cli"
  "$meshc_bin" test "$cli_dir/tests/transport.test.mpl"
  MESSENGER_M10_INTEROP_PATH="$database" "$meshc_bin" test "$interop_dir"
  encrypted_database_nonempty "$database" || \
    fail "CLI/mobile interoperability did not persist encrypted SQLite blobs"
  local interop_leaks
  interop_leaks="$(LC_ALL=C grep -a -E -o 'm10-cli-greeting-opaque|m10-mobile-reply-opaque' "$database" || true)"
  if [[ -n "$interop_leaks" ]]; then
    fail "CLI/mobile interoperability leaked message plaintext into SQLite: $interop_leaks"
  fi

  # meshc's e2e_library suite owns the generic foreign-host ABI, link, and
  # lifecycle proof. Messenger behavior stays in the Mesh tests below.
  "$meshc_bin" build "$core_dir" --artifact cdylib --output "$library"

  MESSENGER_DELIVERY_SEALING_SEED_HEX="$delivery_sealing_seed_hex" \
    MESSENGER_M10_CAPACITY_PATH="$capacity_database" \
    MESSENGER_M10_LEGACY_ACTIVE_PATH="$legacy_active_database" \
    MESSENGER_M10_LEGACY_CONSUMED_PATH="$legacy_consumed_database" \
    "$meshc_bin" test "$core_dir/tests"

  encrypted_database_matches "$capacity_database" 73 || \
    fail "bounded-pool SQLite did not contain sixty-four encrypted one-time prekeys"
  encrypted_database_matches "$legacy_active_database" 10 || \
    fail "active legacy singleton migration did not remain encrypted"
  encrypted_database_matches "$legacy_consumed_database" 11 || \
    fail "consumed legacy singleton migration did not remain encrypted"
  local leak_pattern='whatsdown-mobile-record-key|account-signing-key|device-signing-key|device-identity-key|signed-prekey|one-time-prekey|post-quantum-prekey|pending-link|profile/v1|device-set/v1|sessions/v1|session/v1|history/v1|capacity|legacy-active|legacy-consumed|hello bob|hello alice|synced hello|all alice devices|blocked message|gone soon'
  local leaks
  leaks="$(LC_ALL=C grep -a -E -o "$leak_pattern" "$capacity_database" "$legacy_active_database" "$legacy_consumed_database" || true)"
  if [[ -n "$leaks" ]]; then
    fail "SQLite leaked a record label or profile value: $leaks"
  fi

  "$meshc_bin" build "$core_dir" --artifact staticlib \
    --output "$temp_dir/libmessenger_mobile.a"
  prove_bridge

  local target_proof="host target only; no iOS toolchain was expected"
  if [[ "$(uname -s)" == Darwin ]] && command -v xcrun >/dev/null; then
    [[ -f "$repo_root/mesh-lang/target/aarch64-apple-ios/debug/libmesh_rt.a" ]] || \
      fail "aarch64-apple-ios runtime is missing; build mesh-rt for that target first"
    [[ -f "$repo_root/mesh-lang/target/aarch64-apple-ios-sim/debug/libmesh_rt.a" ]] || \
      fail "aarch64-apple-ios-sim runtime is missing; build mesh-rt for that target first"
    build_ios aarch64-apple-ios iphoneos arm64-apple-ios16.4
    build_ios aarch64-apple-ios-sim iphonesimulator arm64-apple-ios16.4-simulator
    target_proof="iOS device and simulator targets"
  fi

  printf 'M10 proof passed: Mesh CLI/mobile suite-2 round trip, encrypted SQLite plaintext exclusion, Mesh behavior, native bindings, static/dynamic libraries, and %s.\n' \
    "$target_proof"
}

main "$@"
