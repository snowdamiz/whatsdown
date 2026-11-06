#!/usr/bin/env bash
set -euo pipefail

readonly platform="${1:-all}"
case "$platform" in
  all|ios|android) ;;
  *) printf 'usage: %s [all|ios|android]\n' "$0" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd -P)"
readonly repo_root
readonly core_dir="$repo_root/mesh-private-messenger/packages/mobile-core"
readonly module_dir="$repo_root/mesh-private-messenger/apps/mobile/modules/mesh-messenger"
readonly wallet_dir="$repo_root/mesh-private-messenger/packages/wallet-core"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
temp_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
readonly temp_parent
temp_dir="$(mktemp -d "$temp_parent/morse-mobile-native.XXXXXX")"
readonly temp_dir

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    case "$temp_dir" in
      "$temp_parent"/morse-mobile-native.*)
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

require_physical_directory() {
  local path=$1
  [[ -d "$path" && ! -L "$path" ]] && [[ "$(cd "$path" && pwd -P)" == "$path" ]] || {
    printf '%s must be a physical directory inside the checkout\n' "$path" >&2
    return 1
  }
}

check_bindings() {
  local extension
  "$meshc_bin" build "$core_dir" --artifact staticlib \
    --output "$temp_dir/libmessenger_mobile.a"
  check_disclosures "$temp_dir/libmessenger_mobile.a"
  for extension in h swift kt jni.c ts; do
    cmp "$temp_dir/libmessenger_mobile.$extension" \
      "$module_dir/generated/libmessenger_mobile.$extension" >/dev/null || {
        printf 'generated %s binding is stale; rebuild it with the current Mesh compiler\n' \
          "$extension" >&2
        return 1
      }
  done
  node "$repo_root/mesh-private-messenger/apps/mobile/scripts/generate-scoped-bindings.mjs" \
    --abi "$temp_dir/libmessenger_mobile.abi.json" --check
}

check_disclosures() {
  local library=$1
  node "$repo_root/mesh-private-messenger/ops/plaintext/report.mjs" \
    --report "$library.plaintext.json" \
    --review "$repo_root/mesh-private-messenger/protocol/plaintext-disclosures.json" \
    --compiler "$meshc_bin" --artifact "$library" \
    --output "$library.plaintext-evidence.json"
}

install_disclosures() {
  local library=$1
  local target=$2
  local destination="$module_dir/native/plaintext/$target"
  mkdir -p "$destination"
  require_physical_directory "$destination"
  cp "$library.plaintext.json" "$destination/report.json"
  cp "$library.plaintext-evidence.json" "$destination/evidence.json"
}

build_wallet() {
  local target=$1
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  local host_tag
  local linker
  local linker_variable
  case "$target" in
    *-linux-android)
      case "$(uname -s)" in Darwin) host_tag=darwin-x86_64 ;; Linux) host_tag=linux-x86_64 ;; *) return 1 ;; esac
      linker="$ndk/toolchains/llvm/prebuilt/$host_tag/bin/${target}26-clang"
      [[ -x "$linker" ]] || { printf 'Android wallet linker missing: %s\n' "$linker" >&2; return 1; }
      linker_variable="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"
      env "$linker_variable=$linker" "${CARGO:-cargo}" build --locked --release \
        --manifest-path "$wallet_dir/Cargo.toml" --target "$target" --target-dir "$temp_dir/wallet-target"
      ;;
    *)
      "${CARGO:-cargo}" build --locked --release --manifest-path "$wallet_dir/Cargo.toml" \
        --target "$target" --target-dir "$temp_dir/wallet-target"
      ;;
  esac
}

install_wallet_header() {
  mkdir -p "$module_dir/native/include"
  require_physical_directory "$module_dir/native/include"
  cp "$wallet_dir/include/morse_wallet_core.h" "$module_dir/native/include/morse_wallet_core.h"
}

build_ios() {
  local destination_parent="$module_dir/native/ios"
  local destination="$destination_parent/MeshMessengerCore.xcframework"
  local device="$temp_dir/device/libmessenger_mobile.a"
  local simulator="$temp_dir/simulator/libmessenger_mobile.a"
  local staged="$temp_dir/MeshMessengerCore.xcframework"
  local wallet_destination="$destination_parent/MorseWalletCore.xcframework"
  local wallet_staged="$temp_dir/MorseWalletCore.xcframework"

  [[ "$(uname -s)" == Darwin ]] || { printf 'iOS builds require macOS\n' >&2; return 1; }
  command -v xcodebuild >/dev/null
  mkdir -p "$destination_parent"
  require_physical_directory "$destination_parent"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" ]]
    [[ "$(find "$destination" -type l | wc -l | tr -d ' ')" == 0 ]]
  fi
  if [[ -e "$wallet_destination" || -L "$wallet_destination" ]]; then
    [[ -d "$wallet_destination" && ! -L "$wallet_destination" ]]
    [[ "$(find "$wallet_destination" -type l | wc -l | tr -d ' ')" == 0 ]]
  fi
  mkdir -p "$(dirname "$device")" "$(dirname "$simulator")"
  IPHONEOS_DEPLOYMENT_TARGET=16.4 "$meshc_bin" build "$core_dir" \
    --artifact staticlib --target aarch64-apple-ios --output "$device"
  check_disclosures "$device"
  IPHONEOS_DEPLOYMENT_TARGET=16.4 "$meshc_bin" build "$core_dir" \
    --artifact staticlib --target aarch64-apple-ios-sim --output "$simulator"
  check_disclosures "$simulator"
  mkdir "$temp_dir/headers"
  cp "$module_dir/generated/libmessenger_mobile.h" "$temp_dir/headers/"
  xcodebuild -create-xcframework \
    -library "$device" -headers "$temp_dir/headers" \
    -library "$simulator" -headers "$temp_dir/headers" \
    -output "$staged"
  build_wallet aarch64-apple-ios
  build_wallet aarch64-apple-ios-sim
  mkdir "$temp_dir/wallet-headers"
  cp "$wallet_dir/include/morse_wallet_core.h" "$temp_dir/wallet-headers/"
  xcodebuild -create-xcframework \
    -library "$temp_dir/wallet-target/aarch64-apple-ios/release/libmorse_wallet_core.a" -headers "$temp_dir/wallet-headers" \
    -library "$temp_dir/wallet-target/aarch64-apple-ios-sim/release/libmorse_wallet_core.a" -headers "$temp_dir/wallet-headers" \
    -output "$wallet_staged"
  # Keep the installed framework until both architectures and packaging pass.
  # A missing runtime or SDK must not erase the last usable native build.
  if [[ -d "$destination" ]]; then find "$destination" -depth -delete; fi
  mv "$staged" "$destination"
  if [[ -d "$wallet_destination" ]]; then find "$wallet_destination" -depth -delete; fi
  mv "$wallet_staged" "$wallet_destination"
  install_disclosures "$device" aarch64-apple-ios
  install_disclosures "$simulator" aarch64-apple-ios-sim
  install_wallet_header
}

build_android() {
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  local target
  local abi
  local destination
  local destination_parent
  local archive
  local -a artifacts=(libmessenger_mobile.a libmorse_wallet_core.a
    libmessenger_mobile.abi.json libmessenger_mobile.h libmessenger_mobile.swift
    libmessenger_mobile.kt libmessenger_mobile.jni.c libmessenger_mobile.ts)

  [[ -n "$ndk" && -d "$ndk" ]] || {
    printf 'ANDROID_NDK_HOME or ANDROID_NDK_ROOT must name an installed NDK\n' >&2
    return 1
  }
  for target in aarch64-linux-android x86_64-linux-android; do
    case "$target" in
      aarch64-linux-android) abi=arm64-v8a ;;
      x86_64-linux-android) abi=x86_64 ;;
    esac
    destination="$module_dir/native/android/$abi/libmessenger_mobile.a"
    destination_parent="$(dirname "$destination")"
    mkdir -p "$destination_parent"
    require_physical_directory "$destination_parent"
    if [[ -e "$destination" || -L "$destination" ]]; then
      [[ -f "$destination" && ! -L "$destination" ]]
    fi
    mkdir -p "$temp_dir/android/$abi"
    ANDROID_NDK_HOME="$ndk" "$meshc_bin" build "$core_dir" \
      --artifact staticlib --target "$target" --output "$temp_dir/android/$abi/libmessenger_mobile.a"
    check_disclosures "$temp_dir/android/$abi/libmessenger_mobile.a"
    build_wallet "$target"
    cp "$temp_dir/wallet-target/$target/release/libmorse_wallet_core.a" "$temp_dir/android/$abi/libmorse_wallet_core.a"
  done
  # Stage both architectures before replacing any installed archive.
  for abi in arm64-v8a x86_64; do
    destination_parent="$module_dir/native/android/$abi"
    for archive in "${artifacts[@]}"; do
      [[ -f "$temp_dir/android/$abi/$archive" && ! -L "$temp_dir/android/$abi/$archive" ]]
      destination="$destination_parent/$archive"
      if [[ -e "$destination" || -L "$destination" ]]; then [[ -f "$destination" && ! -L "$destination" ]]; fi
    done
  done
  for abi in arm64-v8a x86_64; do
    install_disclosures "$temp_dir/android/$abi/libmessenger_mobile.a" "android-$abi"
    for archive in "${artifacts[@]}"; do
      mv "$temp_dir/android/$abi/$archive" "$module_dir/native/android/$abi/$archive"
    done
  done
  install_wallet_header
}

[[ -x "$meshc_bin" ]] || { printf 'Mesh compiler not found at %s\n' "$meshc_bin" >&2; exit 1; }
check_bindings

case "$platform" in
  ios) build_ios ;;
  android) build_android ;;
  all)
    built=false
    if [[ "$(uname -s)" == Darwin ]]; then build_ios; built=true; fi
    if [[ -n "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then build_android; built=true; fi
    $built || { printf 'no mobile native toolchain is available\n' >&2; exit 1; }
    ;;
esac
