#!/usr/bin/env bash
set -euo pipefail

readonly platform="${1:-all}"
case "$platform" in
  all|ios|android) ;;
  *) printf 'usage: %s [all|ios|android]\n' "$0" >&2; exit 2 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly core_dir="$repo_root/mesh-private-messenger/packages/mobile-core"
readonly module_dir="$repo_root/mesh-private-messenger/apps/mobile/modules/mesh-messenger"
readonly meshc_bin="${MESHC:-$repo_root/mesh-lang/target/debug/meshc}"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-mobile-native.XXXXXX")"
readonly temp_dir

cleanup() {
  local status=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    resolved_parent="$(realpath "$temp_parent")"
    resolved_temp="$(realpath "$temp_dir")"
    case "$resolved_temp" in
      "$resolved_parent"/whatsdown-mobile-native.*)
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

check_bindings() {
  local extension
  "$meshc_bin" build "$core_dir" --artifact staticlib \
    --output "$temp_dir/libmessenger_mobile.a"
  for extension in h swift kt jni.c ts; do
    cmp "$temp_dir/libmessenger_mobile.$extension" \
      "$module_dir/generated/libmessenger_mobile.$extension" >/dev/null || {
        printf 'generated %s binding is stale; rebuild it with the current Mesh compiler\n' \
          "$extension" >&2
        return 1
      }
  done
}

build_ios() {
  local destination="$module_dir/native/ios/MeshMessengerCore.xcframework"
  local device="$temp_dir/libmessenger_mobile_ios.a"
  local simulator="$temp_dir/libmessenger_mobile_ios_sim.a"
  local resolved_destination

  [[ "$(uname -s)" == Darwin ]] || { printf 'iOS builds require macOS\n' >&2; return 1; }
  command -v xcodebuild >/dev/null
  if [[ -e "$destination" ]]; then
    resolved_destination="$(realpath "$destination")"
    [[ "$resolved_destination" == "$destination" ]]
    [[ -d "$resolved_destination" && ! -L "$resolved_destination" ]]
    [[ "$(find "$resolved_destination" -type l | wc -l | tr -d ' ')" == 0 ]]
    find "$resolved_destination" -depth -delete
  fi
  mkdir -p "$(dirname "$destination")"
  IPHONEOS_DEPLOYMENT_TARGET=16.4 "$meshc_bin" build "$core_dir" \
    --artifact staticlib --target aarch64-apple-ios --output "$device"
  IPHONEOS_DEPLOYMENT_TARGET=16.4 "$meshc_bin" build "$core_dir" \
    --artifact staticlib --target aarch64-apple-ios-sim --output "$simulator"
  mkdir "$temp_dir/headers"
  cp "$module_dir/generated/libmessenger_mobile.h" "$temp_dir/headers/"
  xcodebuild -create-xcframework \
    -library "$device" -headers "$temp_dir/headers" \
    -library "$simulator" -headers "$temp_dir/headers" \
    -output "$destination"
}

build_android() {
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  local target
  local abi
  local destination
  local destination_parent
  local resolved_destination
  local resolved_parent

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
    resolved_parent="$(realpath "$destination_parent")"
    [[ "$resolved_parent" == "$destination_parent" ]]
    [[ -d "$resolved_parent" && ! -L "$resolved_parent" ]]
    if [[ -e "$destination" ]]; then
      resolved_destination="$(realpath "$destination")"
      [[ "$resolved_destination" == "$destination" ]]
      [[ -f "$resolved_destination" && ! -L "$resolved_destination" ]]
    fi
    ANDROID_NDK_HOME="$ndk" "$meshc_bin" build "$core_dir" \
      --artifact staticlib --target "$target" --output "$destination"
  done
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
