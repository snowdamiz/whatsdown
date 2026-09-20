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
  local destination_parent="$module_dir/native/ios"
  local destination="$destination_parent/MeshMessengerCore.xcframework"
  local device="$temp_dir/device/libmessenger_mobile.a"
  local simulator="$temp_dir/simulator/libmessenger_mobile.a"

  [[ "$(uname -s)" == Darwin ]] || { printf 'iOS builds require macOS\n' >&2; return 1; }
  command -v xcodebuild >/dev/null
  mkdir -p "$destination_parent"
  require_physical_directory "$destination_parent"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" ]]
    [[ "$(find "$destination" -type l | wc -l | tr -d ' ')" == 0 ]]
    find "$destination" -depth -delete
  fi
  mkdir -p "$(dirname "$device")" "$(dirname "$simulator")"
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
