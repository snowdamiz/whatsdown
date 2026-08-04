#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly app_dir="$repo_root/mesh-private-messenger/apps/mobile"
readonly messenger_module_dir="$app_dir/modules/mesh-messenger"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/whatsdown-m11.XXXXXX")"
readonly temp_dir

fail() {
  printf 'M11 proof failed: %s\n' "$*" >&2
  return 1
}

cleanup() {
  local status=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    if resolved_parent="$(cd "$temp_parent" && pwd -P)" &&
      resolved_temp="$(cd "$temp_dir" && pwd -P)"; then
      case "$resolved_temp" in
        "$resolved_parent"/whatsdown-m11.*)
          if [[ "$(/usr/bin/find "$resolved_temp" -type l -print -quit)" == '' ]]; then
            /usr/bin/find "$resolved_temp" -depth -delete
          fi
          ;;
      esac
    fi
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

main() {
  [[ -d "$app_dir/node_modules" ]] || fail "run npm ci in $app_dir"
  node "$app_dir/scripts/harden-expo-notifications-autolinking.mjs" --check
  local platform
  local resolution
  for platform in apple android; do
    resolution="$temp_dir/autolinking-$platform.json"
    (cd "$app_dir" && ./node_modules/.bin/expo-modules-autolinking resolve --platform "$platform" --json) >"$resolution"
  done
  node - "$temp_dir/autolinking-apple.json" "$temp_dir/autolinking-android.json" <<'NODE'
const { readFileSync } = require('node:fs');

const [applePath, androidPath] = process.argv.slice(2);
const apple = JSON.parse(readFileSync(applePath, 'utf8'));
const android = JSON.parse(readFileSync(androidPath, 'utf8'));
const appleNotifications = apple.modules.find((module) => module.packageName === 'expo-notifications');
const androidNotifications = android.modules.find((module) => module.packageName === 'expo-notifications');
const appleSentinels = apple.modules.flatMap((module) =>
  module.modules
    .filter((candidate) => candidate.class === 'ExpoPushTokenManagerSentinelModule')
    .map(() => module.packageName),
);
const androidSentinels = android.modules.flatMap((module) =>
  module.projects.flatMap((project) =>
    project.modules
      .filter(
        (candidate) =>
          candidate.classifier ===
          'expo.modules.meshmessenger.ExpoPushTokenManagerSentinelModule',
      )
      .map(() => module.packageName),
  ),
);

if (!appleNotifications || !androidNotifications) {
  throw new Error('expo-notifications was absent from Expo autolinking resolution');
}
if (appleSentinels.length !== 1 || appleSentinels[0] !== 'mesh-messenger') {
  throw new Error('Apple ExpoPushTokenManager sentinel was not autolinked exactly once locally');
}
if (androidSentinels.length !== 1 || androidSentinels[0] !== 'mesh-messenger') {
  throw new Error('Android ExpoPushTokenManager sentinel was not autolinked exactly once locally');
}
if (appleNotifications.modules.some((module) => module.class === 'PushTokenModule')) {
  throw new Error('Apple PushTokenModule remains in Expo autolinking resolution');
}
if (
  androidNotifications.projects.some((project) =>
    project.modules.some(
      (module) => module.classifier === 'expo.modules.notifications.tokens.PushTokenModule',
    ),
  )
) {
  throw new Error('Android PushTokenModule remains in Expo autolinking resolution');
}
NODE
  if rg -n '\b(AsyncFunction|Function|OnCreate|OnDestroy)\b|getDevicePushTokenAsync|unregister|sendEvent' \
    "$messenger_module_dir/ios/ExpoPushTokenManagerSentinelModule.swift" \
    "$messenger_module_dir/android/src/main/java/expo/modules/meshmessenger/ExpoPushTokenManagerSentinelModule.kt" \
    >/dev/null; then
    fail "the ExpoPushTokenManager sentinel exposes a raw-token method or emits token events"
  fi
  if rg -n '\b(getDevicePushTokenAsync|getExpoPushTokenAsync|devicePushToken|expoPushToken|ExpoPushTokenManager)\b' \
    "$app_dir/src" "$messenger_module_dir/index.ts" \
    "$messenger_module_dir/generated/libmessenger_mobile.ts" >/dev/null; then
    fail "a raw or provider push token crossed the TypeScript boundary"
  fi
  if rg -n '\b(MESSENGER_EXPO_PROJECT_ID|MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX|MeshMessengerExpoProjectID|MeshMessengerPushBrokerPublicKeyHex|brokerPublicKey)\b|expo/config/v1' \
    "$app_dir/src" "$messenger_module_dir/index.ts" \
    "$messenger_module_dir/generated/libmessenger_mobile.ts" >/dev/null; then
    fail "signed-native push configuration crossed or was selected by the TypeScript runtime"
  fi
  if rg -n 'EXPO_PUBLIC_MESSENGER_(EXPO_PROJECT_ID|PUSH_BROKER_PUBLIC_KEY_HEX)' \
    "$app_dir" -g '!node_modules/**' >/dev/null; then
    fail "push trust pins were exposed as Expo public environment variables"
  fi
  if rg -n '\bpush_action_export\b|mesh_messenger_push_action([^_[:alnum:]]|$)' \
    "$messenger_module_dir" >/dev/null; then
    fail "the unused direct push-action poll crossed the native/JavaScript ABI"
  fi
  "$script_dir/prove-m10.sh"
  npm --prefix "$app_dir" test
  npm --prefix "$app_dir" run typecheck
  (cd "$app_dir" && npx expo-doctor)
  (cd "$app_dir" && npx expo export --platform ios --output-dir "$temp_dir/export")
  [[ "$(find "$temp_dir/export/assets" -type f | wc -l | tr -d ' ')" == 3 ]] || \
    fail "the mobile bundle did not contain exactly the three selected fonts"
  if rg -n '\buseMemo\b' "$app_dir/src" >/dev/null; then
    fail "the React compiler anti-pattern useMemo was introduced"
  fi
  printf 'M11 software proof passed: encrypted restart flow, app parsers, strict generic push, raw-token autolinking exclusion, typecheck, Expo diagnostics, and iOS bundle.\n'
}

main "$@"
