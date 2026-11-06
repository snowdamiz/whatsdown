#!/usr/bin/env bash
set -euo pipefail
product_root="$(cd "$(dirname "$0")/.." && pwd -P)"
module="$product_root/apps/mobile/modules/mesh-messenger"
device="${MORSE_MAILBOX_IOS_DEVICE:-EC972953-AD12-4896-945A-5C5D2BD110D9}"
evidence="${MORSE_MAILBOX_EVIDENCE_DIR:-$product_root/../.morse/witness-proof}"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-mailbox-ios.XXXXXX")"
peer_pid=""
cleanup() {
  local result=$?
  if [[ -n "$peer_pid" ]]; then kill "$peer_pid" 2>/dev/null || true; wait "$peer_pid" 2>/dev/null || true; fi
  xcrun simctl terminate "$device" app.morse.mailbox.proof.ios >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
mkdir -p "$work/MailboxProof.app" "$evidence"
python3 - "$work/entitlements.plist" <<'PY'
import plistlib,sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(plistlib.dumps({'application-identifier':'MORSEPROOF.app.morse.mailbox.proof.ios','keychain-access-groups':['MORSEPROOF.app.morse.mailbox.proof.ios']}))
PY
sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
core="$module/native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a"
[[ -s "$core" ]]
printf '#include "libmessenger_mobile.h"\n#include "MeshMessengerSecureStore.h"\n' > "$work/bridge.h"
xcrun --sdk iphonesimulator clang -c -fobjc-arc -isysroot "$sdk" -target arm64-apple-ios16.4-simulator \
  -I "$module/generated" "$module/ios/MeshMessengerSecureStore.m" -o "$work/host.o"
xcrun --sdk iphonesimulator swiftc -parse-as-library -sdk "$sdk" -target arm64-apple-ios16.4-simulator \
  -I "$module/generated" -I "$module/ios" -import-objc-header "$work/bridge.h" \
  "$module/generated/libmessenger_mobile.swift" "$module/ios/mailbox-proof/MailboxProof.swift" \
  "$work/host.o" "$core" -framework Foundation -framework UIKit -framework Security -framework CoreFoundation \
  -lc++ -lresolv -lz -lm -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __entitlements -Xlinker "$work/entitlements.plist" -o "$work/MailboxProof.app/MailboxProof"
python3 - "$work" <<'PY'
from pathlib import Path
import plistlib,sys
work=Path(sys.argv[1])
info={'CFBundleExecutable':'MailboxProof','CFBundleIdentifier':'app.morse.mailbox.proof.ios','CFBundleName':'MailboxProof','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','CFBundlePackageType':'APPL','MinimumOSVersion':'16.4','UIDeviceFamily':[1], 'LSRequiresIPhoneOS':True,'UIApplicationSupportsIndirectInputEvents':True,
'MeshMessengerNetworkConfig':'1\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:19975/v1/mailbox/stream'}
(work/'MailboxProof.app/Info.plist').write_bytes(plistlib.dumps(info))
(work/'entitlements.plist').write_bytes(plistlib.dumps({'application-identifier':'MORSEPROOF.app.morse.mailbox.proof.ios','keychain-access-groups':['MORSEPROOF.app.morse.mailbox.proof.ios']}))
PY
codesign --force --sign - "$work/MailboxProof.app"
xcrun simctl boot "$device" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$device" -b
xcrun simctl uninstall "$device" app.morse.mailbox.proof.ios >/dev/null 2>&1 || true
xcrun simctl install "$device" "$work/MailboxProof.app"
xcrun simctl launch "$device" app.morse.mailbox.proof.ios
container="$(xcrun simctl get_app_container "$device" app.morse.mailbox.proof.ios data)"
for attempt in $(seq 1 600); do
  [[ ! -s "$container/Documents/profile-entry.hex" ]] || break
  if [[ -f "$container/Documents/result.json" ]]; then cat "$container/Documents/result.json"; exit 1; fi
  sleep 0.1
done
[[ -s "$container/Documents/profile-entry.hex" ]]
node "$product_root/scripts/mailbox-proof-keys.mjs" "$container/Documents/profile-entry.hex" "$work/keys.json" 19975
node "$product_root/scripts/mailbox-proof-peer.mjs" "$work/keys.json" "$work/peer-ready" "$evidence/phase6-mailbox-ios-peer.json" &
peer_pid=$!
for attempt in $(seq 1 100); do [[ ! -f "$work/peer-ready" ]] || break; sleep 0.1; done
[[ -f "$work/peer-ready" ]]
touch "$container/Documents/server-ready"
for attempt in $(seq 1 600); do [[ ! -f "$container/Documents/result.json" ]] || break; sleep 0.1; done
cp "$container/Documents/result.json" "$evidence/phase6-mailbox-ios-native.json"
cat "$evidence/phase6-mailbox-ios-native.json"
kill "$peer_pid"; wait "$peer_pid"; peer_pid=""
python3 - "$evidence/phase6-mailbox-ios-native.json" "$evidence/phase6-mailbox-ios-peer.json" <<'PY'
import json,sys
result=json.load(open(sys.argv[1]));assert result['result']=='passed',result
peer=json.load(open(sys.argv[2]));assert peer['accepted']==3 and peer['rejected']==0,peer
print('three iOS Simulator native sessions independently signature-verified by the owned loopback peer')
PY
