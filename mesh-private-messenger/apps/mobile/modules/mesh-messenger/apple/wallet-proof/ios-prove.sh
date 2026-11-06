#!/usr/bin/env bash
set -euo pipefail
proof_dir="$(cd "$(dirname "$0")" && pwd -P)"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-wallet-ios.XXXXXX")"
serial="${MORSE_WALLET_IOS_SERIAL:-}"
if [[ -z "$serial" ]]; then
  serial="$(xcrun simctl list devices booted --json | python3 -c 'import json,sys; d=json.load(sys.stdin); ids=[v["udid"] for k,values in d["devices"].items() if "iOS" in k for v in values if v["state"]=="Booted"]; assert len(ids)==1,"Select MORSE_WALLET_IOS_SERIAL when there is not exactly one booted iOS simulator"; print(ids[0])')"
fi
cleanup() {
  local status=$?
  if [[ $status == 0 ]]; then
    # Only these explicitly disposable proof bundles are removed.
    xcrun simctl uninstall "$serial" app.morse.wallet.disposable-ios-proof >/dev/null 2>&1 || true
    xcrun simctl uninstall "$serial" app.morse.wallet.disposable-ios-proof-uitests.xctrunner >/dev/null 2>&1 || true
    rm -rf "$work"
  else
    printf 'Failed proof artifacts retained at %s\n' "$work" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
export MORSE_WALLET_IOS_PROOF_DIR="$work"
export MORSE_WALLET_IOS_SERIAL="$serial"
# The build step creates the canonical app plist and simulated entitlements.
# Xcode's debug dylib is disabled so those entitlements live in the executable.
"$proof_dir/ios-build.sh"
ruby "$proof_dir/ios-project.rb"
xcodebuild test -project "$work/WalletProof.xcodeproj" -scheme WalletProof -configuration Debug \
  -destination "platform=iOS Simulator,id=$serial" -derivedDataPath "$work/derived" \
  CODE_SIGNING_ALLOWED=NO
