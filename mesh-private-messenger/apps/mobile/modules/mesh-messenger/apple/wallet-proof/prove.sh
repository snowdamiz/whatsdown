#!/usr/bin/env bash
set -euo pipefail
proof_dir="$(cd "$(dirname "$0")" && pwd -P)"
product_root="$(cd "$proof_dir/../../../../../.." && pwd -P)"
archive="${MORSE_WALLET_HOST_ARCHIVE:-$product_root/packages/wallet-core/target/debug/libmorse_wallet_core.a}"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-wallet-apple.XXXXXX")"
trap 'rm -rf "$work"' EXIT
xcrun clang -fobjc-arc -fmodules -Wall -Wextra -Werror \
  -I "$product_root/packages/wallet-core/include" "$proof_dir/store.m" "$archive" \
  -framework Foundation -framework Security -framework AppKit -o "$work/store-proof"
"$work/store-proof"

if [[ "${MORSE_WALLET_UI_PROOF:-0}" != 1 ]]; then exit 0; fi

xcrun clang -fobjc-arc -fmodules -Wall -Wextra -Werror \
  -I "$product_root/packages/wallet-core/include" "$proof_dir/ui.m" "$archive" \
  -framework Foundation -framework Security -framework AppKit -o "$work/ui-proof"
mkdir -p "$work/MorseWalletProof.app/Contents/MacOS"
cp "$work/ui-proof" "$work/MorseWalletProof.app/Contents/MacOS/WalletProof"
cat > "$work/MorseWalletProof.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>WalletProof</string><key>CFBundleIdentifier</key><string>app.morse.wallet.disposable-ui-proof</string><key>CFBundleName</key><string>Morse Wallet Proof</string><key>CFBundlePackageType</key><string>APPL</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --sign - "$work/MorseWalletProof.app" >/dev/null
open -W -n --stdout "$work/ui.log" --stderr "$work/ui.err" "$work/MorseWalletProof.app"
cat "$work/ui.log" "$work/ui.err"
grep -q 'Apple native UI proof passed:' "$work/ui.log"
