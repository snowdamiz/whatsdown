#!/usr/bin/env bash
set -euo pipefail
proof_dir="$(cd "$(dirname "$0")" && pwd -P)"
product_root="$(cd "$proof_dir/../../../../../.." && pwd -P)"
work="${MORSE_WALLET_IOS_PROOF_DIR:?set MORSE_WALLET_IOS_PROOF_DIR to a disposable output directory}"
archive="${MORSE_WALLET_IOS_ARCHIVE:-$product_root/packages/wallet-core/target/aarch64-apple-ios-sim/debug/libmorse_wallet_core.a}"
mkdir -p "$work/WalletProof.app"
sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
cat > "$work/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>application-identifier</key><string>app.morse.wallet.disposable-ios-proof</string><key>keychain-access-groups</key><array><string>app.morse.wallet.disposable-ios-proof</string></array><key>get-task-allow</key><true/></dict></plist>
PLIST
xcrun clang -target arm64-apple-ios16.4-simulator -isysroot "$sdk" -fobjc-arc -fmodules -Wall -Wextra -Werror \
  -I "$product_root/packages/wallet-core/include" "$proof_dir/ios.m" "$archive" \
  -Wl,-sectcreate,__TEXT,__entitlements,"$work/entitlements.plist" \
  -framework Foundation -framework Security -framework UIKit -o "$work/WalletProof.app/WalletProof"
cat > "$work/WalletProof.app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>WalletProof</string><key>CFBundleIdentifier</key><string>app.morse.wallet.disposable-ios-proof</string><key>CFBundleName</key><string>Wallet Proof</string><key>CFBundleVersion</key><string>1</string><key>CFBundleShortVersionString</key><string>1.0</string><key>CFBundlePackageType</key><string>APPL</string><key>LSRequiresIPhoneOS</key><true/><key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array><key>UILaunchScreen</key><dict/><key>UIApplicationSceneManifest</key><dict><key>UIApplicationSupportsMultipleScenes</key><false/></dict></dict></plist>
PLIST
codesign --force --sign - "$work/WalletProof.app" >/dev/null
xcrun simctl terminate "${MORSE_WALLET_IOS_SERIAL:-booted}" app.morse.wallet.disposable-ios-proof >/dev/null 2>&1 || true
xcrun simctl install "${MORSE_WALLET_IOS_SERIAL:-booted}" "$work/WalletProof.app"
xcrun simctl launch "${MORSE_WALLET_IOS_SERIAL:-booted}" app.morse.wallet.disposable-ios-proof
