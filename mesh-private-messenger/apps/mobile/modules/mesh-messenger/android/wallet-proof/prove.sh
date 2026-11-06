#!/usr/bin/env bash
set -euo pipefail
proof_dir="$(cd "$(dirname "$0")" && pwd)"
product_root="$(cd "$proof_dir/../../../../../.." && pwd)"
android_sdk="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
android_ndk="${ANDROID_NDK_HOME:-$android_sdk/ndk/28.2.13676358}"
java_home="${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
wallet_archive="${MORSE_WALLET_ANDROID_ARCHIVE:?set MORSE_WALLET_ANDROID_ARCHIVE to the real arm64 wallet SDK staticlib}"
serial="${MORSE_WALLET_ANDROID_SERIAL:-emulator-5554}"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-wallet-android.XXXXXX")"
trap 'rm -rf "$work"' EXIT
export JAVA_HOME="$java_home"
export PATH="$java_home/bin:$PATH"
android_jar="$android_sdk/platforms/${MORSE_WALLET_ANDROID_PLATFORM:-android-36}/android.jar"
build_tools="$android_sdk/build-tools/${MORSE_WALLET_ANDROID_BUILD_TOOLS:-36.0.0}"
cache="$HOME/.gradle/caches/modules-2/files-2.1"
jar_one() { find "$cache/$1" -name '*.jar' -type f | head -1; }
compiler="$(jar_one org.jetbrains.kotlin/kotlin-compiler-embeddable/2.1.20)"
stdlib="$(jar_one org.jetbrains.kotlin/kotlin-stdlib/2.1.20)"
daemon="$(jar_one org.jetbrains.kotlin/kotlin-daemon-embeddable/2.1.20)"
coroutines="$(jar_one org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.1)"
annotations="$(jar_one org.jetbrains/annotations/13.0)"
trove="$(jar_one org.jetbrains.intellij.deps/trove4j)"
mkdir -p "$work/classes" "$work/dex" "$work/lib/arm64-v8a"
java -cp "$compiler:$stdlib:$daemon:$coroutines:$annotations:$trove" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 1.8 -classpath "$android_jar:$android_sdk/platforms/${MORSE_WALLET_ANDROID_PLATFORM:-android-36}/optional/android.test.runner.jar:$android_sdk/platforms/${MORSE_WALLET_ANDROID_PLATFORM:-android-36}/optional/android.test.base.jar:$stdlib:$annotations" \
  -d "$work/classes" "$proof_dir/../src/main/java/expo/modules/meshmessenger/MeshMessengerWalletStore.kt" "$proof_dir/WalletProof.kt"
"$android_ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang++" -std=c++17 -static-libstdc++ -shared -fPIC \
  -I "$product_root/packages/wallet-core/include" "$proof_dir/../src/main/cpp/MeshMessengerWalletHost.cpp" \
  "$wallet_archive" -Wl,--exclude-libs,ALL -llog -landroid -ldl -lm -o "$work/lib/arm64-v8a/libwallet_proof.so"
jar cf "$work/proof.jar" -C "$work/classes" .
"$build_tools/d8" --min-api 26 --lib "$android_jar" --output "$work/dex" "$work/proof.jar" "$stdlib"
"$build_tools/aapt2" link -I "$android_jar" --manifest "$proof_dir/AndroidManifest.xml" -o "$work/proof.apk"
cp "$work/dex/classes.dex" "$work/classes.dex"
(cd "$work" && zip -q proof.apk classes.dex lib/arm64-v8a/libwallet_proof.so)
keytool -genkeypair -keystore "$work/test-key.p12" -storepass android -keypass android -alias proof -dname CN=MorseWalletProof -keyalg RSA -validity 1 >/dev/null 2>&1
"$build_tools/apksigner" sign --ks "$work/test-key.p12" --ks-pass pass:android "$work/proof.apk"
adb="$android_sdk/platform-tools/adb"
# This explicitly named disposable proof package is never the Morse app.
"$adb" -s "$serial" uninstall app.morse.wallet.proof >/dev/null 2>&1 || true
"$adb" -s "$serial" install "$work/proof.apk"
"$adb" -s "$serial" shell am instrument -w -e class expo.modules.meshmessenger.WalletProofTest#testNativeCustodyAndExplicitForegroundConfirmation app.morse.wallet.proof/android.test.InstrumentationTestRunner | tee "$work/result.log"
grep -q 'OK (1 test)' "$work/result.log"
