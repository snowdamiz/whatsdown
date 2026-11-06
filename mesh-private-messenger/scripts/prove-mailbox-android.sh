#!/usr/bin/env bash
set -euo pipefail
product_root="$(cd "$(dirname "$0")/.." && pwd -P)"
module="$product_root/apps/mobile/modules/mesh-messenger"
proof="$module/android/mailbox-proof"
sdk="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
java_home="${JAVA_HOME:-/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home}"
serial="${MORSE_MAILBOX_ANDROID_SERIAL:-emulator-5554}"
evidence="${MORSE_MAILBOX_EVIDENCE_DIR:-$product_root/../.morse/witness-proof}"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-mailbox-android.XXXXXX")"
peer_pid=""
instrument_pid=""
cleanup() {
  local result=$?
  if [[ -n "$peer_pid" ]]; then kill "$peer_pid" 2>/dev/null || true; wait "$peer_pid" 2>/dev/null || true; fi
  if [[ -n "$instrument_pid" ]]; then kill "$instrument_pid" 2>/dev/null || true; fi
  if [[ -n "${adb:-}" ]]; then "$adb" -s "$serial" reverse --remove tcp:19974 >/dev/null 2>&1 || true; fi
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
export JAVA_HOME="$java_home" PATH="$java_home/bin:$PATH"
mkdir -p "$work/classes" "$work/dex" "$work/lib/arm64-v8a" "$evidence"
cache="$HOME/.gradle/caches/modules-2/files-2.1"
jar_one() { find "$cache/$1" -name '*.jar' -type f | head -1; }
compiler="$(jar_one org.jetbrains.kotlin/kotlin-compiler-embeddable/2.1.20)"
stdlib="$(jar_one org.jetbrains.kotlin/kotlin-stdlib/2.1.20)"
daemon="$(jar_one org.jetbrains.kotlin/kotlin-daemon-embeddable/2.1.20)"
coroutines="$(jar_one org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.1)"
annotations="$(jar_one org.jetbrains/annotations/13.0)"
trove="$(jar_one org.jetbrains.intellij.deps/trove4j)"
android_jar="$sdk/platforms/android-36/android.jar"
tools="$sdk/build-tools/36.0.0"
adb="$sdk/platform-tools/adb"
python3 - "$module" "$work" <<'PY'
from pathlib import Path
import shutil,sys
module,work=map(Path,sys.argv[1:])
source=(module/'android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt').read_text()
# Compile the exact production callback objects without the Expo UI module.
objects=source[source.index('internal object MeshMessengerHost {'):]
(work/'HostObjects.kt').write_text('package expo.modules.meshmessenger\nimport java.nio.ByteBuffer\n'+objects)
libraries=list((module/'android/build').rglob('arm64-v8a/libmessenger_mobile.so'))
assert libraries,'build the real app native module first'
shutil.copyfile(max(libraries,key=lambda p:p.stat().st_mtime),work/'lib/arm64-v8a/libmessenger_mobile.so')
PY
java -cp "$compiler:$stdlib:$daemon:$coroutines:$annotations:$trove" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 1.8 -classpath "$android_jar:$sdk/platforms/android-36/optional/android.test.runner.jar:$sdk/platforms/android-36/optional/android.test.base.jar:$stdlib:$annotations" \
  -d "$work/classes" "$module/generated/libmessenger_mobile.kt" \
  "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerSecureStore.kt" "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerIssuerTLS.kt" "$work/HostObjects.kt" "$proof/MailboxProof.kt"
jar cf "$work/proof.jar" -C "$work/classes" .
"$tools/d8" --min-api 26 --lib "$android_jar" --output "$work/dex" "$work/proof.jar" "$stdlib"
"$tools/aapt2" link -I "$android_jar" --manifest "$proof/AndroidManifest.xml" -o "$work/proof.apk"
cp "$work/dex/classes.dex" "$work/classes.dex"
(cd "$work" && zip -q proof.apk classes.dex lib/arm64-v8a/libmessenger_mobile.so)
keytool -genkeypair -keystore "$work/test-key.p12" -storepass android -keypass android -alias proof -dname CN=MorseMailboxProof -keyalg RSA -validity 1 >/dev/null 2>&1
"$tools/apksigner" sign --ks "$work/test-key.p12" --ks-pass pass:android "$work/proof.apk"
"$adb" -s "$serial" uninstall app.morse.mailbox.proof >/dev/null 2>&1 || true
"$adb" -s "$serial" install "$work/proof.apk"
"$adb" -s "$serial" reverse tcp:19974 tcp:19974
"$adb" -s "$serial" shell am instrument -w -e class expo.modules.meshmessenger.MailboxProofTest#testSignedNativeMailboxSession \
  app.morse.mailbox.proof/android.test.InstrumentationTestRunner > "$evidence/phase6-mailbox-android-instrumentation.log" 2>&1 &
instrument_pid=$!
for attempt in $(seq 1 600); do
  "$adb" -s "$serial" exec-out run-as app.morse.mailbox.proof cat files/profile-entry.hex > "$work/entry.hex" 2>/dev/null || true
  if node -e 'const s=require("fs").readFileSync(process.argv[1],"utf8");process.exit(/^(?:[0-9a-f]{2})+$/.test(s)?0:1)' "$work/entry.hex"; then break; fi
  sleep 0.1
done
[[ -s "$work/entry.hex" ]]
node "$product_root/scripts/mailbox-proof-keys.mjs" "$work/entry.hex" "$work/keys.json" 19974
node "$product_root/scripts/mailbox-proof-peer.mjs" "$work/keys.json" "$work/peer-ready" "$evidence/phase6-mailbox-android-peer.json" &
peer_pid=$!
for attempt in $(seq 1 100); do [[ ! -f "$work/peer-ready" ]] || break; sleep 0.1; done
[[ -f "$work/peer-ready" ]]
"$adb" -s "$serial" shell run-as app.morse.mailbox.proof touch files/server-ready
wait "$instrument_pid"
instrument_pid=""
cat "$evidence/phase6-mailbox-android-instrumentation.log"
grep -q 'OK (1 test)' "$evidence/phase6-mailbox-android-instrumentation.log"
"$adb" -s "$serial" exec-out run-as app.morse.mailbox.proof cat files/result.json > "$evidence/phase6-mailbox-android-native.json"
kill "$peer_pid"; wait "$peer_pid"; peer_pid=""
python3 - "$evidence/phase6-mailbox-android-peer.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]));assert value['accepted']==3 and value['rejected']==0,value
print('three Android native sessions independently signature-verified by the owned loopback peer')
PY
