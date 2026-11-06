#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "$0")/.." && pwd -P)"
module="$product/apps/mobile/modules/mesh-messenger"
proof="$module/tests/rpc-tls"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-rpc-tls-host.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/Proof.app/Contents/MacOS"
xcrun clang -fobjc-arc -Wall -Wextra -Werror -framework Foundation -framework Security \
  -I "$module/ios" -I "$module/generated" "$module/ios/MeshMessengerSecureStore.m" "$proof/HostProof.m" \
  -o "$work/Proof.app/Contents/MacOS/Proof"
python3 - "$work/Proof.app" <<'PY'
from pathlib import Path
import base64, plistlib, subprocess, sys

app = Path(sys.argv[1])
missing = object()
maximum = bytes((index * 31 + 17) % 256 for index in range(82002))
b64 = lambda value: base64.b64encode(value).decode()
cases = [
    ('absent', missing, 0, 82002), ('absent-exact-capacity', missing, 0, 2),
    ('absent-short-capacity', missing, 4, 1), ('absent-zero-capacity', missing, 4, 0),
    ('opaque', b64(b'\xfe\xdc'), 0, 2), ('present', b64(b'\x01\x02\x03'), 0, 82002),
    ('maximum', b64(maximum), 0, 82002), ('maximum-short-capacity', b64(maximum), 4, 82001),
    ('empty', '', 3, 82002), ('one-byte', b64(b'\x01'), 3, 82002),
    ('oversized-bytes', b64(maximum + b'x'), 3, 82002),
    ('oversized-base64', 'A' * 109337, 3, 82002),
    ('invalid-base64', 'bad-base64!', 3, 82002), ('missing-padding', 'AQA', 3, 82002),
    ('extra-padding', 'AQA==', 3, 82002), ('pad-bits', 'AQB=', 3, 82002),
    ('whitespace', 'AQ A=', 3, 82002), ('newline', 'AQA=\n', 3, 82002),
    ('unicode', '\u00e9', 3, 82002), ('number', 42, 3, 82002),
    ('array', ['AQA='], 3, 82002), ('dictionary', {'value': 'AQA='}, 3, 82002),
    ('data', b'\x01\x00', 3, 82002), ('read-error', b64(b'\x01\x00'), 3, 82002),
]
for name, value, status, capacity in cases:
    data = {'CFBundleIdentifier': 'app.morse.rpc-tls-proof', 'CFBundleExecutable': 'Proof'}
    if value is not missing:
        data['MeshMessengerRpcTLSRoots'] = value
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(data))
    subprocess.run([str(app / 'Contents/MacOS/Proof'), str(status), str(capacity), name], check=True)
print(f'{len(cases)} Apple RPC callback cases passed against production Objective-C')
PY

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
# Reuse an installed compiler. Never resolve dependencies or change the toolchain.
kotlin_lib="${KOTLIN_LIB_DIR:-/opt/homebrew/opt/gradle/libexec/lib}"
compiler_cp="$(python3 - "$kotlin_lib" <<'PY'
from pathlib import Path
import os, sys
root = Path(sys.argv[1])
jars = sorted(root.glob('*.jar'))
if not any(p.name.startswith('kotlin-compiler-embeddable-') for p in jars):
    raise SystemExit('No local Kotlin compiler; set KOTLIN_LIB_DIR to an installed Gradle lib directory')
print(os.pathsep.join(map(str, jars)))
PY
)"
# Compile the complete, unmodified production Host/PushMaterial objects. The rest
# of Module.kt depends on Expo/React; only Android resource APIs are stubbed here.
python3 - "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt" "$work/PushMaterial.kt" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
start = source.index('internal object MeshMessengerHost {')
Path(sys.argv[2]).write_text('package expo.modules.meshmessenger\nimport java.nio.ByteBuffer\n' + source[start:])
PY
java -cp "$compiler_cp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 1.8 -classpath "$compiler_cp" -d "$work/classes" \
  "$work/PushMaterial.kt" \
  "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerIssuerTLS.kt" \
  "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerRpcTLS.kt" \
  "$proof"/*.kt
xcrun clang++ -std=c++17 -Wall -Wextra -Werror -shared -fPIC -pthread \
  -I "$JAVA_HOME/include" -I "$JAVA_HOME/include/darwin" -I "$module/generated" \
  "$module/android/src/main/cpp/MeshMessengerHost.cpp" "$proof/HostProof.cpp" \
  -o "$work/libRpcTLSHostProof.dylib"
for mode in reader absent present maximum empty truncated oversized list-error list-null open-error directory read-error close-error bridge-bounds; do
  java --enable-native-access=ALL-UNNAMED -cp "$work/classes:$compiler_cp" \
    expo.modules.meshmessenger.HostProofKt "$work/libRpcTLSHostProof.dylib" "$mode"
done
echo 'Local Objective-C/JVM/JNI byte plumbing passed; phone apps and TLS behavior are not qualified.'
