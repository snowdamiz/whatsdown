#!/usr/bin/env bash
set -euo pipefail
product="$(cd "$(dirname "$0")/.." && pwd -P)"
module="$product/apps/mobile/modules/mesh-messenger"
proof="$module/tests/issuer-tls"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-issuer-tls-host.XXXXXX")"
trap 'rm -rf "$work"' EXIT
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
cache="$HOME/.gradle/caches/modules-2/files-2.1"
jar_one() { find "$cache/$1" -name '*.jar' -type f | head -1; }
compiler="$(jar_one org.jetbrains.kotlin/kotlin-compiler-embeddable/2.1.20)"
stdlib="$(jar_one org.jetbrains.kotlin/kotlin-stdlib/2.1.20)"
daemon="$(jar_one org.jetbrains.kotlin/kotlin-daemon-embeddable/2.1.20)"
coroutines="$(jar_one org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.1)"
annotations="$(jar_one org.jetbrains/annotations/13.0)"
trove="$(jar_one org.jetbrains.intellij.deps/trove4j)"
java -cp "$compiler:$stdlib:$daemon:$coroutines:$annotations:$trove" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 1.8 -classpath "$stdlib:$annotations" -d "$work/classes" \
  "$module/android/src/main/java/expo/modules/meshmessenger/MeshMessengerIssuerTLS.kt" "$proof/HostProof.kt"
java -cp "$work/classes:$stdlib" expo.modules.meshmessenger.HostProofKt
mkdir -p "$work/Proof.app/Contents/MacOS"
xcrun clang -fobjc-arc -Wall -Wextra -Werror -framework Foundation -framework Security \
  -I "$module/ios" -I "$module/generated" "$module/ios/MeshMessengerSecureStore.m" "$proof/HostProof.m" \
  -o "$work/Proof.app/Contents/MacOS/Proof"
python3 - "$work/Proof.app" <<'PY'
from pathlib import Path
import base64,plistlib,subprocess,sys
app=Path(sys.argv[1]); exe=app/'Contents/MacOS/Proof'; missing=object()
maximum=b'\1'+b'\0'*67590
cases=[(missing,0,67591),(base64.b64encode(b'\1'+b'\0'*6).decode(),0,7),
       (base64.b64encode(maximum).decode(),0,67591),
       ('bad-base64!',3,67591),(42,3,67591),('A'*90125,3,67591),
       (base64.b64encode(b'123456').decode(),3,67591),
       (base64.b64encode(b'\1'+b'\0'*6).decode(),4,6)]
for value,code,capacity in cases:
    data={'CFBundleIdentifier':'app.morse.issuer-tls-proof','CFBundleExecutable':'Proof'}
    if value is not missing:data['MeshMessengerIssuerTLSRoot']=value
    (app/'Contents/Info.plist').write_bytes(plistlib.dumps(data))
    subprocess.run([str(exe),str(code),str(capacity)],check=True)
print('8 Apple callback cases passed against exact production source')
PY
