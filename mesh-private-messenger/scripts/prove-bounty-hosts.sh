#!/usr/bin/env bash
set -euo pipefail
product_root="$(cd "$(dirname "$0")/.." && pwd)"
proof_log="${MORSE_BOUNTY_HOST_LOG_DIR:-$product_root/../.morse/witness-proof}"
work="$(mktemp -d "${TMPDIR:-/tmp}/morse-bounty-hosts.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$proof_log" "$work/kotlin"
rustc --edition=2021 --test "$product_root/apps/desktop/src-tauri/src/bounty.rs" -o "$work/rust"
"$work/rust" > "$proof_log/bounty-host-rust.log" 2>&1
swiftc "$product_root/apps/mobile/modules/mesh-messenger/ios/MeshMessengerBountyBridge.swift" "$product_root/apps/mobile/modules/mesh-messenger/ios/bounty-proof/Proof.swift" -o "$work/swift"
"$work/swift" > "$proof_log/bounty-host-swift.log" 2>&1
cache="$HOME/.gradle/caches/modules-2/files-2.1"
jar_one() { rg --files "$cache/$1" -g '*.jar' | head -1; }
compiler="$(jar_one org.jetbrains.kotlin/kotlin-compiler-embeddable/2.1.20)"
stdlib="$(jar_one org.jetbrains.kotlin/kotlin-stdlib/2.1.20)"
daemon="$(jar_one org.jetbrains.kotlin/kotlin-daemon-embeddable/2.1.20)"
coroutines="$(jar_one org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.1)"
annotations="$(jar_one org.jetbrains/annotations/13.0)"
trove="$(jar_one org.jetbrains.intellij.deps/trove4j)"
java_home="${JAVA_HOME:-/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home}"
"$java_home/bin/java" -cp "$compiler:$stdlib:$daemon:$coroutines:$annotations:$trove" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -jvm-target 1.8 -classpath "$stdlib:$annotations" -d "$work/kotlin" "$product_root/apps/mobile/modules/mesh-messenger/android/src/main/java/expo/modules/meshmessenger/MeshMessengerBountyBridge.kt" "$product_root/apps/mobile/modules/mesh-messenger/android/bounty-proof/Proof.kt"
"$java_home/bin/java" -cp "$work/kotlin:$stdlib" expo.modules.meshmessenger.ProofKt > "$proof_log/bounty-host-kotlin.log" 2>&1
printf 'Bounty host control: Rust, Swift and Kotlin passed\n'
