# Android wallet custody proof

This disposable test APK compiles the production `MeshMessengerWalletStore.kt`
and `MeshMessengerWalletHost.cpp` directly with the real Rust wallet SDK. It
never installs or clears the Morse application and uses only the distinct
`app.morse.wallet.proof` package. Its fixed mint/purpose are test configuration.

Run after building `morse-wallet-core` for `aarch64-linux-android`:

```sh
MORSE_WALLET_ANDROID_ARCHIVE="$PWD/packages/wallet-core/target/aarch64-linux-android/debug/libmorse_wallet_core.a" \
  apps/mobile/modules/mesh-messenger/android/wallet-proof/prove.sh
```

The script requires an explicitly available arm64 emulator/device (default
`emulator-5554`), Android SDK platform/build tools 36, NDK 28.2.13676358, a JDK,
and cached Kotlin 2.1.20 compiler dependencies. SDK, NDK, Java and device paths
can be overridden with `ANDROID_HOME`, `ANDROID_NDK_HOME`, `JAVA_HOME`, and
`MORSE_WALLET_ANDROID_SERIAL`. Platform and build-tools overrides are
`MORSE_WALLET_ANDROID_PLATFORM` and `MORSE_WALLET_ANDROID_BUILD_TOOLS`.
Missing prerequisites fail the command; no tests silently skip.

The instrumentation exercises actual Android Keystore AES-GCM, native JNI and
Rust calls, foreground creation/payment confirmation, cancellation, a real HOME
transition during confirmation, full-u64 amount presentation, purpose/mint
rejection, and 32 unique bounty indices reserved by two independent processes
and concurrent threads. It also tests ciphertext corruption, deleted records,
restoration of a valid older encrypted snapshot, and an interrupted replacement
whose Keystore highwater advanced before file persistence failed.

The native host stores one 44-byte seed/counter record in an 80-byte sealed file
inside `noBackupFilesDir`, with purpose/mint bound as authenticated encryption
data. A permanent OS file lock serializes all application processes. File writes
fsync before atomic rename, then fsync the containing directory before success.
A Keystore-owned counter generation advances before each replacement; restoring
old app files cannot rewind it. A crash or storage failure between advancing
that marker and committing the file fails closed. There is no automatic reset,
old-snapshot fallback, or seed export. This deliberately favors never reusing a
bounty address over automatic recovery from ambiguous native storage failure.

`invoke` and its callbacks are a privileged native boundary. Production JS
payment requests must select an existing durable purchase; the native Module
obtains its raw quote from Mesh's verified journal before invoking this host.
The host never accepts arbitrary signing instructions. Its UI reports public
payment information and returns approval only after an explicit foreground
button press. Seeds and internal records never cross the native boundary.

This proof establishes the emulator's native custody behavior. It does not
replace application wrapper/authentication tests, physical-device validation,
independent wallet review, or production release configuration checks.
