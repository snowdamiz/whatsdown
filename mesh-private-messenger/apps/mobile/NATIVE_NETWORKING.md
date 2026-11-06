# JavaScript network boundary

`index.ts` initializes Expo, then installs `src/network-lockdown-bootstrap.ts`
before importing the app or headless notification tasks. The guard replaces
fetch with an immutable rejected-Promise function and replaces XHR, WebSocket,
EventSource, WebTransport, WebRTC constructors and navigator.sendBeacon with
immutable refusals. RN and Expo development backup aliases are replaced without
evaluating their lazy getters. A capability that cannot be replaced aborts
startup. URLs, headers and request bodies are never included in these errors.

Tauri uses `src-tauri/src/ipc-postmessage.js` for every native invocation,
including binary replies and channel data. IPC does not need an HTTP exception.
The desktop CSP retains `connect-src 'none'`, forbids frames and remote images,
and permits only local/data/blob image sources. Native domain exports choose
their network origins from immutable native pins and authenticate their results.

This is a boundary for the reviewed application source, not a JavaScript sandbox.
An original capability captured by code before initialization, a direct native
module import, a remote image loader or a native updater is outside this global
replacement. The inventory below makes those dependencies explicit. It does not
prove that arbitrary malicious JavaScript cannot reach an existing native API.
No complete Phase 6 or release claim follows from this slice.

## Native dependency review

`npm run check:native-network` resolves both Expo and React Native autolinking for
iOS and Android and compares the result with `native-network-inventory.json`.
The reviewed snapshot contains 36 packages and 5,901 native source/build files.
It fingerprints all included source, not just files matching the connection
search, so a new connection in an existing source file also changes the gate.
The package lock, desktop native source, Rust dependency lock/manifest, desktop
CSP, IPC transport, bootstrap and public native adapters are pinned too. A new module, version, registration, source change or control
change fails. The checker does not update its own reviewed baseline.
It also recursively checks application source for ordinary raw transports,
direct native HTTP/WebView imports and filesystem upload/download APIs. This
source check is not an obfuscation-resistant JavaScript security proof.

Capture a proposed update with
`node scripts/native-network-inventory.mjs --capture /path/to/review.json`, then
review its changes before replacing the baseline. The check excludes its listed
build, prebuild, test and proof directories; directory names are case-sensitive.
For `expo-modules-jsi`, it also excludes the package's `.DerivedData` tree and
recognized generated Swift headers in its staged framework. Staged authored
headers and the `expo-updates` BSPatch copy, when present, must be regular files
matching their inventoried canonical sources byte-for-byte. Changed or
symlinked copies, and copies without a regular canonical source, refuse.
The JSI generator scripts, API notes and visibility list are inventoried.
These rules keep the reviewed source snapshot stable across CocoaPods runs;
they do not authenticate generated binaries. Package integrity
pins cover the npm artifacts; public Mesh and platform runtime/library bytes
have separate build evidence. The connection-site matcher is a review aid,
not a completeness proof or runtime firewall.

| Packages | Native connections and reviewed application use |
| --- | --- |
| `mesh-messenger` | Mesh owns service HTTP, WebSockets, authenticated chain RPC and sealed journals. Native host dispatch accepts typed bounded actions. Wallet custody/signing and typed OS payment handoffs remain native. |
| `react-native` | Native HTTP/WebSocket modules, remote image loading and OS URL handling remain installed. Application source does not import the raw network modules or construct transports; the three main globals and backups are locked. Metro/inspector connections belong to development hosts. |
| `expo` | ExpoFetch is still a native capability behind the blocked ordinary fetch global. Direct `expo/fetch` imports are not an approved application path. |
| `expo-file-system` | Local bounded file selection, staging and save operations are used. Native upload/download APIs remain a capability; application service/object transfers use Mesh exports. |
| `expo-asset`, `expo-font`, `expo-image-loader`, `expo-image-manipulator`, `expo-image-picker`, `react-native-svg` | Asset/font/image loaders can resolve remote resources or user-selected cloud media through native code. App fonts and SVGs are bundled; attachments/avatars use local file/blob URIs and explicit user selection. These loaders are not covered by the JS transport guard. |
| `expo-notifications`, `expo-task-manager` | OS APNs/FCM registration and background wakeup are native. The app uses opaque, profile-bound Mesh push actions; no JS receipt of a signed wire or authority to acknowledge arbitrary HTTP success. Native notification image downloading remains installed; Morse's wakeup payload is generic. |
| `expo-updates`, `expo-updates-interface`, `expo-manifests`, `expo-structured-headers`, `unimodules-app-loader`, `expo-eas-client` | Native OTA update loading is outside Mesh. It uses build configuration and its own update validation; removing fetch does not disable it or establish build transparency. |
| `@expo/dom-webview`, `@expo/ui` | Native WebView and image/URL loaders can make connections. No remote WebView/DOM surface is used by the application. Android excludes `@expo/ui`; iOS uses native layout/glass controls. |
| `@expo/log-box`, `expo-modules-core`, `expo-modules-jsi`, `react-native-worklets` | Developer tools, native request instrumentation and Worklets script-buffer networking are separate capabilities. App worklets are bundled animation logic; the guard does not sandbox native JSI APIs. |
| `expo-application`, `expo-camera`, `expo-constants`, `expo-glass-effect`, `expo-json-utils`, `expo-keep-awake`, `expo-localization`, `expo-splash-screen`, `expo-status-bar`, `react-native-keyboard-controller`, `react-native-reanimated`, `react-native-safe-area-context` | Application/device metadata, local camera/UI/layout/lifecycle support. Included in the source/version gate even when the connection matcher finds no direct connection primitive. Native OS/provider behavior is outside Mesh's checker. |
| Tauri Rust plugins | Notifications use OS facilities. The updater checks a configured signed release endpoint. Dialogs/save handles operate on user-selected local files. Single-instance/window IPC is local. Rust dependency/control pins are part of this inventory; the former arbitrary `binary_request` IPC is absent. |

## Run iOS with the network guard

Use production-mode JavaScript in the installed Debug native app. React Native
still constructs an HMR socket when Fast Refresh is off. Production-mode JS uses
`HMRClientProdShim` while the app's JS transport refusals stay intact.

Use an owned simulator with the signed Debug app already installed. Match the
port below to that build's `RCTMetroPort` and choose an unused port. Expo's plist
port takes precedence over the launch environment. From `apps/mobile`, start Metro:

```sh
MORSE_METRO_PORT=59391
node node_modules/expo/bin/cli start --dev-client --localhost \
	--port "$MORSE_METRO_PORT" --no-dev --max-workers 1
```

In another terminal, set the exact simulator UDID and launch that app:

```sh
MORSE_SIMULATOR_UDID='YOUR_OWNED_SIMULATOR_UDID'
MORSE_METRO_PORT=59391
SIMCTL_CHILD_RCT_METRO_PORT="$MORSE_METRO_PORT" \
	xcrun simctl launch "$MORSE_SIMULATOR_UDID" io.morseapp -RCT_enableDev NO
```

Verify that the native bundle request contains `dev=false` and `lazy=false`.
If Metro runs with `CI=true`, restart it after source edits because watch mode is disabled.
After JS edits, terminate and relaunch the same app to load the updated bundle:

```sh
xcrun simctl terminate "$MORSE_SIMULATOR_UDID" io.morseapp
SIMCTL_CHILD_RCT_METRO_PORT="$MORSE_METRO_PORT" \
	xcrun simctl launch "$MORSE_SIMULATOR_UDID" io.morseapp -RCT_enableDev NO
```

Stop this Metro process with Ctrl+C in its terminal. The launch argument does
not write a stored default. To remove the override, terminate the app and omit
`-RCT_enableDev NO` on the next launch. Do not add JS transport exceptions for HMR.

The local simulator check reached unauthenticated onboarding. Opening iOS
Settings, then returning to the same Morse process, showed onboarding again.
Enabled OS authentication, backups, physical devices and release builds need
separate checks.

## Local qualification

Focused tests exercise real installed RN/Expo lazy-polyfill code, immutable
backup aliases, asynchronous fetch refusal and startup ordering. A test-only
Metro entry, `scripts/network-lockdown-proof.ts`, loads the real application,
checks the real background-task registration and native SQLite/error boundary,
and writes only local proof results. It is not the application entrypoint.
Owned copied iOS/Android app identities preserve the ordinary welcome screen.
Android screen capture remains protected; its accessibility tree confirms the
rendered welcome view.

The local evidence directory retains failed fixture/packaging attempts as well
as passing results. Simulator/emulator tests are not physical-device or
production-network qualification. The complete checked source and artifact
hashes must accompany any broader claim.
