# Morse desktop

Windows 10/11 (x64), macOS 12+ (Intel and Apple silicon). Tauri hosts the shared
Expo/React Native Web interface and the same Mesh protocol library as mobile.
Keys stay in native code, protected by Windows Credential Manager or macOS
Keychain; Mesh keeps encrypted history in the app's local data directory.

Desktop has a resizable window with a persistent sidebar (chats and
groups, your account) beside the open conversation, Enter to send (Shift+Enter
for a newline), groups, device linking, and selectable device codes. Desktop has
no camera: a new message is addressed by username, and the codes that link
devices or join groups are pasted as text. Use **Show text code** on the other
device and paste it into the desktop code screen.
Messages synchronize while the app is running, including when minimized.
Enable native macOS/Windows message and @mention alerts in You → Notifications.
The visible conversation suppresses alerts; previews are formatted locally after
decryption. Desktop alerts require Morse to remain running. Notification clicks
do not deep-link on desktop (the Tauri plugin only exposes actions on mobile).
Mobile uses headless push tasks when background execution is permitted by the OS.

The window has no separate title bar: the toolbar strip of each pane is the
pane's own colour and draggable, with its title set flush left, and on macOS
the window buttons sit inside it (`titleBarStyle`/`trafficLightPosition` in
`src-tauri/tauri.conf.json`).
Windows uses the same toolbar surfaces, with custom minimize, maximize/restore
and close buttons at the upper right instead of Mac traffic lights.
The sidebar's strip is laid out like a toolbar: the window buttons and Chats/Groups switch lead, the list's actions trail,
and the account bar sits below the list. Chrome is glass, as on the phone:
rows frost as they scroll under a toolbar, while scrollbar tracks stay clear
of the content fade and blur. Scrollbar thumbs are thin and faint, appearing
while scrolling and fading out after a short pause. Toolbar buttons, the list switch, buttons
with a surface, the composer and the status pill are translucent capsules
(`src/glass.web.tsx` in the mobile app, drawn with the web view's backdrop
blur). The system's reduce-transparency setting swaps them for solid surfaces.
Status never covers content: the pill opens a lane of its own under the pane
(above the screen on a phone) and the layout eases out of its way. Detail
screens (settings, devices, conversation and group details) keep to a reading
column centred in the pane. Every pane header spans the full width with the
same 72px height and 16px side padding as chats, vertically aligning with the inset sidebar toolbar; content starts 12px below it.
Screens that show a QR code place it beside the copy. Before an account exists, the same screens span the
window and centre their content like a sheet. Keyboard shortcuts use Cmd on macOS and
Ctrl on Windows: N for a new message, comma for settings,
Escape to return to the list.

## Develop

In a development build, **You → Development → Windows UI** previews the Windows
title bar on your current desktop. It replaces the Mac traffic lights with working
Windows-style controls and resets on reload. Sample content can be enabled separately.

On macOS, run `./run.sh` from the repository root to build and start the desktop
and simulator apps with Docker, PostgreSQL, and every local backend service.
Use `./run.sh desktop` for desktop only. It reuses running
services; logs are in `.morse/logs/`. The manual steps below are useful when
building the desktop app separately.

Install Node 24+, Rust, and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).
Keep the separate `mesh-lang` checkout at the repository root (a symlink works),
at the revision pinned in `.github/workflows/desktop-release.yml`. Build its
compiler and host runtime with LLVM 21:

```sh
cd mesh-lang
cargo build --locked -p meshc -p mesh-rt
cd ../mesh-private-messenger/apps/desktop
npm ci --prefix ../mobile
npm ci
npm run native -- --development
npm run dev
```

Set `LLVM_SYS_211_PREFIX` to your LLVM 21 installation when building Mesh.
On macOS set `MACOSX_DEPLOYMENT_TARGET=12.0` for the Rust runtime build; the native
library build also reads and verifies the minimum version from the Tauri config.
On Windows use an MSVC developer shell and the LLVM setup from the workflow.
`MESHC` can select a different compiler binary. Development defaults to local
messenger/edge/stream endpoints; export the same public pins and URLs used by
`../mobile` to connect to your local backend. The root `./run.sh` shares the
backend URLs and public pins with the desktop build automatically;
`./run.sh mobile` starts only the mobile simulator app with Expo instead.

`npm run native` creates the host DLL/dylib and configuration. Rerun it after
Mesh or service-configuration changes. `npm run dev` bundles the web UI and
starts Tauri. Restart it after UI edits. Set `MORSE_DEVTOOLS=1` to open the
webview inspector in a debug build.

On macOS, `npm run dev` signs each executable after Cargo links it, using an
installed **Apple Development** certificate. Set `MORSE_DEV_SIGNING_IDENTITY`
to a specific certificate name if needed (it also respects
`APPLE_SIGNING_IDENTITY`). Missing or ad-hoc signing identities fail before the
app launches. Signing-key access may need initial authorization on a new Mac;
the app's own Keychain records then remain accessible across launches and
rebuilds without asking for your Mac password. Use Node 24+ for the launch runner.

Development uses `io.morseapp.desktop.dev` for both Keychain records and its
app-data directory. The packaged release keeps `io.morseapp.desktop`, including
all existing accounts, keys, counters, and history. The first development launch
therefore opens onboarding; create or link a separate development device.
Never copy the storage key and counter into independent stores: both could
then reuse the same encryption nonces. To use existing local data, open the
signed `Morse.app` built with the default configuration.

Older records approved for ad-hoc builds can still require one final **Always
Allow** authorization for the signed app. Do not delete or reset these records
to clear a prompt. The existing encryption key and counter must be preserved.

```sh
npm test
npm run typecheck --prefix ../mobile
npm test --prefix ../mobile
npm run build -- --debug
```

Native tests load the real bundled library, verify its exports, and open a
temporary database. Build the native library before running them.

## GitHub builds and releases

[Desktop build and release](../../../.github/workflows/desktop-release.yml)
builds and tests Windows x64, macOS Intel, and macOS Apple silicon on native
runners. Every push to `release` produces production installers as workflow
artifacts, using the deployed backend and release signing. PRs and manual runs
on other branches produce debug installers using local endpoints; those
previews require your local backend.
Previews use `io.morseapp.desktop.preview` with separate credentials and data,
so their unsigned/ad-hoc identities cannot disturb development or release data.

These **GitHub repository variables** are provisioned from the deployed backend
and match the mobile EAS production environment:

| Variable | Value |
| --- | --- |
| `EXPO_PUBLIC_MESSENGER_BASE_URL` | HTTPS directory/delivery URL |
| `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL` | HTTPS privacy-edge URL |
| `EXPO_PUBLIC_MESSENGER_STREAM_URL` | Optional WSS URL; defaults to the messenger origin's `/v1/mailbox/stream` |
| `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX` | Service public key, 64 lowercase hex characters |
| `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX` | First witness public key |
| `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX` | Distinct second witness public key |
| `MESSENGER_DELIVERY_PUBLIC_KEY_HEX` | Delivery X25519 public key |
| `MESSENGER_ABUSE_DIFFICULTY` | Canonical integer 1–24 |

Keep `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json` versions
aligned, update the lockfiles, then push `desktop-v<VERSION>` (initially
`desktop-v0.1.0`). Release builds reject missing pins and non-TLS endpoints.
After all three builds pass, the workflow publishes `.dmg` installers for both
Mac architectures and a Windows `.exe` installer to that GitHub Release.
Mobile EAS/TestFlight/OTA releases continue through the existing mobile workflow.

macOS releases require these GitHub Actions secrets:
`APPLE_CERTIFICATE` (base64 Developer ID certificate),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD` (app-specific password), and `APPLE_TEAM_ID`.
The OpenWorth Developer ID certificate, its export password, signing identity,
and team ID have been provisioned in this repository's encrypted secrets.
`APPLE_ID` and `APPLE_PASSWORD` are also configured. To rotate the password, generate it
at [Apple Account](https://account.apple.com) → Sign-In and Security →
App-Specific Passwords, then save it in [Actions secrets](https://github.com/snowdamiz/whatsdown/settings/secrets/actions).
Never use the normal Apple Account password.

The workflow imports the certificate into a temporary keychain, signs the Mesh
library and app with hardened runtime enabled, notarizes and staples the app,
and verifies the signature/ticket before publishing. It deletes the temporary
keychain afterward. Missing credentials fail the release; PR previews remain unsigned/ad-hoc
signed. Windows Authenticode signing is not configured, so Windows production
packaging remains blocked; the two macOS jobs run independently.
Desktop updates are installed from a new release; there is no desktop OTA updater.

For a local signed build with the installed certificate:

```sh
APPLE_SIGNING_IDENTITY='Developer ID Application: OpenWorth Technologies, LLC (CD2RXM358N)' npm run build -- --debug --bundles app
```

## Apple identifiers and capabilities

Use `io.morseapp` for iOS and `io.morseapp.desktop` for macOS. Enable **Push
Notifications** for iOS. The current Mac app needs no extra portal capabilities.
Normal Keychain use does not require Keychain Sharing. Camera permission belongs
in the app's usage descriptions; desktop currently accepts pasted codes.

Add **Associated Domains** when implementing HTTPS invitation links; **App
Groups** for shared extension/widget data; **Keychain Sharing** if an extension
needs shared secrets; and macOS **Push Notifications** when implementing APNs
there. These capabilities can be enabled later. GitHub Mac downloads use a
Developer ID Application certificate; Mac App Store distribution would need
a separate Apple Distribution/sandboxing setup.

The Windows DLL support and its CI proof are pinned to Mesh commit
`79138a027221268c7a255ab92b0a27411a2ba0fa`. Keep the compiler pins in desktop CI,
main CI, and `scripts/eas-build-native.sh` aligned.


Release-branch and tagged Windows builds require `WINDOWS_SIGN_COMMAND` (the issuer's supported
Tauri custom signer, including `%1` for the file) and
`WINDOWS_SIGNER_THUMBPRINT` repository variables. Provision the issuer's tool
and credentials through its hardware/cloud signing integration on the release
runner; no exportable PFX key is assumed. Packaging fails if signing fails,
and publication requires a valid Windows Authenticode signature from the
configured publisher. A command that merely exits successfully cannot bypass
that verification. Windows signing execution is not verified by macOS tests.
