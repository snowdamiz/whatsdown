# Native network inventory advance

Verdict: candidate can advance. No verified new unreviewed native network exit.
Source was not modified. No OS, UI, Keychain, or network execution.

## Pins

- HEAD `c49561af92b286745d644e6133a0b5b5c68da3c2` ("Adapt relay scheduler proof to explicit WebPKI RPC transport").
- Candidate recomputed equal to current bytes: desktopHost sha256 `915dee830adf6015704519234641e2de6ddb1e90718e21486ddf29f07083cef7`, 83 files, 11 sites; mesh-messenger sha256 `b201625512fe010028c950ecf4ac1a45e0e2dde75bfda67a9aebd6452133aff9`, 52 files, connectionSites `[]`.
- Baseline desktopHost was sha256 `ee22dfae…`, 9 files, sites `[]`. All 36 package records match the baseline except mesh-messenger sha256 and source count 51→52. mesh-messenger connectionSites stay `[]`.
- Control hashes in the candidate match current `Cargo.toml`, `Cargo.lock`, `tauri.conf.json`, `ipc-postmessage.js`, `index.ts`, both network-lockdown files, both mesh-messenger index adapters, and `package-lock.json`.
- Those three changed controls last matched the baseline at `646d30a7dd4af746710d6a353ef0bc6ad9feef43`.

Concurrent parent edits (`account_transition_tests.rs` under `desktop_lock/tests/`, plus witness/plaintext docs) are outside this pin. The collector omits `tests/`. Recompute after those edits still matched.

## Eleven desktop connection sites

Matcher is `native-network-inventory.mjs:12` (`WKWebView` substring, `openURL`, `URLRequest`, session/socket tokens).

| Site | Class |
| --- | --- |
| `bootstrap.rs:167`, `PrivateJob.h:5`, `PrivatePreview.h:26`, `Protection.h:58` and `:82`, `Protection.m:226`, `native_protection.rs:293`, `receiver_scope.rs:79` | Comment or doc mention of the existing Tauri WKWebView. No socket, request, or URL open. |
| `private_preview.rs` | Flagged because `WKWebViewConfiguration` contains `WKWebView`. It only builds the provider for the ObjC handler (`start` at `:42-70`). |
| `LegacyStorage.m:61-88` | `callAsyncJavaScript` runs a fixed `localStorage.getItem` / `removeItem` in content world `MorseNativePrivateStorage.v1`. Arguments are the key only. Not a load. |
| `PrivatePreview.m:92-124` | Local custom-scheme reply. See below. |
| `ProtectionBridge.m:388` | `NSWorkspace openURL`. See below. Line `:91` is workspace notification center for session lifecycle, not an open. |

## Private preview is an in-process image reply

`MDPrivatePreviewConfiguration` (`PrivatePreview.m:117-124`) registers a handler only for `morse-private` and sets the app default website data store. Wry 0.55.1 keeps a supplied configuration's data store (`wkwebview/mod.rs:227-228`). Wry's own non-incognito default is already `defaultDataStore` (`:243`). This app does not set incognito.

Admission before any bytes (`PrivatePreview.m:100-109`): GET only; scheme `morse-private`; host `preview`; no user, password, port, query, or fragment; path is one lowercase UUID; absolute string must equal `morse-private://preview/<uuid>`. The provider receives that 36-byte handle, not the request body.

`private_preview.rs:42-67` resolves `FileHandle` and `preview_for_receiver` (`private_files.rs:195-204`), which returns only a `Role::Preview` item owned by the actual WK receiver. MIME is one of seven image types (`private_files.rs:166`, again `PrivatePreview.m:72`). Response is status 200, `Cache-Control: no-store`, no `Location` (`PrivatePreview.m:78-86`). Failures call `didFailWithError`. The handler does not follow the request or issue another URL.

Top-level navigation stays `tauri://localhost` with empty user, password, and port (`navigation.rs:1-8`), installed at `main.rs:87`. `morse-private` cannot become the document. CSP `img-src` is what allows the subresource.

## Payment open is the existing wallet handoff

Live macOS command is `desktop_lock::private_commands::credit_open_payment` (`main.rs:479`), not `wallet::open_payment_url`.

Chain: `private_call` (`commands.rs:201-203`) requires the header owner and epoch on the actual webview and refuses a non-app document (`commands.rs:57-60`). `execute_checked` (`receiver_scope.rs:219-226`) checks the lease before and after `mesh_messenger_credit_payment_handoff`. The URL is Mesh's return bytes (`private_commands.rs:139-146`). `valid_payment_url` (`wallet.rs:147-157`) rejects controls; `lightning:` must be `ln` plus ASCII alphanumerics, length 1..=7089; `solana:` is only a non-control prefix and length <= 4096. `receiving` checks navigation and that the owner is still the actual WK (`private_commands.rs:147-149`). `open_payment_on_main` (`native_protection.rs:368-371`) checks the scope again. `MDNativeProtectionOpenPayment` (`ProtectionBridge.m:380-389`) requires the main thread, length 1..=7100, UTF-8, NSURL scheme exactly `lightning` or `solana`, matching window/page, not boot-failed, `scope.current`, and `permitsPrivateActionAtRevision` (`Protection.m:384-386`: uncovered, not exchanging, eligible revision).

A string whose parsed scheme is not `lightning` or `solana` is refused, so this call does not open `http`, `https`, or `file`. Preview image bytes are not an argument. The loose `solana:` shape is the pre-existing predicate, now with a parsed-scheme recheck and private-scope admission.

## RPC TLS packager adds no HTTP client

Since `646d30a`, production native delta is `MeshMessengerRpcTLS.kt` (new), `MeshMessengerModule.kt`, `MeshMessengerHost.cpp`, `MeshMessengerSecureStore.m`. Tests under `tests/rpc-tls/` are omitted by the collector.

`MeshMessengerRpcTLS.read` (`MeshMessengerRpcTLS.kt:9-22`) reads a caller `InputStream` into at most 82002 bytes. The caller opens asset `morse-rpc-tls-roots-v1.bin` (`MeshMessengerModule.kt:749-752`). iOS reads Info.plist `MeshMessengerRpcTLSRoots` and checks canonical base64, length 2..=82002 (`MeshMessengerSecureStore.m:237-258`). JNI copies that array for selector `messenger/rpc-tls-roots/v1` (`MeshMessengerHost.cpp:217-255`). A search of the module for `URLSession`, `NSURLConnection`, `HttpURLConnection`, `OkHttp`, `socket(`, `getaddrinfo`, `TcpStream`, and `reqwest` found none. Recomputed connectionSites stay empty.

## Dependency and CSP controls

`Cargo.toml` / lock direct adds since `646d30a`: `sha2`, pinned `libc`, `chacha20poly1305` and its cipher crates, pinned `objc2`, and `objc2-web-kit` with `default-features = false` and only `WKWebViewConfiguration`. `tauri-plugin-updater` was already direct. Lock names added are only AEAD/ChaCha crates. `reqwest` was already present. Updater endpoint in `tauri.conf.json` is unchanged.

CSP change is `img-src` gaining `morse-private://preview`. The rule `connect-src 'none'` is still present (`tauri.conf.json:33`). The collector refuses a capture without that exact directive (`native-network-inventory.mjs:149-150`). `network-lockdown.ts` and `index.ts` (lockdown import before the app) are hash-identical to the baseline.

## Scope limits

- The matcher is a review aid. Comment hits are not exits. `/usr/bin/open` and `ShellExecuteW` in `wallet.rs:159-195` do not match `openURL`. That function is not the macOS command. The non-macOS `credit_open_payment` (`main.rs:291-311`) is not in the non-macOS invoke list (`main.rs:494-495`).
- Collector omits `test`/`tests` and a local module's root `native/` directory. mesh-messenger has no root `native/` directory.
- Other 35 packages were compared as candidate JSON versus the baseline, not by a fresh autolink walk. Parent still runs the collector gate.
- WebKit process behavior and the external wallet app are outside this source review.
