# Mobile releases

The [Mobile release workflow](../../../.github/workflows/mobile-release.yml)
runs on every push to `release`. It verifies the candidate, then starts iOS
and Android EAS cloud builds. Android produces an AAB in EAS. Setting the
optional `ASC_APP_ID` repository variable also submits that exact iOS build
to TestFlight; without it, the IPA remains available in EAS.

Signed OTA publishing to the `production` channel is configured but disabled:
`MORSE_OTA_ENABLED=false` in GitHub. After upgrading the personal EAS account
to a plan supporting update code signing, set that repository variable to
`true`. Native builds remain enabled while OTA publishing is disabled.

Run the workflow manually with `all`, `build`, or `update` to retry a release
or publish just an OTA update. Production runs are serialized; an active
release is not canceled by a later push. GitHub keeps at most one pending run,
so rapid pushes can coalesce into the newest pending revision.

## Configured account

- Project: [@120356aa-user/morse](https://expo.dev/accounts/120356aa-user/projects/morse), under the personal account.
- Project ID: `f41ebb5b-47f4-4c55-8f02-aab6bfeb96a8`; the app config includes it and the owner.
- EAS channel `production` points to EAS branch `production`; the Git trigger is `release`.
- GitHub has `EXPO_TOKEN`, the project ID, and the deployed backend's public URLs and native pins.
- EAS production has the same client configuration and `MORSE_OTA_CERTIFICATE=./certs/certificate.pem`.
- Android's signing keystore and iOS distribution certificate/provisioning profile are stored in EAS. iOS uses the OpenWorth team `CD2RXM358N`, matching macOS signing; the EAS owner remains the personal account.
- The OTA public certificate is in `certs/certificate.pem`. Its private key is in GitHub's `ota-signing` environment, restricted to `release`, with a local recovery copy at `~/.config/morse/ota/private-key.pem`.

The workflows and application sources must be committed and merged into the
existing `release` branch before GitHub can run them. Do not force-push over
its backend deployment commits. Pushes also trigger the backend's own release
workflow and the desktop installer workflow.

## Account recovery and remaining setup

Run the commands below from `mesh-private-messenger/apps/mobile`.

1. If restoring the project on another machine, use the existing personal project:

   ```sh
   npx eas-cli@24.7.0 login
   npx eas-cli@24.7.0 init --id f41ebb5b-47f4-4c55-8f02-aab6bfeb96a8
   ```

   `app.config.js` already contains the project UUID and personal owner.
   `EXPO_PROJECT_ID` can override the UUID for isolated environments.

2. These values are managed in [GitHub Actions settings](https://github.com/snowdamiz/whatsdown/settings/secrets/actions):

   | Kind | Name | Value |
   | --- | --- | --- |
   | Secret | `EXPO_TOKEN` | An [Expo access token](https://expo.dev/settings/access-tokens) with access to this project |
   | Variable | `EXPO_PROJECT_ID` | The EAS project UUID |
   | Variable | `ASC_APP_ID` | Optional: numeric Apple ID from App Store Connect → App Information, enabling TestFlight submission |
   | Variable | `MORSE_OTA_ENABLED` | `false` until the personal account supports signed updates; then `true` |

3. For optional TestFlight submission, create **Morse** in App Store Connect
   using bundle ID `io.morseapp`, set `ASC_APP_ID`, and configure an App Store
   Connect API key for EAS Submit. To inspect or rotate native signing:

   ```sh
   npx eas-cli@24.7.0 credentials --platform ios
   npx eas-cli@24.7.0 credentials --platform android
   ```

   Select the `production` profile. Store the distribution certificate,
   provisioning profile, Android keystore, and submission API key in EAS.
   Non-interactive GitHub runs cannot create missing Apple credentials.

4. When backend settings change, update the project's **production** EAS
   environment and matching GitHub variables. Use the Expo dashboard or
   `eas env:set --environment production`.
   Use plaintext or sensitive visibility so both builds and OTA exports can
   read them. These are public URLs and public build pins, not private keys.
   Secret visibility is not available during OTA export.

   | Variable | Value |
   | --- | --- |
   | `EXPO_PROJECT_ID` | The same project UUID as GitHub |
   | `EXPO_PUBLIC_MESSENGER_BASE_URL` | Deployed HTTPS messenger URL |
   | `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL` | Deployed HTTPS privacy-edge URL |
   | `EXPO_PUBLIC_MESSENGER_STREAM_URL` | Optional WSS URL; defaults to `/v1/mailbox/stream` on the messenger origin |
   | `EXPO_PUBLIC_MESSENGER_OBJECT_URL` | Optional HTTPS object-store URL; defaults to the messenger origin, where the worker serves `/v1/objects` |
   | `EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY` | Optional integer 1–24, at least the object store's difficulty; defaults to 16 |
   | `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX` | Transparency service's 32-byte lowercase-hex public key |
   | `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX` | First witness's public key |
   | `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX` | Distinct second witness's public key |
   | `MESSENGER_DELIVERY_PUBLIC_KEY_HEX` | Delivery service's X25519 public key |
   | `MESSENGER_ABUSE_DIFFICULTY` | Canonical integer 1–24 matching the service |

   For notifications, also set **both** `MESSENGER_EXPO_PROJECT_ID` (the same
   EAS UUID) and `MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX`. Omitting both preserves
   no-push mode. The workflow checks release configuration before sending a
   build or update.

5. Run **Mobile release → build** on the `release` branch from GitHub Actions.
   Download the AAB and IPA from EAS. When TestFlight submission is configured,
   check the iOS build in TestFlight after Apple processing.
   TestFlight tester groups and Apple's required app information are managed
   in App Store Connect. This workflow does not submit an App Store review or
   publish to Google Play.

## Native builds and OTA compatibility

EAS invokes `eas-build-pre-install` before prebuild and CocoaPods. It checks out
the pinned Mesh compiler, installs Rust 1.97.0 and checksum-verified LLVM 21.1.8,
builds the target runtimes, then calls the existing `build-mobile-native.sh`.
That script verifies generated bindings and produces the iOS XCFramework or
Android arm64/x86_64 static libraries. Compiler source and generated archives
remain ignored by Git. The build hook and CI both read the compiler revision
from `mesh-private-messenger/mesh-revision`.

The [fingerprint runtime policy](https://docs.expo.dev/eas-update/runtime-versions/)
limits updates to compatible installed builds. The fingerprint includes Mesh
core/protocol sources, native bridges, compiler/build scripts, and native build
pins. It ignores generated archives, allowing an OTA export without a native
toolchain to match an EAS build. Native changes require a new binary; they
cannot be delivered through OTA. Use the same production environment for
builds and updates, including native public pins.

Local development uses the linked personal project. For production checks,
load the same EAS environment used by the workflow:

```sh
npx eas-cli@24.7.0 env:exec production 'node scripts/check-release-config.mjs'
# Publish through Mobile release → update on release after enabling MORSE_OTA_ENABLED.
```

Install a production build, publish a compatible JS change, and close/reopen
the app twice to test the default download-then-apply-on-next-launch behavior.
Use the [EAS Update dashboard](https://expo.dev) to roll back a bad update.


## Update authentication

Configure Expo's supported [update code signing](https://docs.expo.dev/eas-update/code-signing/).
Commit only the public certificate and set `MORSE_OTA_CERTIFICATE` in the EAS
production environment to its project-relative path. Store the corresponding
private key as `MORSE_OTA_PRIVATE_KEY` in the separate GitHub `ota-signing`
environment; restrict that environment's deployment permissions independently
of routine `EXPO_TOKEN` access. Never put the private key in the repository,
application environment, or EAS upload. The publication job writes it to a
mode-0600 temporary file, signs through EAS, and removes the file on exit.

A native build embeds the certificate and key ID in its runtime fingerprint.
Certificate or policy changes require a new native runtime. Without a
certificate, development apps disable OTA and release configuration fails.
A valid fingerprint alone does not authenticate an update. Native checks for
altered, wrong-key, incompatible and replayed updates still require executed
iOS/Android acceptance evidence. No such device results are implied by the
configuration test. Signing material is provisioned. Publication remains
disabled until the personal account supports signed updates and
`MORSE_OTA_ENABLED` is enabled.

All publication jobs call the reusable protocol CI at the candidate commit,
then compare both Morse and Mesh revisions with its successful outputs. The
Mesh pin is `mesh-private-messenger/mesh-revision`; update it only after the
corresponding Mesh changes are committed and available remotely. Manual
publication should use this workflow's dispatch path.
