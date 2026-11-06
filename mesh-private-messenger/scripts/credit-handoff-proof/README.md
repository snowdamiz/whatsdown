# Owned external-wallet handoff proof

`prove-credit-os-handoff.py` composes the existing local Bitcoin/LND,
PostgreSQL, Mesh issuer and native HTTPS qualification with a full React Native
app. The test entry loads the normal `index.ts`, the normal `credits.ts`
adapters and the production `openCreditPayment(database, purchaseId)` wrapper.
The launcher receives no URL, invoice, CA or provider selected by JavaScript.

The owned iOS/Android receiver registers `lightning:` and records only the
OS-delivered URI's SHA-256, length, scheme and invocation count. It never pays an
invoice. The sender is a separately identified debug app; production app data
is untouched. No screenshots, UI trees, screen snapshots or recordings are
used. The issuer setup uses only owned regtest data and synthetic identities.

The proof checks a missing receiver, wrong database and unknown purchase,
exact verified invoice delivery, reopening the same durable invoice after a
sender restart, and refusal after native authentication of a real LND
cancellation. Existing direct HTTPS and actual regtest payment checks still
run unchanged before each OS proof. These results establish owned OS delivery,
not compatibility with any third-party wallet or a live payment.

Example from the product directory (set the compiler/runtime wrapper and frozen
issuer source to the locally qualified pins):

```sh
MESHC=/absolute/path/to/pinned-meshc-wrapper.py \
MORSE_LIGHTNING_SERVICE_SOURCE=/absolute/path/to/frozen/credit-issuer \
MORSE_LIGHTNING_PROOF_DIR=/absolute/path/to/new-evidence-directory \
MORSE_LIGHTNING_CASES=ordinary \
MORSE_LIGHTNING_IOS_TLS_PROOF=1 \
MORSE_LIGHTNING_ANDROID_TLS_PROOF=1 \
python3 scripts/prove-credit-os-handoff.py
```

The driver copies the complete protocol dependency tree before compiling either
backend executable. Its private Android RN workbench currently reuses
`.morse/js-network-closure/android-root`; the iOS host defaults to the full
`build-phase6-mailbox` app. `MORSE_HANDOFF_IOS_APP` can select another already
built simulator app. The saved simulator debug-launcher link arguments in the
network-closure workbench supply the simulator Keychain entitlements; the
production Expo host dylib stays unchanged. Exact host and JS inputs are
recorded separately from the standalone native HTTPS artifacts.

Metro uses owned ports 25389/8088. Only the separately identified apps and
receiver are stopped. Logs, JSON assertions, public native resource frames,
compiled backends and plaintext reports provide the evidence. Do not archive
the temporary TLS private keys or any app database/Keychain state.
