# Native device HTTP proof

```sh
python3 scripts/prove-device-http-native.py \
  --platform both \
  --evidence ../.morse/witness-proof/device-http-native162-new \
  --compiler ../.morse/native-reader-meshc.py
```

The compiler/runtime, installed native module and completed account HTTP
checkpoint are prerequisites. The backend copies that checkpoint's exact
production directory-delivery sources and declared dependencies. Only its
test bootstrap and this explicit external-device/witness fixture differ.
`--reuse-backend` verifies a saved executable/source pair before another
platform run. `MORSE_DEVICE_HTTP_PRODUCT` may select an independently copied
native module tree so another build can replace installed artifacts safely.

The proof calls the real generated Swift or Kotlin/JNI ABI with actual
Keychain/Keystore storage. Each platform uses its own PostgreSQL database and
native build-pinned localhost origins. All commands and assertions are terminal
driven; no computer-use, browser, screen capture or UI inspection is involved.

Fresh primary credentials are not due for renewal. The proof asserts that
early renewal makes no HTTP request. An owned external Mesh device supplies a
link request, the native primary authorizes it, and the production server
accepts that linked device's genuine signed renewal request. The proof's one
local witness signs actual service checkpoints and is explicitly registered
in the owned database. Native resolution verifies the service signature,
witness signature, inclusion/consistency and immutable native pins.

The native primary answers the request and publishes a renewed credential.
The proxy drops the accepted response after the server commits. A fresh native
process must replay the exact journaled directory entry without incrementing
the server sequence again. Its proof-of-work envelope may be freshly minted;
the canonical entry hash must stay identical. Only newly verified witnessed
state retires the publication queue.

Revocation uses the admitted successor. A linked-device signature is refused
as an account authorization. A dropped accepted native revocation leaves an
unknown result; replay of the exact old statement returns a safe conflict.
New witnessed revoked state then returns terminal success without another
mutation. The proof checks the persisted revocation, inactive mailbox and
remaining primary, plus self/last-device refusal and old-account actions
refusing before HTTP after replacement.

Per platform the final gate has six case groups, 15 native HTTP requests and
three separately labeled external-fixture HTTP requests. Body hashes and
lengths are recorded; profiles, mailbox capabilities, generated private keys
and database files must not be archived. There is no clock bypass, mobile
private-key export, operator-independence claim, linked-client receiving or
decryption proof, physical-device qualification or release claim.
