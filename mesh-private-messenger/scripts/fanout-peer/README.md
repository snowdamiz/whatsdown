# Owned native fanout proof

Run from the product directory after the current mobile native libraries and
Android merged `.so` have been built. Both commands build an isolated synthetic
app. They use separate native OS-sealed databases for Alice and Bob and an owned
Mesh HTTP peer with ephemeral signing keys. No production service, account,
funding, deployment or feature flag is involved.

```
python3 scripts/prove-fanout-platform.py ios --compiler /absolute/path/to/meshc
python3 scripts/prove-fanout-platform.py android --compiler /absolute/path/to/meshc --port 24332
```

The peer test fixture uses the public runtime's in-memory test secure store only
for its ephemeral server signing keys. Client custody, native HTTP, prekey work,
witness verification, session encryption and persistent group state use the
production compiled Mesh library and real Keychain/Android Keystore callbacks.
The supplied public signing pins and loopback origins are native Info.plist or
Android manifest build resources. They are not JS selectors.

The proof performs a typed message send and decryption, group invitation and
acceptance, exact control-message no-op retries, OS process restart, and refusal
to reuse the erased account's profile after replacement. Internal raw outbox and
receive exports are used only by this synthetic test driver to deliver and
inspect encrypted packets. They remain denied by generic app dispatch.

Evidence is written under the outer workspace `.morse/witness-proof` as
`fanout-native-{ios,android}-evidence.json` and peer logs. It records exact native
library/generated/host/proof input hashes. This qualifies simulator/emulator ABI
execution; it does not claim physical-device execution or arbitrary JS/native
network capability removal.
