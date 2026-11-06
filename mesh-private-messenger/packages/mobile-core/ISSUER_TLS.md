# Private issuer HTTPS trust

Ordinary builds use the platform-independent Mesh webPKI root set. Private issuer
operators may provide `MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE` **at native build time**.
The file must contain only 1–8 parsed PEM CA certificates, at most 65,536 bytes.
Its origin is derived from `MESSENGER_CREDIT_ISSUER_ORIGIN`, which must be the exact
canonical HTTPS origin already included in native SecurityConfig. Missing or
malformed issuer pins, unreadable files, non-CA certificates and oversized files
fail the build. No JavaScript, OTA setting or request parameter selects a CA.

The resource selector is `messenger/issuer-tls-root/v1`. Its binary framing is:

| Field | Encoding |
| --- | --- |
| version | one byte, `01` |
| origin length | u16 big endian, at most 2,048 |
| origin | exact ASCII native issuer origin |
| PEM length | u32 big endian, at most 65,536 |
| PEM | unchanged certificate bundle |

A missing native resource returns exactly `01 0000 00000000` (seven bytes),
selecting ordinary webPKI. Present resources require both nonempty fields and an
exact total length (maximum 67,591 bytes). Read failures, malformed resources and
origin mismatches fail closed; they never select default roots.

The iOS Info.plist key is `MeshMessengerIssuerTLSRoot`, canonical base64 of the
frame. Android packages `assets/morse-issuer-tls-root-v1.bin`; the config plugin
removes a stale asset when the build-time file setting is absent. Desktop's
bundled native config uses `issuerTlsRoot` with the same canonical base64 frame.
These values are native build resources, not web configuration.

`Mobile.NativeIssuerTls.issuer_tls_request(request, config.issuer_origin)` applies
these roots only to `Mobile.Credits.post_credit`. Explicit roots replace the
request's default root set, enforce HTTPS (including redirects), retain chain,
hostname and certificate-expiry verification, and use an isolated connection
pool. Core, object-store, RPC and other HTTP requests retain their own existing
trust policy. The resource grants no authority to forge signed quotes,
checkpoints, receipts or cancellation proofs.

Local checks:

```sh
node --test apps/mobile/scripts/issuer-tls-root.test.mjs
scripts/test-issuer-tls-host.sh
cd packages/mobile-core
../../../mesh-lang/target/debug/meshc test tests/native_issuer_tls.test.mpl
```

The host proof runs the exact production Android reader on the JVM and the
production Objective-C callback on macOS, including absent, bound, malformed and
read-error cases. Full native HTTPS credit execution is a separate owned-service
proof (`scripts/credit_tls_proof.py`); host parser tests alone do not establish
mobile TLS execution or release readiness.
