# Native RPC TLS roots

`MORSE_RPC_TLS_ROOTS_FILE` is a native build input. Unset builds omit the RPC TLS
resource and use Mesh webPKI roots. A set value names a UTF-8 JSON manifest:

```json
{
	"version": 1,
	"origins": [
		{ "origin": "https://rpc-a.example:8443", "pemFile": "ca-a.pem" },
		{ "origin": "https://rpc-b.example", "pemFile": "ca-b.pem" },
		{ "origin": "https://rpc-c.example", "pemFile": null }
	]
}
```

The manifest contains exactly `version` and `origins`. Each row contains exactly
`origin` and `pemFile`. A nonempty `pemFile` names a local CA bundle. Relative
paths resolve against the manifest directory. Explicit `null` selects webPKI for
that origin. At least one row must name a CA bundle.

The rows cover all 3 through 8 distinct RPC origins in the generated native
SecurityConfig. Unknown, duplicate, and missing origins fail the build. Each
origin is exact canonical ASCII HTTPS text, at most 2,048 bytes. Credentials,
paths, queries, fragments, whitespace, backslashes, uppercase hosts, and explicit
default ports are invalid in manifest origins. Full RPC URLs, including paths
and queries, remain in SecurityConfig.

Manifest files contain 1 through 65,536 bytes. Each CA bundle contains 1 through
8 parsed PEM CA certificates. All CA bundles together contain at most 65,536
bytes. Repeated bundles count separately. The packager preserves PEM bytes and
rejects non-CA certificates, invalid encoding, trailing content, and non-ASCII
PEM. Empty settings, missing files, unreadable files, nonregular files, and
oversized files fail the build. No runtime environment variable, JavaScript
argument, or OTA setting supplies roots.

## Resource format

The selector is `messenger/rpc-tls-roots/v1` on the existing `Host.push_get_token`
ABI. Physical absence returns exactly two bytes, `01 00`. A present resource has
these fields:

| Field | Encoding |
| --- | --- |
| Version | One byte, `01` |
| Origin count | One byte, 3 through 8 |
| SecurityConfig digest | SHA-256, 32 bytes |
| Origin length, repeated per row | u16 big endian, 1 through 2,048 |
| Origin | Exact canonical ASCII HTTPS origin |
| PEM length | u32 big endian |
| PEM | Unchanged bundle, or zero bytes for explicit webPKI |

Rows sort by origin in ASCII order. The digest covers every UTF-8 byte of the
canonical generated SecurityConfig, including any v6 session-suite envelope.
Changes to endpoint paths, queries, or other security pins change the digest.
The maximum frame is 82,002 bytes. Its canonical base64 encoding contains at
most 109,336 characters.

Hosts deliver bounded opaque bytes. They do not parse origins, validate X509,
select roots, or implement HTTP. The Mesh companion decoder owns frame
validation and SecurityConfig binding. The public Mesh HTTP runtime owns TLS
certificate parsing and verification. A resource read, type, encoding, or size
error returns a Host error. Such an error never becomes the absence sentinel.

## Native packaging

| Host | Bundled resource |
| --- | --- |
| iOS | `MeshMessengerRpcTLSRoots` Info.plist string, canonical base64 |
| Android | `assets/morse-rpc-tls-roots-v1.bin`, raw bytes |
| Desktop | `rpcTlsRoots` in the bundled native config, canonical base64 |

An unset build setting removes a stale iOS key and Android asset. Desktop writes
an empty string when roots are unset. Desktop accepts a missing field or an
empty string as absence. A field with another JSON type is an error. iOS accepts
only a missing key as absence. Android distinguishes a missing asset from a
failed asset listing or a failed read. Resource errors remain errors after
installation. Android installs one copy and returns a clone to the Host bridge.

The native resource is separate from issuer, directory, OHTTP, and network
counter trust. The resource does not change the C ABI layout or the 176 exported
MobileCore operations. Expo public fields and the desktop web configuration do
not contain the manifest path or root bytes.

## Local verification

From `mesh-private-messenger`, the packager and reader checks are:

```sh
node --test apps/mobile/scripts/rpc-tls-roots.test.mjs
scripts/test-rpc-tls-host.sh
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked rpc_tls
```

The desktop Cargo command requires the existing `src-tauri/native` bundle
resources. A build that stops before compilation because those resources are
missing does not establish a passing reader test.

The mobile host proof compiles the production Objective-C callback on macOS and
the production Kotlin reader on the JVM. Desktop tests exercise the production
Rust resource reader and Host callback. These checks establish resource byte
delivery and error behavior. They do not qualify an iOS or Android app session,
other desktop operating systems, actual RPC HTTPS, release artifacts, or
production readiness. Compiled MobileCore transport and full native builds need
their own qualification.
