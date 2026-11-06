# Opt-in sealed ingress certificate guard

This implements an optional backend certificate guard and rejects an unsupported
edge configuration. **M2 is not closed end to end.** No certificate, account,
route, WAF rule or deployment is created by this change. The existing combined
development topology is unchanged when the policy is entirely absent.

## Current platform constraint

Cloudflare's outbound mTLS binding exposes a Fetch API on a certificate binding,
but the official documentation says that a Cloudflare-proxied destination is
unsupported and returns 520. Our backend Worker is such a destination. No
documented `workers.dev`, Worker-route or Custom Domain exception was found.
Enabling incoming mTLS on a Custom Domain does not remove that outbound limit.

- [Outbound mTLS binding and destination limitation](https://developers.cloudflare.com/workers/runtime-apis/bindings/mtls/)
- [Authenticated client-certificate metadata](https://developers.cloudflare.com/ssl/client-certificates/client-certificate-variables/)
- [Incoming hostname setup and verification](https://developers.cloudflare.com/ssl/client-certificates/troubleshooting/)
- [SHA-256 fingerprint format](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha256/)
- [No local simulation of the mTLS binding](https://developers.cloudflare.com/workers/local-development/#mtls)

Accordingly, `prepare-build.mjs --edge` rejects a supplied sealed-ingress mTLS
policy, certificate ID or mTLS binding. The runtime sealed-delivery mapper also
refuses configured mTLS rather than reverting to ordinary `fetch`. It does not
emit an unusable certificate binding or claim certificate exchange was tested.
Do not unset the policy to treat that refusal as production qualification.

A future supported option is a **non-Cloudflare-proxied ingress** with its own TLS
termination and a private authenticated route to core. The edge could then use
the documented outbound certificate binding against that origin. That gateway,
private route and its certificate-validation code do not exist here and need
separate review/qualification. Forwarding a certificate HTTP header to the
current public backend is not a substitute. No gateway is added by this change.

## Backend policy and operator prerequisites

An operator can configure the incoming guard independently, for a real TLS client
that Cloudflare supports. Set all three build inputs for the isolated backend:

```sh
MORSE_SEALED_INGRESS_MTLS=required
MORSE_SEALED_INGRESS_ORIGIN=https://backend.example
MORSE_EDGE_CLIENT_CERT_SHA256=<actual-64-lowercase-hex-leaf-fingerprint>
```

These are public policy values. The origin must be an exact canonical HTTPS
origin (no path, credentials, query, fragment or trailing slash). The fingerprint
is SHA-256 of the DER-encoded client leaf certificate, not a certificate ID,
issuer name or HTTP header. For example, obtain the public fingerprint from the
actual issued certificate with:

```sh
openssl x509 -in edge-client.pem -outform DER | shasum -a 256
```

`isolatedConfig` validates and copies these inputs into backend Worker vars. A
partial policy, an unknown mode (including `off`), or a malformed pin/origin is
rejected; runtime configuration errors also refuse ingress. The entirely absent
policy retains the prior bearer-only development behavior and makes no mTLS
claim. There is no partially configured downgrade. Do not provide a private
client key to the backend or any service container.

Before an actual incoming test, the operator must associate a Worker route or
Custom Domain with the exact hostname, enable client-certificate validation for
that hostname, and configure a real trusted CA / issued client certificate in
the backend account. Client key ownership must remain with the edge operator.
The fingerprint pin must match the actual issued leaf. Cloudflare account/CA
eligibility, certificate issuance, revocation/rotation, live hostname rules and
the separate-account cutover are operator gates. Nothing here provisions them.

With the guard configured, only `POST /v1/ingress/sealed` at that exact origin
can pass. Cloudflare's `request.cf.tlsClientAuth` must contain all of:

- `certPresented === "1"`
- `certVerified === "SUCCESS"`
- `certRevoked === "0"`
- `certFingerprintSHA256` exactly equal to the configured pin

Missing, differently typed, unverified, revoked or mismatched certificate
metadata returns 404 before Directory. The ingress mapper checks again, and the
combined Worker's internal sealed-delivery hop cannot bypass an enabled policy.
No client-supplied `X-CERT-*`, `Client-Cert`, `Client-Cert-Chain` or `CF-*` header
authorizes a request. TLS metadata is never forwarded into the Mesh container.

The body and existing `Authorization: Bearer` credential are still forwarded to
the core's internal sealed route, which retains its independent constant-time
bearer check. A valid certificate does not grant admission without that bearer.
The certificate pin and TLS policy are not added to the container environment.
Credits/postage/administration are outside this sealed-ingress-only change.

## Local qualification boundary

Run from `ops/cloudflare`:

```sh
node --test sealed-ingress-mtls.test.mjs build.test.mjs edge.test.mjs routing.test.mjs
```

The fixtures bundle the production Worker in Miniflare, inject **synthetic**
connection metadata, and verify refusal before Directory, origin/path checks,
header spoof refusal, combined-path refusal, opaque-byte/header preservation,
independent bearer refusal, and build/runtime topology preflight. The CLI
preflight test also checks that an unsupported build leaves existing output
untouched. Local positives establish policy/control-flow behavior, **not an
actual Cloudflare mTLS handshake**. The official binding has no local simulation.
No live certificate exchange or production readiness is claimed.
