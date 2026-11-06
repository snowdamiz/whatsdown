# Owned native retention qualification

Run from the product checkout:

```sh
MORSE_RETENTION_PROOF_DIR=/absolute/new/evidence-directory \
  python3 scripts/prove-retention-native.py
```

The driver composes the existing real Bitcoin regtest/LND/issuer proof with an
optional test extension. The ordinary issuer driver keeps its previous default
behavior when no extension is supplied. Use a new evidence directory for each
independent qualification; the driver checks any reused compiled core and source
snapshot against recorded hashes.

Both test apps link the exact generated production 162-export ABI and frozen
reader162 libraries retained in the device/account native checkpoints. Swift
uses the real Keychain callbacks; Kotlin uses the real JNI and Android Keystore
callbacks. The driver copies those native inputs and declared protocol/public
package dependencies before compiling its owned backend. It does not rebuild or
replace shared app libraries.

Each app creates and registers a synthetic account through the production native
directory API. A test-only route invokes the normal legacy seal, owned witness,
RFC cutover and issuer-admission functions. Paid requests then pass through an
owned HTTPS ingress whose CA is pinned by the immutable native issuer resource.
The local development directory origin is HTTP. The signup-policy proxy adds 1.1 seconds of real forwarding latency so a signed
policy does not arrive before its issued_at on the emulator clock, which trails
the host by about half a second. Signed freshness verification is unchanged.
The single owned witness is an
explicit fixture, with no operator-independence claim.

The proof buys 100 test credits per platform from the actual LND-backed issuer,
rejects premature retention, and waits at least 600 real seconds. An app restart
at maturity checks durable token custody. It reserves exactly ten credits for a
32-day retention action, rejects a forged core receipt, drops the original
reconciliation response, restarts and recovers the exact saved action. Server
rows prove one effect and no double charge. A second action encounters an owned
503, remains reserved before and after local expiry, rejects a forged signed
cancellation, and restores exactly ten credits only after authenticated core
non-consumption. Terminal recovery performs no HTTP. Both action expiries use
real time; no purchase-time, clock or maturity bypass exists.

The coordinator preserves only public identities, request/response digests,
status/length traces, executable and exact source bodies, public trust resources,
and test app artifacts. Runtime signer environment values, private keys, bearer
capabilities, native wallet databases and raw action/token frames remain in
cleaned temporary directories. Do not archive the full temporary work directory.
No screenshots, screen recording, UI automation or computer-use tools are used.
No live funds, production flags, physical-device, release or whole-plan
qualification is implied. Postage ownership and once-per-request policy are
unchanged.
