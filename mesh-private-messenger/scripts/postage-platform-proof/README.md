# Owned dual-native postage proof

```sh
python3 scripts/prove-postage-platform.py --build-only
python3 scripts/prove-postage-platform.py --setup-only --run-name setup-new
python3 scripts/prove-postage-platform.py --run-name paid-new
```

Each run name must be new. `--evidence` and `--compiler` select proof output and
an explicitly pinned compiler. Existing backend/source pairs are verified before
reuse. This driver uses independent reader162 native module bodies and protocol,
public package and directory-service snapshots from the account/device
checkpoints. It copies and hashes the production privacy-edge source before
building. It does not replace installed application libraries.

The test-only Core module creates one externally owned recipient account with
eight legitimately account-signed hybrid devices. It publishes device-signed
one-time and reusable prekeys plus an account-wide one-credit postage policy.
These are external fixture devices, not eight mobile clients; recipient private
keys are ephemeral and no recipient-decryption claim is made. Real native
senders register through the production directory API. Normal seal, witness and
RFC cutover functions admit the real issuer. Native resolution verifies actual
service/witness signatures and inclusion/consistency proofs.

The setup-only stage calls the generated Swift or Kotlin/JNI ABI with real
Keychain/Keystore callbacks. Native fanout creates eight queued ciphertexts.
Ordinary delivery through the actual Mesh privacy edge/Core returns 402, and the
native read-only preview reports one account-wide credit for the complete
recipient device set. No native credit purchase, maturity or spend is claimed by
that stage.

The paid stage buys 100 real regtest Lightning credits per native wallet. The
initial native balances/previews show delayed credits. Both wallets share one
wait of at least 600 real seconds, followed by process restart. A normal fresh
Core checkpoint and registered owned witness are produced after the wait;
native freshness checks remain enabled.

An explicit native prepare reserves exactly one credit for all eight device
envelopes. The exact sealed batch and reply key are durable before submission.
The HTTPS gateway injects a forged encrypted receipt and then drops a real
cached response after Core has committed. Native failure/restart/recovery must
retain the original encrypted batch and token reservation. Work-stamp wrappers
may be refreshed; the authenticated inner PSB must remain identical. A valid
encrypted response verifies the pinned signed Core receipt, completes the same
reservation and acknowledges only its original outbox IDs. Terminal retry makes
no paid HTTP request. SQL checks count two spent credits/effects and sixteen
enqueues across the two native payers.

A distinct message exercises an injected 503 and real action expiry. Local
expiry does not release the reserved credit. Forged encrypted cancellation is
rejected; only the Core's authenticated non-consumption proof restores the one
credit. Its original outbox IDs return to the ordinary queue, and terminal paid
recovery performs no HTTP. No automatic replacement nonce or payment is made
for an unknown outcome.

The owned HTTPS gateway uses an immutable native issuer CA resource. Directory
and ordinary edge origins are explicit development HTTP loopback pins. Runtime
signer secrets, native wallet databases, mailbox capabilities and raw credit
frames must not be archived. Preserve only source bodies, binaries/reports,
public trust resources, digests/statuses and test app artifacts. No screens,
computer-use tools, browser automation, live funds, production enablement,
physical-device or release qualification are involved. These instrumented ABI
calls do not prove rendered confirmation UI acceptance.
