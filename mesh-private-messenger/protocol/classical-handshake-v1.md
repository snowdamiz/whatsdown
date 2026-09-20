# Classical Handshake, Version 1

Profile A uses the four X25519 calculations and asynchronous prekey roles from
the [X3DH specification](https://signal.org/docs/specifications/x3dh/), adapted
to Morse's separate Ed25519 credential key and X25519 device identity key.
This is a development construction pending independent protocol review.

## Published bundle

The canonical bundle binds protocol and suite `1`, the canonical signed device
credential, device signing and identity-DH public keys, a nonzero signed-prekey
ID and public key, its Ed25519 signature and expiration, and a nonzero one-time
prekey ID and public key. The signed-prekey statement is:

```text
"mesh-msg/v1/signed-prekey" ||
u16(version) || u16(suite) || account_id || device_id ||
u64(signed_prekey_id) || signed_prekey_public || u64(expires_at)
```

Profile A initial messages require a prekey in the one-time slot. Bundle fetch
and claim must be atomic at the directory; an accepted or rejected receive
attempt burns the locally claimed private one-time prekey.

When a device's one-time pool is empty the directory fills that slot with the
device's reusable last-resort prekey instead of refusing the claim, so draining
a pool cannot stop new sessions. The handshake is unchanged and the initiator
cannot tell the difference. The responder keeps that secret after use, and
because it is also the responder's first ratchet key, forward secrecy for such a
session's first chain rests on the last-resort key until the first Diffie-Hellman
ratchet step, exactly as it rests on the signed prekey in X3DH without a
one-time key. The responder therefore remembers the transcript hash of every
first message that used the key (the newest 1,024) and permanently refuses a
repeat, which a deleted one-time secret makes impossible by itself.

Device credential signatures cover the exact bytes
`"mesh-msg/v1/device-credential" || canonical_unsigned_credential`, where the
unsigned encoding retains the 64-byte signature field filled with zeroes.
Verification also requires an explicit current Unix-millisecond time and the
caller's minimum observed directory sequence. Credentials created in the
future, expired credentials or bundles, and account or credential sequence
rollback are rejected before key agreement.

## Agreement and derivation

The initiator verifies the account-signed device credential and signed prekey,
then generates a fresh ephemeral X25519 key. Both peers calculate, in this exact
order:

```text
DH1 = DH(initiator identity, responder signed prekey)
DH2 = DH(initiator ephemeral, responder identity)
DH3 = DH(initiator ephemeral, responder signed prekey)
DH4 = DH(initiator ephemeral, responder one-time prekey)
IKM = DH1 || DH2 || DH3 || DH4
```

`Secret.concat` assembles IKM inside the actor-owned secret table; no DH output
enters ordinary `Bytes`. The canonical handshake transcript binds both
credential/bundle hashes, both prekey IDs and keys, the selected suite, and the
initiator ephemeral key. Then:

```text
transcript_hash = SHA-256(canonical_transcript)
salt = SHA-256("mesh-msg/v1/handshake" || transcript_hash)
root_key = HKDF-SHA256(IKM, salt, "mesh-msg/v1/root-key", 32)
initial_key = HKDF-SHA256(IKM, salt, "mesh-msg/v1/initial-message", 32)
```

The initial plaintext is sealed with ChaCha20-Poly1305 under `initial_key`, a
fresh 12-byte CSPRNG nonce, and `transcript_hash` as associated data. IKM and
the initial AEAD key are destroyed after use. Initial plaintext is limited to
65,171 bytes so the ciphertext and complete canonical initial message fit the
65,536-byte wire ceiling.

## Failure and replay behavior

- Unsupported suites, invalid credentials/signatures, mismatched public keys,
  stale directory state, IDs, transcripts, lengths, or authentication tags
  create no session.
- Candidate roots and message keys are automatically dropped on every error.
- A consumed one-time-prekey resource cannot be reused; replay therefore fails
  before a second session can be created.
- The responder creates a fresh local ratchet key after authenticating the
  initial ciphertext. Ratchet sending must mix it into the root before the
  responder emits ciphertext, matching X3DH's replay/key-reuse guidance.
