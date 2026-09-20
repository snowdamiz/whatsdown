# Cryptographic Profile A, Version 1

- Profile identifier: `mesh-msg/profile-a/v1`
- Protocol version: `1`
- Suite identifier: `0x0001`

> This is a development profile for the classical encrypted-envelope vertical
> slice. It has not received independent cryptographic review and must not be
> represented as independently audited. Release candidates require internal
> verification of the exact revision and applicable platform evidence.

## Primitive suite

| Purpose | Profile A selection |
|---|---|
| Hash | SHA-256; 32-byte binary digest |
| Message authentication | HMAC-SHA-256; 32-byte tag |
| Key derivation | HKDF-SHA-256 |
| Key agreement | X25519; 32-byte public keys and shared secrets |
| Device and account credentials | Ed25519; 32-byte public keys and 64-byte signatures |
| Authenticated encryption | ChaCha20-Poly1305; 32-byte key, 12-byte nonce, 16-byte tag |
| Randomness | Operating-system CSPRNG only |
| Initial establishment | Classical asynchronous signed-prekey handshake |
| Ongoing session | Classical Double Ratchet |

Private keys, root keys, chain keys, message keys, and HKDF/HMAC outputs use
secret or resource types. Ordinary `Bytes` is limited to public keys,
signatures, nonces, associated data, ciphertext, and public protocol fields.
Deterministic providers and secret revelation are test-build-only.

The all-zero X25519 shared result is invalid. AEAD key and nonce lengths are
checked exactly; nonce/key pairs are never reused. Authentication failure
returns no plaintext and leaves committed protocol state unchanged.

## Domain separation

The following ASCII labels are protocol constants and are included exactly in
their corresponding derivations:

```text
mesh-msg/v1/account-credential
mesh-msg/v1/device-credential
mesh-msg/v1/handshake
mesh-msg/v1/root-key
mesh-msg/v1/sending-chain
mesh-msg/v1/receiving-chain
mesh-msg/v1/message-key
mesh-msg/v1/initial-message
mesh-msg/v1/header-key
mesh-msg/v1/attachment-key
mesh-msg/v1/storage-wrap
mesh-msg/v1/transparency-leaf
```

These exact ASCII bytes are part of the published protocol. A label for one
purpose must never be reused for another purpose.

## Development limits

These limits are part of Profile A and are enforced before expensive work:

| Limit | Value |
|---|---:|
| Padded ciphertext bucket | At most 65,536 bytes |
| Padding buckets | 256, 512, 1,024, 2,048, 4,096, 8,192, 16,384, 32,768, 65,536 bytes |
| Skipped message keys per session | 64, shared by every receiving chain |
| Message-number jump | 64 within a chain; 64 remaining in the previous chain plus 64 in a new chain |
| Initial messages consuming one one-time prekey | 1 |
| Initial messages accepted through the reusable last-resort prekey | Unbounded; each transcript accepted once (newest 1,024 remembered) |

The 64-key bound matches the 64-envelope mailbox capacity: a larger gap cannot
be queued for one device at a time. A message that would exceed it returns
`ExcessiveJump` without changing session state.

Not yet enforced, and therefore not claimed: skipped keys do not expire by age
and are not evicted per receiving chain, so a skipped key persists until its
message arrives or the session is replaced; signed prekeys are issued with the
device credential's one-year lifetime and are not rotated. Both are tracked as
hardening work. Earlier revisions of this table stated 1,000-key limits, a
five-chain and seven-day skipped-key policy, a two-session cap, and a seven-day
signed-prekey lifetime that the implementation never had.

Content that does not fit the 64 KiB ciphertext bucket uses encrypted
attachments. Decoders also enforce canonical integer widths, bounded vectors
and nesting, no duplicate fields, no trailing bytes, and rejection of unknown
mandatory extensions. Exceeding a ratchet limit returns a typed error and
requires session recovery.

## Authenticated negotiation

Protocol version and suite identifier appear in canonical transcripts and AEAD
associated data. Credentials and prekey bundles advertise supported suites.
Devices remember the strongest suite previously observed for a remote device;
a lower suite then fails as a downgrade instead of silently falling back.
Unsupported higher suites fail explicitly.

## Outside Profile A

Suite `0x0002` is the experimental hybrid Profile B defined in
[`hybrid-handshake-v1.md`](hybrid-handshake-v1.md). It is implemented for
interoperability and performance testing and is reachable in the application.
Release readiness uses the internal criteria in the security plan. Independent
cryptographic review has not been recorded and is not a release prerequisite.
