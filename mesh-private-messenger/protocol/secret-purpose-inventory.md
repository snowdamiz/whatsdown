# Secret Purpose Inventory, Version 1

This inventory tells protocol implementers which values require Mesh resource
semantics, who owns them, and whether they may survive a restart. It applies to
Cryptographic Profile A, Version 1.

| Purpose | Mesh representation | Owner and lifetime | Persistence |
|---|---|---|---|
| Account authorization private key | `SigningPrivateKey` | Account device; until rotation or revocation | Sealed |
| Device signing private key | `SigningPrivateKey` | Device; until revocation | Sealed |
| Device identity DH private key | `X25519PrivateKey` | Device; until rotation or revocation | Sealed |
| Signed-prekey private key | `X25519PrivateKey` | Device; current key plus the bounded overlap window | Sealed |
| One-time-prekey private key | `X25519PrivateKey` | Device; consumed by one accepted establishment | Sealed until consumed |
| Handshake shared secret | `SecretBytes` | Establishment operation only | Never |
| Ratchet root key | `SecretBytes` | One local session | Sealed in the session snapshot |
| Sending and receiving chain keys | `SecretBytes` | One local session and chain generation | Sealed in the session snapshot |
| Header key | `SecretBytes` | One local session and header-key generation | Sealed in the session snapshot |
| Message key | `SecretBytes` | One message attempt; destroyed after commit or failure | Never |
| Attachment key | `SecretBytes` | One attachment until upload/download completion or expiry | Sealed while work is pending |
| Skipped message key | `SecretBytes` | One session; at most 1,000 keys for at most 7 days | Sealed in the session snapshot |
| HKDF or HMAC intermediate | `SecretBytes` | One derivation call; consumed into a named key or tag | Never |
| Storage wrapping key | `StorageKey` | Platform-backed device capability | Never placed in a Mesh snapshot |

Post-quantum private keys, backup recovery keys, and group sender keys are not
part of Profile A. They must be added to a later version of this inventory
before their implementations land.

Every Profile A private key, shared secret, ratchet key, message key, and
derivation output is exactly 32 bytes. An Ed25519 private key is its 32-byte
RFC 8032 seed. An X25519 private key is the 32-byte RFC 7748 scalar input; the
provider applies clamping during the operation rather than rewriting stored
key material.

Every listed value is actor-owned, bounded, non-printable, non-serializable,
and ineligible for actor messages or unrestricted collections. Temporary
values are destroyed on every success and failure path. Persistent values are
sealed using the storage-wrapping format; ordinary `Bytes` may contain only the
resulting authenticated ciphertext.

Storage wrapping is a privileged runtime operation, not general serialization.
It borrows a live resource directly into the AEAD provider without exposing
plaintext to the Mesh heap. Unsealing authenticates first, validates the exact
32-byte purpose-specific length, and constructs the requested resource kind in
the zeroizing table.

Operational server credentials such as database, TLS, push-provider, and
transparency signing keys are managed by the deployment secret store. They do
not enter messenger protocol values or client snapshots.
