# Secret Purpose Inventory, Version 1

This inventory tells protocol implementers which values require Mesh resource
semantics, who owns them, and whether they may survive a restart. It applies to
the version 1 classical and experimental hybrid profiles.

| Purpose | Mesh representation | Owner and lifetime | Persistence |
|---|---|---|---|
| Account authorization private key | `SigningPrivateKey` | Account device; until rotation or revocation | Sealed |
| Device signing private key | `SigningPrivateKey` | Device; until revocation | Sealed |
| Device identity DH private key | `X25519PrivateKey` | Device; until rotation or revocation | Sealed |
| Signed-prekey private key | `X25519PrivateKey` | Device; current key plus the bounded overlap window | Sealed |
| One-time-prekey private key | `X25519PrivateKey` | Device; consumed by one accepted establishment | Sealed until consumed |
| Post-quantum prekey seed | `MlKemPrivateKey` | Device; current hybrid prekey | Sealed |
| ML-KEM shared secret | `SecretBytes` | Hybrid establishment operation only | Never |
| Handshake shared secret | `SecretBytes` | Establishment operation only | Never |
| Ratchet root key | `SecretBytes` | One local session | Sealed in the session snapshot |
| Sending and receiving chain keys | `SecretBytes` | One local session and chain generation | Sealed in the session snapshot |
| Header key | `SecretBytes` | One local session and header-key generation | Sealed in the session snapshot |
| Message key | `SecretBytes` | One message attempt; destroyed after commit or failure | Never |
| Group epoch secret | `SecretBytes` | One local group state and epoch | Sealed in the group snapshot |
| Group TreeKEM leaf and parent private keys | `X25519PrivateKey` | One local group state; replaced when its path is updated | Sealed in the group snapshot |
| Attachment key | `SecretBytes` | One attachment until upload/download completion or expiry | Sealed while work is pending |
| Backup recovery secret | `SecretBytes` | User-held recovery capability; until its backup is retired or replaced | Never uploaded or stored in an app snapshot; user-controlled export is not yet integrated |
| Derived backup content key | `SecretBytes` | One backup creation or restore operation | Never; re-derived from the recovery secret and versioned profile |
| Skipped message key | `SecretBytes` | One session; at most 1,000 keys for at most 7 days | Sealed in the session snapshot |
| HKDF or HMAC intermediate | `SecretBytes` | One derivation call; consumed into a named key or tag | Never |
| Storage wrapping key | `StorageKey` | Platform-backed device capability | Never placed in a Mesh snapshot |
| Transparency signing key | `SigningPrivateKey` | Directory request transaction | Deployment secret only |
| Delivery sealing private key | `X25519PrivateKey` | Sealed-delivery request | Deployment secret only |
| Push broker private key | `X25519PrivateKey` | HTTP request or broker worker actor | Deployment secret only |
| Witness signing key | `SigningPrivateKey` | One witness run | Deployment secret only |

Every private key, shared secret, ratchet key, message key, and derivation
output is exactly 32 bytes except the 64-byte ML-KEM-768 seed. An Ed25519
private key is its 32-byte RFC 8032 seed. An X25519 private key is the 32-byte
RFC 7748 scalar input; the provider applies clamping during the operation
rather than rewriting stored key material.

Every listed value is actor-owned, bounded, non-printable, non-serializable,
and ineligible for actor messages or unrestricted collections. Temporary
values are destroyed on every success and failure path. Persistent values are
sealed using the storage-wrapping format; ordinary `Bytes` may contain only the
resulting authenticated ciphertext.

Storage wrapping is a privileged runtime operation, not general serialization.
It borrows a live resource directly into the AEAD provider without exposing
plaintext to the Mesh heap. Unsealing authenticates first, validates the exact
purpose-specific length, and constructs the requested resource kind in the
zeroizing table.

Server private-key environment values are ingested with `Env.get_secret_hex`
directly into `SecretBytes`, then consumed into the private-key resource in the
same actor. They never become Mesh `String` or `Bytes` values and never cross
actor messages. Other operational credentials such as database, TLS, and
push-provider tokens remain managed by the deployment secret store; they do
not enter messenger protocol values or client snapshots.
