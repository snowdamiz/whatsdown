# Secret Purpose Inventory, Version 1

This inventory tells protocol implementers which values require Mesh resource
semantics, who owns them, and whether they may survive a restart. It applies to
the version 1 classical and experimental hybrid profiles.

| Purpose | Mesh representation | Owner and lifetime | Persistence |
|---|---|---|---|
| Account authorization private key | `SigningPrivateKey` | Account device; until rotation or revocation | Sealed |
| Device signing private key | `SigningPrivateKey` | Device; until revocation | Sealed |
| Device identity DH private key | `X25519PrivateKey` | Device; until rotation or revocation | Sealed |
| Signed-prekey private key | `X25519PrivateKey` | Device; replaced with each renewal, ninety days into its one-year life, then kept until 35 days after the verified device set shows its successor; at most sixteen replaced bundles | Sealed until destroyed |
| One-time-prekey private key | `X25519PrivateKey` | Device; consumed by one accepted establishment. A session reset makes one it hands the peer inside the session instead of publishing it ([`session-reset-v1.md`](session-reset-v1.md)); it lives in the same pool | Sealed until consumed |
| Last-resort-prekey private key | `X25519PrivateKey` | Device; handed out for a week, then kept until 35 days after the directory confirms its replacement; at most sixteen replaced keys | Sealed until destroyed |
| Post-quantum prekey seed | `MlKemPrivateKey` | Device; replaced with each renewal of its credential, then kept as long as the signed prekey it was renewed with | Sealed until destroyed |
| ML-KEM shared secret | `SecretBytes` | Hybrid establishment operation only (the post-quantum ratchet's secret is its own row) | Never |
| Handshake shared secret | `SecretBytes` | Establishment operation only | Never |
| Ratchet root key | `SecretBytes` | One local session | Sealed in the session snapshot |
| Sending and receiving chain keys | `SecretBytes` | One local session and chain generation | Sealed in the session snapshot |
| Header key | `SecretBytes` in the session's header-key map, by role (`send`, `next-send`, `receive`, `next-receive`) | One local session, from the version 4 upgrade or the root step two before its chain; replaced at each root step ([`ratchet-message-v2.md`](ratchet-message-v2.md)) | Sealed in the session snapshot, storage purpose `4`, one slot a role |
| Earlier chain's header key | `SecretBytes` in the header-key map, under the chain's ratchet key | One session; until that chain's last skipped message key goes, at most eight | Sealed in the session snapshot as a `SecretMap`, purpose `12`, slot `header-keys` |
| Post-quantum ratchet seed | `SecretBytes` (32 bytes; the ML-KEM-768 key pair is derived from it when needed) | The owner of one epoch, until it decapsulates that epoch's ciphertext | Sealed in the session snapshot as a `SecretMap`, purpose `12`, slot `pq` |
| Post-quantum ratchet secret | `SecretBytes` | One epoch, from encapsulation or decapsulation until the root step that mixes it | Sealed in the same `pq` map |
| Message key | `SecretBytes` | One message attempt; destroyed after commit or failure | Never |
| Group epoch secret | `SecretBytes` | One local group state and epoch | Sealed in the group snapshot |
| Group TreeKEM leaf and parent private keys | `X25519PrivateKey` | One local group state; replaced when its path is updated | Sealed in the group snapshot |
| Group sender signing private key | `SigningPrivateKey` | One device, group and epoch: made at the device's first deniable message of the epoch, replaced by the next epoch's, deleted when the group is forgotten ([`mls-groups-v1.md`](mls-groups-v1.md#deniable-sender-authentication)) | Sealed, purpose `7`, in `group-signing/v1/<group>` |
| Attachment key | `SecretBytes` | One attachment until upload/download completion or expiry | Sealed while work is pending |
| Backup recovery secret | 32 random bytes the user holds (imported as `SecretBytes` only to derive) | Until backups are turned off or on again | Never uploaded or stored; shown once, as 52 characters, and typed back ([backup-wire-v1.md](backup-wire-v1.md#the-recovery-code)) |
| Derived backup content key | `SecretBytes` | While backups are on, or during one restore | Sealed on the device under purpose `5` (`backup-key/v1`, `backup-restore-key/v1`); never uploaded |
| Backup account-key storage key | `StorageKey` from `StorageKey.from_secret` | One backup or one restore | Never stored; derived again from the content key. Seals the account authorization key (purpose `6`) into backups made on the device that holds it |
| Skipped message key | `SecretBytes` | One session; at most 64 keys, each until its message arrives, five further receiving chains begin, or newer keys push it out | Sealed in the session snapshot |
| HKDF or HMAC intermediate | `SecretBytes` | One derivation call; consumed into a named key or tag | Never |
| Storage wrapping key | `StorageKey` | Platform-backed device capability | Never placed in a Mesh snapshot |
| Local label key | 32 bytes of local data, held as `Bytes` while one storage call runs: HMAC over `SecretBytes` gives `SecretBytes`, which Mesh can't make into a row ID | One device database; made with it, or on the move to [local record format 2](storage-wrapping-v1.md#local-record-format-2), and never replaced | Sealed under the storage wrapping key as purpose `14` (local data), object `SHA-256("storage-label-key/v1")`, in the database's `storage_label_key` table; never in a backup, which is written through the storage API under the restoring device's own key |
| Transparency signing key | `SigningPrivateKey` | Directory request transaction | Deployment secret only |
| Delivery sealing private key | `X25519PrivateKey` | Sealed-delivery request | Deployment secret only |
| OHTTP gateway private key | `X25519PrivateKey` | One Oblivious HTTP request at the directory ([ohttp-v1.md](ohttp-v1.md)); a current and a retiring key, by key id | Deployment secret only (`MESSENGER_OHTTP_GATEWAY_SEED_HEX`, `MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX`) |
| OHTTP response secret | `SecretBytes` (32 bytes exported from the request's HPKE context) | One request, until its answer is opened; the gateway destroys its copy after encapsulating the answer | Handed to the app between request and answer as a blob sealed under purpose `5`, label `ohttp-response-key/v1/<hex enc>`; never stored |
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
The local label key is the exception: it is opened into `Bytes`, like any
local-data record, for the one storage call that needs it, because its HMAC
outputs are public row IDs and Mesh has no way to release a `SecretBytes` result
as `Bytes`. A runtime `StorageKey` operation that computes the row ID would end
the exception.

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
