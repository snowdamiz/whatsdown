# Client privacy revision 2

Development protocol; independent cryptographic review is still required.

## Account safety numbers

Each side contributes `account_id[32] || authorization_public_key[32]`.
Sort the two 64-byte values lexicographically, concatenate them after the ASCII
label `mesh-msg/mobile/account-safety/v2`, and display the lowercase hexadecimal
SHA-256 digest. Linked devices share the account authorization key and therefore
the same safety number. Changing either account's key changes the number even
if its account ID stays the same.

The authenticated session record stores the fingerprint. Encrypted self-sync
messages carry it to linked devices. Legacy records without this binding are
unverified and cannot be marked verified until a new handshake establishes the
binding. Old verification flags do not carry over. A changed fingerprint clears
verification and sets the key-change warning.

## Recipient-encrypted initial packets

Initial client packets now use `0x01 || "SIP" || hpke_ciphertext`.
The complete previous `M8P` initial packet (account identity and handshake,
including its public sender credential) is padded and encrypted for the
recipient's authenticated X25519 device identity key using Mesh's RFC 9180
base-mode HPKE: X25519, HKDF-SHA256, ChaCha20-Poly1305.

HPKE info is the ASCII label `mesh-msg/v1/recipient-initial`; associated data
is the recipient's 32-byte public key. Mesh's ciphertext is the 32-byte
encapsulation followed by the authenticated ciphertext. Including the four-byte
`SIP` header, overhead is 52 bytes. The maximum complete packet is 65,536 bytes.
Wrong keys, malformed packets, or failed authentication produce no initial
session. Receivers do not fall back to unencrypted initial packets.

The delivery core can open its separate sealed-delivery wrapper but cannot
open this recipient layer. The inner signed-prekey handshake continues to
authenticate the sender and provide replay protection. The recipient layer
uses a long-lived classical key; it does not claim forward-secret or
post-quantum protection of sender metadata. It does not replace the hybrid
handshake's content protection.

## Encrypted padding

Before encryption, plaintext becomes `length:u32be || plaintext || zeroes`.
Choose the smallest total packet bucket from 256, 512, 1,024, 2,048, 4,096,
8,192, 16,384, 32,768, and 65,536 bytes. Account for the complete packet's
unencrypted headers and encryption overhead when adding zeroes:

| Packet | Overhead outside padded plaintext |
|---|---:|
| Recipient-encrypted initial packet | 52 bytes |
| Ratchet message inside `M8P` | 123 bytes |
| Group message inside `GRP` | 190 bytes |

The length prefix and padding are authenticated and encrypted. Receivers check
the length, minimal bucket, and all-zero padding before committing protocol
state. Maximum new ratchet plaintext is 65,409 bytes; maximum new group
plaintext is 65,342 bytes. Existing application input limits still apply.

New ratchet and group messages carry message version `2`; that version is
included in authenticated associated data (and group signatures). Version `1`
messages remain readable for queued messages and existing history, but new
sends always use version `2`. Group membership-control packets are not padded
by this revision. Ratchet headers and group routing/control metadata are still
visible to delivery; this is not a complete metadata-anonymity protocol.

## Rollout and transport

Update mobile and CLI clients together: old clients cannot open `SIP` initial
packets or version-2 messages. Already queued legacy initial packets are rejected;
establish a fresh session from an updated sender. No silent cleartext fallback
is allowed. Existing encrypted history remains readable.

Mobile service URLs require HTTPS. Debug builds additionally allow HTTP to
localhost, loopback IPs, and RFC 1918 private IPv4 addresses for local testing.
URL credentials, queries, and fragments are rejected. Expo's native fetch is
used with redirects disabled; native prekey requests also disable redirects.
