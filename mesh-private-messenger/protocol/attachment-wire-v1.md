# Attachment Wire Version 1

Attachment wire version `1` is a development profile. It has not received an
independent cryptographic review and must not be represented as production
ready.

The client creates a random 32-byte `SecretBytes` attachment key and a random
32-byte object identifier. The key never leaves an encrypted inner message.
Filename, MIME type, and exact plaintext size are present only in the encrypted
manifest. Object storage receives only the random identifier, encrypted chunks,
their approximate sizes, access timing, and expiry.

## Key and authentication rules

Manifest and chunk AEAD keys are derived with HKDF-SHA-256 using the object
identifier as salt and the exact ASCII info label
`mesh-msg/v1/attachment-key`. Each value uses an independent 12-byte
operating-system-random nonce. ChaCha20-Poly1305 associated data binds:

- manifests to `mesh-msg/v1/attachment-manifest` and the object identifier;
- chunks to `mesh-msg/v1/attachment-chunk`, the SHA-256 hash of the canonical
  plaintext manifest, and the chunk index.

A changed manifest, chunk index, ciphertext, or tag is rejected without
plaintext output. An object identifier and attachment key pair must never be
reused.

## Plaintext manifest (`AMF`)

```text
version:u8 = 1
tag:3 = "AMF"
object_identifier:32
chunk_size:u32 (1..65,536)
chunk_count:u32 (1..256)
plaintext_size:u32
expires_at:u64 (Unix milliseconds)
filename:vector (at most 255 bytes)
mime_type:vector (1..127 bytes)
```

`plaintext_size` must be greater than `(chunk_count - 1) * chunk_size` and no
greater than `chunk_count * chunk_size`. The final chunk therefore has one
canonical nonzero size. The maximum plaintext attachment is 16 MiB; increasing
that ceiling requires streaming host I/O rather than actor-mailbox byte values.

The maximum encoded plaintext manifest is 446 bytes.

`expires_at` is an absolute Unix timestamp in milliseconds. When the encrypted
attachment is uploaded through opaque object wire v1, the object grant's
`OGR.expires_at` must equal this manifest value exactly; clients must not round,
truncate, extend, or otherwise substitute the storage expiry.

## Encrypted manifest (`EAM`)

```text
version:u8 = 1
tag:3 = "EAM"
object_identifier:32
nonce:12
ciphertext:vector (16..462 bytes)
```

The maximum encoded encrypted manifest is 514 bytes.

## Encrypted chunk (`ACH`)

```text
version:u8 = 1
tag:3 = "ACH"
index:u32 (0..255)
nonce:12
ciphertext:vector (16..65,552 bytes)
```

Non-final plaintext chunks are exactly `chunk_size`; the final plaintext chunk
is exactly the manifest-derived remainder. The maximum encoded encrypted chunk
is 65,576 bytes. All decoders reject oversized input, truncation, unsupported
versions, invalid indices or sizes, and trailing bytes before decryption.
