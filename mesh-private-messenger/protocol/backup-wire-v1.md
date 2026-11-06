# Encrypted Backup Wire v1

Backup v1 is an opt-in client-side format. The service may store the sealed
manifest and chunks, but it never receives the recovery secret, derived key,
plaintext state, or plaintext history.

## Recovery profile

Version 1 has one fixed profile:

| Field | Value |
|---|---:|
| Salt | 16 random bytes |
| KDF | Argon2id v1.3 |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 1 |
| Output | 32 secret bytes |

The Argon2 salt input is the ASCII domain `mesh-msg/v1/backup-key` followed by
the stored random salt. Decoders reject any changed parameter. A future profile
requires a new version; implementations must not silently weaken version 1.

## User-held recovery code

The development `Backups.Recovery` adapter calls public Mesh
`RecoveryCode.generate()` to create a new 256-bit opaque recovery secret and
its display String. `RecoveryCode.parse()` restores the opaque owner from the
canonical user-held code. Generation cannot export an existing key. The code
is `MRC1-` followed by nine groups of eight uppercase hexadecimal digits:
eight encode the secret and the last is a 32-bit transcription checksum.
The checksum is not authentication or proof of sufficient entropy; generation
uses operating-system randomness, while a caller can construct a chosen code.

The String deliberately discloses recovery material. The eventual setup UI must
show it only during creation, require acknowledgement and clear its references;
it must never log, persist or upload the code. String/JS/native copies cannot
promise prompt memory erasure. Parsing the code and decrypting an archive do not
authorize an account or a device. The fixed Argon2id profile above is unchanged.

Host dogfood generates a code, seals a real manifest/chunk, destroys the original
secret owners, imports the code and authenticates the backup. Wrong valid codes
fail manifest authentication and malformed codes fail import; correct retries
remain usable. The existing tamper/index/size/KDF tests also pass. The public
Mesh source and two Morse adapter/test files are adopted in
`.morse/d4-recovery-code-adoption-v1/result.json`. The additive
[portable text-archive codecs](backup-text-archive-v1.md) now provide bounded
payload and file framing. Guarded core export/import, UI, native and release
qualification remain unfinished. Raw local SQLite rows and active protocol,
nonce, prekey or financial state are not a portable backup payload.

## Sealed manifest

The canonical wrapper is:

```text
u8 version = 1
3 bytes "EBM"
u8 profile_version = 1
16 bytes salt
u32 memory_kib = 65536
u32 iterations = 3
u8 parallelism = 1
32 bytes backup_id
12 bytes random nonce
vector ciphertext (exactly 104 bytes)
```

The encrypted 88-byte manifest contains `BMF`, the backup ID, creation time,
chunk size/count, total plaintext size, and SHA-256 of the complete plaintext
snapshot. Manifest encryption derives a subkey with HKDF-SHA-256 and
`mesh-msg/v1/backup-manifest`; the clear profile and backup ID are authenticated
as associated data. The complete wrapper is exactly 182 bytes.

## Sealed chunks

```text
u8 version = 1
3 bytes "BCH"
32 bytes backup_id
u32 chunk_index
12 bytes random nonce
vector ciphertext
```

Chunks use the `mesh-msg/v1/backup-chunk` HKDF label. Their associated data
binds the canonical manifest hash and chunk index. Chunks are at most 65,536
plaintext bytes; a backup has at most 256 chunks and 16 MiB plaintext. Wrong
keys, changed manifests, reordered chunks, truncation, oversized vectors, and
trailing bytes fail closed.

A maximum plaintext chunk seals to 65,552 ciphertext bytes, and its complete
`BCH` wrapper is therefore at most 65,608 bytes.

The clear framing exposes the KDF profile and salt, backup ID, nonces, chunk
indices and ciphertext lengths. Subtracting each fixed 16-byte authentication
tag reveals that chunk's plaintext byte length and, across all chunks, the
total payload byte length. Backup v1 does not pad those lengths. Record counts,
names, text and the snapshot hash remain inside the encrypted payload or
manifest.

The snapshot hash is checked only after every authenticated chunk has been
reassembled. A successful cryptographic restore does not itself recover account
access or authorize a new device; those are separate product operations.
