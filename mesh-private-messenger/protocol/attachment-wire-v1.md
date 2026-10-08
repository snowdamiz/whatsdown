# Attachment Wire Version 1

Attachment wire version `1` is a development profile. It has not received an
independent cryptographic review and must not be represented as production
ready.

The client creates a random 32-byte `SecretBytes` attachment key and a random
32-byte object identifier. The key never leaves an encrypted inner message.
Filename, MIME type, and exact plaintext size are present only in the encrypted
manifest. Object storage receives only the random identifier, encrypted chunks,
their sizes, access timing, and expiry. Version 2 (below) pads every object to
one of 53 size buckets, so those sizes name the bucket and nothing finer;
version 1 objects expose the exact size to within the chunk overhead. Files up
to 16 MiB are free; larger ones, up to 512 MiB, are paid for with credits
("Large files").

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

Version 1 (version 2 is the same frame with the changes in "Version 2"):

```text
version:u8 = 1
tag:3 = "AMF"
object_identifier:32
chunk_size:u32 (1..65,536)
chunk_count:u32 (1..256; version 2: 1..8,192)
plaintext_size:u32
expires_at:u64 (Unix milliseconds)
filename:vector (at most 255 bytes)
mime_type:vector (1..127 bytes)
```

`plaintext_size` must be greater than `(chunk_count - 1) * chunk_size` and no
greater than `chunk_count * chunk_size`. The final chunk therefore has one
canonical nonzero size. The maximum plaintext attachment is 16 MiB in version
1 and 512 MiB in version 2. Hosts move a file one chunk at a time (read from
disk, sealed, uploaded; downloaded, opened, written), so nothing ever holds a
whole large file.

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
index:u32 (0..8,191)
nonce:12
ciphertext:vector (16..65,552 bytes)
```

Non-final plaintext chunks are exactly `chunk_size`; the final plaintext chunk
is exactly the manifest-derived remainder. The maximum encoded encrypted chunk
is 65,576 bytes. All decoders reject oversized input, truncation, unsupported
versions, invalid indices or sizes, and trailing bytes before decryption.

## Version 2: padded objects

Senders create version 2 manifests; receivers read versions 1 and 2, so
attachments sent before padding stay readable until they expire. Only the `AMF`
version byte changes. `EAM` and `ACH` keep version byte 1, and each chunk's
associated data binds the manifest hash, which covers the manifest version.

### Size buckets

The padded size of a file of `n` bytes (1 through 536,870,912) is:

```text
padded(n) = 65,536                         if n <= 65,536
padded(n) = ceil(n / step) * step          otherwise, where
            step = 2^floor(log2(n)) / 4
```

Everything up to one chunk pads to one chunk. Above that there are four steps
per doubling: 80, 96, 112 and 128 KiB, then 160, 192, 224 and 256 KiB, and so
on through 12, 14 and 16 MiB (33 buckets, the free ones), then 20, 24, 28 and
32 MiB and on to 384, 448 and 512 MiB. That is 53 buckets, so an object's size
carries at most about 5.7 bits. The ceilings are themselves buckets, so padding
never pushes a free file past 16 MiB (256 chunks) nor any file past 512 MiB
(8,192 chunks). Every bucket above 256 KiB is a whole number of chunks.

The trade-off, for sizes spread evenly on a log scale between 64 KiB and
16 MiB (the ladder is the same shape at every scale, so the overheads hold to
512 MiB):

| Ladder | Buckets | Bits | Mean overhead | Worst overhead |
|---|---:|---:|---:|---:|
| Powers of two above 64 KiB | 9 | 3.2 | 44% | 100% |
| **Four steps per doubling (version 2)** | **33** | **5.0** | **9.6%** | **25%** |
| 5% geometric ladder | 114 | 6.8 | 2.5% | 5% |

Powers of two hide slightly more but nearly double a large upload on a phone's
data plan. A 5% ladder is cheap but leaves the size known to within 5%, which is
enough to recognize a specific known file, the attack padding exists to stop.
Four steps per doubling costs a tenth on average and never more than a
quarter; below one chunk the cost is at most 64 KiB, which buys every small
file (a voice note, a sticker, a short document) the same size.

### Manifest

A version 2 manifest has `version:u8 = 2`, `chunk_size` exactly 65,536,
`plaintext_size` from 1 through 536,870,912, and
`chunk_count = ceil(padded(plaintext_size) / 65,536)`. After `mime_type` it is
filled with zero bytes to exactly 446 bytes, the version 1 maximum, so every
version 2 `EAM` is exactly 514 bytes and part 0 no longer reveals the length of
the filename or MIME type. Decoders reject any other length, nonzero fill, a
`chunk_count` that isn't the one the bucket implies, or any other chunk size.

### Chunks

The file followed by `padded(plaintext_size) - plaintext_size` zero bytes is
cut into 65,536-byte chunks. Each chunk is sealed at its padded length, so the
last chunk may be partly padding and trailing chunks may be padding alone. The
sender passes only the file's own bytes for each index (none for a chunk of
padding alone) and the seal adds the zeros. The receiver requires the padded
length exactly (`invalid_attachment_chunk_size` otherwise), then requires every
padding byte to be zero (`invalid_attachment_padding` otherwise), and returns
only the file's bytes: nothing for a chunk of padding alone. Hosts upload and
download every chunk, so a transfer's length is the bucket's too.

### What object storage sees

For a bucket of `p` bytes and `c = ceil(p / 65,536)` chunks, the object has
`c + 1` parts: part 0 of 514 bytes, `c - 1` parts of 65,576 bytes, and a last
part of `p - (c - 1) * 65,536 + 40` bytes. Its stored total is
`514 + p + 40c`, from 66,090 bytes for the smallest bucket to 16,787,970 for
16 MiB (the largest free object) and 537,199,106 for 512 MiB. The grant's
`part_count` is `c + 1`, fixed before any upload.

## Large files (over 16 MiB)

A file whose bucket is above 16 MiB costs credits
([credits-v1.md](credits-v1.md#large-files)): one credit for every 16 MiB of
the bucket beyond the first,

```text
credits(n) = ceil(padded(n) / 16,777,216) - 1
```

so 20 through 32 MiB cost 1, 40 and 48 MiB 2, 56 and 64 MiB 3, and 512 MiB 31.
A 40 MB video (40,000,000 bytes) pads to 40 MiB and costs 2. The price follows
the bucket, never the exact size, so paying says no more about the file than
its stored size already does.

The sender's grant is `CRD ‖ OGR` ([opaque-object-wire-v1.md](opaque-object-wire-v1.md#large-objects)):
exactly that many tokens, bound to the grant. The core's prepare call takes the
tokens from the host (the device's credits), refuses a size above the free
ceiling without them (`attachment_credits_required`) and a token count that is
not the price (`invalid_attachment_credits`), and mints the frame around the
grant it made. The object store redeems the frame before it grants anything.

Receivers need no credits and nothing new: a large object is an ordinary
version 2 attachment of more chunks. Builds from before large files refuse a
manifest of more than 256 chunks as `invalid_attachment_manifest` and show the
message without the file.

## Multiple attachments in messages

A message may carry up to ten files of any MIME type, subject to the 512 MiB
per-file limit (credits above 16 MiB) and the encrypted-message size limits. A single attachment retains
its `ATR` reference or `ATG` group-envelope encoding. Multiple attachments use:

```
0x01 | "ATB" | count:u32 | count × (length:u32 | attachment bytes)
```

The count must be 2–10. Empty entries, nested batches, trailing bytes, and
truncated entries are rejected. Direct messages and local history contain `ATR`
entries, each bounded to 1024 bytes; each key is rewrapped for its recipient as
before. Group messages contain `ATG` entries, from which each recipient extracts
its own reference. History exports use the same `ATB` framing around the opened
summaries, preserving selection order in one message. Group albums still fit
within the existing group-message byte ceiling; recipient key wraps count
against that ceiling.

Both clients need a native core and UI that understand `ATB` to exchange albums.
Existing single-file messages remain readable. Failed partial uploads are
removed; once sending starts, objects are retained until expiry because the
native outbox may already contain the message even if delivery reports failure.
