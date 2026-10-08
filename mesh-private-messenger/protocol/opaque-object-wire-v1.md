# Opaque object wire v1

This wire is the shared storage transport for encrypted attachment parts and encrypted backup parts. The service cannot distinguish those uses. Clients encrypt, chunk, and describe content before using this protocol; object storage never receives a filename, MIME type, encryption key, account, device, conversation, or mailbox identifier.

All integers are unsigned, fixed-width, big-endian values. All byte fields have fixed lengths. Every message starts with version byte `0x01` followed by its three-byte ASCII message code. Decoders require the exact canonical length and reject trailing bytes.

## Client material

For every new object, the client independently generates three values with a cryptographically secure random number generator:

- `object_id`: 32 bytes
- `upload_capability`: 32 bytes
- `download_capability`: 32 bytes, different from the upload capability

The object identifier is not a capability. It is encoded as 64 lowercase hexadecimal characters only when placed in an HTTP path. Capabilities are transmitted only in the grant/control bodies or the part request header. The service persists only `SHA-256(upload_capability)` and `SHA-256(download_capability)` and performs exact constant-time hash comparisons.

## Grant request (`OGR`, 124 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | version `0x01` |
| 1 | 3 | ASCII `OGR` |
| 4 | 32 | `object_id` |
| 36 | 4 | `part_count`, 1 through 8,193 (above 257 only as a paid large object) |
| 40 | 8 | `expires_at`, Unix milliseconds |
| 48 | 8 | `work_expires_at`, Unix milliseconds |
| 56 | 4 | proof-of-work `nonce` |
| 60 | 32 | `upload_capability` |
| 92 | 32 | `download_capability` |

The object expiry must be strictly in the future and no more than seven days in the future. The work expiry must be current and no more than five minutes in the future. At `now >= expires_at`, object operations return expired and the purge worker may delete the object.

The proof-of-work digest is:

```text
SHA-256(
  UTF8("mesh-msg/v1/object-grant-work") ||
  object_id ||
  u64be(work_expires_at) ||
  u32be(nonce) ||
  u32be(part_count) ||
  u64be(expires_at) ||
  SHA-256(upload_capability) ||
  SHA-256(download_capability)
)
```

The configured difficulty is 1 through 24 and means that many leading zero bits in the digest. The grant is anonymous: the proof contains no account, device, mailbox, conversation, or network identity field.

`POST /v1/attachments/grant` accepts the exact `OGR` bytes, or `CRD ‖ OGR` for a large object (below). A new grant returns `201`; an exact body replay returns `200`. Both return `OGS`. Reusing an existing object ID with any changed grant body returns `409`.

## Grant response (`OGS`, 36 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | version `0x01` |
| 1 | 3 | ASCII `OGS` |
| 4 | 32 | echoed `object_id` |

The response echoes the client-generated identifier; the server does not mint or replace it.

## Part transfer

Part indices are canonical decimal integers from 0 through `part_count - 1`, with no signs or leading zeroes. Object IDs in paths are exactly 64 lowercase hexadecimal characters.

```text
PUT /v1/objects/{object_id}/parts/{part_index}
GET /v1/objects/{object_id}/parts/{part_index}
X-Object-Capability: {64 lowercase hex characters}
```

`PUT` uses the upload capability and a raw binary body of 1 through 65,608 bytes. The sum of all unique parts of an object of up to 257 parts cannot exceed 16,795,830 bytes (large objects: below). This is the exact shared maximum required by the current encodings: `182 + (256 × 65,608) = 16,795,830` for one encrypted backup manifest and 256 maximum-size encrypted backup chunks. The corresponding maximum attachment object is `514 + (256 × 65,576) = 16,787,970` bytes, so it fits below the same bounded ceiling. The first accepted body returns `201`; replaying the exact body returns `200`; replaying the same index with different bytes returns `409`. Oversized parts or totals return `413`.

`GET` uses the download capability and returns the exact raw binary part only after completion. Capability failure returns `403`. Part hashes and file lengths are checked before bytes are returned.

## Completion (`OCP`, 68 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | version `0x01` |
| 1 | 3 | ASCII `OCP` |
| 4 | 32 | `object_id` |
| 36 | 32 | `upload_capability` |

`POST /v1/attachments/complete` accepts `OCP`. It returns `200` only when metadata and files exist for every index from zero through `part_count - 1`; otherwise it returns `409`. Repeating completion is idempotent and returns `200`.

## Deletion (`ODL`, 68 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | version `0x01` |
| 1 | 3 | ASCII `ODL` |
| 4 | 32 | `object_id` |
| 36 | 32 | `upload_capability` |

`POST /v1/attachments/delete` accepts `ODL`. An authorized deletion removes every bounded part and its metadata and returns `204`. A wrong capability returns `403`.

## Large objects

An object of more than 257 parts is an attachment above 16 MiB
([attachment-wire-v1.md](attachment-wire-v1.md#large-files-over-16-mib)), and
credits pay for it ([credits-v1.md](credits-v1.md#large-files)). Its
`part_count` is `c + 1` for a padded bucket of `c` whole chunks, 320 (20 MiB)
through 8,192 (512 MiB): `(part_count - 1) × 65,536` must be a bucket, so no
other size can be stored. It costs `ceil((part_count - 1) / 256) - 1` credits,
1 for 321 parts, 2 for 641, 31 for 8,193.

Its grant request is a `CRD` frame in front of the `OGR`
([credits-v1.md](credits-v1.md#spending-the-crd-frame)): at least that many
tokens, bound to exactly these 124 bytes. The proof of work is still required.
For a new object ID the store checks the frame and the work, then posts
`RDQ(action 4, CRD)` to the core's redeem route and grants only on its `201`:

| Status | Meaning |
|---|---|
| `201` / `200` | granted / an exact replay of a granted `OGR`, answered from the store without redeeming again (with or without its frame) |
| `400` | malformed, a frame not bound to the `OGR` that follows it, or a part count above 257 that is not a bucket |
| `402` | no `CRD` frame, or fewer tokens than the price; nothing is redeemed |
| `403` | this store redeems no credits (the core's credits are off, or the store has no core to ask) |
| `409` | a token of the frame was spent before (the core's answer), or a changed grant for an existing object ID; nothing of the frame is spent |
| `422` | a token is not a credit |
| `429` | missing, stale or short work |
| `503` | the core could not be asked or failed; the frame may or may not be spent |

Up to 257 parts nothing changes: no frame is needed, and a frame sent anyway is
neither checked against the core nor spent. The store redeems before it writes
the grant, inside the grant's transaction, so a failure after a `201` from the
core leaves the tokens spent and the object ungranted (a `500`).

A large object's parts have one size each: part 0 exactly 514 bytes, every
other part exactly 65,576 (`400` otherwise), so its total is exactly
`514 + 65,576 × (part_count - 1)`, 537,199,106 bytes at most. Completion checks
that every part is stored at that total; it does not read the parts back (a
download checks each part's hash before serving it). Part indices in paths run
0 through 8,192. The lifetime is the same seven days at most as any object.
Deleting or expiring a large object removes all its parts in one storage
request.

## Storage invariants

SQLite tables are `STRICT`. Object IDs, grant hashes, capability hashes, and content hashes are BLOB values. SQL is fixed and parameterized. Files use the sole leaf-name form `{lowercase_object_id_hex}.{part_index}` beneath a prevalidated storage root. Metadata and errors contain no content descriptors or user identifiers.
