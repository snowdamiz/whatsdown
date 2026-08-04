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
| 36 | 4 | `part_count`, 1 through 257 |
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

`POST /v1/attachments/grant` accepts the exact `OGR` bytes. A new grant returns `201`; an exact body replay returns `200`. Both return `OGS`. Reusing an existing object ID with any changed grant body returns `409`.

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

`PUT` uses the upload capability and a raw binary body of 1 through 65,608 bytes. The sum of all unique parts cannot exceed 16,795,830 bytes. This is the exact shared maximum required by the current encodings: `182 + (256 × 65,608) = 16,795,830` for one encrypted backup manifest and 256 maximum-size encrypted backup chunks. The corresponding maximum attachment object is `514 + (256 × 65,576) = 16,787,970` bytes, so it fits below the same bounded ceiling. The first accepted body returns `201`; replaying the exact body returns `200`; replaying the same index with different bytes returns `409`. Oversized parts or totals return `413`.

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

## Storage invariants

SQLite tables are `STRICT`. Object IDs, grant hashes, capability hashes, and content hashes are BLOB values. SQL is fixed and parameterized. Files use the sole leaf-name form `{lowercase_object_id_hex}.{part_index}` beneath a prevalidated storage root. Metadata and errors contain no content descriptors or user identifiers.
