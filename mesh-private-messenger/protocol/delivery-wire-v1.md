# Delivery wire v1

The M8 directory and delivery APIs use canonical binary bodies. All records
begin with version `1` and a three-byte magic value; integers are unsigned and
big-endian, and vectors use a `u32` byte length.

| Record | Magic | Fields | Maximum |
|---|---|---|---:|
| Directory lookup | `DLK` | username vector | 72 bytes |
| Directory entry | `DRE` | username, account identity, prekey bundle, 32-byte mailbox token | 33,636 bytes |
| Mailbox fetch | `FET` | 32-byte mailbox token, `u64` cursor | 44 bytes |
| Delivery batch | `BAT` | `u8` count, then `u64` sequence and envelope vector | 524,949 bytes |
| Mailbox acknowledgement | `ACK` | 32-byte mailbox token, `u8` count, 16-byte envelope IDs | 165 bytes |

Directory usernames are 1–64 lowercase ASCII letters, digits, dots,
underscores, or hyphens. Fetch and acknowledgement batches contain at most
eight envelopes. Every delivered envelope is decoded as a canonical
`OuterEnvelope` before it is accepted. Decoders reject unsupported versions,
wrong magic, invalid lengths, oversized input, truncation, and trailing bytes.
