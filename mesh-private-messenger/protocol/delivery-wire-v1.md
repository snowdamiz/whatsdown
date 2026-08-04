# Delivery wire v1

The M8 directory and delivery APIs use canonical binary bodies. All records
begin with version `1` and a three-byte magic value; integers are unsigned and
big-endian, and vectors use a `u32` byte length.

| Record | Magic | Fields | Maximum |
|---|---|---|---:|
| Directory lookup | `DLK` | username vector | 72 bytes |
| Directory entry | `DRE` | username, account identity, prekey bundle, 32-byte mailbox token | 36,006 bytes |
| Mailbox fetch | `FET` | 32-byte mailbox token, `u64` cursor | 44 bytes |
| Delivery batch | `BAT` | `u8` count, then `u64` sequence and envelope vector | 524,949 bytes |
| Mailbox acknowledgement | `ACK` | 32-byte mailbox token, `u8` count, 16-byte envelope IDs | 165 bytes |

Directory usernames are 1–64 lowercase ASCII letters, digits, dots,
underscores, or hyphens. Fetch and acknowledgement batches contain at most
eight envelopes. Every delivered envelope is decoded as a canonical
`OuterEnvelope` before it is accepted. Decoders reject unsupported versions,
wrong magic, invalid lengths, oversized input, truncation, and trailing bytes.
The server-visible `u16` suite is `1` for classical direct messages, `2` for
hybrid direct messages, or development-only `3` for group commits, welcomes,
and messages.

Mobile batch processing may return empty bytes instead of an `ACK` when every
suite-3 envelope is retryable (for example, a message for a future epoch whose
commit has not arrived). The client must skip the acknowledgement request in
that case. A mixed batch contains only the IDs that were durably applied or
classified as permanent poison; retryable IDs remain absent for redelivery.
