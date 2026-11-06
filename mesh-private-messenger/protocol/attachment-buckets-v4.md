# Padded attachment profile 4

Current development native writers emit AMF4/EAM4/ACH4 for both free and paid
attachments. Every authenticated recipient, including linked devices, must
advertise ACH3 support (mask 2) and padded-reader support (mask 4). There is no
silent fallback for a new write. Deployment and independent review remain
separate from the local native qualification.

## Canonical wire

Integers are unsigned big-endian. AMF4 keeps the field order in
[attachment wire v1](attachment-wire-v1.md), uses version 4, and appends zero
bytes to exactly 446 clear bytes. The encrypted original file size, filename
and MIME type retain their existing validation. Chunk size is 65,536;
`N = ceil(S / 65536)` for original size `S` in 1 through 536,870,912.
Canonical zero padding is checked after authentication.

```text
EAM4 = 04 | "EAM" | attachment_id:32 | nonce:12
       ciphertext_length:u32 = 462 | ciphertext:462
ACH4 = 04 | "ACH" | chunk_index:u32 | nonce:12
       ciphertext_length:u32 = 65552 | ciphertext:65552
```

Every encrypted manifest is 514 bytes and every encrypted chunk is 65,576
bytes. Each clear chunk is 65,536 bytes; the last contains the original nonzero
remainder followed by zeros. The reader authenticates and validates padding
before returning only the original bytes, including a one-byte final remainder.

HKDF-SHA256 uses the attachment secret, attachment ID as salt, and
`mesh-msg/v4/attachment-key` as info. Manifest AAD uses
`mesh-msg/v4/attachment-manifest` and the attachment ID. Chunk AAD is
`UTF8("mesh-msg/v4/attachment-chunk") || SHA256(exact EAM4) || U32BE(index)`.
Fresh independent 12-byte nonces and the existing ChaCha20-Poly1305 primitive
are retained. Version/domain substitution and mixed manifest/chunk profiles
are rejected. EAM1/2 and ACH1/2/3 retain their original reader rules.

## Paid authorization and recovery

Let capacity `B = N * 65536`. New LAG2 keeps the legacy 186-byte field layout
in [paid attachments](paid-attachment-v1.md), with version 2, capacity `B` in
the size field and manifest size 514. LAR2 keeps its 84-byte layout and binds
the versioned request hash, part count and total wire budget
`514 + 65576 * N`. The action quantity is capacity. Because the credit tier
width is an exact multiple of the chunk width, this rounding does not change
the integer credit price for the original size.

The object-store `large_objects.plaintext_size` column contains exact size for
layout 1 and rounded capacity for layout 2. The additive `layout_version`
defaults to 1 for existing rows and comes from the verified grant for new
rows. Typed code calls this value `size_bytes`; capacity is never used as the
exact local file length. Native inventory/download plans take exact output
ranges from the authenticated encrypted manifest. Host parsers explicitly
accept plan version 4 and retain exact attachment-size equality.

Saved LAG1/LAR1 operations keep their exact grants, ciphertext, receipts,
reservations, repair and cancellation semantics. They are never silently
re-encrypted or converted. Deploy compatible directory/core/object readers
before promoting matching native writers and host parsers. HTTP `/v1` free
and `/v2` paid namespaces are independent of the attachment wire version.

## Visibility and qualification

The object service observes 64-KiB capacity intervals and fixed manifest length,
rather than the exact new file length or metadata length. It still sees bucket
count, free/paid route, credit tier, IDs/capabilities, timing, expiry and traffic.
Legacy transfers retain their earlier size leakage. This is not resistance to
traffic analysis or a claim of complete private-field labeling.

The combined candidate builds all five host/mobile targets with the unchanged
163-export ABI. Material tests on iOS Simulator and Android emulator cover
new writes, legacy reads, recipient refusal, restart and authentication. The
actual production ABI also completed funded regtest transfers on both: 257
chunks per object, a one-byte final remainder, exact retries, authenticated
cancellation, and real 600-second maturity/expiry intervals. These are owned
local services and OS custody, not a live-funds, deployed-client-population,
physical attachment-I/O or independent-audit claim.
