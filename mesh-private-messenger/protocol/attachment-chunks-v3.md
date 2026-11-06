# Attachment chunks v3

Status: retained compatibility profile. Current development free and paid
writers use [padded profile 4](attachment-buckets-v4.md), which retains the
encrypted-manifest commitment introduced here. ACH3 reads and exact saved
operations remain supported. Native rollout and complete private-field labeling
remain separate qualification gates.

ACH3 authenticates a chunk against the exact encrypted manifest carried in its
attachment reference. ACH1/2 derive authenticated data from the clear manifest,
including filename and MIME type. A digest of that private metadata is still a
private value for the plaintext checker. ACH3 instead commits to ciphertext
that has already passed the attachment seal.

## Wire and cryptography

All integers use unsigned big-endian encoding. AMF and EAM retain versions 1
and 2 and their existing formats. Version 3 is accepted only for ACH.

| Offset | Size | Value |
|---|---|---|
| 0 | 1 | Version `3` |
| 1 | 3 | ASCII `ACH` |
| 4 | 4 | Zero-based chunk index |
| 8 | 12 | Fresh AEAD nonce |
| 20 | 4 | Ciphertext length, including the 16-byte tag |
| 24 | Variable | Ciphertext and authentication tag |

The 32-byte key is derived by the existing HKDF-SHA256 primitive with the
attachment secret as input, attachment ID as salt, and UTF-8
`mesh-msg/v3/attachment-key` as info. Authenticated data is:

```
UTF8("mesh-msg/v3/attachment-chunk")
|| SHA256(exact encrypted EAM bytes)
|| U32BE(chunk index)
```

The encrypted manifest must be retained byte-for-byte. Re-encrypting the same
clear metadata produces a different commitment and must fail authentication.
Changing a chunk's index, version, domain, key, nonce or ciphertext must not
make it valid under another attachment.

The parser consumes the entire input, accepts at most 65,576 bytes, and bounds
the ciphertext to 16–65,552 bytes. The reader authenticates the manifest and
checks its declared chunk count and exact expected final-chunk length. EAM1
retains its 256-chunk limit; EAM2 retains its 8,192-chunk and 512 MiB limits.
No whole-file allocation is needed.

## Compatibility and admission

`open_bound_chunk` selects ACH1/2's original authenticated reader for legacy
frames. ACH3 uses the stored EAM bytes and the v3 key/domain. Relabeling an
ACH1/2 frame as ACH3, or the reverse, fails. The native attachment reader uses
this dispatch for both small and paid attachments.

The paid object store accepts bounded ACH2 or ACH3 frames under an EAM2 grant.
It enforces the grant's committed encrypted manifest, part count, index and
byte budget. This is public framing admission; only recipients possess the
key needed to authenticate chunk content.

Legacy `seal_attachment_chunk` and `seal_large_attachment_chunk` retain ACH3
for EAM1 and EAM2; current native preparation selects EAM4/ACH4. ACH3 recipient
support comes from mask `2` in account-signed
credentials and current verified transparency evidence, including linked
devices and every actual group recipient. See
[the authenticated capability upgrade](device-capabilities-v1.md).

Native preflight returns an opaque OS-sealed authorization tied to the account,
selected recipients and release pins. Free-upload requests carry it as field5;
paid preparation carries it as field6 and paid grant submission as field3.
Each operation rechecks current recipients and trust. The final message commit
also compares the captured recipient, membership, custody and other mutable
source rows atomically, before writing any envelope or ratchet update. These
checks do not turn a local reservation into a lock on remote recipient state.

Saved uploads are not converted and payment digests do not change. A pending
grant containing ACH2 parts is refused before HTTP; an uncertain old grant must
recover an authenticated receipt or cancellation before it can progress. A
verified completed grant can repair its exact existing upload. Retries retain
EAM and chunk bytes, references, grants and reservations exactly, and legacy
attachments remain readable.

The manifest sealing helper separates raw encryption from private metadata
admission. It always returns the original encoding error before exposing the
encryption result. Invalid metadata can cause bounded unpublished encryption,
but no encrypted fallback is returned to a caller.

## Evidence and limits

The protocol tests compare the documented wire offsets, KDF and AAD to the raw
public crypto primitives, reject substituted EAMs and mutated frames, and cover
legacy reads plus maximum chunk/index bounds. Native reader tests exercise
account state with a test secure store, HPKE-wrapped attachment keys, EAM1/2
references, actual new writers and explicit legacy fixtures. Recipient tests
reject one legacy linked device, unauthenticated group capability claims,
changed send sources, retained fork evidence and new legacy paid grants.
These local checks do not establish a deployed receiver population, complete
private-field labeling, physical-device performance or independent review.
