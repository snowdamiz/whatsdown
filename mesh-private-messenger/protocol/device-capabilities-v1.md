# Device capabilities and authenticated reader upgrades

Device capabilities are public, account-signed fields of `DeviceCredential`.
The existing baseline mask is `0x00000001`; ACH3 bound attachment chunks use
`0x00000002`; padded EAM4/ACH4 readers use `0x00000004`. The adopted development C4/D3
profile adds HE `0x00000008` and timed group-message readers `0x00000010`.
Its new mobile account credentials and new device-link requests advertise `31`;
the text-only Mesh CLI advertises `9` (baseline + HE). Historical C4-only mobile
credentials advertised `15`, while the earlier attachment reader mask was `7`.
A retained link request keeps its exact original mask and bytes. These
masks do not establish release or deployed backend compatibility.

`Protocol.Capabilities.supports_ach3(capabilities)` tests only mask `2`, retaining
full unsigned precision; `supports_attachment_buckets` tests mask `4`,
`supports_header_encryption` mask `8`, and `supports_group_expiry` mask `16`.
These helpers authenticate nothing. Senders rely on the
credential only after verifying its account signature, bundle, current device
set and transparency evidence. Host flags, pending renewal requests and group
extensions do not establish recipient support. New attachments require support
for both attachment bits from every actual recipient device, including the
sender's linked devices.

HE admission separately requires mask `8` on every actual current authenticated
peer/own-device target before sending or reserving prekeys. A timed group send
requires mask `16` on its current authenticated group readers. Neither policy
allows an unsupported device to be inferred capable. See
[header encryption](header-encryption-v1.md) for wire/routing/legacy behavior.

Existing devices upgrade through a device-signed request followed by an
account-signed credential. The account key must not infer that a linked device
supports a new format. The primary device uses the same two-phase process when
its own current credential lacks any of the current reader bits.

## Renewal request wire

RNWv1 remains exactly **1,412 bytes**. Its canonical bytes and signing domain are
unchanged. It requests new keys and preserves the previous capability mask.
RNWv2 is **1,416 bytes** and additionally signs the requested capability mask.
Integers use big-endian encoding; expiry is Unix milliseconds.

| Field | Offset | Length |
| --- | ---: | ---: |
| Version (`1` or `2`) | 0 | 1 |
| ASCII `RNW` | 1 | 3 |
| Account ID | 4 | 32 |
| Device ID | 36 | 16 |
| Next signed-prekey ID, u64 | 52 | 8 |
| Next signed prekey | 60 | 32 |
| Expiry, u64 | 92 | 8 |
| Signed-prekey signature | 100 | 64 |
| Next ML-KEM prekey | 164 | 1,184 |
| Requested capabilities, u32, **v2 only** | 1,348 | 4 |
| Device signature, v1 | 1,348 | 64 |
| Device signature, v2 | 1,352 | 64 |

The device signs ASCII `mesh-msg/v1/device-renewal-request` followed by the
canonical complete request with its signature replaced by 64 zero bytes. The
version byte and v2 mask are therefore signed. Decoders reject truncation,
trailing bytes and version/field mismatches. In the Mesh representation,
`requested_capabilities` is `None` for v1 and `Some(mask)` for v2.

A valid v2 target is exactly one of the preserved upgrade routes: `old_mask | 2`
for ACH3, `old_mask | 6` for attachment buckets, `old_mask | 14` for the historical
HE-reader method, or `old_mask | 22` for the historical group-reader method. The
joint current-readers method is `old_mask | 30` (attachment + HE + group), yielding
`31` from baseline `1`. For example, a signed prior mask `65` upgrades to `95`,
preserving its existing higher bit. Each route retains every original bit;
clearing bits or adding arbitrary unrelated bits is refused even with a valid
device signature. Credential and RNWv2 mask fields are u32 and never silently
truncated. Historical `15`/`23` requests retain their exact signed meaning; they
are not rewritten into a current-readers claim by an account manager.

The request still occupies optional bundle extensions `1` and `2`: the first
1,024 bytes, then the remaining 388 bytes for v1 or 392 bytes for v2. Other
extensions retain their existing meaning.

## Publication, answer and recovery

1. A device lacking a current reader bit prepares and durably seals its next private
   keys and signed RNWv2 request. Its first publication retains the old
   credential and capabilities.
2. The account key answers only after the authenticated current device set
   contains the device-signed request. A primary answering itself also requires
   that exact request to match its durable local generation.
3. The answer takes the next directory sequence and exactly the requested mask,
   signed-prekey ID/key/signature, ML-KEM prekey and signed-prekey expiry. The directory refuses
   capability changes without the stored valid v2 request. An account signature
   alone cannot change an existing device's capability mask through renewal.
4. The device adopts the new capability only when the verified directory set
   shows the answer. Until then retries retain the exact saved request or
   prepared answer. Rebasing an answer after an intervening directory transition
   retains its requested keys and mask.

Queued RNWv1 requests remain v1 and receive the previous mask, including when a
new primary answers an old linked device. After that answer is adopted, a new
client still lacking a current reader bit prepares a separate RNWv2 request. Normal
same-capability primary renewals retain their existing one-step behavior;
linked-device key renewals can continue using RNWv1. Older account managers that
cannot decode RNWv2 must update before answering an upgrade request.

ACH1/2/3 readers and exact saved ciphertext retries remain supported. New writers
use [profile 4](attachment-buckets-v4.md); no private filename/MIME digest exception is
introduced to keep creating legacy chunks.

The implementation is in `prekeys/renewal.mpl`, `protocol/capabilities.mpl`,
`mobile/account.mpl` and `mobile/renewal.mpl`. Protocol and mobile renewal tests
exercise signature/wire tampering, unsolicited capability claims, exact retry,
sequence rebasing, queued legacy requests and both primary/linked upgrades.
These development checks do not establish production deployment or independent
security review.
