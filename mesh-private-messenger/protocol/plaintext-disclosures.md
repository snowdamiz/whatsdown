# Current disclosure inventory

`plaintext-disclosures.json` is the reviewed development baseline for the
current mobile-core build: twenty finite value declassifications, five
result-tag reviews and seven native display exports. Native mobile
and desktop build entry points compare every
reported site with this file before replacing an installed library. Missing
reports, additions, removals, moved sites and changed reasons fail the build.

This baseline records the exits present during the application migration. It
does not establish complete private-source labeling, independent review or
release approval. Those remain required by
[the plaintext specification](plaintext-types-v1.md).

The original fifteen metadata sites follow
[the bounded helper policies](../ops/plaintext/BOUNDED_HELPERS.md):

| Modules | Sites | Observed value |
|---|---:|---|
| Mobile.Codec, Transport.Packet | 4 | Closed concatenation/vector framing success or error classes; framed contents and encoded lengths stay private. |
| Protocol.EnvelopeWire | 2 | The explicit 0–17 envelope admission/encoding classifier; no arbitrary error payload. |
| Session.Handshake, Session.Ratchet | 3 | Transport capacity admission or padding failure bits; no message body or padding bytes. |
| Mobile.HistoryWire, Storage.HistoryBlobs | 3 | Closed history framing/part errors and valid encoded history length, or zero for invalid capacity. |
| Mobile.Presentation | 3 | Bounded structural validity, accepted framing and presence of group presentation metadata; no role authority or record content. |

The preceding attachment metadata migration added five reviewed boundaries.
Their reasons remain unchanged; the JSON inventory tracks current source spans:

| Boundary | Released value | Restrictions retained |
|---|---|---|
| `Attachments.Protocol.validate_manifest` | One Boolean: filename length is at most 255 and MIME length is 1–127. | No metadata bytes or exact length; existing version/chunk/size error priority and unrelated private control remain. |
| `Attachments.Protocol.seal_manifest` | One Boolean: bounded manifest encoding succeeded. Failure retains `InvalidManifest`. | Private bytes and errors are not released. Ciphertext preparation precedes the decision; failed encoding never publishes its fallback. |
| `Attachments.Protocol.seal` | Raw AEAD success/error tag before matching. | Ciphertext follows the encryption exit; error payloads, prior/caller control and public key/nonce/AAD requirements remain. |
| `Mobile.Attachments.describe_attachment_error` | Exactly six existing constant error classes: manifest, chunk, index, size, authentication and crypto failure. | No arbitrary error text or nested crypto payload. A future error variant fails exhaustive matching until reviewed. |
| `Session.Handshake.initiate` | Raw initial-message AEAD success/error tag before propagation. | Message bytes, error payloads, prior/caller control and authenticated metadata remain restricted. |

The filename/MIME ingress migration adds five further boundaries, bringing the
development inventory to 32 sites:

| Boundary | Released value | Restrictions retained |
|---|---|---|
| `Mobile.AttachmentMetadata` admission | One Boolean: filename at most 255 bytes, MIME 1–127 bytes and valid UTF-8 when required by the free-request parser. | Metadata bytes, exact lengths, derived digests and unrelated private control remain private. |
| `Mobile.CreditAttachmentJournal` storage seal | Raw storage-seal success/error tag. | Filename, MIME, binding digest, storage error payloads and unrelated private control remain private. |
| `Mobile.CreditAttachmentJournal` retry binding | One Boolean: supplied filename, MIME and public size exactly match the saved intent. | Metadata bytes and binding digests remain private. |
| `Mobile.CreditAttachmentJournal` intent framing | Raw bounded encoding success/error tag. | Private bytes, exact lengths, binding digest and error payloads remain private. |
| `Mobile.CreditAttachmentJournal` length framing | Raw four-byte writer success/error tag. | Exact metadata lengths encoded in private bytes and error payloads remain private. |

The seven display boundaries give content to the native host/UI process:

| Export | Observers and purpose |
|---|---|
| `load_history_export` | React Native direct chat, conversation previews and local notification adapter. |
| `group_history_export` | React Native group chat, previews and local notification adapter. |
| `attachment_fetch_chunk_export` | Native attachment display/save path after authenticated chunk opening. |
| `credit_attachments_export` | React Native paid-attachment inventory, including names, MIME types and journal status for explicit resume/cancel controls. |
| `attachment_download_plan_export` | React Native attachment display/save adapter; authenticated names, MIME types and bounded download metadata. Object fetching stays in Mesh. |
| `presentation_load_export` | React Native profile/contact/group/community presentation store and local group notification presentation. |
| `presentation_save_export` | React Native edit and community-state adapters receive the confirmed selected record after the authenticated local update. |

History consumers include `App.tsx`, `network.ts` and
`message-notifications.ts`. Notification code receives private bodies to choose
the user's allowed local preview and derive receipt timestamps; receipt sends
return through native sealing. Display permission covers these process
observers, rather than only visible text. It does not authorize HTTP, logging
or another unreviewed export inside Mesh. JavaScript networking restrictions
and the native connection inventory are separate controls on these observers.

Attachment consumers are in `paid-attachments.ts`; presentation consumers use
`presentation-store.ts` and its bounded presentation decoder. The presentation
load getter now validates the stored record before returning it, preserving
valid legacy/current bytes and empty cleared records while rejecting malformed
authenticated storage. These labels cover getter results and their error
outcomes. The attachment manifest and native free/paid preparation inputs now
label filename and MIME fields. Legacy private binding digests migrate into
separate authenticated storage seals before the wallet returns to public code.
Message-body ingress, presentation request aliases and internal presentation
reads still need complete source coverage. New free/paid attachment writers
use ACH3, with authenticated recipient
capability checks and opaque native authorization before upload. Legacy reads
and exact recovery of already completed paid uploads remain supported; pending
legacy chunks cannot initiate a new paid grant. The writer migration is a
prerequisite for the manifest-field migration, not proof of full source labeling.

The existing group-presentation presence classifier now lives in an independent
preparation helper. Its Boolean value, reason and storage-access gate are
unchanged. User and group ciphertext plans are prepared before observing their
results in the original error order; failed plans do not commit. On a user-plan
failure this can perform two extra local reads and one discarded seal, whose
reserved storage-counter gap is harmless. That earlier writer/capability change
moved one reviewed site without adding a disclosure; the later metadata and
ingress additions are listed above.

The compile-only `ops/plaintext/prove_display_sources.py` regression checks the
actual getters and exported wrappers against HTTP sinks. Calling a display
export from Mesh retains the private result; its display permission applies
only at the reviewed native boundary. Removing the five getter annotations in
the isolated mutation permits the forbidden flows again, while the unchanged
production app must compile. The probes never execute network requests.

`ops/plaintext/prove_attachment_metadata.py` separately freezes the actual
protocol fields and mobile error classifier. It checks forbidden field/error
flows and encrypted positive paths, verifies that removing labels permits the
corresponding leaks, and rejects an unreviewed future error variant. These probes
are compiled only. Native execution is qualified separately with exact source,
compiler, runtime and artifact pins.

The JSON file preserves each exact reason and source span. Updating it requires
reviewing the value released, its observers and affected refusal tests. Copying
the output of a new build into the inventory without that review is insufficient.
Test-only synthetic fixture observers are outside the production build and must
not be added to this inventory.

Mobile builds retain per-target reports and evidence in `native/plaintext/`;
desktop builds retain them beside the native library. The evidence hashes the
compiler entry point passed to the build. When that entry point is a wrapper,
qualification must additionally preserve and identify its underlying compiler,
runtime and exact source inputs; the wrapper hash alone is not a compiler pin.
