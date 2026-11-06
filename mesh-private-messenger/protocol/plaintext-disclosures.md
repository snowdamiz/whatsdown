# Current disclosure inventory

`plaintext-disclosures.json` is the reviewed development baseline for the
current mobile-core build: 41 finite value declassifications, 12
result-tag reviews and 16 native display exports. Native mobile
and desktop build entry points compare every
reported site with this file before replacing an installed library. Missing
reports, additions, removals, moved sites and changed reasons fail the build.

The raw storage, fanout-target and triple-payload request parsers are now private
to `MobileCore`. Moving their imports shifts the 16 existing display sites by
four lines and minus 28 bytes; their exact expressions, reasons and kinds are
unchanged. This move adds no disclosure and does not establish complete ingress
labeling.

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

The filename/MIME ingress migration added five further boundaries, bringing its
development checkpoint to 32 sites:

| Boundary | Released value | Restrictions retained |
|---|---|---|
| `Mobile.AttachmentMetadata` admission | One Boolean: filename at most 255 bytes, MIME 1–127 bytes and valid UTF-8 when required by the free-request parser. | Metadata bytes, exact lengths, derived digests and unrelated private control remain private. |
| `Mobile.CreditAttachmentJournal` storage seal | Raw storage-seal success/error tag. | Filename, MIME, binding digest, storage error payloads and unrelated private control remain private. |
| `Mobile.CreditAttachmentJournal` retry binding | One Boolean: supplied filename, MIME and public size exactly match the saved intent. | Metadata bytes and binding digests remain private. |
| `Mobile.CreditAttachmentJournal` intent framing | Raw bounded encoding success/error tag. | Private bytes, exact lengths, binding digest and error payloads remain private. |
| `Mobile.CreditAttachmentJournal` length framing | Raw four-byte writer success/error tag. | Exact metadata lengths encoded in private bytes and error payloads remain private. |

The original seven display boundaries give content to the native host/UI process:

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
Message-body ingress and complete request-field labeling remain open. Presentation
validation, internal storage reads, framed encoding and body projection now
introduce or retain labels; their actual-source proofs are described below.
New free/paid attachment writers
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

The intervening backup, header-ratchet, storage-seal and native view-once work
extended the JSON baseline to 51 sites. Its six additional native observers cover
backup metadata, archive inventory/detail/page views, pending export state and
the dedicated view-once opening. Those existing boundaries are unchanged by
the presentation migration; their presence does not establish complete native
integration or release qualification.

The presentation migration adds 18 reviewed boundaries:

| Boundary | Released value | Restrictions retained |
|---|---|---|
| Local group add/remove/invite operations and signed commit application | One permission Boolean at each of four operation boundaries. Local operations load their account principal; received commits pass signature, transcript and key validation before the decision is observed. | The reusable policy helper returns a private Boolean. Arbitrary claimed identities and role-membership queries cannot use it as a public oracle. A refused received transition is destroyed without committing its state. |
| Local presentation editing | One of allowed, community-admin-required or group-creator-required, after loading the local account and authenticated group creator. | The reusable helper returns a private closed enum; records, identities and revision values stay private. |
| Stored community rule selection | One Boolean selecting community-owner versus plain-group-creator rules. | Stored record contents and role identities stay private; group storage addressing remains public. |
| Presentation admission and group sending/encryption/padding | Four bounded capacity or padding-refusal Booleans. | Message/presentation bytes, exact lengths, padding bytes and error payloads remain private. The internal group-send capacity helper is called only with fixed transport limits. |
| Group and timed-group payload framing | Two bounded encoding success/refusal Booleans. | The existing fixed failure strings remain; bodies, hints, recipient identities, timestamps and durations remain private. |
| Group history framing | A closed success/framing/integer failure class. | Encoded history and arbitrary error payloads remain private before storage sealing. |
| Legacy ratchet and group-body AEAD sealing | Two raw success/error tags. | Ciphertext follows the encryption exit; private error payloads and prior/caller control remain restricted. |
| Legacy initial, direct and group native receive exports | Authenticated receive results at three existing native ABI entry points. | Calling them from Mesh retains private results. Internal mailbox processing uses internal functions and gains no display permission. |

The native receive annotations describe a host-process boundary, not a guarantee
that only rendering code can call it. Generic native dispatch also permits host
access. Native ownership and host networking closure remain separate gates.

Unchanged or older selected presentation records are resealed before the storage
write, avoiding a content-dependent write/no-write branch. Public fallback
framing is prepared before private profile selection. Initial handshake error
conversion is explicit and exactly matches the existing `From<CryptoError>`
wrapper; that correction adds no disclosure.

The compile-only `ops/plaintext/prove_display_sources.py` regression checks 14
actual source/getter/native-wrapper flows and three policy-helper flows against
exact HTTP sinks. Calling a display export from Mesh retains the private result.
The isolated positive control removes the relevant result/input/local labels and
the two attachment manifest field labels, admitting the 14 content flows. The
policy probes intentionally retain private caller inputs and are excluded from
that mutation control. The protected production core must also compile. The
runner freezes dependencies and records compiler/runtime, runner, source and log
hashes; none of its forbidden network probes executes.

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
