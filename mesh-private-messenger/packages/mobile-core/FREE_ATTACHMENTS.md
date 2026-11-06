# Native free attachment transfers

Files up to 16 MiB use the existing in-memory flow. The app passes file bytes to
Mesh once. Mesh prepares the reference, proves work, uploads the encrypted
manifest and each 64 KiB encrypted chunk, and completes the object. The app never
receives the upload capability, grant, completion wire or deletion wire.

`attachment_upload_export` accepts a counted four-vector frame:
`[database, filename, mimeType, plaintext]`. The database is bound to the host's
own app path. Field limits are 4096,255,127 and 16,777,216 bytes; the complete
request is capped at 16,782,000 bytes by the Mesh export's `max_input` declaration.
History loading separately declares a 16,794,632-byte response ceiling; other
Mesh boundaries retain their default 1 MiB limit. Other desktop IPC requests retain their
existing 8 MiB ceiling. The result uses the ordinary output-list encoding with
three values: `[reference, objectId, discardTicket]`.

`attachment_discard_export` accepts counted `[database, discardTicket]`. The
platform storage key authenticates the ticket and binds it to the exact local
profile, database path, native object origin and deletion control. Substitution,
account replacement and changed destinations fail before HTTP. An already
absent object is an idempotent successful deletion. The ticket cannot authorize
an arbitrary URL or object.

`attachment_fetch_chunk_export` accepts counted `[database, reference, index]`.
Mesh authenticates the manifest and derives the download capability and route.
Version 1 uses the native object origin; version 2 retains the paid issuer/TLS
path. Both reject account/configuration changes after HTTP and authenticate the
ciphertext before returning plaintext to the display/save boundary.

The immutable `messenger/network/v1` resource now supports frame version 2:
version, development flag, core origin, edge origin, object origin, stream URL,
and object work difficulty, separated by newlines. Difficulty is a canonical
integer 1..24. Legacy six-field version 1 remains readable with difficulty 16.
Mobile and desktop build writers emit version 2. JavaScript cannot change it.

Every upload request uses the fixed native object origin, no redirects, a 12 s
per-request timeout, octet-stream content and no-store. Grant replies are at
most 36 bytes and must name the requested object; other replies must be empty.
Encrypted parts are at most 65,576 bytes. Profile and destination checks fence
each request. Failures attempt deletion only while that original authority is
still current; the object service's expiry handles abandoned objects.

Free uploads are not resumable across process exits. Progress advances per file
in the app. Paid files keep their separate durable staging, exact ciphertext
retries and credit recovery protocol described in `PAID_ATTACHMENTS.md`.

Verification includes 13 owned native HTTP peer cases, a full 16 MiB/256-chunk
round trip, oversize refusal before HTTP, forged replies, failed-part cleanup,
account and destination changes, and opaque-ticket misuse. Shared Swift/Kotlin
host vectors cover the exact 16 MiB input boundary and reject cross-database,
trailing, wrong-count and oversized frames. The rendered app sends a nine-file
album through the typed native export while JavaScript attachment HTTP throws.
Platform transfer evidence is recorded separately under `.morse/witness-proof`;
these checks do not claim production object-store or live deployment acceptance.

The owned iOS Simulator and Android emulator harnesses now each verify a full
16 MiB upload, process restart, all 256 downloaded chunks and the complete-file
SHA-256 digest, plus failed upload cleanup, forged deletion tickets, tampered
downloads and account replacement (530 checked HTTP requests per platform).
Run `python3 scripts/prove-attachment-ios.py` or
`python3 scripts/prove-attachment-android.py` after building the corresponding
native module. These exercise production Swift/C or Kotlin/JNI calls and OS
secure storage; the rendered picker and Expo JS bridge are separate checks.
