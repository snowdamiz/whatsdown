# Safety-number QR verification

Conversation details displays a QR code containing only
`mesh://safety/v1/` followed by the existing shared safety number: exactly 64
lowercase hexadecimal characters. It contains no profile, private key, device
identifier or message. Compare in person or over an already trusted channel.
A matching code does not establish independence from that comparison channel.

The scanner accepts only that exact version and encoding. Other QR kinds,
uppercase digits, extra path segments, query strings and fragments are refused.
The text-code fallback uses the same parser and native comparison. Groups do
not acquire a verification action through this format.

## Native comparison and commit

The existing `mesh_messenger_update_conversation` export accepts action 6 with
value 0 and a fifth length-prefixed vector containing the 64 ASCII bytes. Its
first four vectors retain the existing path, peer, action and value framing.
Actions 1–5 retain their original wire shapes for installed-client compatibility;
current UI manual verification also uses action 6 with the displayed number.
Old cores reject the extra vector, so the new UI requires its matching native
build and must not be shipped as an OTA-only change.

Mesh opens the original encrypted session index, captures the encrypted session
records and compares the supplied number against the same preferred session
selection used by conversation details. It prepares verification updates only
for the captured peer's sessions. Records with a different number remain
unverified and marked as changed.

The final SQLite transaction checks the exact account profile, original session
index and every captured ciphertext under a write lock before writing any
updates. Account replacement, a new session or a ratchet/session write during
comparison rejects the whole commit. The user must compare again. The bounded
snapshot supports up to 256 session records across pages; duplicate indexes,
missing records and malformed state fail closed. No database transaction spans
camera input or cryptographic preparation.

The app reports success only after the native comparison and commit. Canceling
or replacing the scanner prevents a late result from navigating that newer
screen. Verification is local; it is not a message to the contact or a public
attestation.

## Local evidence and remaining qualification

`packages/mobile-core/tests/safety_qr.test.mpl` exercises the actual native export,
canonical/malformed frames, mismatches, account/index/session replacement, and
atomic rollback/success across 71 encrypted session records. The first behavior
regression failed on the old policy parser before implementation.

`apps/mobile/scripts/test-safety-qr.mjs` exercises the real React app, QR display,
text-code scan, native refusal/success handling, delayed identity change, manual
comparison and cancellation with an explicit platform-I/O fixture. The fixture
is not a physical camera or a native-runtime test; native authority is covered
by the separate Mesh tests. Matching iOS/Android/desktop native builds and
physical-device scanning remain qualification gates.
