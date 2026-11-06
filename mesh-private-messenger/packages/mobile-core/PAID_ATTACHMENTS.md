# Bounded native paid attachment contracts

`Mobile.CreditAttachmentNative` owns authorization, native HTTPS and chunk
cryptography. The host owns bounded file range I/O and progress presentation. The free attachment path remains limited to 16 MiB.
The composer supports larger selections only when the release-pinned native
credit configuration admits their price preview. Default disabled builds keep
the free path; these functions do not enable a server feature flag.

Every input is `pack_credit_parts` (u32 count and length-prefixed vectors).
The native wrapper obtains account/device identity from its encrypted profile,
service key/origin from native security configuration and live/test purpose from
signed platform configuration. None is supplied by a network response.

| Function | Input vectors after database path | Output |
| --- | --- | --- |
| `native_credit_attachment_prepare` | nonce32, filename<=255, MIME1..127, size:u32BE | MCA |
| `native_credit_attachment_recover` | nonce32 | same MCA/material |
| `native_credit_attachment_receipt` | signed CAR462 | updated MCA |
| `native_credit_attachment_part` | nonce32, zero-based chunk index:u32BE, plaintext1..65536 | exact durably staged ACH<=65576 |
| `native_credit_attachment_part_recover` | nonce32, chunk index:u32BE | same staged ACH without rereading source file |
| `native_credit_attachment_prune` | nonce32, cleanup cursor:u32BE | next cursor:u32BE |
| `native_credit_attachment_preview` | size:u32BE | APV9 price/balance plus a native random nonce; no reservation |
| `native_credit_attachments` | none | AIV durable inventory; no reservation |
| `native_credit_attachment_grant` | nonce32 | MCA after native staged-part scan, HTTPS grant and pinned receipt verification |
| `native_credit_attachment_upload` | nonce32, object-part index:u32BE (0=manifest) | empty after bounded native PUT of saved ciphertext |
| `native_credit_attachment_complete` | nonce32 | byte0=pending, byte1=complete |
| `native_credit_attachment_delete` | nonce32 | byte0=pending, byte1=deleted; does not refund credits |
| `native_attachment_fetch_chunk` | device-wrapped ATR, zero-based chunk index:u32BE | authenticated plaintext chunk<=65536 |
| `native_attachment_download_plan` | one device-wrapped ATR | ADP11 authenticated version and transport; spending need not be enabled |

APV9 is `01APV`, nonce32, purpose:u8, size:u32, exact price:u32, available:u32,
delayed:u32, reserved:u32 and wallet revision:u64. AIV contains `01AIV`, wallet
revision:u64, then at most 128 counted rows. Each row contains nonce32,
operation-ID32, status:u8, filename, MIME, size:u32, price:u32, action expiry in
seconds:u64, object expiry in milliseconds:u64, cleanup cursor:u32 and chunk
count:u32. Status 3 is saved material without a reservation; listing never
reserves credits or starts a transfer.

ADP11 contains `01ADP`, authenticated manifest version:u8, pinned paid origin,
part-path prefix, ATR, object-ID32, download capability32, filename, MIME,
size:u32 and chunk count:u32. Version 2 supplies the release-pinned origin and
`/v2/objects/<id>/parts/` prefix. Version 1 leaves origin/prefix empty for the
existing legacy transport. The native manifest authentication distinguishes the
versions; legacy attachment IDs remain independent of their storage object IDs.

MCA is twelve counted vectors: `01MCA`, nonce32, operation-ID32, status byte,
revision:u64BE, pinned edge origin, grant path, exact CAP, device-wrapped ATR,
encrypted EAM, OCP completion control and ODL deletion control. Status 0 remains
reserved, 1 is consumed by an authenticated core grant, and 2 is cancelled by an
authenticated core non-consumption result. Statuses 0 and 1 retain the exact
CAP and `/v1/attachments/paid-grant` path. Reposting a completed CAP can repair
a lost object-store commit without charging again. Status 2 omits route/body.

Preparation persists sealed kind-6 material before reserving tokens. A failed
balance check leaves the same object, key and capabilities recoverable; retrying
that nonce with changed filename, MIME or size rejects. An unknown response
retains the same reservation and body. Expiry alone never releases tokens.
A generic HTTP success, another core key, changed result or changed frame cannot
complete the reservation. Generic reconciliation uses the same reservation and
can later be followed by attachment recovery.

Part 0 is the saved EAM. Host chunk index `i` goes to object part `i+1`, using
the upload capability in the canonical LAG/OCP. `native_credit_attachment_part`
commits the exact encrypted ACH through SQLite CAS before returning it. A
concurrent winner is reread; changed plaintext at an already staged index
rejects. Retrying a failed PUT must reuse this saved ACH. It must not call a
stateless encryption function and transmit a fresh random nonce.

The first-session host stages every exact encrypted chunk before invoking
the native grant. Mesh independently scans every saved part before any paid
grant POST. A restart accepts no replacement plaintext source: it scans
all saved parts in bounded calls before any network request. Incomplete staging
retains its existing reservation for signed reconciliation rather than consuming
credits for a file it cannot finish. A completed staging pass can replay without
the original file.

The host reads at most 65,536 plaintext bytes per call and writes downloads in
bounded file ranges. Mesh sends at most 65,576 ciphertext bytes per PUT. It must
not call a whole-file Bytes/read API for a 512 MiB attachment. The profile uses
at most 8,192 chunks and a fixed bounded manifest. After all parts are accepted,
repeat the exact OCP at `/v2/attachments/complete`: 202 advances its durable
128-part verification cursor, 200 completes, and errors preserve recovery.
Downloads remain blocked until completion.

Local staging cleanup starts at cursor 0 after object expiry plus seven days,
or immediately after a verified core-signed cancellation (status 2).
Each call deletes at most 128 sealed part records and durably advances the
cursor; skipped or out-of-order cursors reject. The last call removes kind-6
material. Shared reservation/receipt records are not released or deleted by
this cleanup. The host should schedule this bounded sweep; there is no automatic
wall-clock-based token release.
First part inserts atomically compare the wallet manifest that authorized
staging. A part encrypted before a concurrent cancellation cannot be inserted
after cleanup has passed its index. Cancelled intents reject new staging.

The protocol and service wire are defined in
[paid-attachment-v1.md](../../protocol/paid-attachment-v1.md). Native boundary
and custody tests use real BR1 tokens, pinned signatures, HPKE wrapping, durable
part replay and cleanup. UI and physical-device release qualification remain
separate integration gates.

These functions have generated Kotlin, Swift, C and TypeScript bindings
and platform dispatch entries. `apps/mobile/src/paid-attachments.ts` provides
typed native transfer calls with exact staged-part retries, central grant
repair, repeated 202 completion and streaming downloads. JavaScript supplies
only the app database plus nonce/reference/index; it supplies no URL, capability,
request body or network response to these operations. It never releases
credits after a transport failure. `attachment-range-io` uses native file handles
or web Blob slices for 64 KiB reads. Desktop downloads use native opaque save
handles, contiguous bounded writes and a temporary file; completion replaces the
selected destination only after the expected size is written and synced.
Abort removes its partial output. Native directory saves refuse an existing
filename and delete incomplete output on failure. Filesystem, host-contract and
transfer tests pass. The composer shows the native exact price and live/test
purpose before any reservation. Cancel closes the selected range source without
reserving tokens. A new selection retains its original source only until all
encrypted parts are staged; send retries then use the saved nonce and parts.
Saved uploads are available from the composer clock button and Credits. They
can repair a consumed grant, recover a reservation with a signed receipt, or
clean up a signed cancellation. A restarted incomplete staging pass cannot
select replacement bytes for its old intent.

While the saved-upload view is open, a 30-second timer runs at most one native
128-part cleanup batch; explicit cleanup uses the same native guard. No upload
inventory or wallet is opened eagerly on a default free startup. Received large
files obtain their authenticated ADP before opening a range sink. They never
enter the whole-file memory cache or inline image preview.

The rendered integration proof covers price/cancel, disabled spending, complete
prestaging before a lost grant response, source-free restart recovery, bounded
recipient saves, incomplete-stage refusal, signed cancellation and cleanup.
This proof uses native/network fixtures. Fresh paired native artifacts and
physical-device transfer qualification remain separate release gates.

Native HTTP uses the immutable issuer origin and optional exact-origin TLS root
resource described in `ISSUER_TLS.md`, a 12-second timeout, no redirects,
`application/octet-stream` and `no-store`. Grant responses are bounded to 462
bytes, chunk responses to 65,576; control responses must be empty. Profiles and
configuration are rechecked after I/O. Grant acceptance checks the expected
operation ID before applying a signed receipt. Upload/complete/delete require
an existing authorized reservation before recovery, so a transport call cannot
reserve an unfunded draft after a later deposit. Download authenticates its
manifest and derives routing/capability inside Mesh, including when purchasing
is disabled.

`MESHC=/path/to/meshc python3 scripts/prove-attachment-native-https.py` runs the
real native Mesh journal and cryptography against an owned HTTPS peer. It covers
missing staging and missing CA before HTTP, grant errors/redirects/forgeries/lost
replies, exact grant and ciphertext retries, bounded completion/deletion,
first/last chunk decrypt, disabled-purchase downloads and tampered/oversized
ciphertext. This fixture is distinct from production object-store integration,
external operators and physical-device qualification.
