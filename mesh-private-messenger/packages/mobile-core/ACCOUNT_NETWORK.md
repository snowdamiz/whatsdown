# Native account and device actions

Account deletion, linked-device departure, device renewal and revocation use
native immutable NetworkPins. JavaScript supplies local database and action
identity; it receives typed status rather than signed wire or removal proofs.
Requests use ordinary u32BE-length vectors with no count prefix.

| Action | Input fields | Maximum bytes | Output |
| --- | --- | ---: | --- |
| account_capabilities | db, expected public profile | 40238 | `01414350`, canManage u8 |
| account_delete | db, expected public profile | 40238 | `0141444e`, removal kind 1 or 3 |
| account_discard | db, exact expected public profile | 40238 | `01414453`, success 1 |
| devices_renew | db, authenticated DeviceSet | 309364 | `01444e52`, sent u8, blocked HTTP u16BE, verified removal kind u8 |
| device_revoke | db, authenticated DeviceSet, target ID16 | 309384 | `01445256`, HTTP 200 u16BE |

Database paths are nonempty UTF-8, at most 4096 bytes, and contain no NUL. Public
profiles are at most 36134 bytes; DeviceSets at most 305260 bytes. Extra fields,
count prefixes, malformed lengths and trailing bytes are refused before storage.
Removal kinds are 1 account deleted, 2 device revoked, 3 device left. No HTTP 410
status is reported as removal without native signature verification and guarded
local erasure. A renewal refusal stops the ordered pass and retains its queue.

The expected profile for deletion/capabilities binds account ID, device ID,
account authorization key, device signing key and device DH key. Routine renewal
of that same identity is accepted. Discard requires exact public bytes, suitable
for rollback of an unpublished onboarding account. All eventual mutations compare
the exact captured encrypted profile, plus relevant source records, inside one
SQLite transaction. Crypto and network operations hold no transaction open.
Delayed responses and valid old removal statements cannot erase a replacement.

A private renewal publication queue persists up to 8 individually sealed signed
entries before the first HTTP request. Unknown outcomes and acknowledgements
retain exact bytes and order until a newer authenticated DeviceSet supersedes the
queue. A same-sequence different set is refused. Renewal and cached-device writes
are guarded against erased/replaced profiles and concurrent source changes.
A revoke HTTP 200 is only an acknowledgement; UI confirms removal using a fresh
witnessed DeviceSet. Native HTTP follows no redirects, bounds each request to 8s
and each reply to 1024 bytes. Renewal publishes at most 8 entries with a 30s pass
budget checked between work and sends; cryptographic work is not preempted.

The UI captures only exact presented message-notification IDs while its original
account is current, checking native identity before and after the OS read. After
native erasure it checks storage and visible identity around exact-ID dismissal
before resetting that account's view. It never clears a provider token or globally
dismisses notifications. The current desktop provider has no per-ID listing API,
so that optional cleanup is unavailable there rather than widened to dismiss-all.

Focused local qualification covers 18 Mesh tests (9 new, 9 existing), 29 owned HTTP
peers and 8 concurrent storage writers. Pure TS tests reproduce replacement during
notification capture/dismissal and prove that stale completion cannot reset its
replacement. These are domain/adapter results; native artifact execution is a
separate integration gate. No live identities or funds are used.
