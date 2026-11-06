# Native directory networking

Directory registration, prekey synchronization and device-set resolution send
requests from Mesh to `Mobile.NetworkPins.core_origin`. Callers cannot choose a
URL, supply proof of work, select a witness policy or submit an evidence response
to these operations. HTTPS uses ordinary certificate and hostname verification;
only explicit native development loopback pins permit cleartext HTTP.

## Embedding API

| Export | Input | Successful output |
| --- | --- | --- |
| `directory_register_export` | Raw UTF-8 native database path, 1..4096 bytes | Seven bytes: `01 DRG`, active prekeys u16BE, verified removal kind u8 |
| `prekeys_synchronize_export` | Same raw path | Six bytes: `01 DPK`, active prekeys u16BE |
| `directory_resolve_export` | Exactly two u32BE-length-prefixed vectors: native database path, UTF-8 username/account alias | Authenticated canonical DeviceSet, 1..305260 bytes |

Resolution has no leading vector count. Its complete input is at most 4169 bytes;
the username/reference is 1..65 bytes. An account alias is `@` followed by 64
canonical lowercase hexadecimal digits. Mesh validates the lookup syntax before
sending. All hosts must parse the entire frame and compare its database field
with the app's native database path. Extra fields, trailing bytes, counted-list
framing, invalid UTF-8 and NUL in the path fail closed.

Registration succeeds only with 64 active prekeys and removal kind 0. A verified
removal instead reports count 0 and kind 1 (account deleted),2 (device revoked) or3
(device departed); native code has already authenticated the statement and erased
the account before reporting it. Other count/kind combinations are invalid.

## Registration and prekeys

Registration reads the native signup policy itself. Only explicit
`credits_disabled` configuration permits the existing base-work path. Policy
transport, signature, freshness and storage failures never silently select base
work. A paid signup draft is refused before network I/O. The fixed registration
request has redirects disabled, an 8-second timeout and a 1024-byte response cap.
Profile and origin changes fence both successful and failed responses.

Prekey synchronization reconciles the saved publication first. A lost
acknowledgment resends its exact signed bytes before generating replacements.
Canonical full-pool429 responses also reconcile. A native pass allows at most two
bounded publication requests and verifies that the resulting pool contains 64
active keys. A response cannot create authorization for another account, device
or unknown key ID.

## Resolution and cache admission

Mesh derives permitted v1/v2 lookup steps from native security pins and durable
checkpoint history. It tries v1 after v2 only for an exact 404 body
`transparency_v2_not_active` and only when migration policy permits that step.
HTTP errors, redirects, malformed or invalid evidence, a response using the wrong
log version, and durable v2 history cannot create legacy permission.

Each HTTP request has an 8-second maximum and a 570418-byte response cap. A
30-second monotonic budget is checked between transport, verification retries
and witness waits; this is not a guarantee that arbitrary native work is
preempted at that instant. There are at most five verification attempts. Every
retry rebuilds work and fetches signed evidence for the current durable basis;
it does not blindly replay an obsolete response. The fixed paths are
`/v1/devices/resolve` and `/v2/devices/resolve`, with no cookies, authorization
headers or redirects.

The existing verifier checks the pinned service, witness quorum and timestamps,
recipient identity, inclusion, consistency and any configured native anchor
policy before returning DeviceSet bytes. Cache writes compare both checkpoint
ciphertext and the original profile ciphertext in one SQLite transaction. A late
first lookup cannot restore state after account erasure or profile replacement.
Concurrent first lookups have one winning insertion; a losing resolver obtains
new evidence using the new basis. Exact checkpoint refreshes reuse the saved
checkpoint ciphertext, allowing idempotent refreshes without relaxing rollback
checks. All associated view, witness, leaf and device-set caches commit together.

The lower-level verifier retains its existing preprofile use: an explicitly
absent profile is compared as absent in the same write. Creating a profile
invalidates that basis. The typed native resolution operation requires an
existing profile and never substitutes this preprofile basis after erasure.

## Verification and scope

`tests/directory_network.test.mpl` exercises real signed registration/prekey
requests against 17 owned local peer modes. `tests/directory_resolve.test.mpl`
exercises 17 local resolution modes, including signed v1/v2 admission, duplicate
checkpoints, strict fallback, malformed/oversized responses, origin changes,
wrong signer/witness, stale/future data, erasure/replacement and fresh-basis retry.
`tests/transparency_commit.test.mpl` covers stale/absent bases and eight
concurrent first-lookup writers. Existing transparency and migration tests remain
required. Host framing, TS integration and rendered signup/removal checks are
separate from these Mesh tests.

Legacy lookup/work/evidence helpers remain internal C ABI/test APIs but are
denied by generic JS host dispatch. Renewal/revocation, normal outbox submission,
account/group operations and other network paths still have separate migration
work. These operations alone do not establish complete Phase 6 network closure.
