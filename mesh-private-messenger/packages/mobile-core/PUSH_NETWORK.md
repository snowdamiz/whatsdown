# Native push actions

`Mobile.PushNetwork` owns push bind/unbind HTTP. Its exported requests are ordinary
length-prefixed vectors (no count prefix), and native hosts require their exact
app database path:

| Export | Fields | Maximum input |
|---|---|---:|
| `push_flow_begin` | database, expected public profile, intent byte (0 resume, 1 enable, 2 disable) | 40,243 |
| `push_flow_complete` | database, PFA2 action, outcome byte (0 success, 1 failure) | 4,159 |
| `push_flow_send` | database, PFA2 action | 4,154 |
| `push_flow_validate` (trusted host only) | database, PFA2 platform action | 4,154 |

PFA2 is version 2, `PFA`, kind byte, failure byte, big-endian u64 epoch and a
length-prefixed payload. Done frames are 19 bytes with a status byte. Actions
are 50 bytes with a 32-byte ticket derived from the database path and exact sealed
profile/push records. They expose no mailbox identity, provider ciphertext or
signed network request. The UI executor accepts only PFA2. Legacy intent and
completion exports, including unbound `push_flow_intent`, remain in the C ABI for compatibility tests, but public
Swift/Kotlin/desktop dispatch denies them.

Only permission, platform token priming and platform clear actions accept UI
completion. A UI success byte cannot acknowledge a bind or unbind. Native send
uses build-pinned core origin, fixed PUT `/v1/push/bind` or POST
`/v1/push/unbind`, an 8-second timeout, no redirects and a 1,024-byte response cap.
Only an empty 201 bind or empty 200 unbind response settles the operation. Errors
retain the exact signed request for retry. The native push configuration and
stored profile/intent are checked before and after HTTP; SQLite compare-and-swap
commits prevent late responses from overwriting another intent or identity.
Provider registration similarly checks the saved basis and native configuration
before committing its result. The installation identifier is reserved once.

The 153-export checkpoint has real owned HTTP peers for successful bind/unbind,
unknown replies, redirects, oversized/unexpected replies, wrong status,
forgeries, timeout/late reply, disable, configuration change and account replacement.
Production library simulator/emulator proofs exercise tickets, platform outcome
handling and OS-backed state across process restart and account replacement.
Those native proofs supply platform outcomes; they do not establish real
APNs/FCM registration, provider HTTP or physical-device notification delivery.

The current adapter captures a copy of the rendered public profile before
queuing. `push_flow_begin` verifies its account and device keys against the
current sealed profile; ordinary credential/prekey renewal is allowed. Results
from begin, completion and HTTP send remain bound to the captured account.

OS prime/clear methods require the database plus exact PFA2 ticket. The trusted
host validates this with `push_flow_validate` under its core lock immediately
before starting the OS operation and before caching its result. Generic
Swift/Kotlin/desktop dispatch cannot call this validation export. Process-wide
queues serialize token work across React module reloads; an in-flight Firebase
deletion must finish before the next registration can start. Duplicate old
callbacks cannot advance a newer queue item. Module destruction does not clear
another module's installation token. A queued stale action is rejected; work
already accepted by the OS is not claimed to be cancellable.

Platform serialization is exercised separately using production Swift/Kotlin
queue classes. The native boundary runner exercises expected-profile and
platform-ticket refusal using production libraries and real OS storage. These
proofs still do not establish real APNs/FCM delivery. Desktop notification
preferences are keyed by account/device identity, so a replacement account must
enable them independently. Prior path-only preferences are not migrated.

The new bounded C ABI exports allow 4,096 response/error bytes even though
success frames are at most 50 bytes. `prove-native-error-bounds.py` checks that
malformed input produces an application error with its bounded message rather
than an output-size failure.
