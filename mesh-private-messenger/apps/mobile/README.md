# Morse mobile

The Expo app calls the local `mesh-messenger` native module; private keys and protocol state never cross into TypeScript.

[Release setup](./RELEASING.md) covers automatic EAS iOS/Android builds,
TestFlight submissions, and production OTA updates through GitHub Actions.

The [Windows and macOS app](../desktop/README.md) reuses these screens through
React Native Web and provides its own native Mesh bridge and installer workflow.

In a development build, open **You → Development → Sample content** to preview
16 chats, 6 groups, and 528 messages, with read rows and varied unread counts.
Opening a sample conversation clears its badge; toggle the preview off and on
to reset the examples. The preview is read-only and held in memory;
sample records never enter encrypted storage or delivery. Turn it off to return
to your real chats. Reloading the app clears it. The fixture file loads only when
the toggle is enabled; release bundles exclude it entirely. Run
`npm run test:preview-bundles` to check fixture inclusion in actual iOS, Android,
and desktop development and release exports.

The Morse mark is defined once in `src/brand.ts`. `npm run render-icons`
regenerates the launcher icons in `assets/` (iOS light, dark, and tinted;
Android adaptive foreground and background) and the desktop icon source at
`../desktop/src-tauri/icons/icon-source.png`, which `npx tauri icon` fans out.
The in-app glyph draws the same path, so the icon and the app never drift.

Startup uses one dark Morse canvas from the OS splash through font and local
storage loading, then fades into the saved appearance. Reduced motion skips
the fade. `npm run render-icons` also regenerates `assets/splash.png` and the
desktop's pre-JavaScript cover in `public/index.html`. Splash changes require
a new native build; an OTA update cannot replace the OS launch screen.
To check the real desktop bundle with delayed fonts/storage, run
`npm run web --prefix ../desktop`, `npx playwright install chromium`, then
`npm run test:startup` (or set `PLAYWRIGHT_CHANNEL=chrome` to use installed Chrome).

Chats, groups, and invitations update from one foreground WebSocket subscription.
The app catches up after subscribing or reconnecting, drains all mailbox batches,
and reloads local views after actions even when delivery fails. Backgrounding
closes the stream; foregrounding reconnects. No-push mode still receives live
updates while open, without manual refresh or mailbox polling.

Unread chats and groups use a count badge and stronger text. Navigation badges
include unread messages and pending requests. Opening a loaded conversation in
the active window marks it read; settings, details, and inactive windows do not.
Read status is saved locally per account and device, with no read receipts sent.
Only opaque message identifiers are saved, never message text. Run
`node scripts/test-unread.mjs` after the desktop web export to check counts,
restart persistence, late arrivals, and foreground behavior in both themes.

Create a group with a name and optional photo, then invite members from its details.
Group messages show each sender's name, avatar, and stable account color; a small
star marks the creator. Only the creator can update the group photo. Profile
photos can be added during signup and changed or removed in **You → Profile photo**.
Photos and group details are stored encrypted and travel inside encrypted messages;
photo announcements do not appear in chat history. Update native clients together
for this presentation format and the new image picker; an OTA-only update is insufficient.
After the desktop web export, `npm run test:profiles` checks these flows in the real
bundle with a test native bridge. Mesh tests cover persistence, permissions, delivery,
and transaction rollback.

Invite someone from **Group details → Invite someone** using their username.
They accept or decline in **Groups**. Invitations and responses travel through
encrypted direct-message delivery; the inviting device finishes the join when
it next connects. Each device accepts separately, and QR joining is optional.
Both devices need a native build with the
[group invitation protocol](../../protocol/group-invitations-v1.md).

[Client privacy revision 2](../../protocol/client-privacy-v2.md) binds safety
numbers to account keys, encrypts initial sender credentials for the recipient,
and pads new message packets inside encryption. Update mobile and CLI clients
together. Old verification badges are cleared until a fresh session establishes
a key-bound safety number. Release builds require HTTPS; debug HTTP is limited
to loopback and private IPv4 addresses. Redirects are disabled.

```sh
npm ci
EXPO_PUBLIC_MESSENGER_BASE_URL=http://YOUR-MESSENGER-HOST:18086 \
EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL=http://YOUR-EDGE-HOST:18087 \
EXPO_PUBLIC_MESSENGER_STREAM_URL=ws://YOUR-MESSENGER-HOST:18090/v1/mailbox/stream \
EXPO_PUBLIC_MESSENGER_OBJECT_URL=http://YOUR-OBJECT-HOST:18089 \
EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY=8 \
MESSENGER_DELIVERY_PUBLIC_KEY_HEX=DELIVERY_X25519_PUBLIC_KEY \
MESSENGER_ABUSE_DIFFICULTY=16 \
MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=SERVICE_PUBLIC_KEY \
MESSENGER_WITNESS_A_PUBLIC_KEY_HEX=WITNESS_A_PUBLIC_KEY \
MESSENGER_WITNESS_B_PUBLIC_KEY_HEX=WITNESS_B_PUBLIC_KEY \
MESSENGER_EXPO_PROJECT_ID=YOUR_EAS_PROJECT_UUID \
MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX=PUSH_BROKER_X25519_PUBLIC_KEY \
npm run ios
```

Use a LAN or deployed HTTPS URL on physical devices. `127.0.0.1` only reaches the device itself. A custom development build is required because the app contains the local native module.
Release builds require a `wss://` stream URL. If no stream URL is configured,
the app uses `/v1/mailbox/stream` on the HTTP service's origin; route that path
to `MESSENGER_STREAM_PORT` (default 18090) through the TLS reverse proxy.
`./run.sh` configures both local stream endpoints automatically.
Messages accept up to 10 files of any type (16 MiB each). Pick multiple files,
or drop/paste them on desktop; remove individual files before sending. Click a
photo to open a larger view with a Download button. File cards download other
attachments through the system save picker. Albums require updated native
builds on both ends; single-file messages keep their existing format.
After exporting the desktop web app, `npm run test:attachments` checks selection,
removal, limits, image viewing, and downloads in the real UI with native I/O mocked.

Attachments are encrypted on the device and stored as opaque parts in the
object store. Without an object URL the app uses the messenger origin, which
is where the production worker serves `/v1/objects`; local development runs the
object store on `MESSENGER_OBJECT_PORT` (default 18089), and `./run.sh` points
the app there. `EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY` (default 16) must
be at least the store's `MESSENGER_OBJECT_WORK_DIFFICULTY`.
New accounts keep notifications off until the user enables them in You → Notifications.
New development accounts advertise experimental hybrid suite `0x0002`; linked
classical devices remain on suite `0x0001` until credential rotation. Suite
`0x0002` is not production-approved until the independent cryptographic review
[gate](../../protocol/hybrid-handshake-v1.md) is complete.
Transparency, witness, and delivery keys plus abuse difficulty are provisioned together as the canonical signed native `messenger/config/v1` resource; they are never OTA TypeScript configuration. Mesh validates the exact frame, distinct witness keys, contributory delivery key, and difficulty 1 through 24 before verifying directory evidence or sealing a send.
Notification enablement requires the Expo project UUID and push-broker X25519 public key together. The broker key is a 32-byte lowercase-hex public build pin. Both non-public environment variables are provisioned into signed native resources during prebuild; they are not OTA JavaScript configuration. Missing, partial, or malformed build configuration fails before notification permission is requested. No-push startup recovery remains available when both pins are absent.

Group messages support exact `@username` tags, member suggestions at the cursor,
and highlighted mentions. Usernames travel inside the existing encrypted message
body. The device formats ordinary message previews and “@sender mentioned you”
alerts after decryption; the push provider sees only `kind=encrypted-wakeup`.
Tapping a mobile message notification opens its conversation. The visible chat,
blocked contacts, your own messages, and repeated wakeups do not create alerts.
The local notification journal stores opaque message IDs, never message text.
Disappearing messages use a generic preview so their text does not outlive them
in OS notification history.

A message's menu holds its emoji reactions, Reply and Copy. Long-press a bubble
on a phone, or swipe it right to reply; on desktop, rest the pointer on it for
the React and Reply controls, or right-click. A reply quotes the message it
answers, in chats and groups, and pressing the quote jumps to the original. Only
the target's ID travels, inside the encrypted body; each device draws the quote
from its own history
([quote replies](../../protocol/quote-replies-v1.md),
[emoji reactions](../../protocol/emoji-reactions-v1.md)). After exporting the
desktop web app, `node scripts/test-reactions.mjs` checks both in the real UI
with native I/O mocked.

Mobile push uses an Expo headless notification task, registered when notifications
are enabled and restored on startup. Rebuild the native app for `expo-task-manager`
and the iOS `remote-notification` background mode; this cannot ship as an OTA-only
update. Deploy compatible clients before switching the broker to data-only wakes;
older clients cannot display those wakes. Configure APNs/FCM credentials in EAS,
the signed client pins above, and the broker settings in the runbook.

Background delivery is best effort: force-stop, disabled background activity,
Doze, and iOS throttling can delay or prevent execution. A task that runs but
cannot sync/decrypt posts a generic fallback alert. The app does not currently
have an iOS Notification Service Extension, so it cannot promise a rich alert
when iOS declines background execution. See [Expo's delivery behavior](https://docs.expo.dev/push-notifications/what-you-need-to-know/).
Verify on signed physical iOS and Android builds: enable/deny permission, receive
a direct message, an ordinary group message and an exact @mention while locked,
tap each alert, retry a wake, restart, and disable notifications. Check the same
flows with background activity restricted and document the observed OS limits.

Outbound session state, history, and the encrypted outbox commit atomically. Submission is at-least-once with server deduplication; only a durable 2xx response permits local acknowledgement. The iOS and Android bridges serialize native calls.

Each device keeps at most 64 server-active and 64 retired/in-flight
storage-wrapped one-time prekey secrets, indexed by their public `prekey_id`.
`mesh_messenger_replenish_prekeys` returns a canonical, device-signed `OTB`
batch for upload; a requested count of zero re-exports pending entries or sends
an authenticated empty recovery query. The server's identity-bound `OTA`
response is applied through `mesh_messenger_reconcile_prekeys` before native
code generates replacements. Foreground registration and mailbox sync perform
that recovery and refill automatically. An accepted initial message deletes
only the exact claimed secret and active marker in the same SQLite transaction
as its session and history; a failed transaction retains both, while replay
after commit fails.
When all 64 retired slots are occupied, refill evicts the oldest retired
secrets. This bounds storage, but more than 64 claimed initial messages delayed
past delivery can no longer decrypt and require a protocol-level delivery
acknowledgement before raising the limit.
Existing singleton records are opened with their historical storage context,
resealed under the per-ID context, and retained provisionally active until the
first `OTA` classifies them as active or retired. A consumed singleton remains
available for a delayed initial message but its ID is never generated again.
Bundle claim responses
must preserve the transparently verified base bundle and substitute the
server-claimed ID/public key pair without changing other fields.

Run the software acceptance proof from the repository root:

```sh
mesh-private-messenger/scripts/prove-m11.sh
```

Push payloads are accepted only when the visible body is `New encrypted activity` and the data object is exactly `{ "kind": "encrypted-wakeup" }`.
