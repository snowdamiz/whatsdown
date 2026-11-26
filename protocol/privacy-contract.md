# Privacy Contract

Status: development contract. It states the intended visibility boundaries; it
is not a production-security claim.

Morse encrypts message content on user devices. Delivery services store and
forward opaque envelopes and must never possess message, attachment, backup, or
session decryption keys.

## Visibility

| Data | Visibility outside the device |
|---|---|
| Message plaintext | Never visible to the server |
| Attachment plaintext | Never visible to the server or object store |
| Attachment filename and MIME type | Encrypted inside the message |
| Session keys and ratchet state | Never leave the device in plaintext |
| Local contact names | Never sent to the server |
| Conversation identifier | Encrypted. Session IDs, ratchet headers, and group IDs travel inside the [recipient-sealed transport](recipient-transport-v1.md); legacy bare ratchet and group packets exposed them |
| Sender identity | Every packet is recipient-sealed; delivery learns neither the sender nor group membership |
| Destination | Opaque mailbox token visible to delivery |
| Whether the sender is a contact | One bit per envelope: delivery sees whether it arrived at the device's public address or at the secret [contact address](contact-address-v1.md) the device hands to contacts. It does not see which contact, and the edge sees neither |
| Username | Visible to the directory in the initial design |
| Device public keys | Visible to directory and transparency services |
| Source IP address | Visible to the privacy edge for submissions and the requests it relays as Oblivious HTTP (lookups, prekey claims, transparency proofs, mailbox fetch and acknowledgement), and to the backend for the mailbox stream and device-signed writes ("Paths and correlation"); on desktop, also to GitHub when the user checks for an update |
| Message timing | Observable in reduced form |
| Message size | A power-of-two size bucket; legacy packets may expose exact lengths |
| Attachment size | One of 53 size buckets: one 64 KiB chunk, then four steps per doubling up to 512 MiB (above 16 MiB paid with credits); attachments from builds before padding expose the exact size until they expire |
| Backups | To the object store, an object framed, sized and timed like an attachment of its bucket, under an ID only the recovery code names; never the account. Behaviour can hint which objects are backups (below) |
| Packet kind and protocol suite | Hidden: every new envelope is outer suite `4`. Only the size bucket hints at kind; legacy outer suites `1`-`3` named it |
| Push timing | Visible to the push provider |
| Credit purchases | Public on their chain (payer, deposit address, amount, time); the issuer holds quotes and payments but never a token |
| Checks against the public record | The phone's IP address and that it reads Morse's anchor accounts, about once a day, to the pinned RPC providers; nothing names the account or its contacts, and nothing goes to Morse |
| Fork evidence | Only when the phone caught a fork: the proof (two checkpoints, witness signatures, one leaf and its paths, a one-time finder address or zeros) and the phone's IP, to every pinned relay |
| Checkpoint gossip | To each contact, inside the encrypted session: the size and root of the key log when the phone last refreshed its view, with every message; and, when either side asks, the phone's signed checkpoint and which witnesses attested it. All of it is public. No server sees it; the directory sees only the consistency and leaf proofs the phone asks for, as it does for lookups |
| In-app wallet | Never to Morse. The pinned RPC providers see the addresses the wallet reads (its address and its bounty addresses), the device's IP and when, and every transaction it submits; the chain shows every transfer to everyone. The seed never leaves the device |
| Credit spends | The core sees a nullifier per token and when it was spent; neither it nor the issuer can tie it to a purchase or an account |
| Social graph | Reduced, not eliminated |
| Local history | Visible to an attacker controlling the endpoint |
| Screenshots and forwarding | Not preventable |

Push notifications contain only a generic encrypted-message wakeup. Object
storage receives random object identifiers, encrypted chunks, access times,
expiry, and each object's size; it does not receive file keys, names, MIME
types, identities, or conversation identifiers. Senders pad every attachment
to one of 53 size buckets ([attachment wire version 2](attachment-wire-v1.md#version-2-padded-objects)):
anything up to 64 KiB is one 64 KiB chunk, and above that there are four
steps per doubling up to the 512 MiB ceiling, so a file grows by at most a
quarter. Every file in a bucket leaves the store the same part count, part
sizes and total, and the encrypted manifest is the same length whatever the
filename. A file above 16 MiB is paid for with credits
([credits-v1.md](credits-v1.md#large-files)): its price follows its bucket,
so paying tells the store nothing its size did not. The store passes the
tokens to the directory-delivery core, which records their nullifiers and that
a file was paid for, never which object; the store keeps no token. An attachment sent by a build from before padding (version 1)
exposes its exact size, to within the chunk overhead, until it expires, seven
days at most.

Push registration goes through Expo: the phone sends its raw APNs or FCM token
and its installation ID to Expo's service, which therefore sees the phone's IP
address and that token, and through it Apple or Google see when each wakeup is
sent. The push broker receives only the provider token sealed to its key. The
build deploys the broker on its own, apart from the delivery core that knows
which mailbox a push is for; the backend holds only the broker's bearer
credential, never its unsealing key. Both still run under one operator and one
account.

Delivery keeps an envelope's times only to the minute: when it arrived, when
it was acknowledged, and when its push wake was queued and finished. The
database rounds the arrival and acknowledgement times whatever a writer sends;
a wake still being retried keeps its next attempt time to the second for the
few minutes its five attempts can take. Acknowledged envelopes stay for one
hour, because the envelope ID's uniqueness per mailbox is what turns a
sender's retried submission into a duplicate rather than a second delivery.
Per-mailbox rate buckets exist because the deposit and stream limits count
against them; each records only the minute its window opened and a count, and
is purged within a day.

A prekey claim marks one of the device's one-time prekeys consumed and keeps
the claim's hashes and exact answer, so a claim retried after a lost response
gets the same bundle. A day later the directory deletes that row, and with it
the record of when a session with the device began; the device keeps only the
highest prekey identifier deleted, so a replayed publication cannot bring the
key back.

The key transparency log keeps every leaf hash for good, since every proof
covers the whole tree. The device keys behind a superseded entry (an account's
earlier device set) are kept for 90 days after the account's next entry, then
only as hashes: the directory's daily pruning drops the entry's bytes and every
device record no remaining entry lists
([key-transparency-v1.md](key-transparency-v1.md), "Directory storage").
An account's current device set stays readable, as lookups need it. A deleted
account's entries and device records go at deletion. Checkpoints and witness
signatures are kept for 35 days, and anchored checkpoints for good; they name no
account.

Credits ([credits-v1.md](credits-v1.md)) are optional; nothing needs them.
Buying them is as public as any on-chain payment: the chain shows the payer, the
one-time deposit address, the amount and the time, and later the sweep of that
deposit to the treasury. The issuer keeps quotes and payments (including the
payer's address, as the refund destination) and the blinded messages it signed,
but never sees a token, so it cannot tell where one is spent. Quotes and issue
requests reach it through the privacy edge, which forwards the body alone. The
directory-delivery core keeps each spent token's nullifier, key epoch and spend
time, and for each redemption its action, a hash binding it to the request and
the number of credits, never a quote or a payment; spent tokens go 7 days after
their key stops being accepted. The two databases share no column that could
join them, so what can still link a purchase to a spend is timing: fixed pack
sizes, one key per epoch for everyone, and clients spending in random order no
sooner than 10 minutes after buying are what blur it. A credited request tells
the edge and the core that its sender paid, not who.

Extras bought with credits add their own records. A device's price for message
requests (its signed policy) is public: the directory serves it to anyone who
claims a prekey bundle for that device. Paid storage ties a mailbox to the fact
that it bought storage and until when, though not to the purchase or the
payer. The core keeps weekly totals of credits spent per extra, never per
sender or per mailbox.

What a buyer reveals, and to whom. Paying from the in-app wallet puts the
wallet's address on chain as the payer, next to the deposit address, the amount
and the time, and the RPC providers the build pins see that address and the
device's IP address when they send and confirm the transfer; paying from
another wallet reveals whatever that wallet does; a Lightning payment reveals
what the payer's node and the route learn. The issuer sees the quote come
through the edge (never the device's address) and the payment. The phone keeps
its purchases (quotes, payment signatures, purchase references) sealed on the
device and nowhere else. On a spend the edge sees the credited request's source
connection and its token bytes in transit, the core each token's nullifier,
key epoch and spend time with the action it paid for, and the issuer nothing.
A sender to a priced inbox learns the price from the prekey claim that starts
the conversation. A device that sets a price hands its contact address to the
members of its groups, as it already does to its contacts; it tells them
nothing else.

The phone checks what the directory showed it against the public record
([key-transparency-v1.md](key-transparency-v1.md), "The phone's check against
the public record"). It reads the chain straight from the RPC providers the
release pins, never through Morse: a Morse proxy could hand a victim a forged
public record. Those providers therefore learn the phone's IP address and that
it reads the judge's Log account, anchor ring and bond accounts, about once a
day, after a contact's keys change (at most hourly), and when Settings → Network
is opened. The reads are the same for every phone and name no account, contact
or checkpoint of the phone's; only the directory, which already serves the
phone's lookups, is asked for the consistency and leaf proofs. Everything the
check finds stays on the device; there is no report to Morse. If the phone
catches a fork it posts the proof to every pinned relay, which sees the
phone's IP and the proof: two checkpoints, the witness signatures on them, and
for a contradiction one leaf hash with its audit paths, which is a hash of a
device set the phone looked up. When the person collects fork bounties the
proof also names a one-time wallet address made for it; it is never tied to
the account and never reaches a Morse server. Relays and the chain see that a
fork was proven, not whose phone proved it.

Checkpoint gossip ([checkpoint-gossip-v1.md](checkpoint-gossip-v1.md)) tells
every contact a person messages the size of Morse's key log, and its root,
when the phone last refreshed its view: public data, sent at a time that
matches the message anyway, naming no account, device or lookup. A contact
whose hint the phone cannot check asks, at most once a day, for the signed
checkpoint behind it, and learns which witnesses attested it, which is public
too. The phone only gossips in conversations it accepted and has not blocked.
To settle a hint it asks the directory, which already serves its lookups, for
at most one consistency proof per conversation per hour, and for a disputed
checkpoint the leaves of its own recent lookups in the contact's version.

The in-app wallet (plan §6.13, `packages/wallet-core`) keeps its seed in the
platform keystore and signs on the device; Morse never holds it and can't
recover it. It reaches the chain only through the RPC providers the release
pins (the same list as the check above), never through a Morse server, and no
wallet address ever reaches the directory, delivery core or privacy edge. Those
providers therefore learn the device's IP address and the addresses it asks
about: its account address when Settings → Wallet shows a balance, each bounty
address it lists or moves, the addresses it scans once after a restore, and
every transaction it submits and polls. Asking about several addresses from one
IP lets a provider link them, which is why the wallet asks only when that
screen is open. On chain everything is public: a payment shows the payer
address, the recipient and the amount; a bounty move shows the bounty address,
the destination, and the account address that paid the fee, which links the
bounty address to the wallet (the app says so before the first move, and before
the first payment). A bounty address sits unlinked until then: it appears only
in the finder field of the one proof it was made for, and the judge pays it
there. What the wallet chose (whether to collect bounties, which notices were
seen) is sealed in the app's database; the next bounty index is kept with the
seed and never sent anywhere.

A directory lookup answers `200` or `404`, so anyone can learn whether a
username exists. Only the proof of work each lookup needs limits how fast that
can be probed, and that work is cheap for native code or a GPU: a lookup asks
for two bits fewer than the configured difficulty, 14 at the default of 16
([sealed-delivery-v1.md](sealed-delivery-v1.md#per-endpoint-difficulty)).

In sealed-delivery mode the privacy edge receives the source connection, an
opaque sealed record, and an anonymous proof of work. The delivery core receives
the mailbox capability only after unsealing a request forwarded by the edge, so
it observes the edge connection rather than the sender connection. The
backend's sealed ingress route is guarded by the edge's bearer credential. The
build can also require a credential only the edge holds: an Ed25519 signature on
every request, or a TLS client certificate (which can't be used while both run
as Cloudflare Workers). Either needs a provisioning step that hasn't been done,
so today the bearer is the route's only guard (see the
[sealed-delivery contract](sealed-delivery-v1.md)). The edge and the core are
not yet run by separate accounts or operators, so nothing about their split
should be read as independent.

## On the device: disappearing and view-once messages, app lock, the database

### Disappearing messages

- **Direct chats.** Each side sets its own timer: Off, 1 minute, 1 hour or 1
  day in the app (the core accepts up to 30 days). A message carries its
  sender's timer and expires that long after it was sent, by the sender's clock.
- **Groups.** A group has one timer, part of its state. Any member of a plain
  group changes it, and only the owner and admins in a community; the change
  is an authenticated group message (group message version 5, see
  [mls-groups-v1.md](mls-groups-v1.md#disappearing-and-view-once-messages)),
  and every member applies it and shows who changed it. Every timed message
  carries the timer, so a device added later learns it from the next message;
  the app sends one after every membership change. A message expires that long
  after it was sent, by the sender's clock, but never later than by the
  receiving device's.
- **Deletion.** When its time is up a message is deleted from the device's
  sealed history, not only hidden: at the end of every mailbox sync, on the
  app's own timer while it runs (at the next expiry, and at least once a
  minute), and whenever its chat is opened. The objects its attachments named
  are handed to the app, which deletes its decrypted previews and the
  decrypted bytes it held in memory.
- **Limits.** A device that is off or not syncing keeps an expired message,
  sealed, until it next syncs or runs. The encrypted object of an attachment
  stays on the object store until it expires on its own schedule (seven days
  at most). A timer does not stop a screenshot, a copy, or a modified client
  that ignores it. A build older than group timers never receives a timed group
  message: it drops version 5 unread.

### View-once messages

- The sender marks a message, words and photos only, view once (inner message
  type `8` in a direct chat, `GOP` flag 1 in a group). No device of the sender's
  account keeps its content: the sending device keeps a stub that says one was
  sent, the account's other devices get no copy of a direct one and keep only a
  stub of a group one.
- Each recipient device keeps the content sealed but never lists it. Opening
  it hands the content over once and deletes it from that device's history in
  the same step; the app shows it and deletes the decrypted photo when the view
  closes. After that the message reads "Opened".
- **Limits.** It is sent to all of the recipient's devices, and each can open it
  once. Morse can't stop a screenshot or a photo of the screen (Android keeps
  screenshots out of the whole app, but not a camera), and a modified recipient
  client can keep what it receives. A build without view-once drops the message
  unread, and the sender is not told. The encrypted photo stays on the object
  store until it expires.

### App lock

- Optional, in Settings → Privacy: the device owner's Face ID, Touch ID,
  fingerprint or passcode (on a Mac, Touch ID or the login password) every time
  Morse opens, or once it has been away for a minute or an hour. At launch
  nothing of the app is loaded until the owner unlocks; after it has been away
  it is covered and hidden from assistive technology until they do. The app
  switcher never shows Morse's content whether or not the lock is on.
- **Scope.** It is a lock on the screen, not on the data: history is sealed
  under the platform storage key either way, and push wakeups and
  notifications arrive as their own settings say. A device without a passcode
  can't turn it on, and one whose passcode was removed since opens. The
  setting is kept in the sealed journal.

### What the database shows

- Everything the core and the app keep on a phone or a desktop is in one
  SQLite database, each record sealed ciphertext
  ([local record format 2](storage-wrapping-v1.md#local-record-format-2)).
  Someone holding a copy of it, but not the device's keychain or keystore,
  learns how many records there are and roughly how large each is, and, from
  two copies, which records changed between them. They can't tell which label
  a record is for, so not whether a given account, contact, group or
  conversation is on the device, nor when any record was written or in what
  order: records are found by HMAC under a label key sealed under the platform
  key, nothing is timestamped, and each value's storage-wrap header, with its
  write counter and context binding, is masked under the same key. A database
  from before format 2 moves on its first open, in one transaction, and the
  pages its old rows held are zeroed.
- The app's settings (read receipts, notification previews, appearance, app
  lock) and its journals are sealed in the same database. Nothing of them is
  kept beside it in the clear; a copy an older build left there is sealed the
  first time it is found and then removed. They go with the database when the
  account is erased.
- A decrypted picture is shown from a file in the app's cache (on the desktop,
  from memory) only while its conversation is open: the file is removed when
  the conversation closes, and whatever an earlier run left is removed at
  launch. The decrypted bytes stay in the app's memory until it quits.
- **Limits.** Someone with the database and the keychain, or with the
  unlocked device, reads everything the device can. The database's size and
  record count still show roughly how much the device keeps.

## Backups

A backup ([backup wire version 2](backup-wire-v1.md#version-2-backups-in-the-object-store))
is an attachment wire version 2 object: the same `EAM` and `ACH` frames, part
count and sizes for its size bucket, proof of work, and six-day lifetime. Its
object ID and capabilities are derived from the recovery code and the UTC day,
so the store cannot tell whose it is, or link one day's backup to the next.
What can set backups apart is behaviour, not the objects: one is made about
once a day, it is never downloaded unless someone restores, a restore first
asks for part 0 of up to 32 objects that mostly do not exist, and turning
backups off deletes a week of them together. The store sees the connection IP
of each of those requests, as it does for attachments.

A backup never holds a device key, a ratchet session, group state, a message
with a disappearing timer, view-once content, or an attachment. A backup from
the device that created the account holds the account key, sealed under a key
derived from the recovery code. The device
keeps neither the code nor anything that could show it again: only the
locator and the derived key, sealed under its storage key.

If a recovery code leaks, its holder can find and open that device's backups
of the past six days: the contacts and history of every accepted conversation,
the history of every group, the names and photos the device showed, and its
settings and read marks, and each later backup for as long as backups stay on
with that code. If the backups came from the device that created the account,
they also carry the account key, so the holder can take over the account: add
their own device (a logged transition the account's devices see), remove the
others, delete it, and read what is sent to it from then on. Backups from
linked devices carry no key and open history only. Turning backups off deletes the stored backups and makes the
device forget the key; turning them on again makes a new code.

## Required implementation properties

- Devices are the cryptographic security boundary.
- The delivery database stores opaque ciphertext, not conversation semantics.
- No delivery record contains a clear sender, conversation identifier, message
  type, attachment type, reply target, or receipt policy.
- Logs, metrics, crash reports, push payloads, object keys, and network traces
  are tested for plaintext, private keys, raw mailbox tokens, contact names,
  sender-recipient pairs, filenames, MIME types, and recovery secrets.
- Optional blockchain anchoring contains only a transparency checkpoint
  commitment and never user, message, relationship, or mailbox data.

## Residual risks and non-claims

Morse does not claim to prevent global traffic analysis, endpoint malware,
recipient disclosure, screenshots, compelled access to an unlocked device,
push-provider timing correlation, or long-term metadata correlation without
cover traffic. A fully compromised sender or recipient device can reveal the
content available to that device.

New group control and application packets use recipient HPKE transport, described
in [group schedule revision 2](group-schedule-v2.md#recipient-transport). Queued
legacy packets still expose their original identifiers and membership fields;
receivers refuse them from 2026-11-20 ([recipient transport](recipient-transport-v1.md#compatibility)).
Later compromise of a recipient device DH key exposes captured wrapper metadata. Direct-message sender sealing and encrypted message padding
are specified in [client privacy revision 2](client-privacy-v2.md); they do not
constitute complete sender anonymity or hide all relationships.

## Paths and correlation

Which connection each request arrives on, and what it carries:

| Request | Path | The backend sees | The privacy edge sees |
|---|---|---|---|
| Envelope submission, credit purchases, longer storage | Through the edge, sealed to the delivery core ([sealed-delivery-v1.md](sealed-delivery-v1.md)) | The edge's connection; the envelope's mailbox and ciphertext | The phone's address and timing; an opaque sealed record and its proof of work or credits |
| Directory lookup, prekey claim, transparency consistency and leaf proofs, the credit issuer's keys, mailbox fetch and acknowledgement | Through the edge as Oblivious HTTP ([ohttp-v1.md](ohttp-v1.md)), sealed to the gateway key the build pins | The edge's connection; the request as the direct route would receive it: the username or account looked up, the device a claim is for, the signed fetch or acknowledgement over the hashed mailbox address | The phone's address and timing; the gateway's key id and the padded sizes of the request and its answer, never either one |
| Mailbox stream (WebSocket) | Direct to the backend | The phone's address, for as long as the app is open, and the device signature over the hashed mailbox address that opens the stream | Nothing |
| Registration and renewal, prekey publication, revocation, account deletion, leaving, push binding, the mailbox policy | Direct to the backend | The phone's address and timing, with the device-signed request | Nothing |
| Attachment grants, uploads and downloads | Direct to the object store | The phone's address and timing, and the object capability | Nothing |

So a fetch or a lookup no longer ties the phone's address to its mailbox or to
what it looked up: the backend, which knows the mailbox and the username, sees
only the edge, and the edge, which sees the address, can't read the request.
The gateway refuses a replayed request, so the edge can't resend a fetch to
watch a mailbox fill. What still links them:

- **The stream.** While the app is in the foreground its mailbox stream is a
  direct connection whose authorization names the mailbox, so the backend sees
  the phone's address beside its mailbox then. OHTTP has no long-lived
  exchange, and moving the socket to the edge would give the edge that
  authorization beside the address instead.
- **The direct writes above**, each of which is signed by the device or
  carries its capability, from the phone's own address.
- **Timing.** The edge sees when a phone sends and fetches, and the sizes in
  buckets (a request is padded to 256 bytes or a power of two, an answer to
  1 KiB, a power of two, then 64 KiB steps). One operator, or Cloudflare,
  running both the edge and the backend can match an OHTTP request to its
  answer, and a sender's submission to a recipient's fetch, by when they
  happen. The edge and the backend are not yet run by separate accounts or
  operators (M1), so nothing about their split should be read as independent.
- **Older and development builds.** Builds from before this change, and
  development builds that pin no gateway, send the stateless requests directly
  as before; the direct routes stay for them. Release builds pin a gateway and
  never fall back.

Shared infrastructure or colluding operators can correlate these paths.
