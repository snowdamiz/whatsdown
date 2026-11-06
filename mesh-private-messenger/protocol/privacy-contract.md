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
| Checkpoint gossip | Contacts and group members learn the sender's last verified public log size/root. On a mismatch, encrypted controls carry public signed checkpoints and attestations; group members can read group controls even when another device is addressed |
| Source IP address | Visible to the connection edge; on desktop, also to GitHub when the user checks for an update |
| Message timing | Connection timing is observable. Stored envelope receipt times are rounded to the minute after migration 029; this does not coarsen every operational timestamp |
| Message size | A power-of-two size bucket; legacy packets may expose exact lengths |
| Packet kind and protocol suite | Hidden: every new envelope is outer suite `4`. Only the size bucket hints at kind; legacy outer suites `1`-`3` named it |
| Push timing | Visible to the push provider |
| Social graph | Reduced, not eliminated |
| Local history | Visible to an attacker controlling the endpoint |
| Screenshots and forwarding | Not preventable |

Push notifications contain only a generic encrypted-message wakeup. Object
storage receives random object identifiers, encrypted chunks, exact encrypted
wire lengths, access times, and expiry. Current development writers use
[profile 4](attachment-buckets-v4.md): 514-byte encrypted manifests and fixed
64-KiB clear chunk capacity, including a padded final chunk. Original length,
filename and MIME type remain inside encryption. Bucket count, free/paid route,
credit tier and timing remain visible; legacy formats retain their earlier
exact-size leakage. Local qualification does not establish a production cutover.
The object wire does not carry file keys, names, MIME types, identities or
conversation identifiers; network paths can still permit correlation.

Local encrypted records use [keyed version-2 indexes](local-storage-index-v2.md)
and have no clear update-time column or row IDs. Record count, ciphertext lengths
and changes remain observable. Old database copies, pages/WAL, snapshots and
backups may retain the previous labels/timestamps; migration is not erasure.

In sealed-delivery mode the privacy edge receives the source connection, an
opaque sealed record, and an anonymous proof of work. The delivery core receives
the mailbox capability only after unsealing a request forwarded by the edge, so
it observes the edge connection rather than the sender connection. Direct and
internal delivery endpoints need an independently enforced ingress boundary as
specified by the [sealed-delivery contract](sealed-delivery-v1.md). Separate
accounts, certificate enforcement and a verified production cutover are rollout
requirements; a bearer credential alone does not establish network isolation.

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
- When native anchoring is configured, phones read pinned public RPC
  providers directly. Providers learn the phone's IP address and that it reads
  the public Morse ring; reads contain no account lookup or contact identifier.
  The scheduler checks daily and on verified key changes, at most hourly.
  The native reader and app scheduling are implemented locally; release pins
  and production activation remain separate. Morse is not an RPC proxy for
  this check. An optional Settings counter also reads public bond and slash
  accounts directly when its native configuration is enabled.

## Residual risks and non-claims

Morse does not claim to prevent global traffic analysis, endpoint malware,
recipient disclosure, screenshots, compelled access to an unlocked device,
push-provider timing correlation, or long-term metadata correlation without
cover traffic. A fully compromised sender or recipient device can reveal the
content available to that device.

New group control and application packets use recipient HPKE transport, described
in [group schedule revision 2](group-schedule-v2.md#recipient-transport). Queued
legacy packets still expose their original identifiers and membership fields.
Later compromise of a recipient device DH key exposes captured wrapper metadata. Direct-message sender sealing and encrypted message padding
are specified in [client privacy revision 2](client-privacy-v2.md); they do not
constitute complete sender anonymity or hide all relationships.

## Paths and correlation

Message submission uses the privacy edge. Development native source can also
route configured directory, prekey and proof operations through the default-off
[OHTTP relay and gateway](../ops/cloudflare/OHTTP.md). Required mode refuses
direct fallback; matching native artifacts and production activation remain
open. In off mode those operations, and currently mailbox fetch/stream/ACK,
object reads/uploads and push registration, connect to their configured service
endpoints. Those services see the connection IP and
request timing; directory lookups include the requested username or account ID,
mailbox fetch, stream, and acknowledgement carry a device signature over the
hashed mailbox address (the published address alone authorizes only deposits),
object operations carry the object capability, and push registration associates a mailbox with a push binding.
Shared infrastructure or colluding operators can correlate those paths. Sending
through the privacy edge does not conceal this traffic.

Consumed one-time prekeys retain their claim hashes, exact responses and
consumption times while a response remains usable. The implemented retention
worker deletes those fields only after the earlier signed bundle/credential
expiry has passed, with an inclusive retry boundary. Cleanup defaults off until
the compatible server rollout is complete. Enabled cleanup may lag because of
backlogs or busy devices; malformed or unverifiable legacy responses remain
unpruned. Timestamp-free retired key IDs and public keys remain linked to their
device to prevent reactivation, so this does not erase all session metadata.
There is no universal retry TTL for custom signed expiries. See
[consumed prekey retention](../services/directory-delivery/PREKEY_RETENTION.md).

In off mode, checkpoint gossip consistency reads use the saved directory origin
directly; configured required mode uses the pinned OHTTP gateway. They carry
only an exact pair of public tree sizes, not contact,
account, group or message identifiers. The directory can still observe the
request's IP, timing and size range. Reads are limited to once an hour per peer
account across direct and group conversations. Signed fork evidence is retained
locally. With release-pinned relays configured, the native client can submit
the public fork proof and independently read its finalized receipt. Relays and
RPC providers see the connection IP, timing, public proof and any finder address
in that proof. Public relay deployment is not claimed. See
[checkpoint gossip](checkpoint-gossip-v1.md) and [phone filing](phone-filing-v1.md).

## Stored metadata and cleanup

Migration 029 rounds existing envelope `received_at` values and new defaults to
the minute, and rejects writes with finer precision. Sequence numbers still
preserve ordering. Expiry, storage entitlements, ACK times and operational
outbox timestamps retain their precision; an observer of live traffic can still
measure exact timing.

An ACK immediately hides an envelope from fetch and releases mailbox capacity.
Its row is eligible for deletion after one hour, or sooner if its effective
expiry is reached. This retry window preserves the mailbox/envelope identifier
for duplicate-delivery handling; it is not another hour of readable mailbox
history. Rate-limit and spent-work buckets become eligible for deletion after
one day. Cleanup is bounded and can lag those deadlines during downtime or a
backlog; they are eligibility thresholds, not guaranteed deletion instants.

When transparency retention is enabled, superseded account/device entry content
older than 90 days is eligible for pruning. The current entry, commitments,
sequence numbers, leaf hashes and Merkle nodes remain. Device records shared
with a retained entry also remain. Retention is off by default; dry-run does not
delete anything. See [key transparency](key-transparency-v1.md#entry-storage-and-retention).

## Directory probing and push providers

A successful username lookup and a missing username return distinguishable
responses (200 and 404). Proof of work raises the cost of probing; it does not
hide whether a username exists or prevent enumeration by a determined caller.

For push registration the phone sends its raw APNs or FCM token, installation
device identifier, app/project identifiers and development flag directly to
Expo. Expo sees the phone's connection IP and can associate these values with
the resulting Expo push token. Apple or Google handles delivery using its own
device token and sees notification delivery timing. The generic wakeup contains
no message body, sender name or attachment name. This provider visibility is not
removed by sealing the token for Morse's push broker.

## Credit issuance and spending

The issuer observes purchase quotes, asset amounts, payment evidence and blinded
issuance requests. On-chain payments and treasury transfers are public; a wallet
or Lightning provider can associate its own payment activity with its customer.
The blinded credit token contains no wallet address or purchase reference.
Redemption exposes tokens, nullifiers and the action being authorized to the
relevant service, which retains replay/recovery records under that action's
policy. Blind issuance does not hide network timing, pack sizes or correlations
between colluding services. See [credits](credits-v1.md),
[Lightning purchases](credits-lightning-v1.md) and [postage](credits-postage-v1.md).
