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
| Source IP address | Visible to the connection edge; on desktop, also to GitHub when the user checks for an update |
| Message timing | Observable in reduced form |
| Message size | A power-of-two size bucket; legacy packets may expose exact lengths |
| Packet kind and protocol suite | Hidden: every new envelope is outer suite `4`. Only the size bucket hints at kind; legacy outer suites `1`-`3` named it |
| Push timing | Visible to the push provider |
| Social graph | Reduced, not eliminated |
| Local history | Visible to an attacker controlling the endpoint |
| Screenshots and forwarding | Not preventable |

Push notifications contain only a generic encrypted-message wakeup. Object
storage receives random object identifiers, encrypted chunks, approximate
sizes, access times, and expiry; it does not receive file keys, names, MIME
types, identities, or conversation identifiers.

In sealed-delivery mode the privacy edge receives the source connection, an
opaque sealed record, and an anonymous proof of work. The delivery core receives
the mailbox capability only after unsealing a request forwarded by the edge, so
it observes the edge connection rather than the sender connection. Direct and
internal delivery endpoints require production network policy as specified by
the [sealed-delivery contract](sealed-delivery-v1.md).

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
legacy packets still expose their original identifiers and membership fields.
Later compromise of a recipient device DH key exposes captured wrapper metadata. Direct-message sender sealing and encrypted message padding
are specified in [client privacy revision 2](client-privacy-v2.md); they do not
constitute complete sender anonymity or hide all relationships.

## Paths and correlation

Only message submission uses the privacy edge. Directory and prekey lookups,
mailbox fetch/stream/ACK, object reads/uploads, and push registration connect to
their configured service endpoints. Those services see the connection IP and
request timing; directory lookups include the requested username or account ID,
mailbox fetch, stream, and acknowledgement carry a device signature over the
hashed mailbox address (the published address alone authorizes only deposits),
object operations carry the object capability, and push registration associates a mailbox with a push binding.
Shared infrastructure or colluding operators can correlate those paths. Sending
through the privacy edge does not conceal this traffic.
