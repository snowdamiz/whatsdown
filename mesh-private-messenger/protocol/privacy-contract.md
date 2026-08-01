# Privacy Contract

Status: development contract. It states the intended visibility boundaries; it
is not a production-security claim.

Whatsdown encrypts message content on user devices. Delivery services store and
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
| Conversation identifier | Never clear in delivery records |
| Sender identity | Hidden from delivery in sealed-delivery mode |
| Destination | Opaque mailbox token visible to delivery |
| Username | Visible to the directory in the initial design |
| Device public keys | Visible to directory and transparency services |
| Source IP address | Visible to the connection edge |
| Message timing | Observable in reduced form |
| Message size | Approximate size is visible; padding reduces precision |
| Push timing | Visible to the push provider |
| Social graph | Reduced, not eliminated |
| Local history | Visible to an attacker controlling the endpoint |
| Screenshots and forwarding | Not preventable |

Push notifications contain only a generic encrypted-message wakeup. Object
storage receives random object identifiers, encrypted chunks, approximate
sizes, access times, and expiry; it does not receive file keys, names, MIME
types, identities, or conversation identifiers.

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

Whatsdown does not claim to prevent global traffic analysis, endpoint malware,
recipient disclosure, screenshots, compelled access to an unlocked device,
push-provider timing correlation, or long-term metadata correlation without
cover traffic. A fully compromised sender or recipient device can reveal the
content available to that device.
