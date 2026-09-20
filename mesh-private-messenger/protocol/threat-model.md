# Threat Model

Status: development baseline. This model defines what implementations and
reviews must test; it does not establish that the current software is secure for
production use.

## Assets and trust boundaries

Protected assets include message and attachment plaintext, private device and
account keys, session and ratchet state, recovery secrets, local contact names,
conversation metadata, and mailbox capabilities.

User devices perform protocol state transitions and hold decryption keys.
Directory and transparency services hold public identity material. Delivery
services and PostgreSQL hold opaque mailbox envelopes. The connection edge can
observe source addresses and timing, and the push provider can observe generic
wakeup timing. No server component should automatically possess all metadata;
this holds only under the separated edge, witness, and backend deployments
described in the operations guide, and never against one operator who controls
all of them.

## Adversaries in scope

- A curious or compromised delivery server, database, object store, or cluster
  node
- A network attacker or denial-of-service attacker
- A malicious sender, recipient, or unauthenticated client
- Any third party who knows a username, and therefore that account's public
  device credentials and mailbox addresses, attempting to read, watch, or
  remove another device's queued envelopes
- A dependency supply-chain attacker
- An operator who accidentally logs secrets
- A server attempting silent device-key substitution or protocol downgrade
- A delivery service that replays, duplicates, drops, delays, or reorders data

## Adversaries partly in scope

A compromised push provider, privacy edge, directory service, transparency
witness, or regional network observer is mitigated through split trust, generic
push payloads, key transparency, independent witnesses, and optional relays.
These controls reduce exposure; they do not eliminate it.

## Out of scope for confidentiality

- A fully compromised sender or recipient device
- A user voluntarily exporting or forwarding content
- A camera or screenshot capturing the display
- A global observer with complete network visibility and no cover traffic

## Target security properties

The protocol targets confidentiality, integrity, sender and recipient
authentication, forward secrecy, post-compromise recovery, replay resistance,
bounded reordering and duplicate tolerance, visible device revocation,
detectable key substitution, bounded work under hostile input, downgrade
resistance, and explicit versioning.

Authentication failure must not mutate committed session state. Superseded
secret material must be destroyed. Unknown mandatory protocol elements and
resource-limit violations must fail explicitly. PostgreSQL commit is the
durability boundary; a lost actor wakeup may delay retrieval but must not lose a
committed envelope.
