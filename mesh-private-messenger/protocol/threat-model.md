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

Checkpoint gossip compares service-signed views received inside authenticated
direct and group messages. Invented size/root hints and unavailable consistency
proofs cannot establish a fork or pause trust. Only a conflict verified against
the native service key can retain evidence and pause new sessions and key
admission. Per-account budgets survive restarts and cover direct conversations,
linked devices and groups together. Group controls are readable to existing
members, addressed to one device, and never displayed in chat history.
Gossip cannot compare users who never exchange messages, and suppression of
delivery can delay detection. Public anchors and relay filing remain separate
unfinished controls; safety-number verification remains available.

The implemented anchor reader requires two matching responses from three
sampled, pinned RPC origins and checks the expected program owner and log
identity. It detects disagreement and ring overwrites without treating either
as fork evidence. Origin separation alone does not prove operator independence;
release review must select independently operated providers. Two colluding
providers can forge a matching view. The Log reader additionally binds the
service key, log version and ring address to native pins and retains the slash
flag. The witness-set decoder and quorum reader bind a historical generation to
the expected log, preserving key identity across rotations and distinguishing
native from C2SP signatures. The judge now records both signature kinds within
1,500 slots and requires a 14-day delay before activating a new immutable set.
Chain registration does not itself make a witness a release pin or prove operator
independence. The phone derives the log/ring/generation PDAs locally using the
public Mesh Solana package; caller-supplied alternative addresses are rejected.
Freshness requires two providers to agree on the finalized posting slot's chain
time. Missing, conflicting or future time cannot manufacture a fresh result;
these and the two-hour stale threshold are notices, not fork evidence. Service
timestamps do not influence anchor age. Native program/log pin activation,
durable scheduling and the phone's full anchor verdict remain
unfinished; see [the account and reader contract](anchor-ring-v1.md).
