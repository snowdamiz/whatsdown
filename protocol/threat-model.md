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

## The public record

Phones check what the directory showed them against the checkpoints anchored
on Solana ([key-transparency-v1.md](key-transparency-v1.md), "The phone's
check against the public record"). The chain can only take trust away: a
slashed service key or a view that does not match fails new sessions and key
changes closed, and nothing read from the chain ever makes a phone accept a
key it would otherwise refuse.

- **RPC providers that lie.** Phones read from pinned providers directly,
  never through Morse, and a read counts only when two of them return the same
  bytes; a third is asked after a disagreement. Providers that disagree give a
  warning (`rpc_disagree`), never a pass. A single lying provider is
  outvoted; providers that all serve the same forged record can at worst make
  a phone raise a false alarm, never accept a fork: the directory can't prove
  the phone's view consistent with a record it never signed.
- **RPC providers that profile.** They learn the phone's IP address and that
  it reads the anchor accounts, about once a day and when the person opens
  Settings → Network. The reads are the same for every phone and name no
  account. Releases rotate providers.
- **A directory that stops answering** the consistency query is
  `directory_unavailable` and retried, so an outage never blocks messaging; a
  refusal (4xx) or a proof that does not verify is a mismatch. A mismatch that
  a later check disproves clears itself: a real fork can never later prove
  consistent.
- **Anchoring that stalls** (a Solana outage, censorship) shows "Public record
  is behind" after two hours and never blocks.
- **Relays.** Evidence goes to every pinned relay. A relay sees the phone's IP
  and the proof; it can refuse or sit on it (the others still land it) or land
  it with its own address as the finder, which only changes who is paid, and
  the phone shows where the bounty went.
- **A split view.** Every direct message carries the sender's view of the log
  ([checkpoint-gossip-v1.md](checkpoint-gossip-v1.md)), so to fool one person
  the directory must fool everyone they message. Two phones holding
  service-signed checkpoints that cannot both be true each build `FRK`, raise
  the same blocking alarm and post the proof to the relays; the one whose view
  also disagrees with the anchor ring was targeted. Gossip only compares people
  who message each other and never replaces the anchor check.
- **A hostile contact inventing gossip.** A hint is unsigned, so it never
  blocks anything: it costs at most one checkpoint request a day to that
  contact. Only a checkpoint signed by the pinned service key can raise an
  alarm, and only Morse can sign one. A checkpoint that fails the signature is
  dropped and the contact is not asked again for a day.
- **Gossip used to probe when someone was online.** The tree size in a message
  shows when the sender last refreshed, which matches the send time anyway.
  Only accepted, unblocked conversations are heard or answered, and a device
  answers a contact's requests at most hourly.
- **Evidence at rest** is sealed with the device's storage key like every
  other record.

## Backups

A backup is only as safe as its recovery code. A backup from the device that
created the account carries the account key, sealed under a key derived from
the code, so that the account survives the loss of every device: whoever holds
the code can therefore take over the account (add a device, remove the others,
delete it) and read the backed-up history, for as long as a backup made with
that code is stored. The code is 256 random bits, so only its storage matters;
it is shown once, kept nowhere on the device, and the app asks for it to be kept
like a password. Backups from linked devices carry no account key and open
history only. No backup holds a ratchet or group state, so a leaked code never
opens live sessions, and every device added with it is a logged transition the
account's other devices see. The object
store is in scope as a curious server: backups carry attachment framing, size
buckets and lifetimes, and code-derived IDs, so objects do not reveal their
owner or that they are backups; upload cadence and deletions can
([privacy contract](privacy-contract.md#backups)). A restore never replays
ratchet or group state, so a stale backup cannot cause key or nonce reuse, and
it adds history only to a device the account already linked.

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
