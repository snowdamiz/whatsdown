# Checkpoint gossip

Direct messages carry optional `PAY` extension 2: the newest locally verified
checkpoint's `u64` tree size followed by its 32-byte root. These 40 bytes travel
inside the encrypted envelope. The sender retains its application body, and
older decoders ignore the optional extension. Group application messages use
the same hint inside the encrypted payload of `GMS` message version 5 below.

The phone skips its own size/root and a pair it has already proved consistent.
Otherwise it fetches one compact consistency proof for the exact size range
from its saved directory origin. The profile follows its authenticated local
checkpoint. Requests have a three-second timeout, a 1,070-byte response cap,
no redirects, and u32 tree-size bounds. The hourly budget is persisted before
the fetch. The limiter uses the peer account, covering all its devices and old
conversation aliases. It therefore permits at most one fetch per conversation
per hour, including across restarts and backward clock changes. Direct and group
exchanges share the account budget, so additional groups cannot multiply it.

Missing or invalid consistency evidence is not proof of a fork. It may enqueue
one checkpoint request per peer account per 24 hours. Controls use message type
5, have no attachments or visible history entry, and travel only on an existing
accepted, unblocked ratchet session, or an already authorized linked-device
session for the same account. Sibling controls use the self-sync conversation
identity and do not require a contact's message-request acceptance. A control never creates an initial session
that an older receiver would discard. The ordinary durable outbox commits the
advanced send ratchet and queue removal atomically. Full outboxes leave controls
pending; repeated reads reuse the same encrypted envelope.

## Controls

All integers are unsigned and big endian. `KTK` and `KTW` use their canonical
versioned codecs. A vector is a u32 byte count and those bytes.

```text
CheckpointRequest (60 bytes)
  version:u8 = 1, tag:3 = "GQR", request_id:16, hint:40

CheckpointAnswer (at most 2,987 bytes)
  version:u8 = 1, tag:3 = "GQA", request_id:16, request_peer:u8 (0 or 1)
  checkpoint:188, attestations:vector (at most 2,774 bytes)
```

A request gets the sender's latest checkpoint and attestations, with
`request_peer=1`. A valid answer to an outstanding local request gets one
reciprocal answer with `request_peer=0`. Request identifiers prevent unsolicited
answers and replay loops; a peer gets at most one initial answer per day.
Malformed controls and bad service signatures are silently ignored. The daily
request budget remains spent. Blocked contacts cannot influence gossip state.

## Groups

`GMS` message version 5 retains the existing schedule-v2 sender ratchet,
signature and outer recipient encryption. Its authenticated version selects the
following plaintext framing. The outer recipient transport supplies padding,
as it does for version 4. Changing the version byte invalidates authentication.

```text
Application (at most 65,290 bytes)
  version:u8 = 1, tag:3 = "GAP", kind:u8 = 1
  hint:vector (empty or 40 bytes)
  body:vector (at most 65,237 bytes, including presentation/attachment framing)

Control (at most 3,044 bytes)
  version:u8 = 1, tag:3 = "GAP", kind:u8 = 5
  recipient_account:32, recipient_device:16
  body:vector (a GQR or GQA, at most 2,987 bytes)
```

Members can exchange controls without a direct session. A control is encrypted
to the existing group and delivered to every other member, keeping sender
generations in step. Only the addressed device processes it; other devices
advance the ratchet without responding. No device displays it in history.
The group reveals these public checkpoints and their signed attestations to
its members. Servers receive only padded recipient ciphertext.

A sealed pending-peer index holds at most 256 group controls, sharing the
account limits above. A full index drops the new control while retaining the
spent check/request budget. A full outbox or unavailable verified recipient
material leaves an admitted control pending. Group state, outbox envelopes and
queue consumption commit together. Each flush sends at most eight group
controls, subject to the existing 256-envelope outbox cap, including any epoch
refresh. Removed members and blocked contacts lose their queued controls.
Epoch refresh preserves the admitted roster and witness policy.

Version 1–4 stored messages remain readable as their original application
bodies. New group sends use version 5 and require a native build that supports
it; older native builds reject it. There is no ambiguous prefix detection or
fallback that could display a control as text.

The phone verifies both service signatures against its native pin. Equal-size
root conflicts and sequence/size rollback conflicts produce a canonical `FRK`
through the shared verifier. Both phones retain evidence independently, even
if one subsequently loses network access. A missing consistency proof, a
different root at a different size, or a legacy/RFC profile transition cannot
alone prove a fork. A kind-2 claim needs actual contradictory inclusion paths;
the phone does not invent them from a failed consistency fetch.

The proof includes up to eight pairs of double-signing witness attestations
within FRK's 16-signature bound. Missing witness signatures never conceal a
directory fork. Historical verification does not apply the current freshness
window to old signatures. Until bounty wallets exist, the finder address is
all zeroes; it is never derived from a messaging identity.

## Local response

The first verified proof is sealed separately from contact and ratchet state;
later hints cannot replace it. New direct sessions, new groups, group admissions,
linked-device authorization, and witness-policy changes pause. Lookup can
refresh the exact previously trusted device set but cannot admit a changed or
new set. Automatic credential renewal pauses. Established messaging and its
ordinary ratchet/key evolution continue; removing access remains available.

The persistent banner opens Details with a copyable FRK hex encoding and filing
status. Evidence is currently retained locally; relay submission belongs to the
public-checkpoint phase. The native `mesh_messenger_transparency_fork` export
returns this verified evidence or an empty value, so JavaScript does not make a
cryptographic trust decision. No in-app dismiss or reset removes the pause.

Focused native tests cover invented hints and bad signatures, durable daily
limits, two conflicting phones, encrypted request/answer/reciprocal delivery,
outbox retries, and continued established messaging with new sessions paused.
Group proofs cover two members with no direct session, a third device ignoring
controls addressed elsewhere, missing recipient material recovering without
losing the queue, unchanged visible history, and the maximum payload boundary.
