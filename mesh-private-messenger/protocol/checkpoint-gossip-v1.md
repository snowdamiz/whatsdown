# Checkpoint gossip v1

Status: implemented. The frames and pure decisions are `Transparency.Gossip`
in `packages/messenger-protocol`; the phone side is `Mobile.GossipState`,
`Mobile.GossipRun` and `Mobile.GossipEvidence` in `packages/mobile-core`
("Mobile transport" below), with tests in `tests/transparency_gossip.test.mpl`
and `packages/mobile-core/tests/gossip.test.mpl`.

Every direct message carries the sender's view of the key log, and every phone
compares what it receives with its own. To fool one person, a split view then
has to fool everyone that person talks to, and everyone they talk to. Gossip
adds evidence to the witness threshold and the chain anchor check; it never
replaces them.

All integers are big-endian. `vector32(x)` is `u32 length || x`. `KTK` is the
188-byte checkpoint and `KTW` v2 the attestation list of
[key-transparency-v1.md](key-transparency-v1.md).

## The hint: inner-envelope extension 2

```text
tree_size:u64 || root:32                                   (40 bytes)
```

The newest checkpoint the sender verified: its tree size and Morse root. It is
optional (flag `0`) and rides inside end-to-end encryption, beside extension 1,
the contact address ([canonical-codecs-v1.md](canonical-codecs-v1.md), "Inner
envelope"). No server sees it. A size of 2^62 or more, or any length other than
40, makes it malformed; a malformed hint is ignored, never an error. A client
that does not know extension 2 keeps and ignores it.

`gossip_encode_hint`, `gossip_decode_hint`, `gossip_hint_extension` and
`gossip_hint_from_extensions` build and read it.

## Control frames

```text
GCQ  u8 1 || "GCQ" || tree_size:u64 || root:32                        (44 bytes)
GCA  u8 1 || "GCA" || vector32(KTK) || vector32(KTW v2) || ask_back:u8 (0 | 1)
```

`GCQ` asks the sender of a hint for the signed checkpoint behind it. `GCA`
answers with that checkpoint and the attestations the sender verified it with,
at most 2,847 bytes; `ask_back = 1` asks the receiver for its own in return.
Decoders refuse other versions, an `ask_back` other than 0 or 1, a KTK that is
not 188 bytes, an invalid `KTW` v2, truncation and trailing bytes.

## What the receiver does

1. It skips any tree size and root it has already verified.
   `gossip_hint_action(own_size, own_root, hint)` answers `skip` for its own
   view, `check` for another size, and `ask` for the same size with another
   root, where no consistency proof can exist.
2. For `check`, it fetches one consistency proof between the two sizes (`KTS`
   v2), at most once an hour per conversation. If it verifies, nothing happens.
3. For `ask`, a failed proof or no proof served, the receiver still holds only
   an unsigned hint, which a hostile contact could invent. It sends `GCQ`, at
   most once a day per contact.
4. The sender answers with `GCA`, `ask_back = 1`, and the receiver answers that
   with its own `GCA`, `ask_back = 0`.
5. Each phone now holds two service-signed checkpoints and calls
   `gossip_compare(own, other, log_key, consistency_path)`:
   - a checkpoint that fails the log's signature is refused
     (`gossip_checkpoint_rejected`): drop it and do not ask that contact again
     that day, so an invented hint costs one control message and never blocks
     anything;
   - `consistent`: the same checkpoint, the same size and root, or a verified
     consistency proof;
   - `fork` with kind 1 (same size, different roots) or 3 (sequence and size
     disagree): build `FRK` from the two checkpoints and the attestations each
     side holds ([witness-network-v1.md](witness-network-v1.md), "Fork
     evidence") with the phone's own finder address;
   - `check`: sizes differ in the right order but no consistency proof
     verified. The phone asks the directory (`KTP` v2) for each leaf it looked
     up, at that index in the contact's tree; one that reads differently
     proves kind 2. Finding none proves nothing, and nothing is raised.
6. A phone that holds a valid `FRK` raises a `contact_fork` trust alarm: it
   blocks new sessions and key changes, keeps the evidence for "Details" and
   posts the proofs to every pinned relay. The phone whose view also disagrees
   with the anchor ring was the one targeted.

## Limits

| What | Limit |
|---|---|
| Hint | 40 bytes per direct message (47 with the extension's framing), inside the existing padding buckets |
| Consistency proofs fetched for gossip | at most 1 per conversation per hour, for hints and signed checkpoints together |
| `GCQ` sent | at most 1 per contact per day |
| After a checkpoint fails its signature | no further `GCQ` to that contact for a day |
| `GCA` sent | at most 1 per contact per hour; a request that arrives inside the hour is not answered |
| `GCA` | at most 2,847 bytes |
| Leaf queries (`KTP` v2) per signed checkpoint compared | at most one per leaf this device looked up (its last 8 lookups); at most 2 proofs built |
| Notes waiting | at most 32, one per kind and contact device; dropped after 2 days |
| Proven hints remembered | the newest 64 |

Direct messages carry the hint from this version; group application messages
from the next group wire version ("Groups" below).

## What a contact learns

The size and root of the log when the sender last refreshed its view. Both are
public, since every checkpoint is published, and the timing matches when the
message was sent. The hint names no account, device or lookup. A `GCA` reveals
the same checkpoint in signed form and which witnesses attested it, which is
also public.

Gossip only compares people who message each other. Someone who talks to
nobody is covered by the chain anchor check alone.

## Mobile transport

How `packages/mobile-core` carries the hint and the two frames, and what it
keeps. The app only carries requests and drains the outbox.

### Sending the hint

`outgoing_extensions` (the one place every outgoing inner envelope gets the
contact address) appends extension 2 whenever the device holds a verified view
(`KTV` v2): the view checkpoint's tree size and root. That covers every direct
send: a new conversation, a message in one, the fanout to each of the peer's
devices and to the account's own other devices, session reset messages and the
two gossip frames themselves. A device with no verified view sends no hint, and
a view that cannot be read never stops a send. History keeps no extensions.

### Noting what arrives

After an inner envelope authenticates (the handshake or ratchet opened it and
its sender account and device are the session's), the receive path hands it to
`gossip_received`, in its own write, as it does the contact address: a message
delivered again says the same. Only a conversation the device listens to is
heard: accepted (request state 1) and not blocked. A stranger's message
request, or a blocked contact, is ignored. Noting never fails a delivery.

- A hint (extension 2 on any message but type 7) is compared with the view:
  its own view, or one of the newest 64 hints it already proved, is skipped;
  the same size with another root becomes an **ask**; another size becomes a
  **check**. A malformed hint, or none, is ignored.
- A `GCQ` becomes an **answer** (a `GCA` with `ask_back = 1`).
- A `GCA` whose checkpoint fails the pinned service key is dropped, and the
  contact counts as asked now: no `GCQ` goes to it for a day and any waiting
  ask is removed. Otherwise it becomes a **compare** holding the `KTK` and
  `KTW` v2, plus an **answer** with `ask_back = 0` when it asked back.

A note waits in the local record until a run settles it: one per kind and
contact device (a newer one replaces it), at most 32, dropped after two days.

### The control messages

`GCQ` and `GCA` travel as inner messages of **type 7** whose body is exactly
the frame: sender and recipient device as in any message, the direct
conversation's ID (the self-sync ID between an account's own devices), no
attachment, receipt policy 0, no timer, and the sender's usual extensions.
They go in the existing session with that one device, never a new one, and
leave through the outbox like any message, without delivery marks. None is
sent when the conversation is blocked or not accepted, when a reset replaced
the session, or when the outbox is full.

A receiver stores a type 7 message nowhere but the gossip record: the session
advances, the envelope is acknowledged, and history never sees it, so it is
never shown. A build without gossip rejects type 7 like any unknown type,
unshown, but is never sent one: a `GCQ` goes only to a device that sent
extension 2, and a `GCA` only to a device that sent a `GCQ` or a `GCA` asking
back.

A `GCA` carries the device's view checkpoint and the kind-1 attestations it
verified on it (kept with its recent lookups).

### The run

`mesh_messenger_gossip_check` settles the notes in the anchor check's step
framing (`Mobile.AnchorSteps`, [key-transparency-v1.md](key-transparency-v1.md)):
the input is `vector32(database path) || vector32(u16 n || n x exchange)` and
each call answers an `ACS` step with the requests still needed. It uses the
directory's `POST /v1/transparency/consistency` (`KTS` v2, tag
`gossip-consistency:<account>:<old>:<new>`) and `POST /v1/transparency/leaf`
(`KTP` v2, tag `gossip-leaf:<index>:<size>`), the finder-address request
(tag `gossip-finder:<proof hash>`), and the relays' `/v1/fork-evidence`. The
app runs it after every pass over the mailbox, then drains the outbox.

Notes are settled in order, and a conversation's hourly consistency proof goes
to the first note that needs it:

- **check**: its own view or a proven hint is done; the same size is an ask;
  a hint of size 0 needs no proof (the empty root). Otherwise, once the hour
  allows, one `KTS` v2 between the two sizes: proven, the hint is remembered
  and never checked again; no answer at all waits for the next hour; a refusal
  or a proof that fails becomes an ask.
- **ask**: a `GCQ` about the hint unless the contact was asked (or sent a bad
  checkpoint) in the last 24 hours, in which case it waits.
- **answer**: a `GCA` unless the contact was answered in the last hour, in
  which case it is dropped.
- **compare**: `gossip_compare` against the view. A bad signature is dropped
  as above. Consistent: remembered. Kind 1 or 3: `FRK` now. Sizes in order but
  unproven: once the hour allows, one `KTS` v2 between the two signed
  checkpoints; if it does not prove them consistent, the leaf search: each leaf
  this device looked up (its last 8 lookups) is asked for at the contact's
  size, and one proven under the contact's root that reads differently gives
  an `FRK` of kind 2 (the lookup's checkpoint, path and leaf against the
  contact's). At most two are built. None found is not a provable fork, and
  nothing is raised.

Each `FRK` carries the second checkpoint inline, pairs of attestations for up
to eight witnesses that attested both versions (the device's own, and the
contact's pinned kind-1 ones from its `GCA`), then any others up to 16, and a
finder address from the app's hook (zero while bounties are off). It is kept
only if `fork_verify` accepts it under the pinned service key and witness
list. The device then raises a `contact_fork` trust alarm with the two
versions and the proofs: new sessions and key changes fail with
`trust_alarm_active`, existing chats keep working, and the same run files
every proof with every pinned relay; a relay that did not answer is tried
again by the daily anchor check.

### What the app shows

"A contact's phone was shown a different key log." with the same pause as the
other trust alarms, and "Details" shows both versions, each proof and where it
was filed. Details also says which phone was targeted: this one if its own
public-record check also finds its view at odds with the chain (an active
`anchor_mismatch`), the contact's if a check that passed came after the fork
was raised, and otherwise that the next check will tell (or that the build
checks no public record). After a run raises the alarm the app runs the
public-record check, at most hourly.

### Local record

`checkpoint-gossip/v1`, sealed with the device's storage key:

```text
u8 1 || "CGS" || u8 v || v x (tree_size:u64 || root:32)      proven hints
|| u16 c || c x (account_id:32 || proof_at_ms:u64 || asked_at_ms:u64 || answered_at_ms:u64)
|| u8 p || p x vector32(note)
note = kind:u8 (1 check, 2 ask, 3 answer, 4 compare) || account_id:32 || device_id:16
       || received_at_ms:u64 || tree_size:u64 || root:32 || ask_back:u8
       || vector32(KTK or empty) || vector32(KTW v2 or empty)
```

A record that does not read starts over empty: gossip only ever adds evidence.

### Groups

Group application messages have no extension slot: their plaintext is the
presentation frame, and a new trailing field would read as a malformed body in
current builds. They carry the hint from the next group wire version. Until
then, group members compare views through their direct conversations.
