# Session reset, version 1

Development protocol; release readiness requires internal verification of the
exact candidate. No independent cryptographic audit is claimed.

A receiver keeps at most 64 skipped message keys and refuses a message more
than 64 ahead (`crypto-profile-v1.md`, "Development limits"). A device that
stays away until more than 64 consecutive messages from one sender have expired
used to find every later message from that sender too far ahead, and the
session went dark with nobody told (§22.3 C8). A session reset heals it: the
receiver asks, the sender starts a new session and sends again what it can.
The code is `packages/mobile-core/mobile/session_reset.mpl`, with the jump check
in `packages/messenger-protocol/session/ratchet.mpl`.

## Flow

R is the device whose receiving chain broke, S the peer device whose messages
it can no longer open.

1. **The trigger is authenticated.** R refuses a message as `ExcessiveJump`.
   It then derives that message's key without keeping any key in between, at
   most 16,384 positions ahead (`ratchet_jump_authentic`), and opens it. Only a
   message that opens counts: a forged or damaged cleartext header (version 3)
   or an undecryptable encrypted one (version 4) is `message_rejected` as
   before and asks for nothing. R also needs S to have advertised session
   resets (feature bit `4`, [`ratchet-message-v2.md`](ratchet-message-v2.md)),
   the session not to have asked already, the conversation not to be blocked,
   and S's identity key in the session record (written for every session
   created or sent on by this build).
2. **The request (inner message type 5)** goes in the broken session, in the
   direction that still works, R to S, so only R can have sent it: it is an
   ordinary authenticated ratchet message. It leaves through R's durable outbox.
   Body:

   ```text
   u8 version = 1 || "SRQ"
   u64 last received       newest client timestamp R holds from S's device, 0 if none
   u64 one-time prekey ID
   bytes32 one-time prekey R made for this reset and never published
   u32 length || R's current client profile (directory entry, bundle, credential)
   ```

   R marks the session record *asked* (`reset_state` 1) and stamps the
   conversation's reset time. The envelope that triggered it is acknowledged
   unopened (`session_reset_requested`); S sends it again.
3. **S checks the requester.** The profile must name the session's peer
   account and device and give the same safety number (the account
   authorization key), and the prekey must be 32 bytes. S builds R's bundle as
   the profile's normalized bundle with that prekey in the one-time slot.
4. **S starts a new session** with an ordinary signed-prekey handshake to that
   bundle (hybrid when both devices are suite `0x0002`), no weaker than the
   strongest suite S has seen from R's device, and never below the suite floor
   (a refusal is `session_reset_refused`). The credential and signed prekey are
   verified under R's account key as in any handshake; the one-time prekey came
   in R's authenticated request instead of from the directory. The first
   message (inner type 6) names the broken session and the newest message S
   holds from R:

   ```text
   u8 version = 1 || "SRA" || bytes32 broken session ID || u64 last received
   ```

5. **S sends again what it can**: its messages in that conversation from after
   R's newest, still visible (disappearing ones that expired are not), the
   newest 32 of them, oldest first, as ordinary messages in the new session,
   with their original message IDs and timestamps and attachments rewrapped to
   R's device. All of it goes through S's outbox with the retired session's
   write, in one transaction. R's newest has to be the exact time of a message
   S sent: R knows only the times of messages it received, so a device cannot
   ask for what was sent before it had anything (a device linked to R's account
   later, say); any other time, 0 included, gets nothing sent again.
6. **R does the same the other way** when the answer arrives: it sends again,
   in the new session, its own messages from after the newest one S holds, so
   messages lost in both directions are covered.
7. **Both sides retire the broken session** (`reset_state` 2): it stays
   readable for envelopes already on their way and is never chosen for sending
   again. R retires it when the answer arrives; the new session takes over the
   conversation (its record copies the old one's policy, verification and
   reset time). Neither side shows a message twice: a received message whose ID
   the conversation already holds from that sender is not added again.

Both conversations carry the reset time in their summary, and the app shows
"Secure session with @name was reset. Messages sent while it was broken were
sent again where they could be." for a week (`apps/mobile/src/session-reset.ts`).

## Why it cannot be forged or loop

- A network attacker holds no session key: it can neither make a far message
  that opens, nor send a request, nor answer one with a session R accepts (the
  answer is a handshake to R's prekey, authenticated by S's credential).
- A replayed request is refused by the ratchet; a replayed answer finds its
  one-time prekey gone.
- R asks once a session. S answers a request with a handshake, never with a
  request, and a request for a session S already retired changes nothing. A
  new session asks again only for its own jumps.
- If each side lost more than it can skip of the other's messages, each side's
  request is itself too far ahead for the other. A request is still read then:
  a far message that proves genuine and is a reset request from the session's
  peer is answered, without changing the broken session, and the receiver asks
  for nothing itself. If both had already asked, each answers the other with a
  new session; both are readable by both sides, and no answer asks for anything.

## What it does not do

- Messages sent before the other side's newest one, and more than 32 after it,
  are not sent again; nor is anything already gone from the sender's history
  (256 records) or expired, nor anything to a device that had received nothing
  from the sender yet.
- A gap longer than 16,384 messages cannot be authenticated, so the session
  stays dark as before. So does a session with a peer that predates resets, a
  session whose record never learned the peer's identity key (created before
  this build and never sent on since), and a new session below the suite floor.
- A reset needs one more handshake's worth of trust in R's bundle from R's
  account key; unlike a directory claim it is not checked against the
  transparency log. The device ID and the account key are the ones the broken
  session already authenticated, and renewal never changes a device's keys.

## Tests

`packages/mobile-core/tests/session_healing.test.mpl`: 70 of Bob's messages
lost, the 71st triggers exactly one request, a later far message asks nothing,
Bob's answer is one handshake and 32 messages sent again, Alice opens all of
them into her history, both conversations show the reset, and the two go on in
the new session; and a mutual loss, where each side's request is itself too
far ahead, heals in both directions. `ratchet_v4.test.mpl` checks that forged and damaged far
messages are not authentic, for both header versions, and a 3,000-message gap
that is.
