# Safety Number Codes, Version 1

Status: implemented in `packages/mobile-core/mobile/safety_code.mpl` and the app
(`apps/mobile/src/EphemeralDialogs.tsx`). Checks: `tests/safety_code.test.mpl` in
`packages/mobile-core`, `npm run test:ephemeral` in `apps/mobile`.

Two people compare a chat's safety number to know that nobody sits between
their devices. Reading 64 digits aloud still works ("Mark as verified"). A
safety code does the same comparison by camera or by pasting: one device shows
its code as a QR code, the other scans or pastes it, and the core compares.

## The safety number

Unchanged: for accounts `A` and `B`, each identity is `account_id (32) ||
authorization_public_key (32)`. With the two identities in ascending byte
order as `first` and `second`,

```text
safety_number = lowercase_hex(SHA-256("mesh-msg/mobile/account-safety/v2" || first || second))
```

64 lowercase hex digits, the same on both devices.

## The code

One line of ASCII, no whitespace:

```text
morse-verify:1:<shower account ID>:<viewer account ID>:<safety number>
```

- `morse-verify` names the kind of code and `1` its version.
- `<shower account ID>` is the account whose device shows the code, 64 lowercase hex.
- `<viewer account ID>` is the account it is shown to, the other side of the
  chat, 64 lowercase hex.
- `<safety number>` is that chat's safety number as above.

A code is 209 characters, which a QR code holds at error-correction level M in
one frame. The app draws it with `react-native-qrcode-svg`, as it draws contact
and device codes, and offers the same text under "Show text code".

`mesh_messenger_safety_code` (path, peer) returns the code this device shows for
its chat with that peer. It fails with `safety_number_unavailable` while the
chat has no safety number yet (no message exchanged, or the peer's keys changed
and a new session has not started).

## Checking a code

`mesh_messenger_safety_code_check` (path, peer, scanned text) trims the text and
answers with one of four words:

| Answer | When | Effect |
|---|---|---|
| `invalid` | The text is not `morse-verify:1:` followed by three fields of 64 lowercase hex | None |
| `wrong_contact` | The shower is not this chat's peer, or the viewer is not this account: the code was made for another chat, or it is this device's own code | None |
| `mismatch` | It is the peer's code for this account, but its safety number differs from this device's | The chat is no longer marked verified (policy action 6); `key_changed` is not set |
| `verified` | It is the peer's code for this account and the numbers match (constant-time comparison) | The chat is marked verified exactly as "Mark as verified" does (policy action 4) |

The account IDs in the code only route the comparison: they make a code scanned
in the wrong chat say so plainly instead of reading as an attack. The security
rests on the safety number, which binds both accounts' authorization keys.

A mismatch means the two devices see different keys for one of the accounts:
someone may be between them, or one device has not caught up with a key change.
The app says "The codes don’t match" and asks the person not to trust the chat
until they have compared again. Scanning a stale code (a photo taken before a
key change) also reads as a mismatch, which is the safe way to be wrong.

## Where it is offered

- Phone: conversation details → "Verify with a code" shows this device's code,
  with "Scan their code" (the camera through `expo-camera`, QR codes only; frames
  never leave the device) and "Paste their code".
- Desktop: the same dialog shows the code and offers "Paste their code"; it has
  no camera flow.
- "Mark as verified" stays for people who compare the digits by eye or aloud.

Safety codes carry nothing secret: the account IDs and the safety number are
what the two people are comparing. A code does not travel over the network; it
is shown and scanned in person or pasted from a channel the two already trust.
