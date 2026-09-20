# Quote replies

A reply is application content carried through the existing encrypted direct and
group message paths, including the durable outbox, attachments and encrypted local
history. The server receives no new plaintext metadata or reply endpoint.

The UTF-8 body is `MORSE-REPLY/1\n`, the target message ID as lowercase hex (16
bytes for direct messages, 32 for groups), `\n`, and then the reply's own words,
which may be empty when the reply is only attachments. IDs are the ones
[emoji reactions](emoji-reactions-v1.md) use, so legacy group records without an
ID can be neither quoted nor reacted to.

The header names the target and nothing else. The quoted sender and words are
never on the wire: every reader draws them from its own authenticated history.

- A reply cannot attribute words to someone who did not send them. A forged or
  unknown target quotes nothing.
- A quote lives exactly as long as the message it quotes. When the target expires
  under the disappearing-message timer or leaves the bounded history, the reply
  keeps its words and shows that the original is unavailable.
- Quotes are one level deep. A quoted reply shows its own words, not its quote, so
  messages naming each other cannot form a cycle.

A body that starts with the prefix but has no valid header is ordinary text; no
message is dropped. Replies are ordinary messages in every other respect: they
notify, count as unread, take reactions and can themselves be quoted. Older
clients show the header as text above the words and must be upgraded for the UI.

Checks: `npm test` and `npm run typecheck` in `apps/mobile`; build the desktop web
bundle, then run `node scripts/test-reactions.mjs` in `apps/mobile`.
