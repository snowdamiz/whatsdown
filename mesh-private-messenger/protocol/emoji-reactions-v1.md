# Emoji reactions

Reactions are application content carried through the existing encrypted direct
and group message paths, including the durable outbox and encrypted local history.
The server receives no new plaintext metadata or reaction endpoint.

The UTF-8 body is `MORSE-REACTION/1\n` followed by a JSON array containing:

1. The target message ID, as lowercase hex (16 bytes for direct messages, 32 for groups).
2. One of `👍 ❤️ 😂 😮 😢 🙏 🎉 👎`, or an empty string to remove the sender's reaction.
3. A positive safe-integer revision in Unix milliseconds.

Each authenticated account has one reaction per target. Direct histories distinguish
the local account from the peer using the core's sent/received direction; group
histories use the authenticated sender account, so linked devices count once.
The payload cannot supply an actor. The highest revision wins; equal revisions
choose the lexicographically smaller emoji, with removal winning over any emoji.
Explicit replacement/removal makes duplicate and reordered deliveries idempotent.

The UI folds these events into visible targets. Reserved malformed controls and
controls for absent targets produce no bubbles, previews, or unread messages.
Events follow the existing history retention and disappearing-message policies;
they do not create a separate durable reaction store. Older clients may show the
control body as text and must be upgraded for the reaction UI.

New group history records append a ninth field containing SHA-256 of the canonical
encrypted group message. Sender and recipients compute the same ID independently
of local receipt times. The core still reads seven- and eight-field records, and
exports an empty ID for those legacy messages. Their IDs cannot be recovered from
plaintext history, so the UI offers reactions only on newer group messages.

Checks: `npm test` and `npm run typecheck` in `apps/mobile`; build the desktop web
bundle, then run `node scripts/test-reactions.mjs` in `apps/mobile`. The native
`tests/groups.test.mpl` exercises matching sender/recipient IDs through encryption
and persisted history.
