# Message receipts

Delivery and read receipts are application content carried through the existing
encrypted direct message path, including the durable outbox and encrypted local
history. The server receives no new plaintext metadata or receipt endpoint, and a
receipt envelope is padded and sealed like any other. The reserved
`receipt_policy` wire field stays `0`.

The UTF-8 body is `MORSE-RECEIPT/1\n` followed by a JSON array containing:

1. The state: `1` for delivered to one of the recipient's devices, `2` for read.
2. A watermark: a positive safe-integer timestamp in Unix milliseconds.

A receipt is cumulative. It acknowledges every message from the other side whose
timestamp is at or before the watermark. That timestamp is the one the sender
stamped, so only the sender's clock is involved. Read implies delivered. The
highest watermark per state wins, so duplicate and reordered receipts converge.

The payload cannot supply an actor or a target; both come from the authenticated
history record. A receipt only reaches messages that precede it in the local
history, so a forged watermark cannot acknowledge a message that had not been sent
when the receipt arrived. A message that crosses a receipt in flight stays
unacknowledged until the next one.

## When receipts are sent

- **Delivered:** after a mailbox sync in which new messages arrived, one receipt
  per conversation. History from before the local notification journal existed,
  such as before an upgrade, is never acknowledged. The foreground does not wait
  for the send; a headless wakeup does, before the OS suspends it.
- **Read:** when a loaded, visible, focused conversation marks messages as read,
  one receipt for everything on screen. A conversation that is open and sends read
  receipts skips the delivery receipt, since read says both.
- Never for message requests or blocked conversations, so a stranger learns
  nothing. The core's trust policy applies as it does to any send.
- Receipts and reactions are not acknowledged, so receipts cannot echo.
- Receipts a linked device sent arrive here as sent records, so devices do not
  repeat each other.

Sending is best effort. A lost receipt is covered by the next one.

Read receipts can be turned off per account. Doing so also hides the other side's
read state, leaving "delivered". An unreadable preference counts as off. Delivery
receipts are always sent.

## What the sender sees

A sent bubble shows one of five states, and the first three come from the core's
own record of what became of the message's envelopes. One message fans out to
several envelopes; the ones addressed to the other side are linked to it when
they are queued. *Sending*: none of them has been accepted yet and some still
wait. *Sent*: at least one was accepted, or none was addressed outward. *Not
delivered*: every one of them was refused for good, because its mailbox was
revoked or it waited out its 30 days. That state is stored, so it survives a
restart, and a message that reached any one of the other side's devices never
shows it. Then *delivered* and *read*. A receipt outranks all three: the other
side has the message, whatever one device refused.

The state used to be inferred from the oldest envelope still queued. That stops
being true once an envelope for a recipient who cannot take it now is allowed
to wait while later ones leave, which is what keeps one full mailbox from
holding up everybody else.

Each side's disappearing timer stamps only what it sends, so a receipt can expire
long before the message it acknowledged. To keep a message's state from going
backwards, the sync that receives receipts keeps, per conversation, the newest
acknowledged timestamp for each state. It is raised only as far as a receipt really
reached, and dropped with the last message it covers, so it never outlives them.

## Limits

- Each receipt occupies one slot of the 256-record direct history on both sides,
  and follows the existing retention and disappearing-message policies. A busy
  conversation therefore keeps fewer messages. Consuming receipts in the native
  core, as presentation records are, would remove this cost.
- Groups send no receipts. Acknowledging every member would fill the bounded group
  history. Group bubbles show *sending* and *sent* only.
- A sender with several devices whose clocks disagree may see a message from the
  slower clock acknowledged early.
- A receipt is a second envelope soon after a fetch. It strengthens the timing
  correlation between two mailboxes that the privacy contract already disclaims,
  and adds to the silent wakeups the recipient's OS budgets.
- Older clients show the control body as text and must be upgraded.

Checks: `npm test` and `npm run typecheck` in `apps/mobile`; build the desktop web
bundle, then run `npm run test:receipts` in `apps/mobile`.
