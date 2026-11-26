// 1 is delivered to one of the recipient's devices; 2 is read.
export type ReceiptState = 1 | 2;
export type MessageStatus = 'pending' | 'sent' | 'delivered' | 'read' | 'failed';

type Receipted = {
  direction: 'sent' | 'received';
  timestamp: number;
  receipt?: ReceiptState;
  delivery?: 'pending' | 'failed';
};

const prefix = 'MORSE-RECEIPT/1\n';
type Update = [state: ReceiptState, through: number];

function validUpdate(value: unknown): value is Update {
  return Array.isArray(value) && value.length === 2 && (value[0] === 1 || value[0] === 2) &&
    Number.isSafeInteger(value[1]) && value[1] > 0;
}

// A receipt is cumulative: it covers every message whose timestamp, on the
// sender's own clock, is at or before `through`. One receipt answers a batch.
export function encodeReceipt(state: ReceiptState, through: number): string {
  const update = [state, through];
  if (!validUpdate(update)) throw new Error('Invalid receipt');
  return prefix + JSON.stringify(update);
}

// Receipts use the same encrypted, bounded history as messages. Who acknowledged
// comes from the authenticated history record, never from the receipt body.
// ponytail: each receipt occupies one slot of the core's 256-record history, and
// expires with the conversation's disappearing timer. Consume receipts in the
// native core, as it does presentation records, if history depth matters.
export function applyReceipts<T extends { body: string; direction: 'sent' | 'received'; timestamp: number }>(
  history: T[],
): (T & { receipt?: ReceiptState })[] {
  // The highest watermark among later receipts, by who sent them and for which state.
  const through = { sent: [0, 0, 0], received: [0, 0, 0] };
  const messages: (T & { receipt?: ReceiptState })[] = [];
  // Newest first, so a receipt only ever reaches messages that came before it:
  // a forged watermark cannot acknowledge what had not been sent yet.
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const message = history[index]!;
    if (message.body.startsWith(prefix)) {
      // Reserved control messages, including malformed ones, never become bubbles.
      if (message.body.length > 64) continue;
      let update: unknown;
      try { update = JSON.parse(message.body.slice(prefix.length)); }
      catch { continue; }
      if (!validUpdate(update)) continue;
      const marks = through[message.direction];
      // Read implies delivered. Keeping the maximum makes retries idempotent.
      for (let state = update[0]; state >= 1; state -= 1) marks[state] = Math.max(marks[state]!, update[1]);
      continue;
    }
    const marks = through[message.direction === 'sent' ? 'received' : 'sent'];
    const receipt = marks[2]! >= message.timestamp ? 2 : marks[1]! >= message.timestamp ? 1 : undefined;
    messages.push(receipt ? { ...message, receipt } : message);
  }
  return messages.reverse();
}

// The watermark this account still owes the other side, if any. Receipts sent
// from a linked device are in this history too, so devices do not repeat them.
export function receiptDue(messages: readonly Receipted[], state: ReceiptState): number | undefined {
  const owed = messages.filter((message) => message.direction === 'received' && (message.receipt ?? 0) < state);
  return owed.length ? Math.max(...owed.map((message) => message.timestamp)) : undefined;
}

// How far the other side has acknowledged this account's messages in one chat, as
// the newest acknowledged timestamp: [delivered, read]. Each side's disappearing
// timer stamps only what it sends, so a receipt can expire long before the message
// it acknowledged; without this, that message's ticks would go backwards.
export type ReceiptMarks = [delivered: number, read: number];

// Raised only as far as a receipt really reached, so a forged watermark is not
// remembered, and dropped with the last message it covers, so nothing outlives it.
export function advanceReceiptMarks(messages: readonly Receipted[], marks: ReceiptMarks = [0, 0]): ReceiptMarks {
  const reached = (state: ReceiptState) => Math.max(0, ...messages
    .filter((message) => message.direction === 'sent' &&
      ((message.receipt ?? 0) >= state || message.timestamp <= marks[state - 1]!))
    .map((message) => message.timestamp));
  return [reached(1), reached(2)];
}

export function parseReceiptMarks(input: string | null): Record<string, ReceiptMarks> {
  try {
    const value: unknown = JSON.parse(input ?? '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value).filter(([key, marks]) =>
      /^chat\/[a-f0-9]{32}$/.test(key) && Array.isArray(marks) && marks.length === 2 &&
      marks.every((mark) => Number.isSafeInteger(mark) && mark >= 0)));
  } catch {
    return {};
  }
}

// `delivery` is the core's own record of what became of the message's
// envelopes. A receipt outranks it: whatever one device refused, the other side
// has said the message arrived.
export function messageStatus(
  message: Receipted,
  showRead = true,
  marks: ReceiptMarks = [0, 0],
): MessageStatus | undefined {
  if (message.direction !== 'sent') return undefined;
  const read = message.receipt === 2 || message.timestamp <= marks[1];
  if (read || message.receipt || message.timestamp <= marks[0]) return read && showRead ? 'read' : 'delivered';
  return message.delivery ?? 'sent';
}

export const describeStatus = (status: MessageStatus): string =>
  ({ pending: 'Sending', sent: 'Sent', delivered: 'Delivered', read: 'Read', failed: 'Not delivered' })[status];
