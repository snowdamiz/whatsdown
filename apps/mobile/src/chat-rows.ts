import { formatDayLabel, sameDay } from './format.ts';

type Timed = { timestamp: number; direction: 'sent' | 'received' };

export type ChatRow<T extends Timed> =
  | { kind: 'day'; key: string; label: string }
  | { kind: 'message'; key: string; message: T; spaced: boolean; tail: boolean };

// Rows are in chronological order; reverse them for an inverted list.
export function buildChatRows<T extends Timed>(
  messages: readonly T[],
  keyOf: (message: T, index: number) => string,
  now = Date.now(),
  senderOf: (message: T) => string = (message) => message.direction,
): ChatRow<T>[] {
  const rows: ChatRow<T>[] = [];
  messages.forEach((message, index) => {
    const previous = messages[index - 1];
    const next = messages[index + 1];
    const newDay = !previous || !sameDay(previous.timestamp, message.timestamp);
    if (newDay) {
      rows.push({
        kind: 'day',
        key: `day-${message.timestamp}`,
        label: formatDayLabel(message.timestamp, now),
      });
    }
    rows.push({
      kind: 'message',
      key: keyOf(message, index),
      message,
      spaced: newDay || senderOf(previous!) !== senderOf(message),
      tail:
        !next ||
        senderOf(next) !== senderOf(message) ||
        !sameDay(next.timestamp, message.timestamp),
    });
  });
  return rows;
}
