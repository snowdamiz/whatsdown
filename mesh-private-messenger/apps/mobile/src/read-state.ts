import { hex, type GroupHistoryMessage, type HistoryMessage } from './codec.ts';

export type ReadState = Record<string, string[]>;

export function parseReadState(input: string | null): ReadState {
  try {
    const value: unknown = JSON.parse(input ?? '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value).filter(([key, ids]) =>
      /^(chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/.test(key) &&
      Array.isArray(ids) && ids.length <= 256 &&
      ids.every((id) => typeof id === 'string' && /^[a-f0-9/]{1,180}$/.test(id))));
  } catch {
    return {};
  }
}

export function receivedMessageKeys(
  messages: readonly (HistoryMessage | GroupHistoryMessage)[],
  ownAccount?: string,
): string[] {
  const occurrences = new Map<string, number>();
  return messages.flatMap((message) => {
    if (message.direction !== 'received') return [];
    if (!('senderAccountId' in message)) return [hex(message.messageId)];
    if (hex(message.senderAccountId) === ownAccount) return [];
    if (message.messageId) return [hex(message.messageId)];
    // ponytail: group history exposes no message ID; receipt time + sender + occurrence
    // identify it until same-millisecond siblings roll out. Export IDs if that matters.
    const key = `${message.epoch}/${hex(message.senderAccountId)}/${hex(message.senderDeviceId)}/${message.timestamp}`;
    const occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    return [`${key}/${occurrence}`];
  });
}

export function unreadCount(incoming: readonly string[], read: readonly string[] = []): number {
  const seen = new Set(read);
  return incoming.filter((key) => !seen.has(key)).length;
}
