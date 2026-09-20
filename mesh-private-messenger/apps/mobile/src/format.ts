const day = 86_400_000;

const startOfDay = (timestamp: number): number => {
  const date = new Date(timestamp);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
};

export const sameDay = (a: number, b: number): boolean => startOfDay(a) === startOfDay(b);

const daysAgo = (timestamp: number, now: number): number =>
  Math.round((startOfDay(now) - startOfDay(timestamp)) / day);

export const formatClock = (timestamp: number): string =>
  new Date(timestamp).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

export function formatDayLabel(timestamp: number, now = Date.now()): string {
  const age = daysAgo(timestamp, now);
  if (age <= 0) return 'Today';
  if (age === 1) return 'Yesterday';
  const date = new Date(timestamp);
  if (age < 7) return date.toLocaleDateString('en-US', { weekday: 'long' });
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString('en-US', {
    month: 'long',
    day: 'numeric',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

export function formatInboxTime(timestamp: number, now = Date.now()): string {
  const age = daysAgo(timestamp, now);
  if (age <= 0) return formatClock(timestamp);
  if (age === 1) return 'Yesterday';
  const date = new Date(timestamp);
  if (age < 7) return date.toLocaleDateString('en-US', { weekday: 'short' });
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

export const groupDigits = (value: string, size: number): string[] =>
  value.match(new RegExp(`.{1,${size}}`, 'g')) ?? [];

const knownErrors: readonly [RegExp, string][] = [
  [/transparency_stale/, 'Security information is out of date. Reconnect and refresh before sending.'],
  [/peer_keys_changed/, 'Their security keys changed. Verify before sending.'],
  [/message_request_pending/, 'Accept this message request before replying.'],
  [/conversation_blocked/, 'Unblock this conversation before sending.'],
  [/recipient_unavailable/, 'Someone can’t receive more messages right now. Yours will send on its own when they can.'],
  [/\b404\b/, 'No exact username match was found.'],
  [/AbortError/, 'The server did not respond. Try again when connected.'],
  [
    /Could not connect|Network request failed|fetch failed|ECONNREFUSED/i,
    'Can’t reach the server. Check your connection and try again.',
  ],
  [/\b5\d\d\b/, 'The server hit a problem. Try again in a moment.'],
];

export function friendlyError(error: unknown): string {
  const raw = error instanceof Error ? error.message : error == null ? '' : String(error);
  for (const [pattern, message] of knownErrors) {
    if (pattern.test(raw)) return message;
  }
  const cleaned = raw
    .replace(/\s*\(at [^)]*\)\s*$/, '')
    .replace(/^(?:[A-Za-z]*(?:Exception|Error)):\s*/, '')
    .replace(/^Mesh library call failed \(status=\d+\):\s*/, '')
    .trim();
  if (/^[a-z0-9_]+$/.test(cleaned)) {
    const words = cleaned.replace(/_/g, ' ');
    return `${words.charAt(0).toUpperCase()}${words.slice(1)}.`;
  }
  return cleaned || 'Something went wrong.';
}
