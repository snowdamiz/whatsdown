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
