import type { HistoryMessage } from './codec';

export function historyRefreshDelay(
  messages: readonly Pick<HistoryMessage, 'timestamp' | 'disappearingSeconds'>[],
  now: number,
): number | undefined {
  const deadlines = messages
    .filter((message) => message.disappearingSeconds > 0)
    .map((message) => message.timestamp + message.disappearingSeconds * 1_000);
  if (!deadlines.length) return undefined;
  return Math.min(2_147_483_647, Math.max(0, Math.min(...deadlines) - now));
}
