export function historyRefreshDelay(
  messages: readonly { timestamp: number; disappearingSeconds?: number }[],
  now: number,
): number | undefined {
  const deadlines = messages
    .filter((message) => (message.disappearingSeconds ?? 0) > 0)
    .map((message) => message.timestamp + (message.disappearingSeconds ?? 0) * 1_000);
  if (!deadlines.length) return undefined;
  return Math.min(2_147_483_647, Math.max(0, Math.min(...deadlines) - now));
}

// Display uses only the authenticated timestamp/timer already returned by
// Mesh. Storage cleanup remains native. Preserve row/array identity if none
// expires; callers still compare the captured cache before replacing it.
export function unexpiredHistory<T extends { timestamp: number; disappearingSeconds?: number }>(
  messages: T[], now: number,
): T[] {
  const visible = messages.filter(message => {
    const seconds = message.disappearingSeconds ?? 0;
    return seconds === 0 || now < message.timestamp || now - message.timestamp < seconds * 1_000;
  });
  return visible.length === messages.length ? messages : visible;
}
