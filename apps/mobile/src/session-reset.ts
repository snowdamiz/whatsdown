// A secure session is reset when one side lost more messages than it could
// skip: the other side started a new session and sent again what it could.
// The conversation says so for a week.
const shownFor = 7 * 86_400_000;

export function sessionResetNotice(
  conversation: { username: string; sessionResetAt: number },
  now = Date.now(),
): string | undefined {
  const at = conversation.sessionResetAt;
  if (!at || now - at > shownFor) return undefined;
  return `Secure session with @${conversation.username} was reset. Messages sent while it was broken were sent again where they could be.`;
}
