export const GENERIC_PUSH_BODY = 'New encrypted activity';
export const BACKGROUND_NOTIFICATION_TASK = 'morse-encrypted-wakeup';

export function isGenericWakeupContent(
  body: string | null,
  data: Record<string, unknown> | undefined,
): boolean {
  const payload = data ?? {};
  const keys = Object.keys(payload);
  return (
    (body === null || body === GENERIC_PUSH_BODY) &&
    keys.length === 1 &&
    keys[0] === 'kind' &&
    payload.kind === 'encrypted-wakeup'
  );
}

export function backgroundWakeup(data: Record<string, unknown>): boolean {
  try {
    const payload = typeof data.dataString === 'string' ? JSON.parse(data.dataString) : data;
    return payload !== null && typeof payload === 'object' && isGenericWakeupContent(null, payload);
  } catch { return false; }
}

export function notificationScope(data: Record<string, unknown> | undefined): string | null {
  return data?.kind === 'message' && typeof data.scope === 'string' &&
    /^(chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/.test(data.scope) ? data.scope : null;
}
