export const GENERIC_PUSH_BODY = 'New encrypted activity';

export function isGenericWakeupContent(
  body: string | null,
  data: Record<string, unknown> | undefined,
): boolean {
  const payload = data ?? {};
  const keys = Object.keys(payload);
  return (
    body === GENERIC_PUSH_BODY &&
    keys.length === 1 &&
    keys[0] === 'kind' &&
    payload.kind === 'encrypted-wakeup'
  );
}
