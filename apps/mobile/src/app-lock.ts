// App lock: the device owner's Face ID, Touch ID, fingerprint or passcode before
// the app shows anything, at launch and once it has been away for the chosen time.
// null is off; otherwise the minutes it may spend in the background (0: none).
export type LockSetting = number | null;

export const lockChoices = [0, 1, 60] as const;

export const lockOptions: { label: string; short: string; value: number }[] = [
  { label: 'Off', short: 'Off', value: -1 },
  { label: 'Immediately', short: 'Now', value: 0 },
  { label: 'After 1 minute', short: '1m', value: 1 },
  { label: 'After 1 hour', short: '1h', value: 60 },
];

// Sealed in the core's journal as `settings/app-lock`.
export const encodeLockSetting = (setting: LockSetting): string => JSON.stringify({ minutes: setting });

export function parseLockSetting(text: string | null): LockSetting {
  try {
    const minutes: unknown = text ? JSON.parse(text)?.minutes : null;
    return (lockChoices as readonly unknown[]).includes(minutes) ? minutes as number : null;
  } catch {
    return null;
  }
}

// Settings changes the setting while the gate around the app (LockGate) keeps time.
const listeners = new Set<(setting: LockSetting) => void>();

export function publishLockSetting(setting: LockSetting): void {
  for (const listener of listeners) listener(setting);
}

export function onLockSetting(listener: (setting: LockSetting) => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

// `leftAt` is when the app last went to the background; undefined at launch.
export function lockDue(setting: LockSetting, leftAt: number | undefined, now: number): boolean {
  if (setting === null) return false;
  if (leftAt === undefined) return true;
  return now - leftAt >= setting * 60_000;
}
