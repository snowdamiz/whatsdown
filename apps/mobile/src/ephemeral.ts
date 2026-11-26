import { hex, parseByteList, type ViewOnce } from './codec.ts';

// Disappearing and view-once messages, and safety codes: what the app says
// about them. The rules themselves are the core's (Mobile.Expiry,
// Mobile.GroupTimer, Mobile.ViewOnce, Mobile.SafetyCode).

const units: [number, string][] = [[86_400, 'day'], [3_600, 'hour'], [60, 'minute'], [1, 'second']];

export function timerLength(seconds: number): string {
  const [size, unit] = units.find(([step]) => seconds % step === 0 && seconds >= step) ?? [1, 'second'];
  const count = seconds / size;
  return `${count} ${unit}${count === 1 ? '' : 's'}`;
}

export function timerNotice(name: string, seconds: number): string {
  return seconds === 0
    ? `${name} turned off disappearing messages.`
    : `${name} set disappearing messages to ${timerLength(seconds)}.`;
}

export type Purge = { next: number; objectIds: string[] };

// mesh_messenger_expiry_purge: the next expiry (u64 ms, 0 for none), then the
// objects of attachments whose messages were purged, as hex.
export function parsePurge(input: Uint8Array): Purge {
  const [next, ...objects] = parseByteList(input, 513, 32);
  if (!next || next.length !== 8 || objects.some((id) => id.length !== 32)) throw new Error('Invalid purge');
  return {
    next: Number(new DataView(next.buffer, next.byteOffset, 8).getBigUint64(0, false)),
    objectIds: objects.map(hex),
  };
}

// The app purges at the next expiry, and at least once a minute in case a
// message with a timer arrived some other way than a sync.
export function purgeDelay(next: number, now: number): number {
  if (next === 0) return 60_000;
  return Math.min(60_000, Math.max(1_000, next - now));
}

export function viewOnceText({ direction, viewOnce }: { direction: 'sent' | 'received'; viewOnce: ViewOnce }): string {
  if (direction === 'sent') return 'View once message';
  return viewOnce === 'unopened' ? 'View once · Tap to open' : 'Opened';
}

export const viewOnceCaution =
  'It can be opened once, then it’s deleted from their device. Morse can’t stop a screenshot or a photo of the screen.';

export type SafetyOutcome = 'verified' | 'mismatch' | 'wrong_contact' | 'invalid';

export function describeSafetyCheck(outcome: SafetyOutcome, username: string): { tone: 'success' | 'warning' | 'error'; text: string } {
  switch (outcome) {
    case 'verified':
      return { tone: 'success', text: `The codes match. @${username} is verified on this device.` };
    case 'mismatch':
      return {
        tone: 'error',
        text: `The codes don’t match. Someone may be between you and @${username}. Don’t trust this chat until you’ve compared again.`,
      };
    case 'wrong_contact':
      return { tone: 'warning', text: `That code is for a chat with someone else. Scan the code @${username} shows for you.` };
    case 'invalid':
      return { tone: 'warning', text: 'That isn’t a safety code. Open this chat’s details on their device and show the code there.' };
  }
}

export const safetyOutcome = (value: string): SafetyOutcome => {
  if (value === 'verified' || value === 'mismatch' || value === 'wrong_contact' || value === 'invalid') return value;
  throw new Error('Unexpected safety check result');
};
