import { formatBytes } from './attachments';

function creationTime(value: string): string {
  const milliseconds = BigInt(value);
  return milliseconds <= 8_640_000_000_000_000n ? new Date(Number(milliseconds)).toLocaleString() : `${value} ms`;
}
const english = {
  title: 'Resume pending encrypted backup',
  details: (createdAt: string, wireSize: number) => `Created ${creationTime(createdAt)} · Encrypted file size: ${formatBytes(wireSize)}`,
  destination: 'Choose a destination before entering your saved recovery code. The encrypted backup stays on this device until it is saved or explicitly discarded.',
  choose: 'Choose backup destination',
  choosing: 'Selecting a backup destination…',
  code: 'Saved recovery code',
  continue: 'Continue pending export',
  authenticating: 'Opening the original encrypted backup…',
  failedCode: 'The saved code could not unlock this backup.',
  limited: 'Too many attempts. Close and start again to retry.',
  ready: 'The original encrypted backup is ready to save.',
  save: 'Save encrypted backup',
  saving: 'Saving encrypted backup…',
  keep: 'Keep pending backup and close',
  kept: 'The pending encrypted backup has been kept on this device.',
  discard: 'Discard pending backup',
  discardWarning: 'Discarding removes the pending encrypted copy from this device. A backup file you already saved is kept.',
  confirmDiscard: 'Permanently discard pending backup',
  back: 'Go back',
  repairTitle: 'Pending backup is incomplete or damaged',
  repairDescription: 'Remove the incomplete or damaged pending copy to start a new backup. This cannot recover a lost recovery code.',
  repair: 'Remove damaged pending backup',
  confirmRepair: 'Remove damaged pending copy',
  changing: 'Updating the pending backup…',
  failedAction: 'The pending backup could not be changed. Check it again before continuing.',
  checking: 'Checking for a pending encrypted backup…',
  stateFailed: 'Could not check for a pending backup. Try again.',
  retryState: 'Check pending backup',
  savedPending: 'Encrypted backup saved. Its pending encrypted copy is still on this device. You can discard it on your next visit.',
};
export type PendingExportLabels = typeof english;
// Translation proposal only. Root combines these keys with the catalogs.
export const pendingExportEnglish: PendingExportLabels = Object.freeze(english);
