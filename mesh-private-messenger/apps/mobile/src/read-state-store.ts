import { File, Paths } from 'expo-file-system';
import { parseReadState, type ReadState } from './read-state';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';

// Local UI metadata only: opaque identifiers, never message text.
const fileFor = (account: string) => new File(Paths.document, `read-state-${account}.json`);

export function loadReadState(account: string): ReadState {
  const file = fileFor(account);
  return parseReadState(file.exists ? file.textSync() : null);
}

export function saveReadState(account: string, state: ReadState): void {
  const file = fileFor(account);
  if (!file.exists) file.create();
  file.write(JSON.stringify(state));
}

const notificationFile = (account: string) => new File(Paths.document, `notification-state-${account}.json`);
export function loadNotificationState(account: string): ReadState | null {
  const file = notificationFile(account);
  return file.exists ? parseReadState(file.textSync()) : null;
}
export function saveNotificationState(account: string, state: ReadState): void {
  const file = notificationFile(account);
  if (!file.exists) file.create();
  file.write(JSON.stringify(state));
}

// Whether this account tells people when it has read their messages. On unless turned off.
const receiptsFile = (account: string) => new File(Paths.document, `read-receipts-${account}`);
export function loadReadReceipts(account: string): boolean {
  const file = receiptsFile(account);
  return !file.exists || file.textSync() !== 'off';
}
export function saveReadReceipts(account: string, enabled: boolean): void {
  const file = receiptsFile(account);
  if (!file.exists) file.create();
  file.write(enabled ? 'on' : 'off');
}

// How far each chat's other side has acknowledged; see ReceiptMarks. Timestamps of
// messages still in history only, and gone when they are.
const marksFile = (account: string) => new File(Paths.document, `receipt-marks-${account}.json`);
export function loadReceiptMarks(account: string): Record<string, ReceiptMarks> {
  const file = marksFile(account);
  return parseReceiptMarks(file.exists ? file.textSync() : null);
}
export function saveReceiptMarks(account: string, marks: Record<string, ReceiptMarks>): void {
  const file = marksFile(account);
  if (!file.exists) file.create();
  file.write(JSON.stringify(marks));
}
