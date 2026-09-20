import { parseReadState, type ReadState } from './read-state';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { databasePath } from './storage';

const keyFor = (account: string) => `${databasePath}/read-state/v1/${account}`;

export function loadReadState(account: string): ReadState {
  return parseReadState(localStorage.getItem(keyFor(account)));
}

export function saveReadState(account: string, state: ReadState): void {
  localStorage.setItem(keyFor(account), JSON.stringify(state));
}

const notificationKey = (account: string) => `${databasePath}/notification-state/v1/${account}`;
export function loadNotificationState(account: string): ReadState | null {
  const value = localStorage.getItem(notificationKey(account));
  return value === null ? null : parseReadState(value);
}
export function saveNotificationState(account: string, state: ReadState): void {
  localStorage.setItem(notificationKey(account), JSON.stringify(state));
}

// Whether this account tells people when it has read their messages. On unless turned off.
const receiptsKey = (account: string) => `${databasePath}/read-receipts/v1/${account}`;
export const loadReadReceipts = (account: string): boolean => localStorage.getItem(receiptsKey(account)) !== 'off';
export function saveReadReceipts(account: string, enabled: boolean): void {
  localStorage.setItem(receiptsKey(account), enabled ? 'on' : 'off');
}

// How far each chat's other side has acknowledged; see ReceiptMarks.
const marksKey = (account: string) => `${databasePath}/receipt-marks/v1/${account}`;
export const loadReceiptMarks = (account: string): Record<string, ReceiptMarks> =>
  parseReceiptMarks(localStorage.getItem(marksKey(account)));
export function saveReceiptMarks(account: string, marks: Record<string, ReceiptMarks>): void {
  localStorage.setItem(marksKey(account), JSON.stringify(marks));
}
