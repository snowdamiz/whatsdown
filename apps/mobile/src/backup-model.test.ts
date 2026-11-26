import assert from 'node:assert/strict';
import test from 'node:test';

import {
  backupDue,
  backupErrorMessage,
  backupLine,
  decodeAppState,
  encodeAppState,
  mergeAppState,
  parseBackupStatus,
  parseRestored,
  type AppState,
} from './backup-model.ts';
import { vectors, writeU32 } from './codec.ts';

const u64 = (value: number): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};
const day = 86_400_000;

test('backups run once a UTC day while they are on', () => {
  const noon = Date.UTC(2026, 8, 29, 12);
  assert.equal(backupDue({ on: false, lastBackupAt: 0 }, noon), false);
  assert.equal(backupDue({ on: true, lastBackupAt: 0 }, noon), true);
  assert.equal(backupDue({ on: true, lastBackupAt: noon - 3_600_000 }, noon), false);
  assert.equal(backupDue({ on: true, lastBackupAt: Date.UTC(2026, 8, 28, 23, 59) }, noon), true);
  assert.equal(parseBackupStatus(vectors(Uint8Array.of(2), u64(noon))).lastBackupAt, noon);
  assert.equal(parseBackupStatus(vectors(Uint8Array.of(0), u64(0))).on, false);
  assert.equal(backupLine({ on: true, lastBackupAt: 0 }, noon), 'On · No backup yet');
  assert.equal(backupLine({ on: true, lastBackupAt: noon - 2 * day }, noon), 'On · Last backup Sep 27');
  assert.equal(backupLine({ on: false, lastBackupAt: 0 }, noon), 'Off');
});

test('a restored app record fills in what this device lacks and keeps what it has', () => {
  const backup: AppState = {
    v: 1,
    readState: { 'chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': ['01', '02'], 'chat/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb': ['03'] },
    receiptMarks: { 'chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': [5, 4] },
    declined: { 'chat/cccccccccccccccccccccccccccccccc': ['dddddddddddddddddddddddddddddddd'] },
    readReceipts: false,
    notificationPreview: 'sender',
    appearance: 'dark',
  };
  const decoded = decodeAppState(encodeAppState(backup));
  assert.deepEqual(decoded, backup);
  const merged = mergeAppState({ ...backup, readState: { 'chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': ['09'] }, receiptMarks: {}, declined: {} }, decoded!);
  assert.deepEqual(merged.readState, { 'chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': ['09'], 'chat/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb': ['03'] });
  assert.deepEqual(merged.receiptMarks, { 'chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': [5, 4] });
  assert.deepEqual(merged.declined, { 'chat/cccccccccccccccccccccccccccccccc': ['dddddddddddddddddddddddddddddddd'] });
  assert.equal(decodeAppState(new TextEncoder().encode('{"v":2}')), null);
  assert.equal(decodeAppState(new Uint8Array()), null);
});

test('a restore reports what came back', () => {
  const restored = parseRestored(vectors(writeU32(3), writeU32(1), u64(1_700_000_000_000), Uint8Array.of(7), writeU32(99)));
  assert.deepEqual(restored, { conversations: 3, groups: 1, createdAt: 1_700_000_000_000, appState: Uint8Array.of(7) });
  assert.equal(backupErrorMessage(new Error('Mesh 1: backup_account_mismatch')),
    'That backup belongs to another account.');
  assert.equal(backupErrorMessage(new Error('backup_not_found')),
    'No backup from the past week opens with that code. Check the code, or turn backups on again.');
  assert.equal(backupErrorMessage(new Error('something odd')), 'something odd');
});
