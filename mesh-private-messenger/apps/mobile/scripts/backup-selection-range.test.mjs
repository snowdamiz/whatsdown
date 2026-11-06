import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import vm from 'node:vm';

const source = fileURLToPath(new URL('..',import.meta.url));
process.env.TZ = 'America/New_York';
const module = new vm.SourceTextModule(stripTypeScriptTypes(await readFile(resolve(source, 'src/backup-selection.ts'), 'utf8')));
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { backupSelections } = module.namespace;
const scope = () => ({ kind: 'direct', id: new Uint8Array(16).fill(3) });

test('calendar limits include the complete local day across daylight-saving changes', () => {
  assert.equal(process.env.TZ, 'America/New_York');
  const [spring] = backupSelections({ scopes: [scope()], fromDay: '2024-03-10', throughDay: '2024-03-10' });
  assert.equal(spring.fromTime, '1710046800000');
  assert.equal(spring.throughTime, '1710129599999');
  const [fall] = backupSelections({ scopes: [scope()], fromDay: '2024-11-03', throughDay: '2024-11-03' });
  assert.equal(fall.fromTime, '1730606400000');
  assert.equal(fall.throughTime, '1730696399999');
});

test('impossible dates, reversed ranges and empty or oversized selections are refused before creation', () => {
  for (const day of ['2025-02-29', '2024-04-31', '2024-13-01', '2024-00-01', '2024-01-00', 'March 10, 2024', '2024-1-01']) {
    assert.throws(() => backupSelections({ scopes: [scope()], fromDay: day, throughDay: '' }), /invalid_backup_date/);
  }
  assert.throws(() => backupSelections({ scopes: [scope()], fromDay: '2024-03-11', throughDay: '2024-03-10' }), /invalid_backup_date_range/);
  for (const count of [0, 33]) {
    assert.throws(() => backupSelections({ scopes: Array.from({ length: count }, scope), fromDay: '', throughDay: '' }), /invalid_backup_selection/);
  }
});

test('blank limits mean full history and selected scope IDs are owned copies', () => {
  const direct = Buffer.alloc(16, 7), group = Buffer.alloc(32, 8);
  const result = backupSelections({ scopes: [{ kind: 'direct', id: direct }, { kind: 'group', id: group }], fromDay: '', throughDay: '' });
  direct.fill(0); group.fill(0);
  assert.equal(result.length, 2);
  assert.equal(result[0].scope.kind, 'direct'); assert.deepEqual([...result[0].scope.id], Array(16).fill(7));
  assert.equal(result[1].scope.kind, 'group'); assert.deepEqual([...result[1].scope.id], Array(32).fill(8));
  assert.ok(result.every(item => item.fromTime === null && item.throughTime === null));
});
