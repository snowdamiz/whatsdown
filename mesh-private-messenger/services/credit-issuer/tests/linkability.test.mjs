// Plan §15 (Credits): the issuer and the core store disjoint data. The issuer
// keeps quotes and payments and never a redemption; the core keeps nullifiers
// and never a quote; no column could join the two. Asserted on the migrations
// both databases are built from.
//
//   node --test services/credit-issuer/tests/linkability.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const services = fileURLToPath(new URL('../../', import.meta.url));
const keywords = new Set(['CHECK', 'PRIMARY', 'UNIQUE', 'FOREIGN', 'CONSTRAINT', 'EXCLUDE']);

// table name -> column names, from CREATE TABLE and ALTER TABLE ... ADD COLUMN.
function schema(directory) {
  const tables = new Map();
  for (const file of readdirSync(directory).filter((name) => name.endsWith('.sql')).sort()) {
    const sql = readFileSync(`${directory}/${file}`, 'utf8').replace(/--[^\n]*/g, '');
    for (const [, name, body] of sql.matchAll(/CREATE TABLE (\w+) \(([\s\S]*?)\n\);/g)) {
      const columns = body.split('\n').map((line) => line.trim().split(/\s+/)[0]).filter((word) => word && !keywords.has(word) && /^[a-z_]+$/.test(word));
      tables.set(name, new Set(columns));
    }
    for (const [, name, body] of sql.matchAll(/ALTER TABLE (\w+)([^;]*);/g)) {
      for (const [, column] of body.matchAll(/ADD COLUMN (\w+)/g)) tables.get(name)?.add(column);
    }
  }
  return tables;
}

const core = schema(`${services}directory-delivery/migrations`);
const issuer = schema(`${services}credit-issuer/migrations`);
const redemption = ['credit_spent', 'credit_holds', 'credit_spend_totals'];

test('the core keeps exactly the spent set and holds it needs', () => {
  assert.deepEqual([...core.get('credit_spent')], ['nullifier', 'key_epoch', 'spent_at']);
  assert.deepEqual([...core.get('credit_holds')], ['redemption_id', 'action', 'binding', 'credits', 'held_at', 'taken_at']);
  assert.deepEqual([...core.get('credit_spend_totals')], ['week_start', 'action', 'credits']);
});

test('no issuer column shares a name with a core redemption column', () => {
  const issuerColumns = new Set([...issuer.values()].flatMap((columns) => [...columns]));
  for (const table of redemption) {
    for (const column of core.get(table)) assert.ok(!issuerColumns.has(column), `${table}.${column} is also an issuer column`);
  }
});

test('neither database holds the other side\'s records', () => {
  for (const table of ['quotes', 'payments', 'refunds', 'sweeps', 'issuer_keys']) assert.ok(!core.has(table), `core has ${table}`);
  for (const table of redemption) assert.ok(!issuer.has(table), `issuer has ${table}`);
  const issuerColumns = [...issuer.values()].flatMap((columns) => [...columns]);
  assert.ok(!issuerColumns.some((column) => /nullifier|redemption|token_input|spent/.test(column)));
  const coreColumns = [...core.entries()].filter(([name]) => name.startsWith('credit_')).flatMap(([, columns]) => [...columns]);
  assert.ok(!coreColumns.some((column) => /quote|payment|deposit|payer|blind|invoice|tx_/.test(column)));
});
