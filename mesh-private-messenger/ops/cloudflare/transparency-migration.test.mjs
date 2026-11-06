import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import { postgresEnv, runSql } from './postgres.mjs';

test('compact-tree migration preserves roots and assigns dense positions across sequence gaps', {
  skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'), 'use an isolated test database');
  const name = `morse_tree_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  const migrations = new URL('../../services/directory-delivery/migrations/', import.meta.url);
  const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
  const leaf = text => hash(Buffer.from('mesh-msg/v1/transparency-leaf'), Buffer.from(text));
  const node = (left, right) => hash(Buffer.from('mesh-msg/v1/transparency-node'), left, right);
  const leaves = ['one', 'two', 'three'].map(leaf);
  const parentHash = node(leaves[0], leaves[1]);
  const root = node(parentHash, leaves[2]);
  const query = sql => execFileSync('psql', ['-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql], {
    env: postgresEnv(database.href), encoding: 'utf8',
  }).trim();
  runSql(parent, `CREATE DATABASE ${name}`);
  try {
    for (const file of readdirSync(migrations).filter(file => /^\d{3}_.+\.sql$/.test(file) && file < '019_').sort()) {
      runSql(database.href, readFileSync(new URL(file, migrations), 'utf8'));
    }
    for (const [index, sequence] of [1, 9, 100].entries()) {
      runSql(database.href, `INSERT INTO transparency_entries (sequence, account_commitment, entry_bytes, leaf_hash)
        VALUES (${sequence}, decode('${'11'.repeat(32)}', 'hex'), 'entry', decode('${leaves[index].toString('hex')}', 'hex'))`);
    }
    runSql(database.href, `INSERT INTO transparency_checkpoints
      (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature)
      VALUES (1, 3, decode('${root.toString('hex')}', 'hex'), decode('${'00'.repeat(32)}', 'hex'),
      1000, decode('${'22'.repeat(32)}', 'hex'), decode('${'33'.repeat(64)}', 'hex'))`);
    runSql(database.href, readFileSync(new URL('019_compact_transparency.sql', migrations), 'utf8'));
    assert.equal(query("SELECT string_agg(sequence::text || ':' || leaf_index::text, ',' ORDER BY sequence) FROM transparency_entries"), '1:0,9:1,100:2');
    assert.equal(query('SELECT count(*) FROM transparency_nodes'), '4');
    assert.equal(query('SELECT encode(hash, \'hex\') FROM transparency_nodes WHERE level = 1 AND node_index = 0'), parentHash.toString('hex'));
    assert.equal(query('SELECT encode(tree_root, \'hex\') FROM transparency_checkpoints'), root.toString('hex'));
    assert.equal(query('SELECT encode(service_signature, \'hex\') FROM transparency_checkpoints'), '33'.repeat(64));
    assert.equal(query('SELECT count(*) FROM transparency_nodes WHERE tile_index != node_index / 256 OR tile_offset != node_index % 256'), '0');
  } finally {
    runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`);
  }
});
