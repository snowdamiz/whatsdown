import assert from 'node:assert/strict';
import { sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assembleStatement, privateKeyFrom, signStatement, statementMessage, verifyStatement } from './pinning-statement.mjs';

// RFC 8032 test 1: the seed and public key the witness tests call witness A.
const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const publicKey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const fields = {
  witness_id: 'witness-c',
  public_key: publicKey,
  operator: 'Example Witness GmbH',
  jurisdiction: 'DE',
  software: 'mesh 0.1.9',
  payout: '11111111111111111111111111111112',
  date: '2026-10-01',
};

test('a signed pinning statement verifies and names its fields in the fixed order', () => {
  const text = signStatement(fields, privateKeyFrom(seed));
  const lines = text.split('\n');
  assert.deepEqual(lines.slice(0, 8), [
    'morse-witness-pin-v1',
    'witness_id: witness-c',
    `public_key: ${publicKey}`,
    'operator: Example Witness GmbH',
    'jurisdiction: DE',
    'software: mesh 0.1.9',
    'payout: 11111111111111111111111111111112',
    'date: 2026-10-01',
  ]);
  assert.match(lines[8], /^signature: [0-9a-f]{128}$/);
  assert.equal(lines[9], '');
  assert.deepEqual(verifyStatement(text), fields);
});

test('an HSM or KMS signs the printed message and the statement is assembled from its signature', () => {
  const message = statementMessage(fields);
  assert.ok(message.endsWith('date: 2026-10-01\n'));
  const signature = sign(null, Buffer.from(message, 'utf8'), privateKeyFrom(seed)).toString('hex');
  assert.equal(assembleStatement(fields, signature), signStatement(fields, privateKeyFrom(seed)));
  assert.throws(() => assembleStatement({ ...fields, jurisdiction: 'FR' }, signature), /signature does not verify/);
});

test('tampered, re-keyed or non-canonical statements are refused', () => {
  const text = signStatement(fields, privateKeyFrom(seed));
  assert.throws(() => verifyStatement(text.replace('Example Witness GmbH', 'Example Witness AG')), /signature does not verify/);
  const otherKey = privateKeyFrom('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
  assert.throws(() => signStatement(fields, otherKey), /does not match public_key/);
  assert.throws(() => verifyStatement(text.trimEnd()), /canonical/);
  assert.throws(() => verifyStatement(text.replace('jurisdiction: DE', 'jurisdiction:  DE')), /jurisdiction/);
  const lines = text.split('\n');
  [lines[4], lines[5]] = [lines[5], lines[4]];
  assert.throws(() => verifyStatement(lines.join('\n')), /canonical/);
});

test('fields are checked before anything is signed', () => {
  const key = privateKeyFrom(seed);
  for (const [name, value, error] of [
    ['witness_id', 'Witness_C', /witness_id/],
    ['operator', ' Leading space', /operator/],
    ['operator', 'x'.repeat(49), /operator/],
    ['jurisdiction', 'Germany', /jurisdiction/],
    ['software', 'mesh', /software/],
    ['software', 'c2sp litewitness', /software/],
    ['payout', '0OIl', /payout/],
    ['payout', '1111', /payout/],
    ['date', '2026-02-30', /date/],
  ]) assert.throws(() => signStatement({ ...fields, [name]: value }, key), error, `${name}=${value}`);
  assert.equal(verifyStatement(signStatement({ ...fields, software: 'c2sp litewitness v0.10.0' }, key)).software,
    'c2sp litewitness v0.10.0');
});

test('the command line signs with a seed file or an OpenSSL PEM and verifies what it printed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pin-'));
  const seedFile = join(dir, 'seed.hex');
  writeFileSync(seedFile, `${seed}\n`);
  const pemFile = join(dir, 'witness.pem');
  writeFileSync(pemFile, privateKeyFrom(seed).export({ type: 'pkcs8', format: 'pem' }));
  const tool = new URL('./pinning-statement.mjs', import.meta.url).pathname;
  const args = Object.entries(fields).filter(([name]) => name !== 'public_key')
    .flatMap(([name, value]) => [`--${name.replace('_', '-')}`, value]);
  const fromSeed = execFileSync('node', [tool, 'sign', ...args, '--key-file', seedFile], { encoding: 'utf8' });
  const fromPem = execFileSync('node', [tool, 'sign', ...args, '--key-file', pemFile], { encoding: 'utf8' });
  assert.equal(fromSeed, fromPem);
  const statementFile = join(dir, 'statement.txt');
  writeFileSync(statementFile, fromSeed);
  assert.match(execFileSync('node', [tool, 'verify', statementFile], { encoding: 'utf8' }), /verified: witness-c/);
});
