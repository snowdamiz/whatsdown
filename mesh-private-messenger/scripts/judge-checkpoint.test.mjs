import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const fixture = fileURLToPath(new URL('../tests/fixtures/fork-v1/anchor-checkpoints.json', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest();
function checkpoints() {
  // Public deterministic fixture seed, never a deployed signing identity.
  const key = createPrivateKey({ key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 11),
  ]), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
  const witnessKey = createPrivateKey({ key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 31),
  ]), format: 'der', type: 'pkcs8' });
  const witnessPublic = createPublicKey(witnessKey).export({ format: 'der', type: 'spki' }).subarray(-32);
  return [1, 2].map(version => {
    const fields = Buffer.alloc(120);
    fields.writeBigUInt64BE(18446744073709551615n, 0);
    fields.writeBigUInt64BE(1n, 8);
    hash(Buffer.concat([version === 1 ? Buffer.from('mesh-msg/v1/transparency-leaf') : Buffer.from([0]),
      Buffer.from('public judge checkpoint fixture')])).copy(fields, 16);
    fields.writeBigUInt64BE(1791504000000n, 80);
    publicKey.copy(fields, 88);
    const statement = Buffer.concat([Buffer.from('mesh-key-transparency-v1'), Buffer.from([0, version]), fields]);
    const signature = sign(null, statement, key);
    const wire = Buffer.concat([Buffer.from([version]), Buffer.from('KTK'), fields, signature]);
    const checkpointHash = hash(Buffer.concat([Buffer.from('mesh-msg/v1/transparency-checkpoint'), statement, signature]));
    const nativeStatement = Buffer.concat([Buffer.from('mesh-msg/v1/transparency-witnesswitness-a'), checkpointHash]);
    const seconds = Buffer.alloc(8); seconds.writeBigUInt64BE(18446744073709551615n);
    const c2spStatement = Buffer.from(`cosignature/v1\ntime 18446744073709551615\nmorseapp.io/log/main/v2\n1\n${fields.subarray(16, 48).toString('base64')}\nmorse-checkpoint ${wire.toString('base64')}\n`);
    return {
      version,
      wire: wire.toString('hex'),
      statement: statement.toString('hex'),
      hash: checkpointHash.toString('hex'),
      witness: { id: 'witness-a', publicKey: witnessPublic.toString('hex'),
        nativeStatement: nativeStatement.toString('hex'), nativeSignature: sign(null, nativeStatement, witnessKey).toString('hex'),
        ...(version === 2 ? { c2spStatement: c2spStatement.toString('hex'),
          c2spSignature: Buffer.concat([seconds, sign(null, c2spStatement, witnessKey)]).toString('hex') } : {}),
      },
    };
  });
}

if (process.argv.includes('--write-fixture')) {
  writeFileSync(fixture, JSON.stringify(checkpoints(), null, 2) + '\n');
} else {
  test('judge checkpoint fixtures reproduce in OpenSSL and Mesh rejects an altered hash', { timeout: 120_000 }, () => {
    const published = JSON.parse(readFileSync(fixture, 'utf8'));
    assert.deepEqual(published, checkpoints());
    const run = path => spawnSync(process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url)), [
      'test', fileURLToPath(new URL('../packages/messenger-protocol/security/anchor-checkpoints.test.mpl', import.meta.url)),
    ], { encoding: 'utf8', timeout: 55_000, env: { ...process.env, MORSE_ANCHOR_CHECKPOINTS_PATH: path } });
    const correct = run(fixture);
    assert.equal(correct.status, 0, correct.stderr + correct.stdout);
    const directory = mkdtempSync(join(tmpdir(), 'morse-anchor-checkpoints-'));
    try {
      published[1].hash = '00'.repeat(32);
      const altered = join(directory, 'altered.json');
      writeFileSync(altered, JSON.stringify(published));
      const incorrect = run(altered);
      assert.notEqual(incorrect.status, 0);
      assert.match(incorrect.stdout + incorrect.stderr, /assert failed/);
      published[1].hash = checkpoints()[1].hash;
      published[1].witness.c2spSignature = '00'.repeat(72);
      writeFileSync(altered, JSON.stringify(published));
      const unsigned = run(altered);
      assert.notEqual(unsigned.status, 0);
      assert.match(unsigned.stdout + unsigned.stderr, /assert failed/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
