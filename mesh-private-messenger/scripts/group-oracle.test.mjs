import assert from 'node:assert/strict';
import { createCipheriv, createHash, hkdfSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('C3 Mesh group derivation matches OpenSSL, and an altered oracle is detected', { timeout: 120_000 }, () => {
  const root = Buffer.alloc(32, 1), prior = Buffer.alloc(32, 2);
  const context = Buffer.from('group schedule oracle');
  const salt = createHash('sha256').update(context).digest();
  const derive = (key, label) => Buffer.from(hkdfSync('sha256', key, salt, label, 32));
  const mixed = Buffer.concat([derive(prior, 'mesh-mls/v2/epoch-mix'), root]);
  const epoch = derive(mixed, 'mesh-mls/v2/epoch');
  const cipher = createCipheriv('chacha20-poly1305', derive(epoch, 'mesh-mls/v2/confirmation'), Buffer.alloc(12), { authTagLength: 16 });
  cipher.setAAD(context);
  cipher.final();
  const run = tag => spawnSync(process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url)), [
    'test', fileURLToPath(new URL('../packages/messenger-protocol/security/group-schedule.test.mpl', import.meta.url)),
  ], { encoding: 'utf8', timeout: 55_000, env: { ...process.env,
    MORSE_TEST_GROUP_ROOT: root.toString('hex'), MORSE_TEST_GROUP_PRIOR: prior.toString('hex'),
    MORSE_TEST_GROUP_CONFIRMATION: tag,
  } });
  const correct = run(cipher.getAuthTag().toString('hex'));
  assert.equal(correct.status, 0, correct.stderr + correct.stdout);
  const altered = run('00'.repeat(16));
  assert.notEqual(altered.status, 0);
  assert.match(altered.stdout + altered.stderr, /assert failed/);
});
