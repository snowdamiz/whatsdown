import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canaryProcess } from './canary.mjs';

// Stands in for `meshc test canary-device`: writes lines like the helper until
// the stop file appears, and records the environment it was given.
const fakeHelper = `
const { appendFileSync, existsSync } = require('node:fs');
const out = process.env.MORSE_CANARY_OUT;
appendFileSync(out, JSON.stringify({ kind: 'env', keys: Object.keys(process.env).filter(k => k.startsWith('MORSE_')).sort(),
  role: process.env.MORSE_CANARY_ROLE, config: process.env.MORSE_CANARY_CONFIG }) + '\\n');
let round = 0;
const tick = () => {
  appendFileSync(out, JSON.stringify({ kind: 'lookup', round: round++, ok: true }) + '\\n');
  if (process.env.MORSE_CANARY_ROLE !== 'watch' || existsSync(process.env.MORSE_CANARY_STOP) || round > 200) return;
  setTimeout(tick, 20);
};
tick();`;

test('canary process: streams the helper\'s lines, stops on request, passes only its own settings', async () => {
  process.env.MORSE_CANARY_PAYER_KEYPAIR = 'secret';
  const workdir = mkdtempSync(join(tmpdir(), 'canary-test-'));
  const watch = canaryProcess({ role: 'watch', directory: 'https://dir.test', frame: '2\nframe', workdir, command: [process.execPath, '-e', fakeHelper] });
  while (watch.lines().filter(line => line.kind === 'lookup').length < 3) await new Promise(resolve => setTimeout(resolve, 20));
  const lines = await watch.stop();
  const env = lines[0];
  assert.equal(env.role, 'watch');
  assert.equal(env.config, '2\nframe');
  assert.ok(!env.keys.includes('MORSE_CANARY_PAYER_KEYPAIR'), 'secrets of other checks never reach the helper');
  assert.ok(env.keys.includes('MORSE_CANARY_DIRECTORY'));
  assert.ok(lines.filter(line => line.kind === 'lookup').length < 200, 'stopped by the stop file');

  const check = canaryProcess({ role: 'check', directory: 'https://dir.test', frame: 'x', workdir, env: { MORSE_CANARY_ANCHOR: 'on' },
    command: [process.execPath, '-e', fakeHelper] });
  assert.equal((await check.done).filter(line => line.kind === 'lookup').length, 1);
  delete process.env.MORSE_CANARY_PAYER_KEYPAIR;
});

test('canary process: a helper that writes nothing reports why', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'canary-test-'));
  const run = canaryProcess({ role: 'check', directory: 'https://dir.test', frame: 'x', workdir,
    command: [process.execPath, '-e', 'console.log("COMPILE ERROR: canary.test.mpl"); process.exit(1)'] });
  const [line] = await run.done;
  assert.equal(line.kind, 'error');
  assert.match(line.error, /COMPILE ERROR/);
});

for (const [name, ending, expected] of [
  ['nonzero exit', 'process.exit(7)', /exited 7/],
  ['signal', "process.kill(process.pid, 'SIGTERM')", /SIGTERM/],
  ['timeout', 'setInterval(() => {}, 1000)', /timed out/],
]) {
  test(`canary process: successful output cannot hide a ${name}`, async t => {
    const workdir = mkdtempSync(join(tmpdir(), 'canary-test-'));
    t.after(() => rmSync(workdir, { recursive: true, force: true }));
    const line = { kind: 'lookup', account: 'morse-canary-1', ok: true };
    const helper = `require('node:fs').appendFileSync(process.env.MORSE_CANARY_OUT,
      JSON.stringify(${JSON.stringify(line)}) + '\\n'); ${ending};`;
    const run = canaryProcess({ role: 'check', directory: 'https://dir.test', frame: 'x', workdir,
      command: [process.execPath, '-e', helper], timeoutMs: 2000 });
    const lines = await run.done;
    assert.deepEqual(lines[0], line, 'retain the completed lookup for diagnosis');
    assert.match(lines.find(line => line.kind === 'error')?.error ?? '', expected);
  });
}
