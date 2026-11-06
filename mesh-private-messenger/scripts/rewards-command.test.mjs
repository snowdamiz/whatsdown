import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('optimized rewards reads require explicit operator pins and never report unauthenticated custody', { timeout: 90_000 }, async () => {
  const work = mkdtempSync(join(tmpdir(), 'morse-rewards-command-'));
  const binary = join(work, 'morse');
  const compiler = process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url));
  const source = fileURLToPath(new URL('../clients/mesh-cli', import.meta.url));
  const servers = Array.from({ length: 3 }, () => createServer());
  let connections = 0;
  try {
    for (const server of servers) {
      server.on('connection', () => connections++);
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
    }
    const pin = `outside ${'12'.repeat(32)} Outside`;
    const frame = ['4', '11'.repeat(32), '22'.repeat(32), '8', '1', '1', pin,
      '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb', '3',
      ...servers.map(server => `https://127.0.0.1:${server.address().port}`),
      '-', '2', '1', '1', pin, '1'.repeat(32), 'morse-main'].join('\n');
    const env = { ...process.env, MESSENGER_SECURITY_CONFIG: frame, MORSE_REWARDS_MIN_CONTEXT_SLOT: '9007199254740993' };
    const build = spawnSync(compiler, ['build', source, '--output', binary, '--opt-level', '2'], { env, encoding: 'utf8', timeout: 60_000 });
    assert.equal(build.status, 0, build.stderr);
    const valid = ['rewards', '--program', '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
      '--mint', 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', '--log', 'morse-main', '--epoch', '11'];
    const run = async (overrides = {}, args = valid) => {
      const child = spawn(binary, args, { env: { ...env, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      child.stdout.on('data', data => { stdout += data; });
      child.stderr.on('data', data => { stderr += data; });
      const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
      try {
        const [code, signal] = await once(child, 'exit');
        assert.equal(signal, null, stderr);
        assert.equal(code, 1, stderr);
        assert.equal(stdout, '', 'no report without authenticated custody');
        return stderr;
      } finally { clearTimeout(timer); }
    };
    assert.match(await run({}, ['rewards']), /usage: morse rewards/);
    for (const index of [2, 4]) {
      const args = [...valid]; args[index] = 'invalid';
      assert.match(await run({}, args), /usage:/);
      args[index] = '11111111111111111111111111111111';
      assert.match(await run({}, args), /usage:/);
    }
    for (const epoch of ['01', '-1', '+1', '18446744073709551616']) {
      assert.match(await run({}, [...valid.slice(0, -1), epoch]), /usage:/);
    }
    assert.match(await run({ MESSENGER_SECURITY_CONFIG: '' }), /MESSENGER_SECURITY_CONFIG/);
    const wrongLog = [...valid]; wrongLog[6] = 'morse-canary';
    assert.match(await run({}, wrongLog), /rewards_log_mismatch/);
    for (const minimum of ['01', '-1', '18446744073709551616']) await run({ MORSE_REWARDS_MIN_CONTEXT_SLOT: minimum });
    assert.equal(connections, 0, 'invalid local options fail before network reads');
    assert.match(await run(), /anchor_rpc_unavailable/);
    assert.ok(connections >= 2, 'valid queries require independent provider observations');
  } finally {
    for (const server of servers) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    rmSync(work, { recursive: true, force: true });
  }
});
