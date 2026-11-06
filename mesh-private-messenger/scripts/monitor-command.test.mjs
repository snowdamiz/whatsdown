import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const packagePath = fileURLToPath(new URL('../clients/mesh-cli', import.meta.url));
const compiler = process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url));

async function execute(binary, args, env) {
  const child = spawn(binary, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 20_000);
  try {
    const [code, signal] = await once(child, 'exit');
    assert.equal(signal, null, stderr);
    return { code, stdout, stderr };
  } finally { clearTimeout(timeout); }
}

test('monitor CLI validates configuration, reports outages durably and serves cached status through restart', { timeout: 90_000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-monitor-command-'));
  const binary = join(directory, 'mesh-cli');
  // Three distinct local origins refuse TLS immediately. No public network or
  // RPC credentials are involved; healthy/fork cases use live Mesh fixtures.
  const servers = Array.from({ length: 4 }, () => createServer((request, response) => {
    if (request.url === '/v1/transparency/registry') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ witnesses: [1, 2].map((number, index) => ({
        witness_id: index === 0 ? 'a' : 'b', public_key: `0${number}`.repeat(32), status: 'pinned',
      })) }));
    } else { response.writeHead(404); response.end(); }
  }));
  let daemon;
  try {
    for (const server of servers) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
    const ports = servers.map(server => server.address().port);
    const config = ['4', '11'.repeat(32), '22'.repeat(32), '8', '2', '2',
      `a ${'01'.repeat(32)} Morse`, `b ${'02'.repeat(32)} Outside`,
      '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb', '3',
      ...ports.slice(0, 3).map(port => `https://127.0.0.1:${port}`), '-', '2', '2', '2',
      `a ${'01'.repeat(32)} Morse`, `b ${'02'.repeat(32)} Outside`, '1'.repeat(32), 'morse-main'].join('\n');
    const env = { ...process.env, MESSENGER_SECURITY_CONFIG: config, MORSE_MONITOR_POLICY_FILES: '',
      MORSE_MONITOR_LOG_VERSION: '2', MORSE_MONITOR_STATE_PATH: join(directory, 'monitor.sqlite'),
      MESSENGER_BASE_URL: `http://127.0.0.1:${ports[3]}` };
    const build = spawnSync(compiler, ['build', packagePath, '--opt-level', '2', '--output', binary], { env, encoding: 'utf8', timeout: 60_000 });
    assert.equal(build.status, 0, build.stderr);
    const invalid = await execute(binary, ['monitor', '--log', 'morse-main', '--port', '0'], env);
    assert.equal(invalid.code, 1); assert.match(invalid.stderr, /usage:/);
    const missing = await execute(binary, ['monitor', '--log', 'morse-main', '--once'], { ...env, MESSENGER_SECURITY_CONFIG: '' });
    assert.equal(missing.code, 1); assert.match(missing.stderr, /MESSENGER_SECURITY_CONFIG is required/);
    const result = await execute(binary, ['monitor', '--log', 'morse-main', '--once'], env);
    assert.equal(result.code, 2, result.stderr);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.healthy, false); assert.deepEqual(report.issues, ['chain_unavailable']);
    assert.equal(report.log, 'morse-main'); assert.equal(report.log_version, 2);
    // Reserve a port separately from the RPC fixtures, then start the actual
    // CLI service on it. The persisted report must be served before any poll.
    const reservation = createServer(); reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
    const port = reservation.address().port;
    await new Promise(resolve => reservation.close(resolve));
    daemon = spawn(binary, ['monitor', '--log', 'morse-main', '--port', String(port)], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let logs = ''; daemon.stdout.on('data', data => { logs += data; }); daemon.stderr.on('data', data => { logs += data; });
    const url = `http://127.0.0.1:${port}`;
    let status;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { status = await fetch(`${url}/status`, { signal: AbortSignal.timeout(500) }); break; }
      catch { await delay(50); }
    }
    assert.ok(status, logs); assert.equal(status.status, 503);
    assert.equal(status.headers.get('cache-control'), 'no-store');
    const cached = await status.json();
    assert.equal(cached.healthy, false); assert.equal(cached.stale, false);
    assert.deepEqual(cached.snapshot.issues, ['chain_unavailable']);
    const page = await fetch(url); assert.equal(page.status, 200);
    assert.match(await page.text(), /Morse log monitor/);
    assert.equal((await fetch(`${url}/evidence.frk`)).status, 404);
    assert.equal((await fetch(`${url}/evidence-context`)).status, 404);
    const exit = once(daemon, 'exit'); daemon.kill('SIGTERM');
    const watchdog = setTimeout(() => daemon.kill('SIGKILL'), 10_000);
    const [code, signal] = await exit; clearTimeout(watchdog);
    assert.equal(code, 0, logs); assert.equal(signal, null, logs);
    daemon = undefined;
  } finally {
    daemon?.kill('SIGKILL');
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    rmSync(directory, { recursive: true, force: true });
  }
});
