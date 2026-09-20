import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('C3 the consumed-key attack detects retained sender chains in an isolated mutant', { timeout: 180_000 }, t => {
  const source = fileURLToPath(new URL('../packages/messenger-protocol', import.meta.url));
  const candidate = mkdtempSync(join(tmpdir(), 'morse-group-mutant-'));
  t.after(() => rmSync(candidate, { recursive: true, force: true }));
  cpSync(source, candidate, { recursive: true });
  const manifest = join(candidate, 'mesh.toml');
  writeFileSync(manifest, readFileSync(manifest, 'utf8').replace(/path = "([^"]+)"/g, (_, path) => `path = ${JSON.stringify(resolve(source, path))}`));
  const path = join(candidate, 'groups/sender_keys.mpl');
  let code = readFileSync(path, 'utf8');
  const start = code.indexOf('  let next = group_derive_secret(');
  const end = code.indexOf('  delete_key(chains, id)', start);
  assert.ok(start >= 0 && end > start, 'Mutation target moved; update the retained-chain mutation');
  code = code.slice(0, start) + '  let next = copy_key(chains, id) ?\n' + code.slice(end);
  writeFileSync(path, code);
  const result = spawnSync(process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url)), [
    'test', join(candidate, 'tests/groups.test.mpl'),
  ], { encoding: 'utf8', timeout: 150_000, maxBuffer: 2 * 1024 * 1024 });
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /assert failed: !current_chain_opens/);
});
