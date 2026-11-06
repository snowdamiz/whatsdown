import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { vectors } from './fork-vectors.mjs';

const fixture = fileURLToPath(new URL('../tests/fixtures/fork-v1/vectors.json', import.meta.url));
test('shared FRK vectors reproduce independently and Mesh detects an altered oracle', { timeout: 120_000 }, () => {
  const published = JSON.parse(readFileSync(fixture, 'utf8'));
  assert.deepEqual(published, vectors());
  assert.equal(published.cases[0].proof_hash, published.cases[1].proof_hash, 'finder is excluded');
  const run = path => spawnSync(process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url)), [
    'test', fileURLToPath(new URL('../packages/messenger-protocol/security/fork-vectors.test.mpl', import.meta.url)),
  ], { encoding: 'utf8', timeout: 55_000, env: { ...process.env, MORSE_FORK_VECTORS_PATH: path } });
  const correct = run(fixture);
  assert.equal(correct.status, 0, correct.stderr + correct.stdout);
  const dir = mkdtempSync(join(tmpdir(), 'morse-fork-oracle-'));
  try {
    published.cases[0].proof_hash = '00'.repeat(32);
    const altered = join(dir, 'altered.json');
    writeFileSync(altered, JSON.stringify(published));
    const incorrect = run(altered);
    assert.notEqual(incorrect.status, 0);
    assert.match(incorrect.stdout + incorrect.stderr, /assert failed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
