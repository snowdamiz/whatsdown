import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('judge proof rejects SBF stack diagnostics even when the builder exits successfully', () => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-sbf-diagnostics-'));
  try {
    const calls = join(directory, 'calls');
    writeFileSync(join(directory, 'cargo'), '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$PROOF_TEST_CALLS"\n', { mode: 0o755 });
    const builder = join(directory, 'cargo-build-sbf');
    writeFileSync(builder, '#!/usr/bin/env bash\nif [[ "$1" == --version ]]; then echo "cargo-build-sbf 4.4.0"; exit 0; fi\nif [[ "$PROOF_TEST_STACK_ERROR" == 1 ]]; then echo "Error: A function call overwrites values in the frame" >&2; fi\nexit 0\n', { mode: 0o755 });
    const run = flag => spawnSync('bash', [fileURLToPath(new URL('./prove-judge.sh', import.meta.url))], {
      env: { ...process.env, PATH: directory + delimiter + process.env.PATH, CARGO_BUILD_SBF: builder,
        PROOF_TEST_CALLS: calls, PROOF_TEST_STACK_ERROR: flag }, encoding: 'utf8', timeout: 10_000,
    });
    const bad = run('1');
    assert.notEqual(bad.status, 0, 'stack overflow diagnostics must fail the proof');
    assert.match(bad.stdout + bad.stderr, /overwrites values in the frame/);
    assert.doesNotMatch(readFileSync(calls, 'utf8'), /^test /m, 'do not test a known-invalid SBF binary');
    const good = run('0');
    assert.equal(good.status, 0, good.stderr);
    assert.match(readFileSync(calls, 'utf8'), /^test /m);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
