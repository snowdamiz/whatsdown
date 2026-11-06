import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('native callbacks run synchronously on one ordinary OS stack with exact output and failure status', () => {
  const work = mkdtempSync(join(tmpdir(), 'morse-callback-proof-'));
  try {
    const root = new URL('../modules/mesh-messenger/android/', import.meta.url);
    const compile = spawnSync(process.env.CXX || 'clang++', ['-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror',
      '-I', fileURLToPath(new URL('src/main/cpp/', root)),
      fileURLToPath(new URL('mailbox-proof/CallbackThreadProof.cpp', root)), '-o', join(work, 'proof')], { encoding: 'utf8' });
    assert.equal(compile.status, 0, compile.stdout + compile.stderr);
    const proof = spawnSync(join(work, 'proof'), [], { encoding: 'utf8', timeout: 10000 });
    assert.equal(proof.status, 0, proof.stdout + proof.stderr);
  } finally { rmSync(work, { recursive: true, force: true }); }
});
