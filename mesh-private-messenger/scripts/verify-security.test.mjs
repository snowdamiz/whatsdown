import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { describeTree, unchangedSources, runCheck } from './verify-security.mjs';

test('C8 evidence preserves a real failed command and never promotes a timeout to success', t => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-evidence-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const run = (id, code, timeout) => runCheck(directory, { id, properties: ['C8'], command: process.execPath, args: ['-e', code], timeout });
  assert.equal(run('pass', 'console.log("positive control")').status, 'pass');
  const failed = run('fail', 'console.error("attack detected"); process.exit(7)');
  assert.equal(failed.status, 'fail');
  assert.equal(failed.exitCode, 7);
  assert.match(readFileSync(join(directory, failed.log), 'utf8'), /attack detected/);
  assert.equal(run('timeout', 'setTimeout(() => {}, 10000)', 100).status, 'fail');
});

test('C8 evidence fails when tracked or untracked source changes during verification', t => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-evidence-tree-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', args, { cwd: directory, stdio: 'pipe' });
  git('init');
  writeFileSync(join(directory, 'source'), 'candidate');
  git('add', 'source');
  git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-m', 'fixture');
  const before = { morse: describeTree(directory) };
  assert.equal(unchangedSources(before, { morse: directory }).status, 'pass');
  writeFileSync(join(directory, 'source'), 'different candidate');
  assert.equal(unchangedSources(before, { morse: directory }).status, 'fail');
  writeFileSync(join(directory, 'source'), 'candidate');
  writeFileSync(join(directory, 'new-source'), 'untracked change');
  assert.equal(unchangedSources(before, { morse: directory }).status, 'fail');
});
