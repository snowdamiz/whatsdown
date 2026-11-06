import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

test('release refuses missing broker setup before any deployment or migration command', () => {
  const workflow = readFileSync(new URL('../../../.github/workflows/backend-release.yml', import.meta.url), 'utf8');
  const step = workflow.split('- name: Migrate and deploy all backend services')[1];
  assert(step, 'the production release step must have a bounded setup preflight');
  const preflight = step.match(/for name in ([^;\n]+); do\n([\s\S]*?)\n\s*done/);
  assert(preflight, 'input checks must run before deployment');
  const env = Object.fromEntries(preflight[1].split(/\s+/).map(name => [name, 'owned-fixture-only']));
  delete env.MORSE_PUSH_BROKER_URL;
  const result = spawnSync('/bin/bash', ['-c', preflight[0]], { env, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1, 'without broker origin the old release would proceed to deployments');
  assert.match(result.stdout, /Set MORSE_PUSH_BROKER_URL/);
  assert.match(step, /MORSE_PUSH_BROKER_URL: \$\{\{ vars\.MORSE_PUSH_BROKER_URL \}\}/);
  assert(step.indexOf(preflight[0]) < step.indexOf('npm run deploy'));
});
