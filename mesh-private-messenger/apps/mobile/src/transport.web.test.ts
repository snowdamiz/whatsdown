import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';

registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@tauri-apps/api/core') return {
    shortCircuit: true,
    url: 'data:text/javascript,export const invoke = () => { throw Error("raw HTTP IPC must not be reachable"); };',
  };
  return next(specifier, context);
} });

test('desktop transport exposes no caller-authorized HTTP or WebSocket capability', async () => {
  const transport = await import('./transport.web.ts');
  assert.equal('fetch' in transport, false);
  assert.equal('openMailboxSocket' in transport, false);
  assert.deepEqual(Object.keys(transport), ['isDevelopmentBuild']);
});

test('app transport modules and network orchestration contain no direct JS network exits', () => {
  for (const name of ['network.ts', 'transport.ts', 'transport.web.ts']) {
    const source = readFileSync(new URL(name, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/, name);
    assert.doesNotMatch(source, /['"](?:expo\/fetch|binary_request)['"]/, name);
  }
});
