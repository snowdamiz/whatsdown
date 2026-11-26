import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const calls: { command: string; args: Record<string, unknown>; options?: { headers: Record<string, string> } }[] = [];
Object.assign(globalThis, { __desktopInvoke: async (
  command: string, args: Record<string, unknown>, options?: { headers: Record<string, string> },
) => {
  calls.push({ command, args, options });
  if (command === 'mailbox_connect') (args.events as { onmessage: (data: string) => void }).onmessage('ready');
  if (command === 'binary_request') {
    const status = options?.headers['X-Object-Capability'] ? 204 : 201;
    const body = status === 204 ? [] : [7, 8, 9];
    return Uint8Array.from([status >> 8, status & 255, ...body]).buffer;
  }
  return undefined;
} });
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@tauri-apps/api/core') return {
    shortCircuit: true,
    url: 'data:text/javascript,export const invoke = globalThis.__desktopInvoke; export class Channel {}',
  };
  return next(specifier, context);
} });
const { fetch, openMailboxSocket } = await import('./transport.web.ts');

test('desktop fetch sends raw bodies with route headers and decodes the framed status', async () => {
  const response = await fetch('https://messenger.example/v1/mailbox/fetch', {
    method: 'POST', body: Uint8Array.of(1, 2).buffer, headers: { 'Content-Type': 'application/octet-stream' },
  });
  assert.equal(response.status, 201);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), Uint8Array.of(7, 8, 9));
  const call = calls.find((item) => item.command === 'binary_request')!;
  assert.deepEqual(call.args, Uint8Array.of(1, 2));
  assert.deepEqual(call.options?.headers, {
    'X-Service-Url': 'https://messenger.example/v1/mailbox/fetch', 'X-Service-Method': 'POST',
  });
  const capability = 'ab'.repeat(32);
  const part = await fetch('https://objects.example/v1/objects/00/parts/1', {
    method: 'GET', headers: { 'X-Object-Capability': capability },
  });
  assert.equal(part.status, 204);
  assert.equal(part.body, null);
  const partCall = calls.filter((item) => item.command === 'binary_request')[1]!;
  assert.deepEqual(partCall.args, new Uint8Array(0));
  assert.equal(partCall.options?.headers['X-Object-Capability'], capability);
  assert.equal(partCall.options?.headers['X-Service-Method'], 'GET');
});

test('desktop sockets retain early readiness and close only their own connection', async () => {
  const first = await openMailboxSocket('wss://example.com', 'MeshMailbox 01');
  const messages: unknown[] = [];
  first.onmessage = (event) => { messages.push(event.data); };
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(messages, ['ready']);
  const second = await openMailboxSocket('wss://example.com', 'MeshMailbox 02');
  first.close();
  second.close();
  const connects = calls.filter((call) => call.command === 'mailbox_connect');
  const disconnects = calls.filter((call) => call.command === 'mailbox_disconnect');
  assert.notEqual(connects[0]!.args.id, connects[1]!.args.id);
  assert.deepEqual(disconnects.map((call) => call.args.id), connects.map((call) => call.args.id));
});
