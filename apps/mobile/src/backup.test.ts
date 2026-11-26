import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';

import { hex, utf8, vectors, writeU32 } from './codec.ts';

// Every export network.ts and backup.ts take from the native module, mocked.
const imported = (file: string): string[] => {
  const block = readFileSync(new URL(file, import.meta.url), 'utf8')
    .match(/import \{([^}]*)\} from '\.\.\/modules\/mesh-messenger'/)?.[1] ?? '';
  return block.split(',').map((name) => name.trim()).filter(Boolean);
};
const names = [...new Set([...imported('./network.ts'), ...imported('./backup.ts')])];
type MeshExport = (request: Uint8Array) => Promise<Uint8Array>;
const mesh: Record<string, MeshExport> = Object.fromEntries(names.map((name) => [name, async () => {
  throw new Error(`Unexpected Mesh call: ${name}`);
}]));
(globalThis as typeof globalThis & { __meshBackupMocks: typeof mesh }).__meshBackupMocks = mesh;
// A development build that pins no OHTTP gateway sends stateless requests directly.
if ('oblivious_encapsulate_export' in mesh) mesh.oblivious_encapsulate_export = async () => new Uint8Array();
const mockModule = names.map((name) => `export const ${name} = (...args) => globalThis.__meshBackupMocks['${name}'](...args);`).join('\n');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'expo/fetch') {
      return { shortCircuit: true, url: 'data:text/javascript,export const fetch = (...args) => globalThis.fetch(...args);' };
    }
    if (specifier === '../modules/mesh-messenger') {
      return { shortCircuit: true, url: `data:text/javascript,${encodeURIComponent(mockModule)}` };
    }
    if (/^\.\/(codec|single-flight|transport)$/.test(specifier)) return nextResolve(`${specifier}.ts`, context);
    return nextResolve(specifier, context);
  },
});
(globalThis as typeof globalThis & { __DEV__: boolean }).__DEV__ = true;
const { backUp, disableBackups, recoverAccount, restoreBackup } = await import('./backup.ts');

const u64 = (value: number): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};
const list = (...values: Uint8Array[]): Uint8Array => vectors(writeU32(values.length), ...values);
const readU32 = (value: Uint8Array): number => new DataView(value.buffer, value.byteOffset, 4).getUint32(0);
type Call = { method: string; path: string; capability: string | null; body: Uint8Array };

function serve(t: { after: (fn: () => void) => void }, answer: (call: Call) => Response): Call[] {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit & { headers: Record<string, string> }) => {
    const call = {
      method: init.method ?? 'GET',
      path: new URL(url).pathname,
      capability: init.headers['X-Object-Capability'] ?? null,
      body: init.body ? new Uint8Array(init.body as ArrayBuffer) : new Uint8Array(),
    };
    calls.push(call);
    return answer(call);
  }) as typeof fetch;
  t.after(() => { globalThis.fetch = original; });
  return calls;
}

const objectId = new Uint8Array(32).fill(1);
const upload = new Uint8Array(32).fill(2);
const download = new Uint8Array(32).fill(3);

test('a backup uploads every part with its capability, completes, and only then counts', async (t) => {
  const finished: number[] = [];
  mesh.backup_prepare_export = async () => list(objectId, upload, Uint8Array.of(9, 9), Uint8Array.of(8), Uint8Array.of(7), writeU32(3));
  mesh.backup_part_export = async (request) => Uint8Array.of(100 + readU32(request.slice(-4)));
  mesh.backup_finish_export = async (request) => { finished.push(request.at(-1)!); return new Uint8Array(); };
  const calls = serve(t, () => new Response(new Uint8Array(), { status: 201 }));
  await backUp('/data/backup.db', Uint8Array.of(1));
  assert.deepEqual(calls.map((call) => `${call.method} ${call.path}`), [
    'POST /v1/attachments/grant',
    `PUT /v1/objects/${hex(objectId)}/parts/0`,
    `PUT /v1/objects/${hex(objectId)}/parts/1`,
    `PUT /v1/objects/${hex(objectId)}/parts/2`,
    'POST /v1/attachments/complete',
  ]);
  assert.deepEqual(calls.slice(1, 4).map((call) => [call.capability, call.body[0]]),
    [[hex(upload), 100], [hex(upload), 101], [hex(upload), 102]]);
  assert.deepEqual(finished, [1]);
  // A part the store refuses discards the object, and the backup does not count.
  finished.length = 0;
  const failing = serve(t, (call) => new Response(new Uint8Array(), { status: call.path.endsWith('/parts/1') ? 507 : 201 }));
  await assert.rejects(backUp('/data/backup.db', Uint8Array.of(1)), /507/);
  assert.equal(failing.at(-1)!.path, '/v1/attachments/delete');
  assert.deepEqual(finished, [0]);
});

test('a restore finds the newest backup the code names and feeds the core every chunk', async (t) => {
  const older = new Uint8Array(32).fill(4);
  const fed: number[] = [];
  mesh.backup_restore_slots_export = async () => list(
    new Uint8Array([...objectId, ...download]),
    new Uint8Array([...new Uint8Array(32).fill(5), ...download]),
    new Uint8Array([...older, ...download]),
  );
  mesh.backup_restore_begin_export = async (request) => {
    assert.equal(request.at(-1), 200);
    return writeU32(2);
  };
  mesh.backup_restore_chunk_export = async (request) => {
    const at = 4 + '/data/restore'.length + 4;
    fed.push(readU32(request.slice(at, at + 4)));
    return new Uint8Array();
  };
  mesh.backup_restore_finish_export = async () =>
    vectors(writeU32(2), writeU32(1), u64(1_700_000_000_000), Uint8Array.of(42), writeU32(10));
  const calls = serve(t, (call) => {
    if (call.path.includes(hex(objectId))) return new Response(new Uint8Array(), { status: 410 });
    if (call.path.includes(hex(older))) return new Response(Uint8Array.of(200 + Number(call.path.at(-1))), { status: 200 });
    return new Response(new Uint8Array(), { status: 404 });
  });
  const restored = await restoreBackup('/data/restore', new Uint8Array(32).fill(6));
  assert.deepEqual(restored, { conversations: 2, groups: 1, createdAt: 1_700_000_000_000, appState: Uint8Array.of(42) });
  assert.deepEqual(calls.map((call) => call.path.slice(-10)), [
    `${hex(objectId).slice(-2)}/parts/0`, '05/parts/0', `${hex(older).slice(-2)}/parts/0`,
    `${hex(older).slice(-2)}/parts/1`, `${hex(older).slice(-2)}/parts/2`,
  ]);
  assert.ok(calls.every((call) => call.method === 'GET' && call.capability === hex(download)));
  assert.deepEqual(fed, [0, 1]);
  serve(t, () => new Response(new Uint8Array(), { status: 404 }));
  await assert.rejects(restoreBackup('/data/restore', new Uint8Array(32)), /backup_not_found/);
});

test('turning backups off sends every deletion, and says how many it could not', async (t) => {
  mesh.backup_disable_export = async () => list(Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3));
  const calls = serve(t, (call) => new Response(null, { status: call.body[0] === 2 ? 503 : 204 }));
  assert.equal(await disableBackups('/data/backup.db'), 1);
  assert.deepEqual(calls.map((call) => call.body[0]), [1, 2, 3]);
});

test('an account with no device left comes back: resolved through the key log, restored, registered', async (t) => {
  const order: string[] = [];
  const record = (name: string, answer: Uint8Array) => async () => { order.push(name); return answer; };
  mesh.backup_restore_slots_export = async () => list(new Uint8Array([...objectId, ...download]));
  mesh.backup_restore_begin_export = async () => writeU32(1);
  mesh.backup_restore_chunk_export = async () => new Uint8Array();
  const identity = (holds: number) => vectors(utf8('alice'), new Uint8Array(32).fill(7), Uint8Array.of(holds));
  mesh.backup_restore_identity_export = record('identity', identity(1));
  mesh.resolve_request_export = record('resolve_request', Uint8Array.of(1));
  mesh.verify_transparency_export = record('verify_transparency', Uint8Array.of(0xd5));
  mesh.backup_restore_account_export = async (request) => {
    order.push('restore_account');
    assert.equal(request.at(-1), 0xd5, 'The account is restored onto the set the key log showed');
    return vectors(writeU32(3), writeU32(0), u64(1_700_000_000_000), new Uint8Array(), writeU32(10));
  };
  mesh.register_request_export = record('register_request', Uint8Array.of(1));
  mesh.replenish_prekeys_export = async () => Uint8Array.of(1);
  mesh.reconcile_prekeys_export = async () => writeU32(64);
  const calls = serve(t, (call) => {
    if (call.path.startsWith('/v1/objects/')) return new Response(Uint8Array.of(1), { status: 200 });
    if (call.path === '/v1/devices/resolve') return new Response(Uint8Array.of(2), { status: 200 });
    if (call.path === '/v1/devices/register') return new Response(new Uint8Array(), { status: 201 });
    return new Response(Uint8Array.of(1), { status: 200 });
  });
  const recovered = await recoverAccount('/data/fresh.db', new Uint8Array(32).fill(6));
  assert.equal(recovered.username, 'alice');
  assert.equal(recovered.conversations, 3);
  assert.deepEqual(order, ['identity', 'resolve_request', 'verify_transparency', 'restore_account', 'register_request']);
  assert.ok(calls.findIndex((call) => call.path === '/v1/devices/register') >
    calls.findIndex((call) => call.path === '/v1/devices/resolve'));
  // A backup from a device without the account key restores only onto a linked device.
  order.length = 0;
  mesh.backup_restore_identity_export = record('identity', identity(0));
  await assert.rejects(recoverAccount('/data/fresh.db', new Uint8Array(32).fill(6)), /backup_has_no_account_key/);
  assert.deepEqual(order, ['identity']);
});
