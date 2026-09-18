import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

import { utf8, vectors, writeU32 } from './codec.ts';

const meshExports = [
  'authorize_device_link_for_set_export',
  'create_device_revocation_export',
  'directory_entry_export',
  'group_add_export',
  'group_create_export',
  'group_history_export',
  'group_inspect_export',
  'group_key_package_export',
  'group_list_export',
  'group_remove_export',
  'group_send_export',
  'inspect_device_set_export',
  'load_profile_export',
  'mailbox_fetch_export',
  'outbox_ack_export',
  'outbox_list_export',
  'privacy_submission_export',
  'prepare_fanout_prekeys_export',
  'process_delivery_batch_export',
  'reconcile_prekeys_export',
  'replenish_prekeys_export',
  'send_fanout_export',
  'transparency_lookup_export',
  'verify_transparency_export',
] as const;

type MeshExport = (request: Uint8Array) => Promise<Uint8Array>;
const meshMocks = Object.fromEntries(meshExports.map((name) => [name, async () => {
  throw new Error(`Unexpected Mesh call: ${name}`);
}])) as Record<(typeof meshExports)[number], MeshExport>;
(globalThis as typeof globalThis & { __meshNetworkMocks: typeof meshMocks }).__meshNetworkMocks = meshMocks;

const mockModule = [
  "const call = (name) => (...args) => globalThis.__meshNetworkMocks[name](...args);",
  ...meshExports.map((name) => `export const ${name} = call('${name}');`),
].join('\n');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'expo/fetch' && context.parentURL?.includes('/src/network.ts')) {
      return {
        shortCircuit: true,
        url: 'data:text/javascript,export const fetch = (...args) => globalThis.fetch(...args);',
      };
    }
    if (specifier === '../modules/mesh-messenger' && context.parentURL?.includes('/src/network.ts')) {
      return {
        shortCircuit: true,
        url: `data:text/javascript,${encodeURIComponent(mockModule)}`,
      };
    }
    if (
      (specifier === './codec' || specifier === './single-flight') &&
      context.parentURL?.includes('/src/network.ts')
    ) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});

const development = (value: boolean): void => {
  (globalThis as typeof globalThis & { __DEV__: boolean }).__DEV__ = value;
};
development(true);
const { sendFanout, submitPushBind, submitEnvelope } = await import('./network.ts');

test('rejects cleartext service requests in release builds before network I/O', async (t) => {
  development(false);
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    calls += 1;
    return new Response();
  });
  try {
    await assert.rejects(submitPushBind(Uint8Array.of(1)), /HTTPS/);
    assert.equal(calls, 0);
  } finally {
    development(true);
  }
});

test('allows HTTP only for local development and refuses redirects', async (t) => {
  meshMocks.privacy_submission_export = async (value) => value;
  const previous = process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    calls += 1;
    assert.equal(init?.redirect, 'error');
    return new Response();
  });
  try {
    for (const url of ['http://example.com', 'http://127.0.0.1.example.com', 'https://user:password@example.com', 'https://example.com?token=1']) {
      process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL = url;
      await assert.rejects(submitEnvelope(Uint8Array.of(1)));
    }
    assert.equal(calls, 0);
    for (const url of ['http://127.0.0.1:18087', 'http://192.168.1.20:18087', 'https://example.com']) {
      process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL = url;
      await submitEnvelope(Uint8Array.of(1));
    }
    assert.equal(calls, 3);
  } finally {
    if (previous === undefined) delete process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
    else process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL = previous;
  }
});

const u64 = (value: bigint): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
};

const profile = (username: string): Uint8Array => vectors(
  utf8(username),
  new Uint8Array(32).fill(1),
  new Uint8Array(16).fill(2),
  Uint8Array.of(3),
);

const deviceSummary = (username: string, changed: boolean): Uint8Array => vectors(
  utf8(username),
  new Uint8Array(32).fill(4),
  u64(1n),
  Uint8Array.of(changed ? 1 : 0),
  Uint8Array.of(1),
  vectors(writeU32(0)),
);

function installFanoutMocks(
  prepared: Uint8Array[],
  sent: Uint8Array[],
): void {
  const peerSet = Uint8Array.of(21, 22);
  const localSet = Uint8Array.of(31, 32);
  let verified = 0;
  let inspected = 0;
  meshMocks.load_profile_export = async () => profile('local');
  meshMocks.transparency_lookup_export = async () => Uint8Array.of(1);
  meshMocks.verify_transparency_export = async () => [peerSet, localSet][verified++ % 2]!;
  meshMocks.inspect_device_set_export = async () =>
    [deviceSummary('peer', true), deviceSummary('local', false)][inspected++ % 2]!;
  meshMocks.prepare_fanout_prekeys_export = async (request) => {
    prepared.push(request);
    return new Uint8Array();
  };
  meshMocks.send_fanout_export = async (request) => {
    sent.push(request);
    return new Uint8Array();
  };
  meshMocks.outbox_list_export = async () => vectors(writeU32(0));
}

test('delegates bounded prekey preparation to Mesh before fanout', async (t) => {
  const prepared: Uint8Array[] = [];
  const sent: Uint8Array[] = [];
  installFanoutMocks(prepared, sent);
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    assert.match(String(input), /\/v1\/devices\/resolve$/);
    return new Response(Uint8Array.of(1));
  });

  assert.equal(await sendFanout('/data/mobile.db', 'peer', 'hello'), true);
  assert.deepEqual(prepared, [
    vectors(
      utf8('/data/mobile.db'),
      Uint8Array.of(21, 22),
      Uint8Array.of(31, 32),
      utf8('http://127.0.0.1:18086'),
    ),
  ]);
  assert.deepEqual(sent, [
    vectors(
      utf8('/data/mobile.db'),
      Uint8Array.of(21, 22),
      Uint8Array.of(31, 32),
      utf8('hello'),
    ),
  ]);
});

test('binds sends to the account selected by a saved chat or contact code', async (t) => {
  const prepared: Uint8Array[] = [];
  const sent: Uint8Array[] = [];
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));

  for (const accountId of [new Uint8Array(32).fill(9), new Uint8Array()]) {
    installFanoutMocks(prepared, sent);
    await assert.rejects(
      sendFanout('/data/mobile.db', 'peer', 'private message', accountId),
      /contact identity/i,
    );
    assert.equal(prepared.length, 0);
    assert.equal(sent.length, 0);
  }

  installFanoutMocks(prepared, sent);
  await sendFanout('/data/mobile.db', 'peer', 'private message', new Uint8Array(32).fill(4));
  assert.equal(prepared.length, 1);
  assert.equal(sent.length, 1);
});

test('serializes the complete fanout transaction for one database', async (t) => {
  installFanoutMocks([], []);
  let profileLoads = 0;
  meshMocks.load_profile_export = async () => {
    profileLoads += 1;
    return profile('local');
  };

  let releaseResolve = (_response: Response): void => {
    throw new Error('First resolve did not start');
  };
  const blockedResolve = new Promise<Response>((resolve) => { releaseResolve = resolve; });
  let observeResolve = (): void => {};
  const resolveObserved = new Promise<void>((resolve) => { observeResolve = resolve; });
  let resolveRequests = 0;
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    if (String(input).endsWith('/v1/devices/resolve')) {
      resolveRequests += 1;
      if (resolveRequests === 1) {
        observeResolve();
        return blockedResolve;
      }
      return new Response(Uint8Array.of(1));
    }
    return new Response(Uint8Array.of(9));
  });

  const first = sendFanout('/data/mobile.db', 'peer', 'first');
  await resolveObserved;
  const second = sendFanout('/data/mobile.db', 'peer', 'second');
  await Promise.resolve();
  try {
    assert.equal(profileLoads, 1);
  } finally {
    releaseResolve(new Response(Uint8Array.of(1)));
    await Promise.allSettled([first, second]);
  }
});
