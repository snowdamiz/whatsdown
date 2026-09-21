import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

import { utf8, vectors, writeU32 } from './codec.ts';

const meshExports = [
  'attachment_open_chunk_export',
  'attachment_prepare_export',
  'attachment_seal_chunk_export',
  'authorize_device_link_for_set_export',
  'create_device_revocation_export',
  'register_request_export',
  'group_add_export',
  'group_create_export',
  'group_history_export',
  'group_inspect_export',
  'group_key_package_export',
  'group_invite_export',
  'group_invitation_accept_export',
  'group_invitation_complete_export',
  'group_invitation_decline_export',
  'group_invitations_export',
  'group_list_export',
  'group_remove_export',
  'group_send_export',
  'inspect_device_set_export',
  'load_profile_export',
  'mailbox_fetch_export',
  'outbox_ack_export',
  'outbox_fail_export',
  'outbox_list_export',
  'outbox_page_export',
  'privacy_submission_export',
  'prepare_fanout_prekeys_export',
  'process_delivery_batch_export',
  'reconcile_prekeys_export',
  'replenish_prekeys_export',
  'send_fanout_export',
  'resolve_request_export',
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
    if (specifier === 'expo/fetch' && context.parentURL?.includes('/src/transport.ts')) {
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
      (specifier === './codec' || specifier === './single-flight' || specifier === './transport') &&
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
const {
  downloadAttachment, sendGroupMessage, sendFanout, submitPushBind, submitEnvelope, inviteToGroup, uploadAttachment,
} = await import('./network.ts');

const hexOf = (value: Uint8Array): string => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

test('uploads encrypt every chunk natively and complete the object only after the last part', async (t) => {
  const database = '/data/attach.db';
  const reference = Uint8Array.of(1, 65, 84, 82, 9);
  const objectId = new Uint8Array(32).fill(5);
  const uploadCapability = new Uint8Array(32).fill(6);
  const prepared: Uint8Array[] = [];
  const sealed: Uint8Array[] = [];
  meshMocks.attachment_prepare_export = async (request) => {
    prepared.push(request);
    return vectors(writeU32(7), reference, objectId, uploadCapability, utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'));
  };
  meshMocks.attachment_seal_chunk_export = async (request) => {
    sealed.push(request);
    return utf8(`sealed-${sealed.length}`);
  };
  const requests: { url: string; method: string; capability: string | null; body: string }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({
      url: String(input), method: init?.method ?? 'GET',
      capability: new Headers(init?.headers).get('X-Object-Capability'),
      body: init?.body ? new TextDecoder().decode(new Uint8Array(init.body as ArrayBuffer)) : '',
    });
    return new Response(null, { status: requests.length === 1 ? 201 : 200 });
  });
  const bytes = new Uint8Array(65_536 + 10).fill(7);
  const progress: number[] = [];
  const uploaded = await uploadAttachment(database, { filename: 'a.bin', mimeType: 'application/octet-stream', bytes },
    (completed) => progress.push(completed));
  assert.deepEqual(uploaded.reference, reference);
  assert.deepEqual(uploaded.objectId, objectId);
  assert.deepEqual(prepared, [vectors(utf8(database), utf8('a.bin'), utf8('application/octet-stream'), writeU32(65_546), writeU32(16))]);
  assert.deepEqual(sealed, [
    vectors(utf8(database), reference, writeU32(0), bytes.subarray(0, 65_536)),
    vectors(utf8(database), reference, writeU32(1), bytes.subarray(65_536)),
  ]);
  assert.deepEqual(progress, [1, 2]);
  const parts = `http://127.0.0.1:18086/v1/objects/${hexOf(objectId)}/parts/`;
  assert.deepEqual(requests, [
    { url: 'http://127.0.0.1:18086/v1/attachments/grant', method: 'POST', capability: null, body: 'grant' },
    { url: `${parts}0`, method: 'PUT', capability: hexOf(uploadCapability), body: 'manifest' },
    { url: `${parts}1`, method: 'PUT', capability: hexOf(uploadCapability), body: 'sealed-1' },
    { url: `${parts}2`, method: 'PUT', capability: hexOf(uploadCapability), body: 'sealed-2' },
    { url: 'http://127.0.0.1:18086/v1/attachments/complete', method: 'POST', capability: null, body: 'complete' },
  ]);
  await uploaded.discard();
  assert.deepEqual(requests.at(-1), { url: 'http://127.0.0.1:18086/v1/attachments/delete', method: 'POST', capability: null, body: 'delete' });
  await assert.rejects(uploadAttachment(database, { filename: '', mimeType: 'text/plain', bytes: new Uint8Array() }), /empty/);
  await assert.rejects(uploadAttachment(database, { filename: '', mimeType: 'text/plain', bytes: new Uint8Array(256 * 65_536 + 1) }), /16 MB/);
});

test('a failed part upload deletes the object before surfacing the error', async (t) => {
  meshMocks.attachment_prepare_export = async () => vectors(writeU32(7), Uint8Array.of(1), new Uint8Array(32), new Uint8Array(32),
    utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'));
  meshMocks.attachment_seal_chunk_export = async () => utf8('sealed');
  const bodies: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    bodies.push(init?.body ? new TextDecoder().decode(new Uint8Array(init.body as ArrayBuffer)) : '');
    return new Response(null, { status: String(input).endsWith('/parts/1') ? 413 : 200 });
  });
  await assert.rejects(uploadAttachment('/data/attach.db', { filename: 'a', mimeType: 'text/plain', bytes: Uint8Array.of(1) }), /413/);
  assert.deepEqual(bodies, ['grant', 'manifest', 'sealed', 'delete']);
});

test('downloads fetch chunks with the download capability and reassemble the exact plaintext', async (t) => {
  const database = '/data/attach.db';
  const summary = {
    reference: Uint8Array.of(1, 65, 84, 82, 3), objectId: new Uint8Array(32).fill(8), downloadCapability: new Uint8Array(32).fill(9),
    filename: 'a.txt', mimeType: 'text/plain', size: 5, chunkCount: 1, chunkSize: 65_536, expiresAt: 1,
  };
  const opened: Uint8Array[] = [];
  meshMocks.attachment_open_chunk_export = async (request) => { opened.push(request); return utf8('hello'); };
  const requests: { url: string; method: string; capability: string | null; body: unknown }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(input), method: init?.method ?? 'GET', capability: new Headers(init?.headers).get('X-Object-Capability'), body: init?.body });
    return new Response(utf8('sealed'));
  });
  assert.deepEqual(await downloadAttachment(database, summary), utf8('hello'));
  assert.deepEqual(opened, [vectors(utf8(database), summary.reference, writeU32(0), utf8('sealed'))]);
  assert.deepEqual(requests, [{
    url: `http://127.0.0.1:18086/v1/objects/${hexOf(summary.objectId)}/parts/1`, method: 'GET',
    capability: hexOf(summary.downloadCapability), body: undefined,
  }]);
  meshMocks.attachment_open_chunk_export = async () => utf8('hell');
  await assert.rejects(downloadAttachment(database, summary), /manifest/);
});

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
  meshMocks.resolve_request_export = async () => Uint8Array.of(1);
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
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
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
  // An attachment reference rides as one trailing vector after the body.
  await sendFanout('/data/mobile.db', 'peer', '', undefined, Uint8Array.of(1, 65, 84, 82));
  assert.deepEqual(sent[1], vectors(
    utf8('/data/mobile.db'), Uint8Array.of(21, 22), Uint8Array.of(31, 32), new Uint8Array(), Uint8Array.of(1, 65, 84, 82),
  ));
});

test('invites by username through the verified encrypted delivery path', async (t) => {
  const prepared: Uint8Array[] = [];
  const messages: Uint8Array[] = [];
  installFanoutMocks(prepared, messages);
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));
  const invitations: Uint8Array[] = [];
  meshMocks.group_invite_export = async (request) => {
    invitations.push(request);
    return new Uint8Array();
  };
  const groupId = new Uint8Array(32).fill(7);
  await inviteToGroup('/data/mobile.db', groupId, 'peer');
  assert.deepEqual(invitations, [vectors(utf8('/data/mobile.db'),
    Uint8Array.of(21, 22), Uint8Array.of(31, 32), groupId)]);
  assert.equal(prepared.length, 1);
  assert.equal(messages.length, 0);
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

test('one mailbox wakeup drains every batch and still receives when outbox delivery fails', async (t) => {
  const { synchronizeMailbox } = await import('./network.ts');
  let fetches = 0;
  let applied = 0;
  meshMocks.outbox_page_export = async () => { throw new Error('outbox unavailable'); };
  meshMocks.mailbox_fetch_export = async () => Uint8Array.of(1);
  // A real acknowledgement says at byte 44 how many envelopes Mesh is done with: all eight.
  const acknowledgedAll = new Uint8Array(125);
  acknowledgedAll[44] = 8;
  meshMocks.process_delivery_batch_export = async () => ++applied < 3 ? acknowledgedAll : new Uint8Array();
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    if (String(input).endsWith('/v1/mailbox/fetch')) {
      fetches += 1;
      return new Response(Uint8Array.of(1, 66, 65, 84, fetches < 3 ? 8 : 0));
    }
    return new Response();
  });
  await assert.rejects(synchronizeMailbox('/data/receive.db'), /outbox unavailable/);
  assert.equal(fetches, 3);
  assert.equal(applied, 3);
});

test('retries unprocessed deliveries instead of treating a nonempty mailbox as current', async (t) => {
  const { synchronizeMailbox } = await import('./network.ts');
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  meshMocks.mailbox_fetch_export = async () => Uint8Array.of(1);
  meshMocks.process_delivery_batch_export = async () => new Uint8Array();
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1, 66, 65, 84, 1)));
  await assert.rejects(synchronizeMailbox('/data/retry.db'), /processing.*retry/i);
});

// Envelopes that cannot be opened yet stay unacknowledged, and the service hands
// the oldest unacknowledged ones over first. A pass must reach what is behind them.
test('envelopes set aside for later do not keep a pass from what is queued behind them', async (t) => {
  const { synchronizeMailbox } = await import('./network.ts');
  const positions: number[] = [];
  let acknowledged = 0;
  // Mesh asks from 0, then past the eight it set aside, then past the two it took.
  const frame = (after: number): Uint8Array => {
    const bytes = new Uint8Array(116);
    new DataView(bytes.buffer).setBigUint64(36, BigInt(after));
    return bytes;
  };
  const ack = (count: number): Uint8Array => { const bytes = new Uint8Array(125); bytes[44] = count; return bytes; };
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  meshMocks.mailbox_fetch_export = async () => frame([0, 8, 10][positions.length] ?? 10);
  meshMocks.process_delivery_batch_export = async (request) => (request.at(-1) === 8 ? new Uint8Array() : request.at(-1) === 2 ? ack(2) : new Uint8Array());
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/v1/mailbox/fetch')) {
      const after = Number(new DataView(init?.body as ArrayBuffer).getBigUint64(36));
      positions.push(after);
      return new Response(Uint8Array.of(1, 66, 65, 84, after === 0 ? 8 : after === 8 ? 2 : 0));
    }
    if (url.endsWith('/v1/mailbox/ack')) acknowledged += 1;
    return new Response();
  });
  // Something is still waiting, so the caller is told to come back, but only
  // after everything that could be taken was taken.
  await assert.rejects(synchronizeMailbox('/data/set-aside.db'), /processing.*retry/i);
  assert.deepEqual(positions, [0, 8, 10]);
  assert.equal(acknowledged, 1);
});

test('connects the stream with opaque mailbox authorization and enforces TLS', async (t) => {
  const network = await import('./network.ts');
  assert.equal(typeof network.connectMailboxStream, 'function');
  const previous = process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL;
  const opened: unknown[][] = [];
  t.mock.method(globalThis, 'WebSocket', class {
    constructor(...args: unknown[]) { opened.push(args); }
  } as unknown as typeof WebSocket);
  t.mock.method(globalThis, 'fetch', async () => new Response());
  meshMocks.register_request_export = async () => Uint8Array.of(1);
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(2);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.mailbox_fetch_export = async () => Uint8Array.of(1, 70, 69, 84);
  try {
    development(false);
    process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL = 'ws://127.0.0.1:18090/v1/mailbox/stream';
    await assert.rejects(network.connectMailboxStream('/data/stream.db'), /HTTPS/);
    assert.equal(opened.length, 0);
    development(true);
    await network.connectMailboxStream('/data/stream.db');
    assert.deepEqual(opened, [[
      'ws://127.0.0.1:18090/v1/mailbox/stream', [],
      { headers: { Authorization: 'MeshMailbox 01464554' } },
    ]]);
  } finally {
    development(true);
    if (previous === undefined) delete process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL;
    else process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL = previous;
  }
});

test('reconciles a full prekey pool without retrying publication or suppressing other 429 errors', async (t) => {
  const { synchronizePrekeys } = await import('./network.ts');
  const database = '/data/full-prekeys.db';
  const acknowledgement = Uint8Array.of(1, 79, 84, 65);
  let reconciled = false;
  let publications = 0;
  meshMocks.replenish_prekeys_export = async () => {
    publications += 1;
    return Uint8Array.of(1);
  };
  meshMocks.reconcile_prekeys_export = async (request) => {
    assert.deepEqual(request, vectors(utf8(database), acknowledgement));
    reconciled = true;
    return writeU32(64);
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(acknowledgement, { status: 429 }));
  await synchronizePrekeys(database);
  assert.equal(reconciled, true);
  assert.equal(publications, 1);
  await assert.rejects(submitPushBind(Uint8Array.of(1)), /Server returned 429/);
});

test('group sending refreshes each account once and waits for every authorization', async t => {
  const groupId = new Uint8Array(32).fill(10);
  const accounts = [new Uint8Array(32).fill(11), new Uint8Array(32).fill(12)];
  const member = (index: number, account: Uint8Array) => vectors(writeU32(7), Uint8Array.of(1), writeU32(index), Uint8Array.of(index === 0 ? 1 : 0), account, new Uint8Array(16).fill(index + 1), u64(1n), Uint8Array.of(2));
  meshMocks.group_inspect_export = async () => vectors(writeU32(7), Uint8Array.of(1), groupId, u64(1n), writeU32(0), new Uint8Array(32), new Uint8Array(32), vectors(writeU32(3), member(0, accounts[0]!), member(1, accounts[0]!), member(2, accounts[1]!)));
  let lookups = 0;
  let verified = 0;
  let sends = 0;
  let reject = true;
  meshMocks.resolve_request_export = async request => {
    const account = accounts[lookups++ % 2]!;
    const reference = '@' + Array.from(account, byte => byte.toString(16).padStart(2, '0')).join('');
    assert.deepEqual(request, vectors(utf8('/group-test.db'), utf8(reference)));
    return Uint8Array.of(1);
  };
  meshMocks.verify_transparency_export = async () => {
    verified++;
    if (reject && verified === 2) throw new Error('transparency_stale');
    return Uint8Array.of(1);
  };
  const requests: Uint8Array[] = [];
  meshMocks.group_send_export = async request => { assert.equal(verified, 2); sends++; requests.push(request); return Uint8Array.of(1); };
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));
  await assert.rejects(sendGroupMessage('/group-test.db', groupId, 'pending'), /transparency_stale/);
  assert.equal(sends, 0);
  assert.equal(lookups, 2);
  reject = false; verified = 0; lookups = 0;
  await sendGroupMessage('/group-test.db', groupId, 'authorized');
  assert.equal(sends, 1);
  assert.equal(lookups, 2);
  assert.deepEqual(requests[0], vectors(utf8('/group-test.db'), groupId, utf8('authorized')));
  verified = 0;
  await sendGroupMessage('/group-test.db', groupId, '', Uint8Array.of(1, 65, 84, 82));
  assert.deepEqual(requests[1], vectors(utf8('/group-test.db'), groupId, new Uint8Array(), Uint8Array.of(1, 65, 84, 82)));
});

test('sending ten attachments calls send once; partial uploads are cleaned and queued sends keep their objects', async (t) => {
  const { sendWithAttachments } = await import('./network.ts');
  const files = Array.from({ length: 10 }, (_, index) => ({ filename: `${index}.jpg`, mimeType: 'image/jpeg', bytes: Uint8Array.of(index) }));
  let prepared = 0;
  let failAt = 0;
  meshMocks.attachment_prepare_export = async () => {
    prepared += 1;
    if (prepared === failAt) throw new Error('upload failed');
    return vectors(writeU32(7), Uint8Array.of(prepared), new Uint8Array(32).fill(prepared), new Uint8Array(32),
      utf8('grant'), utf8('complete'), utf8(`delete-${prepared}`), utf8('manifest'));
  };
  meshMocks.attachment_seal_chunk_export = async () => utf8('sealed');
  const deleted: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input).endsWith('/delete')) deleted.push(new TextDecoder().decode(init?.body as ArrayBuffer));
    return new Response(null, { status: 200 });
  });
  const sent: Uint8Array[] = [];
  const uploaded = await sendWithAttachments('/data/attach.db', files, async (reference) => { sent.push(reference!); });
  assert.equal(uploaded.length, 10);
  assert.deepEqual(sent, [new Uint8Array([1, 65, 84, 66, ...writeU32(10), ...vectors(...uploaded.map((file) => file.reference))])]);
  prepared = 0;
  failAt = 3;
  await assert.rejects(sendWithAttachments('/data/attach.db', files, async () => assert.fail('sent incomplete album')), /upload failed/);
  assert.deepEqual(deleted.sort(), ['delete-1', 'delete-2']);
  prepared = 0;
  failAt = 0;
  deleted.length = 0;
  await assert.rejects(sendWithAttachments('/data/attach.db', files, async () => { throw new Error('delivery failed'); }), /delivery failed/);
  assert.deepEqual(deleted, []); // Native send may already have committed the message to its durable outbox.
  prepared = 0;
  await assert.rejects(sendWithAttachments('/data/attach.db', [...files, files[0]!], async () => assert.fail()), /up to 10/);
  assert.equal(prepared, 0);
});

// The outbox sends in order. An envelope the service will never accept must not
// hold up what is queued behind it, and must not vanish without a trace either;
// one a recipient cannot take right now must hold up nobody but that recipient.
const { drainOutbox, onUndeliverable } = await import('./network.ts');

// Bytes 20..52 of an envelope are the mailbox it is addressed to.
function queuedEnvelope(id: number, expiresAt: number, mailbox = 1): Uint8Array {
  const envelope = new Uint8Array(70).fill(id);
  envelope.set([1, 0x4d, 0x53, 0x47]); // version 1, "MSG"
  envelope.fill(mailbox, 20, 52);
  new DataView(envelope.buffer).setBigUint64(54, BigInt(expiresAt));
  return envelope;
}

// A stand-in for the native outbox and the delivery service: `statusFor` decides
// how the service answers each envelope, by its first payload byte.
function outboxFixture(t: test.TestContext, queue: Uint8Array[], statusFor: (id: number) => number | 'offline') {
  const submitted: number[] = [];
  const refused: number[] = [];
  const reports: { status: number; queuedAt: number }[] = [];
  const remove = (request: Uint8Array): number => {
    const index = queue.findIndex((envelope) => hexOf(request).endsWith(hexOf(envelope)));
    assert.notEqual(index, -1, 'settled an envelope that is not queued');
    return queue.splice(index, 1)[0]![4]!;
  };
  meshMocks.privacy_submission_export = async (value) => value;
  meshMocks.outbox_page_export = async (request) => {
    const offset = new DataView(request.buffer, request.byteOffset + request.length - 4).getUint32(0);
    const page = queue.slice(offset, offset + 8);
    return vectors(writeU32(page.length), ...page);
  };
  meshMocks.outbox_ack_export = async (request) => { remove(request); return new Uint8Array(); };
  meshMocks.outbox_fail_export = async (request) => { refused.push(remove(request)); return new Uint8Array(); };
  t.mock.method(globalThis, 'fetch', async (_input, init) => {
    const id = new Uint8Array(init?.body as ArrayBuffer)[4]!;
    submitted.push(id);
    const status = statusFor(id);
    if (status === 'offline') throw new TypeError('Network request failed');
    return new Response(null, { status });
  });
  const previous = process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
  process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL = 'http://127.0.0.1:18087';
  const unsubscribe = onUndeliverable((report) => reports.push(report));
  t.after(() => {
    unsubscribe();
    if (previous === undefined) delete process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
    else process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL = previous;
  });
  return { submitted, refused, reports };
}

const inThirtyDays = (): number => Date.now() + 2_592_000_000;
const ids = (queue: Uint8Array[]): number[] => queue.map((envelope) => envelope[4]!);

test('an envelope for a revoked mailbox is refused in the core, reported, and holds nothing up', async (t) => {
  const queue = [queuedEnvelope(7, inThirtyDays()), queuedEnvelope(8, inThirtyDays())];
  const { submitted, refused, reports } = outboxFixture(t, queue, (id) => (id === 7 ? 410 : 202));
  await drainOutbox('/data/outbox-revoked.db');
  assert.deepEqual(submitted, [7, 8]);
  assert.deepEqual(refused, [7]); // The core marks its message as not delivered; 8 was acknowledged.
  assert.equal(queue.length, 0);
  assert.equal(reports.length, 1);
  assert.equal(reports[0]!.status, 410);
});

test('an envelope that expired while queued is refused in the core, reported, and holds nothing up', async (t) => {
  const expired = Date.now() - 1_000;
  const queue = [queuedEnvelope(7, expired), queuedEnvelope(8, inThirtyDays())];
  const { submitted, refused, reports } = outboxFixture(t, queue, (id) => (id === 7 ? 400 : 202));
  await drainOutbox('/data/outbox-expired.db');
  assert.deepEqual(submitted, [7, 8]);
  assert.deepEqual(refused, [7]);
  assert.equal(queue.length, 0);
  assert.deepEqual(reports, [{ status: 400, queuedAt: expired - 2_592_000_000 }]);
});

// A 400 the device cannot explain may mean the service refuses everything this
// build sends (a version or clock mismatch). Discarding on that would empty the
// outbox for good, so it waits like any other failure, and order is kept.
test('an unexplained refusal or an outage keeps every envelope, in order', async (t) => {
  for (const failure of [400, 500, 502, 'offline'] as const) {
    const queue = [queuedEnvelope(7, inThirtyDays()), queuedEnvelope(8, inThirtyDays(), 2)];
    const { submitted, refused, reports } = outboxFixture(t, queue, (id) => (id === 7 ? failure : 202));
    await assert.rejects(drainOutbox(`/data/outbox-${failure}.db`));
    assert.deepEqual(submitted, [7], `envelope 8 overtook a ${failure}`);
    assert.deepEqual(ids(queue), [7, 8]);
    assert.deepEqual(refused, []);
    assert.deepEqual(reports, []);
    t.mock.restoreAll();
  }
});

test('a recipient who cannot take an envelope now holds up nobody else, and keeps their own order', async (t) => {
  // 7 and 8 are for one recipient, 9 for another. 7 is turned away for now.
  const queue = [queuedEnvelope(7, inThirtyDays(), 1), queuedEnvelope(8, inThirtyDays(), 1), queuedEnvelope(9, inThirtyDays(), 2)];
  const { submitted, refused, reports } = outboxFixture(t, queue, (id) => (id === 7 ? 429 : 202));
  await assert.rejects(drainOutbox('/data/outbox-full-mailbox.db'), /recipient_unavailable/);
  // 8 must not overtake 7, so it was not even offered; 9 went out.
  assert.deepEqual(submitted, [7, 9]);
  assert.deepEqual(ids(queue), [7, 8]);
  assert.deepEqual(refused, []);
  assert.deepEqual(reports, []);
});

test('envelopes that must wait cannot hide the ones queued behind the first page', async (t) => {
  // Nine for a recipient who is turned away fill more than the first page of eight.
  const queue = [...Array.from({ length: 9 }, (_, index) => queuedEnvelope(10 + index, inThirtyDays(), 1)),
    queuedEnvelope(99, inThirtyDays(), 2)];
  const { submitted } = outboxFixture(t, queue, (id) => (id === 99 ? 202 : 429));
  await assert.rejects(drainOutbox('/data/outbox-paged.db'), /recipient_unavailable/);
  assert.deepEqual(submitted, [10, 99]);
  assert.equal(queue.length, 9);
});

test('a lookup waits for the witnesses to sign a new checkpoint, and only for that', async (t) => {
  const { resolveDeviceSet } = await import('./network.ts');
  let lookups = 0;
  let unwitnessed = 2;
  meshMocks.resolve_request_export = async () => { lookups++; return Uint8Array.of(1); };
  meshMocks.verify_transparency_export = async () => {
    if (unwitnessed-- > 0) throw new Error('Mesh library call failed (status=9): transparency_verification_failed');
    return Uint8Array.of(9);
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const resolved = resolveDeviceSet('/data/witness-wait.db', 'alice');
  for (let tick = 0; tick < 2; tick++) {
    await new Promise((resolve) => setImmediate(resolve));
    t.mock.timers.tick(5_000);
  }
  assert.deepEqual(await resolved, Uint8Array.of(9));
  assert.equal(lookups, 3);
  // Any other refusal is final.
  meshMocks.verify_transparency_export = async () => { throw new Error('transparency_stale'); };
  await assert.rejects(resolveDeviceSet('/data/witness-wait.db', 'alice'), /transparency_stale/);
  assert.equal(lookups, 4);
});
