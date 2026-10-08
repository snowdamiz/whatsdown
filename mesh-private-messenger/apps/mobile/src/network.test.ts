import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream, openAsBlob } from 'node:fs';
import { appendFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { memoryAttachment } from './attachments.ts';
import { utf8, vector, vectors, writeU32 } from './codec.ts';

const meshExports = [
  'account_deletion_export',
  'backup_disable_export',
  'attachment_open_chunk_export',
  'attachment_prepare_export',
  'attachment_seal_chunk_export',
  'authorize_device_link_for_set_export',
  'create_device_revocation_export',
  'device_departure_export',
  'erase_account_export',
  'forget_on_proof_export',
  'register_request_export',
  'renew_devices_export',
  'group_add_export',
  'group_create_export',
  'group_forget_export',
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
  'transparency_anchor_requests_export',
  'transparency_anchor_proof_export',
  'network_status_export',
  'anchor_check_export',
  'gossip_check_export',
  'trust_alarm_details_export',
  'group_send_view_once_export',
  'group_timer_export',
  'send_view_once_export',
  'credits_postage_quote_export',
  'credits_register_at_export',
  'oblivious_encapsulate_export',
  'oblivious_decapsulate_export',
] as const;

type MeshExport = (request: Uint8Array) => Promise<Uint8Array>;
const meshMocks = Object.fromEntries(meshExports.map((name) => [name, async () => {
  throw new Error(`Unexpected Mesh call: ${name}`);
}])) as Record<(typeof meshExports)[number], MeshExport>;
(globalThis as typeof globalThis & { __meshNetworkMocks: typeof meshMocks }).__meshNetworkMocks = meshMocks;
// No device of a peer asks a price unless a test says so.
meshMocks.credits_postage_quote_export = async () => Uint8Array.of(0);
// A development build that pins no OHTTP gateway sends stateless requests directly.
const unpinned: MeshExport = async () => new Uint8Array();
meshMocks.oblivious_encapsulate_export = unpinned;

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
  checkPublicRecord, downloadAttachment, sendGroupMessage, sendFanout, submitPushBind, submitEnvelope, inviteToGroup,
  setCreditSource, streamAttachment, uploadAttachment,
} = await import('./network.ts');

const hexOf = (value: Uint8Array): string => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

test('uploads encrypt every padded chunk natively and complete the object only after the last part', async (t) => {
  const database = '/data/attach.db';
  const reference = Uint8Array.of(1, 65, 84, 82, 9);
  const objectId = new Uint8Array(32).fill(5);
  const uploadCapability = new Uint8Array(32).fill(6);
  const prepared: Uint8Array[] = [];
  const sealed: Uint8Array[] = [];
  meshMocks.attachment_prepare_export = async (request) => {
    prepared.push(request);
    // The core padded 65,546 bytes to a bucket three chunks long.
    return vectors(writeU32(8), reference, objectId, uploadCapability, utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'),
      writeU32(3));
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
  const uploaded = await uploadAttachment(database, memoryAttachment('a.bin', 'application/octet-stream', bytes),
    (completed) => progress.push(completed));
  assert.deepEqual(uploaded.reference, reference);
  assert.deepEqual(uploaded.objectId, objectId);
  assert.deepEqual(prepared, [vectors(utf8(database), utf8('a.bin'), utf8('application/octet-stream'), writeU32(65_546), writeU32(16))]);
  assert.deepEqual(sealed, [
    vectors(utf8(database), reference, writeU32(0), bytes.subarray(0, 65_536)),
    vectors(utf8(database), reference, writeU32(1), bytes.subarray(65_536)),
    vectors(utf8(database), reference, writeU32(2), new Uint8Array()),
  ]);
  assert.deepEqual(progress, [1, 2, 3]);
  const parts = `http://127.0.0.1:18086/v1/objects/${hexOf(objectId)}/parts/`;
  assert.deepEqual(requests, [
    { url: 'http://127.0.0.1:18086/v1/attachments/grant', method: 'POST', capability: null, body: 'grant' },
    { url: `${parts}0`, method: 'PUT', capability: hexOf(uploadCapability), body: 'manifest' },
    { url: `${parts}1`, method: 'PUT', capability: hexOf(uploadCapability), body: 'sealed-1' },
    { url: `${parts}2`, method: 'PUT', capability: hexOf(uploadCapability), body: 'sealed-2' },
    { url: `${parts}3`, method: 'PUT', capability: hexOf(uploadCapability), body: 'sealed-3' },
    { url: 'http://127.0.0.1:18086/v1/attachments/complete', method: 'POST', capability: null, body: 'complete' },
  ]);
  await uploaded.discard();
  assert.deepEqual(requests.at(-1), { url: 'http://127.0.0.1:18086/v1/attachments/delete', method: 'POST', capability: null, body: 'delete' });
  await assert.rejects(uploadAttachment(database, memoryAttachment('', 'text/plain', new Uint8Array())), /empty/);
  const huge = { filename: '', mimeType: 'text/plain', size: 8192 * 65_536 + 1, read: async () => assert.fail('read a file too large') };
  await assert.rejects(uploadAttachment(database, huge), /512 MB/);
});

test('a failed part upload deletes the object before surfacing the error', async (t) => {
  meshMocks.attachment_prepare_export = async () => vectors(writeU32(8), Uint8Array.of(1), new Uint8Array(32), new Uint8Array(32),
    utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'), writeU32(1));
  meshMocks.attachment_seal_chunk_export = async () => utf8('sealed');
  const bodies: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    bodies.push(init?.body ? new TextDecoder().decode(new Uint8Array(init.body as ArrayBuffer)) : '');
    return new Response(null, { status: String(input).endsWith('/parts/1') ? 413 : 200 });
  });
  await assert.rejects(uploadAttachment('/data/attach.db', memoryAttachment('a', 'text/plain', Uint8Array.of(1))), /413/);
  assert.deepEqual(bodies, ['grant', 'manifest', 'sealed', 'delete']);
});

test('an upload the core left fewer chunks than the file needs never starts', async (t) => {
  meshMocks.attachment_prepare_export = async () => vectors(writeU32(8), Uint8Array.of(1), new Uint8Array(32), new Uint8Array(32),
    utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'), writeU32(1));
  const fetched = t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 200 }));
  await assert.rejects(uploadAttachment('/data/attach.db', memoryAttachment('a', 'text/plain', new Uint8Array(65_537))),
    /invalid attachment/);
  assert.equal(fetched.mock.callCount(), 0);
});

// A 20 MiB file: the grant carries the one credit its bucket costs, taken from
// the device's credits, and the file is read a chunk at a time, never whole.
const MiB = 1_048_576;
const largeFile = (size: number, reads: [number, number][]) => ({
  filename: 'launch.mov', mimeType: 'video/quicktime', size,
  read: async (offset: number, length: number) => {
    reads.push([offset, length]);
    return new Uint8Array(length).fill((offset / 65_536) % 251);
  },
});

test('a file over 16 MB pays for its grant with credits and uploads one chunk at a time', async (t) => {
  const tokens = new Uint8Array(354).fill(1);
  const settled: (boolean | undefined)[] = [];
  setCreditSource({ balance: async () => 1, take: async (count) => {
    assert.equal(count, 1);
    return { tokens, settle: async (spent) => { settled.push(spent); } };
  } });
  const prepared: Uint8Array[] = [];
  meshMocks.attachment_prepare_export = async (request) => {
    prepared.push(request);
    return vectors(writeU32(8), Uint8Array.of(1), new Uint8Array(32).fill(3), new Uint8Array(32).fill(4),
      new Uint8Array(37 + 354 + 124), utf8('complete'), utf8('delete'), new Uint8Array(514), writeU32(320));
  };
  meshMocks.attachment_seal_chunk_export = async () => new Uint8Array(8);
  const urls: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    urls.push(String(input));
    return new Response(null, { status: 201 });
  });
  const reads: [number, number][] = [];
  const progress: number[] = [];
  await uploadAttachment('/data/attach.db', largeFile(20 * MiB, reads), (completed, total) => progress.push(completed / total));
  assert.deepEqual(prepared, [vectors(utf8('/data/attach.db'), utf8('launch.mov'), utf8('video/quicktime'),
    writeU32(20 * MiB), writeU32(16), tokens)]);
  assert.equal(reads.length, 320);
  assert.ok(reads.every(([offset, length], index) => offset === index * 65_536 && length === 65_536));
  assert.equal(urls.filter((url) => url.includes('/parts/')).length, 321);
  assert.ok(urls.at(-2)!.endsWith('/parts/320') && urls.at(-1)!.endsWith('/v1/attachments/complete'));
  assert.equal(progress.length, 320);
  assert.equal(progress.at(-1), 1);
  assert.deepEqual(settled, [true]);
});

test('credits the store refuses are settled by what it says, and a device without credits sends nothing', async (t) => {
  const { sendWithAttachments } = await import('./network.ts');
  const settled: (boolean | undefined)[] = [];
  let balance = 2;
  setCreditSource({ balance: async () => balance, take: async () => ({
    tokens: new Uint8Array(354 * 2), settle: async (spent) => { settled.push(spent); },
  }) });
  meshMocks.attachment_prepare_export = async () => vectors(writeU32(8), Uint8Array.of(1), new Uint8Array(32), new Uint8Array(32),
    utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'), writeU32(640));
  let status = 409;
  const fetched = t.mock.method(globalThis, 'fetch', async () => new Response(null, { status }));
  const video = () => largeFile(40_000_000, []);
  // The core already spent a token of the frame: the tokens are gone, the send stops.
  await assert.rejects(uploadAttachment('/data/attach.db', video()), /already used/);
  status = 402;
  await assert.rejects(uploadAttachment('/data/attach.db', video()), /credits/);
  status = 503;
  await assert.rejects(uploadAttachment('/data/attach.db', video()), /503/);
  assert.deepEqual(settled, [true, false, undefined]);
  balance = 1;
  fetched.mock.resetCalls();
  await assert.rejects(sendWithAttachments('/data/attach.db', [memoryAttachment('a.txt', 'text/plain', Uint8Array.of(1)), video()],
    async () => assert.fail('sent without its credits')), /needs 2 credits and you have 1/);
  assert.equal(fetched.mock.callCount(), 0);
  setCreditSource({ balance: async () => 0, take: async () => assert.fail('took credits that do not exist') });
});

// The last vector of a core request: the chunk a seal or open call carries.
const payloadOf = (request: Uint8Array): Uint8Array => {
  let offset = 0;
  let payload = new Uint8Array();
  const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
  while (offset < request.length) {
    const length = view.getUint32(offset);
    payload = request.subarray(offset + 4, offset + 4 + length);
    offset += 4 + length;
  }
  return payload;
};

const fileHash = async (path: string): Promise<string> => {
  const hash = createHash('sha256');
  for await (const piece of createReadStream(path)) hash.update(piece as Buffer);
  return hash.digest('hex');
};

// A real file on disk over 16 MiB goes up read a chunk at a time and comes back
// written a chunk at a time, byte for byte. The fake core seals a chunk as
// itself; the fake store keeps the parts.
test('a large file on disk streams up and back down in chunks, byte for byte', async (t) => {
  const directory = await mkdtemp(join(process.env.MESSENGER_LARGE_TEST_DIR ?? tmpdir(), 'morse-large-'));
  try {
    const source = join(directory, 'film.mov');
    const size = 20 * MiB + 3;
    await writeFile(source, new Uint8Array());
    for (let offset = 0; offset < size; offset += MiB) {
      await appendFile(source, new Uint8Array(Math.min(MiB, size - offset)).map((_, index) => (offset + index * 7) % 251));
    }
    const blob = await openAsBlob(source);
    let largestRead = 0;
    const file = {
      filename: 'film.mov', mimeType: 'video/quicktime', size: blob.size,
      read: async (offset: number, length: number) => {
        largestRead = Math.max(largestRead, length);
        return new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer());
      },
    };
    setCreditSource({ balance: async () => 1, take: async () => ({ tokens: new Uint8Array(354), settle: async () => {} }) });
    // 20 MiB and 3 bytes pad to 24 MiB: 384 chunks, the last 63 padding alone.
    meshMocks.attachment_prepare_export = async () => vectors(writeU32(8), Uint8Array.of(1), new Uint8Array(32).fill(7),
      new Uint8Array(32), utf8('grant'), utf8('complete'), utf8('delete'), utf8('manifest'), writeU32(384));
    meshMocks.attachment_seal_chunk_export = async (request) => payloadOf(request).slice();
    meshMocks.attachment_open_chunk_export = async (request) => payloadOf(request);
    const stored = new Map<string, Uint8Array>();
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === 'PUT') stored.set(url, new Uint8Array(init.body as ArrayBuffer));
      if ((init?.method ?? 'GET') === 'GET') return new Response(stored.get(url) as BodyInit);
      return new Response(null, { status: 201 });
    });
    const uploaded = await uploadAttachment('/data/attach.db', file);
    assert.equal(largestRead, 65_536);
    assert.equal(stored.size, 385);
    const copy = join(directory, 'copy.mov');
    await writeFile(copy, new Uint8Array());
    await streamAttachment('/data/attach.db', {
      reference: uploaded.reference, objectId: uploaded.objectId, downloadCapability: new Uint8Array(32),
      filename: 'film.mov', mimeType: 'video/quicktime', size, chunkCount: 384, chunkSize: 65_536, expiresAt: 0,
    }, (chunk) => appendFile(copy, chunk));
    assert.equal(await fileHash(copy), await fileHash(source));
  } finally {
    setCreditSource({ balance: async () => 0, take: async () => assert.fail('took credits that do not exist') });
    await rm(directory, { recursive: true, force: true });
  }
});

test('downloads fetch chunks with the download capability and reassemble the exact plaintext', async (t) => {
  const database = '/data/attach.db';
  const summary = {
    reference: Uint8Array.of(1, 65, 84, 82, 3), objectId: new Uint8Array(32).fill(8), downloadCapability: new Uint8Array(32).fill(9),
    filename: 'a.txt', mimeType: 'text/plain', size: 5, chunkCount: 2, chunkSize: 65_536, expiresAt: 1,
  };
  const opened: Uint8Array[] = [];
  // The second chunk is padding alone, so it opens to nothing but is still fetched.
  meshMocks.attachment_open_chunk_export = async (request) => {
    opened.push(request);
    return opened.length === 1 ? utf8('hello') : new Uint8Array();
  };
  const requests: { url: string; method: string; capability: string | null; body: unknown }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(input), method: init?.method ?? 'GET', capability: new Headers(init?.headers).get('X-Object-Capability'), body: init?.body });
    return new Response(utf8('sealed'));
  });
  assert.deepEqual(await downloadAttachment(database, summary), utf8('hello'));
  assert.deepEqual(opened, [
    vectors(utf8(database), summary.reference, writeU32(0), utf8('sealed')),
    vectors(utf8(database), summary.reference, writeU32(1), utf8('sealed')),
  ]);
  assert.deepEqual(requests.map((request) => request.url), [1, 2].map((part) =>
    `http://127.0.0.1:18086/v1/objects/${hexOf(summary.objectId)}/parts/${part}`));
  assert.ok(requests.every((request) => request.method === 'GET' && request.capability === hexOf(summary.downloadCapability)));
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
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(0));
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
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(0));
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
  const files = Array.from({ length: 10 }, (_, index) => memoryAttachment(`${index}.jpg`, 'image/jpeg', Uint8Array.of(index)));
  let prepared = 0;
  let failAt = 0;
  meshMocks.attachment_prepare_export = async () => {
    prepared += 1;
    if (prepared === failAt) throw new Error('upload failed');
    return vectors(writeU32(8), Uint8Array.of(prepared), new Uint8Array(32).fill(prepared), new Uint8Array(32),
      utf8('grant'), utf8('complete'), utf8(`delete-${prepared}`), utf8('manifest'), writeU32(1));
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

test('this device is erased only once the directory has let the account go', async (t) => {
  const { deleteAccount } = await import('./network.ts');
  const database = '/data/delete.db';
  const calls: string[] = [];
  let statement = Uint8Array.of(1, 65, 68, 76);
  meshMocks.account_deletion_export = async (request) => {
    assert.deepEqual(request, utf8(database));
    calls.push('sign');
    return statement;
  };
  meshMocks.erase_account_export = async (request) => {
    assert.deepEqual(request, utf8(database));
    calls.push('erase');
    return new Uint8Array();
  };
  let status = 500;
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    calls.push(`${init?.method} ${new URL(String(input)).pathname} ${hexOf(new Uint8Array(init?.body as ArrayBuffer))}`);
    return new Response(null, { status });
  });
  // Unless the directory says the account is gone, it is kept whole: its key is
  // still here to try again with. A 404 is a directory without this route.
  for (const [answer, error] of [[500, /Server returned 500/], [404, /account_deletion_unsupported/]] as const) {
    calls.length = 0;
    status = answer;
    await assert.rejects(deleteAccount(database), error);
    assert.deepEqual(calls, ['sign', 'POST /v1/accounts/delete 0141444c']);
  }
  calls.length = 0;
  status = 204;
  await deleteAccount(database);
  assert.deepEqual(calls, ['sign', 'POST /v1/accounts/delete 0141444c', 'erase']);
  // A linked device holds no account key. It leaves the account on its own key
  // instead, so that no one keeps sending to a device that is gone.
  meshMocks.device_departure_export = async (request) => {
    assert.deepEqual(request, utf8(database));
    calls.push('depart');
    return Uint8Array.of(1, 68, 80, 84);
  };
  statement = new Uint8Array();
  for (const [answer, erased] of [[404, false], [204, true]] as const) {
    calls.length = 0;
    status = answer;
    if (erased) await deleteAccount(database);
    else await assert.rejects(deleteAccount(database), /account_deletion_unsupported/);
    assert.deepEqual(calls, ['sign', 'depart', 'POST /v1/devices/leave 01445054', ...(erased ? ['erase'] : [])]);
  }
});

test('a device no longer in its account hears it with signed proof, and erases only on it', async (t) => {
  const { RemovedFromAccount, forgetOnProof, registerDirectory } = await import('./network.ts');
  const statement = Uint8Array.of(1, 68, 86, 82, 9);
  meshMocks.register_request_export = async () => Uint8Array.of(1);
  t.mock.method(globalThis, 'fetch', async () => new Response(statement, { status: 410 }));
  await assert.rejects(registerDirectory('/data/left.db'),
    (error) => error instanceof RemovedFromAccount && error.message === 'removed_from_account' && hexOf(error.statement) === '014456520' + '9');
  // The core says which proof it checked: the account deleted, this device
  // removed by the account, or this device leaving on its own key.
  const forgotten: Uint8Array[] = [];
  for (const [kind, removal] of [[1, 'account-deleted'], [2, 'device-removed'], [3, 'device-left']] as const) {
    meshMocks.forget_on_proof_export = async (request) => { forgotten.push(request); return Uint8Array.of(kind); };
    assert.equal(await forgetOnProof('/data/left.db', statement), removal);
  }
  assert.deepEqual(forgotten[0], vectors(utf8('/data/left.db'), statement));
});

test('a registration the directory will never take is told apart from an outage', async (t) => {
  const { registerDirectory } = await import('./network.ts');
  meshMocks.register_request_export = async () => Uint8Array.of(1);
  let status = 409;
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status }));
  await assert.rejects(registerDirectory('/data/refused.db'), /registration_refused/);
  status = 410;
  await assert.rejects(registerDirectory('/data/refused.db'), /removed_from_account/);
  status = 503;
  await assert.rejects(registerDirectory('/data/refused.db'), /Server returned 503/);
});

test('loading the account\'s devices renews them through the directory, in order, until one is refused', async (t) => {
  const { RemovedFromAccount, loadAccountDevices } = await import('./network.ts');
  const database = '/data/renew.db';
  const profile = vectors(utf8('alice'), new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), Uint8Array.of(0));
  const deviceSet = Uint8Array.of(0xd5, 0x5e);
  meshMocks.resolve_request_export = async () => Uint8Array.of(1);
  meshMocks.verify_transparency_export = async () => deviceSet;
  meshMocks.inspect_device_set_export = async () =>
    vectors(utf8('alice'), new Uint8Array(32).fill(1), new Uint8Array(8), Uint8Array.of(0), Uint8Array.of(1), vectors(writeU32(0)));
  const renewed: Uint8Array[] = [];
  meshMocks.renew_devices_export = async (request) => {
    renewed.push(request);
    return vectors(writeU32(2), Uint8Array.of(0xa1), Uint8Array.of(0xa2));
  };
  const registered: string[] = [];
  let answers: number[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    if (path === '/v1/devices/resolve') return new Response(Uint8Array.of(1));
    registered.push(`${init?.method} ${path} ${hexOf(new Uint8Array(init?.body as ArrayBuffer))}`);
    return new Response(null, { status: answers.shift() ?? 500 });
  });
  // Each registration is the next transition of the account's device set, so
  // they go in order.
  answers = [201, 201];
  const loaded = await loadAccountDevices(database, profile);
  assert.deepEqual(loaded.wire, deviceSet);
  assert.deepEqual(renewed, [vectors(utf8(database), deviceSet)]);
  assert.deepEqual(registered, ['PUT /v1/devices/register a1', 'PUT /v1/devices/register a2']);
  // A refusal (the set moved on, or no room in the log) or an outage ends the
  // pass; the next one starts again from the set the directory shows then.
  for (const refusal of [409, 507, 503]) {
    registered.length = 0;
    answers = [refusal, 201];
    await loadAccountDevices(database, profile);
    assert.deepEqual(registered, ['PUT /v1/devices/register a1']);
  }
  // Removal comes with its proof, as on any registration.
  answers = [410];
  await assert.rejects(loadAccountDevices(database, profile), (error) => error instanceof RemovedFromAccount);
});

// What Mesh lists for one anchor: the KTS v2 query, then the anchor and view checkpoints.
const anchorRequest = (fill: number): Uint8Array => {
  const request = new Uint8Array(397).fill(fill);
  request.set([2, 75, 84, 83], 0);
  return request;
};

test('an operation that needs a group anchor proven fetches one consistency proof and retries once', async (t) => {
  const { addGroupMember } = await import('./network.ts');
  const groupId = new Uint8Array(32).fill(10);
  const request = anchorRequest(4);
  meshMocks.group_inspect_export = async () => vectors(writeU32(7), Uint8Array.of(1), groupId, u64(1n), writeU32(0), new Uint8Array(32), new Uint8Array(32), vectors(writeU32(0)));
  meshMocks.resolve_request_export = async () => Uint8Array.of(1);
  meshMocks.verify_transparency_export = async () => Uint8Array.of(21);
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  let adds = 0;
  let pending = [request];
  meshMocks.group_add_export = async () => {
    adds += 1;
    if (pending.length > 0) throw new Error('transparency_anchor_proof_needed:024b5453');
    return vectors(writeU32(0));
  };
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(pending.length), ...pending);
  const accepted: Uint8Array[] = [];
  meshMocks.transparency_anchor_proof_export = async (value) => { accepted.push(value); pending = []; return new Uint8Array(32); };
  const posted: { url: string; body: Uint8Array }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/v1/transparency/consistency')) {
      posted.push({ url, body: new Uint8Array(init?.body as ArrayBuffer) });
      return new Response(Uint8Array.of(2, 75, 84, 67));
    }
    return new Response(Uint8Array.of(1));
  });
  await addGroupMember('/anchor.db', groupId, 'bob', new Uint8Array(369));
  assert.equal(adds, 2);
  assert.deepEqual(posted, [{ url: 'http://127.0.0.1:18086/v1/transparency/consistency', body: request.subarray(0, 21) }]);
  assert.deepEqual(accepted, [vectors(utf8('/anchor.db'), request, Uint8Array.of(2, 75, 84, 67))]);

  // A proof Mesh refuses is not retried around, and nothing else is fetched.
  pending = [request];
  adds = 0;
  meshMocks.transparency_anchor_proof_export = async () => { throw new Error('transparency_anchor_proof_invalid'); };
  await assert.rejects(addGroupMember('/anchor.db', groupId, 'bob', new Uint8Array(369)), /transparency_anchor_proof_invalid/);
  assert.equal(adds, 1);
  assert.equal(posted.length, 2);
});

test('a welcome that waits on an unproven group anchor is taken after the proof arrives', async (t) => {
  const { synchronizeMailbox } = await import('./network.ts');
  const request = anchorRequest(5);
  let pending = [request];
  let passes = 0;
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  meshMocks.mailbox_fetch_export = async () => Uint8Array.of(1);
  const acknowledged = new Uint8Array(125);
  acknowledged[44] = 1;
  // Until the anchor is proven the welcome is set aside; afterwards Mesh takes it.
  meshMocks.process_delivery_batch_export = async () => { passes += 1; return pending.length > 0 ? new Uint8Array() : acknowledged; };
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(pending.length), ...pending);
  meshMocks.transparency_anchor_proof_export = async () => { pending = []; return new Uint8Array(32); };
  let delivered = false;
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith('/v1/transparency/consistency')) return new Response(Uint8Array.of(2, 75, 84, 67));
    if (url.endsWith('/v1/mailbox/fetch')) {
      const count = pending.length > 0 || !delivered ? 1 : 0;
      if (pending.length === 0) delivered = true;
      return new Response(Uint8Array.of(1, 66, 65, 84, count));
    }
    return new Response();
  });
  await synchronizeMailbox('/data/welcome.db');
  assert.equal(pending.length, 0);
  assert.ok(passes >= 2);
});

test('an account that changed while this device was away is reported once and looked up again', async (t) => {
  const { onAccountChangedWhileAway, resolveDeviceSet } = await import('./network.ts');
  let lookups = 0;
  let verified = 0;
  let reports = 0;
  const stop = onAccountChangedWhileAway(() => { reports += 1; });
  meshMocks.resolve_request_export = async () => { lookups += 1; return Uint8Array.of(1); };
  meshMocks.verify_transparency_export = async () => {
    verified += 1;
    if (verified === 1) throw new Error('account_changed_while_away');
    return Uint8Array.of(42);
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));
  assert.deepEqual(await resolveDeviceSet('/away.db', 'alice'), Uint8Array.of(42));
  assert.equal(reports, 1);
  assert.equal(lookups, 2);
  stop();
});

test('the network status comes from the core, with the pinned witnesses and their labels', async () => {
  const { loadNetworkStatus } = await import('./network.ts');
  const witness = (id: string): Uint8Array => concatBytes(vector(utf8(id)), vector(utf8('Morse')), Uint8Array.of(1));
  meshMocks.network_status_export = async (request) => {
    assert.deepEqual(request, utf8('/status.db'));
    return concatBytes(
      Uint8Array.of(1), utf8('NST'), vector(utf8('bootstrap')), Uint8Array.of(2, 2, 2), new Uint8Array(32),
      witness('witness-a'), witness('witness-b'), Uint8Array.of(0),
    );
  };
  const status = await loadNetworkStatus('/status.db');
  assert.equal(status.profile, 'bootstrap');
  assert.deepEqual(status.witnesses.map((pinned) => pinned.id), ['witness-a', 'witness-b']);
});

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

test('the public-record check carries Mesh\'s requests and hands every exchange back', async (t) => {
  const database = '/data/anchor.db';
  const request = (kind: number, tag: string, target: string, body: string): Uint8Array =>
    concatBytes(Uint8Array.of(kind), vector(utf8(tag)), vector(utf8(target)), vector(utf8(body)));
  const step = (done: boolean, requests: Uint8Array[]): Uint8Array =>
    concatBytes(Uint8Array.of(1), utf8('ACS'), Uint8Array.of(done ? 1 : 0, 0, requests.length), ...requests.map(vector));
  const asked = [
    request(1, 'log', 'https://rpc-1.test/v1', '{"method":"getAccountInfo"}'),
    request(2, 'consistency', '/v1/transparency/consistency', 'KTS'),
    request(3, 'relay:ab:https://relay-a.test', 'https://relay-a.test/v1/fork-evidence', 'FRK'),
    request(4, 'finder:0', '', ''),
  ];
  const calls: Uint8Array[] = [];
  meshMocks.anchor_check_export = async (input) => {
    calls.push(input);
    return calls.length === 1 ? step(false, asked) : step(true, []);
  };
  const seen: { url: string; type: string | null; body: string }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    seen.push({
      url: String(input),
      type: new Headers(init?.headers).get('Content-Type'),
      body: new TextDecoder().decode(new Uint8Array(init?.body as ArrayBuffer)),
    });
    if (String(input).includes('relay-a')) throw new TypeError('fetch failed');
    return new Response(utf8(String(input).includes('rpc-1') ? 'answer-1' : 'answer-2'), { status: 200 });
  });
  await checkPublicRecord(database);
  // RPC reads go straight to the pinned provider as JSON; the directory gets
  // its own path on the messenger service; relays get the FRK. They run at once.
  seen.sort((left, right) => left.url.localeCompare(right.url));
  assert.deepEqual(seen, [
    { url: 'http://127.0.0.1:18086/v1/transparency/consistency', type: 'application/octet-stream', body: 'KTS' },
    { url: 'https://relay-a.test/v1/fork-evidence', type: 'application/octet-stream', body: 'FRK' },
    { url: 'https://rpc-1.test/v1', type: 'application/json', body: '{"method":"getAccountInfo"}' },
  ]);
  const exchange = (index: number, status: number, body: Uint8Array): Uint8Array =>
    concatBytes(vector(asked[index]!), Uint8Array.of(status >> 8, status & 255), vector(body));
  assert.deepEqual(calls, [
    vectors(utf8(database), Uint8Array.of(0, 0)),
    vectors(utf8(database), concatBytes(
      Uint8Array.of(0, 4),
      exchange(0, 200, utf8('answer-1')),
      exchange(1, 200, utf8('answer-2')),
      // A relay that did not answer is status 0; no bounty address is named yet.
      exchange(2, 0, new Uint8Array()),
      exchange(3, 200, new Uint8Array()),
    )),
  ]);
});

test('checkpoint gossip carries Mesh\'s steps, and a contact fork makes the phone check the public record', async (t) => {
  const { exchangeCheckpoints, onPublicRecordChecked } = await import('./network.ts');
  const database = '/data/gossip.db';
  const request = (kind: number, tag: string, target: string, body: string): Uint8Array =>
    concatBytes(Uint8Array.of(kind), vector(utf8(tag)), vector(utf8(target)), vector(utf8(body)));
  const step = (done: boolean, requests: Uint8Array[]): Uint8Array =>
    concatBytes(Uint8Array.of(1), utf8('ACS'), Uint8Array.of(done ? 1 : 0, 0, requests.length), ...requests.map(vector));
  const u64 = (value: number): Uint8Array => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value)); return out; };
  const section = (tag: number, body: Uint8Array): Uint8Array => concatBytes(Uint8Array.of(0, tag), vector(body));
  // Checked OK two hours ago; a contact fork is raised.
  const anchor = concatBytes(Uint8Array.of(1), u64(Date.now() - 7_200_000), u64(0), u64(0), u64(0));
  meshMocks.network_status_export = async () => concatBytes(
    Uint8Array.of(1), utf8('NST'), vector(utf8('bootstrap')), Uint8Array.of(1, 1, 1), new Uint8Array(32),
    vector(utf8('witness-a')), vector(utf8('Morse')), Uint8Array.of(1),
    Uint8Array.of(2), section(2, anchor), section(4, concatBytes(Uint8Array.of(3), u64(Date.now()))),
  );
  const gossip: Uint8Array[] = [];
  meshMocks.gossip_check_export = async (input) => {
    gossip.push(input);
    return gossip.length === 1 ? step(false, [request(2, 'gossip-consistency:ab:1:2', '/v1/transparency/consistency', 'KTS')]) : step(true, []);
  };
  let anchorRuns = 0;
  meshMocks.anchor_check_export = async () => { anchorRuns += 1; return step(true, []); };
  const seen: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    seen.push(String(input));
    return new Response(utf8('KTC'), { status: 200 });
  });
  let reloads = 0;
  const stop = onPublicRecordChecked(() => { reloads += 1; });
  await exchangeCheckpoints(database);
  stop();
  assert.deepEqual(seen, ['http://127.0.0.1:18086/v1/transparency/consistency']);
  assert.equal(gossip.length, 2);
  assert.deepEqual(gossip[0], vectors(utf8(database), Uint8Array.of(0, 0)));
  // The banners reloaded, and the public-record check ran to tell which phone was targeted.
  assert.ok(reloads >= 1);
  assert.equal(anchorRuns, 1);
});

// Credits (credits.ts installs the hooks; network.ts carries the requests).

test('a priced inbox\'s 402 is paid with credits, or the envelope is given up when the person says no', async (t) => {
  const { setCreditHooks } = await import('./network.ts');
  const policies: string[] = [];
  let answer: 'paid' | 'declined' | 'waiting' = 'paid';
  setCreditHooks({ postage: async (_path, _envelope, policy) => { policies.push(new TextDecoder().decode(policy)); return answer; } });
  t.after(() => setCreditHooks({ postage: async () => 'waiting' }));
  const priced = [queuedEnvelope(7, inThirtyDays(), 1), queuedEnvelope(8, inThirtyDays(), 2)];
  const paid = outboxFixture(t, priced, (id) => (id === 7 ? 402 : 202));
  await drainOutbox('/data/outbox-postage.db');
  assert.deepEqual(paid.submitted, [7, 8]);
  assert.equal(priced.length, 0);
  assert.deepEqual(paid.refused, []);
  t.mock.restoreAll();
  answer = 'declined';
  const declined = [queuedEnvelope(7, inThirtyDays(), 1)];
  const refused = outboxFixture(t, declined, () => 402);
  await drainOutbox('/data/outbox-postage-declined.db');
  assert.deepEqual(refused.refused, [7]);
  assert.equal(refused.reports[0]!.status, 402);
  t.mock.restoreAll();
  // Nobody to ask (a background pass): it waits, like a full mailbox.
  answer = 'waiting';
  const waiting = [queuedEnvelope(7, inThirtyDays(), 1)];
  outboxFixture(t, waiting, () => 402);
  await assert.rejects(drainOutbox('/data/outbox-postage-waiting.db'), /recipient_unavailable/);
  assert.equal(waiting.length, 1);
  assert.equal(policies.length, 3);
});

test('a busy sign-up is worked past at the difficulty the directory names, or skipped with credits', async (t) => {
  const { registerDirectory, setCreditHooks } = await import('./network.ts');
  meshMocks.register_request_export = async () => Uint8Array.of(1);
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(2);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  const asked: number[] = [];
  meshMocks.credits_register_at_export = async (request) => { asked.push(request[request.length - 1]!); return Uint8Array.of(3); };
  const sent: number[] = [];
  const work = Uint8Array.of(1, 0x57, 0x52, 0x4b, 14, 20);
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    if (!String(input).endsWith('/v1/devices/register')) return new Response(writeU32(64), { status: 200 });
    const body = new Uint8Array(init?.body as ArrayBuffer)[0]!;
    sent.push(body);
    return body === 1 ? new Response(work, { status: 429 }) : new Response(null, { status: 201 });
  });
  await registerDirectory('/data/busy.db');
  assert.deepEqual(asked, [14]);
  assert.deepEqual(sent, [1, 3]);
  const settled: number[] = [];
  setCreditHooks({ busySignup: async () => ({ body: Uint8Array.of(4), settle: async (status) => { settled.push(status); } }) });
  t.after(() => setCreditHooks({
    busySignup: async (path, answer) => ({ body: await meshMocks.credits_register_at_export(vectors(utf8(path), answer.subarray(4, 5))) }),
  }));
  await registerDirectory('/data/busy.db');
  assert.deepEqual(sent, [1, 3, 1, 4]);
  assert.deepEqual(settled, [201]);
});

test('a first message to devices that ask a price is sent only once the person agrees', async (t) => {
  const { setCreditHooks } = await import('./network.ts');
  const priced = Uint8Array.of(1, ...new Uint8Array(32).fill(9), 5);
  const quotes: Uint8Array[] = [];
  meshMocks.credits_postage_quote_export = async (request) => { quotes.push(request); return priced; };
  t.after(() => { meshMocks.credits_postage_quote_export = async () => Uint8Array.of(0); });
  const prompts: string[] = [];
  let agree = false;
  setCreditHooks({ firstContact: async (_path, username, quote) => { prompts.push(`${username}:${quote[33]}`); return agree; } });
  t.after(() => setCreditHooks({ firstContact: async () => true }));
  const sends: Uint8Array[] = [];
  installFanoutMocks([], sends);
  t.mock.method(globalThis, 'fetch', async () => new Response(Uint8Array.of(1)));
  await assert.rejects(sendFanout('/data/priced.db', 'bob', 'hello'), /postage_declined/);
  assert.equal(sends.length, 0);
  agree = true;
  await sendFanout('/data/priced.db', 'bob', 'hello');
  assert.equal(sends.length, 1);
  assert.deepEqual(prompts, ['bob:5', 'bob:5']);
  assert.equal(quotes.length, 2);
});

// §22 M3 (protocol/ohttp-v1.md): Mesh seals each stateless request to the
// gateway key the build pins; this code only carries the sealed bytes to the
// pinned relay and back.
const opened = (status: number, body: Uint8Array): Uint8Array => {
  const output = new Uint8Array(2 + body.length);
  output.set([status >> 8, status & 255]);
  output.set(body, 2);
  return output;
};

test('a lookup goes sealed through the pinned relay, and only a development build without a pin sends it directly', async (t) => {
  const { resolveDeviceSet } = await import('./network.ts');
  const sealed: Uint8Array[] = [];
  meshMocks.resolve_request_export = async () => utf8('stamped-lookup');
  meshMocks.oblivious_encapsulate_export = async (request) => {
    sealed.push(request);
    return vectors(utf8('https://edge.example'), utf8('encapsulated'), utf8('sealed-key'));
  };
  let answer = opened(200, utf8('evidence'));
  meshMocks.oblivious_decapsulate_export = async (request) => {
    assert.deepEqual(request, vectors(utf8('sealed-key'), utf8('encapsulated-answer')));
    return answer;
  };
  meshMocks.verify_transparency_export = async (request) => {
    assert.ok(new TextDecoder().decode(request).endsWith('evidence'));
    return Uint8Array.of(9);
  };
  const posted: { url: string; type: string | null; body: string }[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    posted.push({ url: String(input), type: new Headers(init?.headers).get('Content-Type'),
      body: new TextDecoder().decode(new Uint8Array(init?.body as ArrayBuffer)) });
    return new Response(utf8('encapsulated-answer'));
  });
  t.after(() => { meshMocks.oblivious_encapsulate_export = unpinned; development(true); });
  assert.deepEqual(await resolveDeviceSet('/data/ohttp.db', 'alice'), Uint8Array.of(9));
  assert.deepEqual(sealed, [vectors(utf8('POST'), utf8('/v1/devices/resolve'), utf8('stamped-lookup'))]);
  assert.deepEqual(posted, [{ url: 'https://edge.example/v1/ohttp', type: 'message/ohttp-req', body: 'encapsulated' }]);
  // The directory's own refusal comes back inside the sealed answer.
  answer = opened(429, new Uint8Array());
  await assert.rejects(resolveDeviceSet('/data/ohttp.db', 'alice'), /Server returned 429/);
  // A relay that answers anything but a sealed answer is an outage.
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 422 }));
  await assert.rejects(resolveDeviceSet('/data/ohttp.db', 'alice'), /Server returned 422/);
  // A release build that pins no gateway refuses rather than go direct.
  meshMocks.oblivious_encapsulate_export = unpinned;
  development(false);
  await assert.rejects(resolveDeviceSet('/data/ohttp.db', 'alice'), /oblivious_http_unconfigured/);
});

test('the signed mailbox fetch and acknowledgement and the anchor proofs take the relay too', async (t) => {
  const { synchronizeMailbox, supplyAnchorProofs } = await import('./network.ts');
  const paths: string[] = [];
  meshMocks.oblivious_encapsulate_export = async (request) => {
    const method = new TextDecoder().decode(request.subarray(4, 4 + new DataView(request.buffer, request.byteOffset).getUint32(0)));
    const rest = request.subarray(4 + method.length);
    const path = new TextDecoder().decode(rest.subarray(4, 4 + new DataView(rest.buffer, rest.byteOffset).getUint32(0)));
    paths.push(`${method} ${path}`);
    return vectors(utf8('https://edge.example'), utf8(path), utf8('key'));
  };
  meshMocks.oblivious_decapsulate_export = async (request) => {
    const answered = new TextDecoder().decode(request).endsWith('/v1/mailbox/fetch');
    return opened(200, answered ? Uint8Array.of(1, 66, 65, 84, 0) : new Uint8Array());
  };
  const acknowledged = new Uint8Array(125);
  meshMocks.mailbox_fetch_export = async () => Uint8Array.of(1);
  meshMocks.process_delivery_batch_export = async () => acknowledged;
  meshMocks.outbox_page_export = async () => vectors(writeU32(0));
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(0));
  meshMocks.gossip_check_export = async () => Uint8Array.of(1, 0, 0, 0, 0);
  const urls: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    urls.push(String(input));
    // What the relay forwards back is the sealed answer to the path above.
    return new Response(new Uint8Array(init?.body as ArrayBuffer));
  });
  t.after(() => { meshMocks.oblivious_encapsulate_export = unpinned; });
  await synchronizeMailbox('/data/ohttp-mailbox.db').catch(() => {});
  assert.ok(paths.includes('POST /v1/mailbox/fetch'));
  assert.ok(paths.includes('POST /v1/mailbox/ack'));
  assert.ok(!urls.some((url) => url.endsWith('/v1/mailbox/fetch') || url.endsWith('/v1/mailbox/ack')));
  // Publishing prekeys is signed but not stateless: it stays direct.
  assert.ok(urls.some((url) => url.endsWith('/v1/prekeys/one-time/batch')));

  paths.length = 0;
  const request = new Uint8Array(397);
  request.set(utf8('\x02KTS'));
  meshMocks.transparency_anchor_requests_export = async () => vectors(writeU32(1), request);
  meshMocks.transparency_anchor_proof_export = async () => new Uint8Array();
  assert.equal(await supplyAnchorProofs('/data/ohttp-mailbox.db'), 1);
  assert.deepEqual(paths, ['POST /v1/transparency/consistency']);
});
