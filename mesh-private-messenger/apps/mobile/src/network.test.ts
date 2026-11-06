import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';

import { utf8, vectors, writeU32 } from './codec.ts';

test('group package transport accepts both wire versions and rejects other lengths', async () => {
  const { getGroupKeyPackage } = await scopedNetwork();
  for (const length of [369, 401]) {
    meshMocks.group_key_package_export = async () => new Uint8Array(length);
    assert.equal((await getGroupKeyPackage('test.db')).length, length);
  }
  for (const length of [368, 370, 400, 402]) {
    meshMocks.group_key_package_export = async () => new Uint8Array(length);
    await assert.rejects(() => getGroupKeyPackage('test.db'), /invalid group key package/);
  }
});

type MeshExport = (request: Uint8Array) => Promise<Uint8Array>;
const unexpectedNative = (name: string): MeshExport => async () => { throw new Error(`Unexpected Mesh call: ${name}`); };
const meshMocks = {
  fanout_send_export: unexpectedNative('fanout_send_export'),
  account_deletion_export: unexpectedNative('account_deletion_export'),
  account_delete_export: unexpectedNative('account_delete_export'),
  account_discard_export: unexpectedNative('account_discard_export'),
  account_capabilities_export: unexpectedNative('account_capabilities_export'),
  devices_renew_export: unexpectedNative('devices_renew_export'),
  device_revoke_export: unexpectedNative('device_revoke_export'),
  attachment_open_chunk_export: unexpectedNative('attachment_open_chunk_export'),
  attachment_fetch_chunk_export: unexpectedNative('attachment_fetch_chunk_export'),
  attachment_upload_export: unexpectedNative('attachment_upload_export'),
  attachment_discard_export: unexpectedNative('attachment_discard_export'),
  attachment_prepare_export: unexpectedNative('attachment_prepare_export'),
  attachment_seal_chunk_export: unexpectedNative('attachment_seal_chunk_export'),
  authorize_device_link_for_set_export: unexpectedNative('authorize_device_link_for_set_export'),
  create_device_revocation_export: unexpectedNative('create_device_revocation_export'),
  device_departure_export: unexpectedNative('device_departure_export'),
  erase_account_export: unexpectedNative('erase_account_export'),
  forget_on_proof_export: unexpectedNative('forget_on_proof_export'),
  directory_register_export: unexpectedNative('directory_register_export'),
  directory_resolve_export: unexpectedNative('directory_resolve_export'),
  prekeys_synchronize_export: unexpectedNative('prekeys_synchronize_export'),
  register_request_export: unexpectedNative('register_request_export'),
  register_signup_policy_export: unexpectedNative('register_signup_policy_export'),
  credit_discovery_export: unexpectedNative('credit_discovery_export'),
  credit_discover_online_export: unexpectedNative('credit_discover_online_export'),
  credit_purchase_continue_export: unexpectedNative('credit_purchase_continue_export'),
  credit_action_continue_export: unexpectedNative('credit_action_continue_export'),
  credit_signup_policy_online_export: unexpectedNative('credit_signup_policy_online_export'),
  credit_admit_export: unexpectedNative('credit_admit_export'),
  credit_prepare_export: unexpectedNative('credit_prepare_export'),
  credit_prepare_again_export: unexpectedNative('credit_prepare_again_export'),
  credit_quote_export: unexpectedNative('credit_quote_export'),
  credit_payment_export: unexpectedNative('credit_payment_export'),
  credit_finalize_export: unexpectedNative('credit_finalize_export'),
  credit_recover_export: unexpectedNative('credit_recover_export'),
  credit_purchases_export: unexpectedNative('credit_purchases_export'),
  credit_balance_export: unexpectedNative('credit_balance_export'),
  credit_reserve_export: unexpectedNative('credit_reserve_export'),
  credit_postage_prepare_export: unexpectedNative('credit_postage_prepare_export'),
  credit_reservation_export: unexpectedNative('credit_reservation_export'),
  credit_retention_export: unexpectedNative('credit_retention_export'),
  credit_retention_recover_export: unexpectedNative('credit_retention_recover_export'),
  credit_receipt_export: unexpectedNative('credit_receipt_export'),
  credit_payment_url_export: unexpectedNative('credit_payment_url_export'),
  credit_payment_signature_export: unexpectedNative('credit_payment_signature_export'),
  credit_signup_policy_export: unexpectedNative('credit_signup_policy_export'),
  credit_signup_policy_view_export: unexpectedNative('credit_signup_policy_view_export'),
  credit_signup_export: unexpectedNative('credit_signup_export'),
  credit_signup_recover_export: unexpectedNative('credit_signup_recover_export'),
  credit_action_recovery_export: unexpectedNative('credit_action_recovery_export'),
  create_signup_draft_export: unexpectedNative('create_signup_draft_export'),
  signup_draft_state_export: unexpectedNative('signup_draft_state_export'),
  signup_draft_rename_export: unexpectedNative('signup_draft_rename_export'),
  signup_draft_free_export: unexpectedNative('signup_draft_free_export'),
  signup_draft_free_complete_export: unexpectedNative('signup_draft_free_complete_export'),
  renew_devices_export: unexpectedNative('renew_devices_export'),
  group_add_export: unexpectedNative('group_add_export'),
  group_create_export: unexpectedNative('group_create_export'),
  group_forget_export: unexpectedNative('group_forget_export'),
  group_history_export: unexpectedNative('group_history_export'),
  group_policy_export: unexpectedNative('group_policy_export'),
  group_inspect_export: unexpectedNative('group_inspect_export'),
  group_key_package_export: unexpectedNative('group_key_package_export'),
  group_invite_export: unexpectedNative('group_invite_export'),
  group_invitation_accept_export: unexpectedNative('group_invitation_accept_export'),
  group_invitation_complete_export: unexpectedNative('group_invitation_complete_export'),
  group_invitation_decline_export: unexpectedNative('group_invitation_decline_export'),
  group_invitations_export: unexpectedNative('group_invitations_export'),
  group_list_export: unexpectedNative('group_list_export'),
  group_remove_export: unexpectedNative('group_remove_export'),
  group_send_export: unexpectedNative('group_send_export'),
  inspect_device_set_export: unexpectedNative('inspect_device_set_export'),
  load_profile_export: unexpectedNative('load_profile_export'),
  mailbox_fetch_export: unexpectedNative('mailbox_fetch_export'),
  mailbox_synchronize_export: unexpectedNative('mailbox_synchronize_export'),
  mailbox_stream_open_export: unexpectedNative('mailbox_stream_open_export'),
  mailbox_stream_poll_export: unexpectedNative('mailbox_stream_poll_export'),
  mailbox_stream_close_export: unexpectedNative('mailbox_stream_close_export'),
  outbox_drain_export: unexpectedNative('outbox_drain_export'),
  outbox_ack_export: unexpectedNative('outbox_ack_export'),
  outbox_fail_export: unexpectedNative('outbox_fail_export'),
  outbox_list_export: unexpectedNative('outbox_list_export'),
  outbox_page_export: unexpectedNative('outbox_page_export'),
  privacy_submission_export: unexpectedNative('privacy_submission_export'),
  prepare_fanout_prekeys_export: unexpectedNative('prepare_fanout_prekeys_export'),
  process_delivery_batch_export: unexpectedNative('process_delivery_batch_export'),
  reconcile_prekeys_export: unexpectedNative('reconcile_prekeys_export'),
  replenish_prekeys_export: unexpectedNative('replenish_prekeys_export'),
  send_fanout_export: unexpectedNative('send_fanout_export'),
  resolve_request_export: unexpectedNative('resolve_request_export'),
  resolve_plan_export: unexpectedNative('resolve_plan_export'),
  verify_transparency_export: unexpectedNative('verify_transparency_export'),
};
const meshExports = Object.keys(meshMocks);
meshMocks.directory_register_export = async () => Uint8Array.of(1,68,82,71,0,64,0);
meshMocks.prekeys_synchronize_export = async () => Uint8Array.of(1,68,80,75,0,64);
meshMocks.credit_signup_policy_online_export = async () => { throw new Error('credits_disabled'); };
meshMocks.directory_resolve_export = async () => Uint8Array.of(1);
meshMocks.outbox_drain_export = async () => outboxStatus();
(globalThis as typeof globalThis & { __meshNetworkMocks: typeof meshMocks }).__meshNetworkMocks = meshMocks;

const mockModule = [
  "export const isLegacyDesktopBridge=false;",
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
    if (specifier === '../modules/mesh-messenger' && (context.parentURL?.endsWith('/network.ts') || context.parentURL?.endsWith('/credits.ts') || context.parentURL?.endsWith('/network.test.ts'))) {
      return {
        shortCircuit: true,
        url: `data:text/javascript,${encodeURIComponent(mockModule)}`,
      };
    }
    if (
      (specifier === './codec' || specifier === './single-flight' || specifier === './transport' || specifier === './credits') &&
      (context.parentURL?.endsWith('/network.ts') || context.parentURL?.endsWith('/credits.ts'))
    ) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});

const { scope } = scopeFixture();
type ScopedNetwork = typeof import('./network.ts') & ReturnType<typeof import('./network.ts').createNetworkServices>;
let scopedServices: ScopedNetwork | undefined;
async function scopedNetwork(): Promise<ScopedNetwork> {
  if (!scopedServices) {
    const module = await import('./network.ts');
    scopedServices = { ...module, ...module.createNetworkServices({ ...await import('../modules/mesh-messenger'), ...scope }) };
  }
  return scopedServices;
}

const development = (value: boolean): void => {
  (globalThis as typeof globalThis & { __DEV__: boolean }).__DEV__ = value;
};
development(true);
const {
  downloadAttachment, sendGroupMessage, sendFanout, inviteToGroup, uploadAttachment,
} = await scopedNetwork();

const attachmentRequest = (...parts: Uint8Array[]): Uint8Array => {
  const payload = vectors(...parts);
  const request = new Uint8Array(4 + payload.length);
  request.set(writeU32(parts.length)); request.set(payload, 4); return request;
};

const attachmentAuthorization = Uint8Array.of(71, 72, 73);
const hexOf = (value: Uint8Array): string => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

test('uploads pass bounded plaintext to native transport and retain only opaque discard authority', async (t) => {
  const database = '/data/attach.db';
  const reference = Uint8Array.of(1, 65, 84, 82, 9);
  const objectId = new Uint8Array(32).fill(5);
  const ticket = utf8('opaque-sealed-discard');
  const calls: Uint8Array[] = [];
  meshMocks.attachment_upload_export = async (request) => {
    calls.push(request);
    return vectors(writeU32(3), reference, objectId, ticket);
  };
  meshMocks.attachment_discard_export = async (request) => { calls.push(request); return new Uint8Array(); };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('JS attachment HTTP is forbidden'); });
  const bytes = new Uint8Array(65_546).fill(7);
  const progress: number[] = [];
  const uploaded = await uploadAttachment(database, { filename: 'a.bin', mimeType: 'application/octet-stream', bytes }, attachmentAuthorization,
    (completed) => progress.push(completed));
  assert.deepEqual(uploaded.reference, reference);
  assert.deepEqual(uploaded.objectId, objectId);
  assert.deepEqual(calls, [attachmentRequest(utf8(database), utf8('a.bin'), utf8('application/octet-stream'), bytes, attachmentAuthorization)]);
  assert.deepEqual(progress, [0, 2]);
  await uploaded.discard();
  assert.deepEqual(calls[1], attachmentRequest(utf8(database), ticket));
  await assert.rejects(uploadAttachment(database, { filename: '', mimeType: 'text/plain', bytes: new Uint8Array() }, attachmentAuthorization), /empty/);
  await assert.rejects(uploadAttachment(database, { filename: '', mimeType: 'text/plain', bytes: new Uint8Array(256 * 65_536 + 1) }, attachmentAuthorization), /16 MB/);
  assert.equal(calls.length, 2);
});

test('a native upload failure is surfaced without JS HTTP or a fabricated attachment', async (t) => {
  meshMocks.attachment_upload_export = async () => { throw new Error('attachment_http_413'); };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('JS attachment HTTP is forbidden'); });
  await assert.rejects(uploadAttachment('/data/attach.db', { filename: 'a', mimeType: 'text/plain', bytes: Uint8Array.of(1) }, attachmentAuthorization), /413/);
});

test('downloads use native authenticated chunk fetch with no JS HTTP or capability routing', async (t) => {
  const database = '/data/attach.db';
  const summary = {
    reference: Uint8Array.of(1, 65, 84, 82, 3), objectId: new Uint8Array(32).fill(8), downloadCapability: new Uint8Array(32).fill(9),
    filename: 'a.txt', mimeType: 'text/plain', size: 5, chunkCount: 1, chunkSize: 65_536, expiresAt: 1,
  };
  const fetched: Uint8Array[] = [];
  meshMocks.attachment_fetch_chunk_export = async (request) => { fetched.push(request); return utf8('hello'); };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('JavaScript download HTTP is forbidden'); });
  assert.deepEqual(await downloadAttachment(database, summary), utf8('hello'));
  assert.deepEqual(fetched, [Uint8Array.from([...writeU32(3), ...vectors(utf8(database), summary.reference, writeU32(0))])]);
  meshMocks.attachment_fetch_chunk_export = async () => utf8('hell');
  await assert.rejects(downloadAttachment(database, summary), /manifest/);
  await assert.rejects(downloadAttachment(database, { ...summary, size: 536_870_912, chunkCount: 8192 }), /range/);
});

test('push transport exposes no JavaScript wire submission helpers', async () => {
  const network = await scopedNetwork();
  assert.equal('submitPushBind' in network, false);
  assert.equal('submitPushUnbind' in network, false);
});

test('outbox transport ignores JavaScript endpoint overrides and exposes no raw wire helpers', async (t) => {
  const { drainOutbox } = await scopedNetwork();
  const previous = process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
  let calls = 0;
  t.mock.method(meshMocks,'outbox_drain_export',async (input: Uint8Array)=>{
    calls++; assert.deepEqual(input,vectors(utf8('/data/pins.db'),Uint8Array.of(0))); return outboxStatus();
  });
  t.mock.method(globalThis,'fetch',async()=>assert.fail('outbox HTTP stays in Mesh'));
  for(const legacy of ['outbox_page_export','outbox_ack_export','outbox_fail_export','privacy_submission_export'] as const) {
    t.mock.method(meshMocks,legacy,async()=>assert.fail('saved outbox authority stays in Mesh'));
  }
  try {
    for(const url of ['http://example.com','https://user:password@example.com','https://attacker.example/?token=1']) {
      process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL=url;
      await drainOutbox('/data/pins.db');
    }
    assert.equal(calls,3);
  } finally {
    if(previous === undefined) delete process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL;
    else process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL=previous;
  }
});

function outboxStatus(status=0,accepted=0,remaining=0,postage:Uint8Array[]=[],failures:{status:number;queuedAt:number}[]=[]):Uint8Array {
  const u16=(n:number)=>Uint8Array.of(n>>>8,n&255);
  const packed=(parts:Uint8Array[])=>Uint8Array.from([...writeU32(parts.length),...vectors(...parts)]);
  return packed([Uint8Array.of(1,79,66,88),Uint8Array.of(status),u16(accepted),u16(remaining),packed(postage),
    packed(failures.map(row=>Uint8Array.from([...u16(row.status),...u64(BigInt(row.queuedAt))]))) ]);
}

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

test('fanout submits only its captured local profile and intent to native and then drains', async (t) => {
  const calls: Uint8Array[] = [];
  meshMocks.fanout_send_export = async input => { calls.push(input); return Uint8Array.of(1,70,78,79,1); };
  meshMocks.outbox_drain_export = async () => outboxStatus();
  for (const name of ['load_profile_export', 'directory_resolve_export', 'inspect_device_set_export', 'prepare_fanout_prekeys_export', 'send_fanout_export'] as const) {
    meshMocks[name] = async () => assert.fail(`legacy fanout call ${name}`);
  }
  t.mock.method(globalThis, 'fetch', async () => assert.fail('fanout HTTP stays native'));
  const local = profile('local');
  assert.equal(await sendFanout('/data/mobile.db', local, 'peer', 'hello'), true);
  assert.deepEqual(calls[0], vectors(utf8('/data/mobile.db'), local, utf8('peer'), Uint8Array.of(1), utf8('hello'), new Uint8Array(), new Uint8Array()));
  await sendFanout('/data/mobile.db', local, 'peer', '', undefined, Uint8Array.of(1,65,84,82));
  assert.deepEqual(calls[1], vectors(utf8('/data/mobile.db'), local, utf8('peer'), Uint8Array.of(1), new Uint8Array(), new Uint8Array(), Uint8Array.of(1,65,84,82)));
});

test('group invitations use the same native profile-bound intent without raw device sets', async () => {
  const calls: Uint8Array[] = [];
  meshMocks.fanout_send_export = async input => { calls.push(input); return Uint8Array.of(1,70,78,79,0); };
  meshMocks.outbox_drain_export = async () => outboxStatus();
  const local = profile('local'); const id = new Uint8Array(32).fill(7);
  await inviteToGroup('/data/mobile.db', local, id, 'peer');
  assert.deepEqual(calls, [vectors(utf8('/data/mobile.db'), local, utf8('peer'), Uint8Array.of(2), id, new Uint8Array(), new Uint8Array())]);
});

test('fanout preserves native refusal and never drains after malformed status or stale account', async () => {
  let drained = 0;
  meshMocks.outbox_drain_export = async () => { drained++; return outboxStatus(); };
  for (const error of ['account_state_changed', 'fanout_contact_identity_changed', 'prekey_claim_failed']) {
    meshMocks.fanout_send_export = async () => { throw Error(error); };
    await assert.rejects(sendFanout('/data/mobile.db', profile('local'), 'peer', 'private'), new RegExp(error));
  }
  meshMocks.fanout_send_export = async () => Uint8Array.of(1,70,78,79,2);
  await assert.rejects(sendFanout('/data/mobile.db', profile('local'), 'peer', 'private'), /invalid_native_fanout_status/);
  assert.equal(drained, 0);
});

test('serialized sends freeze the initiating profile and body before waiting behind another action', async () => {
  const calls: Uint8Array[] = [];
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  let started!: () => void;
  const observed = new Promise<void>(resolve => { started = resolve; });
  meshMocks.outbox_drain_export = async () => outboxStatus();
  meshMocks.fanout_send_export = async input => {
    calls.push(input); if (calls.length === 1) { started(); await blocked; }
    return Uint8Array.of(1,70,78,79,0);
  };
  const local = profile('local');
  const copy = local.slice();
  const first = sendFanout('/data/mobile.db', local, 'peer', 'first');
  await observed;
  const second = sendFanout('/data/mobile.db', local, 'peer', 'second');
  local.fill(9);
  assert.equal(calls.length, 1);
  release(); await Promise.all([first, second]);
  assert.deepEqual(calls[1], vectors(utf8('/data/mobile.db'), copy, utf8('peer'), Uint8Array.of(1), utf8('second'), new Uint8Array(), new Uint8Array()));
});

const mailboxOutcome = (batches: number, received: number, acknowledged: number, more = false): Uint8Array => {
  const bytes = new Uint8Array(12); bytes.set([1, 77, 83, 89]);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, batches); view.setUint16(6, received); view.setUint16(8, acknowledged);
  bytes[10] = acknowledged < received ? 1 : 0; bytes[11] = more ? 1 : 0;
  return bytes;
};

function mailboxTasksWithoutJavaScriptTransport(): void {
  meshMocks.prekeys_synchronize_export = async () => Uint8Array.of(1,68,80,75,0,64);
  meshMocks.mailbox_fetch_export = async () => assert.fail('signed FET must stay inside Mesh');
  meshMocks.process_delivery_batch_export = async () => assert.fail('delivery batches must stay inside Mesh');
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(3);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.group_invitations_export = async () => vectors(writeU32(0));
}

test('one mailbox wakeup finishes bounded native passes even when outbox delivery fails', async (t) => {
  const { synchronizeMailbox } = await scopedNetwork();
  mailboxTasksWithoutJavaScriptTransport();
  meshMocks.outbox_drain_export = async () => { throw new Error('outbox unavailable'); };
  let passes = 0;
  meshMocks.mailbox_synchronize_export = async (request) => {
    assert.deepEqual(request, utf8('/data/receive.db'));
    return ++passes === 1 ? mailboxOutcome(16, 128, 128, true) : mailboxOutcome(2, 1, 1);
  };
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    assert.ok(!String(input).includes('/v1/mailbox/'), 'JavaScript must not send mailbox requests');
    return new Response();
  });
  await assert.rejects(synchronizeMailbox('/data/receive.db'), /outbox unavailable/);
  assert.equal(passes, 2);
});

test('native pending deliveries remain visible after later batches finish', async (t) => {
  const { synchronizeMailbox } = await scopedNetwork();
  mailboxTasksWithoutJavaScriptTransport();
  meshMocks.outbox_drain_export = async () => outboxStatus();
  let passes = 0;
  meshMocks.mailbox_synchronize_export = async () => ++passes === 1
    ? mailboxOutcome(16, 10, 2, true) : mailboxOutcome(1, 0, 0);
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    assert.ok(!String(input).includes('/v1/mailbox/'), 'JavaScript must not send mailbox requests');
    return new Response();
  });
  await assert.rejects(synchronizeMailbox('/data/pending.db'), /processing.*retry/i);
  assert.equal(passes, 2);
});

test('native mailbox failures propagate without a JavaScript transport fallback', async (t) => {
  const { synchronizeMailbox } = await scopedNetwork();
  mailboxTasksWithoutJavaScriptTransport();
  meshMocks.outbox_drain_export = async () => outboxStatus();
  meshMocks.mailbox_synchronize_export = async () => { throw new Error('mailbox_sync_identity_changed'); };
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
    assert.ok(!String(input).includes('/v1/mailbox/'), 'JavaScript must not send mailbox requests');
    return new Response();
  });
  await assert.rejects(synchronizeMailbox('/data/replaced.db'), /mailbox_sync_identity_changed/);
});

test('mailbox streaming uses native tickets and ignores JS endpoint/auth overrides', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const network = await scopedNetwork();
  meshMocks.directory_register_export = async () => Uint8Array.of(1,68,82,71,0,64,0);
  const previous = process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL;
  let opens = 0;
  let closes = 0;
  t.mock.method(globalThis, 'WebSocket', class {
    constructor() { assert.fail('JavaScript must not start a WebSocket'); }
  } as unknown as typeof WebSocket);
  t.mock.method(globalThis, 'fetch', async () => new Response());
  meshMocks.register_request_export = async () => Uint8Array.of(1);
  meshMocks.replenish_prekeys_export = async () => Uint8Array.of(2);
  meshMocks.reconcile_prekeys_export = async () => writeU32(64);
  meshMocks.mailbox_fetch_export = async () => assert.fail('authorization must stay inside Mesh');
  const ticket = new Uint8Array(32).fill(7);
  const session = new Uint8Array([...writeU32(2), ...vectors(utf8('/data/stream.db'), ticket)]);
  meshMocks.mailbox_stream_open_export = async (input) => {
    assert.deepEqual(input, utf8('/data/stream.db')); opens++; return ticket;
  };
  meshMocks.mailbox_stream_poll_export = async (input) => { assert.deepEqual(input, session); return utf8('ready'); };
  meshMocks.mailbox_stream_close_export = async (input) => { assert.deepEqual(input, session); closes++; return new Uint8Array(); };
  try {
    process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL = 'https://attacker.example/?auth=caller';
    const socket = await network.connectMailboxStream('/data/stream.db');
    assert.equal(opens, 1);
    socket.close();
    await Promise.resolve();
    assert.equal(closes, 1);
  } finally {
    if (previous === undefined) delete process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL;
    else process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL = previous;
  }
});

test('prekey sync sends only the native path and leaves unrelated 429 errors visible', async (t) => {
  const { synchronizePrekeys } = await scopedNetwork();
  const database = '/data/full-prekeys.db';
  let calls = 0;
  meshMocks.replenish_prekeys_export = async () => assert.fail('publication stays in Mesh');
  meshMocks.reconcile_prekeys_export = async () => assert.fail('acknowledgements stay in Mesh');
  meshMocks.prekeys_synchronize_export = async request => {
    calls++; assert.deepEqual(request, utf8(database)); return Uint8Array.of(1,68,80,75,0,64);
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 429 }));
  await synchronizePrekeys(database);
  assert.equal(calls, 1);
  t.mock.method(meshMocks, 'prekeys_synchronize_export', async () => { throw new Error('prekeys_http_429'); });
  await assert.rejects(synchronizePrekeys(database), /prekeys_http_429/);
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
  meshMocks.directory_resolve_export = async request => {
    const account = accounts[lookups++ % 2]!;
    const reference = '@' + Array.from(account, byte => byte.toString(16).padStart(2, '0')).join('');
    assert.deepEqual(request, vectors(utf8('/group-test.db'), utf8(reference)));
    verified++;
    if (reject && verified === 2) throw new Error('transparency_stale');
    return Uint8Array.of(1);
  };
  const requests: Uint8Array[] = [];
  meshMocks.group_send_export = async request => { assert.equal(verified, 2); sends++; requests.push(request); return Uint8Array.of(1); };
  meshMocks.outbox_drain_export = async () => outboxStatus();
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
  const { sendWithAttachments } = await scopedNetwork();
  const files = Array.from({ length: 10 }, (_, index) => ({ filename: `${index}.jpg`, mimeType: 'image/jpeg', bytes: Uint8Array.of(index) }));
  let prepared = 0;
  let failAt = 0;
  meshMocks.attachment_upload_export = async () => {
    prepared += 1;
    if (prepared === failAt) throw new Error('upload failed');
    return vectors(writeU32(3), Uint8Array.of(prepared), new Uint8Array(32).fill(prepared), utf8(`delete-${prepared}`));
  };
  const deleted: string[] = [];
  meshMocks.attachment_discard_export = async request => {
    const pathLength = new DataView(request.buffer, request.byteOffset, request.byteLength).getUint32(4);
    deleted.push(new TextDecoder().decode(request.subarray(12 + pathLength)));
    return new Uint8Array();
  };
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('JS attachment HTTP is forbidden'); });
  const sent: Uint8Array[] = [];
  const uploaded = await sendWithAttachments('/data/attach.db', files, attachmentAuthorization, async (reference) => { sent.push(reference!); });
  assert.equal(uploaded.length, 10);
  assert.deepEqual(sent, [new Uint8Array([1, 65, 84, 66, ...writeU32(10), ...vectors(...uploaded.map((file) => file.reference))])]);
  prepared = 0;
  failAt = 3;
  await assert.rejects(sendWithAttachments('/data/attach.db', files, attachmentAuthorization, async () => assert.fail('sent incomplete album')), /upload failed/);
  assert.deepEqual(deleted.sort(), ['delete-1', 'delete-2']);
  prepared = 0;
  failAt = 0;
  deleted.length = 0;
  await assert.rejects(sendWithAttachments('/data/attach.db', files, attachmentAuthorization, async () => { throw new Error('delivery failed'); }), /delivery failed/);
  assert.deepEqual(deleted, []); // Native send may already have committed the message to its durable outbox.
  prepared = 0;
  await assert.rejects(sendWithAttachments('/data/attach.db', [...files, files[0]!], attachmentAuthorization, async () => assert.fail()), /up to 10/);
  assert.equal(prepared, 0);
});

// Service policy and saved-frame ordering are proved by the owned native peer
// suite. These tests exercise only the typed UI route, presentation and retries.
const { drainOutbox, onUndeliverable } = await scopedNetwork();

test('native permanent-refusal reports are presented without JS settlement authority',async t=>{
  const reports:{status:number;queuedAt:number}[]=[];
  const first=onUndeliverable(()=>{throw Error('listener failure');});
  const second=onUndeliverable(value=>reports.push(value));t.after(first);t.after(second);
  t.mock.method(globalThis,'fetch',async()=>assert.fail('outbox HTTP stays native'));
  t.mock.method(meshMocks,'outbox_drain_export',async()=>outboxStatus(0,1,0,[],[{status:400,queuedAt:1700000000000},{status:410,queuedAt:1700000001000}]));
  t.mock.method(meshMocks,'outbox_fail_export',async()=>assert.fail('native already settled this failure'));
  await drainOutbox('/data/refused.db');
  assert.deepEqual(reports,[{status:400,queuedAt:1700000000000},{status:410,queuedAt:1700000001000}]);
});

test('native postage triggers never reserve credits and survive later unknown outcomes',async t=>{
  const { PostageRequired,onPostageRequired }=await scopedNetwork();
  const ids=[new Uint8Array(16).fill(7),new Uint8Array(16).fill(8)];
  const reports:Uint8Array[]=[];let calls=0;
  const unsubscribe=onPostageRequired(value=>reports.push(value.triggerId));t.after(unsubscribe);
  t.mock.method(globalThis,'fetch',async()=>assert.fail('outbox HTTP stays native'));
  t.mock.method(meshMocks,'credit_postage_prepare_export',async()=>assert.fail('402 never spends credits'));
  t.mock.method(meshMocks,'outbox_drain_export',async()=>{calls++;return outboxStatus(2,1,2,ids);});
  for(let attempt=0;attempt<2;attempt++) {
    await assert.rejects(drainOutbox('/data/postage.db'),error=>error instanceof PostageRequired && error.triggerIds.length===2);
  }
  assert.equal(calls,2);assert.deepEqual(reports,[...ids,...ids]);
});

test('unknown or bounded native progress preserves pending mail without a JS fallback',async t=>{
  t.mock.method(globalThis,'fetch',async()=>assert.fail('outbox HTTP stays native'));
  for(const [status,error] of [[1,/recipient_unavailable/],[2,/outbox_transport_unavailable/],[3,/outbox_transport_budget_exhausted/]] as const) {
    let calls=0;
    t.mock.method(meshMocks,'outbox_drain_export',async()=>{calls++;return outboxStatus(status,0,2);});
    await assert.rejects(drainOutbox('/data/pending-'+status+'.db'),error);
    assert.equal(calls,1);
  }
});

test('explicit free retry waits for an in-flight pass and is never coalesced away',async t=>{
  const { retryFreePostage,PostageRequired }=await scopedNetwork();
  let release=()=>{};let observed=()=>{};
  const held=new Promise<void>(resolve=>{release=resolve;});
  const started=new Promise<void>(resolve=>{observed=resolve;});
  const calls:Uint8Array[]=[];
  t.mock.method(meshMocks,'outbox_drain_export',async (input: Uint8Array)=>{
    calls.push(input);
    if(calls.length===1){observed();await held;return outboxStatus(0,0,1,[new Uint8Array(16).fill(7)]);}
    return outboxStatus(0,1);
  });
  t.mock.method(globalThis,'fetch',async()=>assert.fail('outbox HTTP stays native'));
  const ordinary=drainOutbox('/data/free-retry.db');
  const ordinaryRejected=assert.rejects(ordinary,PostageRequired);
  await started;
  const joined = drainOutbox('/data/free-retry.db');
  const joinedRejected = assert.rejects(joined, PostageRequired);
  const retry=retryFreePostage('/data/free-retry.db');
  await Promise.resolve();assert.equal(calls.length,1);
  release();await ordinaryRejected;await joinedRejected;await retry;
  assert.deepEqual(calls,[vectors(utf8('/data/free-retry.db'),Uint8Array.of(0)),vectors(utf8('/data/free-retry.db'),Uint8Array.of(1))]);
});

test('the scoped outbox refuses a coalesced call and a late result after native revocation', async t => {
  const fixture = scopeFixture();
  t.after(() => fixture.scope.dispose());
  const module = await import('./network.ts');
  const client = module.createNetworkServices({ ...await import('../modules/mesh-messenger'), ...fixture.scope });
  let release!: () => void;
  let entered!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  let calls = 0;
  t.mock.method(meshMocks, 'outbox_drain_export', async () => {
    calls++; entered(); await held; return outboxStatus();
  });
  const pending = client.drainOutbox('/data/revoked-outbox.db');
  const refused = assert.rejects(pending, /stale_epoch/);
  await started;
  fixture.revoke();
  await assert.rejects(client.drainOutbox('/data/revoked-outbox.db'), /stale_epoch/);
  release(); await refused;
  assert.equal(calls, 1);
});

test('malformed native progress is never reported as settled or paid',async t=>{
  const reports:unknown[]=[];const unsubscribe=onUndeliverable(value=>reports.push(value));t.after(unsubscribe);
  t.mock.method(meshMocks,'outbox_drain_export',async()=>Uint8Array.of(0));
  await assert.rejects(drainOutbox('/data/malformed.db'),/invalid_outbox_status/);
  assert.deepEqual(reports,[]);
});

test('resolution delegates admission and witness waiting to one native operation', async t => {
  const { resolveDeviceSet } = await scopedNetwork();
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => assert.fail('resolution HTTP stays in Mesh'));
  t.mock.method(meshMocks, 'resolve_plan_export', async () => assert.fail('plans stay in Mesh'));
  t.mock.method(meshMocks, 'verify_transparency_export', async () => assert.fail('verification stays in Mesh'));
  t.mock.method(meshMocks, 'directory_resolve_export', async (input: Uint8Array) => {
    calls++; assert.deepEqual(input, vectors(utf8('/data/lookup.db'),utf8('alice'))); return Uint8Array.of(9);
  });
  assert.deepEqual(await resolveDeviceSet('/data/lookup.db','alice'),Uint8Array.of(9));
  assert.equal(calls,1);
});

test('account actions carry the captured public profile and never sign, fetch or erase in JS', async t => {
  const { deleteAccount, discardAccount, holdsAccountKey } = await scopedNetwork();
  const database = '/data/delete.db';
  const profile = Uint8Array.of(9,8,7);
  const calls: string[] = [];
  t.mock.method(globalThis,'fetch',async () => assert.fail('account HTTP stays in Mesh'));
  for (const name of ['account_deletion_export','device_departure_export','erase_account_export','forget_on_proof_export'] as const) {
    t.mock.method(meshMocks,name,async () => assert.fail('legacy account authority stays private'));
  }
  meshMocks.account_capabilities_export = async input => {
    assert.deepEqual(input,vectors(utf8(database),profile)); calls.push('capabilities'); return Uint8Array.of(1,65,67,80,1);
  };
  meshMocks.account_discard_export = async input => {
    assert.deepEqual(input,vectors(utf8(database),profile)); calls.push('discard'); return Uint8Array.of(1,65,68,83,1);
  };
  meshMocks.account_delete_export = async input => {
    assert.deepEqual(input,vectors(utf8(database),profile)); calls.push('delete'); return Uint8Array.of(1,65,68,78,1);
  };
  assert.equal(await holdsAccountKey(database,profile),true);
  await deleteAccount(database,profile);
  await discardAccount(database,profile);
  assert.deepEqual(calls,['capabilities','delete','discard']);
  for (const reason of ['account_state_changed','account_deletion_unsupported','account_deletion_refused','account_http_500','account_transport_unavailable']) {
    meshMocks.account_delete_export = async () => { throw Error(reason); };
    await assert.rejects(deleteAccount(database,profile),new RegExp(reason));
  }
});

test('directory and device removal expose only a verified native kind', async t => {
  const { VerifiedDirectoryRemoval, registerDirectory, renewDevices } = await scopedNetwork();
  t.mock.method(globalThis,'fetch',async () => assert.fail('removal authority stays in Mesh'));
  for (const [kind,removal] of [[1,'account-deleted'],[2,'device-removed'],[3,'device-left']] as const) {
    meshMocks.directory_register_export = async () => Uint8Array.of(1,68,82,71,0,0,kind);
    meshMocks.devices_renew_export = async () => Uint8Array.of(1,68,78,82,0,1,154,kind);
    await assert.rejects(registerDirectory('/data/left.db'),error => error instanceof VerifiedDirectoryRemoval && error.removal===removal);
    await assert.rejects(renewDevices('/data/left.db',Uint8Array.of(9)),error => error instanceof VerifiedDirectoryRemoval && error.removal===removal);
  }
});

test('native registration refusals and unavailable transport remain distinct without JS fallback', async (t) => {
  const { registerDirectory } = await scopedNetwork();
  t.mock.method(globalThis, 'fetch', async () => assert.fail('registration HTTP stays in Mesh'));
  for (const reason of ['registration_refused', 'unproven_removal', 'directory_http_503', 'credit_transport_unavailable']) {
    meshMocks.directory_register_export = async () => { throw new Error(reason); };
    await assert.rejects(registerDirectory('/data/refused.db'), new RegExp(reason));
  }
});

test('device renewal and revocation delegate exact intents and preserve native ordered retry status', async t => {
  const { loadAccountDevices, revokeDevice } = await scopedNetwork();
  const database = '/data/renew.db';
  const profile = vectors(utf8('alice'),new Uint8Array(32).fill(1),new Uint8Array(16).fill(2),Uint8Array.of(0));
  const deviceSet = Uint8Array.of(0xd5,0x5e);
  meshMocks.directory_resolve_export = async () => deviceSet;
  meshMocks.inspect_device_set_export = async () => vectors(utf8('alice'),new Uint8Array(32).fill(1),new Uint8Array(8),Uint8Array.of(0),Uint8Array.of(1),vectors(writeU32(0)));
  t.mock.method(globalThis,'fetch',async () => assert.fail('device HTTP stays in Mesh'));
  t.mock.method(meshMocks,'renew_devices_export',async () => assert.fail('signed renewal entries stay in Mesh'));
  t.mock.method(meshMocks,'create_device_revocation_export',async () => assert.fail('revocation signatures stay in Mesh'));
  const calls: Uint8Array[] = [];
  for (const httpStatus of [0,409,507,503]) {
    meshMocks.devices_renew_export = async input => {
      calls.push(input); return Uint8Array.of(1,68,78,82,2,httpStatus>>>8,httpStatus&255,0);
    };
    assert.deepEqual((await loadAccountDevices(database,profile)).wire,deviceSet);
  }
  assert.deepEqual(calls,Array.from({length:4},()=>vectors(utf8(database),deviceSet)));
  const target = new Uint8Array(16).fill(7);
  meshMocks.device_revoke_export = async input => {
    assert.deepEqual(input,vectors(utf8(database),deviceSet,target)); return Uint8Array.of(1,68,82,86,0,200);
  };
  await revokeDevice(database,deviceSet,target);
  meshMocks.device_revoke_export = async () => { throw Error('account_state_changed'); };
  await assert.rejects(revokeDevice(database,deviceSet,target),/account_state_changed/);
});

test('resolution never retries or invents a legacy route after a native refusal', async t => {
  const { resolveDeviceSet } = await scopedNetwork();
  t.mock.method(globalThis,'fetch',async () => assert.fail('native refusal cannot trigger JS HTTP'));
  let calls = 0;
  for (const code of ['directory_http_404','transparency_stale','transparency_response_version_mismatch','directory_identity_changed']) {
    t.mock.method(meshMocks,'directory_resolve_export',async () => { calls++; throw Error(code); });
    await assert.rejects(resolveDeviceSet('/data/refused-lookup.db','alice'),new RegExp(code));
  }
  assert.equal(calls,4);
  t.mock.method(meshMocks,'directory_resolve_export',async () => Uint8Array.of(9));
  assert.deepEqual(await resolveDeviceSet('/data/refused-lookup.db','alice'),Uint8Array.of(9));
});

test('registration delegates fresh policy and work to native code even when a caller supplies a policy', async (t) => {
  const { registerDirectory } = await scopedNetwork();
  meshMocks.register_request_export = async () => assert.fail('base work stays in Mesh');
  meshMocks.register_signup_policy_export = async () => assert.fail('signed policy stays in Mesh');
  meshMocks.directory_register_export = async request => {
    assert.deepEqual(request, utf8('/data/draft.db')); throw new Error('registration_refused');
  };
  t.mock.method(globalThis, 'fetch', async () => assert.fail('registration HTTP stays in Mesh'));
  await assert.rejects(registerDirectory('/data/draft.db', new Uint8Array(88).fill(9)), /registration_refused/);
});

test('mailbox reconnect uses one native registration and never falls back after a policy failure', async (t) => {
  const { connectMailboxStream } = await scopedNetwork();
  let calls = 0;
  meshMocks.register_request_export = async () => assert.fail('work stays in Mesh');
  meshMocks.register_signup_policy_export = async () => assert.fail('policy stays in Mesh');
  meshMocks.credit_signup_policy_online_export = async () => assert.fail('registration refreshes policy internally');
  t.mock.method(globalThis, 'fetch', async () => assert.fail('reconnect HTTP stays in Mesh'));
  for (const reason of ['registration_refused', 'untrusted_credit_signup_policy', 'credit_transport_unavailable', 'native_storage_unavailable']) {
    meshMocks.directory_register_export = async request => {
      calls++; assert.deepEqual(request, utf8('/data/reconnect.db')); throw new Error(reason);
    };
    await assert.rejects(connectMailboxStream('/data/reconnect.db'), new RegExp(reason));
  }
  assert.equal(calls, 4);
});

test('closing an attachment session stops chunks and erases a late native chunk without progress', async () => {
  const controller = new AbortController();
  const late = Uint8Array.of(9,8,7); let calls = 0; let progress = 0;
  meshMocks.attachment_fetch_chunk_export = async () => { calls++; controller.abort(); return late; };
  const summary = { reference: Uint8Array.of(1), objectId: new Uint8Array(32), downloadCapability: new Uint8Array(32),
    filename: 'a.txt', mimeType: 'text/plain', size: 6, chunkCount: 2, chunkSize: 3, expiresAt: 1 };
  await assert.rejects(downloadAttachment('test.db', summary, () => { progress++; }, controller.signal), /abort/i);
  assert.equal(calls, 1); assert.equal(progress, 0); assert.deepEqual(late, new Uint8Array(3));
});

test('close immediately clears assembled plaintext while the next native chunk is still pending', async (t) => {
  const controller = new AbortController(); const first = Uint8Array.of(7,6,5), late = Uint8Array.of(4,3,2);
  let assembled: Uint8Array | undefined;
  const set = Uint8Array.prototype.set;
  t.mock.method(Uint8Array.prototype, 'set', function(this: Uint8Array, source: ArrayLike<number>, offset?: number) {
    if (source === first) assembled = this;
    return set.call(this, source, offset);
  });
  let enter!: () => void, finish!: (bytes: Uint8Array) => void; let calls = 0;
  const entered = new Promise<void>(resolve => { enter = resolve; });
  meshMocks.attachment_fetch_chunk_export = async () => {
    if (++calls === 1) return first;
    enter(); return new Promise(resolve => { finish = resolve; });
  };
  const summary = { reference: Uint8Array.of(1), objectId: new Uint8Array(32), downloadCapability: new Uint8Array(32),
    filename:'two.txt',mimeType:'text/plain',size:6,chunkCount:2,chunkSize:3,expiresAt:1 };
  const pending = downloadAttachment('test.db', summary, undefined, controller.signal);
  await entered; assert.deepEqual(assembled, Uint8Array.of(7,6,5,0,0,0));
  controller.abort();
  // The in-flight native callback has deliberately not returned yet.
  assert.deepEqual(assembled, new Uint8Array(6));
  finish(late); await assert.rejects(pending, /abort/i);
  assert.deepEqual(first, new Uint8Array(3)); assert.deepEqual(late, new Uint8Array(3));
});

test('group timer wrapper validates native-bound duration and exact returned group', async () => {
  const { groupMessageTimer } = await scopedNetwork();
  const group = new Uint8Array(32).fill(7);
  let calls = 0;
  meshMocks.group_policy_export = async request => {
    calls++; assert.deepEqual(request, vectors(utf8('test.db'), group, writeU32(60)));
    return vectors(writeU32(3), Uint8Array.of(1), group, writeU32(60));
  };
  assert.equal(await groupMessageTimer('test.db', group, 60), 60);
  for (const invalid of [-1, 0.5, 2_592_001, NaN]) await assert.rejects(() => groupMessageTimer('test.db', group, invalid), /invalid_group_policy/);
  assert.equal(calls, 1, 'Invalid input must never invoke native');
  meshMocks.group_policy_export = async request => {
    assert.deepEqual(request, vectors(utf8('test.db'), group));
    return vectors(writeU32(3), Uint8Array.of(1), new Uint8Array(32).fill(8), writeU32(60));
  };
  await assert.rejects(() => groupMessageTimer('test.db', group), /invalid_group_policy/);
});


const desktopTick = () => new Promise<void>(resolve => setImmediate(resolve));
function desktopGate() {
  let resolve: () => void = () => { throw Error('resolver_not_initialized'); };
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
function desktopScope(check: () => Promise<void>) {
  const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
  return createDesktopPrivateSession({ check, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
}
test('desktop group package request waits for enclosing asynchronous native admission', async t => {
  const gate = desktopGate(); let checks = 0, calls = 0, published = false;
  const held = desktopScope(async () => { if (++checks === 1) await gate.promise; });
  const module = await import('./network.ts');
  const client = module.createNetworkServices({ ...await import('../modules/mesh-messenger'), ...held });
  t.mock.method(meshMocks, 'group_key_package_export', async () => { calls++; return new Uint8Array(401); });
  const reading = client.getGroupKeyPackage('/captured/db').then(value => { published = true; return value; });
  await desktopTick(); const earlyCalls = calls, earlyPublication = published;
  gate.resolve(); const result = await reading; await desktopTick(); held.dispose();
  assert.equal(result.length, 401); assert.equal(calls, 1); assert.equal(earlyCalls, 0); assert.equal(earlyPublication, false);
});
for (const kind of ['postage', 'undeliverable'] as const) {
  test(`desktop ${kind} listener waits for native authority and respects unsubscribe during admission`, async t => {
    const gate = desktopGate(); let block = false, delivered = 0;
    const held = desktopScope(async () => { if (block) await gate.promise; });
    const module = await import('./network.ts');
    const client = module.createNetworkServices({ ...await import('../modules/mesh-messenger'), ...held });
    const unsubscribe = kind === 'postage'
      ? client.onPostageRequired(() => { delivered++; })
      : client.onUndeliverable(() => { delivered++; });
    t.mock.method(meshMocks, 'outbox_drain_export', async () => {
      block = true;
      return kind === 'postage' ? outboxStatus(0, 0, 1, [new Uint8Array(16).fill(7)])
        : outboxStatus(0, 1, 0, [], [{ status: 400, queuedAt: 1700000000000 }]);
    });
    const pending = client.drainOutbox('/captured/db');
    const settled = kind === 'postage' ? assert.rejects(pending, module.PostageRequired) : pending;
    await desktopTick(); const earlyDelivery = delivered; unsubscribe(); gate.resolve();
    await settled; await desktopTick(); held.dispose();
    assert.equal(earlyDelivery, 0); assert.equal(delivered, 0);
  });
}

for (const duringOpen of [false, true]) {
  test(`native mailbox lifetime closes ${duringOpen ? 'an unreturned' : 'a returned'} socket on scope disposal`, async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const held = desktopScope(async () => {}), module = await import('./network.ts');
    let closes = 0;
    const native = await import('../modules/mesh-messenger');
    const client = module.createNetworkServices({ ...native, ...held,
      directory_register_export: async () => Uint8Array.of(1, 68, 82, 71, 0, 64, 0),
      mailbox_stream_open_export: async () => { if (duringOpen) held.dispose(); return new Uint8Array(32).fill(7); },
      mailbox_stream_close_export: async () => { closes++; return new Uint8Array(); },
    });
    if (duringOpen) await assert.rejects(client.connectMailboxStream('/owned/db'), /stale_epoch/);
    else { const socket = await client.connectMailboxStream('/owned/db'); held.dispose(); await desktopTick(); const atDisposal = closes; socket.close(); assert.equal(atDisposal, 1); }
    await desktopTick(); assert.equal(closes, 1);
  });
}
