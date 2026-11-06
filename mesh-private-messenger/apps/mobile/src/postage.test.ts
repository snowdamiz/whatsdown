import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
const text = (s: string) => new TextEncoder().encode(s);
const key = (n: number, length = 32) => new Uint8Array(length).fill(n);
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const u64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; };
const packet = (...fields: Uint8Array[]) => { const b = new Uint8Array(4 + fields.reduce((n, f) => n + 4 + f.length, 0)); b.set(u32(fields.length)); let at = 4; for (const f of fields) {
    b.set(u32(f.length), at);
    at += 4;
    b.set(f, at);
    at += f.length;
} return b; };
const ids = packet(...Array.from({ length: 8 }, (_, i) => key(i === 0 ? 3 : i + 10, 16)));
const candidate = packet(text('\u0001MPC'), key(2), text('bob'), key(4, 16), key(3, 16));
const preview = packet(text('\u0001MPB'), key(5), key(2), text('bob'), key(4, 16), key(3, 16), ids, u64(9007199254740993n), u64(9n), Uint8Array.of(0, 25), Uint8Array.of(1), u32(100), u32(0));
let state = 0, fail = true, nativeError = '', receiptCalls = 0, policyRevision = 1n;
const requests: Uint8Array[] = [];
const nativeCalls: string[] = [];
const plan = () => packet(text('\u0001MPS'), key(5), key(6), Uint8Array.of(state), Uint8Array.of(0, 25), u64(9007199254740993n), text('https://edge.example'), text(state === 0 ? '/v1/credits/postage' : ''), state === 0 ? Uint8Array.of(7, 8, 9) : new Uint8Array());
const mocks: Record<string, (input: Uint8Array) => Promise<Uint8Array>> = {
    credit_postage_candidate_export: async () => candidate,
    credit_postage_preview_export: async () => preview,
    credit_postage_prepare_export: async () => { nativeCalls.push('prepare'); return plan(); },
    credit_postage_recover_export: async () => { nativeCalls.push('recover'); return plan(); },
    credit_postage_receipt_export: async () => { throw Error('JS must not submit a transport receipt'); },
    credit_postage_continue_export: async input => { nativeCalls.push('continue'); requests.push(input); if (fail) throw Error('unknown outcome'); if (nativeError) throw Error(nativeError); receiptCalls++; state = 1; return plan(); },
    credit_postage_inventory_export: async () => packet(text('\u0001MPI'), u64(18446744073709551615n), Uint8Array.of(1), packet(key(5), key(4, 16), key(2), text('bob'), key(6), Uint8Array.of(3), Uint8Array.of(0, 25), u64(18446744073709551615n), ids)),
    postage_policy_view_export: async () => packet(text('\u0001MPV'), key(2), u64(policyRevision), u64(policyRevision === 1n ? 9n : 10n), Uint8Array.of(5)),
    postage_policy_publish_export: async input => { nativeCalls.push('publish'); assert.deepEqual(input, packet(text('/db'), u64(2n), u64(9n), Uint8Array.of(5))); return new Uint8Array(); },
    postage_policy_prepare_export: async () => packet(text('\u0001MPP'), key(2), u64(2n), u64(9n), Uint8Array.of(5), text('https://edge.example'), text('/v1/credits/postage-policy'), key(7, 121)),
};
Object.assign(globalThis, { __postageMocks: mocks, __postageResolve: async (_db: string, name: string) => { assert.equal(name, '@' + '02'.repeat(32)); nativeCalls.push('witness'); return key(8, 100); }, __postageFetch: async () => { throw Error('JavaScript postage HTTP is disabled'); } });
registerHooks({ resolve(specifier, context, next) {
        if (specifier === '../modules/mesh-messenger')
            return { shortCircuit: true, url: 'data:text/javascript,export const isLegacyDesktopBridge=false;' + Object.keys(mocks).map(name => `export const ${name}=async input=>globalThis.__postageMocks.${name}(input);`).join('') };
        if (specifier === './network')
            return { shortCircuit: true, url: 'data:text/javascript,export const resolveDeviceSet=globalThis.__postageResolve;' };
        if (specifier === './transport')
            return { shortCircuit: true, url: 'data:text/javascript,export const fetch=globalThis.__postageFetch;' };
        return next(specifier, context);
    } });
const postageModule = await import('./postage.ts');
const { scope } = scopeFixture();
const postage = { ...postageModule, ...postageModule.createPostageServices({ ...await import('../modules/mesh-messenger'), ...scope, resolveDeviceSet: globalThis.__postageResolve }) };
test('postage preview uses witnessed recipient and native whole-message IDs; unknown retry keeps the same sealed batch', async () => {
    const view = await postage.previewPostage('/db', key(3, 16));
    assert.equal(view.credits, 25);
    assert.equal(view.ids.length, 8);
    assert.equal(view.policyRevision, 9007199254740993n);
    assert.deepEqual(nativeCalls, ['witness']);
    await postage.preparePostage('/db', view);
    await assert.rejects(postage.continuePostage('/db', view.nonce), /unknown outcome/);
    assert.equal(receiptCalls, 0);
    fail = false;
    const result = await postage.continuePostage('/db', view.nonce);
    assert.equal(result.status, 1);
    assert.equal(receiptCalls, 1);
    assert.deepEqual(requests[0], packet(text('/db'), view.nonce));
    assert.deepEqual(requests[0], requests[1]);
    assert.equal(nativeCalls.filter(x => x === 'prepare').length, 1);
});
test('native refusal leaves the UI pending and never submits a JS receipt', async () => {
    state = 0;
    nativeError = 'invalid_postage_reply';
    const before = receiptCalls;
    await assert.rejects(postage.continuePostage('/db', key(5)), /invalid_postage_reply/);
    nativeError = 'credit_transport_unavailable';
    await assert.rejects(postage.continuePostage('/db', key(5)), /credit_transport_unavailable/);
    assert.equal(receiptCalls, before);
    nativeError = '';
});
test('inventory is read-only, keeps prepared-before-reservation distinct and preserves full U64 values', async () => {
    const before = nativeCalls.length;
    const inventory = await postage.readPostages('/db');
    assert.equal(inventory.revision, 18446744073709551615n);
    assert.equal(inventory.items[0]!.status, 3);
    assert.equal(inventory.items[0]!.expiresAt, 18446744073709551615n);
    assert.equal(inventory.items[0]!.ids.length, 8);
    assert.equal(nativeCalls.length, before);
});
test('a policy HTTP acknowledgement cannot stand in for fresh witnessed admission', async () => {
    const policy = await postage.preparePostagePolicy('/db', 5);
    await assert.rejects(postage.publishPostagePolicy('/db', policy), /postage_policy_not_witnessed/);
    policyRevision = 2n;
    const admitted = await postage.publishPostagePolicy('/db', policy);
    assert.equal(admitted.credits, 5);
    assert.equal(admitted.revision, 2n);
});

test('invalid nonce never crosses the native boundary', async () => {
  const before = nativeCalls.length;
  await assert.rejects(postage.continuePostage('/db', key(5,31)), /invalid_postage_request/);
  assert.equal(nativeCalls.length,before);
});

test('policy view restores a pending native signed intent after UI restart', async () => {
  mocks.postage_policy_view_export = async () => packet(text('\u0002MPV'), key(2), u64(1n), u64(9n), Uint8Array.of(1),
    packet(text('\u0001MPP'), key(2), u64(2n), u64(9n), Uint8Array.of(5), text('https://edge.example'), text('/v1/credits/postage-policy'), key(7,141)));
  const view = await postage.readPostagePolicy('/db',key(2));
  assert.equal(view.credits,1);
  assert.equal(view.pending?.credits,5);
  assert.equal(view.pending?.revision,2n);
});
