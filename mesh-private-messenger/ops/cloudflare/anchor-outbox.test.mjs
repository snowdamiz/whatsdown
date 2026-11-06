import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const post = { kind: 'post', version: 2, checkpointHash: 'ab'.repeat(32), sequence: '9007199254740993', treeSize: '12' };
const transaction = { signature: '2'.repeat(88), wire: Buffer.alloc(400, 7).toString('base64'), lastValidBlockHeight: '9007199254741010', witnessIndices: [] };
const confirmation = { slot: '9007199254741011', ringIndex: 4095 };

test('anchor outbox survives lost broadcasts and receipt failures without signing or replacing a transaction', async () => {
  const path = await mkdtemp(join(tmpdir(), 'morse-anchor-outbox-'));
  let observed = { state: 'pending' }, loseBroadcast = true, loseReceipt = true;
  const sent = [], receipts = [];
  const entry = `import { DurableObject } from 'cloudflare:workers';
    import { AnchorOutbox } from './anchor-outbox.mjs';
    export class Harness extends DurableObject {
      constructor(ctx, env) { super(ctx,env); this.box = new AnchorOutbox(ctx.storage.sql, env.SCOPE); }
      async fetch(request) {
        try {
          const body = await request.json();
          const call = async (method, data) => {
            const result = await this.env.CHAIN.fetch('http://chain/' + method, {method:'POST',body:JSON.stringify(data)});
            if (!result.ok) throw new Error('injected network failure');
            return result.json();
          };
          const adapter = { observe: row => call('observe', row), broadcast: tx => call('broadcast', tx),
            record: (intent, confirmation) => call('record', {intent,confirmation}) };
          let value;
          if (body.action === 'stage') value = this.box.stage(body.intent, body.transaction, body.now);
          if (body.action === 'drain') value = await this.box.drain(adapter, body.now);
          if (body.action === 'parallel') value = await Promise.all([this.box.drain(adapter, body.now), this.box.drain(adapter, body.now)]);
          if (body.action === 'list') value = this.box.list();
          if (body.action === 'ack') { this.box.acknowledge(body.id); value = true; }
          return Response.json(value);
        } catch (error) { return new Response(String(error), {status:409}); }
      }
    }
    export default {fetch: (r,e) => e.OUTBOX.getByName('log').fetch(r)};`;
  const options = convertV4MiniflareOptions({
    name: 'morse-anchor-outbox-proof', compatibilityDate: '2026-09-18',
    bindings: { SCOPE: 'devnet:judge:log:payer:authority' },
    modules: [{ type: 'ESModule', path: 'entry.mjs', contents: entry },
      { type: 'ESModule', path: 'anchor-outbox.mjs', contents: await readFile(new URL('./anchor-outbox.mjs', import.meta.url), 'utf8') }],
    durableObjects: { OUTBOX: { className: 'Harness', useSQLite: true, unsafeUniqueKey: 'morse-anchor-outbox-proof' } },
    serviceBindings: { CHAIN: async request => {
      const body = await request.json();
      switch (new URL(request.url).pathname) {
        case '/observe': return Response.json(observed);
        case '/broadcast': sent.push(body); return loseBroadcast ? new Response(null, {status:503}) : Response.json(body.signature);
        case '/record': receipts.push(body); return loseReceipt ? new Response(null, {status:503}) : Response.json(true);
        default: throw new Error('unexpected adapter operation');
      }
    } },
  });
  options.resourcePersistencePath = path;
  let mf = new Miniflare(options);
  const request = body => mf.dispatchFetch('http://outbox/', { method: 'POST', body: JSON.stringify(body) });
  const call = async body => {
    const response = await request(body);
    assert.equal(response.status, 200, await response.clone().text());
    return response.json();
  };
  const restart = async () => { await mf.dispose(); mf = new Miniflare(options); };
  try {
    const id = await call({ action: 'stage', intent: post, transaction, now: 1000 });
    assert.equal(sent.length, 0, 'staging crosses no network boundary');
    assert.equal(await call({ action: 'stage', intent: post, transaction, now: 1001 }), id);
    assert.equal((await request({ action: 'stage', intent: post, transaction: {...transaction, wire: Buffer.alloc(400, 8).toString('base64')}, now: 1002 })).status, 409);
    assert.equal((await request({ action: 'ack', id })).status, 409, 'unsettled work cannot be discarded');
    await call({ action: 'drain', now: 1000 });
    assert.deepEqual(sent, [transaction]);
    let [saved] = await call({ action: 'list' });
    assert.equal(saved.phase, 'pending');
    assert.equal(saved.attempts, 1);
    assert.equal(saved.transaction.lastValidBlockHeight, transaction.lastValidBlockHeight);
    await restart();
    await call({ action: 'drain', now: 1001 });
    assert.equal(sent.length, 1, 'restart retains retry backoff');
    loseBroadcast = false;
    await call({ action: 'parallel', now: 31000 });
    assert.deepEqual(sent, [transaction, transaction], 'concurrent wakeups retransmit the same saved wire only once');
    observed = { state: 'finalized', confirmation };
    await call({ action: 'drain', now: 32000 });
    [saved] = await call({ action: 'list' });
    assert.equal(saved.phase, 'finalized');
    assert.deepEqual(saved.confirmation, confirmation);
    assert.equal(sent.length, 2);
    assert.equal(receipts.length, 1);
    await restart();
    loseReceipt = false;
    observed = { state: 'pending' }; // Receipt retry must not depend on a new RPC observation.
    await call({ action: 'drain', now: 62000 });
    [saved] = await call({ action: 'list' });
    assert.equal(saved.phase, 'complete');
    assert.deepEqual(receipts[0], receipts[1]);
    assert.deepEqual(receipts[0], {intent: post, confirmation: {...confirmation, signature: transaction.signature}});
    await call({ action: 'ack', id });
    assert.deepEqual(await call({ action: 'list' }), []);

    // Expiry/finalized failure are durable outcomes, never implicit permission to replace a wire.
    for (const state of ['expired', 'failed']) {
      await call({ action: 'stage', intent: post, transaction, now: 70000 });
      observed = { state };
      await call({ action: 'drain', now: 70000 });
      [saved] = await call({ action: 'list' });
      assert.equal(saved.phase, state);
      assert.equal(sent.length, 2);
      await restart();
      assert.equal((await call({ action: 'list' }))[0].phase, state);
      await call({ action: 'ack', id });
    }

    // Provider/parser failures cannot authorize a replacement or a receipt.
    await call({ action: 'stage', intent: post, transaction, now: 80000 });
    for (const invalid of [{state:'confirmed'}, {state:'finalized',confirmation:{slot:1,ringIndex:0}},
      {state:'finalized',confirmation:{slot:'2',ringIndex:4096}}]) {
      observed = invalid;
      await call({ action: 'drain', now: 80000 });
      assert.equal((await call({ action: 'list' }))[0].phase, 'pending');
    }
    assert.equal(sent.length, 2);
    assert.equal(receipts.length, 2);
    observed = { state: 'failed' };
    await call({ action: 'drain', now: 81000 });
    await call({ action: 'ack', id });

    // The queue holds a post plus all sixteen worst-case single-witness
    // packets. Four observations per wakeup must not starve later witnesses.
    const cosign = {...post, kind:'cosign', ringIndex:4095, slot:confirmation.slot, generation:7};
    for (let index = 0; index < 16; index++) {
      await call({action:'stage', intent:cosign, transaction:{...transaction,witnessIndices:[index]}, now:90000});
    }
    await call({action:'stage', intent:post, transaction, now:90000});
    assert.equal((await request({action:'stage', intent:{...cosign,checkpointHash:'cd'.repeat(32)}, transaction:{...transaction,witnessIndices:[0]}, now:90000})).status, 409);
    observed = {state:'pending'};
    await call({action:'drain', now:90000});
    assert.equal(sent.length, 6);
    assert.deepEqual(sent.slice(2).map(value => value.witnessIndices), [[], [0], [1], [2]]);
    await call({action:'drain', now:90001});
    assert.deepEqual(sent.slice(6).map(value => value.witnessIndices), [[3], [4], [5]]);
    observed = {state:'finalized', confirmation};
    for (let round = 0; round < 5; round++) await call({action:'drain', now:91000 + round});
    const completed = await call({action:'list'});
    assert.equal(completed.length, 17);
    assert.ok(completed.every(row => row.phase === 'complete'));
    assert.equal(receipts.length, 3, 'cosigns never create directory anchor receipts');
    for (const row of completed) await call({action:'ack',id:row.id});
    await call({action:'stage',intent:post,transaction,now:92000});
    await mf.dispose();
    options.workers[0].config.env.SCOPE.value = 'mainnet:different-log';
    mf = new Miniflare(options);
    assert.equal((await request({action:'list'})).status, 500, 'scope change refuses old signed work');
  } finally {
    await mf.dispose();
    await rm(path, {recursive:true,force:true});
  }
});
