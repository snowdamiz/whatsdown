import assert from 'node:assert/strict';
import test from 'node:test';
import { stringifyJsonWithBigInts, parseJsonWithBigInts } from '@solana/rpc-spec-types';
import { connectAnchorRpc, feePayerHealth } from './anchor-rpc.mjs';

const genesisHash = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const transaction = {signature:'2'.repeat(88),wire:Buffer.alloc(400,7).toString('base64'),lastValidBlockHeight:'9007199254741010'};
const row = {transaction,intent:{kind:'post',checkpointHash:'ab'.repeat(32)}};
const slot = 9007199254741011n;
const pending = {context:{slot},value:[null]};
const status = (confirmationStatus, err = null) => ({context:{slot},value:[{slot,confirmationStatus,confirmations:confirmationStatus === 'finalized' ? null : 1n,err}]});

test('RPC reconciliation requires finality and entry readback; expiry rechecks historical status beyond the exact lifetime', async () => {
  const calls = [], reads = [];
  let replies = [], height = 9007199254741010n;
  const fetcher = async (url, init) => {
    assert.equal(url, 'https://rpc.example/');
    assert.equal(init.redirect, 'error');
    assert.equal(init.signal.aborted, false);
    const request = parseJsonWithBigInts(init.body);
    calls.push(request);
    const result = request.method === 'getGenesisHash' ? genesisHash : request.method === 'getBlockHeight' ? height :
      request.method === 'sendTransaction' ? transaction.signature : replies.shift();
    assert.notEqual(result, undefined, request.method);
    return new Response(stringifyJsonWithBigInts({jsonrpc:'2.0',id:request.id,result}));
  };
  const chain = await connectAnchorRpc({url:'https://rpc.example/',genesisHash}, fetcher);
  const readback = async (intent, options) => {
    reads.push({intent,options});
    return {slot:slot.toString(),ringIndex:4095};
  };
  for (const confirmationStatus of ['processed','confirmed']) {
    replies = [status(confirmationStatus, {InstructionError:[1,'Custom']})];
    assert.deepEqual(await chain.observe(row, readback), {state:'pending'});
    assert.equal(reads.length, 0);
  }
  replies = [status('finalized')];
  assert.deepEqual(await chain.observe(row, readback), {state:'finalized',confirmation:{slot:slot.toString(),ringIndex:4095}});
  assert.deepEqual(reads, [{intent:row.intent,options:{minContextSlot:slot}}]);
  replies = [status('finalized')];
  await assert.rejects(chain.observe(row, async () => {throw new Error('entry unavailable');}), /entry unavailable/);
  replies = [status('finalized', {InstructionError:[1,'Custom']})];
  assert.deepEqual(await chain.observe(row, readback), {state:'failed'});

  replies = [pending];
  assert.deepEqual(await chain.observe(row, readback), {state:'pending'}, 'equal block height is still valid');
  height++;
  replies = [pending, status('finalized')];
  assert.equal((await chain.observe(row, readback)).state, 'finalized', 'landing during the expiry check wins');
  replies = [pending, status('confirmed')];
  assert.deepEqual(await chain.observe(row, readback), {state:'pending'});
  replies = [pending, pending];
  assert.deepEqual(await chain.observe(row, readback), {state:'expired'});
  replies = [pending, {context:{slot:slot-1n},value:[null]}];
  await assert.rejects(chain.observe(row, readback), /context/);
  for (const malformed of [{context:{slot},value:[]}, {context:{slot},value:[{slot,confirmationStatus:'finalized'}]}]) {
    replies = [malformed];
    await assert.rejects(chain.observe(row, readback));
  }
  assert.equal(await chain.broadcast(transaction), transaction.signature);
  const send = calls.at(-1);
  assert.equal(send.method, 'sendTransaction');
  assert.equal(send.params[0], transaction.wire);
  assert.deepEqual(send.params[1], {encoding:'base64',maxRetries:0n,preflightCommitment:'finalized',skipPreflight:false});
  for (const call of calls.filter(value => value.method === 'getSignatureStatuses')) {
    assert.deepEqual(call.params, [[transaction.signature],{searchTransactionHistory:true}]);
  }
  for (const call of calls.filter(value => value.method === 'getBlockHeight')) {
    assert.deepEqual(call.params, [{commitment:'finalized',minContextSlot:slot}]);
  }
});

test('RPC transport refuses wrong clusters, response IDs, oversized bodies, redirects and insecure origins', async () => {
  let mode = 'wrong-cluster';
  const fetcher = async (_, init) => {
    const request = JSON.parse(init.body);
    if (mode === 'redirect') return new Response(null, {status:302,headers:{location:'https://elsewhere.example/'}});
    if (mode === 'oversize') return new Response('x'.repeat(32769));
    return Response.json({jsonrpc:'2.0',id:mode === 'wrong-id' ? 'other' : request.id,
      result:mode === 'wrong-cluster' ? 'different-genesis' : genesisHash});
  };
  for (const value of ['wrong-cluster','wrong-id','oversize','redirect']) {
    mode = value;
    await assert.rejects(connectAnchorRpc({url:'https://rpc.example/',genesisHash},fetcher));
  }
  for (const url of ['http://rpc.example/','https://user:password@rpc.example/','https://rpc.example/#fragment']) {
    await assert.rejects(connectAnchorRpc({url,genesisHash},fetcher));
  }
});

test('fee payer thresholds preserve integer lamports and distinguish excess funds', () => {
  assert.deepEqual(feePayerHealth(50_000_000n), {balanceLamports:'50000000',level:'critical',withinCap:true});
  assert.equal(feePayerHealth(50_000_001n).level, 'warning');
  assert.equal(feePayerHealth(200_000_000n).level, 'warning');
  assert.equal(feePayerHealth(200_000_001n).level, 'healthy');
  assert.equal(feePayerHealth(1_000_000_000n).withinCap, true);
  assert.deepEqual(feePayerHealth(1_000_000_001n), {balanceLamports:'1000000001',level:'overfunded',withinCap:false});
  assert.throws(() => feePayerHealth(1));
  assert.throws(() => feePayerHealth(-1n));
});

test('a stalled RPC request is aborted within its transport deadline', async () => {
  let aborted = false;
  const fetcher = (_, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => {aborted = true; reject(init.signal.reason);}, {once:true});
  });
  // Keep the test process alive while AbortSignal's unreferenced timer runs.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    await assert.rejects(connectAnchorRpc({url:'https://rpc.example/',genesisHash}, fetcher), /transport unavailable/);
    assert.equal(aborted, true);
  } finally { clearInterval(keepAlive); }
});
