import assert from 'node:assert/strict';
import test from 'node:test';
import { getBase58Decoder } from '@solana/kit';
import { createAnchorDirectory } from './anchor-directory.mjs';

test('directory writer requests stay internal, bound exact history and serialize the Mesh receipt frame', async () => {
  const calls = [], entry = {version:2,sequence:'9007199254740993',treeSize:'12',checkpointHash:'ab'.repeat(32),ringIndex:4095,generation:7};
  const set = {bytes:new Uint8Array(2752).fill(9),generation:7};
  const response = {version:2,sequence:entry.sequence,tree_size:'12',checkpoint_hash:entry.checkpointHash,
    root:'ac'.repeat(32),timestamp_ms:'1791504000000',service_key:'cd'.repeat(32),log_id:'ef'.repeat(32),generation:7,ring_index:4095,cosigns:[]};
  let reply = response, status = 200;
  const client = createAnchorDirectory({DIRECTORY:{getByName:name=>({fetch:async(url,init)=> {
    assert.equal(name,'primary'); calls.push({url,init});
    return new Response(status === 404 ? null : JSON.stringify(reply),{status});
  }})},MESSENGER_DELIVERY_INTERNAL_TOKEN:'11'.repeat(32)}, {version:2,serviceKey:response.service_key,logId:response.log_id});
  assert.equal((await client.candidate()).sequence,entry.sequence);
  assert.deepEqual((await client.cosigns(entry,set)).cosigns,[]);
  const query = Buffer.from(calls[1].init.body);
  assert.equal(query.length,2768); assert.equal(query.subarray(0,4).toString('hex'),'01415751');
  assert.equal(query.readUInt16BE(4),2); assert.equal(query.readBigUInt64BE(6),9007199254740993n);
  assert.equal(query.readUInt16BE(14),4095); assert.deepEqual(query.subarray(16),Buffer.from(set.bytes));
  for (const altered of [{checkpoint_hash:'aa'.repeat(32)},{sequence:'1'},{generation:8},{ring_index:0},
    {service_key:'aa'.repeat(32)},{log_id:'aa'.repeat(32)}]) {
    reply = {...response,...altered}; await assert.rejects(client.cosigns(entry,set));
  }
  for (const altered of [{root:undefined},{root:'00'},{timestamp_ms:12},{timestamp_ms:'18446744073709551616'}]) {
    reply = {...response,...altered}; await assert.rejects(client.candidate());
  }
  status = 404; assert.equal(await client.candidate(),null);
  status = 201;
  const signature = getBase58Decoder().decode(new Uint8Array(64).fill(42));
  await client.record({kind:'post',version:2,checkpointHash:entry.checkpointHash,sequence:entry.sequence,treeSize:entry.treeSize},
    {slot:'9007199254740994',ringIndex:4095,signature});
  const receipt = Buffer.from(calls.at(-1).init.body);
  assert.equal(receipt.length,128); assert.equal(receipt.subarray(0,4).toString('hex'),'014b5441');
  assert.equal(receipt.readUInt16BE(4),2); assert.equal(receipt.readBigUInt64BE(6),9007199254740993n);
  assert.equal(receipt.readBigUInt64BE(14),12n); assert.equal(receipt.subarray(22,54).toString('hex'),entry.checkpointHash);
  assert.equal(receipt.readUInt16BE(54),4095); assert.deepEqual(receipt.subarray(56,120),Buffer.alloc(64,42));
  assert.equal(receipt.readBigUInt64BE(120),9007199254740994n);
  status = 200; await client.record({kind:'post',...entry}, {slot:'1',ringIndex:0,signature});
  assert.ok(calls.every(value=>value.url.startsWith('http://service/internal/v1/transparency/')));
  assert.ok(calls.every(value=>value.init.headers.Authorization === 'Bearer '+'11'.repeat(32)));
  assert.ok(calls.every(value=>value.init.redirect === 'error'));
  status = 409;
  await assert.rejects(client.record({kind:'post',version:2,checkpointHash:entry.checkpointHash,sequence:entry.sequence,treeSize:entry.treeSize},
    {slot:'1',ringIndex:0,signature}));
});
