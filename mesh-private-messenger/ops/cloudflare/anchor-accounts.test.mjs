import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { getAddressDecoder, getAddressEncoder, getProgramDerivedAddress } from '@solana/kit';
import { openAnchorAccounts } from './anchor-accounts.mjs';

const address = value => getAddressDecoder().decode(Buffer.alloc(32,value));
const raw = value => Buffer.from(getAddressEncoder().encode(value));
const hash = value => createHash('sha256').update(value).digest();
const program = address(3), authority = address(42), serviceKey = '07'.repeat(32);
const logName = 'morse-main', logId = hash(Buffer.from(logName));
const derive = async seeds => (await getProgramDerivedAddress({programAddress:program,seeds}))[0];
const config = {program,logName,version:2,serviceKey,authority,origin:'morseapp.io/log/main/v2'};

async function fixture() {
  const log = await derive([Buffer.from('log'),Buffer.from(logName)]);
  const ring = await derive([Buffer.from('ring'),Buffer.from(logName)]);
  const generation = await derive([Buffer.from('witness-set'),logId,Buffer.from([7,0])]);
  const witness = Buffer.from('08'.repeat(32),'hex'), id = Buffer.from('witness-a');
  const identity = hash(Buffer.concat([Buffer.from('morse-witness-record-v1'),Buffer.from([id.length]),id,witness]));
  const witnessAddress = await derive([Buffer.from('witness'),logId,identity]);
  const logData = Buffer.alloc(352);
  logData.set(Buffer.from('MLG\x01')); logData[4] = 2; logData[6] = logName.length;
  logData.set(Buffer.from(logName),8); logData.set(logId,40); logData.set(Buffer.from(serviceKey,'hex'),72);
  logData.set(raw(authority),104); logData.set(raw(ring),136); logData.writeBigUInt64LE(10n,200);
  logData.writeUInt16LE(8,208); // The current generation has already rotated.
  logData.writeUInt16LE(config.origin.length,210); logData.set(Buffer.from(config.origin),212);
  const set = Buffer.alloc(2752); set.set(Buffer.from('MWS\x01')); set.set(logId,4); set.writeUInt16LE(7,36); set[38] = 1;
  set.set(raw(witnessAddress),64); set[96] = id.length; set.set(id,104); set.set(witness,168); set.set(raw(address(11)),200);
  const ringData = Buffer.alloc(426048); ringData.set(Buffer.from('MRG\x01')); ringData.set(logId,4);
  ringData.writeUInt16LE(1,36); ringData.writeUInt16LE(2,38);
  ringData.writeBigUInt64LE(20n,40); ringData.writeBigUInt64LE(12n,48); ringData.writeBigUInt64LE(99n,56);
  const entry = (index, seq, slot, digest) => {
    const offset = 64 + index * 104;
    ringData.writeBigUInt64LE(seq,offset); ringData.writeBigUInt64LE(12n,offset+8);
    ringData.fill(5,offset+16,offset+48); ringData.fill(digest,offset+48,offset+80);
    ringData.writeBigUInt64LE(1000n,offset+80); ringData.writeBigUInt64LE(slot,offset+88);
    ringData.writeUInt16LE(1,offset+96); ringData[offset+98] = 2; ringData.writeUInt16LE(1,offset+100);
    ringData.writeUInt16LE(7,offset+102);
  };
  entry(0,19n,98n,10); entry(1,20n,99n,11);
  const records = new Map([[log,logData],[ring,ringData],[generation,set]]);
  const calls = [];
  let mutate = value => value;
  const rpc = {getAccountInfo:(account, options) => ({send:async () => {
    calls.push({account,options});
    assert.equal(options.commitment,'finalized'); assert.equal(options.encoding,'base64');
    const data = records.get(account);
    const offset = Number(options.dataSlice.offset), length = Number(options.dataSlice.length);
    const reply = {context:{slot:100n},value:data ? {owner:program,executable:false,lamports:1n,space:BigInt(data.length),
      data:[data.subarray(offset,offset+length).toString('base64'),'base64']} : null};
    return mutate(reply, account, options);
  }})};
  return {rpc,records,calls,log,ring,generation,logData,ringData,set,entry,change:fn => {mutate = fn;}};
}

test('writer authenticates exact historical entries and sets, including a rotated current generation', async () => {
  const f = await fixture(), accounts = await openAnchorAccounts(f.rpc,config);
  assert.equal(accounts.log,f.log); assert.equal(accounts.ring,f.ring);
  assert.equal(accounts.logState.generation,8);
  const snapshot = await accounts.readRing({limit:16,minContextSlot:99n});
  assert.deepEqual(snapshot.entries.map(value=>[value.ringIndex,value.sequence,value.slot]), [[1,'20','99'],[0,'19','98']]);
  const material = {kind:'post',version:2,checkpointHash:'0a'.repeat(32),sequence:'19',treeSize:'12'};
  assert.deepEqual(await accounts.readback(material,{minContextSlot:100n}),{slot:'98',ringIndex:0});
  const cosign = {...material,kind:'cosign',ringIndex:0,slot:'98',generation:7,witnessIndices:[0]};
  assert.deepEqual(await accounts.readback(cosign,{minContextSlot:100n}),{slot:'98',ringIndex:0});
  const historical = await accounts.witnessSet(7,{minContextSlot:100n});
  assert.equal(historical.address,f.generation); assert.equal(historical.witnesses[0].id,'witness-a');
  assert.deepEqual(Buffer.from(historical.bytes),f.set);
  assert.ok(f.calls.every(call=>call.options.dataSlice.length <= 128n * 104n));
  for (const altered of [{checkpointHash:'ff'.repeat(32)},{version:1},{sequence:'18'},{treeSize:'11'},
    {ringIndex:1},{generation:8},{slot:'97'},{witnessIndices:[1]}]) {
    await assert.rejects(accounts.readback({...cosign,...altered},{minContextSlot:100n}));
  }
  f.ringData.writeUInt16LE(0,64+96); f.ringData.writeUInt16LE(0,64+100);
  await assert.rejects(accounts.readback(cosign,{minContextSlot:100n}),/cosign/i);
});

test('writer refuses wrong owners, account metadata, pins and noncanonical data', async () => {
  for (const mutate of [
    reply=>({...reply,value:{...reply.value,owner:address(9)}}),
    reply=>({...reply,value:{...reply.value,executable:true}}),
    reply=>({...reply,value:{...reply.value,lamports:0n}}),
    reply=>({...reply,value:{...reply.value,space:351n}}),
    reply=>({...reply,context:{slot:99n}}),
  ]) {
    const f = await fixture(); f.change(mutate);
    await assert.rejects(openAnchorAccounts(f.rpc,config,{minContextSlot:100n}));
  }
  for (const [offset,value] of [[4,1],[7,2],[8,120],[40,0],[72,0],[104,0],[136,0],[340,1]]) {
    const f = await fixture(); f.logData[offset] = value;
    await assert.rejects(openAnchorAccounts(f.rpc,config));
  }
  const f = await fixture(), accounts = await openAnchorAccounts(f.rpc,config);
  f.set[64] ^= 1;
  await assert.rejects(accounts.witnessSet(7),/witness/i,'witness records must have their own canonical PDA');
});

test('attendance uses the chain clock for posts and retained posting epoch for late cosigns', async () => {
  const f=await fixture(); f.logData[7]=1;
  const clockAddress=await derive([Buffer.from('attendance'),logId]);
  const clock=Buffer.alloc(65616); clock.set(Buffer.from('MAC\x01')); clock.set(logId,4);
  clock.writeBigUInt64LE(6048010n,36); clock.writeBigUInt64LE(90n,44);
  clock.writeBigUInt64LE(11n,52); clock.writeBigUInt64LE(10n,60);
  clock.writeBigUInt64LE(11n,96); clock.writeBigUInt64LE(99n,104);
  f.records.set(clockAddress,clock);
  const sysvar='SysvarC1ock11111111111111111111111111111111';
  const chain=Buffer.alloc(40); chain.writeBigUInt64LE(100n,0); chain.writeBigUInt64LE(6652800n,32);
  f.records.set(sysvar,chain);
  f.change((reply,key)=> {if(key===sysvar)reply.value.owner='Sysvar1111111111111111111111111111111111111';return reply;});
  const accounts=await openAnchorAccounts(f.rpc,config);
  assert.equal(accounts.logState.attendanceEnabled,true);
  const current=await accounts.attendanceForPost();
  assert.equal(current.clock,clockAddress); assert.equal(current.number,11n);
  const retained=await accounts.attendanceForCosign({ringIndex:1,slot:'99'});
  assert.equal(retained.number,10n); assert.notEqual(retained.epoch,current.epoch);
  assert.equal((await accounts.attendanceForCosign({ringIndex:0,slot:'89'})).number,10n);
  await assert.rejects(accounts.attendanceForCosign({ringIndex:0,slot:'91'}));
  await assert.rejects(accounts.attendanceForCosign({ringIndex:1,slot:'98'}));
  clock[68]=1;
  await assert.rejects(accounts.attendanceForPost());
  clock[68]=0; chain.writeBigUInt64LE(101n,0);
  await assert.rejects(accounts.attendanceForPost());
});

test('ring wrap, sparse reads and a moving header never accept overwritten coordinates', async () => {
  const f = await fixture();
  f.ringData.writeUInt16LE(0,36); f.ringData.writeUInt16LE(4096,38);
  f.ringData.writeBigUInt64LE(21n,40); f.ringData.writeBigUInt64LE(100n,56);
  f.entry(4095,20n,99n,11); f.entry(0,21n,100n,12);
  const accounts = await openAnchorAccounts(f.rpc,config);
  assert.deepEqual((await accounts.readRing({limit:2})).entries.map(value=>value.ringIndex),[0,4095]);
  let headers = 0;
  f.change((reply,account,options)=> {
    if (account === f.ring && options.dataSlice.offset === 0n && ++headers === 2) {
      const changed = Buffer.from(reply.value.data[0],'base64'); changed.writeBigUInt64LE(22n,40);
      reply.value.data[0] = changed.toString('base64');
    }
    return reply;
  });
  await assert.rejects(accounts.readRing({limit:2}),/snapshot/i);
});
