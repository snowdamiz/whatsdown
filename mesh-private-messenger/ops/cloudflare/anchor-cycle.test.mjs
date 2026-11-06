import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AnchorCycle } from './anchor-cycle.mjs';
import { anchorTestStorage as storage } from './anchor-test-support.mjs';
const digest = value => value.toString(16).padStart(2,'0').repeat(32);
const candidate = (sequence,root=sequence) => ({version:2,sequence:String(sequence),tree_size:'12',
  root:digest(root),checkpoint_hash:digest(sequence),timestamp_ms:'1000000'});

function network() {
  const state = {entries:[],slot:100n,seconds:1000n,balance:500_000_000n,candidate:candidate(1),
    generation:7,readyAt:'0',slashed:false,witnessCount:0,prepared:new Map(),signed:[],sent:[],recorded:[],
    repliesLost:0,receiptFailures:0,readFailures:0,cosignRequests:[],generationRequests:[]};
  const chainTimes = new Map(), transactions = new Map();
  const sign = (kind,material,indices=[]) => {
    const number = state.signed.length+1;
    const transaction = {signature:String(number%8+2).repeat(87)+String(Math.floor(number/8)%8+2),
      wire:Buffer.alloc(400,number).toString('base64'),lastValidBlockHeight:'1000',witnessIndices:indices};
    const value={kind,material,transaction};state.signed.push(value);transactions.set(transaction.signature,value);
    return transaction;
  };
  const adapter = {
    balance:async()=>state.balance,
    snapshot:async({limit})=> {
      if(state.readFailures) {state.readFailures--;throw new Error('RPC unavailable');}
      return {header:{count:state.entries.length},contextSlot:state.slot,entries:state.entries.slice(0,limit).map(value=>({...value}))};
    },
    blockTime:async slot=>chainTimes.get(slot.toString()) ?? state.seconds,
    logState:()=>({readyAt:state.readyAt,slashed:state.slashed}),
    candidate:async()=>state.candidate,
    lifetime:async()=>({blockhash:'fixture',lastValidBlockHeight:1000n}),
    signPost:async material=>sign('post',material),
    witnessSet:async generation=> {
      state.generationRequests.push(generation);
      return {address:`generation-${generation}`,generation,witnesses:Array.from({length:state.witnessCount},(_,index)=>({id:`witness-${index}`}))};
    },
    cosigns:async(entry,set)=> {
      assert.equal(set.generation,entry.generation);state.cosignRequests.push(entry.checkpointHash);
      return {cosigns:state.prepared.get(entry.checkpointHash) ?? []};
    },
    signCosigns:async(pairs,set,entry)=>pairs.map(pair=>sign('cosign',entry,[pair.witness_index])),
    observe:async row=> {
      const value=transactions.get(row.transaction.signature);
      return value?.landed ? {state:'finalized',confirmation:{slot:value.slot,ringIndex:value.index}} : {state:'pending'};
    },
    broadcast:async transaction=> {
      state.sent.push(transaction);
      const value=transactions.get(transaction.signature);
      if(!value.landed) {
        if(value.kind==='post') {
          const material=value.material;
          const entry={version:2,sequence:material.sequence,treeSize:material.tree_size,root:material.root,
            checkpointHash:material.checkpoint_hash,slot:state.slot.toString(),ringIndex:state.entries.length,
            generation:state.generation,cosignBitmap:0,nativeBitmap:0};
          state.entries.unshift(entry);chainTimes.set(entry.slot,state.seconds);
          value.slot=entry.slot;value.index=entry.ringIndex;
        } else {
          const entry=state.entries.find(entry=>entry.checkpointHash===value.material.checkpointHash);
          for(const index of transaction.witnessIndices) {entry.cosignBitmap |= 1<<index;entry.nativeBitmap |= 1<<index;}
          value.slot=entry.slot;value.index=entry.ringIndex;
        }
        value.landed=true;
      }
      if(state.repliesLost) {state.repliesLost--;throw new Error('lost broadcast reply');}
      return transaction.signature;
    },
    record:async(intent,confirmation)=> {
      state.recorded.push({intent,confirmation});
      if(state.receiptFailures) {state.receiptFailures--;throw new Error('receipt write failed');}
    },
  };
  return {state,adapter,chainTimes};
}

test('scheduled posting persists its minute limit, recovers lost replies, and sends quiet-log heartbeats', async()=> {
  const path=await mkdtemp(join(tmpdir(),'morse-anchor-cycle-'));
  let store=storage(join(path,'state.sqlite')), cycle=new AnchorCycle(store,'test:cluster:log:wallets');
  const {state,adapter}=network(); let now=1_000_000;
  const run=()=>cycle.run({mode:'devnet',cosign:false},adapter,()=>now);
  try {
    state.repliesLost=1;state.receiptFailures=1;
    await run();assert.equal(state.signed.length,1);assert.equal(state.sent.length,1);
    assert.equal(cycle.outbox.list().length,1);
    store.close();store=storage(join(path,'state.sqlite'));cycle=new AnchorCycle(store,'test:cluster:log:wallets');
    now+=1000;state.seconds=BigInt(now/1000);await run();
    assert.equal(state.signed.length,1);assert.equal(state.sent.length,1,'a finalized lost reply never causes another broadcast');
    state.candidate=candidate(2);
    now=1_059_999;state.seconds=1059n;await run();assert.equal(state.signed.length,1);
    now=1_060_000;state.seconds=1060n;state.slot=200n;await run();assert.equal(state.signed.length,2);
    assert.ok(state.recorded.length>=2);
    state.candidate=candidate(3);now=1_120_000;state.seconds=1061n;
    await run();assert.equal(state.signed.length,2,'an advanced local clock cannot bypass the chain-time minute limit');
    state.candidate=candidate(3,2);
    now=1_120_000;state.seconds=1120n;state.slot=300n;await run();assert.equal(state.signed.length,2,'new sequence alone does not spend an anchor fee');
    now=4_599_999;state.seconds=4599n;state.slot=500n;await run();assert.equal(state.signed.length,2);
    now=4_600_000;state.seconds=4600n;await run();assert.equal(state.signed.length,3,'dispatch leaves a minute for finality before the hourly deadline');
    now=4_599_000;state.seconds=4599n;state.candidate=candidate(4);await run();
    assert.equal(state.signed.length,3,'a backward clock never lifts the persisted limit');
  } finally {store.close();await rm(path,{recursive:true,force:true});}
});

test('the crank revisits historical generations, includes slot 1500, and drains sixteen cosigns without duplicating bits', async()=> {
  const store=storage(':memory:'),cycle=new AnchorCycle(store,'test:crank');
  const {state,adapter,chainTimes}=network();let now=2_000_000;
  try {
    state.seconds=2000n;state.slot=1600n;state.witnessCount=16;
    state.entries=[{version:2,sequence:'3',treeSize:'12',root:digest(3),checkpointHash:digest(3),slot:'1599',ringIndex:2,generation:8,cosignBitmap:65535,nativeBitmap:0},
      {version:2,sequence:'2',treeSize:'12',root:digest(2),checkpointHash:digest(2),slot:'100',ringIndex:1,generation:7,cosignBitmap:0,nativeBitmap:0},
      {version:2,sequence:'1',treeSize:'12',root:digest(1),checkpointHash:digest(1),slot:'99',ringIndex:0,generation:6,cosignBitmap:0,nativeBitmap:0}];
    state.candidate=candidate(3);chainTimes.set('1599',1999n);
    state.prepared.set(digest(2),Array.from({length:16},(_,index)=>({witness_index:index,instruction:'09'})));
    await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);
    assert.equal(state.signed.length,16);assert.deepEqual(state.cosignRequests,[digest(2)]);
    assert.ok(state.generationRequests.includes(7));assert.ok(!state.generationRequests.includes(6));
    for(let round=0;round<4;round++) {now+=15000;state.seconds=BigInt(now/1000);await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);}
    assert.equal(state.entries[1].cosignBitmap,65535);assert.equal(cycle.outbox.list().length,0);
    assert.equal(state.signed.length,16,'finalized work is not immediately staged again from an older snapshot');
    assert.ok(state.cosignRequests.every(hash=>hash===digest(2)),'complete C2SP entries do not consume historical preparation turns');
    assert.equal(state.recorded.length,0,'cosigns do not create new post receipts');
    state.slot=1601n;state.entries[1].cosignBitmap=0;state.entries[1].nativeBitmap=0;
    await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);
    assert.equal(state.signed.length,16,'slot 1501 is outside the window');
  } finally {store.close();}
});

test('zero witnesses, kill switches, fee limits, slash and timelock states do not authorize unwanted signatures', async()=> {
  const store=storage(':memory:'),cycle=new AnchorCycle(store,'test:limits');
  const {state,adapter}=network();let now=1_000_000;
  try {
    state.generation=0;
    state.balance=1_000_000_001n;
    assert.equal((await cycle.run({mode:'devnet',cosign:true},adapter,()=>now)).fee.level,'overfunded');
    assert.equal(state.signed.length,1,'an unsolicited deposit must not disable public anchoring');
    state.candidate=candidate(2);now+=60000;state.seconds=1060n;state.slot=200n;
    state.balance=20_000n;
    assert.equal((await cycle.run({mode:'devnet',cosign:true},adapter,()=>now)).fee.level,'critical');
    assert.equal(state.signed.length,1);
    state.balance=200_000_000n;state.slashed=true;
    assert.equal((await cycle.run({mode:'devnet',cosign:true},adapter,()=>now)).fee.level,'warning');
    assert.equal(state.signed.length,1);
    state.slashed=false;state.readyAt='1061';await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);assert.equal(state.signed.length,1);
    state.readyAt='0';state.generation=0;
    await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);assert.equal(state.signed.length,2);
    now+=15000;state.seconds=1075n;
    await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);
    assert.deepEqual(state.generationRequests,[],'a zero-witness log still anchors');
    state.candidate=candidate(3);now+=60000;state.seconds=1135n;
    await cycle.run({mode:'off',cosign:true},adapter,()=>now);assert.equal(state.signed.length,2);
  } finally {store.close();}
});

test('pending cosigns respect the crank switch and slot deadline while finalized work still reconciles',async()=> {
  const store=storage(),cycle=new AnchorCycle(store,'test:pending-policy');
  const {state,adapter}=network();let now=2_000_000;
  try {
    const entry={version:2,sequence:'1',treeSize:'12',root:digest(1),checkpointHash:digest(1),slot:'100',ringIndex:0,
      generation:7,cosignBitmap:0,nativeBitmap:0};
    state.entries=[entry];state.slot=1600n;state.seconds=2000n;state.witnessCount=1;
    const [signed]=await adapter.signCosigns([{witness_index:0}],{},entry);
    cycle.outbox.stage({kind:'cosign',...entry},signed,now);
    await cycle.run({mode:'devnet',cosign:false},adapter,()=>now);
    assert.equal(state.sent.length,0);assert.equal(cycle.outbox.list().length,1);
    state.slot=1601n;now+=15000;state.seconds=2015n;
    await cycle.run({mode:'devnet',cosign:true},adapter,()=>now);
    assert.equal(state.sent.length,0,'already-signed work cannot bypass the public slot deadline');
    adapter.observe=async()=>({state:'finalized',confirmation:{slot:'100',ringIndex:0}});
    await cycle.run({mode:'devnet',cosign:false},adapter,()=>now);
    assert.equal(cycle.outbox.list().length,0,'a prior accepted transaction still settles after crank shutdown');
    assert.equal(state.sent.length,0);assert.equal(state.signed.length,1);
  } finally {store.close();}
});
