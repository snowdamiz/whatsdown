import assert from 'node:assert/strict';
import test from 'node:test';
import { drainNativeOutbox, parseNativeOutbox } from './native-outbox.ts';
const u16=(n:number)=>Uint8Array.of(n>>>8,n&255);
const u32=(n:number)=>Uint8Array.of(n>>>24,n>>>16&255,n>>>8&255,n&255);
const u64=(n:bigint)=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
const concat=(parts:Uint8Array[])=>Uint8Array.from(parts.flatMap(b=>Array.from(b)));
const vectors=(parts:Uint8Array[])=>concat(parts.flatMap(b=>[u32(b.length),b]));
const pack=(parts:Uint8Array[])=>concat([u32(parts.length),vectors(parts)]);
const id=(n:number)=>new Uint8Array(16).fill(n);
const parts=(status=0,accepted=0,remaining=0,postage:Uint8Array[]=[],failures:Uint8Array[]=[])=>[
  Uint8Array.of(1,79,66,88),Uint8Array.of(status),u16(accepted),u16(remaining),pack(postage),pack(failures),
];
const record=(status=0,accepted=0,remaining=0,postage:Uint8Array[]=[],failures:Uint8Array[]=[])=>pack(parts(status,accepted,remaining,postage,failures));

test('outbox invokes one typed native operation with only path and explicit free-retry mode',async()=>{
  const original=globalThis.fetch;let fetches=0;
  globalThis.fetch=async()=>{fetches++;throw Error('JS HTTP is forbidden');};
  try {
    for(const retry of [false,true]) {
      let calls=0;
      const result=await drainNativeOutbox('/native/мorse.db',retry,async input=>{
        calls++;
        assert.deepEqual(input,vectors([new TextEncoder().encode('/native/мorse.db'),Uint8Array.of(retry?1:0)]));
        return record(2,1,2,[id(3)],[concat([u16(410),u64(1_700_000_000_000n)])]);
      });
      assert.equal(calls,1);assert.equal(fetches,0);
      assert.equal(result.status,2);assert.equal(result.accepted,1);assert.equal(result.remaining,2);
      assert.deepEqual(result.postage,[id(3)]);assert.deepEqual(result.failures,[{status:410,queuedAt:1_700_000_000_000}]);
    }
  } finally {globalThis.fetch=original;}
});

test('unknown native outcomes and errors never select another envelope or retry automatically',async()=>{
  let calls=0;
  const result=await drainNativeOutbox('/native/morse.db',false,async()=>{calls++;return record(2,0,1);});
  assert.equal(result.remaining,1);assert.equal(calls,1);
  await assert.rejects(drainNativeOutbox('/native/morse.db',false,async()=>{calls++;throw Error('outbox_identity_changed');}),/outbox_identity_changed/);
  assert.equal(calls,2);
});

test('outbox presentation strictly rejects unsupported versions, counts, trailing bytes and hostile rows',()=>{
  const invalid:Uint8Array[]=[record().slice(0,-1),concat([record(),Uint8Array.of(0)]),new Uint8Array(8750),
    pack([Uint8Array.of(2,79,66,88),...parts().slice(1)]),record(4),record(0,257),record(0,0,257),
    record(0,0,1,[new Uint8Array(15)]),record(0,0,2,[id(1),id(1)]),record(0,0,0,[],[new Uint8Array(9)]),
    record(0,0,0,[],[concat([u16(503),u64(0n)])]),record(0,0,0,[],[concat([u16(410),u64(9_007_199_254_740_992n)])]),
    record(0,0,0,Array.from({length:257},()=>id(1))),pack(parts().slice(0,5)),pack([...parts(),new Uint8Array()]),
    pack([parts()[0]!,Uint8Array.of(0,0),...parts().slice(2)]),pack([parts()[0]!,parts()[1]!,new Uint8Array(1),...parts().slice(3)]),
  ];
  for(const input of invalid) assert.throws(()=>parseNativeOutbox(input),/invalid_outbox_status/);
  for(const status of [0,1,2,3]) assert.equal(parseNativeOutbox(record(status)).status,status);
  assert.deepEqual(parseNativeOutbox(record(0,0,0,[],[concat([u16(400),u64(0n)])])).failures,[{status:400,queuedAt:0}]);
});

test('native outbox presentation supports the full bounded queue without numeric truncation',()=>{
  const ids=Array.from({length:256},(_,i)=>{const value=id(0);value[0]=i;return value;});
  const failures=Array.from({length:256},()=>concat([u16(410),u64(9_007_199_254_740_991n)]));
  assert.equal(parseNativeOutbox(record(0,0,256,ids)).postage.length,256);
  assert.equal(parseNativeOutbox(record(0,0,0,[],failures)).failures[255]!.queuedAt,9_007_199_254_740_991);
  assert.equal(parseNativeOutbox(record(0,256)).accepted,256);
});

test('invalid path framing fails locally before calling native code',async()=>{
  let calls=0;
  for(const path of ['', '/native/\0morse.db','x'.repeat(4097),'é'.repeat(2049)]) {
    await assert.rejects(drainNativeOutbox(path,false,async()=>{calls++;return record();}),/invalid_database_path/);
  }
  assert.equal(calls,0);
});
