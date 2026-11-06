import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { prepareRelayTransactions, relayStepMessage, signRelayStep } from './transactions.mjs';
import { connectRelayRpc } from './rpc.mjs';

const path=process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH;
if(!path)throw new Error('Run scripts/prove-relay-writer.sh for fresh Mesh plans');
const plans=(await readFile(path,'utf8')).trim().split('\n').map(JSON.parse),plan=plans[0];
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const prepared=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex}),step=prepared.preparation[0];
const slot=9007199254741011n,life={blockhash:plan.program,lastValidBlockHeight:9007199254741000n};
const genesisHash='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const config={urls:['https://a.example/?token=secret','https://b.example/','https://c.example/'],genesisHash};
const context=value=>({context:{slot},value});
const status=(value=null)=>context([value]);
const finalized=(err=null)=>({slot,confirmationStatus:'finalized',confirmations:null,err});
function fixture(custom=()=>undefined){
  const calls=[];
  const fetcher=async (url,init)=>{
    const request=parseJsonWithBigInts(init.body),provider=new URL(url).hostname[0];calls.push({provider,...request});
    assert.equal(init.redirect,'error');
    let result=await custom(request,provider);
    if(result===undefined){
      if(request.method==='getGenesisHash')result=genesisHash;
      else if(request.method==='getLatestBlockhash')result=context(life);
      else if(request.method==='getFeeForMessage')result=context(5000n);
      else if(request.method==='getMinimumBalanceForRentExemption')result=1000n+request.params[0]*10n;
      else if(request.method==='getBlockHeight')result=life.lastValidBlockHeight+1n;
      else if(request.method==='getSlot')result=slot;
      else if(request.method==='getFirstAvailableBlock')result=1n;
      else if(request.method==='getSignatureStatuses')result=status();
      else if(request.method==='getTransaction')result=null;
      else throw new Error(`Unexpected ${request.method}`);
    }
    return new Response(stringifyJsonWithBigInts({jsonrpc:'2.0',id:request.id,result}));
  };
  return {calls,fetcher};
}
function metadata(signed,info,{fee=5000n,err=null,refund=0n,rent=0n}={}){
  const pre=info.accountKeys.map(()=>100000000n),post=[...pre];post[0]-=fee+rent;post[0]+=refund;
  if(rent)post[info.accountKeys.indexOf(info.rentAllocations[0].address)]+=rent;
  if(refund)post[info.accountKeys.indexOf(info.refundAccount)]-=refund;
  return {slot,version:0n,transaction:[signed.wire,'base64'],meta:{err,fee,preBalances:pre,postBalances:post,
    loadedAddresses:{readonly:info.loadedAddresses.readonly,writable:info.loadedAddresses.writable}}};
}

test('quotes require independent matching blockhash, exact-message fee and full allocation rent without refund credits',async ()=>{
  const f=fixture((request,provider)=>request.method==='getFeeForMessage'&&provider==='c'?context(1n):undefined);
  const chain=await connectRelayRpc(config,f.fetcher),quote=await chain.quote(step);
  assert.equal(quote.blockhash,life.blockhash);assert.equal(quote.lastValidBlockHeight,life.lastValidBlockHeight.toString());
  const space=plan.rent_allocations.find(value=>value.step==='initialize').space;
  assert.equal(quote.maxDebitLamports,(6000n+BigInt(space)*10n).toString());
  assert.equal(quote.messageHash,relayStepMessage(step,life).messageHash);
  const fee=f.calls.find(value=>value.method==='getFeeForMessage');
  assert.equal(fee.params[0],relayStepMessage(step,life).messageBase64);
  assert.deepEqual(fee.params[1],{commitment:'finalized',minContextSlot:slot});
  assert.equal((await chain.quote(prepared.cleanup[0])).maxDebitLamports,'5000');
  const old=structuredClone(plan);delete old.rent_allocations;
  await assert.rejects(chain.quote(prepareRelayTransactions(old,{...old,proofHex:old.proof_hex}).preparation[0]),/allocation/i);
  for(const method of ['getLatestBlockhash','getFeeForMessage','getMinimumBalanceForRentExemption']){
    const broken=fixture((request,provider)=>request.method===method?(method==='getLatestBlockhash'?context({...life,lastValidBlockHeight:BigInt(provider.charCodeAt(0))}):method==='getFeeForMessage'?context(BigInt(provider.charCodeAt(0))):BigInt(provider.charCodeAt(0))):undefined);
    await assert.rejects((await connectRelayRpc(config,broken.fetcher)).quote(step),/quorum/i);
  }
});

test('broadcast preserves journal bytes and context, disables RPC retries, and tolerates one unavailable provider',async ()=>{
  const signed=await signRelayStep(step,signer,life),f=fixture((request,provider)=>{
    if(request.method==='sendTransaction'){
      assert.equal(request.params[0],signed.wire);
      assert.deepEqual(request.params[1],{encoding:'base64',skipPreflight:false,preflightCommitment:'finalized',maxRetries:0n,minContextSlot:BigInt(signed.minContextSlot)});
      if(provider==='c')throw new Error('secret upstream error');
      return signed.signature;
    }
  });
  const chain=await connectRelayRpc(config,f.fetcher);
  assert.deepEqual(await chain.broadcast(signed),{accepted:2});
  assert.deepEqual(await chain.broadcast(signed),{accepted:2});
});

test('finalized metadata is bound to exact signed bytes and includes gross rent and fees even with cleanup refunds',async ()=>{
  for(const [current,charges] of [[step,{rent:24000000n}],[prepared.cleanup[0],{refund:24000000n}],
    [step,{err:{InstructionError:[0n,'Custom']}}]]){
    const signed=await signRelayStep(current,signer,life),info=relayStepMessage(current,life),tx=metadata(signed,info,charges);
    const f=fixture((request,provider)=>{
      if(request.method==='getSignatureStatuses')return status(finalized(charges.err??null));
      if(request.method==='getTransaction')return provider==='c'?{...tx,transaction:['changed','base64']}:tx;
    });
    const result=await (await connectRelayRpc(config,f.fetcher)).observe(current,signed);
    assert.deepEqual(result,{state:'finalized',success:!charges.err,debitLamports:(5000n+(charges.rent??0n)).toString(),slot:slot.toString()});
    const call=f.calls.find(value=>value.method==='getTransaction');
    assert.deepEqual(call.params,[signed.signature,{commitment:'finalized',encoding:'base64',maxSupportedTransactionVersion:0n}]);
  }
});

test('unknown, inconsistent, stale and unfinalized metadata never settle a journal reservation',async ()=>{
  const signed=await signRelayStep(step,signer,life),info=relayStepMessage(step,life),tx=metadata(signed,info,{rent:30n});
  const variants=[null,{...tx,slot:slot-1n},{...tx,transaction:[signed.wire+'\n','base64']},
    {...tx,meta:{...tx.meta,loadedAddresses:{writable:[plan.program],readonly:[]}}},
    {...tx,meta:{...tx.meta,fee:-1n}}, {...tx,meta:{...tx.meta,postBalances:tx.meta.postBalances.slice(1)}},
    {...tx,meta:{...tx.meta,postBalances:tx.meta.preBalances}},
    {...tx,meta:{...tx.meta,err:'changed'}}];
  for(const bad of variants){
    const f=fixture(request=>request.method==='getSignatureStatuses'?status(finalized()):request.method==='getTransaction'?bad:undefined);
    assert.equal((await (await connectRelayRpc(config,f.fetcher)).observe(step,signed)).state,'pending');
  }
  const f=fixture(request=>request.method==='getSignatureStatuses'?status({...finalized(),confirmationStatus:'confirmed',confirmations:1n}):undefined);
  assert.equal((await (await connectRelayRpc(config,f.fetcher)).observe(step,signed)).state,'pending');
  assert.equal(f.calls.filter(value=>value.method==='getTransaction').length,0);
});

test('expiry requires height then fresh history and a Mesh effect check; pruned history cannot prove no fees',async ()=>{
  const signed=await signRelayStep(step,signer,life),f=fixture(),chain=await connectRelayRpc(config,f.fetcher);
  const barrier=await chain.observe(step,signed);
  assert.equal(barrier.state,'expiry-barrier');
  const reads=[];
  const expired=await chain.observe(step,signed,async request=>{reads.push(request);return {state:'absent',slot:slot.toString()};});
  assert.deepEqual(expired,{state:'expired',slot:slot.toString(),blockHeight:(life.lastValidBlockHeight+1n).toString()});
  assert.deepEqual(reads,[{minContextSlot:slot.toString()}]);
  assert.equal((await chain.observe(step,signed,async()=>({state:'present',slot:slot.toString()}))).state,'effect');
  await assert.rejects(chain.observe(step,signed,async()=>({state:'absent',slot:'0'})),/context/i);
  const pruned=fixture(request=>request.method==='getFirstAvailableBlock'?BigInt(signed.minContextSlot)+1n:undefined);
  const result=await (await connectRelayRpc(config,pruned.fetcher)).observe(step,signed,async()=>({state:'absent',slot:slot.toString()}));
  assert.equal(result.state,'pending','missing historical coverage cannot release fee reservations');
  const calls=f.calls.filter(value=>value.provider==='a').map(value=>value.method);
  const height=calls.indexOf('getBlockHeight');
  assert.equal(calls[height+1],'getSlot');assert.equal(calls[height+2],'getSignatureStatuses');
  assert.ok(calls.indexOf('getTransaction',height)>height);
});

test('a packet landing during the expiry barrier wins, and unequal or regressing observations cannot authorize expiry',async ()=>{
  const signed=await signRelayStep(step,signer,life),tx=metadata(signed,relayStepMessage(step,life)),counts={};
  const f=fixture((request,provider)=>{
    if(request.method==='getSignatureStatuses'){counts[provider]=(counts[provider]??0)+1;return counts[provider]===1?status():status(finalized());}
    if(request.method==='getTransaction')return tx;
  });
  assert.equal((await (await connectRelayRpc(config,f.fetcher)).observe(step,signed)).state,'finalized');
  for(const mode of ['equal','regress','outage']){
    const counts={};const broken=fixture((request,provider)=>{
      if(mode==='outage'&&provider!=='a'&&request.method!=='getGenesisHash')throw new Error('offline');
      if(mode==='equal'&&request.method==='getBlockHeight')return life.lastValidBlockHeight;
      if(mode==='regress'&&request.method==='getSignatureStatuses'){
        counts[provider]=(counts[provider]??0)+1;
        return counts[provider]===1?status():{context:{slot:slot-1n},value:[null]};
      }
    });
    assert.equal((await (await connectRelayRpc(config,broken.fetcher)).observe(step,signed)).state,'pending');
  }
});

test('provider identity, bounds and transport failures are enforced without leaking endpoint secrets',async ()=>{
  const f=fixture();
  for(const urls of [['https://a.example','https://a.example/other','https://b.example'],
    ['http://a.example','https://b.example','https://c.example'],['https://a.example/#x',...config.urls.slice(1)]]){
    await assert.rejects(connectRelayRpc({...config,urls},f.fetcher));
  }
  for(const mode of ['cluster','id','oversize','redirect']){
    const fetcher=async (_,init)=>{
      const r=parseJsonWithBigInts(init.body);
      if(mode==='oversize')return new Response('x'.repeat(262145));
      if(mode==='redirect')return new Response(null,{status:302});
      return Response.json({jsonrpc:'2.0',id:mode==='id'?'wrong':r.id,result:'wrong-cluster'});
    };
    await assert.rejects(connectRelayRpc(config,fetcher),error=>!error.message.includes('secret'));
  }
  const body=()=>new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('{'));}}));
  const timer=setInterval(()=>{},1000);
  try{await assert.rejects(connectRelayRpc({...config,timeoutMs:30},body),/quorum/i);}
  finally{clearInterval(timer);}
});
