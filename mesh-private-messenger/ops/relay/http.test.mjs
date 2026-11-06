import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { request } from 'node:http';
import { createRelayHttpServer, createIpLimiter } from './http.mjs';

async function fixture(t,options={}) {
  const received=[];const server=createRelayHttpServer({submit:async bytes=>{received.push(bytes);return {schema_version:1,status:'queued',proof_hash:'ab'.repeat(32),finder:'finder',duplicate:false};},...options});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
  return {server,received,async post(body,headers={},url='/v1/fork-evidence',method='POST'){
    return new Promise((resolve,reject)=>{const req=request({host:'127.0.0.1',port:server.address().port,path:url,method,headers:{'Content-Type':'application/octet-stream',...headers}},res=>{
      const chunks=[];res.on('data',value=>chunks.push(value));res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks)),headers:res.headers}));
    });req.on('error',reject);if(Array.isArray(body)){for(const part of body)req.write(part);req.end();}else req.end(body);});
  }};
}

test('HTTP accepts bounded binary evidence without forwarding request fields as plans or wallet input',async t=>{
  const f=await fixture(t),bytes=Buffer.alloc(8192,7),result=await f.post(bytes,{'x-wallet':'untrusted','x-program':'untrusted'});
  assert.equal(result.status,202);assert.deepEqual(f.received,[bytes]);assert.equal(result.headers['cache-control'],'no-store');
  assert.equal((await f.post(bytes,{},'/v1/fork-evidence?wallet=other')).status,404);
  assert.equal((await f.post('',{},'/v1/fork-evidence','GET')).status,405);
});

test('oversize, empty, encoded and text bodies are refused before native verification',async t=>{
  const f=await fixture(t);
  assert.equal((await f.post(Buffer.alloc(8193))).status,413);
  assert.equal((await f.post([Buffer.alloc(4096),Buffer.alloc(4097)])).status,413);
  assert.equal((await f.post('')).status,400);
  assert.equal((await f.post('{}',{'Content-Type':'application/json'})).status,415);
  assert.equal((await f.post('x',{'Content-Encoding':'gzip'})).status,415);
  assert.equal(f.received.length,0);
});

test('per-IP limits ignore spoofed forwarding headers and keep rate state bounded',async t=>{
  let now=0;const limiter=createIpLimiter({now:()=>now,capacity:2,perMinute:2,maxClients:2});
  const f=await fixture(t,{limiter});
  assert.equal((await f.post('x',{'x-forwarded-for':'192.0.2.1'})).status,202);
  assert.equal((await f.post('x',{'x-forwarded-for':'192.0.2.2'})).status,202);
  const limited=await f.post('x',{'x-forwarded-for':'192.0.2.3'});assert.equal(limited.status,429);assert.equal(limited.headers['retry-after'],'60');
  assert.equal(limiter.take('second'),true);assert.equal(limiter.take('third'),false);
  now=60000;assert.equal(limiter.take('third'),true);assert.equal((await f.post('x')).status,202);
  now=1;assert.equal(limiter.take('third'),false);
});

test('HTTP reports Mesh outages generically and paid receipts as settled',async t=>{
  const down=await fixture(t,{submit:async()=>{throw new Error('secret/provider/file');}});
  const result=await down.post('x');assert.equal(result.status,503);assert.ok(!JSON.stringify(result.body).includes('secret'));
  const paid=await fixture(t,{submit:async()=>({schema_version:1,status:'settled',proof_hash:'ab'.repeat(32),finder:'winner'})});
  assert.equal((await paid.post('x')).status,200);
});

test('HTTP bounds concurrent admissions and cancels a disconnected submitter',async t=>{
  let release,started,aborted;const entering=new Promise(resolve=>{started=resolve;});const cancellation=new Promise(resolve=>{aborted=resolve;});
  const f=await fixture(t,{maxInFlight:1,submit:async(_bytes,{signal})=>{signal.addEventListener('abort',aborted,{once:true});started();return new Promise(resolve=>{release=resolve;});}});
  const controller=new AbortController();const active=fetch(`http://127.0.0.1:${f.server.address().port}/v1/fork-evidence`,{method:'POST',body:'x',headers:{'Content-Type':'application/octet-stream'},signal:controller.signal});
  const abortedFetch=assert.rejects(active);await entering;assert.equal((await f.post('x')).status,503);
  controller.abort();await abortedFetch;await cancellation;release({status:'queued'});
});

test('slow bodies and stalled admissions expire with bounded errors and cancellation',{timeout:2000},async t=>{
  const slow=await fixture(t,{bodyTimeoutMs:20});
  const body=await new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:slow.server.address().port,path:'/v1/fork-evidence',method:'POST',headers:{'Content-Type':'application/octet-stream','Content-Length':'2'}},res=>{
      res.resume();res.on('end',()=>resolve(res.statusCode));
    });req.on('error',reject);req.write('x');
  });
  assert.equal(body,408);assert.equal(slow.received.length,0);
  let cancelled=false;
  const busy=await fixture(t,{admissionTimeoutMs:20,submit:async(_bytes,{signal})=>new Promise((_,reject)=>signal.addEventListener('abort',()=>{cancelled=true;reject(new Error('cancelled'));},{once:true}))});
  assert.equal((await busy.post('x')).status,503);assert.equal(cancelled,true);
});
