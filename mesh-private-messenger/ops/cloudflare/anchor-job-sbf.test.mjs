import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressEncoder, getBase58Encoder, getTransactionDecoder, getSignatureFromTransaction } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { anchorTestStorage } from './anchor-test-support.mjs';
import { runAnchorJob } from './anchor-job.mjs';

test('the scheduled writer posts, records and cosigns actual SBF accounts through its production adapters', {
  skip:!process.env.MORSE_ANCHOR_SBF_BRIDGE || !process.env.MORSE_ANCHOR_WORK_PATH,timeout:120_000,
},async()=> {
  const fixtures=JSON.parse(await readFile(process.env.MORSE_ANCHOR_WORK_PATH,'utf8'));
  const payer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(41));
  const authority=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(42));
  const secret=(seed,signer)=>Buffer.concat([Buffer.alloc(32,seed),Buffer.from(getAddressEncoder().encode(signer.address))]).toString('hex');
  for(const fixture of fixtures.flatMap(value=>[false,true].map(attendance=>({...value,attendance})))) {
    const child=spawn(process.env.MORSE_ANCHOR_SBF_BRIDGE,[],{stdio:['pipe','pipe','inherit']});
    const done=new Promise((resolve,reject)=>{child.once('exit',code=>code===0?resolve():reject(new Error(`bridge exit ${code}`)));child.once('error',reject);});
    done.catch(()=>{});
    const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
    let queue=Promise.resolve();
    const call=value=> {
      const result=queue.then(async()=> {child.stdin.write(JSON.stringify(value)+'\n');const line=await lines.next();assert.equal(line.done,false);return JSON.parse(line.value);});
      queue=result.catch(()=>{});return result;
    };
    const storage=anchorTestStorage();
    try {
      const setup=await call({method:'initialize',version:fixture.version,service:fixture.service_key,witness:fixture.witness_key,payer:payer.address,authority:authority.address,attendance:fixture.attendance});
      const statuses=new Map(), receipts=[], sent=[];
      const fetcher=async(url,options)=> {
        assert.equal(url,'https://rpc.example/');
        const request=parseJsonWithBigInts(options.body), args=request.params;
        let result;
        switch(request.method) {
          case 'getGenesisHash':result='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';break;
          case 'getAccountInfo': {
            result=await call({method:'account',address:args[0],offset:Number(args[1].dataSlice.offset),length:Number(args[1].dataSlice.length)});
            result.context.slot=BigInt(result.context.slot);
            if(result.value) {result.value.lamports=BigInt(result.value.lamports);result.value.space=BigInt(result.value.space);}
            break;
          }
          case 'getBalance': {
            const account=await call({method:'account',address:args[0],offset:0,length:0});
            result={context:{slot:100n},value:BigInt(account.value.lamports)};break;
          }
          case 'getBlockTime':result=1791504000n;break;
          case 'getLatestBlockhash':result={context:{slot:100n},value:{...await call({method:'context'}),lastValidBlockHeight:1000n}};break;
          case 'getBlockHeight':result=100n;break;
          case 'getSignatureStatuses':result={context:{slot:100n},value:[statuses.get(args[0][0])??null]};break;
          case 'sendTransaction': {
            const signature=getSignatureFromTransaction(getTransactionDecoder().decode(Buffer.from(args[0],'base64')));
            const journal=storage.sql.exec('SELECT transaction_body FROM anchor_outbox').toArray().map(row=>JSON.parse(row.transaction_body));
            assert.ok(journal.some(row=>row.signature===signature && row.wire===args[0]),'signed wire must commit before RPC send');
            const execution=await call({method:'send',transaction:args[0]});
            assert.equal(execution.ok,true,JSON.stringify(execution));
            sent.push({signature,...execution});
            statuses.set(signature,{slot:100n,confirmationStatus:'finalized',confirmations:null,err:null});
            result=signature;break;
          }
          default:throw new Error(`unexpected RPC ${request.method}`);
        }
        return new Response(stringifyJsonWithBigInts({id:request.id,jsonrpc:'2.0',result}));
      };
      const directory={getByName:()=>({fetch:async(url,options)=> {
        assert.equal(options.headers.Authorization,'Bearer '+'11'.repeat(32));
        if(url.endsWith(`/anchor-candidate/${fixture.version}`))return Response.json(fixture.post);
        if(url.endsWith('/anchors')) {receipts.push(Buffer.from(options.body));return new Response(null,{status:201});}
        if(url.endsWith('/anchor-cosigns')) {
          const query=Buffer.from(options.body);
          const historical=await call({method:'account',address:setup.generation,offset:0,length:2752});
          assert.deepEqual(query.subarray(16),Buffer.from(historical.value.data[0],'base64'));
          return Response.json({...fixture.post,log_id:query.subarray(20,52).toString('hex'),generation:7,ring_index:0,cosigns:[fixture.native]});
        }
        throw new Error(`unexpected directory operation ${url}`);
      }})};
      const env={MORSE_ANCHOR_MODE:'devnet',MORSE_COSIGN_CRANK:'on',
        MORSE_ANCHOR_CONFIG:JSON.stringify({program:setup.program,logName:'morse-main',version:fixture.version,serviceKey:fixture.service_key,
          origin:fixture.version===2?'morseapp.io/log/main/v2':'',rpcUrl:'https://rpc.example/'}),
        MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX:secret(41,payer),MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX:secret(42,authority),
        MESSENGER_DELIVERY_INTERNAL_TOKEN:'11'.repeat(32),DIRECTORY:directory};
      for(let index=0;index<3;index++) {
        const report=await runAnchorJob({storage},env,{fetcher,clock:()=>1791504000000+index*15000});
        assert.deepEqual(report.issues,[],JSON.stringify(report));
      }
      assert.equal(sent.length,2);assert.equal(receipts.length,1);
      assert.equal(sent[0].count,1);assert.equal(sent[1].count,1);assert.equal(sent[1].native_bitmap,1);
      const expected=Buffer.from(fixture.receipt,'hex');
      expected.set(getBase58Encoder().encode(sent[0].signature),56);
      assert.deepEqual(receipts[0],expected);
      assert.equal(storage.sql.exec('SELECT count(*) AS count FROM anchor_outbox').one().count,0);
      assert.equal((await runAnchorJob({storage},{MORSE_ANCHOR_MODE:'off'},{fetcher:()=>{throw new Error('off must not access RPC');}})).mode,'off');
    } finally {storage.close();child.stdin.end();await done;}
  }
});
