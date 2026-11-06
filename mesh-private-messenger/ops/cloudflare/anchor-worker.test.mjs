import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressDecoder, getAddressEncoder, getTransactionDecoder } from '@solana/kit';

test('the production Worker bundle signs with non-extractable wallets and bootstraps enabled anchor jobs',async()=> {
  const fixtures=JSON.parse(await readFile(new URL('../../tests/fixtures/fork-v1/anchor-checkpoints.json',import.meta.url),'utf8'));
  const payer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(41));
  const authority=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(42));
  const secret=(seed,signer)=>Buffer.concat([Buffer.alloc(32,seed),Buffer.from(getAddressEncoder().encode(signer.address))]).toString('hex');
  const address=byte=>getAddressDecoder().decode(new Uint8Array(32).fill(byte));
  const bundle=await build({stdin:{resolveDir:fileURLToPath(new URL('.',import.meta.url)),sourcefile:'anchor-worker-proof.mjs',contents:`
    import worker from './worker.mjs';
    export * from './worker.mjs';
    import {anchorWriterConfig} from './anchor-config.mjs';
    import {signAnchorPost} from './anchor-transactions.mjs';
    export default {async fetch(request,env) {
      const input=await request.json();
      if(input.operation==='cron') {
        const calls=[],promises=[];
        await worker.scheduled({}, {...env,MORSE_ANCHOR_MODE:input.mode,JOBS:{getByName(name){
          return {async register(kind,id){calls.push({name,kind,id});}};
        }}}, {waitUntil(promise){promises.push(promise);}});
        await Promise.all(promises);return Response.json(calls);
      }
      const config=await anchorWriterConfig({...env,MORSE_ANCHOR_CONFIG:JSON.stringify(input.config)});
      const signed=await signAnchorPost(input.material,{...input.accounts,feePayer:config.feePayer,anchorAuthority:config.anchorAuthority},
        {blockhash:input.blockhash,lastValidBlockHeight:18446744073709551615n});
      return Response.json({signed,extractable:[config.feePayer.keyPair.privateKey.extractable,config.anchorAuthority.keyPair.privateKey.extractable]});
    }};`},bundle:true,write:false,platform:'browser',format:'esm',conditions:['workerd','browser'],
    external:['cloudflare:workers','node:*'],minify:true,
    // Match Wrangler's nodejs_compat mapping for Kit's workerd exports.
    alias:Object.fromEntries(builtinModules.filter(name=>!name.startsWith('node:')).map(name=>[name,`node:${name}`]))});
  const mf=new Miniflare(convertV4MiniflareOptions({name:'morse-anchor-worker-proof',compatibilityDate:'2026-09-18',
    compatibilityFlags:['nodejs_compat'],modules:[{type:'ESModule',path:'entry.mjs',contents:bundle.outputFiles[0].text}],
    bindings:{MORSE_ANCHOR_MODE:'devnet',MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX:secret(41,payer),MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX:secret(42,authority)}}));
  const request=async input=> {
    const response=await mf.dispatchFetch('http://test/',{method:'POST',body:JSON.stringify(input)});
    assert.equal(response.status,200,await response.clone().text());return response.json();
  };
  try {
    for(const fixture of fixtures) {
      const wire=Buffer.from(fixture.wire,'hex'),statement=Buffer.from(fixture.statement,'hex');
      const header=Buffer.from('01003000ffff1000ffff70000000ffff','hex');header.writeUInt16LE(statement.length,12);
      const serviceKey=wire.subarray(92,124).toString('hex');
      const result=await request({operation:'sign',config:{program:address(3),logName:'morse-main',version:fixture.version,
        serviceKey,origin:fixture.version===2?'morseapp.io/log/main/v2':'',rpcUrl:'https://rpc.example/'},
        accounts:{program:address(3),log:address(4),ring:address(5)},blockhash:address(7),
        material:{checkpoint:fixture.wire,service_key:serviceKey,
          ed25519:Buffer.concat([header,wire.subarray(92,124),wire.subarray(124),statement]).toString('hex'),
          instruction:Buffer.concat([Buffer.from([3,0,0]),wire]).toString('hex')}});
      assert.deepEqual(result.extractable,[false,false]);
      assert.equal(result.signed.lastValidBlockHeight,'18446744073709551615');
      const transaction=getTransactionDecoder().decode(Buffer.from(result.signed.wire,'base64'));
      for(const signer of [payer,authority])assert.equal(await crypto.subtle.verify('Ed25519',signer.keyPair.publicKey,
        transaction.signatures[signer.address],transaction.messageBytes),true);
    }
    assert.deepEqual(await request({operation:'cron',mode:'off'}),[]);
    for(const mode of ['devnet','mainnet'])assert.deepEqual(await request({operation:'cron',mode}),[{name:'anchor',kind:'anchor',id:'0'}]);
    const config=JSON.parse(await readFile(new URL('./wrangler.jsonc',import.meta.url),'utf8'));
    assert.deepEqual(config.triggers.crons,['* * * * *']);
  } finally {await mf.dispose();}
});
