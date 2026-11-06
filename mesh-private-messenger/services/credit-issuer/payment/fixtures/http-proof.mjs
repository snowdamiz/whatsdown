// Local-only integration: actual native Mesh server, PostgreSQL, public BR1,
// SDK-signed payments and bundled real SPL/ATA SBF. No live RPC or real funds.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import {createRequire} from 'node:module';
import {spawn, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {issuerIngressRequest} from '../../../../ops/cloudflare/issuer-ingress.mjs';
const product=path.resolve(import.meta.dirname,'../../../..');
const kit=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/kit');
const work=process.env.MORSE_HTTP_WORK;
const env={...process.env};
const admin='issuer-proof-admin-'+'a'.repeat(32), purchase='issuer-proof-purchase-'+'b'.repeat(32);
let issuer,issuerOutput='',admissionAllowed=false,coreAdmitted=false,rpcOffline=false,wrongRpcId=false;
const calls={announce:0,evidence:0,admit:0,denied:0,transaction:0,oracle:0};
const payments=new Map();
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const readHex=async file=>Buffer.from((await fs.readFile(file,'utf8')).trim(),'hex');
const callFixture=(operation,output=work,asset=0)=>{
 const result=spawnSync(env.MORSE_HTTP_CLIENT_BIN,[],{env:{...env,MORSE_HTTP_OPERATION:operation,MORSE_HTTP_OUTPUT:output,MORSE_HTTP_ASSET:String(asset)},encoding:'utf8',timeout:90000});
 assert.equal(result.status,0,`native fixture ${operation}: ${result.stderr||result.error||'failed'}`);
 assert.equal(result.stdout.trim(),'issuer-http-fixture:ok');
};
const sql=text=>{const result=spawnSync(env.MORSE_HTTP_PSQL,['-At','-v','ON_ERROR_STOP=1','-c',text],{env,encoding:'utf8'});assert.equal(result.status,0,result.stderr);return result.stdout.trim();};
const listen=async server=>{server.listen(0,'127.0.0.1');await once(server,'listening');return `http://127.0.0.1:${server.address().port}`;};
const receive=async request=>{const rows=[];for await(const row of request)rows.push(row);return Buffer.concat(rows);};
const respond=(response,status,body)=>{response.writeHead(status,{'content-type':'application/octet-stream','cache-control':'no-store'});response.end(body);};
callFixture('bootstrap');
const seed=JSON.parse(await fs.readFile(path.join(work,'bootstrap.json'),'utf8'));
assert.equal(sql('SELECT count(*) FROM issuer_keys WHERE admitted_evidence IS NOT NULL'),'0');
const core=http.createServer(async(req,res)=>{try{
 assert.equal(req.headers.authorization,`Bearer ${admin}`);
 const body=await receive(req);
 if(req.url==='/internal/credits/issuers/announce'){
  calls.announce++;assert.equal(JSON.parse(body).leaf,seed.issuer);return respond(res,201,'{}');
 }
 if(req.url==='/internal/credits/issuers/evidence'){
  calls.evidence++;assert.equal(body.length,13);assert.equal(body.subarray(0,5).toString('hex'),'0143494b01');
  const previous=body.readBigUInt64BE(5);assert.ok(previous===0n||previous===1n);
  return respond(res,200,Buffer.from(previous===0n?seed.evidence0:seed.evidence1,'hex'));
 }
 if(req.url==='/internal/credits/issuers/cursor')return respond(res,200,coreAdmitted?Buffer.from(seed.checkpoint,'hex'):Buffer.alloc(0));
 if(req.url==='/internal/credits/issuers/admit'){
  calls.admit++;assert.equal(JSON.parse(body).evidence,coreAdmitted?seed.evidence1:seed.evidence0);
  if(!admissionAllowed){calls.denied++;return respond(res,503,'');}
  coreAdmitted=true;return respond(res,201,'{}');
 }
 respond(res,404,'');
 }catch(error){res.destroy(error);}});
const oracleAddress=kit.getAddressDecoder().decode(new Uint8Array(32).fill(91));
const rpc=http.createServer(async(req,res)=>{try{
 const request=JSON.parse(await receive(req));
 if(rpcOffline){res.writeHead(503);return res.end('unavailable');}
 let result;
 if(request.method==='getTransaction'){
  calls.transaction++;assert.deepEqual(request.params[1],{encoding:'base64',commitment:'finalized',maxSupportedTransactionVersion:0});
  const item=payments.get(request.params[0]);assert.ok(item,'RPC query must match a known signed payment');result=item.finalized?item.response.result:null;
 }else if(request.method==='getAccountInfo'){
  calls.oracle++;assert.equal(request.params[0],oracleAddress);assert.equal(request.params[1].commitment,'finalized');
  const data=Buffer.alloc(134);Buffer.from('22f123639d7ef4cd','hex').copy(data);data[40]=1;
  Buffer.from('ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d','hex').copy(data,41);
  data.writeBigInt64LE(20_000_000_000n,73);data.writeBigUInt64LE(1_000_000n,81);data.writeInt32LE(-8,89);
  const now=BigInt(Math.floor(Date.now()/1000));data.writeBigInt64LE(now,93);data.writeBigInt64LE(now-1n,101);data.writeBigUInt64LE(100000n,125);
  result={context:{slot:100000},value:{data:[data.toString('base64'),'base64'],owner:'rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp',executable:false,lamports:2000000,rentEpoch:0,space:134}};
 }else throw Error('unexpected RPC method');
 res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:wrongRpcId?request.id+1:request.id,result}));
 }catch(error){res.destroy(error);}});
const coreUrl=await listen(core),rpcUrl=await listen(rpc);
// Run the same bounded Worker ingress mapper over a real local HTTP hop.
const gateway=http.createServer(async(req,res)=>{try{
 const body=await receive(req);
 const input=new Request(coreUrl+req.url,{method:req.method,headers:req.headers,
  ...(req.method==='POST'?{body}:{} )});
 const mapped=await issuerIngressRequest(input);
 assert.ok(mapped instanceof Request,'issuer must use an allowed ingress route');
 assert.ok(!mapped.headers.has('cookie')&&!mapped.headers.has('x-forwarded-for'));
 const response=await fetch(mapped);
 respond(res,response.status,Buffer.from(await response.arrayBuffer()));
}catch(error){res.destroy(error);}});
const gatewayUrl=await listen(gateway);
const portProbe=http.createServer();const issuerUrl=await listen(portProbe);const port=portProbe.address().port;await new Promise(resolve=>portProbe.close(resolve));
Object.assign(env,{MORSE_CREDITS_MODE:'test',MESSENGER_CREDITS_PURPOSE:'test',MESSENGER_ISSUER_PORT:String(port),
 MESSENGER_CREDIT_USDC_MINT:'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',MESSENGER_CREDIT_SOLANA_RPC_URL:rpcUrl,
 MESSENGER_CREDIT_SOL_PRICE_ACCOUNT:oracleAddress,MESSENGER_DELIVERY_INTERNAL_URL:gatewayUrl,MESSENGER_CREDIT_ADMIN_TRANSPORT:'ingress',
 MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN:admin,MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN:purchase});
const pin=`outside ${seed.witness_key} Local test operator`;
env.MESSENGER_ISSUER_SECURITY_CONFIG=['3',seed.service_key,'33'.repeat(32),'16','1','1',pin,'-','0','https://credits.example','2','1','1',pin].join('\n');
const start=async()=>{
 issuer=spawn(env.CREDIT_ISSUER_BIN,[],{env,stdio:['ignore','pipe','pipe']});
 issuer.stdout.on('data',row=>issuerOutput+=row);issuer.stderr.on('data',row=>issuerOutput+=row);
 for(let attempt=0;attempt<100;attempt++){
  if(issuer.exitCode!==null)throw Error(`issuer exited: ${issuerOutput}`);
  try{const response=await fetch(issuerUrl+'/health');if(response.status===200)return;}catch{}
  await delay(50);
 }
 throw Error('issuer health did not become ready');
};
const stop=async()=>{if(issuer&&issuer.exitCode===null){const exited=once(issuer,'exit');issuer.kill('SIGKILL');await exited;}issuer=undefined;};
const post=async(route,body,token=purchase)=>{
 const response=await fetch(issuerUrl+'/internal/v1/credits/'+route,{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/octet-stream'},body});
 assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(response.headers.get('content-type'),'application/octet-stream');
 return {status:response.status,body:Buffer.from(await response.arrayBuffer())};
};
const paymentFor=async quote=>{
 const asset=quote[132],amount=quote.readBigUInt64BE(133);const address=bytes=>kit.getAddressDecoder().decode(bytes);
 const mint=kit.address(env.MESSENGER_CREDIT_USDC_MINT),token=kit.address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),system=kit.address('11111111111111111111111111111111'),ata=kit.address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
 const payer=await kit.createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));
 const destination=address(quote.subarray(68,100)),deposit=address(quote.subarray(36,68)),reference=address(quote.subarray(4,36));
 const source=asset===0?(await kit.getProgramDerivedAddress({programAddress:ata,seeds:[kit.getAddressEncoder().encode(payer.address),kit.getAddressEncoder().encode(token),kit.getAddressEncoder().encode(mint)]}))[0]:payer.address;
 const account=(address,role)=>({address,role});const data=Buffer.alloc(asset===0?10:12);
 if(asset===0){data[0]=12;data.writeBigUInt64LE(amount,1);data[9]=6;}else{data.writeUInt32LE(2,0);data.writeBigUInt64LE(amount,4);}
 const setup=asset===0?[{programAddress:ata,accounts:[account(payer.address,3),account(destination,1),account(deposit,0),account(mint,0),account(system,0),account(token,0)],data:Uint8Array.of(1)}]:[];
 const transfer={programAddress:asset===0?token:system,accounts:asset===0?[account(source,1),account(mint,0),account(destination,1),account(payer.address,3),account(reference,0)]:[account(payer.address,3),account(destination,1),account(reference,0)],data};
 let message=kit.createTransactionMessage({version:0});message=kit.setTransactionMessageFeePayerSigner(payer,message);
 message=kit.setTransactionMessageLifetimeUsingBlockhash({blockhash:address(new Uint8Array(32).fill(4)),lastValidBlockHeight:123n},message);
 message=kit.appendTransactionMessageInstructions([...setup,transfer],message);
 const transaction=await kit.signTransactionMessageWithSigners(message);
 let wire=kit.getTransactionEncoder().encode(transaction),fixturePayer=payer.address,fixtureSource=source,version=0;
 if(env.MORSE_HTTP_WALLET_BRIDGE){
  const wallet=spawnSync(env.MORSE_HTTP_WALLET_BRIDGE,[],{input:JSON.stringify({quote_hex:quote.toString('hex'),usdc_mint_hex:Buffer.from(kit.getAddressEncoder().encode(mint)).toString('hex')}),encoding:'utf8'});
  assert.equal(wallet.status,0,wallet.stderr);const signed=JSON.parse(wallet.stdout);wire=Buffer.from(signed.wire_hex,'hex');fixturePayer=address(Buffer.from(signed.address_hex,'hex'));
  fixtureSource=asset===0?(await kit.getProgramDerivedAddress({programAddress:ata,seeds:[kit.getAddressEncoder().encode(fixturePayer),kit.getAddressEncoder().encode(token),kit.getAddressEncoder().encode(mint)]}))[0]:fixturePayer;version='legacy';
 }
 const fixture={version,asset,payer:fixturePayer,mint,source:fixtureSource,destination,wire_hex:Buffer.from(wire).toString('hex')};
 const executed=spawnSync(env.MORSE_HTTP_PAYMENT_ORACLE,[],{input:JSON.stringify({fixture,prefund:0,block_time:Number(quote.readBigUInt64BE(144))}),encoding:'utf8'});
 assert.equal(executed.status,0,executed.stderr);const value=JSON.parse(executed.stdout),response=JSON.parse(value.response);
 for(const group of response.result.meta.innerInstructions)for(const row of group.instructions){row.data=kit.getBase58Decoder().decode(Buffer.from(row.data_hex,'hex'));delete row.data_hex;}
 const signature=kit.getBase58Decoder().decode(Buffer.from(wire).subarray(1,65)),signatureHex=Buffer.from(wire).subarray(1,65).toString('hex');
 payments.set(signature,{response,finalized:false});return {signature,signatureHex,response};
};

try{
 await start();
 const output=path.join(work,'usdc');await fs.mkdir(output);callFixture('prepare',output,0);
 const query=await readHex(path.join(output,'quote-request'));
 assert.equal((await post('quote',query,admin)).status,401,'admin authority cannot purchase');
 assert.equal((await post('quote',Buffer.from('{"paid":true}'))).status,400);
 for(let i=0;calls.denied===0&&i<100;i++)await delay(50);
 assert.ok(calls.denied>0,'production worker must reach denied core admission');
 assert.equal(sql('SELECT count(*) FROM issuer_keys WHERE admitted_evidence IS NOT NULL'),'0');
 assert.equal((await post('quote',query)).status,503,'local quote cannot precede core acknowledgment');
 console.log('issuer HTTP: core admission denial leaves local key inactive');
 admissionAllowed=true;
 let quoteResult;
 for(let i=0;i<80;i++){quoteResult=await post('quote',query);if(quoteResult.status===200)break;assert.equal(quoteResult.status,503);await delay(500);}
 assert.equal(quoteResult.status,200,'actual key worker retry must activate after core acknowledgment');
 assert.equal(sql('SELECT count(*) FROM issuer_keys WHERE admitted_evidence IS NOT NULL'),'1');
 assert.equal(quoteResult.body.length,292);await fs.writeFile(path.join(output,'quote'),quoteResult.body.toString('hex'));
 const payment=await paymentFor(quoteResult.body.subarray(4,228));await fs.writeFile(path.join(output,'signature'),payment.signatureHex);callFixture('issue',output);
 const request=await readHex(path.join(output,'issue-request'));
 assert.equal((await post('issue',request)).status,425);
 assert.equal(sql('SELECT count(*) FROM issuer_quotes WHERE issued_response IS NOT NULL'),'0');
 payments.get(payment.signature).finalized=true;wrongRpcId=true;assert.equal((await post('issue',request)).status,503);wrongRpcId=false;
 const results=await Promise.all(Array.from({length:4},()=>post('issue',request)));
 for(const result of results){assert.equal(result.status,200);assert.ok(result.body.equals(results[0].body),'concurrent retries must return identical signatures');}
 assert.equal(results[0].body.length,25670);await fs.writeFile(path.join(output,'response'),results[0].body.toString('hex'));
 callFixture('finalize',output);const firstHash=await fs.readFile(path.join(output,'tokens-hash'),'utf8');
 callFixture('finalize',output);assert.equal(await fs.readFile(path.join(output,'tokens-hash'),'utf8'),firstHash,'restoring the same inverse cannot create a second token value');
 assert.equal(sql('SELECT count(*) FROM issuer_quotes WHERE issued_response IS NOT NULL'),'1');
 const changed=Buffer.from(request);changed[36]^=1;assert.equal((await post('issue',changed)).status,409);
 const swapped=Buffer.concat([request.subarray(0,102),...Array.from({length:100},(_,i)=>request.subarray(102+(99-i)*259,102+(100-i)*259))]);assert.equal((await post('issue',swapped)).status,409);
 console.log('issuer HTTP: pending425, wrong RPC id rejected, concurrent paid100-token issuance verified');
 const transactionCalls=calls.transaction;await stop();rpcOffline=true;await start();
 const recovered=await post('issue',request);assert.equal(recovered.status,200);assert.ok(recovered.body.equals(results[0].body));
 const quoteReplay=await post('quote',query);assert.equal(quoteReplay.status,200);assert.ok(quoteReplay.body.equals(quoteResult.body));
 assert.equal(calls.transaction,transactionCalls,'committed retry must not need chain RPC');rpcOffline=false;
 console.log('issuer HTTP: hard process restart replays exact response during RPC outage');
 const solOutput=path.join(work,'sol');await fs.mkdir(solOutput);callFixture('prepare',solOutput,1);
 const solQuote=await post('quote',await readHex(path.join(solOutput,'quote-request')));assert.equal(solQuote.status,200);assert.equal(solQuote.body.readBigUInt64BE(137),25_000_000n);
 await fs.writeFile(path.join(solOutput,'quote'),solQuote.body.toString('hex'));
 const solPayment=await paymentFor(solQuote.body.subarray(4,228));await fs.writeFile(path.join(solOutput,'signature'),solPayment.signatureHex);callFixture('issue',solOutput,1);
 const solRequest=await readHex(path.join(solOutput,'issue-request'));assert.equal((await post('issue',solRequest)).status,425);
 const crossQuote=Buffer.from(solRequest);Buffer.from(payment.signatureHex,'hex').copy(crossQuote,36);assert.notEqual((await post('issue',crossQuote)).status,200);
 payments.get(solPayment.signature).finalized=true;const solResponse=await post('issue',solRequest);assert.equal(solResponse.status,200);
 await fs.writeFile(path.join(solOutput,'response'),solResponse.body.toString('hex'));callFixture('finalize',solOutput,1);
 assert.equal(sql('SELECT count(*) FROM issuer_quotes WHERE issued_response IS NOT NULL'),'2');
 assert.equal(sql('SELECT count(DISTINCT payment_signature) FROM issuer_quotes'),'2');
 assert.ok(calls.oracle>0);assert.ok(coreAdmitted);
 const report={schema_version:1,status:'passed',native_mesh_http:true,owned_postgresql:true,filesystem_storage_key:true,
  signed_payment_quotes:true,rust_wallet_sdk:Boolean(env.MORSE_HTTP_WALLET_BRIDGE),bounded_admin_ingress_http:true,lifecycle_denied_until_core_ack:true,pending_status:425,assets:['USDC','SOL'],tokens_finalized:200,concurrent_first_issuance_requests:4,
  hard_restart_exact_replay:true,replay_without_rpc:true,duplicate_blinding_restore_same_token:true,sdk:'@solana/kit8.4.0',
  payment_execution:'LiteSVM0.17 bundled System/SPL/ATA programs',blockhash_check:false,live_rpc:false,real_funds:false,calls};
 if(env.MORSE_HTTP_REPORT_PATH)await fs.writeFile(env.MORSE_HTTP_REPORT_PATH,JSON.stringify(report,null,2)+'\n');
 console.log('MORSE_ISSUER_HTTP_JSON='+JSON.stringify(report));
}finally{
 await stop();await Promise.all([new Promise(resolve=>gateway.close(resolve)),new Promise(resolve=>core.close(resolve)),new Promise(resolve=>rpc.close(resolve))]);
}
