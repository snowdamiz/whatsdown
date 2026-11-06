// Local fixture keys only. Independent Node SLIP0010 + official Kit wire oracle,
// followed by real System/SPL/ATA execution and compiled Mesh RPC verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,createPrivateKey,createPublicKey,verify,sign} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawn,spawnSync} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
const product=path.resolve(import.meta.dirname,'../../..');
const sdk=path.join(product,'packages/wallet-core');
const publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const kit=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/kit');
const bridge=process.env.WALLET_FIXTURE_BRIDGE||path.join(sdk,'target/debug/examples/wallet_fixture_bridge');
const oracle=process.env.WALLET_PAYMENT_ORACLE||path.join(product,'programs/target/debug/examples/credit_payment_fixture');
const address=bytes=>kit.getAddressDecoder().decode(bytes);
const SYSTEM=kit.address('11111111111111111111111111111111'),TOKEN=kit.address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),ATA=kit.address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const mint=address(Buffer.alloc(32,7)),hash=address(Buffer.alloc(32,4));
const call=value=>{const result=spawnSync(bridge,[],{input:JSON.stringify(value),encoding:'utf8'});assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);};
const derive=path=>{let node=createHmac('sha512','ed25519 seed').update(Buffer.alloc(32,1)).digest();for(const index of path){const child=Buffer.alloc(37);node.copy(child,1,0,32);child.writeUInt32BE(index+0x80000000,33);node=createHmac('sha512',node.subarray(32)).update(child).digest();}return node.subarray(0,32);};
const publicBytes=seed=>createPublicKey(createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'})).export({format:'der',type:'spki'}).subarray(-32);
const ata=async(owner,mint)=> (await kit.getProgramDerivedAddress({programAddress:ATA,seeds:[kit.getAddressEncoder().encode(owner),kit.getAddressEncoder().encode(TOKEN),kit.getAddressEncoder().encode(mint)]}))[0];
const run=(cmd,args,opts={})=>new Promise((resolve,reject)=>{const child=spawn(cmd,args,opts);let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));});
test('Rust wallet matches independent SLIP0010+Kit and actual Mesh accepts its SBF payments',{timeout:120000},async()=>{
 const seed=derive([44,501,0,0]),payer=await kit.createKeyPairSignerFromPrivateKeyBytes(seed);
 const known=call({bounty_count:256});assert.equal(known.address_hex,publicBytes(seed).toString('hex'));assert.equal(address(Buffer.from(known.address_hex,'hex')),payer.address);
 for(const [index,row] of known.bounties.entries()){assert.equal(row.index,index);assert.equal(row.address_hex,publicBytes(derive([44,501,2147483647,index])).toString('hex'));}
 assert.equal(new Set(known.bounties.map(row=>row.address_hex)).size,256);
 const cases=[],now=Math.floor(Date.now()/1000);
 for(const [caseIndex,spec] of [{asset:0,credits:100,prefund:0},{asset:0,credits:500,prefund:1},{asset:0,credits:2000,prefund:2039280},{asset:0,credits:100,existing:true},{asset:1,credits:100,amount:25000000n},{asset:1,credits:100,amount:9007199254740993n}].entries()){
  const asset=spec.asset,amount=spec.amount??BigInt(spec.credits)*50000n,deposit=address(Buffer.alloc(32,20+caseIndex)),reference=address(Buffer.alloc(32,40+caseIndex)),destination=asset===0?await ata(deposit,mint):deposit,source=asset===0?await ata(payer.address,mint):payer.address;
  const quote=Buffer.alloc(224);quote.set(Buffer.from('01435154','hex'));quote.fill(40+caseIndex,4,36);quote.fill(20+caseIndex,36,68);quote.set(kit.getAddressEncoder().encode(destination),68);if(asset===0)quote.fill(7,100,132);quote[132]=asset;quote.writeBigUInt64BE(amount,133);quote[141]=1;quote.writeUInt16BE(spec.credits,142);quote.writeBigUInt64BE(BigInt(now),144);quote.writeBigUInt64BE(BigInt(now+900),152);quote.fill(8,160,192);quote.fill(9,192);
  const actual=call({quote_hex:quote.toString('hex')});const wire=Buffer.from(actual.wire_hex,'hex');
  const account=(address,role)=>({address,role});const data=Buffer.alloc(asset===0?10:12);if(asset===0){data[0]=12;data.writeBigUInt64LE(amount,1);data[9]=6;}else{data.writeUInt32LE(2,0);data.writeBigUInt64LE(amount,4);}
  const setup=asset===0?[{programAddress:ATA,accounts:[account(payer.address,3),account(destination,1),account(deposit,0),account(mint,0),account(SYSTEM,0),account(TOKEN,0)],data:Uint8Array.of(1)}]:[];
  const transfer={programAddress:asset===0?TOKEN:SYSTEM,accounts:asset===0?[account(source,1),account(mint,0),account(destination,1),account(payer.address,3),account(reference,0)]:[account(payer.address,3),account(destination,1),account(reference,0)],data};
  let message=kit.createTransactionMessage({version:'legacy'});message=kit.setTransactionMessageFeePayerSigner(payer,message);message=kit.setTransactionMessageLifetimeUsingBlockhash({blockhash:hash,lastValidBlockHeight:123n},message);message=kit.appendTransactionMessageInstructions([...setup,transfer],message);
  const expected=await kit.signTransactionMessageWithSigners(message);
  // Rust SDK uses raw-address BTree order within each permission class;
  // Kit uses a different legal order. Reindex Kit's compiled instruction
  // references into Rust's documented order before its independent codec.
  const compiled=kit.compileTransactionMessage(message),keys=compiled.staticAccounts;
  const compare=(a,b)=>Buffer.compare(Buffer.from(kit.getAddressEncoder().encode(a)),Buffer.from(kit.getAddressEncoder().encode(b)));
  assert.equal(compiled.header.numSignerAccounts,1);assert.equal(compiled.header.numReadonlySignerAccounts,0);
  const writableEnd=keys.length-compiled.header.numReadonlyNonSignerAccounts;
  const ordered=[keys[0],...keys.slice(1,writableEnd).sort(compare),...keys.slice(writableEnd).sort(compare)];
  const remap=index=>ordered.indexOf(keys[index]);
  const canonical={...compiled,staticAccounts:ordered,instructions:compiled.instructions.map(ix=>({...ix,programAddressIndex:remap(ix.programAddressIndex),accountIndices:ix.accountIndices.map(remap)}))};
  const canonicalBytes=Buffer.from(kit.getCompiledTransactionMessageEncoder().encode(canonical));
  assert.equal(wire.subarray(65).toString('hex'),canonicalBytes.toString('hex'),'complete canonical signed message differs from Kit codec');
  const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  assert.equal(wire.subarray(1,65).toString('hex'),sign(null,canonicalBytes,privateKey).toString('hex'),'Ed25519 signature differs from Node/OpenSSL');
  const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(known.address_hex,'hex')]),format:'der',type:'spki'});assert.ok(verify(null,wire.subarray(65),publicKey,wire.subarray(1,65)));
  if(amount>9007199254740992n)assert.ok(actual.authorization_text.includes('9007199.254740993 SOL'));
  const fixture={version:'legacy',asset,payer:payer.address,mint,source,destination,deposit,wire_hex:actual.wire_hex};
  const executed=spawnSync(oracle,[],{input:JSON.stringify({fixture,prefund:spec.prefund??0,existing_ata:spec.existing??false,block_time:now,payer_lamports:(amount+100000000n).toString()}),encoding:'utf8'});assert.equal(executed.status,0,executed.stderr);
  const value=JSON.parse(executed.stdout);
  // Preserve Rust's exact u64 JSON number lexemes, including balances above
  // 2^53. Only translate the test oracle's inner-instruction data encoding.
  const response=value.response.replace(/"data_hex":"([0-9a-f]*)"/g,(_all,hex)=>'"data":'+JSON.stringify(kit.getBase58Decoder().decode(Buffer.from(hex,'hex'))));
  cases.push({quote_hex:quote.toString('hex'),signature_hex:wire.subarray(1,65).toString('hex'),payer_hex:known.address_hex,signature:kit.getBase58Decoder().decode(wire.subarray(1,65)),response});
 }
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'morse-wallet-sdk-'));const directory=path.join(temporary,'wallet-proof');await fs.mkdir(path.join(directory,'payment'),{recursive:true});
 let server;
 try{
  await fs.writeFile(path.join(directory,'mesh.toml'),`[package]\nname="wallet-proof"\nversion="0.1.0"\n[dependencies]\nmessenger-protocol={path=${JSON.stringify(path.join(product,'packages/messenger-protocol'))}}\nmesh-solana={path=${JSON.stringify(path.join(publicRoot,'packages/mesh-solana'))}}\n`);
  await fs.copyFile(path.join(product,'services/credit-issuer/payment/verify.mpl'),path.join(directory,'payment/verify.mpl'));await fs.copyFile(path.join(sdk,'tests/payment.mpl.fixture'),path.join(directory,'main.mpl'));await fs.writeFile(path.join(directory,'cases.json'),JSON.stringify(cases));
  const built=await run(process.env.MESHC||path.join(publicRoot,'target/debug/meshc'),['build',directory]);assert.equal(built.code,0,built.stdout+built.stderr);
  let calls=0;server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;const request=JSON.parse(body);const current=cases[calls++];assert.equal(request.method,'getTransaction');assert.equal(request.id,41);assert.equal(request.params[0],current.signature);assert.deepEqual(request.params[1],{encoding:'base64',commitment:'finalized',maxSupportedTransactionVersion:0});res.writeHead(200,{'content-type':'application/json','connection':'close'});res.end(current.response);});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const result=await run(path.join(directory,'wallet-proof'),[],{env:{...process.env,WALLET_CASES:path.join(directory,'cases.json'),RPC_URL:`http://127.0.0.1:${server.address().port}`}});assert.equal(result.code,0,result.stdout+result.stderr);assert.equal(result.stdout,`wallet-payments:${cases.length}:ok\n`,result.stdout+result.stderr);assert.equal(calls,cases.length);
  const report={schema_version:1,passed:true,fixture_seed:'public repeated01 test seed',independent_derivation:'Node crypto HMAC-SHA512 SLIP0010',independent_signature:'Node/OpenSSL Ed25519',sdk:'@solana/kit8.4.0',canonical_full_wire_matches:cases.length,account_order_normalized:true,bounty_addresses:256,local_sbf_payments:cases.length,compiled_mesh_rpc_verifications:calls,above_2pow53:true,real_funds:false};
  if(process.env.WALLET_SDK_REPORT)await fs.writeFile(process.env.WALLET_SDK_REPORT,JSON.stringify(report,null,2)+'\n');console.log('WALLET_SDK_JSON='+JSON.stringify(report));
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}
});
