import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {once} from 'node:events';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const here=path.dirname(fileURLToPath(import.meta.url));
const configure=require('../../apps/mobile/plugins/network-counter-config.cjs');
assert(process.env.MORSE_NETWORK_COUNTER_BIN,'provide the exact compiled local counter proof executable');
assert(process.env.MORSE_NETWORK_COUNTER_OUTPUT,'provide a new proof output directory');
fs.mkdirSync(process.env.MORSE_NETWORK_COUNTER_OUTPUT);
const corpus=JSON.parse(fs.readFileSync(path.resolve(here,'fixtures/morse-main-banks.json')));
assert.equal(corpus.snapshots.length,24);assert(corpus.snapshots.every(s=>s.log_name==='morse-main'));
const find=name=>{const s=corpus.snapshots.find(s=>s.name===name);assert(s,name);return s};
const B=(s,r)=>Buffer.from(s.accounts[r].data_hex,'hex');
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(b){let n=BigInt(`0x${b.toString('hex')}`),out='';while(n){out=alphabet[Number(n%58n)]+out;n/=58n;}for(const c of b){if(c)break;out='1'+out;}return out;}
const key=(s,r,i)=>base58(B(s,r).subarray(i,i+32));
const number=(s,r,i)=>B(s,r).readBigUInt64LE(i).toString();
function pins(s,urls,root,patch={}){
 const witnesses=Object.keys(s.accounts).filter(k=>/^witness\d+$/.test(k)).map(r=>{const b=B(s,r);return{id:b.subarray(8,8+b[4]).toString(),key:b.subarray(72,104).toString('hex')}}).sort((a,b)=>a.id.localeCompare(b.id));
 const threshold=String(Math.floor(witnesses.length/2)+1),lines=witnesses.map(w=>`${w.id} ${w.key} Fixture operator`);
 const security=['4',B(s,'log').subarray(72,104).toString('hex'),'22'.repeat(32),'4',threshold,String(lines.length),...lines,key(s,'log',136),String(urls.length),...urls,'-','2',threshold,String(lines.length),...lines,s.program,'morse-main'].join('\n');
 const c=s.name==='legacy-active'?{schema_version:1,mode:'legacy-v1',minimum_context_slot:s.context_slot,judge_slot:number(s,'judge_data',4),log_version:B(s,'log')[4],governance:key(s,'judge_config',4),anchor_authority:key(s,'log',104),mint:s.accounts.usdc.address,...patch}:{schema_version:1,mode:'v2',minimum_context_slot:s.context_slot,judge_slot:number(s,'judge_data',4),log_version:B(s,'log')[4],token_program:s.token_program,token_slot:number(s,'token_data',4),token_governance:key(s,'token_config',4),usdc_mint:s.accounts.usdc.address,morse_mint:s.accounts.morse.address,rewards_program:s.rewards_program,rewards_slot:number(s,'rewards_data',4),rewards_governance:key(s,'pool',4),network_started:number(s,'pool',164),...patch};
 return {security,pins:configure({MESSENGER_ANCHOR_LOG_NAME:'morse-main',MESSENGER_NETWORK_COUNTER_CONFIG:JSON.stringify(c),MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH:root},security),checked_at:(BigInt(s.now)*1000n).toString()};
}
const temporary=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'morse-native-counter-')));
const cert=path.join(temporary,'root.pem'),keyfile=path.join(temporary,'server.key'),servercert=path.join(temporary,'server.pem');
function ssl(args){const r=spawnSync('openssl',args,{encoding:'utf8'});assert.equal(r.status,0,r.stderr);}
ssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(temporary,'root.key'),'-out',cert,'-days','1','-subj','/CN=counter-owned-root','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']);
ssl(['req','-newkey','rsa:2048','-nodes','-keyout',keyfile,'-out',path.join(temporary,'server.csr'),'-subj','/CN=counter-owned-fixture']);
fs.writeFileSync(path.join(temporary,'server.ext'),'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
ssl(['x509','-req','-in',path.join(temporary,'server.csr'),'-CA',cert,'-CAkey',path.join(temporary,'root.key'),'-CAcreateserial','-out',servercert,'-days','1','-extfile',path.join(temporary,'server.ext')]);
let serial=0;
let selected=find('token-active');let modes=['good','good','good'];let requests=0;const errors=[];const records=[];
const servers=modes.map((_,i)=>https.createServer({key:fs.readFileSync(keyfile),cert:fs.readFileSync(servercert)},async(req,res)=>{
 try{
  let raw='';for await(const data of req)raw+=data;
  const rpc=JSON.parse(raw);requests++;assert.equal(req.method,'POST');assert.equal(rpc.method,'getMultipleAccounts');assert.equal(rpc.id,1);assert(rpc.params[0].length<=100);assert.equal(rpc.params[1].commitment,'finalized');assert.deepEqual(rpc.params[1].dataSlice,{offset:0,length:8416});
  const mode=modes[i];if(mode==='outage'){res.writeHead(503).end();return}if(mode==='redirect'){res.writeHead(302,{location:'https://127.0.0.1:1/forbidden'}).end();return}
  const s=mode==='other-bank'?find('token-pending'):selected;
  const by=new Map(Object.values(s.accounts).map(a=>[a.address,a]));
  const values=rpc.params[0].map(address=>{const a=by.get(address);assert(a,`actual same-bank observation required for ${address}`);return a.missing?null:{owner:a.owner,lamports:Number(a.lamports),executable:a.executable,rentEpoch:0,space:Number(a.space),data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64']}});
  const change=(role,fn)=>{const at=rpc.params[0].indexOf(s.accounts[role]?.address);if(at<0)return;const value=values[at];assert(value);const b=Buffer.from(value.data[0],'base64');fn(b,value);value.data[0]=b.toString('base64')};
  if(mode==='owner')values[1].owner=s.accounts.usdc.owner;
  if(mode==='partial')values.pop();
  if(mode==='wrong-order')[values[0],values[1]]=[values[1],values[0]];
  if(mode==='missing')values[1]=null;
  if(mode==='padding')change('binding',b=>{b[319]=1});
  if(mode==='service')change('log',b=>{b[72]^=1});
  if(mode==='wrong-clock')change('clock',b=>b.writeBigUInt64LE(BigInt(s.context_slot)+1n,0));
  if(mode==='future-code')change('judge_data',b=>b.writeBigUInt64LE(BigInt(s.context_slot)+1n,4));
  if(mode==='underfunded')change('vault0',b=>b.writeBigUInt64LE(0n,64));
  if(mode==='pending')change('pending0',b=>{b[4]^=1});
  if(mode==='mint')change('morse',b=>{b[44]=9});
  res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({jsonrpc:'2.0',id:mode==='id'?2:1,result:{context:{slot:Number(s.context_slot)-(mode==='old-slot'?1:0)},value:values}}));
 }catch(error){errors.push(error.stack);res.writeHead(500).end()}
}));
async function run(patch={},extra={}){
 const input=pins(extra.pin_snapshot?find(extra.pin_snapshot):selected,urls,cert,patch);Object.assign(input,extra);const file=path.join(temporary,`request-${serial++}.json`);fs.writeFileSync(file,JSON.stringify(input));
 const child=spawn(process.env.MORSE_NETWORK_COUNTER_BIN,[file],{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);const [code]=await once(child,'exit');const value=out.startsWith('NCR1')?JSON.parse(out.slice(4)):null;records.push({name:selected.name,modes:[...modes],patch,code,stdout:out,stderr:err});return {code,value,out,err};
}
let urls;
try{
 for(const server of servers){server.listen(0,'127.0.0.1');await once(server,'listening')}
 urls=servers.map(s=>`https://127.0.0.1:${s.address().port}`);
 selected=find('legacy-active');let legacy=await run();assert.equal(legacy.code,0,legacy.err);assert(legacy.value.observation.rows.every(r=>r.asset==='legacy'&&r.pending_units===null&&r.usd_micros===null));assert.equal(legacy.value.observation.rows[0].principal_units,'500000000');
 selected=find('v2-usdc-legacy-bond');let migrated=await run();assert.equal(migrated.code,0,migrated.err);assert.equal(migrated.value.observation.rows[1].asset,'USDC');assert.equal(migrated.value.observation.rows[1].layout,1);assert.equal(migrated.value.observation.rows[1].principal_units,'100000000');
 selected=find('registered-only');let registered=await run();assert.equal(registered.code,0,registered.err);const unbonded=registered.value.observation.rows[1];assert.equal(unbonded.status,0);assert.equal(unbonded.asset,'unassigned');assert.equal(unbonded.principal_units,null);assert.equal(unbonded.balance_units,null);assert.equal(unbonded.morse_vault_units,'17');assert.equal(unbonded.usdc_vault_units,null);
 selected=find('token-active');
 let r=await run();assert.equal(r.code,0,r.err);assert.equal(r.value.status,'available');assert.equal(r.value.observation.rows[1].principal_units,'50000000');assert.equal(r.value.observation.rows[1].donation_units,'17');assert.equal(r.value.observation.rows[1].asset,'MORSE');assert.equal(r.value.observation.valuation,'unconfigured');
 for(const name of ['token-pending','token-underwater','token-grace-expired','token-withdrawn','mixed-proof-settled']){
  selected=find(name);r=await run();assert.equal(r.code,0,r.err);const o=r.value.observation;
  if(name==='token-pending'){assert.equal(o.rows[1].pending_units,'1');assert.equal(o.rows[1].donation_units,'17')}
  if(name.includes('underwater')||name.includes('grace')){assert.equal(o.rows[1].status,1);assert.notEqual(o.rows[1].underwater_since,'0')}
  if(name==='token-withdrawn'){assert.equal(o.rows[1].status,4);assert.equal(o.rows[1].principal_units,'0')}
  if(name==='mixed-proof-settled'){assert(o.service_slashed);assert.equal(o.witnesses_slashed,2);assert.deepEqual(new Set(o.rows.map(x=>x.asset)),new Set(['USDC','MORSE']));assert.equal(o.rows.find(x=>x.pending_recorded_units==='7').pending_units,'0')}
 }
 selected=find('token-active');
 for(const mode of ['owner','partial','wrong-order','missing','padding','service','wrong-clock','future-code','underfunded','pending','mint','old-slot','id','redirect']){modes.fill(mode);r=await run();assert.notEqual(r.code,0,mode);assert.equal(r.value,null,mode)}
 modes.splice(0,3,'good','good','outage');assert.equal((await run()).code,0);
 modes.splice(0,3,'good','owner','outage');assert.notEqual((await run()).code,0);
 modes.splice(0,3,'good','other-bank','outage');r=await run();assert.notEqual(r.code,0);assert.match(r.err,/counter_rpc_disagreed/);
 modes.fill('good');assert.notEqual((await run({judge_slot:'999'})).code,0,'code changes are unavailable, never merely warnings');
 assert.notEqual((await run({}, {checked_at:((BigInt(selected.now)+121n)*1000n).toString()})).code,0,'old historical Clock is not current');
 assert.notEqual((await run({}, {checked_at:((BigInt(selected.now)-1n)*1000n).toString()})).code,0,'future bank time');
 const oracle={receiver:key(selected,'oracle',68),source:key(selected,'oracle',100),feed:B(selected,'oracle').subarray(132,164).toString('hex'),revision:number(selected,'oracle',292)};
 r=await run({oracle});assert.equal(r.code,0,r.err);assert.equal(r.value.observation.valuation,'available');assert.equal(r.value.observation.twap_usd_micros,'2000000');assert.equal(r.value.observation.rows[1].usd_micros,'100000000');
 r=await run({oracle:{...oracle,revision:'999'}});assert.equal(r.code,0,r.err);assert.equal(r.value.observation.valuation,'unavailable');assert.equal(r.value.observation.rows[1].usd_micros,null);
 // Each subprocess restarts the reader and opens the same private wrapping
 // directory. The database and private key directory are disposable, never
 // qualification artifacts. All accepted accounts remain exact actual banks.
 selected=find('mixed-proof-prepared');modes.fill('good');
 const at=BigInt(selected.now)*1000n;
 const saved={pin_snapshot:'mixed-proof-prepared',action:'refresh',database:path.join(temporary,'cache.db'),key_directory:path.join(temporary,'cache-key')};
 r=await run({},saved);assert.equal(r.code,0,r.err);assert.equal(r.value.observation.service_slashed,false);
 let before=requests;modes.fill('outage');r=await run({}, {...saved,checked_at:(at+1000n).toString()});assert.equal(r.code,0,r.err);assert.equal(requests,before,'cached refresh performs no network');
 selected=find('mixed-proof-settled');modes.fill('good');
 r=await run({}, {...saved,checked_at:(at+61000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.observation.service_slashed,true);assert.equal(r.value.slash_history.length,2);
 before=requests;modes.fill('outage');r=await run({}, {...saved,checked_at:(at+62000n).toString()});assert.equal(r.code,0,r.err);assert.equal(requests,before);assert.equal(r.value.slash_history.length,2);
 r=await run({}, {...saved,checked_at:(at+122000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.status,'historical');assert.equal(r.value.observation.service_slashed,true);assert.equal(r.value.slash_history.length,2);
 const other={pin_snapshot:'mixed-proof-prepared',action:'refresh',database:path.join(temporary,'contradiction.db'),key_directory:path.join(temporary,'contradiction-key')};
 modes.fill('good');r=await run({},other);assert.equal(r.code,0,r.err);const id=r.value.config_id;
 selected=find('mixed-proof-prepared');r=await run({}, {...other,checked_at:(at+61000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.config_id,id);assert.equal(r.value.status,'historical');assert.equal(r.value.reason,'slash-contradiction');assert.equal(r.value.observation,null,'contradicting current rows cannot look like retained history');assert.equal(r.value.slash_history.length,2);
 before=requests;r=await run({}, {...other,checked_at:(at+60000n).toString()});assert.equal(r.code,0,r.err);assert.equal(requests,before);assert.equal(r.value.reason,'clock-rollback');assert.equal(r.value.slash_history.length,2);
 r=await run({judge_slot:'999'}, {...other,checked_at:(at+61000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.status,'unavailable');assert.deepEqual(r.value.slash_history,[],'facts never cross configuration identities');
 const concurrent={pin_snapshot:'mixed-proof-prepared',action:'refresh',database:path.join(temporary,'race.db'),key_directory:path.join(temporary,'race-key')};
 r=await run({},concurrent);assert.equal(r.code,0,r.err);selected=find('mixed-proof-settled');
 const outcomes=await Promise.all([run({}, {...concurrent,checked_at:(at+61000n).toString()}),run({}, {...concurrent,checked_at:(at+61000n).toString()})]);assert(outcomes.some(x=>x.code===0));
 for(const x of outcomes.filter(x=>x.code===0))assert.equal(x.value.slash_history.length,2);
 modes.fill('outage');r=await run({}, {...concurrent,checked_at:(at+122000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.status,'historical');assert.equal(r.value.slash_history.length,2,'same-bank proven facts survive concurrent display CAS');
 // A short cache interval cannot extend the bank freshness contract.
 const aged={pin_snapshot:'mixed-proof-prepared',action:'refresh',database:path.join(temporary,'age.db'),key_directory:path.join(temporary,'age-key')};
 selected=find('mixed-proof-prepared');modes.fill('good');r=await run({}, {...aged,checked_at:(at+119000n).toString()});assert.equal(r.code,0,r.err);assert.equal(r.value.status,'available');
 before=requests;r=await run({}, {...aged,checked_at:(at+121000n).toString()});assert.equal(r.code,0,r.err);assert.equal(requests,before);assert.equal(r.value.status,'historical','cache reuse cannot label a >120s bank current');
 // Authenticated history must remain visible even if the replaceable display
 // cache is corrupted. This is a refusal/recovery mutation of an owned DB.
 const mutate=spawnSync('python3',['-c',`import sqlite3,hashlib,sys
c=sqlite3.connect(sys.argv[1]);h=hashlib.sha256(('network-counter/v1/'+sys.argv[2]).encode()).hexdigest();b=bytearray(c.execute('SELECT ciphertext FROM encrypted_blobs WHERE record_hash=?',(h,)).fetchone()[0]);b[-1]^=1;c.execute('UPDATE encrypted_blobs SET ciphertext=? WHERE record_hash=?',(bytes(b),h));c.commit()`,other.database,id],{encoding:'utf8'});assert.equal(mutate.status,0,mutate.stderr);
 before=requests;r=await run({}, {...other,checked_at:(at+122000n).toString()});assert.equal(r.code,0,r.err);assert.equal(requests,before);assert.equal(r.value.status,'historical');assert.equal(r.value.observation,null);assert.equal(r.value.slash_history.length,2);
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({passed:true,cases:records.length,https_requests:requests,origins:urls.length,scope:'exact actual SBF bank replay; test-only observation clock; no provider independence claim'}));
}finally{
 fs.writeFileSync(path.join(process.env.MORSE_NETWORK_COUNTER_OUTPUT,'results.json'),JSON.stringify({records,requests,errors},null,2)+'\n');
 for(const s of servers){s.closeAllConnections();await new Promise(resolve=>s.close(resolve))}
 fs.rmSync(temporary,{recursive:true,force:true});
}
