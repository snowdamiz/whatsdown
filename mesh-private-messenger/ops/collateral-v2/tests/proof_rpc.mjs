import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const here=dirname(fileURLToPath(import.meta.url));
const required=name=>{assert(process.env[name],`${name} required`);return process.env[name];};
const compiler=required('MESH_COMPILER_BIN'),runtime=required('MESH_RT_LIB_PATH'),testRuntime=required('MESH_TEST_RT_LIB_PATH');
const input=required('MORSE_COLLATERAL_OPERATOR_VECTORS_PATH'),out=required('MORSE_COLLATERAL_PROOF_HTTP_OUTPUT');
await mkdir(out,{recursive:true});
const hash=async p=>createHash('sha256').update(await readFile(p)).digest('hex');
const pins=new Map([[compiler,'25a8e3f78695e3c190bc2fc153c5294336451c3b120564ceca6f0e33c6333ef1'],[runtime,'347da0ed305c88999ea82c9f1f1a82a04eed643c180db014a938b0edb1d88fdf'],[testRuntime,'c10c5256d6c1a65aeb6e5047253fc7c0830eb2ca241087d704588650232a093b']]);
for(const[p,v]of pins)assert.equal(await hash(p),v,p);
const row=JSON.parse(await readFile(input,'utf8')).cases.find(r=>r.tag===41&&r.anchor_generation!==null&&r.success);
assert(row);const rowPath=resolve(out,'actual-row.json'),modePath=resolve(out,'mode.txt');await writeFile(rowPath,JSON.stringify(row)+'\n');
const unsigned=v=>{assert.match(v,/^(0|[1-9][0-9]*)$/);assert(BigInt(v)<=18446744073709551615n);return v;};
const problems=[],calls=[],servers=[];
function account(value,offset,length,mode,origin){
 if(value.missing)return 'null';
 const copy={...value};let data=Buffer.from(value.data_hex,'hex').subarray(offset,offset+length);
 if(mode===2&&origin===2&&length===2752)copy.owner='11111111111111111111111111111111';
 if(mode===4&&origin>0&&length===104){data=Buffer.from(data);data.fill(3,16,48);}
 if(mode===8&&origin>0&&offset===0&&length===9216&&data.subarray(0,4).equals(Buffer.from('03000000','hex'))){data=Buffer.from(data);data.writeBigUInt64LE(data.readBigUInt64LE(4)+1n,4);}
 return `{"data":[${JSON.stringify(data.toString('base64'))},"base64"],"executable":${copy.executable},"owner":${JSON.stringify(copy.owner)},"lamports":${unsigned(copy.lamports)},"rentEpoch":${unsigned(copy.rent_epoch)},"space":${unsigned(copy.space)}}`;
}
try{
 for(let origin=0;origin<3;origin++){
  const server=createServer(async(req,res)=>{try{
   let body='';for await(const chunk of req){body+=chunk;assert(body.length<=32768);}
   const request=JSON.parse(body),mode=Number(await readFile(modePath,'utf8'));
   assert(['getMultipleAccounts','getAccountInfo'].includes(request.method));assert.equal(request.params[1].commitment,'finalized');assert.equal(request.params[1].encoding,'base64');assert.equal(body.match(/"minContextSlot":([0-9]+)/)?.[1],row.clock_slot);
   const{offset,length}=request.params[1].dataSlice;const many=request.method==='getMultipleAccounts';
   if(many){assert.deepEqual({offset,length},{offset:0,length:9216});assert(request.params[0].length<=97);}else assert([[0,64],[64,104],[0,2752]].some(([a,b])=>a===offset&&b===length));
   calls.push({mode,origin,method:request.method,offset,length});
   if(mode===5&&origin>0&&length===2752){res.writeHead(503);res.end();return;}
   const selected=many?request.params[0]:[request.params[0]];let values=selected.map(key=>{assert(Object.hasOwn(row.accounts,key),`actual same-bank account missing ${key}`);return account(row.accounts[key],offset,length,mode,origin);});
   if(mode===7&&origin>0&&many)values=values.slice(1);
   const slot=(mode===3&&origin>0&&length===104)?(BigInt(row.clock_slot)+1n).toString():(mode===6&&origin>0&&many)?(BigInt(row.clock_slot)-1n).toString():row.clock_slot;
   res.writeHead(200,{'content-type':'application/json'});res.end(`{"jsonrpc":"2.0","id":${request.id},"result":{"context":{"slot":${unsigned(slot)}},"value":${many?'['+values.join(',')+']':values[0]}}}`);
  }catch(e){problems.push(String(e.stack??e));res.writeHead(500);res.end('owned fixture failure');}});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));servers.push(server);
 }
 const endpoints=servers.map(s=>`http://127.0.0.1:${s.address().port}`);
 const child=spawn(compiler,['test',resolve(here,'proof_rpc.test.mpl')],{cwd:resolve(here,'..'),env:{...process.env,MORSE_COLLATERAL_PROOF_HTTP_ROW:rowPath,MORSE_COLLATERAL_PROOF_HTTP_MODE:modePath,MORSE_COLLATERAL_PROOF_HTTP_SOURCES:JSON.stringify(endpoints)},stdio:['ignore','pipe','pipe']});
 let log='';child.stdout.on('data',v=>log+=v);child.stderr.on('data',v=>log+=v);
 const code=await new Promise((r,j)=>{child.on('error',j);child.on('close',r);});await writeFile(resolve(out,'mesh.log'),log);process.stdout.write(log);assert.equal(code,0);assert.deepEqual(problems,[]);
 for(let mode=1;mode<=8;mode++)assert(calls.filter(c=>c.mode===mode).length>=3);
 for(const[p,v]of pins)assert.equal(await hash(p),v,p);
 await writeFile(resolve(out,'results.json'),JSON.stringify({schema_version:1,scope:'fresh-local-HTTP-replay-of-one-actual-anchored-SBF-bank',cases:8,requests:calls.length,calls,input_sha256:await hash(input),problems},null,2)+'\n');
}finally{for(const server of servers)await new Promise(r=>server.close(r));}
