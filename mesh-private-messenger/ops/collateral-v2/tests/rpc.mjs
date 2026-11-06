import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
const here=dirname(fileURLToPath(import.meta.url));
const required=name=>{assert(process.env[name],`${name} is required`);return process.env[name];};
const compiler=required('MESH_COMPILER_BIN'), runtime=required('MESH_RT_LIB_PATH'), testRuntime=required('MESH_TEST_RT_LIB_PATH');
const input=required('MORSE_COLLATERAL_OPERATOR_VECTORS_PATH'), out=required('MORSE_COLLATERAL_OPERATOR_RPC_OUTPUT');
await mkdir(out,{recursive:true});
const hash=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
const pins=new Map([[compiler,'25a8e3f78695e3c190bc2fc153c5294336451c3b120564ceca6f0e33c6333ef1'],[runtime,'347da0ed305c88999ea82c9f1f1a82a04eed643c180db014a938b0edb1d88fdf'],[testRuntime,'c10c5256d6c1a65aeb6e5047253fc7c0830eb2ca241087d704588650232a093b']]);
for(const [path,expected]of pins)assert.equal(await hash(path),expected,path);
const source=JSON.parse(await readFile(input,'utf8'));
const row=source.cases.find(r=>r.tag===34&&r.asset===1&&r.success);
assert(row);const fixture=resolve(out,'actual-row.json');await writeFile(fixture,JSON.stringify(row)+'\n');
const unsigned=value=>{assert.match(value,/^(0|[1-9][0-9]*)$/);assert(BigInt(value)<=18446744073709551615n);return value;};
let calls=0, redirects=0;const problems=[];
const redirect=createServer((req,res)=>{redirects++;res.writeHead(500);res.end();});
await new Promise(r=>redirect.listen(0,'127.0.0.1',r));
const redirectURL=`http://127.0.0.1:${redirect.address().port}/must-not-follow`;
function account(value,id,index){
 if(value.missing)return 'null';
 const result={...value};let data=Buffer.from(value.data_hex,'hex');
 if(id===2&&index===2)result.owner='11111111111111111111111111111111';
 if(id===3&&data.subarray(0,4).equals(Buffer.from('4d454302','hex'))){data=Buffer.from(data);data.writeBigUInt64LE(data.readBigUInt64LE(168)+BigInt(index),168);}
 if(id===8&&index>0&&data.subarray(0,4).equals(Buffer.from('03000000','hex'))){data=Buffer.from(data);data.writeBigUInt64LE(data.readBigUInt64LE(4)+1n,4);}
 if(id===10&&index>0&&data.subarray(0,4).equals(Buffer.from('4d544f01','hex'))){data=Buffer.from(data);data[100]^=1;}
 if(id===11&&index>0)result.space='0';
 return `{"data":[${JSON.stringify(data.toString('base64'))},"base64"],"executable":${result.executable},"owner":${JSON.stringify(result.owner)},"lamports":${unsigned(result.lamports)},"rentEpoch":${unsigned(result.rent_epoch)},"space":${unsigned(result.space)}}`;
}
const servers=[];
try{
 for(let index=0;index<3;index++){
  const server=createServer(async(req,res)=>{try{
   let body='';for await(const chunk of req){body+=chunk;assert(body.length<=32768);}
   const request=JSON.parse(body);assert.equal(request.method,'getMultipleAccounts');assert.equal(request.params[1].commitment,'finalized');assert.equal(request.params[1].encoding,'base64');assert.deepEqual(request.params[1].dataSlice,{offset:0,length:9216});assert.equal(body.match(/"minContextSlot":([0-9]+)/)?.[1],row.clock_slot);assert.equal(request.params[0].length,27);calls++;
   const id=request.id;assert(id>=1&&id<=12);
   if(id===4&&index>0){res.writeHead(503);res.end('not available');return;}
   if(id===12&&index>0){res.writeHead(302,{location:redirectURL});res.end();return;}
   let values=request.params[0].map(key=>{assert(Object.hasOwn(row.accounts,key),`actual role missing ${key}`);return account(row.accounts[key],id,index);});
   if(id===6&&index>0)values=values.slice(1);
   if(id===9&&index>0)values[0]='null';
   const slot=id===5&&index>0?(BigInt(row.clock_slot)-1n).toString():row.clock_slot;
   const answer=`{"jsonrpc":"2.0","id":${id===7?999:id},"result":{"context":{"slot":${unsigned(slot)}},"value":[${values.join(',')}]}}`;
   res.writeHead(200,{'content-type':'application/json'});res.end(answer);
  }catch(error){problems.push(String(error.stack??error));res.writeHead(500);res.end('fixture failure');}});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));servers.push(server);
 }
 const endpoints=servers.map(s=>`http://127.0.0.1:${s.address().port}`);
 const command=[compiler,'test',resolve(here,'rpc.test.mpl')];
 const child=spawn(command[0],command.slice(1),{cwd:resolve(here,'..'),env:{...process.env,MORSE_COLLATERAL_OPERATOR_RPC_FIXTURE:fixture,MORSE_COLLATERAL_OPERATOR_RPC_SOURCES:JSON.stringify(endpoints)},stdio:['ignore','pipe','pipe']});
 let output='';child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>output+=v);
 const code=await new Promise((r,j)=>{child.on('error',j);child.on('close',r);});
 await writeFile(resolve(out,'mesh.log'),output);process.stdout.write(output);
 assert.equal(code,0);assert.equal(calls,36);assert.equal(redirects,0);assert.deepEqual(problems,[]);
 for(const[path,expected]of pins)assert.equal(await hash(path),expected,path);
 await writeFile(resolve(out,'results.json'),JSON.stringify({schema_version:1,mode:'fresh-local-HTTP-replay-of-actual-historical-SBF-state',cases:12,requests:calls,redirects_followed:redirects,input_sha256:await hash(input),compiler_sha256:pins.get(compiler),runtime_sha256:pins.get(runtime),test_runtime_sha256:pins.get(testRuntime),problems},null,2)+'\n');
}finally{
 for(const server of [...servers,redirect])await new Promise(r=>server.close(r));
}
