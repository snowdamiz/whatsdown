// Owned temporary PostgreSQL only. This proves actual compiled Mesh adapters,
// not a SQL imitation of their lock order. No service/data outside this DB.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
const service=path.resolve(import.meta.dirname,'..'),product=path.resolve(service,'../..');
const compiler=process.env.MESHC||path.resolve(process.env.MESH_LANG_ROOT||path.join(product,'../mesh-lang'),'target/debug/meshc');
const pgBin=process.env.CREDIT_TEST_PG_BIN||execFileSync('pg_config',['--bindir'],{encoding:'utf8'}).trim();
const run=(file,args,options={})=>{try{return execFileSync(file,args,{encoding:'utf8',timeout:60000,...options});}catch(error){error.message+=`\n${error.stdout||''}\n${error.stderr||''}`;throw error;}};
test('compiled retention and redemption cannot invert mailbox/operation locks',{timeout:120000},async()=>{
 const temp=await mkdtemp(path.join(tmpdir(),'morse-retention-lock-')),data=path.join(temp,'postgres');let started=false;
 const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(resolve=>server.close(resolve));
 const pg=name=>path.join(pgBin,name),url=`postgres://credits_test@127.0.0.1:${port}/credits_retention_lock_test?sslmode=disable`;
 try{
  run(pg('initdb'),['-D',data,'-U','credits_test','-A','trust','--no-locale']);run(pg('pg_ctl'),['-D',data,'-l',path.join(temp,'postgres.log'),'-w','start','-o',`-h 127.0.0.1 -p ${port} -F`]);started=true;
  run(pg('createdb'),['-h','127.0.0.1','-p',String(port),'-U','credits_test','credits_retention_lock_test']);
  const sql=query=>run(pg('psql'),['-X','-qAt','-v','ON_ERROR_STOP=1',url,'-c',query]).trim();
  for(const name of (await readdir(path.join(service,'migrations'))).filter(n=>n.endsWith('.sql')).sort())run(pg('psql'),['-X','-q','-v','ON_ERROR_STOP=1',url,'-f',path.join(service,'migrations',name)]);
  sql("ALTER DATABASE credits_retention_lock_test SET statement_timeout='2500ms'");
  sql("INSERT INTO transparency_log_cutover (phase,legacy_checkpoint,legacy_witnesses,activated_at) VALUES ('active',decode(repeat('00',188),'hex'),decode(repeat('00',6),'hex'),now())");
  const output=run(compiler,['test',path.join(service,'security/credits-retention-locking.test.mpl')],{env:{...process.env,MESSENGER_TEST_DATABASE_URL:url,MESH_SCHEDULER_MIN_WORKERS:'1',MESH_SCHEDULER_MAX_WORKERS:'1',MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX:'5b'.repeat(32),MESSENGER_WITNESS_A_PUBLIC_KEY_HEX:'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',MESSENGER_WITNESS_B_PUBLIC_KEY_HEX:'3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',CREDIT_FIXTURE_WITNESS_A_SEED:'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',CREDIT_FIXTURE_WITNESS_B_SEED:'4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',MESSENGER_CREDITS_PURPOSE:'test',MESSENGER_JOBS_URL:''}});
  assert.match(output,/1 passed/);assert.match(output,/CREDITS_RETENTION_LOCK_ORDER/);console.log(output.trim());
 }finally{if(started)run(pg('pg_ctl'),['-D',data,'-w','-m','fast','stop']);await rm(temp,{recursive:true,force:true});}
});
