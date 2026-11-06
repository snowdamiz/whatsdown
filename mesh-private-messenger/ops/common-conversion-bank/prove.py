#!/usr/bin/env python3
"""One fresh owned bank; Mesh conversion journals and aggregate tag14/tag15.
Host code only copies public files, starts owned processes and asserts results.
"""
import argparse, concurrent.futures, hashlib, json, os, shutil, socket, subprocess, time, threading, signal
from pathlib import Path
HERE=Path(__file__).resolve().parent

def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def copy(a,b):
 b=Path(b);b.parent.mkdir(parents=True,exist_ok=True);subprocess.run(['/bin/cp','-c',str(a),str(b)],check=True)
def save(p,value):
 p=Path(p);tmp=p.with_name(p.name+'.tmp')
 with tmp.open('xb') as f:f.write((json.dumps(value,indent=2)+'\n').encode());f.flush();os.fsync(f.fileno())
 os.replace(tmp,p)
def durable_packet(a,b):
 b=Path(b)
 with b.open('xb') as f:f.write(Path(a).read_bytes());f.flush();os.fsync(f.fileno())
 fd=os.open(b.parent,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
def wait(p,child=None,timeout=180):
 stop=time.monotonic()+timeout
 while not Path(p).exists():
  if child and child.poll() is not None:raise RuntimeError('owned child stopped before '+Path(p).name)
  if time.monotonic()>stop:raise TimeoutError(Path(p).name)
  time.sleep(.1)
 return json.loads(Path(p).read_text()) if Path(p).suffix=='.json' else Path(p).read_text()
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ['compiler','runtime','test-runtime','dex-dir','spl-elf','token-elf','btc-driver','btc-sbf','btc-harness','lightning-tools','cargo-target','pg-bin','output']:
  ap.add_argument('--'+n,type=Path,required=True)
 ap.add_argument('--btc-driver-sha',required=True);ap.add_argument('--btc-sbf-sha',required=True)
 a=ap.parse_args()
 for k,v in vars(a).items():
  if isinstance(v,Path):setattr(a,k,v.resolve())
 out=a.output;assert not out.exists();out.mkdir(parents=True)
 save(out/'invocation.json',{'argv':__import__('sys').argv,'cwd':str(Path.cwd())})
 assert sha(a.btc_driver)==a.btc_driver_sha and sha(a.btc_sbf)==a.btc_sbf_sha
 product=HERE.parents[1];source=out/'source';prod=source/'product';op=prod/'ops/common-conversion-bank';sol=prod/'ops/sol-conversion'
 def tree(origin,target):
  for p in sorted(origin.rglob('*')):
   if p.is_file() and not p.name.endswith('.plaintext.json') and (p.suffix in ['.mpl','.sql','.rs','.py','.md','.json'] or p.name in ['mesh.toml','Cargo.toml','Cargo.lock']):copy(p,target/p.relative_to(origin))
 for rel in ['services/credit-issuer','packages/messenger-protocol','ops/sol-conversion','ops/common-conversion-bank','ops/token/fixtures/dex']:
  tree(product/rel,prod/rel)
 copy(product/'ops/token/dex-source.json',prod/'ops/token/dex-source.json')
 for name in ['mesh-solana','mesh-binary','mesh-lightning']:tree(product.parent/'mesh-lang/packages'/name,source/'mesh-lang/packages'/name)
 # Preserve the BTC harness's normal directory relationships, not a shadow
 # launcher or rewritten product path. Its executable source closure is separate.
 ext=out/'external';harness=ext/'.morse/btc-conversion-work/harness';tree(a.btc_harness.parent,harness)
 copy(product/'scripts/lightning_regtest.py',ext/'mesh-private-messenger/scripts/lightning_regtest.py')
 before={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file()};save(out/'source-before.json',before)
 ext_before={str(p.relative_to(ext)):sha(p) for p in ext.rglob('*') if p.is_file()};save(out/'external-before.json',ext_before)
 btc_source=a.btc_driver.parent/'source'
 assert btc_source.is_dir(),'exact BTC fixture source closure required'
 copy(a.btc_driver.parent/'manifest.json',out/'inputs/btc-driver-provenance.json')
 copy(a.btc_harness.parent/'manifest.json',out/'inputs/btc-hook-provenance.json')
 tree(btc_source,out/'inputs/btc-source')
 tools={}
 for name in ['compiler','runtime','test_runtime','spl_elf','token_elf','btc_driver','btc_sbf']:
  path=getattr(a,name);tools[name]={'path':str(path),'sha256':sha(path)};copy(path,out/'inputs'/({'runtime':'libmesh_rt.a','test_runtime':'libmesh_test_rt.a'}.get(name,name)))
 for name in ['jupiter.so','raydium.so']:copy(a.dex_dir/name,out/'inputs/dex'/name)
 for name,rel in [('bitcoind','bitcoin-31.1/bin/bitcoind'),('lnd','lnd-darwin-arm64-v0.21.4-beta/lnd')]:
  p=a.lightning_tools/rel
  if p.is_file():tools[name]={'path':str(p),'sha256':sha(p)}
 save(out/'toolchain.json',tools)
 env=os.environ|{'PATH':str(a.pg_bin)+os.pathsep+os.environ['PATH'],'MESH_RT_LIB_PATH':str(out/'inputs/libmesh_rt.a'),'MESH_TEST_RT_LIB_PATH':str(out/'inputs/libmesh_test_rt.a'),'CARGO_TARGET_DIR':str(a.cargo_target),'CARGO_BUILD_JOBS':'1','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','LIGHTNING_TEST_TOOLS':str(a.lightning_tools),'BITCOIND':str(a.lightning_tools/'bitcoin-31.1/bin/bitcoind'),'LND':str(a.lightning_tools/'lnd-darwin-arm64-v0.21.4-beta/lnd'),'BTC_FIXTURE_PRODUCT':str(ext/'mesh-private-messenger')}
 env.pop('MORSE_COMMON_BANK_SELF_TEST',None)
 results=[];results_lock=threading.Lock()
 def run(cmd,name,cwd=prod,ok=True,timeout=360):
  r=subprocess.run(list(map(str,cmd)),cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
  (out/(name+'.log')).write_bytes(r.stdout)
  with results_lock:
   results.append({'name':name,'exit':r.returncode,'expected_success':ok});save(out/'results.json',results)
  assert (r.returncode==0)==ok,(name,r.stdout.decode(errors='replace')[-2500:])
  return r.stdout.decode()
 run(['python3',op/'rpc_capacity_test.py'],'rpc-capacity')
 compiler=out/'inputs/compiler'
 run([compiler,'build','.', '--opt-level','2','--output',op/'common-driver'],'common-build',op)
 run([compiler,'build','.', '--opt-level','2','--output',sol/'sol-conversion'],'sol-build',sol)
 built=run(['cargo','test','--offline','--manifest-path',sol/'tests/sbf/Cargo.toml','--test','common_bank','--no-run','--message-format=json'],'sbf-build')
 items=[json.loads(x) for x in built.splitlines() if x.startswith('{')];runner=Path(next(x['executable'] for x in items if x.get('executable') and x.get('profile',{}).get('test')));copy(runner,out/'inputs/sbf-runner')
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 env.update(PGHOST='127.0.0.1',PGPORT=str(port),PGUSER='common_conversion',PGDATABASE='postgres')
 pg=False;children=[];streams=[];bank=out/'bank';bank.mkdir()
 url=f'postgresql://common_conversion@127.0.0.1:{port}/common_bank';expiry_url=url.replace('/common_bank','/common_expiry')
 def sql(body,target=url):return subprocess.run([a.pg_bin/'psql',target,'-XAt','-v','ON_ERROR_STOP=1','-c',body],check=True,capture_output=True,text=True).stdout.strip()
 def child(cmd,name,extra=None):
  f=(out/(name+'.log')).open('w');streams.append(f);p=subprocess.Popen(list(map(str,cmd)),cwd=prod,env=env|(extra or {}),stdout=f,stderr=subprocess.STDOUT,start_new_session=True);children.append(p);return p
 try:
  run([a.pg_bin/'initdb','-D',out/'pg-data','-U','common_conversion','--auth=trust','--no-locale'],'pg-init')
  run([a.pg_bin/'pg_ctl','-D',out/'pg-data','-l',out/'pg.log','-o',f'-h 127.0.0.1 -p {port} -k /private/tmp','-w','start'],'pg-start');pg=True
  run([a.pg_bin/'createdb','common_bank'],'db-create')
  for p in sorted((prod/'services/credit-issuer/migrations').glob('*.sql')):run([a.pg_bin/'psql',url,'-X','-v','ON_ERROR_STOP=1','-f',p],'migration-'+p.stem)
  sbf=child([out/'inputs/sbf-runner','--exact','common_bank_real_outputs_and_exact_burn_funding','--nocapture'],'sbf',{'MORSE_SOL_CONVERSION_PRODUCT':str(prod),'MORSE_TOKEN_DEX_BIN_DIR':str(out/'inputs/dex'),'MORSE_SOL_CONVERSION_TOKEN_ELF':str(out/'inputs/spl_elf'),'MORSE_COMMON_BANK_TOKEN_ELF':str(out/'inputs/token_elf'),'MORSE_SOL_CONVERSION_EXPORT':str(bank),'MORSE_SOL_CONVERSION_BUCKET':'1','MORSE_SOL_CONVERSION_HANDOFF':'1','MORSE_COMMON_BANK_HANDOFF':'1','MORSE_COMMON_BANK_NOW':str(int(time.time()))})
  initial=wait(bank/'initial.json',sbf)
  cfg={k:initial[k] for k in ['owner','payer','usdc','pool','amm_config','authority','input_vault','output_vault','observation','oracle','amm_hash','raydium_code','token_code','rent','treasury_config','providers','providers_hash','cluster','nonce_authority','nonce_address','rewards_program','rewards_pool']};cfg.update(schema=1,maximum_fee='100000',owned_loopback_test=True,database_url=url);save(bank/'operator.json',cfg)
  week=int(initial['now'])//604800-1
  sql(f"INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,{week},1,1,decode(repeat('00',32),'hex'),decode('{initial['treasury_config']}','hex'),5000000000,1000000000,1500000000,2500000000,0,0,decode('{initial['membership_hash']}','hex'),2,decode('{initial['policy_hash']}','hex'))")
  sql('INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES(1,1500000000)')
  mode=bank/'rpc.mode';mode.write_text('normal')
  rpc=child(['python3',sol/'fixtures/common_rpc.py','--bank',bank/'initial.json','--execution',bank/'execution.json','--mode',mode,'--trace',bank/'http-trace.jsonl','--handoff','--database',url,'--expiry-database',expiry_url],'rpc')
  for _ in range(100):
   try:
    with socket.create_connection(('127.0.0.1',24494),timeout=.1):break
   except OSError:assert rpc.poll() is None;time.sleep(.1)
  identity=initial['id'];operator=sol/'sol-conversion'
  for i,args in enumerate([['prepare','1','1',bank/'message.base64'],['commit',identity,'0',bank/'signed.packet.base64'],['submit',identity],['status',identity],['reconcile',identity],['status',identity]]):
   if args[0]=='commit':wait(bank/'signed.packet.base64',sbf)
   if args[0]=='submit':mode.write_text('dropack')
   if args[0]=='reconcile':mode.write_text('executed')
   result=json.loads(run([operator,bank/'operator.json',*args],f'sol-{i}-{args[0]}'))
   assert result['state']==[0,1,1,1,2,2][i]
  btc=child(['python3',harness/'prove.py','--output',out/'btc','--driver',out/'inputs/btc_driver','--driver-sha',a.btc_driver_sha,'--sbf',out/'inputs/btc_sbf','--sbf-sha',a.btc_sbf_sha,'--bucket','burn','--external-bank',bank,'--database-url',url],'btc')
  arrived=wait(bank/'btc-arrived.json',btc,timeout=300);ready=wait(bank/'funding-ready.json',sbf)
  assert arrived['actual_arrival']['amount']=='74599302'
  sql(f"INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(2,{week},0,1,decode('{bytes_to_hex_address(initial['usdc'])}','hex'),decode('{initial['treasury_config']}','hex'),1000,200,300,500,0,0,decode('{hashlib.sha256(b'common actual USDC original liability').hexdigest()}','hex'),2,decode('{initial['policy_hash']}','hex'))")
  sql('INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES(2,300)')
  mode.write_text('common-disagree');run([op/'common-driver',bank/'operator.json',bank/'funding-ready.json','prepare',out/'rejected.json',out/'rejected.message'],'ready-disagreement',ok=False)
  assert sql('SELECT count(*) FROM issuer_treasury_burn_intents')=='0'
  mode.write_text('common-code');run([op/'common-driver',bank/'operator.json',bank/'funding-ready.json','prepare',out/'rejected-code.json',out/'rejected-code.message'],'ready-code-change',ok=False)
  assert sql('SELECT count(*) FROM issuer_treasury_burn_intents')=='0'
  mode.write_text('common-ready')
  def prepare(i):
   plan=bank/f'plan-{i}.json';message=bank/f'message-{i}.base64';run([op/'common-driver',bank/'operator.json',bank/'funding-ready.json','prepare',plan,message],f'aggregate-prepare-{i}');return json.loads(plan.read_text()),message
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:plans=list(pool.map(prepare,range(6)))
  assert len({x[0]['intent_id'] for x in plans})==1 and len({x[1].read_bytes() for x in plans})==1
  identity=plans[0][0]['intent_id'];copy(bank/'plan-0.json',bank/'aggregate-funding.plan.json')
  assert sql('SELECT count(*) FROM issuer_treasury_burn_intents')=='1'
  assert sql("SELECT string_agg(batch_id::text,',' ORDER BY batch_id) FROM issuer_treasury_burn_members")=='1,2'
  assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses WHERE NOT released')=='1'
  run([a.pg_bin/'createdb','-T','common_bank','common_expiry'],'expiry-db-clone')
  expiry_cfg=cfg|{'database_url':expiry_url};save(bank/'expiry-operator.json',expiry_cfg)
  copy(bank/'message-0.base64',bank/'aggregate-funding.message.base64');wait(bank/'aggregate-funding.signed.packet.base64',sbf)
  durable_packet(bank/'aggregate-funding.signed.packet.base64',bank/'aggregate-funding.external.packet.base64')
  mode.write_text('common-fund-send');run([op/'common-driver',bank/'operator.json',bank/'funding-ready.json','submit',identity,bank/'aggregate-funding.external.packet.base64','fund'],'funded-lost-ack',ok=False)
  funded=wait(bank/'funded.json',sbf);assert funded['cash_debited']=='299003525' and funded['exact_intent_replays']==2
  assert sql('SELECT state FROM issuer_treasury_burn_intents')=='0'
  mode.write_text('common-funded')
  for i in range(2):assert json.loads(run([op/'common-driver',bank/'operator.json',bank/'funding-ready.json','reconcile',identity],f'funded-restart-{i}'))['state']=='funded'
  assert sql('SELECT string_agg(amount::text,\',\' ORDER BY batch_id) FROM issuer_treasury_burn_liabilities')=='1500000000,300'
  assert sql('SELECT count(*) FROM issuer_treasury_burn_liabilities WHERE state=1')=='2'
  assert sql("SELECT burn::text FROM issuer_lightning_weekly WHERE batch_id=1")=='75000000'
  assert sql("SELECT source_msat::text FROM issuer_btc_conversion_intents WHERE bucket=1")=='75000000'
  assert sql("SELECT count(*) FROM issuer_btc_conversion_output_uses WHERE NOT released")=='1'
  expiry=wait(bank/'expiry-ready.json',sbf);mode.write_text('common-expiry')
  run([op/'common-driver',bank/'expiry-operator.json',bank/'expiry-ready.json','reconcile',identity],'elapsed-without-tombstone',ok=False)
  assert sql('SELECT state FROM issuer_treasury_burn_intents',expiry_url)=='0'
  report=json.loads(run([op/'common-driver',bank/'expiry-operator.json',bank/'expiry-ready.json','expiry',identity,bank/'aggregate-expiry.message.base64'],'expiry-prepare'));assert report['state']=='expiry_pending'
  wait(bank/'aggregate-expiry.signed.packet.base64',sbf);durable_packet(bank/'aggregate-expiry.signed.packet.base64',bank/'aggregate-expiry.external.packet.base64')
  mode.write_text('common-expire-send');run([op/'common-driver',bank/'expiry-operator.json',bank/'expiry-ready.json','submit',identity,bank/'aggregate-expiry.external.packet.base64','expiry'],'expiry-lost-ack',ok=False)
  expired=wait(bank/'expired.json',sbf);assert expired['source_unchanged'] is True
  assert sql('SELECT state FROM issuer_treasury_burn_intents',expiry_url)=='0'
  mode.write_text('common-expired')
  for i in range(2):assert json.loads(run([op/'common-driver',bank/'expiry-operator.json',bank/'expiry-ready.json','reconcile',identity],f'expiry-restart-{i}'))['state']=='expired_unfunded'
  assert sql('SELECT count(*) FROM issuer_treasury_burn_members WHERE released',expiry_url)=='2'
  assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses WHERE released',expiry_url)=='1'
  assert sql('SELECT count(*) FROM issuer_treasury_burn_liabilities WHERE state=0',expiry_url)=='2'
  for name,target in [('funded',url),('expired',expiry_url)]:run([a.pg_bin/'pg_dump',target,'-f',out/(name+'.sql')],name+'-dump')
  save(bank/'btc-proof-complete.json',{'status':'passed'});assert btc.wait(timeout=30)==0 and sbf.wait(timeout=30)==0
  save(out/'summary.json',{'status':'passed','cash':'299003525','canonical_source_ids':['1','2','9223372036854775809'],'actual_sol_swap':True,'actual_provider_spl_transfer':True,'exact_mesh_tag14':True,'fresh_hash_replays':2,'six_workers_single_intent':True,'actual_alternate_tag15':True,'restart_authenticated_funding_and_expiry':True,'original_denominations_preserved':True,'boundary':'Fresh owned genesis and explicit provider liquidity; regtest LND/mock provider protocol; controlled SBF Clock/height/finality. No historical receipt relabeling, live funds/provider settlement/finality, oracle guardian, organizational independence, keeper or deployment claim.'})
 finally:
  (bank/'abort').touch()
  for c in reversed(children):
   if c.poll() is None:
    os.killpg(c.pid,signal.SIGTERM)
    try:c.wait(timeout=20)
    except subprocess.TimeoutExpired:os.killpg(c.pid,signal.SIGKILL);c.wait()
  for f in streams:f.close()
  if pg:run([a.pg_bin/'pg_ctl','-D',out/'pg-data','-m','fast','-w','stop'],'pg-stop')
 after={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file() and str(p.relative_to(source)) in before};assert before==after;save(out/'source-after.json',after)
 ext_after={str(p.relative_to(ext)):sha(p) for p in ext.rglob('*') if p.is_file() and str(p.relative_to(ext)) in ext_before};assert ext_before==ext_after;save(out/'external-after.json',ext_after)
 records=[{'path':str(p.relative_to(out)),'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(out.rglob('*')) if p.is_file() and 'pg-data' not in p.parts]
 save(out/'manifest.json',{'records':records});print(json.dumps({'manifest':str(out/'manifest.json'),'sha256':sha(out/'manifest.json'),'records':len(records)}))
def bytes_to_hex_address(value):
 n=0
 for c in value:n=n*58+'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(c)
 return n.to_bytes(32,'big').hex()
if __name__=='__main__':main()
