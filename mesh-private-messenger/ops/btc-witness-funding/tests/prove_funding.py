#!/usr/bin/env python3
"""Fresh owned BTC arrival -> explicit Mesh accounting handoff -> actual fund_once.
No scheduler/signing service: private test keys stay inside one bounded Rust test.
"""
import base64,concurrent.futures,hashlib,http.server,json,os,socket,struct,subprocess,threading,time,urllib.parse
from pathlib import Path
W=Path(__file__).resolve().parent;FIXTURE=Path(os.environ.get('BTC_FUNDING_FIXTURE_BIN',W/'funding-fixture'));OUT=W/'evidence'/os.environ.get('BTC_FUNDING_OUTPUT','fresh');OUT.mkdir(exist_ok=False)
BANK=OUT/'bank';BANK.mkdir();URL=os.environ['BTC_FUNDING_DATABASE']
PSQL=[str(Path(os.environ.get('PG_BIN','/opt/homebrew/opt/postgresql@17/bin'))/'psql'),'-X',URL,'-qAt','-v','ON_ERROR_STOP=1']
ELF=Path(os.environ['BTC_FUNDING_REWARDS_ELF']).resolve()
TOKEN=Path(os.environ['BTC_FUNDING_TOKEN_ELF']).resolve()
BIN=next(p for p in (Path(os.environ.get('CARGO_TARGET_DIR',W/'sbf/target'))/'debug/deps').glob('witness-*') if p.is_file() and os.access(p,os.X_OK))
ALPH='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58(b):
 n=int.from_bytes(b,'big');s=''
 while n:n,r=divmod(n,58);s=ALPH[r]+s
 return '1'*(len(b)-len(b.lstrip(b'\0')))+s
def wait(p,child=None,timeout=120):
 end=time.monotonic()+timeout
 while not p.is_file():
  if child and child.poll() is not None:raise AssertionError(('child stopped',child.returncode,p))
  assert time.monotonic()<end,('timeout',p)
  time.sleep(.03)
 return json.loads(p.read_text())
def sql(q,ok=True):
 r=subprocess.run(PSQL,input=q,text=True,capture_output=True);assert (r.returncode==0)==ok,(q,r.stderr);return r.stdout.strip()
class Bank:
 serial=0
 lock=threading.Lock()
 def command(self,**value):
  with self.lock:
   n=self.serial;self.serial+=1
   p=BANK/f'command-{n}.json';temporary=p.with_suffix('.tmp');temporary.write_text(json.dumps(value)+'\n');os.replace(temporary,p);return wait(BANK/f'reply-{n}.json',self.child)
bank=Bank();rpc_log=[];mode='healthy';initial=None
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  try:
   size=int(self.headers.get('Content-Length',0));assert 0<size<=8192
   request=json.loads(self.rfile.read(size));assert request['method'] in ['getGenesisHash','getMultipleAccounts']
   rpc_log.append({'source':self.server.index,'request':request,'mode':mode})
   if request['method']=='getGenesisHash':result=b58(bytes.fromhex(initial['cluster'])) if mode!='genesis' else b58(b'x'*32)
   else:
    keys,options=request['params'];assert len(keys)==2 and options['commitment']=='finalized'
    actual=bank.command(kind='inspect',keys=keys);accounts=[r['account'] for r in actual['accounts']];slot=actual['slot']
    if mode=='slot':slot+=1
    if accounts[0] is not None:
     if mode=='owner':accounts[0]['owner']='11111111111111111111111111111111'
     if mode in ['pool','amount','future','disagreed','source','mint','funder','id','epoch','kind']:
      raw=bytearray(base64.b64decode(accounts[0]['data'][0]))
      if mode=='pool':raw[4]^=1
      if mode=='amount':raw[112]^=1
      for key,offset in [('source',120),('mint',152),('funder',36),('id',68),('epoch',100),('kind',108)]:
       if mode==key:raw[offset]^=1
      if mode=='future':struct.pack_into('<q',raw,184,int(time.time())+10**9)
      if mode=='disagreed' and self.server.index==1:raw[112]^=1
      accounts[0]['data'][0]=base64.b64encode(raw).decode()
    if mode=='partial':accounts=accounts[:1]
    result={'context':{'slot':slot},'value':accounts}
   response={'jsonrpc':'2.0','id':request['id'],'result':result};status=200
  except Exception as e:response={'owned_fixture_error':repr(e)};status=500
  raw=json.dumps(response).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
servers=[];handles=[];processes=[];records=[]
try:
 for i in range(2):
  s=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);s.index=i;threading.Thread(target=s.serve_forever,daemon=True).start();servers.append(s)
 providers=[f'http://127.0.0.1:{s.server_port}' for s in servers]
 db=urllib.parse.urlsplit(URL);assert db.hostname=='127.0.0.1' and db.port not in [55438,61546] and db.path.startswith('/witness_') and db.password is None
 subprocess.run([str(Path(os.environ.get('PG_BIN','/opt/homebrew/opt/postgresql@17/bin'))/'createdb'),'-h127.0.0.1','-p'+str(db.port),'-U'+db.username,db.path[1:]],check=True)
 for p in sorted((W/'sources/credit-issuer/migrations').glob('*.sql')):sql('BEGIN;\n'+p.read_text()+'\nCOMMIT;')
 env=dict(os.environ,BTC_SBF_OUTPUT=str(BANK),BTC_SBF_TOKEN_ELF=str(TOKEN),BTC_SBF_NOW=str(int(time.time())),BTC_SBF_TRANSFER_MICROS='49699202',BTC_FUNDING_PROVIDERS=json.dumps(providers),MORSE_SOL_CONVERSION_REWARDS_ELF=str(ELF))
 log=(OUT/'sbf.log').open('wb');handles.append(log);bank.child=subprocess.Popen([str(BIN),'--exact','actual_owned_btc_witness_funding','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT);processes.append(bank.child)
 initial=wait(BANK/'initial.json',bank.child)
 proofenv=dict(os.environ,BTC_FIXTURE_PRODUCT=str(W/'product'),LIGHTNING_TEST_TOOLS=str(Path(os.environ['LIGHTNING_TEST_TOOLS']).resolve()))
 pins={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [FIXTURE,W/'conversion-fixture',BIN,ELF,TOKEN,*[W/'toolchain'/n for n in ['meshc','libmesh_rt.a','libmesh_test_rt.a']]]}
 (OUT/'inputs.json').write_text(json.dumps({'pins':pins,'database':URL,'treasury_origins':providers,'boundary':'Fresh owned test mint/key bank. Controlled finalized RPC fixture, no external provider independence/live funds.'},indent=2)+'\n')
 log=(OUT/'btc-conversion.log').open('wb');handles.append(log)
 child=subprocess.Popen(['python3',str(W/'harness/prove.py'),'--output',str(OUT/'conversion'),'--driver',str(W/'conversion-fixture'),'--sbf',str(BIN),'--driver-sha',pins[str(W/'conversion-fixture')],'--sbf-sha',pins[str(BIN)],'--external-bank',str(BANK),'--database-url',URL,'--bucket','witness'],env=proofenv,stdout=log,stderr=subprocess.STDOUT);processes.append(child)
 arrived=wait(BANK/'btc-arrived.json',child,timeout=240);conversion=arrived['actual_arrival']['intent_id'];assert arrived['actual_arrival']['source_msat']=='50000000' and arrived['actual_arrival']['amount']=='49699202'
 config=OUT/'conversion/public-config.json';fixture_env=dict(os.environ,BTC_FIXTURE_CONFIG=str(config),BTC_FIXTURE_DATABASE=URL,BTC_FIXTURE_MACAROON='00',BTC_FIXTURE_JUDGE=initial['judge'],BTC_FIXTURE_LOG=initial['log_name'])
 def command(*args,ok=True):
  r=subprocess.run([str(FIXTURE),*map(str,args)],env=fixture_env,text=True,capture_output=True,timeout=90)
  records.append({'args':args,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert (r.returncode==0)==ok,(args,r.stderr)
  return json.loads(r.stdout) if ok else r.stderr
 immutable_tables=['issuer_lightning_revenue','issuer_lightning_weekly','issuer_btc_conversion_outputs','issuer_btc_conversion_accounting']
 def immutable():return {t:sql("SELECT encode(sha256(convert_to(json_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'UTF8')),'hex') FROM "+t+' t') for t in immutable_tables}
 before=immutable()
 with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:plans=list(pool.map(lambda _:command('prepare',conversion),range(6)))
 assert all(p==plans[0] for p in plans);old=plans[0];assert old['state']==0 and old['amount']=='49699202'
 old_packet=command('instruction',old['id']);(OUT/'old-instruction.json').write_text(json.dumps(old_packet,indent=2)+'\n')
 reservation=sql("SELECT encode(operation_id,'hex') FROM issuer_btc_conversion_output_uses")
 assert command('prepare',conversion)==old
 advanced=int(old['epoch'])+1;bank.command(kind='warp',epoch=advanced)
 refused=bank.command(kind='fund',epoch=int(old['epoch']),instruction=old_packet,expect_ok=False);assert not refused['ok']
 current=command('prepare',conversion);assert current['state']==0 and current['id']!=old['id'] and int(current['epoch'])==advanced
 assert command('load',old['id'])['state']==2
 assert sql("SELECT encode(operation_id,'hex') FROM issuer_btc_conversion_output_uses")==reservation
 assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses')=='1'
 bank.command(kind='open')
 packet=command('instruction',current['id']);(OUT/'current-instruction.json').write_text(json.dumps(packet,indent=2)+'\n')
 paid=bank.command(kind='fund',epoch=advanced,instruction=packet,expect_ok=True)
 def units(account):return struct.unpack_from('<Q',base64.b64decode(account['data'][0]),64)[0]
 assert units(paid['source_before'])-units(paid['source_after'])==49699202
 assert units(paid['vault_after'])-units(paid['vault_before'])==49699202
 assert len(base64.b64decode(paid['receipt']['data'][0]))==192
 # Actual accepted SBF receipt is refused by reader/storage if source, slot,
 # quorum or exact economic binding is changed. Saved state stays pending.
 for bad in ['genesis','slot','partial','owner','pool','amount','future','disagreed','source','mint','funder','id','epoch','kind']:
  mode=bad;command('reconcile',current['id'],ok=False);assert command('load',current['id'])['state']==0
 mode='healthy';funded=command('reconcile',current['id']);assert funded['state']==1
 duplicate=bank.command(kind='fund',epoch=advanced,instruction=packet,expect_ok=True)
 assert duplicate['source_before']==duplicate['source_after'] and duplicate['vault_before']==duplicate['vault_after'] and duplicate['receipt']==paid['receipt']
 bank.command(kind='warp',epoch=advanced+1)
 permanent=bank.command(kind='fund',epoch=advanced,instruction=packet,expect_ok=True)
 assert permanent['source_before']==permanent['source_after'] and permanent['vault_before']==permanent['vault_after'] and permanent['receipt']==paid['receipt']
 assert command('prepare',conversion)==funded and command('reconcile',current['id'])==funded
 command('absent',current['id'],advanced+1,ok=False)
 command('reserve',conversion,advanced+1);assert sql('SELECT count(*) FROM issuer_btc_witness_funding')=='2'
 for query in ['DELETE FROM issuer_btc_witness_funding',"UPDATE issuer_btc_witness_funding SET state=0,receipt=NULL WHERE state=1",'UPDATE issuer_btc_conversion_output_uses SET released=true']:
  sql(query,False)
 assert before==immutable()
 receipt=base64.b64decode(paid['receipt']['data'][0]);(OUT/'actual-funding-receipt.hex').write_text(receipt.hex())
 sql("SELECT 1")
 # Exact permanent receipt read after a new DB client/process; no new attempts.
 assert command('load',current['id'])==funded
 (BANK/'btc-proof-complete.json').write_text('{"completed":true}\n');child.wait(timeout=30);assert child.returncode==0
 bank.command(kind='stop');bank.child.wait(timeout=30);assert bank.child.returncode==0
 # Restart after actual SBF/receipt/RPC recovery, then replay without any RPC.
 pg=str(Path(os.environ.get('PG_BIN','/opt/homebrew/opt/postgresql@17/bin'))/'pg_ctl')
 for args in [['-D',str(W/'pg/data'),'-m','fast','-w','stop'],['-D',str(W/'pg/data'),'-l',str(W/'evidence/postgres.log'),'-w','start']]:
  r=subprocess.run([pg,*args],text=True,capture_output=True);records.append({'pg_ctl':args,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0
 before_rpc=len(rpc_log);assert command('prepare',conversion)==funded and command('reconcile',current['id'])==funded and len(rpc_log)==before_rpc
 assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in pins.items())
 result={'status':'passed','original_source_msat':'50000000','exact_output_units':'49699202','permanent_reservation':reservation,'old':old,'current':funded,'actual_sbf_attempts':4,'old_epoch_refused':True,'duplicate_and_rollover_noop':True,'funded_restart_no_rpc':True,'rpc_mutations_refused':14,'prepare_race_processes':6,'unchanged_accounting':before,'scope':'Existing program-identity/two-source trust; no current Pool/code-release authentication, external provider/finality claim, scheduler or live funds.'}
 (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
finally:
 (OUT/'commands.json').write_text(json.dumps(records,indent=2)+'\n');(OUT/'rpc.json').write_text(json.dumps(rpc_log,indent=2)+'\n')
 (BANK/'abort').touch()
 # Conversion harness observes abort while its LND context is still alive.
 for p in reversed(processes):
  if p.poll() is None:
   if p is bank.child:p.terminate()
   try:p.wait(timeout=15)
   except subprocess.TimeoutExpired:
    p.terminate()
    try:p.wait(timeout=15)
    except subprocess.TimeoutExpired:p.kill();p.wait()
 for s in servers:s.shutdown();s.server_close()
 for h in handles:h.close()
