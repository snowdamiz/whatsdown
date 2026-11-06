#!/usr/bin/env python3
"""Owned loopback Kraken/LND/PG/SBF dogfood. Never accepts a live origin/key."""
import argparse,base64,concurrent.futures,contextlib,hashlib,hmac,http.server,importlib.util,json,os,secrets,socket,struct,subprocess,threading,time,urllib.parse
from pathlib import Path
import external_bank
import signal
def owned_stop(signum,frame):
 raise KeyboardInterrupt("owned proof termination")
signal.signal(signal.SIGTERM,owned_stop)
ROOT=Path(__file__).resolve().parents[1]
PRODUCT=Path(os.environ.get('BTC_FIXTURE_PRODUCT',ROOT.parents[1]/'mesh-private-messenger')).resolve()
spec=importlib.util.spec_from_file_location('owned_lightning',PRODUCT/'scripts/lightning_regtest.py');lnmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(lnmod)
PSQL=['/opt/homebrew/opt/postgresql@17/bin/psql','-X','-h','127.0.0.1','-p','61546','-U','andreyyurlov','-d','postgres','-qAt','-v','ON_ERROR_STOP=1']
SECRET=bytes.fromhex('0b'*20)
METHOD='11111111-2222-3333-4444-555555555555';NETWORK='66666666-7777-8888-9999-aaaaaaaaaaaa';ADDRESS='AB7J4FF-BGM7G-V2JMIH'
ALPH='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58(b):
 n=int.from_bytes(b,'big');s=''
 while n:n,r=divmod(n,58);s=ALPH[r]+s
 return '1'*(len(b)-len(b.lstrip(b'\0')))+s
ORACLE=b58(hashlib.sha256(b'owned-btc-oracle').digest())
def sql(body):
 r=subprocess.run(PSQL,input=body,text=True,capture_output=True)
 if r.returncode:raise AssertionError(r.stderr)
 return r.stdout.strip()
def reset():
 sql('DROP SCHEMA public CASCADE;CREATE SCHEMA public;')
 for p in sorted((ROOT/'sources/credit-issuer/migrations').glob('*.sql')):sql('BEGIN;\n'+p.read_text()+'\nCOMMIT;')
def wait_file(p,child=None):
 end=time.monotonic()+120
 while not p.is_file():
  if child and child.poll() is not None:raise AssertionError('owned SBF stopped before handoff')
  if time.monotonic()>end:raise AssertionError('owned file handoff timeout')
  time.sleep(.05)
 return json.loads(p.read_text())
def amount(raw):return {'asset':{'class':'currency','name':'USDC'},'amount':raw}
class State:
 def __init__(self,ln,out,fault,bucket):
  self.bucket=bucket;self.ln=ln;self.out=out;self.fault=fault;self.counts={};self.last_nonce=0;self.trace=[];self.error=[];self.order=None;self.sbf=None;self.mode='healthy';self.oracle_at=int(time.time());self.bootstrap=None;self.pagination='page2';self.lock=threading.RLock()
  self.invoice_msat=74999000 if bucket=='burn' else 49999000
  self.invoice_btc='0.00074999' if bucket=='burn' else '0.00049999'
  self.volume='0.00074849' if bucket=='burn' else '0.00049899'
  self.cost='74.849' if bucket=='burn' else '49.899'
  self.fee='0.149698' if bucket=='burn' else '0.099798'
  self.gross='74.699302' if bucket=='burn' else '49.799202'
  self.net='74.599302' if bucket=='burn' else '49.699202'
  self.output_micros=74599302 if bucket=='burn' else 49699202
  self.provider_reserve=150000 if bucket=='burn' else 100000
 def event(self,path):
  with self.lock:self.counts[path]=self.counts.get(path,0)+1
 def record(self,**data):
  with self.lock:self.trace.append(data);(self.out/'http-trace.json').write_text(json.dumps(self.trace,indent=2)+'\n')
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def send(self,value,status=200):
  raw=json.dumps(value,separators=(',',':')).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):self.handle_request()
 def do_POST(self):self.handle_request()
 def handle_request(self):
  state=self.server.state
  try:
   size=int(self.headers.get('Content-Length',0));assert 0<=size<=16384
   body=self.rfile.read(size);path=urllib.parse.urlsplit(self.path).path
   if self.server.role.startswith('rpc'):return self.rpc(json.loads(body))
   if self.server.role=='lnd':
    state.event(path);result=state.ln.lnd('payer',self.path,None if self.command=='GET' else json.loads(body),timeout=60)
    if path=='/v2/router/send' and state.fault=='payment-after':self.close_connection=True;return
    return self.send(result)
   assert self.headers['API-Key']=='owned-test-account-public-api-key'
   fields=urllib.parse.parse_qs(body.decode(),strict_parsing=True) if path.startswith('/0/') else {}
   nonce=fields['nonce'][0] if fields else self.headers['API-Nonce']
   assert nonce.isdecimal() and str(int(nonce))==nonce and int(nonce)>state.last_nonce
   state.last_nonce=int(nonce)
   message=self.path.encode()+hashlib.sha256(nonce.encode()+body).digest()
   assert hmac.compare_digest(base64.b64encode(hmac.new(SECRET,message,hashlib.sha512).digest()).decode(),self.headers['API-Sign'])
   if fields:assert body.startswith(('nonce='+nonce+'&').encode())
   state.event(path);state.record(role='kraken',method=self.command,path=self.path,nonce=nonce,body_sha256=hashlib.sha256(body).hexdigest())
   result=self.kraken(path,fields,body)
   if state.fault==path.rsplit('/',1)[-1]+'-after':self.close_connection=True;return
   self.send(result)
  except Exception as e:
   state.error.append(type(e).__name__+': '+str(e));self.send({'owned_fixture_error':type(e).__name__},500)
 def kraken(self,path,fields,body):
  s=self.server.state;b=s.bootstrap
  if path=='/funding/v1/methods/withdraw':return {'methods':[{'method_id':METHOD,'withdrawal':{},'asset':{'class':'currency','name':'USDC'},'network':{'network_id':NETWORK,'network_name':'Solana','contract_address':b['mint']},'minimum_amount':'1','maximum_amount':'1000000'}]}
  if path=='/funding/v1/addresses':return {'addresses':[{'address_id':ADDRESS,'scope':{'method_id':METHOD},'verified':True,'address_details':{'crypto':{'address':b['owner']}}}]}
  if path=='/0/private/DepositAddresses':
   assert fields['asset']==['XBT'] and fields['method']==['Bitcoin Lightning'] and fields['new']==['true']
   assert fields['amount']==[s.invoice_btc]
   response=s.ln.lnd('issuer','/v1/invoices',{'value_msat':str(s.invoice_msat),'expiry':'900','memo':'owned provider BTC conversion'})
   return {'error':[],'result':[{'address':response['payment_request'],'expiretm':'0','new':True}]}
  if path=='/0/private/AddOrder':
   assert fields['pair']==['XBTUSDC'] and fields['type']==['sell'] and fields['ordertype']==['limit'] and fields['timeinforce']==['FOK'] and fields['oflags']==['fciq']
   assert fields['volume']==[s.volume] and len(fields['cl_ord_id'][0])==32
   assert s.order is None,'duplicate provider order effect'
   s.order=fields;return {'error':[],'result':{'txid':['ORDER-1']}}
  if path=='/0/private/QueryOrders':
   assert fields['txid']==['ORDER-1'] and s.order
   return {'error':[],'result':{'ORDER-1':{'cl_ord_id':s.order['cl_ord_id'][0],'time_in_force':'fok','descr':{'pair':'XBTUSDC','type':'sell','ordertype':'limit','price':s.order['price'][0],'leverage':'none','close':''},'vol':s.volume,'vol_exec':s.volume,'status':'closed','cost':s.cost,'trades':['TRADE-1']}}}
  if path=='/0/private/QueryTrades':
   assert fields['txid']==['TRADE-1'];return {'error':[],'result':{'TRADE-1':{'ordertxid':'ORDER-1','pair':'XBTUSDC','type':'sell','ordertype':'limit','margin':'0','vol':s.volume,'cost':s.cost,'ledgers':['L-BTC','L-USDC']}}}
  if path=='/0/private/QueryLedgers':
   assert fields['id']==['L-BTC,L-USDC'];return {'error':[],'result':{'L-BTC':{'refid':'TRADE-1','type':'trade','aclass':'currency','asset':'XXBT','amount':'-'+s.volume,'fee':'0','balance':'999999999'},'L-USDC':{'refid':'TRADE-1','type':'trade','aclass':'currency','asset':'USDC','amount':s.cost,'fee':s.fee,'balance':'999999999'}}}
  if path.startswith('/funding/v1/fees/'):
   assert path.endswith(METHOD);q=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query);assert q['amount']==[s.gross] and q['fee_included']==['true']
   return {'gross_amount':amount(s.gross),'net_amount':amount(s.net),'fee':amount('0.1'),'withdrawal_fee_token':'exact-owned-fee'}
  if path=='/funding/v1/withdrawals' and self.command=='POST':
   value=json.loads(body);assert value=={'scope':{'method_id':METHOD},'address_id':ADDRESS,'amount':{'asset_amount':amount(s.gross)},'fee':{'quoted_fee':{'token':'exact-owned-fee'},'fee_included':True},'expected_address':b['owner']}
   return {'withdrawal_id':'FTABCDE-'+'x'*22,'gross_amount':{'asset_amount':amount(s.gross)},'net_amount':{'asset_amount':amount(s.net)},'fee':{'asset_amount':amount('0.1')}}
  if path=='/funding/v1/withdrawals':
   q=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
   if 'cursor' not in q:
    assert q=={'scope[method_id]':[METHOD],'limit':['100']}
    return {'withdrawals':[{'withdrawal_id':'UNRELATED-WITHDRAWAL'}],'next_cursor':None if s.pagination=='malformed' else 'page+/=2'}
   assert len(q)==1 and len(q['cursor'])==1,'cursor request must omit all other parameters'
   cursor=q['cursor'][0]
   if s.pagination=='repeated':return {'withdrawals':[],'next_cursor':cursor}
   if s.pagination=='long':
    assert cursor in ['page+/='+str(i) for i in range(2,7)]
    page=int(cursor.rsplit('=',1)[1])
    if page<6:return {'withdrawals':[{'withdrawal_id':'UNRELATED-'+str(page)}],'next_cursor':'page+/='+str(page+1)}
   else:assert cursor=='page+/=2'
   return {'withdrawals':[{'withdrawal_id':'FTABCDE-'+'x'*22,'method_id':METHOD,'address_id':ADDRESS,'amount':amount(s.net),'fee':amount('0.1'),'status':'success' if s.sbf else 'pending',**({'onchain_transaction':s.sbf['signature']} if s.sbf else {})}]}
  raise AssertionError('unexpected provider path '+path)
 def rpc(self,request):
  s=self.server.state;role=self.server.role;method=request['method'];s.record(role=role,method=method)
  if s.mode=='outage' and role!='rpc0':return self.send({'error':'owned outage'},503)
  if method=='getGenesisHash':result=b58(bytes.fromhex(s.bootstrap['cluster'])) if s.mode!='chain' or role=='rpc0' else b58(b'x'*32)
  elif method=='getAccountInfo':
   assert request['params'][0]==ORACLE
   data=bytearray(134);data[:8]=bytes.fromhex('22f123639d7ef4cd');data[40]=1;data[41:73]=bytes.fromhex('e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43');struct.pack_into('<Q',data,73,100000000000);struct.pack_into('<Q',data,81,1000);struct.pack_into('<i',data,89,-6)
   at=s.oracle_at+61 if s.mode=='future' else s.oracle_at-61 if s.mode=='stale' else s.oracle_at
   struct.pack_into('<QQ',data,93,at,at-1);struct.pack_into('<Q',data,125,999)
   result={'context':{'slot':1000},'value':{'owner':'rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp','lamports':1000000,'executable':False,'rentEpoch':0,'data':[base64.b64encode(data).decode(),'base64']}}
  elif method=='getTransaction':
   assert s.sbf and request['params'][0]==s.sbf['signature'];result=json.loads(json.dumps(s.sbf['transaction']))
   if role!='rpc0':
    row=next(x for x in result['meta']['postTokenBalances'] if x['owner']==s.bootstrap['owner'])
    if s.mode=='delta':row['uiTokenAmount']['amount']=str(int(row['uiTokenAmount']['amount'])+1)
    if s.mode=='mint':row['mint']=b58(b'z'*32)
    if s.mode=='owner':row['owner']=b58(b'z'*32)
  else:raise AssertionError('unexpected RPC method '+method)
  self.send({'jsonrpc':'2.0','id':request['id'],'result':result})
@contextlib.contextmanager
def servers(state):
 stack=contextlib.ExitStack();urls={}
 try:
  for role in ['rpc0','rpc1','rpc2','kraken','lnd']:
   server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.role=role;server.state=state;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();urls[role]=f'http://127.0.0.1:{server.server_port}';stack.callback(server.server_close);stack.callback(server.shutdown)
  yield urls
 finally:stack.close()
def configuration(state,urls):
 b=state.bootstrap
 return {'MESSENGER_BTC_CONVERSION_TREASURY_CONFIG_HASH_HEX':(b.get('treasury_config') or '77'*32),'MORSE_BTC_CONVERSION_MODE':'test','MESSENGER_BTC_CONVERSION_DEDICATED_ACCOUNT':'yes','MESSENGER_BTC_CONVERSION_ACCOUNT_PROFILE_HEX':'11'*32,'MESSENGER_KRAKEN_API_KEY':'owned-test-account-public-api-key','MESSENGER_KRAKEN_ORIGIN':urls['kraken'],'MESSENGER_KRAKEN_LIGHTNING_PAYEE_HEX':state.ln.nodes['issuer']['public_key'],'MESSENGER_KRAKEN_WITHDRAW_METHOD':METHOD,'MESSENGER_KRAKEN_WITHDRAW_NETWORK':NETWORK,'MESSENGER_KRAKEN_WITHDRAW_ADDRESS_ID':ADDRESS,'MESSENGER_BTC_CONVERSION_RPC_A':urls['rpc0'],'MESSENGER_BTC_CONVERSION_RPC_B':urls['rpc1'],'MESSENGER_BTC_CONVERSION_RPC_C':urls['rpc2'],'MESSENGER_BTC_CONVERSION_GENESIS':b58(bytes.fromhex(b['cluster'])),'MESSENGER_BTC_CONVERSION_ORACLE':ORACLE,'MESSENGER_BTC_CONVERSION_OWNER':b['owner'],'MESSENGER_BTC_CONVERSION_MAX_SOURCE_MSAT':'1000000000','MESSENGER_BTC_CONVERSION_MIN_ORDER_SATS':'1000','MESSENGER_BTC_CONVERSION_ROUTING_FEE_MSAT':'1000','MESSENGER_BTC_CONVERSION_TRADE_FEE_BPS':'20','MESSENGER_BTC_CONVERSION_WITHDRAW_FEE_UNITS':'100000','MESSENGER_BTC_CONVERSION_PRICE_TICK_MICROS':'100000','MESSENGER_BTC_CONVERSION_MAX_INVOICE_SECONDS':'900','mint':b['mint'],'lnd_origin':urls['lnd'],'lnd_payee':state.ln.nodes['payer']['public_key']}
def prove(output,driver,sbf_binary,fault,bucket,driver_sha,sbf_sha,external=None,database_url=None,draft_recovery=False):
 global PSQL
 if external:
  parsed=urllib.parse.urlsplit(database_url or "")
  assert parsed.scheme=="postgresql" and parsed.hostname=="127.0.0.1" and parsed.port and parsed.password is None and parsed.path not in ["","/"],"explicit owned loopback database required"
  PSQL=["/opt/homebrew/opt/postgresql@17/bin/psql","-X",database_url,"-qAt","-v","ON_ERROR_STOP=1"]
 else:assert database_url is None,"database override belongs only to external-bank mode"
 pins={str(driver):driver_sha,str(sbf_binary):sbf_sha}
 for path,expected in pins.items():
  assert len(expected)==64 and all(c in '0123456789abcdef' for c in expected)
  assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected,'immutable fixture executable pin mismatch'
 output.mkdir(parents=True,exist_ok=False);(output/'inputs.json').write_text(json.dumps({'executable_pins':pins,'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'external_owned_database':database_url,'external_bank':str(external) if external else None},indent=2)+'\n')
 for name in ['prove.py','external_bank.py','fixture_main.mpl']:(output/('input-'+name)).write_bytes((Path(__file__).parent/name).read_bytes())
 dependencies={}
 tools=Path(os.environ.get('LIGHTNING_TEST_TOOLS',lnmod.DEFAULT_TOOLS))
 for name,path in [('lightning_regtest',PRODUCT/'scripts/lightning_regtest.py'),('bitcoind',Path(os.environ.get('BITCOIND',tools/'bitcoin-31.1/bin/bitcoind'))),('lnd',Path(os.environ.get('LND',tools/'lnd-darwin-arm64-v0.21.4-beta/lnd')))]:
  dependencies[name]={'path':str(path.resolve()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
 (output/'fixture-dependencies.json').write_text(json.dumps(dependencies,indent=2)+'\n')
 (output/'input-lightning_regtest.py').write_bytes((PRODUCT/'scripts/lightning_regtest.py').read_bytes())
 if not external:reset()
 with lnmod.LightningRegtest() as ln:
  state=State(ln,output,fault,bucket);child=None;banklog=None;chain=None;initial_digest=None
  if external:
   assert bucket=='witness' and not fault,'common bank requires the exact complete witness path'
   bank=external.resolve();state.bootstrap,chain,initial_digest=external_bank.bootstrap(bank/'initial.json')
   (output/'common-bank-initial.json').write_bytes((bank/'initial.json').read_bytes())
  else:
   bank=output/'sbf';bank.mkdir();banklog=(output/'sbf.log').open('wb')
   env=dict(os.environ,BTC_SBF_OUTPUT=str(bank),BTC_SBF_TOKEN_ELF='/Users/andreyyurlov/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/litesvm-0.17.0/src/programs/elf/spl_token-3.5.0.so',BTC_SBF_NOW=str(int(time.time())),BTC_SBF_HANDOFF='1',BTC_SBF_TRANSFER_MICROS=str(state.output_micros),BTC_SBF_SCOPE=str((ROOT.parents[1]/'.morse/witness-proof/sol-conversion-final-layout5/burn/initial.json').resolve()),BTC_SBF_SCOPE_SHA256=hashlib.sha256((ROOT.parents[1]/'.morse/witness-proof/sol-conversion-final-layout5/burn/initial.json').read_bytes()).hexdigest())
   child=subprocess.Popen([str(sbf_binary),'--exact','actual_owned_classic_spl_arrival','--nocapture'],env=env,stdout=banklog,stderr=subprocess.STDOUT)
  try:
   if not external:state.bootstrap=wait_file(bank/'bootstrap.json',child)
   with servers(state) as urls:
    cfg=configuration(state,urls)
    if chain:cfg['treasury_chain']=chain
    configfile=output/'public-config.json';configfile.write_text(json.dumps(cfg,indent=2)+'\n');macaroon=(ln.nodes['payer']['directory']/'data/chain/bitcoin/regtest/admin.macaroon').read_bytes().hex()
    env=dict(os.environ,BTC_FIXTURE_CONFIG=str(configfile),BTC_FIXTURE_DATABASE=database_url or 'postgresql://andreyyurlov@127.0.0.1:61546/postgres',BTC_FIXTURE_MACAROON=macaroon,MESSENGER_KRAKEN_API_SECRET_HEX=SECRET.hex(),BTC_FIXTURE_BUCKET=bucket);counter=0;command_lock=threading.Lock()
    def command(*args,ok=True):
     nonlocal counter
     with command_lock:counter+=1;number=counter
     r=subprocess.run([str(driver),*map(str,args)],env=env,text=True,capture_output=True,timeout=90);(output/f'{number:03d}-{args[0]}.log').write_text(r.stdout+r.stderr)
     if ok is True:assert r.returncode==0,(args,r.stderr)
     elif ok is False:assert r.returncode!=0,(args,'expected refusal')
     return r.stdout.strip()
    batch=command('seed');assert batch.isdecimal()
    for mode in ['stale','future']:
     state.mode=mode;command('reserve',batch,ok=False);assert not state.counts
    state.mode='healthy';assert json.loads(command('reserve',batch))['stage']=='reserved'
    refreshed=set()
    for _ in range(16):
     current=json.loads(command('status',batch))['stage']
     if current=='withdrawal-known':break
     if draft_recovery and current in ['order-ready','withdrawal-ready'] and current not in refreshed:
      kind='order' if current=='order-ready' else 'withdrawal';ttl=60 if kind=='order' else 240
      observed=int(sql("SELECT d.observed_at FROM issuer_btc_conversion_drafts d JOIN issuer_btc_conversion_intents c ON d.intent_id=c.intent_id WHERE d.kind='"+kind+"' AND d.revision=c."+kind+"_draft_revision"))
      (output/(kind+'-natural-expiry-start.json')).write_text(json.dumps({'observed_at':observed,'ttl_seconds':ttl,'host_wait_started_at':int(time.time())})+'\n')
      time.sleep(max(0,observed+ttl+1-time.time()))
      before=dict(state.counts);command('step',batch,ok=False);assert state.counts==before,'expired draft must refuse before any provider call'
      state.oracle_at=int(time.time())
      with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(lambda _:command('refresh',batch,ok=None),range(2)))
      assert int(sql("SELECT count(*) FROM issuer_btc_conversion_drafts WHERE kind='"+kind+"'"))>=2
      with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(lambda _:command('step',batch,ok=None),range(2)))
      refreshed.add(current)
      assert state.counts.get('/0/private/AddOrder',0)==1
      if kind=='withdrawal':assert sql("SELECT count(*) FROM issuer_btc_conversion_requests WHERE kind='withdrawal'")=='1'
      continue
     if current in ['invoice-unknown','order-unknown','withdrawal-unknown']:
      before=dict(state.counts);command('step',batch);command('step',batch);command('refresh',batch,ok=False);assert state.counts==before
      assert fault;break
     command('step',batch,ok=not ((current=='reserved' and fault=='DepositAddresses-after')or(current=='invoice-ready' and fault=='payment-after')or(current=='order-ready' and fault=='AddOrder-after')or(current=='withdrawal-ready' and fault=='withdrawals-after')))
    current=json.loads(command('status',batch))['stage']
    if current=='withdrawal-known':
     assert state.sbf is None
     assert json.loads(command('step',batch))['stage']=='withdrawal-known','pending exact withdrawal must remain recoverable'
     assert sql('SELECT count(*) FROM issuer_btc_conversion_outputs')=='0'
     (output/'pending-before-transfer.json').write_text(json.dumps({'stage':'withdrawal-known','outputs':0,'separate_cli_call_completed':True})+'\n')
     if external:
      external_bank.request_transfer(bank,initial_digest,int(time.time()),str(state.output_micros))
      wait_file(bank/'btc-transfer.json')
      state.sbf,transfer_digest=external_bank.transfer(bank/'btc-transfer.json',str(state.output_micros))
      (output/'common-bank-transfer.json').write_bytes((bank/'btc-transfer.json').read_bytes())
      (output/'common-bank-pins.json').write_text(json.dumps({'initial_sha256':initial_digest,'transfer_sha256':transfer_digest},indent=2)+'\n')
     else:
      (bank/'proceed.json').write_text(json.dumps({'now':int(time.time())}));state.sbf=wait_file(bank/'execution.json',child);child.wait(timeout=10);assert child.returncode==0
     for pagination in ['malformed','repeated']:
      state.pagination=pagination;command('step',batch,ok=False)
      assert json.loads(command('status',batch))['stage']=='withdrawal-known'
     state.pagination='page2';state.mode='chain';command('step',batch,ok=False)
     state.pagination='long';state.mode='healthy';before=state.counts['/funding/v1/withdrawals']
     assert json.loads(command('step',batch))['stage']=='withdrawal-known'
     assert state.counts['/funding/v1/withdrawals']-before==4,'bounded page work must survive a separate-process restart'
     state.mode='chain';command('step',batch,ok=False)
     state.pagination='page2'
     for mode in ['chain','outage','delta','mint','owner']:
      state.mode=mode;command('step',batch,ok=False);assert json.loads(command('status',batch))['stage']=='withdrawal-known'
     state.mode='healthy';assert json.loads(command('step',batch))['stage']=='arrived'
     for suffix,args in [('sql',[]),('data.sql',['--data-only'])]:
      destination=output/('db-arrived.'+suffix)
      dump=subprocess.run(['/opt/homebrew/opt/postgresql@17/bin/pg_dump',database_url or 'postgresql://andreyyurlov@127.0.0.1:61546/postgres',*args,'-f',str(destination)],check=True,capture_output=True)
      (output/('pg-dump-'+suffix+'.log')).write_bytes(dump.stdout+dump.stderr)
     metadata=json.loads(sql("SELECT json_build_object('intent_id',encode(c.intent_id,'hex'),'batch_id',c.batch_id::text,'bucket',c.bucket,'source_msat',c.source_msat::text,'profile_hash',encode(c.profile_hash,'hex'),'backend_hash',encode(c.backend_hash,'hex'),'membership_hash',encode(c.membership_hash,'hex'),'treasury_config',encode(c.treasury_config_hash,'hex'),'amount',o.amount::text,'receipt',encode(o.receipt,'hex'),'signature',encode(o.transaction_signature,'hex')) FROM issuer_btc_conversion_intents c JOIN issuer_btc_conversion_outputs o ON o.intent_id=c.intent_id WHERE c.stage='arrived'"))
     (output/'actual-arrival.json').write_text(json.dumps(metadata,indent=2)+'\n')
     command('step',batch);assert json.loads(command('audit',batch))['outputs']==1
     if draft_recovery:
      with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:assert list(pool.map(lambda _:command('reserve-output',batch),range(4)))==['reserved']*4
      command('reserve-other',batch,ok=False)
      assert json.loads(command('reserve',batch))['stage']=='output-reserved'
      assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses WHERE NOT released')=='1'
      assert json.loads(command('read-status',batch))['source_discharge_proven'] is False
     assert state.counts['/0/private/DepositAddresses']==1 and state.counts['/0/private/AddOrder']==1 and state.counts['/v2/router/send']==1
     assert state.counts['/funding/v1/withdrawals']>=1
     count=sql("SELECT count(*) FROM issuer_btc_conversion_requests WHERE kind='withdrawal'");assert count=='1'
     accounting=sql('SELECT actual_routing_fee_msat::text,lnd_residual_msat::text,provider_btc_residual_msat::text,provider_usdc_residual_100ths::text,provider_net_usdc::text FROM issuer_btc_conversion_accounting');assert accounting==f'0|1000|{state.provider_reserve}|0|{state.output_micros+100000}',accounting
    else:assert fault and current in ['invoice-unknown','order-unknown','withdrawal-unknown']
    assert not state.error,state.error
    result={'status':'passed','fault':fault,'bucket':bucket,'final_stage':json.loads(command('status',batch))['stage'],'actual_sbf_transfer_executed':state.sbf is not None,'withdrawal_mutation_requests':int(sql("SELECT count(*) FROM issuer_btc_conversion_requests WHERE kind='withdrawal'")),'natural_expiry_and_concurrent_drafts':sorted(refreshed),'provider_effect_counts':{k:v for k,v in state.counts.items() if k in ['/0/private/DepositAddresses','/0/private/AddOrder','/v2/router/send']},'boundary':'Owned regtest LND + authenticated loopback Kraken protocol fixtures + actual classic SPL test-mint bank; no live provider credit/finality/USDC evidence.'};(output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
    if external:
     metadata=json.loads(sql("SELECT json_build_object('intent_id',encode(c.intent_id,'hex'),'batch_id',c.batch_id::text,'bucket',c.bucket,'source_msat',c.source_msat::text,'treasury_config',encode(c.treasury_config_hash,'hex'),'amount',o.amount::text,'receipt',encode(o.receipt,'hex'),'signature',encode(o.transaction_signature,'hex')) FROM issuer_btc_conversion_intents c JOIN issuer_btc_conversion_outputs o ON o.intent_id=c.intent_id WHERE c.stage='arrived' AND c.bucket=0"))
     (output/'actual-arrival.json').write_text(json.dumps(metadata,indent=2)+'\n')
     marker=bank/'btc-arrived.json';temporary=marker.with_suffix('.tmp');temporary.write_text(json.dumps({'status':'arrived','output_directory':str(output),'actual_arrival':metadata},indent=2)+'\n');os.replace(temporary,marker)
     deadline=time.monotonic()+1200
     while not (bank/'btc-proof-complete.json').is_file():
      if (bank/'abort').exists():raise AssertionError('common proof explicitly aborted')
      if time.monotonic()>deadline:raise AssertionError('bounded common proof completion timeout')
      time.sleep(.2)
  finally:
   (output/'diagnostic.json').write_text(json.dumps({'counts':state.counts,'errors':state.error},indent=2)+'\n')
   if child is not None and child.poll() is None:(bank/'abort').touch();child.wait(timeout=10)
   if banklog is not None:banklog.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--driver',type=Path,required=True);p.add_argument('--sbf',type=Path,required=True);p.add_argument('--fault',default='');p.add_argument('--external-bank',type=Path);p.add_argument('--database-url');p.add_argument('--draft-recovery',action='store_true');p.add_argument('--bucket',choices=['witness','burn'],default='witness');p.add_argument('--driver-sha',required=True);p.add_argument('--sbf-sha',required=True);a=p.parse_args();prove(a.output.resolve(),a.driver.resolve(),a.sbf.resolve(),a.fault,a.bucket,a.driver_sha,a.sbf_sha,a.external_bank,a.database_url,a.draft_recovery)
