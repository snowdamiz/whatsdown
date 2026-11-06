#!/usr/bin/env python3
"""Restored actual historical arrival, real PG transaction/race qualification.
No chain RPC, signing or modification of historical receipt/accounting data.
"""
import concurrent.futures,hashlib,json,os,subprocess
from pathlib import Path
W=Path(__file__).resolve().parent;FIXTURE=Path(os.environ.get('BTC_FUNDING_FIXTURE_BIN',W/'funding-fixture'));OUT=W/'evidence'/os.environ.get('BTC_STORAGE_OUTPUT','storage');OUT.mkdir(exist_ok=False)
URL=os.environ['BTC_STORAGE_DATABASE']
PSQL=[str(Path(os.environ.get('PG_BIN','/opt/homebrew/opt/postgresql@17/bin'))/'psql'),'-X',URL,'-qAt','-v','ON_ERROR_STOP=1']
CFG=W/'fixtures/arrived/funding-config.json';CONV='5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee'
records=[]
def sql(query,ok=True):
 r=subprocess.run(PSQL,input=query,text=True,capture_output=True);records.append({'sql':query,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert (r.returncode==0)==ok,(query,r.stderr);return r.stdout.strip()
def command(*args,ok=True,config=CFG):
 env=dict(os.environ,BTC_FIXTURE_CONFIG=str(config),BTC_FIXTURE_DATABASE=URL,BTC_FIXTURE_MACAROON='00')
 r=subprocess.run([str(FIXTURE),*map(str,args)],env=env,text=True,capture_output=True,timeout=90);records.append({'args':args,'config':str(config),'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert (r.returncode==0)==ok,(args,r.stderr);return json.loads(r.stdout) if ok else r.stderr
TABLES=['issuer_lightning_revenue','issuer_lightning_weekly','issuer_btc_conversion_outputs','issuer_btc_conversion_accounting','issuer_btc_conversion_requests','issuer_btc_conversion_artifacts','issuer_btc_conversion_drafts']
def fingerprints():return {t:sql('SELECT encode(sha256(convert_to(COALESCE(json_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,\'null\'),\'UTF8\')),\'hex\') FROM '+t+' t') for t in TABLES}
before=fingerprints();assert sql('SELECT stage FROM issuer_btc_conversion_intents')=='arrived';assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses')=='0'
# First actual missing migration failure was captured before any source/schema fix.
assert 'issuer_btc_witness_funding' in (W/'evidence/storage-red-missing015.log').read_text()
sql('BEGIN;\n'+(W/'sources/credit-issuer/migrations/015_btc_witness_funding.sql').read_text()+'\nCOMMIT;')
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:values=list(pool.map(lambda _:command('reserve',CONV,2810),range(8)))
assert all(v==values[0] for v in values);first=values[0];assert first['amount']=='49699202' and first['state']==0
assert sql('SELECT count(*) FROM issuer_btc_witness_funding')=='1';assert sql('SELECT count(*) FROM issuer_btc_conversion_output_uses')=='1'
reservation=sql("SELECT encode(operation_id,'hex') FROM issuer_btc_conversion_output_uses")
assert command('load',first['id'])==first
for field,value in [('rewards_pool','88'*32),('rewards_program','88'*32),('owner','11111111111111111111111111111112'),('usdc','11111111111111111111111111111112')]:
 c=json.loads(CFG.read_text());c['treasury_chain'][field]=value;p=OUT/(field+'.json');p.write_text(json.dumps(c));command('reserve',CONV,2810,ok=False,config=p)
command('absent',first['id'],2809,ok=False);assert command('absent',first['id'],2810)==first
expired=command('absent',first['id'],2811);assert expired['state']==2
command('reserve',CONV,2810,ok=False)
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:again=list(pool.map(lambda _:command('reserve',CONV,2811),range(6)))
assert all(v==again[0] for v in again);second=again[0];assert second['id']!=first['id'] and second['state']==0 and second['amount']==first['amount']
assert sql("SELECT encode(operation_id,'hex') FROM issuer_btc_conversion_output_uses")==reservation
assert sql('SELECT count(*) FROM issuer_btc_witness_funding WHERE state IN(0,1)')=='1'
for query in ["UPDATE issuer_btc_conversion_output_uses SET released=true",'DELETE FROM issuer_btc_conversion_output_uses','DELETE FROM issuer_btc_witness_funding',"UPDATE issuer_btc_witness_funding SET state=0 WHERE state=2","UPDATE issuer_btc_witness_funding SET epoch=9999 WHERE state=0","UPDATE issuer_btc_witness_funding SET pool=decode(repeat('11',32),'hex') WHERE state=0"]:sql(query,False)
# Restart the owned cluster; recovery is a new process on the same exact saved intent.
pg=str(Path(os.environ.get('PG_BIN','/opt/homebrew/opt/postgresql@17/bin'))/'pg_ctl')
for args in [['-D',str(W/'pg/data'),'-m','fast','-w','stop'],['-D',str(W/'pg/data'),'-l',str(W/'evidence/postgres.log'),'-w','start']]:
 r=subprocess.run([pg,*args],text=True,capture_output=True);records.append({'pg_ctl':args,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0
assert command('load',second['id'])==second
assert before==fingerprints(),'original Lightning/msat/output/residual accounting changed'
result={'status':'passed','historical_storage_only':True,'concurrent_reservations':14,'attempts':2,'one_permanent_reservation':reservation,'immutable_tables':before,'missing015_rollback':True,'restart':True,'first':first,'second':second,'records':records}
(OUT/'results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='records'}))
