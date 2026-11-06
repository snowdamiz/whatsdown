#!/usr/bin/env python3
"""Create only owned isolated PG/services and qualify the explicit funding bridge.
Requires the exact reviewed toolchain/ELFs and actual arrived checkpoint below.
Never uses a pre-existing DB or accepts external provider RPC credentials.
"""
import argparse,getpass,hashlib,json,os,shutil,socket,subprocess
from pathlib import Path
PROFILES={'legacy-hmac':{'meshc':'889dac5873bb3136e25689d17ea6f9a5bbee84fa57552d93c2f12d0a485961f9','libmesh_rt.a':'02b58f1ce33f86c75c7ad422aa3ecdfd9f8555b1e82840e5906ae62e44562d9c','libmesh_test_rt.a':'47369320e2e3673f748e90fc14ca45323340a613ca10717a3690c301277a13e5'},'http10-fixed':{'meshc':'03c59afda774c14671c6bb782afa7e44e3eabff3790a3d78f42ab2f641424269','libmesh_rt.a':'f53971a7d4a35ace76142c82dc8c138af3b008f440c1d9da5ef138e1ab4a5f92','libmesh_test_rt.a':'8143091199d40902fc1361acf113b29b2a03571831107b43003ab1a7414dda63'}}
def validate_toolchain(folder,profile):
 if profile not in PROFILES:raise ValueError('unknown toolchain profile')
 pins=PROFILES[profile]
 for name,digest in pins.items():
  with (folder/name).open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
  assert actual==digest,('toolchain pin mismatch',profile,name)
 return pins

p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--product',type=Path,required=True);p.add_argument('--mesh-lang',type=Path,required=True);p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--rewards-elf',type=Path,required=True);p.add_argument('--rewards-sha',required=True);p.add_argument('--token-elf',type=Path,required=True);p.add_argument('--lightning-tools',type=Path,required=True);p.add_argument('--pg-bin',type=Path,default=Path('/opt/homebrew/opt/postgresql@17/bin'));p.add_argument('--toolchain-profile',choices=sorted(PROFILES),default='legacy-hmac');a=p.parse_args()
PIN=validate_toolchain(a.toolchain.resolve(),a.toolchain_profile)
W=a.work.resolve();assert not W.exists(),'use a new output directory';W.mkdir(parents=True);HERE=Path(__file__).resolve().parent
records=[];cluster=False
ENV=dict(os.environ,PG_BIN=str(a.pg_bin.resolve()),LIGHTNING_TEST_TOOLS=str(a.lightning_tools.resolve()),CARGO_TARGET_DIR=str(W/'sbf/target'))
def run(name,args,ok=True,env=ENV,input=None):
 r=subprocess.run(list(map(str,args)),env=env,input=input,text=True,capture_output=True);(W/'evidence'/name).write_text(r.stdout+r.stderr);records.append({'name':name,'args':list(map(str,args)),'exit':r.returncode});assert (r.returncode==0)==ok,(name,r.stderr);return r
try:
 (W/'evidence').mkdir();(W/'toolchain').mkdir();(W/'sources').mkdir()
 (W/'toolchain-profile.json').write_text(json.dumps({'profile':a.toolchain_profile,'pins':PIN},indent=2)+'\n')
 for name,digest in PIN.items():
  src=a.toolchain/name;assert hashlib.sha256(src.read_bytes()).hexdigest()==digest;shutil.copy2(src,W/'toolchain'/name)
 assert hashlib.sha256(a.rewards_elf.read_bytes()).hexdigest()==a.rewards_sha
 assert hashlib.sha256(a.token_elf.read_bytes()).hexdigest()=='7b44674b9704fa7640fbebfac68389f338b500b8c2bc29175c27ed66838b5a3c'
 for name,src in [('credit-issuer',a.product/'services/credit-issuer'),('messenger-protocol',a.product/'packages/messenger-protocol'),('mesh-binary',a.mesh_lang/'packages/mesh-binary'),('mesh-solana',a.mesh_lang/'packages/mesh-solana'),('mesh-lightning',a.mesh_lang/'packages/mesh-lightning')]:
  shutil.copytree(src,W/'sources'/name,ignore=shutil.ignore_patterns('target','.git','__pycache__'))
 # Package paths alone differ from the live layout; all MPL/SQL bodies stay exact.
 for toml in (W/'sources').glob('*/mesh.toml'):
  text=toml.read_text().replace('../../packages/messenger-protocol','../messenger-protocol').replace('../../../mesh-lang/packages/mesh-binary','../mesh-binary').replace('../../../mesh-lang/packages/mesh-solana','../mesh-solana').replace('../../../mesh-lang/packages/mesh-lightning','../mesh-lightning')
  toml.write_text(text)
 for name,src in [('funding-fixture',HERE/'fixture'),('conversion-fixture',HERE/'conversion-fixture')]:shutil.copytree(src,W/'sources'/name)
 for name in ['harness','fixtures','sbf']:shutil.copytree(HERE/name,W/name)
 for name in ['prove_storage.py','prove_funding.py']:shutil.copy2(HERE/name,W/name)
 (W/'product/scripts').mkdir(parents=True);shutil.copy2(a.product/'scripts/lightning_regtest.py',W/'product/scripts/lightning_regtest.py')
 manifest={str(p.relative_to(W)):hashlib.sha256(p.read_bytes()).hexdigest() for base in [W/'sources',W/'toolchain',W/'sbf',W/'harness',W/'fixtures',W/'product'] for p in base.rglob('*') if p.is_file()}
 (W/'inputs.json').write_text(json.dumps(manifest,indent=2)+'\n')
 ENV.update(MESH_RT_LIB_PATH=str(W/'toolchain/libmesh_rt.a'),MESH_TEST_RT_LIB_PATH=str(W/'toolchain/libmesh_test_rt.a'))
 for name in ['funding-fixture','conversion-fixture']:run(name+'-build.log',[W/'toolchain/meshc','build',W/'sources'/name,'-o',W/name])
 run('sbf-build.log',['cargo','test','--manifest-path',W/'sbf/Cargo.toml','--locked','--test','witness','--no-run'],env=dict(ENV,CARGO_BUILD_JOBS='1',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0'))
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 assert port not in [55438,61546];user=getpass.getuser();(W/'pg/socket').mkdir(parents=True)
 run('pg-init.log',[a.pg_bin/'initdb','-D',W/'pg/data','-U',user,'-A','trust','--no-locale','-E','UTF8'])
 conf=W/'pg/data/postgresql.conf';conf.write_text(conf.read_text()+f"\nport={port}\nlisten_addresses='127.0.0.1'\nunix_socket_directories=''\n")
 run('pg-start.log',[a.pg_bin/'pg_ctl','-D',W/'pg/data','-l',W/'evidence/pg.log','-w','start']);cluster=True
 storage=f'postgresql://{user}@127.0.0.1:{port}/witness_arrived';fresh=f'postgresql://{user}@127.0.0.1:{port}/witness_fresh'
 run('createdb.log',[a.pg_bin/'createdb','-h127.0.0.1','-p'+str(port),'-U'+user,'witness_arrived']);run('restore.log',[a.pg_bin/'psql','-X',storage,'-v','ON_ERROR_STOP=1','-f',W/'fixtures/arrived/db-arrived.sql'])
 fixture=dict(ENV,BTC_FIXTURE_CONFIG=str(W/'fixtures/arrived/funding-config.json'),BTC_FIXTURE_DATABASE=storage,BTC_FIXTURE_MACAROON='00')
 r=run('storage-red-missing015.log',[W/'funding-fixture','reserve','5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee','2810'],ok=False,env=fixture);assert 'issuer_btc_witness_funding' in r.stderr
 run('storage-proof.log',['python3',W/'prove_storage.py'],env=dict(ENV,BTC_STORAGE_DATABASE=storage))
 run('funding-proof.log',['python3',W/'prove_funding.py'],env=dict(ENV,BTC_FUNDING_DATABASE=fresh,BTC_FUNDING_REWARDS_ELF=str(a.rewards_elf.resolve()),BTC_FUNDING_TOKEN_ELF=str(a.token_elf.resolve())))
 for path,digest in manifest.items():assert hashlib.sha256((W/path).read_bytes()).hexdigest()==digest,('source changed',path)
 (W/'result.json').write_text(json.dumps({'status':'passed','records':records,'source_pins_verified_after':True},indent=2)+'\n')
finally:
 if cluster:run('pg-stop.log',[a.pg_bin/'pg_ctl','-D',W/'pg/data','-m','fast','-w','stop'])
 (W/'run-records.json').write_text(json.dumps(records,indent=2)+'\n')
