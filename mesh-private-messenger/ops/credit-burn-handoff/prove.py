#!/usr/bin/env python3
"""Isolated owned-PG proof for the staged external burn liability journal."""
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
PRODUCT=HERE.parents[1]
ROOT=PRODUCT.parent
pg=Path(os.environ.get('PG_BIN') or Path(shutil.which('initdb') or '/opt/homebrew/opt/postgresql@17/bin/initdb').parent)
meshc=Path(os.environ.get('MESHC',ROOT/'mesh-lang/target/debug/meshc'))
with tempfile.TemporaryDirectory(prefix='morse-burn-journal-',dir='/tmp') as raw:
 work=Path(raw).resolve()
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 env=os.environ.copy();env.update(PGHOST='127.0.0.1',PGPORT=str(port),PGUSER='burn_test',PGDATABASE='postgres',CREDIT_TEST_PSQL=str(pg/'psql'))
 def run(args,**kwargs):return subprocess.run([str(a) for a in args],cwd=PRODUCT,env=env,check=True,**kwargs)
 started=False
 try:
  run([pg/'initdb','-D',work/'data','-U','burn_test','--auth=trust','--no-locale'],stdout=subprocess.DEVNULL)
  run([pg/'pg_ctl','-D',work/'data','-l',work/'postgres.log','-o',shlex.join(['-h','127.0.0.1','-p',str(port),'-k',str(work)]),'-w','start'],stdout=subprocess.DEVNULL);started=True
  run([pg/'createdb','burn_test']);env['PGDATABASE']='burn_test'
  for migration in list(sorted((PRODUCT/'services/credit-issuer/migrations').glob('*.sql')))+list(sorted((HERE/'migrations').glob('*.sql'))):
   run([pg/'psql','-X','-v','ON_ERROR_STOP=1','-f',migration],stdout=subprocess.DEVNULL)
  env['MESSENGER_ISSUER_TEST_DATABASE_URL']=f'postgres://burn_test@127.0.0.1:{port}/burn_test?sslmode=disable'
  if os.environ.get('BURN_PROOF_CASE')=='cli':
   run(['node','--test',HERE/'cli.test.mjs'])
  else:
   run([meshc,'test',PRODUCT/'services/credit-issuer/tests/treasury_burn.test.mpl'])
 finally:
  if started:run([pg/'pg_ctl','-D',work/'data','-m','fast','-w','stop'],stdout=subprocess.DEVNULL)
