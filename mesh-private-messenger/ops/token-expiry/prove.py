#!/usr/bin/env python3
"""Owned disposable PostgreSQL; no external database or chain mutations."""
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PRODUCT = HERE.parents[1]
pg = Path(os.environ.get('PG_BIN') or Path(shutil.which('initdb') or '/opt/homebrew/opt/postgresql@17/bin/initdb').parent)
with tempfile.TemporaryDirectory(prefix='morse-expiry-pg-', dir='/tmp') as raw:
    work = Path(raw).resolve()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env.update(PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='expiry_test',
               PGDATABASE='postgres', CREDIT_TEST_PSQL=str(pg / 'psql'))
    def run(args, **kwargs):
        return subprocess.run([str(a) for a in args], cwd=PRODUCT, env=env, check=True, **kwargs)
    started = False
    try:
        run([pg / 'initdb', '-D', work / 'data', '-U', 'expiry_test', '--auth=trust', '--no-locale'], stdout=subprocess.DEVNULL)
        run([pg / 'pg_ctl', '-D', work / 'data', '-l', work / 'postgres.log', '-o',
             shlex.join(['-h', '127.0.0.1', '-p', str(port), '-k', str(work)]), '-w', 'start'], stdout=subprocess.DEVNULL)
        started = True
        run([pg / 'createdb', 'expiry_test'])
        env['PGDATABASE'] = 'expiry_test'
        for migration in sorted((PRODUCT / 'services/credit-issuer/migrations').glob('*.sql')):
            run([pg / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', migration], stdout=subprocess.DEVNULL)
        env['MESSENGER_ISSUER_TEST_DATABASE_URL'] = f'postgres://expiry_test@127.0.0.1:{port}/expiry_test?sslmode=disable'
        run(['node', '--test', HERE / 'cli.test.mjs'])
    finally:
        if started:
            run([pg / 'pg_ctl', '-D', work / 'data', '-m', 'fast', '-w', 'stop'], stdout=subprocess.DEVNULL)
