#!/usr/bin/env python3
"""Text-only native account HTTP proof against owned Mesh/PostgreSQL services.

The native calls use the installed generated ABI and actual Keychain/Keystore
callbacks. The server uses unchanged production directory-delivery handlers and
storage. Its thin bootstrap omits background witness and push workers. No live
service, credential, funds, capture, or caller-selected network destination is
used. Client profiles contain mailbox capabilities and are never archived.
"""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import http.client
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

from attachment_android_proof import AttachmentAndroidProof
from credit_ios_proof import CreditIOSProof

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent
MODULE = PRODUCT / 'apps/mobile/modules/mesh-messenger'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def available_port():
    with socket.socket() as value:
        value.bind(('127.0.0.1', 0))
        return value.getsockname()[1]


def snapshot(directory):
    return {str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and (p.suffix in ('.mpl', '.sql', '.fixture') or p.name == 'mesh.toml')}


def copy_sources(source, target):
    target.mkdir(parents=True)
    for name in snapshot(source):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, path)


def public_key(seed):
    # Independent Node Ed25519 conversion for this ephemeral owned fixture.
    code = "const c=require('node:crypto');let b='';process.stdin.on('data',v=>b+=v);process.stdin.on('end',()=>{const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(b.trim(),'hex')]),format:'der',type:'pkcs8'});process.stdout.write(c.createPublicKey(k).export({type:'spki',format:'der'}).subarray(-32).toString('hex'))})"
    return subprocess.run(['node', '-e', code], input=seed, text=True, capture_output=True, check=True).stdout


class Database:
    def __init__(self, migrations):
        self.migrations = migrations

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='morse-account-pg-', dir='/tmp')
        self.work = Path(self.temp.name).resolve()
        self.pg = Path(os.environ.get('PG_BIN', '/opt/homebrew/opt/postgresql@17/bin'))
        self.port = available_port()
        self.env = dict(os.environ, PGHOST='127.0.0.1', PGPORT=str(self.port),
                        PGUSER='morse_account_test', PGDATABASE='morse_account_test')
        self.started = False
        try:
            self.run('initdb', '-D', self.work/'data', '-U', 'morse_account_test', '--auth=trust', '--no-locale')
            self.run('pg_ctl', '-D', self.work/'data', '-l', self.work/'postgres.log', '-o',
                     shlex.join(['-h', '127.0.0.1', '-p', str(self.port), '-k', str(self.work)]), '-w', 'start')
            self.started = True
            self.run('createdb', 'morse_account_test')
            for file in sorted(self.migrations.glob('*.sql')):
                self.run('psql', '-v', 'ON_ERROR_STOP=1', '-f', file)
            self.url = f'postgres://morse_account_test@127.0.0.1:{self.port}/morse_account_test?sslmode=disable'
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def run(self, name, *args):
        return subprocess.run([str(self.pg/name), *map(str, args)], env=self.env,
                              capture_output=True, text=True, check=True, timeout=60)

    def sql(self, text):
        return self.run('psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', text).stdout.strip()

    def counts(self):
        value = self.sql('SELECT (SELECT count(*) FROM messenger_accounts), '
                         '(SELECT count(*) FROM messenger_devices), '
                         '(SELECT count(*) FROM messenger_one_time_prekeys WHERE NOT last_resort), '
                         '(SELECT count(*) FROM messenger_deleted_accounts)')
        return tuple(map(int, value.split('|')))

    def __exit__(self, *_):
        try:
            if self.started:
                self.run('pg_ctl', '-D', self.work/'data', '-m', 'fast', '-w', 'stop')
        finally:
            self.temp.cleanup()


class Peer:
    def __init__(self, binary, db, log, service_seed):
        self.port = available_port()
        self.binary, self.db, self.log, self.seed = binary, db, log, service_seed

    def __enter__(self):
        self.output = self.log.open('wb')
        env = dict(os.environ, MESSENGER_DATABASE_URL=self.db.url, MESSENGER_PORT=str(self.port),
                   MESSENGER_ABUSE_DIFFICULTY='1', MESSENGER_SIGNUP_DIFFICULTY='1',
                   MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX=self.seed,
                   MESSENGER_DELIVERY_SEALING_SEED_HEX=secrets.token_hex(32),
                   MESSENGER_DELIVERY_INTERNAL_TOKEN=secrets.token_hex(32), MORSE_PAID_SIGNUP='off',
                   MORSE_PAID_RETENTION='off', MORSE_PAID_POSTAGE='off')
        self.process = subprocess.Popen([str(self.binary)], env=env, stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.__exit__(None, None, None)
                raise RuntimeError('owned Mesh peer exited; see '+str(self.log))
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/health', timeout=1) as response:
                    if response.status == 200:
                        return self
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        self.__exit__(None, None, None)
        raise TimeoutError('owned Mesh peer did not start')

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.output.close()


class Proxy:
    """Byte-exact local forwarding; drops an accepted publication reply once.

    Only body hashes/lengths leave memory. A dropped response is never replaced
    by fabricated success. The production server commits the 64 keys first.
    """
    def __init__(self, peer, db):
        self.peer, self.db = peer, db
        self.requests, self.errors = [], []
        self.drop_publication = True
        self.lock = threading.Lock()

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_PUT(self):
                self.route()

            def do_POST(self):
                self.route()

            def route(self):
                try:
                    expected = {'PUT': {'/v1/devices/register'}, 'POST': {'/v1/prekeys/one-time/batch', '/v1/accounts/delete'}}
                    assert self.path in expected[self.command], ('unexpected route', self.command, self.path)
                    assert self.headers.get('Content-Type') == 'application/octet-stream'
                    assert self.headers.get('Cache-Control') == 'no-store'
                    assert self.headers.get('Authorization') is None and self.headers.get('Cookie') is None
                    size = int(self.headers['Content-Length'])
                    assert 0 < size <= 100000
                    body = self.rfile.read(size)
                    assert len(body) == size
                    connection = http.client.HTTPConnection('127.0.0.1', fixture.peer.port, timeout=20)
                    try:
                        connection.request(self.command, self.path, body, {'Content-Type':'application/octet-stream', 'Cache-Control':'no-store'})
                        response = connection.getresponse()
                        status, content = response.status, response.read(4097)
                        assert len(content) <= 4096
                    finally:
                        connection.close()
                    counts = fixture.db.counts()
                    with fixture.lock:
                        drop = self.path == '/v1/prekeys/one-time/batch' and status in (200, 201) and counts[2] == 64 and fixture.drop_publication
                        fixture.requests.append(dict(method=self.command, path=self.path, bytes=size,
                            sha256=hashlib.sha256(body).hexdigest(), status=status,
                            response_sha256=hashlib.sha256(content).hexdigest(), dropped=drop, database_counts=list(counts)))
                    if drop:
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                except BaseException as error:
                    with fixture.lock:
                        fixture.errors.append(str(error))
                    self.close_connection = True

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        self.origin = f'http://127.0.0.1:{self.port}'
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class AccountIOSHTTPProof(CreditIOSProof):
    bundle = 'app.morse.accounthttp.proof.ios'


class AccountAndroidHTTPProof(AttachmentAndroidProof):
    bundle = 'app.morse.accounthttp.proof.android'
    instrumentation_class = 'AccountHTTPProofTest'


def build_backend(evidence, compiler):
    """Freeze declared dependencies before build so source attribution is exact."""
    sources = evidence/'sources'
    service = sources/'directory-delivery'
    copy_sources(PRODUCT/'services/directory-delivery', service)
    jobs = sources/'service-jobs'
    copy_sources(PRODUCT/'packages/service-jobs', jobs)
    reader = ROOT/'.morse/witness-proof/reader162/sources'
    protocol = sources/'messenger-protocol'
    copy_sources(reader/'whatsdown/mesh-private-messenger/packages/messenger-protocol', protocol)
    dependencies = ['mesh-binary', 'mesh-solana', 'mesh-lightning']
    for name in dependencies:
        copy_sources(reader/'mesh-lang/packages'/name, sources/name)
    (protocol/'mesh.toml').write_text('[package]\nname="messenger-protocol"\nversion="0.1.0"\n[dependencies]\n'+
        ''.join(name+'={path="'+str(sources/name)+'"}\n' for name in dependencies))
    (service/'mesh.toml').write_text('[package]\nname="account-http-proof"\nversion="0.1.0"\n[dependencies]\n'+
        'messenger-protocol={path="'+str(protocol)+'"}\nservice-jobs={path="'+str(jobs)+'"}\n')
    (service/'main.mpl').write_bytes((PRODUCT/'scripts/account-http-proof/main.mpl.fixture').read_bytes())
    before = snapshot(sources)
    binary = evidence/'directory-account-peer'
    command = [str(compiler), 'build', str(service), '--opt-level', '0', '-o', str(binary)]
    with (evidence/'backend-build.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, cwd=PRODUCT)
    assert result.returncode == 0, 'Mesh backend build failed; see backend-build.log'
    assert before == snapshot(sources), 'frozen backend sources changed during compilation'
    report = json.loads(binary.with_name(binary.name+'.plaintext.json').read_text())
    known = set(before.values())
    assert all(row['source_sha256'] in known for row in report['modules']), 'compiled module missing from source archive'
    record = dict(command=command, compiler=str(compiler), compiler_sha256=sha(compiler),
                  executable_sha256=sha(binary), sources=before, compiled_modules=len(report['modules']),
                  scope='Production API/router/storage, proof-only bootstrap; no background push/witness workers')
    (evidence/'backend.json').write_text(json.dumps(record, indent=2)+'\n')
    return binary, service/'migrations'


def prove(platform, evidence, binary, migrations):
    output = evidence/platform
    output.mkdir()
    source = MODULE/platform/'account-http-proof'/('AccountHTTPProof.swift' if platform == 'ios' else 'AccountHTTPProof.kt')
    runner = AccountIOSHTTPProof if platform == 'ios' else AccountAndroidHTTPProof
    cases = []
    service_seed, witness_seed = secrets.token_hex(32), secrets.token_hex(32)
    service_key, witness_key = public_key(service_seed), public_key(witness_seed)
    witness = 'outside '+witness_key+' Test'
    security = '\n'.join(['3', service_key, '22'*32, '1', '1', '1', witness, '-', '0', '-', '2', '1', '1', witness])
    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='morse-account-http-', dir='/tmp'))).resolve()
        db = stack.enter_context(Database(migrations))
        peer = stack.enter_context(Peer(binary, db, output/'peer.log', service_seed))
        proxy = stack.enter_context(Proxy(peer, db))
        pins = '\n'.join(['2', '1', proxy.origin, proxy.origin, proxy.origin, proxy.origin.replace('http:', 'ws:')+'/v1/mailbox/stream', '1'])
        (output/'native-network-config.txt').write_text(pins)
        (output/'native-security-config.txt').write_text(security)
        native = stack.enter_context(runner(PRODUCT, work, security, proof_source=source,
                                           network_config=pins, artifact_dir=output/'native'))
        first = native.invoke('create', body=('account_'+platform).encode())
        first_sha = hashlib.sha256(first).hexdigest()
        assert native.invoke('capabilities', id=first) == b'\1ACP\1'
        assert db.counts() == (0, 0, 0, 0)
        error = native.invoke('register', rejected=True)
        assert 'directory_transport_unavailable' in error, error
        assert db.counts() == (1, 1, 64, 0), db.counts()
        assert db.sql('SELECT count(*) FROM messenger_one_time_prekeys WHERE last_resort AND consumed_at IS NULL') == '1'
        dropped = [row for row in proxy.requests if row['dropped']]
        assert dropped and len({row['sha256'] for row in dropped}) == 1
        assert native.invoke('profile') == first
        cases.append('accepted prekey publication loses its reply; remote account and 64 keys commit while local profile and pending publication survive')
        proxy.drop_publication = False
        native.restart()
        assert native.invoke('profile') == first
        marker = len(proxy.requests)
        assert native.invoke('prekeys') == b'\1DPK\0@'
        recovered = proxy.requests[marker:]
        assert len(recovered) == 1 and recovered[0]['sha256'] == dropped[0]['sha256'], recovered
        assert db.counts() == (1, 1, 64, 0)
        cases.append('real process restart republishes exactly the durable pending bytes; production server reconciles the same 64 keys without duplicates')
        assert native.invoke('register') == b'\1DRG\0@\0'
        assert db.counts() == (1, 1, 64, 0)
        native.restart()
        assert native.invoke('profile') == first
        cases.append('idempotent native registration and full prekey reconciliation succeed against the production Mesh API')
        assert native.invoke('delete', id=first) == b'\1ADN\1'
        assert db.counts() == (0, 0, 0, 1), db.counts()
        assert 'local_state_not_found' in native.invoke('profile', rejected=True)
        native.restart()
        assert 'local_state_not_found' in native.invoke('profile', rejected=True)
        cases.append('signed account deletion receives the production server 204, erases local custody and all server account/device/prekey rows, and retains the deletion tombstone across restart')
        second = native.invoke('create', body=('replacement_'+platform).encode())
        assert second != first
        marker = len(proxy.requests)
        error = native.invoke('delete', id=first, rejected=True)
        assert 'account_state_changed' in error, error
        assert len(proxy.requests) == marker and native.invoke('profile') == second
        assert native.invoke('discard', id=second) == b'\1ADS\1'
        assert not proxy.errors, proxy.errors
        cases.append('a delayed request from erased account A cannot contact HTTP or erase replacement B')
        result = dict(status='passed_native_account_http', platform=platform, inputs=native.input_hashes,
                      checks=cases, requests=proxy.requests, final_database_counts=list(db.counts()),
                      first_profile_sha256=first_sha,
                      limits='Owned local development HTTP pins, real generated ABI and OS storage, unchanged production Mesh API/storage with a proof-only bootstrap. No witnessed quorum admission, linked-device renewal/revocation, physical device or release claim. Profiles, mailbox bearer capabilities, private keys and databases are not archived.')
        (output/'evidence.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(dict(platform=platform, status=result['status'], cases=len(cases), requests=len(proxy.requests))), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['ios', 'android', 'both'], default='both')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, default=ROOT/'.morse/native-reader-meshc.py')
    parser.add_argument('--reuse-backend', action='store_true', help='Reuse only the existing frozen executable/source pair in this evidence directory')
    args = parser.parse_args()
    evidence, compiler = args.evidence.resolve(), args.compiler.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if args.reuse_backend:
        record = json.loads((evidence/'backend.json').read_text())
        binary, migrations = evidence/'directory-account-peer', evidence/'sources/directory-delivery/migrations'
        assert sha(binary) == record['executable_sha256'] and snapshot(evidence/'sources') == record['sources']
    else:
        binary, migrations = build_backend(evidence, compiler)
    platforms = ['ios', 'android'] if args.platform == 'both' else [args.platform]
    results = [prove(platform, evidence, binary, migrations) for platform in platforms]
    (evidence/'result.json').write_text(json.dumps(dict(status='passed', platforms=[r['platform'] for r in results],
        cases=sum(len(r['checks']) for r in results), requests=sum(len(r['requests']) for r in results)), indent=2)+'\n')


if __name__ == '__main__':
    main()
