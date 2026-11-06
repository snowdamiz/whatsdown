#!/usr/bin/env python3
"""Owned Core/PostgreSQL RNWv2 HTTP interop; no native library mutation."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import tomllib

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


account = load('renewal_account_helpers', PRODUCT/'scripts/prove-account-http-native.py')


def snapshot_closure(package, destination, copied=None):
    copied = {} if copied is None else copied
    package = package.resolve()
    if package in copied:
        return copied[package]
    target = destination/package.name
    assert not target.exists()
    copied[package] = target
    account.copy_sources(package, target)
    manifest = package/'mesh.toml'
    original = manifest.read_text()
    config = tomllib.loads(original)
    for dependency in config.get('dependencies', {}).values():
        assert isinstance(dependency, dict) and set(dependency) == {'path'}, dependency
        source = (package/dependency['path']).resolve()
        resolved = snapshot_closure(source, destination, copied)
        original = original.replace('"'+dependency['path']+'"', '"'+str(resolved)+'"')
    (target/'mesh.toml').write_text(original)
    return target


class Proxy:
    def __init__(self, peer, db, trace):
        self.peer, self.db, self.trace = peer, db, trace
        self.requests, self.errors = [], []
        self.dropped = set()

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_PUT(self):
                try:
                    assert self.path == '/v1/devices/register'
                    assert self.headers.get('Content-Type') == 'application/octet-stream'
                    assert self.headers.get('Cache-Control') == 'no-store'
                    assert self.headers.get('Authorization') is None and self.headers.get('Cookie') is None
                    size = int(self.headers['Content-Length'])
                    assert 0 < size <= 36026
                    body = self.rfile.read(size)
                    assert body[:4] == b'\1PWR' and len(body) == 20+int.from_bytes(body[16:20], 'big')
                    label = self.headers.get('X-Morse-Proof-Case', '')
                    assert label and len(label) < 80
                    connection = http.client.HTTPConnection('127.0.0.1', fixture.peer.port, timeout=15)
                    try:
                        connection.request('PUT', self.path, body,
                            {'Content-Type':'application/octet-stream', 'Cache-Control':'no-store'})
                        response = connection.getresponse()
                        status, content = response.status, response.read(4097)
                        assert len(content) <= 4096
                    finally:
                        connection.close()
                    drop = label in {'v2-publication-lost', 'v2-answer-lost'} and label not in fixture.dropped
                    if drop:
                        assert status == 201
                        fixture.dropped.add(label)
                    sequence = fixture.db.sql('SELECT sequence::text FROM messenger_accounts')
                    fixture.requests.append(dict(case=label, method='PUT', path=self.path,
                        payload_bytes=len(body)-20, payload_sha256=hashlib.sha256(body[20:]).hexdigest(),
                        status=status, response_bytes=len(content), sequence=int(sequence), dropped=drop))
                    fixture.trace.write_text(json.dumps(fixture.requests, indent=2)+'\n')
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
                    fixture.errors.append(str(error))
                    self.close_connection = True

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def compile_package(compiler, package, binary, log):
    command = [str(compiler), 'build', str(package), '--opt-level', '0', '-o', str(binary)]
    with log.open('w') as output:
        result = subprocess.run(command, cwd=PRODUCT, stdout=output, stderr=subprocess.STDOUT)
    assert result.returncode == 0, 'Mesh build failed; see '+str(log)
    report = json.loads(binary.with_name(binary.name+'.plaintext.json').read_text())
    return dict(command=command, sha256=account.sha(binary), compiled_modules=len(report['modules']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, default=ROOT/'.morse/witness-proof/renewal-v2-http')
    parser.add_argument('--compiler', type=Path, default=ROOT/'.morse/native-reader-meshc.py')
    parser.add_argument('--build-only', action='store_true')
    parser.add_argument('--resume-client', action='store_true',
        help='preserve the previous attempt and rebuild only the isolated client')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    if args.resume_client:
        previous = json.loads((evidence/'build.json').read_text())
        assert account.snapshot(evidence/'sources') == previous['sources']
        assert account.sha(args.compiler.resolve()) == previous['compiler_wrapper_sha256']
        attempts = evidence/'attempts'
        attempts.mkdir(exist_ok=True)
        attempt = attempts/str(len(list(attempts.iterdir()))+1)
        attempt.mkdir()
        for name in ['driver.py', 'build.json', 'renewal-client', 'renewal-client-build.log',
                     'renewal-client.plaintext.json', 'client.log', 'http-trace.json', 'core.log',
                     'evidence.json']:
            if (evidence/name).exists():
                shutil.copyfile(evidence/name, attempt/name)
        shutil.copyfile(evidence/'sources/renewal-client/main.mpl', attempt/'client.mpl')
        (evidence/'evidence.json').unlink(missing_ok=True)
    else:
        evidence.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(Path(__file__), evidence/'driver.py')
    sources = evidence/'sources'
    service = sources/'directory-delivery'
    if not args.resume_client:
        service = snapshot_closure(PRODUCT/'services/directory-delivery', sources)
        (service/'main.mpl').write_bytes((PRODUCT/'scripts/account-http-proof/main.mpl.fixture').read_bytes())
    client = sources/'renewal-client'
    if not args.resume_client:
        client.mkdir()
        (client/'mesh.toml').write_text('[package]\nname="renewal-v2-http-client"\nversion="0.1.0"\n'
            '[dependencies]\ncore={path="'+str(service)+'"}\n'
            'messenger-protocol={path="'+str(sources/'messenger-protocol')+'"}\n')
    (client/'main.mpl').write_bytes((PRODUCT/'scripts/renewal-v2-http-proof/client.mpl.fixture').read_bytes())
    frozen = account.snapshot(sources)
    compiler = args.compiler.resolve()
    binaries = {}
    for name, package in [('core-peer', service), ('renewal-client', client)]:
        if name == 'core-peer' and args.resume_client:
            binaries[name] = previous['executables'][name]
            assert account.sha(evidence/name) == binaries[name]['sha256']
        else:
            binaries[name] = compile_package(compiler, package, evidence/name, evidence/(name+'-build.log'))
        assert account.snapshot(sources) == frozen
        report = json.loads((evidence/(name+'.plaintext.json')).read_text())
        assert all(row['source_sha256'] in frozen.values() for row in report['modules'])
    (evidence/'build.json').write_text(json.dumps(dict(compiler=str(compiler),
        compiler_wrapper_sha256=account.sha(compiler), sources=frozen, executables=binaries), indent=2)+'\n')
    if args.build_only:
        print(json.dumps(dict(status='built_owned_RNWv2_HTTP_fixture', evidence=str(evidence))))
        return
    with ExitStack() as stack:
        db = stack.enter_context(account.Database(service/'migrations'))
        peer = stack.enter_context(account.Peer(evidence/'core-peer', db, evidence/'core.log', secrets.token_hex(32)))
        proxy = stack.enter_context(Proxy(peer, db, evidence/'http-trace.json'))
        env = dict(os.environ, MESSENGER_TEST_DATABASE_URL=db.url, MORSE_RENEWAL_HTTP_ORIGIN=proxy.origin)
        with (evidence/'client.log').open('w') as log:
            result = subprocess.run([str(evidence/'renewal-client')], env=env, stdout=log,
                stderr=subprocess.STDOUT, timeout=90)
        assert result.returncode == 0, 'RNWv2 client failed; see '+str(evidence/'client.log')
        assert not proxy.errors, proxy.errors
        rows = {row['case']: row for row in proxy.requests}
        assert len(rows) == len(proxy.requests)
        for first, retry in [('v2-publication-lost','v2-publication-retry'), ('v2-answer-lost','v2-answer-retry')]:
            assert rows[first]['dropped'] and rows[first]['status'] == 201 and rows[retry]['status'] == 200
            assert rows[first]['payload_sha256'] == rows[retry]['payload_sha256']
            assert rows[first]['sequence'] == rows[retry]['sequence']
        assert proxy.dropped == {'v2-publication-lost', 'v2-answer-lost'}
        stored = db.sql('SELECT (SELECT sequence FROM messenger_accounts), '
            '(SELECT count(*) FROM messenger_devices), (SELECT count(*) FROM transparency_entries), '
            '(SELECT count(*) FROM messenger_one_time_prekeys)')
        assert stored == '9|3|9|3', stored
        report = dict(status='passed_owned_RNWv2_HTTP', requests=len(proxy.requests),
            committed_reply_losses=2, exact_retry_payloads_verified=2,
            final_sequence=9, devices=3, transparency_entries=9, registration_prekeys=3,
            case_groups=['stored capability1 credential and account-only capability3 refusal',
                'RNWv1 retained exact bytes and capability1 answer',
                'RNWv2 publication loss/replay and exact requested fields',
                'intervening transition/stale refusal/rebase and answer loss/replay',
                'primary also requires stored device-signed capability request'],
            scope='Actual production Core/Postgres HTTP with Mesh-generated signatures; no native execution, '
                'witnessed mobile adoption, deployment, operator independence or live funds claim.')
        (evidence/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    assert account.snapshot(sources) == frozen
    print(json.dumps(report))


if __name__ == '__main__':
    main()
