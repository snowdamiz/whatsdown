#!/usr/bin/env python3
"""Terminal-only native renewal/revocation proof with owned signed evidence.

The fresh native primary answers a genuine linked-device renewal request. The
external linked-device producer and witness are synthetic Mesh roles; no clock
bypass or private mobile key export is used. Installed reader162 ABI/libraries
remain unchanged. No computer-use, browser, screen, or UI tool is invoked.
"""
from contextlib import ExitStack, contextmanager
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
import tempfile
import threading
import urllib.request

from attachment_android_proof import AttachmentAndroidProof
from credit_ios_proof import CreditIOSProof

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent
MODULE = PRODUCT/'apps/mobile/modules/mesh-messenger'
spec = importlib.util.spec_from_file_location('account_http_proof', PRODUCT/'scripts/prove-account-http-native.py')
account = importlib.util.module_from_spec(spec)
spec.loader.exec_module(account)


@contextmanager
def fixture_environment(values):
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class DeviceIOSProof(CreditIOSProof):
    bundle = 'app.morse.devicehttp.proof.ios'


class DeviceAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.devicehttp.proof.android'
    instrumentation_class = 'DeviceHTTPProofTest'


class Proxy:
    def __init__(self, peer, db, trace):
        self.peer, self.db, self.trace = peer, db, trace
        self.requests, self.errors = [], []
        self.drop = None
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
                    routes = {'PUT': {'/v1/devices/register'}, 'POST': {'/v1/prekeys/one-time/batch',
                        '/v1/devices/resolve', '/v2/devices/resolve', '/v1/devices/revoke'}}
                    assert self.path in routes[self.command], (self.command, self.path)
                    assert self.headers.get('Content-Type') == 'application/octet-stream'
                    assert self.headers.get('Cache-Control') == 'no-store'
                    assert self.headers.get('Authorization') is None and self.headers.get('Cookie') is None
                    size = int(self.headers['Content-Length'])
                    assert 0 < size <= 309384
                    body = self.rfile.read(size)
                    assert len(body) == size
                    payload = body
                    if body[:4] == b'\1PWR':
                        assert len(body) >= 20 and int.from_bytes(body[16:20], 'big') == len(body)-20
                        payload = body[20:]
                    source = self.headers.get('X-Morse-Proof-Source', 'native')
                    assert source in ('native', 'external_mesh_fixture')
                    connection = http.client.HTTPConnection('127.0.0.1', fixture.peer.port, timeout=20)
                    try:
                        connection.request(self.command, self.path, body,
                                           {'Content-Type':'application/octet-stream', 'Cache-Control':'no-store'})
                        response = connection.getresponse()
                        status, content = response.status, response.read(570419)
                        assert len(content) <= 570418
                    finally:
                        connection.close()
                    sequence = fixture.db.sql('SELECT sequence::text FROM messenger_accounts')
                    with fixture.lock:
                        drop = source == 'native' and status in (200, 201) and (
                            (fixture.drop == 'renewal' and self.command == 'PUT') or
                            (fixture.drop == 'revocation' and self.path == '/v1/devices/revoke'))
                        fixture.requests.append(dict(source=source, method=self.command, path=self.path,
                            bytes=size, sha256=hashlib.sha256(body).hexdigest(),
                            payload_sha256=hashlib.sha256(payload).hexdigest(), status=status,
                            response_sha256=hashlib.sha256(content).hexdigest(), dropped=drop, account_sequence=sequence))
                        fixture.trace.write_text(json.dumps(dict(requests=fixture.requests, errors=fixture.errors), indent=2)+'\n')
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
                        fixture.trace.write_text(json.dumps(dict(requests=fixture.requests, errors=fixture.errors), indent=2)+'\n')
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


def request_http(origin, path, body=None, method=None, source=None):
    headers = {'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store'}
    if source:
        headers['X-Morse-Proof-Source'] = source
    request = urllib.request.Request(origin+path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read(570419)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4097)


def helper(peer, path, body=None):
    status, value = request_http(f'http://127.0.0.1:{peer.port}', '/proof/'+path, body)
    assert status == 200, (path, status, value[:200])
    return value


def summary(peer):
    lines = helper(peer, 'summary').decode().splitlines()
    return dict(sequence=int(lines[0]), devices={row.split(',')[0]: dict(
        credential_sequence=int(row.split(',')[1]), signed_prekey_id=int(row.split(',')[2]),
        renewal_request=row.split(',')[3] == '1') for row in lines[1:]})


def build_backend(evidence, compiler):
    frozen = ROOT/'.morse/witness-proof/account-http-native162-checkpoint/evidence/sources'
    sources = evidence/'sources'
    shutil.copytree(frozen, sources)
    service = sources/'directory-delivery'
    for file in sources.glob('*/mesh.toml'):
        text = file.read_text().replace(str(ROOT/'.morse/witness-proof/account-http-native162/sources'), str(sources))
        file.write_text(text)
    fixture = service/'proof/device_fixture.mpl'
    fixture.parent.mkdir()
    fixture.write_bytes((PRODUCT/'scripts/device-http-proof/device_fixture.mpl.fixture').read_bytes())
    main = (service/'main.mpl').read_text()
    main = 'from Proof.DeviceFixture import proof_router\n'+main.replace('HTTP.serve(build_router(), port)', 'HTTP.serve(proof_router(build_router()), port)')
    (service/'main.mpl').write_text(main)
    before = account.snapshot(sources)
    binary = evidence/'directory-device-peer'
    command = [str(compiler), 'build', str(service), '--opt-level', '0', '-o', str(binary)]
    with (evidence/'backend-build.log').open('w') as log:
        result = subprocess.run(command, cwd=PRODUCT, stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode == 0, 'Mesh fixture build failed; see backend-build.log'
    assert before == account.snapshot(sources)
    report = json.loads(binary.with_name(binary.name+'.plaintext.json').read_text())
    assert all(row['source_sha256'] in before.values() for row in report['modules'])
    (evidence/'backend.json').write_text(json.dumps(dict(command=command,
        compiler_sha256=account.sha(compiler), executable_sha256=account.sha(binary), sources=before,
        compiled_modules=len(report['modules']), scope='Production API/storage with owned external-device/witness fixture and test-only bootstrap'), indent=2)+'\n')
    return binary, service/'migrations'


def prove(platform, evidence, binary, migrations):
    output = evidence/platform
    output.mkdir()
    source = MODULE/platform/'device-http-proof'/('DeviceHTTPProof.swift' if platform == 'ios' else 'DeviceHTTPProof.kt')
    runner = DeviceIOSProof if platform == 'ios' else DeviceAndroidProof
    service_seed, witness_seed = secrets.token_hex(32), secrets.token_hex(32)
    witness = 'outside '+account.public_key(witness_seed)+' Test'
    security = '\n'.join(['3', account.public_key(service_seed), '22'*32, '1', '1', '1', witness, '-', '0', '-', '2', '1', '1', witness])
    external_id = secrets.token_hex(16)
    username = 'device_'+platform
    cases, observations = [], []
    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='morse-device-http-', dir='/tmp'))).resolve()
        stack.enter_context(fixture_environment(dict(MORSE_DEVICE_PROOF_WORK=str(work),
            MORSE_DEVICE_PROOF_SIGNING=secrets.token_hex(32), MORSE_DEVICE_PROOF_IDENTITY=secrets.token_hex(32),
            MORSE_DEVICE_PROOF_ID=external_id, MORSE_DEVICE_PROOF_WITNESS=witness_seed,
            MORSE_DEVICE_PROOF_USERNAME=username)))
        db = stack.enter_context(account.Database(migrations))
        witness_key = account.public_key(witness_seed)
        db.sql("INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, morse_run) VALUES ('outside', decode('"+witness_key+"','hex'), 'Owned local proof', 'pinned', 'mesh', true)")
        peer = stack.enter_context(account.Peer(binary, db, output/'peer.log', service_seed))
        proxy = stack.enter_context(Proxy(peer, db, output/'http-trace.json'))
        pins = '\n'.join(['2', '1', proxy.origin, proxy.origin, proxy.origin,
                          proxy.origin.replace('http:', 'ws:')+'/v1/mailbox/stream', '1'])
        (output/'native-network-config.txt').write_text(pins)
        (output/'native-security-config.txt').write_text(security)
        native = stack.enter_context(runner(Path(os.environ.get('MORSE_DEVICE_HTTP_PRODUCT', PRODUCT)), work, security, proof_source=source,
            network_config=pins, artifact_dir=output/'native'))
        profile = native.invoke('create', body=username.encode())
        assert native.invoke('register') == b'\1DRG\0@\0'
        first = summary(peer)
        assert first['sequence'] == 1 and len(first['devices']) == 1, first
        primary_id = next(iter(first['devices']))
        helper(peer, 'cosign')
        current = native.invoke('resolve', body=username.encode())
        marker = len(proxy.requests)
        assert native.invoke('renew', body=current) == b'\1DNR\0\0\0\0'
        assert len(proxy.requests) == marker
        assert 'invalid_device_revocation' in native.invoke('revoke', id=bytes.fromhex(primary_id), body=current, rejected=True)
        assert len(proxy.requests) == marker
        cases.append('fresh witnessed primary does not renew early, and cannot revoke its own/last device before HTTP')
        pending = helper(peer, 'device-request')
        authorization = native.invoke('authorize', body=json.dumps(dict(devices=current.hex(), pending=pending.hex())).encode())
        entry = helper(peer, 'entry', authorization)
        assert request_http(proxy.origin, '/v1/devices/register', entry, method='PUT', source='external_mesh_fixture')[0] == 201
        linked = summary(peer)
        assert linked['sequence'] == 2 and external_id in linked['devices'], linked
        asking = helper(peer, 'renewal', b'')
        assert request_http(proxy.origin, '/v1/devices/register', asking, method='PUT', source='external_mesh_fixture')[0] in (200, 201)
        requested = summary(peer)
        assert requested['sequence'] == 3 and requested['devices'][external_id]['renewal_request'], requested
        observations.extend([first, linked, requested])
        helper(peer, 'cosign')
        requesting_set = native.invoke('resolve', body=username.encode())
        marker = len(proxy.requests)
        tampered = requesting_set[:-1]+bytes([requesting_set[-1] ^ 1])
        error = native.invoke('renew', body=tampered, rejected=True)
        assert 'device_set_transparency_unverified' in error or 'invalid_device_set' in error, error
        assert len(proxy.requests) == marker and native.invoke('profile') == profile
        cases.append('native primary authorizes the linked device; production API accepts its signed request; native admission binds the exact witnessed set and refuses a changed set before HTTP')
        proxy.drop = 'renewal'
        error = native.invoke('renew', body=requesting_set, rejected=True)
        assert 'device_transport_unavailable' in error, error
        renewed = summary(peer)
        assert renewed['sequence'] == 4 and renewed['devices'][external_id]['credential_sequence'] == 4, renewed
        assert renewed['devices'][external_id]['signed_prekey_id'] == 2 and not renewed['devices'][external_id]['renewal_request']
        dropped = [row for row in proxy.requests if row['dropped']]
        assert len(dropped) >= 1 and len({row['payload_sha256'] for row in dropped}) == 1
        proxy.drop = None
        native.restart()
        marker = len(proxy.requests)
        assert native.invoke('renew', body=requesting_set) == b'\1DNR\1\0\0\0'
        replayed = proxy.requests[marker:]
        assert len(replayed) == 1 and replayed[0]['payload_sha256'] == dropped[0]['payload_sha256'], replayed
        assert summary(peer) == renewed
        cases.append('native account signs the renewed credential; lost accepted reply and real restart replay the exact journaled entry without another server sequence change (fresh PoW envelope allowed)')
        helper(peer, 'cosign')
        renewed_set = native.invoke('resolve', body=username.encode())
        marker = len(proxy.requests)
        assert native.invoke('renew', body=renewed_set) == b'\1DNR\0\0\0\0'
        assert len(proxy.requests) == marker
        wrong = helper(peer, 'forged-revocation')
        assert request_http(proxy.origin, '/v1/devices/revoke', wrong, source='external_mesh_fixture')[0] == 400
        assert summary(peer) == renewed
        cases.append('only the newer witnessed successor retires the renewal queue; a linked-device signature cannot authorize account revocation')
        proxy.drop = 'revocation'
        marker = len(proxy.requests)
        error = native.invoke('revoke', id=bytes.fromhex(external_id), body=renewed_set, rejected=True)
        assert 'device_transport_unavailable' in error, error
        assert db.sql('SELECT count(*) FROM messenger_devices WHERE revoked_at IS NOT NULL') == '1'
        assert db.sql('SELECT count(*) FROM messenger_revoked_devices') == '1'
        assert db.sql('SELECT count(*) FROM messenger_mailboxes WHERE NOT active') == '1'
        assert db.sql('SELECT count(*) FROM messenger_devices WHERE revoked_at IS NULL') == '1'
        drop_revoke = proxy.requests[marker:]
        assert len(drop_revoke) == 1 and drop_revoke[0]['dropped']
        proxy.drop = None
        native.restart()
        marker = len(proxy.requests)
        error = native.invoke('revoke', id=bytes.fromhex(external_id), body=renewed_set, rejected=True)
        assert 'device_http_409' in error, error
        assert len(proxy.requests) == marker+1 and proxy.requests[-1]['sha256'] == drop_revoke[0]['sha256']
        helper(peer, 'cosign')
        revoked_set = native.invoke('resolve', body=username.encode())
        marker = len(proxy.requests)
        assert native.invoke('revoke', id=bytes.fromhex(external_id), body=revoked_set) == b'\1DRV\0\xc8'
        assert len(proxy.requests) == marker
        last = summary(peer)
        assert last['sequence'] == 5 and list(last['devices']) == [primary_id], last
        assert 'invalid_device_revocation' in native.invoke('revoke', id=bytes.fromhex(primary_id), body=revoked_set, rejected=True)
        assert len(proxy.requests) == marker
        observations.extend([renewed, last])
        cases.append('native authorized revocation persists exactly one revoked device/inactive mailbox; unknown reply retries identical bytes safely, then witnessed revoked state recovers terminal success without HTTP; last primary remains')
        assert native.invoke('discard', id=profile) == b'\1ADS\1'
        replacement = native.invoke('create', body=('replacement_'+platform).encode())
        marker = len(proxy.requests)
        for operation in ['renew', 'revoke']:
            error = native.invoke(operation, id=bytes.fromhex(external_id), body=revoked_set, rejected=True)
            assert 'device_set_transparency_unverified' in error, error
            assert len(proxy.requests) == marker and native.invoke('profile') == replacement
        assert native.invoke('discard', id=replacement) == b'\1ADS\1'
        assert not proxy.errors, proxy.errors
        cases.append('erasure/replacement removes the old admitted basis; delayed renewal/revocation refuses before HTTP and preserves the new OS-sealed profile')
        result = dict(status='passed_native_device_http', platform=platform, inputs=native.input_hashes,
            checks=cases, requests=proxy.requests, persisted_observations=observations,
            native_http_requests=sum(row['source']=='native' for row in proxy.requests),
            external_fixture_http_requests=sum(row['source']=='external_mesh_fixture' for row in proxy.requests),
            limits='Owned development HTTP pins, real generated ABI and Keychain/Keystore. Production router/API/storage unchanged; external Mesh linked-device producer and one owned witness are fixture roles. No clock bypass, mobile key export, independent-operator claim, linked-client receipt/decryption, physical device or release claim. Fresh primary early-renewal and self/last-device refusals are tested; primary answers a valid signed linked-device renewal request. Profiles, mailbox capabilities, generated private material and databases are not archived.')
        (output/'evidence.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(dict(platform=platform, status=result['status'], cases=len(cases),
            native_requests=result['native_http_requests'], fixture_requests=result['external_fixture_http_requests'])), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['ios','android','both'], default='both')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, default=ROOT/'.morse/native-reader-meshc.py')
    parser.add_argument('--reuse-backend', action='store_true')
    args = parser.parse_args()
    evidence, compiler = args.evidence.resolve(), args.compiler.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if args.reuse_backend:
        record = json.loads((evidence/'backend.json').read_text())
        binary, migrations = evidence/'directory-device-peer', evidence/'sources/directory-delivery/migrations'
        assert account.sha(binary) == record['executable_sha256'] and account.snapshot(evidence/'sources') == record['sources']
    else:
        binary, migrations = build_backend(evidence, compiler)
    platforms = ['ios','android'] if args.platform == 'both' else [args.platform]
    results = [prove(platform, evidence, binary, migrations) for platform in platforms]
    (evidence/'result.json').write_text(json.dumps(dict(status='passed', platforms=platforms,
        cases=sum(len(row['checks']) for row in results)), indent=2)+'\n')


if __name__ == '__main__':
    main()
