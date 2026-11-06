"""Local orchestration. All signed evidence, lookup admission and cache reads are Mesh."""
import base64
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import ssl
import struct
import subprocess
import sys
import threading
import urllib.request


def sha(data):
    return hashlib.sha256(data).hexdigest()


def vector(value):
    return struct.pack('>I', len(value)) + value


def fields(data):
    values = []
    while data:
        assert len(data) >= 4, 'truncated ABI vector'
        size = struct.unpack('>I', data[:4])[0]
        assert len(data) >= size + 4, 'truncated ABI value'
        values.append(data[4:4 + size])
        data = data[4 + size:]
    assert values and values[0] == struct.pack('>I', len(values) - 1), 'invalid ABI list'
    return values[1:]


class Native:
    def __init__(self, library, root, custody):
        environment = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
        environment['BOOTSTRAP_FIXTURE'] = str(root)
        self.stderr = (root / (custody.name + '.stderr')).open('ab')
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('native_host.py')),
                                         str(library), str(root), str(custody)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                                        env=environment)
        self.lock = threading.Lock()
        assert self.read(20) == {'ready': True}

    def read(self, timeout):
        assert select.select([self.process.stdout], [], [], timeout)[0], 'native ABI deadline'
        line = self.process.stdout.readline()
        assert line, f'native host exited {self.process.poll()}'
        return json.loads(line)

    def invoke(self, symbol, data, rejected=False):
        with self.lock:
            self.process.stdin.write((json.dumps({'symbol': symbol, 'hex': data.hex()}) + '\n').encode())
            self.process.stdin.flush()
            response = self.read(45)
        result = bytes.fromhex(response['hex'])
        assert not response['host_errors'], response
        if rejected:
            assert response['code'] == 9, (symbol, response['code'], result)
        else:
            assert response['code'] == 0, (symbol, response['code'], result)
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.stderr.close()
        assert self.process.returncode == 0, f'host shutdown failed: {self.process.returncode}'


def certificates(root):
    def run(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True, timeout=20)
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root / 'ca.key',
        '-out', root / 'ca.pem', '-days', '1', '-subj', '/CN=Morse synthetic bootstrap CA')
    run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', root / 'server.key',
        '-out', root / 'server.csr', '-subj', '/CN=127.0.0.1')
    (root / 'extensions.cnf').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=IP:127.0.0.1\n')
    run('x509', '-req', '-in', root / 'server.csr', '-CA', root / 'ca.pem',
        '-CAkey', root / 'ca.key', '-CAcreateserial', '-out', root / 'server.pem',
        '-days', '1', '-extfile', root / 'extensions.cnf')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    return context


def run(work, library):
    root = work / 'local'
    root.mkdir(mode=0o700)
    requests, errors, checks = [], [], []
    fixture_host = None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, payload):
            self.send_response(code)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self.reply(200 if self.path == '/ready' else 404, b'bootstrap-local-ready')

        def do_POST(self):
            try:
                assert not self.headers.get('Authorization') and not self.headers.get('Cookie')
                size = int(self.headers['Content-Length'])
                assert 0 < size <= 600000
                body = self.rfile.read(size)
                requests.append({'origin': self.server.index, 'path': self.path,
                                 'request_sha256': sha(body)})
                if self.server.index == 'directory':
                    assert self.path == '/v2/devices/resolve'
                    payload = fixture_host.invoke('bootstrap_lookup_response', body)
                else:
                    request = json.loads(body)
                    if request['method'] == 'getBlockTime':
                        result = int((root / 'block-time').read_text())
                    else:
                        assert request['method'] == 'getAccountInfo'
                        address, options = request['params']
                        assert options['commitment'] == 'finalized' and options['encoding'] == 'base64'
                        assert options['minContextSlot'] <= 501
                        if address == (root / 'ring-address').read_text():
                            raw = bytes.fromhex((root / 'header.hex').read_text()
                                                + (root / 'ring-entry.hex').read_text())
                        else:
                            assert address == (root / 'log-address').read_text()
                            raw = bytes.fromhex((root / 'log.hex').read_text())
                        offset, length = options['dataSlice']['offset'], options['dataSlice']['length']
                        result = {'context': {'slot': 501}, 'value': {
                            'data': [base64.b64encode(raw[offset:offset + length]).decode(), 'base64'],
                            'owner': '1' * 32, 'executable': False, 'lamports': 1, 'rentEpoch': 0}}
                    payload = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}).encode()
                self.reply(200, payload)
            except Exception as error:
                errors.append(repr(error))
                self.reply(500, b'fixture failure')

    with ExitStack() as stack:
        tls = certificates(root)
        servers = []
        for index in ['directory', 0, 1, 2]:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.index = index
            if index != 'directory':
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
            servers.append(server)
        origin = f'http://127.0.0.1:{servers[0].server_port}'
        rpc_origins = [f'https://127.0.0.1:{s.server_port}' for s in servers[1:]]
        # A response deadline verifies readiness; no fixed startup sleeps.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(origin + '/ready', timeout=2) as response:
            assert response.read() == b'bootstrap-local-ready'
        (root / 'rpc-origins').write_text('\n'.join(rpc_origins))
        (root / 'network').write_text('\n'.join(['2', '1', origin, origin, origin,
                                                origin.replace('http:', 'ws:') + '/v1/mailbox/stream', '1']))
        (root / 'lookup-mode').write_text('valid')
        fixture_host = Native(library, root, root / 'fixture-custody')
        stack.callback(fixture_host.close)
        canary = str(root / 'synthetic-canary.db').encode()
        fixture_host.invoke('mesh_messenger_create_account', vector(canary) + vector(b'morse-canary-1'))
        entry = fixture_host.invoke('mesh_messenger_directory_entry', canary)
        (root / 'entry.hex').write_text(entry.hex())
        devices = fixture_host.invoke('bootstrap_generate', str(root).encode())
        for rpc in rpc_origins:
            assert fixture_host.invoke('bootstrap_tls_control', rpc.encode()) == b'bootstrap-local-ready'
        checks.append({'name': 'three owned HTTPS peers with explicit request root', 'status': 'PASS'})
        client = Native(library, root, root / 'client-custody')
        stack.callback(client.close)
        path = str(root / 'client.db').encode()
        client.invoke('mesh_messenger_create_account', vector(path) + vector(b'bootstrap-reader'))
        empty = client.invoke('bootstrap_cache_snapshot', path)
        assert all(not value for value in fields(empty))
        lookup = vector(path) + vector(b'morse-canary-1')
        resolved = client.invoke('mesh_messenger_directory_resolve', lookup)
        assert resolved == devices
        before = client.invoke('bootstrap_cache_snapshot', path)
        cached = fields(before)
        assert cached[0] == bytes.fromhex((root / 'checkpoint.hex').read_text())
        assert all(cached), 'missing verified cache records'
        assert cached[4] == origin.encode()
        checks.append({'name': 'native lookup commits verified cache', 'status': 'PASS',
                       'before_sha256': sha(empty), 'after_sha256': sha(before),
                       'resolved_sha256': sha(resolved)})
        (root / 'lookup-mode').write_text('forged')
        error = client.invoke('mesh_messenger_directory_resolve', lookup, rejected=True)
        assert error == b'transparency_verification_failed', error
        assert client.invoke('bootstrap_cache_snapshot', path) == before
        checks.append({'name': 'corrupted directory signature refused; prior cache unchanged',
                       'status': 'PASS', 'error': error.decode(), 'cache_sha256': sha(before)})
        (root / 'lookup-mode').write_text('valid')
        client.close()
        client = Native(library, root, root / 'client-custody')
        stack.callback(client.close)
        assert client.invoke('bootstrap_cache_snapshot', path) == before
        assert client.invoke('mesh_messenger_directory_resolve', lookup) == devices
        assert (root / 'lookup-history').read_text().splitlines()[-1] == '1'
        checks.append({'name': 'process restart retains verified checkpoint and lookup continuity basis', 'status': 'PASS'})
        result = fields(client.invoke('mesh_messenger_anchor_check', path))
        status = result[0].decode()
        schedule = client.invoke('bootstrap_schedule_snapshot', path)
        assert fields(schedule)[4] == b'', 'unfinished claim'
        calls = len(requests)
        client.close()
        client = Native(library, root, root / 'client-custody')
        stack.callback(client.close)
        assert client.invoke('bootstrap_schedule_snapshot', path) == schedule
        assert fields(client.invoke('mesh_messenger_anchor_check', path)) == result
        assert len(requests) == calls, 'restart spent reserved network budget'
        checks.append({'name': 'anchor completed result and reservation survive process restart',
                       'status': 'PASS', 'anchor_status': status, 'schedule_sha256': sha(schedule)})
        security = (root / 'security').read_text()
        try:
            (root / 'security').write_text(security.replace('https://127.0.0.1:', 'http://127.0.0.1:'))
            refused = client.invoke('mesh_messenger_anchor_check', path, rejected=True)
            assert refused == b'invalid_messenger_configuration', refused
            assert len(requests) == calls
        finally:
            (root / 'security').write_text(security)
        checks.append({'name': 'native release pins refuse HTTP loopback RPCs before I/O',
                       'status': 'PASS', 'error': refused.decode()})
        assert not errors, errors
        rpc_requests = sum(r['origin'] != 'directory' for r in requests)
        blocked = status == 'rpc_unavailable' and rpc_requests == 0
        report = {'status': 'BLOCKED_NATIVE_RPC_TLS' if blocked else 'INCOMPLETE_LOCAL',
                  'checks': checks, 'anchor_result': [x.decode() for x in result],
                  'rpc_http_requests': rpc_requests,
                  'directory_requests': sum(r['origin'] == 'directory' for r in requests),
                  'lookup_previous_sizes': (root / 'lookup-history').read_text().splitlines(),
                  'acceptance_gate': {'expected': 'consistent', 'actual': status,
                                      'status': 'PASS' if status == 'consistent' else 'FAIL'},
                  'not_run': ['RPC disagreement', 'stale/incorrect anchor', 'missing-cache anchor control',
                              'next daily boundary', 'three canaries'],
                  'public_fixture_hashes': {p.name: sha(p.read_bytes()) for p in root.iterdir()
                                           if p.suffix == '.hex' or p.name in ('security', 'network', 'ohttp', 'ca.pem')}}
        (work / 'local-result.json').write_text(json.dumps(report, indent=2) + '\n')
        return report
