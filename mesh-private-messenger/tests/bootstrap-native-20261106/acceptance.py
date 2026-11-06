"""Owned local TLS peers driving actual compiled MobileCore exports.

Python owns orchestration/HTTP fixtures only. Mesh signs and verifies directory
proofs, admits lookups, stores encrypted state, and performs anchor decisions.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import shutil
import socket
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


def companion(security, rows):
    assert 3 <= len(rows) <= 8
    assert sum(len(pem) for _, pem in rows) <= 65536
    frame = b'\x01' + bytes([len(rows)]) + hashlib.sha256(security).digest()
    for origin, pem in sorted(rows):
        encoded = origin.encode('ascii')
        frame += struct.pack('>H', len(encoded)) + encoded + vector(pem)
    assert len(frame) <= 82002
    return frame


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

    def result(self, symbol, data):
        with self.lock:
            self.process.stdin.write((json.dumps({'symbol': symbol, 'hex': data.hex()}) + '\n').encode())
            self.process.stdin.flush()
            response = self.read(60)
        assert not response['host_errors'], response
        return response['code'], bytes.fromhex(response['hex'])

    def invoke(self, symbol, data, rejected=False):
        code, result = self.result(symbol, data)
        assert code == (9 if rejected else 0), (symbol, code, result)
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
    root.mkdir(mode=0o700)
    def run(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True, timeout=20)
    (root / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'
        'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
        'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root / 'ca.key',
        '-out', root / 'ca.pem', '-days', '1', '-subj', '/CN=Morse disposable local CA',
        '-config', root / 'ca.cnf', '-extensions', 'v3_ca')
    run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', root / 'server.key',
        '-out', root / 'server.csr', '-subj', '/CN=127.0.0.1')
    (root / 'extensions.cnf').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    run('x509', '-req', '-in', root / 'server.csr', '-CA', root / 'ca.pem',
        '-CAkey', root / 'ca.key', '-CAcreateserial', '-out', root / 'server.pem',
        '-days', '1', '-extfile', root / 'extensions.cnf')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    return context, (root / 'ca.pem').read_bytes()


def run(work, library):
    root = work / 'local'
    root.mkdir(mode=0o700)
    requests, handshakes, errors, checks = [], [], [], []
    state = {'scenario': 'setup', 'redirect': None, 'barrier': None, 'rpc_mode': 'valid'}
    report = {'status': 'FAIL', 'checks': checks, 'scope': 'LOCAL compiled MobileCore C ABI',
              'not_run': ['native platform packages and phone UI', 'production/funded/external RPC',
                          'production C ABI next-day clock boundary',
                          'bounded native context path (owned by production context tests)',
                          'pause exactly after receive/before dispatch inside Mesh',
                          'next-due retained-mismatch retry under production wall clock']}
    fixture_host = None
    lock = threading.Lock()

    def event(collection, row):
        with lock:
            row = {'scenario': state['scenario'], **row}
            collection.append(row)
            with (root / 'http-events.jsonl').open('a') as log:
                log.write(json.dumps(row) + '\n')
        return row

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        def get_request(self):
            connection, address = super().get_request()
            if self.tls is None:
                return connection, address
            try:
                connection.settimeout(5)
                secured = self.tls.wrap_socket(connection, server_side=True)
                event(handshakes, {'peer': self.index, 'tls': 'accepted'})
                return secured, address
            except OSError as error:
                event(handshakes, {'peer': self.index, 'tls': 'refused', 'error': type(error).__name__})
                connection.close()
                raise

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, payload, location=None):
            self.send_response(code)
            self.send_header('Content-Length', str(len(payload)))
            if location:
                self.send_header('Location', location)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            event(requests, {'peer': self.server.index, 'path': self.path, 'method': 'GET'})
            self.reply(200 if self.path == '/ready' else 404, b'bootstrap-local-ready')

        def account(self, address):
            if address == (root / 'ring-address').read_text():
                entry = bytes.fromhex((root / 'ring-entry.hex').read_text())
                if state['rpc_mode'] == 'mismatch':
                    entry = entry[:16] + bytes([entry[16] ^ 1]) + entry[17:]
                raw = bytes.fromhex((root / 'header.hex').read_text()) + entry
            else:
                assert address == (root / 'log-address').read_text(), address
                raw = bytes.fromhex((root / 'log.hex').read_text())
                if state['rpc_mode'] == 'slashed':
                    raw = raw[:5] + b'\x01' + raw[6:]
            return raw

        @staticmethod
        def account_json(raw):
            return {'data': [base64.b64encode(raw).decode(), 'base64'],
                    'owner': '1' * 32, 'executable': False, 'lamports': 1, 'rentEpoch': 0}

        def do_POST(self):
            try:
                assert not self.headers.get('Authorization') and not self.headers.get('Cookie')
                size = int(self.headers['Content-Length'])
                assert 0 < size <= 600000
                body = self.rfile.read(size)
                row = {'peer': self.server.index, 'path': self.path, 'method': 'POST',
                       'request_sha256': sha(body)}
                if self.server.index == 'directory':
                    if self.path == '/v2/devices/resolve':
                        payload = fixture_host.invoke('bootstrap_lookup_response', body)
                    else:
                        assert self.path == '/v2/transparency/checkpoint', self.path
                        assert body == struct.pack('>Q', 1), body.hex()
                        row['proof_sequence'] = 1
                        payload = bytes.fromhex((root / 'checkpoint.hex').read_text())
                else:
                    assert self.path == f'/rpc/{self.server.index}?owned=1', self.path
                    request = json.loads(body)
                    assert request['jsonrpc'] == '2.0' and request['id'] == 1, request
                    row['rpc'] = request
                    if request['method'] == 'getBlockTime':
                        assert request['params'] == [500], request
                        result = int((root / 'block-time').read_text())
                    else:
                        assert request['method'] in ('getAccountInfo', 'getMultipleAccounts')
                        addresses, options = request['params']
                        assert options['commitment'] == 'finalized' and options['encoding'] == 'base64'
                        assert 0 <= options['minContextSlot'] <= 501
                        if request['method'] == 'getAccountInfo':
                            raw = self.account(addresses)
                            offset, length = options['dataSlice']['offset'], options['dataSlice']['length']
                            assert (offset, length) in ((0, 64), (0, 352), (64, 104))
                            value = self.account_json(raw[offset:offset + length])
                        else:
                            assert addresses == [(root / 'ring-address').read_text(),
                                                 (root / 'log-address').read_text()]
                            value = [self.account_json(self.account(address)) for address in addresses]
                        result = {'context': {'slot': 501}, 'value': value}
                    payload = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}).encode()
                row = event(requests, row)
                barrier = state['barrier']
                if barrier and barrier['matches'](row) and not barrier['entered'].is_set():
                    barrier['entered'].set()
                    assert barrier['release'].wait(20), 'HTTP barrier release deadline'
                    if barrier['fail']:
                        # A transport error, not an application-level 503, exercises
                        # Http.send's Err branch and its postflight currency guard.
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                if state['redirect'] and self.server.index != 'directory':
                    self.reply(307, b'', state['redirect'])
                else:
                    self.reply(200, payload)
            except Exception as error:
                errors.append(repr(error))
                self.reply(500, b'fixture failure')

    def passed(name, **values):
        checks.append({'name': name, 'status': 'PASS', **values})
        print(json.dumps(checks[-1]), flush=True)

    try:
        with ExitStack() as stack:
            contexts, roots = [], []
            for i in range(4):
                context, pem = certificates(root / f'pki-{i}')
                contexts.append(context)
                roots.append(pem)
            (root / 'ca.pem').write_bytes(b''.join(roots[:3]))
            (root / 'wrong-ca.pem').write_bytes(roots[3])
            servers = []
            for index in ['directory', 0, 1, 2, 'redirect-target']:
                server = Server(('127.0.0.1', 0), Handler)
                server.index = index
                server.tls = None if index == 'directory' else contexts[index if isinstance(index, int) else 0]
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
                thread.start()
                stack.callback(server.server_close)
                stack.callback(server.shutdown)
                servers.append(server)
            directory = f'http://127.0.0.1:{servers[0].server_port}'
            origins = [f'https://127.0.0.1:{s.server_port}' for s in servers[1:4]]
            endpoints = [f'{origin}/rpc/{i}?owned=1' for i, origin in enumerate(origins)]
            (root / 'rpc-origins').write_text('\n'.join(endpoints))
            (root / 'network').write_text('\n'.join(['2', '1', directory, directory, directory,
                                                    directory.replace('http:', 'ws:') + '/v1/mailbox/stream', '1']))
            (root / 'lookup-mode').write_text('valid')
            fixture_host = Native(library, root, root / 'fixture-custody')
            stack.callback(fixture_host.close)
            canary = str(root / 'synthetic-canary.db').encode()
            fixture_host.invoke('mesh_messenger_create_account', vector(canary) + vector(b'morse-canary-1'))
            (root / 'entry.hex').write_text(fixture_host.invoke('mesh_messenger_directory_entry', canary).hex())
            devices = fixture_host.invoke('bootstrap_generate', str(root).encode())
            security = (root / 'security').read_bytes()
            good = companion(security, list(zip(origins, roots)))
            (root / 'rpc-tls').write_bytes(good)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(root / 'ca.pem'))))
            for origin in [directory, *origins]:
                with opener.open(origin + '/ready', timeout=3) as response:
                    assert response.read() == b'bootstrap-local-ready'
            passed('three independently rooted owned TLS peers ready', origins=origins,
                   root_sha256=[sha(p) for p in roots[:3]], frame_sha256=sha(good))

            def new_client(name, frame=good):
                state['scenario'] = name
                owned = root / name
                owned.mkdir(mode=0o700)
                for resource in ('security', 'network', 'ohttp', 'ca.pem', 'wrong-ca.pem'):
                    shutil.copy2(root / resource, owned / resource)
                if frame is not None:
                    (owned / 'rpc-tls').write_bytes(frame)
                client = Native(library, owned, owned / 'custody')
                stack.callback(client.close)
                path = str(owned / 'client.db').encode()
                client.invoke('mesh_messenger_create_account', vector(path) + vector(b'bootstrap-reader'))
                return client, path, owned

            def lookup(client, path):
                return client.invoke('mesh_messenger_directory_resolve', vector(path) + vector(b'morse-canary-1'))

            def rpc_rows(start=0):
                return [row for row in requests[start:] if 'rpc' in row]

            client, path, owned = new_client('positive')
            empty = client.invoke('bootstrap_cache_snapshot', path)
            assert all(not value for value in fields(empty))
            start = len(requests)
            resolved = lookup(client, path)
            assert resolved == devices
            before = client.invoke('bootstrap_cache_snapshot', path)
            cached = fields(before)
            assert cached[0] == bytes.fromhex((root / 'checkpoint.hex').read_text())
            assert all(cached), 'missing verified checkpoint/view/witness/leaf/origin'
            assert cached[4] == directory.encode()
            result = fields(client.invoke('mesh_messenger_anchor_check', path))
            assert result[0] == b'consistent', result
            assert result[2:4] == [b'501', b'500'], result
            rows = rpc_rows(start)
            assert len({row['peer'] for row in rows}) >= 2
            assert any(row['rpc']['method'] == 'getBlockTime' for row in rows)
            slices = [row['rpc']['params'][1]['dataSlice'] for row in rows
                      if row['rpc']['method'] == 'getAccountInfo']
            assert slices.count({'offset': 0, 'length': 64}) >= 4, slices
            assert {'offset': 0, 'length': 352} in slices and {'offset': 64, 'length': 104} in slices
            assert any(row.get('proof_sequence') == 1 for row in requests[start:])
            passed('actual create/resolve/anchor C ABI commits cache and consistent finalized TLS proof',
                   anchor_result=[x.decode() for x in result], rpc_http=len(rows),
                   cache_sha256=sha(before), resolved_sha256=sha(resolved))
            report['anchor_result'] = [x.decode() for x in result]
            report['acceptance_gate'] = {'expected': 'consistent', 'actual': 'consistent', 'status': 'PASS'}

            (root / 'lookup-mode').write_text('forged')
            error = client.invoke('mesh_messenger_directory_resolve',
                                  vector(path) + vector(b'morse-canary-1'), rejected=True)
            assert error == b'transparency_verification_failed', error
            assert client.invoke('bootstrap_cache_snapshot', path) == before
            (root / 'lookup-mode').write_text('valid')
            passed('corrupted directory signature refused with unchanged verified cache',
                   error=error.decode(), cache_sha256=sha(before))
            schedule = client.invoke('bootstrap_schedule_snapshot', path)
            assert fields(schedule)[4] == b'', 'unfinished successful claim'
            calls = len(requests)
            old_pid = client.process.pid
            client.close()
            client = Native(library, owned, owned / 'custody')
            stack.callback(client.close)
            assert client.process.pid != old_pid
            assert client.invoke('bootstrap_cache_snapshot', path) == before
            assert client.invoke('bootstrap_schedule_snapshot', path) == schedule
            assert fields(client.invoke('mesh_messenger_anchor_check', path)) == result
            assert len(requests) == calls, 'restart spent persisted reservation'
            assert lookup(client, path) == devices
            assert (root / 'lookup-history').read_text().splitlines()[-1] == '1'
            passed('real process restart retains previous_tree_size=1, cache, result and network reservation',
                   process_a=old_pid, process_b=client.process.pid, schedule_sha256=sha(schedule))

            assert client.invoke('bootstrap_batch', b'') == b'501'
            assert any(row['rpc']['method'] == 'getMultipleAccounts' for row in rpc_rows())
            for origin in origins:
                assert client.invoke('bootstrap_tls_pool', origin.encode()) == b'isolated'
            passed('shared compiled batch and runtime pooled explicit/default/wrong root isolation')

            # Roots are transport authority only. A new valid resource cannot
            # clear the stable public-log schedule or consume another hour.
            rotated = companion(security, [(origin, pem + b'\n') for origin, pem in zip(origins, roots)])
            (owned / 'rpc-tls').write_bytes(rotated)
            calls = len(requests)
            assert fields(client.invoke('mesh_messenger_anchor_check', path)) == result
            assert client.invoke('bootstrap_schedule_snapshot', path) == schedule
            assert len(requests) == calls
            (owned / 'rpc-tls').write_bytes(good)
            passed('root-only rotation preserves public-log identity and hourly/daily budget')

            # Exercise the public checker with injected time separately from
            # native wall-clock acceptance, retaining the real persisted state.
            old_time = (root / 'block-time').read_text()
            start = len(requests)
            try:
                (root / 'block-time').write_text(str(int(old_time) + 86400))
                due = fields(client.invoke('bootstrap_anchor_due', path))
                assert due[0] == b'consistent', due
                headers = [row['rpc']['params'][1] for row in rpc_rows(start)
                           if row['rpc']['method'] == 'getAccountInfo'
                           and row['rpc']['params'][1]['dataSlice'] == {'offset': 0, 'length': 64}]
                assert headers and all(row['minContextSlot'] >= 501 for row in headers)
            finally:
                (root / 'block-time').write_text(old_time)
            passed('public Mesh checker next-due injected time retains slot floor and performs fresh TLS',
                   boundary='supplementary explicit-time API; native wall clock not injected')
            client.close()

            wrong_rows = [(origin, roots[3]) for origin in origins]
            negatives = [('absent-default', None, 'outage'),
                         ('wrong-ca-all', companion(security, wrong_rows), 'outage'),
                         ('malformed-pem-all', companion(security, [(o, b'broken PEM') for o in origins]), 'invalid'),
                         ('truncated-frame', good[:-1], 'invalid'),
                         ('trailing-frame', good + b'\x00', 'invalid'),
                         ('bad-version', b'\x02' + good[1:], 'invalid'),
                         ('zero-present-count', b'\x01\x00' + good[2:], 'invalid'),
                         ('incomplete-count', b'\x01\x02' + good[2:], 'invalid'),
                         ('excess-count', b'\x01\x09' + good[2:], 'invalid'),
                         ('present-without-explicit-roots', companion(security, [(o, b'') for o in origins]), 'invalid'),
                         ('absent-with-tail', b'\x01\x00\x00', 'invalid'),
                         ('security-digest', good[:2] + b'\x00' * 32 + good[34:], 'invalid')]
            for name, replacement in [('wrong-origin', 'https://localhost:1'),
                                      ('wrong-port', f'https://127.0.0.1:{servers[4].server_port}'),
                                      ('suffix-lookalike', 'https://127.0.0.1.invalid')]:
                negatives.append((name, companion(security, [(replacement, roots[0]),
                    (origins[1], roots[1]), (origins[2], roots[2])]), 'invalid'))
            negatives.append(('resource-read-error', good, 'unavailable'))
            for name, frame, expected in negatives:
                negative, negative_path, negative_root = new_client(name, frame)
                if expected == 'unavailable':
                    (negative_root / 'rpc-tls-read-error').touch()
                start = len(requests)
                tls_start = len(handshakes)
                code, output = negative.result('mesh_messenger_anchor_check', negative_path)
                if expected == 'outage':
                    assert code == 0 and fields(output)[0] == b'rpc_unavailable', (name, code, output)
                    assert any(row['tls'] == 'refused' for row in handshakes[tls_start:]), name
                else:
                    assert code == 9, (name, code, output)
                    assert output == (b'rpc_tls_config_unavailable' if expected == 'unavailable'
                                      else b'rpc_tls_config_invalid'), (name, output)
                assert not rpc_rows(start), (name, rpc_rows(start))
                if name == 'absent-default':
                    reads = [json.loads(line) for line in (negative_root / 'resource-reads.jsonl').read_text().splitlines()]
                    assert any(row['selector'] == 'messenger/rpc-tls-roots/v1'
                               and row['length'] == 2 and row['sha256'] == sha(b'\x01\x00') for row in reads)
                assert all(not value for value in fields(negative.invoke('bootstrap_cache_snapshot', negative_path)))
                passed(name + ' refuses without RPC HTTP or cache commit', code=code,
                       result=output.decode() if code else fields(output)[0].decode(),
                       tls_attempts=len(handshakes) - tls_start)
                negative.close()

            one_bad = companion(security, [(origin, roots[3] if i == 0 else roots[i])
                                          for i, origin in enumerate(origins)])
            tolerant, tolerant_path, _ = new_client('one-bad-ca', one_bad)
            start = len(requests)
            assert lookup(tolerant, tolerant_path) == devices
            assert fields(tolerant.invoke('mesh_messenger_anchor_check', tolerant_path))[0] == b'consistent'
            assert tolerant.invoke('bootstrap_batch', b'') == b'501'
            assert {row['peer'] for row in rpc_rows(start)} == {1, 2}
            passed('one wrong CA plus two agreeing peers preserves native quorum and deterministic batch fallback')
            tolerant.close()

            mixed = companion(security, [(origin, roots[i] if i != 0 else b'')
                                        for i, origin in enumerate(origins)])
            mixed_client, mixed_path, _ = new_client('explicit-mixed-webpki', mixed)
            assert lookup(mixed_client, mixed_path) == devices
            assert fields(mixed_client.invoke('mesh_messenger_anchor_check', mixed_path))[0] == b'consistent'
            passed('explicit mixed WebPki row preserves two-root native quorum without implicit fallback')
            mixed_client.close()

            poisoned = companion(security, [(origin, b'broken PEM' if i == 0 else roots[i])
                                            for i, origin in enumerate(origins)])
            attempted, attempted_path, _ = new_client('one-malformed-attempted', poisoned)
            start = len(requests)
            error = attempted.invoke('bootstrap_batch', b'', rejected=True)
            assert error == b'rpc_tls_config_invalid', error
            assert not rpc_rows(start), 'poisoned first request dispatched'
            passed('attempted malformed PEM is fatal despite two valid peer roots',
                   boundary='compiled shared batch reader; no eager unused-row claim')
            attempted.close()

            for target in [origins[1] + '/redirected',
                           f'https://127.0.0.1:{servers[4].server_port}/redirected',
                           directory + '/redirected']:
                redirected, redirected_path, _ = new_client('redirect-' + str(len(checks)))
                state['redirect'] = target
                start = len(requests)
                try:
                    output = fields(redirected.invoke('mesh_messenger_anchor_check', redirected_path))
                    assert output[0] == b'rpc_unavailable', output
                    assert rpc_rows(start)
                    assert not any(row['path'] == '/redirected' for row in requests[start:])
                finally:
                    state['redirect'] = None
                passed('RPC redirect never followed', target=target)
                redirected.close()

            for changed in ['resource', 'account']:
                for failure in [False, True]:
                    name = f'barrier-{changed}-' + ('http-error' if failure else 'success')
                    blocked, blocked_path, blocked_root = new_client(name)
                    cache = blocked.invoke('bootstrap_cache_snapshot', blocked_path)
                    barrier = {'entered': threading.Event(), 'release': threading.Event(),
                               'matches': lambda row: 'rpc' in row, 'fail': failure}
                    state['barrier'] = barrier
                    try:
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            future = executor.submit(blocked.result, 'mesh_messenger_directory_resolve',
                                vector(blocked_path) + vector(b'morse-canary-1'))
                            assert barrier['entered'].wait(20), 'actual RPC response barrier not reached'
                            if changed == 'resource':
                                (blocked_root / 'rpc-tls').write_bytes(rotated)
                            else:
                                replacement = Native(library, blocked_root, blocked_root / 'custody')
                                stack.callback(replacement.close)
                                replacement.invoke('mesh_messenger_erase_account', blocked_path)
                                replacement.invoke('mesh_messenger_create_account',
                                                   vector(blocked_path) + vector(b'new-account'))
                                replacement_entry = replacement.invoke('mesh_messenger_directory_entry', blocked_path)
                                replacement.close()
                            barrier['release'].set()
                            code, output = future.result(timeout=30)
                        assert code == 9, (name, code, output)
                        if changed == 'account':
                            # The directory wrapper deliberately checks its
                            # original identity after the inner anchor result.
                            assert output == b'directory_identity_changed', (name, output)
                            assert blocked.invoke('mesh_messenger_directory_entry', blocked_path) == replacement_entry
                        else:
                            assert output.startswith(b'rpc_context_changed:'), (name, output)
                        assert blocked.invoke('bootstrap_cache_snapshot', blocked_path) == cache
                        snapshot = fields(blocked.invoke('bootstrap_schedule_snapshot', blocked_path))
                        if changed == 'resource':
                            assert snapshot[4] and not snapshot[5], 'retired operation completed old claim'
                        else:
                            assert not snapshot[4] and not snapshot[5], 'old operation completed in replacement account'
                        passed('actual TLS barrier ' + changed + ' replacement refuses ' +
                               ('Http.send Err' if failure else 'successful response'),
                               error=output.decode(), cache_sha256=sha(cache))
                    finally:
                        barrier['release'].set()
                        state['barrier'] = None
                    blocked.close()

            fresh, fresh_path, _ = new_client('fresh-rotated-capture', rotated)
            assert lookup(fresh, fresh_path) == devices
            assert fields(fresh.invoke('mesh_messenger_anchor_check', fresh_path))[0] == b'consistent'
            passed('fresh native capture accepts new immutable root resource')
            fresh.close()

            slashed, slashed_path, slashed_root = new_client('stable-slash')
            state['rpc_mode'] = 'slashed'
            try:
                value = fields(slashed.invoke('mesh_messenger_anchor_check', slashed_path))
                assert value[0] == b'service_slashed', value
            finally:
                state['rpc_mode'] = 'valid'
            (slashed_root / 'rpc-tls').write_bytes(rotated)
            calls = len(requests)
            assert fields(slashed.invoke('mesh_messenger_anchor_check', slashed_path)) == value
            assert len(requests) == calls
            passed('root rotation cannot clear authenticated slash refusal')
            (slashed_root / 'rpc-tls').write_bytes(b'broken frame')
            assert slashed.invoke('bootstrap_service_refused', slashed_path) == b'refused'
            passed('stable slash refusal remains readable with malformed transport')
            slashed.close()

            mismatched, mismatch_path, mismatch_root = new_client('stable-mismatch')
            state['rpc_mode'] = 'mismatch'
            try:
                error = mismatched.invoke('mesh_messenger_directory_resolve',
                    vector(mismatch_path) + vector(b'morse-canary-1'), rejected=True)
                assert error == b'transparency_fork_detected', error
                value = fields(mismatched.invoke('mesh_messenger_anchor_check', mismatch_path))
                assert value[0] == b'mismatch', value
            finally:
                state['rpc_mode'] = 'valid'
            schedule = mismatched.invoke('bootstrap_schedule_snapshot', mismatch_path)
            (mismatch_root / 'rpc-tls').write_bytes(rotated)
            calls = len(requests)
            assert fields(mismatched.invoke('mesh_messenger_anchor_check', mismatch_path)) == value
            assert mismatched.invoke('bootstrap_schedule_snapshot', mismatch_path) == schedule
            assert len(requests) == calls
            (mismatch_root / 'rpc-tls').write_bytes(b'broken frame')
            assert mismatched.invoke('bootstrap_service_refused', mismatch_path, rejected=True) == b'anchor_mismatch'
            passed('root rotation preserves mismatch reservation and refusal even with malformed transport')
            mismatched.close()
            assert not errors, errors
            report['status'] = 'PASS_LOCAL_RPC_TLS'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report.update(rpc_http_requests=sum('rpc' in row for row in requests),
                      directory_requests=sum(row['peer'] == 'directory' for row in requests),
                      tls_handshakes=handshakes, server_errors=errors,
                      lookup_previous_sizes=((root / 'lookup-history').read_text().splitlines()
                                             if (root / 'lookup-history').exists() else []),
                      public_fixture_hashes={str(p.relative_to(root)): sha(p.read_bytes())
                          for p in root.rglob('*') if p.is_file() and
                          (p.suffix == '.hex' or p.name in ('security', 'network', 'ohttp', 'rpc-tls',
                                                           'ca.pem', 'http-events.jsonl', 'resource-reads.jsonl'))})
        (work / 'local-result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
