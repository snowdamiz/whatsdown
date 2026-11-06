"""Loopback orchestration only. Mesh owns signing, verification, proofs and cache writes."""
import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.request


def sha(value):
    return hashlib.sha256(value).hexdigest()


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
        environment = {'PATH': os.environ['PATH'], 'BOOTSTRAP_FIXTURE': str(root),
                       **{'OUTAGE_SEED_' + label: seed for label, seed in
                          json.loads((root / 'synthetic-seeds.json').read_text()).items()}}
        self.stderr = (root / (custody.name + '.stderr')).open('ab')
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('native_host.py')),
            str(library), str(root), str(custody)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, env=environment)
        self.lock = threading.Lock()
        self.pending = b''
        try:
            assert self.read(20) == {'ready': True}
        except BaseException:
            self.close()
            raise

    def read(self, timeout):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError('native ABI deadline')
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError(f'native host exited {self.process.poll()}')
            self.pending += chunk
            assert len(self.pending) <= 2_000_000, 'native ABI output limit'
        line, self.pending = self.pending.split(b'\n', 1)
        return json.loads(line)

    def invoke(self, symbol, data=b'', rejected=False):
        with self.lock:
            self.process.stdin.write((json.dumps({'symbol': symbol, 'hex': data.hex()}) + '\n').encode())
            self.process.stdin.flush()
            response = self.read(45)
        result = bytes.fromhex(response['hex'])
        assert not response['host_errors'], response
        assert response['code'] == (9 if rejected else 0), (symbol, response, result)
        return result

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        self.stderr.close()


def run(work, evidence, duration):
    root = evidence / 'local'
    root.mkdir(mode=0o700)
    # New public synthetic identities per run. Never reuse a signing identity on reset history.
    (root / 'synthetic-seeds.json').write_text(json.dumps(
        {label: os.urandom(32).hex() for label in ['11', '22', '33', '44']}) + '\n')
    library = work / ('libbootstrap.dylib' if sys.platform == 'darwin' else 'libbootstrap.so')
    condition = threading.Condition(threading.RLock())
    processes, open_logs, errors, attestations, queries, lookups = {}, [], [], [], [], []
    last_get = {}
    state = {'size': 0, 'checkpoint': b'', 'phase': 'setup'}
    events = (evidence / 'events.jsonl').open('w')
    started = time.monotonic_ns()
    deadline = time.monotonic() + duration + 240

    def event(kind, **values):
        row = {'kind': kind, 'monotonic_ns': time.monotonic_ns(), 'unix_ns': time.time_ns(),
               'utc': datetime.now(timezone.utc).isoformat(), **values}
        with condition:
            events.write(json.dumps(row) + '\n')
            events.flush()
        return row

    def healthy(expected):
        assert time.monotonic() < deadline, 'owned run deadline'
        assert not errors, errors
        for name in expected:
            assert processes[name].poll() is None, f'{name} exited: {processes[name].returncode}'

    def barrier(predicate, expected, seconds=22):
        end = min(deadline, time.monotonic() + seconds)
        with condition:
            while not predicate():
                healthy(expected)
                remaining = end - time.monotonic()
                assert remaining > 0, 'observed publication deadline'
                condition.wait(min(.5, remaining))
            healthy(expected)

    def accepted(size):
        return {row['id'] for row in attestations if row['size'] == size}

    def state_bytes(name):
        return (root / name / 'checkpoint').read_bytes()

    def absent(process):
        assert process.poll() == 0, 'stopped process not reaped cleanly'
        try:
            os.kill(process.pid, 0)
        except ProcessLookupError:
            return
        raise AssertionError('stopped PID still exists or was reused')

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(6)

        def log_message(self, *_):
            pass

        def reply(self, code, payload=b''):
            self.send_response(code)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            try:
                with condition:
                    if self.path == '/ready':
                        return self.reply(200, b'local-witness-outage-ready')
                    name, path = self.path.lstrip('/').split('/', 1)
                    assert name in processes and path == 'v2/transparency/checkpoint'
                    last_get[name] = state['size']
                    event('checkpoint_get', id=name, size=state['size'])
                    self.reply(200, state['checkpoint'])
            except BaseException as error:
                errors.append(repr(error))
                self.reply(500, b'fixture failure')

        def do_POST(self):
            try:
                assert not self.headers.get('Authorization') and not self.headers.get('Cookie')
                size = int(self.headers['Content-Length'])
                assert 0 < size <= 600000
                body = self.rfile.read(size)
                with condition:
                    if self.path == '/v2/devices/resolve':
                        payload = directory.invoke('outage_lookup', body)
                        event('directory_response', size=state['size'], mode=(root / 'lookup-mode').read_text(),
                              request_sha256=sha(body), response_sha256=sha(payload))
                        return self.reply(200, payload)
                    name, path = self.path.lstrip('/').split('/', 1)
                    assert name in processes
                    if path == 'v2/transparency/consistency':
                        # The service supplies the exact persisted-to-current range.
                        assert body[:4] == b'\x02KTS' and len(body) == 12
                        old_size, new_size = struct.unpack('>II', body[4:])
                        payload = directory.invoke('outage_consistency', body)
                        row = event('consistency', id=name, old_size=old_size, new_size=new_size,
                                    query_hex=body.hex(), proof_hex=payload.hex())
                        queries.append(row)
                        return self.reply(200, payload)
                    assert path == 'v2/transparency/witnesses'
                    target = last_get[name]
                    (root / 'verify-size').write_text(str(target))
                    verified = directory.invoke('outage_attestation', body).decode()
                    assert verified == name, 'process identity differs from pinned signature'
                    raw = bytes.fromhex((root / f'checkpoint-{target}.hex').read_text())
                    durable = state_bytes(name)
                    assert base64.b64decode(durable, validate=True) == raw, 'signature preceded durable checkpoint'
                    (root / f'attest-{target}-{name}.hex').write_text(body.hex())
                    row = event('verified_attestation', id=name, size=target, phase=state['phase'],
                                wire_hex=body.hex(), checkpoint_hex=raw.hex(), durable_base64=durable.decode())
                    attestations.append(row)
                    self.reply(201)
                    condition.notify_all()
            except BaseException as error:
                errors.append(repr(error))
                self.reply(500, b'fixture failure')

    def start_witness(name, first):
        directory_path = root / name
        directory_path.mkdir(mode=0o700, exist_ok=True)
        public = next(line.split(' ')[1] for line in (root / 'security').read_text().splitlines()
                      if line.startswith(name + ' '))
        seed_label = {'witness-a': '11', 'witness-b': '22', 'witness-c': '33'}[name]
        seed = json.loads((root / 'synthetic-seeds.json').read_text())[seed_label]
        environment = {'PATH': os.environ['PATH'], 'MESSENGER_BASE_URL': origin + '/' + name,
            'MESSENGER_WITNESS_MODE': 'pull', 'MESSENGER_WITNESS_ID': name,
            'MESSENGER_WITNESS_CHECKPOINT_PATH': str(directory_path / 'checkpoint'),
            'MESSENGER_WITNESS_SIGNING_SEED_HEX': seed,
            'MESSENGER_WITNESS_PUBLIC_KEY_HEX': public,
            'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX': (root / 'log-public-key').read_text(),
            'MESSENGER_SECURITY_CONFIG': (root / 'security').read_text()}
        if first:
            environment['WITNESS_INITIAL_CHECKPOINT_HEX'] = 'new-identity'
        streams = [(directory_path / f'{"initial" if first else "restart"}.{suffix}').open('ab')
                   for suffix in ['stdout', 'stderr']]
        open_logs.extend(streams)
        row = event('process_start_requested', id=name, first=first,
                    state_sha256=None if first else sha(state_bytes(name)),
                    initial_checkpoint='new-identity' if first else 'absent')
        # Holding the condition prevents an immediate GET before the PID is registered.
        with condition:
            process = subprocess.Popen([str(work / 'witness-service')], stdin=subprocess.DEVNULL,
                                       stdout=streams[0], stderr=streams[1], env=environment)
            processes[name] = process
        event('process_started', id=name, pid=process.pid, first=first)
        return row

    def advance():
        with condition:
            raw = directory.invoke('outage_advance')
            state['size'] = int((root / 'size').read_text())
            state['checkpoint'] = raw
            event('checkpoint_advanced', size=state['size'], checkpoint_hex=raw.hex())

    def lookup(client, path, expected, rejected=False):
        healthy(expected)
        before = client.invoke('outage_cache', path)
        request = vector(path) + vector(b'morse-canary-1')
        result = client.invoke('mesh_messenger_directory_resolve', request, rejected=rejected)
        after = client.invoke('outage_cache', path)
        if rejected:
            assert result == b'transparency_verification_failed', result
            assert before == after, 'negative response modified verified cache'
        else:
            assert result == devices
            cached = fields(after)
            assert cached[0] == state['checkpoint'] and all(cached), 'current verified cache not published'
            assert cached[4] == origin.encode()
            # Public Core view loader rechecks native trust and cached signatures. Mesh also
            # compares every proof/cache record to the exact successful directory response.
            assert client.invoke('outage_audit', path) == after, 'cache audit changed the observation'
        row = event('native_lookup_rejected' if rejected else 'native_lookup_succeeded',
                    size=state['size'], phase=state['phase'], result_hex=result.hex() if rejected else None,
                    result_sha256=sha(result), cache_sha256=sha(after),
                    checkpoint_hex=fields(after)[0].hex(), available=sorted(accepted(state['size'])))
        if not rejected:
            lookups.append(row)
        return row

    def terminate_all():
        for name, process in processes.items():
            if process.poll() is None:
                process.terminate()
        for name, process in processes.items():
            if process.poll() is None:
                try:
                    process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            event('process_teardown', id=name, pid=process.pid, returncode=process.returncode)
        for stream in open_logs:
            stream.close()

    def close_native(native, name):
        native.close()
        event('native_process_teardown', id=name, pid=native.process.pid,
              returncode=native.process.returncode)
        assert native.process.returncode == 0, f'{name} native shutdown failed'

    def interrupted(signum, _frame):
        raise RuntimeError(f'owned run interrupted by signal {signum}')

    old_handlers = {sig: signal.signal(sig, interrupted) for sig in [signal.SIGTERM, signal.SIGINT]}
    try:
        with ExitStack() as stack:
            stack.callback(events.close)
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True).start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
            origin = f'http://127.0.0.1:{server.server_port}'
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(origin + '/ready', timeout=2) as response:
                assert response.read() == b'local-witness-outage-ready'
            (root / 'network').write_text('\n'.join(['2', '1', origin, origin, origin,
                                                    origin.replace('http:', 'ws:') + '/v1/mailbox/stream', '1']))
            (root / 'lookup-mode').write_text('valid')
            directory = Native(library, root, root / 'directory-custody')
            stack.callback(close_native, directory, 'directory')
            canary = str(root / 'public-canary.db').encode()
            directory.invoke('mesh_messenger_create_account', vector(canary) + vector(b'morse-canary-1'))
            (root / 'entry.hex').write_text(directory.invoke('mesh_messenger_directory_entry', canary).hex())
            devices = directory.invoke('outage_initialize')
            advance()
            client = Native(library, root, root / 'client-custody')
            stack.callback(close_native, client, 'client')
            path = str(root / 'client.db').encode()
            client.invoke('mesh_messenger_create_account', vector(path) + vector(b'outage-reader'))
            assert not any(fields(client.invoke('outage_cache', path)))
            # RED: real native delivery with zero attestations must refuse and preserve empty cache.
            lookup(client, path, [], rejected=True)
            event('control_passed', name='zero real attestations refused at native delivery')
            stack.callback(terminate_all)
            for name in ['witness-a', 'witness-b', 'witness-c']:
                start_witness(name, True)
            barrier(lambda: accepted(state['size']) == set(processes), list(processes))
            # GREEN: unchanged delivery now succeeds using actual durable process signatures.
            lookup(client, path, list(processes))
            for mode in ['one', 'forged', 'forged-witness']:
                (root / 'lookup-mode').write_text(mode)
                lookup(client, path, list(processes), rejected=True)
                event('control_passed', name=mode + ' response refused; verified cache unchanged')
            (root / 'lookup-mode').write_text('valid')
            lookup(client, path, list(processes))
            stopped = processes['witness-c']
            retained = state_bytes('witness-c')
            stop_sequence = state['size']
            event('process_stop_requested', id='witness-c', pid=stopped.pid)
            stopped.terminate()
            assert stopped.wait(timeout=5) == 0
            absent(stopped)
            state['phase'] = 'outage'
            stopped_at = event('outage_started_after_wait', id='witness-c', pid=stopped.pid,
                               size=stop_sequence, state_sha256=sha(retained))
            print(json.dumps({'outage_started': stopped_at, 'required_seconds': duration}), flush=True)
            start_ns = stopped_at['monotonic_ns']
            next_advance, next_lookup, next_report = 0, 0, 0
            while True:
                elapsed = (time.monotonic_ns() - start_ns) / 1e9
                healthy(['witness-a', 'witness-b'])
                absent(stopped)
                assert state_bytes('witness-c') == retained, 'stopped state changed'
                if elapsed >= duration:
                    break
                if elapsed >= next_advance:
                    advance()
                    barrier(lambda: {'witness-a', 'witness-b'} <= accepted(state['size']),
                            ['witness-a', 'witness-b'])
                    assert 'witness-c' not in accepted(state['size']), 'absent witness submitted'
                    next_advance = elapsed + 30
                if elapsed >= next_lookup:
                    lookup(client, path, ['witness-a', 'witness-b'])
                    next_lookup = elapsed + 5
                if elapsed >= next_report:
                    row = event('outage_progress', elapsed_seconds=elapsed, size=state['size'],
                                successful_lookups=len([x for x in lookups if x['phase'] == 'outage']))
                    print(json.dumps(row), flush=True)
                    next_report = elapsed + 30
                # Bounded scheduling wait only; all success/time proof uses observations and clocks above.
                with condition:
                    condition.wait(.25)
            lookup(client, path, ['witness-a', 'witness-b'])
            absent(stopped)
            assert state_bytes('witness-c') == retained
            state['phase'] = 'recovery'
            restart = start_witness('witness-c', False)
            elapsed_ns = restart['monotonic_ns'] - start_ns
            assert elapsed_ns >= duration * 1_000_000_000
            assert restart['unix_ns'] - stopped_at['unix_ns'] >= duration * 1_000_000_000
            barrier(lambda: 'witness-c' in accepted(state['size']), list(processes))
            assert base64.b64decode(state_bytes('witness-c'), validate=True) == state['checkpoint']
            recovery = [q for q in queries if q['id'] == 'witness-c'
                        and q['old_size'] == stop_sequence and q['new_size'] == state['size']]
            assert recovery and state['size'] >= stop_sequence + 2, 'no observed skipped-history catch-up'
            assert not list((root / 'witness-c').glob('*.evidence-*')), 'witness reported history/time failure'
            lookup(client, path, list(processes))
            outage_rows = [row for row in lookups if row['phase'] == 'outage']
            times = [start_ns] + [row['monotonic_ns'] for row in outage_rows] + [restart['monotonic_ns']]
            max_gap = max(b - a for a, b in zip(times, times[1:])) / 1e9
            assert max_gap <= 45, f'lookup coverage gap {max_gap}'
            assert len({row['size'] for row in outage_rows}) >= max(2, duration // 45)
            assert not errors, errors
            report = {'status': 'PASS_LOCAL_900S' if duration >= 900 else 'PASS_SHORT_ONLY',
                'requested_outage_seconds': duration, 'outage_elapsed_monotonic_ns': elapsed_ns,
                'outage_elapsed_wall_ns': restart['unix_ns'] - stopped_at['unix_ns'],
                'outage_start': stopped_at, 'restart_requested': restart,
                'outage_successful_native_lookups': len(outage_rows), 'max_lookup_gap_seconds': max_gap,
                'outage_checkpoint_sizes': sorted({row['size'] for row in outage_rows}),
                'retained_checkpoint_base64': retained.decode(),
                'recovered_checkpoint_hex': state['checkpoint'].hex(),
                'recovered_state_base64': state_bytes('witness-c').decode(),
                'recovery_consistency': recovery, 'initial_pid': stopped.pid,
                'restarted_pid': processes['witness-c'].pid,
                'native_pids': {'directory': directory.process.pid, 'client': client.process.pid},
                'verified_attestations': len(attestations), 'total_seconds': (time.monotonic_ns() - started) / 1e9,
                'origin': origin}
            event('qualification_passed', **report)
            return report
    finally:
        for sig, previous in old_handlers.items():
            signal.signal(sig, previous)
