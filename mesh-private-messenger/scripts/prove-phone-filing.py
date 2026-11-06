"""Exercise the real Mesh actor/receipt reader through its compiled byte ABI.

Arguments: test fixture library, SBF-generated adjudication account JSON,
optional fork kind (1–3), optional 'c2sp' selector for anchored fixtures.
Only this test library substitutes HTTP loopback origins; release configuration
and the app export continue to require their native HTTPS pins.
"""
import base64
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def b58(value):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number, result = int.from_bytes(value, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        result = alphabet[digit] + result
    return '1' * (len(value) - len(value.lstrip(b'\0'))) + result


kind = int(sys.argv[3]) if len(sys.argv) > 3 else 1
assert kind in (1, 2, 3)
c2sp = len(sys.argv) > 4 and sys.argv[4] == 'c2sp'
fixture = next(row for row in json.loads(Path(sys.argv[2]).read_text())
               if row['version'] == 2 and row['kind'] == kind and bool(row.get('c2sp')) == c2sp)
accounts = {row['address']: bytes.fromhex(row['data_hex']) for row in fixture['accounts']}
log_address, log = next((address, data) for address, data in accounts.items() if data[:4] == b'MLG\1')
receipt = bytes.fromhex(fixture['receipt_hex'])
accounts[fixture['receipt_address']] = receipt
proof = bytes.fromhex(fixture['wire_hex'])
proof_hash = hashlib.sha256(proof[:5] + proof[37:]).hexdigest()
assert receipt[40:72].hex() == proof_hash
frame = '\n'.join(['5', fixture['service_key'], '22' * 32, '8', '1', '1',
    f"a {fixture['signing_key']} Fixture", b58(log[136:168]), '3',
    'https://one.example', 'https://two.example', 'https://three.example', '-', '2',
    '1', '1', f"a {fixture['signing_key']} Fixture", fixture['program'], fixture['log_name'], fixture['mint'],
    '3', 'https://relay-one.example', 'https://relay-two.example', 'https://relay-three.example']).encode()
state = {'mode': 'missing', 'wire': proof, 'rpc': 0, 'posts': 0, 'floor': 0, 'errors': []}
entered, release = threading.Event(), threading.Event()
guard = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            data = self.rfile.read(int(self.headers['Content-Length']))
            assert not self.headers.get('Authorization') and not self.headers.get('Cookie')
            if self.path == '/v1/fork-evidence':
                assert data == state['wire']
                with guard:
                    state['posts'] += 1
                body = {'schema_version': 1, 'status': 'queued', 'proof_hash': proof_hash}
                status = 202
            else:
                with guard:
                    state['rpc'] += 1
                request = json.loads(data)
                assert request['method'] == 'getMultipleAccounts'
                addresses, options = request['params']
                assert addresses == [log_address, fixture['economics_address'], fixture['receipt_address']]
                assert options['commitment'] == 'finalized' and options['encoding'] == 'base64'
                assert options['minContextSlot'] >= state['floor']
                entered.set()
                assert release.wait(10), 'receipt I/O was never released'
                mode = state['mode']
                values = []
                for address in addresses:
                    raw, owner = accounts[address], fixture['program']
                    if address == fixture['receipt_address']:
                        if mode == 'missing':
                            values.append(None)
                            continue
                        if mode == 'wrong-owner':
                            owner = '1' * 32
                        if mode in ['wrong-mint', 'wrong-hash']:
                            offset = 136 if mode == 'wrong-mint' else 40
                            raw = raw[:offset] + bytes([12]) * 32 + raw[offset + 32:]
                        if mode == 'disagree':
                            raw = raw[:72] + bytes([self.server.index + 12]) * 32 + raw[104:]
                    values.append({'data': [base64.b64encode(raw).decode(), 'base64'], 'owner': owner,
                                   'executable': False, 'lamports': 10000000, 'rentEpoch': 0})
                body = {'jsonrpc': '2.0', 'id': request['id'], 'result': {
                    'context': {'slot': 1 if mode == 'old' else 9007199254740993}, 'value': values}}
                status = 200
            payload = json.dumps(body).encode()
        except Exception as error:
            state['errors'].append(repr(error))
            status, payload = 500, b'fixture failed'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class Bytes(c.Structure):
    _fields_ = [('data', c.c_void_p), ('len', c.c_uint64)]


Callback = c.CFUNCTYPE(c.c_int32, c.c_void_p, c.c_void_p, c.c_uint64,
                      c.c_void_p, c.c_uint64, c.POINTER(c.c_uint64))


class Callbacks(c.Structure):
    _fields_ = [('version', c.c_uint32), ('size', c.c_uint32), ('context', c.c_void_p), ('calls', Callback * 9)]


store = {}


def host(operation):
    def call(_context, pointer, length, output, capacity, output_length):
        try:
            data = c.string_at(pointer, length)
            if operation == 1:
                size = struct.unpack('>I', data[:4])[0]
                store[data[4:4 + size]] = data[4 + size:]
                result = b''
            elif operation == 2:
                if data not in store:
                    return 2
                result = store[data]
            elif operation == 3:
                store.pop(data, None)
                result = b''
            elif operation == 4 and data == b'messenger/config/v1':
                result = frame
            else:
                return 2
            assert len(result) <= capacity
            c.memmove(output, result, len(result))
            output_length[0] = len(result)
            return 0
        except Exception as error:
            state['errors'].append(repr(error))
            return 5
    return Callback(call)


library = c.CDLL(str(Path(sys.argv[1]).resolve()))
library.mesh_library_free_returned_bytes.argtypes = [c.POINTER(Bytes)]
callbacks = Callbacks(1, c.sizeof(Callbacks), None, (Callback * 9)(*[host(i) for i in range(1, 10)]))
assert library.mesh_library_init() == 0
assert library.mesh_library_register_host_callbacks(c.byref(callbacks)) == 0


def invoke(symbol, value):
    function = getattr(library, symbol)
    function.argtypes = [c.c_void_p, c.c_uint64, c.POINTER(Bytes)]
    output = Bytes()
    code = function(value, len(value), c.byref(output))
    try:
        data = c.string_at(output.data, output.len)
    finally:
        library.mesh_library_free_returned_bytes(c.byref(output))
    assert code == 0, (symbol, code, data)
    return data


def fields(data):
    result = []
    while data:
        size = struct.unpack('>I', data[:4])[0]
        result.append(data[4:4 + size])
        data = data[4 + size:]
    assert result[0] == struct.pack('>I', 12) and len(result) == 13
    return [value.decode() for value in result[1:]]


def view(path):
    return fields(invoke('phone_fixture_start', str(path).encode()))


def finish(path):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = view(path)
        if value[11] == '0':
            assert not state['errors'], state['errors']
            return value
        time.sleep(.01)
    raise AssertionError('filing actor did not finish')


servers = []
try:
    for index in range(3):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.index = index
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    os.environ['MORSE_PHONE_FILING_PORTS'] = ','.join(str(server.server_port) for server in servers)
    with tempfile.TemporaryDirectory(prefix='morse-phone-filing-') as directory:
        for mode in ['missing', 'settled', 'elsewhere', 'fallback', 'wrong-owner', 'wrong-mint', 'wrong-hash', 'disagree']:
            path = Path(directory) / (mode + '.db')
            wire = proof
            if mode in ['elsewhere', 'fallback']:
                wire = proof[:5] + bytes([7 if mode == 'elsewhere' else 0]) * 32 + proof[37:]
            state.update(mode=mode, wire=wire, rpc=0, posts=0, floor=0)
            entered.clear()
            release.clear()
            Path(str(path) + '.wire').write_text(wire.hex())
            Path(str(path) + '.now').write_text('1000')
            assert invoke('phone_fixture_seed', str(path).encode()) == wire
            start = time.monotonic()
            initial = view(path)
            assert time.monotonic() - start < 1, 'native call waited for network I/O'
            assert initial[11] == '1'
            assert entered.wait(5)
            start = time.monotonic()
            assert invoke('mesh_messenger_transparency_fork', str(path).encode()) == wire
            assert time.monotonic() - start < 1, 'filing blocked another native invocation'
            release.set()
            result = finish(path)
            expected = {'missing': 'accepted', 'settled': 'settled', 'elsewhere': 'paid_elsewhere',
                        'fallback': 'settled', 'disagree': 'rpc_disagree'}.get(mode, 'rpc_unavailable')
            assert result[0] == expected, (mode, result)
            paid = mode in ['settled', 'elsewhere', 'fallback']
            assert result[3] == (fixture['finder'] if paid else '')
            assert result[4] == (str(struct.unpack_from('<Q', receipt, 248)[0]) if paid else '0')
            assert state['posts'] == (0 if paid else 3)
            counts = (state['rpc'], state['posts'])
            assert view(path) == result and counts == (state['rpc'], state['posts']), 'repeat wake spent network budget'
            if mode == 'missing':
                state.update(mode='old', floor=9007199254740993)
                Path(str(path) + '.now').write_text('61000')
                stale = finish(path)
                assert stale[0] == 'rpc_unavailable' and stale[10] == '9007199254740993', stale
            print(f'Native filing F{kind}:', mode, flush=True)
        empty = Path(directory) / 'empty.db'
        assert fields(invoke('mesh_messenger_fork_filing', str(empty).encode()))[0] == 'none'
        frame = b'\n'.join(frame.split(b'\n')[:-5] + [b'-', b'0'])
        assert fields(invoke('mesh_messenger_fork_filing', str(path).encode()))[0] == 'disabled'
        assert not state['errors'], state['errors']
        print('Production export: no evidence and disabled configuration', flush=True)
finally:
    release.set()
    for server in servers:
        server.shutdown()
        server.server_close()
    assert library.mesh_library_shutdown() == 0
