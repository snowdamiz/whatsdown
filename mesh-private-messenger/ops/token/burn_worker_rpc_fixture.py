#!/usr/bin/env python3
"""Owned loopback RPC fixture only. Invoke through prove_burn_worker.py."""
from pathlib import Path
import os, json, time, subprocess, hashlib, tempfile, threading, base64, copy
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import argparse
p = argparse.ArgumentParser()
p.add_argument('--work-root', required=True)
p.add_argument('--proof-dir', required=True)
a = p.parse_args()
w = Path(a.work_root).resolve()
pins = json.loads((w / 'proof/basis.json').read_text())
fixture = w / 'fixtures/bank.json'
source = json.loads(fixture.read_text())
bank = source['bank']
out = Path(a.proof_dir).resolve()
out.mkdir(parents=True, exist_ok=False)
requests = []
problems = []
redirects = []

class Server(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            count = int(self.headers['Content-Length'])
            assert 0 < count <= 16384
            rpc = json.loads(self.rfile.read(count))
            mode, peer = self.path.strip('/').split('/')
            method = rpc['method']
            requests.append({'mode': mode, 'peer': peer, 'method': method, 'id': rpc['id'], 'origin_port': self.server.server_port})
            if mode == 'target':
                redirects.append(self.path)
                raise AssertionError('redirect followed')
            if mode == 'redirect':
                self.send_response(302)
                self.send_header('Location', '/target/a')
                self.end_headers()
                return
            assert rpc['jsonrpc'] == '2.0'
            if method == 'getLatestBlockhash':
                assert rpc['id'] == 30
                assert rpc['params'] == [{'commitment': 'finalized', 'minContextSlot': int(bank['slot'])}]
                tip = bank['latest_blockhash']
                result = {'context': {'slot': int(tip['context_slot'])}, 'value': {'blockhash': tip['blockhash'], 'lastValidBlockHeight': int(tip['last_valid_block_height'])}}
                if mode == 'quoted-context':
                    result['context']['slot'] = str(result['context']['slot'])
                if mode == 'nested-context':
                    result['context'] = json.dumps(result['context'])
                if mode == 'future-tip':
                    result['context']['slot'] += 1
                if mode == 'expired-tip':
                    result['value']['lastValidBlockHeight'] = int(bank['block_height']) - 1
            elif method == 'getMultipleAccounts':
                market = mode.startswith('market-')
                assert rpc['id'] == (1 if market else 31)
                assert rpc['params'][0] == [a['address'] for a in bank['accounts'][:19 if market else 31]]
                minimum = int(bank['slot']) + (mode == 'future-tip')
                assert rpc['params'][1] == {'commitment': 'finalized', 'encoding': 'base64', 'dataSlice': {'offset': 0, 'length': 5728}, 'minContextSlot': minimum}
                values = []
                for a in bank['accounts']:
                    values.append(None if a.get('missing') else {'owner': a['owner'], 'lamports': int(a['lamports']), 'executable': a['executable'], 'rentEpoch': 0, 'space': int(a['space']), 'data': [base64.b64encode(bytes.fromhex(a['data_hex'])).decode(), 'base64']})
                result = {'context': {'slot': int(bank['slot'])}, 'value': values}
                if mode == 'stale':
                    result['context']['slot'] -= 1
                if mode == 'missing':
                    values[15] = None
                if mode == 'wrong-owner':
                    values[2]['owner'] = source['pins']['payer']
                if mode == 'custody-owner':
                    values[21]['owner'] = source['pins']['payer']
                if mode == 'wrong-space':
                    values[15]['space'] = 2176
                if mode in ['wrong-carry', 'market-carry']:
                    raw = bytearray(base64.b64decode(values[15]['data'][0]))
                    raw[272:304] = bytes.fromhex('ab' * 32)
                    values[15]['data'][0] = base64.b64encode(raw).decode()
                if mode == 'trailing':
                    values[15]['space'] += 1
                    values[15]['data'][0] = base64.b64encode(base64.b64decode(values[15]['data'][0]) + b'\x00').decode()
                if mode == 'upgraded':
                    for i in [18, 30]:
                        raw = bytearray(base64.b64decode(values[i]['data'][0]))
                        raw[4:12] = (int(source['pins']['program_slot']) + 1).to_bytes(8, 'little')
                        values[i]['data'][0] = base64.b64encode(raw).decode()
                if mode == 'contradictory-copy':
                    values[19]['lamports'] += 1
                if mode == 'split':
                    values[14]['lamports'] += ord(peer)
                if market:
                    result['value'] = values[:19]
            elif method == 'getBlock':
                assert rpc['id'] == 32
                assert rpc['params'] == [int(bank['slot']), {'commitment': 'finalized', 'transactionDetails': 'none', 'rewards': False, 'maxSupportedTransactionVersion': 0}]
                result = {'blockHeight': int(bank['block_height']), 'blockhash': bank['blockhash'], 'parentSlot': int(bank['parent_slot']), 'previousBlockhash': bank['previous_blockhash'], 'blockTime': int(bank['timestamp'])}
                if mode == 'quoted-height':
                    result['blockHeight'] = str(result['blockHeight'])
                if mode == 'null-height':
                    result['blockHeight'] = None
                if mode == 'mismatched-time':
                    result['blockTime'] += 1
            elif method == 'isBlockhashValid':
                assert rpc['id'] == 33
                assert rpc['params'] == [bank['blockhash'], {'commitment': 'finalized', 'minContextSlot': int(bank['slot'])}]
                result = {'context': {'slot': int(bank['slot'])}, 'value': True}
                if mode == 'hash-quoted':
                    result['value'] = 'false'
                if mode == 'hash-context':
                    result['context']['slot'] += 1
                    result['value'] = False
                if mode == 'hash-null':
                    result['value'] = None
                if mode == 'hash-disagree':
                    result['value'] = False if peer == 'a' else True if peer == 'b' else None
            else:
                raise AssertionError('unexpected RPC method ' + method)
            output = json.dumps({'jsonrpc': '2.0', 'id': rpc['id'] + (mode == 'wrong-id'), 'result': result}).encode()
            if mode == 'oversized':
                output = b'x' * 262145
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            problems.append(type(e).__name__ + ':' + str(e))
            self.send_response(500)
            self.end_headers()
servers = [ThreadingHTTPServer(('127.0.0.1', 0), Server) for _ in range(3)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
server = servers[0]
start = time.monotonic()
env = dict(os.environ, MESH_RT_LIB_PATH=pins['runtime'], MESH_TEST_RT_LIB_PATH=pins['test_runtime'], MORSE_BURN_WORKER_TEST_RPC=f'http://127.0.0.1:{server.server_port}', MORSE_BURN_WORKER_TEST_RPC_PEERS=','.join(f'http://127.0.0.1:{peer.server_port}' for peer in servers), MORSE_BURN_WORKER_BANK_FIXTURE=str(fixture))
cmd = [pins['compiler'], 'test', str(w / 'sources/token/burn_worker_rpc.test.mpl')]
try:
    with (out / 'test.log').open('w') as log:
        r = subprocess.run(cmd, cwd=w / 'sources/token', env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    assert not problems, problems
    assert not redirects
    assert not any(request["mode"] == "alias" for request in requests)
    assert len({request["origin_port"] for request in requests}) == 3
    assert r.returncode == 0
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    (out / 'requests.json').write_text(json.dumps(requests, indent=2) + '\n')
    (out / 'problems.json').write_text(json.dumps(problems) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {'exit_code': r.returncode, 'requests': len(requests), 'seconds': round(time.monotonic() - start, 2), 'fixture_sha256': sha(fixture), 'compiler_sha256': pins['compiler_sha256'], 'runtime_sha256': pins['runtime_sha256'], 'test_runtime_sha256': pins['test_runtime_sha256'], 'limits': ['Owned loopback fixture replays authentic local SBF prefixes with deliberate malformed variants.', 'Endpoint separation is a quorum contract test, not independent real providers or ledger finality.']}
(out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record), flush=True)
