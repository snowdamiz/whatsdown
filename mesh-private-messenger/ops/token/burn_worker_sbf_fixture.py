#!/usr/bin/env python3
"""Owned test adapter only: SBF file handoff, loopback RPC, subprocess/restart/race assertions.
All scheduling, validation, packet generation and custody logic execute in compiled Mesh.
The private test key is read in memory and passed only through the opaque native Env API.
"""
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import argparse, os, json, time, subprocess, hashlib, tempfile, threading, base64, sqlite3, concurrent.futures, shutil
p = argparse.ArgumentParser()
p.add_argument('--work-root', required=True)
p.add_argument('--hook-dir', required=True)
p.add_argument('--key-path', required=True)
p.add_argument('--proof-dir', required=True)
a = p.parse_args()
w = Path(a.work_root).resolve()
hook = Path(a.hook_dir).resolve()
key_path = Path(a.key_path).resolve()
out = Path(a.proof_dir).resolve()
out.mkdir(parents=True, exist_ok=False)
pins = json.loads((w / 'proof/basis.json').read_text())
build = json.loads((w / 'proof/worker-build/result.json').read_text())
binary = w / 'proof/worker-build/burn-worker'
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
assert sha(binary) == build['binary_sha256']
private = Path(tempfile.mkdtemp(prefix='morse-burn-sbf-worker-', dir=tempfile.gettempdir())).resolve()
storage = private / 'key'
storage.mkdir(mode=448)
db = private / 'worker.db'
requests = []
sends = []
problems = []
runs = []
state = {'file': 'initial.json', 'db': db, 'ack': False}
mutex = threading.Lock()

def wait(name, seconds=1200):
    limit = time.monotonic() + seconds
    while time.monotonic() < limit:
        if (hook / 'abort').exists():
            raise RuntimeError('SBF fixture aborted')
        f = hook / name
        if f.exists():
            return f
        time.sleep(0.1)
    raise TimeoutError(name)

def atomic(name, text):
    f = hook / (name + '.tmp')
    f.write_text(text)
    f.replace(hook / name)

def b58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(raw, 'big')
    r = ''
    while n:
        n, v = divmod(n, 58)
        r = alphabet[v] + r
    return '1' * (len(raw) - len(raw.lstrip(b'\x00'))) + r

def table_rows(path):
    if not path.exists():
        return {}
    with sqlite3.connect(path, timeout=3) as d:
        names = {x[0] for x in d.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {n: list(d.execute('SELECT * FROM ' + n + ' ORDER BY 1,2')) for n in ['token_burn_journal', 'token_burn_retired', 'token_burn_missed'] if n in names}

def ledger_digest(path):
    rows = table_rows(path)
    return hashlib.sha256(repr(rows).encode()).hexdigest()

class Server(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            count = int(self.headers['Content-Length'])
            assert 0 < count <= 16384
            rpc = json.loads(self.rfile.read(count))
            method = rpc['method']
            assert rpc['jsonrpc'] == '2.0'
            mode, peer = self.path.strip('/').split('/')
            with mutex:
                source = json.loads((hook / state['file']).read_text())
                database = state['db']
                ack = state['ack']
                file = state['file']
            bank = source['bank']
            requests.append({'mode': mode, 'peer': peer, 'method': method, 'id': rpc['id'], 'bank': file, 'origin_port': self.server.server_port})
            if method == 'sendTransaction':
                assert mode == 'good'
                assert rpc['id'] == 2
                packet = base64.b64decode(rpc['params'][0], validate=True)
                assert len(packet) <= 1232 and packet[0] == 1
                assert rpc['params'][1] == {'encoding': 'base64', 'skipPreflight': False, 'preflightCommitment': 'confirmed', 'maxRetries': 0, 'minContextSlot': int(bank['slot'])}
                rows = table_rows(database)
                assert len(rows['token_burn_journal']) == 1
                cipher = rows['token_burn_journal'][0][1]
                assert packet not in cipher
                event = {'bank': file, 'wire_base64': rpc['params'][0], 'wire_sha256': hashlib.sha256(packet).hexdigest(), 'signature': b58(packet[1:65]), 'retired_count': len(rows.get('token_burn_retired', [])), 'journal_present_before_send': True}
                if file == 'expired.json':
                    assert event['retired_count'] == 1
                sends.append(event)
                if not ack:
                    self.send_response(503)
                    self.end_headers()
                    return
                result = event['signature']
            elif method == 'getLatestBlockhash':
                assert rpc['id'] == 30
                assert rpc['params'][0]['commitment'] == 'finalized'
                assert int(rpc['params'][0]['minContextSlot']) <= int(bank['slot'])
                tip = bank['latest_blockhash']
                result = {'context': {'slot': int(tip['context_slot'])}, 'value': {'blockhash': tip['blockhash'], 'lastValidBlockHeight': int(tip['last_valid_block_height'])}}
                if mode == 'quoted-context':
                    result['context']['slot'] = str(result['context']['slot'])
            elif method == 'getMultipleAccounts':
                assert rpc['id'] == 31
                assert rpc['params'][0] == [x['address'] for x in bank['accounts']]
                assert rpc['params'][1] == {'commitment': 'finalized', 'encoding': 'base64', 'dataSlice': {'offset': 0, 'length': 5728}, 'minContextSlot': int(bank['slot'])}
                values = [None if x.get('missing') else {'owner': x['owner'], 'lamports': int(x['lamports']), 'executable': x['executable'], 'space': int(x['space']), 'rentEpoch': 0, 'data': [base64.b64encode(bytes.fromhex(x['data_hex'])).decode(), 'base64']} for x in bank['accounts']]
                result = {'context': {'slot': int(bank['slot'])}, 'value': values}
                if mode == 'owner':
                    values[2]['owner'] = source['pins']['payer']
                if mode == 'stale':
                    result['context']['slot'] -= 1
                if mode == 'split':
                    values[14]['lamports'] += ord(peer)
                if mode == 'upgraded':
                    for i in [18, 30]:
                        data = bytearray(base64.b64decode(values[i]['data'][0]))
                        data[4:12] = (int(source['pins']['program_slot']) + 1).to_bytes(8, 'little')
                        values[i]['data'][0] = base64.b64encode(data).decode()
            elif method == 'getBlock':
                assert rpc['id'] == 32
                assert rpc['params'] == [int(bank['slot']), {'commitment': 'finalized', 'transactionDetails': 'none', 'rewards': False, 'maxSupportedTransactionVersion': 0}]
                result = {'blockHeight': int(bank['block_height']), 'blockhash': bank['blockhash'], 'parentSlot': int(bank['parent_slot']), 'previousBlockhash': bank['previous_blockhash'], 'blockTime': int(bank['timestamp'])}
                if mode == 'quoted-height':
                    result['blockHeight'] = str(result['blockHeight'])
                if mode == 'null-height':
                    result['blockHeight'] = None
            elif method == 'isBlockhashValid':
                assert rpc['id'] == 33
                assert rpc['params'] == [initial['bank']['blockhash'], {'commitment': 'finalized', 'minContextSlot': int(bank['slot'])}]
                valid = file == 'initial.json'
                if not valid:
                    assert (hook / 'old-refusal.json').exists()
                result = {'context': {'slot': int(bank['slot'])}, 'value': valid}
            else:
                raise AssertionError('unexpected RPC ' + method)
            payload = json.dumps({'jsonrpc': '2.0', 'id': rpc['id'] + (mode == 'wrong-id'), 'result': result}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            problems.append(type(error).__name__ + ':' + str(error))
            self.send_response(500)
            self.end_headers()
servers = [ThreadingHTTPServer(('127.0.0.1', 0), Server) for _ in range(3)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
started = time.monotonic()
try:
    wait('initial.json')
    limit = time.monotonic() + 60
    while not key_path.exists() and time.monotonic() < limit:
        time.sleep(0.1)
    material = bytes.fromhex(key_path.read_text().strip())
    assert len(material) == 64
    seed = material[:32].hex()
    initial = json.loads((hook / 'initial.json').read_text())
    assert b58(material[32:]) == initial['pins']['payer']
    del material

    def configuration(name, replace=True, mode='good', database=None, directory=None):
        active = json.loads((hook / state['file']).read_text())
        config = {'schema_version': '1', 'pins': active['pins'], 'payer': initial['pins']['payer'], 'epoch': initial['epoch'], 'minimum_slot': active['bank']['slot'], 'rpc_urls': [f'http://127.0.0.1:{peer.server_port}/{mode}/{name}' for peer, name in zip(servers, ['a', 'b', 'c'])], 'test_mode': True, 'replace_expired': replace, 'routes_hex': [initial['route_hex']] * 24, 'journal_path': str(database or db), 'storage_key_directory': str(directory or storage), 'ticks': '1', 'interval_ms': '1000'}
        if name in ['missed', 'late', 'late-repeat']:
            config['routes_hex'] = ['00' * 39] * 24
        file = private / (name + '.json')
        file.write_text(json.dumps(config))
        return file

    def run(label, config):
        before = len(sends)
        start = time.monotonic()
        r = subprocess.run([str(binary), str(config)], env=dict(os.environ, MORSE_BURN_WORKER_PAYER_SEED_HEX=seed), capture_output=True, text=True, timeout=90)
        (out / (label + '.stdout')).write_text(r.stdout)
        (out / (label + '.stderr')).write_text(r.stderr)
        assert r.returncode == 0, (label, r.returncode, r.stderr)
        results = [json.loads(x) for x in r.stdout.splitlines() if x.startswith('{')]
        assert len(results) == 1, (label, r.stdout)
        record = {'label': label, 'result': results[0], 'seconds': round(time.monotonic() - start, 3), 'observed_sends': len(sends) - before}
        runs.append(record)
        return results[0]
    original_config = configuration('initial')
    first = run('initial-unknown', original_config)
    assert first['status'] == 'pending:unknown', first
    assert len(sends) == 1
    second = run('restart-exact', original_config)
    assert second['status'] == 'pending:unknown' and second['signature'] == first['signature']
    assert len(sends) == 2 and sends[0]['wire_base64'] == sends[1]['wire_base64']
    legacy_db = private / 'legacy.db'
    legacy_key = private / 'legacy-key'
    legacy_key.mkdir(mode=448)
    legacy_packet = out / 'legacy-live.packet.base64'
    legacy_packet.write_text(sends[0]['wire_base64'])
    legacy_env = dict(os.environ, MESH_RT_LIB_PATH=pins['runtime'], MESH_TEST_RT_LIB_PATH=pins['test_runtime'], MORSE_BURN_WORKER_BANK_FIXTURE=str(hook / 'initial.json'), MORSE_BURN_WORKER_LEGACY_PACKET=str(legacy_packet), MORSE_BURN_WORKER_LEGACY_DB=str(legacy_db), MORSE_BURN_WORKER_LEGACY_KEY=str(legacy_key))
    with (out / 'legacy-import.log').open('w') as log:
        legacy_import = subprocess.run([pins['compiler'], 'test', str(w / 'sources/token/burn_worker_legacy.test.mpl')], cwd=w / 'sources/token', env=legacy_env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    assert legacy_import.returncode == 0
    state['db'] = legacy_db
    legacy_before = ledger_digest(legacy_db)
    before = len(sends)
    legacy_result = run('legacy-still-valid-refused', configuration('legacy', database=legacy_db, directory=legacy_key))
    assert legacy_result['status'].startswith('reconcile:') and len(sends) == before and (ledger_digest(legacy_db) == legacy_before)
    assert len(table_rows(legacy_db)['token_burn_retired']) == 0
    state['db'] = db
    atomic('old.packet.base64', sends[0]['wire_base64'])
    wait('expired.json')
    wait('old-refusal.json')
    refusal = json.loads((hook / 'old-refusal.json').read_text())
    assert refusal['error'] == 'BlockhashNotFound' and refusal['unchanged_week'] and refusal['pre_expiry_simulation_passed']
    state['file'] = 'expired.json'
    no_replace = run('explicit-recovery-disabled', configuration('no-replace', replace=False))
    assert no_replace['status'] == 'reconcile:expired-packet' and len(sends) == 2
    original_digest = ledger_digest(db)
    for mode in ['owner', 'stale', 'quoted-context', 'quoted-height', 'null-height', 'wrong-id', 'split', 'upgraded']:
        before = len(sends)
        result = run('refuse-' + mode, configuration('refuse-' + mode, mode=mode))
        assert result['status'].startswith('reconcile:')
        assert len(sends) == before
        assert ledger_digest(db) == original_digest
    replacement_config = configuration('replacement')
    state['ack'] = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        race = list(pool.map(lambda i: run('replace-race-' + str(i), replacement_config), range(4)))
    replacements = [x for x in sends if x['bank'] == 'expired.json']
    assert replacements and len({x['wire_base64'] for x in replacements}) == 1
    assert all((x['retired_count'] == 1 for x in replacements))
    assert replacements[0]['wire_base64'] != sends[0]['wire_base64']
    assert len(table_rows(db)['token_burn_retired']) == 1
    late_db = private / 'late.db'
    shutil.copy2(db, late_db)
    atomic('replacement.packet.base64', replacements[0]['wire_base64'])
    wait('executed.json')
    wait('replacement-result.json')
    state['file'] = 'executed.json'
    before = len(sends)
    completed = run('restart-finalized', configuration('executed'))
    assert completed['status'] == 'complete:chunk' and completed['signature'] == replacements[0]['signature'] and (len(sends) == before)
    again = run('repeat-finalized', configuration('executed-repeat'))
    assert again == completed and len(sends) == before
    wait('executed-later.json')
    state['file'] = 'executed-later.json'
    state['db'] = late_db
    late_before = ledger_digest(late_db)
    late = run('receipt-after-original-window', configuration('late', database=late_db))
    assert ledger_digest(late_db) != late_before and len(sends) == before
    assert len(table_rows(late_db)['token_burn_journal']) == 1 and len(table_rows(late_db)['token_burn_retired']) == 1
    late_after = ledger_digest(late_db)
    run('repeat-late-receipt', configuration('late-repeat', database=late_db))
    assert ledger_digest(late_db) == late_after and len(sends) == before
    wait('missed.json')
    wait('close-ready.json')
    state['file'] = 'missed.json'
    missed_db = private / 'missed.db'
    missed_key = private / 'missed-key'
    missed_key.mkdir(mode=448)
    state['db'] = missed_db
    missed = run('missed-next-window', configuration('missed', database=missed_db, directory=missed_key))
    assert len(table_rows(missed_db)['token_burn_missed']) >= 1
    state['file'] = 'close-ready.json'
    state['ack'] = False
    before = len(sends)
    close = run('canonical-close', configuration('close', database=missed_db, directory=missed_key))
    assert close['kind'] == 13 and close['status'] == 'pending:unknown' and (len(sends) == before + 1)
    atomic('close.packet.base64', sends[-1]['wire_base64'])
    wait('closed.json')
    state['file'] = 'closed.json'
    before = len(sends)
    closed = run('restart-closed', configuration('closed', database=missed_db, directory=missed_key))
    assert closed['status'] == 'complete:carry' and len(sends) == before
    assert len(table_rows(missed_db)['token_burn_missed']) == 24
    assert not problems, problems
    assert len({request['origin_port'] for request in requests}) == 3
    for name in ['initial.json', 'expired.json', 'executed.json', 'executed-later.json', 'missed.json', 'close-ready.json', 'closed.json', 'old-refusal.json', 'replacement-result.json']:
        shutil.copy2(hook / name, out / name)
    record = {'schema_version': 1, 'exit_code': 0, 'seconds': round(time.monotonic() - started, 3), 'binary_sha256': sha(binary), 'compiler_sha256': build['compiler_sha256'], 'runtime_sha256': build['runtime_sha256'], 'build_source_manifest_sha256': build['source_manifest_sha256'], 'runs': runs, 'requests': len(requests), 'submissions': len(sends), 'replacement_workers': 4, 'legacy_still_valid_refused': True, 'retired_packets': 1, 'missed_windows': 24, 'late_receipt_journal_changed_before_any_send': True, 'private_test_workspace': str(private), 'scope': ['Owned loopback RPC and controlled LiteSVM height/time, not a production ledger-finality proof or independent operators.', 'Actual Mesh opaque signing, encrypted durable journal before RPC, exact packet retry, CAS replacement, and genuine SBF execution.', 'No live funds, deployment, provider RPC, service registration or native devices.']}
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'runs'}), flush=True)
except Exception:
    atomic('abort', 'driver failure; see sanitized test logs')
    raise
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    (out / 'requests.json').write_text(json.dumps(requests, indent=2) + '\n')
    (out / 'submissions.json').write_text(json.dumps(sends, indent=2) + '\n')
    (out / 'problems.json').write_text(json.dumps(problems, indent=2) + '\n')
    (out / 'runs.json').write_text(json.dumps(runs, indent=2) + '\n')
