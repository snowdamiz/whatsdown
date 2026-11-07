#!/usr/bin/env python3
"""Local compiled bounty proof. No external RPC, accounts, keys, or funding."""
import argparse
import base64
import copy
import importlib.util
import inspect
import json
import os
from pathlib import Path
import select
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRODUCT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('phone_proof', PRODUCT / 'scripts/prove-phone-filing-mpr2.py')
phone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phone)


def snapshots(directory):
    pins = json.loads((directory / 'pins-winner-a.json').read_text())
    bank_input = json.loads((directory / 'bank-input-winner-a.json').read_text())
    prepared, settled = copy.deepcopy(bank_input['fixture']), copy.deepcopy(bank_input['fixture'])
    prepared['accounts']['economics'] = bank_input['fixture']['accounts']['economics']
    for stage, meta in [('prepared', prepared), ('settled', settled)]:
        request = json.loads((directory / f'phone-{stage}.raw.request.json').read_text())
        reply = json.loads((directory / f'phone-{stage}.raw.response.json').read_text())
        keys, values = request['params'][0], reply['result']['value']
        for name, index in [('proof', 3), ('log', 2)]:
            meta['accounts'][name] = dict(values[index], address=keys[index], data_hex=base64.b64decode(values[index]['data'][0]).hex())
        meta.update(payer=pins['governance'], token_program=pins['token'], rewards_program=pins['rewards'])
    return prepared, settled, (directory / 'evidence-winner-a.frk').read_bytes()


def packed(*parts):
    return len(parts).to_bytes(4, 'big') + phone.vectors(*parts)


def unpack(data):
    count, data = int.from_bytes(data[:4], 'big'), data[4:]
    parts = []
    for _ in range(count):
        size = int.from_bytes(data[:4], 'big')
        assert len(data) >= size + 4
        parts.append(data[4:4+size])
        data = data[4+size:]
    assert not data
    return parts


class LiveBank:
    """TLS-only native RPC adapter to the actual disposable SBF bank."""
    def __init__(self, root, sdk, retained):
        self.root, self.calls, self.errors, self.servers = root, [], [], []
        self.signs, self.sends, self.before_send = [], [], None
        self.drop_ack, self.reject_source, self.stale = False, None, False
        self.hash_override, self.history_mode = None, None
        self.barrier_method = None
        self.entered, self.release = threading.Event(), threading.Event()
        self.release.set()
        self.wallet = json.loads(subprocess.check_output([str(sdk)], input=b'{"bounty_count":4}'))
        capture = root / 'capture'
        capture.mkdir()
        repository = retained.parents[2]
        env = dict(os.environ,
            BOUNTY_RELAY_TEST_SOURCE=str(repository / 'mesh-private-messenger/ops/relay/mpr2-sbf.test.mjs'),
            MORSE_MPR2_RELAY_PROOF_OUTPUT=str(capture),
            MORSE_TOKEN_CUSTODY_FIXTURES_PATH='/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/token-custody-fixtures.json',
            MORSE_MPR2_RELAY_VECTORS_PATH='/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/collateral-v2-operator/sdk-vector-subset-final3.json',
            MORSE_MPR2_RELAY_BINARY=str(retained / 'relay-mpr2'),
            MORSE_MPR2_RELAY_SBF_BRIDGE=str(retained.parent / 'mpr2_relay_bridge'),
            BOUNTY_FIXTURE_FINDER=self.wallet['bounties'][3]['address_hex'],
            BOUNTY_FIXTURE_WALLET=json.dumps(self.wallet))
        sbf = Path('/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-63282176/.morse/grace-assessment/sbf')
        for role in ('JUDGE', 'TOKEN', 'REWARDS'):
            env['MORSE_' + role + '_SBF_PATH'] = str(sbf / ('morse_' + role.lower() + '.so'))
        self.log = (root / 'bank-stderr.log').open('w')
        self.process = subprocess.Popen(['node', str(PRODUCT / 'tests/bounty-mixed-native/bank.mjs')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, env=env)
        self.ready = self.line(60)
        (root / 'bank-ready.json').write_text(json.dumps(self.ready, indent=2) + '\n')
        self.fixture = self.ready['fixture']
        self.wire = bytes.fromhex(self.ready['wire_hex'])
        def openssl(*args):
            subprocess.run(['openssl', *map(str, args)], capture_output=True, check=True)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=Bounty local CA')
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',root/'leaf.key','-out',root/'leaf.csr','-subj','/CN=127.0.0.1')
        (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in',root/'leaf.csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-CAcreateserial','-out',root/'leaf.pem','-days','1','-extfile',root/'ext')
        self.pem = (root/'ca.pem').read_bytes()
        bank = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                try:
                    raw = self.rfile.read(int(self.headers['Content-Length']))
                    request = json.loads(raw)
                    assert not any(self.headers.get(x) for x in ('Authorization','Cookie','X-Account-ID','X-Device-ID'))
                    bank.calls.append({'peer':self.server.index,'request':request,'sha256':phone.sha(raw)})
                    if request['method'] == 'sendTransaction':
                        wire = base64.b64decode(request['params'][0])
                        assert bank.before_send, 'send lacks durable-packet check'
                        bank.before_send(wire)
                        bank.sends.append(phone.sha(wire))
                    endpoint = bank.ready['endpoints'][self.server.index]
                    response = urllib.request.urlopen(urllib.request.Request(endpoint, raw, {'Content-Type':'application/json'}), timeout=25).read()
                    if request['method']==bank.barrier_method:
                        bank.entered.set()
                        assert bank.release.wait(15), 'RPC response barrier timed out'
                    body = json.loads(response)
                    if request['method']=='getLatestBlockhash' and bank.hash_override:
                        body['result']['value']['blockhash']=bank.hash_override
                    if request['method']=='getTransaction' and bank.history_mode:
                        if self.server.index==2:body['result']=None
                        elif self.server.index==1 and body['result']:
                            if bank.history_mode=='delta':body['result']['meta']['postTokenBalances'][0]['uiTokenAmount']['amount']='0'
                            elif bank.history_mode=='wire':
                                bad=bytearray(base64.b64decode(body['result']['transaction'][0]));bad[-1]^=1
                                body['result']['transaction'][0]=base64.b64encode(bad).decode()
                            elif bank.history_mode=='mint':body['result']['meta']['postTokenBalances'][0]['mint']=phone.b58(bytes([23])*32)
                    if request['method']=='getMultipleAccounts' and len(request['params'][0])==2 and bank.reject_source:
                        data = bytearray(base64.b64decode(body['result']['value'][1]['data'][0]))
                        if bank.reject_source=='frozen': data[108]=2
                        elif bank.reject_source=='insufficient': data[64:72]=b'\0'*8
                        elif bank.reject_source=='delegated': data[72:76]=(1).to_bytes(4,'little');data[76:108]=bytes([33])*32
                        body['result']['value'][1]['data'][0]=base64.b64encode(data).decode()
                    if bank.stale and request['method']=='getMultipleAccounts':body['result']['context']['slot']=1
                    response=json.dumps(body).encode()
                    if request['method']=='sendTransaction' and bank.drop_ack:
                        self.connection.close()
                        return
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(response)))
                    self.end_headers();self.wfile.write(response)
                except Exception as error:
                    bank.errors.append(repr(error))
                    self.send_response(500);self.end_headers()
        for index in range(3):
            server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
            server.index=index
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'leaf.pem',root/'leaf.key')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            self.servers.append(server)
        self.origins=[f'https://127.0.0.1:{server.server_port}' for server in self.servers]

    def line(self, timeout=30):
        assert select.select([self.process.stdout],[],[],timeout)[0], 'bank helper timed out'
        line=self.process.stdout.readline()
        assert line, 'bank exited; see '+str(self.root/'bank-stderr.log')
        return json.loads(line)

    def ask(self, method, **kwargs):
        self.process.stdin.write(json.dumps(dict(method=method,**kwargs))+'\n');self.process.stdin.flush()
        return self.line(60 if method=='settle' else 30)

    def close(self):
        self.release.set()
        for server in self.servers:server.shutdown();server.server_close()
        if self.process.poll() is None:
            self.process.stdin.write('{"method":"stop"}\n');self.process.stdin.flush()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=5)
        self.log.close()


def verify_capture(directory):
    report = json.loads((directory / 'qualification.json').read_text())
    assert report['verdict'] == 'PASS' and not report['source_drift'] and not report['artifact_drift']
    for path, expected in report['artifacts'].items():
        assert phone.sha(Path(path).read_bytes()) == expected, path
    return {'qualification_sha256': phone.sha((directory / 'qualification.json').read_bytes()),
            'head': report['head_start'], 'tree': report['tree']}


def output_parts(data):
    rows=[]
    while data:
        size=int.from_bytes(data[:4],'big');rows.append(data[4:4+size]);data=data[4+size:]
    assert int.from_bytes(rows[0],'big')==len(rows)-1
    return rows[1:]


def invoke_result(native, symbol, value):
    native.process.stdin.write(json.dumps({'symbol':symbol,'hex':value.hex()})+'\n');native.process.stdin.flush()
    result=native.line();assert not result['host_errors'],result
    raw=bytes.fromhex(result['hex'])
    return {'error':raw.decode()} if result['code'] else raw


def batch_worker(library_path, root):
    # Preserve the existing embedding host, adding concurrent calls inside its
    # one runtime process. Platform nonce reservation is process-scoped.
    source=inspect.getsource(phone.worker).split('    for line in sys.stdin:')[0]
    source=source.replace('def worker(', 'def run_batch_worker(', 1)
    source+='''    def call(request, gate=None):
        if gate: gate.wait(timeout=5)
        function=getattr(library,request['symbol'])
        function.argtypes=[c.c_void_p,c.c_uint64,c.POINTER(Returned)]
        value,output=bytes.fromhex(request['hex']),Returned()
        code=function(value,len(value),c.byref(output))
        try: raw=c.string_at(output.data,output.len)
        finally: library.mesh_library_free_returned_bytes(c.byref(output))
        return {'code':code,'hex':raw.hex(),'host_errors':errors}
    from concurrent.futures import ThreadPoolExecutor
    for line in sys.stdin:
        requests=json.loads(line)['batch']
        gate=threading.Barrier(len(requests))
        with ThreadPoolExecutor(max_workers=len(requests)) as pool:
            futures=[pool.submit(call,request,gate) for request in requests]
            print(json.dumps([future.result() for future in futures]),flush=True)
    assert library.mesh_library_shutdown()==0
'''
    namespace=dict(phone.__dict__)
    exec(compile(source,'retained-phone-host-with-concurrent-calls','exec'),namespace)
    namespace['run_batch_worker'](library_path,root)


def concurrent_native(library, root, requests):
    process=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--batch-worker',str(library.resolve()),str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert select.select([process.stdout],[],[],10)[0]
        assert json.loads(process.stdout.readline())=={'ready':True}
        process.stdin.write(json.dumps({'batch':[{'symbol':symbol,'hex':value.hex()} for symbol,value in requests]})+'\n');process.stdin.flush()
        assert select.select([process.stdout],[],[],30)[0], 'concurrent native calls timed out'
        outcomes=json.loads(process.stdout.readline())
        with (root/'concurrent-native-results.jsonl').open('a') as log:
            log.write(json.dumps(outcomes)+'\n')
        result=[]
        for value in outcomes:
            assert not value['host_errors'],value
            raw=bytes.fromhex(value['hex'])
            if value['code']==3:
                assert not raw
                result.append({'error':'native_busy','abi_code':3})
            else:result.append({'error':raw.decode()} if value['code'] else raw)
        return result
    finally:
        process.stdin.close()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        assert process.returncode==0,process.returncode


def zeros(args):
    root=args.out.resolve();results=[]
    for name in ('usdc-zero','morse-zero','both-zero'):
        capture=args.zero_captures/name
        for phase in ('prepared','settled'):
            manifest=json.loads((capture/f'phone-{phase}.json').read_text())
            for path,expected in manifest['artifacts'].items():assert phone.sha(Path(path).read_bytes())==expected,path
        prepared,settled,wire=snapshots(capture)
        work=root/name;work.mkdir()
        raw=work/'raw';raw.mkdir()
        for phase in ('prepared','settled','legacy'):
            for kind in ('request','response'):
                source=(args.snapshots if phase=='legacy' else capture)/f'phone-{phase}.raw.{kind}.json'
                (raw/source.name).write_bytes(source.read_bytes())
        with tempfile.TemporaryDirectory(prefix='bounty-zero-tls-') as temporary:
            bank=phone.Bank(Path(temporary),prepared,settled,wire,raw);native=None
            try:
                phone.resources(work,bank,prepared,wire)
                native=phone.Native(args.library.resolve(),work,dict(os.environ))
                path=work/'zero.db';Path(str(path)+'.wire').write_text(wire.hex())
                native.invoke('mesh_messenger_create_account',phone.vectors(str(path).encode(),name.encode()))
                assert native.invoke('bounty_fixture_seed_selected',str(path).encode())==wire
                def prep(asset):return invoke_result(native,'mesh_messenger_bounty_transfer_prepare',packed(bytes.fromhex('02424d52'),str(path).encode(),bytes([asset]),bytes([21])*32,bytes([22])*32))
                before=prep(1);assert isinstance(before,dict) and before['error']=='bounty_not_paid',before
                bank.mode='settled'
                receipt=bytes.fromhex(settled['accounts']['proof']['data_hex'])
                units=[int.from_bytes(receipt[280:288],'little'),int.from_bytes(receipt[304:312],'little')]
                for asset,amount in enumerate(units,1):
                    if amount:continue
                    result=prep(asset);assert isinstance(result,bytes),result
                    view=unpack(result);assert view[3]==b'\0' and not view[4] and not view[5],view
                    aggregate=unpack(view[7]);assert aggregate[1]==b'\2'
                    for sibling,quantity in enumerate(units,1):
                        leg=unpack(aggregate[3+sibling])
                        assert int.from_bytes(leg[4],'big')==quantity and leg[2]==bytes([1 if quantity==0 else 2]) and not leg[6],leg
                before=native.invoke('mesh_messenger_bounty_transfer_status',packed(bytes.fromhex('02424d52'),str(path).encode()))
                native.restart()
                assert native.invoke('mesh_messenger_bounty_transfer_status',packed(bytes.fromhex('02424d52'),str(path).encode()))==before
                assert not bank.controls and not bank.posts and not bank.errors
                results.append({'case':name,'status':'PASS','units':units,'prepared_not_zero':True,'explicit_zero_legs':True,'sdk_sign_calls':0,'sends':0,'restart_exact':True,'receipt_sha256':phone.sha(receipt),'rpc_requests':bank.requests})
            finally:
                if native:native.close()
                bank.close()
    report={'status':'PASS_native_genuine_zero_receipts','library_sha256':phone.sha(args.library.read_bytes()),'cases':results}
    (root/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':[{'case':row['case'],'units':row['units']} for row in results]}))


def legacy(args):
    root=args.out.resolve();prepared,settled,wire=snapshots(args.snapshots)
    wallet=json.loads(subprocess.check_output([str(args.sdk.resolve())],input=b'{"bounty_count":4}'))
    wire=wire[:5]+bytes.fromhex(wallet['bounties'][3]['address_hex'])+wire[37:]
    evidence={'status':'FAIL_incomplete','old_library_sha256':phone.sha(args.legacy_library.read_bytes()),
              'new_library_sha256':phone.sha(args.library.read_bytes()),'sdk_sha256':phone.sha(args.sdk.read_bytes()),
              'scope':'old production BWJ1 state codec/controller plus actual SDK historical signature; no legacy paid-receipt admission claim'}
    with tempfile.TemporaryDirectory(prefix='bounty-legacy-tls-') as temporary:
        bank=phone.Bank(Path(temporary),prepared,settled,wire,args.snapshots);old=None;new=None
        try:
            bank.allow_legacy_bounty=True
            phone.resources(root,bank,prepared,wire)
            names=('security','network','ohttp','rpc-tls','counter','wallet')
            current={name:(root/name).read_bytes() for name in names}
            historical_mint=bytes([7])*32
            assert historical_mint!=phone.un58(prepared['accounts']['usdc']['address'])
            security=current['security'].replace(prepared['accounts']['usdc']['address'].encode(),phone.b58(historical_mint).encode())
            (root/'security').write_bytes(security)
            companion=current['ohttp'].decode().split('\n');companion[2]=phone.sha(security)
            (root/'ohttp').write_text('\n'.join(companion))
            (root/'rpc-tls').write_bytes(current['rpc-tls'][:2]+bytes.fromhex(phone.sha(security))+current['rpc-tls'][34:])
            (root/'counter').unlink()
            (root/'wallet').write_bytes(b'\1\1'+historical_mint)
            old=phone.Native(args.legacy_library.resolve(),root,dict(os.environ))
            path=root/'historical.db';Path(str(path)+'.wire').write_text(wire.hex())
            old.invoke('mesh_messenger_create_account',phone.vectors(str(path).encode(),b'historical'))
            assert old.invoke('phone_fixture_seed_selected',str(path).encode())==wire
            issued=int(time.time());payer=bytes.fromhex(wallet['address_hex'])
            intent=b'\1BWT'+(3).to_bytes(8,'big')+wire[5:37]+bytes([21])*32+historical_mint+(7).to_bytes(8,'big')+bytes([8])*32+issued.to_bytes(8,'big')+(issued+300).to_bytes(8,'big')+b'\1\6'
            assert len(intent)==166
            Path(str(path)+'.intent').write_text(intent.hex());Path(str(path)+'.payer').write_text(payer.hex())
            prepared_old=output_parts(old.invoke('bounty_fixture_prepare_legacy',str(path).encode()))
            identity=prepared_old[0];assert prepared_old[1]==intent
            signed=json.loads(subprocess.check_output([str(args.sdk.resolve())],input=json.dumps({'bounty_count':4,'usdc_mint_hex':historical_mint.hex(),'bounty_transfer_hex':intent.hex()}).encode()))
            packet=bytes.fromhex(signed['wire_hex']);Path(str(path)+'.packet').write_text(packet.hex())
            committed=output_parts(old.invoke('bounty_fixture_commit_legacy',str(path).encode()))
            assert committed[:3]==[identity,intent,packet] and committed[3]==packet[1:65]
            before=output_parts(old.invoke('bounty_fixture_old_capture',str(path).encode()))
            Path(str(path)+'.old').write_text(before[0].hex());Path(str(path)+'.guard').write_text(before[1].hex())
            old.close();old=None
            replacement=current['ohttp'].decode().split('\n');replacement[3]='2'
            current['ohttp']='\n'.join(replacement).encode()
            for name,content in current.items():(root/name).write_bytes(content)
            new=phone.Native(args.library.resolve(),root,dict(os.environ))
            request=packed(bytes.fromhex('02424d52'),str(path).encode(),b'\0',identity)
            value=new.invoke('mesh_messenger_bounty_transfer_recover',request)
            assert unpack(value)[1]==b'\1'
            retained=output_parts(new.invoke('bounty_fixture_journal',packed(str(path).encode(),b'\0')))
            assert retained[0]==b'2' and retained[1]==identity and retained[2]==intent and retained[3]==packet and retained[4]==committed[3]
            new.restart();assert new.invoke('mesh_messenger_bounty_transfer_recover',request)==value
            assert output_parts(new.invoke('bounty_fixture_journal',packed(str(path).encode(),b'\0')))==retained
            old=phone.Native(args.legacy_library.resolve(),root,dict(os.environ))
            marker=output_parts(old.invoke('bounty_fixture_old_capture',str(path).encode()))
            assert marker[0]!=before[0] and marker[1]==before[1]
            stale=old.invoke('bounty_fixture_old_write',str(path).encode(),rejected=True)
            assert stale=='local_state_changed',stale
            assert output_parts(old.invoke('bounty_fixture_old_capture',str(path).encode()))==marker
            old_decode=old.invoke('mesh_messenger_bounty_transfer_status',str(path).encode(),rejected=True)
            assert old_decode
            assert all(call['method']=='getTransaction' for call in bank.controls) and not bank.posts and not bank.errors
            evidence.update(status='PASS_actual_old_BWJ1_SDK_pin_rotation_migration',identity=identity.hex(),old_mint=historical_mint.hex(),new_usdc=current['wallet'][2:].hex(),
                intent_sha256=phone.sha(intent),wire_sha256=phone.sha(packet),signature=phone.b58(committed[3]),old_ciphertext_sha256=phone.sha(before[0]),marker_ciphertext_sha256=phone.sha(marker[0]),
                stale_old_binary_writer=stale,restarted_old_binary_marker_error=old_decode,sdk_sign_calls=1,recovery_sdk_calls=0,sends=0,
                authorization_text=signed['authorization_text'],exact_restart=True)
            print(json.dumps({'status':evidence['status'],'stale_old_binary_writer':stale,'sends':0,'recovery_sdk_calls':0}))
        finally:
            if old:old.close()
            if new:new.close()
            bank.close();evidence['control_requests']=bank.controls;evidence['server_errors']=bank.errors
            (root/'result.json').write_text(json.dumps(evidence,indent=2)+'\n')


def green(args):
    root=args.out.resolve()
    (root/'driver.py').write_bytes(Path(__file__).read_bytes())
    (root/'bank-source.mjs').write_bytes((PRODUCT/'tests/bounty-mixed-native/bank.mjs').read_bytes())
    evidence={'status':'FAIL_incomplete','library_sha256':phone.sha(args.library.read_bytes()),
              'sdk_sha256':phone.sha(args.sdk.read_bytes()),'cases':[],
              'driver_sha256':phone.sha((root/'driver.py').read_bytes()),
              'bank_source_sha256':phone.sha((root/'bank-source.mjs').read_bytes()),
              'limits':['Local disposable bank; three loopback origins are not independent providers or validator finality.',
                        'Native embedding uses test platform storage/resources. Private iOS/Android/desktop owner leases are not exercised.']}
    bank=LiveBank(root,args.sdk.resolve(),args.snapshots.resolve())
    native=None
    try:
        phone.resources(root,bank,bank.fixture,bank.wire)
        native=phone.Native(args.library.resolve(),root,dict(os.environ))
        def seed(name,wire=bank.wire):
            path=root/(name+'.db')
            Path(str(path)+'.wire').write_text(wire.hex())
            native.invoke('mesh_messenger_create_account',phone.vectors(str(path).encode(),name.encode()))
            assert native.invoke('bounty_fixture_seed_selected',str(path).encode())==wire
            return path
        path=seed('mixed')
        payer=bytes.fromhex(bank.wallet['address_hex']);destination=bytes([21])*32
        tag=bytes.fromhex('02424d52')
        def request(symbol,*parts,path=path):
            return invoke_result(native,'mesh_messenger_bounty_transfer_'+symbol,packed(tag,str(path).encode(),*parts))
        def prepare(asset,dest=destination,path=path):
            return request('prepare',bytes([asset]),dest,payer,path=path)
        def aggregate():
            value=request('status');assert isinstance(value,bytes),value
            parts=unpack(value);assert parts[0]==bytes.fromhex('02424d57') and len(parts)==6,parts
            return parts
        def status(asset):
            parts=unpack(aggregate()[3+asset]);assert parts[0]==bytes.fromhex('02424d4c'),parts
            return None if not parts[6] else unpack(parts[6])[2][0]
        def journal(asset):
            raw=native.invoke('bounty_fixture_journal',packed(str(path).encode(),bytes([asset])))
            return output_parts(raw)
        def require_prepared(value,asset):
            assert isinstance(value,bytes),value
            rows=unpack(value)
            assert len(rows)==8 and rows[0]==bytes.fromhex('02424d50') and rows[1]==bytes([asset]),rows
            assert rows[3]==b'\1' and len(rows[4])==166 and len(rows[2])==32,rows
            return rows
        def sign(rows):
            before=len(bank.sends)
            signed=json.loads(subprocess.check_output([str(args.sdk.resolve())],input=json.dumps({'bounty_count':4,'usdc_mint_hex':phone.un58(bank.fixture['accounts']['usdc']['address']).hex(),'bounty_transfer_hex':rows[4].hex()}).encode()))
            packet=bytes.fromhex(signed['wire_hex'])
            assert before==len(bank.sends) and signed['authorization_text']
            bank.signs.append({'intent_sha256':phone.sha(rows[4]),'wire_sha256':phone.sha(packet),'authorization_text':signed['authorization_text']})
            return packet
        def action(symbol,asset,handle):
            saved=journal(asset)
            fields=[bytes([asset]),saved[1]]
            if symbol=='submit':fields.append(saved[4])
            value=request(symbol,*fields);assert isinstance(value,bytes),value
            return value
        before=prepare(1)
        if isinstance(before,dict):assert before['error']=='bounty_not_paid',before
        else:assert unpack(before)[3]==b'\0',unpack(before)
        assert not bank.sends and not bank.signs
        evidence['cases'].append('actual prepared SBF MPR2 cannot prompt or send')
        bank.ask('settle')
        receipt=base64.b64decode(json.loads((root/'capture/phone-settled.raw.response.json').read_text())['result']['value'][3]['data'][0])
        amounts=[int.from_bytes(receipt[280:288],'little'),int.from_bytes(receipt[304:312],'little')]
        assert all(amounts) and amounts[0]!=amounts[1],amounts
        evidence['entitlements']=amounts
        alternate=seed('another-finder',bank.wire[:5]+bytes([7])*32+bank.wire[37:])
        elsewhere=prepare(1,path=alternate)
        if isinstance(elsewhere,dict):assert elsewhere['error']=='bounty_paid_elsewhere',elsewhere
        else:assert unpack(elsewhere)[3]==b'\0'
        assert not bank.signs and not bank.sends
        evidence['cases'].append('actual winning SBF finder refuses another selected reservation')
        retired_accounts=[value['address'] for role,value in bank.fixture['accounts'].items()
            if role in ('economics','oracle') or bytes.fromhex(value.get('data_hex',''))[:3] in (b'MBD',b'MBP')]
        bank.ask('remove_accounts',addresses=retired_accounts)
        evidence['retired_economic_accounts']=retired_accounts
        evidence['cases'].append('actual post-settlement economic/oracle/bond/pending accounts removed from bank before fresh receipt admission; immutable receipt still authorizes its exact finder amounts')
        contender=seed('competing-destinations')
        outcomes=concurrent_native(args.library,root,[('mesh_messenger_bounty_transfer_prepare',packed(tag,str(contender).encode(),b'\1',bytes([byte])*32,payer)) for byte in (21,31)])
        assert len(outcomes)==2,outcomes
        winner=output_parts(native.invoke('bounty_fixture_journal',packed(str(contender).encode(),b'\1')))
        accepted=[unpack(value) for value in outcomes if isinstance(value,bytes)]
        assert accepted and winner[0]==b'1'
        for value in accepted:
            if value[3]==b'\1':assert value[4]==winner[2]
        for value in outcomes:
            if isinstance(value,dict):assert value['error'] in ('native_busy','database is locked','local_state_changed','account_state_changed','bounty_transfer_destination_changed'),value
        assert not bank.signs and not bank.sends
        evidence['concurrent_destinations']={'callers':2,'accepted':len(accepted),'winning_intent_sha256':phone.sha(winner[2]),'errors':[value for value in outcomes if isinstance(value,dict)]}
        evidence['cases'].append('two concurrent actual native calls in one runtime race distinct destinations behind a barrier; only stored winning packet may be presented for SDK signing')
        retired=seed('resource-replacement')
        bank.entered.clear();bank.release.clear();bank.barrier_method='getMultipleAccounts';held=[]
        def held_prepare():
            try:held.append(prepare(1,path=retired))
            except Exception as error:held.append({'exception':repr(error)})
        thread=threading.Thread(target=held_prepare);thread.start()
        security=(root/'security').read_bytes()
        try:
            assert bank.entered.wait(5), 'production receipt read did not reach barrier'
            (root/'security').write_bytes(security+b'\n')
            bank.release.set();thread.join(15)
            assert not thread.is_alive() and len(held)==1 and isinstance(held[0],dict),held
            assert 'error' in held[0],held
        finally:
            (root/'security').write_bytes(security);bank.release.set();bank.barrier_method=None
        absent=request('status',path=retired)
        assert isinstance(absent,bytes) and unpack(absent)[1]==b'\0' and not bank.signs and not bank.sends
        evidence['resource_replacement_error']=held[0]['error']
        evidence['cases'].append('real receipt RPC barrier plus captured native security-frame replacement rejects before immutable root/journal admission; separate from private-owner leases')
        first_asset,second_asset=args.first_asset,3-args.first_asset
        usdc=require_prepared(prepare(first_asset),first_asset)
        assert int.from_bytes(usdc[4][108:116],'big')==amounts[first_asset-1]
        ag=aggregate();assert ag[1]==b'\2'
        assert int.from_bytes(unpack(ag[4])[4],'big')==amounts[0] and int.from_bytes(unpack(ag[5])[4],'big')==amounts[1]
        native.restart();assert journal(first_asset)[0]==b'1'
        assert not bank.signs and not bank.sends
        evidence['cases'].append('independent unequal exact entitlements; unsigned prepare survives host restart without SDK/send')
        old_journal=journal(first_asset)
        untagged=invoke_result(native,'mesh_messenger_bounty_transfer_cancel',packed(str(path).encode(),old_journal[1]))
        assert isinstance(untagged,dict) and journal(first_asset)==old_journal,untagged
        extra=invoke_result(native,'mesh_messenger_bounty_transfer_prepare',packed(tag,str(path).encode(),bytes([first_asset]),destination,payer,b'economic-extra'))
        assert isinstance(extra,dict) and not bank.sends and not bank.signs,extra
        assert isinstance(prepare(3),dict)
        evidence['cases'].append('closed selector and exact field count; untagged legacy cancellation cannot mutate a mixed leg')
        packet=sign(usdc)
        outcomes=concurrent_native(args.library,root,[('mesh_messenger_bounty_transfer_commit',packed(tag,str(path).encode(),bytes([first_asset]),usdc[2],packet)) for _ in range(2)])
        assert len(outcomes)==2,outcomes
        assert any(isinstance(value,bytes) for value in outcomes),outcomes
        for value in outcomes:
            if isinstance(value,dict):assert value['error'] in ('native_busy','database is locked','local_state_changed','account_state_changed'),value
        evidence['concurrent_commits']={'callers':2,'accepted':sum(isinstance(value,bytes) for value in outcomes),'errors':[value for value in outcomes if isinstance(value,dict)]}
        native.restart();durable=journal(first_asset);assert durable[0]==b'2' and durable[3]==packet
        def durable_before_send(wire):
            observer=phone.Native(args.library.resolve(),root,dict(os.environ))
            try:
                rows=output_parts(observer.invoke('bounty_fixture_journal',packed(str(path).encode(),bytes([first_asset]))))
                if rows[3]!=wire:
                    rows=output_parts(observer.invoke('bounty_fixture_journal',packed(str(path).encode(),bytes([second_asset]))))
                assert rows[3]==wire and rows[4]==wire[1:65],rows
            finally:observer.close()
        bank.before_send=durable_before_send
        bank.ask('controls',value={'hideHistory':True});bank.drop_ack=True
        action('submit',first_asset,usdc[2]);assert status(first_asset)==2 and bank.sends
        sends=len(bank.sends);native.restart();action('recover',first_asset,usdc[2]);assert status(first_asset)==2 and len(bank.sends)==sends
        assert len(bank.signs)==1 and journal(first_asset)[3]==packet
        expired=int.from_bytes(usdc[4][156:164],'big')+1
        observed=native.invoke('bounty_fixture_submit_time',packed(str(path).encode(),bytes([first_asset]),str(expired).encode()))
        assert observed==b'2' and len(bank.sends)==sends and journal(first_asset)[3]==packet
        evidence['cases'].append('SDK exact166 intent; cryptographic commit; independent fresh process authenticates packet before every send; executed/lostack/restart keeps unknown exact packet without re-sign/send')
        evidence['cases'].append('injected post-expiry clock preserves unknown exact signature and refuses another broadcast')
        bank.ask('controls',value={'hideHistory':False})
        for mode in ('delta','wire','mint'):
            bank.history_mode=mode
            refused=request('recover',bytes([first_asset]),journal(first_asset)[1])
            assert isinstance(refused,dict) and status(first_asset)==2 and journal(first_asset)[3]==packet,refused
            assert len(bank.signs)==1 and len(bank.sends)==sends
        bank.history_mode=None
        bank.ask('controls',value={'hideHistory':True})
        evidence['cases'].append('one exact result plus mismatched token delta/wire/mint and null third peer cannot settle or replace packet')
        bank.stale=True
        stale=prepare(second_asset)
        assert isinstance(stale,dict) and status(first_asset)==2 and len(bank.sends)==sends,stale
        bank.stale=False
        for mode in ('insufficient','frozen','delegated'):
            bank.reject_source=mode;blocked=prepare(second_asset)
            if isinstance(blocked,dict):assert blocked['error']=='bounty_transfer_asset_unavailable',blocked
            else:assert unpack(blocked)[3]==b'\0'
            assert status(first_asset)==2 and len(bank.signs)==1 and len(bank.sends)==sends
        bank.reject_source=None
        morse=require_prepared(prepare(second_asset),second_asset)
        assert int.from_bytes(morse[4][108:116],'big')==amounts[second_asset-1] and morse[4][76:108]!=usdc[4][76:108]
        assert journal(first_asset)[3]==packet
        second=sign(morse);committed=request('commit',bytes([second_asset]),morse[2],second);assert isinstance(committed,bytes),committed
        native.restart();assert journal(first_asset)[3]==packet and journal(second_asset)[3]==second
        bank.ask('controls',value={'hideHistory':False});bank.drop_ack=False
        bank.entered.clear();bank.release.clear();bank.barrier_method='getTransaction';held=[]
        def held_recovery():
            try:held.append(request('recover',bytes([first_asset]),journal(first_asset)[1]))
            except Exception as error:held.append({'exception':repr(error)})
        thread=threading.Thread(target=held_recovery);thread.start()
        wallet=(root/'wallet').read_bytes()
        try:
            assert bank.entered.wait(5), 'actual transaction outcome did not reach response barrier'
            (root/'wallet').write_bytes(wallet[:2]+bytes([24])*32)
            bank.release.set();thread.join(15)
            assert not thread.is_alive() and len(held)==1 and isinstance(held[0],dict) and 'error' in held[0],held
        finally:bank.release.set();bank.barrier_method=None
        assert status(first_asset)==2 and journal(first_asset)[3]==packet
        native.restart()
        action('recover',first_asset,usdc[2]);assert status(first_asset)==4
        (root/'wallet').write_bytes(wallet);native.restart()
        evidence['wallet_replacement_error']=held[0]['error']
        evidence['cases'].append('actual outcome-response barrier plus same-purpose/new-USDC wallet frame retires in-flight recovery; next invocation recaptures new frame and settles exact historical old-mint packet without SDK/send')
        first_done=journal(first_asset)
        source=phone.pda('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',morse[4][12:44],phone.un58('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),morse[4][76:108])
        source_account=bank.ask('account',address=source)
        bank.ask('remove_accounts',addresses=[source])
        action('submit',second_asset,morse[2]);action('recover',second_asset,morse[2]);assert status(second_asset)==5
        failed=journal(second_asset);assert failed[3]==second and failed[8] and journal(first_asset)==first_done
        native.restart();assert journal(second_asset)==failed
        bank.ask('restore_source',address=source,account=source_account)
        bank.hash_override=phone.b58(morse[4][116:148])
        same_hash=prepare(second_asset)
        assert isinstance(same_hash,dict) and journal(second_asset)==failed and len(bank.signs)==2,same_hash
        bank.hash_override=None
        retry=require_prepared(prepare(second_asset),second_asset)
        assert retry[4][116:148]!=morse[4][116:148]
        archive=output_parts(native.invoke('bounty_fixture_history',packed(str(path).encode(),bytes([second_asset]),failed[4])))
        assert failed[3] in archive[1] and failed[4] not in archive[0]
        evidence['archive']={'ciphertext_sha256':phone.sha(archive[0]),'plaintext_sha256':phone.sha(archive[1]),'old_wire_retained':True}
        third=sign(retry);assert third!=second
        committed=request('commit',bytes([second_asset]),retry[2],third);assert isinstance(committed,bytes),committed
        native.restart();assert journal(first_asset)==first_done and journal(second_asset)[3]==third
        action('submit',second_asset,retry[2]);action('recover',second_asset,retry[2]);assert status(second_asset)==4
        evidence['failed_attempt']={'wire_sha256':phone.sha(second),'signature':phone.b58(failed[4]),'fee':failed[5].decode(),'execution_error':failed[8].decode()}
        evidence['cases'].append('actual SBF finalized failure in sibling preserves completed first leg; restart retains fee/wire; same old hash refused; new eligible hash gets explicit new SDK prompt and successful retry')
        evidence['cases'].append('unknown first leg survives independently blocked sibling; exact distinct packets execute through real SPL/ATA and finalize by actual token deltas')
        terminal=[journal(1),journal(2)];counts=(len(bank.signs),len(bank.sends),len(bank.calls))
        native.restart()
        for asset,old in [(first_asset,usdc),(second_asset,retry)]:
            result=prepare(asset,bytes([31])*32)
            assert isinstance(result,bytes) and unpack(result)[3]==b'\0',result
            action('recover',asset,old[2]);assert journal(asset)==terminal[asset-1]
        assert counts==(len(bank.signs),len(bank.sends),len(bank.calls)),(counts,len(bank.calls))
        assert not bank.errors,bank.errors
        evidence['cases'].append('two finalized legs survive restart and changed destination; no new signing, send, RPC or entitlement')
        evidence['final_journals']=[{'status':row[0].decode(),'identity':row[1].hex(),'intent_sha256':phone.sha(row[2]),'wire_sha256':phone.sha(row[3]),'signature':phone.b58(row[4]),'fee':row[5].decode(),'slot':row[7].decode()} for row in terminal]
        evidence['status']='PASS_native_mixed_SDK_SBF'
        print(json.dumps({'status':evidence['status'],'entitlements':amounts,'cases':evidence['cases']}))
    finally:
        if native:native.close()
        evidence.update(calls=bank.calls,sends=bank.sends,sdk_signs=bank.signs,server_errors=bank.errors)
        try:evidence['bank']=bank.ask('report')
        except Exception as error:evidence['bank_report_error']=repr(error)
        bank.close()
        (root/'result.json').write_text(json.dumps(evidence,indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--snapshots', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expect-old-red', action='store_true')
    parser.add_argument('--singleton-red', action='store_true')
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--first-asset', type=int, choices=(1,2), default=1)
    parser.add_argument('--zero-captures', type=Path)
    parser.add_argument('--legacy-library', type=Path)
    args = parser.parse_args()
    if not (args.sdk or args.zero_captures or args.expect_old_red):
        parser.error('select --sdk, --zero-captures, or --expect-old-red')
    args.out.mkdir(parents=True, exist_ok=True)
    if args.zero_captures:return zeros(args)
    if args.legacy_library:return legacy(args)
    if args.sdk:
        return green(args)
    root = args.out.resolve()
    prepared, settled, wire = snapshots(args.snapshots)
    evidence = {'capture': verify_capture(args.snapshots), 'library_sha256': phone.sha(args.library.read_bytes()),
                'script_sha256': phone.sha(Path(__file__).read_bytes()), 'cases': [], 'sdk_sign_calls': 0}
    with tempfile.TemporaryDirectory(prefix='bounty-mixed-tls-') as temporary:
        bank = phone.Bank(Path(temporary), prepared, settled, wire, args.snapshots)
        native = None
        try:
            phone.resources(root, bank, prepared, wire)
            bank.allow_legacy_bounty = True
            bank.mode = 'settled'
            native = phone.Native(args.library.resolve(), root, dict(os.environ))
            path = root / 'mixed.db'
            Path(str(path) + '.wire').write_text(wire.hex())
            native.invoke('mesh_messenger_create_account', phone.vectors(str(path).encode(), b'mixed-proof'))
            retained = native.invoke('phone_fixture_seed_selected', str(path).encode())
            assert retained == wire
            receipt = bytes.fromhex(settled['accounts']['proof']['data_hex'])
            request = packed(str(path).encode(), bytes([21]) * 32, receipt[72:104])
            error = native.invoke('mesh_messenger_bounty_transfer_prepare', request, rejected=True)
            assert error in ('invalid_anchor_custody', 'invalid_slash_receipt', 'slash_receipt_identity_mismatch'), error
            assert len(bank.requests) >= 2 and all(len(r['keys']) == 3 for r in bank.requests)
            assert not bank.posts and not bank.errors
            assert all(row['method'] == 'getBlockHeight' for row in bank.controls)
            evidence.update(status='RED_actual_native_prepare_rejects_settled_MPR2', error=error,
                            sends=0, receipt_sha256=phone.sha(receipt), expected='independent USDC/MORSE preparation')
            if args.singleton_red:
                error = native.invoke('bounty_fixture_singleton_red', str(path).encode()).decode()
                assert error == 'bounty_transfer_identity_changed', error
                evidence['singleton'] = {'error': error, 'first_asset_preserved': True,
                                         'boundary': 'actual prepare_bounty_transfer/load_bounty_transfer encrypted SQLite'}
            print(json.dumps({'status': evidence['status'], 'error': evidence['error'], 'singleton':evidence.get('singleton'), 'sdk_sign_calls': 0, 'sends': 0}))
        finally:
            if native:
                native.close()
            bank.close()
            evidence['requests'], evidence['relay_posts'], evidence['control_requests'] = bank.requests, bank.posts, bank.controls
            evidence['server_errors'] = bank.errors
            evidence.setdefault('status', 'FAIL_incomplete')
            (root / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv)>1 and sys.argv[1]=='--batch-worker':batch_worker(*sys.argv[2:])
    else:main()
