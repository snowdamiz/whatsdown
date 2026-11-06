#!/usr/bin/env python3
"""Native filing proof against byte-exact local SBF accounts and owned TLS RPC.

No RPC callback grants authority: the production export and deterministic clock
fixture both capture native resources and use the production receipt reader.
Mutated accounts below are rejection tests, never evidence of settlement.
"""
import argparse
import base64
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRODUCT = Path(__file__).resolve().parents[1]
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b58(data):
    n, result = int.from_bytes(data, 'big'), ''
    while n:
        n, digit = divmod(n, 58)
        result = ALPHABET[digit] + result
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + result


def un58(text):
    n = 0
    for char in text:
        n = n * 58 + ALPHABET.index(char)
    return b'\0' * (len(text) - len(text.lstrip('1'))) + n.to_bytes((n.bit_length()+7)//8, 'big')


def on_curve(data):
    # Solana rejects decompressible Edwards points for PDAs.
    p = 2**255 - 19
    y = int.from_bytes(data, 'little') & (2**255-1)
    if y >= p:
        return False
    d = -121665 * pow(121666, p-2, p) % p
    xx = (y*y-1) * pow(d*y*y+1, p-2, p) % p
    return xx == 0 or pow(xx, (p-1)//2, p) == 1


def pda(program, *seeds):
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join(seeds)+bytes([bump])+un58(program)+b'ProgramDerivedAddress').digest()
        if not on_curve(raw):
            return b58(raw)
    raise AssertionError('no PDA')


def vectors(*items):
    return b''.join(len(x).to_bytes(4, 'big')+x for x in items)


def fields(data):
    # Output-list ABI is an outer vector containing a u32 count followed by
    # individually length-prefixed opaque byte vectors.
    result = []
    while data:
        assert len(data) >= 4
        size = int.from_bytes(data[:4], 'big')
        assert len(data) >= 4+size
        result.append(data[4:4+size])
        data = data[4+size:]
    assert result and len(result[0]) == 4
    assert int.from_bytes(result[0], 'big') == len(result)-1
    return [x.decode() for x in result[1:]]


def reconstruct(snapshot):
    """Reproduce support/token_fork.rs::prepare, checking retained SBF hash."""
    code = """const c=require('node:crypto'),q=JSON.parse(require('fs').readFileSync(0,'utf8'));
const k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,q.seed)]),format:'der',type:'pkcs8'});
console.log(JSON.stringify({public:c.createPublicKey(k).export({type:'spki',format:'der'}).subarray(-32).toString('hex'),signature:c.sign(null,Buffer.from(q.message,'hex'),k).toString('hex')}));"""
    def sign(seed, message):
        return json.loads(subprocess.run(['node', '-e', code], input=json.dumps({'seed':seed,'message':message.hex()}), text=True, capture_output=True, check=True).stdout)
    key = bytes.fromhex(sign(11, b'')['public'])
    cps, hashes = [], []
    for root, timestamp in [(3,int(snapshot['now'])*1000-1000),(4,int(snapshot['now'])*1000)]:
        statement = b'mesh-key-transparency-v1'+(1).to_bytes(2,'big')+(1).to_bytes(8,'big')*2+bytes([root])*32+b'\0'*32+timestamp.to_bytes(8,'big')+key
        signature = bytes.fromhex(sign(11, statement)['signature'])
        cps.append(b'\1KTK'+statement[26:]+signature)
        hashes.append(hashlib.sha256(b'mesh-msg/v1/transparency-checkpoint'+statement+signature).digest())
    receipt = bytes.fromhex(snapshot['accounts']['proof']['data_hex'])
    wire = b'\1FRK\1'+receipt[72:104]+key+cps[0]+b'\0'+cps[1]+b'\4'
    for checkpoint in hashes:
        for name, seed in [(b'outside',12),(b'token-outside',15)]:
            signature = bytes.fromhex(sign(seed,b'mesh-msg/v1/transparency-witness'+name+checkpoint)['signature'])
            wire += bytes([len(name)])+name+checkpoint+signature
    assert hashlib.sha256(wire[:5]+wire[37:]).digest() == receipt[40:72], 'reconstructed fork differs from actual SBF receipt'
    assert hashes[0] == receipt[200:232] and hashes[1] == receipt[232:264]
    return wire


class Returned(c.Structure):
    _fields_ = [('data', c.c_void_p), ('len', c.c_uint64)]


Callback = c.CFUNCTYPE(c.c_int32,c.c_void_p,c.c_void_p,c.c_uint64,c.c_void_p,c.c_uint64,c.POINTER(c.c_uint64))


class Callbacks(c.Structure):
    _fields_ = [('version',c.c_uint32),('size',c.c_uint32),('context',c.c_void_p),('calls',Callback*9)]


def worker(library_path, root):
    library = c.CDLL(str(Path(library_path).resolve()))
    library.mesh_library_free_returned_bytes.argtypes = [c.POINTER(Returned)]
    root = Path(root)
    custody = root/'custody'
    custody.mkdir(exist_ok=True)
    errors = []
    def host(operation):
        def call(_context,pointer,length,output,capacity,output_length):
            output_length[0] = 0
            try:
                data = c.string_at(pointer,length)
                if operation == 1:
                    size = int.from_bytes(data[:4],'big')
                    path = custody/sha(data[4:4+size])
                    path.write_bytes(data[4+size:])
                    result = b''
                elif operation in (2,3):
                    path = custody/sha(data)
                    if not path.exists(): return 2
                    result = path.read_bytes() if operation == 2 else b''
                    if operation == 3: path.unlink()
                elif operation == 4:
                    names = {b'messenger/config/v1':'security', b'messenger/network/v1':'network', b'messenger/ohttp/v1':'ohttp', b'messenger/rpc-tls-roots/v1':'rpc-tls',b'messenger/network-counter/v1':'counter',b'messenger/wallet/v1':'wallet'}
                    if data not in names or not (root/names[data]).exists(): return 2
                    result = (root/names[data]).read_bytes()
                    with (root/'resources.jsonl').open('a') as log:
                        log.write(json.dumps({'selector':data.decode(),'sha256':sha(result)})+'\n')
                else: return 2
                if len(result) > capacity: return 4
                c.memmove(output,result,len(result))
                output_length[0] = len(result)
                return 0
            except Exception as error:
                errors.append(repr(error))
                return 5
        return Callback(call)
    callbacks = Callbacks(1,c.sizeof(Callbacks),None,(Callback*9)(*[host(i) for i in range(1,10)]))
    assert library.mesh_library_init() == 0
    assert library.mesh_library_register_host_callbacks(c.byref(callbacks)) == 0
    print(json.dumps({'ready':True}),flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        function = getattr(library,request['symbol'])
        function.argtypes = [c.c_void_p,c.c_uint64,c.POINTER(Returned)]
        value, output = bytes.fromhex(request['hex']), Returned()
        code = function(value,len(value),c.byref(output))
        try: raw = c.string_at(output.data,output.len)
        finally: library.mesh_library_free_returned_bytes(c.byref(output))
        print(json.dumps({'code':code,'hex':raw.hex(),'host_errors':errors}),flush=True)
    assert library.mesh_library_shutdown() == 0


class Native:
    def __init__(self,library,root,env):
        self.library,self.root,self.env = library,root,env
        self.lock_errors = 0
        self.restart()
    def line(self):
        assert select.select([self.process.stdout],[],[],20)[0], 'native host timed out'
        line = self.process.stdout.readline()
        assert line, 'native host exited: '+str(self.process.poll())
        return json.loads(line)
    def restart(self):
        if hasattr(self,'process'): self.close()
        self.process = subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--worker',str(self.library),str(self.root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=self.env)
        assert self.line() == {'ready':True}
    def invoke(self,symbol,value,rejected=False,retry_locked=False):
        self.process.stdin.write(json.dumps({'symbol':symbol,'hex':value.hex()})+'\n')
        self.process.stdin.flush()
        result = self.line()
        assert not result['host_errors'], result
        raw = bytes.fromhex(result['hex'])
        if rejected:
            assert result['code'] != 0, (symbol,result)
            return raw.decode()
        if retry_locked and result['code'] != 0 and raw == b'database is locked':
            self.lock_errors += 1
            deadline = time.monotonic()+2
            while time.monotonic()<deadline:
                time.sleep(.02)
                try: return self.invoke(symbol,value)
                except AssertionError as error:
                    if "database is locked" not in str(error): raise
                    self.lock_errors += 1
            raise AssertionError('native database remained locked for two seconds')
        assert result['code'] == 0, (symbol,result,raw)
        return raw
    def close(self):
        self.process.stdin.close()
        try: self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=5)
        assert self.process.returncode == 0, self.process.returncode


class Bank:
    def __init__(self,work,prepared,settled,wire,raw_directory=None):
        self.work,self.prepared,self.settled,self.wire = work,prepared,settled,wire
        self.mode,self.requests,self.posts,self.errors = 'prepared',[],[],[]
        self.entered,self.release = threading.Event(),threading.Event()
        self.release.set()
        self.minimum = 0
        self.controls = []
        self.allow_legacy_bounty = False
        self.raw_directory = raw_directory
        if raw_directory:
            self.raw_requests = {stage:json.loads((raw_directory/f'phone-{stage}.raw.request.json').read_text()) for stage in ('prepared','settled','legacy')}
            self.raw_responses = {stage:(raw_directory/f'phone-{stage}.raw.response.json').read_bytes() for stage in ('prepared','settled','legacy')}
        self.servers = []
        def openssl(*args): subprocess.run(['openssl',*map(str,args)],check=True,capture_output=True)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',work/'ca.key','-out',work/'ca.pem','-days','1','-subj','/CN=Morse filing proof CA')
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',work/'leaf.key','-out',work/'leaf.csr','-subj','/CN=127.0.0.1')
        (work/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in',work/'leaf.csr','-CA',work/'ca.pem','-CAkey',work/'ca.key','-CAcreateserial','-out',work/'leaf.pem','-days','1','-extfile',work/'ext')
        bank = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_): pass
            def do_POST(self):
                try:
                    raw = self.rfile.read(int(self.headers['Content-Length']))
                    assert not any(self.headers.get(x) for x in ('Authorization','Cookie','X-Account-ID','X-Device-ID'))
                    if self.path == '/v1/fork-evidence':
                        assert raw == bank.wire
                        bank.posts.append({'sha256':sha(raw),'length':len(raw)})
                        return self.respond(202,{'schema_version':1,'status':'queued','proof_hash':sha(raw[:5]+raw[37:])})
                    request = json.loads(raw)
                    if request['method'] in ('getBlockHeight','getTransaction'):
                        assert bank.allow_legacy_bounty,request
                        bank.controls.append(request)
                        if request['method'] == 'getBlockHeight':
                            assert request['params'][0]['commitment'] == 'confirmed'
                            return self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':70})
                        assert request['params'][1]['commitment'] == 'finalized'
                        return self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':None})
                    assert request['method'] == 'getMultipleAccounts'
                    addresses,options = request['params']
                    if bank.raw_directory:
                        stage = 'legacy' if bank.mode == 'legacy' else 'prepared'
                        expected = bank.raw_requests[stage]['params'][0]
                        if bank.allow_legacy_bounty and len(addresses)==3:
                            expected = [expected[2],bank.prepared['accounts']['economics']['address'],expected[3]]
                        else:
                            assert options['dataSlice'] == {'offset':0,'length':9216}, options
                        assert addresses == expected, addresses
                    else:
                        expected = [bank.prepared['accounts'][x]['address'] for x in ('log','economics','proof')]
                        assert addresses == expected, addresses
                    assert options['commitment'] == 'finalized' and options['encoding'] == 'base64'
                    assert int(options.get('minContextSlot',0)) >= (0 if self.server.index>=4 or bank.allow_legacy_bounty and len(addresses)==3 else bank.minimum)
                    bank.requests.append({'keys':addresses,'options':options,'mode':bank.mode,'peer':self.server.index})
                    bank.entered.set()
                    assert bank.release.wait(15), 'RPC barrier not released'
                    mode = 'settled' if self.server.index>=4 else bank.mode
                    stage = 'legacy' if mode == 'legacy' else 'prepared' if mode == 'prepared' else 'settled'
                    if bank.raw_directory:
                        response = json.loads(bank.raw_responses[stage])
                        values = response['result']['value']
                        slot = response['result']['context']['slot']
                        if bank.allow_legacy_bounty and len(addresses)==3:
                            economy = dict(bank.prepared['accounts']['economics'])
                            data = bytes.fromhex(economy.pop('data_hex'))
                            economy.pop('address',None)
                            economy.update(data=[base64.b64encode(data).decode(),'base64'],lamports=int(economy['lamports']),rentEpoch=int(economy.pop('rent_epoch','0')))
                            values = [values[2],economy,values[3]]
                    else:
                        snapshot = bank.prepared if stage == 'prepared' else bank.settled
                        accounts = {v['address']:v for v in snapshot['accounts'].values()}
                        values = []
                        for address in addresses:
                            value = dict(accounts[address])
                            data = bytes.fromhex(value.pop('data_hex'))
                            value.update(data=[base64.b64encode(data).decode(),'base64'],lamports=int(value['lamports']),rentEpoch=0)
                            value.pop('space',None)
                            values.append(value)
                        slot = 9007199254740993
                    value = values[-1]
                    if mode == 'missing':
                        values[-1] = None
                    else:
                        data = base64.b64decode(value['data'][0])
                        if mode == 'wrong-owner': value['owner'] = '1'*32
                        if mode == 'wrong-program-owner': values[0]['owner'] = bank.prepared['program']
                        offsets = {'wrong-mint':136,'wrong-morse-mint':168,'wrong-proof':40,'wrong-first':200,'wrong-second':232,'wrong-stage':328,'wrong-witness-pda':432}
                        if mode in offsets:
                            offset = offsets[mode]; data = data[:offset]+b'\x0c'*32+data[offset+32:]
                        if mode == 'disagree':
                            data = data[:72]+bytes([self.server.index+12])*32+data[104:]
                        if mode == 'wrong-witness':
                            data = data[:464]+b'\x0c'*32+data[496:]
                        value['data'] = [base64.b64encode(data).decode(),'base64']
                    if mode == 'stale': slot = 1
                    self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':{'context':{'slot':slot},'value':values}})
                except Exception as error:
                    bank.errors.append(repr(error)); self.respond(500,{'error':'fixture failed'})
            def respond(self,status,body):
                body = json.dumps(body).encode()
                self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        self.pem = (work/'ca.pem').read_bytes()
        for index in range(7):
            server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
            server.index = index
            if index < 3:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(work/'leaf.pem',work/'leaf.key')
                server.socket = context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            self.servers.append(server)
        self.origins = [f'https://127.0.0.1:{s.server_port}' for s in self.servers[:3]]
        self.relay = f'http://127.0.0.1:{self.servers[3].server_port}'
        self.http_origins = [f'http://127.0.0.1:{s.server_port}' for s in self.servers[4:]]
    def close(self):
        self.release.set()
        for server in self.servers: server.shutdown(); server.server_close()



class ProductionRelay:
    """Unchanged production Node route/service/verifier; read-only native admit."""
    def __init__(self,args,bank,root,pins):
        self.work = root/'production-relay'
        self.work.mkdir()
        repository = args.snapshots.resolve().parents[2]
        modules = repository/'mesh-private-messenger/ops/relay'
        planner = dict(pins,endpoints=bank.http_origins)
        configuration = {'modules':str(modules),'binary':str((args.snapshots/'relay-mpr2').resolve()),
                         'work':str(self.work),'security':(root/'security').read_text(),'planner':planner,
                         'log':bank.raw_requests['prepared']['params'][0][2]}
        config = self.work/'configuration.json'
        config.write_text(json.dumps(configuration))
        code = r"""import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {once} from 'node:events';
const config=JSON.parse(await readFile(process.argv[2],'utf8'));
const load=name=>import(pathToFileURL(config.modules+'/'+name+'.mjs'));
const {createRelayVerifier}=await load('verifier');
const {createRelayService,runRelayLoop}=await load('service');
const {createRelayHttpServer}=await load('http');
const {RelayJournal}=await load('journal');
const p=config.planner,pins={program:p.judge,log:config.log,mint:p.usdc_mint,submitter:p.submitter,usdcMint:p.usdc_mint,morseMint:p.morse_mint};
const verifier=await createRelayVerifier({binary:config.binary,tempRoot:config.work+'/native',securityConfig:config.security,
 plannerConfig:JSON.stringify(p),logVersion:p.log_version,pins});
const journal=new RelayJournal({path:config.work+'/journal.sqlite',identity:'phone-native-real-admission',pins,
 policy:{perJobLamports:'1',windowLamports:'1',maxJobs:1}});
const service=createRelayService({journal,verifier,scheduler:{tick:async()=>({state:'idle'})}});
let submissions=0;
const server=createRelayHttpServer({submit:(wire,options)=>{submissions++;return service.submit(wire,options);}});
server.listen(0,'127.0.0.1');await once(server,'listening');
const controller=new AbortController(),loop=runRelayLoop(service,{signal:controller.signal,intervalMs:5});
console.log(JSON.stringify({origin:'http://127.0.0.1:'+server.address().port}));
await new Promise(resolve=>{process.stdin.once('data',resolve);process.once('SIGTERM',resolve);});
controller.abort();await loop;await service.close();
await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});journal.close();
console.log(JSON.stringify({submissions}));
"""
        script = self.work/'composition.mjs'
        script.write_text(code)
        self.log = (self.work/'stderr.log').open('w')
        self.process = subprocess.Popen(['node',str(script),str(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,start_new_session=True)
        assert select.select([self.process.stdout],[],[],15)[0], 'production relay did not start'
        ready = self.process.stdout.readline()
        assert ready, 'production relay startup failed; see '+str(self.work/'stderr.log')
        self.origin = json.loads(ready)['origin']
        self.sources = {str(modules/name):sha((modules/name).read_bytes()) for name in ('http.mjs','service.mjs','verifier.mjs','journal.mjs')}
        self.binary_hash = sha(Path(configuration['binary']).read_bytes())
    def close(self):
        self.process.stdin.write('stop\n');self.process.stdin.flush();self.process.stdin.close()
        try: self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=5)
            raise
        self.log.close()
        assert self.process.returncode==0, 'production relay composition failed'
        self.result = json.loads(self.process.stdout.readline())

def resources(root,bank,snapshot,wire):
    a = snapshot['accounts']
    log = bytes.fromhex(a['log']['data_hex'])
    ring = pda(snapshot['program'],b'ring',snapshot['log_name'].encode())
    service = wire[37:69].hex()
    # SecurityConfig v5 canonical frame, preserving the raw SBF's pinned log.
    witnesses = ['outside 0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d Fixture','token-outside d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c Fixture']
    security = '\n'.join(['5',service,'22'*32,'8','2','2',*witnesses,ring,'3',*bank.origins,'-','2','2','2',*witnesses,snapshot['program'],snapshot['log_name'],a['usdc']['address'],'3',*bank.origins]).encode()
    network = '\n'.join(['2','0',bank.origins[0],bank.origins[0],bank.origins[0],bank.origins[0].replace('https:','wss:')+'/v1/mailbox/stream','1']).encode()
    ohttp = f'1\n{sha(network)}\n{sha(security)}\n1\noff\n0'.encode()
    roots = b'\1\3'+hashlib.sha256(security).digest()
    for origin in sorted(bank.origins):
        raw = origin.encode(); roots += len(raw).to_bytes(2,'big')+raw+len(bank.pem).to_bytes(4,'big')+bank.pem
    counter = '\n'.join(['1',sha(security),'v2','100000','0',snapshot['token_program'],'0',snapshot['payer'],a['usdc']['address'],a['morse']['address'],snapshot['rewards_program'],'0',snapshot['payer'],'1700092799','-',base64.b64encode(bank.pem).decode(),str(snapshot.get('chain_log_version',1))]).encode()
    for name,data in [('security',security),('network',network),('ohttp',ohttp),('rpc-tls',roots),('counter',counter),('wallet',b'\1\1'+un58(a['usdc']['address']))]: (root/name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library',type=Path)
    parser.add_argument('fixtures',type=Path)
    parser.add_argument('--wire',type=Path)
    parser.add_argument('--snapshots',type=Path,help='directory of exact four-key raw getMultipleAccounts captures')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--expect-old-red',action='store_true')
    parser.add_argument('--expect-old-reader-red',action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    root = args.out.resolve()
    raw = json.loads(args.fixtures.read_text())
    snapshots = raw['snapshots']
    prepared = next(s for s in snapshots if s['name']=='mixed-proof-prepared')
    settled = next(s for s in snapshots if s['name']=='mixed-proof-settled')
    wire = args.wire.read_bytes() if args.wire else reconstruct(prepared)
    pins = None
    if args.snapshots:
        pins = json.loads((args.snapshots/'pins-winner-a.json').read_text())
        input_bank = json.loads((args.snapshots/'bank-input-winner-a.json').read_text())
        prepared['accounts']['economics'] = input_bank['fixture']['accounts']['economics']
        for stage,meta in [('prepared',prepared),('settled',settled)]:
            request = json.loads((args.snapshots/f'phone-{stage}.raw.request.json').read_text())
            reply = json.loads((args.snapshots/f'phone-{stage}.raw.response.json').read_text())
            keys,values = request['params'][0],reply['result']['value']
            meta['accounts']['proof'] = dict(values[3],address=keys[3],data_hex=base64.b64decode(values[3]['data'][0]).hex())
            meta['accounts']['log'] = dict(values[2],address=keys[2],data_hex=base64.b64decode(values[2]['data'][0]).hex())
            meta.update(payer=pins['governance'],token_program=pins['token'],rewards_program=pins['rewards'])
    receipt = bytes.fromhex(prepared['accounts']['proof']['data_hex'])
    assert receipt[:4] == b'MPR\2' and receipt[7] == 0
    assert hashlib.sha256(wire[:5]+wire[37:]).digest() == receipt[40:72]
    assert prepared['accounts']['proof']['address'] == pda(prepared['program'],b'proof',bytes.fromhex(prepared['log_id']),receipt[40:72])
    (root/'evidence.frk').write_bytes(wire)
    with tempfile.TemporaryDirectory(prefix='phone-mpr2-tls-',dir='/tmp') as raw_work:
        bank = Bank(Path(raw_work),prepared,settled,wire,args.snapshots)
        native = None
        evidence = {'library_sha256':sha(args.library.read_bytes()),'fixtures_sha256':sha(args.fixtures.read_bytes()),'wire_sha256':sha(wire),'proof_hash':receipt[40:72].hex(),'cases':[]}
        try:
            metadata = args.library.with_suffix(args.library.suffix+'.plaintext.json')
            if metadata.exists():
                evidence['artifact_metadata_sha256'] = sha(metadata.read_bytes())
                evidence['artifact_source_modules'] = {row['module']:row['source_sha256'] for row in json.loads(metadata.read_text())['modules']}
            evidence['proof_script_sha256'] = sha(Path(__file__).read_bytes())
            evidence['fixture_source_sha256'] = sha((PRODUCT/'tests/phone-filing-native/main.mpl').read_bytes())
            evidence['tools'] = {name:{'path':value,'sha256':sha(Path(value).read_bytes())} for name in ('MESHC','MESH_RT_LIB_PATH') if (value:=os.environ.get(name)) and Path(value).is_file()}
            if args.snapshots:
                evidence['raw_sources'] = {p.name:sha(p.read_bytes()) for p in sorted(args.snapshots.glob('phone-*.raw.*.json'))}
                evidence['raw_directory'] = str(args.snapshots.resolve())
                evidence['raw_auxiliary_sources'] = {name:sha((args.snapshots/name).read_bytes()) for name in ('pins-winner-a.json','pins-legacy.json','bank-input-winner-a.json','evidence-winner-a.frk','evidence-legacy.frk')}
                qualification = args.snapshots/'qualification.json'
                if qualification.exists():
                    report = json.loads(qualification.read_text())
                    assert report['verdict']=='PASS' and report['head_start']==report['head_end'] and not report['source_drift'] and not report['artifact_drift'],report
                    evidence['upstream_capture_qualification'] = {'sha256':sha(qualification.read_bytes()),'head':report['head_start'],'tree':report['tree']}
                    for name,expected in report['artifacts'].items():
                        assert sha(Path(name).read_bytes())==expected,name
            resources(root,bank,prepared,wire)
            bank.minimum = 0 if args.expect_old_reader_red or args.expect_old_red else 100000
            env = dict(os.environ,MORSE_PHONE_FILING_PORTS=str(bank.servers[3].server_port),MORSE_PHONE_FILING_ORIGINS=','.join([bank.relay]*3))
            native = Native(args.library.resolve(),root,env)
            def seed(name,wire_value=wire,selected=False):
                path = root/(name+'.db')
                Path(str(path)+'.wire').write_text(wire_value.hex())
                Path(str(path)+'.now').write_text('1000')
                Path(str(path)+'.floor').write_text('0')
                native.invoke('mesh_messenger_create_account',vectors(str(path).encode(),b'native-proof'))
                symbol = 'phone_fixture_seed' if args.expect_old_red else 'phone_fixture_seed_selected' if selected else 'phone_fixture_seed_exact'
                retained = native.invoke(symbol,str(path).encode())
                assert retained[:5]+retained[37:] == wire_value[:5]+wire_value[37:]
                if not args.expect_old_red: assert retained == wire_value
                return path
            def view(path,symbol='mesh_messenger_fork_filing'):
                return fields(native.invoke(symbol,str(path).encode(),retry_locked=True))
            def finish(path,symbol='mesh_messenger_fork_filing'):
                deadline = time.monotonic()+12
                while time.monotonic() < deadline:
                    result = view(path,symbol)
                    if result[11] == '0': return result
                    time.sleep(.02)
                raise AssertionError('native filing did not finish')
            path = seed('production-prepared')
            if args.expect_old_reader_red:
                error = native.invoke('phone_fixture_native_legacy_read',str(path).encode(),rejected=True)
                assert error in ('invalid_slash_receipt','invalid_anchor_custody'), error
                assert len(bank.requests) >= 2 and all(len(r['keys']) == 3 for r in bank.requests),bank.requests
                evidence.update(status='RED_old_native_reader_rejects_exact_SBF_MPR2',error=error)
                print(json.dumps({'status':evidence['status'],'error':error,'rpc_requests':len(bank.requests)}))
                return
            bank.release.clear()
            started = time.monotonic(); initial = view(path)
            if args.expect_old_red and initial[0] == 'invalid_evidence':
                evidence.update(status='RED_old_production_export_rejects_legacy_fork',initial=initial)
                print(json.dumps({'status':evidence['status'],'initial':initial}))
                return
            assert time.monotonic()-started < 2 and initial[11] == '1', initial
            assert bank.entered.wait(5), ('no actual production RPC',initial)
            retained = native.invoke('mesh_messenger_transparency_fork',str(path).encode())
            assert retained[:5]+retained[37:] == wire[:5]+wire[37:]
            bank.release.set()
            result = finish(path)
            evidence.update(initial=initial,prepared=result,requests=bank.requests,host_resource_reads=[json.loads(line) for line in (root/'resources.jsonl').read_text().splitlines()])
            if args.expect_old_red:
                assert result[0] == 'rpc_unavailable' and result[3:5] == ['', '0'], result
                assert all(len(r['keys']) == 3 for r in bank.requests), bank.requests
                evidence['status'] = 'RED_old_production_rejects_actual_prepared_MPR2'
                evidence['expected'] = 'prepared with actual finder, zero USDC and MORSE, 4 derived finalized keys'
                print(json.dumps({'status':evidence['status'],'view':result,'rpc_requests':len(bank.requests)}))
                return
            assert len(initial) == 16 and initial[12:] == ['2','0',prepared['accounts']['morse']['address'], '0'], initial
            assert len(result) == 16 and result[0] == 'prepared' and result[3] == b58(receipt[72:104]) and result[4] == '0' and result[13] == '0' and result[15] == '2', result
            assert all(len(r['keys']) == 4 for r in bank.requests)
            evidence['cases'].append('production export prepared; owned TLS finalized four-key RPC; concurrent retained export')
            bank.mode = 'settled'
            settled_path = seed('production-settled')
            settled_result = finish(settled_path)
            assert settled_result[0] == 'settled' and settled_result[15] == '2', settled_result
            paid = bytes.fromhex(settled['accounts']['proof']['data_hex'])
            expected_amounts = [str(int.from_bytes(paid[280:288],'little')),str(int.from_bytes(paid[304:312],'little'))]
            assert settled_result[3] == b58(paid[72:104]) and [settled_result[4],settled_result[13]] == expected_amounts,settled_result
            assert all(int(amount)>0 for amount in expected_amounts),expected_amounts
            evidence['settled'] = settled_result
            native.restart()
            before = len(bank.requests)
            assert view(settled_path) == settled_result and len(bank.requests) == before
            evidence['cases'].append('production export both-asset settlement survives exact host process restart without RPC')
            if args.snapshots:
                bank.mode = 'legacy'
                legacy_wire = (args.snapshots/'evidence-legacy.frk').read_bytes()
                legacy_pins = json.loads((args.snapshots/'pins-legacy.json').read_text())
                saved = {name:(root/name).read_bytes() for name in ('security','network','ohttp','rpc-tls','counter','wallet')}
                legacy_meta = json.loads(json.dumps(prepared))
                legacy_meta.update(program=legacy_pins['judge'],chain_log_version=legacy_pins['log_version'])
                legacy_meta['accounts']['usdc']['address'] = legacy_pins['usdc_mint']
                resources(root,bank,legacy_meta,legacy_wire)
                try:
                    legacy_path = seed('production-legacy-receipt',legacy_wire)
                    legacy = finish(legacy_path)
                finally:
                    for name,value in saved.items(): (root/name).write_bytes(value)
                legacy_raw = json.loads(bank.raw_responses['legacy'])['result']['value'][-1]
                legacy_receipt = base64.b64decode(legacy_raw['data'][0])
                assert legacy_receipt[:4] == b'MPR\1'
                assert len(legacy)==16 and legacy[0]=='settled' and legacy[15]=='1' and legacy[13]=='0',legacy
                assert legacy[3] == b58(legacy_receipt[72:104]) and legacy[4]==str(int.from_bytes(legacy_receipt[248:256],'little')),legacy
                evidence['legacy_view'] = legacy
                evidence['cases'].append('actual legacy MPR1 settled receipt remains readable through v2 native four-key pins')
            symbol = 'phone_fixture_native_start'
            bank.mode = 'prepared'
            retry_path = seed('retry-prepared')
            retry_prepared = finish(retry_path,symbol)
            assert retry_prepared[0] == 'prepared' and retry_prepared[3] == b58(receipt[72:104]) and retry_prepared[4] == retry_prepared[13] == '0',retry_prepared
            counts = (len(bank.requests),len(bank.posts))
            assert view(retry_path,symbol) == retry_prepared and counts == (len(bank.requests),len(bank.posts))
            bank.mode = 'settled'
            Path(str(retry_path)+'.now').write_text('61000')
            retry_settled = finish(retry_path,symbol)
            assert retry_settled[0] == 'settled' and [retry_settled[4],retry_settled[13]] == expected_amounts,retry_settled
            evidence['cases'].append('deterministic prepared zero amounts; budget preserved; later finalized settlement')
            bank.wire = wire[:5]+bytes([7])*32+wire[37:]
            other_path = seed('another-finder',bank.wire)
            other = finish(other_path,symbol)
            assert other[0] == 'paid_elsewhere' and other[3] == b58(paid[72:104]) and [other[4],other[13]] == expected_amounts,other
            bank.wire = wire
            evidence['cases'].append('same admitted proof attributed to actual winning finder when this phone selected another finder')
            evidence['negative_views'] = {}
            for mode in ['missing','wrong-owner','wrong-program-owner','wrong-mint','wrong-morse-mint','wrong-proof','wrong-first','wrong-second','wrong-stage','wrong-witness','wrong-witness-pda','stale','disagree']:
                bank.mode = mode
                path = seed(mode)
                negative = finish(path,symbol)
                expected = 'accepted' if mode == 'missing' else 'rpc_disagree' if mode == 'disagree' else 'rpc_unavailable'
                assert negative[0] == expected and negative[3] == '' and negative[4] == negative[13] == '0' and negative[15] == '0',(mode,negative)
                counts = (len(bank.requests),len(bank.posts))
                assert view(path,symbol) == negative and counts == (len(bank.requests),len(bank.posts)),mode
                evidence['negative_views'][mode] = negative
            evidence['cases'].append('missing/owner/program/mints/proof/checkpoints/stage/witness/PDA/stale/disagreement rejected without payout; repeat wake no network')
            bank.mode = 'settled'
            for resource in ['security','network','ohttp','rpc-tls','counter']:
                path = seed('replace-'+resource)
                original = (root/resource).read_bytes()
                bank.entered.clear(); bank.release.clear()
                outcome = []
                def read_held():
                    try: outcome.append(native.invoke('phone_fixture_native_read',str(path).encode(),rejected=True))
                    except Exception as error: outcome.append(error)
                thread = threading.Thread(target=read_held)
                thread.start()
                try:
                    assert bank.entered.wait(5),resource
                    (root/resource).write_bytes(original+b'\n')
                    bank.release.set(); thread.join(15)
                    assert not thread.is_alive() and len(outcome)==1 and isinstance(outcome[0],str),(resource,outcome)
                    assert outcome[0] in ('account_state_changed','filing_pins_changed','filing_config_changed','rpc_context_changed:account_state_changed','rpc_context_changed:filing_pins_changed','rpc_context_changed:filing_config_changed'),(resource,outcome)
                    evidence.setdefault('resource_replacement_errors',{})[resource] = outcome[0]
                finally:
                    (root/resource).write_bytes(original); bank.release.set()
                evidence['cases'].append(resource+' native resource replacement during held RPC retires captured authority')
            path = seed('fatal-tls')
            roots = (root/'rpc-tls').read_bytes()
            # WebPKI sentinel is a valid native resource but trusts none of this
            # owned CA. This tests the real public HTTP certificate validator.
            (root/'rpc-tls').write_bytes(b'\1\0')
            try:
                error = native.invoke('phone_fixture_native_read',str(path).encode(),rejected=True)
                assert 'tls' in error or 'rpc_unavailable' in error,error
            finally: (root/'rpc-tls').write_bytes(roots)
            evidence['cases'].append('untrusted real TLS peer refuses receipt authority')
            invalid_roots = b'\1\3'+hashlib.sha256((root/'security').read_bytes()).digest()
            for origin in sorted(bank.origins):
                raw = origin.encode(); pem = b'not a PEM root'
                invalid_roots += len(raw).to_bytes(2,'big')+raw+len(pem).to_bytes(4,'big')+pem
            (root/'rpc-tls').write_bytes(invalid_roots)
            before = (len(bank.requests),len(bank.posts))
            try:
                error = native.invoke('phone_fixture_native_read',str(path).encode(),rejected=True)
                assert error == 'rpc_tls_config_invalid',error
                assert before == (len(bank.requests),len(bank.posts))
            finally: (root/'rpc-tls').write_bytes(roots)
            evidence['cases'].append('malformed PEM in bound native TLS resource produces fatal rpc_tls_config_invalid before HTTP')
            counter = (root/'counter').read_bytes()
            for invalid in [b'',b'bad-native-resource']:
                (root/'counter').write_bytes(invalid)
                before = len(bank.requests)
                error = native.invoke('mesh_messenger_fork_filing',str(settled_path).encode(),rejected=True)
                assert len(bank.requests)==before and error in ('invalid_filing_pins','invalid_network_counter_configuration'),error
            (root/'counter').write_bytes(counter)
            evidence['cases'].append('present malformed optional pin frame refuses before RPC')
            # A persisted paid observation may not be relabeled by a valid
            # replacement token program/mint pair after the host restarts.
            counter_fields = counter.decode().split('\n')
            alternate = list(counter_fields)
            alternate[5] = b58(bytes([19])*32)
            alternate[9] = pda(alternate[5],b'mint')
            (root/'counter').write_text('\n'.join(alternate))
            native.restart()
            before = len(bank.requests)
            cached_error = native.invoke('mesh_messenger_fork_filing',str(settled_path).encode(),rejected=True)
            assert len(bank.requests)==before,cached_error
            (root/'counter').write_bytes(counter)
            assert view(settled_path) == settled_result
            evidence['cached_pin_rotation_error'] = cached_error
            evidence['cases'].append('restart refuses persisted receipt under different valid token/MORSE pins')
            economic = list(counter_fields)
            economic[7],economic[12] = b58(bytes([42])*32),b58(bytes([43])*32)
            economic[14] = 'rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ '+b58(bytes([44])*32)+' '+'09'*32+' 2'
            (root/'counter').write_text('\n'.join(economic))
            before = len(bank.requests)
            assert view(settled_path) == settled_result and len(bank.requests)==before
            (root/'counter').write_bytes(counter)
            evidence['cases'].append('governance and oracle source rotations preserve earned receipt identity')
            # This is the actual native transfer prepare export. There is no
            # signer callback in this host; unsupported receipts must stop it
            # before asking the wallet to sign or building a movement intent.
            bounty_path = seed('bounty-mpr2',selected=True)
            bank.allow_legacy_bounty = True
            before = (len(bank.requests),len(bank.posts))
            request = (3).to_bytes(4,'big')+vectors(str(bounty_path).encode(),bytes([21])*32,paid[72:104])
            bounty_error = native.invoke('mesh_messenger_bounty_transfer_prepare',request,rejected=True)
            assert bounty_error in ('invalid_anchor_custody','invalid_slash_receipt','slash_receipt_identity_mismatch'),bounty_error
            assert before[1] == len(bank.posts)
            assert any(len(row['keys'])==3 for row in bank.requests[before[0]:])
            evidence['bounty_prepare_error'] = bounty_error
            evidence['cases'].append('actual native bounty prepare refuses authenticated MPR2 before signing')
            pending_path = root/'pending-bounty.db'
            Path(str(pending_path)+'.wire').write_text(wire.hex())
            native.invoke('mesh_messenger_create_account',vectors(str(pending_path).encode(),b'pending-bounty'))
            journal = native.invoke('phone_fixture_seed_pending_bounty',str(pending_path).encode())
            # The helper's output uses the same outer-vector output-list ABI.
            raw_parts = []
            while journal:
                size = int.from_bytes(journal[:4],'big'); raw_parts.append(journal[4:4+size]); journal = journal[4+size:]
            assert raw_parts[0] == (2).to_bytes(4,'big') and len(raw_parts[1])==32 and len(raw_parts[2])==64
            identity,signature = raw_parts[1:]
            request = (2).to_bytes(4,'big')+vectors(str(pending_path).encode(),identity)
            prior = native.invoke('mesh_messenger_bounty_transfer_status',str(pending_path).encode())
            controls = len(bank.controls)
            assert native.invoke('mesh_messenger_bounty_transfer_recover',request) == prior
            native.restart()
            assert native.invoke('mesh_messenger_bounty_transfer_recover',request) == prior
            assert len(bank.controls)>=controls+4
            assert all(row['method']=='getTransaction' for row in bank.controls[controls:])
            evidence['pending_bounty_signature_sha256'] = sha(signature)
            evidence['cases'].append('valid historical signed bounty journal under v2 pins recovers None history and preserves exact signature across process restart')
            bank.allow_legacy_bounty = False
            if args.snapshots:
                relay = ProductionRelay(args,bank,root,pins)
                try:
                    native.env['MORSE_PHONE_FILING_ORIGINS'] = ','.join([relay.origin]*3)
                    native.restart()
                    bank.mode = 'prepared'
                    path = seed('production-relay-admission')
                    admitted = finish(path,symbol)
                    assert admitted[0]=='prepared' and admitted[4]==admitted[13]=='0' and admitted[6]=='3',admitted
                    evidence['production_relay_view'] = admitted
                finally: relay.close()
                assert relay.result['submissions']==3,relay.result
                evidence['production_relay'] = {'sources':relay.sources,'binary_sha256':relay.binary_hash,**relay.result}
                evidence['cases'].append('native HTTP -> production Node route/service -> production verifier.admit -> frozen native permanent reader; settled relay ACK leaves prepared phone payouts zero')
            # Endpoint changes require a new OHTTP revision but do not change
            # the immutable meaning of an already earned receipt.
            bank.origins.reverse()
            resources(root,bank,prepared,wire)
            companion = (root/'ohttp').read_text().split('\n'); companion[3] = '2'
            (root/'ohttp').write_text('\n'.join(companion))
            before = len(bank.requests)
            assert view(settled_path) == settled_result and len(bank.requests)==before
            evidence['cases'].append('RPC/relay endpoint rotation with new native OHTTP revision preserves earned receipt')
            evidence['status'] = 'PASS_native_MPR2_filing'
            assert not bank.errors,bank.errors
            print(json.dumps({'status':evidence['status'],'cases':evidence['cases']}))
        finally:
            if native:
                evidence['transient_database_locks'] = native.lock_errors
                native.close()
            bank.close()
            evidence['requests'],evidence['relay_posts'],evidence['server_errors'] = bank.requests,bank.posts,bank.errors
            evidence['control_requests'] = bank.controls
            evidence.setdefault('status','FAIL_incomplete_native_proof')
            (root/'result.json').write_text(json.dumps(evidence,indent=2)+'\n')


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv)>1 and sys.argv[1]=='--worker': worker(*sys.argv[2:])
    else: main()
