#!/usr/bin/env python3
"""Real local Bitcoin/LND + PostgreSQL + compiled Mesh credit issuance proof.

Everything is owned regtest data. No live payment, node, wallet, or credential
is used. Oracle account bytes are an explicit authenticated-RPC test fixture,
not a proof of Pyth guardian verification.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import base64
import hashlib
import json
import os
import secrets
import shlex
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from lightning_regtest import LightningRegtest, await_value, port
from credit_ios_proof import CreditIOSProof, packet_fields
from credit_tls_proof import prove_native_tls

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent
PROOF = Path(os.environ.get('MORSE_LIGHTNING_PROOF_DIR', ROOT / '.morse/witness-proof'))
ISSUER_SOURCE = Path(os.environ.get('MORSE_LIGHTNING_SERVICE_SOURCE', PRODUCT / 'services/credit-issuer'))


class Database:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='morse-ln-pg-', dir='/tmp')
        self.work = Path(self.temp.name).resolve()
        self.pg = Path(os.environ.get('PG_BIN', '/opt/homebrew/opt/postgresql@17/bin'))
        self.port = port()
        self.env = dict(os.environ, PGHOST='127.0.0.1', PGPORT=str(self.port), PGUSER='lightning_test', PGDATABASE='lightning_test')
        self.started = False
        try:
            self.run('initdb', '-D', self.work/'data', '-U', 'lightning_test', '--auth=trust', '--no-locale')
            self.run('pg_ctl', '-D', self.work/'data', '-l', self.work/'postgres.log', '-o', shlex.join(['-h','127.0.0.1','-p',str(self.port),'-k',str(self.work)]), '-w', 'start')
            self.started = True
            self.run('createdb', 'lightning_test')
            for migration in sorted((ISSUER_SOURCE/'migrations').glob('*.sql')):
                self.run('psql', '-v', 'ON_ERROR_STOP=1', '-f', migration)
            self.url = f'postgres://lightning_test@127.0.0.1:{self.port}/lightning_test?sslmode=disable'
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def run(self, tool, *args):
        return subprocess.run([str(self.pg/tool), *map(str,args)], env=self.env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def sql(self, sql):
        return self.run('psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql).stdout.strip()

    def __exit__(self, *_):
        if self.started:
            self.run('pg_ctl','-D',self.work/'data','-m','fast','-w','stop')
        self.temp.cleanup()


class FixtureServers:
    def __init__(self, lnd_origin):
        self.lnd_origin = lnd_origin
        self.drop_creation = False
        self.drop_settlement = False
        self.reject_settlement = False
        self.fail_lookup = False
        self.oracle_calls = 0
        self.counts = {'create':0, 'settle':0, 'cancel':0}
        self.servers = []

    def __enter__(self):
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.route()
            def do_POST(self):
                self.route()
            def route(self):
                body = self.rfile.read(int(self.headers.get('Content-Length','0')))
                if self.path == '/oracle':
                    value = json.loads(body)
                    assert value['method'] == 'getAccountInfo'
                    assert value['params'][0] == '11111111111111111111111111111111'
                    assert value['params'][1]['commitment'] == 'finalized'
                    fixture.oracle_calls += 1
                    data = bytearray(134)
                    data[:8] = bytes.fromhex('22f123639d7ef4cd')
                    data[40] = 1
                    data[41:73] = bytes.fromhex('e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43')
                    # The issuer samples now before read_btc_price's 5000ms RPC.
                    # A response-time publication can be future at that sample.
                    # Keep this fixture observation recent, with five seconds of
                    # RPC slack; derive both timestamps from one clock sample.
                    published = int(time.time()) - 5
                    struct.pack_into('<qQiqq', data, 73, 10_000_000_000_000, 1_000_000, -8, published, published-1)
                    struct.pack_into('<Q', data, 125, 100)
                    import base64
                    result = {'jsonrpc':'2.0','id':value['id'],'result':{'context':{'slot':100},'value':{'data':[base64.b64encode(data).decode(),'base64'],'owner':'rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp','executable':False,'lamports':2_000_000,'rentEpoch':0}}}
                    return self.respond(200,json.dumps(result).encode())
                if self.path.startswith('/v1/invoice/') and fixture.fail_lookup:
                    fixture.fail_lookup = False
                    return self.respond(503,b'{}')
                if self.path == '/v2/invoices/hodl': fixture.counts['create'] += 1
                if self.path == '/v2/invoices/settle': fixture.counts['settle'] += 1
                if self.path == '/v2/invoices/settle' and fixture.reject_settlement:
                    fixture.reject_settlement = False
                    fixture.fail_lookup = True
                    return self.respond(503,b'{}')
                if self.path == '/v2/invoices/cancel': fixture.counts['cancel'] += 1
                request = urllib.request.Request(fixture.lnd_origin+self.path, data=body if self.command=='POST' else None,
                    headers={'Content-Type':'application/json','Grpc-Metadata-macaroon':self.headers.get('Grpc-Metadata-macaroon','')})
                try:
                    with urllib.request.urlopen(request,timeout=15) as result:
                        status, content = result.status, result.read(65537)
                except urllib.error.HTTPError as error:
                    status, content = error.code, error.read(65537)
                if status==200 and ((self.path=='/v2/invoices/hodl' and fixture.drop_creation) or (self.path=='/v2/invoices/settle' and fixture.drop_settlement)):
                    fixture.drop_creation = fixture.drop_settlement = False
                    fixture.fail_lookup = True
                    self.close_connection = True
                    self.connection.close()
                    return
                self.respond(status,content)
            def respond(self,status,body):
                self.send_response(status)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.origin = f'http://127.0.0.1:{server.server_port}'
        return self

    def __exit__(self,*_):
        for server in self.servers:
            server.shutdown()
            server.server_close()


def main(native_tls_extension=None):
    PROOF.mkdir(parents=True,exist_ok=True)
    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='morse-ln-issuer-',dir='/tmp'))).resolve()
        project = work/'project'
        project.mkdir()
        source = ISSUER_SOURCE
        for directory in ('api','runtime','payment','storage'):
            shutil.copytree(source/directory,project/directory)
        (project/'main.mpl').write_text((source/'payment/fixtures/lightning-client.mpl.fixture').read_text())
        (project/'mesh.toml').write_text('[package]\nname="lightning-proof"\nversion="0.1.0"\n[dependencies]\nmessenger-protocol={path="'+str(PRODUCT/'packages/messenger-protocol')+'"}\n')
        compiler = Path(os.environ.get('MESHC',ROOT/'mesh-lang/target/debug/meshc'))
        binary = work/'lightning-proof'
        build = subprocess.run([str(compiler),'build',str(project),'--opt-level',os.environ.get('LIGHTNING_OPT_LEVEL','0'),'-o',str(binary)],capture_output=True,text=True)
        (PROOF/'lightning-issuance-build.log').write_text(build.stdout+build.stderr)
        if build.returncode:
            raise RuntimeError('Mesh integration build failed; see lightning-issuance-build.log')
        (project/'main.mpl').write_text((source/'main.mpl').read_text())
        server_binary = work/'credit-issuer'
        server_build = subprocess.run([str(compiler),'build',str(project),'--opt-level',os.environ.get('LIGHTNING_OPT_LEVEL','0'),'-o',str(server_binary)],capture_output=True,text=True)
        (PROOF/'lightning-production-build.log').write_text(server_build.stdout+server_build.stderr)
        if server_build.returncode:
            raise RuntimeError('Production issuer build failed; see lightning-production-build.log')
        # Preserve the exact executable/report pair before temporary cleanup,
        # including when a later mobile or framework assertion fails.
        artifacts = PROOF/'compiled'
        artifacts.mkdir(exist_ok=True)
        reports = []
        for executable in (binary, server_binary):
            shutil.copyfile(executable, artifacts/executable.name)
            report = executable.with_name(executable.name+'.plaintext.json')
            shutil.copyfile(report, artifacts/report.name)
            reports.extend(json.loads(report.read_text())['modules'])
        source_roots = [project, source, PRODUCT/'packages/messenger-protocol']
        source_roots.extend(ROOT/'mesh-lang/packages'/name for name in ('mesh-binary','mesh-solana','mesh-lightning'))
        candidates = {}
        for directory in source_roots:
            for file in directory.rglob('*'):
                if file.is_file() and (file.suffix == '.mpl' or file.name.endswith('.mpl.fixture')):
                    candidates[hashlib.sha256(file.read_bytes()).hexdigest()] = file
        source_archive = artifacts/'sources-by-sha'
        source_archive.mkdir(exist_ok=True)
        for module in reports:
            digest = module['source_sha256']
            original = candidates[digest]
            assert hashlib.sha256(original.read_bytes()).hexdigest() == digest
            shutil.copyfile(original, source_archive/(digest+'.mpl'))
        print('Compiled production Mesh HTTP issuer and client fixture',flush=True)
        db = stack.enter_context(Database())
        lnd = stack.enter_context(LightningRegtest())
        servers = stack.enter_context(FixtureServers(lnd.nodes['issuer']['origin']))
        credential = work/'macaroon.hex'
        credential.write_text((lnd.nodes['issuer']['directory']/'data/chain/bitcoin/regtest/admin.macaroon').read_bytes().hex())
        credential.chmod(0o600)
        env = dict(os.environ, MESSENGER_ISSUER_DATABASE_URL=db.url,
            MESSENGER_CREDIT_STORAGE_DIR=str(work/'issuer-key'), MORSE_HTTP_CLIENT_STORE=str(work/'client-key'),
            MORSE_HTTP_WORK=str(work), MORSE_HTTP_SERVICE_SEED=secrets.token_hex(32),MORSE_HTTP_WITNESS_SEED=secrets.token_hex(32),
            MORSE_LN_ORIGIN=servers.origin, MORSE_LN_MACAROON_FILE=str(credential),MORSE_LN_PAYEE=lnd.nodes['issuer']['public_key'],
            MORSE_LN_ORACLE_RPC=servers.origin+'/oracle',MORSE_LN_ORACLE_ACCOUNT='11111111111111111111111111111111')
        current_server = {"process":None,"enabled":True}
        issuer_origin = f"http://127.0.0.1:{port()}"
        def stop_server():
            child = current_server["process"]
            if child is not None and child.poll() is None:
                child.terminate()
                try: child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            current_server["process"] = None
        def start_server(enabled=True):
            stop_server()
            seed = json.loads((work/'bootstrap.json').read_text())
            witness = 'outside '+seed['witness_key']+' Test'
            trust = '\n'.join(['3',seed['service_key'],'22'*32,'16','1','1',witness,'-','0','https://credits.example','2','1','1',witness])
            server_env = dict(env,MORSE_CREDITS_MODE='test' if enabled else 'off',MESSENGER_CREDITS_PURPOSE='test',
                MESSENGER_ISSUER_SECURITY_CONFIG=trust,MESSENGER_CREDIT_USDC_MINT='EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
                MESSENGER_CREDIT_SOLANA_RPC_URL=servers.origin+'/oracle',MESSENGER_DELIVERY_INTERNAL_URL=servers.origin,
                MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN='a'*32,MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN='b'*32,
                MESSENGER_ISSUER_PORT=issuer_origin.rsplit(':',1)[1],MORSE_LIGHTNING_MODE='test',
                MESSENGER_CREDIT_LIGHTNING_ORIGIN=servers.origin,MESSENGER_CREDIT_LIGHTNING_NETWORK='regtest',
                MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY=lnd.nodes['issuer']['public_key'],
                MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX=credential.read_text(),
                MESSENGER_CREDIT_BTC_PRICE_ACCOUNT='11111111111111111111111111111111',MORSE_TREASURY_MODE='off')
            log = stack.enter_context((work/'issuer-server.log').open('ab'))
            current_server['process'] = subprocess.Popen([str(server_binary)],env=server_env,stdout=log,stderr=subprocess.STDOUT)
            current_server['enabled'] = enabled
            def ready():
                if current_server['process'].poll() is not None:
                    raise AssertionError('issuer startup failed: '+(work/'issuer-server.log').read_text()[-2000:])
                with urllib.request.urlopen(issuer_origin+'/health',timeout=2) as response:
                    return response.status==200
            await_value(ready)
        def http_operation(operation,output):
            request = urllib.request.Request(issuer_origin+'/internal/v1/credits/lightning/'+operation,
                data=bytes.fromhex((output/(operation+'-request')).read_text()),
                headers={'Content-Type':'application/octet-stream','Authorization':'Bearer '+'b'*32})
            try:
                with urllib.request.urlopen(request,timeout=60) as response:
                    status,body=response.status,response.read()
            except urllib.error.HTTPError as error:
                status,body=error.code,error.read()
            (output/'status').write_text(str(status))
            if status==200:
                (output/('quote' if operation=='quote' else 'response')).write_text(body.hex())
            else:
                assert body==b'', 'internal diagnostics must never leave purchase routes'
            return str(status)
        def run(operation, output=work, **extra):
            if operation.endswith('-controller'):
                enabled=extra.get('MORSE_LN_ENABLED','true')=='true'
                if enabled != current_server['enabled']: start_server(enabled)
                return http_operation(operation.split('-')[0],output)
            result = subprocess.run([str(binary)],env=dict(env,MORSE_HTTP_OPERATION=operation,MORSE_HTTP_OUTPUT=str(output),**extra),capture_output=True,text=True,timeout=60)
            if result.returncode:
                raise RuntimeError(f'Mesh {operation} failed: '+result.stdout+result.stderr)
            return (output/'status').read_text() if (output/'status').exists() else None
        run('bootstrap')
        start_server()
        stack.callback(stop_server)
        for route in ('quote','issue'):
            denied = urllib.request.Request(issuer_origin+'/internal/v1/credits/lightning/'+route,data=b'')
            try: urllib.request.urlopen(denied,timeout=5)
            except urllib.error.HTTPError as error: assert error.code==401 and error.read()==b''
            else: raise AssertionError('purchase route accepted missing authorization')
        results = []
        tokens_verified = 0
        all_cases = ('ordinary','lost-creation-and-settlement','rollback-before-disclosure','prepared-integrity-and-worker','canceled')
        selected_cases = tuple(filter(None, os.environ.get('MORSE_LIGHTNING_CASES', ','.join(all_cases)).split(',')))
        if not selected_cases or set(selected_cases)-set(all_cases):
            raise ValueError('Unknown or empty Lightning proof case selection')
        for name in selected_cases:
            output = work/name
            output.mkdir(mode=0o700)
            run('prepare',output)
            old_creates = servers.counts['create']
            if name=='lost-creation-and-settlement':
                servers.drop_creation = True
                assert run('quote-controller',output)=='503'
            quote_status = run('quote-controller',output)
            assert quote_status=='200', (name, 'quote_http_status', quote_status)
            assert servers.counts['create']==old_creates+1
            quote = (output/'quote').read_text()
            before = servers.oracle_calls
            assert run('quote-controller',output)=='200'
            assert (output/'quote').read_text()==quote and servers.oracle_calls==before
            run('issue',output)
            assert run('issue-controller',output)=='425'
            assert not (output/'response').exists()
            payment_hash = (output/'payment-hash').read_text()
            invoice = (output/'invoice').read_text()
            if name == 'canceled':
                where = " WHERE payment_hash=decode('"+payment_hash+"','hex')"
                # New purchases off must not prevent authentic terminal recovery.
                # An unpaid OPEN invoice still has no terminal proof.
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='503'
                assert not (output/'response').exists()
                lnd.lnd('issuer','/v2/invoices/cancel', {'payment_hash':base64.b64encode(bytes.fromhex(payment_hash)).decode()})
                assert lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='CANCELED'
                db.sql("CREATE FUNCTION reject_ln_cancel() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state=4 THEN RAISE EXCEPTION 'fixture cancellation rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_ln_cancel BEFORE UPDATE ON issuer_lightning_quotes FOR EACH ROW EXECUTE FUNCTION reject_ln_cancel();")
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='503'
                assert not (output/'response').exists()
                assert db.sql('SELECT state FROM issuer_lightning_quotes'+where)=='1'
                db.sql('DROP TRIGGER reject_ln_cancel ON issuer_lightning_quotes; DROP FUNCTION reject_ln_cancel();')
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='200', 'canceled invoices need an authenticated terminal response'
                response = (output/'response').read_text()
                assert len(bytes.fromhex(response))==205 and response.startswith('014c434e')
                run('verify-cancellation',output)
                assert db.sql('SELECT state FROM issuer_lightning_quotes'+where)=='4'
                assert db.sql('SELECT count(*) FROM issuer_lightning_revenue r JOIN issuer_lightning_quotes q USING(quote_id)'+where)=='0'
                before = dict(servers.counts)
                servers.fail_lookup = True
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='200'
                assert (output/'response').read_text()==response and servers.counts==before and servers.fail_lookup
                servers.fail_lookup = False
                # A persisted signature is reverified before cached replay.
                corrupted = response[:-2]+format(int(response[-2:],16)^1,'02x')
                db.sql("UPDATE issuer_lightning_quotes SET cancellation=decode('"+corrupted+"','hex')"+where)
                (output/'response').unlink()
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='503'
                assert not (output/'response').exists()
                # Legacy state=4 without a certificate must consult the node.
                db.sql('UPDATE issuer_lightning_quotes SET cancellation=NULL'+where)
                servers.fail_lookup = True
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='503'
                assert not (output/'response').exists()
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='200'
                run('verify-cancellation',output)
                results.append(name)
                print('Verified canceled invoice: authenticated terminal recovery, zero credits/revenue, durable replay and legacy reconciliation',flush=True)
                continue
            with ThreadPoolExecutor(max_workers=1) as executor:
                payment = executor.submit(lnd.pay,invoice)
                await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda value:value['state']=='ACCEPTED')
                if name=='rollback-before-disclosure':
                    db.sql("CREATE FUNCTION reject_ln_prepare() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state=2 THEN RAISE EXCEPTION 'fixture rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_ln_prepare BEFORE UPDATE ON issuer_lightning_quotes FOR EACH ROW EXECUTE FUNCTION reject_ln_prepare();")
                    assert run('issue-controller',output)=='503'
                    assert not (output/'response').exists()
                    assert lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='ACCEPTED'
                    assert db.sql("SELECT state FROM issuer_lightning_quotes WHERE payment_hash=decode('"+payment_hash+"','hex')")=='1'
                    db.sql('DROP TRIGGER reject_ln_prepare ON issuer_lightning_quotes; DROP FUNCTION reject_ln_prepare();')
                if name=='lost-creation-and-settlement':
                    servers.drop_settlement = True
                    assert run('issue-controller',output)=='503'
                    assert not (output/'response').exists()
                    assert lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='SETTLED'
                    assert db.sql("SELECT state FROM issuer_lightning_quotes WHERE payment_hash=decode('"+payment_hash+"','hex')")=='2'
                    start_server(enabled=False)
                    await_value(lambda:db.sql("SELECT state FROM issuer_lightning_quotes WHERE payment_hash=decode('"+payment_hash+"','hex')"),lambda value:value=='3',timeout=10)
                if name=='prepared-integrity-and-worker':
                    servers.reject_settlement = True
                    assert run('issue-controller',output)=='503'
                    assert not (output/'response').exists()
                    assert lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='ACCEPTED'
                    where = " WHERE payment_hash=decode('"+payment_hash+"','hex')"
                    assert db.sql('SELECT state FROM issuer_lightning_quotes'+where)=='2'
                    authentication = db.sql("SELECT encode(prepared_signature,'hex') FROM issuer_lightning_quotes"+where)
                    db.sql("UPDATE issuer_lightning_quotes SET prepared_signature=decode(repeat('00',64),'hex'),next_attempt=0"+where)
                    attempts = servers.counts['settle']
                    start_server(enabled=False)
                    # A claimed corrupt row must neither reveal its preimage nor
                    # release a response, and must leave later rows retryable.
                    await_value(lambda:db.sql('SELECT next_attempt>0 FROM issuer_lightning_quotes'+where),lambda value:value=='t',timeout=10)
                    assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='503'
                    assert not (output/'response').exists()
                    assert servers.counts['settle']==attempts
                    assert lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='ACCEPTED'
                    db.sql("UPDATE issuer_lightning_quotes SET prepared_signature=decode('"+authentication+"','hex'),next_attempt=0"+where)
                    start_server(enabled=False)
                    await_value(lambda:db.sql('SELECT state FROM issuer_lightning_quotes'+where),lambda value:value=='3',timeout=10)
                    assert servers.counts['settle']==attempts+1
                assert run('issue-controller',output)=='200'
                payment.result(timeout=45)
            response = (output/'response').read_text()
            before = dict(servers.counts)
            assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='200'
            assert (output/'response').read_text()==response and before==servers.counts
            run('finalize',output)
            assert db.sql("SELECT count(*) FROM issuer_lightning_revenue r JOIN issuer_lightning_quotes q USING(quote_id) WHERE q.payment_hash=decode('"+payment_hash+"','hex') AND q.state=3 AND r.received_msat=5000000")=='1'
            results.append(name)
            tokens_verified += 100
            print('Verified '+name+': 100 usable credits; exact durable replay',flush=True)
        native_evidence = None
        if os.environ.get('MORSE_LIGHTNING_IOS_PROOF') == '1':
            seed = json.loads((work/'bootstrap.json').read_text())
            witness = 'outside '+seed['witness_key']+' Test'
            trust = '\n'.join(['3',seed['service_key'],'22'*32,'16','1','1',witness,'-','0','https://credits.example','2','1','1',witness])
            output = work/'native-ios'
            output.mkdir()
            with CreditIOSProof(PRODUCT, work, trust) as native:
                native.invoke('create')
                native.invoke('admit',body=bytes.fromhex(seed['evidence0']))
                prepared = packet_fields(native.invoke('prepare'))
                assert prepared[0] == b'\x02MCP' and prepared[2] == b'\0' and prepared[9] == b'\2'
                purchase_id = prepared[1]
                (output/'quote-request').write_text(prepared[7].hex())
                assert run('quote-controller',output)=='200'
                signed = bytes.fromhex((output/'quote').read_text())
                corrupt = signed[:-1]+bytes([signed[-1]^1])
                native.invoke('quote',id=purchase_id,body=corrupt,rejected=True)
                assert packet_fields(native.invoke('recover',id=purchase_id))[2]==b'\0'
                assert packet_fields(native.invoke('quote',id=purchase_id,body=signed))[2]==b'\1'
                uri = native.invoke('handoff',id=purchase_id).decode()
                assert uri.startswith('lightning:lnbcrt')
                saved = packet_fields(native.invoke('recover',id=purchase_id))
                assert saved[2]==b'\2'
                issue_body = saved[7]
                assert issue_body[:4] == b'\x01LIR'
                # Actual app termination after the native handoff cannot lose
                # the blind batch or replace a payment with an unknown outcome.
                native.restart()
                assert packet_fields(native.invoke('recover',id=purchase_id))[7] == issue_body
                assert native.invoke('handoff',id=purchase_id).decode()==uri
                (output/'issue-request').write_text(issue_body.hex())
                assert run('issue-controller',output)=='425'
                payment_hash = issue_body[36:68].hex()
                with ThreadPoolExecutor(max_workers=1) as executor:
                    payment = executor.submit(lnd.pay,uri[len('lightning:'):])
                    await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda value:value['state']=='ACCEPTED')
                    assert run('issue-controller',output)=='200'
                    payment.result(timeout=45)
                response = bytes.fromhex((output/'response').read_text())
                native.invoke('finalize',id=purchase_id,body=response[:-1]+bytes([response[-1]^1]),rejected=True)
                assert packet_fields(native.invoke('recover',id=purchase_id))[2]==b'\2'
                finished = packet_fields(native.invoke('finalize',id=purchase_id,body=response))
                assert finished[2]==b'\3'
                assert packet_fields(native.invoke('finalize',id=purchase_id,body=response))[4] == finished[4]
                native.restart()
                assert packet_fields(native.invoke('recover',id=purchase_id))[2]==b'\3'
                balance = packet_fields(native.invoke('balance'))
                assert balance[0] == b'\x03MCB'
                assert [int.from_bytes(field,'big') for field in balance[1:6]]==[0,100,0,0,0]
                # A second invoice is canceled after the native handoff. The
                # previous successful purchase and its 100 credits stay intact.
                second = packet_fields(native.invoke('prepare'))
                second_id = second[1]
                assert second_id != purchase_id and second[2] == b'\0'
                (output/'quote-request').write_text(second[7].hex())
                assert run('quote-controller',output)=='200'
                native.invoke('quote',id=second_id,body=bytes.fromhex((output/'quote').read_text()))
                native.invoke('handoff',id=second_id)
                second_issue = packet_fields(native.invoke('recover',id=second_id))[7]
                (output/'issue-request').write_text(second_issue.hex())
                second_hash = second_issue[36:68].hex()
                lnd.lnd('issuer','/v2/invoices/cancel',{'payment_hash':base64.b64encode(bytes.fromhex(second_hash)).decode()})
                assert run('issue-controller',output,MORSE_LN_ENABLED='false')=='200'
                cancellation = bytes.fromhex((output/'response').read_text())
                native.invoke('finalize',id=purchase_id,body=cancellation,rejected=True)
                native.invoke('finalize',id=second_id,body=cancellation[:-1]+bytes([cancellation[-1]^1]),rejected=True)
                native.restart()
                assert packet_fields(native.invoke('recover',id=second_id))[2] == b'\2'
                canceled = packet_fields(native.invoke('finalize',id=second_id,body=cancellation))
                assert canceled[2] == b'\4' and canceled[6] == canceled[7] == b''
                assert packet_fields(native.invoke('finalize',id=second_id,body=cancellation))[4] == canceled[4]
                native.invoke('finalize',id=second_id,body=response,rejected=True)
                native.restart()
                assert packet_fields(native.invoke('recover',id=second_id))[2] == b'\4'
                assert [int.from_bytes(field,'big') for field in packet_fields(native.invoke('balance'))[1:6]]==[0,100,0,0,0]
                third = packet_fields(native.invoke('prepare'))
                assert third[2] == b'\0' and third[1] not in (purchase_id, second_id)
                assert packet_fields(native.invoke('recover',id=second_id))[2] == b'\4'
                assert db.sql("SELECT count(*) FROM issuer_lightning_revenue r JOIN issuer_lightning_quotes q USING(quote_id) WHERE q.payment_hash=decode('"+second_hash+"','hex')") == '0'

            results.append('native-ios-journal-handoff-restart')
            tokens_verified += 100
            native_evidence = {'platform':'iOS Simulator','verified_tokens':100,'availability':'ten-minute native delay enforced',
                'input_hashes':native.input_hashes,
                'cases':['forged signed quote refused','claim durable before verified invoice handoff','actual process restart preserves exact blind batch',
                    'real LND settled payment','forged blind response refused','native finalization and duplicate replay','process restart preserves credit balance', 'forged and cross-purchase cancellation refused', 'signed cancellation survives native restart', 'fresh native blind batch allowed only after authenticated cancellation'],
                'transport_limit':'Owned Python coordinator relays issuer responses; native TLS domain transport and external wallet application launch are not covered'}
            print('Verified native iOS journal against real LND: 100 delayed credits; handoff/restart/replay',flush=True)
        # Optional owned native action proof. The default issuer/TLS path is
        # unchanged. Test signer values stay in memory and must not be archived.
        if native_tls_extension is not None:
            start_server(enabled=True)
            extension_work = work/'native-action-extension'
            extension_work.mkdir()
            extension_evidence = native_tls_extension(PRODUCT, extension_work,
                json.loads((work/'bootstrap.json').read_text()), lnd,
                issuer_origin, start_server, env, PROOF/'native-action-extension')
            (PROOF/'native-action-extension.json').write_text(json.dumps(extension_evidence,indent=2)+'\n')
        tls_results = {}
        for platform in ('ios', 'android'):
            if os.environ.get('MORSE_LIGHTNING_'+platform.upper()+'_TLS_PROOF') != '1':
                continue
            start_server(enabled=True)
            tls_work = work/('native-tls-'+platform)
            tls_work.mkdir()
            tls_evidence = prove_native_tls(PRODUCT,tls_work,json.loads((work/'bootstrap.json').read_text()),lnd,issuer_origin,start_server,platform,PROOF/('native-'+platform))
            tls_results[platform] = tls_evidence
            (PROOF/('native-'+platform+'-https.json')).write_text(json.dumps(tls_evidence,indent=2)+'\n')
            canceled_hash = tls_evidence['canceled_payment_hash']
            assert db.sql("SELECT count(*) FROM issuer_lightning_revenue r JOIN issuer_lightning_quotes q USING(quote_id) WHERE q.payment_hash=decode('"+canceled_hash+"','hex')") == '0'
            results.append('native-'+platform+'-https-purchase-cancellation-restart')
            tokens_verified += 100
            print('Verified direct native '+platform+' HTTPS: pinned CA,100 delayed credits, exact claim retry, canceled invoice and process restarts',flush=True)
        artifact = {'proof':'owned_bitcoin_lnd_postgres_mesh_http_credit_issuance','cases':results,'tokens_verified':tokens_verified,'live_funds':False,
            'oracle_limit':'Injected fully verified Pyth-account fixture, not guardian proof',
            'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'server_sha256':hashlib.sha256(server_binary.read_bytes()).hexdigest(),
            'backend_calls':servers.counts,'native_ios':native_evidence,'native_ios_tls':tls_results.get('ios'),'native_android_tls':tls_results.get('android')}
        artifact_name = 'lightning-issuance-local.json' if selected_cases == all_cases else 'lightning-issuance-selected-local.json'
        (PROOF/artifact_name).write_text(json.dumps(artifact,indent=2)+'\n')
        print(json.dumps(artifact),flush=True)


if __name__=='__main__':
    main()
