#!/usr/bin/env python3
"""Owned dual-native retention spend/recovery, with real credit maturity.

Composes the production issuer/LND proof through its optional test extension.
No browser, computer-use, screen capture, clock bypass, live funds, or mobile
private-key export is used. Runtime fixture keys never enter archived logs.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import hashlib
import http.client
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from attachment_android_proof import AttachmentAndroidProof
from credit_ios_proof import CreditIOSProof, packet_fields
from credit_tls_ingress import CreditTLSIngress
from lightning_regtest import await_value

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent
MODULE = PRODUCT/'apps/mobile/modules/mesh-messenger'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


account = load('retention_account_helpers', PRODUCT/'scripts/prove-account-http-native.py')


class RetentionIOSProof(CreditIOSProof):
    bundle = 'app.morse.retention.proof.ios'


class RetentionAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.retention.proof.android'
    instrumentation_class = 'RetentionProofTest'


class CorePeer:
    def __init__(self, binary, db, log, fixture_env):
        self.binary, self.db, self.log, self.fixture_env = binary, db, log, fixture_env
        self.port = account.available_port()

    def __enter__(self):
        self.output = self.log.open('wb')
        env = dict(os.environ, MESSENGER_DATABASE_URL=self.db.url, MESSENGER_PORT=str(self.port),
            MESSENGER_ABUSE_DIFFICULTY='1', MESSENGER_ABUSE_BASE_DIFFICULTY='1', MESSENGER_SIGNUP_DIFFICULTY='1',
            MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX=self.fixture_env['MORSE_HTTP_SERVICE_SEED'],
            MESSENGER_DELIVERY_SEALING_SEED_HEX='77'*32, MESSENGER_DELIVERY_INTERNAL_TOKEN='a'*32,
            MORSE_RETENTION_PROOF_WITNESS=self.fixture_env['MORSE_HTTP_WITNESS_SEED'],
            MESSENGER_CREDITS_PURPOSE='test', MORSE_PAID_RETENTION='on', MORSE_PAID_SIGNUP='off',
            MORSE_PAID_POSTAGE='off')
        self.process = subprocess.Popen([str(self.binary)], env=env, stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+30
        while time.monotonic()<deadline:
            if self.process.poll() is not None:
                self.__exit__(None,None,None)
                raise RuntimeError('owned retention core exited; see '+str(self.log))
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/health', timeout=1) as response:
                    if response.status==200:
                        return self
            except OSError:
                time.sleep(.05)
        self.__exit__(None,None,None)
        raise TimeoutError('owned retention core did not start')

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.output.close()


def build_core(output, compiler):
    frozen = ROOT/'.morse/witness-proof/account-http-native162-checkpoint/evidence/sources'
    sources = output/'core-sources'
    shutil.copytree(frozen, sources, dirs_exist_ok=True)
    old = str(ROOT/'.morse/witness-proof/account-http-native162/sources')
    for manifest in sources.glob('*/mesh.toml'):
        manifest.write_text(manifest.read_text().replace(old, str(sources)))
    service = sources/'directory-delivery'
    proof = service/'proof/retention_fixture.mpl'
    proof.parent.mkdir(exist_ok=True)
    proof.write_bytes((PRODUCT/'scripts/retention-proof/core_fixture.mpl.fixture').read_bytes())
    main = (service/'main.mpl').read_text()
    (service/'main.mpl').write_text('from Proof.RetentionFixture import proof_router\n'+
        main.replace('HTTP.serve(build_router(), port)', 'HTTP.serve(proof_router(build_router()), port)'))
    before = account.snapshot(sources)
    binary = output/'retention-core'
    command = [str(compiler),'build',str(service),'--opt-level','0','-o',str(binary)]
    with (output/'core-build.log').open('w') as log:
        result = subprocess.run(command, cwd=PRODUCT, stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode==0, 'retention core fixture build failed'
    assert account.snapshot(sources)==before
    report = json.loads(binary.with_name(binary.name+'.plaintext.json').read_text())
    assert all(row['source_sha256'] in before.values() for row in report['modules'])
    (output/'core-build.json').write_text(json.dumps(dict(command=command, sources=before,
        executable_sha256=account.sha(binary), compiled_modules=len(report['modules'])),indent=2)+'\n')
    return binary, service/'migrations'


def freeze_product(output):
    native = output/'native-product'
    source = ROOT/'.morse/witness-proof/device-http-native162-checkpoint/evidence/native-product'
    shutil.copytree(source, native, dirs_exist_ok=True)
    pins = json.loads((ROOT/'.morse/witness-proof/device-http-native162-checkpoint/evidence/native-inputs-freeze.json').read_text())
    for name,digest in pins.items():
        assert account.sha(native/'apps/mobile/modules/mesh-messenger'/name)==digest
    (output/'native-inputs-freeze.json').write_text(json.dumps(pins,indent=2)+'\n')
    # The issuer build uses an independent copy of every declared Mesh package.
    snapshot = output/'product-snapshot'
    original = ROOT/'.morse/witness-proof/account-http-native162-checkpoint/evidence/sources'
    for name in ['messenger-protocol','mesh-binary','mesh-solana','mesh-lightning']:
        shutil.copytree(original/name, snapshot/'packages'/name, dirs_exist_ok=True)
    manifest = snapshot/'packages/messenger-protocol/mesh.toml'
    manifest.write_text('[package]\nname="messenger-protocol"\nversion="0.1.0"\n[dependencies]\n'+
        ''.join(name+'={path="'+str(snapshot/'packages'/name)+'"}\n' for name in ['mesh-binary','mesh-solana','mesh-lightning']))
    if not (snapshot/'apps').exists():
        (snapshot/'apps').symlink_to(native/'apps',target_is_directory=True)
    public = snapshot.parent/'mesh-lang/packages'
    public.mkdir(parents=True,exist_ok=True)
    for name in ['mesh-binary','mesh-solana','mesh-lightning']:
        if not (public/name).exists():
            (public/name).symlink_to(snapshot/'packages'/name,target_is_directory=True)
    return native, snapshot


def balance(native):
    fields = packet_fields(native.invoke('balance'))
    assert len(fields)==8 and fields[0]==b'\3MCB' and fields[6]==b'\1' and fields[7]==b'\2'
    assert all(len(value)==4 for value in fields[1:6])
    return [int.from_bytes(value,'big') for value in fields[1:4]]


def wait_until(deadline, label):
    printed = 0
    while time.monotonic()<deadline:
        remaining = deadline-time.monotonic()
        if time.monotonic()>=printed:
            print(label+': '+str(round(remaining))+' seconds remain',flush=True)
            printed = time.monotonic()+30
        time.sleep(min(2, remaining))


def extension(output, native_product, core_binary, migrations):
    def run(_product, work, seed, lnd, issuer_origin, set_mode, fixture_env, _artifact_dir):
        evidence = output/'native-retention'
        evidence.mkdir()
        states, completed, cases = {}, {}, []
        with ExitStack() as stack:
            db = stack.enter_context(account.Database(migrations))
            witness_key = seed['witness_key']
            assert len(witness_key)==64 and bytes.fromhex(witness_key)
            db.sql("INSERT INTO transparency_witness_registry (witness_id,public_key,operator,status,software,morse_run) VALUES ('outside',decode('"+witness_key+"','hex'),'Owned local proof','pinned','mesh',true)")
            peer = stack.enter_context(CorePeer(core_binary, db, evidence/'core.log', fixture_env))
            modes = dict(tamper=False, drop=False, unavailable=False)
            receipts = []
            trace = []
            def handler(request, body):
                route = request.path
                core_route = route in ['/v1/credits/issuer','/v1/credits/signup-policy','/v1/credits/retention','/v1/credits/reconcile']
                if not core_route:
                    assert route in ['/v1/credits/lightning/quote','/v1/credits/lightning/issue']
                if route=='/v1/credits/retention' and modes['unavailable']:
                    modes['unavailable']=False
                    return request.respond(503,b'')
                target = f'http://127.0.0.1:{peer.port}'+route if core_route else issuer_origin+'/internal'+route
                headers = {'Content-Type':'application/octet-stream','Cache-Control':'no-store'}
                if not core_route:
                    headers['Authorization']='Bearer '+'b'*32
                upstream = urllib.request.Request(target,data=body,headers=headers)
                try:
                    with urllib.request.urlopen(upstream,timeout=30) as reply:
                        status,content = reply.status,reply.read(600001)
                except urllib.error.HTTPError as error:
                    status,content = error.code,error.read(600001)
                assert len(content)<=600000
                # The emulator clock trails the host by about half a second.
                # Real forwarding latency keeps an honestly signed fresh SPY
                # from arriving before its issued_at; verification is unchanged.
                if route=='/v1/credits/signup-policy' and status==200:
                    assert len(content)==88
                    time.sleep(1.1)
                trace.append(dict(route=route,status=status,request_sha256=hashlib.sha256(body).hexdigest(),
                    response_sha256=hashlib.sha256(content).hexdigest(),response_bytes=len(content)))
                (evidence/'http-trace.json').write_text(json.dumps(trace,indent=2)+'\n')
                if route in ['/v1/credits/retention','/v1/credits/reconcile'] and status in (200,201):
                    receipts.append(dict(route=route,status=status,bytes=len(content),sha256=hashlib.sha256(content).hexdigest()))
                    if modes['drop']:
                        modes['drop']=False
                        request.close_connection=True
                        request.connection.close()
                        return
                    if modes['tamper']:
                        modes['tamper']=False
                        content=content[:-1]+bytes([content[-1]^1])
                return request.respond(status,content)
            ingress = stack.enter_context(CreditTLSIngress(work,issuer_origin,seed,handler))
            trust = '\n'.join(['3',seed['service_key'],'22'*32,'1','1','1',
                'outside '+witness_key+' Test','-','0',ingress.origin,'2','1','1','outside '+witness_key+' Test'])
            core_origin = f'http://127.0.0.1:{peer.port}'
            pins = '\n'.join(['2','1',core_origin,ingress.origin,ingress.origin,
                core_origin.replace('http:','ws:')+'/v1/mailbox/stream','1'])
            for platform,runner,ext in [('ios',RetentionIOSProof,'swift'),('android',RetentionAndroidProof,'kt')]:
                folder=work/platform;folder.mkdir()
                source=MODULE/platform/'retention-proof'/('RetentionProof.'+ext)
                kwargs=dict(proof_source=source,network_config=pins,artifact_dir=evidence/platform/'native')
                if platform=='android':
                    kwargs.update(credit_purpose='test',lightning_network='regtest')
                native=stack.enter_context(runner(native_product,folder,trust,issuer_tls_root=ingress.resource(),**kwargs))
                if platform=='android':
                    native.device('reverse',f'tcp:{peer.port}',f'tcp:{peer.port}')
                    stack.callback(native.device,'reverse','--remove',f'tcp:{peer.port}',check=False)
                native.invoke('create',body=('retention_'+platform).encode())
                assert native.invoke('register')==b'\1DRG\0@\0'
                states[platform]=dict(native=native,cases=[],input_hashes=native.input_hashes)
            # The normal Mesh cutover functions seal/cosign/copy the two real
            # native registrations. No fabricated checkpoint/cutover row.
            request=urllib.request.Request(core_origin+'/proof/admit',data=bytes.fromhex(seed['issuer']))
            with urllib.request.urlopen(request,timeout=30) as reply:
                admission=reply.read(600000)
            (evidence/'issuer-admission.bin').write_bytes(admission)
            assert db.sql('SELECT phase FROM transparency_log_cutover')=='active'
            assert db.sql('SELECT count(*) FROM credit_issuer_announcements WHERE admitted_at IS NOT NULL')=='1'
            for platform,state in states.items():
                native=state['native']
                native.invoke('discover')
                prepared=packet_fields(native.invoke('prepare'))
                purchase=prepared[1]
                try:
                    native.invoke('continue',id=purchase)
                except AssertionError as error:
                    detail=error.args[0] if error.args else None
                    assert isinstance(detail,dict) and detail.get('error')=='lightning_quote_request_mismatch',detail
                    assert packet_fields(native.invoke('recover',id=purchase))[7]==prepared[7]
                    time.sleep(1.1)
                    native.invoke('continue',id=purchase)
                uri=native.invoke('handoff',id=purchase).decode()
                claim=packet_fields(native.invoke('recover',id=purchase))[7]
                assert uri.startswith('lightning:lnbcrt') and claim[:4]==b'\1LIR'
                payment_hash=claim[36:68].hex()
                with ThreadPoolExecutor(max_workers=1) as executor:
                    payment=executor.submit(lnd.pay,uri[len('lightning:'):])
                    await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda row:row['state']=='ACCEPTED')
                    assert packet_fields(native.invoke('continue',id=purchase))[2]==b'\3'
                    payment.result(timeout=45)
                state['finalized_monotonic']=time.monotonic()
                state['payment_hash']=payment_hash
                assert balance(native)==[0,100,0]
                error=native.invoke('retention',body=(32).to_bytes(4,'big'),rejected=True)
                assert 'insufficient_credit_balance' in error,error
                assert balance(native)==[0,100,0]
                state['cases'].append('real LND purchase finalizes100 OS-sealed tokens; premature paid retention refuses without a reservation')
            wait_until(max(state['finalized_monotonic'] for state in states.values())+602,'real native600-second credit maturity')
            pending_cancellations=[]
            for platform,state in states.items():
                native=state['native']
                assert time.monotonic()-state['finalized_monotonic']>=600
                native.restart()
                assert balance(native)==[100,0,0]
                state['actual_maturity_seconds']=round(time.monotonic()-state['finalized_monotonic'],3)
                plan=packet_fields(native.invoke('retention',body=(32).to_bytes(4,'big')))
                assert plan[0]==b'\1MCT' and plan[2]==b'\0'
                operation=plan[1]
                state['consumed_operation']=operation.hex()
                cap=plan[6]
                assert balance(native)==[90,0,10]
                modes['tamper']=True
                native.invoke('action',id=operation,body=b'\0',rejected=True)
                assert not modes['tamper'] and balance(native)==[90,0,10]
                native.restart()
                recovered=packet_fields(native.invoke('retention-recover',id=operation))
                assert recovered[6]==cap and recovered[2]==b'\0'
                modes['drop']=True
                assert 'credit_transport_unavailable' in native.invoke('action',id=operation,body=b'\2',rejected=True)
                assert not modes['drop']
                native.restart()
                assert packet_fields(native.invoke('retention-recover',id=operation))[6]==cap
                terminal=packet_fields(native.invoke('action',id=operation,body=b'\2'))
                assert terminal[2]==b'\1' and balance(native)==[90,0,0]
                marker=len(ingress.requests)
                assert packet_fields(native.invoke('action',id=operation,body=b'\2'))[2]==b'\1'
                assert len(ingress.requests)==marker
                state['cases'].append('pinned CAR forgery and dropped response preserve exact reservation across OS restart; production reconciliation returns original consumed receipt once')
                canceled=packet_fields(native.invoke('retention',body=(32).to_bytes(4,'big')))
                assert canceled[2]==b'\0' and canceled[1]!=operation
                cancel_cap=canceled[6]
                assert cancel_cap[:4]==b'\1CAP' and len(cancel_cap)>=121
                expires=int.from_bytes(cancel_cap[73:81],'big')
                modes['unavailable']=True
                assert 'credit_http_503' in native.invoke('action',id=canceled[1],body=b'\0',rejected=True)
                assert 'credit_http_425' in native.invoke('action',id=canceled[1],body=b'\2',rejected=True)
                assert balance(native)==[80,0,10]
                state['cancel_operation']=canceled[1]
                state['cancel_cap']=cancel_cap
                state['cancel_expires']=expires
                pending_cancellations.append(expires)
            delay=max(pending_cancellations)+1-time.time()
            wait_until(time.monotonic()+max(0,delay),'real signed-action expiry before cancellation')
            for platform,state in states.items():
                native=state['native'];operation=state['cancel_operation']
                assert balance(native)==[80,0,10], 'local expiry alone must not release tokens'
                modes['tamper']=True
                native.invoke('action',id=operation,body=b'\2',rejected=True)
                assert not modes['tamper'] and balance(native)==[80,0,10]
                native.restart()
                assert packet_fields(native.invoke('retention-recover',id=operation))[6]==state['cancel_cap']
                canceled=packet_fields(native.invoke('action',id=operation,body=b'\2'))
                assert canceled[2]==b'\2' and balance(native)==[90,0,0]
                native.restart()
                marker=len(ingress.requests)
                assert packet_fields(native.invoke('action',id=operation,body=b'\2'))[2]==b'\2'
                assert len(ingress.requests)==marker
                state['cases'].append('HTTP503 and local expiry keep tokens reserved; forged CCR refuses; real expired non-consumption proof restores exactly10 tokens and terminal restart performs no HTTP')
                completed[platform]=dict(platform=platform,status='passed_native_retention',cases=state['cases'],
                    input_hashes=state['input_hashes'],verified_tokens=100,final_balance=[90,0,0],
                    actual_maturity_seconds=state['actual_maturity_seconds'],
                    payment_hash=state['payment_hash'],cancel_expires=state['cancel_expires'],
                    consumed_operation=state['consumed_operation'],canceled_operation=operation.hex())
            assert db.sql('SELECT count(*) FROM credit_spent')=='20'
            assert db.sql('SELECT count(*) FROM credit_action_effects')=='2'
            assert db.sql('SELECT count(*) FROM credit_holds')=='2'
            assert db.sql('SELECT count(*) FROM messenger_mailboxes WHERE credit_retention_until_ms>0')=='2'
            assert not ingress.errors,ingress.errors
            result=dict(status='passed_dual_native_retention',platforms=completed,requests=ingress.requests,
                receipt_observations=receipts,server=dict(spent_tokens=20,effects=2,consumed_holds=2,retained_mailboxes=2),
                scope='Production native162 generated ABI/OS storage, issuer/LND and core retention/reconciliation. Real600s maturity and300s action expiry. One owned witness and local development core origin; native CA-pinned HTTPS paid actions. Signup-policy proxy adds1.1s real forwarding latency for emulator clock skew; signed freshness checks unchanged. No live funds, operator independence, physical-device or release claim; postage policy untouched.')
            (evidence/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
            (evidence/'issuer-ca-resource.bin').write_bytes(ingress.resource())
            (evidence/'native-security-config.txt').write_text(trust)
            (evidence/'native-network-config.txt').write_text(pins)
        return result
    return run


def main():
    output=Path(os.environ.get('MORSE_RETENTION_PROOF_DIR',ROOT/'.morse/witness-proof/retention-native162')).resolve()
    output.mkdir(parents=True,exist_ok=True)
    compiler=Path(os.environ.get('MESHC',ROOT/'.morse/native-reader-meshc.py')).resolve()
    native_product,snapshot=freeze_product(output)
    if (output/'core-build.json').exists():
        record=json.loads((output/'core-build.json').read_text())
        binary=output/'retention-core'
        migrations=output/'core-sources/directory-delivery/migrations'
        assert account.sha(binary)==record['executable_sha256']
        assert account.snapshot(output/'core-sources')==record['sources']
        assert account.sha(PRODUCT/'scripts/retention-proof/core_fixture.mpl.fixture')==record['sources']['directory-delivery/proof/retention_fixture.mpl']
    else:
        binary,migrations=build_core(output,compiler)
    os.environ.update(MESHC=str(compiler),MORSE_LIGHTNING_PROOF_DIR=str(output/'issuer'),
        MORSE_LIGHTNING_IOS_PROOF='0',MORSE_LIGHTNING_IOS_TLS_PROOF='0',MORSE_LIGHTNING_ANDROID_TLS_PROOF='0',
        MORSE_LIGHTNING_CASES='ordinary')
    os.environ.setdefault('MORSE_LIGHTNING_SERVICE_SOURCE',str(ROOT/'.morse/witness-proof/lightning-native162-qualified/sources/whatsdown/mesh-private-messenger/services/credit-issuer'))
    fixture=load('retention_lightning_driver',PRODUCT/'scripts/prove-credit-lightning.py')
    fixture.PRODUCT=snapshot
    fixture.ROOT=snapshot.parent
    fixture.main(native_tls_extension=extension(output,native_product,binary,migrations))


if __name__=='__main__':
    main()
