#!/usr/bin/env python3
"""Owned production-Core/native postage proof; no screen or live payment use."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from credit_ios_proof import CreditIOSProof, packet_fields
from attachment_android_proof import AttachmentAndroidProof
from credit_tls_ingress import CreditTLSIngress
from lightning_regtest import await_value

PRODUCT=Path(__file__).resolve().parents[1]
ROOT=PRODUCT.parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

retention=load('postage_retention_helpers',PRODUCT/'scripts/prove-retention-native.py')
account=retention.account

def freeze_inputs(output):
    native,snapshot=retention.freeze_product(output)
    sources=output/'core-sources'
    manifest_path=output/'source-inputs.json'
    if manifest_path.exists():
        previous=json.loads(manifest_path.read_text())
        assert account.snapshot(sources)==previous
    else:
        original=ROOT/'.morse/witness-proof/account-http-native162-checkpoint/evidence/sources'
        shutil.copytree(original,sources)
        old=str(ROOT/'.morse/witness-proof/account-http-native162/sources')
        for manifest in sources.glob('*/mesh.toml'):
            manifest.write_text(manifest.read_text().replace(old,str(sources)))
        # Freeze the production edge before concurrent application changes.
        shutil.copytree(PRODUCT/'services/privacy-edge',sources/'privacy-edge')
        (sources/'privacy-edge/mesh.toml').write_text('[package]\nname="postage-proof-edge"\nversion="0.1.0"\n[dependencies]\nmessenger-protocol={path="'+str(sources/'messenger-protocol')+'"}\n')
        manifest_path.write_text(json.dumps(account.snapshot(sources),indent=2)+'\n')
    return native,snapshot,sources


def build_backend(output,sources,compiler):
    service=sources/'directory-delivery'
    proof=service/'proof/postage_fixture.mpl'
    proof.parent.mkdir(exist_ok=True)
    proof.write_bytes((PRODUCT/'scripts/postage-platform-proof/core_fixture.mpl.fixture').read_bytes())
    main=service/'main.mpl'
    before=main.read_text()
    if 'from Proof.PostageFixture import proof_router' not in before:
        main.write_text('from Proof.PostageFixture import proof_router\n'+before.replace('HTTP.serve(build_router(), port)','HTTP.serve(proof_router(build_router()), port)'))
    frozen=account.snapshot(sources)
    (output/'source-inputs.json').write_text(json.dumps(frozen,indent=2)+'\n')
    results={}
    for name,package in [('postage-core',service),('postage-edge',sources/'privacy-edge')]:
        binary=output/name
        command=[str(compiler),'build',str(package),'--opt-level','0','-o',str(binary)]
        with (output/(name+'-build.log')).open('w') as log:
            result=subprocess.run(command,cwd=PRODUCT,stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0, name+' fixture build failed; see '+str(output/(name+'-build.log'))
        assert account.snapshot(sources)==frozen
        report=json.loads(binary.with_name(binary.name+'.plaintext.json').read_text())
        assert all(row['source_sha256'] in frozen.values() for row in report['modules'])
        results[name]=dict(command=command,sha256=account.sha(binary),compiled_modules=len(report['modules']))
    (output/'backend.json').write_text(json.dumps(dict(sources=frozen,executables=results),indent=2)+'\n')
    return output/'postage-core',output/'postage-edge',service/'migrations'


class PostageIOSProof(CreditIOSProof):
    bundle='app.morse.postage.proof.ios'

class PostageAndroidProof(AttachmentAndroidProof):
    bundle='app.morse.postage.proof.android'
    instrumentation_class='PostagePlatformProofTest'

class PostageCorePeer(retention.CorePeer):
    def __enter__(self):
        previous=os.environ.get('MORSE_PAID_INBOX_POSTAGE')
        os.environ['MORSE_PAID_INBOX_POSTAGE']='on'
        try:return super().__enter__()
        finally:
            if previous is None:os.environ.pop('MORSE_PAID_INBOX_POSTAGE',None)
            else:os.environ['MORSE_PAID_INBOX_POSTAGE']=previous

class EdgePeer:
    def __init__(self,binary,core_origin,issuer_origin,log):
        self.binary,self.core_origin,self.issuer_origin,self.log=binary,core_origin,issuer_origin,log
        self.port=account.available_port();self.origin=f'http://127.0.0.1:{self.port}'
    def __enter__(self):
        self.output=self.log.open('wb')
        env=dict(os.environ,MESSENGER_PRIVACY_EDGE_PORT=str(self.port),MESSENGER_ABUSE_DIFFICULTY='1',
            MESSENGER_DELIVERY_INTERNAL_URL=self.core_origin,MESSENGER_DELIVERY_INTERNAL_TOKEN='a'*32,
            MESSENGER_CREDIT_ISSUER_INTERNAL_URL=self.issuer_origin,MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN='b'*32)
        self.process=subprocess.Popen([str(self.binary)],env=env,stdout=self.output,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if self.process.poll() is not None:break
            try:
                with urllib.request.urlopen(self.origin+'/health',timeout=1) as response:
                    if response.status==200:return self
            except OSError:time.sleep(.05)
        self.__exit__(None,None,None)
        raise RuntimeError('owned postage edge did not start; see '+str(self.log))
    def __exit__(self,*_):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.output.close()

def vectors(*fields):
    return b''.join(len(field).to_bytes(4,'big')+field for field in fields)

def outbox_items(data):
    # Mobile.Codec uses a vector-wrapped count; CreditState does not.
    assert len(data)>=8 and int.from_bytes(data[:4],'big')==4
    count=int.from_bytes(data[4:8],'big');assert count<=64
    offset=8;fields=[]
    for _ in range(count):
        assert offset+4<=len(data)
        size=int.from_bytes(data[offset:offset+4],'big');offset+=4
        assert size>0 and offset+size<=len(data)
        fields.append(data[offset:offset+size]);offset+=size
    assert offset==len(data)
    return fields

def postage_payload(packed):
    assert len(packed)>=20 and packed[:4]==b'\1PWR'
    size=int.from_bytes(packed[16:20],'big')
    assert size<=541865 and len(packed)==20+size
    return packed[20:]

def fund_and_mature(states,lnd):
    for state in states.values():
        native=state['native'];native.invoke('discover')
        prepared=packet_fields(native.invoke('prepare'));purchase=prepared[1]
        try:native.invoke('continue',id=purchase)
        except AssertionError as error:
            detail=error.args[0] if error.args else None
            assert isinstance(detail,dict) and detail.get('error')=='lightning_quote_request_mismatch',detail
            assert packet_fields(native.invoke('recover',id=purchase))[7]==prepared[7]
            time.sleep(1.1);native.invoke('continue',id=purchase)
        uri=native.invoke('handoff',id=purchase).decode()
        claim=packet_fields(native.invoke('recover',id=purchase))[7]
        assert uri.startswith('lightning:lnbcrt') and claim[:4]==b'\1LIR'
        payment_hash=claim[36:68].hex()
        with ThreadPoolExecutor(max_workers=1) as executor:
            payment=executor.submit(lnd.pay,uri[len('lightning:'):])
            await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda row:row['state']=='ACCEPTED')
            assert packet_fields(native.invoke('continue',id=purchase))[2]==b'\3'
            payment.result(timeout=45)
        state.update(finalized_monotonic=time.monotonic(),payment_hash=payment_hash)
        assert retention.balance(native)==[0,100,0]
        early=packet_fields(native.invoke('postage-preview',body=vectors(state['devices'],state['ids'][0])))
        assert early[11]==bytes(4) and early[9]==b'\0\1'
    retention.wait_until(max(row['finalized_monotonic'] for row in states.values())+602,
        'real native600-second postage credit maturity')
    for state in states.values():
        native=state['native'];native.restart()
        assert retention.balance(native)==[100,0,0]
        state['actual_maturity_seconds']=round(time.monotonic()-state['finalized_monotonic'],3)


def refresh_native_recipient(core_origin,states,username):
    request=urllib.request.Request(core_origin+'/proof/refresh-witness',data=b'')
    with urllib.request.urlopen(request,timeout=30) as reply:assert reply.status==200
    for state in states.values():
        state['devices']=state['native'].invoke('resolve',body=username)


def prepare_postage(state):
    native=state['native']
    preview=packet_fields(native.invoke('postage-preview',body=vectors(state['devices'],state['ids'][0])))
    assert len(preview)==13 and preview[0]==b'\1MPB' and preview[9]==b'\0\1'
    assert len(packet_fields(preview[6]))==8 and int.from_bytes(preview[11],'big')>=1
    nonce=preview[1]
    plan=packet_fields(native.invoke('postage-prepare',body=vectors(nonce,state['devices'],preview[6])))
    assert len(plan)==9 and plan[0]==b'\1MPS' and plan[1]==nonce and plan[3]==b'\0' and plan[4]==b'\0\1'
    return nonce,plan,postage_payload(plan[8])


def prove_paid_postage(states,db,lnd,core_origin,username,ingress,modes):
    fund_and_mature(states,lnd)
    refresh_native_recipient(core_origin,states,username)
    for state in states.values():
        native=state['native'];nonce,plan,batch=prepare_postage(state)
        state.update(nonce=nonce,operation=plan[2],batch=batch)
        assert retention.balance(native)==[99,0,1]
        assert outbox_items(native.invoke('outbox'))==[]
        owned=packet_fields(native.invoke('drain',body=b'\0'))
        assert owned[2]==b'\0\0' and owned[3]==b'\0\0'
        modes['tamper']=True
        native.invoke('postage-continue',id=nonce,rejected=True)
        assert not modes['tamper'] and retention.balance(native)==[99,0,1]
        native.restart()
        assert postage_payload(packet_fields(native.invoke('postage-recover',id=nonce))[8])==batch
        modes['drop']=True
        assert 'credit_transport_unavailable' in native.invoke('postage-continue',id=nonce,rejected=True)
        assert not modes['drop'] and retention.balance(native)==[99,0,1]
        native.restart()
        assert postage_payload(packet_fields(native.invoke('postage-recover',id=nonce))[8])==batch
        consumed=packet_fields(native.invoke('postage-continue',id=nonce))
        assert consumed[3]==b'\1' and retention.balance(native)==[99,0,0]
        assert outbox_items(native.invoke('outbox'))==[]
        marker=len(ingress.requests)
        assert packet_fields(native.invoke('postage-continue',id=nonce))[3]==b'\1'
        assert len(ingress.requests)==marker
    for state in states.values():
        native=state['native']
        message=vectors(username,b'\1',b'owned canceled postage message',b'',b'')
        assert native.invoke('fanout',id=state['profile'],body=message)==b'\1FNO\0'
        drain=packet_fields(native.invoke('drain',body=b'\0'))
        ids=packet_fields(drain[4]);assert len(ids)==8
        state['ids']=ids
        nonce,plan,batch=prepare_postage(state)
        assert nonce!=state['nonce'] and retention.balance(native)==[98,0,1]
        rows=packet_fields(native.invoke('postage-inventory'))
        assert rows[0]==b'\1MPI'
        inventory=[packet_fields(row) for row in rows[3:]]
        selected=[row for row in inventory if row[0]==nonce]
        assert len(selected)==1 and selected[0][5]==b'\0'
        expires=int.from_bytes(selected[0][7],'big')
        state.update(cancel_nonce=nonce,cancel_operation=plan[2],cancel_batch=batch,cancel_expires=expires)
        modes['unavailable']=True
        assert 'credit_http_503' in native.invoke('postage-continue',id=nonce,rejected=True)
        assert not modes['unavailable'] and retention.balance(native)==[98,0,1]
        native.restart()
        assert postage_payload(packet_fields(native.invoke('postage-recover',id=nonce))[8])==batch
    delay=max(state['cancel_expires'] for state in states.values())+2-time.time()
    retention.wait_until(time.monotonic()+max(0,delay),'real postage action expiry before encrypted cancellation')
    refresh_native_recipient(core_origin,states,username)
    for state in states.values():
        native=state['native'];nonce=state['cancel_nonce']
        assert retention.balance(native)==[98,0,1], 'local expiry must not release postage credits'
        modes['tamper']=True
        native.invoke('postage-continue',id=nonce,rejected=True)
        assert not modes['tamper'] and retention.balance(native)==[98,0,1]
        native.restart()
        assert postage_payload(packet_fields(native.invoke('postage-recover',id=nonce))[8])==state['cancel_batch']
        canceled=packet_fields(native.invoke('postage-continue',id=nonce))
        assert canceled[3]==b'\2' and retention.balance(native)==[99,0,0]
        assert len(outbox_items(native.invoke('outbox')))==8
        native.restart();marker=len(ingress.requests)
        assert packet_fields(native.invoke('postage-continue',id=nonce))[3]==b'\2'
        assert len(ingress.requests)==marker
    assert db.sql('SELECT count(*) FROM credit_spent')=='2'
    assert db.sql('SELECT count(*) FROM credit_action_effects WHERE action_kind=3')=='2'
    assert db.sql('SELECT count(*) FROM messenger_envelopes')=='16'
    return dict(status='passed_dual_native_postage',platforms={name:dict(input_hashes=state['input_hashes'],
        verified_tokens=100,actual_maturity_seconds=state['actual_maturity_seconds'],final_balance=[99,0,0],
        account_wide_credits=1,recipient_device_enqueues=8,payment_hash=state['payment_hash'],
        operation=state['operation'].hex(),canceled_operation=state['cancel_operation'].hex(),batch_sha256=hashlib.sha256(state['batch']).hexdigest(),
        cases=['actual LND purchase and OS restart after real600s maturity',
            'one native account-wide credit reservation for8authenticated devices',
            'real Core encrypted receipt tamper/drop and exact sealed-batch restart recovery',
            'one server effect and8enqueues; exact original outbox ACK and terminal noHTTPS',
            'second distinct message503/real expiry, encrypted CCR tamper/restart/release and terminal noHTTPS']) for name,state in states.items()},
        server=dict(spent_tokens=2,postage_effects=2,enqueued_envelopes=16),requests=ingress.requests,
        scope='Actual production162Swift/Kotlin/JNI/Keychain/Keystore, Core and privacy-edge; native CA-pinned paid HTTPS and development HTTP directory/ordinary delivery. Eight externally owned hybrid recipient devices, not eight mobile clients. Real600s maturity and real action expiry; no live funds, operator independence, recipient decryption, physical device or release claim.')

def extension(output,native_product,core_binary,edge_binary,migrations,setup_only):
    def run(_product,work,seed,lnd,issuer_origin,set_mode,fixture_env,_artifact_dir):
        evidence=output/'native-postage';evidence.mkdir()
        states={};trace=[];modes=dict(tamper=False,drop=False,unavailable=False)
        with ExitStack() as stack:
            db=stack.enter_context(account.Database(migrations))
            witness=seed['witness_key']
            assert len(witness)==64 and bytes.fromhex(witness)
            db.sql("INSERT INTO transparency_witness_registry (witness_id,public_key,operator,status,software,morse_run) VALUES ('outside',decode('"+witness+"','hex'),'Owned local proof','pinned','mesh',true)")
            core=stack.enter_context(PostageCorePeer(core_binary,db,evidence/'core.log',fixture_env))
            core_origin=f'http://127.0.0.1:{core.port}'
            edge=stack.enter_context(EdgePeer(edge_binary,core_origin,issuer_origin,evidence/'edge.log'))
            def handler(request,body):
                assert request.path in ['/v1/credits/issuer','/v1/credits/signup-policy','/v1/credits/lightning/quote',
                    '/v1/credits/lightning/issue','/v1/credits/postage','/v1/credits/postage/reconcile']
                if request.path=='/v1/credits/postage' and modes['unavailable']:
                    modes['unavailable']=False
                    trace.append(dict(route=request.path,status=503,injected_before_upstream=True,
                        request_sha256=hashlib.sha256(body).hexdigest(),response_bytes=0))
                    (evidence/'http-trace.json').write_text(json.dumps(trace,indent=2)+'\n')
                    return request.respond(503,b'')
                upstream=urllib.request.Request(edge.origin+request.path,data=body,
                    headers={'Content-Type':'application/octet-stream','Cache-Control':'no-store'})
                try:
                    with urllib.request.urlopen(upstream,timeout=35) as reply:status,content=reply.status,reply.read(600001)
                except urllib.error.HTTPError as error:status,content=error.code,error.read(600001)
                assert len(content)<=600000
                if request.path=='/v1/credits/signup-policy' and status==200:time.sleep(1.1)
                trace.append(dict(route=request.path,status=status,request_sha256=hashlib.sha256(body).hexdigest(),
                    response_sha256=hashlib.sha256(content).hexdigest(),response_bytes=len(content)))
                (evidence/'http-trace.json').write_text(json.dumps(trace,indent=2)+'\n')
                if request.path in ['/v1/credits/postage','/v1/credits/postage/reconcile'] and status in [200,201]:
                    assert len(content)==564
                    if modes['drop']:
                        modes['drop']=False;request.close_connection=True;request.connection.close();return
                    if modes['tamper']:
                        modes['tamper']=False;content=content[:-1]+bytes([content[-1]^1])
                request.respond(status,content)
            ingress=stack.enter_context(CreditTLSIngress(work,issuer_origin,seed,handler))
            with urllib.request.urlopen(urllib.request.Request(core_origin+'/proof/bootstrap-recipient',data=b''),timeout=30) as reply:
                public=packet_fields((3).to_bytes(4,'big')+reply.read(4096))
            assert public[0]==b'postage-owner' and len(public[1])==32 and len(public[2])==32
            trust='\n'.join(['3',seed['service_key'],public[2].hex(),'1','1','1','outside '+witness+' Test','-',
                '0',ingress.origin,'2','1','1','outside '+witness+' Test'])
            pins='\n'.join(['2','1',core_origin,edge.origin,ingress.origin,core_origin.replace('http:','ws:')+'/v1/mailbox/stream','1'])
            for platform,runner,ext in [('ios',PostageIOSProof,'swift'),('android',PostageAndroidProof,'kt')]:
                folder=work/platform;folder.mkdir()
                source=PRODUCT/'apps/mobile/modules/mesh-messenger'/platform/'postage-platform-proof'/('PostagePlatformProof.'+ext)
                kwargs=dict(proof_source=source,network_config=pins,artifact_dir=evidence/platform/'native')
                if platform=='android':kwargs.update(credit_purpose='test',lightning_network='regtest')
                native=stack.enter_context(runner(native_product,folder,trust,issuer_tls_root=ingress.resource(),**kwargs))
                if platform=='android':
                    for port in [core.port,edge.port]:
                        native.device('reverse',f'tcp:{port}',f'tcp:{port}')
                        stack.callback(native.device,'reverse','--remove',f'tcp:{port}',check=False)
                native.invoke('create',body=('postage_'+platform).encode())
                assert native.invoke('register')==b'\1DRG\0@\0'
                states[platform]=dict(native=native,input_hashes=native.input_hashes)
            with urllib.request.urlopen(urllib.request.Request(core_origin+'/proof/admit',data=bytes.fromhex(seed['issuer'])),timeout=30) as reply:
                admission=reply.read(600000)
            (evidence/'issuer-admission.bin').write_bytes(admission)
            assert db.sql('SELECT phase FROM transparency_log_cutover')=='active'
            for platform,state in states.items():
                native=state['native'];profile=native.invoke('profile')
                devices=native.invoke('resolve',body=public[0])
                state.update(profile=profile,devices=devices)
                message=vectors(public[0],b'\1',b'owned postage platform message',b'',b'')
                assert native.invoke('fanout',id=profile,body=message)==b'\1FNO\0'
                assert len(outbox_items(native.invoke('outbox')))==8
                drain=packet_fields(native.invoke('drain',body=b'\0'))
                assert drain[0]==b'\1OBX' and drain[1]==b'\0' and int.from_bytes(drain[2],'big')==0
                ids=packet_fields(drain[4]);assert len(ids)==8 and all(len(id)==16 for id in ids)
                preview=packet_fields(native.invoke('postage-preview',body=vectors(devices,ids[0])))
                assert preview[0]==b'\1MPB' and len(preview)==13 and preview[9]==b'\0\1'
                assert len(packet_fields(preview[6]))==8 and preview[11]==bytes(4)
                state.update(ids=ids,preview=preview)
            if setup_only:
                assert db.sql('SELECT count(*) FROM credit_spent')=='0'
                result=dict(status='passed_native_postage_setup_only',platforms={name:dict(input_hashes=value['input_hashes'],
                    native_outbox_envelopes=8,witnessed_account_price=1) for name,value in states.items()},
                    requests=ingress.requests,scope='Actual native ABI/OS storage, real Core/edge, witnessed8-device recipient and native fanout/402/preview. No credit purchase, maturity or spend claim.')
            else:
                result=prove_paid_postage(states,db,lnd,core_origin,public[0],ingress,modes)
            assert not ingress.errors,ingress.errors
            (evidence/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
            (evidence/'issuer-ca-resource.bin').write_bytes(ingress.resource())
            (evidence/'native-security-config.txt').write_text(trust)
            (evidence/'native-network-config.txt').write_text(pins)
        return result
    return run

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--evidence',type=Path,default=ROOT/'.morse/witness-proof/postage-platform-native162')
    parser.add_argument('--compiler',type=Path,default=ROOT/'.morse/native-reader-meshc.py')
    parser.add_argument('--build-only',action='store_true')
    parser.add_argument('--setup-only',action='store_true')
    parser.add_argument('--run-name',default='setup-1')
    args=parser.parse_args()
    output=args.evidence.resolve();output.mkdir(parents=True,exist_ok=True)
    native,snapshot,sources=freeze_inputs(output)
    if (output/'backend.json').exists():
        record=json.loads((output/'backend.json').read_text())
        assert account.snapshot(sources)==record['sources']
        assert account.sha(PRODUCT/'scripts/postage-platform-proof/core_fixture.mpl.fixture')==record['sources']['directory-delivery/proof/postage_fixture.mpl']
        for name,row in record['executables'].items():assert account.sha(output/name)==row['sha256']
        core,edge,migrations=output/'postage-core',output/'postage-edge',sources/'directory-delivery/migrations'
    else:core,edge,migrations=build_backend(output,sources,args.compiler.resolve())
    if args.build_only:
        print(json.dumps(dict(status='built_owned_postage_fixture',core=str(core),edge=str(edge))))
        return
    assert args.run_name and '/' not in args.run_name and args.run_name not in ['.','..']
    run_output=output/'runs'/args.run_name;run_output.mkdir(parents=True,exist_ok=False)
    shutil.copyfile(Path(__file__),run_output/'driver.py')
    shutil.copyfile(PRODUCT/'scripts/postage-platform-proof/core_fixture.mpl.fixture',run_output/'core_fixture.mpl.fixture')
    os.environ.update(MESHC=str(args.compiler.resolve()),MORSE_LIGHTNING_PROOF_DIR=str(run_output/'issuer'),
        MORSE_LIGHTNING_IOS_PROOF='0',MORSE_LIGHTNING_IOS_TLS_PROOF='0',MORSE_LIGHTNING_ANDROID_TLS_PROOF='0',MORSE_LIGHTNING_CASES='ordinary')
    os.environ.setdefault('MORSE_LIGHTNING_SERVICE_SOURCE',str(ROOT/'.morse/witness-proof/lightning-native162-qualified/sources/whatsdown/mesh-private-messenger/services/credit-issuer'))
    fixture=load('postage_lightning_driver',PRODUCT/'scripts/prove-credit-lightning.py')
    fixture.PRODUCT=snapshot;fixture.ROOT=snapshot.parent
    fixture.main(native_tls_extension=extension(run_output,native,core,edge,migrations,args.setup_only))


if __name__=='__main__':main()
