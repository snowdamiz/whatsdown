#!/usr/bin/env python3
"""Real native regtest credits -> Core grant -> object store -> restart proof."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,shutil,socket,subprocess,sys,time,urllib.request,urllib.error
from build import verify_work,WIRE
PRODUCT=Path(__file__).resolve().parents[2];ROOT=PRODUCT.parent;HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(PRODUCT/'scripts'))
from credit_ios_proof import CreditIOSProof,packet_fields
from attachment_android_proof import AttachmentAndroidProof
from credit_tls_ingress import CreditTLSIngress
from lightning_regtest import await_value

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
postage=load('paid_attachment_postage_helpers',PRODUCT/'scripts/prove-postage-platform.py')
retention=postage.retention;account=retention.account
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
u32=lambda v:v.to_bytes(4,'big')
def private_port():
    while True:
        with socket.socket() as value:
            value.bind(('127.0.0.1',0));port=value.getsockname()[1]
        if port not in (55438,61546):return port
class IOS(CreditIOSProof):
    bundle='app.morse.paidattachment.proof.ios'
    def await_file(self,name,timeout=300):return super().await_file(name,timeout)
class Android(AttachmentAndroidProof):
    bundle='app.morse.paidattachment.proof.android'
    instrumentation_class='PaidAttachmentProofTest'
    def run(self,*command,**kwargs):
        if 'instrument' in command:kwargs.setdefault('timeout',300)
        return super().run(*command,**kwargs)
class ObjectPeer:
    def __init__(self,binary,db,root,core,service,log):
        self.binary,self.db,self.root,self.core,self.service,self.log=binary,db,root,core,service,log
        self.port=account.available_port();self.origin=f'http://127.0.0.1:{self.port}'
    def __enter__(self):
        self.root.mkdir(mode=0o700);self.output=self.log.open('wb')
        env=dict(os.environ,MESSENGER_OBJECT_DATABASE_URL=self.db.url,MESSENGER_OBJECT_STORAGE_ROOT=str(self.root),MESSENGER_OBJECT_CREDIT_CORE_URL=self.core,
          MESSENGER_OBJECT_CREDIT_SERVICE_PUBLIC_KEY_HEX=self.service,MESSENGER_OBJECT_WORK_DIFFICULTY='1',MESSENGER_OBJECT_INTERNAL_TOKEN='a'*32,
          MESSENGER_DELIVERY_INTERNAL_TOKEN='a'*32,MORSE_PAID_LARGE_ATTACHMENTS='on',MESSENGER_OBJECT_PORT=str(self.port),MESSENGER_JOBS_URL='')
        self.process=subprocess.Popen([str(self.binary)],env=env,stdout=self.output,stderr=subprocess.STDOUT)
        def ready():
            if self.process.poll() is not None:raise AssertionError('object-store exited: '+self.log.read_text()[-2000:])
            with urllib.request.urlopen(self.origin+'/health',timeout=2) as response:return response.status==200
        try:await_value(ready)
        except BaseException:
            self.__exit__(None,None,None)
            raise
        return self
    def __exit__(self,*_):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.output.close()

def attachment_inventory_row(encoded,nonce):
    inventory=packet_fields(encoded)
    assert len(inventory)>=2,'invalid attachment inventory fixture'
    matching=[]
    for encoded_row in inventory[2:]:
        row=packet_fields(encoded_row)
        assert len(row)>=8,'invalid attachment inventory row fixture'
        if row[0]==nonce:matching.append(row)
    assert len(matching)==1,'expected one exact attachment inventory row'
    return matching[0]

def extension(output,native_product,backend,postgres_ports,selected):
 def run(_product,work,seed,lnd,issuer_origin,_set_mode,fixture_env,_artifact_dir):
    WIRE.selection(recorded=selected)
    evidence=output/'native-paid-attachment';evidence.mkdir()
    states={};trace=[];modes={'grant':'normal','put':'normal','reconcile':'normal','get':'normal'}
    with ExitStack() as stack:
        db=stack.enter_context(account.Database(backend/'product-snapshot/services/directory-delivery/migrations'))
        empty=work/'empty-migrations';empty.mkdir();object_db=stack.enter_context(account.Database(empty))
        postgres_ports.extend([db.port,object_db.port]);assert len(set(postgres_ports))==3 and 55438 not in postgres_ports
        db.sql("INSERT INTO transparency_witness_registry(witness_id,public_key,operator,status,software,morse_run) VALUES('outside',decode('"+seed['witness_key']+"','hex'),'Owned local proof','pinned','mesh',true)")
        core=stack.enter_context(retention.CorePeer(backend/'directory-delivery',db,evidence/'core.log',fixture_env));core_origin=f'http://127.0.0.1:{core.port}'
        edge=stack.enter_context(postage.EdgePeer(backend/'privacy-edge',core_origin,issuer_origin,evidence/'edge.log'))
        objects=stack.enter_context(ObjectPeer(backend/'object-store',object_db,work/'objects',core_origin,seed['service_key'],evidence/'object-store.log'))
        def handler(request,body):
            route=request.path
            category='grant' if route=='/v1/attachments/paid-grant' else ('put' if request.command=='PUT' else ('get' if request.command=='GET' else ('reconcile' if route=='/v1/credits/reconcile' else None)))
            mode=modes.get(category,'normal')
            if mode=='503':
                modes[category]='normal';trace.append({'route':route,'method':request.command,'status':503,'injected_before_upstream':True,'request_sha256':hashlib.sha256(body).hexdigest()})
                (evidence/'http-trace.json').write_text(json.dumps(trace,indent=2)+'\n');return request.respond(503,b'')
            target=objects.origin if route.startswith('/v2/') or route=='/v1/attachments/paid-grant' else edge.origin
            assert target==objects.origin or route in ['/v1/credits/issuer','/v1/credits/signup-policy','/v1/credits/lightning/quote','/v1/credits/lightning/issue','/v1/credits/reconcile']
            headers={'Content-Type':'application/octet-stream','Cache-Control':'no-store'}
            capability=request.headers.get('X-Object-Capability')
            if capability is not None:headers['X-Object-Capability']=capability
            upstream=urllib.request.Request(target+route,data=body,method=request.command,headers=headers)
            try:
                with urllib.request.urlopen(upstream,timeout=35) as response:status,content=response.status,response.read(600001)
            except urllib.error.HTTPError as error:status,content=error.code,error.read(600001)
            assert len(content)<=600000
            if route=='/v1/credits/signup-policy' and status==200:time.sleep(1.1)
            trace.append({'route':route,'method':request.command,'status':status,'request_sha256':hashlib.sha256(body).hexdigest(),'response_sha256':hashlib.sha256(content).hexdigest(),'response_bytes':len(content),'injected_response':mode if mode!='normal' else None})
            (evidence/'http-trace.json').write_text(json.dumps(trace,indent=2)+'\n')
            if status in [200,201] and mode in ['drop','tamper']:
                modes[category]='normal'
                if mode=='drop':request.close_connection=True;request.connection.close();return
                content=content[:-1]+bytes([content[-1]^1])
            request.respond(status,content)
        ingress=stack.enter_context(CreditTLSIngress(work,issuer_origin,seed,handler))
        trust='\n'.join(['3',seed['service_key'],'22'*32,'1','1','1','outside '+seed['witness_key']+' Test','-','0',ingress.origin,'2','1','1','outside '+seed['witness_key']+' Test'])
        pins='\n'.join(['2','1',core_origin,edge.origin,ingress.origin,core_origin.replace('http:','ws:')+'/v1/mailbox/stream','1'])
        for platform,runner,ext in [('ios',IOS,'swift'),('android',Android,'kt')]:
            folder=work/platform;folder.mkdir()
            kwargs={'proof_source':HERE/'platform'/('PaidAttachmentProof.'+ext),'network_config':pins,'artifact_dir':evidence/platform/'native'}
            if platform=='android':kwargs.update(credit_purpose='test',lightning_network='regtest')
            native=stack.enter_context(runner(native_product,folder,trust,issuer_tls_root=ingress.resource(),**kwargs))
            if platform=='android':
                for port in [core.port,edge.port]:
                    native.device('reverse',f'tcp:{port}',f'tcp:{port}');stack.callback(native.device,'reverse','--remove',f'tcp:{port}',check=False)
            username=('paid_attachment_'+platform).encode();native.invoke('create',body=username)
            assert native.invoke('register')==b'\1DRG\0@\0'
            states[platform]={'native':native,'username':username,'input_hashes':native.input_hashes,'cases':[]}
        with urllib.request.urlopen(urllib.request.Request(core_origin+'/proof/admit',data=bytes.fromhex(seed['issuer'])),timeout=30) as response:assert response.status==200
        assert db.sql('SELECT phase FROM transparency_log_cutover')=='active'
        # Real native blind state + Keychain/Keystore custody; new wallets cannot
        # reuse another bundle's tokens or bypass the real600-second delay.
        for name,state in states.items():
            native=state['native'];native.invoke('discover');prepared=packet_fields(native.invoke('prepare'));purchase=prepared[1]
            try:native.invoke('continue',id=purchase)
            except AssertionError as error:
                detail=error.args[0] if error.args else None
                assert isinstance(detail,dict) and detail.get('error')=='lightning_quote_request_mismatch',detail
                assert packet_fields(native.invoke('recover',id=purchase))[7]==prepared[7]
                time.sleep(1.1);native.invoke('continue',id=purchase)
            uri=native.invoke('handoff',id=purchase).decode();claim=packet_fields(native.invoke('recover',id=purchase))[7]
            assert uri.startswith('lightning:lnbcrt') and claim[:4]==b'\1LIR';payment_hash=claim[36:68].hex()
            with ThreadPoolExecutor(max_workers=1) as executor:
                payment=executor.submit(lnd.pay,uri[len('lightning:'):])
                await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda row:row['state']=='ACCEPTED')
                assert packet_fields(native.invoke('continue',id=purchase))[2]==b'\3';payment.result(timeout=45)
            assert retention.balance(native)==[0,100,0]
            state.update(purchase=purchase,payment_hash=payment_hash,finalized=time.monotonic())
        retention.wait_until(max(s['finalized'] for s in states.values())+602,'real600-second native attachment credit maturity')
        with urllib.request.urlopen(urllib.request.Request(core_origin+'/proof/refresh-witness',data=b''),timeout=30) as response:assert response.status==200
        for name,state in states.items():
            native=state['native'];native.restart();assert retention.balance(native)==[100,0,0]
            profile=native.invoke('profile');ticket=native.invoke('authorize',id=profile,body=state['username']);assert ticket
            preview=packet_fields(native.invoke('attachment-preview'));nonce=preview[1]
            plan=packet_fields(native.invoke('attachment-prepare',id=nonce,body=ticket));assert len(plan)==12 and plan[3]==b'\0'
            assert retention.balance(native)==[99,0,1];before=len(trace)
            native.invoke('attachment-grant',id=nonce,body=ticket,rejected=True);assert len(trace)==before,'incomplete staged file reached network'
            wires=packet_fields(native.invoke('attachment-stage',id=nonce,body=bytes([selected['wire_profile']])));assert len(wires)==2
            write_shape=WIRE.check_new_write(selected,plan[9],wires[0],wires[1],paid=True,last_index=256)
            for mode in ['tamper','drop']:
                modes['grant']=mode;native.invoke('attachment-grant',id=nonce,body=ticket,rejected=True)
                assert modes['grant']=='normal' and retention.balance(native)==[99,0,1]
                native.restart();recovered=packet_fields(native.invoke('attachment-recover',id=nonce));assert recovered[7:]==plan[7:]
            accepted=packet_fields(native.invoke('attachment-grant',id=nonce,body=ticket));assert accepted[3]==b'\1' and accepted[7:]==plan[7:]
            assert retention.balance(native)==[99,0,0]
            modes['put']='drop';native.invoke('attachment-upload',id=nonce,body=u32(0),rejected=True);assert modes['put']=='normal'
            native.restart();assert packet_fields(native.invoke('attachment-recover',id=nonce))[8]==plan[8]
            assert native.invoke('attachment-upload-all',id=nonce)==u32(258)
            for attempt in range(16):
                if native.invoke('attachment-complete',id=nonce)==b'\1':break
            else:raise AssertionError('bounded object completion did not finish')
            assert native.invoke('fetch',id=u32(0),body=plan[8])==bytes([37])*65536
            native.restart();assert native.invoke('fetch',id=u32(256),body=plan[8])==bytes([37])
            modes['get']='tamper';native.invoke('fetch',id=u32(0),body=plan[8],rejected=True);assert modes['get']=='normal'
            marker=len(trace);assert packet_fields(native.invoke('attachment-grant',id=nonce,body=ticket))[3]==b'\1'
            assert len(trace)==marker+1,'completed object grant repair must replay exact authority'
            # A distinct fully staged upload is refused before Core consumes.
            cancel_started=time.monotonic();cancel_started_unix=time.time()
            second=packet_fields(native.invoke('attachment-preview'))[1]
            second_plan=packet_fields(native.invoke('attachment-prepare',id=second,body=ticket));assert second_plan[3]==b'\0'
            native.invoke('attachment-stage',id=second,body=bytes([selected['wire_profile']]))
            modes['grant']='503';native.invoke('attachment-grant',id=second,body=ticket,rejected=True);assert modes['grant']=='normal'
            assert retention.balance(native)==[98,0,1]
            cancel_row=attachment_inventory_row(native.invoke('attachment-inventory'),second)
            expires=int.from_bytes(cancel_row[7],'big')
            state.update(write_shape=write_shape,nonce=nonce,operation=plan[2],reference=plan[8],manifest_bytes=len(plan[9]),cancel_nonce=second,cancel_operation=second_plan[2],cancel_expires=expires,
              cancel_started_monotonic=cancel_started,cancel_started_unix=cancel_started_unix,
              actual_maturity_seconds=round(time.monotonic()-state['finalized'],3),cipher_first_sha256=hashlib.sha256(wires[0]).hexdigest(),cipher_last_sha256=hashlib.sha256(wires[1]).hexdigest())
            state['cases']+=['real regtest100nativecredits and600s maturity','actualsignedrecipientticket beforecreditreservation','incomplete filezeroHTTP','actualCore/object-store grant tamper/drop exactrestart','257persistedACH'+str(selected['wire_profile'])+'chunks and258objectparts','droppedmanifestPUT restart exactretry','actualboundedcomplete andnativeTLSfirstlastdownload','forgedciphertextrefused','fullystageddistinctgrant503 retainsreservation']
            print(json.dumps({'platform':name,'stage':'paid_upload_complete_and_cancel_pending'}),flush=True)
        assert db.sql('SELECT count(*) FROM credit_spent')=='2'
        assert db.sql('SELECT count(*) FROM credit_action_effects WHERE action_kind=1')=='2'
        assert object_db.sql('SELECT count(*) FROM large_objects WHERE completed=1')=='2'
        assert object_db.sql('SELECT count(*) FROM large_object_parts')=='516'
        retention.wait_until(time.monotonic()+max(0,max(s['cancel_expires'] for s in states.values())+2-time.time()),'real native attachment action expiry')
        with urllib.request.urlopen(urllib.request.Request(core_origin+'/proof/refresh-witness',data=b''),timeout=30) as response:assert response.status==200
        for name,state in states.items():
            state['actual_action_expiry_seconds']=round(time.monotonic()-state['cancel_started_monotonic'],3)
            assert state['actual_action_expiry_seconds']>=600
            native=state['native'];assert retention.balance(native)==[98,0,1]
            modes['reconcile']='tamper';native.invoke('action',id=state['cancel_operation'],body=b'\2',rejected=True);assert modes['reconcile']=='normal'
            assert retention.balance(native)==[98,0,1];native.restart()
            canceled=packet_fields(native.invoke('action',id=state['cancel_operation'],body=b'\2'));assert canceled[2]==b'\2'
            assert retention.balance(native)==[99,0,0]
            marker=len(trace);native.restart();assert packet_fields(native.invoke('action',id=state['cancel_operation'],body=b'\2'))[2]==b'\2' and len(trace)==marker
            ticket=native.invoke('authorize',id=native.invoke('profile'),body=state['username'])
            marker=len(trace)
            assert 'credit_reservation_cancelled' in native.invoke('attachment-grant',id=state['cancel_nonce'],body=ticket,rejected=True)
            assert len(trace)==marker
            assert retention.balance(native)==[99,0,0]
            state['cases']+=['realexpiry alonecannotrelease','forgedCCRrefused','authenticCorecancellation restoresonecredit afterrestart','terminalcancelrecovery zeroHTTP']
        assert db.sql('SELECT count(*) FROM credit_spent')=='2' and object_db.sql('SELECT count(*) FROM large_objects')=='2'
        assert not ingress.errors,ingress.errors
        result={'status':'passed_dual_native_paid_attachment_actual_services','wire_profile':selected['wire_profile'],'native_production_exports':selected['production_exports'],'platforms':{name:{k:v for k,v in state.items() if k in ['input_hashes','payment_hash','actual_maturity_seconds','actual_action_expiry_seconds','cancel_started_unix','cancel_expires','cipher_first_sha256','cipher_last_sha256','write_shape','cases']} for name,state in states.items()},'http':trace,'server':{'spent_tokens':2,'attachment_effects':2,'completed_objects':2,'object_parts':516},'private_postgres_ports':postgres_ports,'scope':'Real selected native ABI, Swift/JNI and OS custody, actual issuer/Core/edge/object-store; regtest only, real600s maturity/action expiry. No live funds, production deployment, physical-device or rendered-UI acceptance claim.'}
        (evidence/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
        (evidence/'native-security-config.txt').write_text(trust);(evidence/'native-network-config.txt').write_text(pins);(evidence/'issuer-ca-resource.bin').write_bytes(ingress.resource())
        return result
 return run

def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--run-id',default='first');a=p.parse_args()
    backend,qualification=verify_work(a.work);selected=WIRE.qualification_selection(qualification);snapshot=Path(backend['snapshot']);compiler=Path(backend['compiler'])
    output=a.work/'runs'/a.run_id;output.mkdir(parents=True,exist_ok=False)
    native_product=a.work/'native-product';os.environ.update(MESHC=str(compiler),MESH_RT_LIB_PATH=backend['runtime'],MORSE_PAID_LARGE_ATTACHMENTS='on',
      MORSE_LIGHTNING_PROOF_DIR=str(output/'issuer'),MORSE_LIGHTNING_IOS_PROOF='0',MORSE_LIGHTNING_IOS_TLS_PROOF='0',MORSE_LIGHTNING_ANDROID_TLS_PROOF='0',MORSE_LIGHTNING_CASES='ordinary',
      MORSE_LIGHTNING_SERVICE_SOURCE=str(snapshot/'services/credit-issuer'),MORSE_LIGHTNING_IOS_MODULE=str(native_product/'apps/mobile/modules/mesh-messenger'),
      MORSE_ATTACHMENT_ANDROID_LIBRARY=str(native_product/'apps/mobile/modules/mesh-messenger/android/build/ach3-proof/arm64-v8a/libmessenger_mobile.so'))
    fixture=load('paid_attachment_lightning_driver',PRODUCT/'scripts/prove-credit-lightning.py');fixture.PRODUCT=snapshot;fixture.ROOT=snapshot.parent
    postgres_ports=[];account.available_port=private_port;fixture.port=private_port
    class OwnedIssuerDatabase(fixture.Database):
        def __enter__(self):
            value=super().__enter__();assert self.port not in (55438,61546);postgres_ports.append(self.port);return value
    fixture.Database=OwnedIssuerDatabase
    source_inputs=[*HERE.glob('*.py'),*HERE.glob('platform/*'),HERE/'core_fixture.mpl.fixture',PRODUCT/'scripts/prove-credit-lightning.py',PRODUCT/'scripts/prove-postage-platform.py',PRODUCT/'scripts/prove-retention-native.py',PRODUCT/'scripts/prove-account-http-native.py',PRODUCT/'scripts/credit_ios_proof.py',PRODUCT/'scripts/attachment_android_proof.py',PRODUCT/'scripts/credit_tls_ingress.py']
    source_inputs+=sorted({Path(module.__file__).resolve() for module in list(sys.modules.values()) if getattr(module,'__file__',None) and Path(module.__file__).resolve().is_relative_to(PRODUCT) and Path(module.__file__).suffix=='.py'})
    hashes={str(f):sha(f) for f in source_inputs if f.is_file()};(output/'proof-source-inputs.json').write_text(json.dumps(hashes,indent=2)+'\n')
    archive=output/'sources-by-sha';archive.mkdir()
    for path,digest in hashes.items():shutil.copyfile(path,archive/digest)
    fixture.main(native_tls_extension=extension(output,native_product,a.work,postgres_ports,selected))
    assert hashes=={str(f):sha(f) for f in source_inputs if f.is_file()},'proof sources changed during execution'
if __name__=='__main__':main()
