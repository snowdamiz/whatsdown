#!/usr/bin/env python3
"""Actual isolated iOS/Android ACH3 writer, authorization and legacy read proof."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from xml.sax.saxutils import escape
import argparse,hashlib,json,os,plistlib,shutil,subprocess,sys,threading,time
PRODUCT=Path(__file__).resolve().parents[2];ROOT=PRODUCT.parent;HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(PRODUCT/'scripts'))
from credit_ios_proof import CreditIOSProof
from attachment_android_proof import AttachmentAndroidProof
from credit_tls_ingress import CreditTLSIngress
from wire_profile import (work_selection, record_selection, material_status, check_new_write,
                          encrypted_manifest, validate_material_result)
class IOS(CreditIOSProof):bundle='app.morse.ach3.proof.ios'
class Android(AttachmentAndroidProof):
    bundle='app.morse.ach3.proof.android'
    instrumentation_class='Ach3ProofTest'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
u32=lambda v:v.to_bytes(4,'big')
def fields(data):
    out=[]
    while data:
        assert len(data)>=4
        n=int.from_bytes(data[:4],'big');assert n<=len(data)-4
        out.append(data[4:4+n]);data=data[4+n:]
    return out
def packet(data):
    assert len(data)>=4
    out=fields(data[4:]);assert len(out)==int.from_bytes(data[:4],'big');return out
def output_list(data):
    out=fields(data);assert len(out)>0 and len(out[0])==4 and int.from_bytes(out[0],'big')==len(out)-1
    return out[1:]
def reference_id(ref):
    assert ref[:4]==b'\1ATR';return ref[4:36].hex()
def public_key(seed):
    # Fixture signer only; production verification and key handling stay Mesh.
    private=bytes.fromhex('302e020100300506032b657004220420')+bytes([seed])*32
    result=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=private,capture_output=True,check=True).stdout
    assert len(result)==44 and result[:12]==bytes.fromhex('302a300506032b6570032100')
    return result[-32:].hex()

def swap_network(native,platform,network,original):
    """Change only the owned app's native resource, preserving path/custody."""
    native.restart()
    if platform=='ios':
        native.run('xcrun','simctl','terminate',native.device,native.bundle,check=False)
        installed=Path(native.run('xcrun','simctl','get_app_container',native.device,native.bundle,'app').stdout.strip())
        # Simulator installation relocates the data container, which changes
        # the intentionally path-bound ticket context. Modify/re-sign only
        # this owned simulator app's metadata in place to isolate trust pins.
        # The final runtime rejection proves the native callback read it.
        for app in [native.work/'CreditProof.app',installed]:
            info=plistlib.loads((app/'Info.plist').read_bytes())
            info['MeshMessengerNetworkConfig']=network;(app/'Info.plist').write_bytes(plistlib.dumps(info))
            native.run('codesign','--force','--sign','-',app)
        directory=Path(native.run('xcrun','simctl','get_app_container',native.device,native.bundle,'data').stdout.strip())/'Documents'
        assert directory==native.directory,('native data path changed during pin mutation',str(native.directory),str(directory))
        native.directory=directory
        native.restart()
    else:
        manifest=native.work/'AndroidManifest.xml'
        text=manifest.read_text();old=escape(original,{'"':'&quot;'}).replace('\n','&#10;');new=escape(network,{'"':'&quot;'}).replace('\n','&#10;')
        assert text.count(old)==1
        variant=native.work/'variant-manifest.xml';variant.write_text(text.replace(old,new))
        apk=native.work/'variant.apk';apk.unlink(missing_ok=True)
        build=native.sdk/'build-tools/36.0.0'
        native.run(build/'aapt2','link','-I',native.sdk/'platforms/android-36/android.jar','--manifest',variant,'-o',apk)
        files=['classes.dex','lib/arm64-v8a/libmessenger_mobile.so']
        if (native.work/'assets/morse-issuer-tls-root-v1.bin').exists():files.append('assets/morse-issuer-tls-root-v1.bin')
        subprocess.run(['zip','-q',str(apk),*files],cwd=native.work,check=True)
        native.run(build/'apksigner','sign','--ks',native.work/'test-key.p12','--ks-pass','pass:android',apk)
        native.device('install','-r',apk)
        native.restart()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('platform',choices=['ios','android'])
    parser.add_argument('--work',type=Path,default=ROOT/'.morse/witness-proof/ach3-native-87085')
    parser.add_argument('--run-id',default='first')
    parser.add_argument('--wire-profile',type=int,choices=[3,4]);parser.add_argument('--expected-production-exports',type=int,choices=[162,163]);args=parser.parse_args()
    selected=work_selection(args.work,args.wire_profile,args.expected_production_exports)
    assert record_selection(json.loads((args.work/'host-build.json').read_text()),'production_exports')==selected
    assert all(record_selection(row)==selected for row in json.loads((args.work/'builds.json').read_text()))
    wire_name='ach'+str(selected['wire_profile'])
    evidence=args.work/(args.platform+'-'+args.run_id);evidence.mkdir()
    proof_sources=[*HERE.glob('*.py'),*HERE.glob('platform/*'),HERE/'driver/main.mpl',args.work/'driver/main.mpl',args.work/'driver/fixture/legacy.mpl',
      *[PRODUCT/'scripts'/name for name in ['credit_ios_proof.py','attachment_android_proof.py','credit_tls_ingress.py']]]
    source_hashes={str(p):sha(p) for p in proof_sources if p.is_file()}
    (evidence/'source-inputs.json').write_text(json.dumps(source_hashes,indent=2)+'\n')
    sources=evidence/'sources-by-sha';sources.mkdir()
    for source,digest in source_hashes.items():
        shutil.copyfile(source,sources/digest)
    measurements=[];groups=[];requests=[];errors=[];objects={};tamper=[False]
    shapes={};mask3_refusals=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):self.handle_request()
        def do_PUT(self):self.handle_request()
        def do_GET(self):self.handle_request()
        def respond(self,status,body):
            self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def handle_request(self):
            try:
                size=int(self.headers.get('Content-Length','0'));assert 0<=size<=65576
                body=self.rfile.read(size)
                assert self.headers.get('Content-Type')=='application/octet-stream'
                assert self.headers.get('Cache-Control')=='no-store'
                assert all(self.headers.get(k) is None for k in ['Cookie','Authorization','X-Account-ID','X-Device-ID'])
                requests.append({'method':self.command,'route':self.path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
                if self.command=='GET':
                    assert body==b'' and len(self.headers['X-Object-Capability'])==64
                    value=objects[self.path]
                    if tamper[0]:value=value[:-1]+bytes([value[-1]^1])
                    return self.respond(200,value)
                if self.path=='/v1/attachments/grant':
                    assert self.command=='POST' and len(body)==124 and body[:4]==b'\1OGR'
                    return self.respond(201,b'\1OGS'+body[4:36])
                if self.path in ['/v1/attachments/complete','/v1/attachments/delete']:
                    assert self.command=='POST' and len(body)==68
                    return self.respond(200 if self.path.endswith('complete') else 204,b'')
                assert self.command=='PUT' and self.path.startswith('/v1/objects/')
                objects[self.path]=body;self.respond(201,b'')
            except Exception as error:
                errors.append(repr(error));self.respond(500,b'')
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    origin=f'http://127.0.0.1:{server.server_port}'
    def tls_handler(peer,body):
        try:
            assert peer.command=='GET' and body==b'' and peer.path.startswith('/v2/objects/')
            assert len(peer.headers['X-Object-Capability'])==64
            requests.append({'method':peer.command,'route':peer.path,'bytes':0,'tls':True})
            value=objects[peer.path]
            if tamper[0]:value=value[:-1]+bytes([value[-1]^1])
            peer.respond(200,value)
        except Exception as error:
            errors.append(repr(error));peer.respond(500,b'')
    try:
      with CreditTLSIngress(evidence,'',{},tls_handler) as ingress:
        service,witness=public_key(53),public_key(54)
        security='\n'.join(['3',service,'22'*32,'1','1','1','outside '+witness+' Test','-','0',ingress.origin,'2','1','1','outside '+witness+' Test'])
        network='\n'.join(['2','1',origin,origin,origin,origin.replace('http:','ws:')+'/v1/mailbox/stream','1'])
        (evidence/'security-config.txt').write_text(security);(evidence/'network-config.txt').write_text(network)
        native_product=args.work/'native-product';module=native_product/'apps/mobile/modules/mesh-messenger'
        os.environ['MORSE_LIGHTNING_IOS_MODULE']=str(module)
        os.environ['MORSE_ATTACHMENT_ANDROID_LIBRARY']=str(module/'android/build/ach3-proof/arm64-v8a/libmessenger_mobile.so')
        runner=IOS if args.platform=='ios' else Android
        source=HERE/'platform'/('Ach3Proof.swift' if args.platform=='ios' else 'Ach3Proof.kt')
        kwargs={} if args.platform=='ios' else {'credit_purpose':'test','lightning_network':'regtest'}
        with runner(native_product,evidence,security,proof_source=source,network_config=network,issuer_tls_root=ingress.resource(),artifact_dir=evidence/'artifacts',**kwargs) as native:
            if args.platform=='android':native.device('reverse',f'tcp:{ingress.server.server_port}',f'tcp:{ingress.server.server_port}')
            def call(op,id=b'',body=b'',rejected=False):
                start=time.monotonic();value=native.invoke(op,id=id,body=body,rejected=rejected)
                measurements.append({'operation':op,'expected_refusal':rejected,'input_id_sha256':hashlib.sha256(id).hexdigest(),'input_body_sha256':hashlib.sha256(body).hexdigest(),'output_sha256':hashlib.sha256((value.encode() if rejected else value)).hexdigest(),'error':value if rejected else None,'seconds':round(time.monotonic()-start,4)})
                (evidence/'calls.json').write_text(json.dumps(measurements,indent=2)+'\n')
                return value
            call('create');call('create-other')
            before=len(requests)
            assert call('old-upload',rejected=True)
            assert call('old-prepare',id=bytes([7])*32,rejected=True)
            assert call('free-upload',body=b'forged-ticket',rejected=True)
            assert len(requests)==before
            assert call('install-other',body=b'\3',rejected=True)
            assert call('ticket-other',rejected=True)
            call('install-other',body=b'\1')
            assert 'attachment_recipient_upgrade_required' in call('ticket-other',rejected=True)
            call('erase-other');call('create-other');call('install-other',body=b'\2')
            assert 'attachment_recipient_upgrade_required' in call('ticket-other',rejected=True)
            groups+=['old_framing_and_forged_ticket_zero_http','forged_witness_rejected','authenticated_legacy_primary_and_linked_device_refused']
            if selected['wire_profile']==4:
                # A valid general ACH3 ticket remains useful for old recovery.
                # Only the new padded writer admission refuses mask3-only peers.
                for mode in (4,5):
                    call('erase-other');call('create-other');call('install-other',body=bytes([mode]))
                    old_ticket=call('ticket-other');assert old_ticket
                    call('require-other',body=old_ticket)
                    prior=call('inventory-other');http_before=len(requests)
                    free_error=call('free-upload-other',body=old_ticket,rejected=True)
                    paid_error=call('prepare-other',id=bytes([7])*32,body=old_ticket,rejected=True)
                    after=call('inventory-other')
                    assert 'attachment_recipient_upgrade_required' in free_error
                    assert 'attachment_recipient_upgrade_required' in paid_error
                    assert len(requests)==http_before and prior==after
                    mask3_refusals.append({'mode':mode,'valid_general_ticket':True,
                      'ticket_sha256':hashlib.sha256(old_ticket).hexdigest(),
                      'free_error':free_error,'paid_error':paid_error,'http_before':http_before,'http_after':len(requests),
                      'inventory_before_sha256':hashlib.sha256(prior).hexdigest(),'inventory_after_sha256':hashlib.sha256(after).hexdigest()})
                groups+=['authenticated_ach3_only_primary_and_linked_refuse_padded_writes']
            call('install',body=b'\0');ticket=call('ticket');assert ticket
            call('require',body=ticket);native.restart();call('require',body=ticket)
            assert call('require-other',body=ticket,rejected=True)
            damaged=ticket[:-1]+bytes([ticket[-1]^1]);assert call('require',body=damaged,rejected=True)
            assert len(requests)==before
            groups+=['genuine_ticket_restart_exact_path_and_tamper_binding']
            # Real production free upload includes native prepare, grant, EAM,
            # ACH3 first/last writers, complete and repeated recipient checks.
            upload=output_list(call('free-upload',body=ticket));assert len(upload)==3
            ref=upload[0];oid=reference_id(ref);assert upload[1].hex()==oid
            first=objects[f'/v1/objects/{oid}/parts/1'];last=objects[f'/v1/objects/{oid}/parts/2']
            shapes['free']=check_new_write(selected,encrypted_manifest(ref),first,last,paid=False,last_index=1)
            assert call('fetch',id=u32(0),body=ref)==bytes([37])*65536
            assert call('fetch',id=u32(1),body=ref)==bytes([37])
            alternate=call('alternate',body=ref);assert alternate!=ref
            assert call('fetch',id=u32(0),body=alternate,rejected=True)
            tamper[0]=True;assert call('fetch',id=u32(0),body=ref,rejected=True);tamper[0]=False
            native.restart();assert call('fetch',id=u32(1),body=ref)==bytes([37])
            groups+=['actual_free_upload_http_'+wire_name+'_first_last','free_eam_substitution_and_tamper_rejected','free_download_restart']
            if selected['wire_profile']==4:
                one=output_list(call('free-upload-one',body=ticket));assert len(one)==3
                one_ref=one[0];one_id=reference_id(one_ref);one_wire=objects[f'/v1/objects/{one_id}/parts/1']
                assert objects[f'/v1/objects/{one_id}/parts/0']==encrypted_manifest(one_ref)
                shapes['one_byte']=check_new_write(selected,encrypted_manifest(one_ref),one_wire,one_wire,paid=False,last_index=0)
                assert call('fetch',id=u32(0),body=one_ref)==bytes([37])
                groups+=['one_byte_padded_upload_fixed_manifest_and_exact_download']
            size=u32(16777217);preview=packet(call('preview',body=size));assert len(preview)==9
            nonce=preview[1];inventory=call('inventory')
            assert call('prepare',id=nonce,body=damaged,rejected=True)
            assert call('inventory')==inventory
            assert 'insufficient_credit_balance' in call('prepare',id=nonce,body=ticket,rejected=True)
            inventory=call('inventory');rows=packet(inventory);row=packet(rows[2]);assert row[0]==nonce and row[2]==b'\3'
            paid_ref=call('reference',id=nonce)
            paid_first=call('paid-seal',id=nonce,body=u32(0));paid_last=call('paid-seal',id=nonce,body=u32(256))
            shapes['paid']=check_new_write(selected,encrypted_manifest(paid_ref),paid_first,paid_last,paid=True,last_index=256)
            native.restart();assert call('paid-recover',id=nonce,body=u32(0))==paid_first
            assert call('paid-recover',id=nonce,body=u32(256))==paid_last
            oid=reference_id(paid_ref);objects[f'/v2/objects/{oid}/parts/1']=paid_first;objects[f'/v2/objects/{oid}/parts/257']=paid_last
            assert call('fetch',id=u32(0),body=paid_ref)==bytes([37])*65536
            assert call('fetch',id=u32(256),body=paid_ref)==bytes([37])
            alternate=call('alternate',body=paid_ref)
            assert call('fetch',id=u32(0),body=alternate,rejected=True)
            assert call('inventory')==inventory
            groups+=['paid_material_only_'+wire_name+'_writer_and_exact_ciphertext_restart','paid_tls_reads_and_eam_substitution_rejected']
            for version in [1,2]:
                legacy=packet(call('legacy',body=bytes([version])));assert len(legacy)==3
                legacy_ref,legacy_first,legacy_last=legacy
                assert legacy_first[:4]==legacy_last[:4]==bytes([version])+b'ACH'
                oid=reference_id(legacy_ref);last_index=1 if version==1 else 256
                objects[f'/v{version}/objects/{oid}/parts/1']=legacy_first;objects[f'/v{version}/objects/{oid}/parts/{last_index+1}']=legacy_last
                assert call('fetch',id=u32(0),body=legacy_ref)==bytes([37])*65536
                native.restart();assert call('fetch',id=u32(last_index),body=legacy_ref)==bytes([37])
            groups+=['legacy_ach1_and_ach2_actual_native_read_restart']
            if selected['wire_profile']==4:
                legacy=packet(call('legacy',body=b'\3'));assert len(legacy)==3
                legacy_ref,legacy_first,legacy_last=legacy
                assert legacy_first[:4]==legacy_last[:4]==b'\3ACH' and len(legacy_last)==41
                oid=reference_id(legacy_ref)
                objects[f'/v2/objects/{oid}/parts/1']=legacy_first;objects[f'/v2/objects/{oid}/parts/257']=legacy_last
                assert call('fetch',id=u32(0),body=legacy_ref)==bytes([37])*65536
                native.restart();assert call('fetch',id=u32(256),body=legacy_ref)==bytes([37])
                groups+=['legacy_ach3_actual_native_read_restart']
            # Actual native resource change, same executable and OS store.
            changed=network.replace(origin,origin.replace('127.0.0.1','localhost'))
            count=len(requests);swap_network(native,args.platform,changed,network)
            assert 'attachment_configuration_changed' in call('require',body=ticket,rejected=True)
            assert len(requests)==count
            swap_network(native,args.platform,network,network)
            call('require',body=ticket)
            groups+=['ticket_native_pin_change_rejected_without_path_or_custody_change']
            if args.platform=='ios':
                # A simulator upgrade can move its data container. The old
                # path-bound authorization must fail; fresh authorization from
                # the same authenticated profile/set must recover normally.
                old_directory=native.directory
                native.run('xcrun','simctl','terminate',native.device,native.bundle,check=False)
                native.run('xcrun','simctl','install',native.device,native.work/'CreditProof.app')
                native.directory=Path(native.run('xcrun','simctl','get_app_container',native.device,native.bundle,'data').stdout.strip())/'Documents'
                assert native.directory!=old_directory,'simulator relocation scenario did not occur'
                native.restart()
                assert 'local_state_open_failed' in call('require',body=ticket,rejected=True)
                ticket=call('ticket')
                call('require',body=ticket)
                groups+=['relocated_container_old_ticket_refused_fresh_authenticated_ticket_recovers']
            call('erase');call('create')
            assert call('require',body=ticket,rejected=True)
            groups+=['ticket_account_replacement_rejected']
            if args.platform=='android':native.device('reverse','--remove',f'tcp:{ingress.server.server_port}',check=False)
            assert errors==[] and ingress.errors==[],(errors,ingress.errors)
            assert source_hashes=={str(p):sha(p) for p in proof_sources if p.is_file()},'proof inputs changed during native execution'
            result={'status':material_status(selected),'wire_profile':selected['wire_profile'],'production_exports':selected['production_exports'],'write_shapes':shapes,'mask3_writer_refusals':mask3_refusals,'platform':args.platform,'groups':groups,'native_inputs':native.input_hashes,'calls':measurements,'http':requests,'compiler_sha256':json.loads((args.work/'builds.json').read_text())[0]['compiler_sha256'],
              'source_inputs':source_hashes,
              'limits':['Real Swift/JNI and OS custody on simulator/emulator, not physical devices.','Owned HTTP/TLS object fixture, not deployed object store.','Paid path is unfunded material-only status3; no credits/grant/funds synthesized.','Six ciphertext/signature-only proof exports; selected production ABI unchanged.','No production library installation, live funds, deployment, screen capture or computer-use service.']}
            validate_material_result(result,selected,args.platform)
            (evidence/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps({'platform':args.platform,'status':result['status'],'groups':len(groups),'calls':len(measurements),'http_requests':len(requests)}),flush=True)
    finally:
        server.shutdown();server.server_close()
        (evidence/'http.json').write_text(json.dumps({'requests':requests,'errors':errors},indent=2)+'\n')
if __name__=='__main__':main()
