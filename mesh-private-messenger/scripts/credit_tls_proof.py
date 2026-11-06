"""Direct native HTTPS credit purchase proof using owned TLS/LND peers."""
import base64
import time
from concurrent.futures import ThreadPoolExecutor
from credit_ios_proof import CreditIOSProof, packet_fields
from credit_android_proof import CreditAndroidProof
from credit_tls_ingress import CreditTLSIngress
from lightning_regtest import await_value


def prove_native_tls(product, work, seed, lnd, issuer_origin, set_mode, platform='ios', artifact_dir=None):
    native_type = {'ios': CreditIOSProof, 'android': CreditAndroidProof}[platform]
    platform_label = {'ios': 'iOS Simulator', 'android': 'Android emulator'}[platform]
    quote_clock_retries = []
    def quote(native, prepared):
        purchase_id, request = prepared[1], prepared[7]
        try:
            result = native.invoke('continue', id=purchase_id)
        except AssertionError as error:
            detail = error.args[0] if error.args else None
            if not isinstance(detail, dict) or detail.get('error') != 'lightning_quote_request_mismatch':
                raise
            # The emulator clock can lag the host by a fraction of a second.
            # Keep strict production not-before validation. Recover the same
            # durable request, then permit one retry after time advances.
            pending = packet_fields(native.invoke('recover', id=purchase_id))
            assert pending[2] == b'\0' and pending[7] == request
            quote_clock_retries.append({'purchase_id': purchase_id.hex(), 'error': detail['error']})
            time.sleep(1.1)
            result = native.invoke('continue', id=purchase_id)
        assert packet_fields(result)[2] == b'\1'
    with CreditTLSIngress(work, issuer_origin, seed) as ingress:
        witness = 'outside '+seed['witness_key']+' Test'
        trust = '\n'.join(['3',seed['service_key'],'22'*32,'16','1','1',witness,'-','0',ingress.origin,'2','1','1',witness])
        untrusted = work/'tls-untrusted'
        untrusted.mkdir()
        with native_type(product,untrusted,trust,artifact_dir=None if artifact_dir is None else artifact_dir/'untrusted') as native:
            native.invoke('create')
            rejection = native.invoke('discover',rejected=True)
            assert rejection=='credit_transport_unavailable', rejection
            assert ingress.requests==[], 'a missing CA must fail before HTTP disclosure'
        print(platform_label+': missing packaged CA refused before HTTP', flush=True)
        trusted = work/'tls-trusted'
        trusted.mkdir()
        with native_type(product,trusted,trust,issuer_tls_root=ingress.resource(),artifact_dir=None if artifact_dir is None else artifact_dir/'trusted') as native:
            native.invoke('create')
            native.invoke('discover')
            native.invoke('discover')
            prepared = packet_fields(native.invoke('prepare'))
            purchase_id = prepared[1]
            assert prepared[2]==b'\0'
            quote(native, prepared)
            uri = native.invoke('handoff',id=purchase_id).decode()
            assert uri.startswith('lightning:lnbcrt')
            issued = packet_fields(native.invoke('recover',id=purchase_id))
            claim = issued[7]
            assert issued[2]==b'\2' and claim[:4]==b'\x01LIR'
            assert native.invoke('continue',id=purchase_id,rejected=True)=='credit_http_425'
            payment_hash = claim[36:68].hex()
            with ThreadPoolExecutor(max_workers=1) as executor:
                payment = executor.submit(lnd.pay,uri[len('lightning:'):])
                await_value(lambda:lnd.lnd('issuer','/v1/invoice/'+payment_hash),lambda value:value['state']=='ACCEPTED')
                ingress.tamper_next_issue=True
                native.invoke('continue',id=purchase_id,rejected=True)
                payment.result(timeout=45)
            assert not ingress.tamper_next_issue
            assert packet_fields(native.invoke('recover',id=purchase_id))[2]==b'\2'
            ingress.drop_next_issue=True
            assert native.invoke('continue',id=purchase_id,rejected=True)=='credit_transport_unavailable'
            assert not ingress.drop_next_issue
            native.restart()
            assert packet_fields(native.invoke('recover',id=purchase_id))[7]==claim
            completed = packet_fields(native.invoke('continue',id=purchase_id))
            assert completed[2]==b'\3'
            requests = len(ingress.requests)
            assert packet_fields(native.invoke('continue',id=purchase_id))[4]==completed[4]
            assert len(ingress.requests)==requests, 'terminal retries must remain local'
            native.restart()
            assert [int.from_bytes(field,'big') for field in packet_fields(native.invoke('balance'))[1:6]]==[0,100,0,0,0]
            attempts = [value for value in ingress.requests if value['route'].endswith('/issue')]
            assert len(attempts)==4 and len({value['sha256'] for value in attempts})==1
            second = packet_fields(native.invoke('prepare'))
            second_id = second[1]
            assert second_id!=purchase_id
            quote(native, second)
            native.invoke('handoff',id=second_id)
            second_claim = packet_fields(native.invoke('recover',id=second_id))[7]
            second_hash = second_claim[36:68].hex()
            lnd.lnd('issuer','/v2/invoices/cancel',{'payment_hash':base64.b64encode(bytes.fromhex(second_hash)).decode()})
            set_mode(False)
            ingress.tamper_next_issue=True
            native.invoke('continue',id=second_id,rejected=True)
            assert not ingress.tamper_next_issue
            assert packet_fields(native.invoke('recover',id=second_id))[2]==b'\2'
            native.restart()
            assert packet_fields(native.invoke('continue',id=second_id))[2]==b'\4'
            native.restart()
            assert packet_fields(native.invoke('recover',id=second_id))[2]==b'\4'
            assert [int.from_bytes(field,'big') for field in packet_fields(native.invoke('balance'))[1:6]]==[0,100,0,0,0]
            next_purchase = packet_fields(native.invoke('prepare'))
            assert next_purchase[2]==b'\0' and next_purchase[1] not in (purchase_id,second_id)
            assert ingress.errors==[],ingress.errors
            return {'platform':platform_label,'verified_tokens':100,'native_https':True,'input_hashes':native.input_hashes,
                'requests':ingress.requests,'canceled_payment_hash':second_hash,'quote_clock_retries':quote_clock_retries,
                'cases':['missing CA refused before HTTP','exact native CA/origin HTTPS','native witnessed issuer discovery',
                    'native quote and durable wallet handoff','real LND payment','forged response refused',
                    'lost HTTPS response preserves exact claim across app restart','native finalization stores100 delayed credits',
                    'terminal retry performs no HTTP','forged cancellation refused','disabled issuer cancellation via native HTTPS',
                    'cancellation survives restart and permits fresh purchase'],
                'limits':'Owned TLS ingress fronts production Mesh HTTP issuer; discovery evidence is a local witnessed fixture; external wallet application launch and live funds are not covered'}
