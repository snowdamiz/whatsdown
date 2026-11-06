#!/usr/bin/env python3
"""Owned HTTPS peer for real Mesh postage journals and signed policy publication."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
from credit_tls_ingress import CreditTLSIngress

PRODUCT = Path(__file__).resolve().parents[1]
PROOF = PRODUCT.parent/'.morse/witness-proof'


def main():
    compiler = Path(os.environ.get('MESHC', PRODUCT.parent/'mesh-lang/target/debug/meshc'))
    compiler_hash = hashlib.sha256(compiler.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='morse-postage-tls-',dir='/tmp') as raw:
        work = Path(raw).resolve()
        def handler(peer, body):
            mode = (work/'mode').read_text()
            (work/'request.hex').write_text(body.hex())
            (work/'count').write_text(str(len(ingress.requests)))
            expected = '/v1/credits/postage-policy' if mode == 'policy' else '/v1/credits/postage'
            assert peer.path == expected, (mode,peer.path)
            if mode == 'policy': return peer.respond(201,(2).to_bytes(8,'big'))
            if mode == 'failure': return peer.respond(503,b'')
            if mode == 'redirect':
                peer.send_response(307)
                peer.send_header('Location',ingress.origin+'/untrusted')
                peer.send_header('Content-Length','0')
                peer.end_headers()
                return
            if mode == 'drop':
                peer.close_connection=True
                peer.connection.close()
                return
            if mode == 'empty': return peer.respond(200,b'')
            if mode == 'oversized': return peer.respond(200,b'x'*565)
            assert mode in ('forged','valid')
            return peer.respond(201,bytes.fromhex((work/'response.hex').read_text()))
        with CreditTLSIngress(work,'',{},handler) as ingress:
            (work/'root.hex').write_text(ingress.resource().hex())
            env = dict(os.environ,MORSE_POSTAGE_TLS_ORIGIN=ingress.origin,MORSE_POSTAGE_TLS_FIXTURE=str(work))
            subprocess.run([str(compiler),'test','packages/mobile-core/tests/credits_postage_native.test.mpl'],
                cwd=PRODUCT,env=env,check=True)
            assert hashlib.sha256(compiler.read_bytes()).hexdigest() == compiler_hash, 'compiler changed during proof'
            assert ingress.errors == [], ingress.errors
            assert not any(request['route']=='/untrusted' for request in ingress.requests)
            assert len(ingress.requests)>=8
            files=['packages/mobile-core/mobile/credit_postage_native.mpl','packages/mobile-core/mobile/credit_transport.mpl',
                'packages/mobile-core/mobile/native_issuer_tls.mpl','packages/mobile-core/mobile/postage_policy_intent.mpl',
                'packages/mobile-core/mobile/credit_postage.mpl','packages/mobile-core/tests/credits_postage_native.test.mpl',
                'scripts/prove-postage-native-https.py','scripts/credit_tls_ingress.py']
            evidence={'status':'passed_owned_https_native_mesh_postage','compiler_sha256':compiler_hash,
                'sources':{name:hashlib.sha256((PRODUCT/name).read_bytes()).hexdigest() for name in files},
                'cases':['native signed policy publish201','stale policy revision rejected before HTTP','HTTP503','redirect refused',
                    'empty200','oversized response','forged encrypted receipt','lost response','same sealed batch on retry',
                    'reserved credits and outbox preserved on failure','durable receipt before failed outbox ACK',
                    'native retry completes ACK','terminal retry noHTTP','HTTP ack does not admit policy'],
                'requests':ingress.requests,'limits':'Owned TLS peer with generated signed Mesh fixtures; simulator device flow and live paid postage remain separate gates'}
            (PROOF/'postage-native-https-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
            print(json.dumps({'status':evidence['status'],'requests':len(ingress.requests),'cases':len(evidence['cases'])}))


if __name__ == '__main__': main()
