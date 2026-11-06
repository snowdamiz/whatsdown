#!/usr/bin/env python3
"""Owned HTTPS exercise of native paid-object journals, routing and chunk crypto."""
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
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    compiler_hash = digest(compiler)
    sources = ['packages/mobile-core/mobile/attachment_transport.mpl',
        'packages/mobile-core/mobile/credit_attachment_native.mpl',
        'packages/mobile-core/mobile/credit_attachment.mpl',
        'packages/mobile-core/mobile/credit_attachment_parts.mpl',
        'packages/mobile-core/mobile/native_issuer_tls.mpl',
        'packages/mobile-core/tests/credits_attachment_native.test.mpl',
        'scripts/prove-attachment-native-https.py','scripts/credit_tls_ingress.py']
    hashes = {name:digest(PRODUCT/name) for name in sources}
    with tempfile.TemporaryDirectory(prefix='morse-attachment-tls-',dir='/tmp') as raw:
        work = Path(raw).resolve()
        parts = {}
        captures = []
        def handler(peer, body):
            mode = (work/'mode').read_text()
            (work/'request.hex').write_text(body.hex())
            (work/'count').write_text(str(len(ingress.requests)))
            captures.append({'mode':mode,'method':peer.command,'route':peer.path,'bytes':len(body)})
            if mode.startswith('get') or mode.startswith('put'):
                assert peer.path.startswith('/v2/objects/') and '/parts/' in peer.path
                assert peer.command == ('GET' if mode.startswith('get') else 'PUT')
                capability = peer.headers.get('X-Object-Capability','')
                assert len(capability)==64 and bytes.fromhex(capability) != bytes(32)
                if mode.startswith('put'):
                    if peer.path in parts: assert parts[peer.path] == body, 'retry changed ciphertext'
                    parts[peer.path] = body
                    if mode == 'put-drop':
                        peer.close_connection=True
                        peer.connection.close()
                        return
                    return peer.respond(201,b'')
                assert body == b''
                if mode == 'get-oversized': return peer.respond(200,b'x'*65577)
                value = parts[peer.path]
                if mode == 'get-forged': value = value[:-1]+bytes([value[-1]^1])
                return peer.respond(200,value)
            assert peer.command == 'POST'
            assert peer.headers.get('X-Object-Capability') is None
            if mode.startswith('complete') or mode.startswith('delete'):
                operation = 'complete' if mode.startswith('complete') else 'delete'
                assert peer.path == '/v2/attachments/'+operation
                assert len(body)==68 and body[:4] == (b'\1OCP' if operation=='complete' else b'\1ODL')
                return peer.respond(202 if mode.endswith('pending') else (200 if operation=='complete' else 204),b'')
            assert peer.path == '/v1/attachments/paid-grant'
            assert body.hex() == (work/'grant.hex').read_text(), 'native grant retry changed'
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
            if mode == 'oversized': return peer.respond(200,b'x'*463)
            assert mode in ('grant','forged')
            receipt = bytes.fromhex((work/'receipt.hex').read_text())
            if mode == 'forged': receipt = receipt[:-1]+bytes([receipt[-1]^1])
            return peer.respond(201,receipt)
        with CreditTLSIngress(work,'',{},handler) as ingress:
            (work/'root.hex').write_text(ingress.resource().hex())
            (work/'count').write_text('0')
            env = dict(os.environ,MORSE_ATTACHMENT_TLS_ORIGIN=ingress.origin,MORSE_ATTACHMENT_TLS_FIXTURE=str(work))
            subprocess.run([str(compiler),'test','packages/mobile-core/tests/credits_attachment_native.test.mpl'],
                cwd=PRODUCT,env=env,check=True)
            assert digest(compiler) == compiler_hash, 'compiler changed during proof'
            assert hashes == {name:digest(PRODUCT/name) for name in sources}, 'proof sources changed'
            assert ingress.errors == [], ingress.errors
            assert len(ingress.requests)==20, len(ingress.requests)
            assert not any(request['route']=='/untrusted' for request in ingress.requests)
            evidence={'status':'passed_owned_https_native_mesh_attachments','compiler_sha256':compiler_hash,
                'sources':hashes,'requests':captures,'request_hashes':ingress.requests,
                'cases':['incomplete staging causes zero HTTP','untrusted CA rejected before HTTP',
                    'grant503/redirect/empty/oversize/forgery/drop preserve reservation',
                    'identical committed grant repair after success','same ciphertext after dropped PUT response',
                    'native manifest and first/last chunk upload','upload bounds before HTTP',
                    'bounded complete and delete progress','native decrypts first/last chunk',
                    'downloads work with purchases disabled','tampered and oversized ciphertext rejected',
                    'download bounds before HTTP'],
                'limits':'Owned TLS fixture with real Mesh cryptography/storage; full production object-store and simulator transfer remain separate gates'}
            (PROOF/'attachment-native-https-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
            print(json.dumps({'status':evidence['status'],'requests':len(ingress.requests),'cases':len(evidence['cases'])}))


if __name__ == '__main__': main()
