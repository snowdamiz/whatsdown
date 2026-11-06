#!/usr/bin/env python3
"""Actual iOS Simulator free-file uploads/downloads through production Mesh HTTP."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import tempfile
import threading
import time
from credit_ios_proof import CreditIOSProof, packet_fields

PRODUCT = Path(__file__).resolve().parents[1]
PROOF = PRODUCT.parent/'.morse/witness-proof'

class AttachmentIOSProof(CreditIOSProof):
    bundle = 'app.morse.attachment.proof.ios'


def main(platform='ios'):
    assert platform in ('ios', 'android')
    if platform == 'android':
        from attachment_android_proof import AttachmentAndroidProof
        runner = AttachmentAndroidProof
        platform_name = 'Android emulator'
    else:
        runner = AttachmentIOSProof
        platform_name = 'iOS Simulator'
    objects, captures, errors = {}, [], []
    state = {'mode':'ordinary'}
    class Peer(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def respond(self, status, data=b''):
            self.send_response(status)
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def handle_request(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                assert 0 <= length <= 65576
                body=self.rfile.read(length)
                assert len(body)==length
                assert self.headers.get('Content-Type')=='application/octet-stream'
                assert self.headers.get('Cache-Control')=='no-store'
                assert self.headers.get('Authorization') is None and self.headers.get('Cookie') is None
                captures.append({'method':self.command,'path':self.path,'bytes':length,'sha256':hashlib.sha256(body).hexdigest(),'mode':state['mode']})
                if self.path=='/v1/attachments/grant':
                    assert self.command=='POST' and body[:4]==b'\1OGR' and len(body)==124
                    assert self.headers.get('X-Object-Capability') is None
                    object_id=body[4:36].hex()
                    count=int.from_bytes(body[36:40],'big')
                    upload,download=body[60:92],body[92:124]
                    work=b'mesh-msg/v1/object-grant-work'+body[4:36]+body[48:60]+body[36:48]+hashlib.sha256(upload).digest()+hashlib.sha256(download).digest()
                    assert hashlib.sha256(work).digest()[0] < 128, 'native difficulty1 proof'
                    assert 2<=count<=257 and int.from_bytes(body[48:56],'big')>=int(time.time()*1000)
                    objects[object_id]={'parts':{},'count':count,'upload':upload.hex(),'download':download.hex(),'completed':False}
                    return self.respond(201,b'\1OGS'+body[4:36])
                if self.path.startswith('/v1/objects/'):
                    pieces=self.path.split('/')
                    assert len(pieces)==6 and pieces[4]=='parts'
                    obj=objects[pieces[3]]; index=int(pieces[5])
                    assert 0<=index<obj['count']
                    cap=self.headers.get('X-Object-Capability')
                    if self.command=='PUT':
                        assert cap==obj['upload'] and 41<=len(body)<=65576
                        obj['parts'][index]=body
                        if state['mode']=='part-failure' and index==1: return self.respond(503)
                        return self.respond(201)
                    assert self.command=='GET' and body==b'' and cap==obj['download'] and obj['completed']
                    value=obj['parts'][index]
                    if state['mode']=='tampered-download': value=value[:-1]+bytes([value[-1]^1])
                    return self.respond(200,value)
                assert self.command=='POST' and len(body)==68 and self.headers.get('X-Object-Capability') is None
                object_id=body[4:36].hex(); obj=objects.get(object_id)
                if self.path=='/v1/attachments/complete':
                    assert body[:4]==b'\1OCP' and obj and body[36:].hex()==obj['upload']
                    assert sorted(obj['parts'])==list(range(obj['count']))
                    obj['completed']=True
                    return self.respond(200)
                assert self.path=='/v1/attachments/delete' and body[:4]==b'\1ODL'
                if obj is None: return self.respond(404)
                assert body[36:].hex()==obj['upload']
                del objects[object_id]
                return self.respond(204)
            except Exception as error:
                errors.append(repr(error))
                self.respond(500)
        do_POST=handle_request
        do_PUT=handle_request
        do_GET=handle_request
    server=ThreadingHTTPServer(('127.0.0.1',0),Peer)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    pins=f'2\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\n{origin}\nws://127.0.0.1:18090/v1/mailbox/stream\n1'
    source=PRODUCT/'apps/mobile/modules/mesh-messenger/ios/attachment-proof/AttachmentProof.swift'
    cases=[]
    try:
        with tempfile.TemporaryDirectory(prefix=f'morse-attachment-{platform}-',dir='/tmp') as raw:
            with runner(PRODUCT,Path(raw),'',proof_source=source,network_config=pins) as native:
                native.invoke('create')
                for size in [65537,16777216]:
                    started=time.monotonic()
                    print(f'{platform_name} native upload: {size} plaintext bytes', flush=True)
                    output=native.invoke('upload',body=size.to_bytes(4,'big'))
                    # Native output-list framing has a vector-wrapped count.
                    assert output[:4]==b'\0\0\0\4'
                    reference,object_id,ticket=packet_fields(output[4:])
                    assert object_id.hex() in objects and len(reference)<=1024 and len(ticket)<=4096
                    upload_seconds=time.monotonic()-started
                    native.restart()
                    count=(size+65535)//65536
                    result=native.invoke('read_all',id=count.to_bytes(4,'big'),body=reference)
                    assert int.from_bytes(result[:8],'big')==size
                    assert result[8:]==hashlib.sha256(bytes([37])*size).digest()
                    before=len(captures)
                    native.invoke('discard',body=ticket+b'x',rejected=True)
                    assert len(captures)==before, 'forged discard reached HTTP'
                    state['mode']='tampered-download'
                    native.invoke('read_all',id=(1).to_bytes(4,'big'),body=reference,rejected=True)
                    state['mode']='ordinary'
                    if size==16777216:
                        native.invoke('erase'); native.invoke('create')
                        before=len(captures)
                        native.invoke('discard',body=ticket,rejected=True)
                        assert len(captures)==before, 'replacement identity accepted old discard'
                        objects.pop(object_id.hex())
                    else:
                        assert native.invoke('discard',body=ticket)==b''
                        assert native.invoke('discard',body=ticket)==b'', '404 is idempotent deletion'
                        assert object_id.hex() not in objects
                    cases.append({'bytes':size,'chunks':count,'roundtrip_sha256':result[8:].hex(),'upload_seconds':round(upload_seconds,3),'restart':True})
                    print(f'{platform_name} native round trip passed: {size} bytes, {count} chunks', flush=True)
                state['mode']='part-failure'
                native.invoke('upload',body=(65537).to_bytes(4,'big'),rejected=True)
                assert not objects, 'failed upload did not delete created object'
                assert not errors,errors
                evidence={'status':f'passed_{platform}_native_free_attachment_http','platform':platform_name,'inputs':native.input_hashes,
                    'cases':cases,'checks':['exact complete-file digest','native grant PoW and fixed capability routes','all encrypted parts bounded65576B',
                    'restart download and discard','forged discard rejected before HTTP','tampered download refused','replacement identity cannot discard prior object',
                    'late upload failure deletes remote object','404 deletion is idempotent'],'requests':captures,
                    'limits':'Production compiled Mesh and OS secure-store callbacks in an owned native harness; owned HTTP object peer in development mode, no production object-store or rendered native picker/Expo bridge transfer.'}
                (PROOF/f'attachment-{platform}-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
                print(json.dumps({'status':evidence['status'],'cases':cases,'requests':len(captures)}),flush=True)
    finally:
        server.shutdown();server.server_close();thread.join()

if __name__=='__main__': main()
