"""Owned HTTPS ingress for native credit integration proofs; never production."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import ssl
import subprocess
import threading
import urllib.error
import urllib.request


class CreditTLSIngress:
    def __init__(self, work, issuer_origin, seed, handler=None):
        self.work, self.issuer_origin, self.seed = work/'credit-tls', issuer_origin, seed
        self.requests, self.errors = [], []
        self.handler = handler
        self.drop_next_issue = False
        self.tamper_next_issue = False

    def __enter__(self):
        self.work.mkdir(mode=0o700)
        def openssl(*args):
            subprocess.run(['openssl',*map(str,args)],check=True,capture_output=True)
        root, key = self.work/'ca.pem', self.work/'ca.key'
        cert, leaf = self.work/'server.pem', self.work/'server.key'
        csr, extensions = self.work/'server.csr', self.work/'extensions.cnf'
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',root,
            '-days','1','-subj','/CN=Morse owned credit proof CA')
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',leaf,'-out',csr,'-subj','/CN=127.0.0.1')
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in',csr,'-CA',root,'-CAkey',key,'-CAcreateserial','-out',cert,
            '-days','1','-extfile',extensions)
        key.chmod(0o600)
        leaf.chmod(0o600)
        self.pem = root.read_bytes()
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                try: self.post()
                except Exception as error:
                    fixture.errors.append(type(error).__name__+': '+str(error))
                    self.respond(500,b'')
            def do_PUT(self): self.do_POST()
            def do_GET(self): self.do_POST()
            def post(self):
                size = int(self.headers.get('Content-Length','0'))
                assert 0 <= size <= 600000
                assert self.headers.get('Content-Type')=='application/octet-stream'
                assert self.headers.get('Cache-Control')=='no-store'
                assert all(self.headers.get(name) is None for name in ('Cookie','Authorization','X-Account-ID','X-Device-ID','X-Forwarded-For'))
                body = self.rfile.read(size)
                fixture.requests.append({'route':self.path,'length':len(body),'sha256':hashlib.sha256(body).hexdigest()})
                if fixture.handler is not None:
                    return fixture.handler(self, body)
                if self.path == '/v1/credits/issuer':
                    assert len(body)==13 and body[:5]==bytes.fromhex('0143494b01')
                    previous = int.from_bytes(body[5:],'big')
                    assert previous in (0,1)
                    return self.respond(200,bytes.fromhex(fixture.seed['evidence'+str(previous)]))
                if self.path not in ('/v1/credits/lightning/quote','/v1/credits/lightning/issue'):
                    return self.respond(404,b'')
                request = urllib.request.Request(fixture.issuer_origin+'/internal'+self.path,data=body,
                    headers={'Content-Type':'application/octet-stream','Authorization':'Bearer '+'b'*32})
                try:
                    with urllib.request.urlopen(request,timeout=20) as upstream:
                        status,content = upstream.status,upstream.read(600001)
                except urllib.error.HTTPError as error:
                    status,content = error.code,error.read(600001)
                assert len(content)<=600000
                if self.path.endswith('/issue') and status==200:
                    if fixture.drop_next_issue:
                        fixture.drop_next_issue=False
                        self.close_connection=True
                        self.connection.close()
                        return
                    if fixture.tamper_next_issue:
                        fixture.tamper_next_issue=False
                        content=content[:-1]+bytes([content[-1]^1])
                self.respond(status,content)
            def respond(self,status,body):
                self.send_response(status)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert,leaf)
        self.server.socket = context.wrap_socket(self.server.socket,server_side=True)
        self.origin = f'https://127.0.0.1:{self.server.server_port}'
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        return self

    def resource(self):
        origin = self.origin.encode('ascii')
        return b'\1'+len(origin).to_bytes(2,'big')+origin+len(self.pem).to_bytes(4,'big')+self.pem

    def __exit__(self,*_):
        self.server.shutdown()
        self.server.server_close()
