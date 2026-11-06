#!/usr/bin/env python3
"""Run the production shared RPC readers against disposable local TLS peers.

MESHC, MESH_RT_LIB_PATH and MESH_TEST_RT_LIB_PATH must select one qualified
compiler/runtime family. All outputs and ephemeral keys stay below --output.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prove-red', action='store_true', help='Also prove removal of postflight guards fails the same test')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    package = Path(__file__).resolve().parent.parent
    compiler = Path(os.environ['MESHC']).resolve()
    events = []
    marker = output / 'current.txt'
    marker.write_text('current')

    def openssl(*argv):
        subprocess.run(['openssl', *argv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    for index in range(2):
        prefix = output / f'ca{index}'
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(prefix) + '.key', '-out', str(prefix) + '.pem', '-days', '1', '-subj', f'/CN=RPC Test CA {index}', '-addext', 'basicConstraints=critical,CA:TRUE')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(prefix) + '-server.key', '-out', str(prefix) + '-server.csr', '-subj', '/CN=localhost')
        ext = output / f'ca{index}.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', str(prefix) + '-server.csr', '-CA', str(prefix) + '.pem', '-CAkey', str(prefix) + '.key', '-CAcreateserial', '-out', str(prefix) + '-server.pem', '-days', '1', '-extfile', str(ext))

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            event = {'peer': self.server.peer, 'path': self.path, 'body': body.decode(), 'content_type': self.headers.get('Content-Type')}
            events.append(event)
            route = self.path.split('?', 1)[0]
            if route.startswith('/retire-'):
                marker.write_text('changed')
            if route == '/retire-error':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if route == '/redirect':
                self.send_response(307)
                self.send_header('Location', sources[1]['origin'] + '/redirect-target')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if self.server.peer == 'directory':
                response = b'proof'
            else:
                request = json.loads(body)
                account = {'lamports': 1, 'owner': '11111111111111111111111111111111', 'executable': False, 'rentEpoch': 0, 'data': [base64.b64encode(bytes([1, 2, 3, 4])).decode(), 'base64']}
                method = request['method']
                if method == 'getBlockTime':
                    result = 1700000000
                    assert request['params'] == [12]
                else:
                    assert request['params'][1]['commitment'] == 'finalized'
                    result = {'context': {'slot': 12}, 'value': account if method == 'getAccountInfo' else [account, None]}
                response = json.dumps({'jsonrpc': '2.0', 'id': 2 if route == '/wrong-id' else request['id'], 'result': result}).encode()
            if route == '/oversized':
                response = b' ' * 2048
            self.send_response(200)
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    servers = []
    sources = []
    try:
        for index in range(4):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            server.peer = index if index < 3 else 'directory'
            port = server.server_port
            if index < 3:
                root = index % 2
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(str(output / f'ca{root}-server.pem'), str(output / f'ca{root}-server.key'))
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
                origin = f'https://127.0.0.1:{port}'
                sources.append({'url': origin + '/rpc?release=paired', 'origin': origin, 'pem_hex': (output / f'ca{root}.pem').read_bytes().hex()})
            else:
                directory = f'http://127.0.0.1:{port}'
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        fixture = output / 'fixture.json'
        fixture.write_text(json.dumps({'sources': sources, 'wrong_pem_hex': (output / 'ca1.pem').read_bytes().hex(), 'marker': str(marker), 'directory': directory}))
        env = dict(os.environ, MORSE_RPC_TLS_FIXTURE=str(fixture), TMPDIR=str(output / 'tmp'))
        (output / 'tmp').mkdir(exist_ok=True)

        def run(source, log):
            with (output / log).open('w') as stream:
                return subprocess.run([str(compiler), 'test', str(source / 'security/rpc-tls.test.mpl')], env=env, stdout=stream, stderr=subprocess.STDOUT).returncode

        red = None
        if args.prove_red:
            fault = output / 'without-postflight'
            if fault.exists():
                shutil.rmtree(fault)
            shutil.copytree(package, fault, ignore=shutil.ignore_patterns('target', '.git'))
            manifest = (fault / 'mesh.toml').read_text()
            mesh_root = package.parents[2] / 'mesh-lang'
            manifest = manifest.replace('../../../mesh-lang', str(mesh_root.resolve()))
            (fault / 'mesh.toml').write_text(manifest)
            for name in ('anchor_rpc', 'anchor_http'):
                path = fault / 'transparency' / (name + '.mpl')
                source = path.read_text()
                guard = '  require_rpc_current(rpc.require_current)?' if name == 'anchor_rpc' else '  require_rpc_current(require_current)?'
                before, after = source.rsplit(guard, 1)
                path.write_text(before + after)
            red = run(fault, 'tls-guard-red.log')
            if red == 0 or 'COMPILE ERROR' in (output / 'tls-guard-red.log').read_text():
                raise RuntimeError('postflight-guard mutation did not fail behaviorally')
            events.clear()
            marker.write_text('current')
        result = run(package, 'tls-green.log')
        (output / 'http-events.json').write_text(json.dumps(events, indent=2))
        if result:
            raise RuntimeError(f'Mesh TLS proof failed: see {output / "tls-green.log"}')
        assert events and not any(e['path'] in ('/redirect-target', '/proof', '/never') for e in events)
        assert {e['peer'] for e in events if isinstance(e['peer'], int)} == {0, 1, 2}
        for event in events:
            if isinstance(event['peer'], int):
                assert event['content_type'] == 'application/json'
                assert json.loads(event['body'])['id'] == 1
        receipt = {'result': 'PASS', 'red_exit': red, 'green_exit': result, 'compiler': str(compiler), 'compiler_sha256': hashlib.sha256(compiler.read_bytes()).hexdigest(), 'http_requests': len(events), 'rpc_peers': 3, 'certificate_authorities': 2, 'source_sha256': {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [package / 'transparency/rpc_transport.mpl', package / 'transparency/anchor_rpc.mpl', package / 'transparency/anchor_batch.mpl', package / 'transparency/anchor_http.mpl', package / 'security/rpc-tls.test.mpl']}}
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
        print(json.dumps(receipt, indent=2))
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        # Ephemeral trust never enters an OS/global store. Keep certs as evidence,
        # remove their private signing keys after the owned listeners stop.
        for key in output.glob('*.key'):
            key.unlink()


if __name__ == '__main__':
    main()
