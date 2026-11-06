#!/usr/bin/env python3
"""Owned native ACH3 receive proof, with no screen or accessibility capture."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import base64
import hashlib
import json
import os
import runpy
import subprocess
import tempfile
import threading
from credit_ios_proof import packet_fields

PRODUCT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('ios', 'android'), required=True)
    parser.add_argument('--proof-dir', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--expect-legacy-refusal', action='store_true')
    args = parser.parse_args()
    evidence = args.proof_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    fixture = args.fixture.resolve()
    fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    if args.platform == 'android':
        from attachment_android_proof import AttachmentAndroidProof
        runner = AttachmentAndroidProof
    else:
        runner = runpy.run_path(str(Path(__file__).with_name('prove-attachment-ios.py')))['AttachmentIOSProof']

    requests, errors, rejections = [], [], []
    state = {'mode': 'ordinary', 'parts': []}
    object_id = bytes([47]) * 32
    capability = (bytes([49]) * 32).hex()

    class Peer(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                prefix = f'/v1/objects/{object_id.hex()}/parts/'
                assert self.path.startswith(prefix)
                index = int(self.path[len(prefix):])
                assert index in (1, 2)
                assert self.headers.get('X-Object-Capability') == capability
                assert self.headers.get('Authorization') is None
                assert self.headers.get('Cookie') is None
                assert self.headers.get('Cache-Control') == 'no-store'
                assert int(self.headers.get('Content-Length', '0')) == 0
                value = state['parts'][index - 1]
                if state['mode'] == 'reordered':
                    value = state['parts'][1 - (index - 1)]
                elif state['mode'] == 'tampered':
                    value = value[:-1] + bytes([value[-1] ^ 1])
                elif state['mode'] == 'oversized':
                    value = bytes(65577)
                requests.append({'index': index, 'mode': state['mode'], 'bytes': len(value),
                                 'sha256': hashlib.sha256(value).hexdigest()})
                self.send_response(200)
                self.send_header('Content-Length', str(len(value)))
                self.end_headers()
                self.wfile.write(value)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The native bounded reader may close an oversized reply.
            except Exception as error:
                errors.append(repr(error))
                self.send_response(500)
                self.send_header('Content-Length', '0')
                self.end_headers()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    pins = f'2\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\n{origin}\nws://127.0.0.1:18090/v1/mailbox/stream\n1'
    source = PRODUCT / 'apps/mobile/modules/mesh-messenger/ios/attachment-proof/AttachmentProof.swift'
    try:
        with tempfile.TemporaryDirectory(prefix=f'morse-bound-{args.platform}-', dir='/tmp') as raw:
            with runner(PRODUCT, Path(raw), '', proof_source=source, network_config=pins,
                        artifact_dir=evidence / 'native') as native:
                def refused(body, expected):
                    raw_error = native.invoke('read_all', id=(2).to_bytes(4, 'big'), body=body, rejected=True)
                    error = raw_error
                    for prefix in ('java.lang.IllegalStateException: Mesh library call failed (status=9): ',
                                   'Mesh library call failed (status=9): '):
                        if error.startswith(prefix):
                            error = error[len(prefix):]
                            break
                    assert error == expected, {'expected': expected, 'actual': raw_error}
                    rejections.append({'expected': expected, 'actual': raw_error})

                profile = native.invoke('create')
                result = subprocess.run([str(fixture)], check=True, capture_output=True, text=True,
                                        env=dict(os.environ, MORSE_ATTACHMENT_FIXTURE_PROFILE=base64.b64encode(profile).decode()))
                encoded = base64.b64decode(result.stdout.strip(), validate=True)
                reference, alternate, first, last = packet_fields(encoded)
                assert first[:4] == last[:4] == b'\x03ACH'
                assert len(first) == 65576 and len(last) == 41
                assert int.from_bytes(first[4:8], 'big') == 0
                assert int.from_bytes(last[4:8], 'big') == 1
                state['parts'] = [first, last]
                (evidence / 'public-fixture.bin').write_bytes(encoded)
                count = (2).to_bytes(4, 'big')
                if args.expect_legacy_refusal:
                    refused(reference, 'invalid_attachment_manifest')
                    cases = ['preceding native reader refuses ACH3']
                else:
                    expected = (65537).to_bytes(8, 'big') + hashlib.sha256(bytes([37]) * 65537).digest()
                    assert native.invoke('read_all', id=count, body=reference) == expected
                    native.restart()
                    assert native.invoke('read_all', id=count, body=reference) == expected
                    refused(alternate, 'attachment_authentication_failed')
                    for mode, reason in (('reordered', 'invalid_attachment_chunk_index'),
                                         ('tampered', 'attachment_authentication_failed'),
                                         ('oversized', 'attachment_transport_unavailable')):
                        state['mode'] = mode
                        refused(reference, reason)
                    state['mode'] = 'ordinary'
                    assert native.invoke('read_all', id=count, body=reference) == expected
                    native.invoke('erase')
                    native.invoke('create')
                    before = len(requests)
                    refused(reference, 'attachment_key_unwrap_failed')
                    assert len(requests) == before, 'replacement account reached old object transport'
                    cases = ['exact 65537-byte ACH3 content through native HTTP and OS key storage',
                             'same reference and chunks survive native process restart',
                             'same clear metadata under a different encrypted EAM rejected',
                             'reordered, tampered and oversized chunk replies rejected',
                             'successful retry uses original bytes after failures',
                             'replacement account refuses old wrapped key before HTTP']
                assert not errors, errors
                assert hashlib.sha256(fixture.read_bytes()).hexdigest() == fixture_hash
                report = {'status': 'passed_legacy_refusal' if args.expect_legacy_refusal else 'passed_native_bound_reader',
                          'platform': args.platform, 'inputs': native.input_hashes,
                          'fixture_sha256': fixture_hash, 'cases': cases, 'requests': requests,
                          'rejections': rejections,
                          'limits': 'Owned native harness and development HTTP peer; real generated ABI, Mesh crypto and OS key callbacks. No writer activation, production server, external review or complete Plaintext claim.'}
                (evidence / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps({'status': report['status'], 'platform': args.platform, 'cases': len(cases), 'requests': len(requests)}), flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
