#!/usr/bin/env python3
"""Positive synthetic fanout through the production ABI and an owned Mesh peer."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from credit_ios_proof import CreditIOSProof
from attachment_android_proof import AttachmentAndroidProof

PRODUCT = Path(__file__).resolve().parents[1]
EVIDENCE = PRODUCT.parent / '.morse/witness-proof'


def vectors(*fields):
    return b''.join(len(value).to_bytes(4, 'big')+value for value in fields)


def output_list(data):
    # General Mobile.Codec output lists wrap the item count in a 4-byte vector;
    # they deliberately differ from CreditState's raw counted parts.
    assert len(data) >= 8 and int.from_bytes(data[:4], 'big') == 4
    count = int.from_bytes(data[4:8], 'big')
    assert count <= 64
    offset, fields = 8, []
    for _ in range(count):
        assert offset+4 <= len(data)
        size = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
        assert size > 0 and offset+size <= len(data)
        fields.append(data[offset:offset+size]); offset += size
    assert offset == len(data)
    return fields


class FanoutIOSProof(CreditIOSProof):
    bundle = 'app.morse.fanout.proof.ios'


class FanoutAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.fanout.proof.android'
    instrumentation_class = 'FanoutProofTest'


class Peer:
    def __init__(self, work, compiler, port):
        self.work, self.compiler, self.port = work, compiler, port

    def __enter__(self):
        self.work.mkdir()
        self.log = (self.work/'peer.log').open('w')
        env = dict(os.environ, MORSE_FANOUT_FIXTURE=str(self.work), MORSE_FANOUT_PORT=str(self.port))
        self.process = subprocess.Popen([str(self.compiler), 'test', str(PRODUCT/'scripts/fanout-peer/peer.test.mpl')],
                                        cwd=PRODUCT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+180
        while not (self.work/'ready').exists():
            if self.process.poll() is not None or time.monotonic()>deadline:
                self.log.flush()
                raise RuntimeError('owned peer did not become ready: '+(self.work/'peer.log').read_text())
            time.sleep(.1)
        self.config = self.post('/fixture/config', b'').decode()
        return self

    def post(self, route, body):
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}'+route, body,
                                         {'Content-Type': 'application/octet-stream'}, method='POST')
        with urllib.request.urlopen(request, timeout=30) as response:
            assert response.status == 200
            return response.read()

    def __exit__(self, *_):
        (self.work/'done').write_text('done')
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.log.close()
        assert self.process.returncode == 0, (self.work/'peer.log').read_text()


def main(platform, compiler, port):
    runner = FanoutIOSProof if platform == 'ios' else FanoutAndroidProof
    extension = 'swift' if platform == 'ios' else 'kt'
    source = PRODUCT/f'apps/mobile/modules/mesh-messenger/{platform}/fanout-proof/FanoutProof.{extension}'
    pins = f'2\n1\nhttp://127.0.0.1:{port}\nhttp://127.0.0.1:{port}\nhttp://127.0.0.1:{port}\nws://127.0.0.1:{port}/v1/mailbox/stream\n1'
    with tempfile.TemporaryDirectory(prefix=f'morse-fanout-{platform}-', dir='/tmp') as raw:
        work = Path(raw)
        with Peer(work/'peer', compiler, port) as peer:
            with runner(PRODUCT, work, peer.config, proof_source=source, network_config=pins) as native:
                alice = native.invoke('create-a')
                bob = native.invoke('create-b')
                entries = [native.invoke('entry-a'), native.invoke('entry-b')]
                peer.post('/fixture/entries', (2).to_bytes(4, 'big')+vectors(*entries))
                message = vectors(b'bob', b'\1', b'owned native positive fanout', b'', b'')
                assert native.invoke('fanout-a', id=alice, body=message) == b'\1FNO\0'
                outgoing = output_list(native.invoke('outbox-a'))
                assert len(outgoing) == 1
                assert b'owned native positive fanout' in native.invoke('initial-b', body=outgoing[0])
                native.invoke('ack-a', body=outgoing[0])
                native.restart()
                assert native.invoke('profile-a') == alice
                assert native.invoke('profile-b') == bob
                assert b'owned native positive fanout' in native.invoke('history-b', body=alice)
                group = native.invoke('group-a')
                invitation = vectors(b'bob', b'\2', group, b'', b'')
                assert native.invoke('fanout-a', id=alice, body=invitation) == b'\1FNO\0'
                queued = native.invoke('outbox-a')
                invite = output_list(queued)
                assert len(invite) == 1
                assert native.invoke('fanout-a', id=alice, body=invitation) == b'\1FNO\0'
                assert native.invoke('outbox-a') == queued
                native.invoke('message-b', body=invite[0])
                native.invoke('ack-a', body=invite[0])
                pending = output_list(native.invoke('invitations-b'))
                assert len(pending) == 1
                reference, group_id, username, account, state = output_list(pending[0])
                assert group_id == group and username == b'alice' and state == b'\1'
                acceptance = vectors(b'alice', b'\3', reference, account, b'')
                assert native.invoke('fanout-b', id=bob, body=acceptance) == b'\1FNO\0'
                saved = native.invoke('outbox-b')
                accepts = output_list(saved)
                assert len(accepts) == 1
                native.restart()
                assert native.invoke('fanout-b', id=bob, body=acceptance) == b'\1FNO\0'
                assert native.invoke('outbox-b') == saved
                native.invoke('message-a', body=accepts[0])
                native.invoke('ack-b', body=accepts[0])
                ready = output_list(native.invoke('invitations-a'))
                assert len(ready) == 1 and output_list(ready[0])[4] == b'\3'
                assert 'invalid_fanout_action' in native.invoke('bad-fanout', rejected=True)
                native.invoke('discard-a', id=alice)
                replacement = native.invoke('replacement-a')
                assert replacement != alice
                assert 'account_state_changed' in native.invoke('fanout-a', id=alice, body=message, rejected=True)
                assert native.invoke('profile-a') == replacement and native.invoke('profile-b') == bob
                native.restart()
                assert native.invoke('profile-a') == replacement
                checks = ['real native message decrypts on the second OS-sealed account',
                          'real signed directory and prekey work/admission precede compact native success',
                          'native group invitation and acceptance survive exact no-op retries and process restart',
                          'queued encrypted control packets stay byte-identical until acknowledgement',
                          'old captured local profile cannot sign/send after replacement',
                          'bounded application errors retain their actual native error codes']
                result = dict(status=f'passed_{platform}_native_fanout', inputs=native.input_hashes,
                              security_config_sha256=hashlib.sha256(peer.config.encode()).hexdigest(),
                              peer_source_sha256=hashlib.sha256((PRODUCT/'scripts/fanout-peer/peer.test.mpl').read_bytes()).hexdigest(),
                              compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(), checks=checks,
                              limits='Owned local synthetic signed Mesh peer and real generated ABI/OS custody; no production network, physical-device or UI-rendering claim.')
                EVIDENCE.mkdir(parents=True, exist_ok=True)
                (EVIDENCE/f'fanout-native-{platform}-evidence.json').write_text(json.dumps(result, indent=2)+'\n')
                print(json.dumps(result), flush=True)
        (EVIDENCE/f'fanout-native-{platform}-peer.log').write_text((work/'peer/peer.log').read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=['ios', 'android'])
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--port', type=int, default=24331)
    args = parser.parse_args()
    main(args.platform, args.compiler.resolve(), args.port)
