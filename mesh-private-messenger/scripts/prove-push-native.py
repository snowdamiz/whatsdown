#!/usr/bin/env python3
"""Run production push C ABI against real platform storage in owned native apps."""
from pathlib import Path
import argparse
import json
import tempfile
from credit_ios_proof import CreditIOSProof
from attachment_android_proof import AttachmentAndroidProof

PRODUCT = Path(__file__).resolve().parents[1]
PROOF = PRODUCT.parent/'.morse/witness-proof'

class PushIOSProof(CreditIOSProof):
    bundle = 'app.morse.push.proof.ios'

class PushAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.push.proof.android'
    instrumentation_class = 'PushProofTest'


def main(platform):
    runner = PushIOSProof if platform == 'ios' else PushAndroidProof
    extension = 'swift' if platform == 'ios' else 'kt'
    source = PRODUCT/f'apps/mobile/modules/mesh-messenger/{platform}/push-proof/PushProof.{extension}'
    pins = '2\n1\nhttp://127.0.0.1:20631\nhttp://127.0.0.1:20631\nhttp://127.0.0.1:20631\nws://127.0.0.1:20631/v1/mailbox/stream\n1'
    config = ('01234567-89ab-cdef-0123-456789abcdef', '09'+'00'*31)
    checks = []
    def frame(value, kind, failure=0, status=None):
        assert value[:4] == b'\2PFA' and value[4:6] == bytes([kind, failure]), value.hex()
        assert len(value) == (19 if kind == 0 else 50), len(value)
        assert int.from_bytes(value[14:18], 'big') == (1 if kind == 0 else 32)
        if kind: assert int.from_bytes(value[6:14], 'big') > 0
        if status is not None: assert value[18] == status
        return value
    with tempfile.TemporaryDirectory(prefix=f'morse-push-{platform}-', dir='/tmp') as raw:
        with runner(PRODUCT, Path(raw), '', proof_source=source, network_config=pins, push_config=config) as native:
            profile = native.invoke('create')
            def begin(body, rejected=False):
                return native.invoke('begin',body=body,id=profile,rejected=rejected)
            assert native.invoke('status') == b'disabled'
            frame(begin(body=b'\0'),0,status=0)
            permission = frame(begin(body=b'\1'),1)
            native.restart()
            assert begin(body=b'\0') == permission
            checks.append('opaque permission ticket survives a real process restart')
            forged = permission[:-1] + bytes([permission[-1]^1])
            native.invoke('complete',body=forged,id=b'\0',rejected=True)
            native.invoke('send',body=permission,rejected=True)
            assert begin(body=b'\0') == permission
            checks.append('forged completion and non-network send preserve exact pending state')
            prime = frame(native.invoke('complete',body=permission,id=b'\0'),2)
            assert native.invoke('validate',body=prime) == b'\2'
            native.invoke('validate',body=permission,rejected=True)
            native.invoke('validate',body=prime[:-1]+bytes([prime[-1]^1]),rejected=True)
            native.invoke('complete',body=permission,id=b'\0',rejected=True)
            frame(native.invoke('complete',body=prime,id=b'\1'),0,failure=1,status=2)
            assert begin(body=b'\0') == prime
            checks.append('duplicate permission completion is rejected; failed platform work remains retryable')
            clear = frame(begin(body=b'\2'),5)
            native.invoke('validate',body=prime,rejected=True)
            assert native.invoke('validate',body=clear) == b'\5'
            native.invoke('complete',body=prime,id=b'\0',rejected=True)
            frame(native.invoke('complete',body=clear,id=b'\1'),0,failure=1,status=3)
            native.restart()
            assert begin(body=b'\0') == clear
            frame(native.invoke('complete',body=clear,id=b'\0'),0,status=0)
            assert native.invoke('status') == b'disabled'
            checks.append('disable fences prior token work; platform clear retries after restart')
            old = frame(begin(body=b'\1'),1)
            old_profile = profile
            native.invoke('erase'); profile = native.invoke('create')
            native.invoke('begin',body=b'\1',id=old_profile,rejected=True)
            frame(begin(body=b'\0'),0,status=0)
            replacement = frame(begin(body=b'\1'),1)
            assert replacement != old
            native.invoke('complete',body=old,id=b'\0',rejected=True)
            assert begin(body=b'\0') == replacement
            native.invoke('validate',body=clear,rejected=True)
            checks.append('replacement identity rejects old expected-profile intent and all old account tickets')
            checks.append('platform validator accepts only current prime/clear and refuses wrong kinds or forged tickets')
            for malformed in [b'', b'\3', b'\0\0']:
                begin(body=malformed,rejected=True)
            native.invoke('complete',body=replacement,id=b'\2',rejected=True)
            assert begin(body=b'\0') == replacement
            checks.append('invalid intents and completion outcomes do not mutate pending state')
            native.invoke('erase')
            result = {'status':f'passed_{platform}_native_push_boundary','inputs':native.input_hashes,'checks':checks,
                'limits':'Production160-export Mesh library and actual OS storage/JNI callbacks in an owned harness. Permission/prime/clear outcomes are supplied by the harness; no APNs/FCM registration, provider HTTP, bind/unbind HTTP, or physical-device notification delivery is claimed.'}
            (PROOF/f'native160-push-{platform}-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result),flush=True)

if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('platform',choices=['ios','android'])
    main(parser.parse_args().platform)
