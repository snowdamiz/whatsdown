#!/usr/bin/env python3
"""Qualify five typed account/device ABIs in owned iOS/Android hosts, no HTTP."""
from pathlib import Path
import argparse
import json
import tempfile
from credit_ios_proof import CreditIOSProof
from attachment_android_proof import AttachmentAndroidProof

PRODUCT = Path(__file__).resolve().parents[1]
EVIDENCE = PRODUCT.parent / '.morse/witness-proof'


class AccountIOSProof(CreditIOSProof):
    bundle = 'app.morse.account.proof.ios'


class AccountAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.account.proof.android'
    instrumentation_class = 'AccountProofTest'


def main(platform):
    runner = AccountIOSProof if platform == 'ios' else AccountAndroidProof
    extension = 'swift' if platform == 'ios' else 'kt'
    source = PRODUCT / f'apps/mobile/modules/mesh-messenger/{platform}/account-proof/AccountProof.{extension}'
    # Every network action here is malformed or belongs to the erased account,
    # so the native domains must reject it before an HTTP operation is possible.
    pins = '2\n1\nhttp://127.0.0.1:20632\nhttp://127.0.0.1:20632\nhttp://127.0.0.1:20632\nws://127.0.0.1:20632/v1/mailbox/stream\n1'
    checks = []
    with tempfile.TemporaryDirectory(prefix=f'morse-account-{platform}-', dir='/tmp') as raw:
        with runner(PRODUCT, Path(raw), '', proof_source=source, network_config=pins) as native:
            first = native.invoke('create', body=b'account_a')
            assert native.invoke('capabilities', id=first) == b'\1ACP\1'
            for operation, code in [('bad-capabilities', 'invalid_account_action'),
                                    ('bad-delete', 'invalid_account_action'),
                                    ('bad-renew', 'invalid_device_action'),
                                    ('bad-revoke', 'invalid_device_action')]:
                error = native.invoke(operation, id=first, rejected=True)
                assert code in error, (operation, error)
                assert 'status=6' not in error, 'application errors must fit their ABI output bound'
            assert native.invoke('profile') == first
            checks.append('all five exported boundaries return bounded application errors and preserve storage')
            native.restart()
            assert native.invoke('profile') == first
            assert native.invoke('discard', id=first) == b'\1ADS\1'
            replacement = native.invoke('create', body=b'account_b')
            assert replacement != first
            for operation in ['delete', 'discard', 'capabilities']:
                error = native.invoke(operation, id=first, rejected=True)
                assert 'account_state_changed' in error, (operation, error)
                assert native.invoke('profile') == replacement
            checks.append('erased account A cannot delete, discard, inspect or replace the OS-sealed custody of B')
            native.restart()
            assert native.invoke('profile') == replacement
            assert native.invoke('capabilities', id=replacement) == b'\1ACP\1'
            assert native.invoke('discard', id=replacement) == b'\1ADS\1'
            assert 'local_state_not_found' in native.invoke('profile', rejected=True)
            checks.append('real process restart preserves the replacement and guarded discard reports canonical absence')
            result = {
                'status': f'passed_{platform}_native_account_boundary',
                'inputs': native.input_hashes,
                'checks': checks,
                'limits': 'Production generated ABI and actual OS storage/JNI callbacks. No HTTP peer, successful server deletion, witnessed renewal, revocation publication or physical-device execution is claimed. Owned Mesh peer/race tests qualify those domain behaviors separately.',
            }
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            (EVIDENCE / f'native160-account-{platform}-evidence.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=['ios', 'android'])
    main(parser.parse_args().platform)
