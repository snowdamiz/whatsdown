#!/usr/bin/env python3
"""Exercise account-bound journal capacity, restart and rejection in native hosts."""
from pathlib import Path
import argparse
import hashlib
import json
import tempfile
from credit_ios_proof import CreditIOSProof
from attachment_android_proof import AttachmentAndroidProof

PRODUCT = Path(__file__).resolve().parents[1]
EVIDENCE = PRODUCT.parent / '.morse/witness-proof'

class JournalIOSProof(CreditIOSProof):
    bundle = 'app.morse.journal.proof.ios'

class JournalAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.journal.proof.android'
    instrumentation_class = 'JournalProofTest'

def main(platform):
    runner = JournalIOSProof if platform == 'ios' else JournalAndroidProof
    extension = 'swift' if platform == 'ios' else 'kt'
    source = PRODUCT / f'apps/mobile/modules/mesh-messenger/{platform}/journal-proof/JournalProof.{extension}'
    pins = '2\n1\nhttp://127.0.0.1:20633\nhttp://127.0.0.1:20633\nhttp://127.0.0.1:20633\nws://127.0.0.1:20633/v1/mailbox/stream\n1'
    checks = []
    with tempfile.TemporaryDirectory(prefix=f'morse-journal-{platform}-', dir='/tmp') as raw:
        with runner(PRODUCT, Path(raw), '', proof_source=source, network_config=pins) as native:
            first = native.invoke('create', body=b'account_a')
            assert native.invoke('read', id=first) == b''
            for size in [65536, 65537, 262144]:
                value = bytes(index % 251 for index in range(size))
                assert native.invoke('write', id=first, body=value) == b''
                assert native.invoke('read', id=first) == value
                native.restart()
                assert native.invoke('read', id=first) == value
            checks.append('64KiB, 64KiB+1 and 256KiB records round-trip through real generated ABI and OS storage across process restarts')
            for operation, body, error_code in [('bad-load', b'', 'invalid_journal_request'),
                                                ('bad-write', b'', 'invalid_journal_request'),
                                                ('bad-key', b'bad', 'invalid_journal_key'),
                                                ('write', b'x'*262145, 'invalid_journal_request')]:
                error = native.invoke(operation, id=first, body=body, rejected=True)
                assert error_code in error and 'status=6' not in error, (operation, error)
                assert native.invoke('read', id=first) == value
                assert native.invoke('profile') == first
            assert native.invoke('preview', id=first, body=b'none') == b''
            native.restart()
            assert native.invoke('read-preview', id=first) == b'none'
            assert 'invalid_journal_preference' in native.invoke('preview', id=first, body=b'unknown', rejected=True)
            assert native.invoke('read-preview', id=first) == b'none'
            checks.append('malformed, oversized and unknown preference values preserve both account and existing sealed records')
            assert native.invoke('discard', id=first) == b'\1ADS\1'
            replacement = native.invoke('create', body=b'account_b')
            assert replacement != first
            assert native.invoke('read', id=replacement) == b''
            assert native.invoke('read-preview', id=replacement) == b''
            assert native.invoke('write', id=replacement, body=b'replacement journal') == b''
            for operation, body in [('read', b''), ('write', b'old'), ('write', b'\0'), ('preview', b'full')]:
                error = native.invoke(operation, id=first, body=body, rejected=True)
                assert 'account_state_changed' in error, (operation, error)
                assert native.invoke('read', id=replacement) == b'replacement journal'
            native.restart()
            assert native.invoke('profile') == replacement
            assert native.invoke('read', id=replacement) == b'replacement journal'
            assert native.invoke('write', id=replacement, body=b'\0') == b''
            assert native.invoke('read', id=replacement) == b''
            checks.append('stale A read, write, delete and preference actions cannot cross replacement; B survives restart and can remove its own journal')
            result = {'status': f'passed_{platform}_native_journal_boundary', 'inputs': native.input_hashes,
                      'maximum_value_sha256': hashlib.sha256(value).hexdigest(), 'checks': checks,
                      'limits': 'Owned simulator/emulator with production generated ABI and OS storage/JNI callbacks. No physical-device performance, rendered UI, external review or full plaintext phase exit is claimed.'}
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            (EVIDENCE / f'native162-journal-{platform}-evidence.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result), flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=['ios', 'android'])
    main(parser.parse_args().platform)
