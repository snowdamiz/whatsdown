#!/usr/bin/env python3
"""Check that an old host continuation cannot submit a later signed attempt.

Uses the production Rust host, compiled Core, actual test SDK and disposable SBF
bank. All traffic uses owned loopback listeners. No production accounts are used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bounty_proof', PRODUCT / 'scripts/prove-bounty-mixed.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def run(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    library, sdk = args.library.resolve(), args.sdk.resolve()
    bank = p.LiveBank(out, sdk, args.snapshots.resolve())
    native = driver = None
    events, report = [], {'status': 'FAIL_incomplete', 'scope': 'local Core, SDK, Rust host and disposable bank'}
    try:
        p.phone.resources(out, bank, bank.fixture, bank.wire)
        native = p.phone.Native(library, out, dict(os.environ))
        database = out / 'movement.db'
        Path(str(database) + '.wire').write_text(bank.wire.hex())
        native.invoke('mesh_messenger_create_account', p.phone.vectors(str(database).encode(), b'correlated-submission'))
        assert native.invoke('bounty_fixture_seed_selected', str(database).encode()) == bank.wire
        bank.ask('settle')
        tag, asset = bytes.fromhex('02424d52'), b'\1'
        payer = bytes.fromhex(bank.wallet['address_hex'])
        destination_a, destination_b = bytes([21]) * 32, bytes([31]) * 32

        def call(operation, *fields):
            return native.invoke('mesh_messenger_bounty_transfer_' + operation, p.packed(tag, str(database).encode(), *fields))

        def journal():
            return p.output_parts(native.invoke('bounty_fixture_journal', p.packed(str(database).encode(), asset)))

        def sign(intent):
            result = json.loads(subprocess.check_output([str(sdk)], input=json.dumps({
                'bounty_count': 4,
                'usdc_mint_hex': p.phone.un58(bank.fixture['accounts']['usdc']['address']).hex(),
                'bounty_transfer_hex': intent.hex(),
            }).encode()))
            return bytes.fromhex(result['wire_hex'])

        def before_send(wire):
            observer = p.phone.Native(library, out, dict(os.environ))
            try:
                saved = p.output_parts(observer.invoke('bounty_fixture_journal', p.packed(str(database).encode(), asset)))
            finally:
                observer.close()
            assert saved[3] == wire
            events.append({'event': 'send', 'wire_sha256': p.phone.sha(wire), 'signature': p.phone.b58(saved[4])})

        bank.before_send = before_send
        driver = subprocess.Popen([str(args.host_driver.resolve()), p.packed(tag, str(database).encode(), asset, destination_a).hex(), str(database)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        identity = packet_a = packet_b = None
        while True:
            line = driver.stdout.readline().strip()
            assert line, 'host driver exited without a result'
            if line.startswith('DONE '):
                report['host_result'] = line
                break
            values = line.split(' ', 2)
            kind, name = values[:2]
            request = bytes.fromhex(values[2] if len(values) == 3 else '')
            events.append({'event': kind, 'operation': name, 'request_sha256': p.phone.sha(request)})
            if kind == 'SDK':
                if name == '2':
                    result = payer
                else:
                    assert name == '5'
                    packet_a = sign(request)
                    result = packet_a
            else:
                if name.endswith('_submit'):
                    fields = p.unpack(request)
                    assert fields[3] == identity
                    if not args.expect_old_red:
                        assert len(fields) == 5 and fields[4] == packet_a[1:65]
                value = p.invoke_result(native, name, request)
                result = value
                if name.endswith('_commit'):
                    assert isinstance(value, bytes), value
                    committed_a, saved_a = value, journal()
                    identity, intent_a = saved_a[1], saved_a[2]
                    assert saved_a[0] == b'2' and saved_a[3] == packet_a
                    source = p.phone.pda('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', intent_a[12:44],
                        p.phone.un58('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'), intent_a[76:108])
                    original = bank.ask('account', address=source)
                    bank.ask('remove_accounts', addresses=[source])
                    submit_fields = [asset, identity] + ([] if args.expect_old_red else [saved_a[4]])
                    call('submit', *submit_fields)
                    call('recover', asset, identity)
                    assert journal()[0] == b'5'
                    bank.ask('restore_source', address=source, account=original)
                    prepared_b = p.unpack(call('prepare', asset, destination_b, payer))
                    assert prepared_b[3] == b'\1' and prepared_b[4][116:148] != intent_a[116:148]
                    packet_b = sign(prepared_b[4])
                    assert packet_b != packet_a
                    call('commit', asset, prepared_b[2], packet_b)
                    saved_b = journal()
                    assert saved_b[0] == b'2' and saved_b[1] == identity and saved_b[3] == packet_b
                    assert p.phone.sha(packet_b) not in bank.sends
                    events.append({'event': 'later_attempt_committed', 'same_leg': True, 'different_destination': True})
                    result = committed_a
            driver.stdin.write(('ERR ' + result['error'] if isinstance(result, dict) else result.hex()) + '\n')
            driver.stdin.flush()
        driver.stdin.close()
        driver.wait(timeout=5)
        assert driver.returncode == 0
        sent_b = p.phone.sha(packet_b) in bank.sends
        report.update(stale_host_submitted_later_attempt=sent_b, wire_a_sha256=p.phone.sha(packet_a),
            wire_b_sha256=p.phone.sha(packet_b), library_sha256=p.phone.sha(library.read_bytes()),
            sdk_sha256=p.phone.sha(sdk.read_bytes()), host_driver_sha256=p.phone.sha(args.host_driver.read_bytes()),
            sends_before_explicit_b=list(bank.sends), events=events)
        if args.expect_old_red:
            assert sent_b and report['host_result'] == 'DONE ERR invalid_bounty_transfer_response', report
            report['status'] = 'RED_confirmed_uncorrelated_private_submission'
        else:
            assert not sent_b and report['host_result'] == 'DONE ERR bounty_transfer_attempt_changed', report
            assert journal()[0] == b'2' and journal()[3] == packet_b
            before = len(bank.sends)
            unbound = p.invoke_result(native, 'mesh_messenger_bounty_transfer_submit', p.packed(tag, str(database).encode(), asset, identity))
            assert isinstance(unbound, dict) and len(bank.sends) == before
            call('submit', asset, identity, packet_b[1:65])
            call('recover', asset, identity)
            assert journal()[0] == b'4' and journal()[3] == packet_b
            report['status'] = 'PASS_exact_attempt_submission'
            report['later_attempt_explicitly_submitted_and_settled'] = True
        assert not bank.errors, bank.errors
        report['actual_bank'] = bank.ask('report')
        assert not report['actual_bank']['errors']
        print(json.dumps({key: report[key] for key in ('status', 'host_result', 'stale_host_submitted_later_attempt')}))
    finally:
        if driver and driver.poll() is None:
            driver.kill()
            driver.wait()
        if native:
            native.close()
        report['server_errors'] = bank.errors
        bank.close()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('library', 'sdk', 'snapshots', 'host-driver', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expect-old-red', action='store_true')
    run(parser.parse_args())
