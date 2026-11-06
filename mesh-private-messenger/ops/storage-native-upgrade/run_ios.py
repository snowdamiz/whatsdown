#!/usr/bin/env python3
"""Actual Keychain-backed legacy storage migration in an owned iOS Simulator app.

Prepare builds both versions without touching a device. Run swaps only the
stopped owned app executable in place, preserving its absolute sandbox path.
Simulator reinstall relocates that path, so it is not used as an upgrade model.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import time

HERE = Path(__file__).resolve().parent
PRODUCT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('storage_upgrade_helpers', HERE / 'run_android.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
spec = importlib.util.spec_from_file_location('storage_upgrade_ios_host', PRODUCT / 'scripts/credit_ios_proof.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
sha, save, clone, vector, modern, records = common.sha, common.save, common.clone, common.vector, common.modern, common.records


class Built(Exception):
    pass


class StorageIOSProof(host.CreditIOSProof):
    bundle = 'app.morse.storage.upgrade.proof.ios'
    preparing = False

    def run(self, *command, **kwargs):
        if self.preparing and tuple(command[:2]) == ('xcrun', 'simctl'):
            raise Built()
        return super().run(*command, **kwargs)

    def cold(self, operation, id=b'', body=b'', rejected=False):
        self.restart()
        value = self.invoke(operation, id, body, rejected)
        self.sequence += 1
        save(self.work / f'{self.sequence}-{operation}.json', {'operation': operation, 'expected_rejection': rejected, 'response': value if rejected else value.hex()})
        return value

    def snapshot(self):
        self.run('xcrun', 'simctl', 'terminate', self.device, self.bundle, check=False)
        path = self.directory / 'storage-upgrade-proof.db'
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as database:
            schema = database.execute("SELECT sql FROM sqlite_master WHERE name='encrypted_blobs'").fetchone()[0]
            columns = [row[1] for row in database.execute('PRAGMA table_info(encrypted_blobs)')]
            values = [{'index': key, 'ciphertext_sha256': hashlib.sha256(ciphertext).hexdigest()} for key, ciphertext in database.execute('SELECT record_hash,ciphertext FROM encrypted_blobs ORDER BY record_hash')]
            index_exists = database.execute("SELECT name FROM sqlite_master WHERE name='encrypted_blob_index'").fetchone()
            versions = [row[0] for row in database.execute('SELECT version FROM encrypted_blob_index')] if index_exists else []
            try:
                database.execute('SELECT rowid FROM encrypted_blobs LIMIT 1').fetchone()
                rowid = True
            except sqlite3.OperationalError:
                rowid = False
        return {'schema': schema, 'columns': columns, 'records': values, 'index_versions': versions, 'rowid_available': rowid}

    def replace(self, executable):
        self.run('xcrun', 'simctl', 'terminate', self.device, self.bundle, check=False)
        installed = Path(self.run('xcrun', 'simctl', 'get_app_container', self.device, self.bundle, 'app').stdout.strip())
        shutil.copy2(executable, installed / 'CreditProof')
        self.run('codesign', '--force', '--sign', '-', installed)
        assert sha(installed / 'CreditProof') == sha(executable)
        current = Path(self.run('xcrun', 'simctl', 'get_app_container', self.device, self.bundle, 'data').stdout.strip()) / 'Documents'
        assert current == self.directory, 'owned data sandbox moved during binary upgrade'


def fixture(work, phase, config):
    return StorageIOSProof(work / phase / 'product', work / phase, config['security'], proof_source=HERE / 'StorageUpgradeProof.swift', network_config=config['network'])


def prepare(args):
    args.work.mkdir(parents=True, exist_ok=False)
    config = {'security': args.security_config.read_text(), 'network': args.network_config.read_text()}
    save(args.work / 'config.json', config)
    original = args.prepared_product / 'apps/mobile/modules/mesh-messenger'
    inputs = {}
    for phase, native in [('legacy', args.legacy_native), ('candidate', args.candidate_native)]:
        module = args.work / phase / 'product/apps/mobile/modules/mesh-messenger'
        for name in ['generated/libmessenger_mobile.h', 'generated/libmessenger_mobile.swift', 'ios/MeshMessengerSecureStore.h', 'ios/MeshMessengerSecureStore.m']:
            source = original / name
            clone(source, module / name)
            inputs[str(source.resolve())] = sha(source)
        for extension in ['h', 'swift']:
            assert (native / ('libmessenger_mobile.' + extension)).read_bytes() == (original / 'generated' / ('libmessenger_mobile.' + extension)).read_bytes()
        source = native / 'libmessenger_mobile.a'
        clone(source, module / 'native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a')
        inputs[str(source.resolve())] = sha(source)
        app = fixture(args.work, phase, config)
        app.preparing = True
        os.environ.pop('MORSE_LIGHTNING_IOS_MODULE', None)
        try:
            app.__enter__()
        except Built:
            pass
        else:
            raise AssertionError('prepare unexpectedly reached device operations')
        save(args.work / phase / 'host-inputs.json', app.input_hashes)
    for source in [Path(__file__), HERE / 'StorageUpgradeProof.swift', HERE / 'run_android.py', PRODUCT / 'scripts/credit_ios_proof.py', PRODUCT / 'scripts/attachment_android_proof.py']:
        inputs[str(source)] = sha(source)
    save(args.work / 'inputs.json', inputs)
    for name, digest in inputs.items():
        destination = args.work / 'input-bodies' / digest
        if not destination.exists():
            clone(Path(name), destination)
    artifacts = {str(path.relative_to(args.work)): sha(path) for phase in ['legacy', 'candidate'] for path in (args.work / phase / 'ios-credit/CreditProof.app').rglob('*') if path.is_file()}
    save(args.work / 'prepared.json', {'status': 'prepared_without_device_access', 'inputs': inputs, 'artifacts': artifacts})
    print('Prepared exact legacy and candidate Swift apps without device access.', flush=True)


def run(args):
    prepared = json.loads((args.work / 'prepared.json').read_text())
    for name, digest in prepared['artifacts'].items():
        assert sha(args.work / name) == digest
    for name, digest in prepared['inputs'].items():
        assert sha(name) == digest
    config = json.loads((args.work / 'config.json').read_text())
    app = fixture(args.work, 'legacy', config)
    app.sequence = 0
    result = {'status': 'running', 'started_at': time.time(), 'scope': 'owned iOS Simulator native binary upgrade with Keychain and unchanged sandbox path', 'checks': []}
    save(args.work / 'result.json', result)
    assert app.run('xcrun', 'simctl', 'get_app_container', app.device, app.bundle, 'app', check=False).returncode != 0, 'owned app already installed'
    try:
        app.run('xcrun', 'simctl', 'bootstatus', app.device, '-b')
        app.run('xcrun', 'simctl', 'install', app.device, app.work / 'CreditProof.app')
        app.directory = Path(app.run('xcrun', 'simctl', 'get_app_container', app.device, app.bundle, 'data').stdout.strip()) / 'Documents'
        app.cold('create')
        profile = app.cold('profile')
        key, other_key = b'preferences/read-receipts', b'preferences/notification-preview'
        app.cold('write', profile, vector(key) + vector(b'off'))
        app.cold('write', profile, vector(other_key) + vector(b'sender'))
        before = app.snapshot()
        assert 'updated_at' in before['columns'] and before['rowid_available'] and not before['index_versions']
        for label in [b'profile/v1', b'journal/v1/' + key, b'journal/v1/' + other_key]:
            assert hashlib.sha256(label).hexdigest() in records(before).values()
        save(args.work / 'legacy-schema.json', before)
        app.replace(app.work / 'CreditProof.app/CreditProof')
        assert app.cold('profile') == profile
        assert app.snapshot() == before
        try:
            modern(before)
        except AssertionError as failure:
            result['negative_control'] = {'status': 'expected_failure', 'reason': str(failure)}
        else:
            raise AssertionError('old native code unexpectedly satisfied migration requirements')
        result['checks'].append('legacy executable replacement remains legacy and retains identity')
        app.replace(args.work / 'candidate/ios-credit/CreditProof.app/CreditProof')
        assert app.snapshot() == before
        assert app.cold('profile') == profile
        after = app.snapshot()
        modern(after)
        old_records, new_records = records(before), records(after)
        assert old_records.keys() == new_records.keys()
        assert not set(old_records.values()) & set(new_records.values())
        save(args.work / 'candidate-schema.json', after)
        assert app.cold('read', profile, key) == b'off'
        assert app.cold('read', profile, other_key) == b'sender'
        assert app.cold('profile') == profile
        assert app.snapshot() == after
        result['checks'].extend(['native startup migrates every label with identical ciphertext', 'same profile and both sealed preferences survive cold processes', 'repeat cold open is idempotent'])
        foreign = app.cold('foreign-profile')
        assert foreign != profile
        app.cold('write', foreign, vector(key) + vector(b'on'), rejected=True)
        assert app.snapshot() == after
        app.cold('write', profile, vector(key) + vector(b'on'))
        assert app.cold('read', profile, key) == b'on'
        assert app.cold('read', profile, other_key) == b'sender'
        assert app.cold('profile') == profile
        final = app.snapshot()
        modern(final)
        assert len(records(final)) == len(new_records)
        assert len(records(final).keys() - new_records.keys()) == 1
        result['checks'].extend(['foreign account write rejected without mutation', 'new encrypted write survives cold process and preserves other records'])
        result.update(status='passed', migrated_records=len(new_records), native_calls=app.sequence, profile_sha256=hashlib.sha256(profile).hexdigest())
    except BaseException as failure:
        result.update(status='failed', error=repr(failure))
        raise
    finally:
        if hasattr(app, 'directory'):
            try:
                app.cold('erase')
                result['owned_key_custody_erased'] = True
            except BaseException as failure:
                result['owned_key_cleanup_error'] = repr(failure)
        app.run('xcrun', 'simctl', 'terminate', app.device, app.bundle, check=False)
        app.run('xcrun', 'simctl', 'uninstall', app.device, app.bundle, check=False)
        result['owned_bundle_removed'] = app.run('xcrun', 'simctl', 'get_app_container', app.device, app.bundle, 'app', check=False).returncode != 0
        result['finished_at'] = time.time()
        save(args.work / 'result.json', result)
    assert result['owned_bundle_removed'] and result.get('owned_key_custody_erased')
    print(json.dumps(result, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'run'])
    parser.add_argument('--work', type=Path, required=True)
    for name in ['prepared-product', 'legacy-native', 'candidate-native', 'network-config', 'security-config']:
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    args.work = args.work.resolve()
    if args.action == 'prepare':
        for name in ['prepared_product', 'legacy_native', 'candidate_native', 'network_config', 'security_config']:
            assert getattr(args, name) is not None, f'prepare requires {name}'
        prepare(args)
    else:
        run(args)


if __name__ == '__main__':
    main()
