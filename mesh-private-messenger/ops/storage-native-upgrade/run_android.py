#!/usr/bin/env python3
"""Upgrade an owned Android account from exact old native code to a candidate.

No Mesh recompilation, extra exports, key injection, database rewriting, or live
services. Both APKs retain one signing key, UID, private data path and Keystore.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
PRODUCT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('storage_upgrade_android_host', PRODUCT / 'scripts/attachment_android_proof.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def clone(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    assert not target.exists(), f'owned output already exists: {target}'
    subprocess.run(['cp', '-c', str(source), str(target)], check=True)
    assert sha(source) == sha(target)


def vector(value):
    return len(value).to_bytes(4, 'big') + value


def modern(snapshot):
    assert snapshot['columns'] == ['record_hash', 'ciphertext'], 'legacy clear timestamps remain'
    assert snapshot['index_versions'] == [2], 'keyed index binding is absent'
    assert 'WITHOUT ROWID' in snapshot['schema'].upper() and 'STRICT' in snapshot['schema'].upper()
    assert snapshot['rowid_available'] is False


def records(snapshot):
    values = {row['ciphertext_sha256']: row['index'] for row in snapshot['records']}
    assert len(values) == len(snapshot['records']), 'ambiguous ciphertext mapping'
    return values


class StorageAndroidProof(host.AttachmentAndroidProof):
    bundle = 'app.morse.storage.upgrade.proof'
    instrumentation_class = 'StorageUpgradeProofTest'

    def upgrade(self, library, archive):
        self.restart()
        shutil.copyfile(library, self.work / 'lib/arm64-v8a/libmessenger_mobile.so')
        subprocess.run(['zip', '-q', 'proof.apk', 'lib/arm64-v8a/libmessenger_mobile.so'], cwd=self.work, check=True)
        self.run(self.sdk / 'build-tools/36.0.0/apksigner', 'sign', '--ks', self.work / 'test-key.p12', '--ks-pass', 'pass:android', self.work / 'proof.apk')
        clone(self.work / 'proof.apk', archive)
        self.device('install', '-r', self.work / 'proof.apk')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepared-product', type=Path, required=True)
    parser.add_argument('--legacy-native', type=Path, required=True)
    parser.add_argument('--candidate-native', type=Path, required=True)
    parser.add_argument('--candidate-jni', type=Path, required=True)
    parser.add_argument('--network-config', type=Path, required=True)
    parser.add_argument('--security-config', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    args.work = args.work.resolve()
    args.work.mkdir(parents=True, exist_ok=False)
    result = {'status': 'running', 'serial': args.serial, 'started_at': time.time(), 'scope': 'owned real native account upgrade; no production installation', 'checks': []}
    save(args.work / 'result.json', result)
    module_relative = Path('apps/mobile/modules/mesh-messenger')
    original = args.prepared_product / module_relative
    product = args.work / 'legacy-product'
    module = product / module_relative
    # Frozen current hosts/bindings are identical across the two native ABIs.
    for extension in ['h', 'kt', 'swift', 'jni.c', 'ts']:
        name = 'libmessenger_mobile.' + extension
        assert (args.legacy_native / name).read_bytes() == (args.candidate_native / name).read_bytes() == (original / 'generated' / name).read_bytes(), name
    inputs = {}
    for prefix in ['generated', 'android/src/main', 'native/include']:
        for source in sorted((original / prefix).rglob('*')):
            if source.is_file():
                clone(source, module / source.relative_to(original))
                inputs[str(source)] = sha(source)
    wallet = original / 'native/android/arm64-v8a/libmorse_wallet_core.a'
    clone(wallet, module / wallet.relative_to(original))
    inputs[str(wallet)] = sha(wallet)
    clone(args.legacy_native / 'libmessenger_mobile.a', module / 'native/android/arm64-v8a/libmessenger_mobile.a')
    for source in [args.legacy_native / 'libmessenger_mobile.a', args.candidate_native / 'libmessenger_mobile.a', args.candidate_jni, HERE / 'StorageUpgradeProof.kt', Path(__file__), PRODUCT / 'scripts/attachment_android_proof.py', args.network_config, args.security_config]:
        inputs[str(source.resolve())] = sha(source)
    save(args.work / 'inputs.json', inputs)
    for name, digest in inputs.items():
        destination = args.work / 'input-bodies' / digest
        if not destination.exists():
            clone(Path(name), destination)
    sdk = Path('/opt/homebrew/share/android-commandlinetools')
    cmake = sdk / 'cmake/3.22.1/bin/cmake'
    output = module / 'android/build/storage-upgrade/arm64-v8a'
    commands = [[str(cmake), '-S', str(module / 'android/src/main/cpp'), '-B', str(output), '-G', 'Ninja', '-DCMAKE_MAKE_PROGRAM=' + str(sdk / 'cmake/3.22.1/bin/ninja'), '-DCMAKE_TOOLCHAIN_FILE=' + str(sdk / 'ndk/28.2.13676358/build/cmake/android.toolchain.cmake'), '-DANDROID_ABI=arm64-v8a', '-DANDROID_PLATFORM=android-26', '-DCMAKE_BUILD_TYPE=Debug'], [str(cmake), '--build', str(output), '-j2']]
    with (args.work / 'legacy-jni-build.log').open('w') as log:
        for command in commands:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    legacy_jni = output / 'libmessenger_mobile.so'
    result['libraries'] = {'legacy_jni_sha256': sha(legacy_jni), 'candidate_jni_sha256': sha(args.candidate_jni)}
    os.environ['MORSE_ATTACHMENT_ANDROID_SERIAL'] = args.serial
    os.environ['MORSE_ATTACHMENT_ANDROID_LIBRARY'] = str(legacy_jni)
    fixture = StorageAndroidProof(product, args.work, args.security_config.read_text(), proof_source=HERE / 'StorageUpgradeProof.kt', network_config=args.network_config.read_text())
    assert not fixture.device('shell', 'pm', 'path', fixture.bundle, check=False).stdout.strip(), 'owned bundle already exists; refusing to uninstall it'
    try:
        with fixture as app:
            clone(app.work / 'proof.apk', args.work / 'legacy.apk')
            app.invoke('create')
            profile = app.invoke('profile')
            assert profile
            key = b'preferences/read-receipts'
            other_key = b'preferences/notification-preview'
            app.invoke('write', profile, vector(key) + vector(b'off'))
            app.invoke('write', profile, vector(other_key) + vector(b'sender'))
            assert app.invoke('read', profile, key) == b'off'
            before = json.loads(app.invoke('inspect'))
            assert 'updated_at' in before['columns'] and before['rowid_available']
            assert not before['index_versions']
            for label in [b'profile/v1', b'journal/v1/' + key, b'journal/v1/' + other_key]:
                assert hashlib.sha256(label).hexdigest() in records(before).values()
            save(args.work / 'legacy-schema.json', before)
            # Negative control: a real reinstall retaining custody/data does not
            # itself migrate anything when the native library remains old.
            app.restart()
            app.device('install', '-r', app.work / 'proof.apk')
            assert app.invoke('profile') == profile
            control = json.loads(app.invoke('inspect'))
            assert control == before
            try:
                modern(control)
            except AssertionError as failure:
                result['negative_control'] = {'status': 'expected_failure', 'reason': str(failure)}
            else:
                raise AssertionError('old native code unexpectedly satisfied migration requirements')
            result['checks'].append('legacy native reinstallation preserves account and remains legacy')
            app.upgrade(args.candidate_jni, args.work / 'candidate.apk')
            # Inspect before calling initialize: APK replacement must not have
            # manufactured the keyed database outside Mesh.
            assert json.loads(app.invoke('inspect')) == before
            assert app.invoke('profile') == profile
            after = json.loads(app.invoke('inspect'))
            modern(after)
            old_records, new_records = records(before), records(after)
            assert old_records.keys() == new_records.keys(), 'migration changed ciphertext'
            assert all(old_records[digest] != new_records[digest] for digest in old_records), 'a legacy guessable index survived'
            assert not set(old_records.values()) & set(new_records.values())
            save(args.work / 'candidate-schema.json', after)
            assert app.invoke('read', profile, key) == b'off'
            assert app.invoke('read', profile, other_key) == b'sender'
            assert app.invoke('profile') == profile
            assert json.loads(app.invoke('inspect')) == after
            result['checks'].extend(['native initialize migrates every label with identical ciphertext', 'same profile and both sealed preferences survive cold processes', 'repeat cold open is idempotent'])
            foreign = app.invoke('foreign-profile')
            assert foreign != profile
            app.invoke('write', foreign, vector(key) + vector(b'on'), rejected=True)
            assert json.loads(app.invoke('inspect')) == after
            app.invoke('write', profile, vector(key) + vector(b'on'))
            assert app.invoke('read', profile, key) == b'on'
            assert app.invoke('read', profile, other_key) == b'sender'
            assert app.invoke('profile') == profile
            final = json.loads(app.invoke('inspect'))
            modern(final)
            assert len(records(final)) == len(new_records)
            assert len(records(final).keys() - new_records.keys()) == 1
            result['checks'].extend(['foreign account write rejected without mutation', 'new encrypted write survives cold process and preserves other records'])
            result['profile_sha256'] = hashlib.sha256(profile).hexdigest()
            result['migrated_records'] = len(new_records)
            result['native_calls'] = app.sequence
            result['status'] = 'passed'
    except BaseException as failure:
        result['status'] = 'failed'
        result['error'] = repr(failure)
        raise
    finally:
        # The fixture contains only an owned account. Remove its app/custody and
        # ephemeral APK signing key even if a native assertion fails.
        fixture.device('shell', 'am', 'force-stop', fixture.bundle, check=False)
        fixture.device('uninstall', fixture.bundle, check=False)
        (fixture.work / 'test-key.p12').unlink(missing_ok=True)
        result['owned_bundle_removed'] = not fixture.device('shell', 'pm', 'path', fixture.bundle, check=False).stdout.strip()
        result['finished_at'] = time.time()
        save(args.work / 'result.json', result)
    assert result['owned_bundle_removed']
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
