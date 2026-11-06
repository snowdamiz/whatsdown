#!/usr/bin/env python3
"""Retain exact owned-upgrade evidence; refuse incomplete platform results."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--android-work', type=Path, required=True)
    parser.add_argument('--ios-work', type=Path, required=True)
    parser.add_argument('--prior-android-attempt', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    platforms = {'android': args.android_work, 'ios': args.ios_work}
    results = {}
    for name, work in platforms.items():
        result = json.loads((work / 'result.json').read_text())
        assert result['status'] == 'passed', f'{name} is not passed'
        assert result['owned_bundle_removed'] and result['migrated_records'] > 0
        assert result['negative_control']['status'] == 'expected_failure'
        assert len(result['checks']) == 6
        if name == 'ios':
            assert result['owned_key_custody_erased']
        results[name] = result
    assert not args.output.exists(), 'immutable seal output already exists'
    args.output.mkdir(parents=True)
    records = []

    def retain(source, relative):
        target = args.output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = sha(source)
        if target.exists():
            assert sha(target) == digest
            return
        subprocess.run(['cp', '-c', str(source), str(target)], check=True)
        assert sha(target) == digest
        target.chmod(0o444)
        records.append({'path': str(relative), 'sha256': digest, 'bytes': target.stat().st_size})

    if args.prior_android_attempt:
        platforms['prior-android-attempt'] = args.prior_android_attempt
    for name, work in platforms.items():
        for filename in ['result.json', 'inputs.json', 'legacy-schema.json', 'candidate-schema.json', 'prepared.json', 'config.json', 'legacy-jni-build.log']:
            source = work / filename
            if source.is_file():
                retain(source, Path(name) / filename)
        for original, digest in json.loads((work / 'inputs.json').read_text()).items():
            source = work / 'input-bodies' / digest
            assert sha(source) == digest, f'input body absent or changed: {original}'
            retain(source, Path('input-bodies') / digest)
        candidates = [work / 'legacy.apk', work / 'candidate.apk']
        candidates += list((work / 'android-attachment').glob('*.json'))
        candidates += list((work / 'android-attachment').glob('*.log'))
        for phase in ['legacy', 'candidate']:
            candidates += list((work / phase / 'ios-credit').glob('*.json'))
            candidates += list((work / phase / 'ios-credit/CreditProof.app').rglob('*'))
        for source in candidates:
            if source.is_file():
                retain(source, Path(name) / source.relative_to(work))
    for source in Path(__file__).resolve().parent.iterdir():
        if source.is_file():
            retain(source, Path('proof-source') / source.name)
    manifest = {'schema_version': 1, 'status': 'passed_owned_dual_native_storage_upgrade', 'platforms': results, 'records': sorted(records, key=lambda row: row['path']), 'scope': 'real old/new 163-export native libraries and OS custody; physical Android and iOS Simulator; no store upgrade, physical iOS or forensic-erasure claim'}
    path = args.output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    path.chmod(0o444)
    print(json.dumps({'records': len(records), 'manifest_sha256': sha(path), 'status': manifest['status']}), flush=True)


if __name__ == '__main__':
    main()
