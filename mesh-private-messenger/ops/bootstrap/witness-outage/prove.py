#!/usr/bin/env python3
"""Owned LOCAL process outage and actual MobileCore ABI proof; never B1 acceptance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

PRODUCT = Path(__file__).resolve().parents[3]
FIXTURE = PRODUCT / 'tests/bootstrap-witness-outage-native'
# Read-only use of the delivered bootstrap builder's hash/manifest contract.
HELPER = PRODUCT / 'ops/bootstrap/prove.py'
spec = importlib.util.spec_from_file_location('bootstrap_build_contract', HELPER)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
digest, sources = contract.digest, contract.sources


def inputs(mesh):
    return {'mobile-core': sources(PRODUCT / 'packages/mobile-core'),
            'messenger-protocol': sources(PRODUCT / 'packages/messenger-protocol'),
            'witness': sources(PRODUCT / 'services/transparency-witness'),
            'fixture': sources(FIXTURE), 'runner': sources(Path(__file__).parent),
            'mesh-packages': sources(mesh / 'packages'),
            'bootstrap-build-contract': {str(HELPER.relative_to(PRODUCT)): digest(HELPER)}}


def build(args, work):
    work.mkdir(parents=True, exist_ok=False)
    record = {'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=PRODUCT,
                                                   text=True).strip(),
              'mesh_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.mesh_source,
                                                  text=True).strip(),
              'inputs': inputs(args.mesh_source), 'artifacts': {}, 'commands': [], 'toolchain': {}}
    (work / 'toolchain').mkdir()
    for name, expected in contract.EXPECTED.items():
        source = args.compiler if name == 'meshc' else args.compiler.parent.parent / 'lib' / name
        assert digest(source) == expected, f'unqualified toolchain: {source}'
        shutil.copy2(source, work / 'toolchain' / name)
        assert digest(work / 'toolchain' / name) == expected
        record['toolchain'][name] = {'source': str(source), 'sha256': expected}
    for key, destination in [('mobile-core', 'mobile-core'), ('messenger-protocol', 'messenger-protocol'),
                             ('witness', 'witness')]:
        source = PRODUCT / ('services/transparency-witness' if key == 'witness' else 'packages/' + key)
        for relative, expected in record['inputs'][key].items():
            target = work / destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)
            assert digest(target) == expected
        manifest = work / destination / 'mesh.toml'
        manifest.write_text(manifest.read_text().replace('../../../mesh-lang/packages/',
            str(args.mesh_source / 'packages') + '/').replace('../../packages/messenger-protocol',
                                                            '../messenger-protocol'))
    shutil.copytree(FIXTURE, work / 'driver', ignore=shutil.ignore_patterns('__pycache__'))
    manifest = work / 'driver/mesh.toml'
    manifest.write_text(manifest.read_text().replace('../../packages/mobile-core', '../mobile-core'))
    compiler = str(work / 'toolchain/meshc')
    library = work / ('libbootstrap.dylib' if sys.platform == 'darwin' else 'libbootstrap.so')
    commands = [
        [compiler, 'build', str(work / 'driver'), '--artifact', 'cdylib', '--opt-level', '2',
         '--output', str(library)],
        ['cc', '-Wall', '-Wextra', '-Werror', '-dynamiclib' if sys.platform == 'darwin' else '-shared',
         '-fPIC', str(work / 'driver/abi_host.c'), '-I', str(work), str(library),
         '-Wl,-rpath,' + str(work), '-o', str(work / ('libbootstrap_host' + library.suffix))],
        [compiler, 'build', str(work / 'witness'), '--opt-level', '2', '--output', str(work / 'witness-service')],
    ]
    environment = {'PATH': os.environ['PATH'], 'MESH_RT_LIB_PATH': str(work / 'toolchain/libmesh_rt.a'),
                   'MESH_TEST_RT_LIB_PATH': str(work / 'toolchain/libmesh_test_rt.a')}
    with (work / 'build.log').open('w') as log:
        for command in commands:
            print(json.dumps({'building': command}), flush=True)
            record['commands'].append(command)
            subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=600)
    assert inputs(args.mesh_source) == record['inputs'], 'source drift during build'
    record['copied_sources'] = {name: sources(work / name) for name in
                               ['mobile-core', 'messenger-protocol', 'witness', 'driver']}
    for path in list(work.glob('libbootstrap*')) + [work / 'witness-service', work / 'build.log']:
        if path.is_file():
            record['artifacts'][path.name] = digest(path)
    abi = json.loads(library.with_suffix('.abi.json').read_text())
    assert 'mesh_messenger_directory_resolve' in {row['symbol'] for row in abi['exports']}
    (work / 'build.json').write_text(json.dumps(record, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--mesh-source', required=True, type=Path)
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--outage-seconds', type=int, default=900)
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    assert 60 <= args.outage_seconds <= 1800, 'outage must be bounded to 60..1800 real seconds'
    args.compiler, args.mesh_source = args.compiler.resolve(), args.mesh_source.resolve()
    work, evidence = args.build_dir.resolve(), args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    record = {'scope': 'LOCAL synthetic directory; actual witness pull executables and MobileCore ABI',
              'production_acceptance': False, 'anchors': 'disabled', 'ohttp': 'explicit off',
              'rpc_tls_resource_hex': '0100', 'command': sys.argv, 'status': 'FAIL'}
    record['execution_head'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=PRODUCT,
                                                      text=True).strip()
    try:
        if not work.exists():
            build(args, work)
        built = json.loads((work / 'build.json').read_text())
        assert inputs(args.mesh_source) == built['inputs'], 'build inputs drifted; use a new owned build directory'
        for name, expected in built['artifacts'].items():
            assert digest(work / name) == expected, f'artifact drift: {name}'
        for name, expected in built['copied_sources'].items():
            assert sources(work / name) == expected, f'copied source drift: {name}'
        shutil.copy2(work / 'build.json', evidence / 'build.json')
        record['build_sha256'] = digest(evidence / 'build.json')
        if args.build_only:
            record['status'] = 'BUILT_NOT_RUN'
        else:
            sys.path.insert(0, str(FIXTURE))
            from acceptance import run
            record.update(run(work, evidence, args.outage_seconds))
        assert inputs(args.mesh_source) == built['inputs'], 'source drift during run'
    except BaseException as error:
        record['status'] = 'FAIL'
        record['error'] = repr(error)
        raise
    finally:
        record['evidence_hashes'] = {str(p.relative_to(evidence)): digest(p) for p in sorted(evidence.rglob('*'))
                                    if p.is_file() and p.name != 'receipt.json'}
        (evidence / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps({'status': record['status'], 'receipt': str(evidence / 'receipt.json')}), flush=True)
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
