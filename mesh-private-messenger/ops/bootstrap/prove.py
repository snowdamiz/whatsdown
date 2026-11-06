#!/usr/bin/env python3
"""Repeatable LOCAL synthetic native bootstrap qualification, never production."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PRODUCT = Path(__file__).resolve().parents[2]
FIXTURE = PRODUCT / 'tests/bootstrap-native-20261106'
EXPECTED = {
    'meshc': '19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85',
    'libmesh_rt.a': 'd1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8',
    'libmesh_test_rt.a': '9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*'))
            if p.is_file() and p.suffix in ('.mpl', '.toml', '.py', '.c')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--mesh-source', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--build-only', action='store_true')
    parser.add_argument('--keep-work', action='store_true')
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='bootstrap-native-', dir=evidence))
    record = {'scope': 'LOCAL synthetic fixture; NOT native phone or production acceptance',
              'production_checks': ['pending'] * 8, 'ohttp': 'explicit off',
              'base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=PRODUCT, text=True).strip(),
              'mesh_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.mesh_source, text=True).strip(),
              'toolchain': {}, 'source_hashes': {}, 'artifacts': {}, 'commands': [], 'status': 'FAIL'}
    log = evidence / 'build.log'
    try:
        (work / 'toolchain').mkdir()
        for name in EXPECTED:
            source = args.compiler.resolve() if name == 'meshc' else args.compiler.resolve().parent.parent / 'lib' / name
            assert digest(source) == EXPECTED[name], f'unqualified family: {source}'
            target = work / 'toolchain' / name
            shutil.copy2(source, target)
            assert digest(target) == digest(source) == EXPECTED[name]
            record['toolchain'][name] = {'source': str(source), 'sha256': digest(target)}
        for name in ('mobile-core', 'messenger-protocol'):
            source = PRODUCT / 'packages' / name
            hashes = sources(source)
            for relative, value in hashes.items():
                target = work / name / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target)
                assert digest(target) == value
            record['source_hashes'][name] = hashes
            manifest = work / name / 'mesh.toml'
            manifest.write_text(manifest.read_text().replace('../../../mesh-lang/packages/',
                                str(args.mesh_source.resolve() / 'packages') + '/'))
        shutil.copytree(FIXTURE, work / 'driver', ignore=shutil.ignore_patterns('__pycache__'))
        manifest = work / 'driver/mesh.toml'
        manifest.write_text(manifest.read_text().replace('../../packages/mobile-core', '../mobile-core'))
        record['source_hashes']['fixture'] = sources(FIXTURE)
        record['source_hashes']['runner'] = {str(Path(__file__).name): digest(Path(__file__))}
        record['source_hashes']['mesh-packages'] = sources(args.mesh_source / 'packages')
        compiler = work / 'toolchain/meshc'
        library = work / ('libbootstrap.dylib' if sys.platform == 'darwin' else 'libbootstrap.so')
        command = [str(compiler), 'build', str(work / 'driver'), '--artifact', 'cdylib',
                   '--opt-level', '2', '--output', str(library)]
        record['commands'].append(command)
        environment = dict(os.environ, MESH_RT_LIB_PATH=str(work / 'toolchain/libmesh_rt.a'))
        with log.open('w') as output:
            subprocess.run(command, env=environment, stdout=output, stderr=subprocess.STDOUT,
                           check=True, timeout=600)
            bridge = library.with_name('libbootstrap_host' + library.suffix)
            command = ['cc', '-Wall', '-Wextra', '-Werror',
                       '-dynamiclib' if sys.platform == 'darwin' else '-shared',
                       '-fPIC', str(work / 'driver/abi_host.c'), '-I', str(work), str(library),
                       '-Wl,-rpath,' + str(work), '-o', str(bridge)]
            record['commands'].append(command)
            record['c_compiler'] = subprocess.check_output(['cc', '--version'], text=True)
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=30)
            record['artifacts'][bridge.name] = digest(bridge)
        for path in work.glob('libbootstrap.*'):
            record['artifacts'][path.name] = digest(path)
        abi = json.loads(library.with_suffix('.abi.json').read_text())
        exported = {row['symbol'] for row in abi['exports']}
        assert {'mesh_messenger_directory_resolve', 'mesh_messenger_anchor_check'} <= exported
        if args.build_only:
            record['status'] = 'BUILT_NOT_RUN'
        else:
            sys.path.insert(0, str(work / 'driver'))
            from acceptance import run
            record.update(run(work, library))
        for name in ('mobile-core', 'messenger-protocol'):
            assert sources(PRODUCT / 'packages' / name) == record['source_hashes'][name], 'source drift'
        assert sources(args.mesh_source / 'packages') == record['source_hashes']['mesh-packages'], 'Mesh package drift'
        assert sources(FIXTURE) == record['source_hashes']['fixture'], 'fixture drift'
        assert digest(Path(__file__)) == record['source_hashes']['runner'][Path(__file__).name], 'runner drift'
    except Exception as error:
        record['error'] = str(error)
        raise
    finally:
        record['artifacts']['build.log'] = digest(log) if log.exists() else None
        result = work / 'local-result.json'
        if result.exists():
            shutil.copy2(result, evidence / 'local-result.json')
            record['artifacts']['local-result.json'] = digest(result)
        manifest = evidence / 'sources.json'
        manifest.write_text(json.dumps(record.pop('source_hashes'), indent=2) + '\n')
        record['sources_manifest_sha256'] = digest(manifest)
        record['work'] = str(work) if args.keep_work or args.build_only else 'removed after hashing'
        (evidence / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps({'status': record['status'], 'receipt': str(evidence / 'receipt.json'),
                          'work': record['work']}), flush=True)
        if not (args.keep_work or args.build_only):
            shutil.rmtree(work)
    return 0 if record['status'] == 'BUILT_NOT_RUN' else 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
