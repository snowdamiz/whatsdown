#!/usr/bin/env python3
"""Qualify bounded public discovery locally; never deploy or query public RPC."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(['cp', '-c', str(source), str(target)], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        shutil.copy2(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--meshc', required=True, type=Path)
    parser.add_argument('--runtime-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--browser-executable', type=Path)
    parser.add_argument('--playwright-module', type=Path)
    args = parser.parse_args()
    product = Path(__file__).resolve().parents[2]
    package = Path(__file__).resolve().parent
    out = args.output.resolve()
    if out.exists():
        parser.error('--output must be a fresh directory')
    if bool(args.browser_executable) != bool(args.playwright_module):
        parser.error('provide both browser arguments or neither')
    tools = [args.meshc.resolve(), args.runtime_dir.resolve() / 'libmesh_rt.a',
             args.runtime_dir.resolve() / 'libmesh_test_rt.a']
    if not all(path.is_file() for path in tools):
        parser.error('explicit compiler/runtime inputs must exist')
    provenance = json.loads((package / 'fixtures/history-provenance.json').read_text())
    legacy = json.loads((package / 'fixtures/history-legacy-provenance.json').read_text())
    for record in provenance['fixtures'] + legacy['fixtures']:
        if digest(package / 'fixtures' / record['file']) != record['sha256']:
            parser.error('owned fixture provenance digest mismatch')
    out.mkdir(parents=True)
    records, packages = [], set()

    def capture(path, relative):
        target = out / 'sources' / relative
        copy(path, target)
        records.append({'path': str(path), 'archive': str(target.relative_to(out)), 'sha256': digest(target)})

    def dependency(path):
        path = path.resolve()
        if path in packages:
            return
        packages.add(path)
        manifest = tomllib.loads((path / 'mesh.toml').read_text())
        name = manifest['package']['name']
        for source in sorted(path.rglob('*')):
            if source.is_file() and (source.suffix == '.mpl' or source.name == 'mesh.toml'):
                capture(source, Path('packages') / name / source.relative_to(path))
        for spec in manifest.get('dependencies', {}).values():
            if 'path' in spec:
                dependency(path / spec['path'])

    dependency(package)
    for source in sorted(package.rglob('*')):
        if source.is_file() and source.suffix in ['.mjs', '.json', '.md', '.py']:
            capture(source, Path('product/ops/public-chain') / source.relative_to(package))
    landing = product / 'apps/landing'
    for name in ['network-history.js', 'network-history.test.mjs', 'network-history.browser.test.mjs',
                 'network-report.js', 'network-report.test.mjs', 'network.html', 'network.css', 'network-data.js',
                 'network-history-legacy.test.mjs', 'network-history-legacy.browser.test.mjs']:
        capture(landing / name, Path('product/apps/landing') / name)
    for index, source in enumerate(tools):
        target = out / 'tooling' / (Path('meshc') if index == 0 else Path('runtime') / source.name)
        copy(source, target)
        records.append({'path': str(source), 'archive': str(target.relative_to(out)), 'sha256': digest(target)})
    if args.browser_executable:
        records.append({'path': str(args.browser_executable.resolve()), 'sha256': digest(args.browser_executable.resolve()), 'scope': 'executed browser binary pin; not a reconstructed browser source claim'})
    (out / 'inputs-before.json').write_text(json.dumps({'records': records}, indent=2) + '\n')
    compiler = out / 'tooling/meshc'
    env = os.environ.copy()
    env.update({'MESHC': str(compiler), 'MESH_RT_LIB_PATH': str(out / 'tooling/runtime/libmesh_rt.a'),
                'MESH_TEST_RT_LIB_PATH': str(out / 'tooling/runtime/libmesh_test_rt.a'),
                'MORSE_PUBLIC_CHAIN_BIN': str(out / 'report'),
                'MORSE_PUBLIC_HISTORY_TOKEN_FIXTURE': str(package / 'fixtures/history-token.json'),
                'MORSE_PUBLIC_HISTORY_JUDGE_FIXTURE': str(package / 'fixtures/history-judge.json'),
                'MORSE_PUBLIC_HISTORY_LEGACY_FIXTURE': str(package / 'fixtures/history-legacy.json'),
                'MORSE_PUBLIC_COLLATERAL_FIXTURES_PATH': str(package / 'fixtures/token-custody-snapshots.json'),
                'MORSE_TOKEN_CARRY_FIXTURES_PATH': str(package / 'fixtures/token-carry-snapshots.json'),
                'MORSE_PUBLIC_REPORT_OUTPUT': str(out / 'selected-report.json'),
                'MORSE_PUBLIC_COLLATERAL_REPORT_OUTPUT': str(out / 'selected-collateral-report.json')})
    results = []

    def run(name, command, cwd=product, timeout=240):
        start = time.monotonic()
        with (out / (name + '.log')).open('w') as log:
            result = subprocess.run([str(value) for value in command], cwd=cwd, env=env,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        results.append({'name': name, 'command': [str(value) for value in command],
                        'exit_code': result.returncode, 'seconds': round(time.monotonic() - start, 3)})
        (out / 'results-in-progress.json').write_text(json.dumps(results, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(name + ' failed; inspect its bounded local log')

    failure = None
    try:
        run('build', [compiler, 'build', package, '--output', out / 'report'])
        run('mesh-tests', [compiler, 'test', package / 'tests'], package)
        run('selected-export', ['node', '--test', package / 'export.test.mjs'])
        run('selected-collateral', ['node', '--test', package / 'collateral.test.mjs'])
        for name in ['reports', 'later-reports']:
            (out / name).mkdir()
        env['MORSE_HISTORY_REPORT_DIR'] = str(out / 'reports')
        env['MORSE_HISTORY_LATER_REPORT_DIR'] = str(out / 'later-reports')
        env['MORSE_HISTORY_TRACE_FILE'] = str(out / 'public-requests.json')
        run('history-http', ['node', '--test', package / 'history.test.mjs'])
        (out / 'legacy-reports').mkdir()
        env['MORSE_LEGACY_REPORT_DIR'] = str(out / 'legacy-reports')
        run('legacy-http', ['node', '--test', package / 'legacy.test.mjs'])
        run('viewer', ['node', '--test', landing / 'network-history.test.mjs', landing / 'network-report.test.mjs', landing / 'network-history-legacy.test.mjs'])
        if args.browser_executable:
            env['PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH'] = str(args.browser_executable.resolve())
            env['MORSE_PLAYWRIGHT_MODULE'] = args.playwright_module.resolve().as_uri()
            env['MORSE_HISTORY_BROWSER_EVIDENCE'] = str(out / 'browser-assertions.json')
            env['MORSE_LEGACY_BROWSER_EVIDENCE'] = str(out / 'legacy-browser-assertions.json')
            run('browser', ['node', '--test', landing / 'network-history.browser.test.mjs', landing / 'network-history-legacy.browser.test.mjs'])
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        failure = str(error)
    drift = [record['path'] for record in records if digest(Path(record['path'])) != record['sha256']]
    summary = {'schema_version': 1, 'results': results, 'failure': failure, 'source_drift': drift,
               'browser': 'executed-instrumented-no-capture' if args.browser_executable else 'not-run',
               'limits': ['Owned loopback fixtures only; no live RPC, deployment or funds.',
                          'Whole returned filtered-set quorum is not a proof of provider completeness.',
                          'Discovery and value pages have separate banks; no global total.',
                          'Explicit legacy-v1 context qualifies configured single-mint MEC1/MBD1/MPR1 values; no ticker/fiat identity, v2 reinterpretation or full migration-context support.',
                          'Cloned later banks advance controlled Clock/slot only; no production ledger finality.',
                          'Compiler/runtime executable pins only; this proof does not rebuild the language.']}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    files = [{'path': str(path.relative_to(out)), 'sha256': digest(path), 'bytes': path.stat().st_size}
             for path in sorted(out.rglob('*')) if path.is_file() and path.name != 'manifest.json']
    (out / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'records': files}, indent=2) + '\n')
    print(json.dumps({'failure': failure, 'source_drift': drift, 'manifest_sha256': digest(out / 'manifest.json')}))
    return 1 if failure or drift else 0


if __name__ == '__main__':
    raise SystemExit(main())
