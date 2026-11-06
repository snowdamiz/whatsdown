#!/usr/bin/env python3
"""Frozen local unfunded-week recovery proof; no live chain or broadcasts."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]
PUBLIC = Path(os.environ.get('MESH_LANG_ROOT', PRODUCT / '../mesh-lang')).resolve()
PROOF = Path(os.environ.get('MORSE_PROOF_DIR', PRODUCT.parent / '.morse/witness-proof')).resolve()
EXTENSIONS = {'.mpl', '.toml', '.sql', '.md', '.py', '.mjs', '.json', '.rs', '.lock', '.sh', '.fixture'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    PROOF.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='token-unfunded-expiry-', dir=PROOF))
    env = os.environ.copy()
    # Fixture outputs always belong to this run, never an archived input.
    for key in list(env):
        if key == 'CARGO_TARGET_DIR' or key.startswith('MORSE_CREDIT_BURN_') or (key.startswith('MORSE_TOKEN_') and key.endswith('_PATH')):
            env.pop(key)
    meshc = Path(env.get('MESHC', PUBLIC / 'target/debug/meshc')).resolve()
    env.update(MESHC=str(meshc), MESH_LANG_ROOT=str(PUBLIC))
    env.setdefault('MESH_RT_LIB_PATH', str(PUBLIC / 'target/debug/libmesh_rt.a'))
    env.setdefault('MESH_TEST_RT_LIB_PATH', str(PUBLIC / 'target/debug/libmesh_test_rt.a'))
    env.setdefault('MORSE_TOKEN_DEX_BIN_DIR', str(PROOF / 'token-dex'))
    artifacts = {'compiler': meshc}
    for key in ['MESH_RT_LIB_PATH', 'MESH_TEST_RT_LIB_PATH']:
        artifacts[key] = Path(env[key]).resolve()
    for name in ['jupiter.so', 'raydium.so', 'spl_token-3.5.0.so', 'pinocchio_token_program.so']:
        path = Path(env['MORSE_TOKEN_DEX_BIN_DIR']) / name
        if path.is_file():
            artifacts[name] = path.resolve()
    if 'jupiter.so' not in artifacts or 'raydium.so' not in artifacts:
        raise SystemExit('Set MORSE_TOKEN_DEX_BIN_DIR to qualified local DEX fixture ELFs')
    source_paths = set()
    for folder in ['services/credit-issuer', 'ops/token-expiry', 'ops/token', 'ops/token-v2', 'ops/credit-burn-handoff', 'programs/morse-token', 'programs/morse-token-program']:
        source_paths.update(p for p in (PRODUCT / folder).rglob('*') if p.is_file() and p.suffix in EXTENSIONS and not any(x in {'target', 'node_modules', '__pycache__'} for x in p.parts))
    for folder in [PRODUCT / 'packages/messenger-protocol', PUBLIC / 'packages']:
        source_paths.update(p for p in folder.rglob('*') if p.is_file() and p.suffix in {'.mpl', '.toml'} and 'target' not in p.parts)
    source_paths.update(PRODUCT / p for p in ['programs/Cargo.toml', 'programs/Cargo.lock', 'protocol/token-burn-expiry-v1.md', 'scripts/prove-token-expiry.py', 'scripts/prove-token-expiry.sh', 'scripts/prove-credit-issuer.py', 'scripts/prove-credit-revenue-migration.py'])
    sources = []
    for path in sorted(source_paths):
        root, prefix = (PUBLIC, 'public') if path.is_relative_to(PUBLIC) else (PRODUCT, 'product')
        relative = Path('sources') / prefix / path.relative_to(root)
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        sources.append({'path': str(path), 'sha256': sha(path), 'archived': str(relative)})
    artifact_records = []
    for name, path in artifacts.items():
        target = work / 'artifacts' / name
        target.parent.mkdir(exist_ok=True)
        if subprocess.run(['cp', '-c', str(path), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            shutil.copy2(path, target)
        artifact_records.append({'name': name, 'path': str(path), 'sha256': sha(path), 'archived': str(target.relative_to(work))})
    checks = []

    def run(name, command, **extra):
        print(f'RUN {name}: {work / (name + ".log")}', flush=True)
        started = datetime.datetime.now(datetime.timezone.utc)
        with (work / (name + '.log')).open('w') as output:
            result = subprocess.run([str(a) for a in command], cwd=PRODUCT, env={**env, **extra}, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(f'Failed {name}: {work / (name + ".log")}')
        checks.append({'name': name, 'command': [str(a) for a in command], 'passed': True, 'seconds': (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds(), 'log': name + '.log', 'log_sha256': sha(work / (name + '.log'))})

    for folder in ['services/credit-issuer', 'ops/token-expiry']:
        run('format-' + folder.replace('/', '-'), [meshc, 'fmt', '--check', folder])
        run('lint-' + folder.replace('/', '-'), [meshc, 'lint', folder])
    for name in ['token_burn_expiry', 'token_burn_expiry_read']:
        source = 'packages/messenger-protocol/transparency/' + name + '.mpl'
        run('format-' + name, [meshc, 'fmt', '--check', source])
        run('lint-' + name, [meshc, 'lint', source])
    run('rust-format', ['cargo', 'fmt', '--manifest-path', 'programs/Cargo.toml', '--all', '--check'])
    run('rust-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-token', '--features', 'svm,dex', '--all-targets', '--', '-D', 'warnings'])
    builder = env.get('CARGO_BUILD_SBF', 'cargo-build-sbf')
    with tempfile.TemporaryDirectory(prefix='token-expiry-build-') as raw:
        run('fresh-token-sbf-build', [builder, '--manifest-path', 'programs/morse-token-program/Cargo.toml', '--sbf-out-dir', work / 'artifacts', '--arch', 'v0', '--tools-version', 'v1.57'], CARGO_TARGET_DIR=raw)
    env['MORSE_TOKEN_SBF_PATH'] = str(work / 'artifacts/morse_token.so')
    token_hash = sha(Path(env['MORSE_TOKEN_SBF_PATH']))
    env['MORSE_TOKEN_EXPIRY_FIXTURES_PATH'] = str(work / 'fresh-tombstone.json')
    for key, filename in [('MORSE_TOKEN_CARRY_FIXTURES_PATH', 'fresh-carry.json'), ('MORSE_TOKEN_BURN_FIXTURES_PATH', 'fresh-burn.json'), ('MORSE_TOKEN_FIXTURES_PATH', 'fresh-token.json')]:
        env[key] = str(work / filename)
    run('all-token-sbf-compatibility-and-expiry', ['cargo', 'test', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-token', '--features', 'svm,dex', '--test', 'token_svm', '--', '--nocapture'])
    writer = work / 'expiry-instructions.json'
    run('mesh-codec-reader-writer', [meshc, 'test', 'ops/token-expiry'], MORSE_TOKEN_EXPIRY_INSTRUCTIONS_PATH=str(writer))
    run('mesh-writer-actual-sbf', ['cargo', 'test', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-token', '--features', 'svm,dex', '--test', 'token_svm', 'expired_unfunded_week_is_permanent', '--', '--nocapture'], MORSE_TOKEN_EXPIRY_INSTRUCTIONS_PATH=str(writer))
    run('strict-finalized-rpc19', ['node', '--test', 'ops/token-expiry/rpc.test.mjs'])
    run('legacy-receipts-through-migration012', ['python3', 'scripts/prove-credit-revenue-migration.py'])
    run('all-isolated-issuer-postgresql', ['python3', 'scripts/prove-credit-issuer.py'])
    binary = work / 'credit-issuer'
    run('production-issuer-build', [meshc, 'build', 'services/credit-issuer', '-o', binary])
    run('actual-cli-expiry-release-new-sbf24', ['python3', 'ops/token-expiry/prove.py'], CREDIT_ISSUER_BIN=str(binary), BURN_EXPIRY_ARTIFACT_DIR=str(work / 'cli-fixtures'), BURN_EXPIRY_CLI_REPORT=str(work / 'cli-report.json'))
    if json.loads((work / 'cli-report.json').read_text()).get('passed') is not True:
        raise SystemExit('Unpassed CLI report')
    for record in sources + artifact_records:
        if sha(Path(record['path'])) != record['sha256']:
            raise SystemExit(f'Frozen input changed: {record["path"]}')
    if sha(Path(env['MORSE_TOKEN_SBF_PATH'])) != token_hash:
        raise SystemExit('Fresh token ELF changed')
    generated = [Path(env['MORSE_TOKEN_SBF_PATH']), binary, writer, work / 'fresh-tombstone.json', work / 'cli-report.json'] + sorted((work / 'cli-fixtures').iterdir())
    for path in generated:
        artifact_records.append({'name': path.name, 'path': str(path), 'sha256': sha(path), 'archived': str(path.relative_to(work)), 'generated': True})
    tdd = work / 'tdd'
    tdd.mkdir()
    for name in ['program', 'codec', 'reader', 'rpc', 'ledger', 'command', 'cli']:
        path = PROOF / ('token-expiry-red.log' if name == 'program' else f'token-expiry-{name}-red.log')
        if not path.is_file():
            raise SystemExit(f'Missing functional red evidence: {path}')
        shutil.copy2(path, tdd / path.name)
    result = {'schema_version': 1, 'passed': True, 'checkpoint': str(work), 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': checks, 'sources': sources, 'artifacts': artifact_records, 'all_inputs_unchanged': True, 'live_funds': False, 'phase5_complete': False, 'boundaries': ['Permanent unfunded expiry and authenticated local release are qualified; no elapsed-time/unknown-outcome release', 'Actual compiled operator and locally signed SBF/SPL/DEX execution; synthetic prior SQL accounting and loopback views, not live consensus, price feed, market or independent providers', 'Issuer broadcasts zero transactions and retains immutable old membership after future reallocation/funding', 'Existing 39-check carry and42-check revenue archives remain separate and unchanged', 'Continuous funded operations, SOL/BTC conversion, live four-week gate and production deployment/activation remain open']}
    (work / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    (PROOF / 'token-unfunded-expiry-local.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS {len(checks)} frozen expiry checks: {work / "manifest.json"}', flush=True)


if __name__ == '__main__':
    main()
