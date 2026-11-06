#!/usr/bin/env python3
"""Frozen local proof for versioned 20/30/50 accounting and external handoffs.

No production activation, external signing, broadcasts or live funds. The SBF
lane executes only disposable banks using explicit existing ELF fixtures.
"""
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
PROMOTED = ['token_policy', 'token_chain', 'token_burn', 'token_burn_write', 'token_burn_carry', 'token_burn_carry_write', 'token_burn_read', 'token_burn_carry_read']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    PROOF.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='treasury-revenue-v2-', dir=PROOF))
    env = os.environ.copy()
    env.pop('CARGO_TARGET_DIR', None)
    env.update(MESH_LANG_ROOT=str(PUBLIC))
    meshc = Path(env.get('MESHC', PUBLIC / 'target/debug/meshc')).resolve()
    env['MESHC'] = str(meshc)
    env.setdefault('MESH_RT_LIB_PATH', str(PUBLIC / 'target/debug/libmesh_rt.a'))
    env.setdefault('MESH_TEST_RT_LIB_PATH', str(PUBLIC / 'target/debug/libmesh_test_rt.a'))
    for key, default in {
        'MORSE_TOKEN_SBF_PATH': PRODUCT / 'programs/target/deploy/morse_token.so',
        'MORSE_JUDGE_SBF_PATH': PRODUCT / 'programs/target/deploy/morse_judge.so',
        'MORSE_REWARDS_SBF_PATH': PRODUCT / 'programs/target/deploy/morse_rewards.so',
        'MORSE_TOKEN_DEX_BIN_DIR': PROOF / 'token-dex',
    }.items():
        env.setdefault(key, str(default))
    artifacts = {'compiler': meshc}
    for key in ['MORSE_TOKEN_SBF_PATH', 'MORSE_JUDGE_SBF_PATH', 'MORSE_REWARDS_SBF_PATH', 'MESH_RT_LIB_PATH', 'MESH_TEST_RT_LIB_PATH']:
        if env.get(key):
            artifacts[key] = Path(env[key]).resolve()
    for name in ['jupiter.so', 'raydium.so']:
        artifacts[name] = Path(env['MORSE_TOKEN_DEX_BIN_DIR']) / name
    for path in artifacts.values():
        if not path.is_file():
            raise SystemExit(f'Missing proof artifact: {path}')
    env.setdefault('MORSE_TOKEN_CARRY_FIXTURES_PATH', str(PROOF / 'token-carry-fixtures.json'))
    env.setdefault('MORSE_TOKEN_BURN_FIXTURES_PATH', str(PROOF / 'token-burn-fixtures.json'))
    for key in ['MORSE_TOKEN_CARRY_FIXTURES_PATH', 'MORSE_TOKEN_BURN_FIXTURES_PATH']:
        artifacts[key] = Path(env[key]).resolve()
        if not artifacts[key].is_file():
            raise SystemExit(f'Missing proof fixture: {artifacts[key]}')
    source_paths = set()
    for folder in ['services/credit-issuer', 'ops/credit-treasury-policy', 'ops/credit-burn-handoff', 'ops/token', 'ops/token-v2', 'programs/morse-token', 'programs/morse-token-program', 'programs/morse-rewards', 'programs/morse-judge', 'tools/solana-nonce-proof']:
        source_paths.update(path for path in (PRODUCT / folder).rglob('*') if path.is_file() and path.suffix in EXTENSIONS and not any(part in {'target', 'node_modules', '__pycache__'} for part in path.parts))
    source_paths.update(path for path in (PRODUCT / 'packages/messenger-protocol').rglob('*') if path.is_file() and path.suffix in {'.mpl', '.toml'})
    source_paths.update(path for path in (PUBLIC / 'packages').rglob('*') if path.is_file() and path.suffix in {'.mpl', '.toml'} and 'target' not in path.parts)
    source_paths.update(PRODUCT / 'packages/messenger-protocol/transparency' / (name + '.mpl') for name in PROMOTED)
    source_paths.update(PRODUCT / path for path in ['programs/Cargo.toml', 'programs/Cargo.lock', 'scripts/prove-credit-revenue.py', 'scripts/prove-credit-revenue.sh', 'scripts/prove-credit-revenue-migration.py', 'scripts/prove-credit-issuer.py', 'scripts/prove-credit-treasury.py'])
    sources = []
    for path in sorted(source_paths):
        root, prefix = (PUBLIC, 'public') if path.is_relative_to(PUBLIC) else (PRODUCT, 'product')
        relative = Path(prefix) / path.relative_to(root)
        target = work / 'sources' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        sources.append({'path': str(path), 'sha256': sha(path), 'archived': str(Path('sources') / relative)})
    artifact_records = []
    for name, path in artifacts.items():
        target = work / 'artifacts' / name
        target.parent.mkdir(exist_ok=True)
        if subprocess.run(['cp', '-c', str(path), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            shutil.copy2(path, target)
        artifact_records.append({'name': name, 'path': str(path), 'sha256': sha(path), 'archived': str(target.relative_to(work))})
    (work / 'inputs.json').write_text(json.dumps({'sources': sources, 'artifacts': artifact_records}, indent=2) + '\n')
    checks = []

    def run(name, command, **extra):
        print(f'RUN {name}: {work / (name + ".log")}', flush=True)
        started = datetime.datetime.now(datetime.timezone.utc)
        with (work / (name + '.log')).open('w') as output:
            result = subprocess.run([str(arg) for arg in command], cwd=PRODUCT, env={**env, **extra}, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(f'Failed {name}; see {work / (name + ".log")}')
        checks.append({'name': name, 'command': [str(arg) for arg in command], 'passed': True, 'seconds': (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds(), 'log': name + '.log', 'log_sha256': sha(work / (name + '.log'))})

    for folder in ['services/credit-issuer', 'ops/credit-treasury-policy', 'ops/credit-burn-handoff', 'ops/token', 'ops/token-v2']:
        label = folder.replace('/', '-')
        run('format-' + label, [meshc, 'fmt', '--check', folder])
        run('lint-' + label, [meshc, 'lint', folder])
    for name in PROMOTED:
        run('format-' + name, [meshc, 'fmt', '--check', 'packages/messenger-protocol/transparency/' + name + '.mpl'])
        run('lint-' + name, [meshc, 'lint', 'packages/messenger-protocol/transparency/' + name + '.mpl'])
    run('scalar-reference-and-funding-id', [meshc, 'test', 'ops/credit-treasury-policy'])
    run('historical-migration', ['python3', 'scripts/prove-credit-revenue-migration.py'])
    run('issuer-owned-postgresql', ['python3', 'scripts/prove-credit-issuer.py'])
    run('burn-handoff-and-ready-fixtures', [meshc, 'test', 'ops/credit-burn-handoff'])
    run('burn-pinned-rpc', ['node', '--test', 'ops/credit-burn-handoff/rpc.test.mjs'])
    binary = work / 'credit-issuer'
    run('production-issuer-build', [meshc, 'build', 'services/credit-issuer', '-o', binary])
    run('external-owner-cli-sbf24', ['python3', 'ops/credit-burn-handoff/prove.py'], BURN_PROOF_CASE='cli', CREDIT_ISSUER_BIN=str(binary), BURN_CLI_REPORT=str(work / 'burn-cli.json'))
    run('rewards-bridge-build', ['cargo', 'build', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-rewards', '--features', 'svm', '--example', 'rewards_writer_bridge'])
    operator = work / 'rewards-test-operator'
    run('public-rewards-planner-build', [meshc, 'build', 'ops/rewards/fixtures/operator', '--opt-level', '2', '-o', operator])
    env['MORSE_REWARDS_TEST_OPERATOR_BIN'] = str(operator)
    for version in [1, 2]:
        run(f'witness-funding-v{version}-sbf', ['python3', 'scripts/prove-credit-treasury.py'], TREASURY_PROOF_CASE='funding', TREASURY_REVENUE_POLICY=str(version), TREASURY_REPORT=str(work / f'witness-funding-v{version}.json'))
    run('token-rust-format', ['cargo', 'fmt', '--manifest-path', 'programs/Cargo.toml', '--all', '--check'])
    run('token-rust-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-token', '--features', 'svm,dex', '--all-targets', '--', '-D', 'warnings'])
    run('token-policy-compatibility', [meshc, 'test', 'ops/token/policy.test.mpl'])
    writer = work / 'carry-instructions.json'
    run('promoted-carry-sdk-writer', [meshc, 'test', 'ops/token-v2/burn_carry_write.test.mpl'], MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH=str(writer))
    run('promoted-carry-writer-actual-sbf', ['cargo', 'test', '--locked', '--manifest-path', 'programs/Cargo.toml', '-p', 'morse-token', '--features', 'svm,dex', '--test', 'token_svm', 'missed_input_is_closed_once', '--', '--nocapture'], MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH=str(writer), MORSE_TOKEN_CARRY_FIXTURES_PATH=str(work / 'fresh-carry-fixtures.json'))
    for record in sources + artifact_records:
        if sha(Path(record['path'])) != record['sha256']:
            raise SystemExit(f'Frozen input changed during proof: {record["path"]}')
    for file in ['burn-cli.json', 'witness-funding-v1.json', 'witness-funding-v2.json']:
        if json.loads((work / file).read_text()).get('passed') is not True:
            raise SystemExit(f'Unpassed report: {file}')
    for path in [binary, operator, writer, work / 'fresh-carry-fixtures.json', work / 'burn-cli.json', work / 'witness-funding-v1.json', work / 'witness-funding-v2.json']:
        artifact_records.append({'name': path.name, 'path': str(path), 'sha256': sha(path), 'archived': str(path.relative_to(work)), 'generated': True})
    result = {'schema_version': 1, 'passed': True, 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checkpoint': str(work), 'checks': checks, 'sources': sources, 'artifacts': artifact_records, 'all_inputs_unchanged': True, 'phase5_complete': False, 'live_funds': False, 'boundaries': ['Synthetic SQL accounting rows and disposable local SBF banks; no live chain finality, feed, market or human independence claim', 'Two loopback RPC views are authenticated test providers of one isolated bank, not independent production operators', 'The external owner signs only in the local proof; production issuer neither holds that key nor broadcasts burn funding', 'USDC accounting and witnessed funding/burn handoffs qualified here; SOL/BTC conversion remains pending', 'Expired unfunded burn intents remain reserved until a future authenticated permanent onchain cancellation extension; no silent release', 'Continuous operations, live four-week exit gate, production deployment/activation remain open']}
    (work / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    (PROOF / 'treasury-revenue-v2-local.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS {len(checks)} frozen local checks: {work / "manifest.json"}', flush=True)


if __name__ == '__main__':
    main()
