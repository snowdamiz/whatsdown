#!/usr/bin/env python3
"""Seal passed production checks plus a narrowly revised CLI fixture reproof.

Only the CLI fixture and proof artifact selection may differ from the fail-fast runner's archived
snapshot. The failed original CLI attempt stays visible. No production result
is reused across a changed production input, and this is explicitly a two-
snapshot checkpoint rather than an all-inputs-unchanged claim.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

PRODUCT = Path(__file__).resolve().parents[1]
PUBLIC = Path(os.environ.get('MESH_LANG_ROOT', PRODUCT / '../mesh-lang')).resolve()
PROOF = Path(os.environ.get('MORSE_PROOF_DIR', PRODUCT.parent / '.morse/witness-proof')).resolve()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Pass the existing failed-CLI checkpoint directory')
    work = Path(sys.argv[1]).resolve()
    if work.parent != PROOF or not work.name.startswith('token-unfunded-expiry-'):
        raise SystemExit('Checkpoint must be an owned token-unfunded-expiry proof directory')
    driver = PROOF / 'token-unfunded-expiry-gate.log'
    driver_text = driver.read_text()
    names = re.findall(r'^RUN ([^:]+): (.+)$', driver_text, flags=re.MULTILINE)
    if len(names) != 19 or names[-1][0] != 'actual-cli-expiry-release-new-sbf24' or not driver_text.rstrip().endswith(str(work / 'actual-cli-expiry-release-new-sbf24.log')):
        raise SystemExit('Expected exact fail-fast runner reaching its nineteenth CLI check')
    if 'Failed actual-cli-expiry-release-new-sbf24:' not in driver_text:
        raise SystemExit('Expected the preserved CLI failure, never an unknown failed stage')
    if any(Path(log).parent != work for _, log in names):
        raise SystemExit('Driver references another checkpoint')
    failed = (work / 'actual-cli-expiry-release-new-sbf24.log').read_text()
    if 'cli.test.mjs:111:31' not in failed or 'credit treasury command failed' not in failed:
        raise SystemExit('Expected the reviewed stale-ready fixture refusal')
    sources, changed = [], []
    allowed = {Path('product/ops/token-expiry/cli.test.mjs'), Path('product/scripts/prove-token-expiry.py')}
    for archived in sorted((work / 'sources').rglob('*')):
        if not archived.is_file():
            continue
        relative = archived.relative_to(work / 'sources')
        root = PUBLIC if relative.parts[0] == 'public' else PRODUCT
        current = root.joinpath(*relative.parts[1:])
        if sha(archived) != sha(current):
            if relative not in allowed:
                raise SystemExit(f'Changed production or unrelated test input: {current}')
            revised = work / 'refreshed-harness' / relative.name
            revised.parent.mkdir(exist_ok=True)
            shutil.copy2(current, revised)
            changed.append({'path': str(current), 'before_sha256': sha(archived), 'after_sha256': sha(revised), 'original_archived': str(archived.relative_to(work)), 'revised_archived': str(revised.relative_to(work)), 'reason': 'Refresh ready bank through actual SBF after setup; proof runner selects only four DEX fixture inputs so an unrelated old token ELF cannot collide with the newly generated token ELF. Production behavior and all check commands are unchanged'})
            archived = revised
        sources.append({'path': str(current), 'sha256': sha(current), 'archived': str(archived.relative_to(work))})
    if len(changed) != 2:
        raise SystemExit('Expected exactly the reviewed two proof-only revisions')
    sealer = work / 'refreshed-harness/seal-token-expiry-reproof.py'
    shutil.copy2(Path(__file__), sealer)
    sources.append({'path': str(Path(__file__).resolve()), 'sha256': sha(sealer), 'archived': str(sealer.relative_to(work))})
    shutil.copy2(driver, work / 'frozen-gate-driver.log')
    checks = []
    for name, log in names[:-1]:
        path = Path(log)
        if not path.is_file():
            raise SystemExit(f'Missing passed-stage log: {path}')
        checks.append({'name': name, 'passed': True, 'log': path.name, 'log_sha256': sha(path), 'source_snapshot': 'initial', 'status_evidence': 'Archived fail-fast runner advanced to its next check; it exits immediately on nonzero status'})
    final = work / 'actual-cli-refreshed-sbf24.log'
    text = final.read_text()
    report = json.loads((work / 'cli-report.json').read_text())
    if report.get('passed') is not True or not re.search(r'^# pass 1$', text, re.MULTILINE) or not re.search(r'^# fail 0$', text, re.MULTILINE):
        raise SystemExit('Focused actual CLI reproof has not passed')
    checks.append({'name': names[-1][0], 'passed': True, 'log': final.name, 'log_sha256': sha(final), 'source_snapshot': 'refreshed-cli-harness', 'command': ['python3', 'ops/token-expiry/prove.py'], 'production_binary': 'credit-issuer', 'token_sbf': 'artifacts/morse_token.so'})
    inputs = {'compiler': Path(os.environ['MESHC']), 'MESH_RT_LIB_PATH': Path(os.environ['MESH_RT_LIB_PATH']), 'MESH_TEST_RT_LIB_PATH': Path(os.environ['MESH_TEST_RT_LIB_PATH'])}
    inputs.update({p.name: p for p in Path(os.environ['MORSE_TOKEN_DEX_BIN_DIR']).glob('*.so') if p.name != 'morse_token.so'})
    artifacts = []
    for name, live in inputs.items():
        archived = work / 'artifacts' / name
        if sha(live) != sha(archived):
            raise SystemExit(f'Changed binary input: {live}')
        artifacts.append({'name': name, 'path': str(live), 'sha256': sha(live), 'archived': str(archived.relative_to(work))})
    generated = [work / 'artifacts/morse_token.so', work / 'credit-issuer', work / 'expiry-instructions.json', work / 'cli-report.json', work / 'previous-archives-verification.json', work / 'frozen-gate-driver.log']
    generated += sorted(work.glob('fresh-*.json')) + sorted((work / 'cli-fixtures').iterdir())
    for path in generated:
        artifacts.append({'name': path.name, 'path': str(path), 'sha256': sha(path), 'archived': str(path.relative_to(work)), 'generated': True})
    tdd = work / 'tdd'
    tdd.mkdir(exist_ok=True)
    for name in ['program', 'codec', 'reader', 'rpc', 'ledger', 'command', 'cli']:
        path = PROOF / ('token-expiry-red.log' if name == 'program' else f'token-expiry-{name}-red.log')
        shutil.copy2(path, tdd / path.name)
    shutil.copy2(work / 'actual-cli-expiry-release-new-sbf24.log', tdd / 'fixture-stale-ready-refusal.log')
    result = {'schema_version': 1, 'passed': True, 'checkpoint': str(work), 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': checks, 'sources': sources, 'artifacts': artifacts, 'all_inputs_unchanged': False, 'all_production_inputs_unchanged': True, 'all_checks_use_exact_archived_sources': True, 'changed_test_inputs': changed, 'failed_attempt_preserved': 'tdd/fixture-stale-ready-refusal.log', 'live_funds': False, 'phase5_complete': False, 'boundaries': ['Eighteen unchanged production/source gate stages plus the final actual CLI proof under an explicitly archived test-only clock-refresh revision', 'Production60s freshness guard correctly refused the stale fixture; refreshed clock/oracle account bytes come from actual local SBF execution, never RPC byte rewriting', 'No elapsed-time or unknown-outcome release; exact permanent finalized pair required', 'Synthetic prior SQL accounting and loopback views; real local SBF/SPL/router CPIs do not establish live consensus, feed, market or provider independence', 'Issuer broadcasts zero transactions; immutable member history survives future reallocation/funding', 'Continuous funded operations, SOL/BTC conversion, live four-week gate and production deployment/activation remain open']}
    (work / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    (PROOF / 'token-unfunded-expiry-local.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS {len(checks)} scoped checks; test-only revision disclosed: {work / "manifest.json"}')


if __name__ == '__main__':
    main()
