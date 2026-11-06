#!/usr/bin/env python3
"""Verify retained local acceptance evidence without rebuilding or network I/O."""
import hashlib
import json
from pathlib import Path
import runpy
import sys

base = Path(__file__).resolve().parent
repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
receipt = json.loads((base / 'receipt.json').read_text())
result = json.loads((base / 'local-result.json').read_text())
process = json.loads((base / 'process.json').read_text())
sources = json.loads((base / 'sources.json').read_text())
assert receipt['status'] == result['status'] == 'PASS_LOCAL_RPC_TLS'
assert not receipt.get('error') and not result.get('error')
assert process['process_exit_code'] == 0
assert process['compile'] == process['acceptance'] == 'fresh'
assert receipt['production_checks'] == ['pending'] * 8
assert all(row['status'] == 'PASS' for row in result['checks'])
assert sha(base / 'sources.json') == receipt['sources_manifest_sha256']
work = Path(receipt['work'])
assert work.name.startswith('bootstrap-native-')
assert sha(work.parent / 'receipt.json') == sha(base / 'receipt.json'), 'retained receipt mismatch'
verified = {}
for name, expected in receipt['artifacts'].items():
    path = base / name if name in ('build.log', 'local-result.json') else work / name
    assert sha(path) == expected, name
    verified[name] = expected
for name, row in receipt['toolchain'].items():
    assert sha(work / 'toolchain' / name) == row['sha256'], name
abi = json.loads((work / 'libbootstrap.abi.json').read_text())
exports = {row['symbol'] for row in abi['exports']}
production = {name for name in exports if name.startswith('mesh_messenger_')}
assert len(production) == receipt['abi_exports']['production_count'] == 176
assert production == set(receipt['abi_exports']['production_symbols'])
assert len(exports - production) == receipt['abi_exports']['fixture_count'] == 9
assert exports - production == set(receipt['abi_exports']['fixture_symbols'])
header = (work / 'libbootstrap.h').read_text()
assert all(name in header for name in exports)
for relative, expected in result['public_fixture_hashes'].items():
    assert sha(work / 'local' / relative) == expected, relative
runner = repo / 'mesh-private-messenger/ops/bootstrap/prove.py'
namespace = runpy.run_path(str(runner), run_name='receipt_verifier')
product = repo / 'mesh-private-messenger'
for package in ('mobile-core', 'messenger-protocol'):
    assert namespace['sources'](product / 'packages' / package) == sources[package], package
assert namespace['sources'](product / 'tests/bootstrap-native-20261106') == sources['fixture']
assert sha(runner) == sources['runner']['prove.py']
# The recorded Mesh package closure is checked against the exact --mesh-source
# used by the captured fresh command, not inferred from a compiler install path.
mesh = Path(process['command'][process['command'].index('--mesh-source') + 1])
assert namespace['sources'](mesh / 'packages') == sources['mesh-packages']
events = [json.loads(line) for line in (work / 'local/http-events.jsonl').read_text().splitlines()]
assert not any(row['peer'] == 'redirect-target' for row in events), 'redirect/authority target contacted'
primary = [row for row in events if row['scenario'] == 'positive' and 'rpc' in row]
assert len(primary) >= 10
assert {row['peer'] for row in primary} <= {0, 1, 2}
assert any(row.get('proof_sequence') == 1 and row['scenario'] == 'positive' for row in events)
barriers = {}
for authority in ('resource', 'account'):
    for branch in ('success', 'http-error'):
        scenario = 'barrier-' + authority + '-' + branch
        rows = [row for row in events if row['scenario'] == scenario and 'rpc' in row]
        assert len(rows) == 1, (scenario, len(rows))
        barriers[scenario] = len(rows)
assert not result['server_errors']
report = {'status': 'PASS_LOCAL_RPC_TLS', 'process_exit_code': process['process_exit_code'],
          'compile': 'fresh', 'acceptance': 'fresh', 'current_source_closure': 'verified',
          'base': receipt['base'], 'mesh_source': receipt['mesh_source'],
          'production_exports': len(production), 'fixture_exports': len(exports - production),
          'local_checks': len(result['checks']), 'anchor_result': result['anchor_result'],
          'rpc_http_requests': result['rpc_http_requests'], 'barrier_rpc_counts': barriers,
          'redirect_target_connections': 0, 'production_checks': receipt['production_checks'],
          'not_run': result['not_run'],
          'evidence_sha256': {name: sha(base / name) for name in
              ('receipt.json', 'local-result.json', 'sources.json', 'build.log', 'console.log', 'process.json')},
          'artifacts': verified, 'public_fixture_files_verified': len(result['public_fixture_hashes']),
          'retained_work': str(work)}
(base / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
