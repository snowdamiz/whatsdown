"""Record exact local inputs and outputs without claiming deployment qualification."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root, proof, compiler, runtime = map(Path, sys.argv[1:])
product = root / 'mesh-private-messenger'
fixture = Path(os.environ['MORSE_TOKEN_CUSTODY_FIXTURES_PATH'])

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

sources = {}
for directory in ['ops/token-v2', 'ops/token', 'ops/rewards', 'ops/chain-writer', 'ops/collateral-v2',
                  'tools/rewards-v2-operator', 'packages/messenger-protocol', 'programs']:
    for path in (product / directory).rglob('*'):
        if path.is_file() and not {'target', 'node_modules', '.git', '__pycache__'}.intersection(path.parts) and path.suffix in {'.mpl', '.mjs', '.toml', '.lock', '.rs', '.json', '.md'}:
            sources[str(path.relative_to(root))] = digest(path)
for name in ['prove-rewards-v2.sh', 'rewards-v2-receipt.py']:
    path = product / 'scripts' / name
    sources[str(path.relative_to(root))] = digest(path)
artifacts = {str(path): digest(path) for path in [compiler, runtime, fixture, proof / 'operator',
    Path(os.environ['MORSE_REWARDS_V2_SBF_BRIDGE']), *sorted((proof / 'sbf').glob('*.so'))]}
test_runtime = os.environ.get('MESH_TEST_RT_LIB_PATH')
if test_runtime:
    artifacts[test_runtime] = digest(Path(test_runtime))
logs = {str(path.relative_to(proof)): digest(path) for path in proof.glob('*.txt')}
receipt = {
    'schema_version': 1,
    'scope': 'continuous-grace-assessment-bounded-v2-settlement-and-explicit-claims-local-execution',
    'app_head': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
    'app_dirty': bool(subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True)),
    'language_head': subprocess.check_output(['git', '-C', str(root / 'mesh-lang'), 'rev-parse', 'HEAD'], text=True).strip(),
    'fixture_reused': True,
    'fixture_path': str(fixture),
    'execution': 'Native Mesh executable -> Node CLI / Kit -> SQLite -> HTTP RPC adapter -> LiteSVM SBF',
    'limitations': [
        'Old custody snapshot reused with disclosed bank initialization adaptations; fresh SBF programs and fresh signed execution.',
        'Three loopback HTTP origins share one bank. Not provider independence or live finalized RPC.',
        'Local height and explicit blockhash expiry; not a validator consensus/finality proof.',
        'Fixture oracle histories, source revisions and deployment metadata are explicit test injections; actual assessment/cancel/rebegin effects execute signed SBF.',
        'Grace checks cover the directory and current attendance set; finite completed requests stop. No activation, pending application, pool funding, deployment or live observation.',
        'V1 transaction, journal and writer tests rerun; the separate legacy Mesh/SBF proof is not part of this command.',
    ],
    'sources': dict(sorted(sources.items())),
    'artifacts': artifacts,
    'logs': logs,
}
(proof / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
