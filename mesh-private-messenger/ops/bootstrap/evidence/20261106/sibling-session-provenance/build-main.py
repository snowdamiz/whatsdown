import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

root = Path.cwd()
out = root / '.morse/sibling-authority/main'
out.mkdir(parents=True, exist_ok=True)
family = Path('/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts')
compiler = family / 'bin/meshc'
runtime = family / 'lib/libmesh_rt.a'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
sources = {}
for package in ('mobile-core', 'messenger-protocol'):
    for path in sorted((root / 'mesh-private-messenger/packages' / package).rglob('*')):
        if path.is_file() and path.suffix in ('.mpl', '.toml', '.lock'):
            sources[str(path.relative_to(root))] = sha(path)
standard_sources = {str(p): sha(p) for p in sorted((root / 'mesh-lang/packages').rglob('*.mpl'))}
config = json.loads((root / 'mesh-private-messenger/apps/desktop/src-tauri/tauri.conf.json').read_text())
env = os.environ.copy()
env.update(MESH_RT_LIB_PATH=str(runtime), MACOSX_DEPLOYMENT_TARGET=config['bundle']['macOS']['minimumSystemVersion'])
artifact = out / 'libmessenger_mobile.dylib'
command = [str(compiler), 'build', str(root / 'mesh-private-messenger/packages/mobile-core'), '--artifact', 'cdylib', '--output', str(artifact)]
record = {'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), 'command': command, 'compiler_sha256': sha(compiler), 'runtime_sha256': sha(runtime), 'deployment_target': env['MACOSX_DEPLOYMENT_TARGET'], 'sources': sources, 'standard_library_sources': standard_sources}
start = time.monotonic()
with (out / 'product-main.log').open('w') as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
record.update(exit_code=result.returncode, seconds=round(time.monotonic() - start, 3))
record['source_drift'] = [path for path, digest in sources.items() if sha(root / path) != digest] + [path for path, digest in standard_sources.items() if sha(Path(path)) != digest]
if result.returncode == 0:
    record['artifact_sha256'] = sha(artifact)
    gate = ['/Users/andreyyurlov/.local/share/fnm/node-versions/v24.21.0/installation/bin/node', str(root / 'mesh-private-messenger/ops/plaintext/report.mjs'), '--report', str(artifact) + '.plaintext.json', '--review', str(root / 'mesh-private-messenger/protocol/plaintext-disclosures.json'), '--compiler', str(compiler), '--artifact', str(artifact), '--output', str(out / 'product-main-evidence.json')]
    with (out / 'product-main-gate.log').open('w') as log:
        record['gate_exit_code'] = subprocess.run(gate, stdout=log, stderr=subprocess.STDOUT).returncode
    abi = json.loads((out / 'libmessenger_mobile.abi.json').read_text())
    record['abi_exports'] = len(abi['exports'])
    generated = root / 'mesh-private-messenger/apps/mobile/modules/mesh-messenger/generated'
    record['binding_matches'] = {ext: (out / ('libmessenger_mobile.' + ext)).read_bytes() == (generated / ('libmessenger_mobile.' + ext)).read_bytes() for ext in ('h', 'swift', 'kt', 'jni.c', 'ts')}
    record['otool'] = subprocess.check_output(['otool', '-l', str(artifact)], text=True)
(out / 'product-main.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k: v for k, v in record.items() if k not in ('sources', 'standard_library_sources', 'otool')}, indent=2), flush=True)
assert result.returncode == 0 and not record['source_drift']
assert record['abi_exports'] == 176 and all(record['binding_matches'].values())
assert any(line.strip() == 'minos ' + record['deployment_target'] for line in record['otool'].splitlines())
