#!/usr/bin/env python3
"""Run the real exported app in an isolated signed Tauri WebView, with test IPC only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import uuid

product = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--work', type=Path, required=True, help='New empty evidence directory')
args = parser.parse_args()
work = args.work.resolve()
work.mkdir(parents=True, exist_ok=False)
source = product/'apps/desktop/src-tauri'
fixture = product/'scripts/network-lockdown-proof'
stage = work/'source'
shutil.copytree(source, stage, ignore=shutil.ignore_patterns('target', 'gen', 'native', '.DS_Store'))
(stage/'native').symlink_to(source/'native')
identity = 'io.morseapp.desktop.networkproof.'+uuid.uuid4().hex[:12]
manifest = stage/'Cargo.toml'
manifest.write_text(manifest.read_text().replace('name = "morse-desktop"', 'name = "morse-network-proof"')
                    .replace('name = "Morse"', 'name = "MorseNetworkProof"')
                    .replace('../../../packages/wallet-core', str(product/'packages/wallet-core')))
build = stage/'build.rs'
build.write_text(build.read_text().replace('../../mobile/modules/mesh-messenger', str(product/'apps/mobile/modules/mesh-messenger'))
                 .replace('../../../packages/wallet-core', str(product/'packages/wallet-core')))
config_path = stage/'tauri.conf.json'
config = json.loads(config_path.read_text())
config.update(identifier=identity, productName='MorseNetworkProof')
config['build'] = {'frontendDist': str(product/'apps/desktop/dist')}
config['bundle']['active'] = False
config_path.write_text(json.dumps(config, indent=2))
for path in (stage/'src').glob('*.rs'):
    path.write_text(path.read_text().replace('../../../mobile/modules/mesh-messenger', str(product/'apps/mobile/modules/mesh-messenger')))
main = stage/'src/main.rs'
text = main.read_text()
assert '.invoke_system(include_str!("ipc-postmessage.js"))' in text
assert '.on_navigation(navigation::allowed)' in text
text = text.replace('.on_navigation(navigation::allowed)', '.initialization_script(include_str!("network-probe.js"))\n        .on_navigation(navigation::allowed)')
text = text.replace('tauri::generate_handler![', 'tauri::generate_handler![network_probe_echo, network_probe_fail, network_probe_channel, network_probe_report,')
main.write_text(text+(fixture/'desktop-commands.rs').read_text())
sdk = subprocess.check_output(['node', fixture/'sdk-wrapper.mjs', product/'apps/mobile'], text=True)
(stage/'src/network-probe.js').write_text(sdk+(fixture/'desktop-probe.js').read_text())

def hashes(paths):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}

inputs = list((stage/'src').glob('*'))+[manifest, build, config_path]
inputs += list((product/'apps/desktop/dist').rglob('*'))
inputs += [fixture/'sdk-wrapper.mjs', fixture/'desktop-probe.js', fixture/'desktop-commands.rs']
inputs += [product/'apps/mobile/node_modules/@tauri-apps/api/core.js', product/'apps/mobile/node_modules/@tauri-apps/api/external/tslib/tslib.es6.js']
before = hashes(inputs)
env = dict(os.environ, CARGO_TARGET_DIR=str(source/'target'))
with (work/'build.log').open('w') as output:
    subprocess.run(['cargo', 'build', '--offline', '--features', 'tauri/custom-protocol', '--manifest-path', manifest, '--bin', 'MorseNetworkProof'],
                   env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
app = work/'MorseNetworkProof.app'
contents = app/'Contents'
(contents/'MacOS').mkdir(parents=True)
(contents/'Resources/native').mkdir(parents=True)
binary = contents/'MacOS/MorseNetworkProof'
shutil.copy2(source/'target/debug/MorseNetworkProof', binary)
library = contents/'Resources/native/libmessenger_mobile.dylib'
shutil.copy2(source/'native/libmessenger_mobile.dylib', library)
(contents/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': identity, 'CFBundleExecutable': 'MorseNetworkProof',
    'CFBundleName': 'Morse Network Proof', 'CFBundlePackageType': 'APPL', 'NSHighResolutionCapable': True}))
subprocess.run(['codesign', '--force', '--timestamp=none', '--sign', os.environ.get('MORSE_DEV_SIGNING_IDENTITY', 'Apple Development'),
                '--identifier', identity, app], check=True)
report = work/'report.json'
env['MORSE_NETWORK_PROBE_REPORT'] = str(report)
with (work/'execution.log').open('w') as output:
    # Use the installed application's lifecycle. Directly executing a newly
    # copied bundle can bypass LaunchServices registration used by WebKit.
    result = subprocess.run(['open', '-n', '-W', '--env', f'MORSE_NETWORK_PROBE_REPORT={report}', app],
                            env=env, stdout=output, stderr=subprocess.STDOUT, timeout=85)
after = hashes(inputs)
status = json.loads(report.read_text())
evidence = {'status': status, 'returncode': result.returncode, 'sources_unchanged': before == after,
            'source_hashes': before, 'artifacts': hashes([binary, library, contents/'Info.plist']),
            'dependency_lock': hashes([stage/'Cargo.lock']), 'launch': 'LaunchServices open -n -W',
            'limits': 'Owned isolated macOS Tauri WebView, full exported app, actual SDK Channel and bounded test IPC. No production network or physical-device claim.'}
(work/'evidence.json').write_text(json.dumps(evidence, indent=2))
assert before == after and result.returncode == 0 and status['passed'], status
print(json.dumps({'passed': True, 'evidence': str(work/'evidence.json')}))
