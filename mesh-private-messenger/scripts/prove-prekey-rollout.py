#!/usr/bin/env python3
"""Owned PostgreSQL default-off prekey retention rollout qualification.

Optional legacy inputs replay the originally captured storage implementation,
not an entire historical deployment. They are explicit, hash-pinned test inputs.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import importlib.util
import json
import os
import re
import shutil
import threading

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prekey_proof', HERE/'prove-prekey-retention.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


@contextmanager
def rejecting_scheduler(output):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            requests.append({'path': self.path, 'status': 503})
            self.send_response(503)
            self.send_header('Content-Length', '0')
            self.end_headers()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (output/'scheduler-http-trace.json').write_text(json.dumps(requests, indent=2)+'\n')


def fixture_package(directory, service, source):
    directory.mkdir()
    shutil.copyfile(source, directory/'main.mpl')
    (directory/'mesh.toml').write_text(
        '[package]\nname="prekey-rollout-fixture"\nversion="0.1.0"\n'
        '[dependencies]\ndirectory={path="'+str(service)+'"}\n'
        'messenger-protocol={path="'+str(service.parent/'messenger-protocol')+'"}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product-root', type=Path, default=HERE.parent)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--test-runtime', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    for name in ['prekeys', 'workers']:
        parser.add_argument('--legacy-'+name, type=Path)
        parser.add_argument('--legacy-'+name+'-sha256')
    args = parser.parse_args()
    legacy = [(args.legacy_prekeys, args.legacy_prekeys_sha256, 'storage/prekeys.mpl'),
              (args.legacy_workers, args.legacy_workers_sha256, 'runtime/workers.mpl')]
    values = [value for row in legacy for value in row[:2]]
    if any(values) and not all(values):
        parser.error('all four legacy path/hash arguments are required together')
    for path, expected, _ in legacy:
        if path is not None and proof.sha(path) != expected:
            parser.error('legacy storage input hash mismatch')
    tools = {name: {'path': str(path.resolve()), 'sha256': proof.sha(path)} for name, path in
             [('compiler', args.compiler), ('runtime', args.runtime), ('test_runtime', args.test_runtime)]}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, output/'driver.py')
    (output/'toolchain.json').write_text(json.dumps(tools, indent=2)+'\n')
    originals = {}
    service = proof.copy_closure(args.product_root.resolve()/'services/directory-delivery', output/'sources', originals)
    fixtures = args.product_root.resolve()/'scripts/prekey-retention-proof'
    for name in ['rollout.mpl.fixture', 'legacy-writer.mpl.fixture']:
        originals[str(fixtures/name)] = proof.sha(fixtures/name)
    fixture = output/'sources/rollout'
    fixture_package(fixture, service, fixtures/'rollout.mpl.fixture')
    old_fixture = None
    if all(values):
        old_sources = output/'legacy-sources'
        shutil.copytree(output/'sources', old_sources)
        for manifest in old_sources.rglob('mesh.toml'):
            manifest.write_text(manifest.read_text().replace(str(output/'sources'), str(old_sources)))
        for path, _, relative in legacy:
            originals[str(path.resolve())] = proof.sha(path)
            shutil.copyfile(path, old_sources/'directory-delivery'/relative)
        old_fixture = old_sources/'rollout'
        shutil.copyfile(fixtures/'legacy-writer.mpl.fixture', old_fixture/'main.mpl')
    frozen = {name: proof.snapshot(output/name) for name in ['sources', 'legacy-sources'] if (output/name).exists()}
    (output/'source-before.json').write_text(json.dumps(frozen, indent=2)+'\n')
    (output/'original-source-inputs.json').write_text(json.dumps(originals, indent=2)+'\n')
    env = dict(os.environ, MESH_RT_LIB_PATH=tools['runtime']['path'],
               MESH_TEST_RT_LIB_PATH=tools['test_runtime']['path'],
               MORSE_TRANSPARENCY_RETENTION='off', MESSENGER_JOBS_URL='')
    env.pop('MESSENGER_PREKEY_RETENTION', None)
    results = []

    def run(name, command, environment):
        result = proof.execute(command, environment, output/(name+'.log'))
        results.append(result)
        (output/'results.json').write_text(json.dumps(results, indent=2)+'\n')
        assert result['exit_code'] == 0, result

    binary = output/'rollout-client'
    run('build', [args.compiler.resolve(), 'build', fixture, '--opt-level', '0', '-o', binary], env)
    old_binary = output/'legacy-writer'
    if old_fixture is not None:
        run('legacy-build', [args.compiler.resolve(), 'build', old_fixture, '--opt-level', '0', '-o', old_binary], env)
    with rejecting_scheduler(output) as (jobs_url, requests), proof.database(service/'migrations') as (url, sql):
        base = dict(env, MESSENGER_TEST_DATABASE_URL=url, MESSENGER_JOBS_URL=jobs_url)

        def reset():
            sql('TRUNCATE messenger_retired_prekeys,messenger_one_time_prekeys,'
                'messenger_devices,messenger_mailboxes,messenger_accounts CASCADE')

        for value, name in [(None, 'absent'), ('off', 'off')]:
            reset()
            environment = dict(base, M6_ROLLOUT_MODE='off')
            if value is not None:
                environment['MESSENGER_PREKEY_RETENTION'] = value
            run(name, [binary], environment)
        log = (output/'off.log').read_text()
        fields = {name: re.search('^'+name+'=([0-9a-f]+)$', log, re.M)[1]
                  for name in ['CLAIM_HEX', 'RESPONSE_SHA256', 'OTB_HEX']}
        old_env = dict(base, M6_ROLLOUT_OTB=fields['OTB_HEX'])
        if old_fixture is not None:
            run('legacy-before-activation', [old_binary], old_env)
        run('activation', [binary], dict(
            base, MESSENGER_PREKEY_RETENTION='on', M6_ROLLOUT_MODE='activate',
            M6_COLD_CLAIM_HEX=fields['CLAIM_HEX'], M6_COLD_RESPONSE_SHA256=fields['RESPONSE_SHA256'],
            M6_ROLLOUT_OTB=fields['OTB_HEX']))
        if old_fixture is not None:
            run('legacy-after-activation', [old_binary], dict(old_env, M6_EXPECT_OLD_ACTIVE='1'))
        for number, value in enumerate(['', 'true', 'ON', '1', ' on ']):
            reset()
            run('invalid-'+str(number), [binary], dict(
                base, MESSENGER_PREKEY_RETENTION=value, M6_ROLLOUT_MODE='invalid'))
        assert requests == [], requests
    assert all(proof.sha(Path(path)) == expected for path, expected in originals.items())
    assert all(proof.snapshot(output/name) == expected for name, expected in frozen.items())
    assert all(proof.sha(row['path']) == row['sha256'] for row in tools.values())
    result = {'status': 'passed_owned_rollout', 'results': results,
              'copied_sources_unchanged': True, 'original_sources_unchanged': True,
              'legacy_storage_boundary_exercised': old_fixture is not None,
              'legacy_scope': 'Captured Prekeys/Workers over the current protocol closure, not a full historical service.',
              'legacy_after_activation': 'Known unsafe old-writer resurrection; explicitly unsupported.' if old_fixture is not None else 'not tested',
              'scope': 'Owned PostgreSQL/HTTP only; no deployment or live activation.'}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': result['status'], 'output': str(output)}))


if __name__ == '__main__':
    main()
