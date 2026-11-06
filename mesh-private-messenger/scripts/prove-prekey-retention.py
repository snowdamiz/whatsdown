#!/usr/bin/env python3
"""Owned PostgreSQL prekey replay/retention and durable-wakeup qualification.

All compiles are sequential. Tool artifacts are explicit; no default mutable
compiler, external database, device, deployment or real credential is used.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import tomllib

PRODUCT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(path):
    return {str(p.relative_to(path)): sha(p) for p in sorted(path.rglob('*'))
            if p.is_file() and (p.suffix in {'.mpl', '.sql'} or p.name == 'mesh.toml')}


def copy_closure(package, destination, originals, copied=None):
    copied = {} if copied is None else copied
    package = package.resolve()
    if package in copied:
        return copied[package]
    target = destination/package.name
    target.mkdir(parents=True, exist_ok=False)
    copied[package] = target
    for name, digest in snapshot(package).items():
        source = package/name
        originals[str(source)] = digest
        output = target/name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
    text = (package/'mesh.toml').read_text()
    for dependency in tomllib.loads(text).get('dependencies', {}).values():
        assert isinstance(dependency, dict) and set(dependency) == {'path'}
        child = copy_closure(package/dependency['path'], destination, originals, copied)
        text = text.replace('"'+dependency['path']+'"', '"'+str(child)+'"')
    (target/'mesh.toml').write_text(text)
    return target


def free_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


@contextmanager
def database(migrations):
    with tempfile.TemporaryDirectory(prefix='morse-prekey-retention-', dir='/tmp') as folder:
        directory = Path(folder).resolve()
        pg = Path(os.environ.get('PG_BIN', '/opt/homebrew/opt/postgresql@17/bin'))
        port = free_port()
        env = dict(os.environ, PGHOST='127.0.0.1', PGPORT=str(port),
                   PGUSER='morse_prekey_test', PGDATABASE='morse_prekey_test')

        def run(command, *arguments):
            return subprocess.run([str(pg/command), *map(str, arguments)], env=env,
                                  capture_output=True, text=True, check=True, timeout=60)

        def sql(statement):
            return run('psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                       '-c', statement).stdout.strip()

        started = False
        try:
            run('initdb', '-D', directory/'data', '-U', 'morse_prekey_test',
                '--auth=trust', '--no-locale')
            run('pg_ctl', '-D', directory/'data', '-l', directory/'postgres.log', '-o',
                shlex.join(['-h', '127.0.0.1', '-p', str(port), '-k', str(directory)]),
                '-w', 'start')
            started = True
            run('createdb', 'morse_prekey_test')
            for migration in sorted(migrations.glob('*.sql')):
                run('psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', migration)
            yield f'postgres://morse_prekey_test@127.0.0.1:{port}/morse_prekey_test?sslmode=disable', sql
        finally:
            if started:
                run('pg_ctl', '-D', directory/'data', '-m', 'fast', '-w', 'stop')


def execute(command, environment, logfile, timeout=300):
    started = time.monotonic()
    with logfile.open('w') as output:
        process = subprocess.run(list(map(str, command)), env=environment,
                                 stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    return {'command': list(map(str, command)), 'exit_code': process.returncode,
            'seconds': round(time.monotonic()-started, 3), 'log': logfile.name}


def jobs_proof(compiler, fixture, service, environment, output):
    binary = output/'jobs-client'
    build = execute([compiler, 'build', fixture, '--opt-level', '0', '-o', binary],
                    environment, output/'jobs-build.log')
    assert build['exit_code'] == 0, build
    requests, errors = [], []
    with database(service/'migrations') as (url, sql):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    size = int(self.headers.get('Content-Length', '0'))
                    assert self.path in {'/directory', '/witness'} and 1 <= size <= 20
                    body = self.rfile.read(size)
                    assert body.isdigit()
                    xid = str(int(body))
                    state = sql("SELECT pg_xact_status('"+xid+"'::xid8)")
                    consumed = int(sql('SELECT count(*) FROM messenger_one_time_prekeys '
                                       'WHERE consumed_at IS NOT NULL AND NOT last_resort'))
                    number = sum(row['path'] == '/directory' for row in requests)
                    status = 503 if self.path == '/directory' and number == 0 else 204
                    requests.append({'path': self.path, 'transaction_id': xid,
                                     'state_during_request': state,
                                     'committed_consumed_seen': consumed, 'status': status})
                    self.send_response(status)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                except BaseException as error:
                    errors.append(type(error).__name__)
                    self.close_connection = True

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = dict(environment, MESSENGER_TEST_DATABASE_URL=url,
                       MESSENGER_JOBS_URL=f'http://127.0.0.1:{server.server_port}')
            first = execute([binary], env, output/'jobs-run.log', 60)
            assert first['exit_code'] == 0, first
            # Only synthetic public OTQ bytes and a public PKB digest are passed
            # into the separate cold process. No signer or storage key is saved.
            log = (output/'jobs-run.log').read_text()
            claim = re.search(r'^CLAIM_HEX=([0-9a-f]+)$', log, re.M)[1]
            response = re.search(r'^RESPONSE_SHA256=([0-9a-f]{64})$', log, re.M)[1]
            cold = execute([binary], dict(env, M6_COLD_CLAIM_HEX=claim,
                                          M6_COLD_RESPONSE_SHA256=response),
                           output/'jobs-cold-replay.log', 30)
            assert cold['exit_code'] == 0, cold
            for row in requests:
                row['state_after_client'] = sql("SELECT pg_xact_status('"+
                                                row['transaction_id']+"'::xid8)")
            rows = [row for row in requests if row['path'] == '/directory']
            assert not errors and len(rows) == 3, (errors, rows)
            assert [row['status'] for row in rows] == [503, 204, 204]
            assert [row['committed_consumed_seen'] for row in rows] == [0, 0, 1]
            assert all(row['state_during_request'] == 'in progress' for row in rows)
            assert [row['state_after_client'] for row in rows] == ['aborted', 'committed', 'committed']
            assert sql('SELECT count(*) FROM messenger_one_time_prekeys '
                       'WHERE claim_id_hash IS NOT NULL') == '1'
            assert sql('SELECT count(*) FROM messenger_retired_prekeys') == '1'
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            (output/'jobs-http-trace.json').write_text(json.dumps(requests, indent=2)+'\n')
    return {'build': build, 'first': first, 'cold': cold, 'binary_sha256': sha(binary),
            'owned_directory_requests': 3, 'unexpected_handler_errors': errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product-root', type=Path, default=PRODUCT)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--test-runtime', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--test', action='append', dest='tests',
                        help='one directory test filename; repeat to override the focused default')
    parser.add_argument('--jobs-only', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    tools = {name: {'path': str(path.resolve()), 'sha256': sha(path)} for name, path in
             [('compiler', args.compiler), ('runtime', args.runtime), ('test_runtime', args.test_runtime)]}
    (output/'toolchain.json').write_text(json.dumps(tools, indent=2)+'\n')
    shutil.copyfile(Path(__file__), output/'driver.py')
    originals = {}
    service = copy_closure(args.product_root.resolve()/'services/directory-delivery', output/'sources', originals)
    fixture = output/'sources/prekey-retention-jobs'
    fixture.mkdir()
    fixture_source = args.product_root.resolve()/'scripts/prekey-retention-proof/main.mpl.fixture'
    originals[str(fixture_source)] = sha(fixture_source)
    shutil.copyfile(fixture_source, fixture/'main.mpl')
    (fixture/'mesh.toml').write_text(
        '[package]\nname = "prekey-retention-jobs-fixture"\nversion = "0.1.0"\n'
        '[dependencies]\ndirectory = { path = "'+str(service)+'" }\n'
        'messenger-protocol = { path = "'+str(output/'sources/messenger-protocol')+'" }\n')
    assert all(sha(Path(path)) == digest for path, digest in originals.items())
    frozen = snapshot(output/'sources')
    (output/'original-source-inputs.json').write_text(json.dumps(originals, indent=2)+'\n')
    (output/'source-before.json').write_text(json.dumps(frozen, indent=2)+'\n')
    env = dict(os.environ, MESH_RT_LIB_PATH=tools['runtime']['path'],
               MESH_TEST_RT_LIB_PATH=tools['test_runtime']['path'], MESSENGER_JOBS_URL='',
               MORSE_TRANSPARENCY_RETENTION='off', MESSENGER_PREKEY_RETENTION='on',
               # Existing public M9 fixture vectors, never deployment secrets.
               MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX=bytes([91]).hex()*32,
               MESSENGER_WITNESS_A_PUBLIC_KEY_HEX='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
               MESSENGER_WITNESS_B_PUBLIC_KEY_HEX='3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
               MESSENGER_DELIVERY_SEALING_SEED_HEX='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    tests = [] if args.jobs_only else args.tests or [
        'prekey_retention.test.mpl', 'prekey_pool.test.mpl', 'renewal.test.mpl',
        'devices.test.mpl', 'account_deletion.test.mpl', 'hardening.test.mpl',
        'transparency_retention.test.mpl']
    results = []
    for name in tests:
        assert Path(name).name == name and name.endswith('.test.mpl')
        with database(service/'migrations') as (url, _):
            result = execute([args.compiler.resolve(), 'test', service/'tests'/name],
                             dict(env, MESSENGER_TEST_DATABASE_URL=url), output/(name+'.log'))
        results.append(result)
        (output/'test-results.json').write_text(json.dumps(results, indent=2)+'\n')
        assert result['exit_code'] == 0, result
    jobs = jobs_proof(args.compiler.resolve(), fixture, service, env, output)
    assert snapshot(output/'sources') == frozen
    assert all(sha(Path(path)) == digest for path, digest in originals.items())
    assert all(sha(row['path']) == row['sha256'] for row in tools.values())
    result = {'status': 'passed_owned_prekey_retention', 'tests': results, 'jobs': jobs,
              'source_inputs': len(originals), 'copied_sources_unchanged': True,
              'original_sources_unchanged': True, 'toolchain': tools,
              'scope': 'Owned PostgreSQL + HTTP scheduler; synthetic identities; no devices or deployment.'}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': result['status'], 'output': str(output)}))


if __name__ == '__main__':
    main()
