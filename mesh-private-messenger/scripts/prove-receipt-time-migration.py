#!/usr/bin/env python3
"""Exercise receipt-time privacy migration on an owned, disposable PostgreSQL."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]
MIGRATIONS = PRODUCT / 'services/directory-delivery/migrations'


def main():
    pg = Path(os.environ.get('PG_BIN') or Path(shutil.which('initdb') or '/opt/homebrew/opt/postgresql@17/bin/initdb').parent)
    node = os.environ.get('NODE_BINARY') or shutil.which('node')
    if not node:
        raise RuntimeError('Node is required for the production migration runner')
    with tempfile.TemporaryDirectory(prefix='morse-receipt-time-', dir='/tmp') as raw:
        work = Path(raw).resolve()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='receipt_test', PGDATABASE='postgres',
                   PATH=str(pg) + os.pathsep + env.get('PATH', ''),
                   MESSENGER_DATABASE_URL=f'postgres://receipt_test@127.0.0.1:{port}/receipt_test')

        def run(*args, **kwargs):
            return subprocess.run([str(a) for a in args], env=env, check=True, **kwargs)

        def sql(statement, *, succeeds=True):
            result = subprocess.run([str(pg / 'psql'), '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement],
                                    env=env, capture_output=True, text=True)
            if succeeds and result.returncode:
                raise RuntimeError(result.stderr)
            if not succeeds:
                assert result.returncode and 'messenger_envelopes_received_minute' in result.stderr, result.stderr
            return result.stdout.strip()

        def insert(identifier, received=''):
            columns, values = (', received_at', ', ' + received) if received else ('', '')
            return f"INSERT INTO messenger_envelopes (mailbox_token_hash,envelope_id,suite,expiration_ms,padding_bucket,ciphertext{columns}) VALUES (decode(repeat('11',32),'hex'),decode(repeat('{identifier}',16),'hex'),4,2200000000123,256,decode('1234','hex'){values})"

        started = False
        try:
            run(pg / 'initdb', '-D', work / 'data', '-U', 'receipt_test', '--auth=trust', '--no-locale', stdout=subprocess.DEVNULL)
            run(pg / 'pg_ctl', '-D', work / 'data', '-l', work / 'postgres.log', '-o',
                shlex.join(['-h', '127.0.0.1', '-p', str(port), '-k', str(work)]), '-w', 'start', stdout=subprocess.DEVNULL)
            started = True
            run(pg / 'createdb', 'receipt_test')
            env['PGDATABASE'] = 'receipt_test'
            sql('CREATE TABLE morse_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())')
            for migration in sorted(MIGRATIONS.glob('*.sql')):
                if migration.name >= '029_':
                    break
                body = migration.read_text()
                sql('BEGIN;\n' + body + f"\nINSERT INTO morse_migrations(name,checksum) VALUES ('{migration.name}','{hashlib.sha256(body.encode()).hexdigest()}'); COMMIT;")
            sql("INSERT INTO messenger_mailboxes(mailbox_token_hash) VALUES (decode(repeat('11',32),'hex'))")
            sql(insert('22', "'2026-10-22 11:23:59.987654+00'"))
            sql(insert('33', "'2026-10-22 12:24:00.000001+00'"))
            sql("UPDATE messenger_envelopes SET acknowledged_at='2026-10-22 12:25:47.123456+00' WHERE envelope_id=decode(repeat('33',16),'hex')")
            preserved = "SELECT (to_jsonb(e)-'received_at')::text FROM messenger_envelopes e ORDER BY sequence"
            before = sql(preserved)
            counters = sql('SELECT row_to_json(m)::text FROM messenger_mailboxes m')
            run(node, PRODUCT / 'ops/cloudflare/migrate.mjs', stdout=subprocess.DEVNULL)
            assert sql("SELECT string_agg(to_char(received_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US'),',' ORDER BY sequence) FROM messenger_envelopes") == '2026-10-22 11:23:00.000000,2026-10-22 12:24:00.000000', 'legacy receipt timestamps retain sub-minute precision'
            assert sql(preserved) == before, 'migration changed message data or exact ACK/expiry policy'
            assert sql('SELECT row_to_json(m)::text FROM messenger_mailboxes m') == counters, 'migration changed mailbox accounting'
            sql(insert('44'))
            assert sql("SELECT (received_at=date_trunc('minute',received_at) AND received_at <= clock_timestamp() AND received_at > clock_timestamp()-interval '1 minute')::text FROM messenger_envelopes WHERE envelope_id=decode(repeat('44',16),'hex')") == 'true', 'new default receipt time is not the current minute'
            sql("SET TIME ZONE 'Asia/Kathmandu'; " + insert('55'))
            assert sql("SELECT bool_and(received_at=date_trunc('minute',received_at))::text FROM messenger_envelopes") == 'true'
            counters = sql('SELECT row_to_json(m)::text FROM messenger_mailboxes m')
            sql(insert('66', "'2026-10-22 11:23:59.987654+00'"), succeeds=False)
            sql("UPDATE messenger_envelopes SET received_at=received_at+interval '0.001 second'", succeeds=False)
            assert sql('SELECT row_to_json(m)::text FROM messenger_mailboxes m') == counters, 'rejected timestamp write consumed mailbox capacity'
            after = sql('SELECT row_to_json(e)::text FROM messenger_envelopes e ORDER BY sequence')
            run(node, PRODUCT / 'ops/cloudflare/migrate.mjs', stdout=subprocess.DEVNULL)
            assert sql('SELECT row_to_json(e)::text FROM messenger_envelopes e ORDER BY sequence') == after, 'migration replay changed records'
            print(json.dumps({'proof': 'receipt-time-migration', 'legacy_rows_rounded': 2,
                              'new_default_and_timezone': True, 'precise_insert_and_update_refused': True,
                              'ack_expiry_ciphertext_and_capacity_preserved': True, 'production_runner_replay': True}, sort_keys=True))
        finally:
            if started:
                run(pg / 'pg_ctl', '-D', work / 'data', '-m', 'fast', '-w', 'stop', stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
