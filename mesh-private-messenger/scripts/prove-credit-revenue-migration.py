#!/usr/bin/env python3
"""Local PostgreSQL migration/replay proof; only synthetic keys and funds."""
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
MIGRATIONS = PRODUCT / 'services/credit-issuer/migrations'
V1 = 'morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'
V2 = 'morse-credit-revenue-split-v2:gross=2/10,3/10,5/10;carry=per-share-numerator;reserve=sum-carry/10'


def main():
    pg = Path(os.environ.get('PG_BIN') or Path(shutil.which('initdb') or '/opt/homebrew/opt/postgresql@17/bin/initdb').parent)
    with tempfile.TemporaryDirectory(prefix='morse-policy-migration-', dir='/tmp') as raw:
        work = Path(raw).resolve()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='policy_test', PGDATABASE='policy_test')

        def run(*args, **kwargs):
            return subprocess.run([str(a) for a in args], env=env, check=True, **kwargs)

        def sql(statement, *, succeeds=True):
            result = subprocess.run([str(pg / 'psql'), '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], env=env, capture_output=True, text=True)
            if succeeds and result.returncode:
                raise RuntimeError(result.stderr)
            if not succeeds and not result.returncode:
                raise AssertionError('invalid policy mutation succeeded')
            return result.stdout.strip()

        started = False
        try:
            run(pg / 'initdb', '-D', work / 'data', '-U', 'policy_test', '--auth=trust', '--no-locale', stdout=subprocess.DEVNULL)
            run(pg / 'pg_ctl', '-D', work / 'data', '-l', work / 'postgres.log', '-o', shlex.join(['-h', '127.0.0.1', '-p', str(port), '-k', str(work)]), '-w', 'start', stdout=subprocess.DEVNULL)
            started = True
            env['PGDATABASE'] = 'postgres'
            run(pg / 'createdb', 'policy_test')
            env['PGDATABASE'] = 'policy_test'
            for migration in sorted(MIGRATIONS.glob('*.sql')):
                if migration.name >= '010_revenue_policy.sql':
                    break
                run(pg / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', migration, stdout=subprocess.DEVNULL)
            # Legacy fractional-fifths batch and permanent funded receipt existed
            # before the migration. No production private material is read.
            sql("INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,operations,carry_before,carry_after,membership_hash) VALUES(2800,0,0,decode(repeat('44',32),'hex'),decode(repeat('aa',32),'hex'),17,3,14,0,2,decode(repeat('bb',32),'hex')); INSERT INTO issuer_treasury_rewards_intents(intent_id,batch_id,epoch,pool,funder,source,mint,amount,state,receipt) VALUES(decode(repeat('11',32),'hex'),1,2802,decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),decode(repeat('55',32),'hex'),decode(repeat('44',32),'hex'),3,1,decode('4d524601'||repeat('00',188),'hex'))")
            before_query = "SELECT row_to_json(r)::text FROM (SELECT b.batch_id,b.week,b.asset,encode(b.mint,'hex') mint,encode(b.config_hash,'hex') config,b.amount,b.witness,b.operations,b.carry_before,b.carry_after,encode(b.membership_hash,'hex') members,encode(i.intent_id,'hex') intent,i.epoch,i.amount intent_amount,i.state,encode(i.receipt,'hex') receipt FROM issuer_treasury_weekly b JOIN issuer_treasury_rewards_intents i USING(batch_id)) r"
            before = json.loads(sql(before_query))
            run(pg / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', MIGRATIONS / '010_revenue_policy.sql', stdout=subprocess.DEVNULL)
            run(pg / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', MIGRATIONS / '011_burn_handoff.sql', stdout=subprocess.DEVNULL)
            run(pg / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', MIGRATIONS / '012_burn_expiry.sql', stdout=subprocess.DEVNULL)
            assert json.loads(sql(before_query)) == before
            assert sql('SELECT policy_version::text||\':\'||encode(policy_hash,\'hex\') FROM issuer_treasury_weekly') == '1:' + hashlib.sha256(V1.encode()).hexdigest()
            policies = dict(line.split(':') for line in sql("SELECT policy_version::text||':'||encode(policy_hash,'hex') FROM issuer_revenue_policies ORDER BY policy_version").splitlines())
            assert policies == {'1': hashlib.sha256(V1.encode()).hexdigest(), '2': hashlib.sha256(V2.encode()).hexdigest()}
            sql('UPDATE issuer_revenue_policies SET policy_hash=decode(repeat(\'ff\',32),\'hex\') WHERE policy_version=1', succeeds=False)
            sql('UPDATE issuer_treasury_weekly SET policy_version=2,policy_hash=(SELECT policy_hash FROM issuer_revenue_policies WHERE policy_version=2)', succeeds=False)
            # V2 gross3 must retain2 dust; operations cannot absorb this reserve.
            sql("INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_after,operations_carry_after,reserve_after,membership_hash,policy_version,policy_hash) SELECT 2800,0,0,decode(repeat('44',32),'hex'),decode(repeat('aa',32),'hex'),3,0,0,1,0,6,9,5,2,decode(repeat('cc',32),'hex'),2,policy_hash FROM issuer_revenue_policies WHERE policy_version=2")
            sql('UPDATE issuer_treasury_weekly SET operations=3,reserve_after=0 WHERE policy_version=2', succeeds=False)
            assert json.loads(sql(before_query + ' WHERE r.batch_id=1')) == before
            print(json.dumps({'schema_version': 1, 'proof': 'credit-revenue-policy-migration', 'legacy_batch_and_receipt_exact': True, 'historical_policy': 1, 'same_week_version2': True, 'forbidden_reclassification_rejected': True, 'units': 'original_asset_integer', 'live_funds': False}, sort_keys=True))
        finally:
            if started:
                run(pg / 'pg_ctl', '-D', work / 'data', '-m', 'fast', '-w', 'stop', stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
