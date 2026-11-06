#!/usr/bin/env python3
"""Offline treasury restart proof with an owned PostgreSQL and actual local Bank."""
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]

def main():
    pg = Path(os.environ.get("PG_BIN", "/opt/homebrew/opt/postgresql@17/bin"))
    for tool in ("initdb", "pg_ctl", "createdb", "psql"):
        if not (pg / tool).is_file():
            raise SystemExit(f"Missing {tool}; set PG_BIN")
    with tempfile.TemporaryDirectory(prefix="morse-treasury-", dir=Path("/tmp").resolve()) as raw:
        work = Path(raw)
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1",0))
            port = candidate.getsockname()[1]
        env = os.environ.copy()
        env.update(PGHOST="127.0.0.1",PGPORT=str(port),PGUSER="treasury_test",PGDATABASE="treasury_test",
                   CREDIT_TEST_PSQL=str(pg/"psql"),MESSENGER_ISSUER_TEST_DATABASE_URL=f"postgres://treasury_test@127.0.0.1:{port}/treasury_test?sslmode=disable")
        def run(command,**kwargs):
            return subprocess.run([str(x) for x in command],env=env,cwd=PRODUCT,check=True,**kwargs)
        run([pg/"initdb","-D",work/"db","-U","treasury_test","--auth=trust","--no-locale"],stdout=subprocess.DEVNULL)
        started=False
        try:
            run([pg/"pg_ctl","-D",work/"db","-l",work/"pg.log","-o",shlex.join(["-h","127.0.0.1","-p",str(port),"-k",str(work)]),"-w","start"],stdout=subprocess.DEVNULL)
            started=True
            run([pg/"createdb","treasury_test"])
            for migration in sorted((PRODUCT/"services/credit-issuer/migrations").glob("*.sql")):
                run([pg/"psql","-v","ON_ERROR_STOP=1","-f",migration],stdout=subprocess.DEVNULL)
            case = os.environ.get("TREASURY_PROOF_CASE", "refund")
            if case not in ("refund", "funding", "service"):
                raise SystemExit("Unknown TREASURY_PROOF_CASE")
            if case == "service":
                target = PRODUCT/"services/credit-issuer/tests/treasury-service.test.mjs"
            else:
                test = "funding.test.mjs" if case == "funding" else "treasury.test.mjs"
                target = PRODUCT/"tools/solana-nonce-proof"/test
            run(["node","--test",target])
        except subprocess.CalledProcessError:
            print((work/"pg.log").read_text()[-8000:])
            raise
        finally:
            if started:
                run([pg/"pg_ctl","-D",work/"db","-m","fast","-w","stop"],stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    main()
