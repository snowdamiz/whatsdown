#!/usr/bin/env python3
"""Exercise the issuer ledger against an owned, temporary PostgreSQL instance."""
import os
from pathlib import Path
import shutil
import shlex
import socket
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]
ROOT = PRODUCT.parent


def main():
    pg_bin = os.environ.get("PG_BIN")
    if not pg_bin:
        initdb = shutil.which("initdb") or "/opt/homebrew/opt/postgresql@17/bin/initdb"
        pg_bin = str(Path(initdb).parent)
    pg = Path(pg_bin)
    for tool in ("initdb", "pg_ctl", "createdb", "psql"):
        if not (pg / tool).is_file():
            raise SystemExit(f"Missing PostgreSQL tool {tool}; set PG_BIN")
    meshc = Path(os.environ.get("MESHC", ROOT / "mesh-lang/target/debug/meshc"))
    if not meshc.is_file():
        raise SystemExit("Set MESHC to a compiler with public BR1 support")
    # The short physical path also keeps the Unix socket below the macOS limit.
    with tempfile.TemporaryDirectory(prefix="morse-credit-issuer-", dir=Path("/tmp").resolve()) as raw:
        work = Path(raw)
        data = work / "data"
        log = work / "postgres.log"
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        env = os.environ.copy()
        env.update(PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="issuer_test", PGDATABASE="issuer_test")

        def run(command, **kwargs):
            return subprocess.run([str(part) for part in command], cwd=PRODUCT, env=env, check=True, **kwargs)

        run([pg / "initdb", "-D", data, "-U", "issuer_test", "--auth=trust", "--no-locale"], stdout=subprocess.DEVNULL)
        started = False
        try:
            run([pg / "pg_ctl", "-D", data, "-l", log, "-o", shlex.join(["-h", "127.0.0.1", "-p", str(port), "-k", str(work)]), "-w", "start"], stdout=subprocess.DEVNULL)
            started = True
            tests = PRODUCT / "services/credit-issuer/tests"
            selected = os.environ.get("ISSUER_TEST_FILE")
            if selected:
                target = (tests / selected).resolve()
                if target.parent != tests.resolve() or not target.name.endswith(".test.mpl") or not target.is_file():
                    raise SystemExit("ISSUER_TEST_FILE must name an existing issuer test file")
                targets = [target]
            else:
                targets = sorted(tests.glob("*.test.mpl"))
            # Every file owns its ledger, admission cursor, storage-key fixture
            # and triggers. Different synthetic service identities must never
            # inherit one another's authenticated transparency history.
            for index, target in enumerate(targets):
                database = f"issuer_test_{index}"
                env["PGDATABASE"] = "postgres"
                run([pg / "createdb", database])
                env["PGDATABASE"] = database
                for migration in sorted((PRODUCT / "services/credit-issuer/migrations").glob("*.sql")):
                    run([pg / "psql", "-v", "ON_ERROR_STOP=1", "-f", migration], stdout=subprocess.DEVNULL)
                env["MESSENGER_ISSUER_TEST_DATABASE_URL"] = f"postgres://issuer_test@127.0.0.1:{port}/{database}?sslmode=disable"
                run([meshc, "test", target])
            print(f"{len(targets)} isolated issuer test files passed")
        except subprocess.CalledProcessError:
            if log.exists():
                print(log.read_text()[-8000:])
            raise
        finally:
            if started:
                run([pg / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
