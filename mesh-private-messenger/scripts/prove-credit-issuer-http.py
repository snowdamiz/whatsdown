#!/usr/bin/env python3
"""Actual issuer HTTP, paid issuance and restart proof in owned local state."""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]


def main():
    public = Path(os.environ.get("MESH_LANG_ROOT", PRODUCT.parent / "mesh-lang")).resolve()
    meshc = Path(os.environ.get("MESHC", public / "target/debug/meshc"))
    pg = Path(os.environ.get("PG_BIN", os.environ.get("CREDIT_TEST_PG_BIN", Path(shutil.which("initdb") or "/opt/homebrew/opt/postgresql@17/bin/initdb").parent)))
    for tool in ("initdb", "pg_ctl", "createdb", "psql"):
        if not (pg / tool).is_file():
            raise SystemExit(f"Missing PostgreSQL tool {tool}; set PG_BIN")
    if not meshc.is_file():
        raise SystemExit("Set MESHC to the public compiler")
    with tempfile.TemporaryDirectory(prefix="morse-issuer-http-", dir=Path("/tmp").resolve()) as raw:
        work = Path(raw)
        env = os.environ.copy()
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        env.update(PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="issuer_http", PGDATABASE="issuer_http",
                   MESH_LANG_ROOT=str(public), MESHC=str(meshc), MORSE_HTTP_WORK=str(work),
                   MORSE_HTTP_SERVICE_SEED="11" * 32, MORSE_HTTP_WITNESS_SEED="22" * 32,
                   MESSENGER_ISSUER_DATABASE_URL=f"postgres://issuer_http@127.0.0.1:{port}/issuer_http?sslmode=disable",
                   MESSENGER_CREDIT_STORAGE_DIR=str(work / "issuer-keys"), MORSE_HTTP_CLIENT_STORE=str(work / "client-keys"),
                   MORSE_HTTP_PSQL=str(pg / "psql"))

        def run(command, **kwargs):
            return subprocess.run([str(item) for item in command], cwd=PRODUCT, env=env, check=True, **kwargs)

        project = work / "client"
        project.mkdir()
        (project / "mesh.toml").write_text('[package]\nname="issuer-http-client"\nversion="0.1.0"\n[dependencies]\n'
            + 'credit-issuer={path=' + json.dumps(str(PRODUCT / "services/credit-issuer")) + '}\n'
            + 'messenger-protocol={path=' + json.dumps(str(PRODUCT / "packages/messenger-protocol")) + '}\n')
        (project / "main.mpl").write_text((PRODUCT / "services/credit-issuer/payment/fixtures/http-client.mpl.fixture").read_text())
        run([meshc, "build", project, "-o", work / "http-client"])
        issuer = Path(env.get("CREDIT_ISSUER_BIN", work / "credit-issuer"))
        if "CREDIT_ISSUER_BIN" not in env:
            run([meshc, "build", PRODUCT / "services/credit-issuer", "-o", issuer])
        env.update(CREDIT_ISSUER_BIN=str(issuer.resolve()), MORSE_HTTP_CLIENT_BIN=str(work / "http-client"))
        oracle = PRODUCT / "programs/target/debug/examples/credit_payment_fixture"
        if not oracle.is_file() or oracle.stat().st_mtime < (PRODUCT / "programs/morse-rewards/examples/credit_payment_fixture.rs").stat().st_mtime:
            run(["cargo", "build", "--locked", "--manifest-path", PRODUCT / "programs/Cargo.toml", "-p", "morse-rewards", "--example", "credit_payment_fixture"])
        env["MORSE_HTTP_PAYMENT_ORACLE"] = str(oracle)
        run([pg / "initdb", "-D", work / "pg", "-U", "issuer_http", "--auth=trust", "--no-locale"], stdout=subprocess.DEVNULL)
        started = False
        try:
            run([pg / "pg_ctl", "-D", work / "pg", "-l", work / "postgres.log", "-o",
                 shlex.join(["-h", "127.0.0.1", "-p", str(port), "-k", str(work)]), "-w", "start"], stdout=subprocess.DEVNULL)
            started = True
            run([pg / "createdb", "issuer_http"])
            for migration in sorted((PRODUCT / "services/credit-issuer/migrations").glob("*.sql")):
                run([pg / "psql", "-v", "ON_ERROR_STOP=1", "-f", migration], stdout=subprocess.DEVNULL)
            process = subprocess.Popen(["node", str(PRODUCT / "services/credit-issuer/payment/fixtures/http-proof.mjs")], cwd=PRODUCT, env=env, start_new_session=True)
            try:
                status = process.wait(timeout=420)
                if status:
                    raise subprocess.CalledProcessError(status, process.args)
            finally:
                # Kill only this proof's process group, including a service left
                # alive by an interrupted Node runner. Never touch other DBs.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            if started:
                run([pg / "pg_ctl", "-D", work / "pg", "-m", "fast", "-w", "stop"], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
