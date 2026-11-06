#!/usr/bin/env python3
"""Real priority-signup HTTP and transaction proof in an owned PostgreSQL cluster."""
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen

PRODUCT = Path(__file__).resolve().parents[1]


def main():
    meshc = Path(os.environ.get("MESHC", PRODUCT.parent / "mesh-lang/target/debug/meshc"))
    pg = Path(os.environ.get("PG_BIN", os.environ.get("CREDIT_TEST_PG_BIN", Path(shutil.which("initdb") or "/opt/homebrew/opt/postgresql@17/bin/initdb").parent)))
    for tool in ("initdb", "pg_ctl", "createdb", "psql"):
        if not (pg / tool).is_file():
            raise SystemExit(f"Missing PostgreSQL tool {tool}; set PG_BIN")
    used_ports = set()

    def port():
        while True:
            with socket.socket() as candidate:
                candidate.bind(("127.0.0.1", 0))
                value = candidate.getsockname()[1]
            if value not in used_ports:
                used_ports.add(value)
                return value

    with tempfile.TemporaryDirectory(prefix="morse-credit-signup-", dir=Path("/tmp").resolve()) as raw:
        work = Path(raw)
        db_port = port()
        env = os.environ.copy()
        env.update(PGHOST="127.0.0.1", PGPORT=str(db_port), PGUSER="signup_test", PGDATABASE="credits_signup_test",
                   MESSENGER_DATABASE_URL=f"postgres://signup_test@127.0.0.1:{db_port}/credits_signup_test?sslmode=disable",
                   MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX="5b" * 32,
                   MESSENGER_WITNESS_A_PUBLIC_KEY_HEX="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                   MESSENGER_WITNESS_B_PUBLIC_KEY_HEX="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                   CREDIT_FIXTURE_WITNESS_A_SEED="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                   CREDIT_FIXTURE_WITNESS_B_SEED="4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                   MESSENGER_DELIVERY_SEALING_SEED_HEX="77" * 32,
                   MESSENGER_DELIVERY_INTERNAL_TOKEN="12" * 32,
                   MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN="34" * 32,
                   MESSENGER_CREDITS_PURPOSE="test", MESSENGER_JOBS_URL="",
                   MESSENGER_ABUSE_BASE_DIFFICULTY="16", MESSENGER_ABUSE_DIFFICULTY="16", MESSENGER_SIGNUP_DIFFICULTY="17")
        env["MESSENGER_TEST_DATABASE_URL"] = env["MESSENGER_DATABASE_URL"]

        def run(command, **kwargs):
            command_env = kwargs.pop("env", env)
            return subprocess.run([str(item) for item in command], cwd=PRODUCT, env=command_env, check=True, **kwargs)

        binary = Path(env.get("CREDIT_CORE_BIN", work / "directory-delivery"))
        if "CREDIT_CORE_BIN" not in env:
            run([meshc, "build", PRODUCT / "services/directory-delivery", "-o", binary])
        run([pg / "initdb", "-D", work / "pg", "-U", "signup_test", "--auth=trust", "--no-locale"], stdout=subprocess.DEVNULL)
        started = False
        processes = []
        outputs = []
        try:
            run([pg / "pg_ctl", "-D", work / "pg", "-l", work / "postgres.log", "-o",
                 shlex.join(["-h", "127.0.0.1", "-p", str(db_port), "-k", str(work)]), "-w", "start"], stdout=subprocess.DEVNULL)
            started = True
            run([pg / "createdb", "credits_signup_test"])
            for migration in sorted((PRODUCT / "services/directory-delivery/migrations").glob("*.sql")):
                run([pg / "psql", "-v", "ON_ERROR_STOP=1", "-f", migration], stdout=subprocess.DEVNULL)
            run([pg / "psql", "-v", "ON_ERROR_STOP=1", "-c",
                 "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', decode(repeat('00',188),'hex'), decode(repeat('00',6),'hex'), now())"], stdout=subprocess.DEVNULL)
            for name, enabled, difficulty in [("CORE", "on", "17"), ("BASE_CORE", "on", "16"), ("DISABLED_CORE", "off", "17")]:
                http_port = port()
                service_env = {**env, "MESSENGER_PORT": str(http_port), "MESSENGER_STREAM_PORT": str(port()),
                               "MORSE_PAID_SIGNUP": enabled, "MESSENGER_SIGNUP_DIFFICULTY": difficulty}
                output = (work / f"{name}.log").open("w+")
                outputs.append(output)
                process = subprocess.Popen([str(binary.resolve())], cwd=PRODUCT, env=service_env,
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=output)
                processes.append(process)
                base = f"http://127.0.0.1:{http_port}"
                env[f"CREDIT_TEST_{name}_URL"] = base
                for attempt in range(100):
                    if process.poll() is not None:
                        raise RuntimeError(f"{name} exited before readiness")
                    try:
                        with urlopen(base + "/health", timeout=1) as response:
                            if response.status == 200:
                                break
                    except (URLError, TimeoutError):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f"{name} did not become ready")
            run([meshc, "test", PRODUCT / "services/directory-delivery/security/credits-signup.test.mpl"], timeout=120)
            print("CREDITS_SIGNUP_PROOF: raised-difficulty only; atomic real registration/spend; effect rollback; concurrent exact receipt; no repeat charge")
            # The shared Devices transaction still serves free registration,
            # renewal and hybrid credential transitions. Exercise that existing
            # suite against a separate legacy-log database after the paid proof.
            run([pg / "createdb", "credits_signup_free_test"])
            free_env = {**env, "PGDATABASE": "credits_signup_free_test",
                        "MESSENGER_TEST_DATABASE_URL": env["MESSENGER_DATABASE_URL"].replace("/credits_signup_test?", "/credits_signup_free_test?")}
            for migration in sorted((PRODUCT / "services/directory-delivery/migrations").glob("*.sql")):
                run([pg / "psql", "-v", "ON_ERROR_STOP=1", "-f", migration], env=free_env, stdout=subprocess.DEVNULL)
            run([meshc, "test", PRODUCT / "services/directory-delivery/tests/devices.test.mpl"], env=free_env, timeout=120)
        except Exception:
            for output in outputs:
                output.flush()
                output.seek(0)
                print(output.read()[-6000:])
            raise
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for output in outputs:
                output.close()
            if started:
                run([pg / "pg_ctl", "-D", work / "pg", "-m", "fast", "-w", "stop"], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
