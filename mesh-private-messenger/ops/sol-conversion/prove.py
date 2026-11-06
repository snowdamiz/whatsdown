#!/usr/bin/env python3
"""Owned conversion proof. Explicit tool/ELF inputs, no public RPC or keys.

Python handles processes, test seeding and assertions. Mesh owns canonical
messages, RPC admission, recovery and accounting. Rust owns ephemeral test keys
and validates each exact Mesh message before executing it in the retained SBF.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "-c", str(source), str(target)], check=True)


def wait(path, process=None, timeout=180):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process and process.poll() is not None:
            raise RuntimeError("owned fixture exited before " + path.name)
        if time.monotonic() >= deadline:
            raise TimeoutError(path.name)
        time.sleep(.1)
    return json.loads(path.read_text()) if path.suffix == ".json" else path.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "runtime", "test-runtime", "dex-dir", "token-elf", "rewards-elf", "cargo-target", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--product", type=Path, default=HERE.parents[1])
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--expiry-fixture", type=Path)
    parser.add_argument("--carry-fixture", type=Path)
    parser.add_argument("--skip-tests", action="store_true", help="Run only the fresh retained-bank integrations")
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists():
        raise ValueError("fresh output directory required")
    out.mkdir(parents=True)
    for name in ("compiler", "runtime", "test_runtime", "dex_dir", "token_elf", "rewards_elf", "cargo_target", "product", "pg_bin"):
        setattr(args, name, getattr(args, name).resolve())
    env = os.environ.copy()
    env["PATH"] = str(args.pg_bin.resolve()) + os.pathsep + env["PATH"]
    env.update(MESH_RT_LIB_PATH=str(args.runtime.resolve()), MESH_TEST_RT_LIB_PATH=str(args.test_runtime.resolve()),
               CARGO_BUILD_JOBS="1", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               CARGO_TARGET_DIR=str(args.cargo_target.resolve()))
    source = out / "source"
    product = source / "product"
    issuer = product / "services/credit-issuer"
    op = product / "ops/sol-conversion"
    records = []

    def copy_tree(origin, target, suffixes):
        for p in sorted(origin.rglob("*")):
            if p.is_file() and (p.suffix in suffixes or p.name in ("mesh.toml", "Cargo.toml", "Cargo.lock")):
                copy_file(p, target / p.relative_to(origin))

    copy_tree(args.product / "services/credit-issuer", issuer, {".mpl", ".sql"})
    copy_tree(args.product / "packages/messenger-protocol", product / "packages/messenger-protocol", {".mpl"})
    # Declared public dependencies only; no default executable or runtime chosen.
    dependency_root = args.product.parent / "mesh-lang/packages"
    for name in ("mesh-binary", "mesh-solana", "mesh-lightning"):
        copy_tree(dependency_root / name, source / "mesh-lang/packages" / name, {".mpl"})
    copy_tree(HERE, op, {".mpl", ".py", ".rs", ".md"})
    for p in (args.product / "ops/token/fixtures/dex").glob("*.json"):
        copy_file(p, product / "ops/token/fixtures/dex" / p.name)
    copy_file(args.product / "ops/token/dex-source.json", product / "ops/token/dex-source.json")
    pins = {str(p.relative_to(source)): sha(p) for p in source.rglob("*") if p.is_file()}
    (out / "source-before.json").write_text(json.dumps(pins, indent=2) + "\n")
    tools = {}
    for name in ("compiler", "runtime", "test_runtime", "token_elf", "rewards_elf"):
        p = getattr(args, name).resolve()
        tools[name] = {"path": str(p), "sha256": sha(p)}
        copy_file(p, out / "inputs" / {"runtime": "libmesh_rt.a", "test_runtime": "libmesh_test_rt.a"}.get(name, name))
    env.update(MESH_RT_LIB_PATH=str(out / "inputs/libmesh_rt.a"), MESH_TEST_RT_LIB_PATH=str(out / "inputs/libmesh_test_rt.a"))
    args.compiler = out / "inputs/compiler"
    for p in args.dex_dir.glob("*.so"):
        copy_file(p, out / "inputs/dex" / p.name)
    (out / "toolchain.json").write_text(json.dumps(tools, indent=2) + "\n")

    def run(command, cwd=product, name="command", extra=None, timeout=360):
        log = out / (name + ".log")
        with log.open("w") as stream:
            result = subprocess.run([str(x) for x in command], cwd=cwd, env=env | (extra or {}),
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        records.append({"name": name, "exit": result.returncode, "log": log.name})
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(name + " failed; see " + str(log))
        return log.read_text()

    run([args.compiler, "build", ".", "--opt-level", "2", "--output", op / "sol-conversion"], cwd=op, name="operator-build")
    fund = op / "fixtures/funding-driver"
    run([args.compiler, "build", ".", "--opt-level", "2", "--output", fund / "funding-driver"], cwd=fund, name="funding-driver-build")
    raw = run(["cargo", "test", "--offline", "--manifest-path", op / "tests/sbf/Cargo.toml", "--test", "sol_conversion", "--no-run", "--message-format=json"], name="sbf-build")
    artifacts = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    runner = Path(next(row["executable"] for row in artifacts if row.get("executable") and row.get("profile", {}).get("test")))
    copy_file(runner, out / "inputs/sbf-runner")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); pg_port = sock.getsockname()[1]
    user = "sol_conversion_test"
    env.update(PGHOST="127.0.0.1", PGPORT=str(pg_port), PGUSER=user, PGDATABASE="postgres")
    started = False
    try:
        run([args.pg_bin / "initdb", "-D", out / "pg-data", "-U", user, "--auth=trust", "--no-locale"], name="pg-init")
        run([args.pg_bin / "pg_ctl", "-D", out / "pg-data", "-l", out / "pg.log", "-o", f"-h 127.0.0.1 -p {pg_port} -k /private/tmp", "-w", "start"], name="pg-start")
        started = True

        def database(name):
            run([args.pg_bin / "createdb", name], name=name + "-create")
            for i, migration in enumerate(sorted((issuer / "migrations").glob("*.sql"))):
                run([args.pg_bin / "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", name, "-f", migration], name=f"{name}-migrate-{i}")
            return f"postgresql://{user}@127.0.0.1:{pg_port}/{name}"

        def sql(url, query):
            return subprocess.run([args.pg_bin / "psql", url, "-XAt", "-v", "ON_ERROR_STOP=1", "-c", query], check=True, capture_output=True, text=True).stdout.strip()

        banks = {}
        for case, bucket, failure, funding in (("witness", 0, False, True), ("failed", 0, True, False), ("burn", 1, False, False)):
            directory = out / case
            directory.mkdir()
            banks[case] = directory
            url = database("conversion_" + case)
            variables = {"MORSE_SOL_CONVERSION_PRODUCT": str(product), "MORSE_TOKEN_DEX_BIN_DIR": str(args.dex_dir.resolve()),
                         "MORSE_SOL_CONVERSION_TOKEN_ELF": str(args.token_elf), "MORSE_SOL_CONVERSION_REWARDS_ELF": str(args.rewards_elf.resolve()), "MORSE_SOL_CONVERSION_EXPORT": str(directory),
                         "MORSE_SOL_CONVERSION_HANDOFF": "1", "MORSE_SOL_CONVERSION_BUCKET": str(bucket)}
            if failure: variables["MORSE_SOL_CONVERSION_MINIMUM_FAILURE"] = "1"
            if funding: variables["MORSE_SOL_CONVERSION_FUNDING_HANDOFF"] = "1"
            trace = (directory / "sbf.log").open("w")
            sbf = subprocess.Popen([runner, "--exact", "actual_native_escrow_exactin_and_received_usdc", "--nocapture"], env=env | variables, stdout=trace, stderr=subprocess.STDOUT)
            rpc = None
            try:
                bank = wait(directory / "initial.json", sbf)
                config = {key: bank[key] for key in ("owner", "payer", "usdc", "pool", "amm_config", "authority", "input_vault", "output_vault", "observation", "oracle", "amm_hash", "raydium_code", "token_code", "rent", "treasury_config", "providers", "providers_hash", "cluster", "nonce_authority", "nonce_address", "rewards_program", "rewards_pool")}
                config.update(schema=1, maximum_fee="100000", owned_loopback_test=True, database_url=url)
                config_file = directory / "operator.json"
                config_file.write_text(json.dumps(config, indent=2) + "\n")
                sql(url, f"INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,1,1,1,decode(repeat('00',32),'hex'),decode('{bank['treasury_config']}','hex'),5000000000,1000000000,1500000000,2500000000,0,0,decode('{bank['membership_hash']}','hex'),2,decode('{bank['policy_hash']}','hex'))")
                if bucket == 1: sql(url, "INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES(1,1500000000)")
                mode = directory / "rpc.mode"
                mode.write_text("normal")
                rpc_log = (directory / "rpc.log").open("w")
                rpc = subprocess.Popen(["python3", op / "fixtures/rpc.py", "--bank", directory / "initial.json", "--execution", directory / "execution.json", "--mode", mode, "--trace", directory / "http-trace.jsonl", "--handoff", "--database", url], env=env, stdout=rpc_log, stderr=subprocess.STDOUT)
                for _ in range(100):
                    try:
                        with socket.create_connection(("127.0.0.1", 24494), timeout=.1): break
                    except OSError:
                        if rpc.poll() is not None: raise RuntimeError("owned RPC failed to bind")
                        time.sleep(.1)
                steps = []

                def command(action, *values, expected, mode_name=None):
                    if mode_name: mode.write_text(mode_name)
                    result = run([op / "sol-conversion", config_file, action, *values], name=f"{case}-{len(steps)}-{action}")
                    value = json.loads(result.strip())
                    assert value["state"] == expected, value
                    steps.append({"action": action, "result": value})
                    (directory / "processes.json").write_text(json.dumps(steps, indent=2) + "\n")

                identity = bank["id"]
                command("prepare", "1", str(bucket), directory / "message.base64", expected=0)
                wait(directory / "signed.packet.base64", sbf)
                command("commit", identity, "0", directory / "signed.packet.base64", expected=1)
                command("submit", identity, expected=1, mode_name="dropack")
                wait(directory / "execution.json", sbf)
                command("status", identity, expected=1)
                command("reconcile", identity, expected=3 if failure else 2, mode_name="executed")
                if failure:
                    wait(directory / "retry-ready.json", sbf)
                    assert sql(url, "SELECT count(*) FROM issuer_sol_conversion_outputs") == "0"
                    command("prepare", "1", str(bucket), directory / "retry.message.base64", expected=0, mode_name="retry-ready")
                    wait(directory / "retry.signed.packet.base64", sbf)
                    command("commit", identity, "1", directory / "retry.signed.packet.base64", expected=1)
                    command("submit", identity, expected=1)
                    wait(directory / "retry.execution.json", sbf)
                    command("reconcile", identity, expected=2, mode_name="retry-executed")
                    assert sql(url, "SELECT string_agg(ordinal::text||':'||state::text||':'||octet_length(receipt)::text,',' ORDER BY ordinal) FROM issuer_sol_conversion_attempts") == "0:3:197,1:2:197"
                command("status", identity, expected=2)
                assert sql(url, "SELECT count(*) FROM issuer_sol_conversion_outputs") == "1"
                assert sql(url, "SELECT amount::text||':'||witness::text||':'||burn::text||':'||operations::text FROM issuer_treasury_weekly") == "5000000000:1000000000:1500000000:2500000000"
                if funding:
                    wait(directory / "funding-ready.json", sbf)
                    run([fund / "funding-driver", config_file, directory / "funding-ready.json", identity, directory / "funding.message.base64"], name="witness-funding-plan")
                    wait(directory / "funding.signed.packet.base64", sbf)
                    shutil.copyfile(directory / "funding.signed.packet.base64", directory / "funding.send.packet.base64")
                    result = wait(directory / "funding.json", sbf)
                    assert result["exact_intent_replays"] == 2 and result["source_remaining"] == "1000"
                    mode.write_text("funded")
                    run([fund / "funding-driver", config_file, directory / "funding-ready.json", identity, directory / "unused", "reconcile"], name="witness-funding-reconcile")
                    assert sql(url, "SELECT state::text||':'||octet_length(receipt)::text FROM issuer_sol_witness_funding") == "1:192"
                if sbf.wait(timeout=60): raise RuntimeError("retained SBF failed")
                (directory / "accounting.txt").write_text(sql(url, "SELECT ordinal::text||':'||state::text||':'||octet_length(receipt)::text FROM issuer_sol_conversion_attempts ORDER BY ordinal") + "\n")
            finally:
                if sbf.poll() is None:
                    (directory / "abort").write_text("driver stopped")
                    sbf.terminate(); sbf.wait(timeout=10)
                trace.close()
                if rpc:
                    rpc.terminate(); rpc.wait(timeout=10); rpc_log.close()

        if not args.skip_tests:
            # Each stateful fixture owns a new database. The two RPC fixture
            # ports are sequential; no provider or clock is caller-selected.
            for test in sorted((issuer / "tests").glob("sol_conversion*.test.mpl")):
                name = test.name.removesuffix(".test.mpl")
                url = database(name)
                selected = banks["burn" if name.endswith("_burn") else "witness"]
                mode = selected / "rpc.mode"
                mode.write_text("normal")
                rpc_log = (out / (name + "-rpc.log")).open("w")
                rpc = subprocess.Popen(["python3", op / "fixtures/rpc.py", "--bank", selected / "initial.json", "--execution", selected / "execution.json", "--mode", mode, "--trace", selected / (name + "-trace.jsonl")], env=env, stdout=rpc_log, stderr=subprocess.STDOUT)
                try:
                    time.sleep(.2)
                    run([args.compiler, "test", test], name=name, extra={"MESSENGER_ISSUER_TEST_DATABASE_URL": url, "MORSE_SOL_CONVERSION_BANK": str(selected / "initial.json"), "MORSE_SOL_CONVERSION_EXECUTION": str(selected / "execution.json"), "MORSE_SOL_CONVERSION_MODE": str(mode), "MORSE_SOL_CONVERSION_TRACE": str(selected / (name + "-trace.jsonl"))})
                finally:
                    rpc.terminate(); rpc.wait(timeout=10); rpc_log.close()
            if args.carry_fixture and args.expiry_fixture:
                for name in ("treasury_burn", "treasury_burn_expiry"):
                    url = database(name)
                    run([args.compiler, "test", issuer / "tests" / (name + ".test.mpl")], name=name, extra={"MESSENGER_ISSUER_TEST_DATABASE_URL": url, "MORSE_TOKEN_CARRY_FIXTURES_PATH": str(args.carry_fixture.resolve()), "MORSE_TOKEN_EXPIRY_FIXTURES_PATH": str(args.expiry_fixture.resolve())})
    finally:
        if started: run([args.pg_bin / "pg_ctl", "-D", out / "pg-data", "-m", "fast", "-w", "stop"], name="pg-stop")
    after = {str(p.relative_to(source)): sha(p) for p in source.rglob("*") if p.is_file() and str(p.relative_to(source)) in pins}
    assert after == pins, "captured source changed during proof"
    (out / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    manifest = [{"path": str(p.relative_to(out)), "sha256": sha(p), "bytes": p.stat().st_size} for p in sorted(out.rglob("*")) if p.is_file() and "pg-data" not in p.parts]
    (out / "manifest.json").write_text(json.dumps({"records": manifest, "boundary": "Owned controlled SBF/HTTP/PG; no production finality, public mint, oracle guardian, provider independence, keeper, or deployment claim."}, indent=2) + "\n")
    print(json.dumps({"status": "passed", "manifest": str(out / "manifest.json"), "sha256": sha(out / "manifest.json")}))


if __name__ == "__main__":
    main()
