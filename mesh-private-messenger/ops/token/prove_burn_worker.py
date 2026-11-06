#!/usr/bin/env python3
"""Freeze sources, compile Mesh, and orchestrate owned burn-worker tests only.

No production RPC, signer implementation, financial policy, service installation,
compiler rebuild, native device or deployment is performed by this adapter.
"""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, tempfile, time, tomllib


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--test-runtime", required=True, type=Path)
    parser.add_argument("--proof-dir", required=True, type=Path)
    parser.add_argument("--product-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--token-overlay", type=Path, help="optional reviewed candidate, never a default dependency")
    parser.add_argument("--burn-read-source", type=Path, help="optional reviewed TokenBurnRead candidate")
    parser.add_argument("--burn-fixture", type=Path)
    parser.add_argument("--carry-fixture", type=Path)
    parser.add_argument("--bank-fixture", type=Path)
    parser.add_argument("--hook-dir", type=Path, help="optional already-running owned SBF retained-bank handoff")
    parser.add_argument("--key-path", type=Path, help="private ephemeral SBF test key outside all proof directories")
    args = parser.parse_args()
    if bool(args.hook_dir) != bool(args.key_path):
        parser.error("--hook-dir and --key-path must be supplied together")
    product = args.product_root.resolve()
    token = product / "ops/token"
    tooling = Path(__file__).resolve().parent
    fixture_root = (args.token_overlay.resolve() if args.token_overlay else tooling) / "worker-fixtures"
    proof = args.proof_dir.resolve()
    if proof.exists() or proof.is_relative_to(token):
        parser.error("--proof-dir must be new and outside the source package")
    if args.key_path and (args.key_path.resolve().is_relative_to(proof) or args.key_path.resolve().is_relative_to(args.hook_dir.resolve())):
        parser.error("ephemeral SBF key must be outside proof/hook directories")
    proof.mkdir(parents=True)
    (proof / "proof").mkdir()
    (proof / "fixtures").mkdir()
    (proof / "tooling").mkdir()
    private = Path(tempfile.mkdtemp(prefix="morse-burn-worker-qualification-", dir=tempfile.gettempdir())).resolve()
    started = time.monotonic()
    records = []
    package_paths = {}
    package_meta = {}

    def discover(path):
        path = path.resolve()
        if path in package_paths:
            return
        manifest = tomllib.loads((path / "mesh.toml").read_text())
        name = "token" if path == token.resolve() else manifest["package"]["name"]
        if name in package_paths.values():
            raise ValueError("ambiguous dependency package name")
        package_paths[path] = name
        package_meta[path] = manifest
        for dependency in manifest.get("dependencies", {}).values():
            if not isinstance(dependency, dict) or "path" not in dependency:
                raise ValueError("qualification requires explicit local dependency paths")
            discover(path / dependency["path"])

    discover(token)
    originals = {}
    for origin, name in package_paths.items():
        before = {str(p.relative_to(origin)): sha(p) for p in origin.rglob("*") if p.is_file() and (p.suffix == ".mpl" or p.name == "mesh.toml")}
        for rel, digest in before.items():
            source = origin / rel
            target = proof / "sources" / name / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if sha(target) != digest:
                raise ValueError("source changed during copy")
            originals[str(source)] = digest
        after = {str(p.relative_to(origin)): sha(p) for p in origin.rglob("*") if p.is_file() and (p.suffix == ".mpl" or p.name == "mesh.toml")}
        if before != after:
            raise ValueError("source changed during capture")
    overlay_inputs = {}
    if args.token_overlay:
        for source in args.token_overlay.resolve().rglob("*"):
            if source.is_file() and (source.suffix == ".mpl" or source.name == "mesh.toml"):
                target = proof / "sources/token" / source.relative_to(args.token_overlay.resolve())
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                overlay_inputs[str(source)] = sha(source)
    if args.burn_read_source:
        target = proof / "sources/messenger-protocol/transparency/token_burn_read.mpl"
        shutil.copy2(args.burn_read_source, target)
        overlay_inputs[str(args.burn_read_source.resolve())] = sha(target)
    for origin, name in package_paths.items():
        target = proof / "sources" / name / "mesh.toml"
        value = target.read_text()
        for dependency in package_meta[origin].get("dependencies", {}).values():
            destination = proof / "sources" / package_paths[(origin / dependency["path"]).resolve()]
            value = value.replace('path = "' + dependency["path"] + '"', 'path = "' + str(destination) + '"')
        target.write_text(value)
    for source in fixture_root.rglob("*.mpl.fixture"):
        rel = str(source.relative_to(fixture_root))[:-len(".fixture")]
        target = proof / "sources/token" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        overlay_inputs[str(source)] = sha(source)
    corpus = {
        "token-burn.json": args.burn_fixture or fixture_root / "corpus/token-burn.json",
        "token-carry.json": args.carry_fixture or fixture_root / "corpus/token-carry.json",
        "bank.json": args.bank_fixture or fixture_root / "corpus/bank.json",
    }
    for name, source in corpus.items():
        shutil.copy2(source, proof / "fixtures" / name)
        overlay_inputs[str(Path(source).resolve())] = sha(source)
    shutil.copy2(fixture_root / "corpus/provenance.json", proof / "fixtures/provenance.json")
    write_json(proof / "fixtures/selection.json", {name: {"source": str(Path(source).resolve()), "sha256": sha(source)} for name, source in corpus.items()})
    for name in ["prove_burn_worker.py", "burn_worker_rpc_fixture.py", "burn_worker_sbf_fixture.py"]:
        shutil.copy2(tooling / name, proof / "tooling" / name)
    tools = {"compiler": str(args.compiler.resolve()), "runtime": str(args.runtime.resolve()), "test_runtime": str(args.test_runtime.resolve())}
    for name, path in list(tools.items()):
        tools[name + "_sha256"] = sha(path)
    write_json(proof / "proof/basis.json", tools)
    write_json(proof / "original-inputs.json", {"sources": originals, "explicit_overrides_and_fixtures": overlay_inputs})
    frozen = {str(p.relative_to(proof)): sha(p) for parent in [proof / "sources", proof / "fixtures", proof / "tooling"] for p in parent.rglob("*") if p.is_file()}
    write_json(proof / "source-manifest.json", frozen)
    environment = dict(os.environ, MESH_RT_LIB_PATH=tools["runtime"], MESH_TEST_RT_LIB_PATH=tools["test_runtime"])
    environment.pop("MORSE_BURN_WORKER_PAYER_SEED_HEX", None)
    environment.pop("CARGO_TARGET_DIR", None)
    environment.update(MORSE_TOKEN_BURN_FIXTURES_PATH=str(proof / "fixtures/token-burn.json"), MORSE_TOKEN_CARRY_FIXTURES_PATH=str(proof / "fixtures/token-carry.json"), MORSE_BURN_WORKER_BANK_FIXTURE=str(proof / "fixtures/bank.json"))

    def verify():
        for name in ["compiler", "runtime", "test_runtime"]:
            if sha(tools[name]) != tools[name + "_sha256"]:
                raise ValueError("tool input changed")
        for rel, digest in frozen.items():
            if sha(proof / rel) != digest:
                raise ValueError("frozen source changed")

    def run(label, command, extra=None, timeout=300):
        verify()
        directory = proof / "proof" / label
        directory.mkdir()
        start = time.monotonic()
        with (directory / "run.log").open("w") as log:
            process = subprocess.run(command, cwd=proof / "sources/token", env=dict(environment, **(extra or {})), stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        verify()
        record = {"label": label, "command": [str(x) for x in command], "exit_code": process.returncode, "seconds": round(time.monotonic() - start, 3), "log_sha256": sha(directory / "run.log")}
        write_json(directory / "result.json", record)
        records.append(record)
        print(json.dumps(record), flush=True)
        if process.returncode:
            raise RuntimeError("qualification failed: " + label)
        return directory

    succeeded = False
    try:
        for name in ["burn_schedule.test.mpl", "burn_active_v2.test.mpl", "burn_recovery.test.mpl"]:
            directory = private / name
            directory.mkdir()
            (directory / "key").mkdir(mode=0o700)
            run(name, [tools["compiler"], "test", str(proof / "sources/token" / name)], {"MORSE_BURN_WORKER_TEST_KEY": str(directory / "key"), "MORSE_BURN_WORKER_TEST_DB": str(directory / "worker.db")})
        binary = proof / "proof/worker-build/burn-worker"
        build = run("worker-build", [tools["compiler"], "build", str(proof / "sources/token"), "--opt-level", "2", "-o", str(binary)])
        result = json.loads((build / "result.json").read_text())
        result.update(binary_sha256=sha(binary), compiler_sha256=tools["compiler_sha256"], runtime_sha256=tools["runtime_sha256"], source_manifest_sha256=sha(proof / "source-manifest.json"))
        write_json(build / "result.json", result)
        run("rpc-driver", ["python3", str(proof / "tooling/burn_worker_rpc_fixture.py"), "--work-root", str(proof), "--proof-dir", str(proof / "proof/rpc-peer")])
        sbf = None
        if args.hook_dir:
            run("sbf-driver", ["python3", str(proof / "tooling/burn_worker_sbf_fixture.py"), "--work-root", str(proof), "--hook-dir", str(args.hook_dir.resolve()), "--key-path", str(args.key_path.resolve()), "--proof-dir", str(proof / "proof/sbf-peer")], timeout=1200)
            run("restart-archive-probe", [tools["compiler"], "test", str(proof / "sources/token/burn_worker_restart.test.mpl")], {"MORSE_BURN_WORKER_EVIDENCE": str(proof / "proof/sbf-peer")})
            sbf = json.loads((proof / "proof/sbf-peer/result.json").read_text())
            # Test wrapping state is never included in evidence/source manifests.
            test_state = Path(sbf["private_test_workspace"]).resolve()
            if test_state.parent != Path(tempfile.gettempdir()).resolve() or not test_state.name.startswith("morse-burn-sbf-worker-"):
                raise ValueError("unexpected private test state path")
            journals = proof / "encrypted-journals"
            journals.mkdir()
            for name in ["worker.db", "late.db", "legacy.db", "missed.db"]:
                shutil.copy2(test_state / name, journals / name)
            shutil.rmtree(test_state)
        verify()
        summary = {"schema_version": 1, "exit_code": 0, "seconds": round(time.monotonic() - started, 3), "tools": tools, "source_manifest_sha256": sha(proof / "source-manifest.json"), "commands": records, "sbf": sbf, "scope": ["Current compiled tests are fresh; committed SBF account corpus is historical unit input.", "Optional retained bank proves actual packet/SBF coupling with controlled local height/time, not real ledger finality or independent providers.", "No deployment, live provider call, live funds, native device, service registration or compiler rebuild."]}
        if args.hook_dir and (args.hook_dir / "manifest.json").exists():
            summary["external_sbf_manifest_sha256"] = sha(args.hook_dir / "manifest.json")
        write_json(proof / "result.json", summary)
        print(json.dumps({"exit_code": 0, "source_manifest_sha256": summary["source_manifest_sha256"], "sbf": sbf is not None, "seconds": summary["seconds"]}), flush=True)
        succeeded = True
    finally:
        shutil.rmtree(private)
        if not succeeded:
            write_json(proof / "failure.json", {"exit_code": 1, "completed_commands": records, "source_manifest_sha256": sha(proof / "source-manifest.json")})


if __name__ == "__main__":
    main()
