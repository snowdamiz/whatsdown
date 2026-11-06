#!/usr/bin/env python3
"""Exercise the production history reader through a compiled native export."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--opt-level", choices=("0", "2"), default="2")
    args = parser.parse_args()
    compiler = args.compiler.resolve(strict=True)
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    product = here.parent.parent
    public = product.parent.parent / "mesh-lang"
    runtime = compiler.parent / "libmesh_rt.a"
    if not runtime.is_file():
        raise RuntimeError("compiler-adjacent production runtime archive is required")
    work = Path(tempfile.mkdtemp(prefix="history-native-boundary-", dir=evidence))
    toolchain = work / "toolchain"
    toolchain.mkdir()
    source_compiler, source_runtime = compiler, runtime
    compiler, runtime = toolchain / "meshc", toolchain / "libmesh_rt.a"
    # Shared build folders may be refreshed by another task. Compile and link
    # only immutable copies, including an explicit runtime archive override.
    for source, target in ((source_compiler, compiler), (source_runtime, runtime)):
        before = digest(source)
        shutil.copy2(source, target)
        if digest(target) != before or digest(source) != before:
            raise RuntimeError("toolchain changed during snapshot: " + str(source))
    record = {
        "schema_version": 1,
        "scope": "production history reader through generated C ABI; bounded in-memory host secure-store callbacks",
        "limits": {"default_export": 1048576, "declared_export_output": 16794632,
                   "actual_response": 8404488, "rows": 256, "body_bytes": 32768,
                   "host_callback": 1048576},
        "work_dir": str(work),
        "compiler": {"path": str(compiler), "source_path": str(source_compiler), "sha256": digest(compiler)},
        "runtime": {"path": str(runtime), "source_path": str(source_runtime), "sha256": digest(runtime)},
        "production_sources": {},
        "commands": [],
        "result": "pending",
    }
    log_path = work / "proof.log"
    start = time.monotonic()
    try:
        # Copy a coherent production snapshot. The fixture adds exports only in
        # its own driver; no live application source or generated binding changes.
        for name in ("mobile-core", "messenger-protocol"):
            for source in sorted((product / "packages" / name).rglob("*")):
                if not source.is_file() or source.suffix not in (".mpl", ".toml"):
                    continue
                relative = source.relative_to(product / "packages")
                payload = source.read_bytes()
                record["production_sources"][str(relative)] = hashlib.sha256(payload).hexdigest()
                target = work / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
        for relative, value in record["production_sources"].items():
            if digest(product / "packages" / relative) != value:
                raise RuntimeError("production source changed during snapshot: " + relative)
        for name in ("mobile-core", "messenger-protocol"):
            manifest = work / name / "mesh.toml"
            manifest.write_text(manifest.read_text().replace(
                "../../../mesh-lang/packages/", str(public / "packages") + "/"))
        shutil.copytree(here / "fixture", work / "driver")
        (work / "driver/mesh.toml").write_text(
            '[package]\nname="history-native-boundary"\nversion="0.1.0"\n'
            '[dependencies]\nmessenger-mobile-core={path="../mobile-core"}\n')
        shutil.copyfile(here / "host.c", work / "host.c")
        record["fixture_sources"] = {
            str(p.relative_to(here)): digest(p)
            for p in sorted(here.rglob("*"))
            if p.is_file() and p.suffix in (".mpl", ".toml", ".c", ".py")
        }
        library = work / ("libhistory_native.dylib" if sys.platform == "darwin" else "libhistory_native.so")
        host = work / "history-native-host"

        def run(command, output):
            record["commands"].append([str(x) for x in command])
            environment = dict(os.environ, MESH_RT_LIB_PATH=str(runtime))
            subprocess.run(command, cwd=work, env=environment, stdout=output,
                           stderr=subprocess.STDOUT, check=True)

        with log_path.open("w") as output:
            run([compiler, "build", work / "driver", "--artifact", "cdylib",
                 "--opt-level", args.opt_level, "-o", library], output)
            abi = json.loads(library.with_suffix(".abi.json").read_text())
            exports = {item["symbol"]: item for item in abi["exports"]}
            assert exports["mesh_history_fixture_load"]["maxOutputBytes"] == 16794632
            assert exports["mesh_history_fixture_default_load"]["maxOutputBytes"] == 1048576
            assert exports["mesh_history_fixture_load"]["maxInputBytes"] == 1048576
            link = [os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-Werror", work / "host.c", "-I", work,
                    "-L", work, "-lhistory_native", "-Wl,-rpath," + str(work), "-o", host]
            if sys.platform == "darwin":
                link += ["-framework", "Security", "-framework", "CoreFoundation"]
            run(link, output)
            run([host, work / "history.db"], output)
        log = log_path.read_text()
        for marker in ("default1MiB response correctly refused",
                       "production256-row history verified bytes=8404488",
                       "repeat native production read exact"):
            if marker not in log:
                raise RuntimeError("native proof marker missing: " + marker)
        if digest(compiler) != record["compiler"]["sha256"] or digest(runtime) != record["runtime"]["sha256"]:
            raise RuntimeError("compiler or runtime archive changed during proof")
        record["artifacts"] = {
            p.name: digest(p) for p in (library, library.with_suffix(".abi.json"),
                                       library.with_suffix(".h"), host, log_path)
        }
        record["result"] = "passed"
    except Exception as error:
        record["result"] = "failed"
        record["error"] = str(error)
        raise
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - start, 3)
        (work / "evidence.json").write_text(json.dumps(record, indent=2) + "\n")
        print(str(work / "evidence.json"), flush=True)


if __name__ == "__main__":
    main()
