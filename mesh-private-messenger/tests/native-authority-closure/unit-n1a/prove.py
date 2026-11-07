#!/usr/bin/env python3
"""Build only the small native driver; never rebuild/copy the retained Mesh family."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

BASE = "e036a6240be799e172dfea53faf80581c91ed996"
MESH = Path("/Users/andreyyurlov/Documents/dev/mesh-lang")
EVIDENCE = MESH / ".tmp/native-effect-authority/evidence"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
NATIVE = ROOT / "mesh-private-messenger/apps/desktop/src-tauri/src/desktop_lock/native"
CASES = ["control", "lock-current", "directory-current", "lock-duplicate",
         "directory-duplicate", "lock-restore", "directory-restore",
         "lock-send", "directory-send", "http-close", "accepted-commit"]
LIFECYCLE_CASES = ["stat-current", "stat-postdup", "accepted-store", "accepted-store-drop", "accepted-store-detached",
                   "close-before-store", "store-control", "zero-close-reuse", "rebind",
                   "failed-directory", "failed-lock", "successor"]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["baseline", "green"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    family = json.loads((EVIDENCE / "final-family.json").read_text())
    source_manifest = json.loads((EVIDENCE / "candidate-r5.json").read_text())
    live_source_drift = {}
    for filename, expected in source_manifest["files"].items():
        committed = subprocess.check_output(
            ["git", "show", f"9b844dbab34e61f6de575af2b25b0ed0f321059e:{filename}"], cwd=MESH)
        assert hashlib.sha256(committed).hexdigest() == expected, filename
        live = digest(MESH / filename)
        if live != expected:
            live_source_drift[filename] = live
    for filename, metadata in family["files"].items():
        assert digest(Path(filename)) == metadata["sha256"], filename
    generated = Path(family["generated_directory"])
    library = generated / "libauthority.dylib"
    assert digest(library) == "1d5af0920725bc0449977060a270393192193b09ce896f96049ce3226299bf5d"
    header = MESH / "compiler/meshc/src/library_authority.h"
    assert digest(header) == "5bbaf429dbd3749924b041847aba40ce40ee33c5a13a5c97f454601d79f87843"
    receipt = {"phase": args.phase, "baseline": BASE, "runs": [],
               "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
               "retained_family_sha256": digest(EVIDENCE / "final-family.json"),
               "retained_files_verified": len(family["files"]),
               "runtime_sources_verified": len(source_manifest["files"]),
               "runtime_source_pin": "9b844dbab34e61f6de575af2b25b0ed0f321059e",
               "live_runtime_source_drift_not_used": live_source_drift,
               "runtime_source_manifest_sha256": digest(EVIDENCE / "candidate-r5.json"),
               "library_sha256": digest(library), "authority_header_sha256": digest(header),
               "free_kib_before": shutil.disk_usage(out).free // 1024,
               "scope": "actual macOS ProcessOwner; synthetic in-memory anchor; bounded generated synchronous runtime; owned loopback only",
               "not_run": ["Keychain", "product UI/macOS integration", "iOS/Android/framework ownership", "native SDK", "scheduler/fresh-owner progress", "final publication", "protected app activation", "remaining closure units"]}

    def run(name, command, expected=0):
        result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=40)
        log = out / f"{name}.log"
        log.write_text(result.stdout)
        receipt["runs"].append({"name": name, "command": [str(x) for x in command],
                                "exit": result.returncode, "expected": expected,
                                "log_sha256": digest(log)})
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        assert result.returncode == expected, f"{name}: {result.stdout}"
        print(f"{name}: exit {result.returncode}", flush=True)

    source_dir = NATIVE
    if args.phase == "baseline":
        source_dir = out / "baseline-native"
        source_dir.mkdir()
        for name in ["ProcessOwner.m", "ProcessOwner.h", "Policy.h"]:
            relative = (NATIVE / name).relative_to(ROOT)
            (source_dir / name).write_bytes(subprocess.check_output(
                ["git", "show", f"{BASE}:{relative}"], cwd=ROOT))
    sources = [source_dir / "ProcessOwner.m", HERE / "native_owner_barrier.m"]
    extra_sources = ([NATIVE / "ProcessOwnerRetirementLink.h", NATIVE / "ProcessOwnerRetirementLink.inc",
                      HERE / "native_interpose.c", HERE / "native_interpose.h", HERE / "lifecycle.py"] if args.phase == "green" else [])
    receipt["sources"] = {str(p): digest(p) for p in
                          [*sources, *extra_sources, source_dir / "ProcessOwner.h", source_dir / "Policy.h",
                           HERE / "check.py", Path(__file__), generated / "libauthority.h"]}
    driver = out / "native-owner.dylib"
    compile_args = ["xcrun", "clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-dynamiclib", "-framework", "Foundation",
                    "-I", source_dir, "-I", generated, *sources,
                    "-L", generated, "-lauthority", f"-Wl,-rpath,{generated}", "-o", driver]
    if args.phase == "baseline":
        compile_args.insert(2, "-DN1A_BASELINE")
    run("driver-compile", compile_args)
    receipt["driver_sha256"] = digest(driver)
    run("clang-version", ["xcrun", "clang", "--version"])
    clang = Path(subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip())
    receipt["clang_sha256"] = digest(clang)
    run("os-version", ["sw_vers"])
    for case in CASES:
        expected = 1 if args.phase == "baseline" and case != "control" else 0
        run(case, ["python3", HERE / "check.py", library, driver, case,
                   *(["--baseline"] if args.phase == "baseline" else [])], expected)
        if expected:
            message = ("close released OS exclusion before admitted commit settled" if case == "accepted-commit"
                       else "observed ProcessOwner loss did not retire")
            assert message in (out / f"{case}.log").read_text()
    if args.phase == "green":
        def instrumented(name, owner_source):
            obj = out / f"{name}.o"
            binary = out / f"{name}.dylib"
            run(name + "-owner-compile", ["xcrun", "clang", "-fobjc-arc", "-fblocks",
                "-Wall", "-Wextra", "-Werror", "-I", NATIVE,
                "-include", HERE / "native_interpose.h",
                "-c", owner_source, "-o", obj])
            run(name + "-link", ["xcrun", "clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
                "-Werror", "-Wno-unused-parameter", "-dynamiclib", "-framework", "Foundation",
                "-I", NATIVE, "-I", generated, obj, HERE / "native_owner_barrier.m",
                HERE / "native_interpose.c", "-L", generated, "-lauthority",
                f"-Wl,-rpath,{generated}", "-o", binary])
            receipt[name + "_sha256"] = digest(binary)
            return binary

        observed = instrumented("instrumented-owner", NATIVE / "ProcessOwner.m")
        for case in ["accepted-commit", "http-close"]:
            run("fd-" + case, ["python3", HERE / "check.py", library, observed, case, "--observe-disposal"])
        for case in LIFECYCLE_CASES:
            run(case, ["python3", HERE / "lifecycle.py", library, observed, case])
        # The sequential checks cannot prove the final latch placement. Remove
        # only that conjunct in an owned scratch copy and require both barriers
        # to expose true after concurrent close; production source is untouched.
        source = (NATIVE / "ProcessOwner.m").read_text()
        latch = " &&\n        (!_state->link || (!atomic_load(&_state->lost) && !atomic_load(&_state->closed)))"
        assert source.count(latch) == 1
        mutant = out / "ProcessOwner-no-final-latch.m"
        mutant.write_text(source.replace(latch, ""))
        bad = instrumented("no-final-latch", mutant)
        receipt["no_final_latch_source_sha256"] = digest(mutant)
        for case in ["stat-current", "stat-postdup"]:
            run("red-" + case, ["python3", HERE / "lifecycle.py", library, bad, case], 1)
            assert "in-flight stat returned current after close" in (out / f"red-{case}.log").read_text()
    closure = out / "process-owner-closure"
    run("existing-controls-compile", ["xcrun", "clang", "-fobjc-arc", "-fblocks",
        "-framework", "Foundation", source_dir / "ProcessOwner.m",
        NATIVE.parent / "tests/process_owner_closure.m", "-o", closure])
    run("existing-controls", [closure])
    receipt["existing_control_sha256"] = digest(closure)
    receipt["free_kib_after"] = shutil.disk_usage(out).free // 1024
    receipt["result"] = "EXPECTED_RED" if args.phase == "baseline" else "PASS"
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"result": receipt["result"], "receipt": str(out / "receipt.json")}))


if __name__ == "__main__":
    main()
