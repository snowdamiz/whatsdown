#!/usr/bin/env python3
"""Observe actual pinned invitation sealing and synthetic file-key counters.

Only app sources from BASELINE are frozen; the held policy is applied solely to
the second snapshot. No native build, language copy, platform key or account is
used. Key material is never read by Python: only offset 36, length 8 is read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import time
import tomllib


BASELINE = "a48963b4918f5fc39981176d4e46069b78dfeebb"
TOOLCHAIN = Path("/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts")
PINS = {
    "bin/meshc": "19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85",
    "lib/libmesh_rt.a": "d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8",
    "lib/libmesh_test_rt.a": "9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33",
}
PACKAGES = ("packages/mobile-core", "packages/messenger-protocol")
SUFFIXES = {".mpl", ".toml", ".lock"}
CASES = {
    "empty-list": {"observation": "ciphertext length 75; opens to encode_output_list([])", "original": 1, "held": 1},
    "over-limit": {"observation": "exact Err(group_invitation_limit); 129 encodable records", "original": 0, "held": 1},
    "malformed-record": {"observation": "exact Err(integer_encoding_failed); one record with state=256", "original": 0, "held": 1},
    "invalid-context": {"observation": "direct seal_local exact Err(local_state_seal_failed); empty context", "original": 0, "held": 0},
    "empty-fallback": {"observation": "direct seal_local ciphertext length 67; opens to empty plaintext; valid local context", "original": 1, "held": 1},
}


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def source_hashes(root):
    return {str(p): sha(p) for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in SUFFIXES}


def stable(hashes):
    return all(Path(p).is_file() and sha(Path(p)) == digest for p, digest in hashes.items())


def counter(directory):
    descriptor = os.open(directory / "key", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != 44 or info.st_nlink != 1:
            raise RuntimeError("unexpected synthetic key record metadata")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("synthetic key record is not private")
        trailing = os.pread(descriptor, 8, 36)
        if len(trailing) != 8:
            raise RuntimeError("incomplete synthetic counter")
        return int.from_bytes(trailing, "big")
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    product = Path(__file__).resolve().parents[2]
    repo = product.parent
    owned = repo / ".morse/decoded-body-labels/invitation-seal-effects"
    output = args.output.resolve()
    if not output.is_relative_to(owned.resolve()):
        parser.error("output must be under " + str(owned))
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        parser.error("this bounded proof requires macOS sandbox-exec")
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    (output / "tmp").mkdir(mode=0o700)
    language = (repo / "mesh-lang").resolve(strict=True)
    fixture = Path(__file__).parent / "fixtures/invitation-seal-effects/main.mpl"
    patch = Path(__file__).parent / "fixtures/decoded-body/held-invitation-policy.patch"
    record = {
        "status": "running", "baseline": BASELINE,
        "runner": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__))},
        "fixture": {"path": str(fixture), "sha256": sha(fixture)},
        "held_patch": {"path": str(patch), "sha256": sha(patch)},
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "output": str(output), "commands": [], "snapshots": {}, "cases": [],
        "key_inspection": "os.pread(fd, 8, 36) only, after stat verifies a private 44-byte regular single-link synthetic key file; no material read, hash or copy",
        "scope": "Actual pinned native runtime via app-only executables and StorageKey.file; not held-policy approval, Host platform callback dynamic qualification, or full receive adoption",
        "error_order": {
            "original_source": "list limit -> record encoding -> output list encoding -> local context -> seal_local; each prior error returns immediately",
            "held_source": "encoded result -> context result -> eager seal_local(encoded-or-empty, context-or-empty) -> encoded? -> context? -> sealed",
            "exercised": "Encoding errors retain their exact returned string while held fallback sealing succeeds and consumes one counter; invalid context is tested only as an independent direct seal control",
            "not_exercised": ["encoding failure plus context-construction failure", "encoding failure plus seal/key/counter reservation failure", "context-construction failure plus seal failure", "list-limit plus malformed-record competing failures", "Host callback failure, counter exhaustion, crash durability or concurrent reservations"],
        },
    }
    evidence = output / "evidence.json"

    def save():
        evidence.write_text(json.dumps(record, indent=2) + "\n")

    def command(argv, *, log=None, env=None, timeout=300):
        start = time.monotonic()
        result = subprocess.run(argv, cwd=repo, env=env, capture_output=True, timeout=timeout)
        record["commands"].append({"argv": [str(a) for a in argv], "cwd": str(repo),
                                   "exit_code": result.returncode,
                                   "seconds": round(time.monotonic() - start, 3),
                                   "log": str(log) if log else None})
        if log:
            log.write_bytes(result.stdout + result.stderr)
        save()
        if result.returncode:
            raise RuntimeError("command failed; inspect recorded command/log: " + str(log or argv[0]))
        return result

    def git(*args):
        return command(["git", *args]).stdout

    try:
        record["toolchain"] = {name: {"path": str(TOOLCHAIN / name), "sha256": sha(TOOLCHAIN / name)} for name in PINS}
        if {name: item["sha256"] for name, item in record["toolchain"].items()} != PINS:
            raise RuntimeError("pinned toolchain mismatch")
        record["app_head_at_start"] = git("rev-parse", "HEAD").decode().strip()
        record["baseline_tree"] = git("rev-parse", BASELINE + "^{tree}").decode().strip()
        record["language_head_at_start"] = command(["git", "-C", str(language), "rev-parse", "HEAD"]).stdout.decode().strip()
        record["runtime_source_read_only"] = {
            str(language / name): sha(language / name) for name in (
                "compiler/mesh-rt/src/storage_wrapping.rs",
                "compiler/mesh-rt/src/storage_wrapping/file.rs",
                "compiler/mesh-rt/src/secret.rs",
                "compiler/meshc/src/main.rs")}
        record["runtime_source_limit"] = "Read-only source hashes characterize inspected source; pinned binaries are executed as provided, without rebuilding or claiming source-to-binary reproducibility"
        record["language_dependencies"] = {}
        rules = ['(version 1)', '(allow default)', '(deny network*)',
                 '(deny file-write* (subpath ' + json.dumps(str(language)) + '))']
        build_sandbox = output / "build.sb"
        build_sandbox.write_text("\n".join(rules) + "\n")
        runtime_sandbox = output / "runtime.sb"
        runtime_sandbox.write_text("\n".join(rules + [
            '(deny file-write*)',
            '(allow file-write* (subpath ' + json.dumps(str(output)) + ') (literal "/dev/null"))'
        ]) + "\n")
        record["sandbox"] = {str(p): sha(p) for p in (build_sandbox, runtime_sandbox)}
        env = os.environ | {"TMPDIR": str(output / "tmp"),
                            "MESH_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_rt.a"),
                            "MESH_TEST_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_test_rt.a")}
        record["build_env_overrides"] = {k: env[k] for k in ("TMPDIR", "MESH_RT_LIB_PATH", "MESH_TEST_RT_LIB_PATH")}
        paths = git("ls-tree", "-r", "--name-only", BASELINE, "--", *[str((product / p).relative_to(repo)) for p in PACKAGES]).decode().splitlines()
        baseline_sources = {name: git("show", BASELINE + ":" + name) for name in paths if Path(name).suffix in SUFFIXES}
        record["baseline_source_hashes"] = {name: hashlib.sha256(data).hexdigest() for name, data in baseline_sources.items()}

        for family in ("original", "held"):
            directory = output / family
            sources = directory / "sources"
            sources.mkdir(parents=True)
            (sources / "mesh-lang").symlink_to(language, target_is_directory=True)
            for name, data in baseline_sources.items():
                target = sources / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            if family == "held":
                command(["git", "apply", "--unsafe-paths", "--directory=" + str(sources), str(patch)], log=directory / "patch.log")
            probe = directory / "probe"
            probe.mkdir()
            shutil.copyfile(fixture, probe / "main.mpl")
            mobile = sources / product.name / "packages/mobile-core"
            (probe / "mesh.toml").write_text('[package]\nname="invitation-seal-effects"\nversion="0.1.0"\n[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
            hashes = source_hashes(sources / product.name) | source_hashes(probe)
            record["snapshots"][family] = hashes
            visited = set()

            def dependencies(package):
                package = package.resolve()
                if package in visited:
                    return
                visited.add(package)
                if not package.is_relative_to(output):
                    if not package.is_relative_to(language / "packages"):
                        raise RuntimeError("unexpected non-app dependency")
                    for path, digest in source_hashes(package).items():
                        previous = record["language_dependencies"].setdefault(path, digest)
                        if previous != digest:
                            raise RuntimeError("language dependency drift")
                manifest = tomllib.loads((package / "mesh.toml").read_text())
                for dep in manifest.get("dependencies", {}).values():
                    if not isinstance(dep, dict) or "path" not in dep:
                        raise RuntimeError("only preexisting local dependencies allowed")
                    dependencies(package / dep["path"])

            dependencies(probe)
            artifact = directory / "proof"
            command(["/usr/bin/sandbox-exec", "-f", str(build_sandbox), str(TOOLCHAIN / "bin/meshc"),
                     "build", "--json", str(probe), "--artifact", "executable",
                     "--plaintext-report", str(directory / "plaintext.json"), "-o", str(artifact)],
                    log=directory / "build.log", env=env)
            if not artifact.is_file() or not stable(hashes):
                raise RuntimeError("missing executable or changed frozen source")
            record.setdefault("artifacts", {})[family] = {
                str(p): sha(p) for p in (artifact, directory / "plaintext.json", directory / "build.log")}
            for name, expected in CASES.items():
                key_directory = directory / "keys" / name
                key_directory.parent.mkdir(mode=0o700, exist_ok=True)
                key_directory.mkdir(mode=0o700)
                runtime = ["/usr/bin/sandbox-exec", "-f", str(runtime_sandbox), str(artifact)]
                for operation in ("init", name):
                    if operation != "init":
                        before = counter(key_directory)
                    result = command([*runtime, operation, str(key_directory)],
                                     log=directory / (name + "." + operation + ".log"), env=env, timeout=30)
                    if result.stdout != b"invitation-seal-fixture:pass\n" or result.stderr:
                        raise RuntimeError("unexpected fixed fixture marker or stderr")
                after = counter(key_directory)
                item = {"family": family, "case": name, "observation": expected["observation"],
                        "counter_before": before, "counter_after": after, "delta": after - before,
                        "expected_delta": expected[family], "fixed_marker_passed": True,
                        "key_directory": str(key_directory)}
                record["cases"].append(item)
                save()
                print(f"{family} {name}: expected observation matched; counter {before}->{after}", flush=True)
                if before != 0 or after - before != expected[family]:
                    raise RuntimeError("persisted counter did not match expected seal effect")

        record["integrity"] = {
            "toolchain_stable": all(sha(TOOLCHAIN / name) == digest for name, digest in PINS.items()),
            "language_dependencies_stable": stable(record["language_dependencies"]),
            "inspected_runtime_sources_stable": stable(record["runtime_source_read_only"]),
            "snapshots_stable": all(stable(hashes) for hashes in record["snapshots"].values()),
            "fixture_stable": sha(fixture) == record["fixture"]["sha256"],
            "held_patch_stable": sha(patch) == record["held_patch"]["sha256"],
        }
        if not all(record["integrity"].values()):
            raise RuntimeError("source or toolchain drift during proof")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
