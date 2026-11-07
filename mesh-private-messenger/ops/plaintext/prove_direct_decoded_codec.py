#!/usr/bin/env python3
"""Run the existing direct codec contract with semantic body labels, offline.

Keep original baseline, labeled-before fixture, current fixture, and wrong-error
control separate. Copy application sources only; language dependencies stay in
place and are read-only. This is not full receive or native qualification.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

from prove_cli_decoded_display import BASELINE, TOOLCHAIN_ROOT, PINS, diagnostics


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    product = Path(__file__).resolve().parents[2]
    root = product.parent
    output = args.output.resolve()
    allowed = root / ".morse/decoded-body-labels/direct-codec"
    if not output.is_relative_to(allowed) or output == allowed:
        parser.error("output must be a new directory inside " + str(allowed))
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    language = (root / "mesh-lang").resolve(strict=True)
    protocol = product / "packages/messenger-protocol"
    source = product / "tests/direct-security/protocol_m5.mpl"
    expected_file = product / "tests/direct-security/expected.json"
    expected = json.loads(expected_file.read_text())["protocol_m5"]
    env = os.environ | {
        "TMPDIR": str(output / "tmp"),
        "MESH_RT_LIB_PATH": str(TOOLCHAIN_ROOT / "lib/libmesh_rt.a"),
        "MESH_TEST_RT_LIB_PATH": str(TOOLCHAIN_ROOT / "lib/libmesh_test_rt.a"),
    }
    record = {"status": "running", "baseline": BASELINE, "runs": [],
              "inputs": {}, "language_inputs": {}, "toolchain": PINS,
              "scope": "Existing protocol_m5 golden/hostile contract only; no full Main, receive, native or release claim.",
              "network": "Denied for compilation and execution by sandbox-exec."}
    record["runner_sha256"] = sha(Path(__file__))
    record["helper_sha256"] = sha(Path(__file__).with_name("prove_cli_decoded_display.py"))

    def save():
        (output / "evidence.json").write_text(json.dumps(record, indent=2) + "\n")

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments])

    def capture(path):
        data = path.read_bytes()
        record["inputs"][str(path)] = hashlib.sha256(data).hexdigest()
        return data

    def snapshot(version):
        target = output / version / "sources/mesh-private-messenger/packages/messenger-protocol"
        if version == "baseline":
            paths = git("ls-tree", "-r", "--name-only", BASELINE, "--", str(protocol.relative_to(root))).decode().splitlines()
            files = {Path(p).relative_to(protocol.relative_to(root)): git("show", BASELINE + ":" + p)
                     for p in paths if Path(p).suffix in (".mpl", ".toml", ".lock")}
        else:
            files = {p.relative_to(protocol): capture(p) for p in sorted(protocol.rglob("*"))
                     if p.is_file() and p.suffix in (".mpl", ".toml", ".lock")}
        for relative, data in files.items():
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        (output / version / "sources/mesh-lang").symlink_to(language, target_is_directory=True)
        for dependency in tomllib.loads((target / "mesh.toml").read_text())["dependencies"].values():
            path = (target / dependency["path"]).resolve(strict=True)
            if not path.is_relative_to(language):
                raise RuntimeError("unexpected nonlanguage protocol dependency: " + str(path))
            for item in path.rglob("*"):
                if item.is_file() and item.suffix in (".mpl", ".toml", ".lock"):
                    record["language_inputs"][str(item)] = sha(item)
        return target

    def instantiate(text):
        vectors = {"CREDENTIAL": "m1/device-credential-v1", "ACCOUNT": "m5/account-identity-v1",
                   "PREKEY": "m5/prekey-bundle-v1", "INNER": "m5/inner-envelope-v1",
                   "TRANSCRIPT": "m5/handshake-transcript-v1", "TRANSCRIPT_HASH": "m5/handshake-transcript-hash-v1"}
        result = re.sub(r"__(\w+)_HEX__", lambda m: capture(product / "tests/fixtures" / (vectors[m[1]] + ".hex")).decode().strip(), text)
        if re.search(r"__[A-Z_]+__", result):
            raise RuntimeError("unresolved fixture placeholder")
        return result

    profile = output / "offline.sb"
    profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath ' + json.dumps(str(language)) + '))\n')

    def run(name, package, text, stdout=None, red=False):
        directory = output / name
        project = directory / "probe"
        project.mkdir(parents=True)
        (project / "mesh.toml").write_text('[package]\nname="direct-decoded-codec-proof"\nversion="0.1.0"\n[dependencies]\nprotocol={path=' + json.dumps(str(package)) + '}\n')
        main_source = project / "main.mpl"
        main_source.write_text(instantiate(text))
        before = {str(p): sha(p) for p in package.rglob("*") if p.is_file()}
        before.update({str(p): sha(p) for p in project.iterdir() if p.is_file()})
        (directory / "sources.json").write_text(json.dumps(before, indent=2) + "\n")
        binary = directory / "proof"
        command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(TOOLCHAIN_ROOT / "bin/meshc"),
                   "build", "--json", str(project), "--plaintext-report", str(directory / "plaintext.json"), "-o", str(binary)]
        start = time.monotonic()
        compiled = subprocess.run(command, capture_output=True, text=True, env=env, timeout=180)
        log = compiled.stdout + compiled.stderr
        (directory / "build.log").write_text(log)
        item = {"name": name, "command": command, "build_exit": compiled.returncode,
                "source_sha256": sha(main_source), "seconds": round(time.monotonic() - start, 3)}
        record["runs"].append(item)
        save()
        if red:
            errors = diagnostics(log)
            if compiled.returncode == 0 or binary.exists() or len(errors) != 10:
                raise RuntimeError("expected ten original fixture println refusals")
            data = main_source.read_bytes()
            locations = []
            for error in errors:
                if error["code"] != "E0093" or "`println`" not in error["message"] or error["file"] != str(main_source):
                    raise RuntimeError("unexpected original fixture diagnostic")
                if len(error["spans"]) != 1:
                    raise RuntimeError("unexpected refusal spans")
                span = error["spans"][0]
                locations.append(data[span["start"]:span["end"]].decode())
            expected_locations = ['println("' + marker + '")' for marker in (
                "inner-properties", "inner-property-failed", "inner-golden", "inner-golden-mismatch",
                "inner-limit-setup-error", "inner-limit", "inner-limit-wrong-error", "inner-limit-accepted")]
            expected_locations += ["inner_proof()", "println(error)"]
            if sorted(locations) != sorted(expected_locations):
                raise RuntimeError("refusals did not locate the exact eight observations and two callers")
            item["exact_refusals"] = errors
        else:
            if compiled.returncode != 0 or diagnostics(log) or not binary.is_file():
                raise RuntimeError(name + " failed to compile")
            command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=20)
            (directory / "stdout").write_text(result.stdout)
            (directory / "stderr").write_text(result.stderr)
            item.update(run_command=command, run_exit=result.returncode, stdout_matches=result.stdout == stdout,
                        empty_stderr=not result.stderr, binary_sha256=sha(binary))
            if result.returncode != 0 or result.stdout != stdout or result.stderr:
                raise RuntimeError(name + " did not match exact stdout contract")
        if not all(sha(Path(p)) == value for p, value in before.items()):
            raise RuntimeError(name + " source changed")
        item["source_stable"] = True
        item["artifacts"] = {str(p.relative_to(output)): sha(p) for p in directory.rglob("*") if p.is_file()}
        save()
        print(name + ": passed", flush=True)

    try:
        if any(sha(TOOLCHAIN_ROOT / p) != value for p, value in PINS.items()):
            raise RuntimeError("toolchain pin mismatch")
        capture(expected_file)
        original = git("show", BASELINE + ":" + str(source.relative_to(root))).decode()
        current = capture(source).decode()
        baseline_protocol = snapshot("baseline")
        current_protocol = snapshot("current")
        run("original-baseline", baseline_protocol, original, expected)
        run("labeled-original-fixture", current_protocol, original, red=True)
        run("labeled-current-fixture", current_protocol, current, expected)
        if current.count("Err(OversizedInput) -> true") != 1 or expected.count("inner-limit\n") != 1:
            raise RuntimeError("ambiguous wrong-error control")
        run("wrong-error-control", current_protocol,
            current.replace("Err(OversizedInput) -> true", "Err(InvalidFieldLength) -> true"),
            expected.replace("inner-limit\n", "inner-limit-wrong-error\n"))
        record["inputs_stable"] = all(sha(Path(p)) == value for p, value in (record["inputs"] | record["language_inputs"]).items())
        record["toolchain_stable"] = all(sha(TOOLCHAIN_ROOT / p) == value for p, value in PINS.items())
        if not record["inputs_stable"] or not record["toolchain_stable"]:
            raise RuntimeError("inputs or tools changed")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
