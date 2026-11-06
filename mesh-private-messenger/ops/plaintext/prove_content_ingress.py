#!/usr/bin/env python3
"""Compile actual direct, group-send and self-sync body ingress against HTTP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import tomllib


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_parser_refusal(diagnostics, code, module, parser_name, source):
    action = {"E0034": "not exported by", "E0035": "private in"}[code]
    subject = f"`{parser_name}` is {action} module `{module}`;"
    return any(item.get("code") == code and item.get("file") == str(source)
               and item.get("message", "").startswith(subject) for item in diagnostics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--compiler", type=Path, default=os.environ.get("MESH_COMPILER_BIN"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.compiler is None:
        parser.error("--compiler or MESH_COMPILER_BIN is required")
    compiler = args.compiler.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    raw_parsers = ("parse_store_request", "parse_fanout_targets_request", "parse_triple_payload_request")
    parser_fixtures = {name: sha(Path(__file__).parent / "fixtures" / name)
                      for name in ("raw-request-parsers.mpl", "private-raw-request-parsers.mpl")}
    record = {"status": "running", "compiler_sha256": sha(compiler), "runner_sha256": sha(Path(__file__)), "fixture_sha256": sha(Path(__file__).parent / "fixtures/content-ingress.mpl"), "control_escape_sha256": sha(Path(__file__).parent / "fixtures/control-parser-escape.mpl"), "private_control_sha256": sha(Path(__file__).parent / "fixtures/control-parser-private.mpl"), "raw_parser_fixtures": parser_fixtures, "inputs": {}, "results": [],
              "scope": "Actual parsed direct, fanout, group-send and self-sync bodies, native fanout action, direct/self-sync encoding, and named control/raw-parser import restrictions; general byte decoding and decoded decrypted projections remain outside this proof."}
    runtime = os.environ.get("MESH_RT_LIB_PATH")
    if runtime:
        record["runtime_sha256"] = sha(Path(runtime))
    test_runtime = os.environ.get("MESH_TEST_RT_LIB_PATH")
    if test_runtime:
        record["test_runtime_sha256"] = sha(Path(test_runtime))
    evidence = output / "evidence.json"
    copies = {}

    def snapshot(package):
        package = package.resolve()
        if package in copies:
            return copies[package]
        destination = output / "sources" / (package.name + "-" + hashlib.sha256(str(package).encode()).hexdigest()[:12])
        copies[package] = destination
        for source in sorted(package.rglob("*")):
            if source.is_file() and source.suffix in (".mpl", ".toml", ".lock"):
                target = destination / source.relative_to(package)
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = sha(source)
                shutil.copyfile(source, target)
                if sha(target) != digest:
                    raise RuntimeError("source changed during capture: " + str(source))
                record["inputs"][str(source)] = digest
        manifest = destination / "mesh.toml"
        text = manifest.read_text()
        for dep in tomllib.loads(text).get("dependencies", {}).values():
            if isinstance(dep, dict) and "path" in dep:
                target = snapshot(package / dep["path"])
                pattern = r'(\bpath\s*=\s*)' + re.escape(json.dumps(dep["path"]))
                text, count = re.subn(pattern, lambda match: match[1] + json.dumps(str(target)), text)
                if count == 0:
                    raise RuntimeError("unsupported dependency path quoting: " + str(manifest))
        manifest.write_text(text)
        return destination

    def build(name, package, success):
        directory = output / name
        directory.mkdir()
        artifact = directory / "libproof.a"
        command = [str(compiler), "build", "--json", str(package), "--artifact", "staticlib", "--output", str(artifact)]
        start = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True)
        log = process.stdout + process.stderr
        (directory / "build.log").write_text(log)
        diagnostics = []
        for line in log.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if value.get("code"):
                diagnostics.append(value)
        item = {"name": name, "exit_code": process.returncode, "artifact": artifact.exists(),
                "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
                "seconds": round(time.monotonic() - start, 3), "command": command}
        record["results"].append(item)
        evidence.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(item), flush=True)
        if (process.returncode == 0) != success or artifact.exists() != success:
            raise RuntimeError(name + " did not meet its compile/artifact expectation")
        return diagnostics

    try:
        mobile = snapshot(args.product / "packages/mobile-core")
        for path, digest in record["inputs"].items():
            if sha(Path(path)) != digest:
                raise RuntimeError("input changed during dependency capture: " + path)
        probe = output / "probe"
        probe.mkdir()
        (probe / "mesh.toml").write_text('[package]\nname="content-ingress-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        fixture = Path(__file__).parent / "fixtures/content-ingress.mpl"
        source = fixture.read_text()
        (probe / "main.mpl").write_text(source)
        diagnostics = build("protected-negative", probe, False)
        errors = [value for value in diagnostics if value["code"] != "C0001"]
        if not errors or any(value["code"] != "E0093" for value in errors):
            raise RuntimeError("negative must fail only plaintext policy")
        data = source.encode()
        functions = list(re.finditer(rb"fn (refuse_[a-z_]+)\(", data))
        if len(functions) != 7:
            raise RuntimeError("unexpected probe count")
        for index, function in enumerate(functions):
            stop = functions[index + 1].start() if index + 1 < len(functions) else data.index(b"fn main()")
            if not any(value.get("file") == str(probe / "main.mpl")
                       and "`Http.body_bytes`" in value["message"]
                       and any(function.start() <= span["start"] < stop for span in value["spans"])
                       for value in errors):
                raise RuntimeError("missing exact HTTP refusal for " + function[1].decode())
        record["refused_probes"] = [function[1].decode() for function in functions]
        # The same former public-parser escape compiled before this change.
        # It must now be absent from Requests and private in GroupInvites.
        for name, fixture_name, code in (
                ("control-parser-not-exported", "control-parser-escape.mpl", "E0034"),
                ("control-parser-private", "control-parser-private.mpl", "E0035")):
            (probe / "main.mpl").write_text((fixture.parent / fixture_name).read_text())
            diagnostics = build(name, probe, False)
            module = "Mobile.Requests" if code == "E0034" else "Mobile.GroupInvites"
            if not has_parser_refusal(diagnostics, code, module, "parse_fanout_control_request", probe / "main.mpl"):
                raise RuntimeError(name + " did not reject the exact control parser")
        for name, fixture_name, code in (
                ("raw-parsers-not-exported", "raw-request-parsers.mpl", "E0034"),
                ("raw-parsers-private", "private-raw-request-parsers.mpl", "E0035")):
            (probe / "main.mpl").write_text((fixture.parent / fixture_name).read_text())
            diagnostics = build(name, probe, False)
            for parser_name in raw_parsers:
                module = "Mobile.Requests" if code == "E0034" else "MobileCore"
                if not has_parser_refusal(diagnostics, code, module, parser_name, probe / "main.mpl"):
                    raise RuntimeError(name + " did not reject " + parser_name)
        (probe / "main.mpl").write_text(source)
        path = mobile / "mobile/types.mpl"
        original = path.read_text()
        try:
            mutant = original
            for name in ("MobileStartRequest", "MobileGroupSendRequest", "MobileSyncPayload", "MobileFanoutRequest"):
                start = mutant.index("pub struct " + name + " do")
                end = mutant.index("\nend", start)
                part = mutant[start:end]
                if part.count("  body :: Plaintext<Bytes>") != 1:
                    raise RuntimeError("missing body label in " + name)
                mutant = mutant[:start] + part.replace("  body :: Plaintext<Bytes>", "  body :: Bytes") + mutant[end:]
            path.write_text(mutant)
            action_path = mobile / "mobile/fanout_network.mpl"
            action_original = action_path.read_text()
            if action_original.count("  body :: Plaintext<Bytes>") != 1:
                raise RuntimeError("missing fanout action body label")
            try:
                action_path.write_text(action_original.replace("  body :: Plaintext<Bytes>", "  body :: Bytes"))
                build("removed-labels-positive", probe, True)
            finally:
                action_path.write_text(action_original)
        finally:
            path.write_text(original)
        build("production-green", mobile, True)
        for path, digest in record["inputs"].items():
            if sha(Path(path)) != digest:
                raise RuntimeError("live input changed during proof: " + path)
        if (sha(compiler) != record["compiler_sha256"] or sha(fixture) != record["fixture_sha256"]
                or sha(fixture.parent / "control-parser-escape.mpl") != record["control_escape_sha256"]
                or sha(fixture.parent / "control-parser-private.mpl") != record["private_control_sha256"]
                or any(sha(fixture.parent / name) != digest for name, digest in parser_fixtures.items())
                or (runtime and sha(Path(runtime)) != record["runtime_sha256"])
                or (test_runtime and sha(Path(test_runtime)) != record["test_runtime_sha256"])):
            raise RuntimeError("toolchain or fixture changed during proof")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        evidence.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
