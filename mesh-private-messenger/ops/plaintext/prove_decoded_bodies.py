#!/usr/bin/env python3
"""Compile real semantic decoded-body exits; never execute network probes.

Application packages are frozen for the label-removal control. Language package
dependencies remain read-only in place. Full Main and CLI builds are required.
"""
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


PINS = {
    "compiler": "19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85",
    "MESH_RT_LIB_PATH": "d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8",
    "MESH_TEST_RT_LIB_PATH": "9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33",
}


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def diagnostics(log):
    values = []
    for line in log.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("code") and item["code"] != "C0001":
            values.append(item)
    return values


def require_refusals(items, source, names):
    data = source.read_bytes()
    locations = []
    for name in names:
        start = data.index(("fn " + name + "(").encode())
        stop = data.find(b"\nfn ", start + 1)
        stop = len(data) if stop < 0 else stop
        sink = data.index(b"Http.body_bytes", start, stop)
        locations.append((name, sink, sink + len(b"Http.body_bytes")))
    if len(items) != len(names) or any(item["code"] != "E0093" for item in items):
        raise RuntimeError("expected exactly the named E0093 refusals")
    for name, start, end in locations:
        if not any(item.get("file") == str(source)
                   and "`Http.body_bytes`" in item.get("message", "")
                   and any(span["start"] <= start < span["end"]
                           or start <= span["start"] < end for span in item.get("spans", []))
                   for item in items):
            raise RuntimeError("missing exact HTTP subject/location: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    product, compiler, output = args.product.resolve(), args.compiler.resolve(), args.output.resolve()
    owned = product.parent / ".morse/decoded-body-labels"
    if not output.is_relative_to(owned) or output == owned:
        parser.error("--output must be a new child of .morse/decoded-body-labels")
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    tool_paths = {"compiler": compiler}
    for name in ("MESH_RT_LIB_PATH", "MESH_TEST_RT_LIB_PATH"):
        if not os.environ.get(name):
            parser.error(name + " must name the explicit prebuilt runtime")
        tool_paths[name] = Path(os.environ[name]).resolve()
    if {name: sha(path) for name, path in tool_paths.items()} != PINS:
        parser.error("compiler/runtime pin mismatch")
    env = os.environ | {"TMPDIR": str(output / "tmp"), "PYTHONDONTWRITEBYTECODE": "1"}
    record = {"status": "running", "runner_sha256": sha(Path(__file__)),
              "toolchain": {name: {"path": str(path), "sha256": sha(path)}
                            for name, path in tool_paths.items()},
              "inputs": {}, "results": [], "probe_execution": "none",
              "scope": "Semantic decoded direct/group/timed bodies and nested direct history; raw decryption/unseal and native/release qualification remain separate."}
    evidence = output / "evidence.json"
    copies = {}

    def save():
        evidence.write_text(json.dumps(record, indent=2) + "\n")

    def snapshot(package):
        package = package.resolve()
        if package in copies:
            return copies[package]
        external = not package.is_relative_to(product)
        destination = package if external else output / "sources" / package.relative_to(product)
        copies[package] = destination
        for source in sorted(package.rglob("*")):
            if not source.is_file() or source.suffix not in (".mpl", ".toml", ".lock"):
                continue
            digest = sha(source)
            record["inputs"][str(source)] = digest
            if not external:
                target = destination / source.relative_to(package)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                if sha(target) != digest:
                    raise RuntimeError("source changed during capture: " + str(source))
        manifest = destination / "mesh.toml"
        text = manifest.read_text()
        for dep in tomllib.loads(text).get("dependencies", {}).values():
            if isinstance(dep, dict) and "path" in dep:
                target = snapshot(package / dep["path"])
                if not external:
                    text, count = re.subn(r'(\bpath\s*=\s*)' + re.escape(json.dumps(dep["path"])),
                                         lambda match: match[1] + json.dumps(str(target)), text)
                    if count != 1:
                        raise RuntimeError("ambiguous dependency path: " + str(manifest))
        if not external:
            manifest.write_text(text)
        return destination

    def build(name, package, success, artifact_kind="executable"):
        directory = output / name
        directory.mkdir()
        roots = {package, *copies.values()}
        before = {str(path): sha(path) for root in roots for path in sorted(root.rglob("*"))
                  if path.is_file() and path.suffix in (".mpl", ".toml", ".lock")}
        (directory / "sources.json").write_text(json.dumps(before, indent=2) + "\n")
        if (package / "main.mpl").is_file():
            shutil.copyfile(package / "main.mpl", directory / "main.mpl.source")
        artifact = directory / ("libproof.a" if artifact_kind == "staticlib" else "proof")
        command = [str(compiler), "build", "--json", str(package)]
        if artifact_kind == "staticlib":
            command += ["--artifact", "staticlib"]
        command += ["--plaintext-report", str(directory / "plaintext.json"), "-o", str(artifact)]
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=300)
        log = result.stdout + result.stderr
        (directory / "build.log").write_text(log)
        stable = all(sha(Path(path)) == digest for path, digest in before.items())
        record["results"].append({"name": name, "command": command, "exit_code": result.returncode,
                                  "seconds": round(time.monotonic() - start, 3),
                                  "sources_stable": stable,
                                  "artifacts": {str(path.relative_to(output)): sha(path)
                                                for path in sorted(directory.rglob("*")) if path.is_file()}})
        save()
        print(name, result.returncode, flush=True)
        if not stable:
            raise RuntimeError(name + " sources changed during compilation")
        if (result.returncode == 0) != success or artifact.exists() != success:
            raise RuntimeError(name + " failed its compile/artifact expectation")
        items = diagnostics(log)
        if success and items:
            raise RuntimeError(name + " successful build emitted unexpected diagnostics")
        return items

    try:
        mobile = snapshot(product / "packages/mobile-core")
        cli = snapshot(product / "clients/mesh-cli")
        protocol = copies[(product / "packages/messenger-protocol").resolve()]
        probe = output / "probe"
        probe.mkdir()
        (probe / "mesh.toml").write_text('[package]\nname="decoded-body-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        fixtures = Path(__file__).parent / "fixtures/decoded-body"
        fixture = fixtures / "ingress.mpl"
        source = probe / "main.mpl"
        source.write_bytes(fixture.read_bytes())
        record["fixtures"] = {path.name: sha(path) for path in sorted(fixtures.glob("*.mpl"))}
        names = ["inner_body_http", "group_body_http", "timed_group_body_http", "expiring_group_body_http",
                 "history_body_http", "restored_history_body_http"]
        require_refusals(build("protected-negative", probe, False), source, names)
        record["refused_probes"] = names
        source.write_bytes((fixtures / "caller-control.mpl").read_bytes())
        require_refusals(build("caller-control-negative", probe, False), source,
                         ["body_selected_effect", "unrelated_private_caller", "native_display_called_from_mesh"])
        source.write_bytes((fixtures / "allowed.mpl").read_bytes())
        build("public-seal-display-positive", probe, True)
        source.write_bytes(fixture.read_bytes())
        originals = {}
        try:
            for path in (protocol / "protocol/v1.mpl", protocol / "groups/group_payload.mpl"):
                original = path.read_text()
                originals[path] = original
                if original.count("  body :: Plaintext<Bytes>") != 1:
                    raise RuntimeError("missing unique semantic body label: " + str(path))
                path.write_text(original.replace("  body :: Plaintext<Bytes>", "  body :: Bytes"))
            build("removed-labels-positive", probe, True)
            source.write_bytes((fixtures / "caller-control.mpl").read_bytes())
            require_refusals(build("removed-labels-caller-control", probe, False), source,
                             ["unrelated_private_caller", "native_display_called_from_mesh"])
        finally:
            for path, original in originals.items():
                path.write_text(original)
        build("production-main", mobile, True, "staticlib")
        build("production-cli", cli, True)
        record["inputs_stable"] = all(sha(Path(path)) == digest for path, digest in record["inputs"].items())
        record["toolchain_stable"] = all(sha(path) == record["toolchain"][name]["sha256"]
                                         for name, path in tool_paths.items())
        if (not record["inputs_stable"] or not record["toolchain_stable"]
                or any(sha(fixtures / name) != digest for name, digest in record["fixtures"].items())):
            raise RuntimeError("source or toolchain changed during proof")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
