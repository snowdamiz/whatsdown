#!/usr/bin/env python3
"""Compile actual display getters against forbidden HTTP exits; never run probes."""
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


PROBE = '''from Mobile.Attachments import attachment_summary
from Identity.Device import DeviceKeys
from Mobile.CreditAttachmentNative import native_credit_attachments, native_attachment_download_plan
from MobileCore import credit_attachments_export, attachment_download_plan_export, presentation_load_export, presentation_save_export
fn refuse_summary(device :: borrow DeviceKeys, reference :: Bytes) -> Int do
  Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),attachment_summary(device,reference))
end
fn refuse_inventory(input :: Bytes) -> Int!String do
  let value = native_credit_attachments(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_download(input :: Bytes) -> Int!String do
  let value = native_attachment_download_plan(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_inventory_export(input :: Bytes) -> Int!String do
  let value = credit_attachments_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_download_export(input :: Bytes) -> Int!String do
  let value = attachment_download_plan_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_presentation_load(input :: Bytes) -> Int!String do
  let value = presentation_load_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_presentation_save(input :: Bytes) -> Int!String do
  let value = presentation_save_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn main() do nil end
'''
LABELS = {
    "mobile/attachments.mpl": [
        "pub fn attachment_summary(device :: borrow DeviceKeys, encoded :: Bytes) -> Plaintext<Bytes> do",
    ],
    "mobile/credit_attachment_native.mpl": [
        "pub fn native_credit_attachments(input :: Bytes) -> Plaintext<Bytes>!String do",
        "pub fn native_attachment_download_plan(input :: Bytes) -> Plaintext<Bytes>!String do",
    ],
    "mobile/presentation.mpl": [
        "pub fn load_presentation(request :: MobilePayloadRequest) -> Plaintext<Bytes>!String do",
        "pub fn save_presentation(request :: MobileTriplePayloadRequest) -> Plaintext<Bytes>!String do",
    ],
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    record = {"status": "running", "compiler_sha256": sha(compiler), "inputs": {}, "results": [],
              "scope": "Actual attachment/presentation getter and display-export outputs; not complete ingress or field labeling."}
    runtime = os.environ.get("MESH_RT_LIB_PATH")
    if runtime:
        record["runtime_sha256"] = sha(Path(runtime))
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
        (probe / "mesh.toml").write_text('[package]\nname="display-source-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        (probe / "main.mpl").write_text(PROBE)
        diagnostics = build("protected-negative", probe, False)
        errors = [value for value in diagnostics if value["code"] != "C0001"]
        if not errors or any(value["code"] != "E0093" for value in errors):
            raise RuntimeError("negative must fail only plaintext policy")
        data = PROBE.encode()
        functions = list(re.finditer(rb"fn (refuse_[a-z_]+)\(", data))
        for index, function in enumerate(functions):
            stop = functions[index + 1].start() if index + 1 < len(functions) else data.index(b"fn main()")
            if not any(value.get("file") == str(probe / "main.mpl")
                       and "`Http.body_bytes`" in value["message"]
                       and any(function.start() <= span["start"] < stop for span in value["spans"])
                       for value in errors):
                raise RuntimeError("missing exact HTTP refusal for " + function[1].decode())
        originals = {}
        try:
            for relative, signatures in LABELS.items():
                path = mobile / relative
                text = path.read_text()
                originals[path] = text
                for signature in signatures:
                    if text.count(signature) != 1:
                        raise RuntimeError("getter signature changed: " + signature)
                    text = text.replace(signature, signature.replace("Plaintext<Bytes>", "Bytes"))
                path.write_text(text)
            build("removed-labels-red", probe, True)
        finally:
            for path, text in originals.items():
                path.write_text(text)
        build("production-green", mobile, True)
        if sha(compiler) != record["compiler_sha256"]:
            raise RuntimeError("compiler changed during proof")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        evidence.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
