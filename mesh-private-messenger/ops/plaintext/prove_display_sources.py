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
from MobileCore import credit_attachments_export, attachment_download_plan_export, presentation_load_export, presentation_save_export, receive_initial_export, receive_message_export, group_receive_export
from Mobile.Presentation import load_presentation_record, presentation_data, encode_presented_message, presented_body, presentation_edit_permission, PresentationEditPermission, community_change_allowed
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
fn refuse_presentation_storage(path :: String, key :: Bytes, wrapping :: borrow StorageKey) -> Int!String do
  let value = load_presentation_record(path,wrapping,key)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_presentation_ingress(input :: Bytes) -> Int!String do
  let value = presentation_data(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_presentation_encoding(body :: Bytes, profile :: Bytes, group :: Bytes) -> Int!String do
  let value = encode_presented_message(body,profile,group)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_presentation_body(input :: Bytes) -> Int do
  Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),presented_body(input))
end
fn refuse_initial_receive(input :: Bytes) -> Int!String do
  let value = receive_initial_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_direct_receive(input :: Bytes) -> Int!String do
  let value = receive_message_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn refuse_group_receive(input :: Bytes) -> Int!String do
  let value = group_receive_export(input)?
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),value))
end
fn main() do nil end
'''
POLICY_PROBES = '''fn refuse_private_editor(stored :: Bytes, incoming :: Bytes, sender :: Plaintext<Bytes>, creator :: Bytes) -> Int!String do
  let permission = presentation_edit_permission(stored,incoming,sender,creator)?
  let result = case permission do EditAllowed -> Bytes.from_utf8("allowed") _ -> Bytes.from_utf8("refused") end
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),result))
end
fn refuse_private_committer(path :: String, key :: borrow StorageKey, group :: Bytes, sender :: Plaintext<Bytes>, target :: Bytes) -> Int!String do
  let allowed = community_change_allowed(path,key,group,sender,target)?
  let result = if allowed do Bytes.from_utf8("allowed") else Bytes.from_utf8("refused") end
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),result))
end
fn refuse_stored_roles(path :: String, key :: borrow StorageKey, record :: Bytes, incoming :: Bytes, claimed_sender :: Bytes, creator :: Bytes) -> Int!String do
  let stored = load_presentation_record(path,key,record)?
  let permission = presentation_edit_permission(stored,incoming,claimed_sender,creator)?
  let result = case permission do EditAllowed -> Bytes.from_utf8("allowed") _ -> Bytes.from_utf8("refused") end
  Ok(Http.body_bytes(Http.build(:post,"https://never-contact.invalid"),result))
end
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
        "pub fn presentation_fields(input :: Plaintext<Bytes>) -> PresentationFields!String do",
        "pub fn presentation_data(input :: Plaintext<Bytes>) -> Plaintext<Bytes>!String do",
        "pub fn load_presentation_record(database_path :: String,\n  wrapping_key :: borrow StorageKey,\n  key :: Bytes) -> Plaintext<Bytes>!String do",
        "      let protected :: Plaintext<Bytes> = value",
        "fn save_record(database_path :: String,\n  wrapping_key :: borrow StorageKey,\n  key :: Bytes,\n  data :: Plaintext<Bytes>) -> Plaintext<Bytes>!String do",
        "pub fn encode_presented_message(body :: Plaintext<Bytes>,\n  profile :: Plaintext<Bytes>,\n  group :: Plaintext<Bytes>) -> Plaintext<Bytes>!String do",
        "pub fn encode_presented_message_with_attachment(body :: Plaintext<Bytes>,\n  profile :: Plaintext<Bytes>,\n  group :: Plaintext<Bytes>,\n  attachment :: Plaintext<Bytes>) -> Plaintext<Bytes>!String do",
        "  input :: Plaintext<Bytes>) -> Result<(Plaintext<Bytes>, Plaintext<Bytes>, List<String>, List<Bytes>), String> do",
        "pub fn presented_body(input :: Plaintext<Bytes>) -> Plaintext<Bytes> do",
    ],
    "mobile_core.mpl": [
        'pub fn receive_initial_export(request :: Bytes) -> Plaintext<Bytes>!String do',
        'pub fn receive_message_export(request :: Bytes) -> Plaintext<Bytes>!String do',
        'pub fn group_receive_export(request :: Bytes) -> Plaintext<Bytes>!String do',
    ],
}
PROTOCOL_LABELS = {
    "attachments/protocol.mpl": [
        "  filename :: Plaintext<Bytes>",
        "  mime_type :: Plaintext<Bytes>",
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
    record = {"status": "running", "compiler_sha256": sha(compiler), "runner_sha256": sha(Path(__file__)), "inputs": {}, "results": [],
              "scope": "Actual attachment/display getters and presentation ingress, storage, encoding and body projection; not complete message ingress or field labeling."}
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
        (probe / "mesh.toml").write_text('[package]\nname="display-source-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        negative_source = PROBE.replace("fn main() do nil end", POLICY_PROBES + "fn main() do nil end")
        (probe / "main.mpl").write_text(negative_source)
        diagnostics = build("protected-negative", probe, False)
        errors = [value for value in diagnostics if value["code"] != "C0001"]
        if not errors or any(value["code"] != "E0093" for value in errors):
            raise RuntimeError("negative must fail only plaintext policy")
        data = negative_source.encode()
        functions = list(re.finditer(rb"fn (refuse_[a-z_]+)\(", data))
        for index, function in enumerate(functions):
            stop = functions[index + 1].start() if index + 1 < len(functions) else data.index(b"fn main()")
            if not any(value.get("file") == str(probe / "main.mpl")
                       and "`Http.body_bytes`" in value["message"]
                       and any(function.start() <= span["start"] < stop for span in value["spans"])
                       for value in errors):
                raise RuntimeError("missing exact HTTP refusal for " + function[1].decode())
        record["refused_probes"] = [function[1].decode() for function in functions]
        originals = {}
        try:
            # These controls remove actual source labels. The policy probes have
            # intentionally private caller inputs and must stay refused.
            (probe / "main.mpl").write_text(PROBE)
            protocol = copies[(args.product / "packages/messenger-protocol").resolve()]
            for package, labels in ((mobile, LABELS), (protocol, PROTOCOL_LABELS)):
                for relative, signatures in labels.items():
                    path = package / relative
                    text = path.read_text()
                    originals[path] = text
                    for signature in signatures:
                        if text.count(signature) != 1:
                            raise RuntimeError("source label changed: " + signature)
                        text = text.replace(signature, signature.replace("Plaintext<Bytes>", "Bytes"))
                    path.write_text(text)
            # Request and self-sync labels independently protect the receive
            # wrappers; remove them only in this copied positive control too.
            types_path = mobile / "mobile/types.mpl"
            types_text = types_path.read_text()
            originals[types_path] = types_text
            for name in ("MobileStartRequest", "MobileFanoutRequest", "MobileSyncPayload", "MobileGroupSendRequest"):
                start = types_text.index("pub struct " + name + " do")
                end = types_text.index("\nend", start)
                part = types_text[start:end]
                if part.count("  body :: Plaintext<Bytes>") != 1:
                    raise RuntimeError("missing body label in " + name)
                types_text = types_text[:start] + part.replace("  body :: Plaintext<Bytes>", "  body :: Bytes") + types_text[end:]
            types_path.write_text(types_text)
            action_path = mobile / "mobile/fanout_network.mpl"
            action_text = action_path.read_text()
            originals[action_path] = action_text
            if action_text.count("  body :: Plaintext<Bytes>") != 1:
                raise RuntimeError("missing fanout action body label")
            action_path.write_text(action_text.replace("  body :: Plaintext<Bytes>", "  body :: Bytes"))
            build("removed-labels-red", probe, True)
        finally:
            for path, text in originals.items():
                path.write_text(text)
            (probe / "main.mpl").write_text(negative_source)
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
