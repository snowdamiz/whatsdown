#!/usr/bin/env python3
"""Replay bounded helper disclosures in an isolated copy; never change live labels."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib

TESTS = [
    "mobile-core/tests/plaintext_history.test.mpl",
    "mobile-core/tests/plaintext_history_bounds.test.mpl",
    "mobile-core/tests/plaintext_presentation.test.mpl",
    "mobile-core/tests/history_storage.test.mpl",
    "mobile-core/tests/presentation.test.mpl",
    "mobile-core/tests/community_roles.test.mpl",
    "messenger-protocol/tests/hybrid.test.mpl",
    "messenger-protocol/tests/recipient_transport.test.mpl",
    "messenger-protocol/tests/transport_privacy.test.mpl",
    "messenger-protocol/tests/gossip.test.mpl",
]
NEGATIVE = '''from Mobile.HistoryWire import encode_history
from Mobile.Types import MobileHistoryEntry
from Mobile.Presentation import presented_message_writes
from Storage.HistoryBlobs import seal_history_blob
from Identity.Device import DeviceKeys, VerificationPolicy
from Protocol.V1 import DeviceCredential, AccountIdentity, PrekeyBundle, InitialMessage
from Session.Handshake import SessionError, initiate
from Session.State import RatchetState
fn refuse_history(values :: Plaintext<List<MobileHistoryEntry>>) -> Int!String do
  let encoded = encode_history(values)?
  Ok(Http.body_bytes(Http.build(:post,"https://example.invalid/never"),encoded))
end
fn refuse_nonce(values :: Plaintext<List<MobileHistoryEntry>>, key :: borrow AeadKey,
  nonce :: Plaintext<Bytes>) -> Result<Result<Bytes,CryptoError>,String> do
  let encoded = encode_history(values)?
  Ok(Crypto.aead_seal(key,nonce,Bytes.empty(),encoded))
end
fn refuse_context(value :: Plaintext<Bytes>, wrapping :: borrow StorageKey,
  label :: Plaintext<String>) -> Bytes!String do
  seal_history_blob(value,wrapping,label)
end
fn refuse_body(input :: Plaintext<Bytes>, wrapping :: borrow StorageKey) -> Int!String do
  let (body, attachment, labels, blobs) = presented_message_writes("/tmp/never-opened.db", wrapping,
    Bytes.from_utf8("11111111111111111111111111111111"), Bytes.empty(), Bytes.empty(), input)?
  Ok(Http.body_bytes(Http.build(:post,"https://example.invalid/never"),body))
end
fn refuse_sender(sender :: Plaintext<Bytes>, input :: Bytes,
  wrapping :: borrow StorageKey) -> Result<(Bytes,Bytes,List<String>,List<Bytes>),String> do
  presented_message_writes("/tmp/never-opened.db",wrapping,sender,Bytes.empty(),Bytes.empty(),input)
end
fn refuse_database(path :: Plaintext<String>, input :: Bytes,
  wrapping :: borrow StorageKey) -> Result<(Bytes,Bytes,List<String>,List<Bytes>),String> do
  presented_message_writes(path,wrapping,Bytes.from_utf8("11111111111111111111111111111111"),
    Bytes.empty(),Bytes.empty(),input)
end
fn refuse_credential(initiator :: borrow DeviceKeys, credential :: Plaintext<DeviceCredential>,
  account :: AccountIdentity, bundle :: PrekeyBundle, policy :: VerificationPolicy,
  suite :: Int, plaintext :: Bytes) -> Result<(RatchetState,InitialMessage),SessionError> do
  initiate(initiator,credential,account,bundle,policy,suite,plaintext)
end
fn refuse_policy(initiator :: borrow DeviceKeys, credential :: DeviceCredential,
  account :: AccountIdentity, bundle :: PrekeyBundle, policy :: Plaintext<VerificationPolicy>,
  suite :: Int, plaintext :: Bytes) -> Result<(RatchetState,InitialMessage),SessionError> do
  initiate(initiator,credential,account,bundle,policy,suite,plaintext)
end
fn main() do nil end
'''
POSITIVE = '''from Protocol.EnvelopeWire import encode_inner_envelope
from Protocol.V1 import InnerEnvelope, ProtocolError
fn private_encoding(value :: Plaintext<InnerEnvelope>) -> Bytes!ProtocolError do
  encode_inner_envelope(value)
end
fn main() do nil end
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(base):
    return {
        str(path.relative_to(base)): digest(path)
        for package in ("mobile-core", "messenger-protocol")
        for path in sorted((base / "packages" / package).rglob("*"))
        if path.is_file() and path.suffix in (".mpl", ".toml")
    }


def fixture(directory, mobile, protocol, source):
    directory.mkdir()
    (directory / "mesh.toml").write_text(
        '[package]\nname="plaintext-helper-proof"\nversion="0.1.0"\n'
        f'[dependencies]\nmessenger-protocol={{path="{protocol}"}}\n'
        + (f'messenger-mobile-core={{path="{mobile}"}}\n' if mobile else "")
    )
    (directory / "main.mpl").write_text(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--compiler", type=Path, default=os.environ.get("MESH_COMPILER_BIN"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.compiler:
        parser.error("--compiler or MESH_COMPILER_BIN is required")
    compiler = args.compiler.resolve()
    product = args.product.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    work = Path(tempfile.mkdtemp(prefix="sources-", dir=output))
    before = sources(product)
    for package in ("messenger-protocol", "mobile-core"):
        original = product / "packages" / package
        copied = work / package
        shutil.copytree(original, copied)
        manifest = copied / "mesh.toml"
        text = manifest.read_text()
        for name, dep in tomllib.loads(text).get("dependencies", {}).items():
            if isinstance(dep, dict) and "path" in dep:
                target = work / "messenger-protocol" if name == "messenger-protocol" else (original / dep["path"]).resolve()
                text = text.replace('path = "' + dep["path"] + '"', 'path = "' + str(target) + '"')
                text = text.replace('path="' + dep["path"] + '"', 'path="' + str(target) + '"')
        manifest.write_text(text)
    if before != sources(product):
        raise RuntimeError("production sources changed during isolated capture")
    record = {"schema_version": 1, "status": "running", "compiler": str(compiler),
              "compiler_sha256": digest(compiler), "product": str(product), "inputs": before,
              "scope": "15 reviewed helper metadata releases; no whole-app plaintext closure",
              "results": []}
    evidence = output / "evidence.json"

    def run(name, command, expected=0):
        start = time.monotonic()
        result = subprocess.run([str(compiler), *map(str, command)], capture_output=True, text=True)
        log = result.stdout + result.stderr
        (output / (name + ".log")).write_text(log)
        item = {"name": name, "args": list(map(str, command)), "exit_code": result.returncode,
                "seconds": round(time.monotonic() - start, 3), "log_sha256": hashlib.sha256(log.encode()).hexdigest()}
        record["results"].append(item)
        evidence.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(item), flush=True)
        if (result.returncode == 0) != (expected == 0):
            raise RuntimeError(name + " returned unexpected status; see preserved log")
        return log

    try:
        positive = work / "positive"
        fixture(positive, None, work / "messenger-protocol", POSITIVE)
        run("private-envelope", ["build", positive, "-o", positive / "proof", "--json"])
        v1 = work / "messenger-protocol/protocol/v1.mpl"
        original = v1.read_text()
        if original.count("  MalformedEncoding\n") != 1:
            raise RuntimeError("ProtocolError declaration changed; update reviewed mutation fixture")
        try:
            v1.write_text(original.replace("  MalformedEncoding\n", "  MalformedEncoding\n  UnreviewedPayload(value :: String)\n", 1))
            mutation = run("future-error-payload", ["build", positive, "-o", positive / "must-not-exist", "--json"], 1)
            diagnostics = [json.loads(line) for line in mutation.splitlines() if line.startswith("{")]
            if not any(d.get("code") == "E0012" and "UnreviewedPayload" in d.get("message", "")
                       and d.get("file", "").endswith("/protocol/envelope_wire.mpl") for d in diagnostics):
                raise RuntimeError("new error variant did not fail the exact exhaustive disclosure classifier")
            if (positive / "must-not-exist").exists():
                raise RuntimeError("refused mutation emitted an artifact")
        finally:
            v1.write_text(original)
        negative = work / "negative"
        fixture(negative, work / "mobile-core", work / "messenger-protocol", NEGATIVE)
        refusal = run("private-exits-refused", ["build", negative, "-o", negative / "must-not-exist", "--json"], 1)
        diagnostics = [json.loads(line) for line in refusal.splitlines() if line.startswith("{")]
        errors = [d for d in diagnostics if d.get("code") != "C0001"]
        if not errors or any(d.get("code") != "E0093" for d in errors):
            raise RuntimeError("private negative fixture must fail only plaintext policy, not ordinary compile errors")
        data = NEGATIVE.encode()
        functions = list(re.finditer(rb"fn (refuse_[a-z]+)\(", data))
        for i, function in enumerate(functions):
            stop = functions[i + 1].start() if i + 1 < len(functions) else data.index(b"fn main()")
            if not any(d.get("file") == str(negative / "main.mpl") and any(
                    function.start() <= span.get("start", -1) < stop for span in d.get("spans", [])) for d in errors):
                raise RuntimeError("missing refusal for " + function.group(1).decode())
        if (negative / "must-not-exist").exists():
            raise RuntimeError("private exit fixture emitted an artifact")
        for relative in TESTS:
            run(relative.replace("/", "-").replace(".mpl", ""), ["test", work / relative])
        if digest(compiler) != record["compiler_sha256"]:
            raise RuntimeError("compiler changed during proof")
        record["status"] = "passed"
    except Exception as error:
        record["status"] = "failed"
        record["error"] = str(error)
        raise
    finally:
        evidence.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
