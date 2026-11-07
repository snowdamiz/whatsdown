#!/usr/bin/env python3
"""Qualify the actual CLI display/receive/ACK functions, offline except loopback.

Freeze baseline and working application sources, retain read-only language
dependencies, and replace only Main.main with a test driver. Forbidden privacy
probes are compiled but never executed. All generated files stay in --output.
"""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import tomllib


BASELINE = "a48963b4918f5fc39981176d4e46069b78dfeebb"
TOOLCHAIN_ROOT = Path("/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts")
PINS = {
    "bin/meshc": "19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85",
    "lib/libmesh_rt.a": "d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8",
    "lib/libmesh_test_rt.a": "9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def without_main(text):
    # Main is the last top-level declaration in both pinned CLI versions.
    matches = list(re.finditer(r"(?m)^fn main\(\) do\n", text))
    if len(matches) != 1 or re.search(r"(?m)^(?:pub )?(?:fn|struct|type) ", text[matches[0].end():]):
        raise RuntimeError("Main entrypoint is not unique and last")
    return text[:matches[0].start()]


def diagnostics(log):
    result = []
    for line in log.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("code") and item["code"] != "C0001":
            result.append(item)
    return result


def require_refusals(items, source, expected):
    data = source.read_bytes()
    if len(items) != len(expected) or any(item["code"] != "E0093" for item in items):
        raise RuntimeError("expected exactly the named E0093 diagnostics; inspect build.log")
    matched = []
    for name, token, subject in expected:
        start = data.index(("fn " + name + "(").encode())
        stop = data.find(b"\nfn ", start + 1)
        stop = len(data) if stop < 0 else stop
        location = data.index(token.encode(), start, stop)
        matches = [item for item in items if item.get("file") == str(source)
                   and "`" + subject + "`" in item.get("message", "")
                   and any(span["start"] <= location < span["end"] for span in item.get("spans", []))]
        if len(matches) != 1:
            raise RuntimeError("missing exact refusal subject/location: " + name)
        matched.append({"function": name, "subject": subject, "offset": location,
                        "line": data[:location].count(b"\n") + 1, "diagnostic": matches[0]})
    return matched


def expected_stdout():
    output = []
    for label, initial in (("valid", "display:initial"),
                           ("invalid-inner", "device-b:invalid-inner"),
                           ("invalid-utf8", "device-b:invalid-body")):
        output.extend(["case:initial-" + label, initial, "display:third", "display:first", "display:second"])
        if label != "valid":
            output.extend(["device-b:invalid-inner", "device-b:invalid-body"])
        output.extend(["dedup:suppressed", "device-b:acked=" + ("5" if label == "valid" else "7")])
    return "\n".join(output) + "\n"


def decode_ack(body):
    if len(body) < 109 or body[:4] != b"\x02ACK":
        raise RuntimeError("invalid signed ACK prefix/length")
    count = body[44]
    if not 1 <= count <= 8 or len(body) != 45 + 16 * count + 64:
        raise RuntimeError("invalid ACK count/length")
    return {"mailbox_token_hash": body[4:36].hex(),
            "issued_at_ms": int.from_bytes(body[36:44], "big"), "count": count,
            "ids": [body[45 + 16 * n:61 + 16 * n].hex() for n in range(count)],
            "signature": body[-64:].hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--privacy-only", action="store_true")
    args = parser.parse_args()
    product = args.product.resolve()
    repo = product.parent
    output = args.output.resolve()
    allowed = repo / ".morse/decoded-body-labels/cli-proof-child"
    if not output.is_relative_to(allowed):
        parser.error("--output must be within " + str(allowed))
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    fixtures = Path(__file__).parent / "fixtures/cli-decoded-display"
    language = (repo / "mesh-lang").resolve(strict=True)
    compiler = TOOLCHAIN_ROOT / "bin/meshc"
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "SDKROOT", "DEVELOPER_DIR")
           if key in os.environ}
    env.update(TMPDIR=str(output / "tmp"),
               MESH_RT_LIB_PATH=str(TOOLCHAIN_ROOT / "lib/libmesh_rt.a"),
               MESH_TEST_RT_LIB_PATH=str(TOOLCHAIN_ROOT / "lib/libmesh_test_rt.a"),
               NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    record = {"status": "running", "baseline_commit": BASELINE,
              "runner_sha256": sha(Path(__file__)),
              "fixtures": {p.name: sha(p) for p in sorted(fixtures.glob("*")) if p.is_file()},
              "toolchain": {}, "sources": {}, "language_sources": {}, "builds": [],
              "probe_execution": "none", "network": "only an ephemeral 127.0.0.1 ACK recorder",
              "boundary": "The recording collector is not the production mailbox service and does not prove server authorization, persistence, draining, or live delivery."}
    evidence = output / "evidence.json"

    def sandbox(command, name, port=None):
        profile = output / (name + ".sb")
        rules = ['(version 1)', '(allow default)', '(deny network*)',
                 '(deny file-write* (subpath ' + json.dumps(str(language)) + '))']
        if port is not None:
            # macOS Seatbelt accepts only localhost or * in this filter. The
            # collector and the sole runtime URL both use literal 127.0.0.1.
            rules.append('(allow network-outbound (remote ip "localhost:' + str(port) + '"))')
        profile.write_text("\n".join(rules) + "\n")
        return ["/usr/bin/sandbox-exec", "-f", str(profile), *command]

    def save():
        evidence.write_text(json.dumps(record, indent=2) + "\n")

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    copies = {}

    def snapshot(package, version):
        package = package.resolve()
        key = (package, version)
        if key in copies:
            return copies[key]
        external = not package.is_relative_to(product)
        if external and not package.is_relative_to(language):
            raise RuntimeError("unexpected external dependency: " + str(package))
        destination = package if external else output / version / "sources" / package.relative_to(product)
        copies[key] = destination
        if external or version == "current":
            files = {path.relative_to(package): path.read_bytes() for path in sorted(package.rglob("*"))
                     if path.is_file() and path.suffix in (".mpl", ".toml", ".lock")}
        else:
            prefix = str(package.relative_to(repo))
            paths = git("ls-tree", "-r", "--name-only", BASELINE, "--", prefix).decode().splitlines()
            files = {Path(path).relative_to(prefix): git("show", BASELINE + ":" + path)
                     for path in paths if Path(path).suffix in (".mpl", ".toml", ".lock")}
        for relative, data in files.items():
            if external:
                record["language_sources"][str(package / relative)] = digest(data)
            else:
                record["sources"].setdefault(version, {})[str((package / relative).relative_to(repo))] = digest(data)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        manifest_text = files[Path("mesh.toml")].decode()
        for dep in tomllib.loads(manifest_text).get("dependencies", {}).values():
            if not isinstance(dep, dict) or "path" not in dep:
                raise RuntimeError("only local path dependencies are allowed")
            target = snapshot(package / dep["path"], version)
            if not external:
                manifest_text, count = re.subn(r'(\bpath\s*=\s*)' + re.escape(json.dumps(dep["path"])),
                                               lambda m: m[1] + json.dumps(str(target)), manifest_text)
                if count != 1:
                    raise RuntimeError("ambiguous dependency path")
        if not external:
            (destination / "mesh.toml").write_text(manifest_text)
        return destination

    def build(name, package, success):
        directory = output / "builds" / name
        directory.mkdir(parents=True)
        artifact = directory / "mesh-cli"
        command = [str(compiler), "build", "--json", str(package), "-o", str(artifact),
                   "--plaintext-report", str(directory / "plaintext.json")]
        start = time.monotonic()
        command = sandbox(command, name)
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=300)
        log = result.stdout + result.stderr
        (directory / "build.log").write_text(log)
        (directory / "main.mpl").write_bytes((package / "main.mpl").read_bytes())
        record["builds"].append({"name": name, "command": command, "exit_code": result.returncode,
                                 "source": str(package / "main.mpl"),
                                 "seconds": round(time.monotonic() - start, 3),
                                 "artifacts": {str(p.relative_to(output)): sha(p)
                                               for p in directory.iterdir() if p.is_file()}})
        save()
        print(name, result.returncode, flush=True)
        if (result.returncode == 0) != success or artifact.exists() != success:
            raise RuntimeError(name + " failed its compile/artifact expectation")
        return artifact, diagnostics(log)

    def execute(name, artifact):
        directory = output / "runs" / name
        directory.mkdir(parents=True)
        requests = []

        class Recorder(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 237:
                    self.send_error(400)
                    return
                body = self.rfile.read(length)
                index = len(requests)
                body_path = directory / ("ack-" + str(index) + ".bin")
                body_path.write_bytes(body)
                requests.append({"path": self.path, "content_type": self.headers.get("Content-Type"),
                                 "body_sha256": digest(body), "body_file": str(body_path.relative_to(output)),
                                 "received_at_ms": time.time_ns() // 1_000_000,
                                 "decoded": decode_ack(body)})
                self.send_response(200 if self.path == "/v1/mailbox/ack" else 404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Recorder)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        command = sandbox([str(artifact)], name + "-run", port)
        start_ms = time.time_ns() // 1_000_000
        try:
            result = subprocess.run(command, capture_output=True, env=env | {
                "MESSENGER_BASE_URL": "http://127.0.0.1:" + str(port)}, timeout=90)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        (directory / "stdout.txt").write_bytes(result.stdout)
        (directory / "stderr.txt").write_bytes(result.stderr)
        (directory / "requests.json").write_text(json.dumps(requests, indent=2) + "\n")
        entry = {"name": name, "command": command, "exit_code": result.returncode,
                 "stdout_sha256": digest(result.stdout), "collector": "127.0.0.1:" + str(port),
                 "requests": requests, "signature_verification": []}
        record.setdefault("runs", []).append(entry)
        save()
        if result.returncode != 0 or result.stderr or result.stdout.decode() != expected_stdout():
            raise RuntimeError(name + " failed its exact stdout/stderr/exit expectation")
        if len(requests) != 3:
            raise RuntimeError(name + " did not send exactly three ACKs")
        stable = []
        for index, request in enumerate(requests):
            ack = request["decoded"]
            ids = (1, 4, 2, 3, 5) if index == 0 else (1, 4, 2, 3, 5, 6, 7)
            expected_ids = [(bytes([10 * index + n]) * 16).hex() for n in ids]
            token_hash = digest(bytes([70 + index]) * 32)
            if (request["path"] != "/v1/mailbox/ack" or request["content_type"] != "application/octet-stream"
                    or ack["count"] != len(ids) or ack["ids"] != expected_ids or ack["mailbox_token_hash"] != token_hash
                    or not start_ms <= ack["issued_at_ms"] <= request["received_at_ms"]):
                raise RuntimeError(name + " ACK content/order/freshness mismatch")
            body = (output / request["body_file"]).read_bytes()
            # Validate the actual HTTP body with the actual Mesh decoder and verifier.
            verify_command = sandbox([str(artifact)], name + "-verify-" + str(index))
            verified = subprocess.run(verify_command, capture_output=True, env=env | {
                "PROOF_VERIFY_ACK": body.hex()}, timeout=30)
            (directory / ("verify-" + str(index) + ".log")).write_bytes(verified.stdout + verified.stderr)
            entry["signature_verification"].append({"command": verify_command, "exit_code": verified.returncode})
            if verified.returncode or verified.stderr or verified.stdout != b"ack-signature:valid\n":
                raise RuntimeError(name + " recorded ACK signature did not verify")
            # Timestamps and their signatures vary; all other body bytes must match.
            stable.append((body[:36] + body[44:-64]).hex())
        entry["normalized_ack_bodies"] = stable
        entry["comparison_excludes"] = "issued_at_ms and its signature only; raw bodies retained and signatures verified"
        save()
        print(name, "stdout + 3 signed ACKs passed", flush=True)
        return result.stdout, stable

    try:
        for relative, expected in PINS.items():
            path = TOOLCHAIN_ROOT / relative
            actual = sha(path)
            record["toolchain"][relative] = {"path": str(path), "sha256": actual}
            if actual != expected:
                raise RuntimeError("toolchain pin mismatch: " + relative)
        record["working_head"] = git("rev-parse", "HEAD").decode().strip()
        (output / "working.diff").write_bytes(git("diff", "--", str(product.relative_to(repo))))
        current = snapshot(product / "clients/mesh-cli", "current")
        baseline = snapshot(product / "clients/mesh-cli", "baseline")
        sources = {"current": current, "baseline": baseline}
        prefixes = {name: without_main((path / "main.mpl").read_text()) for name, path in sources.items()}
        record["preserved_main_prefix"] = {name: digest(text.encode()) for name, text in prefixes.items()}
        record["original_main_sha256"] = {name: sha(path / "main.mpl") for name, path in sources.items()}

        def variant(name, version, driver):
            destination = output / "variants" / name
            shutil.copytree(sources[version], destination)
            source = destination / "main.mpl"
            source.write_text(prefixes[version] + driver)
            if source.read_bytes()[:len(prefixes[version].encode())] != prefixes[version].encode():
                raise RuntimeError("production Main function changed")
            return destination

        negative = variant("current-privacy-negative", "current", (fixtures / "privacy.mpl").read_text()
                           + "\nfn main() do nil end\n")
        _, errors = build("current-privacy-negative", negative, False)
        expected = [(name, "println", "println") for name in
                    ("proof_private_text", "proof_private_metadata", "proof_private_decode_error", "proof_private_utf8_error")]
        expected.append(("proof_private_caller", "display(", "println"))
        record["privacy_refusals"] = require_refusals(errors, negative / "main.mpl", expected)
        record["unknown_status_boundary"] = (
            "The current helper returns only 0/1/2; unknown status is unreachable through its inputs. "
            "The preserved Main.display default branch was inspected and prints device-b:invalid-inner; "
            "the harness does not replace the helper to manufacture an unknown status.")
        reviewed = repo / ".morse/decoded-body-labels/cli-reviewed/plaintext.json"
        if reviewed.exists():
            audit = json.loads(reviewed.read_text())
            main_audit = next(module for module in audit["modules"] if module["module"] == "Main")
            record["existing_reviewed_report"] = {"path": str(reviewed), "sha256": sha(reviewed),
                                                  "main": main_audit,
                                                  "matches_current": main_audit["source_sha256"] == record["original_main_sha256"]["current"]}
        if not args.privacy_only:
            driver = (fixtures / "driver.mpl").read_text()
            results = {}
            for name in ("baseline", "current"):
                package = variant(name + "-runtime", name, driver)
                artifact, errors = build(name + "-runtime", package, True)
                if errors:
                    raise RuntimeError(name + " has unexpected diagnostics")
                results[name] = execute(name, artifact)
            if results["baseline"] != results["current"]:
                raise RuntimeError("baseline/current stdout or normalized ACK bodies differ")
            record["baseline_current_equal"] = True
        record["status"] = "passed-privacy-only" if args.privacy_only else "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        record["toolchain_stable"] = all(sha(TOOLCHAIN_ROOT / rel) == pin for rel, pin in PINS.items())
        record["language_sources_stable"] = all(sha(Path(path)) == pin
                                                for path, pin in record["language_sources"].items())
        record["fixtures_stable"] = all(sha(fixtures / name) == pin for name, pin in record["fixtures"].items())
        record["working_source_changes_since_capture"] = [path for path, pin in record["sources"].get("current", {}).items()
                                                         if sha(repo / path) != pin]
        if not all(record[key] for key in ("toolchain_stable", "language_sources_stable", "fixtures_stable")):
            record.update(status="failed", error="pinned toolchain, language dependency, or fixture changed during proof")
            save()
            raise RuntimeError(record["error"])
        save()


if __name__ == "__main__":
    main()
