#!/usr/bin/env python3
"""Qualify frozen self-sync parsers; compile HTTP probes without executing them.

Default runs capture a new coherent app source family and read-only language
dependencies. --capture-only followed by --resume supports retaining a freeze
while preparing fixtures. Every run needs a fresh --output directory.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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
FROZEN = ("packages/mobile-core/mobile/sessions.mpl",
          "packages/mobile-core/tests/decoded_sync_errors.test.mpl")
SUFFIXES = {".mpl", ".toml", ".lock"}


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def source_hashes(root):
    return {str(p): sha(p) for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in SUFFIXES}


def stable(values):
    return all(Path(p).is_file() and sha(Path(p)) == digest for p, digest in values.items())


def diagnostics(log):
    items = []
    for line in log.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get("code"):
            items.append(item)
    return items


def capture(product, output):
    repo = product.parent
    language = (repo / "mesh-lang").resolve(strict=True)
    record = {"baseline": BASELINE,
              "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
              "toolchain": {name: {"path": str(TOOLCHAIN / name), "sha256": sha(TOOLCHAIN / name)}
                            for name in PINS}, "live_sources": {}, "snapshots": {}, "language": {}}
    if {k: v["sha256"] for k, v in record["toolchain"].items()} != PINS:
        raise RuntimeError("pinned toolchain mismatch")
    for package in PACKAGES:
        record["live_sources"].update(source_hashes(product / package))
    for family in ("baseline", "current"):
        root = output / family / "sources"
        root.mkdir(parents=True)
        (root / "mesh-lang").symlink_to(language, target_is_directory=True)
        if family == "current":
            for path, digest in record["live_sources"].items():
                source = Path(path)
                target = root / source.relative_to(repo)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                if sha(target) != digest:
                    raise RuntimeError("source changed while capturing: " + path)
        else:
            names = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", BASELINE,
                                             "--", *[str((product / p).relative_to(repo)) for p in PACKAGES]],
                                            cwd=repo, text=True).splitlines()
            for name in names:
                if Path(name).suffix not in SUFFIXES:
                    continue
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(subprocess.check_output(["git", "show", BASELINE + ":" + name], cwd=repo))
        record["snapshots"][family] = source_hashes(root / product.name)
    visited = set()

    def dependencies(package):
        package = package.resolve()
        if package in visited:
            return
        visited.add(package)
        if not package.is_relative_to(output):
            if not package.is_relative_to(language):
                raise RuntimeError("unexpected external dependency: " + str(package))
            record["language"].update(source_hashes(package))
        manifest = tomllib.loads((package / "mesh.toml").read_text())
        for dep in manifest.get("dependencies", {}).values():
            if not isinstance(dep, dict) or "path" not in dep:
                raise RuntimeError("only local, preexisting dependencies are permitted")
            dependencies(package / dep["path"])

    for family in ("baseline", "current"):
        for package in PACKAGES:
            dependencies(output / family / "sources" / product.name / package)
    record["capture_stable"] = stable(record["live_sources"]) and stable(record["language"])
    if not record["capture_stable"]:
        raise RuntimeError("source family changed during capture")
    (output / "capture.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    product, output = args.product.resolve(), args.output.resolve()
    if args.resume:
        record = json.loads((output / "capture.json").read_text())
        if (output / "evidence.json").exists():
            parser.error("resume is allowed only before qualification has started")
    else:
        output.mkdir(parents=True, exist_ok=False)
        record = capture(product, output)
    if args.capture_only:
        print(output / "capture.json")
        return
    qualify(product, output, record)


def qualify(product, output, record):
    fixtures = Path(__file__).parent / "fixtures/decoded-sync"
    record.update(status="running", runner_sha256=sha(Path(__file__)),
                  fixtures={p.name: sha(p) for p in sorted(fixtures.glob("*.mpl"))},
                  runs=[], mutations=[],
                  semantic_unit="UNADOPTED; no full Main, receive, native, release, or network qualification",
                  execution="Only fixed synthetic parser tests execute. All HTTP and seal probes compile only.",
                  historical_test="Earlier sync-error-baseline/test.log is not qualification evidence here.")
    evidence = output / "evidence.json"
    tmp = output / "tmp"
    tmp.mkdir()
    env_overrides = {"TMPDIR": str(tmp), "MESH_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_rt.a"),
                     "MESH_TEST_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_test_rt.a"),
                     "PYTHONDONTWRITEBYTECODE": "1"}
    env = os.environ | env_overrides
    record["environment"] = env_overrides

    def save():
        evidence.write_text(json.dumps(record, indent=2) + "\n")

    def family_root(family):
        return output / family / "sources" / product.name

    def variant(name, family, files, mutations=()):
        root = output / "variants" / name
        source_root = root / "sources"
        source_root.mkdir(parents=True)
        (source_root / "mesh-lang").symlink_to((product.parent / "mesh-lang").resolve(), target_is_directory=True)
        for package in PACKAGES:
            shutil.copytree(family_root(family) / package, source_root / product.name / package)
        for relative, before, after in mutations:
            path = source_root / product.name / relative
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError("mutation must have one exact target: " + relative)
            changed = original.replace(before, after)
            path.write_text(changed)
            record["mutations"].append({"variant": name, "path": relative, "before": before, "after": after,
                                        "diff": "".join(difflib.unified_diff(original.splitlines(True),
                                                                             changed.splitlines(True)))})
        probe = root / "probe"
        probe.mkdir()
        mobile = source_root / product.name / PACKAGES[0]
        (probe / "mesh.toml").write_text('[package]\nname="sync-parser-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        for name, content in files.items():
            path = probe / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root, probe

    def run(name, family, files, kind="build", expect="positive", names=(), mutations=()):
        root, probe = variant(name, family, files, mutations)
        build = root / "result"
        build.mkdir()
        before = source_hashes(root)
        (build / "sources.json").write_text(json.dumps(before, indent=2) + "\n")
        artifact = build / "libproof.a"
        if kind == "test":
            command = [str(TOOLCHAIN / "bin/meshc"), "test", str(probe)]
        else:
            command = [str(TOOLCHAIN / "bin/meshc"), "build", "--json", str(probe), "--artifact", "staticlib",
                       "--plaintext-report", str(build / "plaintext.json"), "-o", str(artifact)]
        (build / "command.json").write_text(json.dumps({"argv": command, "cwd": str(product.parent),
                                                       "environment": env_overrides}, indent=2) + "\n")
        start = time.monotonic()
        completed = subprocess.run(command, cwd=product.parent, env=env, capture_output=True, text=True, timeout=360)
        log = completed.stdout + completed.stderr
        (build / ("test.log" if kind == "test" else "build.log")).write_text(log)
        items = diagnostics(log)
        errors = [item for item in items if item.get("severity") == "error"]
        result = {"name": name, "family": family, "kind": kind, "command": command,
                  "exit_code": completed.returncode, "seconds": round(time.monotonic() - start, 3),
                  "source_stable": stable(before), "diagnostics": items, "expectation": expect,
                  "artifact_exists": artifact.exists(), "status": "FAIL"}
        if kind == "test":
            if expect == "positive":
                result["status"] = "PASS" if completed.returncode == 0 and "test file passed" in log else "BLOCKED"
            else:
                # The wrong identity must execute and fail its assertion, never merely fail compilation.
                result["status"] = ("PASS" if completed.returncode != 0 and "assertion failed" in log.lower()
                                    and "error[E" not in log and not errors else "FAIL")
        elif expect == "positive":
            result["status"] = "PASS" if completed.returncode == 0 and artifact.exists() and not errors else "BLOCKED"
        elif expect == "http":
            source = probe / "main.mpl"
            data = source.read_bytes()
            matching = []
            missing = []
            for fn in names:
                start_fn = data.index(("fn " + fn + "(").encode())
                end_fn = data.find(b"\nfn ", start_fn + 1)
                end_fn = len(data) if end_fn < 0 else end_fn
                sink = data.index(b"Http.body_bytes", start_fn, end_fn)
                found = [i for i, item in enumerate(errors)
                         if item.get("code") == "E0093" and item.get("file") == str(source)
                         and "`Http.body_bytes`" in item.get("message", "")
                         and any(span["start"] <= sink < span["end"]
                                 or sink <= span["start"] < sink + len(b"Http.body_bytes")
                                 for span in item.get("spans", []))]
                if len(found) == 1:
                    matching.extend(found)
                else:
                    missing.append(fn)
            result["expected_functions"] = list(names)
            result["missing_exact_refusals"] = missing
            result["unrelated_errors"] = [item for i, item in enumerate(errors) if i not in matching]
            if result["unrelated_errors"]:
                result["status"] = "BLOCKED"
            elif not missing and len(matching) == len(errors) and completed.returncode != 0 and not artifact.exists():
                result["status"] = "PASS"
        elif expect == "nonexhaustive":
            source = probe / "main.mpl"
            data = source.read_bytes()
            start_case = data.index(b"case error do")
            result["classifier_refusals"] = [item for item in errors
                if item.get("file") == str(source) and "non-exhaustive" in item.get("message", "").lower()
                and any(span["start"] <= start_case < span["end"] for span in item.get("spans", []))]
            result["status"] = ("PASS" if completed.returncode != 0 and len(result["classifier_refusals"]) == 1
                                and len(errors) == 1 and not artifact.exists() else "BLOCKED")
        if not result["source_stable"]:
            result["status"] = "FAIL"
        result["files"] = {str(p.relative_to(root)): sha(p) for p in sorted(build.iterdir()) if p.is_file()}
        record["runs"].append(result)
        save()
        print(name, result["status"], "exit=" + str(completed.returncode), flush=True)
        return result

    try:
        if not all(stable(record["snapshots"][f]) for f in ("baseline", "current")) or not stable(record["language"]):
            raise RuntimeError("captured inputs changed before qualification")
        if {k: sha(TOOLCHAIN / k) for k in PINS} != PINS:
            raise RuntimeError("toolchain changed before qualification")
        current_test = (family_root("current") / FROZEN[1]).read_text()
        legacy = (fixtures / "legacy-errors.test.mpl").read_text()
        equivalent = current_test.replace("parse_sync_payload, parse_sync_payload_typed, SyncPayloadError", "parse_sync_payload")
        a, b = equivalent.index("fn typed_outcome("), equivalent.index("fn outcome(")
        equivalent = (equivalent[:a] + equivalent[b:]).replace("legacy && typed_outcome(input, expected)", "legacy")
        if equivalent != legacy:
            raise RuntimeError("legacy fixture is not the exact legacy-only equivalent of frozen migration fixture")
        record["legacy_fixture_adaptation"] = "Remove typed parser/type import and typed_outcome helper; replace legacy && typed_outcome(input, expected) with legacy. Every frame and expected legacy string remains byte-identical."
        fields = (fixtures / "fields.test.mpl").read_text()
        run("baseline-legacy", "baseline", {"tests/errors.test.mpl": legacy, "tests/fields.test.mpl": fields}, kind="test")
        run("current-migration", "current", {"tests/errors.test.mpl": current_test,
                                              "tests/fields-legacy.test.mpl": fields,
                                              "tests/fields-typed.test.mpl": fields.replace("parse_sync_payload", "parse_sync_payload_typed")}, kind="test")
        wrong = current_test.replace('outcome(short_tail, "invalid_safety_number")',
                                     'outcome(short_tail, "invalid_store_request")')
        if wrong == current_test:
            raise RuntimeError("wrong-error control target missing")
        record["wrong_error_control"] = 'Only fixed short_tail expected error changes from invalid_safety_number to invalid_store_request in a copied fixture.'
        run("wrong-error-control", "current", {"tests/errors.test.mpl": wrong}, kind="test", expect="runtime-assertion")
        classifier = (fixtures / "classifier.mpl").read_text()
        run("exact-three-classifier", "current", {"main.mpl": classifier})
        sessions = "packages/mobile-core/mobile/sessions.mpl"
        run("future-variant-control", "current", {"main.mpl": classifier}, expect="nonexhaustive", mutations=(
            (sessions, "  SyncInvalidSafetyNumber\nend deriving(Eq, Debug)",
             "  SyncInvalidSafetyNumber\n  SyncFutureVariant\nend deriving(Eq, Debug)"),
            (sessions, '    SyncInvalidSafetyNumber -> "invalid_safety_number"',
             '    SyncInvalidSafetyNumber -> "invalid_safety_number"\n    SyncFutureVariant -> "synthetic_future_variant"')))
        private = (fixtures / "private-exits.mpl").read_text()
        names = re.findall(r"^fn (\w+)\(", private, re.M)
        names.remove("main")
        run("private-exits", "current", {"main.mpl": private}, expect="http", names=names)
        allowed = (fixtures / "allowed.mpl").read_text()
        run("public-routing-and-encode-seal", "current", {"main.mpl": allowed})
        public = private.replace("input :: Plaintext<Bytes>", "input :: Bytes").replace("flag :: Plaintext<Bool>", "flag :: Bool")
        record["public_argument_control"] = "In copied probe only, replace input :: Plaintext<Bytes> with input :: Bytes, and flag :: Plaintext<Bool> with flag :: Bool. Body and encoder labels remain."
        body_names = [name for name in names if name in ("legacy_body_http", "typed_body_http", "encoder_http",
                                                       "legacy_roundtrip_http", "typed_roundtrip_http", "history_body_http")]
        run("public-argument-control", "current", {"main.mpl": public}, expect="http", names=body_names)
        mobile_types = "packages/mobile-core/mobile/types.mpl"
        protocol_types = "packages/messenger-protocol/protocol/v1.mpl"
        sync_body = "pub struct MobileSyncPayload do\n  peer_username :: String\n  peer_account_id :: Bytes\n  conversation_id :: Bytes\n  client_message_id :: Bytes\n  client_timestamp :: U64\n  body :: Plaintext<Bytes>"
        encoder = "pub fn encode_sync_payload(local :: ClientProfile,\n  peer :: ClientProfile,\n  inner :: InnerEnvelope) -> Plaintext<Bytes>!String do"
        removal = ((mobile_types, sync_body, sync_body.replace("Plaintext<Bytes>", "Bytes")),
                   (protocol_types, "  body :: Plaintext<Bytes>", "  body :: Bytes"),
                   (sessions, encoder, encoder.replace("Plaintext<Bytes>", "Bytes")))
        run("removed-labels-public-control", "current", {"main.mpl": public}, mutations=removal)
        still_private = [name for name in names if name not in body_names]
        run("removed-labels-private-control", "current", {"main.mpl": private}, expect="http", names=still_private, mutations=removal)
        record["status"] = "PASS" if all(r["status"] == "PASS" for r in record["runs"]) else "INCOMPLETE"
    except Exception as error:
        record.update(status="FAIL", error=str(error))
        raise
    finally:
        record["snapshot_stable"] = all(stable(record["snapshots"][f]) for f in ("baseline", "current"))
        record["frozen_live_files_stable"] = all(sha(product / p) == record["live_sources"][str(product / p)] for p in FROZEN)
        record["live_changed_since_capture"] = [p for p, digest in record["live_sources"].items()
                                                 if not Path(p).exists() or sha(Path(p)) != digest]
        record["language_stable"] = stable(record["language"])
        record["toolchain_stable"] = {k: sha(TOOLCHAIN / k) for k in PINS} == PINS
        record["runner_stable"] = sha(Path(__file__)) == record["runner_sha256"]
        record["fixtures_stable"] = all(sha(fixtures / n) == digest for n, digest in record["fixtures"].items())
        if not all(record[k] for k in ("snapshot_stable", "frozen_live_files_stable", "language_stable",
                                      "toolchain_stable", "runner_stable", "fixtures_stable")):
            record["status"] = "FAIL"
        save()
    if record["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
