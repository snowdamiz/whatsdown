#!/usr/bin/env python3
"""Retain the rejected public-helper policy as a compile-only authority control.

The actual a48963b API must reject an arbitrary explicitly private body. The
held two-disclosure prototype must demonstrate why it was rejected: it admits
that exact call. Neither archive is executed, and no production file is changed.
This historical counterexample does not qualify the eventual receive migration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


BASELINE = "a48963b4918f5fc39981176d4e46069b78dfeebb"
TOOLCHAIN = Path("/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts")
PINS = {
    "bin/meshc": "19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85",
    "lib/libmesh_rt.a": "d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8",
    "lib/libmesh_test_rt.a": "9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33",
}
SUBJECTS = {
    "DateTime.to_unix_ms", "DateTime.utc_now", "Host.push_get_token", "Http.url_origin",
    "Sqlite.begin", "Sqlite.close", "Sqlite.commit", "Sqlite.execute", "Sqlite.execute_values",
    "Sqlite.execute_values_v2", "Sqlite.open", "Sqlite.query_values", "Sqlite.query_values_v2",
    "Sqlite.rollback", "StorageKey.index_tag", "StorageKey.platform", "StorageKey.unseal_bytes",
    "seal public metadata", "unknown function value",
}


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    product, output = args.product.resolve(), args.output.resolve()
    repo = product.parent
    language = (repo / "mesh-lang").resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    sources = output / "sources"
    sources.mkdir()
    (sources / "mesh-lang").symlink_to(language, target_is_directory=True)
    fixtures = Path(__file__).parent / "fixtures/decoded-body"
    fixture = fixtures / "invitation-authority.mpl"
    patch = fixtures / "held-invitation-policy.patch"
    record = {"status": "running", "baseline": BASELINE, "runner_sha256": sha(Path(__file__)),
              "fixture_sha256": sha(fixture), "held_patch_sha256": sha(patch),
              "scope": "Historical actual-public-API counterexample; the held policy is not approved or applied to production, and corrected receive adoption needs separate qualification.",
              "execution": "compiler only; no generated program or network operation executes",
              "sources": {}, "runs": []}
    evidence = output / "evidence.json"

    def save():
        evidence.write_text(json.dumps(record, indent=2) + "\n")

    def language_hashes():
        return {str(path): sha(path) for name in ("mesh-binary", "mesh-solana", "mesh-lightning")
                for path in sorted((language / "packages" / name).rglob("*"))
                if path.is_file() and path.suffix in (".mpl", ".toml", ".lock")}

    try:
        record["toolchain"] = {name: sha(TOOLCHAIN / name) for name in PINS}
        if record["toolchain"] != PINS:
            raise RuntimeError("toolchain pin mismatch")
        record["language_before"] = language_hashes()
        for package in ("packages/mobile-core", "packages/messenger-protocol"):
            prefix = str((product / package).relative_to(repo))
            paths = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-r", "--name-only",
                                             BASELINE, "--", prefix], text=True).splitlines()
            for name in paths:
                if Path(name).suffix not in (".mpl", ".toml", ".lock"):
                    continue
                data = subprocess.check_output(["git", "-C", str(repo), "show", BASELINE + ":" + name])
                target = sources / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                record["sources"][name] = hashlib.sha256(data).hexdigest()
        probe = output / "probe"
        probe.mkdir()
        source = probe / "main.mpl"
        shutil.copyfile(fixture, source)
        mobile = sources / product.relative_to(repo) / "packages/mobile-core"
        (probe / "mesh.toml").write_text('[package]\nname="invitation-authority-proof"\nversion="0.1.0"\n'
                                        '[dependencies]\nmobile={path=' + json.dumps(str(mobile)) + '}\n')
        owned = mobile / "mobile/group_invites_state.mpl"
        original = owned.read_bytes()
        env = os.environ | {"TMPDIR": str(output / "tmp"),
                            "MESH_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_rt.a"),
                            "MESH_TEST_RT_LIB_PATH": str(TOOLCHAIN / "lib/libmesh_test_rt.a")}
        for name in ("original-refuses", "held-prototype-admits"):
            if name == "held-prototype-admits":
                subprocess.run(["git", "apply", "--unsafe-paths", "--directory=" + str(sources), str(patch)],
                               check=True, cwd=repo)
            directory = output / name
            directory.mkdir()
            shutil.copyfile(source, directory / "main.mpl.source")
            shutil.copyfile(owned, directory / "group_invites_state.mpl.source")
            before = {str(path): sha(path) for path in sources.rglob("*.mpl") if not path.is_symlink()}
            (directory / "source-hashes.json").write_text(json.dumps(before, indent=2) + "\n")
            artifact = directory / "libproof.a"
            command = [str(TOOLCHAIN / "bin/meshc"), "build", "--json", str(probe), "--artifact", "staticlib",
                       "--plaintext-report", str(directory / "plaintext.json"), "-o", str(artifact)]
            start = time.monotonic()
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=300)
            log = result.stdout + result.stderr
            (directory / "build.log").write_text(log)
            items = []
            for line in log.splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("code") and item["code"] != "C0001":
                    items.append(item)
            stable = all(sha(Path(path)) == digest for path, digest in before.items())
            record["runs"].append({"name": name, "command": command, "exit_code": result.returncode,
                                    "seconds": round(time.monotonic() - start, 3), "diagnostics": items,
                                    "source_stable": stable,
                                    "files": {path.name: sha(path) for path in directory.iterdir() if path.is_file()}})
            save()
            print(name, result.returncode, len(items), flush=True)
            if not stable:
                raise RuntimeError("snapshot changed during compilation")
            if name == "original-refuses":
                data = source.read_bytes()
                location = data.index(b"received_invitation_writes(", data.index(b"fn invitation_private_input"))
                if result.returncode == 0 or artifact.exists() or len(items) != len(SUBJECTS):
                    raise RuntimeError("original public API did not refuse all expected private-input effects")
                observed = set()
                for item in items:
                    if (item["code"] != "E0093" or item.get("file") != str(source)
                            or not any(span["start"] <= location < span["end"] for span in item.get("spans", []))):
                        raise RuntimeError("unexpected diagnostic subject/location")
                    observed.add(item["message"].split("`")[1])
                if observed != SUBJECTS:
                    raise RuntimeError("private-input effect subjects changed")
            elif result.returncode != 0 or not artifact.exists() or items:
                raise RuntimeError("held prototype did not reproduce the unsafe acceptance")
        owned.write_bytes(original)
        record["toolchain_stable"] = all(sha(TOOLCHAIN / name) == digest for name, digest in PINS.items())
        record["language_stable"] = language_hashes() == record["language_before"]
        record["snapshot_restored"] = all(sha(sources / name) == digest for name, digest in record["sources"].items())
        if not all(record[key] for key in ("toolchain_stable", "language_stable", "snapshot_restored")):
            raise RuntimeError("toolchain, dependency or restored snapshot drift")
        record["status"] = "passed"
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
