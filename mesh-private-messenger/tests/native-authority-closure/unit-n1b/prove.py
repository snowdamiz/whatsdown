#!/usr/bin/env python3
"""Small Swift driver only. Accepted retained runtime images are never rebuilt."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
IOS = ROOT / "mesh-private-messenger/apps/mobile/modules/mesh-messenger/ios"
MESH = Path("/Users/andreyyurlov/Documents/dev/mesh-lang")
EVIDENCE = MESH / ".tmp/native-effect-authority/evidence"
BASE = "0d6826b"
SOURCES = ["MeshMessengerAppLockPolicy.swift", "MeshMessengerAppLock.swift",
           "MeshMessengerDataProtection.swift", "MeshMessengerProtectedFiles.swift",
           "MeshMessengerLockedNotifications.swift", "MeshMessengerBackupRequest.swift"]

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["baseline", "green"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    family_path = EVIDENCE / "final-family.json"
    family = json.loads(family_path.read_text())
    source_manifest_path = EVIDENCE / family["source_manifest"]
    assert sha(source_manifest_path) == family["source_manifest_sha256"]
    source_manifest = json.loads(source_manifest_path.read_text())
    for filename, expected in source_manifest["files"].items():
        committed = subprocess.check_output(["git", "show",
            f"9b844dbab34e61f6de575af2b25b0ed0f321059e:{filename}"], cwd=MESH)
        assert hashlib.sha256(committed).hexdigest() == expected, filename
    for filename, value in family["files"].items():
        assert sha(Path(filename)) == value["sha256"], filename
    generated = Path(family["generated_directory"])
    library = generated / "libauthority.dylib"
    header = MESH / "compiler/meshc/src/library_authority.h"
    assert sha(header) == "5bbaf429dbd3749924b041847aba40ce40ee33c5a13a5c97f454601d79f87843"
    assert sha(library) == "1d5af0920725bc0449977060a270393192193b09ce896f96049ce3226299bf5d"
    receipt = dict(phase=args.phase, baseline=BASE, runtime_pin="9b844dbab34e61f6de575af2b25b0ed0f321059e",
                   family_sha256=sha(family_path), verified_retained_files=len(family["files"]),
                   runtime_source_manifest_sha256=sha(source_manifest_path),
                   verified_pinned_runtime_sources=len(source_manifest["files"]),
                   header_sha256=sha(header), library_sha256=sha(library), mask=1, runs=[],
                   scope="Foundation native lifetime ports + production RootBindings/retirement + actual generated HTTP/SQLite",
                   unqualified=["UIKit/Expo actual owner/sentinel destruction", "iOS device/simulator runtime",
                                "native policy", "complete effects", "scheduler progress", "publication", "product activation"])
    def run(name, command, expected=0):
        command = [str(x) for x in command]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=90)
        log = out / (name + ".log")
        log.write_text(result.stdout)
        receipt["runs"].append(dict(name=name, command=command, exit=result.returncode,
                                    expected=expected, log_sha256=sha(log)))
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        assert result.returncode == expected, f"{name}: {result.stdout}"
        print(f"{name}: exit {result.returncode}", flush=True)
    sources = [IOS / name for name in SOURCES]
    if args.phase == "baseline":
        original = out / "MeshMessengerDataProtection.swift"
        original.write_bytes(subprocess.check_output(["git", "show", f"{BASE}:{sources[2].relative_to(ROOT)}"], cwd=ROOT))
        sources[2] = original
    else:
        sources.append(IOS / "MeshMessengerNativeRetirement.swift")
    driver = out / "native-lifetime.dylib"
    args_compile = ["xcrun", "swiftc", "-swift-version", "5", "-emit-library",
                    *sources, HERE / "native_lifetime.swift", "-o", driver]
    if args.phase == "baseline":
        args_compile[2:2] = ["-D", "N1B_BASELINE", "-import-objc-header", generated / "libauthority.h",
                            "-L", generated, "-lauthority", "-Xlinker", "-rpath", "-Xlinker", generated]
    receipt["sources"] = {str(p): sha(p) for p in [*sources, HERE / "native_lifetime.swift", HERE / "image_lifetime.swift", HERE / "check.py", Path(__file__)]}
    run("driver-compile", args_compile)
    receipt["driver_sha256"] = sha(driver)
    for case in ["control", "owner", "sentinel", *(["owner-main", "sentinel-main", "capture-owner", "same-root-sentinel", "same-root-stale-capture"] if args.phase == "green" else [])]:
        expected = 1 if args.phase == "baseline" and case != "control" else 0
        run(case, ["python3", "-B", HERE / "check.py", library, driver, case,
                   *(["--baseline"] if args.phase == "baseline" else [])], expected)
        if expected:
            assert "off-Main original lifetime did not retire before teardown returned" in (out / (case + ".log")).read_text()
    if args.phase == "green":
        sdk = subprocess.check_output(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"], text=True).strip()
        run("runtime-platform", ["xcrun", "vtool", "-show-build", library])
        run("ios-support-typecheck", ["xcrun", "--sdk", "iphonesimulator", "swiftc", "-swift-version", "5",
            "-typecheck", "-sdk", sdk, "-target", "arm64-apple-ios16.4-simulator",
            "-module-cache-path", out.parent / "ios-module-cache", IOS / "MeshMessengerNativeRetirement.swift"])
        run("image-lifetime-compile", ["xcrun", "swiftc", "-swift-version", "5",
            IOS / "MeshMessengerNativeRetirement.swift", HERE / "image_lifetime.swift", "-o", out / "image-lifetime"])
        run("image-lifetime", [out / "image-lifetime", library])
        for test in ["MeshMessengerAppLockTests", "MeshMessengerRootBindingTests", "MeshMessengerRetirementTests"]:
            binary = out / test
            run(test + "-compile", ["xcrun", "swiftc", "-swift-version", "5", *sources,
                                    IOS / "Tests" / (test + ".swift"), "-o", binary])
            run(test, [binary])
            if test == "MeshMessengerRootBindingTests":
                for mode in ["startup", "owner-scope", "publication", "headless-admission",
                             "owner-construction", "account-transition", "headless-lifetime"]:
                    run(test + "-" + mode, [binary, "--" + mode])
    receipt["result"] = "EXPECTED_RED" if args.phase == "baseline" else "PASS"
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["result"], flush=True)

if __name__ == "__main__": main()
