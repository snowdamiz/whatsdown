#!/usr/bin/env python3
"""Small native host proofs; no Mesh build, Keychain, network or activation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    ios = root / "mesh-private-messenger/apps/mobile/modules/mesh-messenger/ios"
    desktop = root / "mesh-private-messenger/apps/desktop/src-tauri/src/desktop_lock"
    common = [ios / name for name in (
        "MeshMessengerAppLockPolicy.swift", "MeshMessengerAppLock.swift",
        "MeshMessengerProtectedFiles.swift", "MeshMessengerLockedNotifications.swift",
        "MeshMessengerNativeRetirement.swift",
        "MeshMessengerDataProtection.swift")]
    receipts = []

    def run(name, command, expected=0):
        result = subprocess.run([str(part) for part in command], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=45)
        log = output / (name + ".log")
        log.write_text(result.stdout)
        receipts.append({"name": name, "command": [str(part) for part in command],
                         "exit": result.returncode, "expected": expected,
                         "log_sha256": digest(log)})
        if result.returncode != expected:
            raise RuntimeError(f"{name}: exit {result.returncode}, expected {expected}\n{result.stdout}")
        return result.stdout

    def swift(name, sources):
        binary = output / name
        run(name + "-compile", ["xcrun", "swiftc", *sources, "-o", binary])
        return binary

    retirement_test = ios / "Tests/MeshMessengerRetirementTests.swift"
    source = common[-1].read_text()
    green_dispatch = ("if Thread.isMainThread { retire() }\n"
                      "    else { DispatchQueue.main.async(execute: retire) }")
    if source.count(green_dispatch) != 1:
        raise RuntimeError("retirement dispatcher changed; review the negative control")
    red_source = output / "DataProtection-red-control.swift"
    red_source.write_text(source.replace(green_dispatch, "DispatchQueue.main.async(execute: retire)"))
    red = swift("retirement-red-control", [*common[:-1], red_source, retirement_test])
    red_log = run("retirement-red-control", [red], expected=1)
    if red_log.count("FAIL Main ") != 2 or "RESULT 1/3" not in red_log:
        raise RuntimeError("negative control did not reproduce both Main retirement delays")
    retirement = swift("retirement", [*common, retirement_test])
    run("retirement", [retirement])
    roots_test = ios / "Tests/MeshMessengerRootBindingTests.swift"
    roots = swift("root-bindings", [*common, roots_test])
    for mode in (None, "startup", "owner-scope", "publication", "headless-admission",
                 "owner-construction", "account-transition", "headless-lifetime"):
        run("root-" + (mode or "bindings"), [roots, *(["--" + mode] if mode else [])])
    lock_test = ios / "Tests/MeshMessengerAppLockTests.swift"
    lock = swift("app-lock", [*common[:2], lock_test])
    run("app-lock", [lock])
    owner_source = desktop / "native/ProcessOwner.m"
    owner_test = desktop / "tests/process_owner_closure.m"
    owner = output / "process-owner"
    run("process-owner-compile", ["xcrun", "clang", "-fobjc-arc", "-fblocks",
                                 "-framework", "Foundation", owner_source, owner_test, "-o", owner])
    run("process-owner", [owner])
    tracked = [*common, retirement_test, roots_test, lock_test, owner_source,
               desktop / "native/ProcessOwner.h", desktop / "native/Policy.h", owner_test,
               Path(__file__).resolve()]
    manifest = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                "scope": "macOS Foundation/Objective-C host; no UIKit/Expo/Android product qualification",
                "sources": {str(path.relative_to(root)): digest(path) for path in tracked},
                "binaries": {path.name: digest(path) for path in (red, retirement, roots, lock, owner)},
                "runs": receipts}
    (output / "receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "receipt": str(output / "receipt.json"), "runs": len(receipts)}))


if __name__ == "__main__":
    main()
