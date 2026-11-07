#!/usr/bin/env python3
"""Exercise the compiled Core discriminator before any database effect."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("phone", ROOT / "scripts/prove-phone-filing-mpr2.py")
phone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phone)


def packed(*parts):
    return len(parts).to_bytes(4, "big") + phone.vectors(*parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    library, out = args.library.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    identity = bytes([21]) * 32
    operations = {"prepare": [identity, identity], "commit": [identity, bytes(130)],
                  "submit": [identity, bytes([22]) * 64], "recover": [identity], "cancel": [identity]}
    tags = {"unknown": b"\x03BMR", "short": b"\x02BM", "extended": b"\x02BMRx",
            "unknown-extended": b"\x03BMRx", "wrong-magic": b"\x02BAD", "exact-wrong-count": b"\x02BMR"}
    cases = [(f"{operation}-{name}", operation, packed(tag, *fields),
              "invalid_bounty_transfer_request", False)
             for operation, fields in operations.items() for name, tag in tags.items()]
    cases += [(f"status-{name}", "status", packed(tag, b"unused.db"),
               "invalid_bounty_transfer_request", False) for name, tag in tags.items() if name != "exact-wrong-count"]
    cases += [(f"status-raw-{name}", "status", tag, "invalid_bounty_transfer_request", False)
              for name, tag in tags.items()]
    # Ordinary legacy paths, including BMR within a filename, retain legacy semantics.
    cases += [("legacy-prepare", "prepare", packed(b"legacy-BMR.db", bytes([21]) * 32, bytes([22]) * 32),
               "bounty_not_selected", True),
              ("v2-prepare", "prepare", packed(b"\x02BMR", b"mixed.db", b"\x01", bytes([21]) * 32, bytes([22]) * 32),
               "bounty_not_selected", True)]
    for name, operation, request, expected, database_expected in cases:
        work = out / name
        work.mkdir()
        os.chdir(work)
        native = phone.Native(library, work, dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        try:
            try:
                error = native.invoke("mesh_messenger_bounty_transfer_" + operation, request, rejected=True)
            except AssertionError as failure:
                error = "unexpected native response: " + str(failure)
        finally:
            native.close()
        files = sorted(str(path.relative_to(work)) for path in work.rglob("*") if path.is_file())
        passed = error == expected and (bool(files) if database_expected else not files)
        results.append({"case": name, "request_hex": request.hex(), "error": error,
                        "files_created": files, "passed": passed})
    result = {"status": "PASS" if all(row["passed"] for row in results) else "FAIL",
              "library_sha256": phone.sha(library.read_bytes()), "cases": results,
              "scope": "Actual compiled Core with disposable file-backed host callbacks; no SDK or configured RPC."}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "passed": sum(row["passed"] for row in results), "total": len(results)}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
