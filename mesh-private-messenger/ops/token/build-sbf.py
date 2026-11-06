#!/usr/bin/env python3
"""Build each exercised onchain boundary from fresh temporary artifacts."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

product = Path(__file__).resolve().parents[2]
proof = Path(os.environ.get("MORSE_PROOF_DIR", product.parent / ".morse/witness-proof"))
builder = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="morse-token-required-sbf-") as work:
    env = {**os.environ, "CARGO_TARGET_DIR": str(Path(work) / "target")}
    for name, logfile in [("token", "token-sbf-build.log"), ("judge", "token-judge-sbf-build.log"), ("rewards", "token-rewards-sbf-build.log")]:
        path = proof / logfile
        with path.open("w") as log:
            subprocess.run([builder, "--manifest-path", f"programs/morse-{name}-program/Cargo.toml", "--arch", "v0", "--tools-version", "v1.57", "--sbf-out-dir", str(product / "programs/target/deploy"), "--", "--locked"], cwd=product, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        if re.search(r"(^|\s)(Error:|error:|error\[)", path.read_text()):
            raise SystemExit(f"SBF compiler diagnostic in {path}")
