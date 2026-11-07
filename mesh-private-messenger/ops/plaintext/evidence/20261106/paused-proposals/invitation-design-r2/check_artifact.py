#!/usr/bin/env python3
"""Check patch applicability and bytes inside owned artifacts only; no Mesh build."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
manifest = json.loads((OUT / "source-hashes.json").read_text())
patch = OUT / "invitation-private-boundary.patch"
result = {"scope": "immutable baseline and owned artifact copies only; not live source applicability or compilation",
          "commands": [], "checks": {}}

def run(args):
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    result["commands"].append({"argv": args, "exit_code": proc.returncode,
                               "stdout": proc.stdout, "stderr": proc.stderr})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert sha(patch) == manifest["patch_sha256"]
for name, digest in manifest["base_sha256"].items():
    assert sha(OUT / "base" / name) == digest
    git_bytes = subprocess.check_output(["git", "show", manifest["baseline"] + ":" + name], cwd=ROOT)
    assert hashlib.sha256(git_bytes).hexdigest() == digest
result["checks"]["base_matches_pinned_git_objects"] = True
run(["git", "apply", "--check", "--verbose", "--unsafe-paths",
     "--directory=" + str(OUT / "base"), str(patch)])
result["checks"]["baseline_apply_check"] = True
applied = OUT / "applied-check"
applied.mkdir(exist_ok=False)
for name in manifest["proposed_sha256"]:
    target = applied / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(OUT / "base" / name, target)
run(["git", "apply", "--verbose", "--unsafe-paths",
     "--directory=" + str(applied), str(patch)])
for name, digest in manifest["proposed_sha256"].items():
    assert sha(applied / name) == digest
    assert sha(OUT / "proposed" / name) == digest
result["checks"]["artifact_application_matches_proposal_bytes"] = True
result["checks"]["changed_paths"] = list(manifest["proposed_sha256"])
for name, digest in manifest["base_sha256"].items():
    assert sha(OUT / "base" / name) == digest
result["checks"]["baseline_copies_unchanged"] = True
prefix = "mesh-private-messenger/packages/mobile-core/mobile/"
state = (OUT / "proposed" / (prefix + "group_invites_state.mpl")).read_text()
messages = (OUT / "proposed" / (prefix + "messages.mpl")).read_text()
assert "declassify(" not in state
assert messages.count("authenticated_invitation_writes(") == 3
assert "pub fn authenticated_invitation_writes" not in messages
assert "received_invitation_writes" not in messages
result["checks"]["source_structure_only"] = {
    "new_private_helper_callers": 2, "new_release_sites_in_state_module": 0,
    "new_release_sites_in_private_helper": 3,
    "limits": "Text checks establish placement only; not import privacy, taint propagation, or compiler acceptance."}
result["compiler_run"] = False
result["runtime_run"] = False
result["live_source_apply_check"] = False
result["status"] = "artifact checks passed"
(OUT / "apply-check.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"status": result["status"], "changed_paths": result["checks"]["changed_paths"]}, indent=2))
