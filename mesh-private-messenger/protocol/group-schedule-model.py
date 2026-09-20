"""Bounded symbolic knowledge model, Python 3 stdlib; not an app security proof.

Assumptions: perfect HKDF/AEAD/HPKE, authenticated transcripts, fresh independent
update entropy, erased consumed keys, no plaintext history or old backups.
The finite rules model two epochs and three members; no side channels or liveness.
"""
import json
import platform


def knows(initial, rules, target):
    known = set(initial)
    while True:
        more = {output for inputs, output in rules if set(inputs) <= known}
        if more <= known:
            return target in known
        known |= more


def check():
    rules = [
        (("bob-leaf", "commit0"), "path0"),
        (("path0", "init0"), "epoch0"),
        (("epoch0",), "init1"),
        (("epoch0",), "chain0"),
        (("chain0",), "message0"),
        (("chain0",), "chain1"),
        (("message0", "ciphertext0"), "plaintext0"),
        (("bob-join-key", "welcome0"), "epoch0"),
        (("bob-leaf", "alice-update1"), "path1"),
        (("path1", "init1"), "epoch1"),
        (("epoch1", "ciphertext1"), "plaintext1"),
        # Bob's removal excludes his old leaf and shared ancestor keys.
        (("carol-fresh-leaf", "remove-bob2"), "path2"),
        (("path2", "init2"), "epoch2"),
        (("epoch2", "ciphertext2"), "plaintext2"),
    ]
    traffic = {"commit0", "welcome0", "ciphertext0", "alice-update1", "ciphertext1", "remove-bob2", "ciphertext2"}
    current = traffic | {"bob-leaf", "init1", "chain1", "current-tree-keys"}
    assert not knows(current, rules, "plaintext0")
    # Negative controls: retaining either ancestor or the join key breaks erasure.
    assert knows(current | {"epoch0"}, rules, "plaintext0")
    assert knows(current | {"bob-join-key"}, rules, "plaintext0")
    assert knows(current, rules + [(("path0",), "epoch0")], "plaintext0")
    alice_compromise = traffic | {"alice-old-leaf", "alice-old-path-keys", "init1", "chain1"}
    assert not knows(alice_compromise, rules, "plaintext1")
    # Alice alone cannot heal Bob's continuing/stale key compromise.
    assert knows(alice_compromise | {"bob-leaf"}, rules, "plaintext1")
    removed = traffic | {"bob-leaf", "bob-old-path-keys", "init2"}
    assert not knows(removed, rules, "plaintext2")
    assert knows(removed | {"carol-fresh-leaf"}, rules, "plaintext2")
    print(json.dumps({"model": "group-schedule-v2", "tool": f"Python {platform.python_version()}",
                      "properties": ["C3", "C4"], "assertions": 9, "status": "pass"}))


if __name__ == "__main__":
    check()
