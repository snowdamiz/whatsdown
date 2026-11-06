#!/usr/bin/env python3
"""Read-only, hash-pinned local SBF fixture fetch; never signs or submits a packet."""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import urllib.request

PRODUCT = Path(__file__).resolve().parents[2]
SOURCE = json.loads((PRODUCT / "ops/token/dex-source.json").read_text())
DIRECTORY = Path(os.environ.get("MORSE_TOKEN_DEX_BIN_DIR", PRODUCT.parent / ".morse/witness-proof/token-dex"))
LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data):
    n = int.from_bytes(data, "big")
    text = ""
    while n:
        n, rem = divmod(n, 58)
        text = ALPHABET[rem] + text
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + text


def fetch(key, request_id):
    request = {"jsonrpc": "2.0", "id": request_id, "method": "getAccountInfo", "params": [key, {"encoding": "base64", "commitment": "finalized"}]}
    message = urllib.request.Request(SOURCE["origin"], data=json.dumps(request).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(message, timeout=30) as response:
        raw = response.read(12 * 1024 * 1024 + 1)
    if len(raw) > 12 * 1024 * 1024:
        raise ValueError("fixture response exceeds bound")
    value = json.loads(raw)
    if value.get("jsonrpc") != "2.0" or type(value.get("id")) is not int or value["id"] != request_id or "error" in value:
        raise ValueError("wrong RPC response")
    result = value["result"]
    row = result["value"]
    if type(result["context"]["slot"]) is not int or result["context"]["slot"] < 0 or type(row["executable"]) is not bool or row["data"][1] != "base64":
        raise ValueError("invalid fixture metadata")
    data = base64.b64decode(row["data"][0], validate=True)
    if base64.b64encode(data).decode() != row["data"][0] or row.get("space", len(data)) != len(data):
        raise ValueError("noncanonical fixture data")
    return result["context"]["slot"], row, data


DIRECTORY.mkdir(parents=True, exist_ok=True)
for row in SOURCE["account_fixtures"]:
    if hashlib.sha256((PRODUCT / row["path"]).read_bytes()).hexdigest() != row["sha256"]:
        raise SystemExit(f"Public account fixture hash mismatch: {row['path']}")
for index, source in enumerate(SOURCE["snapshots"]):
    output = DIRECTORY / (source["name"] + ".so")
    if output.is_file() and hashlib.sha256(output.read_bytes()).hexdigest() == source["elf_sha256"]:
        continue
    _, image, data = fetch(source["program"], 100 + index * 2)
    if image["owner"] != LOADER or not image["executable"] or len(data) != 36 or data[:4] != struct.pack("<I", 2) or b58(data[4:]) != source["program_data"]:
        raise SystemExit("Executable identity/loader mismatch")
    slot, account, data = fetch(source["program_data"], 101 + index * 2)
    if account["owner"] != LOADER or account["executable"] or len(data) < 49 or data[:4] != struct.pack("<I", 3) or data[12] > 1 or struct.unpack_from("<Q", data, 4)[0] > slot or data[45:49] != b"\x7fELF":
        raise SystemExit("ProgramData identity/ELF mismatch")
    elf = data[45:]
    if len(elf) != source["elf_bytes"] or hashlib.sha256(elf).hexdigest() != source["elf_sha256"]:
        raise SystemExit("Qualified external program changed; requalification and explicit pin review are required")
    with tempfile.NamedTemporaryFile(dir=DIRECTORY, prefix=".qualified-", delete=False) as target:
        target.write(elf)
        temporary = Path(target.name)
    temporary.replace(output)
print("Pinned local Jupiter/Raydium SBF fixtures verified; no transaction submitted")
