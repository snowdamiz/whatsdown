#!/usr/bin/env python3
"""Real production owner -> retained generated ABI -> loopback / SQLite sinks."""
import ctypes as C
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading

lib = C.CDLL(sys.argv[1], mode=C.RTLD_GLOBAL)
native = C.CDLL(sys.argv[2])
case = sys.argv[3]
baseline = "--baseline" in sys.argv
observe_disposal = "--observe-disposal" in sys.argv
P, U, I = C.c_void_p, C.c_uint64, C.c_int32


class Bytes(C.Structure):
    _fields_ = [("data", P), ("len", U)]


def api(source, name, args, result=I):
    fn = getattr(source, name)
    fn.argtypes, fn.restype = args, result
    return fn


def runtime(name, args, result=I):
    return api(lib, name, args, result)


def wait(event):
    assert event.wait(8), "barrier timeout (not settlement)"


def report(event, **values):
    print(json.dumps({"event": event, **values}), flush=True)


create_domain = runtime("mesh_authority_domain_create_v2", [C.POINTER(P)])
new_node = runtime("mesh_authority_generation_v2", [P, C.POINTER(P)])
bind = runtime("mesh_authority_bind_v2", [P, C.POINTER(P), U, P, C.POINTER(P)])
local = runtime("mesh_authority_local_inflight_v2", [P], U)
scoped = runtime("mesh_library_call_scoped_v2", [P, P, P, U, C.POINTER(Bytes)])
free = runtime("mesh_library_free_returned_bytes", [C.POINTER(Bytes)], None)
release_authority = runtime("mesh_authority_release_v2", [P], None)
release_domain = runtime("mesh_authority_domain_release_v2", [P], None)
create_owner = api(native, "n1a_create", [C.c_char_p, P], P)
current = api(native, "n1a_current", [P])
duplicate = api(native, "n1a_duplicate", [P])
close_owner = api(native, "n1a_close", [P], None)
release_owner = api(native, "n1a_release", [P], None)
anchor_refuses = api(native, "n1a_anchor_refuses", [P])

assert runtime("mesh_library_capabilities_v2", [], U)() == 1
assert runtime("mesh_library_enable_protected_v2", [U])(1) == 0
assert runtime("mesh_library_init", [])() == 0
domain, node, authority = P(), P(), P()
assert create_domain(C.byref(domain)) == 0
assert new_node(domain, C.byref(node)) == 0
assert bind(domain, (P * 1)(node), 1, None, C.byref(authority)) == 0
ready, resume = threading.Event(), threading.Event()
requests, results = [], []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        requests.append(self.path)
        if self.path == "/hold":
            ready.set()
            wait(resume)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{server.server_port}"


def invoke(symbol, payload):
    out = Bytes()
    result = scoped(authority, C.cast(getattr(lib, symbol), P), payload,
                    len(payload), C.byref(out))
    results.append((result, C.string_at(out.data, out.len) if out.len else b""))
    free(C.byref(out))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observe_retirement():
    probe = P()
    status = bind(domain, (P * 1)(node), 1, None, C.byref(probe))
    if probe:
        release_authority(probe)
    report("original-node-bind-after-loss", status=status)
    if not baseline:
        assert status == 10, "original node was not retired before false/close returned"


def flockable(path):
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    finally:
        os.close(fd)


with tempfile.TemporaryDirectory(prefix="n1a-") as directory:
    base = Path(directory)
    owner_path = base / "owner"
    owner_path.mkdir(mode=0o700)
    owner = create_owner(os.fsencode(owner_path), node)
    assert owner and current(owner) and duplicate(owner)
    if observe_disposal:
        api(native, "n1a_watch_closes", [], None)()
    dbpath = base / "effects.db"
    with sqlite3.connect(dbpath) as db:
        db.execute("CREATE TABLE effects (body TEXT)")
    before = digest(dbpath)
    accepted = case == "accepted-commit"
    if accepted:
        CommitHook = C.CFUNCTYPE(I, P)
        AutoExtension = C.CFUNCTYPE(I, P, P, P)

        @CommitHook
        def commit_hook(_):
            report("actual-admitted-commit-hook", local_inflight=local(node))
            ready.set()
            wait(resume)
            return 0

        @AutoExtension
        def extension(db, error, routines):
            runtime("sqlite3_commit_hook", [P, CommitHook, P], P)(db, commit_hook, None)
            return 0

        assert runtime("sqlite3_auto_extension", [AutoExtension])(extension) == 0
    send = case.endswith("-send")
    symbol = "authority_http" if send else "authority_sql"
    payload = (f"{url}/hold\n{url}/later" if send else
               f"{dbpath}\n{'accepted-commit' if accepted else 'write'}\n{url}/hold").encode()
    worker = threading.Thread(target=invoke, args=(symbol, payload))
    worker.start()
    wait(ready)
    report("held-real-commit" if accepted else "held-real-http",
           local_inflight=local(node), db_sha256=before)
    assert local(node) > 0 if accepted else local(node) == 0
    held_at_close = None
    if case in ["accepted-commit", "http-close"]:
        close_owner(owner)
        assert not current(owner) and not duplicate(owner)
        observe_retirement()
        held_at_close = not flockable(owner_path / "process-owner.v1")
        report("close-return-before-barrier-release", held_flock=held_at_close,
               local_inflight=local(node))
        if not accepted:
            assert not held_at_close, "HTTP retained OS exclusion"
        if observe_disposal:
            assert api(native, "n1a_close_count", [])() == (0 if accepted else 2)
    elif case != "control":
        is_directory = case.startswith("directory")
        original = owner_path if is_directory else owner_path / "process-owner.v1"
        retired = base / "old-owner" if is_directory else owner_path / "old-lock"
        original.rename(retired)
        if is_directory:
            original.mkdir(mode=0o700)
        observe = duplicate if "duplicate" in case else current
        assert not observe(owner)
        report("actual-false-return", observer=observe.__name__)
        observe_retirement()
        old_lock = retired / "process-owner.v1" if is_directory else retired
        assert not flockable(old_lock), "old inode exclusion lost"
        new_lock = owner_path / "process-owner.v1"
        fd = os.open(new_lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        assert flockable(new_lock), "replacement inode not independently flockable"
        assert anchor_refuses(owner), "old anchor accepted unlocked replacement"
        if "restore" in case:
            new_lock.unlink()
            if is_directory:
                original.rmdir()
            retired.rename(original)
            report("restored-path", current=bool(current(owner)), duplicate=bool(duplicate(owner)))
            if not baseline:
                assert not current(owner) and not duplicate(owner)
    resume.set()
    worker.join(8)
    assert not worker.is_alive()
    with sqlite3.connect(dbpath) as db:
        rows = db.execute("SELECT body FROM effects").fetchall()
    report("sink-result", rows=rows, requests=requests, status=results[0][0],
           before_sha256=before, after_sha256=digest(dbpath))
    if observe_disposal:
        assert api(native, "n1a_wait_disposed", [])() == 1
        assert local(node) == 0 and flockable(owner_path / "process-owner.v1")
        report("post-settlement-original-descriptors-closed", count=api(native, "n1a_close_count", [])())
    close_owner(owner)
    release_owner(owner)
    release_authority(authority)
    release_domain(domain)
    server.shutdown()
    assert runtime("mesh_library_shutdown", [])() == 0
    if accepted:
        assert rows == [("staged",)] and results[0][0] == (0 if baseline else 10)
        assert held_at_close, "close released OS exclusion before admitted commit settled"
    elif case == "control":
        assert rows == [("later",)] and results[0][0] == 0
    else:
        assert rows == [] and requests == ["/hold"] and results[0][0] == 10, \
            "observed ProcessOwner loss did not retire the original runtime generation"
    report("PASS", case=case)
