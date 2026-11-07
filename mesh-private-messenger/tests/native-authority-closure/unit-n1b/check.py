#!/usr/bin/env python3
"""Owned loopback HTTP -> accepted generated SQLite, with Main undrained."""
import ctypes as C
import hashlib
import http.server
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading

P, U, I = C.c_void_p, C.c_uint64, C.c_int32
class Bytes(C.Structure):
    _fields_ = [("data", P), ("len", U)]

lib = C.CDLL(sys.argv[1], mode=C.RTLD_LOCAL)
native = C.CDLL(sys.argv[2], mode=C.RTLD_LOCAL)
case = sys.argv[3]
same_root = case in ["same-root-sentinel", "same-root-stale-capture"]
baseline = "--baseline" in sys.argv
def api(source, name, args, result=I):
    fn = getattr(source, name)
    fn.argtypes, fn.restype = args, result
    return fn
def runtime(name, args, result=I):
    return api(lib, name, args, result)
def report(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)

bind = runtime("mesh_authority_bind_v2", [P, C.POINTER(P), U, P, C.POINTER(P)])
scoped = runtime("mesh_library_call_scoped_v2", [P, P, P, U, C.POINTER(Bytes)])
free = runtime("mesh_library_free_returned_bytes", [C.POINTER(Bytes)], None)
release_authority = runtime("mesh_authority_release_v2", [P], None)
create = api(native, "n1b_create", [C.c_char_p], P)
get_domain = api(native, "n1b_domain", [P], P)
get_node = api(native, "n1b_node", [P, I], P)
drop = api(native, "n1b_drop", [P, I], None)
assert runtime("mesh_library_capabilities_v2", [], U)() == 1
assert runtime("mesh_library_enable_protected_v2", [U])(1) == 0
assert runtime("mesh_library_init", [])() == 0
fixture = create(sys.argv[1].encode())
assert fixture
domain = get_domain(fixture)
if same_root:
    setup = "n1b_stale_capture" if case == "same-root-stale-capture" else "n1b_same_root"
    assert api(native, setup, [P])(fixture) == 1, "capture crossed an original sentinel registration replacement"
    if case == "same-root-stale-capture": report("same-epoch-old-capture-refused-after-sentinel-replacement")
    drop = api(native, "n1b_drop_obsolete", [P, I], None)
node_values = [get_node(fixture, 3 if same_root else 0), get_node(fixture, 2 if same_root else 1)]
if not baseline: node_values.append(get_node(fixture, 5 if same_root else 4))
assert all(node_values)
nodes = (P * len(node_values))(*node_values)
authority = P()
assert bind(domain, nodes, len(nodes), None, C.byref(authority)) == 0
capture = api(native, "n1b_hold_capture", [P], P)(fixture) if case == "capture-owner" else None
if case == "capture-owner": assert capture
ready, resume = threading.Event(), threading.Event()
requests, results = [], []
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        requests.append(self.path)
        if self.path == "/hold":
            ready.set()
            assert resume.wait(8), "HTTP barrier timeout"
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

def invoke(auth, payload):
    out = Bytes()
    status = scoped(auth, C.cast(lib.authority_sql, P), payload, len(payload), C.byref(out))
    results.append(status)
    free(C.byref(out))

with tempfile.TemporaryDirectory(prefix="n1b-") as directory:
    dbpath = Path(directory) / "effects.db"
    with sqlite3.connect(dbpath) as db:
        db.execute("CREATE TABLE effects (body TEXT)")
    before = hashlib.sha256(dbpath.read_bytes()).hexdigest()
    payload = f"{dbpath}\nwrite\nhttp://127.0.0.1:{server.server_port}/hold".encode()
    worker = threading.Thread(target=invoke, args=(authority, payload))
    worker.start()
    assert ready.wait(8), "generated HTTP did not arrive"
    report("real-http-held-main-undrained", case=case, before_sha256=before)
    observed = None
    if case != "control":
        which = 0 if case.startswith("sentinel") else 1
        if case.endswith("-main"):
            api(native, "n1b_drop_main", [P, I], None)(fixture, which)
            assert api(native, "n1b_epoch_unchanged", [P])(fixture) == 0, "Main retirement deferred"
        else:
            teardown = threading.Thread(target=drop, args=(fixture, which))
            teardown.start(); teardown.join(5)
            assert not teardown.is_alive(), "teardown waited for Main or HTTP"
            assert api(native, "n1b_epoch_unchanged", [P])(fixture) == 1, "Main cleanup drained early"
            if capture:
                probe = P()
                assert bind(domain, nodes, len(nodes), None, C.byref(probe)) == 0
                release_authority(probe)
                assert api(native, "n1b_commit_capture", [P, P])(fixture, capture) == 1
                report("actual-capture-retained-original-owner-through-commit")
                release_capture = api(native, "n1b_release_capture", [P], None)
                teardown = threading.Thread(target=release_capture, args=(capture,))
                teardown.start(); teardown.join(5)
                assert not teardown.is_alive(), "last capture release waited for Main"
        probe = P()
        observed = bind(domain, nodes, len(nodes), None, C.byref(probe))
        if probe: release_authority(probe)
        report("native-teardown-returned-before-http", main_cleanup_deferred=not case.endswith("-main"), bind_status=observed)
    resume.set(); worker.join(8)
    assert not worker.is_alive()
    with sqlite3.connect(dbpath) as db:
        rows = db.execute("SELECT body FROM effects").fetchall()
    report("real-sink-result", rows=rows, statuses=results, requests=requests,
           after_sha256=hashlib.sha256(dbpath.read_bytes()).hexdigest())
    if same_root:
        assert observed == 0 and rows == [("later",)] and results == [0], \
            "obsolete same-root sentinel retired successor before Main cleanup"
        assert api(native, "n1b_drain", [P])(fixture) == 1, "stale same-root sentinel cleanup revoked successor"
        invoke(authority, payload)
        with sqlite3.connect(dbpath) as db:
            assert db.execute("SELECT body FROM effects").fetchall() == [("later",), ("later",)]
        assert results == [0, 0]
        report("same-root-successor-reached-real-sink-before-and-after-stale-cleanup")
    elif case != "control" and not baseline:
        assert api(native, "n1b_successor", [P])(fixture) == 1
        fresh = (P * 3)(get_node(fixture, 2), get_node(fixture, 3), get_node(fixture, 5))
        next_authority = P()
        assert bind(domain, fresh, len(fresh), None, C.byref(next_authority)) == 0
        assert api(native, "n1b_drain", [P])(fixture) == 1, "stale Main cleanup revoked successor"
        invoke(next_authority, payload)
        release_authority(next_authority)
        with sqlite3.connect(dbpath) as db:
            successor_rows = db.execute("SELECT body FROM effects").fetchall()
        assert successor_rows == [("later",)] and results == [10, 0]
        report("successor-after-stale-main-cleanup-reached-real-sink", rows=successor_rows)
    release_authority(authority)
    api(native, "n1b_release", [P], None)(fixture)
    server.shutdown()
    assert runtime("mesh_library_shutdown", [])() == 0
    if same_root:
        assert observed == 0
    elif case == "control":
        assert rows == [("later",)] and results == [0]
    else:
        assert observed == 10 and rows == [] and results[0] == 10, \
            "off-Main original lifetime did not retire before teardown returned"
    report("PASS", case=case)
