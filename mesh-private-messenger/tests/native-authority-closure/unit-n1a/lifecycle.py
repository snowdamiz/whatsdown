#!/usr/bin/env python3
"""Original FD/lifetime observations and actual retained secure-store callbacks."""
import ctypes as C
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

lib = C.CDLL(sys.argv[1], mode=C.RTLD_GLOBAL)
native = C.CDLL(sys.argv[2])
case = sys.argv[3]
P, U, I = C.c_void_p, C.c_uint64, C.c_int32


def api(source, name, args=(), result=I):
    fn = getattr(source, name)
    fn.argtypes, fn.restype = args, result
    return fn


def rt(name, args=(), result=I):
    return api(lib, name, args, result)


def n(name, args=(), result=I):
    return api(native, "n1a_" + name, args, result)


def report(event, **values):
    print(json.dumps({"event": event, **values}), flush=True)


def wait(event):
    assert event.wait(8), "barrier timeout, not settlement"


class Bytes(C.Structure):
    _fields_ = [("data", P), ("len", U)]


Callback = C.CFUNCTYPE(I, P, P, U, P, U, C.POINTER(U))
Lifetime = C.CFUNCTYPE(None, P)


class V1(C.Structure):
    _fields_ = [("abi", C.c_uint32), ("size", C.c_uint32), ("context", P)] + [
        (name, Callback) for name in ["put", "get", "delete", "push", "background",
                                     "network", "monotonic", "wall", "log"]]


class V2(C.Structure):
    _fields_ = [("abi", C.c_uint32), ("size", C.c_uint32), ("callbacks", V1),
                ("retain", Lifetime), ("release", Lifetime)]


ready, resume, host_released = threading.Event(), threading.Event(), threading.Event()
mutations, results, failures, host_lifetime = [], [], [], [0, 0]
domain, node, authority = P(), P(), P()
assert rt("mesh_library_capabilities_v2", result=U)() == 1
assert rt("mesh_library_enable_protected_v2", [U])(1) == 0
assert rt("mesh_library_init")() == 0
assert rt("mesh_authority_domain_create_v2", [C.POINTER(P)])(C.byref(domain)) == 0
assert rt("mesh_authority_generation_v2", [P, C.POINTER(P)])(domain, C.byref(node)) == 0
bind = rt("mesh_authority_bind_v2", [P, C.POINTER(P), U, P, C.POINTER(P)])
local = rt("mesh_authority_local_inflight_v2", [P], U)
release_authority = rt("mesh_authority_release_v2", [P], None)


def node_retired():
    probe = P()
    status = bind(domain, (P * 1)(node), 1, None, C.byref(probe))
    if probe:
        release_authority(probe)
    return status == 10


def available(path):
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    finally:
        os.close(fd)


def closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError as error:
        assert error.errno == 9
        return True


with tempfile.TemporaryDirectory(prefix="n1a-lifetime-") as directory:
    base = Path(directory)
    path = base / "owner"
    path.mkdir(mode=0o700)
    storage = path / "finite-store"

    def host(kind):
        @Callback
        def callback(context, inp, size, out, cap, written):
            try:
                written[0] = 0
                if kind == "network" and case == "close-before-store":
                    ready.set()
                    wait(resume)
                if kind == "put":
                    if case.startswith("accepted-store") or case == "store-control":
                        assert local(node) == 1
                        report("actual-admitted-put-before-write", local_inflight=local(node))
                        ready.set()
                        wait(resume)
                    value = C.string_at(inp, size)
                    with storage.open("wb") as stream:
                        stream.write(value)
                        stream.flush()
                        os.fsync(stream.fileno())
                    mutations.append("put")
                    report("actual-fixture-write-complete", bytes=value.hex())
                if kind == "delete":
                    storage.unlink()
                    mutations.append("delete")
                return 0
            except BaseException as error:
                failures.append(str(error))
                return 90
        return callback

    callbacks = [host(kind) for kind in ["put", "get", "delete", "push", "background",
                                        "network", "monotonic", "wall", "log"]]

    @Lifetime
    def retain(_):
        host_lifetime[0] += 1

    @Lifetime
    def release(_):
        host_lifetime[1] += 1
        host_released.set()

    v1 = V1(1, C.sizeof(V1), None, *callbacks)
    v2 = V2(2, C.sizeof(V2), v1, retain, release)
    create = n("create", [C.c_char_p, P], P)
    if case.startswith("failed-"):
        if case == "failed-directory":
            path.chmod(0o755)
        else:
            (path / "process-owner.v1").write_bytes(b"invalid")
            (path / "process-owner.v1").chmod(0o600)
        owner = create(os.fsencode(path), node)
        assert not owner and n("wait_release")() == 1
        assert n("release_count")() == 1
        assert closed(n("directory_fd")())
        if case == "failed-lock":
            assert closed(n("lock_fd")())
        assert n("total_closes")() == (1 if case == "failed-directory" else 2)
        report("failed-acquire-disposed", closes=n("total_closes")(), node_releases=n("release_count")())
    else:
        owner = create(os.fsencode(path), node)
        assert owner and n("current", [P])(owner)
        assert bind(domain, (P * 1)(node), 1, C.byref(v2), C.byref(authority)) == 0
        assert host_lifetime == [1, 0]
        original_directory, original_lock = n("directory_fd")(), n("lock_fd")()
        caller_duplicate = n("owned_duplicate", [P])(owner)
        assert caller_duplicate >= 0
        n("watch_closes", result=None)()
        report("original-descriptors", directory=original_directory, lock=original_lock)
        close_owner = n("close", [P], None)
        drop_owner = n("drop_owner", [P], None)

        def invoke(selected=None):
            output = Bytes()
            status = rt("mesh_library_call_scoped_v2", [P, P, P, U, C.POINTER(Bytes)])(
                selected or authority, C.cast(lib.authority_store, P), b"exact-finite-write", 18, C.byref(output))
            results.append(status)
            rt("mesh_library_free_returned_bytes", [C.POINTER(Bytes)], None)(C.byref(output))

        if case == "successor":
            close_owner(owner)
            assert n("close_count")() == 2 and node_retired()
            successor_node, successor_authority = P(), P()
            assert rt("mesh_authority_generation_v2", [P, C.POINTER(P)])(domain, C.byref(successor_node)) == 0
            successor = n("successor", [P, P], P)(owner, successor_node)
            assert successor and n("current", [P])(successor)
            assert bind(domain, (P * 1)(successor_node), 1, C.byref(v2), C.byref(successor_authority)) == 0
            for _ in range(3):
                close_owner(owner)
            drop_owner(owner)
            n("release", [P], None)(owner)
            assert n("wait_release")() == 1 and n("release_count")() == 1
            assert n("current", [P])(successor) and not available(path / "process-owner.v1")
            assert n("close_count")() == 2, "stale old cleanup closed a successor FD"
            invoke()
            assert results == [10] and mutations == []
            invoke(successor_authority)
            assert results == [10, 0] and mutations == ["put", "delete"]
            assert os.fstat(caller_duplicate).st_ino == os.stat(path).st_ino
            n("watch_closes", result=None)()
            close_owner(successor)
            assert n("wait_disposed")() == 1
            n("release", [P], None)(successor)
            assert n("wait_release")() == 1 and n("release_count")() == 2
            release_authority(authority)
            release_authority(successor_authority)
            assert host_lifetime == [2, 2]
            os.close(caller_duplicate)
            rt("mesh_authority_domain_release_v2", [P], None)(domain)
            assert rt("mesh_library_shutdown")() == 0
            report("PASS", case=case, old_call=10, successor_call=0, exact_generation_releases=2)
            sys.exit(0)

        if case.startswith("stat-"):
            duplicate = case == "stat-postdup"
            n("arm_stat", [I], None)(2 if duplicate else 1)
            observed = []
            worker = threading.Thread(target=lambda: observed.append(
                n("duplicate" if duplicate else "current", [P])(owner)))
            worker.start()
            assert n("wait_stat")() == 1
            close_owner(owner)
            assert node_retired() and n("close_count")() == 0
            report("close-returned-while-stat-held", node_retired=True, closed_fds=0)
            n("resume_stat", result=None)()
            worker.join(8)
            assert not worker.is_alive()
            assert observed == [0], "in-flight stat returned current after close"
            disposed = n("wait_disposed")()
            report("dispose-observation", disposed=disposed, closes=n("close_count")(), total=n("total_closes")())
            assert disposed == 1
            report("stat-finished-refused", observer="postdup" if duplicate else "current")
        elif case in ["accepted-store", "accepted-store-drop", "accepted-store-detached", "store-control", "close-before-store"]:
            worker = threading.Thread(target=invoke)
            worker.start()
            wait(ready)
            accepted = case.startswith("accepted-store")
            assert local(node) == (1 if accepted or case == "store-control" else 0)
            if case != "store-control":
                if case == "accepted-store-detached":
                    n("drop_link", [P], None)(owner)
                if case in ["accepted-store-drop", "accepted-store-detached"]:
                    drop_owner(owner)
                else:
                    close_owner(owner)
                assert node_retired()
                assert not n("current", [P])(owner) and not n("duplicate", [P])(owner)
                assert available(path / "process-owner.v1") != accepted
                assert n("close_count")() == (0 if accepted else 2)
                report("logical-close-before-write-release", local_inflight=local(node),
                       closed_fds=n("close_count")(), owner_deallocated=case in ["accepted-store-drop", "accepted-store-detached"])
            resume.set()
            worker.join(8)
            assert not worker.is_alive() and not failures
            assert mutations == (["put", "delete"] if case == "store-control" else ["put"] if accepted else [])
            assert results == ([0] if case == "store-control" else [10])
            if accepted:
                assert storage.read_bytes() == b"exact-finite-write"
                if case != "accepted-store-detached":
                    assert local(node) == 0
                assert n("wait_disposed")() == 1
            if case == "store-control":
                assert not node_retired()
                close_owner(owner)
            assert n("wait_disposed")() == 1
            report("settled-and-disposed", mutations=mutations, closed_fds=n("close_count")())
        elif case == "rebind":
            other = base / "other"
            other.mkdir(mode=0o700)
            assert n("rebind_refuses", [P, C.c_char_p])(owner, os.fsencode(other)) == 1
            assert not node_retired() and n("current", [P])(owner)
            assert n("missing_refuses", [C.c_char_p])(os.fsencode(other)) == 1
            invoke()
            assert results == [0] and mutations == ["put", "delete"]
            close_owner(owner)
        else:
            assert case == "zero-close-reuse"
            close_owner(owner)
            assert node_retired() and local(node) == 0
            assert n("close_count")() == 2, "zero-inflight close was not immediate"
        assert n("wait_disposed")() == 1
        assert available(path / "process-owner.v1")
        assert closed(original_directory) and closed(original_lock)
        # A caller's pre-close duplicate remains its own retained descriptor.
        assert os.fstat(caller_duplicate).st_ino == os.stat(path).st_ino
        sentinels = []
        for target in [original_directory, original_lock]:
            assert closed(target)
            fd = os.open(base / f"reuse-{target}", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            if fd != target:
                os.dup2(fd, target)
                os.close(fd)
            sentinels.append((target, os.fstat(target).st_ino))
        for _ in range(3):
            close_owner(owner)
        drop_owner(owner)
        # A late actual generated call has its own resource refs and refuses.
        count = len(mutations)
        invoke()
        assert results[-1] == 10 and len(mutations) == count
        release_authority(authority)
        wait(host_released)
        n("release", [P], None)(owner)
        assert n("wait_release")() == 1 and n("release_count")() == 1
        assert host_lifetime == [1, 1] and n("close_count")() == 2
        for fd, inode in sentinels:
            assert os.fstat(fd).st_ino == inode, "stale close touched reused descriptor"
            os.close(fd)
        os.close(caller_duplicate)
        report("ownership-complete", node_releases=1, host_lifetime=host_lifetime,
               exact_original_closes=2, reused_descriptors_survive=True)
    rt("mesh_authority_domain_release_v2", [P], None)(domain)
    assert rt("mesh_library_shutdown")() == 0
    report("PASS", case=case)
