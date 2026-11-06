#!/usr/bin/env python3
"""Ensure small native success frames still leave room for application errors."""
from pathlib import Path
import argparse
import ctypes

class Buffer(ctypes.Structure):
    _fields_ = [('data', ctypes.c_void_p), ('length', ctypes.c_uint64)]

def main(path):
    library = ctypes.CDLL(str(path.resolve()))
    assert library.mesh_library_init() == 0
    library.mesh_library_free_returned_bytes.argtypes = [ctypes.POINTER(Buffer)]
    failures=[]
    try:
        for symbol in ['push_flow_begin','push_flow_validate','account_delete','account_discard','account_capabilities','devices_renew','device_revoke','journal_load_bound','journal_save_bound','fanout_send','backup_pending_repair']:
            invoke=getattr(library,'mesh_messenger_'+symbol)
            invoke.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(Buffer)]
            invoke.restype=ctypes.c_int32
            result=Buffer()
            status=invoke(None,0,ctypes.byref(result))
            body=ctypes.string_at(result.data,result.length) if result.data else b''
            library.mesh_library_free_returned_bytes(ctypes.byref(result))
            expected = b'invalid_backup_native_request' if symbol == 'backup_pending_repair' else None
            if status != 9 or not body or len(body)>4096 or (expected is not None and body != expected):
                failures.append((symbol,status,body))
        assert not failures,failures
        print('11 production C ABI calls preserve bounded application errors')
    finally:
        assert library.mesh_library_shutdown()==0

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('library',type=Path)
    main(parser.parse_args().library)
