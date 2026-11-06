"""Disposable native ABI host. No messenger signing, verification or cache writes."""
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import struct
import sys


class Bytes(c.Structure):
    _fields_ = [('data', c.c_void_p), ('len', c.c_uint64)]


Callback = c.CFUNCTYPE(c.c_int32, c.c_void_p, c.c_void_p, c.c_uint64,
                      c.c_void_p, c.c_uint64, c.POINTER(c.c_uint64))


class Callbacks(c.Structure):
    _fields_ = [('version', c.c_uint32), ('size', c.c_uint32),
                ('context', c.c_void_p), ('calls', Callback * 9)]


def main():
    library_path, root, custody = map(Path, sys.argv[1:])
    custody.mkdir(mode=0o700, exist_ok=True)
    library = c.CDLL(str(library_path))
    bridge = c.CDLL(str(library_path.with_name('libbootstrap_host' + library_path.suffix)))
    bridge.bootstrap_host_callbacks_size.restype = c.c_size_t
    assert bridge.bootstrap_host_callbacks_size() == c.sizeof(Callbacks)
    bridge.bootstrap_host_call.argtypes = [c.c_char_p, c.c_void_p, c.c_uint64, c.POINTER(Bytes)]
    bridge.bootstrap_host_call.restype = c.c_int32
    library.mesh_library_free_returned_bytes.argtypes = [c.POINTER(Bytes)]
    abi = json.loads(library_path.with_suffix('.abi.json').read_text())
    symbols = {row['symbol'] for row in abi['exports']}
    errors = []

    def host(operation):
        def call(_context, pointer, length, output, capacity, output_length):
            output_length[0] = 0
            try:
                data = c.string_at(pointer, length)
                if operation == 1:
                    size = struct.unpack('>I', data[:4])[0]
                    if not 0 < size < len(data) - 4:
                        return 1
                    path = custody / hashlib.sha256(data[4:4 + size]).hexdigest()
                    temporary = path.with_suffix('.tmp')
                    temporary.write_bytes(data[4 + size:])
                    temporary.chmod(0o600)
                    temporary.replace(path)
                    result = b''
                elif operation in (2, 3):
                    path = custody / hashlib.sha256(data).hexdigest()
                    if not path.exists():
                        return 2
                    result = path.read_bytes() if operation == 2 else b''
                    if operation == 3:
                        path.unlink()
                elif operation == 4:
                    if data == b'messenger/rpc-tls-roots/v1':
                        result = bytes([1, 0])
                        assert capacity >= len(result)
                        c.memmove(output, result, len(result))
                        output_length[0] = len(result)
                        return 0
                    resource = {b'messenger/config/v1': 'security',
                                b'messenger/network/v1': 'network',
                                b'messenger/ohttp/v1': 'ohttp'}.get(data)
                    if resource is None or not (root / resource).exists():
                        return 2
                    result = (root / resource).read_bytes()
                else:
                    return 2
                if len(result) > capacity:
                    return 4
                c.memmove(output, result, len(result))
                output_length[0] = len(result)
                return 0
            except Exception as error:
                errors.append(type(error).__name__)
                return 5
        return Callback(call)

    callbacks = Callbacks(1, c.sizeof(Callbacks), None,
                          (Callback * 9)(*[host(i) for i in range(1, 10)]))
    assert library.mesh_library_init() == 0
    assert library.mesh_library_register_host_callbacks(c.byref(callbacks)) == 0
    try:
        print(json.dumps({'ready': True}), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            symbol = request['symbol']
            assert symbol in symbols
            value = bytes.fromhex(request['hex'])
            output = Bytes()
            code = bridge.bootstrap_host_call(symbol.encode(), value, len(value), c.byref(output))
            try:
                result = c.string_at(output.data, output.len)
            finally:
                library.mesh_library_free_returned_bytes(c.byref(output))
            print(json.dumps({'code': code, 'hex': result.hex(), 'host_errors': errors}), flush=True)
    finally:
        assert library.mesh_library_shutdown() == 0


if __name__ == '__main__':
    os.umask(0o077)
    main()
