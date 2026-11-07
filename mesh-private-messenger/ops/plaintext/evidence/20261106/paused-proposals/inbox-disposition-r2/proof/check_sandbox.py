import errno, json, socket, sys

# No HTTP probe is executed. This checks the kernel denial of a socket connect
# under the same profile used by every build/test. A non-EPERM result fails.
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.settimeout(1)
try:
    sock.connect(('127.0.0.1',9))
except OSError as error:
    denied=error.errno in (errno.EPERM,errno.EACCES)
    print(json.dumps({'network_denied':denied,'errno':error.errno,'message':str(error)}))
    sys.exit(0 if denied else 1)
else:
    print(json.dumps({'network_denied':False,'unexpected_connected':True}))
    sys.exit(1)
finally:
    sock.close()
