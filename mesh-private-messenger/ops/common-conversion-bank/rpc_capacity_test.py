"""Owned fixture accepts a bounded queued request burst before dispatch begins."""
import http.server,importlib.util,socket,threading,unittest
from pathlib import Path

class QueuedProofBurst(unittest.TestCase):
 def test_twelve_queued_owned_requests_survive_before_accept_loop_starts(self):
  source=Path(__file__).resolve().parents[1]/'sol-conversion/fixtures/common_rpc.py'
  spec=importlib.util.spec_from_file_location('owned_common_rpc',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  server_type=getattr(module,'OwnedRPCServer',http.server.ThreadingHTTPServer)
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
  server=server_type(('127.0.0.1',0),Handler);connections=[];thread=None
  try:
   # Deliberately hold the accept loop until the entire small proof burst is
   # queued. This exposes the OS listen capacity, rather than timing Python
   # thread scheduling or relying on the original intermittent client error.
   for _ in range(12):
    connection=socket.create_connection(server.server_address,timeout=.25);connections.append(connection)
    connection.sendall(b'GET / HTTP/1.0\r\nHost: owned.local\r\n\r\n')
   thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
   for connection in connections:
    connection.settimeout(2);body=b''
    while True:
     data=connection.recv(4096)
     if not data:break
     body+=data
    self.assertIn(b'200 OK',body);self.assertTrue(body.endswith(b'ok'))
  finally:
   for connection in connections:connection.close()
   if thread:server.shutdown();thread.join(timeout=3)
   server.server_close()
if __name__=='__main__':unittest.main()
