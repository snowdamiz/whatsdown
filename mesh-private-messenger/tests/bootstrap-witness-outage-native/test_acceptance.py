import importlib.util
from pathlib import Path
import os
from types import SimpleNamespace
import threading
import unittest

source = Path(__file__).with_name('acceptance.py')
spec = importlib.util.spec_from_file_location('outage_acceptance', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class AbiDeadlineTest(unittest.TestCase):
    def test_partial_native_line_cannot_outlive_deadline(self):
        read_fd, write_fd = os.pipe()
        native = module.Native.__new__(module.Native)
        native.pending = b''
        native.process = SimpleNamespace(stdout=os.fdopen(read_fd, 'rb', buffering=0), poll=lambda: None)
        failures = []
        def read():
            try:
                native.read(.05)
            except BaseException as error:
                failures.append(error)
        worker = threading.Thread(target=read)
        os.write(write_fd, b'{"ready":')
        worker.start()
        worker.join(.25)
        bounded = not worker.is_alive()
        os.write(write_fd, b'true}\n')
        worker.join(1)
        os.close(write_fd)
        native.process.stdout.close()
        self.assertTrue(bounded, 'partial ABI line bypassed the response deadline')
        self.assertTrue(any(isinstance(error, TimeoutError) for error in failures), failures)

if __name__ == '__main__': unittest.main()
