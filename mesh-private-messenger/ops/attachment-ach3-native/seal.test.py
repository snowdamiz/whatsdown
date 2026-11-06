#!/usr/bin/env python3
"""Both checkpoint schemas must preserve exact nonempty source bodies."""
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ach3_seal', HERE / 'seal.py')
seal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seal)


class SnapshotInputsTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.source = Path(self.work.name) / 'main.mpl'
        self.source.write_text('fn main() do nil end\n')
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def manifests(self):
        return [
            {'snapshot_inputs': {str(self.source): self.digest}},
            {'files': {str(self.source): {'sha256': self.digest, 'origin': 'prior source'}}},
        ]

    def test_historical_and_current_source_checkpoints(self):
        for source in self.manifests():
            self.assertEqual(seal.checked_source_inputs(source), {str(self.source): self.digest})

    def test_modified_source_is_never_sealed(self):
        self.source.write_text('changed source\n')
        for source in self.manifests():
            with self.assertRaises(AssertionError):
                seal.checked_source_inputs(source)

    def test_empty_or_conflicting_sources_are_rejected(self):
        for source in [{'snapshot_inputs': {}}, {'files': {}}, {
            'snapshot_inputs': {str(self.source): self.digest},
            'files': {str(self.source): {'sha256': 'other source'}},
        }]:
            with self.assertRaises(AssertionError):
                seal.checked_source_inputs(source)


if __name__ == '__main__':
    unittest.main()
