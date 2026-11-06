#!/usr/bin/env python3
"""Reject proof builds whose helpers or production closure differ from review."""
from copy import deepcopy
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ach3_build', HERE / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class FixtureReportTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.driver = Path(self.work.name)
        (self.driver / 'main.mpl').write_text('from MobileCore import initialize\n')
        (self.driver / 'fixture').mkdir()
        (self.driver / 'fixture/legacy.mpl').write_text('# synthetic legacy writer\n')

    def report(self, count):
        modules = [{
            'module': name, 'file': file,
            'source_sha256': hashlib.sha256((self.driver / file).read_bytes()).hexdigest(),
            'sites': [],
        } for name, file in [('Main', 'main.mpl'), ('Fixture.Legacy', 'fixture/legacy.mpl')]]
        production = {'module': 'Attachments.Protocol', 'file': 'attachments/protocol.mpl',
                      'source_sha256': 'canonical source',
                      'sites': [{'kind': 'declassify', 'reason': str(i)} for i in range(count)]}
        return {'modules': modules + [deepcopy(production)]}, {'modules': [production]}

    def test_accepts_exact_old_and_successor_review(self):
        for count in [22, 27]:
            with self.subTest(count=count):
                actual, canonical = self.report(count)
                build.verify_fixture_modules(actual, canonical, self.driver)

    def test_requires_every_production_module_and_exact_source(self):
        for mutation in ['missing', 'hash', 'site']:
            with self.subTest(mutation=mutation):
                actual, canonical = self.report(22)
                if mutation == 'missing':
                    actual['modules'].pop()
                elif mutation == 'hash':
                    actual['modules'][-1]['source_sha256'] = 'substituted source'
                else:
                    actual['modules'][-1]['sites'][0]['reason'] = 'unreviewed'
                with self.assertRaises(AssertionError):
                    build.verify_fixture_modules(actual, canonical, self.driver)

    def test_requires_each_exact_helper_with_no_disclosure(self):
        for mutation in ['missing', 'duplicate', 'path', 'hash', 'site']:
            with self.subTest(mutation=mutation):
                actual, canonical = self.report(22)
                if mutation == 'missing':
                    actual['modules'].pop(0)
                elif mutation == 'duplicate':
                    actual['modules'].append(deepcopy(actual['modules'][0]))
                elif mutation == 'path':
                    actual['modules'][0]['file'] = 'other.mpl'
                elif mutation == 'hash':
                    actual['modules'][0]['source_sha256'] = 'substituted helper'
                else:
                    actual['modules'][0]['sites'] = [{'kind': 'declassify'}]
                with self.assertRaises(AssertionError):
                    build.verify_fixture_modules(actual, canonical, self.driver)


class BuildOptimizationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.work = self.root / 'proof'
        self.toolchain = self.root / 'toolchain'
        (self.toolchain / 'compiler').mkdir(parents=True)
        (self.toolchain / 'compiler/meshc').write_bytes(b'owned compiler fixture')
        for target in ['aarch64-apple-ios-sim', 'aarch64-linux-android']:
            path = self.toolchain / 'runtime' / target
            path.mkdir(parents=True)
            (path / 'libmesh_rt.a').write_bytes(b'owned runtime fixture')
        self.exports = [{'symbol': 'production_' + str(i)} for i in range(162)]
        self.abi = self.root / 'abi.json'
        self.abi.write_text(json.dumps({'exports': self.exports}))
        self.report = self.root / 'report.json'
        self.report.write_text(json.dumps({'modules': []}))
        self.commands = []

    def compile(self, command, **kwargs):
        # Simulate the compiler boundary, retaining exactly the command used.
        self.commands.append(command)
        artifact = Path(command[command.index('--output') + 1])
        artifact.write_bytes(b'owned native artifact fixture')
        exports = self.exports + [{'symbol': 'mesh_ach3_fixture_' + str(i)} for i in range(6)]
        artifact.with_suffix('.abi.json').write_text(json.dumps({'exports': exports}))
        driver = self.work / 'driver'
        modules = [{'module': name, 'file': str(path.relative_to(driver)),
                    'source_sha256': build.sha(path), 'sites': []}
                   for name, path in [('Main', driver / 'main.mpl'),
                                      ('Fixture.Legacy', driver / 'fixture/legacy.mpl')]]
        Path(str(artifact) + '.plaintext.json').write_text(json.dumps({'modules': modules}))

    def invoke(self, *extra):
        args = ['build.py', '--work', str(self.work), '--closure', str(self.root / 'closure'),
                '--toolchain', str(self.toolchain), '--baseline-report', str(self.report),
                '--baseline-abi', str(self.abi), *extra]
        with patch.object(sys, 'argv', args), patch.object(build.subprocess, 'run', self.compile):
            build.main()

    def test_explicit_padded_selection_preserves_exact_163_abi_and_verification(self):
        self.exports = [{'symbol': 'production_' + str(i)} for i in range(163)]
        self.abi.write_text(json.dumps({'exports': self.exports}))
        self.invoke('--wire-profile', '4', '--expected-production-exports', '163',
                    '--opt-level', '2', '--jobs', '1')
        for record in json.loads((self.work / 'builds.json').read_text()):
            self.assertEqual(record['wire_profile'], 4)
            self.assertEqual(record['production_exports_unchanged'], 163)
        self.commands.clear()
        self.invoke('--verify-only', '--jobs', '1')
        self.assertEqual(self.commands, [])
        before = {str(p): p.read_bytes() for p in self.work.rglob('*.json')}
        with self.assertRaises((ValueError, AssertionError, SystemExit)):
            self.invoke('--verify-only', '--wire-profile', '3',
                        '--expected-production-exports', '162', '--jobs', '1')
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.work.rglob('*.json')})

    def test_requested_optimization_reaches_both_compiler_calls_and_evidence(self):
        self.invoke('--opt-level', '2', '--jobs', '1')
        self.assertEqual(len(self.commands), 2)
        for command in self.commands:
            self.assertEqual(command[command.index('--opt-level') + 1], '2')
        for record in json.loads((self.work / 'builds.json').read_text()):
            self.assertEqual(record['opt_level'], 2)
            self.assertIn(record['command'], self.commands)
        original = deepcopy(self.commands)
        self.commands.clear()
        self.invoke('--verify-only', '--jobs', '1')
        self.assertEqual(self.commands, [])
        for record in json.loads((self.work / 'builds.json').read_text()):
            self.assertEqual(record['opt_level'], 2)
            self.assertIn(record['command'], original)

    def test_verify_cannot_relabel_an_artifact_with_another_optimization(self):
        self.invoke('--opt-level', '0', '--jobs', '1')
        before = {str(p): p.read_bytes() for p in self.work.rglob('*.json')}
        self.commands.clear()
        with self.assertRaisesRegex(ValueError, 'optimization'):
            self.invoke('--verify-only', '--opt-level', '2', '--jobs', '1')
        self.assertEqual(self.commands, [])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.work.rglob('*.json')})


if __name__ == '__main__':
    unittest.main()
