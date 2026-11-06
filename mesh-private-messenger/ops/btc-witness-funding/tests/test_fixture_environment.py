"""Exercise the actual handoff environment without starting fixture services."""
import ast
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class FixtureEnvironment(unittest.TestCase):
    def validator(self):
        source = Path(__file__).with_name('qualify.py')
        tree = ast.parse(source.read_text(), filename=str(source))
        nodes = [node for node in tree.body
                 if (isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'PROFILES'
                             for target in node.targets))
                 or (isinstance(node, ast.FunctionDef) and node.name == 'validate_toolchain')]
        namespace = {'hashlib': hashlib}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(source), 'exec'), namespace)
        return namespace['validate_toolchain']

    def test_qualification_tools_survive_a_different_working_directory(self):
        source = Path(__file__).with_name('prove_funding.py')
        tree = ast.parse(source.read_text(), filename=str(source))
        assignment = next(node for node in ast.walk(tree)
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'proofenv'
                                  for target in node.targets))
        executable = compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])),
                             str(source), 'exec')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tools = root / 'qualified-tools'
            tools.mkdir()
            product_cwd = root / 'product-working-directory'
            product_cwd.mkdir()
            work = root / 'owned-proof'
            prior_cwd = Path.cwd()
            try:
                os.chdir(product_cwd)
                with patch.dict(os.environ, {'LIGHTNING_TEST_TOOLS': str(tools)}, clear=True):
                    namespace = {'os': os, 'Path': Path, 'W': work}
                    exec(executable, namespace)
                self.assertEqual(namespace['proofenv']['LIGHTNING_TEST_TOOLS'], str(tools))
                self.assertEqual(namespace['proofenv']['BTC_FIXTURE_PRODUCT'], str(work / 'product'))
            finally:
                os.chdir(prior_cwd)

    def test_exact_profiles_pass_and_mixed_real_binaries_are_refused(self):
        validate = self.validator()
        legacy = Path(os.environ['BTC_TEST_LEGACY_TOOLCHAIN']).resolve()
        fixed = Path(os.environ['BTC_TEST_HTTP10_TOOLCHAIN']).resolve()
        self.assertEqual(set(validate(legacy, 'legacy-hmac')),
                         {'meshc', 'libmesh_rt.a', 'libmesh_test_rt.a'})
        self.assertEqual(set(validate(fixed, 'http10-fixed')),
                         {'meshc', 'libmesh_rt.a', 'libmesh_test_rt.a'})
        with tempfile.TemporaryDirectory() as directory:
            mixed = Path(directory)
            (mixed / 'meshc').symlink_to(fixed / 'meshc')
            (mixed / 'libmesh_rt.a').symlink_to(legacy / 'libmesh_rt.a')
            (mixed / 'libmesh_test_rt.a').symlink_to(fixed / 'libmesh_test_rt.a')
            with self.assertRaisesRegex(AssertionError, 'toolchain pin mismatch'):
                validate(mixed, 'http10-fixed')
            with self.assertRaisesRegex(AssertionError, 'toolchain pin mismatch'):
                validate(mixed, 'legacy-hmac')

    def test_unknown_profile_fails_before_any_tool_or_service_access(self):
        with self.assertRaisesRegex(ValueError, 'unknown toolchain profile'):
            self.validator()(Path('/nonexistent/owned-test-input'), 'unknown')

    def test_inherited_cargo_cache_cannot_redirect_qualification_builds(self):
        source = Path(__file__).with_name('qualify.py')
        tree = ast.parse(source.read_text(), filename=str(source))
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'ENV'
                                  for target in node.targets))
        executable = compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])),
                             str(source), 'exec')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve() / 'fresh-proof'
            with patch.dict(os.environ, {'CARGO_TARGET_DIR': '/owned-prior-proof/cache'}, clear=True):
                namespace = {'os': os, 'W': work,
                             'a': SimpleNamespace(pg_bin=Path('/owned-test/pg-bin'),
                                                  lightning_tools=Path('/owned-test/tools'))}
                exec(executable, namespace)
            self.assertEqual(namespace['ENV']['CARGO_TARGET_DIR'], str(work / 'sbf/target'))


if __name__ == '__main__':
    unittest.main()
