#!/usr/bin/env python3
"""The umbrella report must qualify named SBF cases, not a stale pass count."""
import json
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
REAL = (HERE / "fixtures/report-token-program-13.txt").read_text()
REQUIRED = "dex::carry_tests::expired_unfunded_week_is_permanent_and_cannot_capture_later_funding"
SPEC = importlib.util.spec_from_file_location("token_report", HERE / "report.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class TokenReportTests(unittest.TestCase):
    def run_log(self, value):
        with tempfile.TemporaryDirectory(prefix="token-report-test-") as temporary:
            path = Path(temporary) / "token-program.log"
            path.write_text(value)
            env = dict(os.environ, TOKEN_INCLUDE_DEX="1", MORSE_PROOF_DIR=temporary)
            result = subprocess.run(
                ["python3", str(HERE / "report.py"), "--token-program-log", str(path)],
                env=env, text=True, capture_output=True, check=False,
            )
        return result

    def refused(self, value):
        result = self.run_log(value)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        return result.stderr

    def test_actual_thirteen_case_sbf_log_passes_without_rewriting_evidence(self):
        result = self.run_log(REAL)
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(proof["observed_case_count"], 13)
        self.assertEqual(len(proof["required_cases"]), 13)
        self.assertIn(REQUIRED, proof["required_cases"])
        self.assertEqual(proof["failed"], 0)
        self.assertEqual(proof["ignored"], 0)

    def test_additional_passing_case_does_not_require_a_magic_count_update(self):
        value = REAL.replace("running 13 tests", "running 14 tests")
        value = value.replace("test result: ok. 13 passed", "test result: ok. 14 passed")
        value = value.replace("test result:", "test future_independent_guard ... ok\n\ntest result:", 1)
        result = self.run_log(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["observed_case_count"], 14)

    def test_equal_pass_count_with_missing_required_case_is_refused(self):
        error = self.refused(REAL.replace(REQUIRED, "unrelated_passing_case"))
        self.assertIn("missing", error.lower())
        self.assertIn(REQUIRED, error)

    def test_failed_required_case_cannot_be_hidden_by_success_summary(self):
        self.refused(REAL.replace("test " + REQUIRED + " ... ok", "test " + REQUIRED + " ... FAILED"))

    def test_failed_additional_case_is_also_refused(self):
        self.refused(REAL.replace("test result:", "test additional_case ... FAILED\n\ntest result:", 1))

    def test_ignored_required_case_is_refused(self):
        value = REAL.replace("test " + REQUIRED + " ... ok", "test " + REQUIRED + " ... ignored")
        self.refused(value.replace("13 passed; 0 failed; 0 ignored", "12 passed; 0 failed; 1 ignored"))

    def test_truncated_or_summary_only_logs_are_refused(self):
        self.refused(REAL[:REAL.index("test result:")])
        self.refused(REAL[:REAL.rindex("finished in")])
        self.refused(REAL[REAL.index("test result:"):])

    def test_missing_case_even_with_adjusted_totals_is_refused(self):
        value = re.sub(r"^test " + re.escape(REQUIRED) + r" \.\.\. ok\n", "", REAL, flags=re.M)
        value = value.replace("running 13 tests", "running 12 tests")
        value = value.replace("13 passed;", "12 passed;")
        self.refused(value)

    def test_duplicate_cases_and_combined_runs_are_refused(self):
        duplicate = REAL.replace("running 13 tests", "running 14 tests")
        duplicate = duplicate.replace("13 passed;", "14 passed;")
        duplicate = duplicate.replace("test result:", "test " + REQUIRED + " ... ok\n\ntest result:", 1)
        self.refused(duplicate)
        self.refused(REAL + REAL)

    def test_failed_or_filtered_summary_is_refused(self):
        self.refused(REAL.replace("test result: ok.", "test result: FAILED."))
        self.refused(REAL.replace("0 failed;", "1 failed;"))
        self.refused(REAL.replace("0 filtered out;", "1 filtered out;"))

    def test_compiler_failure_cannot_be_hidden_before_a_valid_case_list(self):
        self.refused("error: prior compilation failed\n" + REAL)

    def test_marker_does_not_hide_another_required_logs_rust_failure(self):
        with tempfile.TemporaryDirectory(prefix="token-report-checks-") as temporary:
            root = Path(temporary)
            path = root / "required.log"
            with patch.object(REPORT, "proof", root), patch.object(
                REPORT, "checks", [("required", path.name, "MORSE_REQUIRED")]
            ):
                for failure in ["test result: FAILED. 0 passed; 1 failed;",
                                "test another_guard ... FAILED", "error: compile failed"]:
                    path.write_text("MORSE_REQUIRED\n" + failure + "\n")
                    with self.assertRaises(ValueError):
                        REPORT.collect_checks()
                path.write_text("no required marker\n")
                with self.assertRaises(ValueError):
                    REPORT.collect_checks()
                path.unlink()
                with self.assertRaises(OSError):
                    REPORT.collect_checks()


if __name__ == "__main__":
    unittest.main()
