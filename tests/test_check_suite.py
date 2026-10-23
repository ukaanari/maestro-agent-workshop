"""The CI known-failure gate (.github/scripts/check_suite.py) matches exact subTest ids.

Synthetic test cases are built inside functions, so discovery never runs them directly.
"""
import importlib.util
import io
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_suite", ROOT / ".github" / "scripts" / "check_suite.py")
check_suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_suite)

PROBES = ("env", "signal_parent", "sibling_environment", "parent_executable")


def synthetic(failing_probes=(), fail_outside_subtests=False):
    """A test with one subTest per probe, shaped like the process-isolation test."""
    class Synthetic(unittest.TestCase):
        def test_isolation(self):
            for probe in PROBES:
                with self.subTest(probe=probe):
                    self.assertNotIn(probe, failing_probes)
            if fail_outside_subtests:
                self.fail("failure outside any subTest")

    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Synthetic))
    return result, Synthetic("test_isolation").id()


def known(parent, *probes):
    return {"%s (probe=%r)" % (parent, probe) for probe in probes}


class KnownFailureGateTests(unittest.TestCase):
    def test_exactly_the_known_subtest_failures_are_accepted(self):
        result, parent = synthetic(failing_probes=("sibling_environment", "parent_executable"))
        ok, report = check_suite.evaluate(result, known(parent, "sibling_environment", "parent_executable"))
        self.assertTrue(ok, report)
        self.assertEqual(report.count("- known failure:"), 2)

    def test_unexpected_subtest_failure_in_the_same_test_is_rejected(self):
        result, parent = synthetic(failing_probes=("sibling_environment", "parent_executable", "signal_parent"))
        ok, report = check_suite.evaluate(result, known(parent, "sibling_environment", "parent_executable"))
        self.assertFalse(ok)
        self.assertIn("UNEXPECTED failure: %s (probe='signal_parent')" % parent, report)

    def test_failure_outside_the_subtests_is_not_excused_by_known_subtests(self):
        result, parent = synthetic(failing_probes=("sibling_environment", "parent_executable"),
                                   fail_outside_subtests=True)
        ok, report = check_suite.evaluate(result, known(parent, "sibling_environment", "parent_executable"))
        self.assertFalse(ok)
        self.assertIn("UNEXPECTED failure: %s\n" % parent, report + "\n")

    def test_listing_the_parent_test_does_not_excuse_its_subtests(self):
        result, parent = synthetic(failing_probes=("env",))
        ok, report = check_suite.evaluate(result, {parent})
        self.assertFalse(ok)
        self.assertIn("UNEXPECTED failure: %s (probe='env')" % parent, report)

    def test_known_failure_that_now_passes_is_rejected_as_stale(self):
        result, parent = synthetic(failing_probes=("sibling_environment",))
        ok, report = check_suite.evaluate(result, known(parent, "sibling_environment", "parent_executable"))
        self.assertFalse(ok)
        self.assertIn("did not fail (update the list): %s (probe='parent_executable')" % parent, report)

    def test_clean_run_passes_and_empty_run_fails(self):
        result, _ = synthetic()
        self.assertTrue(check_suite.evaluate(result, set())[0])
        empty = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.TestSuite())
        self.assertFalse(check_suite.evaluate(empty, set())[0])

    def test_known_failure_file_parsing_ignores_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("# comment\n\n  a.B.test_x (probe='p')  \n# another\n")
        self.addCleanup(Path(handle.name).unlink)
        self.assertEqual(check_suite.read_known(handle.name), {"a.B.test_x (probe='p')"})
        self.assertEqual(check_suite.read_known(""), set())

    def test_committed_known_failures_name_real_inspection_subtests_only(self):
        listed = check_suite.read_known(ROOT / ".github" / "known-failures" / "homebrew-python-3.15.txt")
        source = (ROOT / "tests" / "test_security.py").read_text()
        self.assertEqual(len(listed), 2)
        for name in listed:
            match = re.fullmatch(r"test_security\.ConfinementTests\.(test_\w+) \(probe='(\w+)'\)", name)
            self.assertIsNotNone(match, name)
            self.assertIn("def %s(" % match.group(1), source)
            self.assertIn(match.group(2), ("sibling_environment", "parent_executable"))


if __name__ == "__main__":
    unittest.main()
