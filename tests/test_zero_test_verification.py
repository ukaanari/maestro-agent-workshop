"""AUD-01: verification passes only when the runner reports at least one passing test.

Offline only: no model, network or credentials. Without layout options, verification used
`-m unittest discover -s tests`, which exits 0 when no test runs. Every run now goes through
the fixed runner and must report its own counts. Code under test can still forge that line,
so these tests also pin what the count check does not catch.
"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import trusted
from execution import PolicyError
from sandbox import Seatbelt, python_runtime
from workflow import Store
from workspace import canonical, digest

FAKE_PATCH = ROOT / "tests" / "fixtures" / "fake_patch_implementer.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
FIXTURE = ROOT / "examples" / "trusted-local" / "fixture"
spec = importlib.util.spec_from_file_location("zero_test_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")

FIX = b"def add(a, b):\n    return a + b\n"
NO_TESTS = b"import unittest\n"
EXIT_EARLY = b"import os\nos._exit(0)\n"
# unittest counts skipped tests in testsRun, and each skipped subtest in `skipped`.
ALL_SKIPPED = {
    "every test skipped": b"import unittest\nclass T(unittest.TestCase):\n    @unittest.skip('x')\n    def test_a(self): pass\n"
                          b"    @unittest.skip('x')\n    def test_b(self): pass\n",
    "skipTest in the body": b"import unittest\nclass T(unittest.TestCase):\n    def test_a(self): self.skipTest('x')\n",
    "class skipped": b"import unittest\nclass T(unittest.TestCase):\n    def test_a(self): pass\nT = unittest.skip('x')(T)\n",
    "module skipped at import": b"import unittest\nraise unittest.SkipTest('missing dependency')\n",
    "every subtest skipped": b"import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        for i in range(3):\n"
                             b"            with self.subTest(i=i): self.skipTest('x')\n",
}
PARTLY_SKIPPED = {
    "one test passes, one is skipped": b"import unittest\nclass T(unittest.TestCase):\n    def test_a(self): pass\n"
                                       b"    @unittest.skip('x')\n    def test_b(self): pass\n",
    "one subtest passes, one is skipped": b"import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n"
                                          b"        with self.subTest(i=0): self.skipTest('x')\n"
                                          b"        with self.subTest(i=1): self.assertTrue(True)\n",
}
OLD_DEFAULT = [python_runtime()[0], "-I", "-B", "-m", "unittest", "discover", "-s", "tests"]
LAYOUT = trusted.verify_config(test_dir="tests")


def forged(**counts):
    """A test module that prints the runner's count line itself and exits before any test runs."""
    line = json.dumps(dict({"tests_run": 0, "executed": 0, "failures": 0, "errors": 0, "skipped": 0}, **counts)) + "\n"
    return ("import os, sys\nsys.stdout.write(%r)\nsys.stdout.flush()\nos._exit(0)\n" % line).encode()


class CountedTests(unittest.TestCase):
    def test_a_zero_exit_needs_counts_showing_a_passing_run(self):
        ok = {"tests_run": 3, "executed": 2, "failures": 0, "errors": 0, "skipped": 1}
        self.assertEqual(trusted.counted(ok), ok)
        for summary in (None, dict(ok, tests_run=1), dict(ok, executed=0), dict(ok, failures=1), dict(ok, errors=2)):
            with self.subTest(summary=summary), self.assertRaises(PolicyError):
                trusted.counted(summary)


@RUNTIME
class ZeroTestVerificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".zero-test-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.repo = self.root / "repo"
        self.base = fixture.make_fixture(self.repo)
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def task(self, test_body=None, verify=None, review_model=None, review_context="full"):
        """start, implement (the fixture's fix, and optionally a new test module), verify."""
        self.serial += 1
        change = self.root / ("change-%d" % self.serial)
        (change / "tests").mkdir(parents=True)
        (change / "calc.py").write_bytes(FIX)
        if test_body is not None:
            (change / "tests" / "test_calc.py").write_bytes(test_body)
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text("Implement calc.add.\napply-dir: %s\n" % change)
        task_id = self.engine.start(self.repo, self.base, task, "test-model", verify=verify,
                                    review_model=review_model, review_context=review_context)["id"]
        self.assertEqual(self.engine.implement(task_id, str(FAKE_PATCH))["status"], "reviewing")
        self.engine.verify(task_id)
        return task_id

    def sha(self, task_id):
        return self.store.get(task_id)["evidence"].get("snapshot_sha256")

    def rewrite(self, task_id, spec=None, verification=None):
        """Simulate evidence recorded by an earlier MAESTRO, internally consistent."""
        with self.store.connect() as conn:
            if spec is not None:
                conn.execute("UPDATE tasks SET spec=? WHERE id=?", (canonical(spec).decode(), task_id))
            if verification is not None:
                conn.execute("UPDATE artifacts SET body=?,hash=? WHERE task_id=? AND kind='verification'",
                             (canonical(verification).decode(), digest(verification), task_id))
                evidence = dict(self.store.get(task_id)["evidence"], verification_sha256=digest(verification))
                conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(evidence).decode(), task_id))

    def test_runs_that_report_no_passing_test_fail_with_and_without_layout_options(self):
        cases = [("tests emptied", NO_TESTS, "MAESTRO: no tests ran"),
                 ("exits before reporting", EXIT_EARLY, "without the runner's test counts"),
                 ("forged count line: zero tests", forged(), "do not show a passing run"),
                 ("forged count line: none executed", forged(tests_run=2, skipped=2), "do not show a passing run"),
                 ("forged count line: more executed than run", forged(executed=1), "do not show a passing run"),
                 ("forged count line: a failure", forged(tests_run=2, executed=2, failures=1), "do not show a passing run")]
        cases += [(name, body, "MAESTRO: no test executed: every test that ran was skipped")
                  for name, body in ALL_SKIPPED.items()]
        for verify in (None, LAYOUT):
            for name, body, message in cases:
                with self.subTest(layout=verify is not None, case=name):
                    task_id = self.task(body, verify=verify)
                    self.assertEqual(self.store.get(task_id)["status"], "failed")
                    self.assertIn(message, self.store.events(task_id)[-1]["message"])
                    self.assertIs(self.store.artifact(task_id, "verification")["passed"], False)
                    with self.assertRaises(PolicyError):
                        self.engine.approve(task_id, self.sha(task_id), "human")

    def test_a_passing_run_records_counts_for_status_approval_and_the_reviewer(self):
        for verify, review_context in ((None, "full"), (None, "scoped"), (LAYOUT, "full"), (LAYOUT, "scoped")):
            with self.subTest(layout=verify is not None, review_context=review_context):
                task_id = self.task(verify=verify, review_model="test-reviewer", review_context=review_context)
                self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")
                summary = self.store.artifact(task_id, "verification")["summary"]
                self.assertEqual(summary, {"tests_run": 1, "executed": 1, "failures": 0, "errors": 0, "skipped": 0})
                self.assertEqual(self.engine.status(task_id)["verification"],
                                 {"passed": True, "exit_code": 0, "summary": summary})
                self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")
                record = self.store.artifact(task_id, "review.1")
                staged = (self.store.task_dir(task_id) / record["input"]["path"]).read_bytes()
                self.assertEqual(json.loads(staged.split(b"\n", 1)[1])["verification"]["summary"], summary)
                self.assertEqual(self.engine.approve(task_id, self.sha(task_id), "human")["status"], "approved")

    def test_suites_with_some_skips_pass_and_report_what_executed(self):
        for verify in (None, LAYOUT):
            for name, body in PARTLY_SKIPPED.items():
                with self.subTest(layout=verify is not None, case=name):
                    task_id = self.task(body, verify=verify)
                    self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval", self.store.events(task_id))
                    summary = self.store.artifact(task_id, "verification")["summary"]
                    self.assertEqual((summary["tests_run"], summary["executed"], summary["skipped"]), (
                        (2, 1, 1) if name.startswith("one test") else (1, 1, 1)))

    def test_trusted_check_reports_a_baseline_without_counted_tests_as_failing(self):
        for name, tests, passed, reason in (("passing tests", None, True, None),
                                            ("no tests", NO_TESTS, False, None),
                                            ("every test skipped", ALL_SKIPPED["every test skipped"], False, None),
                                            ("exits before reporting", EXIT_EARLY, False, "without the runner's test counts")):
            with self.subTest(name):
                source = self.root / ("check-src-" + name.replace(" ", "-"))
                for path in FIXTURE.rglob("*"):
                    if path.is_file() and "__pycache__" not in path.parts:
                        (source / path.relative_to(FIXTURE)).parent.mkdir(parents=True, exist_ok=True)
                        (source / path.relative_to(FIXTURE)).write_bytes(path.read_bytes())
                (source / "calc.py").write_bytes(FIX)
                if tests is not None:
                    (source / "tests" / "test_calc.py").write_bytes(tests)
                repo = self.root / ("check-" + name.replace(" ", "-"))
                baseline = trusted.check(repo, fixture.make_fixture(repo, source))["baseline"]
                self.assertIs(baseline["passed"], passed, baseline)
                if passed:
                    self.assertEqual((baseline["summary"]["tests_run"], baseline["summary"]["executed"]), (1, 1))
                if reason:
                    self.assertIn(reason, baseline["reason"])

    def test_tasks_recorded_with_the_old_default_command_fail_closed(self):
        task_id = self.task(verify=None)  # verified under the new default, then made to look older
        old_spec = dict(self.store.get(task_id)["spec"], verify_command=OLD_DEFAULT)
        old_record = dict(self.store.artifact(task_id, "verification"), command=OLD_DEFAULT)
        old_record.pop("summary")
        self.rewrite(task_id, spec=old_spec, verification=old_record)
        with self.assertRaisesRegex(PolicyError, "stale or unsuccessful"):
            self.engine.approve(task_id, self.sha(task_id), "human")
        # Started before the upgrade but not yet verified: refused before anything runs.
        self.serial += 1
        change = self.root / "change-old"
        change.mkdir()
        (change / "calc.py").write_bytes(FIX)
        (self.root / "TASK-old.md").write_text("Implement calc.add, old task.\napply-dir: %s\n" % change)
        task_id = self.engine.start(self.repo, self.base, self.root / "TASK-old.md", "test-model")["id"]
        self.engine.implement(task_id, str(FAKE_PATCH))
        self.rewrite(task_id, spec=dict(self.store.get(task_id)["spec"], verify_command=OLD_DEFAULT))
        with patch.object(Seatbelt, "run") as run:
            self.assertEqual(self.engine.verify(task_id)["status"], "failed")
            run.assert_not_called()
        self.assertIn("unsupported verification", self.store.events(task_id)[-1]["message"])

    def test_approval_requires_the_recorded_counts(self):
        task_id = self.task(verify=None)
        record = dict(self.store.artifact(task_id, "verification"), summary=None)
        self.rewrite(task_id, verification=record)
        with self.assertRaisesRegex(PolicyError, "stale or unsuccessful: verification exited 0 without"):
            self.engine.approve(task_id, self.sha(task_id), "human")

    def test_a_hostile_implementer_can_still_forge_a_passing_run(self):
        # The documented limit, pinned so the count check is never mistaken for a security
        # boundary: test code prints a passing count line and exits before any test runs.
        task_id = self.task(forged(tests_run=5, executed=5))
        self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")
        self.assertEqual(self.store.artifact(task_id, "verification")["summary"]["tests_run"], 5)


if __name__ == "__main__":
    unittest.main()
