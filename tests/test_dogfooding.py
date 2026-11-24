"""Offline dogfooding and `trusted check` diagnostics tests.

No model, login, network service or credentials.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import trusted
from workflow import Store

FAKE_CODEX = ROOT / "tests" / "fixtures" / "fake_codex.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("dogfood_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")


class CheckHintUnitTests(unittest.TestCase):
    """Runs on every Python interpreter."""

    def test_check_hints_cover_common_failure_modes(self):
        self.assertEqual(trusted._check_hints({"passed": True}, True), [])

        dirty = trusted._check_hints({"passed": True}, False)
        self.assertEqual(len(dirty), 1)
        self.assertIn("uncommitted changes", dirty[0])

        no_tests = trusted._check_hints({"passed": False, "excerpt": "MAESTRO: no tests ran"}, True)
        self.assertTrue(any("--test-dir" in h for h in no_tests))

        all_skipped = trusted._check_hints({"passed": False, "excerpt": "MAESTRO: no test executed"}, True)
        self.assertTrue(any("skipped" in h for h in all_skipped))

        subproc = trusted._check_hints({"passed": False, "excerpt": "File subprocess.py Popen PermissionError"}, True)
        self.assertTrue(any("subprocesses" in h for h in subproc))

        imp = trusted._check_hints({"passed": False, "excerpt": "ModuleNotFoundError: No module named 'pkg'"}, True)
        self.assertTrue(any("--pythonpath" in h for h in imp))

        net = trusted._check_hints({"passed": False, "excerpt": "File socket.py PermissionError"}, True)
        self.assertTrue(any("network" in h for h in net))


@RUNTIME
class DogfoodingIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".dogfood-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def git(self, cwd, *args):
        return trusted.git(cwd, self.root, *args)

    @unittest.skipUnless((ROOT / ".git").exists(), "needs the MAESTRO Git checkout")
    def test_01_maestro_self_check_on_pure_stdlib_test_subset(self):
        base = self.git(ROOT, "rev-parse", "HEAD").decode("ascii").strip()
        verify = trusted.verify_config(test_dir="tests", pattern="test_check_suite.py")
        report = trusted.check(ROOT, base, verify)
        self.assertTrue(report["compatible"])
        self.assertTrue(report["baseline"]["passed"], report)
        self.assertEqual(report["baseline"]["summary"]["executed"], 8)
        self.assertEqual(report["baseline"]["summary"]["failures"], 0)
        self.assertEqual(report["baseline"]["summary"]["errors"], 0)
        self.assertIn("source_clean", report)

    def test_02_trusted_check_reports_dirty_tree_and_subprocess_denial_hints(self):
        repo = self.root / "subproc-repo"
        base = fixture.make_fixture(repo)

        # Clean baseline passes with source_clean=True and no hints.
        clean_report = trusted.check(repo, base)
        self.assertTrue(clean_report["compatible"])
        self.assertTrue(clean_report["source_clean"])
        self.assertFalse(clean_report["baseline"]["passed"])  # calc.add is stubbed in base fixture
        self.assertNotIn("hints", clean_report)

        # Dirty working tree is flagged without mutating or failing compatibility.
        (repo / "UNTRACKED_NOTE.txt").write_text("dirty\n")
        dirty_report = trusted.check(repo, base)
        self.assertFalse(dirty_report["source_clean"])
        self.assertTrue(any("uncommitted changes" in h for h in dirty_report.get("hints", [])))
        (repo / "UNTRACKED_NOTE.txt").unlink()

        # Commit a test that invokes subprocess.run -> Seatbelt denies it and hints explain why.
        (repo / "tests" / "test_subproc.py").write_text(
            "import subprocess, unittest\n"
            "class SubprocTest(unittest.TestCase):\n"
            "    def test_spawn(self):\n"
            "        subprocess.run(['/usr/bin/true'], check=True)\n"
        )
        self.git(repo, "add", "tests/test_subproc.py")
        self.git(repo, "commit", "-m", "add subprocess test")
        subproc_base = self.git(repo, "rev-parse", "HEAD").decode("ascii").strip()

        subproc_report = trusted.check(
            repo, subproc_base, trusted.verify_config(test_dir="tests", pattern="test_subproc.py"),
        )
        self.assertTrue(subproc_report["compatible"])
        self.assertFalse(subproc_report["baseline"]["passed"])
        self.assertTrue(any("subprocesses" in h for h in subproc_report.get("hints", [])), subproc_report)

        # Unmatched pattern triggers zero-tests hint.
        empty_report = trusted.check(
            repo, subproc_base, trusted.verify_config(test_dir="tests", pattern="test_nonexistent_*.py"),
        )
        self.assertTrue(empty_report["compatible"])
        self.assertFalse(empty_report["baseline"]["passed"])
        self.assertTrue(any("--test-dir" in h for h in empty_report.get("hints", [])), empty_report)

    def test_03_offline_end_to_end_dogfooding_workflow_produces_applicable_patch(self):
        repo = self.root / "workflow-repo"
        base = fixture.make_fixture(repo)
        self.assertTrue(trusted.check(repo, base)["source_clean"])

        store = Store(self.root / "state")
        engine = trusted.TrustedEngine(store, test_context=True)
        task_file = self.root / "TASK.md"
        task_file.write_text((repo / "TASK.md").read_text() + "\nreview-scenario: pass\n")

        started = engine.start(repo, base, task_file, "test-model", review_model="test-reviewer",
                               review_context="scoped")
        task_id = started["id"]
        self.assertEqual(started["status"], "preparing")
        self.assertEqual(engine.implement(task_id, str(FAKE_CODEX))["status"], "reviewing")
        self.assertEqual(engine.verify(task_id)["status"], "awaiting_approval")
        rev = engine.review(task_id, str(FAKE_CLAUDE))["review"]
        self.assertEqual(rev["outcome"], "completed")
        self.assertFalse(rev["blocking"])
        self.assertIn("not a full-repository review", rev["scope_notice"])

        patch_bytes = engine.diff(task_id)
        self.assertIn(b"calc.py", patch_bytes)

        sha = store.get(task_id)["evidence"]["snapshot_sha256"]
        self.assertEqual(engine.approve(task_id, sha, "Offline dogfooder")["status"], "approved")
        exported = engine.export(task_id)

        # Verify exported patch applies cleanly on a fresh clone of base and passes tests.
        fresh = self.root / "fresh-apply"
        self.git(self.root, "clone", "--no-hardlinks", "--template=", str(repo), str(fresh))
        self.git(fresh, "checkout", "--detach", base)
        self.git(fresh, "apply", "--check", exported["path"])
        self.git(fresh, "apply", exported["path"])
        res = subprocess.run(
            ["/usr/bin/python3", "-B", "-m", "unittest", "discover", "-s", "tests"],
            cwd=str(fresh), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
