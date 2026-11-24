"""Offline tests for read-only Trusted Local listing and JSON/Markdown reporting.

No model, login, network service or credentials. Verifies read-only guarantees,
evidence/integrity checks, scoped review reporting and adversarial Markdown sanitization.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import report
import trusted
from execution import PolicyError
from workflow import Store
from workspace import canonical

FAKE_CODEX = ROOT / "tests" / "fixtures" / "fake_codex.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("report_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-B", str(ROOT / "maestro.py"), *args],
        capture_output=True, text=True, timeout=30,
    )


class ReadOnlySafetyAndMarkdownTests(unittest.TestCase):
    """Runs on every Python interpreter; exercises read-only and sanitization invariants."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".report-unit-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def test_01_list_and_report_never_create_state_root(self):
        missing = self.root / "nonexistent-state"
        listing = report.list_trusted_tasks(missing)
        self.assertEqual(listing["mode"], trusted.MODE)
        self.assertEqual(listing["count"], 0)
        self.assertEqual(listing["tasks"], [])
        self.assertFalse(missing.exists())

        res = run_cli("--root", str(missing), "trusted", "list")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout)["count"], 0)
        self.assertFalse(missing.exists())

        empty_dir = self.root / "empty-state"
        empty_dir.mkdir()
        self.assertEqual(report.list_trusted_tasks(empty_dir)["count"], 0)
        self.assertEqual(list(empty_dir.iterdir()), [])

        with self.assertRaisesRegex(PolicyError, "does not exist"):
            report.build_trusted_report(missing, "a" * 16)
        self.assertFalse(missing.exists())

        res = run_cli("--root", str(missing), "trusted", "report", "a" * 16)
        self.assertEqual(res.returncode, 2)
        self.assertIn("error", json.loads(res.stderr))
        self.assertFalse(missing.exists())

    def test_02_rejects_invalid_status_filter_bad_id_symlink_and_foreign_root(self):
        with self.assertRaisesRegex(PolicyError, "unknown task status filter"):
            report.list_trusted_tasks(self.root / "missing", status="bogus")

        with self.assertRaisesRegex(PolicyError, "invalid task identity"):
            report.build_trusted_report(self.root / "missing", "../escape")

        target = self.root / "target"
        target.mkdir()
        link = self.root / "link-state"
        link.symlink_to(target)
        with self.assertRaisesRegex(PolicyError, "symlink"):
            report.list_trusted_tasks(link)

        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "other.txt").write_text("not maestro")
        with self.assertRaisesRegex(PolicyError, "not owned by MAESTRO"):
            report.list_trusted_tasks(foreign)

    def test_03_confined_tasks_are_excluded_from_list_and_rejected_by_report(self):
        store = Store(self.root / "state")
        confined_id = store.create("confined task")
        listing = report.list_trusted_tasks(store.root)
        self.assertEqual(listing["count"], 0)
        self.assertEqual(listing["tasks"], [])
        with self.assertRaisesRegex(PolicyError, "mode trusted-local"):
            report.build_trusted_report(store.root, confined_id, check_live=False)

    def test_04_markdown_sanitizes_control_chars_and_newlines(self):
        synthetic = {
            "schema": report.SCHEMA,
            "read_only": True,
            "mode": trusted.MODE,
            "notice": trusted.NOTICE,
            "task": {
                "id": "a" * 16,
                "status": "awaiting_approval",
                "cancel_requested": False,
                "execution_context": "test",
                "repo": "/synthetic/repo",
                "base": "0" * 40,
                "model": "test-model",
                "review_required": True,
                "verify_layout": None,
            },
            "codex": {"model": "test-model", "version": "0.0.0-offline-fixture", "environment": {}},
            "changes": [{"status": "M", "path": "calc.py"}],
            "verification": {"passed": True, "exit_code": 0, "snapshot_sha256": "1" * 64,
                             "summary": {"executed": 2, "tests_run": 2, "failures": 0, "errors": 0, "skipped": 0},
                             "layout": None, "error": None},
            "review": {
                "required": True, "provider": "claude-code", "model": "test-reviewer",
                "attempts": 1, "attempts_allowed": 2, "context_mode": "full",
                "outcome": "completed", "model_verified": True, "blocking": True,
                "classification": "offline test",
                "verdict": "changes_requested",
                "summary": "Bad\x1b[31mANSI\x1b[0m and\rCR\n## Injected Heading",
                "findings": [{
                    "severity": "blocking", "file": "calc.py", "line": 2,
                    "title": "Inject\x1b]0;title\x07",
                    "observation": "Line has\rhidden code\x00nul",
                    "conclusion": "Fix it\n- fake bullet",
                }],
            },
            "approval": None,
            "rejection": None,
            "export": None,
            "evidence": {"snapshot_sha256": "1" * 64},
            "integrity": {
                "recorded_evidence_valid": True, "issues": [],
                "live_snapshot_matches": True, "live_snapshot_detail": "ok",
                "source_guard_matches": True, "source_guard_detail": "ok",
            },
            "next": ["trusted diff " + "a" * 16],
            "events": [{"seq": 1, "at": "2026-01-01T00:00:00Z", "status": "created", "message": "ok\x1b[2J"}],
        }
        md = report.render_markdown(synthetic)
        self.assertNotIn("\x1b", md)
        self.assertNotIn("\r", md)
        self.assertNotIn("\x00", md)
        self.assertNotIn("\x07", md)
        self.assertIn("\\x1b[31mANSI\\x1b[0m", md)
        self.assertIn("\\x0dCR", md)
        self.assertIn("\\x00nul", md)
        self.assertNotIn("\n## Injected Heading", md)


@RUNTIME
class TrustedLocalReportIntegrationTests(unittest.TestCase):
    """End-to-end offline Trusted Local listing and reporting tests."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".report-int-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.repo = self.root / "source"
        self.base = fixture.make_fixture(self.repo)
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def task_file(self, extra=""):
        self.serial += 1
        path = self.root / ("TASK-%d.md" % self.serial)
        path.write_text((self.repo / "TASK.md").read_text() + ("\n" + extra if extra else ""))
        return path

    def run_to_verified(self, *, extra="", review_model=None, review_context="full"):
        task_id = self.engine.start(
            self.repo, self.base, self.task_file(extra), "test-model",
            review_model=review_model, review_context=review_context,
        )["id"]
        self.assertEqual(self.engine.implement(task_id, str(FAKE_CODEX))["status"], "reviewing")
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval")
        return task_id

    def test_01_full_lifecycle_json_markdown_and_list_cli(self):
        task_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")

        # List shows the task and honors --status filtering.
        res_list = run_cli("--root", str(self.store.root), "trusted", "list")
        self.assertEqual(res_list.returncode, 0, res_list.stderr)
        listed = json.loads(res_list.stdout)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["id"], task_id)
        self.assertEqual(listed["tasks"][0]["status"], "awaiting_approval")
        self.assertEqual(listed["tasks"][0]["review_model"], "test-reviewer")

        res_filtered = run_cli("--root", str(self.store.root), "trusted", "list", "--status", "approved")
        self.assertEqual(res_filtered.returncode, 0)
        self.assertEqual(json.loads(res_filtered.stdout)["count"], 0)

        # Approve and export, then verify JSON + Markdown reports via CLI.
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.assertEqual(self.engine.approve(task_id, sha, "Offline reviewer")["status"], "approved")
        exported = self.engine.export(task_id)

        res_json = run_cli("--root", str(self.store.root), "trusted", "report", task_id)
        self.assertEqual(res_json.returncode, 0, res_json.stderr)
        dossier = json.loads(res_json.stdout)
        self.assertEqual(dossier["schema"], report.SCHEMA)
        self.assertTrue(dossier["read_only"])
        self.assertEqual(dossier["task"]["status"], "approved")
        self.assertTrue(dossier["verification"]["passed"])
        self.assertEqual(dossier["review"]["verdict"], "no_blocking_findings")
        self.assertEqual(dossier["approval"]["founder"], "Offline reviewer")
        self.assertEqual(dossier["export"]["sha256"], exported["sha256"])
        self.assertTrue(dossier["integrity"]["recorded_evidence_valid"])
        self.assertTrue(dossier["integrity"]["live_snapshot_matches"])
        self.assertTrue(dossier["integrity"]["source_guard_matches"])
        self.assertEqual(dossier["next"], [])

        res_md = run_cli("--root", str(self.store.root), "trusted", "report", task_id, "--format", "markdown")
        self.assertEqual(res_md.returncode, 0, res_md.stderr)
        md = res_md.stdout
        self.assertIn("# MAESTRO Trusted Local Report: `%s`" % task_id, md)
        self.assertIn("## Verification (Seatbelt-Confined)", md)
        self.assertIn("## Independent Review", md)
        self.assertIn("## Decision & Export", md)
        self.assertIn(exported["sha256"], md)

    def test_02_scoped_review_report_preserves_scope_notice_and_counts(self):
        task_id = self.run_to_verified(
            extra="review-scenario: pass", review_model="test-reviewer", review_context="scoped",
        )
        self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")

        dossier = report.build_trusted_report(self.store.root, task_id)
        rev = dossier["review"]
        self.assertEqual(rev["context_mode"], "scoped")
        self.assertIn("not a full-repository review", rev["scope_notice"])
        self.assertIn("included_count", rev["context"])
        self.assertIn("omitted_count", rev["context"])
        self.assertIn("limitations", rev["context"])

        md = report.render_markdown(dossier)
        self.assertIn("not a full-repository review", md)

    def test_03_blocking_review_override_and_rejection_reporting(self):
        blocked_id = self.run_to_verified(extra="review-scenario: blocking", review_model="test-reviewer")
        self.assertTrue(self.engine.review(blocked_id, str(FAKE_CLAUDE))["review"]["blocking"])

        before_override = report.build_trusted_report(self.store.root, blocked_id, check_live=False)
        self.assertTrue(before_override["review"]["blocking"])
        self.assertTrue(any("--override-review" in step for step in before_override["next"]))
        self.assertIsNone(before_override["integrity"]["live_snapshot_matches"])
        self.assertIsNone(before_override["integrity"]["source_guard_matches"])

        sha = self.store.get(blocked_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(blocked_id, sha, "Founder", override_review="Accepted known fixture blocker")
        after_override = report.build_trusted_report(self.store.root, blocked_id, check_live=False)
        self.assertEqual(after_override["approval"]["review_override"], "Accepted known fixture blocker")
        self.assertIn("Accepted known fixture blocker", report.render_markdown(after_override))

        rejected_id = self.run_to_verified(extra="review-scenario: blocking", review_model="test-reviewer")
        self.engine.review(rejected_id, str(FAKE_CLAUDE))
        self.engine.reject(rejected_id, "Founder", "Blocking issue not accepted")
        rej_dossier = report.build_trusted_report(self.store.root, rejected_id, check_live=False)
        self.assertEqual(rej_dossier["task"]["status"], "rejected")
        self.assertEqual(rej_dossier["rejection"]["reason"], "Blocking issue not accepted")
        self.assertIn("Blocking issue not accepted", report.render_markdown(rej_dossier))

    def test_04_live_drift_is_reported_without_mutating_task_state_or_files(self):
        task_id = self.run_to_verified()
        task_dir = self.store.task_dir(task_id)
        db_path = self.store.root / "state.sqlite3"

        # Mutate the live clone AND source repo after verification.
        (task_dir / "clone" / "calc.py").write_text("# drifted clone\n")
        (self.repo / "calc.py").write_text("# drifted source\n")

        files_before = sorted(os.listdir(task_dir))
        events_before = self.store.events(task_id)
        db_bytes_before = db_path.read_bytes()

        dossier = report.build_trusted_report(self.store.root, task_id, check_live=True)
        self.assertTrue(dossier["integrity"]["recorded_evidence_valid"])
        self.assertFalse(dossier["integrity"]["live_snapshot_matches"])
        self.assertFalse(dossier["integrity"]["source_guard_matches"])
        self.assertIn("drifted", dossier["integrity"]["live_snapshot_detail"])
        self.assertIn("changed", dossier["integrity"]["source_guard_detail"])

        # Strict read-only invariant: status stays awaiting_approval, DB bytes and task_dir entries unchanged.
        self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")
        self.assertEqual(self.store.events(task_id), events_before)
        self.assertEqual(sorted(os.listdir(task_dir)), files_before)
        self.assertEqual(db_path.read_bytes(), db_bytes_before)

    def test_05_tampered_evidence_hash_is_flagged_in_report(self):
        task_id = self.run_to_verified()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE artifacts SET body=? WHERE task_id=? AND kind='verification'",
                (canonical({"tampered": True}).decode(), task_id),
            )
        dossier = report.build_trusted_report(self.store.root, task_id, check_live=False)
        self.assertFalse(dossier["integrity"]["recorded_evidence_valid"])
        self.assertTrue(any("corrupt evidence: verification" in item for item in dossier["integrity"]["issues"]))


if __name__ == "__main__":
    unittest.main()
