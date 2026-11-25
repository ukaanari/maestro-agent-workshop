"""Offline tests for strictly read-only Trusted Local listing and JSON/Markdown reporting.

No model, login, network service or credentials. Verifies:
- Zero writes to task clone, Git object store, index, SQLite DB, or artifacts (proven via
  recursive chmod 0o555/0o444 read-only permissions AND full file/mtime/hash comparison).
- Single-transaction consistent SQLite snapshot reading.
- Never suggesting `trusted approve` or `trusted export` when evidence is missing, corrupt,
  invalid, stale, offline-fixture on normal task, or drifted.
- Treating all Markdown output fields as untrusted content (escaping controls, Unicode bidi,
  HTML tags, Markdown links, and backtick code-span breakouts).
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
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


def tree_inventory(root):
    """Recursive inventory of (relpath, kind, size, sha256) to prove zero filesystem writes."""
    items = {}
    for base, dirs, files in os.walk(root):
        dirs.sort()
        files.sort()
        for name in dirs:
            p = Path(base) / name
            items[p.relative_to(root).as_posix() + "/"] = ("dir", 0, "")
        for name in files:
            p = Path(base) / name
            data = p.read_bytes()
            items[p.relative_to(root).as_posix()] = ("file", len(data), hashlib.sha256(data).hexdigest())
    return items


def set_tree_readonly(root, readonly=True):
    """Recursively freeze/unfreeze permissions to kernel-enforce zero writes."""
    entries = []
    for base, dirs, files in os.walk(root):
        for name in files:
            entries.append((Path(base) / name, False))
        for name in dirs:
            entries.append((Path(base) / name, True))
    entries.append((Path(root), True))
    if readonly:
        for path, is_dir in entries:
            if not is_dir:
                path.chmod(0o444)
        for path, is_dir in sorted(entries, key=lambda e: len(e[0].parts), reverse=True):
            if is_dir:
                path.chmod(0o555)
    else:
        for path, is_dir in sorted(entries, key=lambda e: len(e[0].parts)):
            if is_dir:
                path.chmod(0o700)
        for path, is_dir in entries:
            if not is_dir:
                path.chmod(0o600)


class ReadOnlySafetyAndMarkdownTests(unittest.TestCase):
    """Runs on every Python interpreter; exercises read-only and untrusted-Markdown invariants."""

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

    def test_04_markdown_treats_all_fields_as_untrusted_and_escapes_injections(self):
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
                "repo": "/synthetic/`evil`/repo",
                "base": "0" * 40,
                "model": "test-model",
                "review_required": True,
                "verify_layout": None,
            },
            "codex": {"model": "test-model", "version": "0.0.0-offline-fixture", "environment": {}},
            "changes": [{"status": "M", "path": "calc`breakout`.py"}],
            "verification": {"passed": True, "exit_code": 0, "snapshot_sha256": "1" * 64,
                             "summary": {"executed": 2, "tests_run": 2, "failures": 0, "errors": 0, "skipped": 0},
                             "layout": None, "error": None},
            "review": {
                "required": True, "provider": "claude-code", "model": "test-reviewer",
                "attempts": 1, "attempts_allowed": 2, "context_mode": "full",
                "outcome": "completed", "model_verified": True, "blocking": True,
                "classification": "offline test",
                "verdict": "changes_requested",
                "summary": "Bad\x1b[31mANSI\x1b[0m\rCR\u202eBIDI <script>alert(1)</script> [click](https://evil.invalid)\n## Injected",
                "findings": [{
                    "severity": "blocking", "file": "calc`breakout`.py", "line": 2,
                    "title": "Inject\x1b]0;title\x07 <img>",
                    "observation": "Line has\rhidden code\x00nul `tick`",
                    "conclusion": "Fix [link](javascript:alert(1))\n- fake bullet",
                }],
            },
            "approval": None,
            "rejection": None,
            "export": None,
            "evidence": {"snapshot_sha256": "1" * 64},
            "integrity": {
                "recorded_evidence_valid": True, "issues": [], "gate_blockers": [],
                "live_snapshot_matches": True, "live_snapshot_detail": "ok",
                "source_guard_matches": True, "source_guard_detail": "ok",
            },
            "next": ["trusted diff " + "a" * 16],
            "events": [{"seq": 1, "at": "2026-01-01T00:00:00Z", "status": "created", "message": "ok\x1b[2J<b>bold</b>"}],
        }
        md = report.render_markdown(synthetic)
        self.assertIn("Untrusted data warning", md)
        for forbidden_char in ("\x1b", "\r", "\x00", "\x07", "\u202e"):
            self.assertNotIn(forbidden_char, md)
        self.assertNotIn("<script>", md)
        self.assertNotIn("<img>", md)
        self.assertNotIn("<b>bold</b>", md)
        self.assertNotIn("[click](https://evil.invalid)", md)
        self.assertNotIn("[link](javascript:alert(1))", md)
        self.assertNotIn("\n## Injected", md)
        self.assertIn("``calc`breakout`.py``", md)


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

    def run_to_verified(self, *, extra="", review_model=None, review_context="full", engine=None):
        eng = engine or self.engine
        task_id = eng.start(
            self.repo, self.base, self.task_file(extra), "test-model",
            review_model=review_model, review_context=review_context,
        )["id"]
        self.assertEqual(eng.implement(task_id, str(FAKE_CODEX))["status"], "reviewing")
        self.assertEqual(eng.verify(task_id)["status"], "awaiting_approval")
        return task_id

    def test_01_full_lifecycle_json_markdown_and_list_cli(self):
        task_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")

        res_list = run_cli("--root", str(self.store.root), "trusted", "list")
        self.assertEqual(res_list.returncode, 0, res_list.stderr)
        listed = json.loads(res_list.stdout)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["id"], task_id)
        self.assertEqual(listed["tasks"][0]["status"], "awaiting_approval")

        res_filtered = run_cli("--root", str(self.store.root), "trusted", "list", "--status", "approved")
        self.assertEqual(res_filtered.returncode, 0)
        self.assertEqual(json.loads(res_filtered.stdout)["count"], 0)

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
        self.assertEqual(dossier["integrity"]["gate_blockers"], [])
        self.assertTrue(dossier["integrity"]["live_snapshot_matches"])
        self.assertTrue(dossier["integrity"]["source_guard_matches"])
        self.assertEqual(dossier["next"], [])

        res_md = run_cli("--root", str(self.store.root), "trusted", "report", task_id, "--format", "markdown")
        self.assertEqual(res_md.returncode, 0, res_md.stderr)
        md = res_md.stdout
        self.assertIn("# MAESTRO Trusted Local Report: `%s`" % task_id, md)
        self.assertIn("Untrusted data warning", md)
        self.assertIn(exported["sha256"], md)

    def test_02_strict_zero_write_guarantee_enforced_by_readonly_filesystem_permissions(self):
        # Kernel-enforced proof: freeze SQLite DB, state root, task dir, and ALL of
        # clone/.git (including .git/objects and .git/index) to 0o555/0o444 while keeping
        # tracked working-tree modes intact so snapshot matching succeeds. Any write to
        # Git objects, index, DB, or task dir would fail with PermissionError.
        task_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        self.engine.review(task_id, str(FAKE_CLAUDE))
        before = tree_inventory(self.store.root)

        task_dir = self.store.task_dir(task_id)
        git_dir = task_dir / "clone" / ".git"
        db_file = self.store.root / "state.sqlite3"
        set_tree_readonly(git_dir, readonly=True)
        db_file.chmod(0o444)
        task_dir.chmod(0o555)
        self.store.root.chmod(0o555)

        def restore():
            self.store.root.chmod(0o700)
            task_dir.chmod(0o700)
            db_file.chmod(0o600)
            set_tree_readonly(git_dir, readonly=False)

        self.addCleanup(restore)

        dossier = report.build_trusted_report(self.store.root, task_id, check_live=True)
        self.assertTrue(dossier["integrity"]["recorded_evidence_valid"])
        self.assertEqual(dossier["integrity"]["gate_blockers"], [])
        self.assertTrue(dossier["integrity"]["live_snapshot_matches"])
        self.assertTrue(dossier["integrity"]["source_guard_matches"])
        self.assertTrue(any(s.startswith("trusted approve ") for s in dossier["next"]))

        restore()
        self.assertEqual(tree_inventory(self.store.root), before)

    def test_03_live_drift_writes_nothing_to_git_objects_and_suppresses_approve_and_export(self):
        task_id = self.run_to_verified()
        task_dir = self.store.task_dir(task_id)

        # Mutate clone AND source repo after verification.
        (task_dir / "clone" / "calc.py").write_text("# drifted clone\n")
        (task_dir / "clone" / "untracked_drift.py").write_text("# new untracked file\n")
        (self.repo / "calc.py").write_text("# drifted source\n")

        # Freeze the entire state tree (including .git/objects!) and snapshot its exact contents.
        before = tree_inventory(self.store.root)
        set_tree_readonly(self.store.root, readonly=True)
        self.addCleanup(set_tree_readonly, self.store.root, False)

        dossier = report.build_trusted_report(self.store.root, task_id, check_live=True)
        self.assertTrue(dossier["integrity"]["recorded_evidence_valid"])
        self.assertFalse(dossier["integrity"]["live_snapshot_matches"])
        self.assertFalse(dossier["integrity"]["source_guard_matches"])
        self.assertTrue(dossier["integrity"]["gate_blockers"])
        # Critical invariant: NEVER suggest approve when clone or source drifted!
        self.assertFalse(any("trusted approve" in step for step in dossier["next"]), dossier["next"])

        set_tree_readonly(self.store.root, readonly=False)
        self.assertEqual(tree_inventory(self.store.root), before)
        self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")

    def test_04_missing_corrupt_or_blocked_evidence_never_suggests_approve_or_export(self):
        # 1. Missing verification artifact in awaiting_approval -> never suggest approve.
        t0 = self.run_to_verified()
        with self.store.connect() as conn:
            conn.execute("DELETE FROM artifacts WHERE task_id=? AND kind='verification'", (t0,))
        d0 = report.build_trusted_report(self.store.root, t0, check_live=True)
        self.assertFalse(d0["integrity"]["recorded_evidence_valid"])
        self.assertTrue(any("verification" in b for b in d0["integrity"]["gate_blockers"]))
        self.assertFalse(any("trusted approve" in s for s in d0["next"]), d0["next"])

        # 2. Corrupt verification artifact in awaiting_approval -> never suggest approve.
        t1 = self.run_to_verified()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE artifacts SET body=? WHERE task_id=? AND kind='verification'",
                (canonical({"tampered": True}).decode(), t1),
            )
        d1 = report.build_trusted_report(self.store.root, t1, check_live=True)
        self.assertFalse(d1["integrity"]["recorded_evidence_valid"])
        self.assertTrue(d1["integrity"]["gate_blockers"])
        self.assertFalse(any("trusted approve" in s for s in d1["next"]), d1["next"])

        # 3. Wrong snapshot SHA in task evidence -> never suggest approve.
        t_bad_sha = self.run_to_verified()
        bad_ev = dict(self.store.get(t_bad_sha)["evidence"], snapshot_sha256="0" * 64)
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(bad_ev).decode(), t_bad_sha))
        d_sha = report.build_trusted_report(self.store.root, t_bad_sha, check_live=True)
        self.assertFalse(d_sha["integrity"]["recorded_evidence_valid"])
        self.assertFalse(any("trusted approve" in s for s in d_sha["next"]), d_sha["next"])

        # 4. Normal execution_context with offline-fixture codex -> real gate refuses approval,
        # so report MUST flag gate_blocker and NEVER suggest approve!
        normal_engine = trusted.TrustedEngine(self.store, test_context=False)
        t2 = self.run_to_verified(engine=normal_engine)
        d2 = report.build_trusted_report(self.store.root, t2, check_live=True)
        self.assertTrue(any("offline-fixture" in b for b in d2["integrity"]["gate_blockers"]), d2["integrity"])
        self.assertFalse(any("trusted approve" in s for s in d2["next"]), d2["next"])

        # 5. Approved task with partial unrecorded export.patch -> NEVER suggest export!
        t3 = self.run_to_verified()
        sha = self.store.get(t3)["evidence"]["snapshot_sha256"]
        self.engine.approve(t3, sha, "Offline reviewer")
        (self.store.task_dir(t3) / "export.patch").write_bytes(b"partial-unrecorded")
        d3 = report.build_trusted_report(self.store.root, t3, check_live=True)
        self.assertTrue(any("partial export" in b for b in d3["integrity"]["gate_blockers"]))
        self.assertEqual(d3["next"], [])

    def test_05_scoped_review_blocking_override_and_rejection_reporting(self):
        scoped_id = self.run_to_verified(
            extra="review-scenario: pass", review_model="test-reviewer", review_context="scoped",
        )
        self.assertEqual(self.engine.review(scoped_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")
        sd = report.build_trusted_report(self.store.root, scoped_id, check_live=True)
        self.assertIn("not a full-repository review", sd["review"]["scope_notice"])
        self.assertEqual(sd["integrity"]["gate_blockers"], [])

        blocked_id = self.run_to_verified(extra="review-scenario: blocking", review_model="test-reviewer")
        self.assertTrue(self.engine.review(blocked_id, str(FAKE_CLAUDE))["review"]["blocking"])
        before_ov = report.build_trusted_report(self.store.root, blocked_id, check_live=True)
        self.assertTrue(any("--override-review" in step for step in before_ov["next"]))

        sha = self.store.get(blocked_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(blocked_id, sha, "Founder", override_review="Accepted known fixture blocker")
        after_ov = report.build_trusted_report(self.store.root, blocked_id, check_live=True)
        self.assertEqual(after_ov["approval"]["review_override"], "Accepted known fixture blocker")
        self.assertIn("Accepted known fixture blocker", report.render_markdown(after_ov))

        rejected_id = self.run_to_verified(extra="review-scenario: blocking", review_model="test-reviewer")
        self.engine.review(rejected_id, str(FAKE_CLAUDE))
        self.engine.reject(rejected_id, "Founder", "Blocking issue not accepted")
        rej = report.build_trusted_report(self.store.root, rejected_id, check_live=False)
        self.assertEqual(rej["task"]["status"], "rejected")
        self.assertEqual(rej["rejection"]["reason"], "Blocking issue not accepted")
        self.assertEqual(rej["next"], [])

    def test_06_no_live_check_never_suggests_approve_or_export(self):
        # Fail-closed invariant: without live clone & source-guard verification,
        # report MUST NOT suggest `trusted approve` or `trusted export`.
        task_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        self.engine.review(task_id, str(FAKE_CLAUDE))

        no_live = report.build_trusted_report(self.store.root, task_id, check_live=False)
        self.assertIsNone(no_live["integrity"]["live_snapshot_matches"])
        self.assertIsNone(no_live["integrity"]["source_guard_matches"])
        self.assertTrue(any("--no-live-check" in b for b in no_live["integrity"]["gate_blockers"]), no_live["integrity"])
        self.assertFalse(any("trusted approve" in s for s in no_live["next"]), no_live["next"])
        self.assertIn("trusted report " + task_id, no_live["next"])

        # CLI --no-live-check matches the same guarantee.
        res = run_cli("--root", str(self.store.root), "trusted", "report", task_id, "--no-live-check")
        self.assertEqual(res.returncode, 0, res.stderr)
        cli_no_live = json.loads(res.stdout)
        self.assertFalse(any("trusted approve" in s for s in cli_no_live["next"]))

        # Same for approved task before export: --no-live-check MUST NOT suggest export.
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(task_id, sha, "Offline reviewer")
        appr_no_live = report.build_trusted_report(self.store.root, task_id, check_live=False)
        self.assertFalse(any("trusted export" in s for s in appr_no_live["next"]), appr_no_live["next"])
        self.assertIn("trusted report " + task_id, appr_no_live["next"])
        # With live check enabled on the clean approved task, export IS suggested.
        appr_live = report.build_trusted_report(self.store.root, task_id, check_live=True)
        self.assertEqual(appr_live["next"], ["trusted export " + task_id])

    def test_07_stale_review_missing_scoped_context_and_partial_review_block_suggestions(self):
        # Stale review (bound to wrong snapshot/patch hash) -> blocked.
        stale_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        self.engine.review(stale_id, str(FAKE_CLAUDE))
        rec = self.store.artifact(stale_id, "review.1")
        rec["patch_sha256"] = "f" * 64
        rec["review"]["patch_sha256"] = "f" * 64
        from workspace import digest as ws_digest
        ev = dict(self.store.get(stale_id)["evidence"], review_sha256=ws_digest(rec))
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body=?, hash=? WHERE task_id=? AND kind='review.1'",
                         (canonical(rec).decode(), ws_digest(rec), stale_id))
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(ev).decode(), stale_id))
        d_stale = report.build_trusted_report(self.store.root, stale_id, check_live=True)
        self.assertTrue(any("stale" in b for b in d_stale["integrity"]["gate_blockers"]), d_stale["integrity"])
        self.assertFalse(any("trusted approve" in s for s in d_stale["next"]), d_stale["next"])

        # Missing scoped-review context -> blocked.
        scoped_id = self.run_to_verified(
            extra="review-scenario: pass", review_model="test-reviewer", review_context="scoped",
        )
        self.engine.review(scoped_id, str(FAKE_CLAUDE))
        srec = self.store.artifact(scoped_id, "review.1")
        srec.pop("context", None)
        sev = dict(self.store.get(scoped_id)["evidence"], review_sha256=ws_digest(srec))
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body=?, hash=? WHERE task_id=? AND kind='review.1'",
                         (canonical(srec).decode(), ws_digest(srec), scoped_id))
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(sev).decode(), scoped_id))
        d_scoped = report.build_trusted_report(self.store.root, scoped_id, check_live=True)
        self.assertTrue(any("scoped review context" in b for b in d_scoped["integrity"]["gate_blockers"]), d_scoped["integrity"])
        self.assertFalse(any("trusted approve" in s for s in d_scoped["next"]), d_scoped["next"])

        # Crashed partial review folder on disk without review.1 artifact -> never suggest review or approve.
        part_id = self.run_to_verified(extra="review-scenario: pass", review_model="test-reviewer")
        (self.store.task_dir(part_id) / "review-1").mkdir(mode=0o700)
        d_part = report.build_trusted_report(self.store.root, part_id, check_live=True)
        self.assertTrue(any("partial review" in b for b in d_part["integrity"]["gate_blockers"]), d_part["integrity"])
        self.assertFalse(any("trusted approve" in s or "trusted review" in s for s in d_part["next"]), d_part["next"])

    def test_08_consistent_sqlite_snapshot_under_concurrent_update(self):
        # Verify report reads tasks, events, and artifacts from ONE consistent SQLite read transaction:
        # start a concurrent writer right after report begins reading; report must see a consistent
        # pre-write snapshot (either old status+events or new status+events, never torn).
        import sqlite3
        from unittest.mock import patch

        task_id = self.run_to_verified()
        real_read_art = report._read_artifact
        mutated = []

        def concurrent_writer_during_read(conn, tid, kind):
            if not mutated and kind == "verification":
                mutated.append(True)
                # Separate connection tries to write while report holds its BEGIN DEFERRED read tx.
                wconn = sqlite3.connect(str(self.store.root / "state.sqlite3"), timeout=0.05)
                try:
                    wconn.execute("UPDATE tasks SET status='rejected' WHERE id=?", (tid,))
                    wconn.commit()
                except sqlite3.OperationalError:
                    # Expected in rollback journal mode: read transaction blocks writer until ROLLBACK.
                    pass
                finally:
                    wconn.close()
            return real_read_art(conn, tid, kind)

        with patch.object(report, "_read_artifact", side_effect=concurrent_writer_during_read):
            dossier = report.build_trusted_report(self.store.root, task_id, check_live=True)
        self.assertTrue(mutated)
        self.assertEqual(dossier["task"]["status"], "awaiting_approval")
        self.assertTrue(dossier["integrity"]["recorded_evidence_valid"])
        self.assertEqual(dossier["integrity"]["gate_blockers"], [])


if __name__ == "__main__":
    unittest.main()
