"""No third-party agents, repository scripts, dependency installation or commits."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents import ClaudeCodeAdapter, CodexAdapter, decode, envelope, validate
from execution import Cancelled, DeadlineExceeded, PolicyError, execute, private_env
from workflow import Engine, Store
from workspace import Workspace, digest, relative_path


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="maestro-p0-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "state"
        self.store = Store(self.root)
        self.engine = Engine(self.store)

    def task(self, scenario="success", timeout=3):
        return self.store.create("Write deterministic greeting", scenario=scenario, timeout=timeout)

    def run_task(self, scenario="success", timeout=3):
        task_id = self.task(scenario, timeout)
        return task_id, self.engine.run(task_id)

    def test_success_persists_and_requires_exact_explicit_approval(self):
        task_id, result = self.run_task()
        self.assertEqual(result["status"], "awaiting_approval")
        reopened = Engine(Store(self.root))
        sha = reopened.check_evidence(task_id)
        with self.assertRaises(PolicyError):
            reopened.approve(task_id, "wrong", "Founder")
        self.assertEqual(reopened.approve(task_id, sha, "Founder")["status"], "approved")
        self.assertEqual([r["status"] for r in self.store.events(task_id)],
            ["created", "preparing", "implementing", "reviewing", "verifying", "awaiting_approval", "approved"])
        handoff = self.store.artifact(task_id, "handoff")
        self.assertEqual(handoff["source"], "fake-codex")
        self.assertEqual(handoff["destination"], "fake-claude-code")
        # Native orphan worktree exists but no index entry or commit was made.
        ws = self.engine.workspace(task_id)
        self.assertEqual(ws.git("-C", str(ws.path), "ls-files"), b"")
        self.assertEqual(ws.git("--git-dir=" + str(ws.repo), "for-each-ref"), b"")

    def test_failed_review_never_runs_verification(self):
        task_id, result = self.run_task("review-fail")
        self.assertEqual(result["status"], "review_failed")
        with self.assertRaises(PolicyError):
            self.store.artifact(task_id, "verification")
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Founder")

    def test_stale_reviewer_identity_is_blocked(self):
        _, result = self.run_task("stale-review")
        self.assertEqual(result["status"], "blocked")

    def test_changed_new_deleted_and_mode_changed_files_invalidate_approval(self):
        for mutation in ("change", "new", "delete", "mode"):
            with self.subTest(mutation=mutation):
                task_id, result = self.run_task()
                ws = self.engine.workspace(task_id)
                target = ws.path / "result.txt"
                if mutation == "change":
                    target.write_text("changed")
                elif mutation == "new":
                    (ws.path / "new.txt").write_text("new")
                elif mutation == "delete":
                    target.unlink()
                else:
                    target.chmod(0o700)
                with self.assertRaises(PolicyError):
                    self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Founder")
                self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_artifact_corruption_is_detected(self):
        task_id, result = self.run_task()
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body='{}' WHERE task_id=? AND kind='review'", (task_id,))
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Founder")
        self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_timeout_is_terminal_without_retry(self):
        start = time.monotonic()
        task_id, result = self.run_task("timeout", 0.2)
        self.assertEqual(result["status"], "timed_out")
        self.assertLess(time.monotonic() - start, 5)
        with self.assertRaises(PolicyError):
            self.engine.run(task_id)
        self.assertEqual(sum(e["status"] == "implementing" for e in self.store.events(task_id)), 1)

    def test_cancellation_before_and_during_execution(self):
        task_id = self.task()
        self.store.cancel(task_id)
        with self.assertRaises(PolicyError):
            self.engine.run(task_id)
        self.assertFalse((self.store.task_dir(task_id) / "repo.git").exists())
        task_id = self.task("timeout", 10)
        results = []
        thread = threading.Thread(target=lambda: results.append(self.engine.run(task_id)))
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while self.store.get(task_id)["status"] != "implementing":
                if time.monotonic() > deadline:
                    self.fail("execution failed to reach implementation")
                time.sleep(0.02)
            Store(self.root).cancel(task_id)
        finally:
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["status"], "cancelled")

    def test_permission_violation_cannot_escape_worktree(self):
        task_id, result = self.run_task("permission")
        self.assertEqual(result["status"], "blocked")
        self.assertFalse((self.store.task_dir(task_id) / "escape.txt").exists())
        self.assertEqual(self.engine.workspace(task_id).snapshot()["files"], {})
        for path in ("../escape", "/tmp/escape", ".git/config", "a/../../x", "a\\b", "a//b"):
            with self.subTest(path=path), self.assertRaises(PolicyError):
                relative_path(path)

    def test_symlinks_and_hardlinks_rejected(self):
        task_id, _ = self.run_task()
        ws = self.engine.workspace(task_id)
        (ws.path / "link").symlink_to(ws.path / "result.txt")
        with self.assertRaises(PolicyError):
            ws.snapshot()
        (ws.path / "link").unlink()
        os.link(ws.path / "result.txt", ws.path / "hardlink")
        with self.assertRaises(PolicyError):
            ws.snapshot()

    def test_malformed_and_oversized_output_fail_closed(self):
        for scenario in ("malformed", "output-limit"):
            with self.subTest(scenario=scenario):
                _, result = self.run_task(scenario)
                self.assertEqual(result["status"], "blocked")

    def test_verification_can_fail_after_review_passes(self):
        task_id, result = self.run_task("test-fail")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.store.artifact(task_id, "review")["verdict"], "approved")
        self.assertFalse(self.store.artifact(task_id, "verification")["passed"])

    def test_real_adapters_disabled(self):
        for adapter in (CodexAdapter(), ClaudeCodeAdapter()):
            with self.assertRaises(PolicyError):
                adapter.run({})

    def test_cancellation_revokes_pending_approval(self):
        task_id, result = self.run_task()
        self.store.cancel(task_id)
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Fixture")
        self.assertEqual(self.store.get(task_id)["status"], "cancelled")

    def test_non_owned_root_and_symlink_root_are_rejected(self):
        other = Path(self.tmp.name) / "unowned"
        other.mkdir()
        (other / "keep.txt").write_text("untouched")
        with self.assertRaises(PolicyError):
            Store(other)
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PolicyError):
            Store(alias)
        self.assertEqual((other / "keep.txt").read_text(), "untouched")

    def test_snapshot_budget_fails_without_truncating(self):
        task_id, result = self.run_task()
        ws = self.engine.workspace(task_id)
        (ws.path / "oversized.txt").write_bytes(b"x" * 65537)
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Fixture")
        self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_restart_recovery_does_not_replay(self):
        task_id = self.task()
        self.store.transition(task_id, "preparing", "simulated abandoned owner")
        recovered = Engine(Store(self.root)).recover(task_id)
        self.assertEqual(recovered["status"], "interrupted")
        with self.assertRaises(PolicyError):
            self.engine.run(task_id)

    def test_single_owner_lock_and_illegal_transition(self):
        task_id = self.task()
        with self.store.lock(task_id):
            with self.assertRaises(PolicyError):
                Engine(Store(self.root)).run(task_id)
        with self.assertRaises(PolicyError):
            self.store.transition(task_id, "approved", "skip controls")

    def test_disposal_preserves_dirty_worktree(self):
        task_id, result = self.run_task()
        self.engine.approve(task_id, result["evidence"]["snapshot_sha256"], "Test fixture founder")
        with self.assertRaises(PolicyError):
            self.engine.dispose(task_id)
        self.assertTrue((self.engine.workspace(task_id).path / "result.txt").exists())
        clean_id, result = self.run_task("permission")
        self.assertEqual(result["status"], "blocked")
        self.engine.dispose(clean_id)
        self.engine.dispose(clean_id)
        self.assertFalse(self.engine.workspace(clean_id).path.exists())
        self.assertTrue(self.store.get(clean_id)["disposed"])

    def test_cross_task_and_hash_tampering_rejected(self):
        request = envelope("a", "review", {"verdict": "approved"})
        with self.assertRaises(PolicyError):
            validate(request, "b", "review")
        request["payload"]["verdict"] = "changed"
        with self.assertRaises(PolicyError):
            validate(request, "a", "review")
        with self.assertRaises(PolicyError):
            decode('{"a":1,"a":2}')

    def test_cli_roundtrip_and_exit_codes(self):
        cli = Path(__file__).resolve().parents[1] / "maestro.py"
        def call(*args, ok=True):
            result = subprocess.run([sys.executable, str(cli), "--root", str(self.root), *args],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0 if ok else 2, result.stderr)
            return json.loads(result.stdout if result.returncode == 0 else result.stderr)
        task = call("create", "CLI fixture")
        task_id = task["id"]
        result = call("run", task_id)
        self.assertTrue(call("status", task_id)["evidence_current"])
        self.assertEqual(call("artifact", task_id, "handoff")["task_id"], task_id)
        call("approve", task_id, "--snapshot", "wrong", "--founder", "Fixture", ok=False)
        self.assertEqual(call("approve", task_id, "--snapshot", result["evidence"]["snapshot_sha256"],
                              "--founder", "Fixture")["status"], "approved")


class ProcessTests(unittest.TestCase):
    def test_cancellation_terminates_a_running_process(self):
        with tempfile.TemporaryDirectory(prefix="maestro-cancel-test-") as tmp:
            marker = Path(tmp) / "should-not-exist"
            child = "import time,pathlib;time.sleep(0.6);pathlib.Path(%r).write_text('bad')" % str(marker)
            start = time.monotonic()
            with self.assertRaises(Cancelled):
                execute([sys.executable, "-I", "-c", child], tmp, tmp, timeout=2,
                        cancelled=lambda: time.monotonic() - start > 0.15)
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_fake_self_expires_without_coordinator(self):
        with tempfile.TemporaryDirectory(prefix="maestro-watchdog-test-") as tmp:
            worker = Path(__file__).resolve().parents[1] / "agents.py"
            request = envelope("watchdog", "implement", {"scenario": "timeout"})
            proc = subprocess.Popen([sys.executable, "-I", str(worker), "--worker", "0.1"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=tmp, env=private_env(tmp))
            try:
                proc.communicate(json.dumps(request).encode(), timeout=4)
                self.assertLess(proc.returncode, 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()

    def test_timeout_stops_descendants_not_only_parent(self):
        # First-party fixture creates a descendant that would write after timeout.
        with tempfile.TemporaryDirectory(prefix="maestro-process-test-") as tmp:
            marker = Path(tmp) / "escaped-child"
            child = "import time,pathlib;time.sleep(0.6);pathlib.Path(%r).write_text('bad')" % str(marker)
            parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-I','-c',%r]);time.sleep(10)" % child
            with self.assertRaises(DeadlineExceeded):
                execute([sys.executable, "-I", "-c", parent], tmp, tmp, timeout=0.15)
            time.sleep(0.7)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
