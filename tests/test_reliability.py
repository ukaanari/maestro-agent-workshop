"""Offline reliability tests: Trusted Local recovery, cancellation races, and CLI error handling.

No model, login, network service or credentials. Covers deterministic races:
- start / recover
- cancel / owner release
- cancel / approve
- concurrent recover
- partial review & partial export crash recovery
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import maestro
import trusted
from execution import Cancelled, DeadlineExceeded, PolicyError
from workflow import Store

FAKE = ROOT / "tests" / "fixtures" / "fake_codex.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("reliability_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")


class CliErrorHandlingTests(unittest.TestCase):
    """Runs on every Python interpreter."""

    def setUp(self):
        # maestro.main() calls os.umask(0o077); restore the process umask so later
        # in-process tests (such as mode-change checks) see the original umask.
        old = os.umask(0o077)
        os.umask(old)
        self.addCleanup(os.umask, old)

    def test_cli_catches_deadline_exceeded_as_structured_json(self):
        err = io.StringIO()
        with patch.object(maestro, "Store", side_effect=DeadlineExceeded("git timed out")), \
                patch.object(sys, "stderr", err):
            code = maestro.main(["status", "0123456789abcdef"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err.getvalue()), {"error": "git timed out"})

    def test_cli_catches_keyboard_interrupt_as_structured_json(self):
        err = io.StringIO()
        with patch.object(maestro, "Store", side_effect=KeyboardInterrupt()), \
                patch.object(sys, "stderr", err):
            code = maestro.main(["status", "0123456789abcdef"])
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(err.getvalue()), {"error": "interrupted"})


@RUNTIME
class TrustedRecoveryAndCancelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".reliability-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.repo = self.root / "source"
        self.base = fixture.make_fixture(self.repo)
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def task_file(self, extra=""):
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text((self.repo / "TASK.md").read_text() + ("\n" + extra if extra else ""))
        return task

    def start(self, scenario="success", review_model=None):
        result = self.engine.start(
            self.repo, self.base, self.task_file("scenario: " + scenario), "test-model",
            review_model=review_model,
        )
        self.assertEqual(result["status"], "preparing")
        return result["id"]

    def force_status(self, task_id, status, *, drop_clone_ready=False):
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET status=? WHERE id=?", (status, task_id))
            if drop_clone_ready:
                conn.execute("DELETE FROM artifacts WHERE task_id=? AND kind='clone_ready'", (task_id,))

    def wait_file(self, path):
        deadline = time.monotonic() + 15
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail("signal file did not appear: " + str(path))
            select.select([], [], [], 0.01)
        return path

    def test_01_recover_marks_abandoned_mid_phase_tasks_interrupted_and_is_honest_about_cleanup(self):
        cases = (
            ("created", True),
            ("preparing", True),  # crashed before clone_ready was recorded
            ("implementing", False),
            ("verifying", False),
        )
        for status, drop_ready in cases:
            with self.subTest(status=status):
                task_id = self.start()
                self.force_status(task_id, status, drop_clone_ready=drop_ready)
                recovered = self.engine.recover(task_id)
                self.assertEqual(recovered["status"], "interrupted")
                self.assertEqual(self.engine.next_steps(recovered), [])
                self.assertEqual(recovered["recovery"]["reason"], "abandoned_active")
                self.assertFalse(recovered["recovery"]["restarted_agents"])
                self.assertFalse(recovered["recovery"]["process_cleanup_verified"])
                self.assertIn("not verified", self.store.events(task_id)[-1]["message"])
                # Single-attempt preserved: no subsequent phase can proceed.
                with self.assertRaises(PolicyError):
                    self.engine.implement(task_id, str(FAKE))
                with self.assertRaises(PolicyError):
                    self.engine.verify(task_id)

    def test_02_recover_refuses_resting_states_clean_approved_active_owner_and_confined(self):
        prep_id = self.start()
        with self.assertRaisesRegex(PolicyError, "abandoned"):
            self.engine.recover(prep_id)
        self.assertEqual(self.store.get(prep_id)["status"], "preparing")

        rev_id = self.start()
        self.assertEqual(self.engine.implement(rev_id, str(FAKE))["status"], "reviewing")
        with self.assertRaisesRegex(PolicyError, "abandoned"):
            self.engine.recover(rev_id)
        self.assertEqual(self.store.get(rev_id)["status"], "reviewing")

        self.assertEqual(self.engine.verify(rev_id)["status"], "awaiting_approval")
        with self.assertRaisesRegex(PolicyError, "abandoned"):
            self.engine.recover(rev_id)
        sha = self.store.get(rev_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(rev_id, sha, "Human")
        with self.assertRaisesRegex(PolicyError, "abandoned"):
            self.engine.recover(rev_id)

        locked_id = self.start()
        self.force_status(locked_id, "implementing")
        with self.store.lock(locked_id):
            with self.assertRaisesRegex(PolicyError, "active owner"):
                self.engine.recover(locked_id)
        self.assertEqual(self.store.get(locked_id)["status"], "implementing")

        confined = self.store.create("confined")
        with self.assertRaisesRegex(PolicyError, "mode trusted-local"):
            self.engine.recover(confined)

    def test_03_start_and_recover_race_cannot_interrupt_starting_task(self):
        # start() must hold executor.lock BEFORE inserting the DB row, so a recover()
        # arriving right after INSERT (while status=='created') always sees active owner.
        real_guard = trusted.source_guard
        race_outcome = []

        def intercept_first_source_guard(repo, home):
            if not race_outcome:
                task_id = home.name
                self.assertEqual(self.store.get(task_id)["status"], "created")
                try:
                    self.engine.recover(task_id)
                    race_outcome.append("unexpected-recovered")
                except PolicyError as exc:
                    race_outcome.append(str(exc))
            return real_guard(repo, home)

        with patch.object(trusted, "source_guard", side_effect=intercept_first_source_guard):
            started = self.engine.start(self.repo, self.base, self.task_file("scenario: success"), "test-model")
        self.assertEqual(race_outcome, ["task already has an active owner"])
        self.assertEqual(started["status"], "preparing")
        self.assertTrue(self.store.has_artifact(started["id"], "clone_ready"))

    def test_04_cancel_and_owner_release_race_never_leaves_task_stuck_non_terminal(self):
        # Deterministically reproduce the race where an owner holds executor.lock during
        # cancel()'s first lock probe, then releases the lock just before cancel=1 commits.
        task_id = self.start()
        self.assertEqual(self.engine.implement(task_id, str(FAKE))["status"], "reviewing")

        owner_locked = threading.Event()
        release_owner = threading.Event()

        def hold_and_release():
            with self.store.lock(task_id):
                owner_locked.set()
                release_owner.wait(timeout=10)

        owner = threading.Thread(target=hold_and_release)
        owner.start()
        self.assertTrue(owner_locked.wait(timeout=5))

        real_request = self.engine._request_cancel_flag

        def release_during_flag(tid):
            release_owner.set()
            owner.join(timeout=5)
            return real_request(tid)

        try:
            with patch.object(self.engine, "_request_cancel_flag", side_effect=release_during_flag):
                cancelled = self.engine.cancel(task_id)
        finally:
            release_owner.set()
            owner.join(timeout=5)

        self.assertEqual(cancelled["status"], "cancelled")
        self.assertTrue(cancelled["cancel"])
        self.assertEqual(cancelled["cancellation"]["mode"], "immediate_after_owner_release")
        self.assertFalse(cancelled["cancellation"]["process_cleanup_verified"])
        with self.assertRaises(PolicyError):
            self.engine.verify(task_id)

    def test_05_cancel_and_approve_race_is_atomic_with_no_orphaned_approval(self):
        # Case A: cancel arrives while approve() holds executor.lock inside checked().
        # Cancellation must win cleanly (status=='cancelled', NOT 'invalidated', NO approval artifact).
        task_id = self.start()
        self.assertEqual(self.engine.implement(task_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval")
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]

        real_checked = self.engine.checked
        cancel_res = []

        def cancel_mid_approve(tid):
            snap = real_checked(tid)
            cancel_res.append(self.engine.cancel(tid))
            return snap

        with patch.object(self.engine, "checked", side_effect=cancel_mid_approve):
            with self.assertRaises(Cancelled):
                self.engine.approve(task_id, sha, "Human")

        self.assertEqual(cancel_res[0]["cancellation"]["mode"], "signalled_active_owner")
        self.assertEqual(self.store.get(task_id)["status"], "cancelled")
        self.assertTrue(self.store.get(task_id)["cancel"])
        self.assertFalse(self.store.has_artifact(task_id, "approval"))
        with self.assertRaises(PolicyError):
            self.engine.export(task_id)

        # Case B: once approve() commits, cancel() fails cleanly without setting cancel=1.
        ok_id = self.start()
        self.assertEqual(self.engine.implement(ok_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(ok_id)["status"], "awaiting_approval")
        ok_sha = self.store.get(ok_id)["evidence"]["snapshot_sha256"]
        self.assertEqual(self.engine.approve(ok_id, ok_sha, "Human")["status"], "approved")
        with self.assertRaisesRegex(PolicyError, "terminal"):
            self.engine.cancel(ok_id)
        self.assertEqual(self.store.get(ok_id)["status"], "approved")
        self.assertFalse(self.store.get(ok_id)["cancel"])

    def test_06_concurrent_recover_allows_exactly_one_winner(self):
        task_id = self.start()
        self.force_status(task_id, "implementing")

        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def worker():
            eng = trusted.TrustedEngine(Store(self.store.root), test_context=True)
            barrier.wait(timeout=10)
            try:
                res = eng.recover(task_id)
                entry = ("ok", res["status"])
            except PolicyError as exc:
                entry = ("err", str(exc))
            with lock:
                outcomes.append(entry)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "err"]
        self.assertEqual(len(winners), 1, outcomes)
        self.assertEqual(winners[0][1], "interrupted")
        self.assertEqual(len(losers), 1, outcomes)
        self.assertEqual(self.store.get(task_id)["status"], "interrupted")

    def test_07_partial_review_and_partial_export_crashes_fail_closed_and_recover_cleanly(self):
        # Partial review: review-1/ created on disk before review.1 artifact recorded.
        rev_id = self.start(review_model="test-reviewer")
        self.assertEqual(self.engine.implement(rev_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(rev_id)["status"], "awaiting_approval")
        partial_dir = self.store.task_dir(rev_id) / "review-1"
        partial_dir.mkdir(mode=0o700)
        (partial_dir / "input.txt").write_text("partial")

        recovered = self.engine.recover(rev_id)
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["recovery"]["reason"], "partial_review")
        self.assertFalse(recovered["recovery"]["restarted_agents"])
        self.assertFalse(recovered["recovery"]["process_cleanup_verified"])
        self.assertTrue(partial_dir.is_dir())
        with self.assertRaises(PolicyError):
            self.engine.review(rev_id, str(FAKE_CLAUDE))

        # Partial export: export.patch written on disk before export artifact recorded.
        exp_id = self.start()
        self.assertEqual(self.engine.implement(exp_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(exp_id)["status"], "awaiting_approval")
        sha = self.store.get(exp_id)["evidence"]["snapshot_sha256"]
        self.assertEqual(self.engine.approve(exp_id, sha, "Human")["status"], "approved")
        patch_file = self.store.task_dir(exp_id) / "export.patch"
        patch_file.write_bytes(b"partial-unrecorded-patch")

        # Subsequent export() MUST fail closed without overwriting partial export.patch.
        with self.assertRaisesRegex(PolicyError, "partial export"):
            self.engine.export(exp_id)
        self.assertEqual(patch_file.read_bytes(), b"partial-unrecorded-patch")

        # recover() invalidates the partial-export task without overwriting export.patch.
        rec_exp = self.engine.recover(exp_id)
        self.assertEqual(rec_exp["status"], "invalidated")
        self.assertEqual(rec_exp["recovery"]["reason"], "partial_export")
        self.assertFalse(rec_exp["recovery"]["process_cleanup_verified"])
        self.assertEqual(patch_file.read_bytes(), b"partial-unrecorded-patch")

    def test_08_cancel_resting_and_running_tasks_and_cli(self):
        # Resting preparing -> immediate cancel.
        prep_id = self.start()
        c_prep = self.engine.cancel(prep_id)
        self.assertEqual(c_prep["status"], "cancelled")
        self.assertEqual(c_prep["cancellation"]["mode"], "immediate")
        self.assertEqual(self.engine.cancel(prep_id)["cancellation"]["mode"], "already_cancelled")

        # Active running worker -> signalled without blocking.
        run_id = self.start("timeout")
        results = []
        worker = threading.Thread(target=lambda: results.append(self.engine.implement(run_id, str(FAKE), timeout=15)))
        worker.start()
        try:
            self.wait_file(self.store.task_dir(run_id) / "fake.started")
            mid = self.engine.cancel(run_id)
            self.assertTrue(mid["cancel"])
            self.assertEqual(mid["cancellation"]["mode"], "signalled_active_owner")
            self.assertFalse(mid["cancellation"]["process_cleanup_verified"])
        finally:
            worker.join(timeout=15)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0]["status"], "cancelled")

        # CLI end-to-end check.
        cli_id = self.start()
        self.force_status(cli_id, "implementing")
        res = subprocess.run(
            ["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root", str(self.store.root),
             "trusted", "recover", cli_id],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        body = json.loads(res.stdout)
        self.assertEqual(body["status"], "interrupted")
        self.assertFalse(body["recovery"]["process_cleanup_verified"])
        self.assertEqual(body["next"], [])

    def test_09_real_subprocess_sigkill_crash_and_stale_lock_file_recovery(self):
        # Spawn a real separate process that acquires flock on executor.lock while the task
        # is in `implementing`, verify recover() refuses while it is alive, SIGKILL it so
        # executor.lock remains on disk as a stale lock file, then verify recover() succeeds.
        task_id = self.start()
        self.force_status(task_id, "implementing")
        task_dir = self.store.task_dir(task_id)
        lock_file = task_dir / "executor.lock"
        ready_file = task_dir / "holder.ready"

        holder_code = (
            "import fcntl, os, select, sys\n"
            "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "open(sys.argv[2], 'w').write(str(os.getpid()))\n"
            "while True:\n"
            "    select.select([], [], [], 1)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-B", "-c", holder_code, str(lock_file), str(ready_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self.wait_file(ready_file)
            with self.assertRaisesRegex(PolicyError, "active owner"):
                self.engine.recover(task_id)
            os.kill(proc.pid, signal.SIGKILL)
        finally:
            proc.wait(timeout=10)

        # Stale executor.lock file still exists on disk, but kernel released flock on SIGKILL.
        self.assertTrue(lock_file.exists())
        recovered = self.engine.recover(task_id)
        self.assertEqual(recovered["status"], "interrupted")
        self.assertTrue(recovered["recovery"]["owner_lock_acquired"])
        self.assertFalse(recovered["recovery"]["restarted_agents"])
        self.assertFalse(recovered["recovery"]["process_cleanup_verified"])

    def test_10_repeated_cancellation_terminal_guarantee_and_terminal_preservation(self):
        # 1. Repeated cancellation on resting task is idempotent and guarantees terminal state.
        tid = self.start()
        c1 = self.engine.cancel(tid)
        ev_count = len(self.store.events(tid))
        c2 = self.engine.cancel(tid)
        c3 = self.engine.cancel(tid)
        self.assertEqual(c1["status"], "cancelled")
        self.assertTrue(c1["cancellation"]["terminal_guaranteed"])
        self.assertFalse(c1["cancellation"]["process_cleanup_verified"])
        self.assertEqual(c2["cancellation"]["mode"], "already_cancelled")
        self.assertEqual(c3["cancellation"]["mode"], "already_cancelled")
        self.assertEqual(len(self.store.events(tid)), ev_count)

        # 2. Signalling an active owner explicitly reports terminal_guaranteed=False and empty next_steps.
        locked_id = self.start()
        self.force_status(locked_id, "implementing")
        with self.store.lock(locked_id):
            sig = self.engine.cancel(locked_id)
            self.assertEqual(sig["cancellation"]["mode"], "signalled_active_owner")
            self.assertFalse(sig["cancellation"]["terminal_guaranteed"])
            self.assertFalse(sig["cancellation"]["process_cleanup_verified"])
            self.assertEqual(self.engine.next_steps(sig), [])
            # Repeated cancel while still locked does not duplicate log entries or fail.
            sig2 = self.engine.cancel(locked_id)
            self.assertEqual(sig2["cancellation"]["mode"], "signalled_active_owner")

        # 3. Terminal states are never overwritten by cancel() or clean recover().
        for term in ("approved", "rejected", "failed", "timed_out", "interrupted", "invalidated", "blocked"):
            with self.subTest(terminal=term):
                t = self.start()
                self.force_status(t, term)
                with self.assertRaisesRegex(PolicyError, "terminal"):
                    self.engine.cancel(t)
                with self.assertRaisesRegex(PolicyError, "abandoned"):
                    self.engine.recover(t)
                self.assertEqual(self.store.get(t)["status"], term)


if __name__ == "__main__":
    unittest.main()
