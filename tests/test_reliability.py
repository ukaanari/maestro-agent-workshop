"""Offline reliability tests: Trusted Local recovery, resting-state cancel, and CLI error handling.

No model, login, network service or credentials.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import select
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
from execution import DeadlineExceeded, PolicyError
from workflow import Store

FAKE = ROOT / "tests" / "fixtures" / "fake_codex.py"
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

    def start(self, scenario="success"):
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text((self.repo / "TASK.md").read_text() + "\nscenario: " + scenario)
        result = self.engine.start(self.repo, self.base, task, "test-model")
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

    def test_01_recover_marks_abandoned_mid_phase_tasks_interrupted_no_retry(self):
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
                # Single-attempt preserved: no subsequent phase can proceed.
                with self.assertRaises(PolicyError):
                    self.engine.implement(task_id, str(FAKE))
                with self.assertRaises(PolicyError):
                    self.engine.verify(task_id)

    def test_02_recover_refuses_resting_states_terminal_tasks_active_owner_and_confined(self):
        # Resting preparing (with clone_ready) is NOT abandoned.
        prep_id = self.start()
        with self.assertRaisesRegex(PolicyError, "abandoned active"):
            self.engine.recover(prep_id)
        self.assertEqual(self.store.get(prep_id)["status"], "preparing")

        # Resting reviewing (after implement) is NOT abandoned.
        rev_id = self.start()
        self.assertEqual(self.engine.implement(rev_id, str(FAKE))["status"], "reviewing")
        with self.assertRaisesRegex(PolicyError, "abandoned active"):
            self.engine.recover(rev_id)
        self.assertEqual(self.store.get(rev_id)["status"], "reviewing")

        # awaiting_approval and terminal approved are refused.
        self.assertEqual(self.engine.verify(rev_id)["status"], "awaiting_approval")
        with self.assertRaisesRegex(PolicyError, "abandoned active"):
            self.engine.recover(rev_id)
        sha = self.store.get(rev_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(rev_id, sha, "Human")
        with self.assertRaisesRegex(PolicyError, "abandoned active"):
            self.engine.recover(rev_id)

        # Active lock owner MUST NOT be recovered.
        locked_id = self.start()
        self.force_status(locked_id, "implementing")
        with self.store.lock(locked_id):
            with self.assertRaisesRegex(PolicyError, "active owner"):
                self.engine.recover(locked_id)
        self.assertEqual(self.store.get(locked_id)["status"], "implementing")

        # Confined mode task is refused by trusted recover.
        confined = self.store.create("confined")
        with self.assertRaisesRegex(PolicyError, "mode trusted-local"):
            self.engine.recover(confined)

    def test_03_cancel_immediately_ends_resting_preparing_and_reviewing_tasks(self):
        # Resting in preparing (after start).
        prep_id = self.start()
        cancelled = self.engine.cancel(prep_id)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertTrue(cancelled["cancel"])
        self.assertEqual(self.engine.next_steps(cancelled), [])
        # Idempotent cancel.
        self.assertEqual(self.engine.cancel(prep_id)["status"], "cancelled")
        with self.assertRaises(PolicyError):
            self.engine.implement(prep_id, str(FAKE))

        # Resting in reviewing (after implement).
        rev_id = self.start()
        self.assertEqual(self.engine.implement(rev_id, str(FAKE))["status"], "reviewing")
        cancelled_rev = self.engine.cancel(rev_id)
        self.assertEqual(cancelled_rev["status"], "cancelled")
        with self.assertRaises(PolicyError):
            self.engine.verify(rev_id)

        # Terminal task cannot be cancelled.
        done_id = self.start()
        self.assertEqual(self.engine.implement(done_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(done_id)["status"], "awaiting_approval")
        self.engine.reject(done_id, "Human", "No")
        with self.assertRaisesRegex(PolicyError, "terminal"):
            self.engine.cancel(done_id)

    def test_04_cancel_while_owner_is_running_signals_owner_without_blocking(self):
        task_id = self.start("timeout")
        results = []
        worker = threading.Thread(target=lambda: results.append(self.engine.implement(task_id, str(FAKE), timeout=15)))
        worker.start()
        try:
            self.wait_file(self.store.task_dir(task_id) / "fake.started")
            mid = self.engine.cancel(task_id)
            self.assertTrue(mid["cancel"])
        finally:
            worker.join(timeout=15)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0]["status"], "cancelled")
        self.assertTrue(self.store.has_artifact(task_id, "cleanup"))

    def test_05_cli_trusted_recover_and_cancel(self):
        task_id = self.start()
        self.force_status(task_id, "implementing")
        res = subprocess.run(
            ["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root", str(self.store.root),
             "trusted", "recover", task_id],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        body = json.loads(res.stdout)
        self.assertEqual(body["status"], "interrupted")
        self.assertEqual(body["next"], [])

        prep_id = self.start()
        res_cancel = subprocess.run(
            ["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root", str(self.store.root),
             "trusted", "cancel", prep_id],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res_cancel.returncode, 0, res_cancel.stderr)
        cancel_body = json.loads(res_cancel.stdout)
        self.assertEqual(cancel_body["status"], "cancelled")
        self.assertEqual(cancel_body["next"], [])


if __name__ == "__main__":
    unittest.main()
