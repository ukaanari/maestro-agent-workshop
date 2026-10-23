"""Regression tests for the independent audit findings F-01..F-07 (synthetic fixtures only).

Every sandbox probe uses only os/stdlib calls (no ctypes), so these tests also run on
interpreters where ctypes cannot be imported inside the profile (#7).
"""
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import doctor
import execution
from execution import Cancelled, DeadlineExceeded, PolicyError, execute, stop_group
from sandbox import (SOURCE_DIR, USER_HOME, ExecPolicy, IsolationUnavailable, Seatbelt,
                     python_runtime)
from workflow import Engine, Store

EXE, PREFIX = python_runtime()
CLI = Path(__file__).resolve().parents[1] / "maestro.py"
PROBE = r'''
import json, os, sys
results = {}
def attempt(name, action):
    try:
        results[name] = "ok:%s" % (action(),)
    except Exception as exc:
        results[name] = "denied:" + type(exc).__name__
'''
REPORT = "\nprint(json.dumps(results))\n"


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-audit-tests-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.root = self.base / "approved"
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True)

    def policy(self, **overrides):
        values = dict(executable=EXE, args=(), cwd=str(self.ws), home=str(self.ws),
                      writable=(str(self.ws),), readable=(PREFIX,), timeout=10)
        values.update(overrides)
        return ExecPolicy(**values)

    def confined(self, sandbox, code, *args):
        return json.loads(sandbox.run(self.policy(args=("-I", "-c", PROBE + code + REPORT) + args)))


class ProtectedOverlapTests(Fixture):
    """F-01: a protected path deeper than a direct child of a writable grant moved with
    an ancestor rename and escaped its deny rule."""

    def test_nested_protected_path_inside_writable_grant_is_rejected(self):
        guard = self.ws / "sub" / "guarded"
        guard.mkdir(parents=True)
        (guard / "secret.txt").write_text("SYNTHETIC-SECRET")
        sandbox = Seatbelt([str(self.root)], protected=[str(guard)], allowed_executables=[EXE])
        with self.assertRaisesRegex(PolicyError, "direct child"):
            self.confined(sandbox, 'attempt("rename", lambda: os.rename("sub", "moved"))')
        self.assertEqual((guard / "secret.txt").read_text(), "SYNTHETIC-SECRET")
        self.assertFalse((self.ws / "moved").exists())

    def test_direct_child_protection_survives_every_move_and_alias_attempt(self):
        guard = self.ws / "guarded"
        guard.mkdir()
        (guard / "secret.txt").write_text("SYNTHETIC-SECRET")
        sandbox = Seatbelt([str(self.root)], protected=[str(guard)], allowed_executables=[EXE])
        result = self.confined(sandbox, '''
ws = sys.argv[1]
os.mkdir("decoy")
os.symlink("guarded/secret.txt", "alias")
attempt("read", lambda: open("guarded/secret.txt").read())
attempt("read_case_variant", lambda: open("GUARDED/secret.txt").read())
attempt("write_case_variant", lambda: open("Guarded/secret.txt", "w").write("x"))
attempt("rename_guard", lambda: os.rename("guarded", "moved"))
attempt("replace_guard", lambda: os.replace("decoy", "guarded"))
attempt("rmdir_guard", lambda: os.rmdir("guarded"))
attempt("rename_root", lambda: os.rename(ws, ws + "-moved"))
attempt("hardlink", lambda: os.link("guarded/secret.txt", "hard"))
attempt("symlink_read", lambda: open("alias").read())
''', str(self.ws))
        for name, outcome in result.items():
            with self.subTest(probe=name):
                self.assertEqual(outcome, "denied:PermissionError")
        self.assertEqual((guard / "secret.txt").read_text(), "SYNTHETIC-SECRET")

    def test_ordinary_workspace_operations_still_work_next_to_protected_state(self):
        guard = self.ws / "guarded"
        guard.mkdir()
        sandbox = Seatbelt([str(self.root)], protected=[str(guard)], allowed_executables=[EXE])
        result = self.confined(sandbox, '''
attempt("mkdir", lambda: os.makedirs("a/b") or "made")
attempt("write", lambda: open("a/b/f.txt", "w").write("data"))
attempt("rename_dir", lambda: os.rename("a", "c") or "moved")
attempt("read", lambda: open("c/b/f.txt").read())
attempt("delete", lambda: os.remove("c/b/f.txt") or "deleted")
''')
        self.assertEqual(result, {"mkdir": "ok:made", "write": "ok:4", "rename_dir": "ok:moved",
                                  "read": "ok:data", "delete": "ok:deleted"})

    def test_protected_rule_also_denies_execution(self):
        guard = self.ws / "guarded"
        guard.mkdir()
        sandbox = Seatbelt([str(self.root)], protected=[str(guard)], allowed_executables=[EXE])
        exe, writable, readable, listable, *_ = sandbox.validate(self.policy())
        text, _ = sandbox.profile(exe, writable, readable, listable, False)
        self.assertIn("(deny file-read* file-write* process-exec* (subpath (param \"P0\")))", text)


class ProcessGroupTests(unittest.TestCase):
    """F-02: grace period, signalling after reaping, EPERM handling and cleanup failures."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-audit-proc-")
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.realpath(tmp.name)

    def test_same_group_child_gets_grace_after_leader_exits(self):
        marker = os.path.join(self.dir, "graceful")
        child = ("import signal,sys,time,pathlib\n"
                 "def handler(*_):\n time.sleep(0.05); pathlib.Path(%r).write_text('ok'); sys.exit(0)\n"
                 "signal.signal(signal.SIGTERM, handler)\ntime.sleep(30)") % marker
        leader = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-I','-c',%r]); time.sleep(0.15)" % child
        with self.assertRaises(DeadlineExceeded):
            execute([sys.executable, "-I", "-c", leader], self.dir, self.dir, timeout=0.6)
        time.sleep(0.2)
        self.assertTrue(os.path.exists(marker), "SIGTERM grace was skipped for the same-group child")

    def test_straggler_in_the_group_is_stopped_after_a_normal_exit(self):
        pidfile = os.path.join(self.dir, "straggler.pid")
        leader = ("import subprocess,sys; p = subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],"
                  " stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL);"
                  "open(%r,'w').write(str(p.pid))" % pidfile)
        self.assertEqual(execute([sys.executable, "-I", "-c", leader], self.dir, self.dir, timeout=5), b"")
        pid = int(open(pidfile).read())
        deadline = time.monotonic() + 2
        while execution.process_state(pid) == "live":
            self.assertLess(time.monotonic(), deadline, "same-group straggler survived a normal exit")
            time.sleep(0.02)

    def test_no_signal_is_sent_after_the_child_was_reaped(self):
        seen, after_reap = {}, []
        real_stop, real_killpg = execution.stop_group, os.killpg

        def stop(proc):
            seen["proc"] = proc
            return real_stop(proc)

        def killpg(pgid, sig):
            if seen.get("proc") is not None and seen["proc"].returncode is not None:
                after_reap.append(sig)
            return real_killpg(pgid, sig)

        with mock.patch.object(execution, "stop_group", stop), mock.patch.object(execution.os, "killpg", killpg):
            self.assertEqual(execute([sys.executable, "-I", "-c", "print('hi')"], self.dir, self.dir), b"hi\n")
        self.assertEqual(after_reap, [])

    def test_eperm_with_a_live_member_is_an_error_not_success(self):
        pidfile = os.path.join(self.dir, "child.pid")
        leader = ("import os,subprocess,sys; p = subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)']);"
                  "open(%r,'w').write(str(p.pid))" % pidfile)
        proc = subprocess.Popen([sys.executable, "-I", "-c", leader], start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (os.path.exists(pidfile) and os.path.getsize(pidfile)):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            real = os.killpg

            def eperm(pgid, sig):
                if sig:
                    raise PermissionError(1, "Operation not permitted")
                return real(pgid, sig)

            with mock.patch.object(execution.os, "killpg", eperm):
                with self.assertRaisesRegex(PolicyError, "cannot signal live member"):
                    stop_group(proc)
        finally:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()

    def test_reap_timeout_is_reported_and_pipes_are_closed(self):
        procs, real_wait = [], subprocess.Popen.wait

        def wait(self, timeout=None):
            procs.append(self)
            if timeout == execution.REAP:
                raise subprocess.TimeoutExpired(self.args, timeout)
            return real_wait(self, timeout)

        try:
            with mock.patch.object(subprocess.Popen, "wait", wait):
                with self.assertRaisesRegex(PolicyError, "not reaped"):
                    execute([sys.executable, "-I", "-c", "import time; time.sleep(5)"], self.dir, self.dir, timeout=0.2)
            self.assertTrue(procs[-1].stdout.closed and procs[-1].stderr.closed)
        finally:
            for proc in procs:
                if proc.returncode is None:
                    real_wait(proc)


class PolicyValidationTests(Fixture):
    """F-03: policy validation gaps."""

    def test_user_home_comes_from_the_password_database_not_home_env(self):
        out = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import sandbox; "
                              "print(sandbox.USER_HOME)" % str(Path(SOURCE_DIR))],
                             env={"HOME": str(self.base), "PATH": "/usr/bin:/bin"},
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.stdout.strip(), USER_HOME)
        self.assertNotEqual(out.stdout.strip(), str(self.base))

    def test_listable_grants_are_limited_to_source_and_approved_roots(self):
        sandbox = Seatbelt([str(self.root)], allowed_executables=[EXE])
        for path in ("/", str(Path(USER_HOME).parent), USER_HOME, "/Applications", "/usr/bin"):
            with self.subTest(path=path), self.assertRaises(PolicyError):
                sandbox.validate(self.policy(listable=(path,)))
        inner = self.root / "inner"
        inner.mkdir()
        for path in (SOURCE_DIR, str(inner)):
            with self.subTest(path=path):
                sandbox.validate(self.policy(listable=(path,)))

    def test_executables_in_agent_roots_or_protected_state_are_rejected(self):
        state = self.root / "state"
        state.mkdir()
        for folder in (self.root / "other", state):
            folder.mkdir(exist_ok=True)
            tool = folder / "tool"
            shutil.copyfile("/usr/bin/true", tool)
            tool.chmod(0o755)
            sandbox = Seatbelt([str(self.root)], protected=[str(state)], allowed_executables=[EXE, str(tool)])
            with self.subTest(folder=folder.name), self.assertRaisesRegex(PolicyError, "outside agent roots"):
                sandbox.validate(self.policy(executable=str(tool)))

    def test_shared_or_broadly_writable_approved_roots_are_rejected(self):
        loose = self.base / "loose"
        loose.mkdir()
        loose.chmod(0o777)
        self.addCleanup(loose.chmod, 0o700)
        for root in (str(loose), "/private/tmp"):
            with self.subTest(root=root), self.assertRaises(PolicyError):
                Seatbelt([root], allowed_executables=[EXE])

    def test_symlinked_sandbox_engine_is_refused_before_anything_runs(self):
        link = self.base / "sandbox-exec"
        link.symlink_to("/usr/bin/sandbox-exec")
        sandbox = Seatbelt([str(self.root)], allowed_executables=[EXE], binary=str(link))
        with self.assertRaisesRegex(IsolationUnavailable, "symlinks are refused"):
            self.confined(sandbox, 'open("launched.txt", "w").write("x")')
        self.assertFalse((self.ws / "launched.txt").exists())

    def test_engine_that_fakes_the_self_test_is_detected(self):
        stub_dir = self.base / "stub"
        stub_dir.mkdir()
        stub = stub_dir / "sandbox-exec"
        # Never runs the target: creates the inside file itself and reports success.
        stub.write_text('#!/bin/sh\nfor a in "$@"; do prev=$last; last=$a; done\n/usr/bin/touch "$prev"\nexit 0\n')
        stub.chmod(0o700)
        sandbox = Seatbelt([str(self.root)], allowed_executables=[EXE], binary=str(stub))
        with self.assertRaises(IsolationUnavailable):
            self.confined(sandbox, 'open("launched.txt", "w").write("x")')
        self.assertFalse((self.ws / "launched.txt").exists())


class EvidenceAndDisposalTests(unittest.TestCase):
    """F-05 and F-07: directory evidence, evidence-bound disposal, malformed records."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-audit-flow-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "state"
        self.store = Store(self.root)
        self.engine = Engine(self.store)

    def run_task(self, target="result.txt"):
        task_id = self.store.create("Audit fixture", target=target)
        result = self.engine.run(task_id)
        self.assertEqual(result["status"], "awaiting_approval")
        return task_id, result["evidence"]["snapshot_sha256"]

    def test_directory_added_or_rechmodded_after_review_invalidates_approval(self):
        for mutation in ("new_empty_dir", "dir_mode"):
            with self.subTest(mutation=mutation):
                task_id, sha = self.run_task("pkg/result.txt")
                path = self.engine.workspace(task_id).path
                if mutation == "new_empty_dir":
                    (path / "added").mkdir()
                else:
                    (path / "pkg").chmod(0o777)
                with self.assertRaises(PolicyError):
                    self.engine.approve(task_id, sha, "Fixture")
                self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_nested_target_records_and_verifies_its_directories(self):
        task_id, _ = self.run_task("pkg/sub/result.txt")
        snapshot = self.store.artifact(task_id, "handoff")["snapshot"]
        self.assertEqual(sorted(snapshot["dirs"]), ["pkg", "pkg/sub"])
        self.assertTrue(self.store.artifact(task_id, "verification")["passed"])

    def test_reviewed_output_can_be_disposed_only_when_it_matches_evidence(self):
        task_id, sha = self.run_task("pkg/result.txt")
        self.engine.approve(task_id, sha, "Fixture")
        with self.assertRaises(PolicyError):
            self.engine.dispose(task_id)  # default stays clean-only
        changed_id, changed_sha = self.run_task()
        self.engine.approve(changed_id, changed_sha, "Fixture")
        (self.engine.workspace(changed_id).path / "result.txt").write_text("edited after approval")
        with self.assertRaisesRegex(PolicyError, "differs from the reviewed evidence"):
            self.engine.dispose(changed_id, remove_reviewed_output=True)
        self.assertEqual((self.engine.workspace(changed_id).path / "result.txt").read_text(), "edited after approval")
        self.engine.dispose(task_id, remove_reviewed_output=True)
        self.assertFalse(self.engine.workspace(task_id).path.exists())
        self.assertTrue(self.store.get(task_id)["disposed"])
        handoff = self.store.artifact(task_id, "handoff")
        self.assertEqual(handoff["snapshot"]["files"]["pkg/result.txt"]["text"], "MAESTRO P0\n")

    def test_dispose_flag_via_cli(self):
        task_id, sha = self.run_task()
        self.engine.approve(task_id, sha, "Fixture")
        out = subprocess.run([sys.executable, "-B", str(CLI), "--root", str(self.root), "dispose",
                              task_id, "--remove-reviewed-output"], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["disposed"], 1)

    def test_cancel_racing_the_first_transition_ends_cleanly(self):
        task_id = self.store.create("Race fixture")
        real = Store.transition

        def racing(store, tid, status, message, evidence=None):
            if status == "preparing":
                store.cancel(tid)
            return real(store, tid, status, message, evidence)

        with mock.patch.object(Store, "transition", racing):
            self.assertEqual(self.engine.run(task_id)["status"], "cancelled")
        self.assertFalse((self.store.task_dir(task_id) / "repo.git").exists())

    def test_malformed_records_fail_as_policy(self):
        task_id, sha = self.run_task()
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body='[]', hash=? WHERE task_id=? AND kind='review'",
                         (__import__("workspace").digest([]), task_id))
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, sha, "Fixture")
        self.assertEqual(self.store.get(task_id)["status"], "invalidated")
        other_id, other_sha = self.run_task()
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET evidence='[]' WHERE id=?", (other_id,))
        with self.assertRaisesRegex(PolicyError, "malformed task record"):
            self.engine.approve(other_id, other_sha, "Fixture")

    def test_task_specification_must_still_match_the_handoff(self):
        task_id, sha = self.run_task()
        with self.store.connect() as conn:
            row = conn.execute("SELECT spec FROM tasks WHERE id=?", (task_id,)).fetchone()
            spec = json.loads(row["spec"])
            spec["expected"] = "something else"
            conn.execute("UPDATE tasks SET spec=? WHERE id=?", (json.dumps(spec), task_id))
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, sha, "Fixture")
        self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_non_numeric_timeouts_are_rejected(self):
        for timeout in (True, "5"):
            with self.subTest(timeout=timeout), self.assertRaises((PolicyError, TypeError)):
                self.store.create("Bad budget", timeout=timeout)


class SelfTestCancellationTests(Fixture):
    """F-07: the per-launch self-test observes cancellation."""

    def test_self_test_honours_cancellation(self):
        with self.assertRaises(Cancelled):
            Seatbelt([str(self.root)], allowed_executables=[EXE]).available(cancelled=lambda: True)


class DoctorReliabilityTests(unittest.TestCase):
    """F-06 (and the F-04 interpreter warning): doctor always reports, never crashes."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-audit-dr-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))

    def test_unreadable_state_root_is_a_structured_failure(self):
        root = self.base / "locked"
        root.mkdir()
        (root / "x").write_text("x")
        root.chmod(0)
        self.addCleanup(root.chmod, 0o700)
        self.assertEqual(doctor.check_state_root(root)["status"], "fail")
        out = subprocess.run([sys.executable, "-B", str(CLI), "--root", str(root), "doctor"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        report = {c["check"]: c["status"] for c in json.loads(out.stdout)["checks"]}
        self.assertEqual(report["state_root"], "fail")

    def test_unsafe_database_and_task_paths_are_reported(self):
        Store(self.base / "db-link")
        db = self.base / "db-link" / "state.sqlite3"
        db.unlink()
        db.symlink_to(self.base / "elsewhere.sqlite3")
        Store(self.base / "tasks-link")
        tasks = self.base / "tasks-link" / "tasks"
        tasks.rmdir()
        tasks.symlink_to(self.base, target_is_directory=True)
        for root in ("db-link", "tasks-link"):
            with self.subTest(root=root):
                self.assertEqual(doctor.check_state_root(self.base / root)["status"], "fail")
        self.assertEqual(doctor.check_state_root(self.base / "fresh")["status"], "ok")

    def test_probe_timeouts_and_crashing_checks_become_failures(self):
        with mock.patch.object(Seatbelt, "available", side_effect=DeadlineExceeded("probe timed out")):
            self.assertEqual(doctor.check_sandbox()["status"], "fail")
        with mock.patch.object(doctor, "check_git", side_effect=KeyError("boom")):
            report = doctor.run_checks(self.base / "state")
        git = next(c for c in report["checks"] if c["check"] == "git")
        self.assertEqual(git["status"], "fail")
        self.assertIn("KeyError", git["detail"])
        self.assertFalse(report["ok"])

    def test_interpreters_other_than_the_supported_one_warn(self):
        exe = python_runtime()[0]
        self.assertEqual(doctor.check_python(exe, "/opt/python", (3, 9, 6))["status"], "ok")
        newer = doctor.check_python(exe, "/opt/python", (3, 15, 0))
        self.assertEqual(newer["status"], "warn")
        self.assertIn("#7", newer["detail"])


if __name__ == "__main__":
    unittest.main()
