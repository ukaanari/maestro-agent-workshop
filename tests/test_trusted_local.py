"""Offline Trusted Local acceptance tests. No model, login, network service or credentials."""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import trusted
from execution import Cancelled, PolicyError
from sandbox import Seatbelt
from workflow import Engine, Store
from workspace import canonical

FAKE = ROOT / "tests" / "fixtures" / "fake_codex.py"
spec = importlib.util.spec_from_file_location("trusted_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
# The same runtime trusted.TrustedEngine.start() requires; elsewhere these skip, never fail.
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
CANARIES = {"GITHUB_TOKEN": "test-only-sentinel", "AWS_SECRET_ACCESS_KEY": "test-only-sentinel",
            "ANTHROPIC_API_KEY": "test-only-sentinel", "MAESTRO_CANARY_SECRET": "test-only-sentinel",
            "HTTPS_PROXY": "http://user:test-only-sentinel@127.0.0.1:9"}


@RUNTIME
class TrustedLocalAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".trusted-tests-", dir=ROOT)
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
        self.assertEqual(result["status"], "preparing", result)
        return result["id"]

    def implement(self, scenario="success"):
        task_id = self.start(scenario)
        result = self.engine.implement(task_id, str(FAKE))
        self.assertEqual(result["status"], "reviewing", self.store.events(task_id))
        return task_id

    def verified(self, scenario="success"):
        task_id = self.implement(scenario)
        result = self.engine.verify(task_id)
        self.assertEqual(result["status"], "awaiting_approval", self.store.events(task_id))
        return task_id

    def approve(self, task_id):
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.assertEqual(self.engine.approve(task_id, sha, "Offline test human")["status"], "approved")
        return sha

    def clone(self, task_id):
        return self.store.task_dir(task_id) / "clone"

    def git(self, path, *args):
        return trusted.git(path, self.root, *args)

    def wait_file(self, path):
        deadline = time.monotonic() + 15
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail("signal file did not appear: " + str(path))
            select.select([], [], [], 0.01)
        return path

    def cleanup_escaped(self, home):
        pid = int(self.wait_file(home / "escaped.ready").read_text())
        def kill():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(kill)
        return pid

    def assert_patch_tree(self, task_id, exported):
        target = self.root / ("apply-" + task_id)
        self.git(self.root, "clone", "--no-hardlinks", "--template=", self.repo, target)
        self.git(target, "checkout", "--detach", self.base)
        before = self.git(target, "rev-parse", "HEAD")
        self.git(target, "apply", "--check", exported["path"])
        self.git(target, "apply", "--index", exported["path"])
        self.assertEqual(self.git(target, "write-tree").decode().strip(), exported["tree"])
        self.assertEqual(self.git(target, "rev-parse", "HEAD"), before)
        return target

    def test_01_existing_eighty_tests_remain_in_full_suite(self):
        count = 0
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            if path.name in (Path(__file__).name, "test_trusted_review.py"):
                continue
            count += unittest.defaultTestLoader.loadTestsFromName(path.stem).countTestCases()
        self.assertEqual(count, 80)
        # The required external check_suite invocation runs these 80 plus this file.

    def test_02_modes_cannot_cross_at_engine_or_cli_boundary(self):
        confined = self.store.create("confined")
        for call in (self.engine.implement, self.engine.verify, self.engine.export, self.engine.status):
            with self.assertRaisesRegex(PolicyError, "mode trusted-local"):
                call(confined)
        with self.assertRaises(PolicyError):
            self.engine.approve(confined, "x", "human")
        task_id = self.start()
        engine = Engine(self.store)
        for call in (engine.run, engine.workspace, engine.check_evidence, engine.recover, engine.dispose):
            with self.assertRaisesRegex(PolicyError, "mode fake-only"):
                call(task_id)
        with self.assertRaises(PolicyError):
            engine.approve(task_id, "x", "human")
        for args in (("run", task_id), ("status", task_id), ("cancel", task_id), ("trusted", "verify", confined)):
            result = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root",
                                     str(self.store.root), *args], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(self.store.get(task_id)["status"], "preparing")

    def test_03_clone_is_detached_no_remote_and_no_shared_object_inodes(self):
        task_id = self.start()
        clone = self.clone(task_id)
        self.assertEqual(self.git(clone, "remote"), b"")
        self.assertEqual(self.git(clone, "rev-parse", "HEAD").decode().strip(), self.base)
        self.assertFalse((self.store.task_dir(task_id) / "clone.partial").exists())
        for source in (self.repo / ".git" / "objects").rglob("*"):
            if source.is_file():
                dest = clone / ".git" / "objects" / source.relative_to(self.repo / ".git" / "objects")
                if dest.exists():
                    self.assertNotEqual((source.stat().st_dev, source.stat().st_ino),
                                        (dest.stat().st_dev, dest.stat().st_ino))
                    self.assertEqual(dest.stat().st_nlink, 1)
        other = self.root / "same-fixture"
        self.assertEqual(fixture.make_fixture(other), self.base)

    def test_04_guard_identical_and_source_mutations_block_export(self):
        original = canonical(trusted.source_guard(self.repo, self.root))
        task_id = self.verified()
        self.approve(task_id)
        self.engine.export(task_id)
        self.assertEqual(canonical(trusted.source_guard(self.repo, self.root)), original)
        for phase in ("start", "implement", "verify", "approve", "export"):
            for side in ("before", "after"):
                self.assertEqual(canonical(self.store.artifact(task_id, phase + "_source_" + side)), original)
        for mutation in ("ref", "index", "file"):
            with self.subTest(mutation=mutation):
                task_id = self.verified()
                self.approve(task_id)
                if mutation == "ref":
                    self.git(self.repo, "update-ref", "refs/heads/changed", self.base)
                elif mutation == "index":
                    self.git(self.repo, "update-index", "--chmod=+x", "calc.py")
                else:
                    (self.repo / "calc.py").write_text("changed source\n")
                with self.assertRaisesRegex(PolicyError, "source repository guard changed"):
                    self.engine.export(task_id)
                self.assertEqual(self.store.get(task_id)["status"], "invalidated")
                self.assertFalse((self.store.task_dir(task_id) / "export.patch").exists())
                if mutation == "ref":
                    self.git(self.repo, "update-ref", "-d", "refs/heads/changed")
                self.git(self.repo, "reset", "--hard", self.base)

    def test_05_content_file_and_directory_mode_changes_invalidate_approval(self):
        for mutation in ("bytes", "file_mode", "directory_mode", "new_directory", "root_mode"):
            with self.subTest(mutation=mutation):
                task_id = self.verified()
                clone = self.clone(task_id)
                sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
                if mutation == "bytes":
                    (clone / "calc.py").write_text("changed")
                elif mutation == "file_mode":
                    (clone / "calc.py").chmod(0o600)
                elif mutation == "directory_mode":
                    (clone / "tests").chmod(0o700)
                elif mutation == "root_mode":
                    clone.chmod(0o711)
                else:
                    (clone / "empty-new").mkdir()
                with self.assertRaisesRegex(PolicyError, "snapshot changed"):
                    self.engine.approve(task_id, sha, "test")
                self.assertEqual(self.store.get(task_id)["status"], "invalidated")

    def test_06_ignored_names_only_and_unsupported_content_rejected(self):
        task_id = self.start()
        clone, home = self.clone(task_id), self.store.task_dir(task_id)
        (clone / ".gitignore").write_text("secret\nprivate/\n")
        (clone / "secret").write_text("never read me")
        (clone / "private").mkdir()
        (clone / "private" / "hidden").write_text("never enumerate me")
        original_read = trusted.read_regular
        def checked_read(path, *args):
            self.assertNotIn("secret", str(path))
            self.assertNotIn("private", str(path))
            return original_read(path, *args)
        with patch.object(trusted, "read_regular", side_effect=checked_read):
            a = trusted.snapshot(clone, home, self.base)
            (clone / "secret").write_text("changed ignored bytes")
            b = trusted.snapshot(clone, home, self.base)
        self.assertEqual(a["sha256"], b["sha256"])
        self.assertEqual(a["ignored"], ["private/", "secret"])
        self.assertNotIn("secret", a["manifest"])
        for kind in ("symlink", "hardlink", "fifo", "gitmodules", "nested_git", "submodule", "entries", "bytes"):
            with self.subTest(kind=kind):
                task_id = self.start()
                clone, home = self.clone(task_id), self.store.task_dir(task_id)
                if kind == "symlink":
                    (clone / "bad").symlink_to(clone / "calc.py")
                elif kind == "hardlink":
                    os.link(clone / "calc.py", clone / "bad")
                elif kind == "fifo":
                    os.mkfifo(clone / "bad")
                elif kind == "gitmodules":
                    (clone / ".gitmodules").write_text("unsupported")
                elif kind == "nested_git":
                    (clone / "nested" / ".git").mkdir(parents=True)
                elif kind == "submodule":
                    self.git(clone, "update-index", "--add", "--cacheinfo", "160000," + self.base + ",vendor")
                elif kind == "entries":
                    for i in range(trusted.MAX_ENTRIES):
                        (clone / ("empty-%d" % i)).mkdir()
                else:
                    with open(clone / "large", "wb") as out:
                        out.truncate(trusted.MAX_BYTES + 1)
                with self.assertRaises(PolicyError):
                    trusted.snapshot(clone, home, self.base)

    def test_07_claims_do_not_pass_verification_and_nonzero_success_fails(self):
        for scenario in ("no-write", "wrong"):
            with self.subTest(scenario=scenario):
                task_id = self.implement(scenario)
                self.assertEqual(self.engine.verify(task_id)["status"], "failed")
                self.assertFalse(self.store.artifact(task_id, "verification")["passed"])
                with self.assertRaises(PolicyError):
                    self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "test")
        for scenario in ("nonzero-success", "missing-final", "malformed"):
            with self.subTest(scenario=scenario):
                task_id = self.start(scenario)
                self.assertEqual(self.engine.implement(task_id, str(FAKE))["status"], "failed")
                with self.assertRaises(PolicyError):
                    self.engine.implement(task_id, str(FAKE))

    def test_08_verification_copy_hash_command_and_actual_seatbelt_denials(self):
        task_id = self.start()
        clone = self.clone(task_id)
        probe = '''import socket, os, unittest
class IsolationTests(unittest.TestCase):
    def test_network_denied(self):
        with socket.socket() as sock:
            sock.settimeout(0.5)
            with self.assertRaises(PermissionError):
                sock.connect(("1.1.1.1", 443))
    def test_clone_write_denied(self):
        with self.assertRaises(PermissionError):
            with open(%r, "w") as out:
                out.write("escape")
    def test_fork_denied(self):
        with self.assertRaises(PermissionError):
            os.fork()
''' % str(clone / "calc.py")
        (clone / "tests" / "test_isolation.py").write_text(probe)
        self.assertEqual(self.engine.implement(task_id, str(FAKE))["status"], "reviewing")
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval", self.store.events(task_id))
        self.assertEqual((clone / "calc.py").read_text(), "def add(a, b):\n    return a + b\n")
        task_id = self.implement()
        build = self.engine.build_verify
        def corrupt(*args):
            copy = build(*args)
            (copy / "calc.py").write_text("corrupted copy")
            return copy
        with patch.object(self.engine, "build_verify", side_effect=corrupt), patch.object(Seatbelt, "run") as run:
            self.assertEqual(self.engine.verify(task_id)["status"], "failed")
            run.assert_not_called()
        task_id = self.implement()
        spec = self.store.get(task_id)["spec"]
        spec["verify_command"] = ["/bin/sh", "-c", "true"]
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET spec=? WHERE id=?", (canonical(spec).decode(), task_id))
        with patch.object(Seatbelt, "run") as run:
            self.assertEqual(self.engine.verify(task_id)["status"], "failed")
            run.assert_not_called()
        self.assertIn("unsupported verification", self.store.events(task_id)[-1]["message"])
        task_id = self.implement()
        real_run = Seatbelt.run
        def mutate_after_run(runner, *args, **kwargs):
            output = real_run(runner, *args, **kwargs)
            (self.clone(task_id) / "calc.py").write_text("late mutation")
            return output
        with patch.object(Seatbelt, "run", new=mutate_after_run):
            self.assertEqual(self.engine.verify(task_id)["status"], "failed")

    def test_09_timeout_cancellation_crash_and_log_overflow_no_retry(self):
        for scenario, expected in (("timeout", "timed_out"), ("crash", "failed"), ("overflow", "failed")):
            with self.subTest(scenario=scenario):
                task_id = self.start(scenario)
                result = self.engine.implement(task_id, str(FAKE), timeout=0.2 if scenario == "timeout" else 10)
                self.assertEqual(result["status"], expected, self.store.events(task_id))
                cleanup = self.store.artifact(task_id, "cleanup")
                self.assertFalse(cleanup["descendants_guaranteed_stopped"])
                self.assertIn("completed", cleanup["group_cleanup"])
                self.assertLessEqual((self.store.task_dir(task_id) / "stdout.jsonl").stat().st_size, trusted.MAX_LOG)
                with self.assertRaises(PolicyError):
                    self.engine.implement(task_id, str(FAKE))
        task_id = self.start("timeout")
        results = []
        worker = threading.Thread(target=lambda: results.append(self.engine.implement(task_id, str(FAKE), timeout=10)))
        worker.start()
        try:
            self.wait_file(self.store.task_dir(task_id) / "fake.started")
            self.store.cancel(task_id)
        finally:
            worker.join(timeout=15)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0]["status"], "cancelled")
        self.assertTrue(self.store.has_artifact(task_id, "cleanup"))

    def test_10_fixed_argv_sanitized_environment_and_no_implicit_fake(self):
        task_id = self.start()
        with patch.dict(os.environ, dict(CANARIES, OPENAI_API_KEY="test-only-sentinel", CODEX_API_KEY="test-only-sentinel",
                                         CODEX_HOME=str(self.root / "login-home-sentinel"))):
            self.assertEqual(self.engine.implement(task_id, str(FAKE))["status"], "reviewing")
        home = self.store.task_dir(task_id)
        event = json.loads((home / "stdout.jsonl").read_text().splitlines()[0])
        self.assertEqual(event["api_keys_present"], [])
        self.assertEqual(event["codex_home"], str(self.root / "login-home-sentinel"))
        # Constructed environment: credential-bearing names, proxies and canaries never arrive.
        self.assertFalse(set(CANARIES) & set(event["env"]), event["env"])
        self.assertIn("HOME", event["env"])
        self.assertIn("PATH", event["env"])
        recorded = self.store.artifact(task_id, "codex")["environment"]
        self.assertLessEqual(set(recorded["forwarded"]), set(trusted.CHILD_ENV))
        self.assertGreater(recorded["dropped_count"], 0)
        self.assertNotIn("test-only-sentinel", json.dumps(recorded))
        self.assertEqual(event["argv"], ["-a", "never", "exec", "-m", "test-model", "--ignore-user-config", "--sandbox", "workspace-write", "--json",
                                        "--ephemeral", "-C", str(home / "clone"), "-o", str(home / "last-message.txt"), "-"])
        info = self.store.artifact(task_id, "codex")
        self.assertEqual(info["realpath"], str(FAKE.resolve()))
        self.assertIn("offline-fixture", info["version"])
        self.assertEqual(info["model"], "test-model")
        self.assertEqual(self.store.get(task_id)["spec"]["model"], "test-model")
        with patch.dict(os.environ, {}, clear=True), patch.object(trusted.shutil, "which", return_value=None):
            with self.assertRaisesRegex(PolicyError, "no fake fallback"):
                trusted.codex_info()
        with patch.dict(os.environ, {}, clear=True), patch.object(trusted.shutil, "which", return_value=str(FAKE)):
            with self.assertRaisesRegex(PolicyError, "explicit"):
                trusted.codex_info()
        with patch.dict(os.environ, {"MAESTRO_CODEX_BIN": str(FAKE)}):
            self.assertEqual(trusted.codex_info()["realpath"], str(FAKE.resolve()))

    def test_11_patch_applies_and_reproduces_tree_without_committing(self):
        task_id = self.verified()
        clone = self.clone(task_id)
        refs = self.git(clone, "for-each-ref")
        self.approve(task_id)
        record = self.engine.export(task_id)
        self.assert_patch_tree(task_id, record)
        self.assertEqual(self.git(clone, "rev-parse", "HEAD").decode().strip(), self.base)
        self.assertEqual(self.git(clone, "for-each-ref"), refs)
        self.assertEqual(record["sha256"], trusted.hashlib.sha256(Path(record["path"]).read_bytes()).hexdigest())

    def test_12_offline_demo_end_to_end(self):
        result = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "examples/trusted-local/demo.py")],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["offline_demo_passed"])

    def test_13_escaped_descendant_late_write_invalidates_and_patch_uses_tree(self):
        task_id = self.verified("escaped")
        home = self.store.task_dir(task_id)
        self.cleanup_escaped(home)
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        (home / "escaped.go").write_text("go")
        self.wait_file(home / "escaped.done")
        with self.assertRaisesRegex(PolicyError, "snapshot changed"):
            self.engine.approve(task_id, sha, "human")
        self.assertEqual(self.store.get(task_id)["status"], "invalidated")
        task_id = self.verified("escaped")
        home = self.store.task_dir(task_id)
        self.cleanup_escaped(home)
        self.approve(task_id)
        record = self.engine.export(task_id)
        original = Path(record["path"]).read_bytes()
        (home / "escaped.go").write_text("go")
        self.wait_file(home / "escaped.done")
        self.assertIn("999", (self.clone(task_id) / "calc.py").read_text())
        self.assertEqual(Path(record["path"]).read_bytes(), original)
        target = self.assert_patch_tree(task_id, record)
        self.assertEqual((target / "calc.py").read_text(), "def add(a, b):\n    return a + b\n")

    def test_14_interrupted_clone_preserved_not_published_or_retried(self):
        real_git = trusted.git
        for exception in (Cancelled("cancel clone"), PolicyError("clone failed")):
            with self.subTest(exception=type(exception).__name__):
                self.serial += 1
                task = self.root / ("interrupt-%d.md" % self.serial)
                task.write_text("unique clone interruption %d" % self.serial)
                def fail_checkout(cwd, home, *args, **kwargs):
                    if args and args[0] == "checkout":
                        raise exception
                    return real_git(cwd, home, *args, **kwargs)
                with patch.object(trusted, "git", side_effect=fail_checkout):
                    result = self.engine.start(self.repo, self.base, task, "test-model")
                self.assertIn(result["status"], ("failed", "interrupted"))
                home = self.store.task_dir(result["id"])
                self.assertFalse((home / "clone").exists())
                self.assertTrue((home / "clone.partial").is_dir())
                with self.assertRaisesRegex(PolicyError, "no retry"):
                    self.engine.start(self.repo, self.base, task, "test-model")
                with self.assertRaises(PolicyError):
                    self.engine.implement(result["id"], str(FAKE))

    def test_15_offline_fixture_approval_requires_both_task_and_caller_test_context(self):
        # Even with test-looking env/path/name and an explicit fake binary, the
        # normal engine creates a normal task and must refuse its approval.
        normal = trusted.TrustedEngine(self.store)
        task_file = self.root / "normal-test-looking-TASK.md"
        task_file.write_text("Implement addition")
        task_id = normal.start(self.repo, self.base, task_file, "test-model")["id"]
        self.assertEqual(self.store.get(task_id)["spec"]["execution_context"], "normal")
        self.assertEqual(normal.implement(task_id, str(FAKE))["status"], "reviewing")
        result = normal.verify(task_id)
        self.assertEqual(result["status"], "awaiting_approval")
        sha = result["evidence"]["snapshot_sha256"]
        with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": "pretend-test", "MAESTRO_TEST_MODE": "1"}):
            for engine in (normal, self.engine):
                with self.assertRaisesRegex(PolicyError, "offline-fixture"):
                    engine.approve(task_id, sha, "human")
        self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")
        self.assertFalse(self.store.has_artifact(task_id, "approval"))
        # Legacy tasks without a context field are normal too.
        legacy_spec = dict(result["spec"])
        del legacy_spec["execution_context"]
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET spec=? WHERE id=?", (canonical(legacy_spec).decode(), task_id))
        with self.assertRaisesRegex(PolicyError, "offline-fixture"):
            self.engine.approve(task_id, sha, "human")

        # A persisted test marker alone is insufficient in a fresh normal CLI.
        test_id = self.verified()
        sha = self.store.get(test_id)["evidence"]["snapshot_sha256"]
        cli = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root",
                              str(self.store.root), "trusted", "approve", test_id,
                              "--snapshot", sha, "--founder", "human"],
                             capture_output=True, text=True, timeout=20)
        self.assertEqual(cli.returncode, 2, cli.stdout)
        self.assertIn("offline-fixture", cli.stderr)
        self.assertFalse(self.store.has_artifact(test_id, "approval"))
        self.approve(test_id)
        self.assertEqual(self.store.artifact(test_id, "approval")["execution_context"], "test")
        with self.assertRaisesRegex(PolicyError, "offline-fixture"):
            normal.export(test_id)
        self.assertEqual(self.engine.export(test_id)["execution_context"], "test")

        # Simulate genuine-version metadata, still executing only the fake.
        # A normal task with a non-fixture version remains approvable.
        task_file = self.root / "normal-genuine-version-TASK.md"
        task_file.write_text("Implement addition; simulated version metadata")
        task_id = normal.start(self.repo, self.base, task_file, "test-model")["id"]
        info = trusted.codex_info(str(FAKE))
        info["version"] = "codex-cli 0.164.0"
        with patch.object(trusted, "codex_info", return_value=info):
            self.assertEqual(normal.implement(task_id, str(FAKE))["status"], "reviewing")
        result = normal.verify(task_id)
        self.assertEqual(result["status"], "awaiting_approval")
        result = normal.approve(task_id, result["evidence"]["snapshot_sha256"], "human")
        self.assertEqual(result["status"], "approved")
        self.assertEqual(self.store.artifact(task_id, "approval")["execution_context"], "normal")

    def test_16_model_required_validated_and_unknown_model_fails_without_fallback(self):
        task_file = self.repo / "TASK.md"
        for model in ("", "UPPER", "-bad", "bad name", "a/b", "a\n", "a" * 65, None):
            with self.subTest(model=model), self.assertRaisesRegex(PolicyError, "invalid model"):
                self.engine.start(self.repo, self.base, task_file, model)
        self.assertEqual(list((self.store.root / "tasks").iterdir()), [])
        for model in ("a", "0", "gpt-5.4", "model_test.1", "a" * 64):
            self.assertEqual(trusted.validate_model(model), model)
        cli = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root",
                              str(self.store.root), "trusted", "start", "--repo", str(self.repo),
                              "--base", self.base, "--task", str(task_file)], capture_output=True, text=True)
        self.assertEqual(cli.returncode, 2)
        self.assertIn("--model", cli.stderr)
        task_id = self.engine.start(self.repo, self.base, task_file, "unknown-model")["id"]
        result = self.engine.implement(task_id, str(FAKE))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.store.artifact(task_id, "codex")["model"], "unknown-model")
        self.assertEqual(self.store.artifact(task_id, "cleanup")["exit_code"], 2)
        self.assertEqual(sum(e["status"] == "implementing" for e in self.store.events(task_id)), 1)
        with self.assertRaises(PolicyError):
            self.engine.implement(task_id, str(FAKE))
        self.assertFalse(self.store.has_artifact(task_id, "snapshot"))

    def cli(self, *args):
        # Test-only harness; the production CLI cannot enable test context.
        return subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "tests/fixtures/trusted_test_cli.py"),
                               "--root", str(self.store.root), "trusted", *map(str, args)],
                              capture_output=True, timeout=60)

    def test_17_rejection_is_recorded_and_blocks_approval_and_export(self):
        task_id = self.verified()
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        for founder, reason in (("", "wrong"), ("Founder", " "), ("Founder", "x" * 2001)):
            with self.subTest(founder=founder, reason=reason[:8]), self.assertRaises(PolicyError):
                self.engine.reject(task_id, founder, reason)
        result = self.engine.reject(task_id, "Founder", "Wrong approach")
        self.assertEqual(result["status"], "rejected")
        rejection = self.store.artifact(task_id, "rejection")
        self.assertEqual(rejection["snapshot_sha256"], sha)
        self.assertEqual(trusted.digest(rejection), result["evidence"]["rejection_sha256"])
        for action in (lambda: self.engine.approve(task_id, sha, "Founder"),
                       lambda: self.engine.export(task_id),
                       lambda: self.engine.reject(task_id, "Founder", "again")):
            with self.assertRaises(PolicyError):
                action()
        self.assertFalse((self.store.task_dir(task_id) / "export.patch").exists())
        pending = self.implement()
        with self.assertRaisesRegex(PolicyError, "awaiting approval"):
            self.engine.reject(pending, "Founder", "too early")

    def test_18_cancellation_through_cli_blocks_approval_and_export(self):
        task_id = self.verified()
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        result = self.cli("cancel", task_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "cancelled")
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, sha, "Founder")
        with self.assertRaises(PolicyError):
            self.engine.export(task_id)
        self.assertEqual(self.cli("export", task_id).returncode, 2)
        self.assertFalse((self.store.task_dir(task_id) / "export.patch").exists())

    def test_19_diff_shows_exact_patch_before_approval_and_matches_export(self):
        with self.assertRaises(PolicyError):
            self.engine.diff(self.start())
        task_id = self.verified()
        events = len(self.store.events(task_id))
        patch_bytes = self.engine.diff(task_id)
        self.assertIn(b"+    return a + b", patch_bytes)
        result = self.cli("diff", task_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, patch_bytes)
        self.assertEqual(self.store.get(task_id)["status"], "awaiting_approval")
        self.assertEqual(len(self.store.events(task_id)), events)
        self.assertEqual(self.engine.status(task_id)["changes"], [{"status": "M", "path": "calc.py"}])
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(task_id, sha, "Founder")
        self.engine.export(task_id)
        self.assertEqual((self.store.task_dir(task_id) / "export.patch").read_bytes(), patch_bytes)
