"""Offline Claude Code reviewer tests. No model, login, network service or credentials."""
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reviewer
import trusted
from execution import PolicyError
from workflow import Store
from workspace import canonical, digest

FAKE_CODEX = ROOT / "tests" / "fixtures" / "fake_codex.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("trusted_review_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
CANARIES = {"ANTHROPIC_API_KEY": "test-only-sentinel", "ANTHROPIC_AUTH_TOKEN": "test-only-sentinel",
            "ANTHROPIC_BASE_URL": "http://test-only-sentinel.invalid", "CLAUDE_CODE_OAUTH_TOKEN": "test-only-sentinel",
            "CLAUDECODE": "1", "CLAUDE_CODE_SIMPLE": "1", "CLAUDE_CODE_ENTRYPOINT": "test-only-sentinel",
            "OPENAI_API_KEY": "test-only-sentinel", "CODEX_HOME": "/test-only-sentinel",
            "GITHUB_TOKEN": "test-only-sentinel", "MAESTRO_CANARY_SECRET": "test-only-sentinel",
            "HTTPS_PROXY": "http://user:test-only-sentinel@127.0.0.1:9"}
ARGV = ["-p", "--output-format", "json", "--model", "test-reviewer", "--tools", "", "--strict-mcp-config",
        "--safe-mode", "--restricted", "--no-chrome", "--disable-slash-commands", "--no-session-persistence",
        "--permission-mode", "dontAsk", "--system-prompt", reviewer.CONTRACT]


@RUNTIME
class ClaudeReviewerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".review-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.repo = self.root / "source"
        self.base = fixture.make_fixture(self.repo)
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def task_file(self, scenario):
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text((self.repo / "TASK.md").read_text() + "\nreview-scenario: " + scenario)
        return task

    def verified(self, scenario="pass", engine=None, review_model="test-reviewer"):
        engine = engine or self.engine
        task_id = engine.start(self.repo, self.base, self.task_file(scenario), "test-model",
                               review_model=review_model)["id"]
        self.assertEqual(engine.implement(task_id, str(FAKE_CODEX))["status"], "reviewing")
        self.assertEqual(engine.verify(task_id)["status"], "awaiting_approval", self.store.events(task_id))
        return task_id

    def review(self, task_id, **kwargs):
        return self.engine.review(task_id, str(FAKE_CLAUDE), **kwargs)["review"]

    def record(self, task_id, attempt=1):
        return self.store.artifact(task_id, "review.%d" % attempt)

    def fixture_output(self, task_id, attempt=1):
        return json.loads((self.store.task_dir(task_id) / ("review-%d" % attempt) / "stdout.json").read_text())

    def sha(self, task_id):
        return self.store.get(task_id)["evidence"]["snapshot_sha256"]

    def status(self, task_id):
        return self.store.get(task_id)["status"]

    def forge(self, task_id, field):
        """An internally consistent review record bound to a different snapshot, tree or patch."""
        record = self.record(task_id)
        record[field] = "f" * len(record[field])
        if field in record["review"]:
            record["review"][field] = record[field]
        evidence = dict(self.store.get(task_id)["evidence"], review_sha256=digest(record))
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body=?,hash=? WHERE task_id=? AND kind='review.1'",
                         (canonical(record).decode(), digest(record), task_id))
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(evidence).decode(), task_id))

    def test_01_review_is_bound_to_snapshot_patch_and_input_through_export(self):
        task_id = self.verified()
        summary = self.review(task_id)
        self.assertEqual((summary["outcome"], summary["blocking"]), ("completed", False), summary)
        record, task = self.record(task_id), self.store.get(task_id)
        self.assertEqual(task["status"], "awaiting_approval")
        self.assertEqual(task["evidence"]["review_sha256"], digest(record))
        self.assertEqual(task["evidence"]["review_attempts"], 1)
        patch_bytes = self.engine.diff(task_id)
        self.assertEqual(record["snapshot_sha256"], self.sha(task_id))
        self.assertEqual(record["tree"], self.store.artifact(task_id, "snapshot")["tree"])
        self.assertEqual(record["patch_sha256"], hashlib.sha256(patch_bytes).hexdigest())
        self.assertEqual((record["provider"], record["model_requested"]), ("claude-code", "test-reviewer"))
        self.assertTrue(record["model_verified"])
        self.assertEqual(record["models_reported"], ["test-reviewer"])
        self.assertEqual(record["classification"], reviewer.CLASSIFICATION)
        self.assertEqual(record["exit_code"], 0)
        staged = self.store.task_dir(task_id) / record["input"]["path"]
        self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o400)
        data = staged.read_bytes()
        self.assertEqual(record["input"]["sha256"], hashlib.sha256(data).hexdigest())
        payload = json.loads(data.split(b"\n", 1)[1])
        self.assertEqual(payload["patch"].encode("utf-8"), patch_bytes)
        self.assertEqual((payload["snapshot_sha256"], payload["patch_sha256"]),
                         (record["snapshot_sha256"], record["patch_sha256"]))
        self.assertEqual([f["path"] for f in payload["files"]], ["TASK.md", "calc.py", "tests/test_calc.py"])
        self.assertIn("return a + b", payload["files"][1]["content"])
        self.assertTrue(payload["verification"]["passed"])
        self.assertNotIn(str(self.root), data.decode("utf-8"))  # no local paths leave the machine
        # The reviewer's opinion changes no state and cannot stand in for the human.
        self.assertFalse(self.store.has_artifact(task_id, "approval"))
        with self.assertRaises(PolicyError):
            self.engine.export(task_id)
        self.assertEqual(self.engine.approve(task_id, self.sha(task_id), "Offline test human")["status"], "approved")
        approval = self.store.artifact(task_id, "approval")
        self.assertEqual(approval["review_sha256"], digest(record))
        self.assertNotIn("review_override", approval)
        exported = self.engine.export(task_id)
        self.assertEqual(exported["review_sha256"], digest(record))
        self.assertEqual(exported["sha256"], record["patch_sha256"])
        self.assertEqual(Path(exported["path"]).read_bytes(), patch_bytes)

    def test_02_changed_snapshot_or_stale_review_cannot_satisfy_the_gate(self):
        task_id = self.verified()
        self.review(task_id)
        (self.store.task_dir(task_id) / "clone" / "calc.py").write_text("changed after review\n")
        with self.assertRaisesRegex(PolicyError, "snapshot changed"):
            self.engine.approve(task_id, self.sha(task_id), "human")
        self.assertEqual(self.status(task_id), "invalidated")
        self.assertFalse(self.store.has_artifact(task_id, "approval"))
        for field in ("snapshot_sha256", "tree", "patch_sha256"):
            with self.subTest(field=field):
                task_id = self.verified()
                self.review(task_id)
                self.forge(task_id, field)
                with self.assertRaisesRegex(PolicyError, "stale"):
                    self.engine.approve(task_id, self.sha(task_id), "human")
                self.assertEqual(self.status(task_id), "invalidated")
                self.assertFalse(self.store.has_artifact(task_id, "approval"))
        task_id = self.verified()
        self.review(task_id)
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(dict(
                self.store.get(task_id)["evidence"], review_sha256="0" * 64)).decode(), task_id))
        with self.assertRaisesRegex(PolicyError, "review evidence mismatch"):
            self.engine.approve(task_id, self.sha(task_id), "human")
        # A snapshot that changed before the review fails the attempt and invalidates the task.
        task_id = self.verified()
        (self.store.task_dir(task_id) / "clone" / "calc.py").write_text("changed before review\n")
        summary = self.review(task_id)
        self.assertEqual(summary["outcome"], "failed")
        self.assertIn("snapshot changed", summary["error"])
        self.assertEqual(self.status(task_id), "invalidated")

    def test_03_malformed_failed_or_unverified_reviews_never_satisfy_the_gate(self):
        for scenario in ("malformed", "extra-field", "wrong-snapshot", "unknown-file", "error", "nonzero",
                         "wrong-model"):
            with self.subTest(scenario=scenario):
                task_id = self.verified(scenario)
                summary = self.review(task_id)
                self.assertEqual(summary["outcome"], "failed", summary)
                self.assertEqual(self.status(task_id), "awaiting_approval")
                with self.assertRaisesRegex(PolicyError, "review required"):
                    self.engine.approve(task_id, self.sha(task_id), "human")
                self.assertEqual(self.status(task_id), "awaiting_approval")
                self.assertFalse(self.store.has_artifact(task_id, "approval"))
                if scenario == "error":
                    self.assertIn("usage limit", summary["error"])
        task_id = self.verified("timeout")
        summary = self.review(task_id, timeout=0.5)
        self.assertEqual(summary["outcome"], "failed")
        self.assertIn("timed out", summary["error"])
        self.assertEqual(self.record(task_id)["group_cleanup"], "completed; escaped descendants not guaranteed")
        task_id = self.verified("fenced")
        self.assertEqual(self.review(task_id)["outcome"], "completed")
        # One retry after an attempt that did not complete; a completed review is final.
        task_id = self.verified()
        summary = self.engine.review(task_id, str(self.root / "missing-claude"))["review"]
        self.assertEqual(summary["outcome"], "unavailable")
        self.assertIn("no fake fallback", summary["error"])
        self.assertEqual(self.review(task_id)["outcome"], "completed")
        self.assertEqual(self.store.get(task_id)["evidence"]["review_attempts"], 2)
        with self.assertRaisesRegex(PolicyError, "final"):
            self.review(task_id)
        self.assertEqual(self.engine.approve(task_id, self.sha(task_id), "human")["status"], "approved")
        task_id = self.verified("malformed")
        self.review(task_id)
        self.review(task_id)
        with self.assertRaisesRegex(PolicyError, "attempt limit"):
            self.review(task_id)
        self.assertFalse((self.store.task_dir(task_id) / "review-3").exists())

    def test_04_blocking_findings_require_rejection_or_a_recorded_override(self):
        for scenario in ("blocking", "blocking-finding-only"):
            with self.subTest(scenario=scenario):
                task_id = self.verified(scenario)
                summary = self.review(task_id)
                self.assertEqual((summary["outcome"], summary["blocking"]), ("completed", True))
                sha = self.sha(task_id)
                with self.assertRaisesRegex(PolicyError, "blocking findings"):
                    self.engine.approve(task_id, sha, "human")
                for reason in ("", " ", "x" * 2001):
                    with self.assertRaises(PolicyError):
                        self.engine.approve(task_id, sha, "human", override_review=reason)
                self.assertEqual(self.status(task_id), "awaiting_approval")
                reason = "False positive; checked the patch by hand"
                self.assertEqual(self.engine.approve(task_id, sha, "Founder", override_review=reason)["status"],
                                 "approved")
                self.assertEqual(self.store.artifact(task_id, "approval")["review_override"], reason)
                self.assertIn("overridden", self.store.events(task_id)[-1]["message"])
                self.assertIn("review_sha256", self.engine.export(task_id))
        task_id = self.verified("blocking")
        self.review(task_id)
        self.assertEqual(self.engine.reject(task_id, "Founder", "Reviewer is right")["status"], "rejected")
        task_id = self.verified()
        self.review(task_id)
        with self.assertRaisesRegex(PolicyError, "nothing to override"):
            self.engine.approve(task_id, self.sha(task_id), "human", override_review="not needed")
        self.assertEqual(self.status(task_id), "awaiting_approval")

    def test_05_reviewer_cannot_modify_the_implementation_or_approve(self):
        task_id = self.verified("mutate")
        summary = self.review(task_id)
        self.assertEqual(summary["outcome"], "failed")
        self.assertIn("snapshot changed", summary["error"])
        self.assertEqual(self.status(task_id), "invalidated")
        with self.assertRaises(PolicyError):
            self.engine.approve(task_id, self.sha(task_id), "human")
        with self.assertRaises(PolicyError):
            self.engine.export(task_id)
        self.assertFalse((self.store.task_dir(task_id) / "export.patch").exists())
        # Fresh empty working folder, never the clone; staged input only.
        task_id = self.verified()
        self.review(task_id)
        home = self.store.task_dir(task_id)
        output = self.fixture_output(task_id)
        self.assertEqual(output["fixture_cwd"], str(home / "review-1" / "cwd"))
        self.assertTrue(output["fixture_contract_has_injection_rule"])
        self.assertEqual(self.status(task_id), "awaiting_approval")
        # Only a verified task awaiting approval can be reviewed.
        pending = self.engine.start(self.repo, self.base, self.task_file("pass"), "test-model",
                                    review_model="test-reviewer")["id"]
        self.engine.implement(pending, str(FAKE_CODEX))
        with self.assertRaisesRegex(PolicyError, "awaiting approval"):
            self.engine.review(pending, str(FAKE_CLAUDE))
        self.assertFalse((self.store.task_dir(pending) / "review-1").exists())
        with self.assertRaisesRegex(PolicyError, "invalid model"):
            self.engine.start(self.repo, self.base, self.task_file("pass"), "test-model", review_model="Bad Model")

    def test_06_no_api_key_token_or_session_environment_reaches_the_reviewer(self):
        task_id = self.verified()
        config = str(self.root / "claude-config-sentinel")
        with patch.dict(os.environ, dict(CANARIES, CLAUDE_CONFIG_DIR=config)):
            self.assertEqual(self.review(task_id)["outcome"], "completed")
        output = self.fixture_output(task_id)
        self.assertFalse(set(CANARIES) & set(output["fixture_env"]), output["fixture_env"])
        self.assertIn("HOME", output["fixture_env"])
        self.assertEqual(output["fixture_values"], {"CLAUDE_CONFIG_DIR": config,
                                                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
        record = self.record(task_id)
        self.assertLessEqual(set(record["environment"]["forwarded"]), set(reviewer.CHILD_ENV) | set(reviewer.FIXED_ENV))
        self.assertGreater(record["environment"]["dropped_count"], 0)
        self.assertNotIn("test-only-sentinel", json.dumps(record))
        self.assertNotIn("test-only-sentinel", (self.store.task_dir(task_id) / "review-1" / "input.txt").read_text())

    def test_07_exact_supported_cli_invocation_and_no_implicit_or_production_fake(self):
        task_id = self.verified()
        self.review(task_id)
        record = self.record(task_id)
        self.assertEqual(self.fixture_output(task_id)["fixture_argv"], ARGV)
        self.assertEqual(record["argv"], [str(FAKE_CLAUDE)] + ARGV)
        self.assertEqual(record["cli"]["realpath"], str(FAKE_CLAUDE.resolve()))
        self.assertIn("offline-fixture", record["cli"]["version"])
        for forbidden in ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "bypassPermissions",
                          "--add-dir", "--mcp-config", "--fallback-model", "--bare", "--allowedTools", "--resume"):
            self.assertNotIn(forbidden, record["argv"])
        with patch.dict(os.environ, {}, clear=True), patch.object(reviewer.shutil, "which", return_value=None):
            with self.assertRaisesRegex(PolicyError, "no fake fallback"):
                reviewer.claude_info()
        with patch.dict(os.environ, {}, clear=True), patch.object(reviewer.shutil, "which", return_value=str(FAKE_CLAUDE)):
            with self.assertRaisesRegex(PolicyError, "explicit"):
                reviewer.claude_info()
        with patch.dict(os.environ, {"MAESTRO_CLAUDE_BIN": str(FAKE_CLAUDE)}):
            self.assertEqual(reviewer.claude_info()["realpath"], str(FAKE_CLAUDE.resolve()))
        # A normal engine never lets an offline-fixture review satisfy the gate, even for a
        # task whose Codex metadata looks genuine.
        normal = trusted.TrustedEngine(self.store)
        info = trusted.codex_info(str(FAKE_CODEX))
        info["version"] = "codex-cli 0.164.0"
        with patch.object(trusted, "codex_info", return_value=info):
            task_id = self.verified(engine=normal)
        self.assertEqual(normal.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")
        with self.assertRaisesRegex(PolicyError, "offline-fixture review"):
            normal.approve(task_id, self.sha(task_id), "human")
        self.assertEqual(self.status(task_id), "awaiting_approval")
        self.assertFalse(self.store.has_artifact(task_id, "approval"))

    def test_08_codex_only_tasks_keep_their_existing_behaviour(self):
        task_id = self.engine.start(self.repo, self.base, self.task_file("pass"), "test-model")["id"]
        spec = self.store.get(task_id)["spec"]
        self.assertNotIn("review", spec)
        self.assertEqual(task_id, digest(spec)[:16])
        self.engine.implement(task_id, str(FAKE_CODEX))
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval")
        self.assertNotIn("review", self.engine.status(task_id))
        with self.assertRaisesRegex(PolicyError, "did not request a review"):
            self.engine.review(task_id, str(FAKE_CLAUDE))
        with self.assertRaisesRegex(PolicyError, "no review to override"):
            self.engine.approve(task_id, self.sha(task_id), "human", override_review="x")
        self.assertEqual(self.status(task_id), "awaiting_approval")
        self.assertEqual(self.engine.approve(task_id, self.sha(task_id), "human")["status"], "approved")
        self.assertEqual(set(self.store.artifact(task_id, "approval")), {"snapshot_sha256", "founder", "execution_context"})
        self.assertEqual(set(self.engine.export(task_id)), {"snapshot_sha256", "tree", "execution_context", "path", "sha256"})
        self.assertFalse([k for k in self.store.get(task_id)["evidence"] if k.startswith("review")])
        self.assertFalse((self.store.task_dir(task_id) / "review-1").exists())

    def test_09_cli_review_flow_exit_codes_and_override(self):
        def cli(*args):
            return subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "tests/fixtures/trusted_test_cli.py"),
                                   "--root", str(self.store.root), "trusted", *map(str, args)],
                                  capture_output=True, text=True, timeout=60)
        ids = {}
        for scenario in ("pass", "blocking", "malformed"):
            result = cli("start", "--repo", self.repo, "--base", self.base, "--task", self.task_file(scenario),
                         "--model", "test-model", "--review-model", "test-reviewer")
            self.assertEqual(result.returncode, 0, result.stderr)
            ids[scenario] = task_id = json.loads(result.stdout)["id"]
            self.assertEqual(cli("implement", task_id, "--codex-bin", FAKE_CODEX).returncode, 0)
            self.assertEqual(cli("verify", task_id).returncode, 0)
        task_id, sha = ids["pass"], self.sha(ids["pass"])
        result = cli("approve", task_id, "--snapshot", sha, "--founder", "Founder")
        self.assertEqual(result.returncode, 2)
        self.assertIn("review required", result.stderr)
        result = cli("review", task_id, "--claude-bin", FAKE_CLAUDE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["review"]["verdict"], "no_blocking_findings")
        self.assertEqual(json.loads(cli("status", task_id).stdout)["review"]["outcome"], "completed")
        self.assertEqual(cli("approve", task_id, "--snapshot", sha, "--founder", "Founder").returncode, 0)
        self.assertIn("review_sha256", json.loads(cli("export", task_id).stdout))
        result = cli("review", ids["malformed"], "--claude-bin", FAKE_CLAUDE)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["review"]["outcome"], "failed")
        task_id, sha = ids["blocking"], self.sha(ids["blocking"])
        self.assertEqual(cli("review", task_id, "--claude-bin", FAKE_CLAUDE).returncode, 0)
        result = cli("approve", task_id, "--snapshot", sha, "--founder", "Founder")
        self.assertEqual(result.returncode, 2)
        self.assertIn("blocking findings", result.stderr)
        result = cli("approve", task_id, "--snapshot", sha, "--founder", "Founder", "--override-review", "Accepted risk")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "approved")
