"""Verification layouts, `trusted check`, next-step hints and the multi-file project demo.

Offline: synthetic fixtures and fake agents only. No model, login, network or credentials.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import doctor
import maestro
import trusted
from execution import PolicyError
from sandbox import Seatbelt, python_runtime
from workflow import Store
from workspace import canonical

PROJECT = ROOT / "examples" / "project-demo"
FAKE_IMPLEMENTER = PROJECT / "fake_implementer.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("usability_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
LAYOUT = trusted.verify_config(top_level_dir=".", pythonpath=["src"])


class VerificationConfigTests(unittest.TestCase):
    def test_no_options_keep_the_original_discovery_through_the_runner(self):
        # AUD-01: the old `-m unittest discover -s tests` passed with zero tests. The runner
        # discovers the same way (-s tests) but fails when no test runs and records counts.
        self.assertIsNone(trusted.verify_config())
        self.assertIsNone(trusted.verify_config(pythonpath=[]))
        default = [python_runtime()[0], "-I", "-B", "-c", trusted.VERIFY_RUNNER, "--", "-s", "tests"]
        self.assertEqual(trusted.verification_command(), default)
        self.assertEqual(trusted.verification_command(None), default)

    def test_layouts_become_a_constant_runner_with_paths_as_separate_arguments(self):
        cases = (
            (dict(pythonpath=["src"], top_level_dir="."), ["src", "--", "-s", "tests", "-p", "test*.py", "-t", "."]),
            (dict(test_dir="pkg/tests", top_level_dir="."), ["--", "-s", "pkg/tests", "-p", "test*.py", "-t", "."]),
            (dict(pattern="*_test.py"), ["--", "-s", "tests", "-p", "*_test.py"]),
            (dict(test_dir="src/app/tests", top_level_dir="src", pythonpath=["src", "lib"]),
             ["src", "lib", "--", "-s", "src/app/tests", "-p", "test*.py", "-t", "src"]),
        )
        for options, tail in cases:
            with self.subTest(options=options):
                command = trusted.verification_command(trusted.verify_config(**options))
                self.assertEqual(command, [python_runtime()[0], "-I", "-B", "-c", trusted.VERIFY_RUNNER] + tail)

    def test_unsafe_or_unsupported_layouts_are_rejected(self):
        bad = [dict(test_dir=v) for v in ("/abs", "../up", "a/../b", "-s", ".hidden", "a//b", "a/", "", "x y",
                                          "a\nb", 7, "a" * 201)]
        bad += [dict(pattern=v) for v in ("*.txt", "a/test_*.py", "-p.py", "test*.py;rm", "", ".py", 5)]
        bad += [dict(pythonpath=[v]) for v in ("/usr/lib", "..", "src/../..", "-c", ".")]
        bad += [dict(pythonpath=["a", "b", "c", "d", "e"]), dict(pythonpath=["src", "src"]),
                dict(test_dir="tests", top_level_dir="src"), dict(top_level_dir="/"), dict(top_level_dir="..")]
        for options in bad:
            with self.subTest(options=options), self.assertRaises(PolicyError):
                trusted.verify_config(**options)
        for tampered in ({"test_dir": "../x", "top_level_dir": None, "pattern": "test*.py", "pythonpath": []},
                         dict(LAYOUT, command=["/bin/sh"]), dict(LAYOUT, pythonpath="src"), ["tests"]):
            with self.subTest(tampered=tampered), self.assertRaises(PolicyError):
                trusted.verification_command(tampered)

    @unittest.skipUnless(os.path.exists("/bin/zsh"), "zsh is the default macOS shell")
    def test_readme_quickstart_runs_in_zsh(self):
        # A fresh-install walkthrough found `M="…"; $M doctor` failing in zsh (no word splitting).
        readme = (ROOT / "README.md").read_text()
        quickstart = readme[readme.index("## Quickstart"):readme.index("## Trusted Local Mode")]
        self.assertIsNone(re.search(r"^\$M ", quickstart, re.M))
        line = next(l for l in quickstart.splitlines() if l.startswith("MAESTRO=$PWD; m() {")).split("  #")[0]
        result = subprocess.run(["/bin/zsh", "-f", "-c", line + "\nm --version"], cwd=str(ROOT),
                                capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split()[-1], maestro.__version__)

    def test_cli_version_matches_the_latest_changelog_release(self):
        heading = re.search(r"^## v?(\d+\.\d+\.\d+-\w+)", (ROOT / "CHANGELOG.md").read_text(), re.M)
        self.assertEqual(maestro.__version__, heading.group(1))
        result = subprocess.run([sys.executable, "-B", str(ROOT / "maestro.py"), "--version"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout.split()[-1], maestro.__version__)


@RUNTIME
class UsabilityFlowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".usability-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.repo = self.root / "stockroom"
        self.base = fixture.make_fixture(self.repo, PROJECT / "fixture")
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def start(self, change="correct", verify=LAYOUT, review_model=None):
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text((self.repo / "TASK.md").read_text() + "\ndemo-change: %s\n" % change)
        return self.engine.start(self.repo, self.base, task, "demo-model", review_model=review_model, verify=verify)

    def implemented(self, change="correct", verify=LAYOUT, review_model=None):
        task_id = self.start(change, verify, review_model)["id"]
        self.assertEqual(self.engine.implement(task_id, str(FAKE_IMPLEMENTER))["status"], "reviewing")
        return task_id

    def cli(self, *args, root=None):
        return subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root", str(root or self.store.root),
                               "trusted", *map(str, args)], capture_output=True, text=True, timeout=120)

    def test_configured_layout_verifies_the_snapshot_and_catches_the_flawed_change(self):
        task_id = self.implemented()
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval", self.store.events(task_id))
        record = self.store.artifact(task_id, "verification")
        self.assertEqual(record["command"], trusted.verification_command(LAYOUT))
        self.assertEqual(record["summary"], {"tests_run": 8, "failures": 0, "errors": 0, "skipped": 0})
        self.assertEqual(self.store.get(task_id)["spec"]["verify"], LAYOUT)
        task_id = self.implemented("flawed")
        self.assertEqual(self.engine.verify(task_id)["status"], "failed")
        self.assertFalse(self.store.artifact(task_id, "verification")["passed"])
        self.assertIn("test_rejects_a_negative_quantity_in_a_repeated_sku", self.store.events(task_id)[-1]["message"])

    def test_default_command_is_unchanged_and_cannot_import_a_src_layout(self):
        task_id = self.implemented(verify=None)
        spec = self.store.get(task_id)["spec"]
        self.assertNotIn("verify", spec)
        self.assertEqual(spec["verify_command"], trusted.verification_command())
        self.assertEqual(self.engine.verify(task_id)["status"], "failed")
        self.assertIn("ModuleNotFoundError", self.store.events(task_id)[-1]["message"])

    def test_missing_directory_fails_at_start_before_any_agent(self):
        result = self.start(verify=trusted.verify_config(test_dir="spec"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("missing from the snapshot: spec", self.store.events(result["id"])[-1]["message"])
        with self.assertRaises(PolicyError):
            self.engine.implement(result["id"], str(FAKE_IMPLEMENTER))
        self.assertFalse(self.store.has_artifact(result["id"], "codex"))

    def test_a_configured_run_that_collects_no_tests_fails(self):
        task_id = self.implemented(verify=trusted.verify_config(top_level_dir=".", pythonpath=["src"],
                                                                pattern="nothing_*.py"))
        self.assertEqual(self.engine.verify(task_id)["status"], "failed")
        self.assertIn("MAESTRO: no tests ran", self.store.events(task_id)[-1]["message"])

    def test_tampered_configuration_blocks_verification_and_approval(self):
        task_id = self.implemented()
        spec = dict(self.store.get(task_id)["spec"], verify=dict(LAYOUT, pythonpath=["../outside"]))
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET spec=? WHERE id=?", (canonical(spec).decode(), task_id))
        with patch.object(Seatbelt, "run") as run:
            self.assertEqual(self.engine.verify(task_id)["status"], "failed")
            run.assert_not_called()
        self.assertIn("unsupported verification", self.store.events(task_id)[-1]["message"])
        task_id = self.implemented()
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval")
        # A different, valid layout after verification no longer matches the recorded evidence.
        other = trusted.verify_config(top_level_dir=".", pythonpath=["src", "tests"])
        spec = dict(self.store.get(task_id)["spec"], verify=other, verify_command=trusted.verification_command(other))
        with self.store.connect() as conn:
            conn.execute("UPDATE tasks SET spec=? WHERE id=?", (canonical(spec).decode(), task_id))
        with self.assertRaisesRegex(PolicyError, "verification evidence is stale"):
            self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")

    def test_check_is_read_only_and_reports_the_baseline(self):
        guard = trusted.source_guard(self.repo, self.root)
        root = self.root / "never-created"
        result = self.cli("check", "--repo", self.repo, "--base", self.base, "--pythonpath", "src",
                          "--top-level-dir", ".", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["compatible"])
        self.assertEqual((report["files"], report["baseline"]["passed"], report["baseline"]["exit_code"]), (10, False, 1))
        self.assertIn("test_merges_rows_that_repeat_a_sku", report["baseline"]["excerpt"])
        self.assertEqual(report["command"], trusted.verification_command(LAYOUT))
        self.assertFalse(root.exists())
        self.assertEqual(trusted.source_guard(self.repo, self.root), guard)
        # A sandbox or setup failure is an error, never a "compatible" report.
        with patch.object(trusted, "confined_verify", side_effect=PolicyError("sandbox self-test failed")):
            with self.assertRaisesRegex(PolicyError, "sandbox self-test failed"):
                trusted.check(self.repo, self.base, LAYOUT)
        for bad in (["--test-dir", "../x"], ["--test-dir", "spec"]):
            with self.subTest(bad=bad):
                result = self.cli("check", "--repo", self.repo, "--base", self.base, *bad, root=root)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error", json.loads(result.stderr))
        os.symlink("README.md", self.repo / "link")
        trusted.git(self.repo, self.root, "add", "link")
        trusted.git(self.repo, self.root, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "commit", "-q", "-m", "symlink")
        head = trusted.git(self.repo, self.root, "rev-parse", "HEAD").decode().strip()
        result = self.cli("check", "--repo", self.repo, "--base", head, root=root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_next_steps_follow_each_state(self):
        result = self.cli("start", "--repo", self.repo, "--base", self.base, "--task", self.repo / "TASK.md",
                          "--model", "demo-model", "--pythonpath", "src", "--top-level-dir", ".")
        self.assertEqual(result.returncode, 0, result.stderr)
        started = json.loads(result.stdout)
        self.assertEqual(started["next"], ["trusted implement %s" % started["id"]])
        self.assertEqual(started["spec"]["verify"], LAYOUT)
        task_id = self.implemented(review_model="demo-reviewer")
        self.assertEqual(self.engine.status(task_id)["next"], ["trusted diff %s" % task_id, "trusted verify %s" % task_id])
        self.engine.verify(task_id)
        self.assertIn("trusted review %s" % task_id, self.engine.status(task_id)["next"])
        self.assertFalse(any(step.startswith("trusted approve") for step in self.engine.status(task_id)["next"]))
        self.engine.review(task_id, str(FAKE_CLAUDE))
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.assertIn("trusted approve %s --snapshot %s --founder NAME" % (task_id, sha), self.engine.status(task_id)["next"])
        self.engine.approve(task_id, sha, "human")
        self.assertEqual(self.engine.status(task_id)["next"], ["trusted export %s" % task_id])
        self.engine.export(task_id)
        self.assertEqual(self.engine.status(task_id)["next"], [])

    def test_doctor_reports_claude_code_as_optional_information(self):
        with patch.dict(os.environ, {"PATH": "/nonexistent"}):
            report = doctor.run_checks(self.root / "doctor-state")
        row = next(c for c in report["checks"] if c["check"] == "claude")
        self.assertEqual(row["status"], "info")
        self.assertIn("needed only for trusted review", row["detail"])
        linux = doctor.run_checks(self.root / "doctor-state", system="linux")
        self.assertEqual(next(c for c in linux["checks"] if c["check"] == "claude")["status"], "skip")

    def test_multi_file_project_demo_end_to_end(self):
        result = subprocess.run(["/usr/bin/python3", "-B", str(PROJECT / "demo.py")],
                                capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertTrue(summary["project_demo_passed"])
        self.assertEqual(summary["correct"]["status"], "approved")
        self.assertEqual([c["path"] for c in summary["correct"]["changes"]],
                         ["src/stockroom/errors.py", "src/stockroom/importer.py"])
        self.assertEqual(summary["flawed"]["status"], "failed")
