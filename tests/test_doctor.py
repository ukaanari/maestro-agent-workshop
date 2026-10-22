"""`maestro.py doctor`: read-only prerequisite checks. Offline, synthetic paths only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import doctor
from sandbox import USER_HOME, python_runtime
from workflow import Store

CLI = Path(__file__).resolve().parents[1] / "maestro.py"
SCRATCH = ("maestro-doctor-", "maestro-sandbox-probe-")


def leftovers():
    return {n for n in os.listdir(tempfile.gettempdir()) if n.startswith(SCRATCH)}


class DoctorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-dr-tests-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))

    @staticmethod
    def statuses(report):
        return {c["check"]: c["status"] for c in report["checks"]}

    def test_supported_host_passes_without_changing_anything(self):
        root, before = self.base / "state", leftovers()
        proc = subprocess.run([sys.executable, "-B", str(CLI), "--root", str(root), "doctor"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])
        status = self.statuses(report)
        for name in ("python", "state_root", "sandbox", "confined_worker", "git"):
            self.assertEqual(status[name], "ok", report)
        self.assertEqual(status["real_agents"], "info")
        self.assertFalse(root.exists(), "doctor must never create the state root")
        self.assertEqual(os.listdir(self.base), [])
        self.assertEqual(leftovers(), before, "doctor left temporary directories behind")

    def test_missing_sandbox_engine_fails_closed_and_skips_launch(self):
        report = doctor.run_checks(self.base / "state", sandbox_binary=str(self.base / "absent" / "sandbox-exec"))
        self.assertFalse(report["ok"])
        status = self.statuses(report)
        self.assertEqual(status["sandbox"], "fail")
        self.assertEqual(status["confined_worker"], "skip")
        sandbox = next(c for c in report["checks"] if c["check"] == "sandbox")
        self.assertIn("sandbox engine missing", sandbox["detail"])
        self.assertIn("never runs agents unconfined", sandbox["fix"])

    def test_interpreter_under_home_is_a_reported_blocker(self):
        exe = python_runtime()[0]
        check = doctor.check_python(exe, os.path.join(USER_HOME, ".pyenv", "versions", "3.12.0"))
        self.assertEqual(check["status"], "fail")
        self.assertIn("inside the home directory", check["detail"])
        self.assertIn("pyenv", check["fix"])
        self.assertEqual(doctor.check_python(exe, "/opt/python", (3, 8, 18))["status"], "fail")

    def test_state_root_is_inspected_never_created(self):
        unowned = self.base / "unowned"
        unowned.mkdir()
        (unowned / "keep.txt").write_text("untouched")
        alias = self.base / "alias"
        alias.symlink_to(unowned, target_is_directory=True)
        Store(self.base / "owned")
        cases = {unowned: "fail", alias: "fail", self.base / "missing" / "state": "fail",
                 self.base / "owned": "ok", self.base / "new": "ok"}
        for root, expected in cases.items():
            with self.subTest(root=root.name):
                self.assertEqual(doctor.check_state_root(root)["status"], expected)
        self.assertEqual(sorted(os.listdir(self.base)), ["alias", "owned", "unowned"])
        self.assertEqual((unowned / "keep.txt").read_text(), "untouched")

    def test_unsupported_platform_runs_no_host_probes(self):
        report = doctor.run_checks(self.base / "state", system="linux")
        self.assertFalse(report["ok"])
        status = self.statuses(report)
        self.assertEqual(status["platform"], "fail")
        for name in ("sandbox", "confined_worker", "git"):
            self.assertEqual(status[name], "skip")

    def test_platform_and_git_version_rules(self):
        self.assertEqual(doctor.check_platform("darwin", "26.7", "arm64")["status"], "ok")
        self.assertEqual(doctor.check_platform("darwin", "15.6", "arm64")["status"], "warn")
        self.assertEqual(doctor.check_platform("darwin", "26.7", "x86_64")["status"], "warn")
        self.assertEqual(doctor.parse_git_version("git version 2.54.0 (Apple Git-157)"), (2, 54))
        self.assertLess(doctor.parse_git_version("git version 2.39.5 (Apple Git-154)"), doctor.MIN_GIT)
        self.assertIsNone(doctor.parse_git_version("not git"))


if __name__ == "__main__":
    unittest.main()
