"""`maestro.py providers`: read-only capability catalog. Offline, synthetic paths only."""
import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents import ClaudeCodeAdapter, CodexAdapter
from execution import PolicyError
import maestro
import providers
import reviewer
import trusted

CLI = Path(__file__).resolve().parents[1] / "maestro.py"


class ProvidersCatalogTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-providers-tests-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))

    def run_cli(self, *args, env=None):
        return subprocess.run(
            [sys.executable, "-B", str(CLI), *args],
            capture_output=True, text=True, timeout=15, env=env,
        )

    def test_cli_returns_stable_structured_json(self):
        root = self.base / "state"
        first = self.run_cli("--root", str(root), "providers")
        second = self.run_cli("--root", str(root), "providers")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout, "providers output must be deterministic")
        self.assertEqual(first.stderr, "")

        data = json.loads(first.stdout)
        self.assertEqual(data["schema"], providers.SCHEMA)
        self.assertEqual(data["version"], maestro.__version__)
        self.assertTrue(data["read_only"])
        self.assertEqual(data["discovery"], {
            "executes_agents": False,
            "reads_credentials": False,
            "initializes_state": False,
            "checks_host_binaries": False,
        })
        self.assertTrue(all(v is False for v in data["unsupported"].values()))

    def test_distinguishes_confined_and_trusted_local_modes(self):
        data = providers.catalog(version=maestro.__version__)
        self.assertEqual(set(data["modes"]), {"confined", trusted.MODE})

        confined = data["modes"]["confined"]
        self.assertTrue(confined["agents_confined_by_maestro"])
        self.assertFalse(confined["real_agents_supported"])
        self.assertFalse(confined["fallback_to_other_mode"])
        self.assertEqual(confined["providers"], ["fake-codex", "fake-claude-code"])

        tl = data["modes"][trusted.MODE]
        self.assertFalse(tl["agents_confined_by_maestro"])
        self.assertTrue(tl["real_agents_supported"])
        self.assertFalse(tl["fallback_to_fake_agents"])
        self.assertFalse(tl["fallback_to_other_mode"])
        self.assertEqual(tl["notice"], trusted.NOTICE)
        self.assertIn("not confined by MAESTRO", tl["notice"])
        self.assertEqual(tl["providers"], ["codex", reviewer.PROVIDER])

    def test_describes_fake_and_real_providers_separately_and_honestly(self):
        data = providers.catalog(version=maestro.__version__)
        by_id = {item["id"]: item for item in data["providers"]}
        self.assertEqual(set(by_id), {"fake-codex", "fake-claude-code", "codex", reviewer.PROVIDER})

        for fake_id, role in (("fake-codex", "implement"), ("fake-claude-code", "review")):
            p = by_id[fake_id]
            self.assertEqual(p["role"], role)
            self.assertEqual(p["kind"], "synthetic")
            self.assertFalse(p["real_agent"])
            self.assertEqual(p["supported_modes"], ["confined"])
            self.assertTrue(p["availability_by_mode"]["confined"]["available"])
            self.assertTrue(p["availability_by_mode"]["confined"]["confined_by_maestro"])
            self.assertFalse(p["availability_by_mode"][trusted.MODE]["available"])
            self.assertFalse(p["capabilities"]["real_model_calls"])

        for real_id, role in (("codex", "implement"), (reviewer.PROVIDER, "review")):
            p = by_id[real_id]
            self.assertEqual(p["role"], role)
            self.assertEqual(p["kind"], "real-cli")
            self.assertTrue(p["real_agent"])
            self.assertEqual(p["supported_modes"], [trusted.MODE])
            self.assertFalse(p["availability_by_mode"]["confined"]["available"])
            self.assertTrue(p["availability_by_mode"][trusted.MODE]["available"])
            self.assertFalse(p["availability_by_mode"][trusted.MODE]["confined_by_maestro"])
            self.assertFalse(p["capabilities"]["confined_by_maestro"])
            self.assertIn("NOT confined by MAESTRO", p["confinement_warning"])

        self.assertEqual(by_id["codex"]["environment_forwarded"], list(trusted.CHILD_ENV))
        self.assertFalse(by_id["codex"]["capabilities"]["model_fallback"])
        self.assertFalse(by_id["codex"]["capabilities"]["automatic_retries"])

        claude = by_id[reviewer.PROVIDER]
        self.assertEqual(claude["environment_forwarded"], list(reviewer.CHILD_ENV))
        self.assertEqual(claude["review_contexts"], ["full", "scoped"])
        self.assertEqual(claude["protocols"], {"full": reviewer.PROTOCOL, "scoped": reviewer.SCOPED_PROTOCOL})
        self.assertFalse(claude["capabilities"]["can_modify_files_or_approve"])

    def test_never_initializes_or_touches_state_root(self):
        missing_root = self.base / "never_created"
        unowned_root = self.base / "unowned"
        unowned_root.mkdir()
        (unowned_root / "keep.txt").write_text("untouched")
        symlink_root = self.base / "alias"
        symlink_root.symlink_to(unowned_root, target_is_directory=True)

        for root in (missing_root, unowned_root, symlink_root):
            with self.subTest(root=root.name):
                proc = self.run_cli("--root", str(root), "providers")
                self.assertEqual(proc.returncode, 0, proc.stderr)

        self.assertFalse(missing_root.exists(), "providers must never create a state root")
        self.assertEqual(sorted(os.listdir(unowned_root)), ["keep.txt"])
        self.assertEqual((unowned_root / "keep.txt").read_text(), "untouched")
        self.assertEqual(sorted(os.listdir(self.base)), ["alias", "unowned"])

    def test_never_executes_agent_binaries_or_subprocesses(self):
        poison_dir = self.base / "poison_bin"
        poison_dir.mkdir(mode=0o700)
        marker = self.base / "executed.marker"
        for name in ("codex", "claude"):
            script = poison_dir / name
            script.write_text("#!/bin/sh\necho ran > %s\nexit 0\n" % marker)
            script.chmod(0o700)

        env = dict(os.environ)
        env["PATH"] = str(poison_dir) + os.pathsep + env.get("PATH", "")
        env["MAESTRO_CODEX_BIN"] = str(poison_dir / "codex")
        env["MAESTRO_CLAUDE_BIN"] = str(poison_dir / "claude")

        proc = self.run_cli("--root", str(self.base / "state"), "providers", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(marker.exists(), "providers must never execute agent binaries")

        # In-process check: catalog() makes zero subprocess calls.
        with mock.patch("subprocess.run", side_effect=AssertionError("subprocess.run called")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen called")):
            data = providers.catalog(version=maestro.__version__)
        self.assertEqual(data["schema"], providers.SCHEMA)

    def test_never_reads_credentials_or_leaks_environment_values(self):
        fake_home = self.base / "home"
        codex_dir = fake_home / ".codex"
        claude_dir = fake_home / ".claude"
        codex_dir.mkdir(parents=True, mode=0o700)
        claude_dir.mkdir(parents=True, mode=0o700)
        locked = []
        for cred in (codex_dir / "auth.json", claude_dir / ".credentials.json"):
            cred.write_text('{"token":"synthetic-canary-do-not-read"}')
            cred.chmod(0o000)
            locked.append(cred)
        self.addCleanup(lambda: [p.chmod(0o600) for p in locked if p.exists()])

        env = dict(os.environ)
        env.update({
            "HOME": str(fake_home),
            "CODEX_HOME": str(codex_dir),
            "CLAUDE_CONFIG_DIR": str(claude_dir),
            "OPENAI_API_KEY": "synthetic-openai-canary-value",
            "ANTHROPIC_API_KEY": "synthetic-anthropic-canary-value",
            "GITHUB_TOKEN": "synthetic-github-canary-value",
        })
        proc = self.run_cli("--root", str(self.base / "state"), "providers", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for canary in (str(fake_home), "synthetic-openai-canary-value",
                       "synthetic-anthropic-canary-value", "synthetic-github-canary-value"):
            self.assertNotIn(canary, proc.stdout)

        # In-process check: catalog() performs zero file opens or os.open calls.
        with mock.patch.object(builtins, "open", side_effect=AssertionError("file opened")), \
                mock.patch("os.open", side_effect=AssertionError("os.open called")):
            data = providers.catalog(version=maestro.__version__)
        self.assertTrue(data["read_only"])

    def test_existing_confined_real_adapter_refusal_and_cli_help_preserved(self):
        help_proc = self.run_cli("--help")
        self.assertEqual(help_proc.returncode, 0)
        for cmd in ("doctor", "providers", "create", "run", "approve", "trusted"):
            self.assertIn(cmd, help_proc.stdout)
        for adapter in (CodexAdapter(), ClaudeCodeAdapter()):
            with self.assertRaises(PolicyError):
                adapter.run({})


if __name__ == "__main__":
    unittest.main()
