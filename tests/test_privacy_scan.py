"""Offline tests for .github/scripts/privacy_scan.py in throwaway Git repositories.

Every synthetic credential is assembled at runtime from fragments, so this file itself
contains nothing that looks like a real secret.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / ".github" / "scripts" / "privacy_scan.py"
NOREPLY = "1+maestro" + "@users.noreply.github.com"

SECRETS = {  # rule -> synthetic value (never a real credential)
    "aws-access-key": "AKIA" + "QX7T2M9KLP4RWZ3B",
    "github-token": "ghp" + "_" + "a1B2c3D4" * 5,
    "anthropic-key": "sk-" + "ant-" + "api03-" + "x9Y8w7V6" * 4,
    "openai-key": "sk-" + "proj-" + "A1b2C3d4" * 5,
    "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "slack-token": "xox" + "b-" + "1234567890-abcdefghij",
    "google-api-key": "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "jwt": "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3",
    "url-credentials": "https://deploy:" + "s3cr3tP4ssw0rdValue" + "@git.internal.corp/repo.git",
    "secret-assignment": 'api_key = "' + "Zq8rT4mW9xL2pK7nB3vC6yH1" + '"',
    "home-path": "/Users/" + "alice" + "/projects/app/config.py",
    "personal-email": "alice.jones" + "@" + "gmail.com",
}


class PrivacyScanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="privacy-scan-tests-")
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": temp.name, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "LC_ALL": "C"}
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", NOREPLY)

    def git(self, *args, env=None):
        return subprocess.run(["/usr/bin/git", *args], cwd=self.repo, env=dict(self.env, **(env or {})),
                              capture_output=True, text=True, check=True).stdout

    def scan(self, *args, stdin=None, env=None):
        result = subprocess.run([sys.executable, "-B", str(SCANNER), *args], cwd=self.repo, input=stdin,
                                env=dict(self.env, **(env or {})), capture_output=True, text=True, timeout=60)
        return result.returncode, result.stdout + result.stderr

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git("add", "--", path)

    def test_synthetic_credentials_are_blocked_and_never_printed(self):
        for index, (rule, value) in enumerate(SECRETS.items()):
            self.write("src/module_%d.py" % index, "settings = 1\nvalue = %r\n" % value)
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for index, (rule, value) in enumerate(SECRETS.items()):
            with self.subTest(rule=rule):
                self.assertIn(rule, output)
                self.assertIn("src/module_%d.py:2" % index, output)
                self.assertNotIn(value.split("'")[0][-12:], output)  # no part of the value
                self.assertNotIn(value, output)

    def test_dangerous_paths_are_blocked_and_samples_stay_usable(self):
        blocked = {".env": "env-file", "deploy/.env.production": "env-file", "keys/server.pem": "private-key-file",
                   "id_ed25519": "private-key-file", "certs/client.p12": "private-key-file",
                   "state/state.sqlite3": "database", "data/app.db": "database", ".maestro/MAESTRO-P0": "database",
                   ".maestro/tasks/0123456789abcdef/clone/x.py": "maestro-state",
                   "pilot-evidence/run/notes.txt": "maestro-state", "session.jsonl": "agent-transcript",
                   ".claude/settings.json": "agent-transcript", "debug.log": "log-file",
                   ".netrc": "credential-file", "credentials.json": "credential-file",
                   ".review-tests-ab12/x.txt": "test-temp", ".DS_Store": "os-metadata"}
        for path in blocked:
            self.write(path, "harmless\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1)
        for path, rule in blocked.items():
            with self.subTest(path=path):
                self.assertIn("%s %s  (" % (rule.ljust(24), path), output)
        clean = self.repo / "clean"
        self.repo = clean
        clean.mkdir()
        self.git("init", "-q")
        for path in (".env.example", "config/.env.sample", "id_ed25519.pub", "docs/keys.md", "src/database.py"):
            self.write(path, "API_KEY=your-api-key-here\n")
        self.assertEqual(self.scan("staged"), (0, "privacy-scan: clean\n"))

    def test_clean_sources_canaries_and_examples_pass(self):
        self.write("tests/test_env.py", "\n".join([
            'CANARIES = {"ANTHROPIC_API_KEY": "test-only-sentinel",',
            '            "HTTPS_PROXY": "http://user:test-only-sentinel@127.0.0.1:9"}',
            'os.environ["MAESTRO_P1A_SIBLING_SECRET"] = "SYNTHETIC-SIBLING-CANARY-VALUE"',
            'snapshot_sha256 = "a163de5a86dcf4eb7586ecabf7df09280589c19ca6ad5fb996e61391b7f92b5c"',
            'author = "MAESTRO Fixture <fixture@example.invalid>"; committer = "%s"' % NOREPLY,
            'trailer = "Co-Authored-By: Claude <noreply@anthropic.com>"; remote = "git@github.com:owner/repo.git"',
            'paths = ["/Users/runner/work", "/absolute/path/to/repo", "~/.local/bin/claude"]',
            'url = "https://github.com/ukaanari/maestro-agent-workshop"; password = input()',
            'token_budget = 32000  # sk-short is not a key',
            # Local services: exempt by host alone, even with a non-placeholder password.
            'db = "postgres://app:' + 'Zq8rT4mW9xL2' + '@127.0.0.1:5432/dev"; cache = "redis://u:' + 'Kp3v' + '@localhost:6379"',
            '']))
        self.write("README.md", "Use `maestro.py trusted check` before a task.\n")
        self.assertEqual(self.scan("staged"), (0, "privacy-scan: clean\n"))

    def test_staged_content_is_scanned_not_the_working_tree(self):
        self.write("app.py", "key = %r\n" % SECRETS["aws-access-key"])
        (self.repo / "app.py").write_text("key = None\n")  # working copy cleaned, index still dirty
        code, output = self.scan("staged")
        self.assertEqual(code, 1)
        self.assertIn("aws-access-key", output)
        self.write("app.py", "key = None\n")
        (self.repo / "app.py").write_text("key = %r\n" % SECRETS["aws-access-key"])  # unstaged secret
        self.assertEqual(self.scan("staged")[0], 0)

    def test_unusual_file_names(self):
        names = {"dir with space/.env": "env-file", "naïve résumé.txt": "github-token",
                 "-rf.py": "openai-key", "tab\tname.txt": "slack-token", "quote'name\".py": "aws-access-key"}
        for name, rule in names.items():
            value = "x" if rule == "env-file" else SECRETS[rule]
            self.write(name, "value = %r\n" % value)
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for name, rule in names.items():
            with self.subTest(name=name):
                self.assertIn(rule, output)
                self.assertIn(name, output)

    def test_push_scans_every_new_commit_and_identity(self):
        self.write("a.py", "x = 1\n")
        self.git("commit", "-q", "-m", "base")
        self.write("b.py", "key = %r\n" % SECRETS["github-token"])
        self.git("commit", "-q", "-m", "add")
        self.git("rm", "-q", "b.py")
        self.git("commit", "-q", "-m", "remove again")  # the secret survives in history
        head = self.git("rev-parse", "HEAD").strip()
        stdin = "refs/heads/main %s refs/heads/main %s\n" % (head, "0" * 40)
        code, output = self.scan("push", stdin=stdin)
        self.assertEqual(code, 1, output)
        self.assertIn("github-token", output)
        self.assertIn("b.py:1", output)
        self.write("c.py", "y = 2\n")
        personal = "alice.jones" + "@" + "gmail.com"
        self.git("commit", "-q", "-m", "personal identity", env={"GIT_AUTHOR_EMAIL": personal,
                                                               "GIT_COMMITTER_EMAIL": personal})
        tip = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (tip, head))
        self.assertEqual(code, 1)
        self.assertIn("personal-email-identity", output)
        self.assertNotIn(personal, output)
        self.assertEqual(self.scan("push", stdin="refs/heads/gone %s refs/heads/gone %s\n" % ("0" * 40, tip))[0], 0)

    def test_private_terms_come_only_from_a_local_list_and_are_not_printed(self):
        self.write("notes.md", "Shared design notes for Project Bluebird.\n")
        self.assertEqual(self.scan("staged")[0], 0)
        info = Path(self.git("rev-parse", "--git-path", "info").strip())
        if not info.is_absolute():
            info = self.repo / info
        info.mkdir(parents=True, exist_ok=True)
        (info / "privacy-denylist").write_text("# private terms, one per line\nproject bluebird\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1)
        self.assertIn("private-term-1", output)
        self.assertNotIn("luebird", output)

    def test_allow_marker_skips_a_reviewed_public_example(self):
        self.write("docs/example.md", "Example key: %s  <!-- privacy-scan: allow -->\n" % SECRETS["aws-access-key"])
        self.assertEqual(self.scan("staged")[0], 0)

    def test_hooks_install_block_a_commit_and_respect_foreign_hooks(self):
        hooks = self.repo / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        (hooks / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
        self.assertEqual(self.scan("install")[0], 2)  # someone else's hook is never replaced silently
        code, output = self.scan("install", "--force")
        self.assertEqual(code, 0, output)
        # The hook runs the scanner from the work tree, so put this scanner there.
        (self.repo / ".github" / "scripts").mkdir(parents=True)
        (self.repo / ".github" / "scripts" / "privacy_scan.py").write_bytes(SCANNER.read_bytes())
        self.write("leak.py", "key = %r\n" % SECRETS["anthropic-key"])
        env = dict(self.env, PATH=os.path.dirname(sys.executable) + ":/usr/bin:/bin")
        blocked = subprocess.run(["/usr/bin/git", "commit", "-q", "-m", "leak"], cwd=self.repo, env=env,
                                 capture_output=True, text=True)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("anthropic-key", blocked.stderr)
        self.assertNotIn(SECRETS["anthropic-key"], blocked.stderr)
        # Documented limitation: --no-verify skips local hooks; CI and push protection remain.
        bypass = subprocess.run(["/usr/bin/git", "commit", "-q", "--no-verify", "-m", "bypass"], cwd=self.repo,
                                env=env, capture_output=True, text=True)
        self.assertEqual(bypass.returncode, 0)

    @unittest.skipUnless((ROOT / ".git").exists(), "needs the MAESTRO Git checkout")
    def test_this_repository_is_clean(self):
        result = subprocess.run([sys.executable, "-B", str(SCANNER), "tracked"], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
