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
            # Local services with placeholder passwords stay usable.
            'db = "postgres://app:example-password@127.0.0.1:5432/dev"; cache = "redis://u:changeme@localhost:6379"',
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

    def test_github_service_committer_passes_but_its_personal_author_does_not(self):
        # A squash merge on GitHub is committed by "GitHub <noreply@github.com>"; its author stays checked.
        self.write("a.py", "x = 1\n")
        self.git("commit", "-q", "-m", "base")
        base = self.git("rev-parse", "HEAD").strip()
        service = {"GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply" + "@" + "github.com"}
        self.write("b.py", "y = 2\n")
        self.git("commit", "-q", "-m", "squash merge", env=service)
        merged = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (merged, base))
        self.assertEqual(code, 0, output)
        personal = "alice.jones" + "@" + "gmail.com"
        self.write("c.py", "z = 3\n")
        self.git("commit", "-q", "-m", "squash merge", env=dict(service, GIT_AUTHOR_EMAIL=personal))
        tip = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (tip, merged))
        self.assertEqual(code, 1, output)
        self.assertIn("commit %s author" % tip[:12], output)
        self.assertNotIn("committer", output)
        self.assertNotIn(personal, output)
        # Only that exact service address: another github.com address is still personal.
        self.write("d.py", "w = 4\n")
        self.git("commit", "-q", "-m", "web edit", env=dict(service, GIT_COMMITTER_EMAIL="alice" + "@" + "github.com"))
        last = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (last, tip))
        self.assertEqual(code, 1, output)
        self.assertIn("commit %s committer" % last[:12], output)

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

    def test_env_samples_do_not_bypass_forbidden_directories(self):
        blocked = {"pilot-evidence/.env.example": "maestro-state", ".maestro/.env.example": "maestro-state",
                   ".claude/.env.sample": "agent-transcript", ".scoped-tests-x1/.env.template": "test-temp",
                   ".maestro/tasks/0123456789abcdef/clone/.env.dist": "maestro-state"}
        for path in blocked:
            self.write(path, "API_KEY=your-api-key-here\n")
        self.write(".env.example", "API_KEY=your-api-key-here\n")
        self.write("config/.env.sample", "API_KEY=your-api-key-here\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for path, rule in blocked.items():
            with self.subTest(path=path):
                self.assertIn("%s %s  (" % (rule.ljust(24), path), output)
        self.assertEqual(output.count("BLOCKED, %d finding" % len(blocked)), 1, output)  # the samples are not
        self.assertNotIn(" .env.example  (", output)
        self.assertNotIn("config/.env.sample", output)

    def test_localhost_credentials_are_detected_unless_placeholders(self):
        real = {"postgres://app:" + "Zq8rT4mW9xL2" + "@127.0.0.1:5432/dev": "Zq8rT4mW9xL2",
                "redis://u:" + "Kp3vN7" + "@localhost:6379": "Kp3vN7",
                "mysql://root:" + "hunter2xyz" + "@[::1]:3306/db": "hunter2xyz"}
        for index, url in enumerate(real):
            self.write("conf/local_%d.py" % index, "url = %r\n" % url)
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for index, secret in enumerate(real.values()):
            with self.subTest(index=index):
                self.assertIn("url-credentials          conf/local_%d.py:1" % index, output)
                self.assertNotIn(secret, output)
        clean = self.repo / "placeholders"
        self.repo = clean
        clean.mkdir()
        self.git("init", "-q")
        self.write("conf/local.py", "\n".join([
            'proxy = "http://user:test-only-sentinel@127.0.0.1:9"',
            'db = "postgres://app:example-password@localhost:5432/dev"',
            'cache = "redis://u:changeme@127.0.0.1:6379"', '']))
        self.assertEqual(self.scan("staged"), (0, "privacy-scan: clean\n"))

    def test_allow_marker_cannot_suppress_private_terms(self):
        info = Path(self.git("rev-parse", "--git-path", "info").strip())
        if not info.is_absolute():
            info = self.repo / info
        info.mkdir(parents=True, exist_ok=True)
        (info / "privacy-denylist").write_text("project bluebird\n")
        self.write("notes.md", "Roadmap for Project Bluebird  <!-- privacy-scan: allow -->\n"
                               "Example path: /Users/" + "alice/project  <!-- privacy-scan: allow -->\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        self.assertIn("private-term-1           notes.md:1", output)
        self.assertNotIn("luebird", output)
        self.assertNotIn("home-path", output)  # the marker still covers heuristic public examples
        self.git("commit", "-q", "--no-verify", "-m", "Mention project bluebird  privacy-scan: allow")
        head = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (head, "0" * 40))
        self.assertEqual(code, 1)
        self.assertIn("message:1", output)  # commit messages cannot suppress private terms either

    def test_allow_marker_skips_heuristic_example_but_never_high_confidence_secrets(self):
        self.write("docs/example.md", "Example path: /Users/" + "alice/project  <!-- privacy-scan: allow -->\n")
        self.assertEqual(self.scan("staged")[0], 0)

        high_conf = (
            "private-key", "aws-access-key", "github-token", "anthropic-key",
            "openai-key", "slack-token", "google-api-key", "jwt",
        )
        for index, rule in enumerate(high_conf):
            self.write("docs/leak_%d.md" % index, "Example: %s  <!-- privacy-scan: allow -->\n" % SECRETS[rule])
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for index, rule in enumerate(high_conf):
            with self.subTest(rule=rule):
                self.assertIn("%s" % rule, output)
                self.assertIn("docs/leak_%d.md:1" % index, output)
                self.assertNotIn(SECRETS[rule][-10:], output)

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

    def test_unquoted_secret_assignments_and_bearer_tokens_are_blocked(self):
        secret_a = "Zq8rT4mW9xL2" + "pK7nB3vC6yH1"
        secret_b = "Km4nP9qR2sT7" + "vW5xY8zB3cD6"
        secret_c = "Hx7jL2mN5pQ9" + "rS4tU8vW1yZ3"
        self.write("deploy/run.sh", "export API_TOKEN=" + secret_a + "\n")
        self.write("deploy/config.yml", "service_secret: " + secret_b + "\n")
        self.write("deploy/curl.sh", "curl -H 'Authorization: Bearer " + secret_c + "' https://api.example.com\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        self.assertIn("secret-assignment        deploy/run.sh:1", output)
        self.assertIn("secret-assignment        deploy/config.yml:1", output)
        self.assertIn("bearer-token             deploy/curl.sh:1", output)
        for val in (secret_a, secret_b, secret_c):
            self.assertNotIn(val, output)
            self.assertNotIn(val[-10:], output)

        # Benign unquoted code identifiers, placeholders, paths and hex digests must stay clean.
        clean = self.repo / "clean-unquoted"
        self.repo = clean
        clean.mkdir()
        self.git("init", "-q")
        self.write("app.py", "\n".join([
            "api_token = some_module_helper_function_name_here",
            "TOKEN_NAME = SOME_UPPERCASE_CONSTANT_IDENTIFIER_NAME",
            "token_path = /var/run/service/runtime/token_socket_file",
            "api_key = a163de5a86dcf4eb7586ecabf7df09280589c19ca6ad5fb996e61391b7f92b5c",
            "export API_TOKEN=your-example-token-placeholder-value",
            "Authorization: Bearer example-placeholder-token-value-1234",
            "",
        ]))
        self.assertEqual(self.scan("staged"), (0, "privacy-scan: clean\n"))

    def test_trailing_slash_free_home_paths_are_blocked_unless_allowed(self):
        self.write("env.sh", "\n".join([
            "HOME=/Users/" + "alice",
            'cwd="/home/' + 'bob"',
            "WIN=C:\\Users\\" + "charlie",
            "",
        ]))
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for line_no in (1, 2, 3):
            self.assertIn("home-path                env.sh:%d" % line_no, output)
        for name in ("alice", "bob", "charlie"):
            self.assertNotIn(name, output)

        clean = self.repo / "clean-home"
        self.repo = clean
        clean.mkdir()
        self.git("init", "-q")
        self.write("doc.md", "HOME=/Users/runner\nHOME=/home/user\nC:\\Users\\example\n")
        self.assertEqual(self.scan("staged"), (0, "privacy-scan: clean\n"))

    def test_private_terms_and_secrets_in_commit_author_and_committer_names_are_blocked(self):
        info = Path(self.git("rev-parse", "--git-path", "info").strip())
        if not info.is_absolute():
            info = self.repo / info
        info.mkdir(parents=True, exist_ok=True)
        (info / "privacy-denylist").write_text("secretname\n")

        self.write("a.py", "x = 1\n")
        self.git("commit", "-q", "-m", "author denylist",
                 env={"GIT_AUTHOR_NAME": "SecretName Dev", "GIT_COMMITTER_NAME": "Test"})
        c1 = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (c1, "0" * 40))
        self.assertEqual(code, 1, output)
        self.assertIn("private-term-1           commit %s author" % c1[:12], output)
        self.assertNotIn("committer", output)
        self.assertNotIn("SecretName", output)
        self.assertNotIn("secretname", output)

        # Committer name carrying a denylisted term AND author carrying an embedded email/key.
        self.write("b.py", "y = 2\n")
        self.git("commit", "-q", "-m", "committer denylist",
                 env={"GIT_AUTHOR_NAME": "Dev " + SECRETS["personal-email"],
                      "GIT_COMMITTER_NAME": "SecretName Bot"})
        c2 = self.git("rev-parse", "HEAD").strip()
        code, output = self.scan("push", stdin="refs/heads/main %s refs/heads/main %s\n" % (c2, c1))
        self.assertEqual(code, 1, output)
        self.assertIn("personal-email           commit %s author" % c2[:12], output)
        self.assertIn("private-term-1           commit %s committer" % c2[:12], output)
        self.assertNotIn("SecretName", output)
        self.assertNotIn(SECRETS["personal-email"], output)

    def test_placeholder_substrings_inside_real_secrets_do_not_bypass_scanner(self):
        embedded_test = "Zq8rT4mW9xL2" + "test" + "K7nB3vC6yH1"
        prefixed_real = "test-" + "Km4nP9qR2sT7" + "vW5xY8zB3cD6"
        url_embedded = "https://deploy:" + "Ab9xK2testP8mQ" + "@db.internal/app"
        self.write("cfg/a.py", 'api_key = "%s"\n' % embedded_test)
        self.write("cfg/b.sh", "export API_TOKEN=%s\n" % prefixed_real)
        self.write("cfg/c.py", 'url = "%s"\n' % url_embedded)
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        self.assertIn("secret-assignment        cfg/a.py:1", output)
        self.assertIn("secret-assignment        cfg/b.sh:1", output)
        self.assertIn("url-credentials          cfg/c.py:1", output)
        for val in (embedded_test, prefixed_real, "Ab9xK2testP8mQ"):
            self.assertNotIn(val, output)

    def test_secrets_and_private_terms_in_file_paths_are_blocked_and_redacted(self):
        info = Path(self.git("rev-parse", "--git-path", "info").strip())
        if not info.is_absolute():
            info = self.repo / info
        info.mkdir(parents=True, exist_ok=True)
        (info / "privacy-denylist").write_text("project bluebird\n")

        paths = [
            "docs/project-bluebird-notes.md",
            "exports/" + SECRETS["aws-access-key"] + ".bin",
            "mail/" + SECRETS["personal-email"] + ".txt",
            "Users/alice/dump.txt",
        ]
        for p in paths:
            target = self.repo / p
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"\x00binary-payload" if p.endswith(".bin") else b"harmless\n")
            self.git("add", "--", p)
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for expected_rule in ("private-term-1", "aws-access-key", "personal-email", "home-path"):
            self.assertIn(expected_rule, output)
        self.assertIn("<redacted-path>", output)
        for sensitive in ("bluebird", SECRETS["aws-access-key"], SECRETS["personal-email"], "alice"):
            self.assertNotIn(sensitive, output)

    def test_additional_cloud_and_key_paths_are_blocked(self):
        blocked = {
            ".aws/credentials": "credential-file",
            "ops/.kube/config": "credential-file",
            ".docker/config.json": "credential-file",
            "keys/AuthKey.p8": "private-key-file",
        }
        for path in blocked:
            self.write(path, "harmless\n")
        code, output = self.scan("staged")
        self.assertEqual(code, 1, output)
        for path, rule in blocked.items():
            with self.subTest(path=path):
                self.assertIn("%s %s  (" % (rule.ljust(24), path), output)
