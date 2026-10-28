#!/usr/bin/env python3
"""Offline privacy guard for this public repository. Standard library only.

It scans what Git will actually record (staged index blobs, the commits being pushed,
or every tracked file), never the working-tree copy. Findings name the rule, path and
line; matched values are never printed. There is no network access or upload, and
nothing outside this repository is read except an optional private term list kept
in .git/info (which Git never commits).

  privacy_scan.py staged             pre-commit: the staged blobs (index content)
  privacy_scan.py push               pre-push: every commit being pushed (hook stdin)
  privacy_scan.py tracked            every file in the index (CI and manual checks)
  privacy_scan.py commits A..B       every commit in a range (CI for pull requests)
  privacy_scan.py history            every commit reachable from any ref (audit)
  privacy_scan.py install [--force]  install the pre-commit and pre-push hooks

Exit status: 0 clean, 1 findings, 2 error. A line containing `privacy-scan: allow`
is not checked by the secret and identifier rules; such lines are reviewed like any
change. Private terms are checked on every line: the marker cannot suppress them.
Hooks are bypassed by `git commit --no-verify` and `git push --no-verify`, and CI
runs only after a push: it cannot un-publish a secret. See CONTRIBUTING.md.
"""
import math
import os
from pathlib import Path
import re
import subprocess
import sys

ALLOW_MARKER = "privacy-scan: allow"
HOOK_MARK = "Installed by .github/scripts/privacy_scan.py"
ZERO = re.compile(r"^0+$")

# High-confidence credential formats. Fixtures in tests are built at runtime.
SECRETS = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]
URL_CREDENTIALS = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@'\"<>]+:([^\s/@'\"<>]+)@([^\s/:'\"<>?#]+)")
ASSIGNMENT = re.compile(r"(?i)\b[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|credential)[\w.-]*\b['\"]?\s*[:=]\s*"
                        r"['\"]([A-Za-z0-9/+_=.-]{24,})['\"]")
PLACEHOLDER = re.compile(r"(?i)example|sample|sentinel|canary|synthetic|dummy|fake|placeholder|redacted|changeme|your|xxxx|test")
HOME_PATH = re.compile(r"(?<![\w.$])/(?:Users|home)/([A-Za-z0-9._-]+)/|\b[A-Za-z]:\\\\?Users\\\\?([A-Za-z0-9._-]+)")
HOME_ALLOWED = {"runner", "you", "me", "user", "username", "name", "example", "shared", "someone", "jdoe"}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b")
EMAIL_DOMAINS = re.compile(r"(?i)(?:^|\.)(?:example\.(?:com|org|net)|example|invalid|test|localhost|"
                           r"users\.noreply\.github\.com|noreply\.github\.com)$")
EMAIL_ADDRESSES = {"noreply@anthropic.com", "git@github.com", "git@gitlab.com", "git@bitbucket.org"}

# Paths that should never be tracked here, whatever they contain.
FORBIDDEN = [
    ("env-file", re.compile(r"(^|/)\.env(\.[^/]*)?$"),
     "environment files hold secrets; commit a .env.example with placeholder values"),
    ("private-key-file", re.compile(r"(^|/)(id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub$)[^/]*|[^/]*\.(?:pem|key|p12|pfx|ppk|jks|keystore))$"),
     "private keys and certificates belong in a secret store"),
    ("credential-file", re.compile(r"(^|/)(\.netrc|\.pypirc|\.npmrc|\.git-credentials|\.?credentials\.json|auth\.json|"
                                   r"token\.json|service[-_]account[^/]*\.json)$"),
     "credential files must stay local"),
    ("database", re.compile(r"\.(?:sqlite3?|db)(?:-journal|-wal|-shm)?$|(^|/)(?:MAESTRO-P0|executor\.lock)$"),
     "MAESTRO state and databases contain local paths and evidence"),
    ("maestro-state", re.compile(r"(^|/)\.maestro/|(^|/)tasks/[0-9a-f]{16}/|(^|/)pilot-evidence/"),
     "runtime state, task workspaces and frozen evidence stay private"),
    ("agent-transcript", re.compile(r"\.jsonl$|(^|/)\.(?:claude|codex)/|(^|/)last-message\.txt$"),
     "agent transcripts and session data stay local"),
    ("log-file", re.compile(r"\.log$"), "logs can contain paths, prompts and tokens"),
    ("test-temp", re.compile(r"(^|/)\.(?:trusted|review|usability|scoped|project-demo|trusted-demo)-[^/]*/"),
     "temporary test and demo directories"),
    ("os-metadata", re.compile(r"(^|/)\.DS_Store$"), "Finder metadata lists local file names"),
]
ENV_SAMPLE = re.compile(r"\.env\.(?:example|sample|template|dist)$")


def git(*args, data=None):
    # Inherit the environment: inside a hook, GIT_DIR and GIT_INDEX_FILE name the real index.
    proc = subprocess.run(["git", "--literal-pathspecs", "-c", "core.quotepath=off", *args],
                          input=data, capture_output=True)
    if proc.returncode:
        raise RuntimeError("git %s failed: %s" % (args[0], proc.stderr.decode("utf-8", "replace").strip()[:300]))
    return proc.stdout


def blobs(oids):
    """Batch-read blob bodies; one process however many files."""
    oids = sorted(set(oids))
    if not oids:
        return {}
    raw, out, offset = git("cat-file", "--batch", data="".join(o + "\n" for o in oids).encode()), {}, 0
    for oid in oids:
        end = raw.index(b"\n", offset)
        header = raw[offset:end].split()
        size = int(header[2])
        out[oid] = raw[end + 1:end + 1 + size]
        offset = end + 2 + size
    return out


def private_terms():
    """Optional local list (never committed): .git/info/privacy-denylist or $MAESTRO_PRIVACY_DENYLIST."""
    paths = [os.environ.get("MAESTRO_PRIVACY_DENYLIST")]
    try:
        paths.append(git("rev-parse", "--git-path", "info/privacy-denylist").decode().strip())
    except RuntimeError:
        pass
    terms = []
    for path in filter(None, paths):
        if os.path.isfile(path):
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    terms.append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(line) + r"(?![A-Za-z0-9])", re.I))
    return terms


def entropy(value):
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def email_allowed(address, domain):
    return address.lower() in EMAIL_ADDRESSES or EMAIL_DOMAINS.search(domain) is not None


def scan_text(text, terms):
    """(rule, line, length) for each finding. Values are measured, never returned."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        # Private terms come first and are never suppressible: the allow marker exists for
        # deliberate public examples, and a private term is never one.
        for index, term in enumerate(terms, 1):
            if term.search(line):
                found.append(("private-term-%d" % index, number, 0))
        if ALLOW_MARKER in line:
            continue
        for rule, pattern in SECRETS:
            found += [(rule, number, len(m.group(0))) for m in pattern.finditer(line)]
        for m in URL_CREDENTIALS.finditer(line):
            # No host is exempt: a real password for a local database is still a credential.
            if not PLACEHOLDER.search(m.group(1)):
                found.append(("url-credentials", number, len(m.group(1))))
        for m in ASSIGNMENT.finditer(line):
            value = m.group(1)
            if (not re.fullmatch(r"[0-9a-fA-F]+", value) and not PLACEHOLDER.search(value) and
                    entropy(value) >= 3.5 and not any(r == "github-token" or r.endswith("-key") for r, n, _ in found if n == number)):
                found.append(("secret-assignment", number, len(value)))
        for m in HOME_PATH.finditer(line):
            if (m.group(1) or m.group(2)) not in HOME_ALLOWED:
                found.append(("home-path", number, len(m.group(0))))
        for m in EMAIL.finditer(line):
            if not email_allowed(m.group(0), m.group(1)):
                found.append(("personal-email", number, len(m.group(0))))
    return found


def forbidden(path):
    for rule, pattern, why in FORBIDDEN:
        if rule == "env-file" and ENV_SAMPLE.search(path):
            continue  # a sample is fine, but never inside a forbidden directory
        if pattern.search(path):
            return rule, why
    return None


class Report:
    def __init__(self):
        self.findings, self.terms, self.seen = [], private_terms(), set()

    def file(self, where, path, body):
        hit = forbidden(path)
        if hit:
            self.add(hit[0], where + path, hit[1])
        if b"\0" in body[:8192]:
            return  # binary: the path rules above still apply
        for rule, line, length in scan_text(body.decode("utf-8", "replace"), self.terms):
            self.add(rule, "%s%s:%d" % (where, path, line), "%d chars, value hidden" % length if length else "value hidden")

    def add(self, rule, location, note):
        if (rule, location) not in self.seen:
            self.seen.add((rule, location))
            self.findings.append((rule, location, note))

    def commits(self, shas):
        for sha in shas:
            short = sha[:12]
            meta = git("show", "-s", "--format=%ae%x00%ce%x00%B", sha).decode("utf-8", "replace").split("\0", 2)
            for role, address in (("author", meta[0]), ("committer", meta[1])):
                domain = address.rpartition("@")[2]
                if address and not email_allowed(address, domain):
                    self.add("personal-email-identity", "commit %s %s" % (short, role),
                             "use your GitHub noreply address (git config user.email)")
            for rule, line, length in scan_text(meta[2], self.terms):
                self.add(rule, "commit %s message:%d" % (short, line), "value hidden")
            changed = []
            raw = git("diff-tree", "--no-commit-id", "-r", "-z", "--root", "-m", "--no-renames",
                      "--diff-filter=AMT", sha).split(b"\0")
            for header, path in zip(raw[0::2], raw[1::2]):
                fields = header.decode().split()
                if len(fields) >= 4 and fields[1] != "160000":
                    changed.append((fields[3], path.decode("utf-8", "replace")))
            bodies = blobs(oid for oid, _ in changed)
            for oid, path in changed:
                self.file("commit %s " % short, path, bodies[oid])

    def print(self):
        if not self.findings:
            print("privacy-scan: clean")
            return 0
        print("privacy-scan: BLOCKED, %d finding(s); values are never printed" % len(self.findings), file=sys.stderr)
        for rule, location, note in self.findings:
            print("  %-24s %s  (%s)" % (rule, location, note), file=sys.stderr)
        print("Fix: remove the value and rotate it if it was ever pushed, untrack the path, or for a deliberate\n"
              "public example add '%s' to that line. Bypassing the hook does not make a value safe."
              % ALLOW_MARKER, file=sys.stderr)
        return 1


def index_entries():
    raw = git("ls-files", "-s", "-z")
    entries = []
    for row in filter(None, raw.split(b"\0")):
        header, path = row.split(b"\t", 1)
        mode, oid, _ = header.decode().split()
        if mode != "160000":
            entries.append((oid, path.decode("utf-8", "replace")))
    return entries


def scan_index(report, staged_only):
    if staged_only:
        names = {p.decode("utf-8", "replace") for p in
                 git("diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT").split(b"\0") if p}
        entries = [entry for entry in index_entries() if entry[1] in names]
    else:
        entries = index_entries()
    bodies = blobs(oid for oid, _ in entries)
    for oid, path in entries:
        report.file("", path, bodies[oid])


def pushed_commits(stdin):
    shas = []
    for line in stdin.splitlines():
        parts = line.split()
        if len(parts) != 4 or ZERO.match(parts[1]):
            continue  # malformed or a branch deletion
        local, remote = parts[1], parts[3]
        known = not ZERO.match(remote) and subprocess.run(["git", "cat-file", "-e", remote + "^{commit}"],
                                                         capture_output=True).returncode == 0
        spec = ["%s..%s" % (remote, local)] if known else [local, "--not", "--remotes"]
        shas += git("rev-list", *spec).decode().split()
    return list(dict.fromkeys(shas))


def install(force):
    hooks = Path(git("rev-parse", "--git-path", "hooks").decode().strip())
    hooks.mkdir(parents=True, exist_ok=True)
    for name, command in (("pre-commit", "staged"), ("pre-push", "push")):
        hook = hooks / name
        if hook.exists() and HOOK_MARK not in hook.read_text(errors="replace") and not force:
            raise RuntimeError("%s exists and was not installed by this script; rerun with --force to replace it" % hook)
        hook.write_text("#!/bin/sh\n# %s. Bypass (not recommended): git %s --no-verify\n"
                        'exec python3 "$(git rev-parse --show-toplevel)/.github/scripts/privacy_scan.py" %s\n'
                        % (HOOK_MARK, name.split("-")[1], command))
        hook.chmod(0o755)
        print("installed", hook)
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    command = args.pop(0) if args else ""
    try:
        if command == "install":
            return install("--force" in args)
        report = Report()
        if command in ("staged", "tracked"):
            scan_index(report, command == "staged")
        elif command == "push":
            report.commits(pushed_commits(sys.stdin.read()))
        elif command == "commits" and len(args) == 1:
            report.commits(git("rev-list", args[0]).decode().split())
        elif command == "history":
            report.commits(git("rev-list", "--all").decode().split())
        else:
            print(__doc__, file=sys.stderr)
            return 2
        return report.print()
    except (RuntimeError, OSError, ValueError, IndexError) as exc:
        print("privacy-scan: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
