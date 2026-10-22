"""Read-only host prerequisite checks behind `maestro.py doctor`.

Nothing on the host is installed, configured or initialised; the state root is
inspected, never created. The only writes are private temporary directories for
the sandbox self-test, one confined fake-worker launch and one synthetic Git
worktree, all removed before returning. Policies are the production ones, so a
passing check means the real code path works here, not a look-alike.
"""
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

from agents import FakeAdapter, envelope
from execution import PolicyError, execute
from sandbox import SANDBOX_EXEC, USER_HOME, Seatbelt, inside, python_runtime
from workspace import Workspace, read_regular

GIT = "/usr/bin/git"            # the exact binary workspace.Workspace.git runs
MIN_GIT = (2, 42)               # first release with `git worktree add --orphan`
TESTED = ("26", "arm64")        # macOS major version and machine actually tested


def result(check, status, detail, fix=None):
    item = {"check": check, "status": status, "detail": detail}
    if fix:
        item["fix"] = fix
    return item


def skipped(check, reason):
    return result(check, "skip", "not run: " + reason)


def check_platform(system=None, release=None, machine=None):
    system = system or sys.platform
    if system != "darwin":
        return result("platform", "fail", "%s has no MAESTRO isolation backend; every task ends blocked" % system,
                      "Use macOS. Linux and Windows backends do not exist yet")
    release, machine = release or platform.mac_ver()[0], machine or platform.machine()
    detail = "macOS %s on %s" % (release, machine)
    if (release.split(".")[0], machine) != TESTED:
        return result("platform", "warn", detail + "; only macOS 26 on arm64 has been tested",
                      "Run the full test suite before trusting results on this host")
    return result("platform", "ok", detail)


def check_python(exe=None, prefix=None, version=None):
    if exe is None or prefix is None:
        exe, prefix = python_runtime()
    version = tuple((version or sys.version_info)[:3])
    detail = "Python %d.%d.%d, interpreter %s" % (version + (exe,))
    if version < (3, 9):
        return result("python", "fail", detail + "; Python 3.9 or newer is required", "Use Python 3.9+")
    if inside(prefix, USER_HOME):
        return result("python", "fail", detail + "; its prefix %s is inside the home directory, "
                      "which the sandbox path policy refuses to grant" % prefix,
                      "Use an interpreter installed outside your home directory "
                      "(Xcode Command Line Tools, python.org or Homebrew), not pyenv/conda/uv")
    return result("python", "ok", detail)


def check_sandbox(binary=SANDBOX_EXEC):
    with tempfile.TemporaryDirectory(prefix="maestro-doctor-") as tmp:
        try:
            Seatbelt([os.path.realpath(tmp)], allowed_executables=[python_runtime()[0]],
                     binary=binary).available()
        except (PolicyError, OSError) as exc:
            return result("sandbox", "fail", str(exc),
                          "MAESTRO needs a working %s; it never runs agents unconfined" % SANDBOX_EXEC)
    return result("sandbox", "ok", "%s denied an outside write and allowed an inside write "
                  "(self-test); Apple marks sandbox-exec deprecated" % binary)


def check_worker(binary=SANDBOX_EXEC):
    """Run the real fake implementer under the real agent policy in a throwaway root."""
    spec = {"scenario": "success", "target": "doctor.txt", "expected": "doctor\n"}
    with tempfile.TemporaryDirectory(prefix="maestro-doctor-") as tmp:
        root = Path(os.path.realpath(tmp))
        home = root / "home"
        home.mkdir(mode=0o700)
        try:
            sandbox = Seatbelt([str(root)], allowed_executables=[python_runtime()[0]], binary=binary)
            output = FakeAdapter("implement").run(envelope("doctor", "implement", spec), home=home,
                                                  timeout=10, cancelled=lambda: False, sandbox=sandbox)
        except (RuntimeError, OSError, ValueError) as exc:
            return result("confined_worker", "fail", "fake implementer failed under the agent policy: %s" % exc,
                          "Check the python result; the interpreter must start inside the sandbox")
    if not isinstance(output, dict) or output.get("edits") != [{"path": spec["target"], "text": spec["expected"]}]:
        return result("confined_worker", "fail", "fake implementer returned an unexpected result")
    return result("confined_worker", "ok", "deterministic fake implementer ran confined and returned "
                  "a hash-verified envelope (no model involved)")


def parse_git_version(text):
    match = re.search(r"git version (\d+)\.(\d+)", text)
    return tuple(map(int, match.groups())) if match else None


def check_git():
    # On macOS /usr/bin/git is a shim: without developer tools it opens an
    # installer dialog, so confirm they exist first (read-only query).
    try:
        tools = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        tools = None
        reason = str(exc)
    if tools is None or tools.returncode != 0:
        return result("git", "fail", "Xcode Command Line Tools not found (%s)" % (
            reason if tools is None else tools.stderr.strip() or "xcode-select -p failed"),
            "Install them yourself with: xcode-select --install")
    with tempfile.TemporaryDirectory(prefix="maestro-doctor-") as tmp:
        try:
            ws = Workspace(Path(os.path.realpath(tmp)) / "task")
            text = execute([GIT, "--version"], str(ws.task_dir), str(ws.home), timeout=10).decode()
            version = parse_git_version(text)
            if version is None or version < MIN_GIT:
                return result("git", "fail", "%s reports %r; %d.%d+ is required for unborn worktrees" % (
                    (GIT, text.strip()) + MIN_GIT), "Update the Xcode Command Line Tools")
            ws.create()  # bare repo + `worktree add --orphan`, exactly as a task does
        except (RuntimeError, OSError, ValueError) as exc:
            return result("git", "fail", "synthetic worktree setup failed: %s" % exc)
    return result("git", "ok", "%s; created and removed a synthetic unborn worktree" % text.strip())


def check_state_root(root):
    raw = Path(root).absolute()
    if raw.is_symlink():
        return result("state_root", "fail", "%s is a symlink, which MAESTRO refuses" % raw)
    if not raw.exists():
        if not raw.parent.is_dir():
            return result("state_root", "fail", "parent directory %s does not exist" % raw.parent,
                          "Create the parent directory or choose another --root")
        return result("state_root", "ok", "%s does not exist yet; created on first use" % raw)
    if not raw.is_dir():
        return result("state_root", "fail", "%s is not a directory" % raw)
    marker = raw / "MAESTRO-P0"
    if marker.exists() or marker.is_symlink():
        try:
            owned = read_regular(marker)[0] == b"synthetic-only-v1\n"
        except (PolicyError, OSError):
            owned = False
        if owned:
            return result("state_root", "ok", "%s is an existing MAESTRO state root" % raw)
        return result("state_root", "fail", "%s has an unrecognised MAESTRO marker" % raw)
    if any(raw.iterdir()):
        return result("state_root", "fail", "%s is not empty and not a MAESTRO state root" % raw,
                      "Point --root at a new or empty directory")
    return result("state_root", "ok", "%s is empty; initialised on first use" % raw)


def run_checks(root, sandbox_binary=SANDBOX_EXEC, system=None):
    checks = [check_platform(system), check_python(), check_state_root(root)]
    if checks[0]["status"] == "fail":
        checks += [skipped(name, "unsupported platform") for name in ("sandbox", "confined_worker", "git")]
    else:
        checks.append(check_sandbox(sandbox_binary))
        checks.append(check_worker(sandbox_binary) if checks[-1]["status"] == "ok"
                      else skipped("confined_worker", "sandbox unavailable"))
        checks.append(check_git())
    checks.append(result("real_agents", "info", "Codex CLI and Claude Code adapters are disabled; "
                         "only deterministic fake agents run (see docs/ROADMAP.md)"))
    return {"ok": all(c["status"] != "fail" for c in checks), "checks": checks}
