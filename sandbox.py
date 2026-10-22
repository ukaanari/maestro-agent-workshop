"""macOS Seatbelt confinement for untrusted subprocesses. Fails closed.

Every confined process starts under a generated deny-default sandbox profile:
reads only the system runtime plus explicitly listed paths, writes only to
approved disposable directories, executes only allowlisted binaries, and has no
network, Mach service, IPC, process-inspection or outside-signal access. Paths
reach the kernel as profile parameters, never as interpolated profile text.
Before each launch a self-test proves the engine actually denies an outside write.

`sandbox-exec` is deprecated by Apple but is the only OS-enforced, no-install
confinement on this host; see P1A-SECURITY.md for verified properties and gaps.
Worktrees, cwd, HOME and process groups are NOT the boundary; this module is.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

from execution import PolicyError, execute

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
# Read-only OS runtime: dyld shared cache, system libraries and frameworks.
SYSTEM_READ = ("/usr/lib", "/System/Library", "/System/Volumes/Preboot/Cryptexes/OS",
               "/System/Cryptexes/OS")
# dyld opens "/" itself (a listing of top-level names); devices hold no user data.
BASE_READ = ("/", "/dev/null", "/dev/urandom", "/dev/random")
# libSystem initialisation aborts without these read-only kernel values.
SYSCTLS = ("kern.bootargs", "security.mac.lockdown_mode_state")
# Interpreters and launchers that would turn an argv policy into a shell.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "env", "osascript",
          "sudo", "su", "login", "open", "launchctl", "xargs", "sandbox-exec"}
ENV_ALLOWLIST = {"LANG", "NO_COLOR", "TERM"}
MAX_ARGS, MAX_ARG = 64, 8192
USER_HOME = os.path.realpath(os.path.expanduser("~"))
SOURCE_DIR = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))


class IsolationUnavailable(PolicyError):
    pass


def python_runtime():
    """Real interpreter binary and stdlib prefix. Framework launchers re-exec
    Python.app, which would need a second exec grant; run the target directly."""
    prefix = os.path.realpath(sys.base_prefix)
    app = os.path.join(prefix, "Resources", "Python.app", "Contents", "MacOS", "Python")
    return (app if os.path.isfile(app) else os.path.realpath(sys.executable)), prefix


def canonical_path(value, kind="path"):
    """Absolute, existing, symlink-free path: what Seatbelt actually matches."""
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise PolicyError("invalid %s" % kind)
    text = str(value)
    if any(ord(c) < 32 for c in text) or not os.path.isabs(text):
        raise PolicyError("%s must be absolute: %s" % (kind, text))
    if text != os.path.normpath(text) or os.path.realpath(text) != text:
        raise PolicyError("%s must be canonical with no symlink or .. components: %s" % (kind, text))
    if not os.path.lexists(text):
        raise PolicyError("%s does not exist: %s" % (kind, text))
    return text


def inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True)
class ExecPolicy:
    """One explicit grant. Anything not named here is denied by the kernel."""
    executable: str
    args: tuple
    cwd: str
    home: str                   # private HOME/TMPDIR; inside a writable directory
    writable: tuple             # directories strictly inside an approved disposable root
    readable: tuple = ()        # read-only files (exact) or directories (whole subtree)
    listable: tuple = ()        # directories whose entry names, not contents, are readable
    allow_fork: bool = False    # children inherit the sandbox; exec stays allowlisted
    network: str = "deny"
    timeout: float = 5
    max_output: int = 262144
    env: tuple = ()             # (name, value) pairs from ENV_ALLOWLIST only


class Seatbelt:
    def __init__(self, approved_roots, protected=(), allowed_executables=(), binary=SANDBOX_EXEC):
        self.binary = binary
        self.approved_roots = tuple(canonical_path(r, "approved root") for r in approved_roots)
        self.protected = tuple(str(p) for p in protected)
        self.allowed_executables = frozenset(canonical_path(e, "executable") for e in allowed_executables)
        for root in self.approved_roots:
            self._not_broad(root, "approved root")
        for path in self.protected:
            if not os.path.isabs(path) or os.path.realpath(path) != path:
                raise PolicyError("protected paths must be canonical: " + path)

    @staticmethod
    def _not_broad(path, kind):
        if path == "/" or inside(USER_HOME, path):
            raise PolicyError("%s is too broad: %s" % (kind, path))

    def _personal(self, path, allow_source):
        """Under the user's home only approved roots and first-party source are grantable."""
        return inside(path, USER_HOME) and not (
            any(inside(path, root) for root in self.approved_roots) or
            (allow_source and inside(path, SOURCE_DIR)))

    def validate(self, policy):
        if not isinstance(policy, ExecPolicy):
            raise PolicyError("explicit ExecPolicy required")
        if policy.network != "deny":
            raise PolicyError("only network='deny' exists in P1-A")
        if (type(policy.timeout) not in (int, float) or not 0 < policy.timeout <= 60 or
                type(policy.max_output) is not int or not 0 < policy.max_output <= 1048576 or
                type(policy.allow_fork) is not bool):
            raise PolicyError("invalid execution budget")
        exe = canonical_path(policy.executable, "executable")
        info = os.stat(exe)
        if (exe not in self.allowed_executables or not stat.S_ISREG(info.st_mode) or
                info.st_mode & 0o022 or not os.access(exe, os.X_OK) or
                Path(exe).name in SHELLS):
            raise PolicyError("executable is not allowlisted: " + exe)
        if (not isinstance(policy.args, tuple) or len(policy.args) > MAX_ARGS or
                any(not isinstance(a, str) or "\x00" in a or len(a) > MAX_ARG for a in policy.args)):
            raise PolicyError("invalid argument vector")
        if not isinstance(policy.env, tuple) or any(
                not isinstance(pair, tuple) or len(pair) != 2 or pair[0] not in ENV_ALLOWLIST or
                not isinstance(pair[1], str) or "\x00" in pair[1] for pair in policy.env):
            raise PolicyError("environment variable not allowlisted")
        if not all(isinstance(g, tuple) for g in (policy.writable, policy.readable, policy.listable)):
            raise PolicyError("path grants must be tuples")
        if not policy.writable:
            raise PolicyError("at least one approved writable workspace is required")
        writable = [canonical_path(p, "writable path") for p in policy.writable]
        for path in writable:
            if not os.path.isdir(path) or os.lstat(path).st_uid != os.getuid():
                raise PolicyError("writable path must be a directory owned by this user: " + path)
            if not any(inside(path, root) and path != root for root in self.approved_roots):
                raise PolicyError("writable path is outside approved disposable roots: " + path)
            if inside(exe, path):
                raise PolicyError("executable must not be agent-writable")
        readable = [canonical_path(p, "readable path") for p in policy.readable]
        listable = [canonical_path(p, "listable path") for p in policy.listable]
        for path in readable:
            self._not_broad(path, "readable path")
            # Source *files* only: a source directory subtree would include .maestro/.
            if os.path.isdir(path) and inside(SOURCE_DIR, path):
                raise PolicyError("MAESTRO source directory subtree is not grantable: " + path)
            if self._personal(path, allow_source=os.path.isfile(path)):
                raise PolicyError("readable path is inside a personal directory: " + path)
            if any(inside(guarded, path) for guarded in self.protected):
                raise PolicyError("readable grant contains protected MAESTRO state: " + path)
        for path in listable:
            if not os.path.isdir(path) or self._personal(path, allow_source=True):
                raise PolicyError("listable path must be an approved directory: " + path)
        for path in writable + readable + listable:
            # Protected paths inside a writable grant are carved out by a final deny rule.
            if any(inside(path, guarded) for guarded in self.protected):
                raise PolicyError("grant is inside protected MAESTRO state: " + path)
        cwd = canonical_path(policy.cwd, "working directory")
        home = canonical_path(policy.home, "home directory")
        for path in (cwd, home):
            if not os.path.isdir(path) or not any(inside(path, p) for p in writable):
                raise PolicyError("cwd and home must be inside a writable workspace")
        return exe, writable, readable, listable, cwd, home

    def profile(self, exe, writable, readable, listable, allow_fork):
        """Profile text contains only fixed rules and generated parameter names."""
        params, lines = {}, ["(version 1)", "(deny default)"]

        def param(prefix, value):
            name = "%s%d" % (prefix, sum(k.startswith(prefix) for k in params))
            params[name] = value
            return '(param "%s")' % name

        lines.append("(allow file-read* %s %s)" % (
            " ".join('(subpath "%s")' % p for p in SYSTEM_READ),
            " ".join('(literal "%s")' % p for p in BASE_READ)))
        lines.append('(allow file-write-data (literal "/dev/null"))')
        lines.append("(allow sysctl-read %s)" % " ".join('(sysctl-name "%s")' % n for n in SYSCTLS))
        grants = [exe] + writable + readable + listable
        ancestors = sorted({str(a) for g in grants for a in Path(g).parents})
        # realpath() and dyld lstat each ancestor: metadata only, no listing or content.
        lines.append("(allow file-read-metadata %s)" % " ".join(
            "(literal %s)" % param("A", a) for a in ancestors))
        lines.append("(allow file-read* process-exec (literal %s))" % param("E", exe))
        for path in readable:
            matcher = "subpath" if os.path.isdir(path) else "literal"
            lines.append("(allow file-read* (%s %s))" % (matcher, param("R", path)))
        for path in listable:
            lines.append("(allow file-read* (literal %s))" % param("L", path))
        for path in writable:
            ref = param("W", path)
            lines.append("(allow file-read* file-write* (subpath %s))" % ref)
            # The approved directory itself cannot be removed, renamed or re-pointed.
            lines.append("(deny file-write* (literal %s))" % ref)
        for path in self.protected:
            lines.append("(deny file-read* file-write* (subpath %s))" % param("P", path))
        if allow_fork:
            lines.append("(allow process-fork)")
        lines.append("(allow signal (target same-sandbox))")
        # Not covered by (deny default) on macOS 26: without this rule a confined
        # process can read other same-user processes' argv and environment.
        lines.append("(deny process-info*)")
        lines.append("(allow process-info* (target self))")
        lines.append("(deny network*)")
        return "\n".join(lines) + "\n", params

    def command(self, policy):
        exe, writable, readable, listable, cwd, home = self.validate(policy)
        text, params = self.profile(exe, writable, readable, listable, policy.allow_fork)
        argv = [self.binary, "-p", text]
        for name, value in params.items():
            argv += ["-D", "%s=%s" % (name, value)]
        return argv + [exe, *policy.args], cwd, home

    def available(self):
        """Fail closed unless this host enforces a deny-default write boundary now."""
        if sys.platform != "darwin":
            raise IsolationUnavailable("Seatbelt confinement requires macOS")
        try:
            info = os.stat(self.binary)
        except OSError as exc:
            raise IsolationUnavailable("sandbox engine missing: %s" % self.binary) from exc
        if (not os.path.isabs(self.binary) or not stat.S_ISREG(info.st_mode) or
                info.st_mode & 0o022 or info.st_uid not in (0, os.getuid())):
            raise IsolationUnavailable("sandbox engine binary is not trustworthy")
        probe = Path(os.path.realpath(tempfile.mkdtemp(prefix="maestro-sandbox-probe-")))
        try:
            inner, outer = probe / "inside", probe / "outside"
            inner.mkdir()
            outer.mkdir()
            touch = os.path.realpath("/usr/bin/touch")
            checker = Seatbelt([str(probe)], allowed_executables=[touch], binary=self.binary)
            argv, cwd, home = checker.command(ExecPolicy(
                touch, (str(inner / "ok"), str(outer / "escape")), str(inner), str(inner),
                (str(inner),), timeout=5))
            try:
                execute(argv, cwd, home, timeout=5)
            except PolicyError:
                pass  # touch must fail on the outside path
            if (outer / "escape").exists() or not (inner / "ok").exists():
                raise IsolationUnavailable("sandbox self-test failed: outside write not denied "
                                           "or inside write not permitted")
        finally:
            shutil.rmtree(probe, ignore_errors=True)
        return True

    def run(self, policy, data=b"", cancelled=lambda: False):
        argv, cwd, home = self.command(policy)
        self.available()
        return execute(argv, cwd, home, data=data, timeout=policy.timeout, cancelled=cancelled,
                       max_output=policy.max_output, extra_env=dict(policy.env))
