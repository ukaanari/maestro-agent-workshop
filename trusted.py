"""Experimental trusted-local orchestration. Agents have the user's permissions.

Only verification is confined. Agent messages are claims; the Git tree, full
manifest, source guards and independent verification bind human approval.
Process-group cleanup does not contain escaped descendants (issue #2).
"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from execution import (Cancelled, DeadlineExceeded, PolicyError, execute,
                       _running, stop_group)
from sandbox import Seatbelt, ExecPolicy, python_runtime
from workflow import ACTIVE, Engine
from workspace import canonical, digest, directory, read_regular

MODE = "trusted-local"
MAX_ENTRIES, MAX_BYTES, MAX_LOG = 2000, 20 * 1024 * 1024, 10 * 1024 * 1024
NOTICE = "trusted-local: agents run with your user's permissions; not confined by MAESTRO"
GIT = "/usr/bin/git"


def validate_model(model):
    if not isinstance(model, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", model) is None:
        raise PolicyError("invalid model name: expected [a-z0-9][a-z0-9._-]{0,63}")
    return model


def verification_command():
    return [python_runtime()[0], "-I", "-B", "-m", "unittest", "discover", "-s", "tests"]


def git(cwd, home, *args, index=None, cancelled=lambda: False):
    # execute builds a private environment; no inherited Git config or credentials.
    env = {"GIT_OPTIONAL_LOCKS": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1"}
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return execute([GIT, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "-c", "core.attributesFile=/dev/null", "-c", "core.autocrlf=false",
                    "-c", "core.filemode=true", "-c", "protocol.allow=never",
                    "-c", "protocol.file.allow=always", "-c", "diff.external=",
                    "-C", str(cwd), *map(str, args)], str(home), str(home), timeout=60,
                   max_output=32 * 1024 * 1024, extra_env=env, cancelled=cancelled)


def safe_name(name):
    if (not name or name.startswith("/") or "\\" in name or
            any(p in ("", ".", "..") for p in name.split("/")) or
            any(ord(c) < 32 for c in name)):
        raise PolicyError("unsupported path: " + repr(name))
    return name


def names(raw):
    return [safe_name(n.decode("utf-8")) for n in raw.split(b"\0") if n]


def clone_config(clone):
    """No agent-supplied config includes, filters, helpers or alternate metadata.

    This is input validation, not isolation from an agent running as our user.
    Git's own config query can read includes, so inspect the local file directly.
    """
    meta = clone / ".git"
    if meta.is_symlink() or not meta.is_dir():
        raise PolicyError("clone metadata replaced")
    raw, _ = read_regular(meta / "config", MAX_LOG)
    section = ""
    allowed = {"core": {"repositoryformatversion", "filemode", "bare", "logallrefupdates",
                         "ignorecase", "precomposeunicode"}, "extensions": {"objectformat"}}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            if section not in allowed:
                raise PolicyError("unsupported clone Git configuration: " + section)
        elif "=" not in line or line.split("=", 1)[0].strip().lower() not in allowed.get(section, set()):
            raise PolicyError("unsupported clone Git configuration")
    for path in (meta / "objects" / "info" / "alternates", meta / "info" / "attributes",
                 meta / "commondir", meta / "shallow", meta / "config.worktree"):
        if os.path.lexists(path):
            raise PolicyError("unsupported clone metadata: " + path.name)


def source_guard(repo, home):
    """Read-only Git queries. Optional index refresh writes are explicitly disabled."""
    values = {}
    for key, args in (
        ("head", ("rev-parse", "HEAD")),
        ("refs", ("for-each-ref",)),
        ("stash", ("stash", "list")),
        ("index", ("ls-files", "-s", "-z")),
        ("status", ("status", "--porcelain=v2", "--untracked-files=all")),
    ):
        data = git(repo, home, *args)
        values[key] = hashlib.sha256(data).hexdigest() if key == "index" else data.decode("utf-8")
    return values


def scan(root, included=None, ignored=()):
    """Read included regular files only; ignored subtrees are never traversed.

    The root and empty directories are evidence too. Bytes are bound separately
    from Git's executable bit so a filter/normalization cannot silently change them.
    """
    if root.is_symlink() or not root.is_dir():
        raise PolicyError("snapshot directory missing or replaced")
    ignored = set(ignored)
    manifest = {".": {"type": "directory", "mode": root.lstat().st_mode}}
    bodies, total = {}, 0

    def visit(folder):
        nonlocal total
        for entry in sorted(os.scandir(folder), key=lambda e: e.name):
            path = Path(entry.path)
            rel = safe_name(path.relative_to(root).as_posix())
            if rel == ".git":
                continue
            if rel in ignored or rel + "/" in ignored:
                continue  # name only: no lstat/open/recursion into ignored paths
            if entry.name == ".git" or entry.name == ".gitmodules":
                raise PolicyError("nested .git, submodules or .gitmodules rejected: " + rel)
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                manifest[rel] = {"type": "directory", "mode": info.st_mode}
                if len(manifest) > MAX_ENTRIES:
                    raise PolicyError("snapshot entry limit exceeded")
                visit(path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise PolicyError("symlink, special file or hardlink rejected: " + rel)
            elif included is None or rel in included:
                body, mode = read_regular(path, MAX_BYTES - total)
                total += len(body)
                manifest[rel] = {"type": "file", "mode": stat.S_IFREG | mode,
                                 "sha256": hashlib.sha256(body).hexdigest()}
                bodies[rel] = body
            else:
                raise PolicyError("file set changed during snapshot: " + rel)
            if len(manifest) > MAX_ENTRIES:
                raise PolicyError("snapshot entry limit exceeded")
    visit(root)
    return manifest, bodies


def snapshot(clone, home, base):
    clone_config(clone)
    if git(clone, home, "rev-parse", "HEAD").decode().strip() != base:
        raise PolicyError("clone HEAD changed from the approved base")
    stage = git(clone, home, "ls-files", "--stage", "-z")
    if any(row.startswith(b"160000 ") for row in stage.split(b"\0")):
        raise PolicyError("submodules rejected")
    included = set(names(git(clone, home, "ls-files", "--cached", "--others", "--exclude-standard", "-z")))
    ignored_raw = git(clone, home, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    ignored = sorted(n.decode("utf-8") for n in ignored_raw.split(b"\0") if n)
    for n in ignored:
        safe_name(n.rstrip("/"))
    manifest, bodies = scan(clone, included, ignored)
    # Copy the actual index to retain tracked-but-ignored files without force-add.
    index = home / "evidence.index"
    data, _ = read_regular(clone / ".git" / "index", MAX_LOG)
    atomic_write(index, data)
    git(clone, home, "add", "-A", index=index)
    tree = git(clone, home, "write-tree", index=index).decode().strip()
    entries = git(clone, home, "ls-tree", "-rz", tree)
    staged = {}
    for row in entries.split(b"\0"):
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, oid = header.split()
        rel = safe_name(name.decode("utf-8"))
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise PolicyError("unsupported evidence tree entry: " + rel)
        staged[rel] = (mode, oid)
    if set(staged) != set(bodies):
        raise PolicyError("Git evidence tree and included file set differ")
    # Compare raw bytes, not filter-dependent hashes, against the persisted tree.
    for rel, (mode, oid) in staged.items():
        if git(clone, home, "cat-file", "blob", oid.decode()) != bodies[rel]:
            raise PolicyError("Git transformed included bytes: " + rel)
        if (mode == b"100755") != bool(manifest[rel]["mode"] & 0o100):
            raise PolicyError("Git executable mode mismatch: " + rel)
    if scan(clone, included, ignored)[0] != manifest:
        raise PolicyError("clone changed during snapshot")
    value = {"base": base, "tree": tree, "manifest": manifest}
    return dict(value, sha256=digest(value), ignored=ignored)


def atomic_write(path, data):
    fd, temporary = tempfile.mkstemp(prefix=".trusted-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# Constructed, not inherited: the official CLI finds its own login via HOME or
# CODEX_HOME. API keys, tokens, proxies and everything else are never forwarded.
CHILD_ENV = ("HOME", "USER", "LOGNAME", "PATH", "SHELL", "TMPDIR", "CODEX_HOME")


def child_environment():
    return {key: os.environ[key] for key in CHILD_ENV if key in os.environ}


def environment_record():
    """Names only, never values; dropped names are counted, not listed."""
    env = child_environment()
    return {"forwarded": sorted(env), "dropped_count": len(set(os.environ) - set(env))}


def tree_patch(clone, home, snap):
    # Both operands are trees: never built from live files.
    return git(clone, home, "diff-tree", "-p", "--binary", "--no-ext-diff", "--no-textconv",
               snap["base"] + "^{tree}", snap["tree"])


def changes(clone, home, snap):
    raw = git(clone, home, "diff-tree", "-r", "-z", "--no-renames", "--name-status",
              snap["base"] + "^{tree}", snap["tree"])
    parts = [p.decode("utf-8") for p in raw.split(b"\0") if p]
    return [{"status": s, "path": safe_name(p)} for s, p in zip(parts[0::2], parts[1::2])]


def codex_info(explicit=None):
    selected = explicit or os.environ.get("MAESTRO_CODEX_BIN")
    path = shutil.which(str(selected)) if selected else shutil.which("codex")
    if path is None:
        raise PolicyError("Codex CLI not found; no fake fallback")
    path = str(Path(path).absolute())
    realpath = os.path.realpath(path)
    fake = Path(__file__).parent / "tests" / "fixtures" / "fake_codex.py"
    if not selected and (realpath == str(fake.resolve()) or Path(realpath).name == "fake_codex.py"):
        raise PolicyError("fake Codex requires an explicit --codex-bin or MAESTRO_CODEX_BIN")
    version = subprocess.run([path, "--version"], env=child_environment(), capture_output=True,
                             timeout=10, check=False)
    if version.returncode or len(version.stdout) + len(version.stderr) > 65536:
        raise PolicyError("cannot record Codex version")
    return {"path": path, "realpath": realpath, "version": version.stdout.decode("utf-8").strip()}


def launch(clone, task, prompt, binary, timeout, cancelled, cleanup, model):
    validate_model(model)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise PolicyError("trusted timeout must be positive and at most 3600 seconds")
    argv = [binary, "-a", "never", "exec", "-m", model, "--ignore-user-config", "--sandbox", "workspace-write", "--json",
            "--ephemeral", "-C", str(clone), "-o", str(task / "last-message.txt"), "-"]
    cleanup.update(argv=argv, group_cleanup="not_started", descendants_guaranteed_stopped=False)
    if cancelled():
        raise Cancelled("cancelled before launch")
    with tempfile.TemporaryFile(dir=task) as source, \
            open(task / "stdout.jsonl", "xb") as stdout, open(task / "stderr.log", "xb") as stderr:
        source.write(prompt.encode("utf-8"))
        source.seek(0)
        proc = subprocess.Popen(argv, cwd=clone, env=child_environment(), stdin=source,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        cleanup.update(pid=proc.pid, group_cleanup="pending")
        deadline, counts = time.monotonic() + timeout, [0, 0]
        try:
            with selectors.DefaultSelector() as selector:
                for i, stream in enumerate((proc.stdout, proc.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, i)
                while selector.get_map() or _running(proc):
                    if cancelled():
                        raise Cancelled("trusted implementation cancelled")
                    if time.monotonic() >= deadline:
                        raise DeadlineExceeded("trusted implementation timed out")
                    for key, _ in selector.select(0.025):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remaining = MAX_LOG - counts[key.data]
                        (stdout, stderr)[key.data].write(chunk[:remaining])
                        counts[key.data] += len(chunk)
                        if counts[key.data] > MAX_LOG:
                            raise PolicyError("trusted log limit exceeded")
        finally:
            try:
                stop_group(proc)
                cleanup["group_cleanup"] = "completed; escaped descendants not guaranteed"
            except Exception as exc:
                cleanup["group_cleanup"] = "error: " + str(exc)
                raise
            finally:
                cleanup["exit_code"] = proc.returncode
                proc.stdout.close()
                proc.stderr.close()
    if proc.returncode:
        raise PolicyError("Codex exited with code %d" % proc.returncode)
    raw, _ = read_regular(task / "stdout.jsonl", MAX_LOG)
    complete = False
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise PolicyError("malformed Codex JSON event") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise PolicyError("malformed Codex JSON event")
        if event["type"] in ("turn.failed", "error"):
            raise PolicyError("Codex reported a failed turn")
        complete = complete or event["type"] == "turn.completed"
    if not complete:
        raise PolicyError("missing final Codex turn event")


def claims(task):
    result = {"classification": "claims, never verification evidence", "files": {}}
    for name in ("stdout.jsonl", "stderr.log", "last-message.txt"):
        if os.path.lexists(task / name):
            raw, _ = read_regular(task / name, MAX_LOG)
            result["files"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


class TrustedEngine:
    def __init__(self, store, *, test_context=False):
        # Explicit in-process test capability. Never inferred from env, paths,
        # argv or importing unittest; the production CLI never supplies it.
        if type(test_context) is not bool:
            raise PolicyError("test_context must be a boolean")
        self.store = store
        self.test_context = test_context

    def require(self, task_id):
        task = self.store.get(task_id)
        if task["spec"].get("mode") != MODE:
            raise PolicyError("trusted commands require mode trusted-local")
        return task

    def finish(self, task_id, exc):
        state = "failed"
        if isinstance(exc, Cancelled):
            state = "cancelled"
        elif isinstance(exc, DeadlineExceeded):
            state = "timed_out"
        elif isinstance(exc, KeyboardInterrupt):
            state = "interrupted"
        Engine(self.store)._finish(task_id, state, str(exc) or state)

    @contextmanager
    def guard(self, task_id, phase):
        task = self.require(task_id)
        repo, home = Path(task["spec"]["repo"]), self.store.task_dir(task_id)
        expected = self.store.artifact(task_id, "source_guard")
        before = source_guard(repo, home)
        self.store.artifact(task_id, phase + "_source_before", before)
        if before != expected:
            raise PolicyError("source repository guard changed before " + phase)
        try:
            yield
        finally:
            after = source_guard(repo, home)
            self.store.artifact(task_id, phase + "_source_after", after)
            if after != expected:
                raise PolicyError("source repository guard changed after " + phase)

    def start(self, repo, base, task_file, model, cancelled=lambda: False):
        validate_model(model)
        if sys.platform != "darwin" or sys.version_info[:2] != (3, 9):
            raise PolicyError("trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
        repo, task_file = Path(repo).resolve(), Path(task_file).resolve()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", base):
            raise PolicyError("base must be a full lowercase commit SHA")
        prompt = read_regular(task_file, 262144)[0].decode("utf-8")
        spec = {"mode": MODE, "model": model, "execution_context": "test" if self.test_context else "normal",
                "repo": str(repo), "base": base, "task_file": str(task_file),
                "prompt": prompt, "verify_command": verification_command()}
        task_id = digest(spec)[:16]
        home = self.store.task_dir(task_id)
        # Deterministic identity deliberately refuses a second start of the same task.
        if home.exists() or home.is_symlink():
            raise PolicyError("task already started; no retry or partial-clone reuse: " + task_id)
        directory(home)
        with self.store.connect() as conn:
            conn.execute("INSERT INTO tasks(id,status,spec) VALUES(?,?,?)",
                         (task_id, "created", canonical(spec).decode()))
            self.store.log(conn, task_id, "created", NOTICE)
        with self.store.lock(task_id):
            try:
                baseline = source_guard(repo, home)
                self.store.artifact(task_id, "source_guard", baseline)
                self.store.transition(task_id, "preparing", "Preparing isolated clone; single attempt")
                with self.guard(task_id, "start"):
                    partial, clone = home / "clone.partial", home / "clone"
                    git(home, home, "clone", "--no-hardlinks", "--no-checkout", "--template=",
                        str(repo), str(partial), cancelled=cancelled)
                    git(partial, home, "checkout", "--detach", base, cancelled=cancelled)
                    git(partial, home, "remote", "remove", "origin", cancelled=cancelled)
                    if cancelled():
                        raise Cancelled("cancelled before clone promotion")
                    clone_config(partial)
                    # Reject unsupported base content before publishing the clone.
                    snapshot(partial, home, base)
                    partial.rename(clone)
                self.store.artifact(task_id, "clone_ready", {"base": base})
            except (Exception, KeyboardInterrupt) as exc:
                self.finish(task_id, KeyboardInterrupt(str(exc)) if isinstance(exc, Cancelled) else exc)
        return self.store.get(task_id)

    def implement(self, task_id, codex_bin=None, timeout=1200):
        self.require(task_id)
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "preparing" or not self.store.has_artifact(task_id, "clone_ready"):
                raise PolicyError("task is not ready for its single implementation attempt")
            home, cleanup = self.store.task_dir(task_id), {}
            try:
                with self.guard(task_id, "implement"):
                    self.store.transition(task_id, "implementing", "Starting trusted-local Codex CLI")
                    model = validate_model(task["spec"].get("model"))
                    info = dict(codex_info(codex_bin), model=model, environment=environment_record())
                    self.store.artifact(task_id, "codex", info)
                    try:
                        launch(home / "clone", home, task["spec"]["prompt"], info["path"], timeout,
                               lambda: self.store.cancelled(task_id), cleanup, model)
                    finally:
                        self.store.artifact(task_id, "cleanup", cleanup)
                        self.store.artifact(task_id, "claims", claims(home))
                    snap = snapshot(home / "clone", home, task["spec"]["base"])
                    sha = self.store.artifact(task_id, "snapshot", snap)
                    self.store.artifact(task_id, "changes", {"snapshot_sha256": snap["sha256"],
                                                             "files": changes(home / "clone", home, snap)})
                self.store.transition(task_id, "reviewing", "Snapshot ready for independent verification",
                                      {"snapshot_sha256": snap["sha256"], "snapshot_artifact_sha256": sha})
            except (Exception, KeyboardInterrupt) as exc:
                self.finish(task_id, exc)
        return self.store.get(task_id)

    def recorded(self, task_id):
        task = self.require(task_id)
        snap = self.store.artifact(task_id, "snapshot")
        value = {k: snap[k] for k in ("base", "tree", "manifest")}
        if (digest(value) != snap.get("sha256") or snap["base"] != task["spec"]["base"] or
                digest(snap) != task["evidence"].get("snapshot_artifact_sha256") or
                snap["sha256"] != task["evidence"].get("snapshot_sha256")):
            raise PolicyError("snapshot evidence mismatch")
        return snap

    def unchanged(self, task_id):
        snap = self.recorded(task_id)
        home = self.store.task_dir(task_id)
        current = snapshot(home / "clone", home, snap["base"])
        # Ignored names are reported but deliberately outside the approved hash.
        if current["sha256"] != snap["sha256"]:
            raise PolicyError("clone snapshot changed")
        return snap

    def build_verify(self, task_id, snap):
        home = self.store.task_dir(task_id)
        copy = home / "verify"
        if os.path.lexists(copy):
            raise PolicyError("verification copy already exists; no retry")
        copy.mkdir(mode=0o700)
        directories = []
        for rel, entry in snap["manifest"].items():
            if entry["type"] == "directory":
                path = copy if rel == "." else copy / rel
                path.mkdir(parents=True, exist_ok=True)
                directories.append((path, entry["mode"]))
            else:
                path = copy / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                blob = git(home / "clone", home, "show", snap["tree"] + ":" + rel)
                path.write_bytes(blob)
                path.chmod(stat.S_IMODE(entry["mode"]))
        for path, mode in sorted(directories, key=lambda p: len(p[0].parts), reverse=True):
            path.chmod(stat.S_IMODE(mode))
        return copy

    def verify(self, task_id):
        self.require(task_id)
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "reviewing":
                raise PolicyError("task is not ready for verification")
            home = self.store.task_dir(task_id)
            record = {"passed": False, "exit_code": None, "snapshot_sha256": task["evidence"].get("snapshot_sha256")}
            try:
                with self.guard(task_id, "verify"):
                    self.store.transition(task_id, "verifying", "Independent confined verification")
                    if task["spec"].get("verify_command") != verification_command():
                        raise PolicyError("unsupported verification")
                    snap = self.unchanged(task_id)
                    copy = self.build_verify(task_id, snap)
                    manifest, _ = scan(copy)
                    if digest({"base": snap["base"], "tree": snap["tree"], "manifest": manifest}) != snap["sha256"]:
                        raise PolicyError("verification copy hash differs from snapshot")
                    executable, prefix = python_runtime()
                    # A tiny first-party runner is unnecessary: Seatbelt runs the exact
                    # allowlisted argv. execute reports failures as PolicyError.
                    runner = Seatbelt([str(home)], protected=[str(home / "clone")],
                                      allowed_executables=[executable])
                    policy = ExecPolicy(executable, tuple(verification_command()[1:]), str(copy), str(copy),
                                        (str(copy),), readable=(prefix,), timeout=60, max_output=1048576)
                    record["command"] = verification_command()
                    try:
                        output = runner.run(policy, cancelled=lambda: self.store.cancelled(task_id))
                        atomic_write(home / "verification.stdout.log", output)
                        record.update(exit_code=0, passed=True,
                                      stdout={"path": "verification.stdout.log", "bytes": len(output),
                                              "sha256": hashlib.sha256(output).hexdigest()})
                    except PolicyError as exc:
                        # Seatbelt.run exposes a bounded stderr excerpt on nonzero exit.
                        match = re.search(r"child exited with code (-?\d+):", str(exc))
                        error = str(exc).encode("utf-8")[:4000]
                        atomic_write(home / "verification.error.log", error)
                        record.update(exit_code=int(match.group(1)) if match else None,
                                      error=error.decode("utf-8", "replace"),
                                      error_log_sha256=hashlib.sha256(error).hexdigest())
                        raise
                    finally:
                        self.unchanged(task_id)
                record["passed"] = True
                evidence = dict(task["evidence"], verification_sha256=self.store.artifact(task_id, "verification", record))
                self.store.transition(task_id, "awaiting_approval", "Verification passed; exact hash approval required", evidence)
            except (Exception, KeyboardInterrupt) as exc:
                record.update(passed=False, error=str(exc)[:4000])
                if not self.store.has_artifact(task_id, "verification"):
                    self.store.artifact(task_id, "verification", record)
                self.finish(task_id, exc)
        return self.store.get(task_id)

    def checked(self, task_id):
        task = self.require(task_id)
        snap = self.unchanged(task_id)
        verification = self.store.artifact(task_id, "verification")
        if (verification.get("passed") is not True or verification.get("exit_code") != 0 or
                verification.get("snapshot_sha256") != snap["sha256"] or
                verification.get("command") != verification_command() or
                task["spec"].get("verify_command") != verification_command() or
                digest(verification) != task["evidence"].get("verification_sha256")):
            raise PolicyError("verification evidence is stale or unsuccessful")
        return snap

    def approval_context(self, task_id):
        """Fake results need BOTH a recorded test task and a test-only caller.

        Missing context on older tasks means normal. This prevents reopening a
        normal task in a test engine from relabeling it, and prevents a normal
        CLI from approving/exporting a test result. This is an accidental-use
        guard, not a security boundary against a same-user Python caller.
        """
        task = self.require(task_id)
        context = task["spec"].get("execution_context", "normal")
        if context not in ("normal", "test"):
            raise PolicyError("invalid task execution context")
        info = self.store.artifact(task_id, "codex")
        version = info.get("version")
        if not isinstance(version, str) or not version.strip():
            raise PolicyError("missing Codex version evidence")
        if "offline-fixture" in version and not (self.test_context and context == "test"):
            raise PolicyError("offline-fixture approval/export requires a test task and explicit test context")
        if context == "test" and not self.test_context:
            raise PolicyError("test task approval/export requires explicit test context")
        return context

    def approve(self, task_id, snapshot_hash, founder):
        self.require(task_id)
        if not isinstance(founder, str) or not founder.strip() or len(founder) > 200:
            raise PolicyError("explicit founder identity required")
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "awaiting_approval":
                raise PolicyError("task is not awaiting approval")
            if snapshot_hash != task["evidence"].get("snapshot_sha256"):
                raise PolicyError("approval must name the exact snapshot hash")
            context = self.approval_context(task_id)
            try:
                with self.guard(task_id, "approve"):
                    self.checked(task_id)
                approval = {"snapshot_sha256": snapshot_hash, "founder": founder, "execution_context": context}
                evidence = dict(task["evidence"], approval_sha256=self.store.artifact(task_id, "approval", approval))
                self.store.transition(task_id, "approved", "Human approved exact snapshot: " + founder, evidence)
            except (Exception, KeyboardInterrupt) as exc:
                if self.store.get(task_id)["status"] == "awaiting_approval":
                    self.store.transition(task_id, "invalidated", "Approval refused: " + str(exc))
                raise
        return self.store.get(task_id)

    def export(self, task_id):
        self.require(task_id)
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "approved":
                raise PolicyError("export requires exact snapshot approval")
            context = self.approval_context(task_id)
            home = self.store.task_dir(task_id)
            if self.store.has_artifact(task_id, "export"):
                raise PolicyError("patch already exported")
            try:
                with self.guard(task_id, "export"):
                    snap = self.checked(task_id)
                    approval = self.store.artifact(task_id, "approval")
                    if (approval.get("snapshot_sha256") != snap["sha256"] or
                            approval.get("execution_context", "normal") != context or
                            digest(approval) != task["evidence"].get("approval_sha256")):
                        raise PolicyError("approval evidence mismatch")
                    patch = tree_patch(home / "clone", home, snap)
                    self.unchanged(task_id)
                atomic_write(home / "export.patch", patch)
                record = {"snapshot_sha256": snap["sha256"], "tree": snap["tree"], "execution_context": context,
                          "path": str(home / "export.patch"), "sha256": hashlib.sha256(patch).hexdigest()}
                self.store.artifact(task_id, "export", record)
            except (Exception, KeyboardInterrupt) as exc:
                self.store.transition(task_id, "invalidated", "Export refused: " + str(exc))
                raise
        return record

    def diff(self, task_id):
        """The exact patch a human is asked to approve. Changes no task state."""
        task = self.require(task_id)
        if task["status"] not in ("reviewing", "verifying", "awaiting_approval", "approved"):
            raise PolicyError("no recorded snapshot to show for status " + task["status"])
        home = self.store.task_dir(task_id)
        return tree_patch(home / "clone", home, self.recorded(task_id))

    def reject(self, task_id, founder, reason):
        self.require(task_id)
        if not isinstance(founder, str) or not founder.strip() or len(founder) > 200:
            raise PolicyError("explicit founder identity required")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise PolicyError("explicit rejection reason required")
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "awaiting_approval":
                raise PolicyError("only a task awaiting approval can be rejected")
            record = {"snapshot_sha256": task["evidence"].get("snapshot_sha256"),
                      "founder": founder, "reason": reason}
            evidence = dict(task["evidence"], rejection_sha256=self.store.artifact(task_id, "rejection", record))
            self.store.transition(task_id, "rejected", "Human rejected snapshot: " + founder, evidence)
        return self.store.get(task_id)

    def cancel(self, task_id):
        # A running owner polls this flag; a task awaiting approval ends immediately.
        self.require(task_id)
        self.store.cancel(task_id)
        return self.store.get(task_id)

    def status(self, task_id):
        task = self.require(task_id)
        task["events"] = self.store.events(task_id)
        task["notice"] = NOTICE
        if self.store.has_artifact(task_id, "changes"):
            task["changes"] = self.store.artifact(task_id, "changes")["files"]
        return task
