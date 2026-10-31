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
import reviewer
from sandbox import Seatbelt, ExecPolicy, python_runtime
from workflow import ACTIVE, Engine
from workspace import canonical, digest, directory, read_regular

MODE = "trusted-local"
MAX_ENTRIES, MAX_BYTES, MAX_LOG = 2000, 20 * 1024 * 1024, 10 * 1024 * 1024
NOTICE = "trusted-local: agents run with your user's permissions; not confined by MAESTRO"
GIT = "/usr/bin/git"


class IntegrityError(PolicyError):
    """The clone snapshot or the source repository changed: recorded evidence no longer holds."""


def validate_model(model):
    if not isinstance(model, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", model) is None:
        raise PolicyError("invalid model name: expected [a-z0-9][a-z0-9._-]{0,63}")
    return model


SAFE_DIR = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")
SAFE_PATTERN = re.compile(r"[A-Za-z0-9_*?][A-Za-z0-9_.*?-]*\.py")
# A fixed program, never built from configuration: validated paths arrive as separate
# argv items. It reports counts on stdout and fails when no test ran.
VERIFY_RUNNER = (
    "import json, os, sys, unittest\n"
    "i = sys.argv.index('--')\n"
    "sys.path[:0] = [os.path.abspath(p) for p in sys.argv[1:i]]\n"
    "r = unittest.main(module=None, argv=['python -m unittest', 'discover'] + sys.argv[i + 1:], exit=False).result\n"
    "print(json.dumps({'tests_run': r.testsRun, 'failures': len(r.failures), 'errors': len(r.errors),"
    " 'skipped': len(r.skipped)}))\n"
    "if not r.testsRun:\n"
    "    print('MAESTRO: no tests ran', file=sys.stderr)\n"
    "sys.exit(0 if r.wasSuccessful() and r.testsRun else 1)\n")


def verify_config(test_dir=None, top_level_dir=None, pattern=None, pythonpath=None):
    """Explicit unittest layout options; None when none is given (the original fixed command).

    Only relative, plain directory names inside the snapshot and a *.py glob are accepted.
    There is no command, shell or interpreter option to configure.
    """
    if test_dir is None and top_level_dir is None and pattern is None and not pythonpath:
        return None
    test_dir = "tests" if test_dir is None else test_dir
    pattern = "test*.py" if pattern is None else pattern
    if not isinstance(pythonpath or [], (list, tuple)):
        raise PolicyError("pythonpath must be a list of directories")
    pythonpath = list(pythonpath or [])
    for name in [test_dir] + pythonpath + ([] if top_level_dir in (None, ".") else [top_level_dir]):
        if not isinstance(name, str) or len(name) > 200 or SAFE_DIR.fullmatch(name) is None:
            raise PolicyError("verification directories must be relative plain paths inside the "
                              "repository: %r" % (name,))
    if not isinstance(pattern, str) or len(pattern) > 100 or SAFE_PATTERN.fullmatch(pattern) is None:
        raise PolicyError("test pattern must be a simple *.py file glob: %r" % (pattern,))
    if len(pythonpath) > 4 or len(set(pythonpath)) != len(pythonpath):
        raise PolicyError("at most four distinct --pythonpath directories")
    if top_level_dir not in (None, ".") and not (test_dir + "/").startswith(top_level_dir + "/"):
        raise PolicyError("the test directory must be inside the top-level directory")
    return {"test_dir": test_dir, "top_level_dir": top_level_dir, "pattern": pattern, "pythonpath": pythonpath}


def verification_command(config=None):
    if config is None:
        return [python_runtime()[0], "-I", "-B", "-m", "unittest", "discover", "-s", "tests"]
    try:
        valid = (isinstance(config, dict) and set(config) == {"test_dir", "top_level_dir", "pattern", "pythonpath"} and
                 verify_config(**config) == config)
    except PolicyError as exc:
        raise PolicyError("unsupported verification configuration: " + str(exc)) from exc
    if not valid:
        raise PolicyError("unsupported verification configuration")
    args = ["-s", config["test_dir"], "-p", config["pattern"]]
    if config["top_level_dir"] is not None:
        args += ["-t", config["top_level_dir"]]
    return [python_runtime()[0], "-I", "-B", "-c", VERIFY_RUNNER, *config["pythonpath"], "--", *args]


def verification_dirs(snap, config):
    """Configured directories must exist in the exact snapshot being verified."""
    if config is None:
        return
    for name in [config["test_dir"]] + config["pythonpath"] + [config["top_level_dir"] or "."]:
        if snap["manifest"].get(name, {}).get("type") != "directory":
            raise PolicyError("verification directory missing from the snapshot: " + name)


def git(cwd, home, *args, index=None, cancelled=lambda: False, data=b""):
    # execute builds a private environment; no inherited Git config or credentials.
    env = {"GIT_OPTIONAL_LOCKS": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1"}
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return execute([GIT, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "-c", "core.attributesFile=/dev/null", "-c", "core.autocrlf=false",
                    "-c", "core.filemode=true", "-c", "protocol.allow=never",
                    "-c", "protocol.file.allow=always", "-c", "diff.external=",
                    "-C", str(cwd), *map(str, args)], str(home), str(home), data=data, timeout=60,
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


def tree_blobs(clone, home, tree):
    """Every blob of an immutable tree in one batch: path -> {body, mode, oid}, ids rechecked."""
    entries = {}
    for row in git(clone, home, "ls-tree", "-r", "-z", tree).split(b"\0"):
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        rel = safe_name(name.decode("utf-8"))
        if kind != "blob" or mode not in ("100644", "100755"):
            raise PolicyError("unsupported tree entry for review context: " + rel)
        entries[rel] = (mode, oid)
    if len(entries) > MAX_ENTRIES:
        raise PolicyError("tree entry limit exceeded")
    paths = sorted(entries)
    raw = git(clone, home, "cat-file", "--batch",
              data="".join(entries[rel][1] + "\n" for rel in paths).encode("ascii")) if paths else b""
    files, offset = {}, 0
    for rel in paths:
        end = raw.index(b"\n", offset)
        oid, kind, length = raw[offset:end].decode("ascii").split()
        body = raw[end + 1:end + 1 + int(length)]
        algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
        if (oid != entries[rel][1] or kind != "blob" or len(body) != int(length) or
                algorithm(b"blob %d\0" % len(body) + body).hexdigest() != oid):
            raise PolicyError("unexpected blob for review context: " + rel)
        files[rel] = {"body": body, "mode": entries[rel][0], "oid": oid}
        offset = end + 1 + int(length) + 1
    if offset != len(raw):
        raise PolicyError("unexpected trailing blob data")
    return files


def materialize(clone, home, snap, copy):
    """Only the snapshot's included set, from the evidence tree, with recorded modes."""
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
            blob = git(clone, home, "show", snap["tree"] + ":" + rel)
            path.write_bytes(blob)
            path.chmod(stat.S_IMODE(entry["mode"]))
    for path, mode in sorted(directories, key=lambda p: len(p[0].parts), reverse=True):
        path.chmod(stat.S_IMODE(mode))
    return copy


def confined_verify(home, copy, command, cancelled=lambda: False):
    """The derived argv under the unchanged Seatbelt policy; a nonzero exit raises PolicyError."""
    executable, prefix = python_runtime()
    runner = Seatbelt([str(home)], protected=[str(home / "clone")], allowed_executables=[executable])
    policy = ExecPolicy(executable, tuple(command[1:]), str(copy), str(copy), (str(copy),),
                        readable=(prefix,), timeout=60, max_output=1048576)
    return runner.run(policy, cancelled=cancelled)


def runner_summary(output):
    """The fixed runner's count line. Informational only: the exit status decides."""
    lines = output.decode("utf-8", "replace").strip().splitlines()
    try:
        value = json.loads(lines[-1]) if lines else None
    except ValueError:
        return None
    keys = {"tests_run", "failures", "errors", "skipped"}
    if not isinstance(value, dict) or set(value) != keys or any(type(value[k]) is not int for k in keys):
        return None
    return value


def check(repo, base, verify=None):
    """Read-only compatibility check: no task, state, agent or model.

    Clones the base into a private temporary directory, captures the snapshot a task
    would bind and runs the configured verification on it under Seatbelt. Before an
    implementation a failing baseline can be expected; a snapshot or setup error cannot.
    """
    command = verification_command(verify)
    if sys.platform != "darwin" or sys.version_info[:2] != (3, 9):
        raise PolicyError("trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
    repo = Path(repo).resolve()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", base):
        raise PolicyError("base must be a full lowercase commit SHA")
    with tempfile.TemporaryDirectory(prefix="maestro-check-") as temp:
        home = Path(os.path.realpath(temp))
        before = source_guard(repo, home)
        clone = home / "clone"
        git(home, home, "clone", "--no-hardlinks", "--no-checkout", "--template=", str(repo), str(clone))
        git(clone, home, "checkout", "--detach", base)
        git(clone, home, "remote", "remove", "origin")
        clone_config(clone)
        snap = snapshot(clone, home, base)
        verification_dirs(snap, verify)
        report = {"compatible": False, "repo": str(repo), "base": base, "snapshot_sha256": snap["sha256"],
                  "files": sum(e["type"] == "file" for e in snap["manifest"].values()),
                  "ignored_paths": len(snap["ignored"]), "verify": verify, "command": command}
        output = None
        try:
            output = confined_verify(home, materialize(clone, home, snap, home / "verify"), command)
            report["baseline"] = {"passed": True, "exit_code": 0}
        except PolicyError as exc:
            match = re.search(r"child exited with code (-?\d+):", str(exc))
            if match is None:
                raise  # a sandbox or setup failure, not a test result
            report["baseline"] = {"passed": False, "exit_code": int(match.group(1)), "excerpt": str(exc)[:2000]}
        if output is not None and verify is not None:
            report["baseline"]["summary"] = runner_summary(output)
        if source_guard(repo, home) != before:
            raise IntegrityError("source repository guard changed during check")
    report["compatible"] = True
    return report


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
            raise IntegrityError("source repository guard changed before " + phase)
        try:
            yield
        finally:
            after = source_guard(repo, home)
            self.store.artifact(task_id, phase + "_source_after", after)
            if after != expected:
                raise IntegrityError("source repository guard changed after " + phase)

    def start(self, repo, base, task_file, model, cancelled=lambda: False, review_model=None, verify=None,
              review_context="full", review_budget=None):
        validate_model(model)
        if review_model is not None:
            validate_model(review_model)
        if review_context not in ("full", "scoped") or (review_context == "scoped" and review_model is None):
            raise PolicyError("review context must be 'full' or 'scoped'; scoped needs --review-model")
        if review_budget is not None and (review_context != "scoped" or type(review_budget) is not int or
                                          not 1000 <= review_budget <= reviewer.MAX_INPUT // 4):
            raise PolicyError("--review-budget applies only to a scoped review: 1000 to %d estimated tokens"
                              % (reviewer.MAX_INPUT // 4))
        command = verification_command(verify)
        if sys.platform != "darwin" or sys.version_info[:2] != (3, 9):
            raise PolicyError("trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")
        repo, task_file = Path(repo).resolve(), Path(task_file).resolve()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", base):
            raise PolicyError("base must be a full lowercase commit SHA")
        prompt = read_regular(task_file, 262144)[0].decode("utf-8")
        spec = {"mode": MODE, "model": model, "execution_context": "test" if self.test_context else "normal",
                "repo": str(repo), "base": base, "task_file": str(task_file),
                "prompt": prompt, "verify_command": command}
        if review_model is not None:
            # Only review-required tasks carry the key, so Codex-only task identities are unchanged.
            spec["review"] = {"provider": reviewer.PROVIDER, "model": review_model}
            if review_context == "scoped":  # full-context tasks keep their original spec and identity
                spec["review"].update(context="scoped", budget_estimated_tokens=review_budget or reviewer.DEFAULT_BUDGET)
        if verify is not None:
            spec["verify"] = verify
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
                    # Reject unsupported base content or a verification layout that cannot
                    # exist before publishing the clone, and before any agent runs.
                    verification_dirs(snapshot(partial, home, base), verify)
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
            raise IntegrityError("clone snapshot changed")
        return snap

    def build_verify(self, task_id, snap):
        home = self.store.task_dir(task_id)
        copy = home / "verify"
        if os.path.lexists(copy):
            raise PolicyError("verification copy already exists; no retry")
        return materialize(home / "clone", home, snap, copy)

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
                    config = task["spec"].get("verify")
                    command = verification_command(config)
                    if task["spec"].get("verify_command") != command:
                        raise PolicyError("unsupported verification")
                    snap = self.unchanged(task_id)
                    verification_dirs(snap, config)
                    copy = self.build_verify(task_id, snap)
                    manifest, _ = scan(copy)
                    if digest({"base": snap["base"], "tree": snap["tree"], "manifest": manifest}) != snap["sha256"]:
                        raise PolicyError("verification copy hash differs from snapshot")
                    record["command"] = command
                    try:
                        output = confined_verify(home, copy, command, lambda: self.store.cancelled(task_id))
                        atomic_write(home / "verification.stdout.log", output)
                        record.update(exit_code=0, passed=True,
                                      stdout={"path": "verification.stdout.log", "bytes": len(output),
                                              "sha256": hashlib.sha256(output).hexdigest()})
                        if config is not None:
                            record["summary"] = runner_summary(output)
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
        command = verification_command(task["spec"].get("verify"))
        if (verification.get("passed") is not True or verification.get("exit_code") != 0 or
                verification.get("snapshot_sha256") != snap["sha256"] or
                verification.get("command") != command or
                task["spec"].get("verify_command") != command or
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

    def review_gate(self, task_id, context, override=None, snap=None):
        """Approval/export precondition for review-required tasks; returns approval fields.

        Without snap it checks only recorded evidence, so a missing, unfinished or
        blocking review refuses approval without invalidating the task. With snap it
        also binds the review to the current snapshot and its exact tree patch.
        """
        task = self.require(task_id)
        requested = task["spec"].get("review")
        if requested is None:
            if override is not None:
                raise PolicyError("this task has no review to override")
            return {}
        attempts = task["evidence"].get("review_attempts")
        if not attempts:
            raise PolicyError("review required before approval: run trusted review")
        record = self.store.artifact(task_id, "review.%d" % attempts)
        if digest(record) != task["evidence"].get("review_sha256"):
            raise PolicyError("review evidence mismatch")
        if record.get("outcome") != "completed":
            raise PolicyError("review required before approval: latest attempt %s" % record.get("outcome"))
        if (record.get("provider") != reviewer.PROVIDER or record.get("model_requested") != requested.get("model") or
                record.get("model_verified") is not True):
            raise PolicyError("review provider or model not verified")
        if "offline-fixture" in str(record.get("cli", {}).get("version")) and not (self.test_context and context == "test"):
            raise PolicyError("offline-fixture review requires a test task and explicit test context")
        scoped = requested.get("context") == "scoped"
        scope = record.get("context") if scoped else None
        if scoped and (not isinstance(scope, dict) or scope.get("mode") != "scoped" or
                       scope.get("policy") != reviewer.SCOPED_POLICY or scope.get("status") != "selected" or
                       scope.get("budget_estimated_tokens") != requested.get("budget_estimated_tokens")):
            raise PolicyError("scoped review context evidence mismatch")
        review = reviewer.validate_review(record.get("review"), record.get("snapshot_sha256"), record.get("patch_sha256"),
                                          None, scope.get("context_sha256") if scoped else None)
        if record.get("blocking") is not reviewer.blocking(review):
            raise PolicyError("review evidence mismatch")
        gate = {"review_sha256": task["evidence"]["review_sha256"]}
        if scoped:
            gate["review_context"] = "scoped"  # recorded in the approval: never a full-repository review
        if record["blocking"]:
            if override is None:
                raise PolicyError("review reported blocking findings: reject, or approve with an explicit "
                                  "--override-review reason")
            gate["review_override"] = override
        elif override is not None:
            raise PolicyError("review reported no blocking findings; nothing to override")
        if snap is not None:
            home = self.store.task_dir(task_id)
            patch_sha256 = hashlib.sha256(tree_patch(home / "clone", home, snap)).hexdigest()
            if (record.get("snapshot_sha256") != snap["sha256"] or record.get("tree") != snap["tree"] or
                    record.get("patch_sha256") != patch_sha256):
                raise PolicyError("review is stale: not bound to the current snapshot and patch")
        return gate

    def approve(self, task_id, snapshot_hash, founder, override_review=None):
        self.require(task_id)
        if not isinstance(founder, str) or not founder.strip() or len(founder) > 200:
            raise PolicyError("explicit founder identity required")
        if override_review is not None and (not isinstance(override_review, str) or
                                            not override_review.strip() or len(override_review) > 2000):
            raise PolicyError("an explicit review override reason is required")
        with self.store.lock(task_id):
            task = self.require(task_id)
            if task["status"] != "awaiting_approval":
                raise PolicyError("task is not awaiting approval")
            if snapshot_hash != task["evidence"].get("snapshot_sha256"):
                raise PolicyError("approval must name the exact snapshot hash")
            context = self.approval_context(task_id)
            self.review_gate(task_id, context, override_review)
            try:
                with self.guard(task_id, "approve"):
                    snap = self.checked(task_id)
                    gate = self.review_gate(task_id, context, override_review, snap)
                approval = dict(gate, snapshot_sha256=snapshot_hash, founder=founder, execution_context=context)
                evidence = dict(task["evidence"], approval_sha256=self.store.artifact(task_id, "approval", approval))
                message = "Human approved exact snapshot: " + founder
                if "review_override" in gate:
                    message += "; blocking review findings overridden"
                self.store.transition(task_id, "approved", message, evidence)
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
                    gate = self.review_gate(task_id, context, approval.get("review_override"), snap)
                    if gate.get("review_sha256") != approval.get("review_sha256"):
                        raise PolicyError("approval evidence mismatch")
                    patch = tree_patch(home / "clone", home, snap)
                    self.unchanged(task_id)
                atomic_write(home / "export.patch", patch)
                record = {"snapshot_sha256": snap["sha256"], "tree": snap["tree"], "execution_context": context,
                          "path": str(home / "export.patch"), "sha256": hashlib.sha256(patch).hexdigest()}
                if "review_sha256" in gate:
                    record["review_sha256"] = gate["review_sha256"]
                if "review_context" in gate:
                    record["review_context"] = gate["review_context"]
                self.store.artifact(task_id, "export", record)
            except (Exception, KeyboardInterrupt) as exc:
                self.store.transition(task_id, "invalidated", "Export refused: " + str(exc))
                raise
        return record

    def review(self, task_id, claude_bin=None, timeout=600):
        """One fresh Claude Code review of the verified snapshot, recorded as an opinion.

        The reviewer never changes the snapshot, task state, approval or export. A
        completed review is final; an attempt that did not complete may be retried
        once. A snapshot or source change around the review invalidates the task.
        """
        self.require(task_id)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 1800:
            raise PolicyError("review timeout must be positive and at most 1800 seconds")
        with self.store.lock(task_id):
            task = self.require(task_id)
            requested = task["spec"].get("review")
            if requested is None:
                raise PolicyError("this task did not request a review (start it with --review-model)")
            if task["status"] != "awaiting_approval":
                raise PolicyError("review requires a verified task awaiting approval")
            attempts = task["evidence"].get("review_attempts", 0)
            if attempts and self.store.artifact(task_id, "review.%d" % attempts).get("outcome") == "completed":
                raise PolicyError("a completed review is final")
            if attempts >= reviewer.ATTEMPTS:
                raise PolicyError("review attempt limit reached")
            attempt = attempts + 1
            record = {"attempt": attempt, "provider": reviewer.PROVIDER, "model_requested": requested["model"],
                      "model_verified": False, "outcome": "failed", "classification": reviewer.CLASSIFICATION}
            invalid = False
            try:
                with self.guard(task_id, "review_%d" % attempt):
                    snap = self.checked(task_id)
                    try:
                        found = self.run_review(task_id, task, snap, attempt, record, claude_bin, timeout)
                    finally:
                        # Same user, not confined: detect, never assume, an unchanged snapshot.
                        self.unchanged(task_id)
                record.update(found, outcome="completed")
            except (Exception, KeyboardInterrupt) as exc:
                invalid = isinstance(exc, IntegrityError)
                if record["outcome"] != "unavailable":
                    record["outcome"] = "failed"
                record["error"] = (str(exc) or type(exc).__name__)[:2000]
            sha = self.store.artifact(task_id, "review.%d" % attempt, record)
            message = "Claude Code review attempt %d %s" % (attempt, record["outcome"])
            if record["outcome"] == "completed":
                message += "; " + ("blocking findings" if record["blocking"] else "no blocking findings")
            self.annotate(task_id, dict(task["evidence"], review_attempts=attempt, review_sha256=sha), message)
            if invalid and self.store.get(task_id)["status"] == "awaiting_approval":
                self.store.transition(task_id, "invalidated", "Review refused: " + record["error"])
        return self.status(task_id)

    def run_review(self, task_id, task, snap, attempt, record, claude_bin, timeout):
        home = self.store.task_dir(task_id)
        clone, folder = home / "clone", home / ("review-%d" % attempt)
        if os.path.lexists(folder):
            raise PolicyError("review folder already exists; no reuse")
        folder.mkdir(mode=0o700)
        # Disposable read-only input from the snapshot's Git objects, never the live clone.
        patch, files = tree_patch(clone, home, snap), changes(clone, home, snap)
        verification = self.store.artifact(task_id, "verification")
        scoped = task["spec"]["review"].get("context") == "scoped"
        if scoped:
            # Presentation policy only: the full snapshot and exact patch stay the bound evidence.
            data, patch_sha256, scope, audit = reviewer.build_scoped_input(
                task_id, task["spec"]["prompt"], snap, patch, files, tree_blobs(clone, home, snap["base"] + "^{tree}"),
                tree_blobs(clone, home, snap["tree"]), verification, task["spec"]["review"]["budget_estimated_tokens"])
            audit_path = folder / "context-audit.json"
            atomic_write(audit_path, audit)
            audit_path.chmod(0o400)
            record.update(context=dict(scope, audit_path=audit_path.relative_to(home).as_posix()),
                          classification=reviewer.SCOPED_CLASSIFICATION)
            allowed = set(scope["included"]) | {f["path"] for f in files}
        else:
            bodies = {rel: git(clone, home, "show", snap["tree"] + ":" + rel)
                      for rel, entry in snap["manifest"].items() if entry["type"] == "file"}
            data, patch_sha256 = reviewer.build_input(task_id, task["spec"]["prompt"], snap, patch, files, bodies,
                                                      verification)
            allowed = set(bodies) | {f["path"] for f in files}
        schema = reviewer.review_schema(allowed, scoped)
        staged = folder / "input.txt"
        atomic_write(staged, data)
        staged.chmod(0o400)
        record.update(snapshot_sha256=snap["sha256"], tree=snap["tree"], patch_sha256=patch_sha256,
                      input={"path": staged.relative_to(home).as_posix(), "bytes": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})
        if scoped and scope["status"] != "selected":
            # Never send an incomplete context: no launch, a precise reason, the prompt kept as evidence.
            record["outcome"] = "unavailable"
            reason = ("mandatory changed content alone exceeds the budget (%d > %d bytes)"
                      % (scope["mandatory_bytes"], min(scope["budget_estimated_tokens"] * 4, reviewer.MAX_INPUT))
                      if scope["status"] == "budget-exceeded" else
                      "critical related files would be omitted: " + ", ".join(scope["critical_omitted"][:5]))
            raise PolicyError("scoped review not launched (%s): %s; raise --review-budget or use the full context"
                              % (scope["status"], reason))
        try:
            info = reviewer.claude_info(claude_bin)
        except (PolicyError, OSError, subprocess.SubprocessError) as exc:
            record["outcome"] = "unavailable"
            raise PolicyError("reviewer unavailable: " + str(exc)) from exc
        model = task["spec"]["review"]["model"]
        record.update(cli=info, environment=reviewer.environment_record(),
                      argv=reviewer.argv(info["path"], model, scoped, schema))
        workdir = folder / "cwd"
        workdir.mkdir(mode=0o700)
        code = reviewer.run(info["path"], model, workdir, staged, folder, timeout,
                            lambda: self.store.cancelled(task_id), record, scoped, schema)
        if read_regular(staged, reviewer.MAX_INPUT)[0] != data:
            raise PolicyError("staged review input changed")
        found = reviewer.parse_output(read_regular(folder / "stdout.json", reviewer.MAX_LOG)[0], record)
        if code:
            raise PolicyError("Claude Code exited with code %d" % code)
        record["model_verified"] = reviewer.model_verified(model, record["models_reported"])
        if not record["model_verified"]:
            raise PolicyError("review model not verified: requested %s, CLI reported %s"
                              % (model, record["models_reported"]))
        review = reviewer.validate_review(found, snap["sha256"], patch_sha256, allowed,
                                          scope["context_sha256"] if scoped else None)
        return {"review": review, "blocking": reviewer.blocking(review)}

    def annotate(self, task_id, evidence, message):
        """Record review evidence while the task stays awaiting approval; no state change."""
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row["status"] != "awaiting_approval":
                return False
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(evidence).decode(), task_id))
            self.store.log(conn, task_id, row["status"], message)
        return True

    def review_summary(self, task):
        attempts = task["evidence"].get("review_attempts", 0)
        summary = {"required": True, "model": task["spec"]["review"]["model"], "attempts": attempts,
                   "attempts_allowed": reviewer.ATTEMPTS, "context_mode": task["spec"]["review"].get("context", "full")}
        if attempts:
            record = self.store.artifact(task["id"], "review.%d" % attempts)
            summary.update({key: record[key] for key in (
                "outcome", "error", "models_reported", "model_verified", "snapshot_sha256", "patch_sha256",
                "blocking", "classification") if key in record})
            summary["cli_version"] = record.get("cli", {}).get("version")
            if record.get("review"):
                summary.update({key: record["review"][key] for key in ("verdict", "summary", "findings")})
            scope = record.get("context")
            if scope:
                summary["context"] = {key: scope[key] for key in (
                    "status", "included", "included_count", "omitted_count", "snapshot_file_count", "critical_omitted",
                    "context_sha256", "audit_sha256", "payload_bytes", "estimated_tokens", "limitations") if key in scope}
                summary["scope_notice"] = ("scoped review: %d files supplied in full, from a %d-file snapshot; "
                                           "not a full-repository review" % (scope["included_count"],
                                                                             scope["snapshot_file_count"]))
        return summary

    def next_steps(self, task):
        """Suggested commands for the current state: advice only, never executed."""
        tid, status = task["id"], task["status"]
        approve = "trusted approve %s --snapshot %s --founder NAME" % (tid, task["evidence"].get("snapshot_sha256"))
        reject = "trusted reject %s --founder NAME --reason TEXT" % tid
        if status == "preparing":
            return ["trusted implement %s" % tid] if self.store.has_artifact(tid, "clone_ready") else []
        if status == "reviewing":
            return ["trusted diff %s" % tid, "trusted verify %s" % tid]
        if status == "awaiting_approval":
            steps = ["trusted diff %s" % tid]
            review = self.review_summary(task) if task["spec"].get("review") is not None else None
            if review is not None and review.get("outcome") != "completed":
                return steps + (["trusted review %s" % tid] if review["attempts"] < reviewer.ATTEMPTS else []) + [reject]
            if review is not None and review.get("blocking"):
                return steps + [reject, approve + " --override-review REASON"]
            return steps + [approve, reject]
        if status == "approved" and not self.store.has_artifact(tid, "export"):
            return ["trusted export %s" % tid]
        return []  # done, or terminal: a task is never retried; start a new one

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
        if task["spec"].get("review") is not None:
            task["review"] = self.review_summary(task)
        task["next"] = self.next_steps(task)
        return task
