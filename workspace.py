"""Owned synthetic repositories only. Worktrees provide isolation, NOT a sandbox."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from execution import PolicyError, execute

MAX_BYTES = 65536
MAX_FILES = 32


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def relative_path(name):
    if not isinstance(name, str) or not name or len(name) > 200:
        raise PolicyError("invalid relative path")
    parts = name.split("/")
    if (PurePosixPath(name).is_absolute() or "\\" in name or
            any(p in ("", ".", "..") or p.startswith(".") for p in parts) or
            any(ord(c) < 32 for c in name)):
        raise PolicyError("path outside allowed regular-file namespace")
    return name


def directory(path):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise PolicyError("managed directory replaced or symlinked")
    return path


def read_regular(path, limit=MAX_BYTES):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PolicyError("symlink, hardlink or special file rejected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise PolicyError("file replaced while opening")
        body = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if len(body) > limit or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise PolicyError("file exceeds limit or changed while reading")
    return body, stat.S_IMODE(before.st_mode)


class Workspace:
    def __init__(self, task_dir):
        self.task_dir = directory(task_dir)
        self.repo = self.task_dir / "repo.git"
        self.path = self.task_dir / "worktree"
        self.home = directory(self.task_dir / "home")

    def git(self, *args, cancelled=lambda: False):
        # Empty template/global config avoid user hooks, aliases and credentials.
        return execute(["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                        "-c", "protocol.allow=never", "-c", "core.fsmonitor=false",
                        *args], self.task_dir, self.home, timeout=10,
                       cancelled=cancelled)

    def create(self, cancelled=lambda: False):
        if self.repo.exists() or self.path.exists():
            raise PolicyError("workspace already exists; no implicit recovery/retry")
        self.git("init", "--bare", "--template=", "--initial-branch=main", str(self.repo),
                 cancelled=cancelled)
        # Native unborn worktree: no index staging or commit (including commit-tree).
        self.git("--git-dir=" + str(self.repo), "worktree", "add", "--orphan",
                 "-b", "implementation", str(self.path), cancelled=cancelled)

    def snapshot(self):
        if self.path.is_symlink() or not self.path.is_dir():
            raise PolicyError("worktree missing or replaced")
        files, total, entries = {}, 0, 0
        for parent, dirs, names in os.walk(self.path, followlinks=False):
            dirs.sort()
            names.sort()
            for name in dirs + names:
                entries += 1
                if entries > 64:
                    raise PolicyError("snapshot entry limit exceeded")
                p = Path(parent) / name
                rel = p.relative_to(self.path).as_posix()
                if rel == ".git":
                    if not stat.S_ISREG(p.lstat().st_mode):
                        raise PolicyError("invalid worktree metadata pointer")
                    continue
                if p.is_symlink():
                    raise PolicyError("symlink rejected")
                if p.is_dir():
                    continue
                body, mode = read_regular(p)
                total += len(body)
                if len(files) >= MAX_FILES or total > MAX_BYTES:
                    raise PolicyError("snapshot budget exceeded")
                files[rel] = {"sha256": hashlib.sha256(body).hexdigest(),
                              "mode": mode, "text": body.decode("utf-8")}
        return {"files": files, "sha256": digest(files)}

    def apply(self, edits, allowed):
        if not isinstance(edits, list) or len(edits) != 1:
            raise PolicyError("P0 requires exactly one allowed edit")
        edit = edits[0]
        if not isinstance(edit, dict) or set(edit) != {"path", "text"}:
            raise PolicyError("invalid edit schema")
        name = relative_path(edit["path"])
        if name != allowed or not isinstance(edit["text"], str):
            raise PolicyError("agent requested an unauthorized write")
        body = edit["text"].encode("utf-8")
        if len(body) > MAX_BYTES:
            raise PolicyError("edit budget exceeded")
        directory(self.path)
        parent = self.path
        for part in Path(name).parts[:-1]:
            parent = directory(parent / part)
        target = self.path / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())

    def dispose(self):
        if self.path.is_symlink() or self.repo.is_symlink():
            raise PolicyError("unsafe workspace path")
        if not self.path.exists():
            return
        # Deliberately no --force: preserve all uncommitted output.
        self.git("--git-dir=" + str(self.repo), "worktree", "remove", str(self.path))
