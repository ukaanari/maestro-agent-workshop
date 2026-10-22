"""SQLite state machine, immutable evidence and a single-attempt coordinator."""
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from agents import FakeAdapter, SCENARIOS, envelope
from execution import Cancelled, DeadlineExceeded, PolicyError
from sandbox import SANDBOX_EXEC, Seatbelt, python_runtime
from workspace import Workspace, canonical, digest, directory, read_regular, relative_path

ACTIVE = {"preparing", "implementing", "reviewing", "verifying"}
NEXT = {"created": "preparing", "preparing": "implementing",
        "implementing": "reviewing", "reviewing": "verifying",
        "verifying": "awaiting_approval", "awaiting_approval": "approved"}
FAILURES = {"failed", "blocked", "timed_out", "cancelled", "interrupted", "review_failed"}


class Store:
    def __init__(self, root):
        raw = Path(root).absolute()
        if raw.is_symlink():
            raise PolicyError("state root cannot be a symlink")
        self.root = raw.resolve()
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
        directory(self.root)
        marker = self.root / "MAESTRO-P0"
        if not marker.exists():
            if any(self.root.iterdir()):
                raise PolicyError("state root must be new/empty or already owned by MAESTRO")
            marker.write_text("synthetic-only-v1\n")
        if read_regular(marker)[0] != b"synthetic-only-v1\n":
            raise PolicyError("unrecognized state root")
        directory(self.root / "tasks")
        self.db = self.root / "state.sqlite3"
        if self.db.exists() or self.db.is_symlink():
            info = self.db.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PolicyError("unsafe SQLite state file")
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL, spec TEXT NOT NULL,
                    cancel INTEGER NOT NULL DEFAULT 0, evidence TEXT NOT NULL DEFAULT '{}',
                    disposed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS artifacts (
                    task_id TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL,
                    hash TEXT NOT NULL, PRIMARY KEY(task_id, kind));
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY, task_id TEXT NOT NULL,
                    at REAL NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def task_dir(self, task_id):
        if not re.fullmatch(r"[a-f0-9]{16}", task_id):
            raise PolicyError("invalid task identity")
        return self.root / "tasks" / task_id

    def get(self, task_id):
        self.task_dir(task_id)
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise PolicyError("unknown task")
        result = dict(row)
        for key in ("spec", "evidence"):
            result[key] = json.loads(result[key])
        return result

    def log(self, conn, task_id, status, message):
        conn.execute("INSERT INTO events(task_id,at,status,message) VALUES(?,?,?,?)",
                     (task_id, time.time(), status, message[:2000]))

    def create(self, title, target="result.txt", expected="MAESTRO P0\n",
               scenario="success", timeout=5):
        relative_path(target)
        if (not isinstance(title, str) or not title.strip() or len(title) > 2000 or
                not isinstance(expected, str) or len(expected.encode()) > 8192 or
                scenario not in SCENARIOS or not math.isfinite(timeout) or not 0 < timeout <= 30):
            raise PolicyError("invalid task or execution budget")
        task_id = uuid.uuid4().hex[:16]
        spec = {"title": title, "target": target, "expected": expected,
                "scenario": scenario, "timeout": timeout, "mode": "fake-only"}
        directory(self.task_dir(task_id))
        with self.connect() as conn:
            conn.execute("INSERT INTO tasks(id,status,spec) VALUES(?,?,?)",
                         (task_id, "created", canonical(spec).decode()))
            self.log(conn, task_id, "created", "Single attempt, fake-only synthetic task created")
        return task_id

    @contextmanager
    def lock(self, task_id):
        self.get(task_id)
        path = directory(self.task_dir(task_id)) / "executor.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PolicyError("task already has an active owner") from exc
            yield
        finally:
            os.close(fd)

    def transition(self, task_id, status, message, evidence=None):
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            old = row["status"]
            allowed = (NEXT.get(old) == status or
                       (old in ACTIVE | {"created", "awaiting_approval"} and status in FAILURES) or
                       (old in {"awaiting_approval", "approved"} and status == "invalidated"))
            if not allowed:
                raise PolicyError("illegal state transition: %s -> %s" % (old, status))
            if row["cancel"] and status != "cancelled":
                raise Cancelled("cancellation wins over state transition")
            encoded = canonical(evidence).decode() if evidence is not None else row["evidence"]
            conn.execute("UPDATE tasks SET status=?,evidence=? WHERE id=?", (status, encoded, task_id))
            self.log(conn, task_id, status, message)

    def cancel(self, task_id):
        self.get(task_id)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
            old = row["status"]
            if old == "cancelled":
                return
            if old not in ACTIVE | {"created", "awaiting_approval"}:
                raise PolicyError("cannot cancel a terminal task")
            new = "cancelled" if old in {"created", "awaiting_approval"} else old
            conn.execute("UPDATE tasks SET cancel=1,status=? WHERE id=?", (new, task_id))
            self.log(conn, task_id, new, "Cancellation requested by operator")

    def cancelled(self, task_id):
        return bool(self.get(task_id)["cancel"])

    def artifact(self, task_id, kind, body=None):
        with self.connect() as conn:
            if body is not None:
                encoded = canonical(body)
                if len(encoded) > 262144:
                    raise PolicyError("artifact limit exceeded")
                conn.execute("INSERT INTO artifacts VALUES(?,?,?,?)",
                             (task_id, kind, encoded.decode(), digest(body)))
                return digest(body)
            row = conn.execute("SELECT body,hash FROM artifacts WHERE task_id=? AND kind=?",
                               (task_id, kind)).fetchone()
        if row is None:
            raise PolicyError("missing evidence: " + kind)
        value = json.loads(row["body"])
        if digest(value) != row["hash"]:
            raise PolicyError("corrupt evidence: " + kind)
        return value

    def events(self, task_id):
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT seq,at,status,message FROM events WHERE task_id=? ORDER BY seq", (task_id,))]


class Engine:
    def __init__(self, store, sandbox_binary=SANDBOX_EXEC):
        self.store = store
        self.sandbox_binary = sandbox_binary

    def workspace(self, task_id):
        return Workspace(self.store.task_dir(task_id))

    def sandbox(self, task_id):
        """Only this task's directory is grantable; state and Git metadata never are."""
        root, task_dir = self.store.root, self.store.task_dir(task_id)
        protected = [root / name for name in ("MAESTRO-P0", "state.sqlite3", "state.sqlite3-journal",
                                              "state.sqlite3-wal", "state.sqlite3-shm")]
        protected += [task_dir / "repo.git", task_dir / "executor.lock", task_dir / "worktree" / ".git"]
        return Seatbelt([str(task_dir)], protected=protected,
                        allowed_executables=[python_runtime()[0]], binary=self.sandbox_binary)

    def run(self, task_id):
        s = self.store
        with s.lock(task_id):
            task = s.get(task_id)
            if task["status"] in ACTIVE:
                self._finish(task_id, "interrupted", "Previous owner disappeared; no replay permitted")
                return s.get(task_id)
            if task["status"] != "created":
                raise PolicyError("task is single-attempt; create a new task to try again")
            try:
                s.transition(task_id, "preparing", "Creating isolated unborn Git worktree")
                ws = self.workspace(task_id)
                ws.create(cancelled=lambda: s.cancelled(task_id))
                spec = task["spec"]
                baseline = ws.snapshot()
                s.transition(task_id, "implementing", "Starting deterministic Codex stand-in")
                sandbox = self.sandbox(task_id)
                result = FakeAdapter("implement").run(envelope(task_id, "implement", spec),
                    home=ws.home, timeout=spec["timeout"], cancelled=lambda: s.cancelled(task_id),
                    sandbox=sandbox)
                if not isinstance(result, dict) or set(result) != {"edits", "summary"} or not isinstance(result["summary"], str):
                    raise PolicyError("invalid implementation result")
                if s.cancelled(task_id):
                    raise Cancelled("cancelled before applying output")
                ws.apply(result["edits"], spec["target"])
                snapshot = ws.snapshot()
                handoff = {"protocol": 1, "task_id": task_id, "attempt": 1,
                           "source": "fake-codex", "destination": "fake-claude-code",
                           "base": "unborn", "base_snapshot_sha256": baseline["sha256"],
                           "task": spec["title"], "criteria": {"path": spec["target"], "equals": spec["expected"]},
                           "implementation_summary": result["summary"], "snapshot": snapshot}
                handoff_hash = s.artifact(task_id, "handoff", handoff)
                evidence = {"snapshot_sha256": snapshot["sha256"], "handoff_sha256": handoff_hash}
                s.transition(task_id, "reviewing", "Implementation stopped; delivering verified snapshot to fresh reviewer", evidence)
                handoff = s.artifact(task_id, "handoff")
                if digest(handoff) != handoff_hash or ws.snapshot() != snapshot:
                    raise PolicyError("handoff or workspace changed before review")
                review = FakeAdapter("review").run(envelope(task_id, "review", {
                    "scenario": spec["scenario"], "handoff": handoff, "handoff_sha256": handoff_hash}),
                    home=ws.home, timeout=spec["timeout"], cancelled=lambda: s.cancelled(task_id),
                    sandbox=sandbox)
                if (not isinstance(review, dict) or set(review) != {"snapshot_sha256", "handoff_sha256", "verdict", "summary"} or
                        review["snapshot_sha256"] != snapshot["sha256"] or review["handoff_sha256"] != handoff_hash or
                        review["verdict"] not in {"approved", "changes_requested", "blocked"} or not isinstance(review["summary"], str)):
                    raise PolicyError("review is invalid or bound to stale evidence")
                evidence["review_sha256"] = s.artifact(task_id, "review", review)
                if ws.snapshot() != snapshot:
                    raise PolicyError("workspace changed during review")
                if review["verdict"] != "approved":
                    s.transition(task_id, "review_failed", review["summary"], evidence)
                    return s.get(task_id)
                s.transition(task_id, "verifying", "Running fixed, data-only acceptance check", evidence)
                current = ws.snapshot()
                passed = (current == snapshot and set(current["files"]) == {spec["target"]} and
                          current["files"][spec["target"]]["text"] == spec["expected"])
                verification = {"task_id": task_id, "snapshot_sha256": snapshot["sha256"],
                                "passed": passed, "check": "exact-file-content-v1", "fake_only": True}
                evidence["verification_sha256"] = s.artifact(task_id, "verification", verification)
                if not passed:
                    s.transition(task_id, "failed", "Acceptance check failed", evidence)
                else:
                    s.transition(task_id, "awaiting_approval", "Review and verification passed; explicit founder approval required", evidence)
            except Cancelled as exc:
                self._finish(task_id, "cancelled", str(exc))
            except DeadlineExceeded as exc:
                self._finish(task_id, "timed_out", str(exc))
            except (PolicyError, UnicodeError, OSError, ValueError) as exc:
                self._finish(task_id, "blocked", str(exc))
            except KeyboardInterrupt:
                self._finish(task_id, "interrupted", "Operator interrupted execution")
            except Exception as exc:
                self._finish(task_id, "failed", "Unexpected coordinator error: " + str(exc))
            return s.get(task_id)

    def _finish(self, task_id, state, reason):
        if self.store.cancelled(task_id):
            state = "cancelled"
        self.store.transition(task_id, state, reason)

    def check_evidence(self, task_id):
        task = self.store.get(task_id)
        evidence = task["evidence"]
        for kind in ("handoff", "review", "verification"):
            body = self.store.artifact(task_id, kind)
            if digest(body) != evidence.get(kind + "_sha256"):
                raise PolicyError("evidence hash mismatch: " + kind)
        handoff = self.store.artifact(task_id, "handoff")
        review = self.store.artifact(task_id, "review")
        verification = self.store.artifact(task_id, "verification")
        sha = evidence.get("snapshot_sha256")
        if (handoff["task_id"] != task_id or handoff["snapshot"]["sha256"] != sha or
                review["snapshot_sha256"] != sha or review["handoff_sha256"] != evidence["handoff_sha256"] or
                verification["task_id"] != task_id or verification["snapshot_sha256"] != sha or
                review["verdict"] != "approved" or verification["passed"] is not True or
                self.workspace(task_id).snapshot() != handoff["snapshot"]):
            raise PolicyError("stale or unsuccessful evidence")
        return sha

    def approve(self, task_id, snapshot, founder):
        if not founder.strip() or len(founder) > 200:
            raise PolicyError("explicit founder identity required")
        s = self.store
        with s.lock(task_id):
            if s.get(task_id)["status"] != "awaiting_approval":
                raise PolicyError("task is not awaiting approval")
            try:
                current = self.check_evidence(task_id)
            except (PolicyError, OSError, ValueError, KeyError) as exc:
                s.transition(task_id, "invalidated", "Approval blocked: " + str(exc))
                raise PolicyError("evidence invalidated; create a fresh task") from exc
            if snapshot != current:
                raise PolicyError("approval must name the exact current snapshot")
            s.transition(task_id, "approved", "Founder approved locally: " + founder)
        return s.get(task_id)

    def recover(self, task_id):
        with self.store.lock(task_id):
            if self.store.get(task_id)["status"] not in ACTIVE:
                raise PolicyError("only an abandoned active task can be recovered")
            self._finish(task_id, "interrupted", "Owner absent; marked interrupted without restarting agents")
        return self.store.get(task_id)

    def dispose(self, task_id):
        with self.store.lock(task_id):
            task = self.store.get(task_id)
            if task["status"] in ACTIVE | {"created", "awaiting_approval"}:
                raise PolicyError("workspace still needed by task")
            self.workspace(task_id).dispose()
            with self.store.connect() as conn:
                conn.execute("UPDATE tasks SET disposed=1 WHERE id=?", (task_id,))
                self.store.log(conn, task_id, task["status"], "Clean worktree disposed; evidence retained")
