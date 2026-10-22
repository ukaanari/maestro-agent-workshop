"""Versioned provider contract and first-party deterministic fake worker.

Worker IPC is data-only. The supervisor applies validated edits; the reviewer
receives a fresh snapshot envelope, never an implementation session.
"""
import hashlib
import json
import math
from pathlib import Path
import signal
import sys
import time

# -I excludes ambient imports; add only this trusted, first-party code directory.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from execution import PolicyError
from sandbox import SOURCE_DIR, ExecPolicy, python_runtime
from workspace import canonical, digest

# The worker may read exactly these first-party files, plus list their directory
# so the import system can find them. Never the directory subtree (.maestro/).
WORKER_SOURCES = tuple(str(Path(SOURCE_DIR) / name) for name in
                       ("agents.py", "execution.py", "sandbox.py", "workspace.py"))

SCENARIOS = ("success", "review-fail", "stale-review", "timeout", "permission",
             "malformed", "test-fail", "output-limit")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON field")
        result[key] = value
    return result


def decode(body):
    try:
        return json.loads(body, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(PolicyError("nonfinite JSON")))
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("invalid agent JSON") from exc


def envelope(task_id, phase, payload):
    return {"protocol": 1, "task_id": task_id, "attempt": 1, "phase": phase,
            "session_id": task_id + ":" + phase, "payload": payload,
            "payload_sha256": digest(payload)}


def validate(message, task_id, phase):
    if not isinstance(message, dict) or set(message) != {
            "protocol", "task_id", "attempt", "phase", "session_id", "payload", "payload_sha256"}:
        raise PolicyError("invalid adapter envelope")
    if type(message["protocol"]) is not int or type(message["attempt"]) is not int:
        raise PolicyError("protocol and attempt must be integers")
    expected = envelope(task_id, phase, message["payload"])
    if message != expected:
        raise PolicyError("adapter identity or payload hash mismatch")
    return message["payload"]


class CodexAdapter:
    provider = "codex"
    phase = "implement"

    def run(self, request, **limits):
        raise PolicyError("real Codex execution disabled in P0; P1 sandbox approval required")


class ClaudeCodeAdapter:
    provider = "claude-code"
    phase = "review"

    def run(self, request, **limits):
        raise PolicyError("real Claude Code execution disabled in P0; P1 sandbox approval required")


class FakeAdapter:
    def __init__(self, phase):
        if phase not in ("implement", "review"):
            raise PolicyError("invalid fake role")
        self.phase = phase

    def run(self, request, *, home, timeout, cancelled, sandbox):
        # Even the first-party fake runs confined: write only its private home,
        # no fork, no network, no MAESTRO state. Missing isolation fails closed.
        validate(request, request["task_id"], self.phase)
        exe, prefix = python_runtime()
        home = str(home)
        policy = ExecPolicy(exe, ("-I", "-B", WORKER_SOURCES[0], "--worker", str(timeout)),
                            cwd=home, home=home, writable=(home,), readable=(prefix,) + WORKER_SOURCES,
                            listable=(SOURCE_DIR,), timeout=timeout)
        raw = sandbox.run(policy, data=canonical(request), cancelled=cancelled)
        return validate(decode(raw), request["task_id"], self.phase)


def worker():
    # A trusted fake also expires if its coordinator is killed outright.
    budget = float(sys.argv[2])
    if not math.isfinite(budget) or not 0 < budget <= 30:
        raise PolicyError("invalid worker lifetime")
    signal.alarm(math.ceil(budget) + 1)
    request = decode(sys.stdin.buffer.read(262145))
    phase = request["phase"]
    data = validate(request, request["task_id"], phase)
    scenario = data["scenario"]
    if phase == "implement":
        if scenario == "timeout":
            time.sleep(120)
        if scenario == "output-limit":
            sys.stdout.write("x" * 300000)
            return
        if scenario == "malformed":
            sys.stdout.write("{not json}")
            return
        target = "../escape.txt" if scenario == "permission" else data["target"]
        content = "wrong result" if scenario == "test-fail" else data["expected"]
        result = {"edits": [{"path": target, "text": content}],
                  "summary": "Deterministic fake implementation; no model invoked."}
    else:
        handoff = data["handoff"]
        if digest(handoff) != data["handoff_sha256"]:
            raise PolicyError("corrupt handoff")
        snapshot = handoff["snapshot"]
        if digest(snapshot["files"]) != snapshot["sha256"]:
            raise PolicyError("corrupt snapshot")
        for f in snapshot["files"].values():
            if hashlib.sha256(f["text"].encode()).hexdigest() != f["sha256"]:
                raise PolicyError("corrupt snapshot file")
        result = {"snapshot_sha256": "0" * 64 if scenario == "stale-review" else snapshot["sha256"],
                  "handoff_sha256": data["handoff_sha256"],
                  "verdict": "changes_requested" if scenario == "review-fail" else "approved",
                  "summary": "Independent fake review fixture; no semantic code review."}
    sys.stdout.buffer.write(canonical(envelope(request["task_id"], phase, result)))


if __name__ == "__main__":
    worker()
