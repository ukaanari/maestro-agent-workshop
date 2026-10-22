#!/usr/bin/env python3
"""Minimal reproducible MAESTRO demo: three fake-agent tasks in a throwaway state root.

Drives the public CLI only. Runs the bundled deterministic fake agents: no model,
network, API key or installed agent CLI. Requires macOS with /usr/bin/sandbox-exec;
on other hosts every task ends `blocked` by design.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

CLI = Path(__file__).resolve().parents[1] / "maestro.py"
OPERATOR = "Demo operator"
# Snapshots hash content, path and mode, not time or machine, so this value is
# the same on every host. README.md documents it; CI checks it independently.
EXPECTED_SNAPSHOT = "45cb0ff06b4d0feaf105e39f6a4f5a180e77b1a4b08cc27074dd094a1111a3fe"


def maestro(root, *args):
    # -B: never write bytecode next to the sources.
    proc = subprocess.run([sys.executable, "-B", str(CLI), "--root", str(root), *args],
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, json.loads(proc.stdout or proc.stderr)


def check(condition, message, detail=None):
    print(("  ok    " if condition else "  FAIL  ") + message)
    if not condition:
        if detail is not None:
            print(json.dumps(detail, indent=2))
        raise SystemExit(1)


def run_success(root, title, target, content):
    _, task = maestro(root, "create", title, "--file", target, "--content", content)
    code, result = maestro(root, "run", task["id"])
    check(code == 0 and result["status"] == "awaiting_approval",
          "%s: implemented, independently reviewed and verified" % task["id"], result)
    return task["id"], result["evidence"]["snapshot_sha256"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temporary state directory")
    args = parser.parse_args()
    base = Path(tempfile.mkdtemp(prefix="maestro-demo-")).resolve()
    root = base / "state"
    try:
        print("1. Success: synthetic implementer -> fresh synthetic reviewer -> verification -> approval")
        task_id, snapshot = run_success(root, "Create a greeting", "greeting.txt", "Hello MAESTRO")
        check(snapshot == EXPECTED_SNAPSHOT, "snapshot %s... matches the value documented in README.md"
              % snapshot[:16], {"snapshot_sha256": snapshot})
        _, handoff = maestro(root, "artifact", task_id, "handoff")
        _, review = maestro(root, "artifact", task_id, "review")
        _, verification = maestro(root, "artifact", task_id, "verification")
        check(handoff["source"] == "fake-codex" and handoff["snapshot"]["sha256"] == snapshot,
              "handoff from the synthetic implementer is bound to that snapshot")
        check(review["verdict"] == "approved" and review["snapshot_sha256"] == snapshot,
              "the fresh synthetic reviewer approved exactly that snapshot")
        check(verification["passed"] is True and verification["snapshot_sha256"] == snapshot,
              "data-only verification passed for the same snapshot")
        code, _ = maestro(root, "approve", task_id, "--snapshot", "0" * 64, "--founder", OPERATOR)
        check(code == 2, "approval naming a different snapshot is refused")
        code, approved = maestro(root, "approve", task_id, "--snapshot", snapshot, "--founder", OPERATOR)
        check(code == 0 and approved["status"] == "approved", "approval naming the exact snapshot is recorded")

        print("2. Tamper detection: the output changes after review")
        task_id, snapshot = run_success(root, "Create a note", "note.txt", "Reviewed content\n")
        (root / "tasks" / task_id / "worktree" / "note.txt").write_text("Edited after review\n")
        code, error = maestro(root, "approve", task_id, "--snapshot", snapshot, "--founder", OPERATOR)
        _, status = maestro(root, "status", task_id)
        check(code == 2 and status["status"] == "invalidated",
              "approval refused, task invalidated: %s" % error.get("error"), status)

        print("3. Review rejection: the synthetic reviewer requests changes")
        _, task = maestro(root, "create", "Rejected change", "--scenario", "review-fail")
        code, result = maestro(root, "run", task["id"])
        check(code == 2 and result["status"] == "review_failed", "task ends review_failed", result)
        code, _ = maestro(root, "artifact", task["id"], "verification")
        check(code == 2, "verification never ran, so the task cannot be approved")
        print("Demo passed.")
    finally:
        if args.keep:
            print("State kept in", root)
        else:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
