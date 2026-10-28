#!/usr/bin/python3
"""Explicit offline fixture only: copies the files under the directory named by an
`apply-dir: PATH` line in the task into MAESTRO's clone, and deletes paths named by
`delete: PATH` lines. It calls no model; its offline-fixture version keeps it out of
normal-context approval.
"""
import json
from pathlib import Path
import shutil
import sys

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.0.0-offline-fixture (patch implementer)")
    sys.exit(0)
args = sys.argv[1:]
assert len(args) == 15 and args[:4] == ["-a", "never", "exec", "-m"] and args[12] == "-o" and args[14] == "-", args
clone, last = Path(args[11]), Path(args[13])
lines = sys.stdin.read().splitlines()
for line in lines:
    if line.startswith("apply-dir:"):
        source = Path(line.split(":", 1)[1].strip())
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            target = clone / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    elif line.startswith("delete:"):
        target = clone / line.split(":", 1)[1].strip()
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
last.write_text("Claim: applied the fixture change.\n")
print(json.dumps({"type": "thread.started", "thread_id": "offline-patch-fixture"}))
print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 0, "output_tokens": 0}}), flush=True)
