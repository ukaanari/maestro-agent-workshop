#!/usr/bin/python3
"""Offline stand-in for the Codex CLI in the project demo. It calls no model.

It copies one prepared change set into the clone: `correct`, or the one named by a
`demo-change: NAME` line in the task. Its version string marks it offline-fixture, so
only a test task with an explicit test-context caller can approve or export the result.
"""
import json
from pathlib import Path
import sys

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.0.0-offline-fixture (project demo)")
    sys.exit(0)
args = sys.argv[1:]
if not (len(args) == 15 and args[:4] == ["-a", "never", "exec", "-m"] and args[12] == "-o" and args[14] == "-" and
        args[5:11] == ["--ignore-user-config", "--sandbox", "workspace-write", "--json", "--ephemeral", "-C"]):
    sys.exit("unexpected MAESTRO argv: %r" % args)
clone, last = Path(args[11]), Path(args[13])
change = next((line.split(":", 1)[1].strip() for line in sys.stdin.read().splitlines()
               if line.startswith("demo-change:")), "correct")
source = Path(__file__).resolve().parent / "changes" / change
if change not in ("correct", "flawed") or not source.is_dir():
    sys.exit("unknown demo change: " + change)
written = []
for path in sorted(p for p in source.rglob("*") if p.is_file()):
    rel = path.relative_to(source)
    (clone / rel).parent.mkdir(parents=True, exist_ok=True)
    (clone / rel).write_bytes(path.read_bytes())  # existing files keep their mode
    written.append(rel.as_posix())
last.write_text("Claim: applied the %s change set to %s.\n" % (change, ", ".join(written)))
print(json.dumps({"type": "thread.started", "thread_id": "offline-project-demo"}))
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "Claim: done"}}))
print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 0, "output_tokens": 0}}), flush=True)
