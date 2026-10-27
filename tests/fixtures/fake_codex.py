#!/usr/bin/python3
"""Explicit offline fixture only. Never selected as a production fallback."""
import json
import os
from pathlib import Path
import select
import sys
import time

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.0.0-offline-fixture")
    sys.exit(0)
args = sys.argv[1:]
assert args[:4] == ["-a", "never", "exec", "-m"]
assert args[5:11] == ["--ignore-user-config", "--sandbox", "workspace-write", "--json", "--ephemeral", "-C"]
assert len(args) == 15 and args[12] == "-o" and args[14] == "-"
model = args[4]
clone, last = Path(args[11]), Path(args[13])
if model == "unknown-model":
    print("Model does not exist: " + model, file=sys.stderr)
    sys.exit(2)
control = last.parent
prompt = sys.stdin.read()
scenario = next((line.split(":", 1)[1].strip() for line in prompt.splitlines() if line.startswith("scenario:")), "success")
print(json.dumps({"type": "thread.started", "thread_id": "offline", "argv": args, "codex_home": os.environ.get("CODEX_HOME"), "env": sorted(os.environ),
                  "api_keys_present": [key for key in ("OPENAI_API_KEY", "CODEX_API_KEY") if key in os.environ]}), flush=True)
(control / "fake.started").write_text(str(os.getpid()))
if scenario == "timeout":
    while True:
        select.select([], [], [], 1)
if scenario == "crash":
    sys.exit(7)
if scenario == "malformed":
    print("not-json", flush=True)
    sys.exit(0)
if scenario == "missing-final":
    sys.exit(0)
if scenario == "overflow":
    sys.stdout.write("x" * (11 * 1024 * 1024))
    sys.exit(0)
if scenario not in ("no-write", "wrong"):
    (clone / "calc.py").write_text("def add(a, b):\n    return a + b\n")
elif scenario == "wrong":
    (clone / "calc.py").write_text("def add(a, b):\n    return 0\n")
if scenario == "escaped":
    pid = os.fork()
    if pid == 0:
        os.setsid()
        null = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        if null > 2:
            os.close(null)
        (control / "escaped.ready").write_text(str(os.getpid()))
        deadline = time.monotonic() + 120
        while not (control / "escaped.go").exists():
            if time.monotonic() > deadline:
                os._exit(3)
            select.select([], [], [], 0.01)
        (clone / "calc.py").write_text("def add(a, b):\n    return 999\n")
        (control / "escaped.done").write_text("written")
        while time.monotonic() < deadline:
            select.select([], [], [], 0.1)
        os._exit(0)
    deadline = time.monotonic() + 10
    while not (control / "escaped.ready").exists():
        if time.monotonic() > deadline:
            sys.exit(8)
        select.select([], [], [], 0.01)
last.write_text("Claim: implemented and all tests pass.\n")
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "Claim: success"}}))
print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 0, "output_tokens": 0}}), flush=True)
sys.exit(9 if scenario == "nonzero-success" else 0)
