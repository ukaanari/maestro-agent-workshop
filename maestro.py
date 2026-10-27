#!/usr/bin/env python3
"""MAESTRO local CLI: confined synthetic tasks and explicit trusted-local tasks."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

from agents import SCENARIOS
import doctor
from execution import Cancelled, PolicyError
from workflow import Engine, Store

__version__ = "0.1.0-alpha"


def main(argv=None, *, test_context=False):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent / ".maestro")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check host prerequisites; changes nothing")
    create = sub.add_parser("create", help="create a fake-only task in a synthetic repo")
    create.add_argument("title")
    create.add_argument("--file", default="result.txt")
    create.add_argument("--content", default="MAESTRO P0\n")
    create.add_argument("--scenario", choices=SCENARIOS, default="success")
    create.add_argument("--timeout", type=float, default=5)
    for name in ("run", "status", "cancel", "recover", "dispose", "approve", "artifact"):
        cmd = sub.add_parser(name)
        cmd.add_argument("task_id")
        if name == "approve":
            cmd.add_argument("--snapshot", required=True)
            cmd.add_argument("--founder", required=True)
        if name == "artifact":
            cmd.add_argument("kind", choices=("handoff", "review", "verification"))
        if name == "dispose":
            cmd.add_argument("--remove-reviewed-output", action="store_true",
                             help="also delete output that exactly matches the stored handoff")
    trusted = sub.add_parser("trusted", help="experimental trusted-local mode")
    commands = trusted.add_subparsers(dest="trusted_command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--repo", type=Path, required=True)
    start.add_argument("--base", required=True)
    start.add_argument("--task", type=Path, required=True)
    start.add_argument("--model", required=True)
    for name in ("implement", "verify", "diff", "approve", "reject", "cancel", "export", "status"):
        cmd = commands.add_parser(name)
        cmd.add_argument("task_id")
        if name == "implement":
            cmd.add_argument("--codex-bin")
            cmd.add_argument("--timeout", type=float, default=1200)
        if name == "approve":
            cmd.add_argument("--snapshot", required=True)
            cmd.add_argument("--founder", required=True)
        if name == "reject":
            cmd.add_argument("--founder", required=True)
            cmd.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    if args.command == "doctor":
        # Before Store(): diagnosing a host must never create or adopt a state root.
        report = dict(doctor.run_checks(args.root), version=__version__)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0 if report["ok"] else 2
    try:
        store = Store(args.root)
        engine = Engine(store)
        if args.command == "trusted":
            from trusted import TrustedEngine
            trusted_engine = TrustedEngine(store, test_context=test_context)
            action = args.trusted_command
            if action == "start":
                result = trusted_engine.start(args.repo, args.base, args.task, args.model)
            elif action == "implement":
                result = trusted_engine.implement(args.task_id, args.codex_bin, args.timeout)
            elif action == "approve":
                result = trusted_engine.approve(args.task_id, args.snapshot, args.founder)
            elif action == "reject":
                result = trusted_engine.reject(args.task_id, args.founder, args.reason)
            elif action == "diff":
                # The exact patch under review, printed raw for human inspection.
                sys.stdout.buffer.write(trusted_engine.diff(args.task_id))
                return 0
            else:
                result = getattr(trusted_engine, action)(args.task_id)
            print(json.dumps(result, indent=2, ensure_ascii=True))
            expected = {"start": "preparing", "implement": "reviewing", "verify": "awaiting_approval"}
            return 2 if action in expected and result.get("status") != expected[action] else 0
        if hasattr(args, "task_id"):
            engine.require_confined(args.task_id)
        if args.command == "create":
            task_id = store.create(args.title, args.file, args.content, args.scenario, args.timeout)
            result = store.get(task_id)
        elif args.command == "run":
            result = engine.run(args.task_id)
        elif args.command == "approve":
            result = engine.approve(args.task_id, args.snapshot, args.founder)
        elif args.command == "artifact":
            result = store.artifact(args.task_id, args.kind)
        else:
            if args.command == "cancel":
                store.cancel(args.task_id)
            elif args.command == "recover":
                engine.recover(args.task_id)
            elif args.command == "dispose":
                engine.dispose(args.task_id, args.remove_reviewed_output)
            result = store.get(args.task_id)
            result["events"] = store.events(args.task_id)
            if result["status"] in {"awaiting_approval", "approved"}:
                try:
                    engine.check_evidence(args.task_id)
                    result["evidence_current"] = True
                except (PolicyError, OSError, KeyError, ValueError):
                    result["evidence_current"] = False
        print(json.dumps(result, indent=2, ensure_ascii=True))
        if args.command == "run" and result["status"] != "awaiting_approval":
            return 2
        return 0
    except (PolicyError, Cancelled, OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
