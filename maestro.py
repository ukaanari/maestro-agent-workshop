#!/usr/bin/env python3
"""MAESTRO P0 local CLI: only first-party fake providers can execute."""
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


def main(argv=None):
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
    args = parser.parse_args(argv)
    if args.command == "doctor":
        # Before Store(): diagnosing a host must never create or adopt a state root.
        report = dict(doctor.run_checks(args.root), version=__version__)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0 if report["ok"] else 2
    try:
        store = Store(args.root)
        engine = Engine(store)
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
                engine.dispose(args.task_id)
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
