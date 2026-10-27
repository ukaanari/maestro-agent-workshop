#!/usr/bin/python3
"""Explicit offline test harness, never the production CLI entry point.

Used by the disposable demo to keep subprocess/CLI coverage. Tests may also
instantiate TrustedEngine(test_context=True) directly. No environment variable
or ordinary CLI flag can enable this capability in maestro.py.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import maestro

if __name__ == "__main__":
    sys.exit(maestro.main(test_context=True))
