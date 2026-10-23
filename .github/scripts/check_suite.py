#!/usr/bin/env python3
"""Run the full suite and require its failures to be exactly the documented known ones.

Usage: check_suite.py [--known-failures FILE]

FILE lists exact unittest ids, one per line; '#' starts a comment. A failing subTest
keeps its own id, for example
    test_security.ConfinementTests.test_x (probe='sibling_environment')
so a known failure in one subTest never excuses another subTest of the same test, nor
a failure of the test outside its subTests. The run fails on any unlisted failure or
error, and on any listed id that did not fail, so the list cannot go stale. Every
failure is printed in full; nothing is skipped or hidden.
"""
import argparse
import os
from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parents[2] / "tests"


def read_known(path):
    if not path:
        return set()
    lines = (line.strip() for line in Path(path).read_text().splitlines())
    return {line for line in lines if line and not line.startswith("#")}


def failing_ids(result):
    """Exact ids of everything that failed or errored; subTests stay distinct."""
    return {test.id() for test, _ in result.failures + result.errors}


def evaluate(result, known):
    """(ok, report): ok only if the failures are exactly `known` and something ran."""
    failed = failing_ids(result)
    unexpected, stale = sorted(failed - known), sorted(known - failed)
    lines = ["Tests run: %d. Failing tests and subTests: %d." % (result.testsRun, len(failed))]
    lines += ["- known failure: %s" % name for name in sorted(failed & known)]
    lines += ["- UNEXPECTED failure: %s" % name for name in unexpected]
    lines += ["- listed as known but did not fail (update the list): %s" % name for name in stale]
    lines += ["- unexpected success: %s" % test.id() for test in result.unexpectedSuccesses]
    ok = not (unexpected or stale or result.unexpectedSuccesses) and result.testsRun > 0
    return ok, "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the suite against an exact known-failure list.")
    parser.add_argument("--known-failures", default="", help="file of exact unittest ids allowed to fail")
    args = parser.parse_args(argv)
    known = read_known(args.known_failures)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(str(TESTS)))
    ok, report = evaluate(result, known)
    print("\n" + report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            out.write("### Test suite\n\n" + report + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
