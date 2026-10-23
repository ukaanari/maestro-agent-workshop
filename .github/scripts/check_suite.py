#!/usr/bin/env python3
"""Run the full suite and require its failing tests to be exactly the expected ones.

Usage: check_suite.py [EXPECTED_FAILING_TEST_ID ...]

With no arguments every test must pass. An experimental interpreter can name its
known, tracked failures (#7): the run then still fails on any *other* failure, and
also when a known failure starts passing, so the list cannot go stale. Every
failure is printed in full either way; nothing is skipped or hidden.
"""
import os
from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parents[2] / "tests"


def main(expected):
    suite = unittest.defaultTestLoader.discover(str(TESTS))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # A failing subTest counts against the test method that contains it.
    failed = {getattr(test, "test_case", test).id() for test, _ in result.failures + result.errors}
    unexpected, fixed = sorted(failed - expected), sorted(expected - failed)
    lines = ["Tests run: %d. Failing tests: %d." % (result.testsRun, len(failed))]
    lines += ["- known failure (#7): %s" % name for name in sorted(failed & expected)]
    lines += ["- UNEXPECTED failure: %s" % name for name in unexpected]
    lines += ["- expected to fail but passed (update the list): %s" % name for name in fixed]
    report = "\n".join(lines)
    print("\n" + report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            out.write("### Test suite\n\n" + report + "\n")
    return 1 if unexpected or fixed or not result.testsRun else 0


if __name__ == "__main__":
    sys.exit(main(set(sys.argv[1:])))
