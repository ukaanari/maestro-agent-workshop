#!/usr/bin/python3
"""Create an offline fixture repo with a deterministic, fixed-identity commit.

Usage: make_fixture.py DESTINATION [FIXTURE_DIR]   (default: the bundled calculator fixture)
"""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from execution import execute


def make_fixture(destination, fixture=None):
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    fixture = Path(fixture) if fixture is not None else Path(__file__).parent / "fixture"
    for source in sorted(fixture.rglob("*")):
        if "__pycache__" in source.parts:
            continue
        target = destination / source.relative_to(fixture)
        if source.is_dir():
            target.mkdir(mode=0o755)
        else:
            target.write_bytes(source.read_bytes())
            target.chmod(0o644)
    env = {"GIT_AUTHOR_NAME": "MAESTRO Fixture", "GIT_COMMITTER_NAME": "MAESTRO Fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000"}
    def git(*args):
        return execute(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
                        "-C", str(destination), *args], str(destination), str(destination), extra_env=env)
    git("init", "--template=", "--initial-branch=main")
    git("add", "-A")
    git("commit", "-m", "Deterministic trusted-local fixture")
    return git("rev-parse", "HEAD").decode().strip()


if __name__ == "__main__":
    print(make_fixture(*sys.argv[1:3]))
