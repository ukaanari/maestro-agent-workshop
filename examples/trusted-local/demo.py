#!/usr/bin/python3
"""Offline CLI demonstration. The fake is selected explicitly; no model calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from make_fixture import make_fixture

ROOT = Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix=".trusted-demo-", dir=ROOT) as temp:
        folder = Path(temp).resolve()
        repo = folder / "source"
        base = make_fixture(repo)
        def cli(*args):
            result = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "tests/fixtures/trusted_test_cli.py"), "--root",
                                     str(folder / "state"), "trusted", *map(str, args)],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            return json.loads(result.stdout)
        task = cli("start", "--repo", repo, "--base", base, "--task", repo / "TASK.md", "--model", "test-model")
        task_id = task["id"]
        cli("implement", task_id, "--codex-bin", ROOT / "tests/fixtures/fake_codex.py")
        verified = cli("verify", task_id)
        sha = verified["evidence"]["snapshot_sha256"]
        cli("approve", task_id, "--snapshot", sha, "--founder", "Offline demonstration")
        exported = cli("export", task_id)
        assert cli("status", task_id)["status"] == "approved"
        print(json.dumps({"offline_demo_passed": True, "base": base,
                          "snapshot_sha256": sha, "patch_sha256": exported["sha256"]}))


if __name__ == "__main__":
    main()
