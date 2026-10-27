#!/usr/bin/python3
"""Offline multi-file project demonstration of the full Trusted Local CLI flow.

check → start (src layout) → implement → verify → review → diff → approve → export,
then a second task whose deliberately flawed change MAESTRO's confined verification
rejects. Synthetic fixture and fake agents only: no model is called and nothing leaves
this machine. This is not validation against a third-party project.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "examples" / "trusted-local"))
from make_fixture import make_fixture  # noqa: E402

LAYOUT = ["--pythonpath", "src", "--top-level-dir", "."]


def main():
    with tempfile.TemporaryDirectory(prefix=".project-demo-", dir=ROOT) as temp:
        folder = Path(temp).resolve()
        repo = folder / "stockroom"
        base = make_fixture(repo, HERE / "fixture")

        def cli(*args, expect=0):
            # Test-only harness: fake agents can be approved only in explicit test context.
            result = subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "tests/fixtures/trusted_test_cli.py"),
                                     "--root", str(folder / "state"), "trusted", *map(str, args)],
                                    capture_output=True, timeout=120)
            if result.returncode != expect:
                raise RuntimeError("%s exited %d: %s" % (args[0], result.returncode, result.stderr.decode()[-2000:]))
            return result.stdout if args[0] == "diff" else json.loads(result.stdout)

        baseline = cli("check", "--repo", repo, "--base", base, *LAYOUT)
        assert baseline["compatible"] and not baseline["baseline"]["passed"], baseline
        summary = {"base": base, "check": {"files": baseline["files"], "baseline_passed": False,
                                           "baseline_exit_code": baseline["baseline"]["exit_code"]}}
        for change in ("correct", "flawed"):
            task = folder / ("TASK-%s.md" % change)
            task.write_text((repo / "TASK.md").read_text() + "\ndemo-change: " + change + "\n")
            task_id = cli("start", "--repo", repo, "--base", base, "--task", task, "--model", "demo-model",
                          "--review-model", "demo-reviewer", *LAYOUT)["id"]
            cli("implement", task_id, "--codex-bin", HERE / "fake_implementer.py")
            if change == "flawed":
                failed = cli("verify", task_id, expect=2)
                message = cli("status", task_id)["events"][-1]["message"]
                assert failed["status"] == "failed" and "test_rejects_a_negative_quantity_in_a_repeated_sku" in message
                summary[change] = {"status": failed["status"], "verification": "failed",
                                   "failing_test": "test_rejects_a_negative_quantity_in_a_repeated_sku"}
                continue
            verified = cli("verify", task_id)
            snapshot = verified["evidence"]["snapshot_sha256"]
            review = cli("review", task_id, "--claude-bin", ROOT / "tests/fixtures/fake_claude.py")["review"]
            patch = cli("diff", task_id)
            status = cli("status", task_id)
            assert {c["path"] for c in status["changes"]} == {"src/stockroom/errors.py", "src/stockroom/importer.py"}
            cli("approve", task_id, "--snapshot", snapshot, "--founder", "Offline project demonstration")
            exported = cli("export", task_id)
            assert exported["review_sha256"] == status["evidence"]["review_sha256"]
            assert exported["sha256"] == review["patch_sha256"]
            summary[change] = {"status": "approved", "snapshot_sha256": snapshot, "patch_sha256": exported["sha256"],
                               "patch_bytes": len(patch), "changes": status["changes"],
                               "review_verdict": review["verdict"]}
        print(json.dumps(dict(summary, project_demo_passed=True), indent=1))


if __name__ == "__main__":
    main()
