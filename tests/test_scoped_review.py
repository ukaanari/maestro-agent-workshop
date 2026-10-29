"""Scoped Claude review context: selection, binding, labelling and never-send rules.

Offline: synthetic fixtures and fake agents only. No model, login, network or credentials.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import context
import reviewer
import trusted
from execution import PolicyError
from workflow import Store
from workspace import canonical, digest

FAKE_PATCH = ROOT / "tests" / "fixtures" / "fake_patch_implementer.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("scoped_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")

CHECKOUT = "from shop.gateway import charge\nfrom shop.money import to_cents\n\n\ndef checkout(total):\n    return charge(to_cents(total))\n"
DEFECT = "from shop.gateway import charge\n\n\ndef checkout(total):\n    return charge(total)\n"


def shop_files(money_padding=0):
    files = {
        "shop/__init__.py": "",
        "shop/money.py": "def to_cents(amount):\n    return int(round(amount * 100))\n" + "# contract note\n" * money_padding,
        "shop/gateway.py": 'def charge(cents):\n    """cents: a whole number of cents, never dollars."""\n'
                           '    return {"charged_cents": cents}\n',
        "shop/checkout.py": CHECKOUT,
        "shop/reports.py": "def monthly():\n    return 'unrelated'\n",
        "tests/test_checkout.py": "import unittest\n\nfrom shop.checkout import checkout\n\n\n"
                                  "class CheckoutTests(unittest.TestCase):\n    def test_zero(self):\n"
                                  "        self.assertEqual(checkout(0), {'charged_cents': 0})\n",
        "tests/__init__.py": "",
        "TASK.md": "Simplify shop.checkout.checkout.\n",
    }
    files.update({"docs/note_%02d.md" % i: "Unrelated note %d.\n" % i * 20 for i in range(30)})
    return files


def blobs(files):
    out = {}
    for path, text in files.items():
        body = text.encode()
        out[path] = {"body": body, "mode": "100644",
                     "oid": hashlib.sha1(b"blob %d\0" % len(body) + body).hexdigest()}
    return out


def render_bodies(after, before):
    def render(selection):
        return canonical({"files": {p: (after.get(p) or before.get(p))["body"].decode() for p in selection["selected"]},
                          "critical_omitted": selection["critical_omitted"], "map": selection["outline"],
                          "audit": selection["audit_sha256"]})
    return render


class ScopedSelectorTests(unittest.TestCase):
    """The adapted Sprint 06A selector, on in-memory trees."""

    def test_cross_file_helper_gateway_and_test_kept_after_a_removed_import(self):
        before = blobs(shop_files())
        after = blobs(dict(shop_files(), **{"shop/checkout.py": DEFECT}))
        payload, audit, selection = context.select(before, after, render_bodies(after, before), 400000)
        self.assertEqual(selection["status"], "selected")
        for path in ("shop/checkout.py", "shop/money.py", "shop/gateway.py", "tests/test_checkout.py"):
            self.assertIn(path, selection["selected"])
        self.assertIn("shop/money.py", selection["critical"])  # only the BASE still imports it
        self.assertFalse([p for p in selection["selected"] if p.startswith("docs/") or p == "shop/reports.py"])
        records = json.loads(audit)
        self.assertEqual({r["path"] for r in records}, set(after))  # every file, included or not
        self.assertEqual(hashlib.sha256(audit).hexdigest(), selection["audit_sha256"])
        self.assertIn(selection["audit_sha256"].encode(), payload)

    def test_a_critical_helper_that_does_not_fit_is_reported_not_silently_dropped(self):
        before = blobs(shop_files(money_padding=4000))
        after = blobs(dict(shop_files(money_padding=4000), **{"shop/checkout.py": DEFECT}))
        _, _, selection = context.select(before, after, render_bodies(after, before), 12000)
        self.assertEqual(selection["status"], "incomplete-critical-context")
        self.assertEqual(selection["critical_omitted"], ["shop/money.py"])
        self.assertIn("shop/checkout.py", selection["selected"])

    def test_changed_and_deleted_files_are_never_cut_and_overflow_is_explicit(self):
        files = shop_files()
        big = "def huge():\n" + "    x = 1\n" * 3000
        before = blobs(dict(files, **{"shop/legacy.py": "def old():\n    return 1\n"}))
        after = blobs(dict(files, **{"shop/checkout.py": DEFECT + big}))
        payload, _, selection = context.select(before, after, render_bodies(after, before), 4000)
        self.assertEqual(selection["status"], "budget-exceeded")
        self.assertEqual(selection["changed"], ["shop/checkout.py", "shop/legacy.py"])
        self.assertTrue({"shop/checkout.py", "shop/legacy.py"} <= set(selection["selected"]))
        document = json.loads(payload)
        self.assertEqual(document["files"]["shop/checkout.py"], DEFECT + big)  # whole, not truncated
        self.assertEqual(document["files"]["shop/legacy.py"], "def old():\n    return 1\n")  # deleted: base body
        self.assertEqual(document["map"], [])  # the optional map shrank first

    @staticmethod
    def package_files(api_padding=0):
        return {
            "pkg/__init__.py": "from pkg.core import parse\n",
            "pkg/core.py": "def parse(text):\n    return text\n",
            "pkg/extra.py": "def other():\n    return 1\n",
            "deep/a.py": "import deep.b\n", "deep/b.py": "import deep.c\n", "deep/c.py": "import pkg.core\n",
            "tests/__init__.py": "import pkg as lib\n",
            # Reaches pkg/core.py only through two package initializers (the tomli shape).
            "tests/test_api.py": "import unittest\n\nfrom . import lib\n" + "# padding\n" * api_padding +
                                 "\n\nclass ApiTests(unittest.TestCase):\n    def test_parse(self):\n"
                                 "        self.assertEqual(lib.parse('a'), 'a')\n",
            # Imports a sibling submodule: its parent package is implicit and not followed.
            "tests/test_extra.py": "import unittest\n\nfrom pkg.extra import other\n",
            # Four explicit hops to pkg/core.py: beyond the bound, deliberately.
            "tests/test_deep.py": "import unittest\n\nimport deep.a\n",
        }

    def test_tests_reaching_a_change_through_packages_are_critical_within_a_bound(self):
        before = blobs(self.package_files())
        after = blobs(dict(self.package_files(), **{"pkg/core.py": "def parse(text):\n    return text.strip()\n"}))
        _, _, selection = context.select(before, after, render_bodies(after, before), 400000)
        self.assertEqual(selection["status"], "selected")
        self.assertEqual(selection["direct_tests"], [])  # no test imports pkg/core.py or is named after it
        self.assertIn("tests/test_api.py", selection["indirect_tests"])
        self.assertIn("tests/test_api.py", selection["critical"])
        for path in ("tests/test_extra.py", "tests/test_deep.py"):
            self.assertNotIn(path, selection["indirect_tests"])
            self.assertNotIn(path, selection["critical"])
        self.assertEqual(context.TEST_HOPS, 3)

    def test_an_omitted_package_reached_test_makes_the_context_incomplete(self):
        before = blobs(self.package_files(api_padding=2000))
        after = blobs(dict(self.package_files(api_padding=2000), **{"pkg/core.py": "def parse(text):\n    return text.strip()\n"}))
        _, _, selection = context.select(before, after, render_bodies(after, before), 9000)
        self.assertNotIn("tests/test_api.py", selection["selected"])
        self.assertEqual(selection["status"], "incomplete-critical-context")  # never a silent "selected"
        self.assertIn("tests/test_api.py", selection["critical_omitted"])

    def test_selection_is_identical_across_hash_seeds(self):
        program = ("import hashlib, sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
                   "import test_scoped_review as t, context\n"
                   "b = t.blobs(t.shop_files()); a = t.blobs(dict(t.shop_files(), **{'shop/checkout.py': t.DEFECT}))\n"
                   "p, audit, s = context.select(b, a, t.render_bodies(a, b), 400000)\n"
                   "print(hashlib.sha256(p).hexdigest(), hashlib.sha256(audit).hexdigest())\n"
                   % (str(ROOT), str(ROOT / "tests")))
        results = {subprocess.run([sys.executable, "-B", "-c", program], capture_output=True, text=True, timeout=60,
                                  env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": seed}).stdout for seed in ("0", "1", "4242")}
        self.assertEqual(len(results), 1, results)
        self.assertEqual(len(next(iter(results)).split()), 2)


@RUNTIME
class ScopedReviewEngineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".scoped-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def shop(self, money_padding=0, change_padding=0):
        source = self.root / ("shop-fixture-%d-%d" % (money_padding, change_padding))
        for path, text in shop_files(money_padding).items():
            (source / path).parent.mkdir(parents=True, exist_ok=True)
            (source / path).write_text(text)
        repo = self.root / ("shop-%d-%d" % (money_padding, change_padding))
        change = self.root / ("shop-change-%d-%d" % (money_padding, change_padding))
        (change / "shop").mkdir(parents=True)
        (change / "shop" / "checkout.py").write_text(DEFECT + "# changed line\n" * change_padding)
        return repo, fixture.make_fixture(repo, source), change

    def verified(self, repo, base, change, scenario="pass", review_context="scoped", budget=None, engine=None):
        engine = engine or self.engine
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text("Simplify checkout.\napply-dir: %s\nreview-scenario: %s\n" % (change, scenario))
        task_id = engine.start(repo, base, task, "test-model", review_model="test-reviewer",
                               review_context=review_context, review_budget=budget,
                               verify=trusted.verify_config(top_level_dir="."))["id"]
        self.assertEqual(engine.implement(task_id, str(FAKE_PATCH))["status"], "reviewing", self.store.events(task_id))
        self.assertEqual(engine.verify(task_id)["status"], "awaiting_approval", self.store.events(task_id))
        return task_id

    def record(self, task_id):
        return self.store.artifact(task_id, "review.1")

    def test_full_context_remains_the_default_and_unchanged(self):
        repo, base, change = self.shop()
        task_id = self.verified(repo, base, change, review_context="full")
        self.assertEqual(self.store.get(task_id)["spec"]["review"], {"provider": "claude-code", "model": "test-reviewer"})
        self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")
        record = self.record(task_id)
        self.assertNotIn("context", record)
        self.assertEqual(record["argv"][-1], reviewer.CONTRACT)
        staged = (self.store.task_dir(task_id) / record["input"]["path"]).read_bytes()
        self.assertTrue(staged.startswith(b"MAESTRO review input (maestro-review-v1)"))
        self.assertEqual(len(json.loads(staged.split(b"\n", 1)[1])["files"]), 38)
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(task_id, sha, "human")
        self.assertNotIn("review_context", self.store.artifact(task_id, "approval"))
        with self.assertRaisesRegex(PolicyError, "scoped needs --review-model"):
            self.engine.start(repo, base, self.root / "TASK-1.md", "test-model", review_context="scoped")
        with self.assertRaisesRegex(PolicyError, "only to a scoped review"):
            self.engine.start(repo, base, self.root / "TASK-1.md", "test-model", review_model="r", review_budget=5000)

    def test_scoped_review_is_bound_labelled_and_exported(self):
        repo, base, change = self.shop()
        task_id = self.verified(repo, base, change)
        self.assertEqual(self.store.get(task_id)["spec"]["review"]["context"], "scoped")
        summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
        self.assertEqual(summary["outcome"], "completed", summary)
        self.assertIn("not a full-repository review", summary["scope_notice"])
        record = self.record(task_id)
        scope = record["context"]
        self.assertEqual((scope["mode"], scope["status"], scope["policy"]), ("scoped", "selected", context.POLICY))
        self.assertEqual(record["classification"], reviewer.SCOPED_CLASSIFICATION)
        self.assertEqual(record["argv"][-1], reviewer.CONTRACT_SCOPED)
        for path in ("shop/checkout.py", "shop/money.py", "shop/gateway.py", "tests/test_checkout.py"):
            self.assertIn(path, scope["included"])
        self.assertFalse([p for p in scope["included"] if p.startswith("docs/")])
        self.assertEqual(scope["included_count"] + scope["omitted_count"], scope["snapshot_file_count"])
        home = self.store.task_dir(task_id)
        staged = (home / record["input"]["path"]).read_bytes()
        header, body = staged.split(b"\n", 1)
        self.assertIn(b"maestro-review-v2-scoped", header)
        self.assertIn(b"not the full repository", header)
        document = json.loads(body)
        claimed = document.pop("context_sha256")
        self.assertEqual(claimed, scope["context_sha256"])
        self.assertEqual(hashlib.sha256(canonical(document)).hexdigest(), claimed)  # binds task text too
        self.assertEqual(document["review_scope"], "scoped")
        self.assertEqual(document["files"][[f["path"] for f in document["files"]].index("shop/checkout.py")]["content"], DEFECT)
        audit = (home / scope["audit_path"]).read_bytes()
        self.assertEqual(hashlib.sha256(audit).hexdigest(), scope["audit_sha256"])
        self.assertEqual(len(json.loads(audit)), scope["snapshot_file_count"])
        # Same full-snapshot and exact-patch bindings as a full review.
        self.assertEqual(record["snapshot_sha256"], self.store.get(task_id)["evidence"]["snapshot_sha256"])
        self.assertEqual(record["patch_sha256"], hashlib.sha256(self.engine.diff(task_id)).hexdigest())
        self.assertEqual(record["review"]["context_sha256"], scope["context_sha256"])
        sha = self.store.get(task_id)["evidence"]["snapshot_sha256"]
        self.engine.approve(task_id, sha, "human")
        self.assertEqual(self.store.artifact(task_id, "approval")["review_context"], "scoped")
        exported = self.engine.export(task_id)
        self.assertEqual((exported["review_context"], exported["review_sha256"]), ("scoped", digest(record)))

    def test_incomplete_or_overflowing_context_is_never_sent(self):
        repo, base, change = self.shop(money_padding=4000)
        task_id = self.verified(repo, base, change, budget=4000)
        summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
        self.assertEqual(summary["outcome"], "unavailable")
        self.assertIn("critical related files would be omitted: shop/money.py", summary["error"])
        folder = self.store.task_dir(task_id) / "review-1"
        self.assertFalse((folder / "stdout.json").exists())  # the reviewer never ran
        self.assertTrue((folder / "input.txt").exists())     # the would-be input is kept as evidence
        self.assertEqual(self.record(task_id)["context"]["critical_omitted"], ["shop/money.py"])
        with self.assertRaisesRegex(PolicyError, "review required"):
            self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")
        repo, base, change = self.shop(change_padding=400)  # a 6 KB changed file, budget 4 KB
        task_id = self.verified(repo, base, change, budget=1000)
        summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
        self.assertEqual(summary["outcome"], "unavailable")
        self.assertIn("mandatory changed content alone exceeds the budget", summary["error"])
        self.assertEqual(self.record(task_id)["context"]["status"], "budget-exceeded")
        staged = (self.store.task_dir(task_id) / "review-1" / "input.txt").read_bytes()
        self.assertIn(("# changed line\n" * 400).encode().replace(b"\n", b"\\n"), staged)  # never truncated
        self.assertFalse((self.store.task_dir(task_id) / "review-1" / "stdout.json").exists())

    def test_wrong_digest_omitted_file_and_tampered_scope_are_rejected(self):
        repo, base, change = self.shop()
        for scenario in ("wrong-context", "omitted-file"):
            with self.subTest(scenario=scenario):
                task_id = self.verified(repo, base, change, scenario=scenario)
                summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
                self.assertEqual(summary["outcome"], "failed", summary)
        for field, value in (("status", "incomplete-critical-context"), ("budget_estimated_tokens", 99999),
                             ("policy", "other"), ("context_sha256", "0" * 64)):
            with self.subTest(field=field):
                task_id = self.verified(repo, base, change)
                self.engine.review(task_id, str(FAKE_CLAUDE))
                record = self.record(task_id)
                record["context"][field] = value
                evidence = dict(self.store.get(task_id)["evidence"], review_sha256=digest(record))
                with self.store.connect() as conn:
                    conn.execute("UPDATE artifacts SET body=?,hash=? WHERE task_id=? AND kind='review.1'",
                                 (canonical(record).decode(), digest(record), task_id))
                    conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(evidence).decode(), task_id))
                with self.assertRaisesRegex(PolicyError, "scoped review context evidence mismatch|different review context"):
                    self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")
                self.assertFalse(self.store.has_artifact(task_id, "approval"))

    def test_cli_scoped_flags(self):
        repo, base, change = self.shop()
        task = self.root / "cli-TASK.md"
        task.write_text("Simplify checkout.\napply-dir: %s\n" % change)
        def cli(*args):
            return subprocess.run(["/usr/bin/python3", "-B", str(ROOT / "maestro.py"), "--root", str(self.store.root),
                                   "trusted", *map(str, args)], capture_output=True, text=True, timeout=60)
        result = cli("start", "--repo", repo, "--base", base, "--task", task, "--model", "test-model",
                     "--review-model", "test-reviewer", "--review-context", "scoped", "--review-budget", "20000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["spec"]["review"],
                         {"provider": "claude-code", "model": "test-reviewer", "context": "scoped",
                          "budget_estimated_tokens": 20000})
        result = cli("start", "--repo", repo, "--base", base, "--task", task, "--model", "test-model",
                     "--review-model", "test-reviewer", "--review-budget", "20000")
        self.assertEqual(result.returncode, 2)
        self.assertIn("only to a scoped review", result.stderr)
