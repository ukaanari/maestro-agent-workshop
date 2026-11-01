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


def shop_files(money_padding=0, prefix=""):
    files = {
        prefix + "shop/__init__.py": "",
        prefix + "shop/money.py": "def to_cents(amount):\n    return int(round(amount * 100))\n" +
                                  "# contract note\n" * money_padding,
        prefix + "shop/gateway.py": 'def charge(cents):\n    """cents: a whole number of cents, never dollars."""\n'
                                    '    return {"charged_cents": cents}\n',
        prefix + "shop/checkout.py": CHECKOUT,
        prefix + "shop/reports.py": "def monthly():\n    return 'unrelated'\n",
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


def scoped(base, changes, budget=400000, layout=None):
    before, after = blobs(base), blobs(dict(base, **changes))
    return context.select(before, after, render_bodies(after, before), budget, layout)[2]


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


class ScopedLayoutTests(unittest.TestCase):
    """AUD-02: policy v3 resolves imports as the task's verification run does, and fails closed."""

    def test_configured_roots_keep_helpers_outside_the_root_and_src_critical(self):
        self.assertEqual(context.POLICY, "maestro-scoped-context-v3")
        for prefix in ("lib/", "backend/"):
            with self.subTest(prefix=prefix):
                layout = trusted.verify_config(top_level_dir=".", pythonpath=[prefix.rstrip("/")])
                selection = scoped(shop_files(4000, prefix), {prefix + "shop/checkout.py": DEFECT}, 12000, layout)
                self.assertEqual(selection["status"], "incomplete-critical-context")  # never a silent "selected"
                self.assertEqual(selection["critical_omitted"], [prefix + "shop/money.py"])
                selection = scoped(shop_files(0, prefix), {prefix + "shop/checkout.py": DEFECT}, 400000, layout)
                self.assertEqual(selection["status"], "selected")
                self.assertIn(prefix + "shop/money.py", selection["critical"])
                self.assertEqual(selection["unresolved_imports"], [])
        self.assertEqual(context.module_roots(None), ["tests"])  # what `-s tests` alone puts on sys.path
        self.assertEqual(context.module_roots(trusted.verify_config(top_level_dir=".", pythonpath=["lib", "vendor"])),
                         ["", "lib", "vendor"])
        self.assertEqual(context.module_roots(trusted.verify_config(test_dir="app/tests", top_level_dir="app",
                                                                    pythonpath=["app"])), ["app"])

    def test_an_undeclared_import_root_fails_closed(self):
        for budget in (400000, 12000):
            selection = scoped(shop_files(4000, "lib/"), {"lib/shop/checkout.py": DEFECT + "import shop.reports\n"}, budget)
            self.assertEqual(selection["status"], "unresolved-imports")
            self.assertIn("lib/shop/checkout.py imports shop.gateway (lib/shop/gateway.py)",
                          selection["unresolved_imports"])  # the importer sits in the undeclared root
            self.assertIn("lib/shop/checkout.py imports shop.reports (lib/shop/reports.py)",
                          selection["unresolved_imports"])
            self.assertIn("tests/test_checkout.py imports shop.checkout (lib/shop/checkout.py)",
                          selection["unresolved_imports"])  # the changed file sits in it

    def test_changed_importer_outside_undeclared_root_fails_closed(self):
        # B-01: the changed importer lives in a declared root, while the unchanged helper it imports
        # sits inside an undeclared plain directory.
        base = {
            "app/__init__.py": "",
            "app/checkout.py": (
                "import shop.gateway\n"
                "from shop.money import to_cents\n\n"
                "def checkout(total):\n"
                "    return shop.gateway.charge(to_cents(total))\n"
            ),
            "lib/shop/__init__.py": "",
            "lib/shop/gateway.py": "def charge(cents):\n    return {'charged': cents}\n",
            "lib/shop/money.py": "from .rates import to_cents\n" + "# pad\n" * 4000,
            "lib/shop/rates.py": "def to_cents(amount):\n    return int(round(amount * 100))\n",
            "tests/__init__.py": "",
            "tests/test_checkout.py": "import unittest\nfrom app.checkout import checkout\n",
        }
        change = {
            "app/checkout.py": (
                "import shop.gateway\n"
                "from shop.money import to_cents\n\n"
                "def checkout(total, discount=0):\n"
                "    return shop.gateway.charge(total - discount)\n"
            )
        }
        layout = trusted.verify_config(top_level_dir=".")
        for budget in (400000, 12000):
            selection = scoped(base, change, budget, layout)
            self.assertEqual(selection["status"], "unresolved-imports")
            self.assertIn("app/checkout.py imports shop.gateway (lib/shop/gateway.py)",
                          selection["unresolved_imports"])
            self.assertIn("app/checkout.py imports shop.money (lib/shop/money.py)",
                          selection["unresolved_imports"])

    def test_namespace_directory_does_not_mask_unresolved_submodule_imports(self):
        # B-02: a namespace directory (tests/shop/) makes resolver.resolve("shop") return set();
        # per-candidate resolution must still check shop.gateway and shop.money.
        base = shop_files(4000, "lib/")
        base["tests/shop/test_checkout.py"] = base.pop("tests/test_checkout.py")
        change = {
            "lib/shop/checkout.py": (
                "from shop import gateway, money\n\n"
                "def checkout(total, discount=0):\n"
                "    return gateway.charge(money.to_cents(total - discount))\n"
            )
        }
        for budget in (400000, 12000):
            selection = scoped(base, change, budget)
            self.assertEqual(selection["status"], "unresolved-imports")
            self.assertIn("lib/shop/checkout.py imports shop.gateway (lib/shop/gateway.py)",
                          selection["unresolved_imports"])
            self.assertIn("lib/shop/checkout.py imports shop.money (lib/shop/money.py)",
                          selection["unresolved_imports"])
        # When one submodule resolves in a configured namespace portion and another sits only in
        # an undeclared root, only the unresolved submodule is flagged even if the undeclared root
        # also holds a shadowed copy of the resolved one.
        partial = {
            "shop/a.py": "def ok():\n    return 1\n",
            "lib/shop/a.py": "def ok():\n    return 0\n",
            "lib/shop/b.py": "def hidden():\n    return 2\n",
            "app.py": "from shop import a\n",
            "tests/__init__.py": "",
            "tests/test_app.py": "import unittest\nimport app\n",
        }
        selection = scoped(partial, {"app.py": "from shop import a, b\n\ndef run():\n    return a.ok() + b.hidden()\n"},
                           layout=trusted.verify_config(top_level_dir="."))
        self.assertEqual(selection["status"], "unresolved-imports")
        self.assertIn("shop/a.py", selection["critical"])
        self.assertEqual(selection["unresolved_imports"], ["app.py imports shop.b (lib/shop/b.py)"])

    def test_unrelated_fixtures_and_scripts_do_not_trigger_unresolved_imports(self):
        # B-03: unchanged, unrelated scripts and embedded fixtures (including MAESTRO's own
        # examples/trusted-local/fixture) must not block scoped reviews of unrelated changes.
        fixture_calc = (ROOT / "examples/trusted-local/fixture/calc.py").read_text()
        fixture_test = (ROOT / "examples/trusted-local/fixture/tests/test_calc.py").read_text()
        base = dict(
            shop_files(),
            **{
                "scripts/helper.py": "VALUE = 1\n",
                "scripts/run.py": "import helper\n",
                "examples/trusted-local/fixture/calc.py": fixture_calc,
                "examples/trusted-local/fixture/tests/test_calc.py": fixture_test,
            },
        )
        selection = scoped(base, {"shop/checkout.py": DEFECT}, layout=trusted.verify_config(top_level_dir="."))
        self.assertEqual((selection["status"], selection["unresolved_imports"]), ("selected", []))
        self.assertNotIn("examples/trusted-local/fixture/calc.py", selection["critical"])
        self.assertNotIn("scripts/helper.py", selection["critical"])
        # MAESTRO's own repository layout with its tracked example fixture.
        maestro_files = {
            rel: (ROOT / rel).read_text()
            for rel in (
                "doctor.py",
                "context.py",
                "examples/trusted-local/fixture/calc.py",
                "examples/trusted-local/fixture/tests/test_calc.py",
            )
        }
        maestro_selection = scoped(
            maestro_files,
            {"doctor.py": maestro_files["doctor.py"] + "\n# comment\n"},
            layout=trusted.verify_config(top_level_dir="."),
        )
        self.assertEqual((maestro_selection["status"], maestro_selection["unresolved_imports"]), ("selected", []))

    def test_relative_imports_across_namespace_package_portions(self):
        # B-04: PEP 420 namespace package portions across multiple configured roots merge for
        # relative imports, while regular packages stay confined to their own root.
        base = {
            "mspace/a.py": "from .b import helper\nfrom . import c\n\ndef run(x):\n    return helper(x) + c.extra()\n",
            "lib/mspace/b.py": "def helper(x):\n    return x + 1\n" + "# pad\n" * 4000,
            "lib/mspace/c.py": "def extra():\n    return 2\n",
            "mshop/__init__.py": "",
            "mshop/y.py": "def missing():\n    return 9\n",
            "lib/mshop/__init__.py": "",
            "lib/mshop/x.py": "from .y import missing\n\ndef f():\n    return 1\n",
            "tests/__init__.py": "",
            "tests/test_mspace.py": "import unittest\nfrom mspace.a import run\n",
        }
        change = {"mspace/a.py": "from .b import helper\nfrom . import c\n\ndef run(x):\n    return helper(x) * c.extra()\n"}
        layout = trusted.verify_config(top_level_dir=".", pythonpath=["lib"])
        selection = scoped(base, change, 400000, layout)
        self.assertEqual(selection["status"], "selected")
        self.assertIn("lib/mspace/b.py", selection["critical"])
        self.assertIn("lib/mspace/c.py", selection["critical"])
        selection = scoped(base, change, 12000, layout)
        self.assertEqual(selection["status"], "incomplete-critical-context")
        self.assertEqual(selection["critical_omitted"], ["lib/mspace/b.py"])
        # Regular packages with colliding names in different roots do not cross-contaminate.
        regular_change = {"lib/mshop/x.py": "from .y import missing\n\ndef f():\n    return 2\n"}
        regular_selection = scoped(base, regular_change, 400000, layout)
        self.assertNotIn("mshop/y.py", regular_selection["critical"])

    def test_standard_library_and_third_party_imports_are_not_unresolved(self):
        base = {"app/__init__.py": "", "app/core.py": "def run():\n    return 1\n",
                "app/logging.py": "LEVEL = 1\n", "app/requests.py": "def get():\n    return None\n",
                "third_party/requests/__init__.py": "def get():\n    return None\n",
                "scripts/json.py": "DUMP = 1\n", "scripts/tool.py": "import json\n",
                "tests/__init__.py": "", "tests/test_core.py": "import unittest\nfrom app.core import run\n"}
        changed = {"app/core.py": "import os\nimport json\nimport logging\nimport requests\nimport numpy.linalg\n"
                                  "from yaml import safe_load\nfrom . import logging as local_logging\n\n"
                                  "def run():\n    return 2\n",
                   "scripts/json.py": "DUMP = 2\n"}
        selection = scoped(base, changed, layout=trusted.verify_config(top_level_dir="."))
        self.assertEqual((selection["status"], selection["unresolved_imports"]), ("selected", []))
        # A third-party name never resolves to a vendored copy outside the layout.
        self.assertNotIn("third_party/requests/__init__.py", selection["critical"])
        self.assertNotIn("app/requests.py", selection["critical"])

    def test_root_precedence_and_collisions_follow_python(self):
        # Each case: files, sys.path roots, module -> what the resolver says Python loads.
        cases = [
            (["mshop/__init__.py", "mshop/money.py", "lib/mshop/__init__.py", "lib/mshop/money.py"], ["", "lib"],
             {"mshop.money": "mshop/money.py"}),
            (["mshop/extra.py", "lib/mshop/__init__.py", "lib/mshop/money.py"], ["", "lib"],
             {"mshop.money": "lib/mshop/money.py", "mshop": "lib/mshop/__init__.py"}),
            (["mspace/a.py", "lib/mspace/b.py"], ["", "lib"], {"mspace.a": "mspace/a.py", "mspace.b": "lib/mspace/b.py"}),
            (["mutil.py", "mutil/__init__.py"], [""], {"mutil": "mutil/__init__.py"}),
            (["lib/vendor/mtool.py"], ["lib", "lib/vendor"], {"mtool": "lib/vendor/mtool.py",
                                                              "vendor.mtool": "lib/vendor/mtool.py"}),
            (["mcfg.py", "lib/mcfg/__init__.py", "lib/mcfg/sub.py"], ["", "lib"], {"mcfg.sub": None}),
            (["mmod.py", "mmod/sub.py"], [""], {"mmod": "mmod.py", "mmod.sub": None}),
            (["lib/mvend/__init__.py", "vendor/mvend/__init__.py"], ["", "vendor", "lib"],
             {"mvend": "vendor/mvend/__init__.py"}),
        ]
        for files, roots, expected in cases:
            with tempfile.TemporaryDirectory() as d:
                for rel in files:
                    (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                    (Path(d) / rel).write_text("")
                resolver = context.Resolver(files, roots)
                for name, path in expected.items():
                    with self.subTest(files=files, name=name):
                        found = resolver.find(name, roots)
                        self.assertEqual(found and sorted(found), [path] if path else None)
                        program = ("import importlib, os, sys\nsys.path[:0] = %r\n"
                                   "try:\n    m = importlib.import_module(%r)\nexcept ImportError:\n    print('None')\n"
                                   "else:\n    print(os.path.relpath(m.__file__, %r))\n"
                                   % ([os.path.join(d, r) for r in roots], name, d))
                        ran = subprocess.run([sys.executable, "-I", "-B", "-c", program], capture_output=True,
                                             text=True, timeout=60, cwd=d)
                        self.assertEqual(ran.stdout.strip(), str(path), ran.stderr)

    def test_a_default_layout_test_helper_shadows_a_root_module(self):
        base = {"helpers.py": "def make():\n    return 'root'\n", "tests/helpers.py": "def make():\n    return 'tests'\n",
                "tests/test_make.py": "import unittest\nimport helpers\n", "app.py": "def run():\n    return 1\n"}
        selection = scoped(base, {"tests/helpers.py": "def make():\n    return 'changed'\n"})
        self.assertIn("tests/test_make.py", selection["direct_tests"])  # `-s tests` puts tests/ on sys.path
        selection = scoped(base, {"helpers.py": "def make():\n    return 'changed'\n"})
        self.assertNotIn("tests/test_make.py", selection["critical"])  # it never loads the root helpers.py

    @staticmethod
    def initializer_files():
        # tests/test_caller -> caller -> pkg.sub -> pkg.leaf: importing pkg.sub runs pkg/__init__.py,
        # although no module on the chain names the package itself.
        return {"pkg/__init__.py": "MODE = 'safe'\n", "pkg/leaf.py": "def one():\n    return 1\n",
                "pkg/sub.py": "import pkg.leaf\n\ndef cap(x):\n    return x + pkg.leaf.one()\n",
                "caller.py": "import pkg.sub\n\ndef run(x):\n    return pkg.sub.cap(x)\n",
                "far1.py": "import far2\n", "far2.py": "import far3\n", "far3.py": "import pkg.leaf\n",
                "tests/__init__.py": "", "tests/test_caller.py": "import unittest\nimport caller\n" + "# pad\n" * 3000,
                "tests/test_far.py": "import unittest\nimport far1\n",
                "tests/test_leaf.py": "import unittest\nimport pkg.leaf\n"}

    def test_a_changed_package_initializer_reaches_tests_through_submodules(self):
        change = {"pkg/__init__.py": "raise RuntimeError('changed initializer')\n"}
        layout = trusted.verify_config(top_level_dir=".")
        selection = scoped(self.initializer_files(), change, 400000, layout)
        self.assertEqual(selection["status"], "selected")
        self.assertIn("tests/test_caller.py", selection["indirect_tests"])
        self.assertNotIn("tests/test_far.py", selection["critical"])  # four hops: the bound still holds
        self.assertEqual(context.TEST_HOPS, 3)
        selection = scoped(self.initializer_files(), change, 6000, layout)
        self.assertEqual(selection["status"], "incomplete-critical-context")
        self.assertEqual(selection["critical_omitted"], ["tests/test_caller.py"])
        self.assertIn("tests/test_leaf.py", selection["critical"])
        # A changed submodule does not make tests of its sibling modules critical.
        selection = scoped(self.initializer_files(), {"pkg/sub.py": "def cap(x):\n    return x\n"}, 400000, layout)
        self.assertNotIn("tests/test_leaf.py", selection["critical"])
        # A changed module whose stem collides with a directory name is not a package initializer.
        collision = {
            "mmod.py": "VALUE = 1\n",
            "mmod/sub.py": "def helper():\n    return 1\n",
            "caller.py": "import mmod.sub\n",
            "tests/__init__.py": "",
            "tests/test_sub.py": "import unittest\nimport caller\n",
        }
        selection = scoped(collision, {"mmod.py": "VALUE = 2\n"}, 400000, layout)
        self.assertNotIn("tests/test_sub.py", selection["indirect_tests"])
        self.assertNotIn("tests/test_sub.py", selection["critical"])

    @staticmethod
    def reexport_files():
        return {"pkg/__init__.py": "from .impl import rate\nfrom .other import unused\n"
                                   "try:\n    from ._fast import speed\nexcept ImportError:\n    from ._slow import speed\n"
                                   "from .nested import depth\nfrom .star import *\n"
                                   "if True:\n    from .cond import flag\n",
                "pkg/cond.py": "flag = 1\n",
                "pkg/impl.py": "def rate():\n    return 3\n" + "# pad\n" * 3000,
                "pkg/other.py": "def unused():\n    return 0\n", "pkg/_fast.py": "def speed():\n    return 1\n",
                "pkg/_slow.py": "def speed():\n    return 1\n", "pkg/star.py": "def wild():\n    return 1\n",
                "pkg/nested/__init__.py": "from .deep import depth\n",
                "pkg/nested/deep/__init__.py": "from .deepest import depth\n",
                "pkg/nested/deep/deepest.py": "def depth():\n    return 3\n",
                "app.py": "from pkg import rate\n\ndef total(x):\n    return x * rate()\n",
                "tests/__init__.py": "", "tests/test_app.py": "import unittest\nimport app\n"}

    def critical_for(self, line):
        change = {"app.py": line + "\n\ndef total(x):\n    return x + 1\n"}
        return set(scoped(self.reexport_files(), change, layout=trusted.verify_config(top_level_dir="."))["critical"])

    def test_a_reexported_definition_is_critical_and_bounded(self):
        self.assertIn("pkg/impl.py", self.critical_for("from pkg import rate"))
        self.assertNotIn("pkg/other.py", self.critical_for("from pkg import rate"))  # not imported, not followed
        self.assertTrue({"pkg/_fast.py", "pkg/_slow.py"} <= self.critical_for("from pkg import speed"))
        self.assertIn("pkg/star.py", self.critical_for("from pkg import wild"))
        self.assertIn("pkg/cond.py", self.critical_for("from pkg import flag"))
        nested = self.critical_for("from pkg import depth")
        self.assertIn("pkg/nested/deep/__init__.py", nested)  # two initializers: the bound
        self.assertNotIn("pkg/nested/deep/deepest.py", nested)
        self.assertEqual(context.REEXPORT_DEPTH, 2)
        change = {"app.py": "from pkg import rate\n\ndef total(x):\n    return x * rate() + 1\n"}
        layout = trusted.verify_config(top_level_dir=".")
        selection = scoped(self.reexport_files(), change, 6000, layout)
        self.assertEqual(selection["status"], "incomplete-critical-context")  # was a silent "selected"
        self.assertIn("pkg/impl.py", selection["critical_omitted"])

    def test_tests_follow_the_configured_directory_and_pattern(self):
        layout = trusted.verify_config(test_dir="qa", top_level_dir=".", pattern="check_*.py")
        self.assertTrue(context.is_test("qa/check_calc.py", layout))
        self.assertFalse(context.is_test("qa/check_calc.py"))
        self.assertFalse(context.is_test("qa/helpers.py", layout))
        self.assertFalse(context.is_test("other/check_calc.py", layout))
        self.assertTrue(context.is_test("qa/testcalc.py", trusted.verify_config(test_dir="qa", top_level_dir=".")))
        base = {"calc/__init__.py": "from calc.core import add\n", "calc/core.py": "def add(a, b):\n    return a + b\n",
                "qa/__init__.py": "", "qa/check_calc.py": "import unittest\nimport calc\n"}
        change = {"calc/core.py": "def add(a, b):\n    return a - b\n"}
        self.assertIn("qa/check_calc.py", scoped(base, change, layout=layout)["indirect_tests"])
        self.assertNotIn("qa/check_calc.py", scoped(base, change)["indirect_tests"])


@RUNTIME
class ScopedReviewEngineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".scoped-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def shop(self, money_padding=0, change_padding=0, prefix="", extra=None):
        name = "%s%d-%d" % (prefix.replace("/", "-"), money_padding, change_padding)
        source = self.root / ("shop-fixture-" + name)
        for path, text in dict(shop_files(money_padding, prefix), **(extra or {})).items():
            (source / path).parent.mkdir(parents=True, exist_ok=True)
            (source / path).write_text(text)
        repo = self.root / ("shop-" + name)
        change = self.root / ("shop-change-" + name)
        (change / prefix / "shop").mkdir(parents=True)
        (change / prefix / "shop" / "checkout.py").write_text(DEFECT + "# changed line\n" * change_padding)
        return repo, fixture.make_fixture(repo, source), change

    def verified(self, repo, base, change, scenario="pass", review_context="scoped", budget=None, engine=None,
                 verify=None):
        engine = engine or self.engine
        self.serial += 1
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text("Simplify checkout.\napply-dir: %s\nreview-scenario: %s\n" % (change, scenario))
        task_id = engine.start(repo, base, task, "test-model", review_model="test-reviewer",
                               review_context=review_context, review_budget=budget,
                               verify=verify or trusted.verify_config(top_level_dir="."))["id"]
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
        schema = json.loads(record["argv"][record["argv"].index("--json-schema") + 1])
        self.assertIn("context_sha256", schema["required"])
        changed = {f["path"] for f in self.store.artifact(task_id, "changes")["files"]}
        self.assertEqual(schema["properties"]["findings"]["items"]["properties"]["file"]["enum"],
                         sorted(set(scope["included"]) | changed) + [None])
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

    def test_the_task_layout_reaches_the_selector(self):
        extra = {
            "examples/trusted-local/fixture/calc.py": (ROOT / "examples/trusted-local/fixture/calc.py").read_text(),
            "examples/trusted-local/fixture/tests/test_calc.py": (
                ROOT / "examples/trusted-local/fixture/tests/test_calc.py"
            ).read_text(),
        }
        repo, base, change = self.shop(prefix="lib/", extra=extra)
        task_id = self.verified(repo, base, change, verify=trusted.verify_config(top_level_dir=".", pythonpath=["lib"]))
        self.assertEqual(self.engine.review(task_id, str(FAKE_CLAUDE))["review"]["outcome"], "completed")
        scope = self.record(task_id)["context"]
        self.assertEqual((scope["status"], scope["policy"], scope["unresolved_imports"]),
                         ("selected", "maestro-scoped-context-v3", []))
        for path in ("lib/shop/money.py", "lib/shop/gateway.py", "tests/test_checkout.py"):
            self.assertIn(path, scope["included"])
        self.assertNotIn("examples/trusted-local/fixture/calc.py", scope["included"])
        self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")

    def test_an_import_root_hidden_from_the_layout_is_never_sent(self):
        # Verification passes because the test package edits sys.path itself; the layout never says so.
        hack = ("import os\nimport sys\n\n"
                "sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib'))\n")
        repo, base, change = self.shop(prefix="lib/", extra={"tests/__init__.py": hack})
        task_id = self.verified(repo, base, change)
        summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
        self.assertEqual(summary["outcome"], "unavailable")
        self.assertIn("scoped review not launched (unresolved-imports)", summary["error"])
        self.assertIn("tests/test_checkout.py imports shop.checkout (lib/shop/checkout.py)", summary["error"])
        self.assertFalse((self.store.task_dir(task_id) / "review-1" / "stdout.json").exists())
        self.assertEqual(self.record(task_id)["context"]["status"], "unresolved-imports")
        with self.assertRaisesRegex(PolicyError, "review required"):
            self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")

    def test_a_review_chosen_under_an_earlier_policy_never_approves(self):
        repo, base, change = self.shop()
        task_id = self.verified(repo, base, change)
        self.engine.review(task_id, str(FAKE_CLAUDE))
        record = self.record(task_id)
        record["context"]["policy"] = "maestro-scoped-context-v2"
        evidence = dict(self.store.get(task_id)["evidence"], review_sha256=digest(record))
        with self.store.connect() as conn:
            conn.execute("UPDATE artifacts SET body=?,hash=? WHERE task_id=? AND kind='review.1'",
                         (canonical(record).decode(), digest(record), task_id))
            conn.execute("UPDATE tasks SET evidence=? WHERE id=?", (canonical(evidence).decode(), task_id))
        with self.assertRaisesRegex(PolicyError, "used context policy 'maestro-scoped-context-v2', not the current "
                                                 "'maestro-scoped-context-v3'; reject this task and start it again"):
            self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")
        with self.assertRaisesRegex(PolicyError, "a completed review is final"):
            self.engine.review(task_id, str(FAKE_CLAUDE))

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
