"""AUD-03: every changed source byte reaches the reviewer and the approving human as text.

Offline only: no model, network or credentials. A repository's own Git attributes must not
turn a change into an opaque patch, and a Python file is shown the way the interpreter
decodes it (PEP 263), or the review is not launched.
"""
import codecs
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
import reviewer
import trusted
from execution import PolicyError
from workflow import Store

FAKE_PATCH = ROOT / "tests" / "fixtures" / "fake_patch_implementer.py"
FAKE_CLAUDE = ROOT / "tests" / "fixtures" / "fake_claude.py"
spec = importlib.util.spec_from_file_location("visibility_fixture", ROOT / "examples/trusted-local/make_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
RUNTIME = unittest.skipUnless(sys.platform == "darwin" and sys.version_info[:2] == (3, 9),
                              "trusted-local requires macOS and /usr/bin/python3 (Python 3.9)")

UTF8 = b"def add(a, b):\n    return a + b\n"
LATIN1 = b"# -*- coding: latin-1 -*-\n# Caf\xe9 arithmetic\ndef add(a, b):\n    return a + b  # na\xefve\n"
LEGACY = b"# -*- coding: latin-1 -*-\nGREETING = 'Gr\xfc\xdf Gott'\n"
BINARY = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR binary asset"
# Python accepts each of these declarations, but none can be shown faithfully: refused.
REFUSED = {
    "utf-7 (an ASCII comment that runs as code)": b"# coding: utf-7\n# +AAo-import os\nX = 1\n",
    "unicode_escape (an ASCII comment that runs as code)": b"# coding: unicode_escape\n# \\x0aimport os\nX = 1\n",
    "shift_jis (multibyte)": "# coding: shift_jis\nX = '表'\n".encode("shift_jis"),
    "utf-16": "# coding: utf-16\nX = 1\n".encode("utf-16"),
    "unknown declaration": b"# coding: klingon\nX = 1\n",
    "latin-1 bytes, no declaration": b"X = 'caf\xe9'\n",
    "bytes invalid for the declaration": b"# coding: cp1252\nX = '\x81'\n",
}


class TextFormTests(unittest.TestCase):
    def test_utf8_is_unchanged_and_other_files_stay_byte_for_byte(self):
        self.assertEqual(reviewer.text_form("calc.py", UTF8), ({"content": UTF8.decode()}, None))
        self.assertEqual(reviewer.text_form("notes.txt", UTF8), ({"content": UTF8.decode()}, None))
        self.assertEqual(reviewer.text_form("notes.txt", b"caf\xe9\n"), ({"binary": True}, None))
        self.assertEqual(reviewer.text_form("logo.bin", BINARY), ({"binary": True}, None))
        bom = b"\xef\xbb\xbf" + UTF8
        self.assertEqual(reviewer.text_form("calc.py", bom), ({"content": bom.decode("utf-8")}, None))

    def test_a_declared_single_byte_encoding_is_decoded_and_named(self):
        self.assertEqual(reviewer.text_form("calc.py", LATIN1),
                         ({"content": LATIN1.decode("latin-1"), "encoding": "iso8859-1"}, None))
        cp1252 = b"# -*- coding: cp1252 -*-\nX = '\x80'\n"
        self.assertEqual(reviewer.text_form("m.py", cp1252)[0], {"content": "# -*- coding: cp1252 -*-\nX = '€'\n",
                                                                 "encoding": "cp1252"})

    def test_python_files_without_a_faithful_text_are_named_as_problems(self):
        for name, body in REFUSED.items():
            with self.subTest(name):
                view, problem = reviewer.text_form("extra.py", body)
                self.assertEqual(view, {"binary": True})
                self.assertTrue(problem)

    def test_the_allowlist_is_single_byte_and_ascii_compatible(self):
        ascii_text = "".join(map(chr, range(128)))
        for name in sorted(reviewer.SOURCE_ENCODINGS):
            with self.subTest(name):
                self.assertEqual(codecs.lookup(name).name, name)
                self.assertEqual(bytes(range(128)).decode(name), ascii_text)
                for byte in range(128, 256):
                    try:
                        self.assertEqual(len(bytes([byte]).decode(name)), 1)
                    except UnicodeDecodeError:
                        pass  # undefined in this code page: such a file fails closed

    def test_changed_python_without_text_fails_closed_and_deletions_do_not(self):
        bodies = {"calc.py": UTF8, "extra.py": REFUSED["latin-1 bytes, no declaration"]}
        reviewer.require_text([{"status": "M", "path": "calc.py"}], bodies.__getitem__)
        with self.assertRaisesRegex(reviewer.UnreadableSource, "extra.py"):
            reviewer.require_text([{"status": "A", "path": "extra.py"}], bodies.__getitem__)
        reviewer.require_text([{"status": "D", "path": "gone.py"}], bodies.__getitem__)
        self.assertTrue(issubclass(reviewer.UnreadableSource, PolicyError))

    def test_a_patch_that_is_not_utf8_says_so(self):
        self.assertEqual(reviewer.patch_fields(UTF8), {"patch": UTF8.decode()})
        fields = reviewer.patch_fields(LATIN1)
        self.assertIn("�", fields["patch"])
        self.assertEqual(fields["patch_note"], reviewer.PATCH_NOTE)


@RUNTIME
class PatchVisibilityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".visibility-tests-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        source = self.root / "fixture"
        for path in (ROOT / "examples/trusted-local/fixture").rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                target = source / path.relative_to(ROOT / "examples/trusted-local/fixture")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
        (source / "legacy.py").write_bytes(LEGACY)
        (source / "assets").mkdir()
        (source / "assets" / "logo.bin").write_bytes(BINARY)
        self.repo = self.root / "repo"
        self.base = fixture.make_fixture(self.repo, source)
        self.store = Store(self.root / "state")
        self.engine = trusted.TrustedEngine(self.store, test_context=True)
        self.serial = 0

    def verified(self, files, delete=(), review_context="full"):
        self.serial += 1
        change = self.root / ("change-%d" % self.serial)
        for rel, body in files.items():
            (change / rel).parent.mkdir(parents=True, exist_ok=True)
            (change / rel).write_bytes(body)
        change.mkdir(exist_ok=True)
        task = self.root / ("TASK-%d.md" % self.serial)
        task.write_text("Implement calc.add.\napply-dir: %s\n%s" % (change, "".join("delete: %s\n" % d for d in delete)))
        task_id = self.engine.start(self.repo, self.base, task, "test-model", review_model="test-reviewer",
                                    review_context=review_context)["id"]
        self.assertEqual(self.engine.implement(task_id, str(FAKE_PATCH))["status"], "reviewing")
        self.assertEqual(self.engine.verify(task_id)["status"], "awaiting_approval", self.store.events(task_id))
        return task_id

    def reviewed(self, task_id):
        summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
        record = self.store.artifact(task_id, "review.1")
        data = (self.store.task_dir(task_id) / record["input"]["path"]).read_bytes()
        return summary, json.loads(data.split(b"\n", 1)[1])

    @staticmethod
    def section(patch, path):
        lines, inside = [], False
        for line in patch.splitlines():
            if line.startswith("diff --git"):
                inside = line.startswith("diff --git a/%s " % path)
            elif inside:
                lines.append(line)
        return "\n".join(lines)

    def git(self, cwd, *args):
        return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
                               "-C", str(cwd), *args], capture_output=True, check=True).stdout

    def assert_export_reproduces_the_approved_tree(self, task_id):
        snap = self.store.artifact(task_id, "snapshot")
        shown = self.engine.diff(task_id)
        self.engine.approve(task_id, snap["sha256"], "Offline test human")
        exported = Path(self.engine.export(task_id)["path"]).read_bytes()
        self.assertEqual(shown, exported)  # the human sees exactly what is exported
        check = self.root / ("apply-%s" % task_id)
        self.git(self.root, "clone", "-q", "--no-hardlinks", "--no-checkout", str(self.repo), str(check))
        self.git(check, "checkout", "-q", "--detach", self.base)
        (self.root / "export.patch").write_bytes(exported)
        self.git(check, "apply", "--binary", str(self.root / "export.patch"))
        self.git(check, "add", "-A")
        self.assertEqual(self.git(check, "write-tree").decode().strip(), snap["tree"])
        return exported

    def test_declared_latin1_and_opaque_attributes_stay_readable_in_full_and_scoped_review(self):
        cases = {"utf-8 (control)": {"calc.py": UTF8},
                 "declared latin-1": {"calc.py": LATIN1},
                 "*.py binary": {"calc.py": UTF8, ".gitattributes": b"*.py binary\n"},
                 "*.py -diff": {"calc.py": UTF8, ".gitattributes": b"*.py -diff\n"},
                 "latin-1 and *.py binary": {"calc.py": LATIN1, ".gitattributes": b"*.py binary\n"}}
        for review_context in ("full", "scoped"):
            for name, files in cases.items():
                with self.subTest(review_context=review_context, case=name):
                    task_id = self.verified(files, review_context=review_context)
                    summary, payload = self.reviewed(task_id)
                    self.assertEqual(summary["outcome"], "completed", summary)
                    calc = next(f for f in payload["files"] if f["path"] == "calc.py")
                    self.assertEqual(calc["content"], files["calc.py"].decode("latin-1"))
                    self.assertEqual(calc.get("encoding"), "iso8859-1" if files["calc.py"] == LATIN1 else None)
                    self.assertNotIn("binary", calc)
                    patch = self.section(payload["patch"], "calc.py")
                    self.assertNotIn("GIT binary patch", patch)
                    self.assertIn("+    return a + b", patch)
                    self.assertEqual("patch_note" in payload, files["calc.py"] == LATIN1)
                    exported = self.assert_export_reproduces_the_approved_tree(task_id)
                    self.assertIn(b"+" + files["calc.py"].splitlines()[-1], exported)

    def test_real_binary_files_stay_binary_and_deletions_are_shown(self):
        for review_context in ("full", "scoped"):
            with self.subTest(review_context=review_context):
                task_id = self.verified({"calc.py": UTF8, "assets/logo.bin": BINARY + b" v2"},
                                        delete=["legacy.py"], review_context=review_context)
                summary, payload = self.reviewed(task_id)
                self.assertEqual(summary["outcome"], "completed", summary)
                self.assertIn("GIT binary patch", self.section(payload["patch"], "assets/logo.bin"))
                self.assertIn({"status": "D", "path": "legacy.py"}, payload["changed_files"])
                self.assertIn("-GREETING = 'Gr", self.section(payload["patch"], "legacy.py"))
                if review_context == "scoped":
                    legacy = next(f for f in payload["files"] if f["path"] == "legacy.py")
                    self.assertEqual((legacy["source"], legacy["content"], legacy["encoding"]),
                                     ("base-deleted", LEGACY.decode("latin-1"), "iso8859-1"))
                logo = next(f for f in payload["files"] if f["path"] == "assets/logo.bin")
                self.assertEqual((logo.get("binary"), "content" in logo), (True, False))
                self.assert_export_reproduces_the_approved_tree(task_id)

    def test_a_changed_python_file_without_faithful_text_is_never_sent(self):
        for review_context in ("full", "scoped"):
            for name, body in REFUSED.items():
                with self.subTest(review_context=review_context, case=name):
                    task_id = self.verified({"calc.py": UTF8, "extra.py": body}, review_context=review_context)
                    summary = self.engine.review(task_id, str(FAKE_CLAUDE))["review"]
                    self.assertEqual(summary["outcome"], "unavailable", summary)
                    self.assertIn("changed Python file extra.py has no faithful text", summary["error"])
                    self.assertFalse((self.store.task_dir(task_id) / "review-1" / "fake-review.started").exists())
                    self.assertFalse((self.store.task_dir(task_id) / "review-1" / "input.txt").exists())
                    with self.assertRaisesRegex(PolicyError, "review required"):
                        self.engine.approve(task_id, self.store.get(task_id)["evidence"]["snapshot_sha256"], "human")

    def test_repository_attributes_cannot_be_reintroduced_through_git_metadata(self):
        task_id = self.verified({"calc.py": UTF8})
        info = self.store.task_dir(task_id) / "clone" / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "attributes").write_text("*.py binary\n")
        with self.assertRaisesRegex(PolicyError, "unsupported clone metadata: attributes"):
            self.engine.diff(task_id)


if __name__ == "__main__":
    unittest.main()
