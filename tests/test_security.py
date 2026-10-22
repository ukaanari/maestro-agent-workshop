"""P1-A: kernel-enforced confinement. Synthetic canaries in private temp dirs only.

Offline by construction: network probes target a loopback listener owned by the
test or TEST-NET-1 (192.0.2.0/24, reserved, unrouted). No personal paths are read.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution import Cancelled, DeadlineExceeded, PolicyError
from sandbox import (SOURCE_DIR, USER_HOME, ExecPolicy, IsolationUnavailable, Seatbelt,
                     python_runtime)
from workflow import Engine, Store

EXE, PREFIX = python_runtime()
# Each probe reports {name: "ok:<value>" | "denied:<Exception>"} as JSON.
PROBE = r'''
import json, os, sys
results = {}
def attempt(name, action):
    try:
        results[name] = "ok:%s" % (action(),)
    except Exception as exc:
        results[name] = "denied:" + type(exc).__name__
'''
REPORT = "\nprint(json.dumps(results))\n"


class ConfinementTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="maestro-p1a-tests-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.root = self.base / "approved"
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True)
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "canary.txt").write_text("SYNTHETIC-CANARY")
        self.guard = self.ws / "guarded"
        self.guard.mkdir()
        (self.guard / "state.txt").write_text("PROTECTED")
        self.sandbox = Seatbelt([str(self.root)], protected=[str(self.guard)], allowed_executables=[EXE])

    def policy(self, code, *args, **overrides):
        values = dict(executable=EXE, args=("-I", "-c", PROBE + code + REPORT) + args,
                      cwd=str(self.ws), home=str(self.ws), writable=(str(self.ws),),
                      readable=(PREFIX,), timeout=10)
        values.update(overrides)
        return ExecPolicy(**values)

    def confined(self, code, *args, sandbox=None, cancelled=lambda: False, **overrides):
        raw = (sandbox or self.sandbox).run(self.policy(code, *args, **overrides), cancelled=cancelled)
        return json.loads(raw)

    # 1. Allowed workspace operations succeed.
    def test_allowed_workspace_operations_succeed(self):
        result = self.confined('''
attempt("write", lambda: open("made.txt", "w").write("inside"))
attempt("mkdir", lambda: os.makedirs("nested/dir") or "made")
attempt("read", lambda: open("made.txt").read())
attempt("rename", lambda: os.rename("made.txt", "nested/dir/moved.txt") or "moved")
attempt("cwd", os.getcwd)
''')
        self.assertEqual(result["write"], "ok:6")
        self.assertEqual(result["read"], "ok:inside")
        self.assertEqual(result["cwd"], "ok:" + str(self.ws))
        self.assertEqual((self.ws / "nested/dir/moved.txt").read_text(), "inside")

    # 2 + 3. Outside reads/writes, traversal, symlink and hardlink escapes, root
    # replacement and protected carve-outs are all denied by the kernel.
    def test_outside_access_and_escape_routes_are_denied(self):
        result = self.confined('''
outside, ws = sys.argv[1], sys.argv[2]
attempt("read", lambda: open(outside + "/canary.txt").read())
attempt("list", lambda: os.listdir(outside))
attempt("stat", lambda: os.stat(outside + "/canary.txt").st_size)
attempt("write", lambda: open(outside + "/planted.txt", "w").write("x"))
attempt("traversal", lambda: open(ws + "/../../outside/canary.txt").read())
os.symlink(outside + "/canary.txt", "link")
attempt("symlink", lambda: open("link").read())
attempt("hardlink", lambda: os.link(outside + "/canary.txt", "hard"))
attempt("rename_root", lambda: os.rename(ws, ws + "-moved"))
attempt("chmod_root", lambda: os.chmod(ws, 0o777))
attempt("protected_read", lambda: open("guarded/state.txt").read())
attempt("protected_write", lambda: open("guarded/new.txt", "w").write("x"))
attempt("system_secret_file", lambda: open("/etc/passwd").read(1))
attempt("shared_tmp", lambda: os.listdir("/private/tmp"))
''', str(self.outside), str(self.ws))
        for name, outcome in result.items():
            with self.subTest(probe=name):
                self.assertEqual(outcome, "denied:PermissionError")
        self.assertEqual(sorted(os.listdir(self.outside)), ["canary.txt"])
        self.assertEqual((self.outside / "canary.txt").read_text(), "SYNTHETIC-CANARY")
        self.assertEqual(sorted(os.listdir(self.guard)), ["state.txt"])
        self.assertTrue(self.ws.is_dir())

    def test_engine_sandbox_keeps_maestro_state_out_of_reach(self):
        store = Store(self.base / "state")
        engine = Engine(store)
        task_id = store.create("State isolation fixture")
        self.assertEqual(engine.run(task_id)["status"], "awaiting_approval")
        task_dir = store.task_dir(task_id)
        home = str(task_dir / "home")
        result = json.loads(engine.sandbox(task_id).run(ExecPolicy(
            EXE, ("-I", "-c", PROBE + '''
root, task = sys.argv[1], sys.argv[2]
attempt("database", lambda: open(root + "/state.sqlite3", "rb").read(1))
attempt("marker", lambda: open(root + "/MAESTRO-P0").read())
attempt("git_config", lambda: open(task + "/repo.git/config").read())
attempt("lock", lambda: open(task + "/executor.lock", "w"))
attempt("worktree", lambda: open(task + "/worktree/result.txt").read())
attempt("other_tasks", lambda: os.listdir(root + "/tasks"))
''' + REPORT, str(store.root), str(task_dir)), home, home, (home,), (PREFIX,))))
        for name, outcome in result.items():
            with self.subTest(probe=name):
                self.assertEqual(outcome, "denied:PermissionError")
        for grant in ("repo.git", "executor.lock"):
            with self.subTest(grant=grant), self.assertRaises(PolicyError):
                engine.sandbox(task_id).validate(ExecPolicy(
                    EXE, (), home, home, (home,), (str(task_dir / grant),)))
        self.assertTrue(engine.check_evidence(task_id))

    # 4. External network access is denied (loopback control proves the listener works).
    def test_network_is_denied(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        listener.accept()[0].close()
        local = socket.socket(socket.AF_UNIX)
        self.addCleanup(local.close)
        local.bind(str(self.base / "u.sock"))
        local.listen(1)
        result = self.confined('''
import socket
port = int(sys.argv[1])
attempt("loopback_tcp", lambda: socket.create_connection(("127.0.0.1", port), timeout=2))
attempt("external_tcp", lambda: socket.create_connection(("192.0.2.1", 443), timeout=2))
attempt("external_udp", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 53)))
attempt("unix_socket", lambda: socket.socket(socket.AF_UNIX).connect(sys.argv[2]))
''', str(port), str(self.base / "u.sock"))
        for name, outcome in result.items():
            with self.subTest(probe=name):
                self.assertEqual(outcome, "denied:PermissionError")
        for server in (listener, local):
            server.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                server.accept()

    def test_process_isolation_env_signals_and_inspection(self):
        os.environ["MAESTRO_P1A_PARENT_SECRET"] = "SYNTHETIC-PARENT-CANARY"
        self.addCleanup(os.environ.pop, "MAESTRO_P1A_PARENT_SECRET", None)
        sibling = subprocess.Popen([EXE, "-I", "-c", "import time; time.sleep(30)"],
                                   env={"MAESTRO_P1A_SIBLING_SECRET": "SYNTHETIC-SIBLING-CANARY"})
        self.addCleanup(sibling.wait)
        self.addCleanup(sibling.kill)
        result = self.confined('''
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
def procargs(pid):
    mib, size = (ctypes.c_int * 3)(1, 49, pid), ctypes.c_size_t(65536)
    buf = ctypes.create_string_buffer(65536)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        raise PermissionError("procargs")
    return b"SYNTHETIC" in buf.raw[:size.value]
def pidpath(pid):
    buf = ctypes.create_string_buffer(4096)
    if libc.proc_pidpath(pid, buf, 4096) <= 0:
        raise PermissionError("pidpath")
    return buf.value
results["env"] = sorted(os.environ)
attempt("signal_parent", lambda: os.kill(os.getppid(), 0))
attempt("signal_launchd", lambda: os.kill(1, 0))
attempt("sibling_environment", lambda: procargs(int(sys.argv[1])))
attempt("parent_executable", lambda: pidpath(os.getppid()))
attempt("fork", lambda: os.fork() or os._exit(0))
''', str(sibling.pid), env=(("NO_COLOR", "1"),))
        self.assertEqual(result.pop("env"), ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT",
                                             "HOME", "LC_ALL", "NO_COLOR", "PATH", "TMPDIR"])
        for name, outcome in result.items():
            with self.subTest(probe=name):
                self.assertEqual(outcome, "denied:PermissionError")

    def test_forked_children_stay_confined_and_cannot_exec_shells(self):
        result = self.confined('''
import subprocess
for name, argv in (("shell", ["/bin/sh", "-c", "true"]), ("sandbox_exec", ["/usr/bin/sandbox-exec", "-n", "no-network", "/usr/bin/true"]),
                   ("other_binary", ["/usr/bin/true"])):
    attempt(name, lambda: subprocess.run(argv).returncode)
attempt("python_child_reads_outside", lambda: subprocess.run([sys.executable, "-I", "-c",
    "open(%r).read()" % (sys.argv[1] + "/canary.txt")], capture_output=True).returncode)
attempt("python_child_ok", lambda: subprocess.run([sys.executable, "-I", "-c", "print(1)"], capture_output=True).stdout)
''', str(self.outside), allow_fork=True)
        for name in ("shell", "sandbox_exec", "other_binary"):
            self.assertEqual(result[name], "denied:PermissionError", name)
        self.assertEqual(result["python_child_reads_outside"], "ok:1")
        self.assertEqual(result["python_child_ok"], "ok:b'1\\n'")

    # 5. Timeouts stop running processes, including forked descendants.
    def test_timeout_stops_confined_process_tree(self):
        start = time.monotonic()
        with self.assertRaises(DeadlineExceeded):
            self.confined('''
import subprocess, time
subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(1); open('late.txt', 'w').write('x')"])
time.sleep(30)
''', allow_fork=True, timeout=0.5)
        self.assertLess(time.monotonic() - start, 5)
        time.sleep(1.3)
        self.assertFalse((self.ws / "late.txt").exists())

    # 6. Cancellation cleans up child processes.
    def test_cancellation_kills_confined_children(self):
        marker = self.ws / "child.pid"
        with self.assertRaises(Cancelled):
            self.confined('''
import subprocess, time
subprocess.Popen([sys.executable, "-I", "-c",
    "import os, time; open('child.pid', 'w').write(str(os.getpid())); time.sleep(1); open('late.txt', 'w').write('x')"])
time.sleep(30)
''', allow_fork=True, timeout=10, cancelled=lambda: marker.exists() and marker.stat().st_size > 0)
        pid = int(marker.read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("cancelled child process %d survived" % pid)
        time.sleep(1.2)
        self.assertFalse((self.ws / "late.txt").exists())

    def test_output_limit_applies_to_confined_process(self):
        with self.assertRaises(PolicyError):
            self.confined('sys.stdout.write("x" * 5000)', max_output=1000)

    # 7. Invalid execution policies are rejected before anything launches.
    def test_invalid_policies_are_rejected(self):
        ws, outside = str(self.ws), str(self.outside)
        bad = {
            "unlisted executable": dict(executable="/usr/bin/true"),
            "relative executable": dict(executable="python3"),
            "symlinked path": dict(writable=("/tmp",), cwd="/tmp", home="/tmp"),
            "traversal path": dict(writable=(ws + "/../workspace",)),
            "outside approved root": dict(writable=(outside,), cwd=outside, home=outside),
            "approved root itself": dict(writable=(str(self.root),)),
            "cwd outside workspace": dict(cwd=outside),
            "home outside workspace": dict(home=outside),
            "grant inside protected": dict(writable=(ws, str(self.guard))),
            "network allowed": dict(network="allow"),
            "zero timeout": dict(timeout=0),
            "excessive timeout": dict(timeout=61),
            "string timeout": dict(timeout="5"),
            "nan timeout": dict(timeout=float("nan")),
            "excessive output": dict(max_output=10 ** 9),
            "list arguments": dict(args=["-c", "1"]),
            "nul argument": dict(args=("-c", "1\x00")),
            "loader injection": dict(env=(("DYLD_INSERT_LIBRARIES", "/x.dylib"),)),
            "path override": dict(env=(("PATH", "/tmp"),)),
            "read root": dict(readable=("/",)),
            "read user home": dict(readable=(USER_HOME,)),
            "read source subtree": dict(readable=(SOURCE_DIR,)),
            "read subtree containing protected": dict(readable=(ws,)),
            "list user home": dict(listable=(USER_HOME,)),
            "no workspace": dict(writable=()),
        }
        for name, change in bad.items():
            with self.subTest(policy=name), self.assertRaises(PolicyError):
                self.sandbox.validate(self.policy("pass", **change))
        with self.assertRaises(PolicyError):
            self.sandbox.validate({"executable": EXE})
        shell = Seatbelt([str(self.root)], allowed_executables=["/bin/sh"])
        with self.assertRaises(PolicyError):
            shell.validate(self.policy("pass", executable="/bin/sh"))
        for root in ("/", USER_HOME, str(Path(USER_HOME).parent)):
            with self.subTest(root=root), self.assertRaises(PolicyError):
                Seatbelt([root], allowed_executables=[EXE])

    # 8. Missing or non-enforcing isolation fails closed without starting the target.
    def test_missing_isolation_fails_closed(self):
        missing = Seatbelt([str(self.root)], allowed_executables=[EXE],
                           binary=str(self.base / "absent" / "sandbox-exec"))
        with self.assertRaises(IsolationUnavailable):
            self.confined('open("launched.txt", "w").write("x")', sandbox=missing)
        self.assertFalse((self.ws / "launched.txt").exists())

    def test_non_enforcing_sandbox_is_detected(self):
        stub_dir = self.base / "stub"
        stub_dir.mkdir()
        stub = stub_dir / "sandbox-exec"
        # Simulates a broken engine: drops every option and runs the target unconfined.
        stub.write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do case "$1" in -p|-f|-D|-n) shift 2;; '
                        '*) break;; esac; done\nexec "$@"\n')
        stub.chmod(0o700)
        fake = Seatbelt([str(self.root)], allowed_executables=[EXE], binary=str(stub))
        with self.assertRaises(IsolationUnavailable):
            self.confined('open(sys.argv[1] + "/escaped.txt", "w").write("x")', str(self.outside), sandbox=fake)
        self.assertFalse((self.outside / "escaped.txt").exists())

    def test_engine_blocks_task_when_isolation_missing(self):
        store = Store(self.base / "state")
        engine = Engine(store, sandbox_binary=str(self.base / "absent" / "sandbox-exec"))
        task_id = store.create("Isolation-missing fixture")
        result = engine.run(task_id)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("sandbox engine missing", store.events(task_id)[-1]["message"])
        with self.assertRaises(PolicyError):
            store.artifact(task_id, "handoff")
        self.assertEqual(engine.workspace(task_id).snapshot()["files"], {})


if __name__ == "__main__":
    unittest.main()
