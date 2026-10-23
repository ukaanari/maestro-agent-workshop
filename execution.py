"""Bounded POSIX child ownership. No shell, inherited secrets, or agent CLI.

Process-group design adapted from agent-orchestrator v0.14.3 (Apache-2.0),
Copyright 2026 Untrivial. New Python implementation; see UPSTREAM.md.
"""
import errno
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time

GRACE, REAP = 0.15, 2.0     # SIGTERM grace for the whole group; bound for SIGKILL + reap


class PolicyError(RuntimeError):
    pass


class Cancelled(RuntimeError):
    pass


class DeadlineExceeded(RuntimeError):
    pass


def private_env(home):
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home),
            "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}


_PROC_PGRP_ONLY, _PROC_PIDT_SHORTBSDINFO, _SZOMB = 2, 13, 5
_LIBPROC = []


def _libproc():
    """macOS libproc (public <libproc.h>), loaded lazily: this module is also imported
    inside the sandbox, where some interpreters may not load ctypes (issue #7)."""
    if not _LIBPROC:
        lib = None
        if sys.platform == "darwin":
            try:
                import ctypes

                class ShortInfo(ctypes.Structure):  # struct proc_bsdshortinfo
                    _fields_ = [(n, ctypes.c_uint32) for n in ("pid", "ppid", "pgid", "status")] + \
                               [("comm", ctypes.c_char * 16)] + \
                               [(n, ctypes.c_uint32) for n in ("flags", "uid", "gid", "ruid",
                                                               "rgid", "svuid", "svgid", "rfu")]
                lib = (ctypes, ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True), ShortInfo)
            except (ImportError, OSError):
                lib = None
        _LIBPROC.append(lib)
    return _LIBPROC[0]


def process_state(pid):
    """'live', 'gone' (exited, zombie included) or None if it cannot be determined.

    Reads state without reaping. A process whose state is unreadable for any reason
    other than having exited is never reported as gone.
    """
    lib = _libproc()
    if lib is None:
        return None
    ctypes, libproc, ShortInfo = lib
    info = ShortInfo()
    size = libproc.proc_pidinfo(pid, _PROC_PIDT_SHORTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info))
    if size == ctypes.sizeof(info):
        return "gone" if info.status == _SZOMB else "live"
    return "gone" if ctypes.get_errno() == errno.ESRCH else None


def live_members(pgid):
    """Pids of the group's live (non-zombie) members, or None if unknown."""
    lib = _libproc()
    if lib is None:
        return None
    ctypes, libproc, _ = lib
    pids = (ctypes.c_int * 4096)()
    size = libproc.proc_listpids(_PROC_PGRP_ONLY, pgid, pids, ctypes.sizeof(pids))
    if size < 0 or size >= ctypes.sizeof(pids):
        return None
    live = []
    for pid in pids[:size // ctypes.sizeof(ctypes.c_int)]:
        state = process_state(pid) if pid > 0 else "gone"
        if state is None:
            return None
        if state == "live":
            live.append(pid)
    return live


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        # EPERM means no member could be signalled. macOS also answers EPERM for a
        # group holding only unreaped zombies, which cannot act; anything else is fatal.
        live = live_members(pgid)
        if live is None or live:
            raise PolicyError("cannot signal live member(s) %s of owned process group %d"
                              % (live, pgid)) from exc


def _wait_group(pgid, timeout):
    """True once no live member remains, False on timeout, None if unknowable."""
    deadline = time.monotonic() + timeout
    while True:
        live = live_members(pgid)
        if live is None:
            return None
        if not live:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def stop_group(proc):
    """Stop the child's whole process group, then reap the child.

    The child is reaped last: while it is unreaped its pid, and so the group id,
    cannot be reused, so no signal can reach a stranger. Every member gets the
    SIGTERM grace, not only the child. Descendants that left the group (setsid,
    setpgid) are not reached at all; see issue #2. Live-member verification uses
    macOS libproc; where it is unavailable the group is signalled but not verified.
    """
    if proc.returncode is not None:
        return  # already reaped: its pid may belong to someone else now
    pgid = proc.pid
    _signal_group(pgid, signal.SIGTERM)
    _wait_group(pgid, GRACE)
    _signal_group(pgid, signal.SIGKILL)
    if _wait_group(pgid, REAP) is False:
        raise PolicyError("process group %d still has live members after SIGKILL: %s"
                          % (pgid, live_members(pgid)))
    try:
        proc.wait(timeout=REAP)
    except subprocess.TimeoutExpired as exc:
        raise PolicyError("child %d was not reaped after SIGKILL" % pgid) from exc


def _running(proc):
    state = process_state(proc.pid)
    return proc.poll() is None if state is None else state == "live"


def execute(argv, cwd, home, data=b"", timeout=5, cancelled=lambda: False,
            max_output=262144, extra_env=None):
    """Unconfined primitive for fixed coordinator argv (Git, sandbox-exec).

    Untrusted agent code must go through sandbox.Seatbelt.run instead.
    """
    if not 0 < timeout <= 60 or len(data) > 262144:
        raise PolicyError("execution budget exceeded")
    if (not isinstance(argv, list) or not argv or not os.path.isabs(argv[0]) or
            any(not isinstance(a, str) or "\x00" in a for a in argv)):
        raise PolicyError("argv must be a list of strings with an absolute executable")
    if cancelled():
        raise Cancelled("cancelled before launch")
    env = private_env(home)
    env.update(extra_env or {})
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile(dir=home) as source:
        source.write(data)
        source.seek(0)
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=source,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        outputs = [bytearray(), bytearray()]
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((proc.stdout, proc.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                # _running() never reaps: the child stays unreaped until stop_group().
                while selector.get_map() or _running(proc):
                    if cancelled():
                        raise Cancelled("cancelled during execution")
                    if time.monotonic() >= deadline:
                        raise DeadlineExceeded("child execution timed out")
                    if not selector.get_map():
                        time.sleep(0.025)
                    for key, _ in selector.select(0.025) if selector.get_map() else ():
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            outputs[key.data].extend(chunk)
                            if sum(map(len, outputs)) > max_output:
                                raise PolicyError("child output limit exceeded")
                stop_group(proc)  # stragglers still in the group, then reap the child
                if proc.returncode:
                    raise PolicyError("child exited with code %s: %s" % (
                        proc.returncode, bytes(outputs[1])[:1000].decode("utf-8", "replace")))
                return bytes(outputs[0])
        finally:
            try:
                stop_group(proc)
            finally:
                proc.stdout.close()
                proc.stderr.close()
