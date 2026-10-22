"""Bounded POSIX child ownership. No shell, inherited secrets, or agent CLI.

Process-group design adapted from agent-orchestrator v0.14.3 (Apache-2.0),
Copyright 2026 Untrivial. New Python implementation; see UPSTREAM.md.
"""
import os
import selectors
import signal
import subprocess
import tempfile
import time


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


def stop_group(proc):
    # A child can exit while descendants still hold pipes; own the whole group.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM and proc.poll() is None:
            try:
                proc.wait(timeout=0.15)
            except subprocess.TimeoutExpired:
                pass
    proc.wait(timeout=2)


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
                while selector.get_map() or proc.poll() is None:
                    if cancelled():
                        raise Cancelled("cancelled during execution")
                    if time.monotonic() >= deadline:
                        raise DeadlineExceeded("child execution timed out")
                    for key, _ in selector.select(0.025):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            outputs[key.data].extend(chunk)
                            if sum(map(len, outputs)) > max_output:
                                raise PolicyError("child output limit exceeded")
                if proc.returncode:
                    raise PolicyError("child exited with code %s: %s" % (
                        proc.returncode, bytes(outputs[1])[:1000].decode("utf-8", "replace")))
                return bytes(outputs[0])
        finally:
            stop_group(proc)
            proc.stdout.close()
            proc.stderr.close()
