# Research: Feasibility of a Linux Sandbox Backend

**Status:** Research only (Issue #23). **Linux is NOT supported today.** On Linux, MAESTRO's
existing confinement path fails closed (`IsolationUnavailable` → `blocked`) with no unconfined
fallback. Existing macOS Seatbelt results do **not** establish Linux security.

---

## 1. Candidate Linux Isolation Approaches

MAESTRO's constraints (`CONTRIBUTING.md`, `P1A-SECURITY.md`): Python standard library only,
fail-closed startup with per-launch self-test, zero unconfined fallback, no root daemon required
for normal developer runs, and verifiable isolation of filesystem, network, process inspection,
signals, and descendant cleanup.

Heavyweight daemons (Docker, Podman with rootful daemon, VMs) are excluded as primary local
prerequisites for the same reason they were excluded on macOS in `P1A-SECURITY.md`. Two viable
native Linux mechanisms were evaluated:

### Candidate A (Primary): `bubblewrap` (`bwrap`) + Linux Namespaces + `seccomp-bpf` + cgroups v2

* **Mechanism:** Uses unprivileged user namespaces (`CLONE_NEWUSER`) combined with mount
  (`CLONE_NEWNS`), PID (`CLONE_NEWPID`), network (`CLONE_NEWNET`), IPC (`CLONE_NEWIPC`), and UTS
  (`CLONE_NEWUTS`) namespaces via `/usr/bin/bwrap` (with `--unshare-all`, `--die-with-parent`,
  `--new-session`, `--clearenv`, `--ro-bind` for allowlisted runtime/source paths, `--bind` for
  writable task workspace, `--tmpfs` over masked paths, and `--seccomp FD` for a precompiled BPF
  filter). Process cleanup and resource limits pair `CLONE_NEWPID` (killing PID 1 kills every
  descendant in the namespace!) with a delegated **cgroups v2** leaf cgroup (`cgroup.kill`,
  `memory.max`, `pids.max`).
* **Prerequisites:**
  * Linux kernel ≥ 5.10 (≥ 5.14 for `cgroup.kill`; ≥ 5.15+ recommended).
  * `/usr/bin/bwrap` installed from distro package (verified canonical, root-owned, non-writable).
  * Unprivileged user namespaces permitted by host kernel/AppArmor policy.
    * **Operational caveat:** Ubuntu 24.04+ enables `kernel.apparmor_restrict_unprivileged_userns=1`
      by default, which blocks unprivileged userns unless an AppArmor profile permits `bwrap`
      (Ubuntu's packaged `bubblewrap` ships `/etc/apparmor.d/bwrap`, whereas custom binaries do not).
      Debian hardened kernels may also disable `kernel.unprivileged_userns_clone`.
  * For cgroups v2 limits: systemd user slice delegation (`systemd-run --user --scope` or a
    delegated user cgroup directory).
* **Threat boundary:** Strongest unprivileged isolation on Linux. Mount namespaces completely hide
  `$HOME`, `.maestro/`, and unrelated host files (the sandboxed process never even sees their
  directory entries). `CLONE_NEWNET` creates an isolated loopback-only network namespace with zero
  host connectivity. `CLONE_NEWPID` completely prevents inspecting or signalling host processes and
  eliminates the `#2` `setsid()`/double-fork escape gap because the kernel SIGKILLs every process
  in a PID namespace when its init process exits.
* **Trade-offs:** Requires one small distro binary (`/usr/bin/bwrap`) and unprivileged user
  namespaces; kernel userns attack surface must stay patched.

### Candidate B (Secondary): Landlock LSM + `seccomp-bpf` + `PR_SET_NO_NEW_PRIVS` + `setrlimit`

* **Mechanism:** Applied in-process (or in a small stdlib/ctypes pre-exec helper) using Linux
  syscalls `landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self` for
  filesystem (and TCP port on ABI v4+, kernel ≥ 6.7) restriction, plus `prctl(PR_SET_NO_NEW_PRIVS)`
  and `seccomp(SECCOMP_SET_MODE_FILTER)` to block `socket`/`fork`/`ptrace`/etc., and `setrlimit`
  for basic resource bounds.
* **Prerequisites:**
  * Linux kernel ≥ 5.13 for Landlock ABI v1 (filesystem); **≥ 6.7 for ABI v4** (TCP bind/connect
    network rules; UDP/Unix sockets still require seccomp!).
  * Does **not** require `bwrap` or unprivileged user namespaces.
* **Threat boundary & critical limitations:**
  * **No PID/mount/network namespace isolation on its own:** Processes can still see `/proc` PIDs
    (unless `/proc` is blocked by Landlock), cannot mask protected files cleanly if rename races
    exist without careful Landlock rules, and **cannot close Issue #2** (`setsid()`/double-fork
    children still escape process-group cleanup unless combined with `CLONE_NEWPID` or cgroups v2).
  * **High stdlib complexity:** Constructing architecture-specific `seccomp-bpf` bytecode and
    Landlock C structs via Python `ctypes` across `x86_64` and `aarch64` is error-prone and hard
    to audit cleanly compared to `bwrap`.
* **Trade-offs:** Works in environments where unprivileged user namespaces are disabled (e.g.,
  nested unprivileged containers), but provides weaker process/namespace isolation and does not
  solve `#2` alone.

### Summary Comparison

| Criterion | Candidate A (`bwrap` + namespaces + cgroups v2) | Candidate B (Landlock + seccomp, no userns) |
|---|---|---|
| Filesystem deny-default | Mount namespace (complete hiding) | Landlock allowlist (paths stay visible in stat/parent) |
| Network isolation | `CLONE_NEWNET` (zero host routes, kernel-enforced) | Landlock v4 (TCP only, kernel ≥ 6.7) + seccomp for UDP/AF_UNIX |
| Process visibility & signals | `CLONE_NEWPID` + private `/proc` (complete) | Needs `/proc` deny + `ptrace`/signal seccomp |
| Escaped descendants (#2) | **Solved** by `CLONE_NEWPID` + `cgroup.kill` | **Not solved** without PID ns or cgroups v2 |
| Resource limits (#5) | cgroups v2 (`memory.max`, `pids.max`, `cpu.max`) + `RLIMIT_*` | `RLIMIT_*` only (per-process, weak against forks) |
| External dependency | `/usr/bin/bwrap` | None (but raw `ctypes` syscalls + BPF per arch) |
| Restricted-userns environments | Blocked (fails closed → `blocked`) | Works on kernel ≥ 6.7 |

---

## 2. Mapping `P1A-SECURITY.md` Guarantees & Known Gaps to Linux Controls

| Existing Guarantee / Gap (`P1A-SECURITY.md`) | Proposed Linux Control (Candidate A) | Adversarial Test Required |
|---|---|---|
| Deny-default filesystem; outside read/list/stat/write denied | Empty root `--tmpfs /` + minimal `--ro-bind` (Python runtime, `/usr/lib`, `/lib*`) + `--bind` only on approved disposable workspace | Attempt read/list/stat of `/etc/passwd`, `$HOME`, `/tmp`, and sibling tasks; assert `FileNotFoundError`/`PermissionError` |
| Protected direct-child paths (F-01 rename bypass) | Never mount `.maestro/` or `repo.git` at all; mount disposable workspace only, or overlay read-only/empty `--ro-bind /dev/null` on protected files inside a non-renameable parent | Attempt `rename`, `unlink`, hardlink, symlink, and `renameat2(RENAME_EXCHANGE)` against protected paths |
| Network denied (`network="deny"`) | `--unshare-net` (isolated loopback-only netns; optionally seccomp `AF_INET`/`AF_INET6`/`AF_UNIX` deny) | Attempt TCP/UDP to `127.0.0.1` host listener, `192.0.2.1`, DNS, and abstract/path Unix sockets; verify host listener receives nothing |
| Exec allowlist; no shells/interpreters outside allowlist | Bind-mount only the allowlisted Python prefix read-only; do NOT bind `/bin/sh`, `/usr/bin/env`, `sudo`, etc. (plus optional seccomp/Landlock) | With `allow_fork=True`, attempt `execve("/bin/sh")` and `/usr/bin/true`; assert denial |
| Process-info isolation (sibling argv/env) | `--unshare-pid --proc /proc` (container only sees its own PIDs) | Probe `/proc/<parent_pid>/cmdline`, `/proc/<parent_pid>/environ`, `/proc/1` host info; assert absent/denied |
| Signal isolation | `CLONE_NEWPID` + `CLONE_NEWUSER` | Attempt `os.kill(parent_pid, 0)` and `SIGUSR1`; assert `ProcessLookupError`/`PermissionError` |
| Environment scrubbing | `--clearenv` + explicit `--setenv` allowlist only | Verify canary secrets, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH` never arrive |
| **Gap #2: Escaped descendants (`setsid`/double-fork)** | `CLONE_NEWPID` (init death reaps entire PID ns) + `--die-with-parent` + cgroups v2 `cgroup.kill` + `/proc` verification | Spawn `setsid()` + double-fork survivor; trigger timeout and cancellation; verify zero surviving PIDs in cgroup/host |
| **Gap #3: Controlled network/credentials (future P1-B)** | Keep `--unshare-net`; expose MAESTRO loopback CONNECT proxy strictly via a single bind-mounted Unix socket bridge (or restricted loopback helper), never host network | Verify direct external TCP/UDP/DNS fails while allowlisted proxy host succeeds and non-allowlisted hosts are denied |
| **Gap #4: Snapshot-bound verification** | Same `trusted.py` materialize-from-tree + re-snapshot flow, with `bwrap` replacing `Seatbelt` | Mutate `clone/` during verification; assert verification fails and cannot approve |
| **Gap #5: Resource limits** | cgroups v2 (`memory.max`, `pids.max`, `cpu.max`) + `RLIMIT_FSIZE` / `RLIMIT_NOFILE` / `RLIMIT_CPU` | Fork-bomb, memory-allocation bomb, and oversized-file-write probes fail closed within budget |
| **Fail-closed startup & self-test (F-03)** | Verify canonical root-owned `/usr/bin/bwrap`, run pre-launch self-test proving outside write fails (nonzero exit) AND inside write succeeds; any missing prereq or AppArmor/userns denial raises `IsolationUnavailable` → task ends `blocked` | Missing `bwrap`, non-enforcing fake `bwrap`, disabled `unprivileged_userns`, and symlinked engine binary all fail closed with `blocked` and zero unconfined fallback |

---

## 3. Offline Proof-of-Concept Status & Blocker

### 3.1 Observed Host Environment and Blocker

* **Development host:** macOS 26.7 (arm64).
* **Blocker:** No Linux kernel, Linux host, or local Linux container/VM runtime is available on
  this machine, and MAESTRO's offline workflow forbids contacting external services or installing
  hypervisors/containers. Therefore, **no live Linux proof-of-concept was executed here.**
* **Observed vs. assumed:** Everything in Sections 1–2 about Linux namespaces, `bwrap`, AppArmor
  on Ubuntu 24.04, Landlock ABI versions, and cgroups v2 is architecture analysis based on Linux
  kernel interfaces — **not** host-verified evidence.

### 3.2 Reproducible Linux Proof-of-Concept Plan (For a Dedicated Linux Host / CI Runner)

To validate Candidate A offline on a real Linux machine (e.g., GitHub-hosted `ubuntu-24.04` or
Debian 12 with `bubblewrap` installed):

```sh
# 1. Record exact kernel, distro, userns and cgroup v2 capabilities
uname -a
cat /etc/os-release
sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns 2>&1 || true
stat -fc %T /sys/fs/cgroup   # expect cgroup2fs
realpath /usr/bin/bwrap && ls -la /usr/bin/bwrap

# 2. Smoke-test deny-default mount + PID + net isolation without touching $HOME
WORK=$(mktemp -d)
bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --ro-bind /lib /lib \
  --symlink /usr/lib64 /lib64 \
  --proc /proc --dev /dev --tmpfs /tmp \
  --bind "$WORK" /work --chdir /work \
  /usr/bin/python3 -I -B -c '
import os, socket, pathlib
assert not pathlib.Path("/etc/passwd").exists(), "host /etc leaked"
assert len([p for p in os.listdir("/proc") if p.isdigit()]) <= 3, "host PIDs visible"
try:
    socket.create_connection(("1.1.1.1", 443), timeout=1)
    raise AssertionError("network unexpectedly succeeded")
except OSError:
    pass
pathlib.Path("/work/ok.txt").write_text("confined\n")
print("bwrap-poc: ok")
'
rm -rf "$WORK"
```

Verify next:
1. Double-fork + `setsid()` child inside `--unshare-pid` terminates immediately when the `bwrap`
   parent is killed (`SIGKILL`).
2. `doctor.py` detects missing `bwrap` or blocked user namespaces and reports a clear `fail` + `fix`
   hint without creating `.maestro/`.
3. A mutation test (removing `--unshare-net` or `--unshare-pid`) causes the Linux confinement test
   suite to fail immediately.

---

## 4. Feasibility Recommendation

**Recommendation: PROCEED WITH A SEPARATELY SCOPED LINUX POC SPIKE** (do **not** claim Linux
support or ship a production backend yet).

### Why Candidate A (`bwrap` + namespaces + cgroups v2) Is Worth Prototyping

* It maps 1:1 to `sandbox.py`'s `ExecPolicy` abstraction (`SandboxBackend` interface cleanly
  separating `Seatbelt` on macOS from a future `BubblewrapSandbox` on Linux).
* Unlike macOS Seatbelt, `CLONE_NEWPID` + `cgroup.kill` natively eliminates the `#2` escaped-
  descendant cleanup gap and provides a clean path for `#5` resource limits.
* Mount namespaces provide stronger path hiding than SBPL path rules and avoid deprecated OS APIs.

### Remaining Blockers & Security Tests Required Before Any Production Claim

1. **Real Linux execution evidence:** Must run the full adversarial isolation suite (parity with
   `tests/test_sandbox.py` and `tests/test_audit_regressions.py` plus `#2` `setsid`/double-fork
   cleanup and `#5` resource-limit probes) on a real Linux CI runner (e.g., `ubuntu-24.04`),
   including mutation checks proving every control fails loudly when disabled.
2. **Ubuntu 24.04+ AppArmor userns handling:** Must verify whether `/usr/bin/bwrap`'s distro
   AppArmor profile works reliably on GitHub runners and standard desktops, and ensure hosts where
   userns is restricted fail closed to `blocked` with a clear `doctor` diagnosis.
3. **Seccomp / `allow_fork=False` enforcement:** `bwrap` alone does not block `fork()` inside the
   PID namespace; enforcing `allow_fork=False` (matching Confined Mode and Python verification)
   requires either `pids.max=1` (via cgroups v2) or a minimal audited `seccomp-bpf` filter passed
   to `bwrap --seccomp`.
4. **No silent fallback:** Any Linux host lacking `bwrap`, user namespaces, or passing self-tests
   must remain `blocked` — never falling back to unconfined execution.
