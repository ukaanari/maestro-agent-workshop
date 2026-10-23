# P1-A secure execution layer — 2026-10-22

**Result: 36 tests passed (23 P0 + 13 P1-A), 0 failures, ~16.5 s, two consecutive runs.**
Host: macOS 26.7 (25G229), arm64, SIP enabled, Python 3.9.6 (Xcode), Apple Git 2.54.0.
Standard library only. No installs, no network, no model calls, no Git commits.

```sh
python3 -m unittest discover -s tests -v
```

## Mechanism choice (evaluated on this host)

| Mechanism | Status here | Decision |
|---|---|---|
| Seatbelt via `/usr/bin/sandbox-exec` (SBPL, kernel-enforced) | Present, functional; man page marks it **deprecated** | **Used.** Only OS-enforced confinement available without installation. |
| App Sandbox (entitlements) | Requires signed app bundles | Not applicable to CLI child processes. |
| Docker / Podman / Lima / Colima / Apple `container` | Not installed | Out of scope (installation). |
| Endpoint Security / Network Extension | Require Apple entitlements + system approval | Out of scope. |
| Dedicated macOS user account | Possible, needs admin user creation | Recommended for P1-B (see gaps); needs a maintainer decision. |
| Git worktree, cwd, HOME, process groups | — | **Not** security boundaries; retained only for orchestration. |

## What runs confined

`sandbox.Seatbelt.run(ExecPolicy)` is the only path for untrusted code. P0's fake
Codex/Claude workers now run through it (`agents.FakeAdapter`, `workflow.Engine.sandbox`):
write only their private task `home/`, read only the Python runtime and four named
MAESTRO source files, no fork, no network. Git setup commands remain unconfined
coordinator operations with fixed argv (unchanged from P0).

Each launch:
1. validates the policy;
2. runs a self-test that proves the engine denies an outside write and permits an inside
   write;
3. executes.

Any failure leads to `IsolationUnavailable`, and the task ends `blocked`. Nothing falls
back to unconfined execution.

The self-test honours cancellation. It also requires the probe to *report* the refused
write (non-zero exit), so an engine that never runs the target is rejected (F-03).

The engine binary must be a canonical path, not a symlink, and a regular file owned by
root or this user that is not group- or world-writable.

A deliberately deceptive engine binary can defeat any self-test. The real defence is that
binary's location and ownership.

## Controls implemented

**Filesystem**
* Generated profile, `(deny default)`. Reads: `/usr/lib`, `/System/Library`, dyld cryptex,
  `/dev/{null,random,urandom}`, `/` (entry names only), metadata of exact ancestor
  directories of granted paths, plus explicit grants. Writes: approved directories only.
* All paths are passed as SBPL parameters (`-D`), never interpolated into profile text.
* Paths must be absolute, existing and canonical (no symlink or `..` components).
* Writable grants must be user-owned directories **strictly inside** an approved disposable
  root (`tasks/<id>/`). The grant root itself cannot be renamed, removed or chmod-ed.
* Protected paths (`state.sqlite3*`, `MAESTRO-P0`, `tasks/<id>/repo.git`, `executor.lock`,
  `worktree/.git`) are denied reading, writing **and execution** by a final rule. Inside a
  writable grant, a protected path may only be a **direct child** of the grant.
  - A deeper one could be moved out of its `(subpath ...)` rule by renaming an
    intermediate directory. The independent audit confirmed this (F-01), and such
    policies are now rejected.
  - A direct child cannot move: its only ancestor in the grant is the grant root, whose
    rename is denied.
  - These attempts against a direct child are all denied, and the regression tests check
    them: renaming it, replacing or removing it, renaming the root, case-variant paths,
    hard links and symlinks. A `renamex_np` swap was also checked by hand.
* Rejected grants and policies:
  - `/`, the account home or its ancestors;
  - directory subtrees inside the home outside approved roots;
  - the MAESTRO source subtree (contains `.maestro/`);
  - any readable grant containing protected state.
* The account home comes from the password database, not `$HOME`, which the caller
  controls.
* Listable grants are limited to the MAESTRO source directory or directories inside an
  approved root.
* Executables must be owned by root or this user and must not be group- or
  world-writable. They must not sit inside an approved root, protected state or a
  personal directory.
* Approved roots must be directories owned by this user that are not group- or
  world-writable. That rules out shared places such as `/private/tmp`.

**Network** — `(deny network*)`; only `network="deny"` is accepted. No Mach services, so no
DNS either. Future connectivity design is below; nothing is activated.

**Process**
* Executable must be in the per-instance allowlist, canonical, regular, not group/world
  writable; shells, `env`, `osascript`, `sudo`, `open`, `launchctl`, `xargs`, `sandbox-exec`
  are refused even if listed. Children may exec only the same allowlisted binary.
* Fork is denied unless `allow_fork=True` (P1-A uses it only in tests).
* Explicit `(deny process-info*)` + self-only allow. **Finding:** on macOS 26 `(deny default)`
  did *not* block reading other same-user processes' argv **and environment**
  (`KERN_PROCARGS2`) or `proc_pidpath`; the explicit rule closes it (tested).
* Signals only to the same sandbox; POSIX shm/semaphores, `task_for_pid`, `/dev/tty` denied.
* Environment is constructed, not inherited: fixed minimal set plus `LANG`/`NO_COLOR`/`TERM`
  allowlist; `DYLD_*`, `PATH` overrides etc. rejected. Python runs `-I -B`.
* Timeouts (≤60 s), bounded output (≤1 MiB), cancellation polling, process-group
  TERM→KILL and reap — reused from P0 `execution.execute`, now with argv validation.

## Confirmed vs unverified

**Confirmed by automated tests** (each also shown to fail under a targeted mutation of
`sandbox.py`: no process-info deny, no protected deny, no root-literal deny, allow-default,
no self-test, shells allowed, fork always allowed, network allowed):
outside read/list/stat/write denied; `..` traversal, symlink, hardlink creation denied;
workspace root rename/chmod denied; protected carve-outs; `/etc/passwd`, `/private/tmp`
denied; MAESTRO DB, marker, `repo.git`, lock, worktree and other tasks unreachable from the
engine's agent sandbox; loopback TCP, TEST-NET TCP/UDP and Unix sockets denied with the
listener receiving nothing; env scrubbed; signals to parent/launchd denied; sibling
argv/env and parent path unreadable; fork denied by default; with fork, `/bin/sh`,
`sandbox-exec` and `/usr/bin/true` exec denied and children stay confined; timeout and
cancellation kill same-group children before they act; missing engine and a
non-enforcing engine both fail closed; engine run with missing isolation ends `blocked`
with no handoff; 30 invalid-policy cases rejected.

**Verified manually during development, not in the suite:** POSIX shm/sem denied,
`task_for_pid` fails, `/dev/tty` denied, DNS fails, nested `sandbox-exec` inside a MAESTRO
profile fails (`sandbox_apply: Operation not permitted`, kernel op
`forbidden-sandbox-reinit`, not grantable from SBPL), `setsid` escape (gap 1 below).

**Unverified:** other macOS versions/Intel; SBPL operations not probed (default-deny is
demonstrably *not* exhaustive, see process-info); kernel or sandbox vulnerabilities;
any real Codex/Claude Code behaviour.

## Remaining bypass opportunities and gaps

1. **Process-group escape (confirmed).** With `allow_fork=True`, a child calling `setsid()`
   or double-forking survives cleanup. It stays sandboxed (writes only inside its grants),
   but can keep running and mutate the workspace after capture (snapshot hashes would
   detect it). Fakes deny fork, so P1-A is unaffected. **Must be fixed before real agents
   get fork** — options: dedicated agent uid (kill all its processes) or a
   `sandbox_check()`-based sweep (SPI, variadic ctypes on arm64 is fragile).
2. **Deprecated, undocumented engine.** SBPL semantics can change with OS updates. The
   per-launch self-test checks write denial only; rerun the full suite after every macOS
   update before trusting results.
3. **Default-deny is not complete.** `process-info*` needed an explicit rule; other
   unprobed operations may behave similarly.
4. **No resource limits.** Memory, disk usage inside writable grants, CPU within the
   timeout, and fork bombs (when fork is allowed) are bounded only by the wall-clock timeout.
5. **Small information leaks.** Top-level `/` names, metadata of granted paths' ancestor
   directories, system libraries, and the whole Python prefix (including its site-packages)
   are readable. No personal file contents.
6. **Same uid.** Confinement relies entirely on Seatbelt; a sandbox escape yields full user
   access. A dedicated uid would add file-permission and cleanup defence in depth.
7. **Unconfined Git** still runs on agent-influenced worktrees (fixed argv, hooks/fsmonitor/
   protocols disabled, config in protected `repo.git`). Re-evaluate when P1-B lets agents
   write the worktree.
8. **Trusted operator assumption** (from P0) remains: same-user unconfined processes could
   race path validation; MAESTRO itself is trusted.

## Future network design (not implemented, not activated)

Seatbelt filters only by `localhost` or `*` plus port — never by hostname. So:
1. A MAESTRO-owned egress proxy on a per-run loopback port, outside the sandbox, CONNECT
   only, exact-host allowlist per provider (endpoints to be confirmed against the pinned
   CLI versions in P1-B), no TLS interception, deny everything else including telemetry
   and update checks; logs host, bytes, and duration as evidence.
2. Profile adds only `(allow network-outbound (remote tcp "localhost:PORT"))`; no
   `mach-lookup` for DNS (the proxy resolves). Proxy-unaware traffic fails closed.
3. `HTTPS_PROXY`/`HTTP_PROXY` (and provider telemetry opt-outs) join the env allowlist only
   in P1-B, per run.
4. Credentials: never grant `~/.codex`, `~/.claude` or Keychain (`mach-lookup
   com.apple.securityd` would expose the login keychain API). Candidate: a maintainer-approved,
   MAESTRO-owned provider home (e.g. `CODEX_HOME`, `CLAUDE_CONFIG_DIR`) containing only the
   needed token, granted read-only as single files. Verify each variable against the pinned
   CLI version before use.

## Independent CI verification (2026-10-23)

The first runs on a machine other than the development Mac were GitHub-hosted `macos-26`
arm64 runners (image `macos-26-arm64` 20261013.0424, macOS 26.6.2 (25G83), **SIP
disabled**), using `.github/workflows/ci.yml` with read-only permissions and no secrets.

* **Xcode Python 3.9.6:** `doctor`, all 43 tests (including all 13 confinement tests) and
  the demo pass. The demo reproduces the documented snapshot hash. Seatbelt enforcement
  behaved as on the development host, even with SIP disabled.
* **Bug found and fixed:** on the first run, `test_timeout_stops_descendants_not_only_parent`
  failed with `PermissionError` from `os.killpg`. macOS returns EPERM when every remaining
  group member is a zombie awaiting reaping. `execution.stop_group` now treats EPERM like
  ESRCH. This was confirmed locally, and `tests/test_process_cleanup.py` reproduces it.
  Before the fix, a timeout could be reported as `blocked` instead of `timed_out`; it
  never made a task approvable.
* **Homebrew Python 3.15.0: known incompatibility, profile not widened
  ([#7](https://github.com/ukaanari/maestro-agent-workshop/issues/7)).** `doctor`, the
  orchestration tests and the demo pass; the production agent policy denies fork.
  *Correction (independent audit F-04):* an earlier version of this section said all 4
  failing tests use `allow_fork=True`. That was wrong:
  - **3 failing tests use `allow_fork=True`.** They start children through
    `sys.executable`, which on Homebrew is the framework launcher
    (`.../Versions/3.15/bin/python3.15`, reached through the `opt/` symlink). That is not
    the allowlisted interpreter binary.
  - **The 4th, the process-isolation test, does not.** It runs with fork *denied* and
    aborted at a top-level `import ctypes`, because `os.uname()` is denied. As a result,
    *none* of its env, signal, inspection or fork probes ran on 3.15.

  The tests now start children from the allowlisted binary. They run the non-`ctypes`
  probes independently and report a `ctypes`-dependent probe that could not run as a
  failure, never a pass. On 3.15, only the two process-inspection probes are expected to
  fail. That is a prediction CI has not yet confirmed.
  The CI run's kernel sandbox log (diagnostics step) attributes both:
  * **Child spawns:** `file-read-metadata /opt/homebrew/opt/python@3.15` was denied
    exactly 4 times, once per Python child the failing tests start. On Homebrew,
    `sys.executable` goes through the `opt/` symlink, which is outside the granted
    interpreter prefix (`Cellar/...`). Non-Python children (`/bin/sh`, `/usr/bin/true`,
    `sandbox-exec`) were denied `process-exec`, as the tests expect.
  * **`os.uname()`:** `sysctl-read` of `kern.ostype`, `kern.osrelease`, `kern.version`,
    `kern.hostname` and `hw.machine` was denied. The profile allows only
    `kern.bootargs` and `security.mac.lockdown_mode_state`.
  **No failure indicated an escape**: every one was a denial. Granting the `opt/`
  metadata read alone would *not* have helped: the launcher it leads to is not
  allowlisted for `process-exec` either. Any future grant, for example named
  `sysctl-read` entries for `os.uname()`, needs its own justification and
  test, and the mutation checks above must still catch every weakening.
  Until #7 is resolved, CI runs this interpreter as an experimental job, which is not a
  required check. It runs the full suite and passes only if the failing tests are
  *exactly* the listed known ones (`.github/scripts/check_suite.py`), so any other
  regression is visible. The Xcode Python job is the required check.

## Independent audit remediation (2026-10-23)

An independent review of `5c4d596` reported findings F-01 to F-07. Each one was first
reproduced on disposable synthetic fixtures. Each fix has a regression test in
`tests/test_audit_regressions.py` that fails on `5c4d596` and passes after the fix. A
mutation run then put each weakness back into the fixed code, to confirm the suite
catches it. Summary:

* **F-01, protected-path rename bypass:** fixed by rejecting overlaps deeper than a direct
  child. The protected rule now also denies `process-exec*`.
* **F-02, process-group cleanup:**
  - The child stays unreaped until the whole group has been signalled, so no signal can
    reach a reused pid.
  - The SIGTERM grace now covers every group member.
  - EPERM is accepted only when `libproc` shows that every remaining member is a zombie.
    Otherwise it is an error.
  - Cleanup fails loudly if a live member survives SIGKILL, or if the child cannot be
    reaped.
  - The pipes are always closed.
  - Descendants that leave the group are still out of reach (#2).
* **F-03, policy validation:** account home from the password database; listable,
  executable and approved-root restrictions; canonical engine binary; stricter self-test.
* **F-04, Python 3.15 diagnosis and CI:** documentation corrected, test structure fixed,
  and an exact known-failure gate in CI.
* **F-05, evidence and disposal:**
  - Directories, with their path and mode, are now part of the snapshot and its hash.
  - Verification requires exactly the target file and its parent directories.
  - `dispose --remove-reviewed-output` deletes output only when it exactly matches the
    stored, hash-verified handoff.
* **F-06, `doctor` reliability:** every check is guarded and reported, never a traceback.
  The state-root inspection mirrors the store's own rules.
* **F-07, races and malformed records:**
  - A concurrent cancel ends a run cleanly.
  - Malformed records fail as policy errors.
  - Approval re-binds the handoff to the task's title and criteria.
  - The self-test honours cancellation.
  - Non-numeric timeouts are rejected.

Not changed by this work: issues #2 to #7 remain open. The wall-clock time of an agent
phase is its configured timeout, plus a self-test of at most 5 s, plus at most about
2.2 s of cleanup.
