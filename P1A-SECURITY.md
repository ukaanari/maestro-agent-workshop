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

Each launch: (1) validates the policy, (2) runs a self-test that proves the engine
denies an outside write and permits an inside write, (3) executes. Any failure →
`IsolationUnavailable` → task `blocked`. Nothing falls back to unconfined execution.

## Controls implemented

**Filesystem**
* Generated profile, `(deny default)`. Reads: `/usr/lib`, `/System/Library`, dyld cryptex,
  `/dev/{null,random,urandom}`, `/` (entry names only), metadata of exact ancestor
  directories of granted paths, plus explicit grants. Writes: approved directories only.
* All paths are passed as SBPL parameters (`-D`), never interpolated into profile text.
* Paths must be absolute, existing and canonical (no symlink or `..` components).
* Writable grants must be user-owned directories **strictly inside** an approved disposable
  root (`tasks/<id>/`). The grant root itself cannot be renamed, removed or chmod-ed.
* Protected paths are denied by a final rule even inside grants: `state.sqlite3*`,
  `MAESTRO-P0`, `tasks/<id>/repo.git`, `executor.lock`, `worktree/.git`.
* Rejected grants: `/`, `$HOME` or its ancestors, directory subtrees inside `$HOME` outside
  approved roots, the MAESTRO source subtree (contains `.maestro/`), any readable grant
  containing protected state, executables inside writable paths.

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
