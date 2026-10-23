# Architecture

MAESTRO is a single-process coordinator. It drives one task through a fixed sequence of
phases, starting a separate, confined child process for each agent phase. There is no
daemon, no server, no plugin system and no dependency outside the Python standard library.

## Lifecycle

```
created → preparing → implementing → reviewing → verifying → awaiting_approval → approved
```

* **Terminal failure states:** `failed`, `blocked`, `timed_out`, `cancelled`, `interrupted`
  and `review_failed`. They can be reached from `created`, from any active phase, or from
  `awaiting_approval`.
* **`invalidated`:** reached from `awaiting_approval` (or `approved`) when stored evidence
  or the live workspace no longer matches.

* **Transitions** are checked inside a SQLite `BEGIN IMMEDIATE` transaction, and the
  matching event-log row commits with them. Illegal transitions are rejected.
* **Single attempt.** A task runs once. A crashed or abandoned active task is marked
  `interrupted` (`recover`, or the next `run`) and is never replayed. To try again,
  create a new task.
* **Single owner.** A per-task `flock` stops two coordinators from driving the same task.
* **Cancellation** is a persisted flag. The running coordinator polls it every 25 ms, kills
  the child process group, and the cancellation wins over any pending transition. A cancel
  that lands before the first transition ends the run as `cancelled`, not as an error.
* **Process cleanup** (`execution.stop_group`):
  1. SIGTERM to the whole group;
  2. up to 150 ms of grace for every member;
  3. SIGKILL;
  4. a check, through macOS `libproc`, that no live member remains;
  5. only then is the child reaped.

  Keeping the child unreaped until the end reserves its pid and group id, so no signal can
  reach a reused pid. EPERM is accepted only when every remaining member is a zombie.
  A surviving live member, or a child that cannot be reaped, is an error. Processes that
  leave the group (`setsid`, `setpgid`) are not reached (#2).

## Phases

1. **Prepare.** The coordinator runs fixed-argv Git outside the sandbox: `init --bare` with
   an empty template, then `worktree add --orphan`. That makes a new synthetic repository
   per task with an unborn branch. Nothing is staged or committed. Global and system Git
   config, hooks, fsmonitor and all transport protocols are disabled.
2. **Implement.** The fake implementer runs under Seatbelt and returns an *edit request*
   (path + text), never a shell command. The **coordinator**, not the agent, applies it. It
   accepts only the single declared target path, and rejects absolute paths, traversal,
   dot-files, symlinks, hardlinks, special files and overwrites.
3. **Snapshot and handoff.** The coordinator hashes every regular file in the worktree
   (bytes, relative path and permission mode, including untracked and ignored files) and
   every directory (relative path and mode). The
   handoff artifact (task, acceptance criterion, implementation summary, full snapshot) is
   stored in SQLite with its own SHA-256. The implementer has already exited.
4. **Review.** A *fresh* fake reviewer process receives the hash-verified handoff envelope.
   It gets no implementation session, no write interface and no worktree path. Its verdict
   must quote the exact snapshot and handoff hashes. A stale or mismatched verdict blocks
   the task.
5. **Verify.** A fixed, data-only check compares the live file content with the stored
   criterion. It runs no repository code.
6. **Approve.** A human must give the exact current snapshot hash. Approval re-reads all
   stored evidence, re-checks every hash and re-snapshots the live worktree. Any mismatch
   moves the task to `invalidated`.

## Evidence chain

```
spec ──► handoff{snapshot, criteria, summary}  ──sha256──► handoff_sha256
                    │                                          │
                    └── snapshot.sha256 ◄── review{snapshot_sha256, handoff_sha256, verdict}
                                        ◄── verification{snapshot_sha256, passed}
                                        ◄── live worktree re-snapshot at approval time
```

Artifacts are insert-only through the application. The task row stores the expected hash
of each artifact. Unknown or duplicate JSON fields, non-finite numbers, wrong task identity,
wrong phase and payload-hash mismatches all fail closed.

## Trust boundaries

| Component | Trusted? | Boundary |
|---|---|---|
| Operator and MAESTRO source/state directories | Trusted | Same-user filesystem permissions only |
| Coordinator (`workflow.py`, `workspace.py`) | Trusted | Runs unconfined; applies edits itself |
| Git setup commands | Trusted fixed argv | Unconfined; hooks, protocols and global config disabled |
| Agent processes (fake today, real later) | **Untrusted** | `sandbox.Seatbelt.run` only; no other launch path |

### Agent sandbox (`sandbox.py`)

For every launch MAESTRO generates a profile starting from `(deny default)`:

* **Reads:** system runtime paths, the Python prefix, four named MAESTRO source files, and
  metadata of the granted paths' ancestor directories. Nothing else under the user's home.
* **Writes:** only directories strictly inside the task's own directory. Protected paths
  (`state.sqlite3*`, the `MAESTRO-P0` marker, `repo.git`, `executor.lock`, `worktree/.git`)
  are denied reading, writing and execution. Inside a writable grant they may only be
  direct children of it, because a deeper path could be moved by renaming an ancestor.
* **Exec:** only allowlisted, canonical, non-writable binaries. Shells, `env`, `osascript`,
  `sudo`, `open`, `launchctl`, `xargs` and `sandbox-exec` are always refused. Fork is
  denied unless explicitly allowed.
* **Network:** denied, including loopback and Unix sockets (both covered by the suite).
  DNS fails because no Mach services are granted; that was checked by hand, not by the suite.
* **Process isolation:** inspection of other processes (argv, environment, path) is
  explicitly denied, and signals are allowed only within the same sandbox.
* **Environment:** constructed rather than inherited. A fixed minimal set plus `LANG`,
  `NO_COLOR` and `TERM`. Python runs with `-I -B`.
* **Paths** reach the kernel as `-D` profile parameters and are never interpolated into
  the profile text.
* **Self-test:** before every launch MAESTRO proves the engine denies an outside write
  and permits an inside write. If the engine is missing or does not enforce, the task ends
  `blocked`. There is no unconfined fallback.

[P1A-SECURITY.md](../P1A-SECURITY.md) lists what the tests verify, what was checked only
by hand, and the remaining gaps.

## Fixed limits

| Limit | Value |
|---|---|
| Snapshot | 32 regular files, 64 filesystem entries, 64 KiB total |
| Target content | 8 KiB |
| IPC / artifact / agent output | 256 KiB |
| Agent phase deadline | 0–30 s, configurable per task |
| Git setup command deadline | 10 s |
| Cancellation poll / TERM grace | 25 ms / 150 ms, then KILL |
| Retries | 0 |

## Diagnostics (`doctor.py`)

`maestro.py doctor` checks a host without changing it. It never instantiates the state
store, so no state root is created or adopted. It reuses the production code paths:
`Seatbelt.available()` for the self-test, `FakeAdapter("implement").run` under the real
agent policy in a temporary root, and `Workspace.create()` for the Git check. A passing
result therefore means the same code that runs tasks works on this host. The Git check
runs `xcode-select -p` first, because on macOS `/usr/bin/git` opens an installer dialog
when the Command Line Tools are missing.
