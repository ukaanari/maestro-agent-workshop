# MAESTRO Agent Workshop

**An experimental, security-focused local orchestrator for AI coding agents.**
Repository: `maestro-agent-workshop`. In the code and docs the project is called MAESTRO.

MAESTRO runs one coding task through a fixed, auditable pipeline:

```
task → implementation agent → fresh, independent review agent → deterministic verification → explicit human approval
```

Each step's output is hash-bound to the exact files it describes. Agents run inside a
deny-by-default macOS Seatbelt sandbox, and anything unexpected stops the task instead of
retrying it. The aim is a coordinator that people who are wary of handing a coding agent
their machine can still trust: one that does not take an agent's word for what it did,
and that never hands an agent's output to a reviewer or a human without checking it.

> [!WARNING]
> **Status: experimental, pre-release, macOS only.**
> MAESTRO currently runs **only deterministic, first-party fake agents**. The adapters for
> real coding agents (OpenAI Codex CLI, Anthropic Claude Code) exist as interfaces that
> **always refuse to run**. No real Codex-to-Claude automation has been built or validated
> yet. Do not use MAESTRO to confine untrusted code. Read [Limitations](#limitations) first.

MAESTRO is an independent project. It is not affiliated with or endorsed by OpenAI or
Anthropic. "Codex" and "Claude Code" are named only to describe planned integrations. It
is also unrelated to Netflix's Maestro workflow orchestrator and to the Maestro mobile
UI-testing framework.

## Why

Running coding agents unattended raises questions that a prompt cannot answer:

* **Did the reviewer see what was actually written?** Agents summarise their own work, and
  a summary can drift from the files on disk.
* **Can an agent reach things it should not?** That means files outside the task, other
  processes, the network, credentials, or the orchestrator's own approval records.
* **Who decided the result is acceptable?** Was it a human looking at specific evidence,
  or just the exit code of a script?

MAESTRO answers these with mechanisms rather than conventions. It takes its own content
hashes, runs each agent phase in a fresh process with no shared conversation, gates every
transition in a SQLite state machine, and requires a human to name the exact snapshot hash
they approve.

## What works today

| Capability | Status |
|---|---|
| Single-attempt task lifecycle in SQLite (atomic transitions, event log, no retries, no replay after a crash) | **Implemented, tested** |
| Fake implementer → fresh fake reviewer handoff with no manual copying, bound by SHA-256 to a full workspace snapshot | **Implemented, tested** |
| Evidence gate: changed, added, deleted or `chmod`-ed files, or tampered stored evidence, invalidate approval | **Implemented, tested** |
| Explicit approval that must name the exact current snapshot hash | **Implemented, tested** |
| Owned process groups, timeouts, cancellation, output limits, descendant cleanup | **Implemented, tested** |
| Deny-default macOS Seatbelt confinement for agent processes (filesystem, network, process inspection, signals, exec allowlist, scrubbed env), with a fail-closed self-test before every launch | **Implemented, tested on one macOS 26 / arm64 host** |
| Real Codex CLI implementer / Claude Code reviewer adapters | **Not implemented.** Both always refuse. |
| Running a project's own test suite as verification | **Not implemented.** Verification is a fixed, data-only exact-content check. |
| Working on an existing repository | **Not implemented.** Each task gets a new synthetic Git repository. |
| Linux / Windows | **Not supported.** No isolation backend; tasks end `blocked`. |
| Token or cost metering | **Not implemented.** No model is called. |

The full suite has 36 offline tests: 23 for orchestration and 13 for confinement. It needs
no network, no API keys and no installed agent CLIs.

## Requirements

* macOS with `/usr/bin/sandbox-exec`. It is present on current macOS, though Apple marks it
  deprecated (see [Limitations](#limitations)).
* Python 3.9 or newer. Standard library only, nothing to install. The interpreter must be
  installed **outside your home directory** (for example the Xcode Command Line Tools
  Python, python.org or Homebrew). Interpreters under your home directory, such as pyenv,
  conda or uv-managed Pythons, are refused by the sandbox's path policy, and tasks end
  `blocked`. This was established by reading the code, not by testing.
* Git 2.42 or newer (needs `git worktree add --orphan`).

Tested only with macOS 26.7 (arm64, SIP enabled), the Xcode Python 3.9.6 and Apple Git 2.54.0.
Other macOS versions, Intel Macs and other Python builds have not been verified.

## Quick start

```sh
git clone https://github.com/ukaanari/maestro-agent-workshop.git
cd maestro-agent-workshop
python3 -m unittest discover -s tests -v   # 36 tests, about 17 s on the test host
python3 examples/demo.py                   # end-to-end demo in a temporary directory
```

The demo runs three tasks in a throwaway state directory and deletes it afterwards
(`--keep` keeps it for inspection):

1. **Success path.** The fake implementer writes a file and the fake reviewer receives the
   hash-verified handoff. Verification passes, and approval with the exact snapshot hash
   succeeds.
2. **Tamper detection.** After a successful run the demo edits the output file. The approval
   attempt is refused and the task becomes `invalidated`.
3. **Review rejection.** The fake reviewer requests changes, so verification never runs and
   the task cannot be approved.

### Using the CLI directly

```sh
python3 maestro.py create 'Create a greeting' --file greeting.txt --content 'Hello MAESTRO'
python3 maestro.py run TASK_ID
python3 maestro.py status TASK_ID
python3 maestro.py artifact TASK_ID handoff      # also: review, verification
python3 maestro.py approve TASK_ID --snapshot EXACT_SHA_FROM_STATUS --founder 'Your name'
python3 maestro.py cancel  TASK_ID
python3 maestro.py recover TASK_ID               # mark an abandoned active task interrupted
python3 maestro.py dispose TASK_ID               # remove a terminal task's *clean* worktree
```

All output is JSON. State lives in `.maestro/` beside `maestro.py` (git-ignored), or in an
empty or new directory given with `--root PATH`. The `--scenario` flag on `create` selects
a fake-agent behaviour for testing failure paths: `success`, `review-fail`, `stale-review`,
`timeout`, `permission`, `malformed`, `test-fail` or `output-limit`.

`run` exits 0 only when the task reaches `awaiting_approval`, and 2 otherwise. Approval is
a **local record**. It never stages, commits, pushes or merges anything. The `--founder`
value is an audit label typed by the operator, not authentication.

## How it works

Six small Python modules (about 1,000 lines in total):

| Module | Responsibility |
|---|---|
| `maestro.py` | CLI and JSON output |
| `workflow.py` | SQLite state machine, event log, single-attempt engine, evidence gates |
| `workspace.py` | Synthetic Git worktrees, path policy, bounded full-content snapshots |
| `execution.py` | Owned process groups, cancellation, time and output limits |
| `sandbox.py` | Seatbelt profile generation, execution policy validation, fail-closed self-test |
| `agents.py` | Versioned IPC envelopes, disabled real adapters, deterministic fake worker |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the lifecycle, trust boundaries and
evidence chain, and [P1A-SECURITY.md](P1A-SECURITY.md) for the confinement design, what
the tests prove, and the known gaps.

## Limitations

These are deliberate disclosures, not fine print.

* **Only fake agents run.** The pipeline is proven with deterministic stand-ins that emit
  fixed edits and fixed verdicts. The review is *not* a semantic code review. Whether the
  real Codex CLI and Claude Code can run under MAESTRO's sandbox is **unknown and partly
  known to conflict** (next point).
* **Real agents do not yet fit inside the sandbox.** Codex CLI and Claude Code apply their
  own Seatbelt profiles on macOS. Inside a MAESTRO profile any nested `sandbox-exec` fails
  (`forbidden-sandbox-reinit`), so either their inner sandbox is disabled and MAESTRO's
  becomes the only boundary, or MAESTRO cannot wrap them. Real agents also need `fork`,
  shells and network access, all of which the current profile denies. These are open
  design decisions; see [docs/ROADMAP.md](docs/ROADMAP.md).
* **There is a known process-escape gap.** When `fork` is allowed (only in tests today), a
  child that calls `setsid()` or double-forks survives process-group cleanup. It stays
  sandboxed, but it can keep running. This must be fixed before real agents are allowed
  to fork.
* **Seatbelt is deprecated and undocumented.** `sandbox-exec` is Apple's deprecated
  interface, so its semantics can change with OS updates. On macOS 26, `(deny default)`
  turned out *not* to block reading other processes' arguments and environment, and
  MAESTRO adds an explicit rule for that. Other unprobed operations may behave similarly.
  Re-run the full suite after every macOS update.
* **There are no resource limits** beyond wall-clock timeouts and output caps. Memory,
  disk use inside the writable workspace and CPU are not bounded.
* **Agents run as the same user.** A sandbox escape gives the agent full user access.
  Running agents under a dedicated user account is on the roadmap.
* **The operator is trusted.** Hashes detect stale or corrupted evidence, not an attacker
  who can rewrite both the database and its hashes. Path checks protect normal managed use,
  not a hostile same-user process racing the filesystem.
* **Tasks are tiny.** Each task gets one target file. Snapshots allow at most 32 files and
  64 KiB in total.
* **Only one host was tested.** Results come from a single macOS 26.7 arm64 machine.

## Roadmap

The next phase (P1-B) connects the real Codex CLI and Claude Code adapters to the existing
sandbox, without weakening it. It is blocked on four design decisions: the process-escape
fix, the nested-sandbox conflict, shells inside the sandbox, and network and credential
access through an allowlisting proxy. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing and security

* [CONTRIBUTING.md](CONTRIBUTING.md): development rules (standard library only, offline
  tests, fail closed).
* [SECURITY.md](SECURITY.md): how to report a vulnerability, and what is in and out of scope.

## License and acknowledgments

MAESTRO is licensed under the [Apache License 2.0](LICENSE).

The process-ownership, Git-worktree and handoff-artifact designs were adapted (as a new
Python implementation, with no code vendored) from
[OrchestratorInc/agent-orchestrator](https://github.com/OrchestratorInc/agent-orchestrator)
v0.14.3, Copyright 2026 Untrivial, Apache-2.0. Details are in [UPSTREAM.md](UPSTREAM.md),
[NOTICE](NOTICE) and [LICENSES/](LICENSES/).
