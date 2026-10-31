# MAESTRO Agent Workshop

[![CI](https://github.com/ukaanari/maestro-agent-workshop/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ukaanari/maestro-agent-workshop/actions/workflows/ci.yml)

**An experimental, security-focused local orchestrator for AI coding agents.**
Repository: `maestro-agent-workshop`. In the code and docs the project is called MAESTRO.

MAESTRO runs one coding task through a fixed, auditable pipeline:

```
task → implementation agent → fresh, independent review agent → deterministic verification → explicit human approval
```

In Confined Mode, each step's output is hash-bound to the exact files it describes. Its
synthetic agents run inside a deny-by-default macOS Seatbelt sandbox, and anything unexpected stops the task instead of
retrying it. The aim is a coordinator that people who are wary of handing a coding agent
their machine can still trust: one that does not take an agent's word for what it did,
and that never hands an agent's output to a reviewer or a human without checking it.

> [!WARNING]
> **Status: experimental, pre-release, macOS only.**
> Confined Mode runs **only deterministic, first-party fake agents**. Its real-agent
> adapters still refuse. The separate [Trusted Local Mode](#trusted-local-mode-experimental)
> can launch the official Codex CLI and, optionally, a Claude Code reviewer with no built-in tools
> **with your user permissions**; only its verifier is confined. The automated suite runs
> offline with fake agents. Live runs have passed only on small bundled fixtures
> ([Codex pilot](#first-live-pilot), [two-agent run](#two-agent-run)).
> Do not use Trusted Local Mode to contain an untrusted agent.

**New here?** [Quickstart: Trusted Local on your own repository](#quickstart-trusted-local-on-your-own-repository).

MAESTRO is an independent project. It is not affiliated with or endorsed by OpenAI or
Anthropic. "Codex" and "Claude Code" identify their respective tools and integrations. It
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

The following table describes the unchanged Confined Mode. Trusted Local has a separate
flow documented below.

| Capability | Status |
|---|---|
| Single-attempt task lifecycle in SQLite (atomic transitions, event log, no retries, no replay after a crash) | **Implemented, tested** |
| Fake implementer → fresh fake reviewer handoff with no manual copying, bound by SHA-256 to a full workspace snapshot | **Implemented, tested** |
| Evidence gate: changed, added, deleted or `chmod`-ed files or directories, or tampered stored evidence, invalidate approval | **Implemented, tested** |
| Explicit approval that must name the exact current snapshot hash | **Implemented, tested** |
| Owned process groups, timeouts, cancellation, output limits; cleanup verifies that no live group member remains (descendants that leave the group are not covered, #2) | **Implemented, tested** |
| Deny-default macOS Seatbelt confinement for agent processes (filesystem, network, process inspection, signals, exec allowlist, scrubbed env), with a fail-closed self-test before every launch | **Implemented, tested on macOS 26.7 (development Mac) and 26.6.2 (GitHub runner), arm64** |
| Real Codex CLI implementer / Claude Code reviewer adapters | **Not in Confined Mode.** Both adapters always refuse. Trusted Local runs the real Codex CLI and, optionally, a fresh Claude Code reviewer with no built-in tools, both unconfined (below). |
| Running a project's own test suite as verification | **Not in Confined Mode** (fixed, data-only exact-content check). Trusted Local runs the project's `unittest` suite in Seatbelt, with an explicit layout (`--test-dir`, `--top-level-dir`, `--test-pattern`, `--pythonpath`). |
| Working on an existing repository | **Not in Confined Mode** (a new synthetic Git repository per task). Trusted Local clones an existing local repository at a pinned commit. |
| Linux / Windows | **Not supported.** No isolation backend; tasks end `blocked`. |
| Token or cost metering | **Not implemented.** Confined Mode calls no model; Trusted Local stores Codex's own usage report as an unverified claim. |
| `maestro.py doctor`: read-only prerequisite check that exercises the real sandbox, a confined fake worker and Git | **Implemented, tested** |

The suite has 149 offline tests: the original 80 listed below, plus 19 Trusted Local
acceptance tests, 12 Claude reviewer tests, 14 usability tests (verification layouts,
`trusted check`, next steps, the project demo), 11 scoped-review tests and 13 privacy-guard
tests, many with adversarial subcases. On interpreters other than macOS
`/usr/bin/python3` (3.9) the Trusted Local tests are skipped, matching what the mode
itself requires:

* 23 for orchestration and 13 for confinement;
* 6 for `doctor` and 1 cleanup regression test;
* 29 regression tests for the independent audit findings F-01 to F-07 and the re-review
  follow-up;
* 8 for the CI known-failure gate.

It needs no network, no API keys and no installed agent CLIs. [CI](.github/workflows/ci.yml) runs `doctor`, the suite and the demo on GitHub-hosted
`macos-26` arm64 runners, with no secrets. Results by interpreter:

* **Xcode Python: supported, and the required check.** Everything passes.
* **Homebrew Python 3.15: experimental, with known failures
  ([#7](https://github.com/ukaanari/maestro-agent-workshop/issues/7)).** This job runs the
  full suite on every change. It passes only if the failures are *exactly* the listed
  test and subTest ids (`.github/known-failures/`), so any other regression, even
  another subTest of the same test, or a known failure that starts passing, turns it
  red. It is not a required check.
  - **Before the audit remediation:** `doctor`, the orchestration tests and the demo passed, and 4
    confinement tests failed. 3 of them started child processes through `sys.executable`,
    which on Homebrew is a launcher that the profile does not allowlist. The 4th, the
    process-isolation test, aborted at `import ctypes`, because `os.uname()` is denied, so
    none of its probes ran.
  - **Since the audit remediation:** children start from the allowlisted interpreter
    binary, and the non-`ctypes` isolation probes run independently. Only the two
    process-inspection probes fail on 3.15, as CI has confirmed on every run since.
  - Every failure is a denial, not an escape. The profile is deliberately not widened.
    **Python 3.15 is not fully compatible.** See
    [P1A-SECURITY.md](P1A-SECURITY.md#independent-ci-verification-2026-10-23).

## Quickstart: Trusted Local on your own repository

You need macOS, `/usr/bin/python3` (the Xcode Command Line Tools Python 3.9), the official
[Codex CLI](https://github.com/openai/codex) signed in, and optionally Claude Code signed in
for reviews. Agents use your own logins and quotas; MAESTRO never reads credentials.
Rehearse the whole flow offline first, with fake agents on a synthetic multi-file project:

```sh
git clone https://github.com/ukaanari/maestro-agent-workshop.git && cd maestro-agent-workshop
/usr/bin/python3 -B examples/project-demo/demo.py        # offline, no model calls
```

Then on your repository (commit your work first, and leave the repository untouched while
a task is open):

```sh
MAESTRO=$PWD; m() { /usr/bin/python3 -B "$MAESTRO/maestro.py" "$@"; }             # works in zsh and bash
m doctor                                                                          # 1-2. prerequisites; changes nothing
REPO=/absolute/path/to/repo; BASE=$(git -C "$REPO" rev-parse HEAD)
m trusted check --repo "$REPO" --base "$BASE" --pythonpath src --top-level-dir .  # 3. compatibility
m trusted start --repo "$REPO" --base "$BASE" --task /absolute/path/TASK.md \
   --model MODEL --pythonpath src --top-level-dir . --review-model REVIEW_MODEL   # 4. one task
m trusted implement TASK_ID                                                       # 4. one Codex run
m trusted verify TASK_ID                                                          # 5. your tests, in Seatbelt
m trusted review TASK_ID                                                          # 5. optional fresh Claude Code review
m trusted diff TASK_ID; m trusted status TASK_ID                                  # 6. exact patch, findings, next steps
m trusted approve TASK_ID --snapshot SNAPSHOT_SHA256 --founder 'Your Name'        # 7. or: trusted reject
m trusted export TASK_ID                                                          # 8. patch file; you apply it yourself
```

* Use the layout options that match your project, or none for the original
  `unittest discover -s tests` from the repository root:

  | Project layout | Options |
  |---|---|
  | `tests/*.py` that import the code from the root | none |
  | `src/` package, tests import it | `--pythonpath src` |
  | `tests/` is a package (`tests/__init__.py`, relative imports) | `--top-level-dir .` |
  | tests inside the package, e.g. `app/tests/` | `--test-dir app/tests --top-level-dir .` |
  | files named `*_test.py` | `--test-pattern '*_test.py'` |

* `trusted check` creates no task and calls no agent: it clones the base into a temporary
  directory and runs your tests there in Seatbelt. A failing baseline is normal before
  the change; an error means the setup cannot work. Fix the layout before spending a
  Codex run. For a failing run it shows only the first 1,000 bytes of test output, without
  counts, so run the suite yourself if you need every failure.
* Every command prints JSON, including `next`, the suggested commands for the current
  state. Drop `--review-model` and `trusted review` for a Codex-only task. `MODEL` is a
  model your Codex CLI lists (`codex debug models`); `REVIEW_MODEL` is a full Claude model
  name such as `claude-sonnet-5-5`.
* A compatible project has a `unittest` suite that runs on Python 3.9 with the standard
  library (or dependencies inside the repository), in under 60 seconds, with no network
  or subprocesses. See [Limitations](#limitations).

## Trusted Local Mode (experimental)

A separate, recorded `mode: "trusted-local"` implements this flow:

`isolated clone → Codex CLI → confined unittest verification → optional fresh Claude Code review → exact-hash human approval → patch export`

| Confined Mode | Trusted Local Mode |
|---|---|
| Synthetic implementer and reviewer run in Seatbelt. | Codex runs with the user's normal permissions and login environment. MAESTRO does not confine it. |
| New synthetic worktree; fixed data-only verification. | Clone of an existing local repository at a full base commit SHA; a disposable copy runs the allowlisted unittest command in Seatbelt. |
| Private environment; no real model call. | Constructed environment: only `HOME`, `USER`, `LOGNAME`, `PATH`, `SHELL`, `TMPDIR` and `CODEX_HOME` (when set) reach Codex. API keys, tokens, proxies and every other variable are dropped; forwarded names and a dropped count are recorded, never values. The official CLI manages its own subscription login; MAESTRO never reads login files. |
| Explicit approval binds the full confined snapshot. | Explicit approval binds SHA-256 of canonical `{base, tree, manifest}`, independent verification and source-repository guards. Agent messages are claims only. |
| Confined task commands only. | `trusted` commands only; neither mode falls back to the other. |

Use macOS and `/usr/bin/python3` (Python 3.9), with no new dependencies. The fully offline
CLI demonstration explicitly selects `tests/fixtures/fake_codex.py` and removes its own
temporary fixture when finished:

```sh
/usr/bin/python3 -B examples/trusted-local/demo.py
/usr/bin/python3 -B .github/scripts/check_suite.py --known-failures ""
```

A Codex version containing `offline-fixture` cannot receive normal human approval.
The task must have been created with recorded `execution_context: "test"`, AND the
calling Python harness must explicitly construct `TrustedEngine(..., test_context=True)`.
Missing context on old tasks means normal. The production CLI exposes no flag or
environment override for this capability; importing unittest or choosing a test-like
folder, founder name or fake binary does not enable it. Test approvals and exports
are labeled `execution_context: "test"`; normal CLI export refuses them too.
The disposable offline demo uses the dedicated `tests/fixtures/trusted_test_cli.py`
harness, whose only additional capability is `maestro.main(test_context=True)`.
This is an explicit testing convention, not protection against same-user code changes.

For a retained offline fixture, run `examples/trusted-local/make_fixture.py DESTINATION`.
It prints a deterministic base commit created with fixed identities and dates.
The commands below use the normal CLI: with the fake, verification works but approval
is deliberately refused. Use the disposable demo above for a complete offline test.
A separately authorized real Codex run uses the same commands without `--codex-bin`.

```sh
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted start --repo /absolute/fixture --base FULL_SHA --task /absolute/fixture/TASK.md --model test-model
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted implement TASK_ID --codex-bin /absolute/maestro/tests/fixtures/fake_codex.py
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted verify TASK_ID
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted status TASK_ID
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted diff TASK_ID
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted approve TASK_ID --snapshot EXACT_SHA256 --founder YOUR_NAME
/usr/bin/python3 -B maestro.py --root /absolute/new-state trusted export TASK_ID
```

`status` lists the changed files and the `next` suggested commands, and `diff` prints the
exact tree-to-tree patch under review, without changing task state. Instead of approving, a human can run
`trusted reject TASK_ID --founder NAME --reason TEXT` (recorded, terminal `rejected`)
or `trusted cancel TASK_ID`. Both permanently block approval and export.

`--codex-bin` or `MAESTRO_CODEX_BIN` explicitly chooses a binary. Without either, the
production path looks for `codex` and never substitutes the fake. A live run requires
separate founder authorization. The argv is fixed:

```text
codex -a never exec -m <model> --ignore-user-config --sandbox workspace-write --json --ephemeral -C <clone> -o <task>/last-message.txt -
```

`trusted start --model NAME` is required. Names must match
`[a-z0-9][a-z0-9._-]{0,63}` and are recorded in the task spec and Codex artifact.
A syntactically valid but unavailable model fails with the CLI exit status; there is
no model fallback or retry. `test-model` above is only an offline fixture label.
The prompt goes on stdin; binary realpath and `--version` are recorded.
`--ignore-user-config` skips `config.toml` loading on Codex 0.164.0, while the CLI
continues to use the unchanged `CODEX_HOME` for authentication. Implement timeout
is 1,200 seconds by default, at most 3,600. Each output stream is capped at 10 MiB.
Nonzero exit, malformed JSON or a missing final turn event fails without retry. Cleanup
records concern only the original process group; a `setsid`/double-fork descendant can
survive and retain the user's permissions (issue #2 remains open).

Cloning uses `--no-hardlinks --no-checkout --template=`, detached checkout and removal
of `origin`. `clone.partial/` becomes `clone/` only after successful preparation. Failed
partials are retained, never reused or automatically deleted; the same task identity
(repository, base, prompt and model) cannot be started again, so change the prompt or
model to try again. Coordinator Git ignores global/system configuration and
uses no hooks. Source HEAD, refs, stash, staged-index digest and porcelain-v2 status
are compared before and after every phase; differences block export. These are
observations, not confinement of a same-user agent or a lock on the source repository.
They cannot tell your own edits from an agent's: leave the source repository untouched
while a task is open.

<a id="first-live-pilot"></a>
**First live pilot (27 October 2026).** On the bundled fixture, the official Codex CLI
0.164.0 with ChatGPT-subscription login and `-m gpt-6-luna` implemented `calc.add` in
about 12 seconds, changing only `calc.py`. Six environment variable names were forwarded
and the rest dropped. Confined verification passed, and the exported patch passed
`git apply --check` on a fresh clone of the base. The source repository's guard was
unchanged. Codex reported usage of about 61k input tokens (mostly cached) and 326 output
tokens; these are claims, not MAESTRO measurements.

The approval step in this pilot was an **automated pilot approval**: the implementing
engineering agent ran `trusted approve` under the founder's written sprint
authorization, and the approval record names it as such. The pilot therefore shows that
approval is bound to the exact verified snapshot, not that a human reviewed this
particular patch.

Evidence includes tracked files and non-ignored untracked files. Ignored paths are
reported by name only and never force-added. Included bytes, full file modes/types,
and directories (including empty directories and the clone root) are bound by the
manifest and Git tree. Submodules, `.gitmodules`, nested `.git`, symlinks, special files,
hardlinks, more than 2,000 entries or 20 MiB are refused. Git transformations that do
not preserve the included bytes are refused too. Evidence uses a private index;
it does not stage changes in the source repository.

Verification materializes only the included set from the evidence tree and checks its
hash before running exactly `python_runtime()[0] -I -B -m unittest discover -s tests`, or,
for a task started with layout options, a constant first-party runner given the validated
directories and glob as separate arguments (`-I -B -c <runner> [pythonpath…] -- -s DIR -p GLOB
[-t TOP]`). Layout values are plain relative paths that must exist in the snapshot; there is
no command, shell or interpreter option. A configured run fails when no test ran and
records the test counts.
The unchanged Seatbelt policy permits writes only in that disposable copy, denies
fork/network and limits runtime to 60 seconds. Exit status and bounded stdout are
recorded; on failure the existing runner supplies a bounded stderr excerpt. The clone
is re-snapshotted afterwards, again at approval, and again at export. A later write
invalidates pending approval; an already exported patch still represents its recorded
tree, not subsequent live files. Verification is not a proof that arbitrary project
tests are adequate or honest.

`export.patch` and its SHA-256 are stored in the task directory. Export uses the base
and evidence trees and never applies, commits or pushes the patch. Reviewing or applying
it is a separate human action. There is no trusted-local retry, automatic partial
cleanup, credential inspection or sandbox-policy expansion.

### Claude Code reviewer (experimental)

`trusted start --review-model MODEL` makes a task review-required. After verification
passes, `trusted review TASK_ID [--claude-bin PATH] [--timeout SECONDS]` runs one fresh,
non-interactive Claude Code process, and approval then requires its completed review.
Tasks started without `--review-model` behave exactly as before.

* **Input.** MAESTRO builds it from the snapshot's Git objects, never from the live
  clone: the task text, every included file with its hash, the exact tree patch, the
  changed files and the verification record. It is staged read-only as
  `review-N/input.txt`, hashed and sent on stdin. It contains no local paths and nothing
  from Codex's messages or session. The review contract tells the model that all of it
  is untrusted data.
* **Process.** The argv is fixed, the working directory is an empty `review-N/cwd`, and
  the environment is constructed: `HOME`, `USER`, `LOGNAME`, `PATH`, `SHELL`, `TMPDIR`,
  `CLAUDE_CONFIG_DIR` when set, plus `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. API
  keys, tokens, base URLs, proxies and a parent Claude Code session's variables are
  dropped. The official CLI uses its own subscription login; MAESTRO never reads it. The
  timeout is 600 seconds by default (at most 1,800) and each output stream is capped at 1 MiB.

  ```text
  claude -p --output-format json --model <model> --tools "" --strict-mcp-config --safe-mode --restricted --no-chrome --disable-slash-commands --no-session-persistence --permission-mode dontAsk --json-schema <review schema> --system-prompt <review contract>
  ```

  Every flag was checked against `claude --help` of Claude Code 2.1.296. `--tools ""`
  removes all built-in tools, so the reviewer cannot read beyond its input or edit
  anything. `--json-schema` adds one tool, StructuredOutput, which only returns the review. `--safe-mode`, `--restricted` and `--strict-mcp-config` skip CLAUDE.md,
  hooks, plugins, MCP servers and settings files. `--bare` is not used because it
  disables subscription login. None of this is OS confinement: like Codex, the reviewer
  process runs as your user.
* **Output.** One JSON object: the echoed snapshot and patch hashes, a verdict
  (`no_blocking_findings` or `changes_requested`), a summary and at most 20 findings.
  Each finding has a severity (`blocking`, `major`, `minor`, `info`), file, line, an
  *observation* (what the input shows) and a *conclusion* (the reviewer's judgement).
  It must arrive as the input of one StructuredOutput call; reply text is never read as
  a review. Claude Code checks that call against a JSON Schema built from the contract
  (exact keys, allowed values, lengths, and the reviewable files when there are at most
  256) and, on a mismatch, asks the model again within the same run (up to 5 times by
  default). If no call matches, the attempt fails. MAESTRO then validates the object with
  its own rules, including the echoed hashes, which the schema leaves out so the model
  must copy them from its input, and verifies the model from the CLI's own `modelUsage`
  report. One authorized live smoke test on the synthetic fixture (a single call, Claude
  Code 2.1.296, `claude-sonnet-5-5`, every flag above) passed: Claude Code returned a valid
  `structured_output` on the first call and MAESTRO accepted it. The CLI's retry after a
  mismatch was not exercised live; it is covered offline only.
* **Record.** The `review.N` artifact holds the provider, CLI path and version, the
  requested and reported models, the snapshot, tree, patch and input hashes, the exit
  code, duration, output hashes and the validated review. `trusted status` shows the
  latest attempt and its findings.
* **Gate.** Approval and export require the latest attempt to be completed,
  model-verified and bound to the current snapshot hash, tree and exact patch hash. A
  failed, malformed, unverified or stale review cannot satisfy the gate. A snapshot or source
  repository change around the review invalidates the task. Blocking findings refuse
  ordinary approval: a human can `reject`, or approve with `--override-review REASON`,
  which is recorded in the approval. A completed review is final. A second attempt is
  allowed only after one that did not complete.
* **Limits.** The review is a model opinion, not proof of correctness, and prompt
  injection in reviewed files can still influence it. It never approves, exports or
  changes the snapshot. `tests/fixtures/fake_claude.py` is an explicit offline fixture:
  production never selects it, and its `offline-fixture` version satisfies the gate only
  for a test task with a test-context caller.

### Scoped review context (experimental)

`trusted start --review-context scoped [--review-budget TOKENS]` sends the reviewer a
deterministic subset of the verified snapshot instead of every file. The default stays
`full`. A scoped review is labelled as such in its record, the task status, the approval
and the export, and it is **not a full-repository review**.

* **Always included:** every changed file in full, a deleted file's full base content, the
  exact patch, the task text and the verification record. These are never truncated.
* **Selected:** related files in full, ranked by a Python AST graph over both the base and
  the snapshot tree (direct imports and importers, tests by import or naming, then nearby
  files), plus a small map of definition names. The method is adapted from the Sprint 06A
  offline selector, whose design drew on Aider's repo map, Repomix and diffctx; no code
  from them is included.
* **Budget:** the whole input, header and task included, is measured in estimated tokens
  (bytes / 4; default 32,000), within the existing 512 KiB cap. This is a sizing unit,
  not a tokenizer or a measurement of Claude usage.
* **Never sent incomplete:** if the mandatory content alone exceeds the budget, or a
  discovered direct import, importer or direct test would be omitted, Claude is not
  launched. The attempt is recorded as `unavailable` with the reason; raise the budget
  or use the full context.
* **Recorded:** the `review.N` artifact holds the policy version, budget, status,
  included files, omitted count, critical omissions, the context digest (over the whole
  input, task text included) and the digest of a local audit file listing every snapshot
  file with its inclusion reason. The reviewer must echo the context digest. A finding
  may cite only a supplied file. Approval and export still bind the full snapshot and
  exact patch.
* **Limits:** relevance is file-level and approximate. Dynamic imports, fixtures loaded by
  path, configuration and non-Python consumers are not resolved; an omitted file is not
  evidence that it is irrelevant or correct.
* **Tests reached through packages (policy v2).** A test is must-include when it imports a
  changed module directly, is named after it, or reaches it within three explicit import
  hops (tomli's tests use `from . import tomllib`, which reaches the parser through two
  package initializers). Implicit parent-package imports are not followed, so a test that
  imports a sibling submodule is not made critical. On tomli, a 12,000-token budget now
  reports `incomplete-critical-context` instead of `selected`, and the default 32,000
  selection is unchanged. Longer import chains and tests that load code dynamically are
  not detected.
* **Offline measurement on tomli (about 1,000 files):** the full input is 437,968 bytes
  and the scoped input 61,679 bytes (13 files), with every manually chosen target file
  included.
* **One live comparison on a correct patch (Sprint 06C, tomli #312, `claude-sonnet-5-5`):**
  on the same frozen snapshot and patch, the earlier full review used 230,538 Claude input
  tokens and one scoped review used 31,324 (86.4% fewer), as reported by the CLI. Both
  returned `no_blocking_findings`.
  * This is a single sample of each, run about six hours apart, with different envelopes
    and contracts, on a patch already known to be correct.
  * It shows the scoped review neither invented problems nor contradicted the full one
    here. It does not show that scoped reviews are as good as full reviews.
* **One live comparison on a defective patch (Sprint 06D, tomli #312, `claude-sonnet-5-5`):**
  both reviewers got the same frozen, deliberately defective patch. It passes tomli's test
  suite but rejects valid TOML (a document whose last line is a comment ending in a
  backslash); an independent offline test confirms the defect. One run each, no retry:
  * Full review: completed, `changes_requested`, with a blocking finding that names the
    defect (230,678 input tokens).
  * Scoped review: Claude's raw answer also named the defect as blocking (31,446 input
    tokens), but it added an extra `null` key to a finding, so MAESTRO's strict validation
    rejected it. Officially the scoped review failed, and that result stands. The
    `--json-schema` output path above was built afterwards; it does not change this result.
  * One run per side, on a defect visible in the changed file itself, is an anecdote, not a
    detection rate. Equivalent review quality is not proven.

<a id="reviewer-pilot"></a>
**Reviewer pilot (27 October 2026).** Claude Code 2.1.296, signed in with a Claude Pro
subscription, ran with `--model claude-sonnet-5-5` and reviewed the first pilot's Codex output.
Codex was not run again. An offline-fixture stand-in replayed the preserved Codex output
byte for byte, and MAESTRO's capture reproduced the first pilot's snapshot (`836d1a8a…`)
and patch (`2e8763b5…`) exactly. The review completed on its first attempt, in one turn
of about 4 seconds. The CLI reported `claude-sonnet-5-5`, and the result, bound to both
hashes, was `no_blocking_findings` with no findings. Approval and export then succeeded,
and the patch applied cleanly to a fresh clone of the base. The approval was an
automated pilot approval and is recorded as such; because of the replay label, the task
could only be approved in test context.

<a id="two-agent-run"></a>
**Founder-approved two-agent run (27 October 2026).** A fresh live run on the fixture used
the normal CLI with `--model gpt-6-luna --review-model claude-sonnet-5-5`. The first
attempt stopped at verification. Codex announced the change but ended its turn without
editing, so the snapshot was unchanged, the tests failed and the task ended `failed`; no
review was spent on it. The second attempt, a new task with the same prompt, completed.
Codex changed only `calc.py` and confined verification passed. Claude Code then completed
one review with no findings and verdict `no_blocking_findings`, bound to snapshot
`836d1a8a…` and patch `2e8763b5…`. The founder read the diff, the verification result and
the review, and decided to approve. The engineering agent ran the approve command on that
explicit instruction, and the approval record says so. The export passed
`git apply --check` on a fresh clone and reproduced the evidence tree. The source
repository was unchanged.

## Requirements

* macOS with `/usr/bin/sandbox-exec`. It is present on current macOS, though Apple marks it
  deprecated (see [Limitations](#limitations)).
* Python 3.9 or newer. Standard library only, nothing to install.
  - **Supported:** the Xcode Command Line Tools Python (`/usr/bin/python3`).
  - **Experimental:** Homebrew Python 3.15. MAESTRO's task flow works, but some
    confinement tests fail ([#7](https://github.com/ukaanari/maestro-agent-workshop/issues/7)).
    `doctor` warns for any interpreter other than the supported one.
  - The interpreter must be installed **outside your home directory**. Interpreters under
    your home directory, such as pyenv, conda or uv-managed Pythons, are refused by the
    sandbox's path policy, and tasks end `blocked`. `maestro.py doctor` reports this case.
* Git 2.42 or newer at `/usr/bin/git`, from the Xcode Command Line Tools (needs
  `git worktree add --orphan`).

Developed and tested on macOS 26.7 (arm64, SIP enabled), with the Xcode Python 3.9.6 and
Apple Git 2.54.0. CI also verifies GitHub's macOS 26.6.2 arm64 runner image, where SIP is
disabled. Intel Macs and other macOS major versions have not been verified.

## Quick start

```sh
git clone https://github.com/ukaanari/maestro-agent-workshop.git
cd maestro-agent-workshop
python3 maestro.py doctor                  # read-only check of this machine
python3 -m unittest discover -s tests -v   # Trusted Local tests skip unless this is /usr/bin/python3
python3 examples/demo.py                   # end-to-end demo in a temporary directory
```

`doctor` prints one JSON result per check (`ok`, `warn`, `fail`, `skip` or `info`), with a
`fix` hint for each failure, and exits 2 if anything fails. It checks:

* the platform;
* where the Python interpreter lives;
* the state root, which is inspected but never created;
* the Seatbelt self-test;
* a launch of the real fake worker under the real agent policy;
* Git, by creating a synthetic unborn worktree.

It installs and configures nothing. Its only writes are temporary directories, which it
removes.

The demo runs three tasks in a throwaway state directory and deletes it afterwards
(`--keep` keeps it for inspection):

1. **Success path.** The walkthrough below, automated, including a check of the expected
   snapshot hash.
2. **Tamper detection.** After a successful run the demo edits the output file. The approval
   attempt is refused and the task becomes `invalidated`.
3. **Review rejection.** The synthetic reviewer requests changes, so verification never
   runs and the task cannot be approved.

## Walkthrough: one task, end to end

> Every agent here is a **synthetic, deterministic stand-in**: `fake-codex` for the
> implementer and `fake-claude-code` for the reviewer. No model is called, and no real
> Codex or Claude Code is involved. The review is a fixture, not a semantic code review.

The flow is: task creation → deterministic implementation → verified handoff → independent
review → verification → human approval. Use a throwaway state directory:

```sh
ROOT="$(mktemp -d)/state"
m() { python3 maestro.py --root "$ROOT" "$@"; }
```

**1. Create the task.** It is single-attempt and fake-only.

```sh
ID=$(m create 'Create a greeting' --file greeting.txt --content 'Hello MAESTRO' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
```

**2. Run it.** The synthetic implementer runs inside the Seatbelt sandbox and returns an
edit *request*. The coordinator applies the edit, hashes the whole worktree, and stores the
handoff. A *fresh* synthetic reviewer process then receives the hash-verified handoff, and
a data-only check verifies the file.

```sh
m run "$ID"
```

```json
  "status": "awaiting_approval",
  "evidence": {
    "snapshot_sha256": "3c992e2089caf176615f6f9c5bb03865490ff4ba7ade1bbae3259f55cb2f0ec6",
    "handoff_sha256": "…", "review_sha256": "…", "verification_sha256": "…"
  }
```

The snapshot hash covers only file bytes, paths and modes, so you should get **exactly this
value** on any machine. The demo and CI check it. The other hashes differ per run, because
they include the random task ID.

**3. Inspect the evidence.**

```sh
m artifact "$ID" handoff        # "source": "fake-codex", "destination": "fake-claude-code", full snapshot
m artifact "$ID" review
m artifact "$ID" verification
```

```json
{
  "handoff_sha256": "…",
  "snapshot_sha256": "3c992e2089caf176615f6f9c5bb03865490ff4ba7ade1bbae3259f55cb2f0ec6",
  "summary": "Independent fake review fixture; no semantic code review.",
  "verdict": "approved"
}
{
  "check": "exact-file-content-v1",
  "fake_only": true,
  "passed": true,
  "snapshot_sha256": "3c992e2089caf176615f6f9c5bb03865490ff4ba7ade1bbae3259f55cb2f0ec6",
  "task_id": "…"
}
```

**4. Approve.** A human names the exact snapshot. Approval re-checks every stored hash and
re-snapshots the live files first.

```sh
m approve "$ID" --snapshot 3c992e2089caf176615f6f9c5bb03865490ff4ba7ade1bbae3259f55cb2f0ec6 --founder 'Your name'
m status "$ID"
```

The event log in `status` ends like this (`evidence_current: true`):

```
created            Single attempt, fake-only synthetic task created
preparing          Creating isolated unborn Git worktree
implementing       Starting deterministic Codex stand-in
reviewing          Implementation stopped; delivering verified snapshot to fresh reviewer
verifying          Running fixed, data-only acceptance check
awaiting_approval  Review and verification passed; explicit founder approval required
approved           Founder approved locally: Your name
```

If you edit `$ROOT/tasks/$ID/worktree/greeting.txt` before step 4, approval is refused and
the task becomes `invalidated`. Approval is only a local record: nothing is staged,
committed or pushed. Clean up with `rm -rf "$(dirname "$ROOT")"`.

## CLI reference

```sh
python3 maestro.py doctor
python3 maestro.py create 'Create a greeting' --file greeting.txt --content 'Hello MAESTRO'
python3 maestro.py run TASK_ID
python3 maestro.py status TASK_ID
python3 maestro.py artifact TASK_ID handoff      # also: review, verification
python3 maestro.py approve TASK_ID --snapshot EXACT_SHA_FROM_STATUS --founder 'Your name'
python3 maestro.py cancel  TASK_ID
python3 maestro.py recover TASK_ID               # mark an abandoned active task interrupted
python3 maestro.py dispose TASK_ID               # remove a terminal task's *clean* worktree
python3 maestro.py dispose TASK_ID --remove-reviewed-output  # also delete output that exactly matches the stored handoff
```

All output is JSON. State lives in `.maestro/` beside `maestro.py` (git-ignored), or in an
empty or new directory given with `--root PATH`. The `--scenario` flag on `create` selects
a fake-agent behaviour for testing failure paths: `success`, `review-fail`, `stale-review`,
`timeout`, `permission`, `malformed`, `test-fail` or `output-limit`.

`run` exits 0 only when the task reaches `awaiting_approval`, and 2 otherwise. Approval is
a **local record**. It never stages, commits, pushes or merges anything. `dispose` only
removes a clean worktree by default. With `--remove-reviewed-output`, it also deletes
output, but only if the live worktree is *exactly* the stored, hash-verified handoff
snapshot, whose full file contents stay in SQLite. Anything else is retained. The `--founder`
value is an audit label typed by the operator, not authentication.

## How it works

Nine small Python modules (about 2,800 lines in total):

| Module | Responsibility |
|---|---|
| `maestro.py` | CLI and JSON output |
| `doctor.py` | Read-only prerequisite checks, run through the production sandbox and Git code paths |
| `workflow.py` | SQLite state machine, event log, single-attempt engine, evidence gates |
| `workspace.py` | Synthetic Git worktrees, path policy, bounded full-content snapshots |
| `execution.py` | Owned process groups, cancellation, time and output limits |
| `sandbox.py` | Seatbelt profile generation, execution policy validation, fail-closed self-test |
| `agents.py` | Versioned IPC envelopes, disabled real adapters, deterministic fake worker |
| `trusted.py` | Trusted Local mode: isolated clone, Codex CLI launch, snapshots, verification layouts, `check`, approval and export gates |
| `reviewer.py` | Trusted Local Claude Code reviewer: fixed invocation without built-in tools, review input, review schema and strict output validation |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the lifecycle, trust boundaries and
evidence chain, and [P1A-SECURITY.md](P1A-SECURITY.md) for the confinement design, what
the tests prove, and the known gaps.

## Limitations

These are deliberate disclosures, not fine print. Trusted Local first, then Confined Mode.

* **Trusted Local does not confine Codex or Claude Code.** Both run as your user, with
  your permissions and login. Only verification runs in Seatbelt. Source-repository
  guards and snapshot checks detect changes; they do not prevent them.
* **Trusted Local verification is narrow.** It runs the project's `unittest` suite with
  `/usr/bin/python3` (3.9), standard library only, within 60 seconds, with no network and
  no subprocesses. pytest-only suites, third-party test dependencies that are not inside
  the repository, and tests that spawn processes cannot be verified yet. A passing suite
  shows only that those tests passed.
* **Trusted Local snapshots** refuse symlinks, submodules, nested `.git`, hardlinks,
  special files, more than 2,000 entries and more than 20 MiB.
* **Full review context sends the whole snapshot.** By default every included file goes to
  Claude Code, capped at 512 KiB; a larger repository cannot be reviewed in full, and a
  large input uses a correspondingly large share of your Claude quota (tomli, about 1,000
  files: roughly 440 KB). The experimental scoped context sends far less, but it is a
  partial review and its relevance selection is approximate (see
  [Scoped review context](#scoped-review-context-experimental)).
* **Live evidence is small.** Real Codex and Claude Code runs have passed only on bundled
  synthetic fixtures. The project demo is synthetic too; no third-party repository has
  been validated end to end yet.
* **In Confined Mode, only fake agents run.** The pipeline is proven with deterministic
  stand-ins that emit fixed edits and fixed verdicts. The review is *not* a semantic code
  review. Whether the real Codex CLI and Claude Code can run under MAESTRO's sandbox is
  **unknown and partly known to conflict** (next point).
* **Real agents do not yet fit inside the sandbox.** Codex CLI and Claude Code apply their
  own Seatbelt profiles on macOS. Inside a MAESTRO profile any nested `sandbox-exec` fails
  (`forbidden-sandbox-reinit`), so either their inner sandbox is disabled and MAESTRO's
  becomes the only boundary, or MAESTRO cannot wrap them. Real agents also need `fork`,
  shells and network access, all of which the current profile denies. These are open
  design decisions; see [docs/ROADMAP.md](docs/ROADMAP.md).
* **There is a known process-escape gap
  ([#2](https://github.com/ukaanari/maestro-agent-workshop/issues/2)).** When `fork` is
  allowed (only in tests today), a child that calls `setsid()` or `setpgid()`, or
  double-forks, leaves the process group and survives cleanup. It stays sandboxed, but it
  can keep running. This blocks real-agent execution until it is fixed.
  - Cleanup does verify that no *live member of the group* remains after SIGKILL, and it
    fails loudly otherwise.
  - That verification uses macOS `libproc`. Elsewhere, the group is signalled but not
    verified.
* **Protected paths must be direct children of a writable grant.** A deeper protected path
  could be moved out of its deny rule by renaming an ancestor directory. Such policies
  are rejected (audit finding F-01).
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
* **Confined tasks are tiny.** Each task gets one target file. Snapshots allow at most 32
  files and 64 KiB in total.
* **Few hosts were tested.** Results come from one macOS 26.7 arm64 development Mac and
  GitHub's macOS 26.6.2 arm64 runner image. The full suite passes with the Xcode Python
  only; with Homebrew Python 3.15, some confinement tests fail
  ([#7](https://github.com/ukaanari/maestro-agent-workshop/issues/7)).

## Roadmap

Trusted Local (unconfined agents, confined verification) is the usable path today.
Running the real agents *inside* MAESTRO's sandbox (P1-B) is still blocked on four design
decisions: the process-escape fix, the nested-sandbox conflict, shells inside the sandbox,
and network and credential access through an allowlisting proxy. See
[docs/ROADMAP.md](docs/ROADMAP.md).

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
