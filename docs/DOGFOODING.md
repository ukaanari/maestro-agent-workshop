# Dogfooding MAESTRO on MAESTRO (Offline)

This guide explains how to exercise MAESTRO's Trusted Local workflow on MAESTRO itself and on
local Python repositories **without calling real AI agents, spending API quotas, or touching
credentials**.

> [!NOTE]
> Trusted Local Mode runs real Codex and Claude Code **unconfined**, with your normal user
> permissions. Only verification runs inside macOS Seatbelt. Offline rehearsals use explicit
> fake fixtures (`tests/fixtures/fake_codex.py`, `tests/fixtures/fake_claude.py`,
> `examples/project-demo/fake_implementer.py`) and never contact the network.

## 1. Check host prerequisites (read-only)

```sh
/usr/bin/python3 -B maestro.py doctor
```

`doctor` never creates `.maestro/` or modifies the repository.

## 2. Run `trusted check` on MAESTRO itself

MAESTRO's confined verifier denies `fork()`, `subprocess`, and network access. Because most of
MAESTRO's full test suite spawns `git`, `sandbox-exec`, or child Python processes, running
`trusted check` against the whole `tests/` directory fails on Seatbelt `PermissionError`
denials — which is expected and proves confinement is active.

To verify a pure in-process stdlib module inside MAESTRO itself, target a pure-Python test
file with `--test-pattern` (from a full, non-shallow Git clone):

```sh
BASE=$(git rev-parse HEAD)
/usr/bin/python3 -B maestro.py trusted check \
  --repo "$PWD" \
  --base "$BASE" \
  --test-dir tests \
  --test-pattern 'test_check_suite.py'
```

Expected highlights in the JSON output:

* `"compatible": true`
* `"source_clean": true` (`source_clean_scope: "working_tree_vs_source_head_excluding_gitignored"`):
  reports whether the source working tree had staged, unstaged, or non-ignored untracked changes
  relative to its current `HEAD` at check time. Gitignored files do not affect `source_clean`,
  and `trusted check` always clones and verifies the pinned `--base` commit rather than
  working-tree edits.
* `"baseline": {"passed": true, "exit_code": 0, "summary": {"tests_run": 8, "executed": 8, ...}}`

When the source tree is dirty or a baseline fails, `trusted check` may include heuristic
`"hints"` alongside `"hints_note"`. These are **possible causes / observations** matched from
truncated output and Git status — not definitive root-cause diagnoses — covering:

* uncommitted or non-ignored untracked changes in the source working tree
* zero tests discovered (`--test-dir`, `--test-pattern`, `--top-level-dir`)
* all discovered tests skipped (Trusted Local requires at least one executed test)
* possible `subprocess` / `fork()` denial inside Seatbelt
* possible missing imports (`--pythonpath`, `--top-level-dir`, or unavailable third-party packages)
* possible network denial inside Seatbelt

## 3. Rehearse Trusted Local flows offline

Before running any live agent on your repository, rehearse the CLI flows with the bundled
offline demos (temporary directories, automatically cleaned up; approvals use the explicit
test-only `tests/fixtures/trusted_test_cli.py` harness):

```sh
/usr/bin/python3 -B examples/trusted-local/demo.py
/usr/bin/python3 -B examples/project-demo/demo.py
```

What each demo actually exercises:

* `examples/trusted-local/demo.py`: minimal single-file Codex-only flow on the `calc.py` fixture
  (`start → implement (fake_codex.py) → verify → approve → export → status`). It does **not**
  run `trusted check`, `trusted review`, `trusted diff`, or `git apply --check`.
* `examples/project-demo/demo.py`: multi-file `src/` layout flow on the `stockroom` fixture
  (`trusted check → start (--review-model) → implement (fake_implementer.py) → verify →
  review (fake_claude.py) → diff → status → approve → export`), plus a second deliberately flawed
  task that confined verification rejects. It does **not** apply the exported patch with
  `git apply --check`.
* `tests/test_dogfooding.py`: verifies MAESTRO's own `test_check_suite.py` via a non-shallow
  export of `HEAD`, confirms shallow clones are still rejected, tests `source_clean` and
  heuristic hints, and runs an end-to-end offline scoped-review → `export` → `git apply --check`
  workflow.

## 4. Known dogfooding boundaries

* **Full (non-shallow) Git clones are required.** MAESTRO's `clone_config()` intentionally
  rejects `.git/shallow` metadata (`unsupported clone metadata: shallow`). If you checked out
  a repository with `--depth 1` (for example in CI), unshallow it first (`git fetch --unshallow`)
  before running `trusted check` or `trusted start`.
* **Leave the source repository untouched** while a Trusted Local task is open. Source-guard
  checks compare HEAD, refs, stash, index, and working-tree status before and after every phase.
* **Subprocess-heavy test suites** (such as MAESTRO's own `test_sandbox.py` or
  `test_privacy_scan.py`) cannot run inside Seatbelt-confined verification today; run them
  externally on the exported patch in a fresh clone after `trusted export`.
* **Never pass production credentials** or `--codex-bin` pointing at untrusted binaries.
