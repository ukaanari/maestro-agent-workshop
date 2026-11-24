# Dogfooding MAESTRO on MAESTRO (Offline)

This guide explains how to exercise MAESTRO's Trusted Local workflow on MAESTRO itself and on
local Python repositories **without calling real AI agents, spending API quotas, or touching
credentials**.

> [!NOTE]
> Trusted Local Mode runs real Codex and Claude Code **unconfined**, with your normal user
> permissions. Only verification runs inside macOS Seatbelt. Offline rehearsals use explicit
> fake fixtures (`tests/fixtures/fake_codex.py`, `tests/fixtures/fake_claude.py`) and never
> contact the network.

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
file with `--test-pattern`:

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
* `"source_clean": true` (if you have uncommitted changes, `trusted check` reports
  `"source_clean": false` and adds a hint to commit or stash them before `trusted start`)
* `"baseline": {"passed": true, "exit_code": 0, "summary": {"tests_run": 8, "executed": 8, ...}}`

When a baseline fails, `trusted check` includes actionable `"hints"` for common causes:

* zero tests discovered (`--test-dir`, `--test-pattern`, `--top-level-dir`)
* all tests skipped (Trusted Local requires at least one executed test)
* `subprocess` / `fork()` denial inside Seatbelt
* missing imports (`--pythonpath`, `--top-level-dir`, or unavailable third-party packages)
* network denial inside Seatbelt
* uncommitted changes in the source repository

## 3. Rehearse the full Trusted Local flow offline

Before running any live agent on your repository, rehearse the end-to-end lifecycle with the
bundled offline demos (temporary directories, automatically cleaned up):

```sh
/usr/bin/python3 -B examples/trusted-local/demo.py
/usr/bin/python3 -B examples/project-demo/demo.py
```

Both demos exercise `trusted check`, `start`, fake `implement`, Seatbelt-confined `verify`,
fake `review`, `diff`, exact-hash `approve` (via the explicit `test_context=True` harness),
`export`, and `git apply --check` on a fresh clone of the base commit.

## 4. Known dogfooding boundaries

* **Leave the source repository untouched** while a Trusted Local task is open. Source-guard
  checks compare HEAD, refs, stash, index, and working-tree status before and after every phase.
* **Subprocess-heavy test suites** (such as MAESTRO's own `test_sandbox.py` or
  `test_privacy_scan.py`) cannot run inside Seatbelt-confined verification today; run them
  externally on the exported patch in a fresh clone after `trusted export`.
* **Never pass production credentials** or `--codex-bin` pointing at untrusted binaries.
