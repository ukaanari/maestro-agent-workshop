# Changelog

Tagged pre-release: `v0.1.0-alpha` (synthetic-only). "Unreleased" describes work after it.

## Unreleased — Trusted Local MVP

* Codex now receives a constructed environment (`HOME`, `USER`, `LOGNAME`, `PATH`,
  `SHELL`, `TMPDIR`, `CODEX_HOME`) instead of the parent environment minus two keys;
  tokens, other API keys and proxies never reach it. Forwarded names are recorded.
* New `trusted diff` (exact tree-only patch under review), `trusted reject` (recorded,
  terminal `rejected`) and `trusted cancel`; `status` lists changed files.
* Trusted Local tests skip outside macOS `/usr/bin/python3` 3.9, which the mode requires.
  99 offline tests.
* First live pilot on the fixture: Codex CLI 0.164.0, `gpt-6-luna`, subscription login;
  implement → verify → approve → export succeeded and the source repository was unchanged.
  The pilot's approval was an automated pilot approval under the founder's sprint
  authorization, not a human review of that patch.

* Require an explicit validated model at task creation; pass `exec -m MODEL`,
  record it in the Codex artifact, and fail without fallback on model errors.
  Exact argv and model rejection regressions bring the offline suite to 96 tests.

* Fixed Codex argv now includes `exec --ignore-user-config`; `CODEX_HOME` remains
  unchanged while both API-key variables are removed. Test 10 asserts the exact argv.
* Offline-fixture versions cannot be approved outside explicit test tasks and an
  in-process test caller. Normal CLI has no test bypass; test approvals/exports are
  labeled and normal export refuses them. The offline demo uses a dedicated harness.
* Added regression coverage for normal/legacy tasks, environment spoofing, normal CLI
  rejection, test-only export and a simulated non-fixture version (95 offline tests).

* Separate experimental `trusted` CLI and `trusted.py`: staged local clone, fixed Codex
  exec argv, sanitized API-key environment, bounded logs, single-attempt cleanup and
  independent verification through the existing Seatbelt runner.
* Source-repository guards, private-index Git tree plus full-mode manifest, exact-hash
  human approval and binary patch export. Ignored content is excluded and unsupported
  filesystem entries are rejected. The existing confined profile and limits are unchanged.
* Codex path/realpath/version and trust notice in doctor, deterministic offline fixture,
  fake Codex and full CLI demo. Fourteen acceptance tests cover mode separation, claims
  versus evidence, confinement, tampering, escaped descendants and interrupted clones.
* No live model run. Escaped-process containment (issue #2) remains explicitly unsupported.

## 0.1.0-alpha — 2026-10-23 (pre-release, tag `v0.1.0-alpha`)

First pre-release. Experimental and macOS only. **Only deterministic, synthetic agents
run.** The Codex CLI and Claude Code adapters still always refuse.

### Added

* `maestro.py doctor`: a read-only prerequisite check. It reports the platform, interpreter
  location, state root, Seatbelt self-test, a confined launch of the fake worker under the
  real agent policy, and Git `worktree add --orphan` support. It prints structured JSON
  with a fix hint for each failure.
* `maestro.py --version`.
* GitHub Actions CI on macOS 26 arm64. It runs `doctor`, the test suite and the demo with
  the Xcode and Homebrew Pythons, with read-only token permissions and no secrets. The
  Xcode Python passes everything. On `5c4d596`, Homebrew Python 3.15 failed 4
  confinement tests through sandbox denials. 3 of them are fork-enabled, and the
  process-isolation test aborted at `import ctypes` (see F-04 below). This is documented
  in `P1A-SECURITY.md`, and the profile was not widened. Python 3.15 is experimental: its
  job is not required, and it passes only if the failing tests are exactly the known
  ones (#7). The Xcode Python job is the required check.
* A README walkthrough of a single task end to end, verified verbatim in bash and zsh.
  The demo now checks the snapshot hash, which is identical on every machine.
* 6 tests for `doctor`, 1 cleanup regression test and 28 audit regression tests, bringing the suite to 71 (80 after the
  re-review follow-up below).
  The original 36 tests keep every assertion. Three security tests now start children from the
  allowlisted binary, and the process-isolation test runs its probes independently (F-04).

### Security and correctness fixes (independent audit of `5c4d596`, findings F-01 to F-07)

Each fix comes with a regression test in `tests/test_audit_regressions.py`, which fails on
`5c4d596` and passes after the fix.

* **F-01, high.** A protected path nested more than one level inside a writable grant could
  be exposed by renaming an intermediate directory. Such policies are now rejected, and
  protected paths also deny execution.
* **F-02, high.** Process-group cleanup was reworked:
  - every member now gets the SIGTERM grace;
  - nothing is signalled after the child has been reaped;
  - EPERM is accepted only for zombie-only groups, as confirmed through `libproc`;
  - a surviving live member, or a child that cannot be reaped, raises `PolicyError`;
  - the pipes are always closed.
* **F-03, medium.** Policy validation is stricter:
  - the account home comes from the password database;
  - listable grants are restricted;
  - executables must sit outside agent roots, protected state and personal directories,
    and be owned by root or this user;
  - approved roots must not be shared or broadly writable;
  - the sandbox engine must not be a symlink;
  - the self-test requires the refused write to be reported.
* **F-04, medium.** The Python 3.15 analysis was corrected: 3 of the 4 failing tests use
  fork, and the 4th aborted at `import ctypes`. Child processes now start from the
  allowlisted binary. Isolation probes run independently, and a probe that could not run
  is reported as a failure. CI accepts only the exact listed known failures. `doctor` warns
  on interpreters other than the supported one.
* **F-05, medium.** Snapshots now include directories, with path and mode; *this changes
  every snapshot hash*. `dispose --remove-reviewed-output` removes output only when it
  exactly matches the stored, hash-verified handoff.
* **F-06, low.** `doctor` never crashes. Unreadable roots, unsafe database or task paths,
  probe timeouts and failing checks are all reported as structured failures.
* **F-07, low.**
  - A concurrent cancel now ends a run cleanly.
  - Malformed records fail as policy errors.
  - Approval re-checks the handoff against the task specification.
  - The self-test honours cancellation.
  - Non-numeric timeouts are rejected.

### Independent re-review follow-up (of `6274e3d`)

* **NEW-01, CI integrity.** The known-failure gate used to collapse subTest failures into
  their parent test, so one known subTest failure could hide another. It now matches
  exact test and subTest ids from `.github/known-failures/*.txt`. Focused tests in
  `tests/test_check_suite.py` prove that known failures are accepted, and that unexpected,
  parent-level or stale ones are rejected.
* **NEW-02.** Writable grant directories that are group- or world-writable are rejected.
* **NEW-03.** A test file handle is now closed. `doctor` attributes known failures to #7
  only for Python 3.15.

### Fixed

* Process-group cleanup could abort with `PermissionError` instead of reporting a timeout.
  On macOS, `killpg` returns EPERM when the only processes left in the group are dead
  but not yet reaped. `stop_group` now treats that case like "nothing left to kill" and
  still reaps the child. CI found this on its first run on GitHub's macOS 26 runners
  (`test_timeout_stops_descendants_not_only_parent`). The regression test
  `tests/test_process_cleanup.py` reproduces it deterministically.

### Included from the initial publication (2026-10-22)

* P0 orchestration backbone: single-attempt SQLite lifecycle, a synthetic implementer
  handing off to a fresh synthetic reviewer, full-snapshot evidence binding, and approval
  that must name the exact snapshot hash.
* P1-A confinement: deny-default Seatbelt profiles for agent processes, with a
  fail-closed self-test before every launch.

### Known limitations

See the README's [Limitations](README.md#limitations) and [P1A-SECURITY.md](P1A-SECURITY.md):

* only synthetic agents;
* macOS only;
* `sandbox-exec` is deprecated;
* the `setsid` / double-fork cleanup gap is still open;
* no resource limits;
* agents run as the same user;
* the operator is trusted.
