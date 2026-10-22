# Changelog

There are no tagged releases yet. Entries describe the default branch.

## 0.1.0-alpha (release candidate, not yet tagged)

First pre-release. Experimental and macOS only. **Only deterministic, synthetic agents
run.** The Codex CLI and Claude Code adapters still always refuse.

### Added

* `maestro.py doctor`: a read-only prerequisite check. It reports the platform, interpreter
  location, state root, Seatbelt self-test, a confined launch of the fake worker under the
  real agent policy, and Git `worktree add --orphan` support. It prints structured JSON
  with a fix hint for each failure.
* `maestro.py --version`.
* GitHub Actions CI on macOS 26 arm64. It runs `doctor`, the test suite and the demo with
  the Xcode and Homebrew Pythons, with read-only token permissions and no secrets.
* A README walkthrough of a single task end to end, verified verbatim in bash and zsh.
  The demo now checks the snapshot hash, which is identical on every machine.
* 6 tests for `doctor`, bringing the suite to 42. The original 36 are unchanged.

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
