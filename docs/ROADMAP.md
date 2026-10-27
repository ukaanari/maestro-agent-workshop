# Roadmap

This file separates what exists from what is planned. Nothing below "Planned" is
implemented. There are no dates: the project has one maintainer and progresses
phase by phase.

## Done

* **P0: orchestration backbone.** Single-attempt SQLite lifecycle, structured handoff
  from fake implementer to fresh fake reviewer, full-snapshot evidence binding, explicit
  hash-named approval, cancellation, recovery without replay, 23 regression tests.
* **P1-A: confinement layer.** Deny-default macOS Seatbelt profiles for every agent
  process, execution-policy validation, fail-closed per-launch self-test, 13 kernel-enforced
  isolation tests. See [P1A-SECURITY.md](../P1A-SECURITY.md).
* **Continuous integration** on GitHub-hosted macOS 26 arm64 runners, with an exact
  known-failure gate for the experimental Python 3.15 job (#7).
* **Trusted Local Mode** (`v0.2.0-alpha`): the real Codex CLI, run unconfined, on an
  isolated clone of an existing repository; verification by the project's `unittest`
  suite in a confined copy of the snapshot; hash-bound approval; patch export.
* **Claude Code reviewer** (`v0.3.0-alpha`): an optional fresh, tool-less review bound to
  the snapshot and patch, gating approval.
* **Usability MVP** (`v0.4.0-alpha`, unreleased): explicit verification layouts,
  read-only `trusted check`, next-step hints, a multi-file offline project demo and a
  quickstart.

## Planned: P1-B, real agent adapters inside the existing sandbox

Goal: one real Codex CLI implementation and one fresh, independent Claude Code review,
run under MAESTRO's sandbox, with no manual copying between agents. The sandbox must not
be weakened to make a CLI work. If a CLI cannot run under the boundary, the work stops and
the result is documented.

### Design decisions that must be made first

1. **Process-escape fix.** Real agents need `fork`, and a `setsid()` or double-forked child
   currently survives cleanup. Options:
   (a) run agents as a dedicated non-admin macOS user, and clean up by killing every
   process of that uid; or
   (b) a `sandbox_check()`-based sweep that finds processes carrying the run's profile.
   (b) relies on Apple private interfaces, and variadic `ctypes` calls on arm64 are fragile.
2. **Nested-sandbox conflict (verified).** Codex CLI and Claude Code apply their own
   Seatbelt profiles on macOS, and inside a MAESTRO profile nested `sandbox_apply` fails
   with `forbidden-sandbox-reinit`. Either their inner sandbox is disabled and MAESTRO's
   profile is the only boundary, or they cannot be wrapped. Approval prompts must stay
   non-interactive and fail closed.
3. **Shells inside the sandbox.** Agents run tool commands through a shell. Allowing a
   pinned shell plus named tools as *child* executables is a deliberate widening, and needs
   an explicit, reviewed list.
4. **Network and credentials.** Seatbelt can filter only by `localhost` or `*` plus a
   port, never by hostname. The proposed design is a MAESTRO-owned loopback CONNECT proxy
   with an exact-host allowlist per provider and no TLS interception, with everything else
   logged and denied. Credentials would come from one approved token file in a
   MAESTRO-owned provider home, granted read-only as a single file. `~/.codex`,
   `~/.claude` and the Keychain would never be granted.

### Work after those decisions (all tests offline)

* `ExecPolicy.child_executables`, `network="proxy"` mode with a stdlib proxy tested
  against a local fake upstream, per-adapter environment allowlist, single-file credential
  grant, and a read-only snapshot copy for the reviewer.
* Escape-proof cleanup, with a test that `setsid` and double-fork children are gone after
  a timeout and after cancellation.
* Optional `RLIMIT_FSIZE` / `RLIMIT_NOFILE` / `RLIMIT_CPU`.
* `CodexAdapter.run` and `ClaudeCodeAdapter.run` launched only through `Seatbelt.run`,
  with small first-party fixtures emulating each CLI's JSON stream so the tests run
  without the real CLIs. Provider selection stays explicit and never falls back between
  fake and live.
* One synthetic end-to-end pilot run, approved in advance, on a MAESTRO-owned throwaway
  repository.

## Later (not yet designed in detail)

* Trusted Local verification beyond the standard library: pytest and third-party test
  dependencies, without granting personal site-packages or the network.
* Validation on independently maintained third-party repositories.
* Usage and session limits, only where the official CLI actually enforces them. MAESTRO
  will not claim hard token caps based on usage reported after the fact.
* An isolation backend for Linux.

## Explicit non-goals for now

Dashboards, planning agents, multi-agent swarms, automatic retries, automatic commits,
pushes or merges, and any silent fallback to unconfined execution or paid API usage.
