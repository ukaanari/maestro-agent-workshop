# Contributing to MAESTRO

Thanks for your interest. MAESTRO is small, experimental and security-focused. The rules
below exist to keep its guarantees checkable.

## Before you start

* For anything beyond a small fix, please open an issue first. The next phase (real agent
  adapters, P1-B) depends on design decisions listed in [docs/ROADMAP.md](docs/ROADMAP.md),
  and changes that pre-empt those decisions are unlikely to be merged.
* Security vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

macOS, Python 3.9+, Git 2.42+. There is nothing to install.

```sh
python3 maestro.py doctor      # read-only check of your machine
python3 -m unittest discover -s tests -v
python3 examples/demo.py
```

The full suite must pass on macOS before a change can be merged. CI
(`.github/workflows/ci.yml`) runs `doctor`, the suite and the demo on GitHub-hosted
macOS 26 arm64 runners for every pull request. The Xcode Python job is the required
check. The Homebrew Python 3.15 job is experimental and non-blocking while #7 is open; do
not let it hide new failures. CI has read-only permissions and no secrets, and that must
stay true. On other platforms the confinement tests cannot run, and
tasks end `blocked` by design.

## Ground rules

1. **Standard library only.** New runtime or test dependencies need prior discussion.
2. **Fail closed.** Missing capabilities, unexpected input, unknown fields and policy
   violations must stop the task, not degrade it. Never add an unconfined fallback, a
   weaker profile "to make it work", automatic retries or silent mode switches between
   fake and live agents.
3. **Every untrusted process goes through `sandbox.Seatbelt.run`.** `execution.execute` is
   for fixed coordinator argv only.
4. **Tests stay offline and synthetic.** No network beyond test-owned loopback listeners
   and TEST-NET addresses, no real model or API calls, no reading personal files or
   credentials, no installed agent CLIs. Use canaries in private temporary directories.
5. **Security changes need a failing test first.** If you change `sandbox.py`, show that
   the relevant test fails when your rule is removed or weakened (a manual mutation check
   is fine), and describe that in the pull request.
6. **Docs must match behaviour.** Update the README limitations, `P1A-SECURITY.md` or
   `docs/ROADMAP.md` when a capability or a gap changes. Mark anything verified only by
   hand as such.
7. **Keep changes small and readable.** Match the existing style: short modules, explicit
   checks, comments that explain *why*.

## Licensing of contributions

MAESTRO is licensed under the Apache License 2.0. Unless you state otherwise, any
contribution you submit is licensed under the same terms (Apache-2.0, section 5). Do not
submit code you do not have the right to license, and keep third-party attributions in
`UPSTREAM.md`, `NOTICE` and `LICENSES/` up to date.
