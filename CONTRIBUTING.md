# Contributing to MAESTRO

Thanks for your interest. MAESTRO is small, experimental and security-focused. The rules
below exist to keep its guarantees checkable.

## Before you start

* For anything beyond a small fix, please open an issue first. Running real agents inside
  the sandbox (P1-B) depends on design decisions listed in [docs/ROADMAP.md](docs/ROADMAP.md),
  and changes that pre-empt those decisions are unlikely to be merged. Trusted Local
  improvements must keep its approval, review and verification gates intact.
* Security vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

macOS, Python 3.9+, Git 2.42+. There is nothing to install. Use `/usr/bin/python3`: the
Trusted Local tests skip on any other interpreter.

```sh
/usr/bin/python3 -B maestro.py doctor                                   # read-only check
/usr/bin/python3 -B .github/scripts/check_suite.py --known-failures ""   # the full suite, as CI runs it
/usr/bin/python3 -B examples/demo.py                                    # Confined Mode demo
/usr/bin/python3 -B examples/project-demo/demo.py                       # Trusted Local, fake agents
```

The full suite must pass on macOS before a change can be merged. CI
(`.github/workflows/ci.yml`) runs `doctor`, the suite and the demo on GitHub-hosted
macOS 26 arm64 runners for every pull request. The Xcode Python job is the required
check. The Homebrew Python 3.15 job is experimental and is not a required check while #7
is open. It accepts only the exact test and subTest ids listed in
`.github/known-failures/`. Never add an id there to hide a new failure: each entry needs
a tracking issue. CI has read-only permissions and no secrets, and that must stay true. On other platforms the confinement tests cannot run, and
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
