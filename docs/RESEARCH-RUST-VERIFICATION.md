# Research: Feasibility of Sandboxed Rust/Cargo Verification

**Status:** Research only (Issue #22). **Rust/Cargo verification is NOT implemented or supported today.**
Trusted Local Mode currently confines only a narrow Python `unittest` verifier (`/usr/bin/python3` 3.9,
stdlib only, no subprocesses, no network). Real agents in Trusted Local Mode remain unconfined.

---

## 1. Proposed Narrow Scope, Inputs, Paths, and Threat Model

### 1.1 Candidate Verification Tiers

If MAESTRO ever adds confined Rust verification, two distinct tiers should be evaluated separately:

| Tier | Proposed fixed command | Needs `cargo`? | Needs crates / linker? | Blast radius |
|---|---|---|---|---|
| **Tier 0 (Minimal, zero-crate)** | `<toolchain>/bin/rustc --edition 2021 --test <entry.rs> -o <verify>/test_bin && <verify>/test_bin --format=json -Z unstable-options` (or standard output parsing) | No | Linker (`cc`/`ld`) only; no crates, no `build.rs`, no proc-macros | Moderate: still requires `fork`/`exec` for linker and running compiled native test binary |
| **Tier 1 (Workspace `cargo test`)** | `<toolchain>/bin/cargo test --offline --locked --frozen --manifest-path <verify>/Cargo.toml --target-dir <verify>/target --config net.offline=true` | Yes | Yes: `cargo`, `rustc`, system linker (`cc`/`ld`/`xcrun`), vendored crates | High: arbitrary compile-time code execution via `build.rs` and procedural macros |

Neither tier accepts user-supplied shell strings, arbitrary Cargo subcommands, or `RUSTFLAGS` from
environment variables. Every argument is constructed from validated relative paths inside the snapshot.

### 1.2 Pinned Toolchain and Dependency Inputs

To preserve MAESTRO's fail-closed and zero-personal-path guarantees:

* **Toolchain location:** Must live **outside `$HOME`** (never `~/.rustup` or `~/.cargo`, which
  violate `P1A-SECURITY.md`'s personal-directory exclusion). Candidate location: a read-only,
  root- or maintainer-owned prefix such as `/opt/maestro-toolchains/rust-<version>/` verified as
  canonical, regular, and non-group/world-writable.
* **Dependencies:** Zero network access (`(deny network*)`). For Tier 1, every crate dependency
  must be vendored and hash-bound inside the task snapshot (e.g., `vendor/` + `Cargo.lock` +
  `.cargo/config.toml` checked into the repo or materialized read-only from a pinned local vendor
  bundle). Personal Cargo caches (`~/.cargo/registry`, `~/.cargo/git`) are never granted.
* **Environment:** Constructed allowlist only (`PATH` restricted to pinned toolchain + system
  linker directory, `CARGO_HOME=<verify>/.cargo-empty`, `CARGO_TARGET_DIR=<verify>/target`,
  `RUSTUP_HOME` omitted or pointed to the pinned read-only toolchain). All tokens (`CARGO_REGISTRY_TOKEN`,
  API keys, proxies) are dropped.

### 1.3 Proposed Filesystem & Network Policy

* **Readable:** Pinned read-only toolchain prefix, macOS SDK/linker libraries required by `ld`
  (`/usr/lib`, `/System/Library`, Xcode Command Line Tools SDK path), and the materialized
  disposable copy `<task>/verify/`.
* **Writable:** Strictly inside `<task>/verify/` (including `<task>/verify/target/` and a private
  `TMPDIR=<task>/verify/.tmp`). `<task>/clone/`, `.maestro/` state, and `$HOME` remain denied.
* **Network:** `(deny network*)`, unchanged. `--offline --frozen --locked` reinforces this at the
  Cargo layer, while the OS sandbox remains the enforcement boundary.

### 1.4 Threat Model (Including `build.rs` and Procedural Macros)

Unlike Python `unittest` (where untrusted code executes inside a single no-fork interpreter process),
Rust compilation executes untrusted native code at **three** distinct stages:

1. **Build scripts (`build.rs`):** Compiled into native executables and run by `cargo` *before*
   crate compilation. A malicious or buggy `build.rs` can fork arbitrary subprocesses, attempt
   filesystem/network access, emit `cargo:rustc-env=` / `cargo:rustc-link-arg=` directives, or
   consume unbounded disk/CPU/memory inside `target/`.
2. **Procedural macros (`proc-macro = true`):** Compiled into dynamic libraries (`.dylib` on macOS)
   and loaded directly into the `rustc` host process during expansion. A proc-macro runs with the
   full sandbox permissions of `rustc` itself.
3. **Compiled test binaries:** Native binaries generated inside `<verify>/target/debug/deps/` and
   executed directly. Because Seatbelt's current `ExecPolicy` forbids executing binaries inside a
   writable grant (a core `P1A-SECURITY.md` defense against drop-and-exec), **running newly
   compiled `build.rs` and test binaries requires executing newly written files inside `<verify>/target/`**
   — a deliberate widening of the execution policy that does not exist for Python verification.
4. **Output/count forgery:** Just as in Python verification, test binaries control their own stdout
   and can fabricate passing counts; verification remains an honest-mistake check paired with the
   patch diff and independent review, never proof against a hostile implementer.

---

## 2. Offline Experiment Record and Observed Blocker

### 2.1 Environment Checked

* **Host:** macOS 26.7 (arm64), Xcode Python 3.9.6, Apple Git 2.54.0.
* **Check commands run:** `command -v cargo`, `command -v rustc`, `command -v rustup`.
* **Observed outcome:** Neither `cargo`, `rustc`, nor `rustup` is installed on this host (no
  toolchain binaries exist in `/usr/bin`, `/opt/homebrew/bin`, or `/opt/`).
* **Blocker:** Per MAESTRO rules (no installs, no network downloads during offline research), an
  actual confined `cargo test` execution was **not** run on this host. All Seatbelt interactions
  below beyond MAESTRO's existing tested `fork` behavior are analysis, not observed Rust runs.

### 2.2 Reproducible Offline Fixture Experiment Plan (When a Pinned Toolchain Is Provisioned)

Once a standalone Rust toolchain is installed outside `$HOME` (e.g. `/opt/maestro-toolchains/rust-1.x`):

1. Create a tiny zero-dependency fixture crate (`Cargo.toml`, `Cargo.lock`, `src/lib.rs` with one
   passing test and one adversarial test attempting to connect to a local loopback canary listener
   on `127.0.0.1:<ephemeral_port>` and RFC 5737 TEST-NET `192.0.2.1:443` — never a public IP —
   reading `$HOME`, writing `<task>/clone`, and spawning a `setsid()` child).
2. Materialize a disposable copy `<tmp>/verify/` and run `cargo test --offline --locked --frozen`
   under a candidate Seatbelt profile with `allow_fork=True` and `(deny network*)`.
3. Measure:
   * exact Seatbelt `sandbox-exec` denials in system logs (`log show --predicate 'eventMessage contains "Sandbox:"'`) for `cargo`, `rustc`, `cc`, `ld`, and `codesign`/dyld;
   * whether ad-hoc signed binaries in `<verify>/target/` run under SIP/arm64 without extra Mach services;
   * wall-clock time, peak `target/` disk footprint, and whether a `setsid()` child spawned from
     `build.rs` or a test survives `execution.stop_group()`.

---

## 3. Comparison with Open Issues #2, #4, and #5

### 3.1 Descendant-Process Cleanup (#2) — Hard Blocker

* **Current state:** Python verification runs with `allow_fork=False`, so a test process cannot
  spawn children or escape the process group.
* **Rust/Cargo requirement:** `cargo` *must* fork `rustc`, `cc`/`ld`, `build.rs` binaries, and test
  executables. That requires `allow_fork=True`.
* **Gap:** As confirmed in `P1A-SECURITY.md` and Issue #2, once `allow_fork=True` is granted on
  macOS Seatbelt, a child (including a `build.rs` script, proc-macro, or test binary) that calls
  `setsid()` or double-forks leaves the process group and **survives `stop_group()` cleanup**.
* **Conclusion:** Cargo verification cannot be safely confined on macOS until `#2` is closed (e.g.,
  dedicated non-admin UID cleanup or an equivalent escape-proof process killer).

### 3.2 Snapshot-Bound Evidence & Isolated Copies (#4)

* **Current limits:** Trusted Local snapshots cap at **2,000 entries and 20 MiB** (`trusted.py`).
  A zero-dependency Rust crate easily fits, but a realistic vendored `vendor/` directory for even a
  small Cargo project routinely exceeds 2,000 files and 20 MiB.
* **Evidence binding:** `verify/` materializes only snapshot-bound files from the Git tree and
  verifies the hash before execution, while `target/` is created strictly inside disposable
  `verify/` and discarded/ignored relative to `clone/`. That pattern transfers cleanly to Rust,
  provided `clone/` remains read-denied/write-denied and re-snapshotted after verification.
* **Drop-and-exec widening:** Unlike Python (`ExecPolicy` forbids executing anything inside the
  writable grant), Cargo must execute compiled artifacts written into `<verify>/target/`. Any
  future policy must isolate that widening strictly to the verifier phase and prove via adversarial
  tests that protected paths, `$HOME`, and `clone/` remain unreachable.

### 3.3 Resource Limits (#5) — Practical & Security Blocker

* **Wall-clock timeout:** Trusted Local verification currently uses a 60-second wall-clock timeout.
  Cold `cargo test` builds (especially with dependencies or proc-macros) frequently exceed 60s.
* **Disk, memory, and fork-bomb risk:** `rustc` + `target/` debug artifacts easily write hundreds
  of MiB to GiB; a pathological proc-macro or `build.rs` can fill the disk or fork-bomb the host
  within seconds because MAESTRO currently enforces no `RLIMIT_FSIZE`, `RLIMIT_AS`, `RLIMIT_NPROC`,
  or directory quota.

### 3.4 Unresolved Gaps Summary

1. No escape-proof descendant cleanup when `fork` is enabled (#2).
2. No disk, memory, CPU, or process-count limits (#5).
3. Executing newly written binaries from `<verify>/target/` widens the `P1A-SECURITY.md`
   no-exec-in-writable-grant invariant.
4. No pinned, non-`$HOME` Rust toolchain provisioning story or snapshot-size design for vendored
   dependencies beyond 2,000 entries / 20 MiB.
5. `build.rs` and proc-macros execute arbitrary native code during compilation, before test
   execution even starts.

---

## 4. Feasibility Recommendation

**Recommendation: DEFER.**

Do **not** implement Rust/Cargo verification yet, and do **not** add an unconfined `cargo test`
fallback. Revisit only after:

1. **Issue #2 is resolved** (escape-proof cleanup for `allow_fork=True` workloads).
2. **Issue #5 adds basic resource bounds** (at minimum disk/file-size, process count, and
   configurable bounded verification timeouts).
3. A **pinned, non-`$HOME` toolchain experiment** (Section 2.2) is executed offline on a macOS
   (or future Linux) host and its exact syscall/sandbox requirements are measured.
4. If pursued later, start with **Tier 0 (`rustc --test` on single-crate zero-dependency fixtures)**
   or a strict `--offline --locked --frozen` Cargo profile with an explicit policy decision
   documenting whether `build.rs` and proc-macros are permitted or refused.
