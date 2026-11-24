"""Read-only architectural catalog of MAESTRO modes and agent providers.

Reports static capabilities of the current MAESTRO codebase without executing
any agent binary, reading credentials or environment secrets, or creating or
inspecting a state directory. Static catalog support never implies that an
external CLI is installed, signed in, or usable on this host; host binary and
sandbox checks belong to `maestro.py doctor`.
"""
import reviewer
import trusted

SCHEMA = "maestro-providers-v1"


def catalog(*, version):
    """Return a deterministic, JSON-serialisable provider and mode catalog."""
    return {
        "schema": SCHEMA,
        "version": version,
        "read_only": True,
        "catalog_scope": "static_architecture_only",
        "discovery": {
            "host_probed": False,
            "executes_agents": False,
            "reads_credentials": False,
            "initializes_state": False,
            "checks_host_binaries": False,
            "host_check_command": "maestro.py doctor",
        },
        "unsupported": {
            "real_agents_in_confined_mode": False,
            "linux_or_windows": False,
            "token_or_cost_metering": False,
            "automatic_retries": False,
            "automatic_commit_or_push": False,
            "silent_mode_or_provider_fallback": False,
        },
        "modes": {
            "confined": {
                "id": "confined",
                "name": "Confined Mode",
                "status": "experimental",
                "agents_confined_by_maestro": True,
                "confinement": (
                    "macOS Seatbelt deny-default sandbox (no network, no fork, "
                    "scrubbed environment, fail-closed self-test before launch)"
                ),
                "workspace": (
                    "new synthetic unborn Git worktree per task "
                    "(max 32 files, 64 entries, 64 KiB)"
                ),
                "verification": "fixed data-only exact-file-content check (runs no repository code)",
                "real_agents_supported": False,
                "fallback_to_other_mode": False,
                "commands": [
                    "create", "run", "status", "artifact",
                    "approve", "cancel", "recover", "dispose",
                ],
                "providers": ["fake-codex", "fake-claude-code"],
            },
            trusted.MODE: {
                "id": trusted.MODE,
                "name": "Trusted Local Mode",
                "status": "experimental",
                "agents_confined_by_maestro": False,
                "confinement": (
                    "None for agents: Codex CLI and Claude Code run with your user's "
                    "permissions and login; only unittest verification runs in Seatbelt"
                ),
                "notice": trusted.NOTICE,
                "workspace": (
                    "isolated local Git clone at a pinned commit SHA "
                    "(max 2,000 entries, 20 MiB)"
                ),
                "verification": (
                    "Seatbelt-confined /usr/bin/python3 (3.9) stdlib unittest suite on a "
                    "disposable snapshot copy (no network, no fork, 60s timeout; "
                    "requires at least one executed passing test)"
                ),
                "real_agents_supported": True,
                "fallback_to_fake_agents": False,
                "fallback_to_other_mode": False,
                "commands": [
                    "trusted check", "trusted start", "trusted implement",
                    "trusted verify", "trusted review", "trusted diff",
                    "trusted status", "trusted approve", "trusted reject",
                    "trusted cancel", "trusted export",
                ],
                "providers": ["codex", reviewer.PROVIDER],
            },
        },
        "providers": [
            {
                "id": "fake-codex",
                "role": "implement",
                "kind": "synthetic",
                "real_agent": False,
                "description": "Bundled first-party deterministic implementer stand-in; no model is called.",
                "supported_modes": ["confined"],
                "host_availability": {
                    "status": "bundled_first_party",
                    "probed": False,
                    "requires_external_cli": False,
                },
                "availability_by_mode": {
                    "confined": {
                        "supported_in_architecture": True,
                        "host_availability": "not_probed_requires_macos_seatbelt",
                        "confined_by_maestro": True,
                        "reason": "Runs inside MAESTRO's Seatbelt sandbox on synthetic single-target tasks.",
                    },
                    trusted.MODE: {
                        "supported_in_architecture": False,
                        "host_availability": "not_applicable",
                        "confined_by_maestro": False,
                        "reason": (
                            "Trusted Local Mode never falls back to synthetic agents "
                            "(offline test fixtures require explicit --codex-bin or "
                            "MAESTRO_CODEX_BIN and cannot receive normal approval)."
                        ),
                    },
                },
                "credentials": "none",
                "capabilities": {
                    "semantic_coding": False,
                    "real_model_calls": False,
                },
                "os_permissions": {
                    "confined_by_maestro": True,
                    "privilege_level": "macos_seatbelt_deny_default",
                    "network": "denied_by_seatbelt",
                    "filesystem": "private_task_home_write_only",
                    "fork_allowed": False,
                    "descendant_cleanup_guaranteed": True,
                },
                "cli_approval_permissions": {
                    "maestro_approval_authority": "none_human_exact_hash_required",
                    "cli_flags_applied": [],
                    "cli_approval_policy": "none_ipc_envelope_only",
                    "can_modify_clone_directly": False,
                    "can_approve_or_export": False,
                },
            },
            {
                "id": "fake-claude-code",
                "role": "review",
                "kind": "synthetic",
                "real_agent": False,
                "description": "Bundled first-party deterministic review fixture; not a semantic code review.",
                "supported_modes": ["confined"],
                "host_availability": {
                    "status": "bundled_first_party",
                    "probed": False,
                    "requires_external_cli": False,
                },
                "availability_by_mode": {
                    "confined": {
                        "supported_in_architecture": True,
                        "host_availability": "not_probed_requires_macos_seatbelt",
                        "confined_by_maestro": True,
                        "reason": "Runs inside MAESTRO's Seatbelt sandbox on hash-verified handoff envelopes.",
                    },
                    trusted.MODE: {
                        "supported_in_architecture": False,
                        "host_availability": "not_applicable",
                        "confined_by_maestro": False,
                        "reason": (
                            "Trusted Local Mode never falls back to synthetic reviewers "
                            "(offline test fixtures require explicit --claude-bin or "
                            "MAESTRO_CLAUDE_BIN and cannot satisfy normal approval)."
                        ),
                    },
                },
                "credentials": "none",
                "capabilities": {
                    "semantic_review": False,
                    "scoped_context": False,
                    "real_model_calls": False,
                },
                "os_permissions": {
                    "confined_by_maestro": True,
                    "privilege_level": "macos_seatbelt_deny_default",
                    "network": "denied_by_seatbelt",
                    "filesystem": "private_task_home_write_only",
                    "fork_allowed": False,
                    "descendant_cleanup_guaranteed": True,
                },
                "cli_approval_permissions": {
                    "maestro_approval_authority": "none_human_exact_hash_required",
                    "cli_flags_applied": [],
                    "cli_approval_policy": "none_ipc_envelope_only",
                    "can_modify_clone_directly": False,
                    "can_approve_or_export": False,
                },
            },
            {
                "id": "codex",
                "role": "implement",
                "kind": "real-cli",
                "real_agent": True,
                "description": "Official OpenAI Codex CLI implementer (external binary, user-managed login).",
                "supported_modes": [trusted.MODE],
                "host_availability": {
                    "status": "not_checked",
                    "probed": False,
                    "requires_external_cli": True,
                    "check_with": "maestro.py doctor",
                },
                "availability_by_mode": {
                    "confined": {
                        "supported_in_architecture": False,
                        "host_availability": "not_applicable",
                        "confined_by_maestro": False,
                        "reason": (
                            "Disabled in Confined Mode: agents.CodexAdapter always refuses "
                            "until P1-B confinement design decisions are resolved."
                        ),
                    },
                    trusted.MODE: {
                        "supported_in_architecture": True,
                        "host_availability": "not_checked_use_doctor",
                        "confined_by_maestro": False,
                        "reason": (
                            "Supported in experimental Trusted Local Mode architecture with your "
                            "user's OS permissions; not confined by MAESTRO. Host installation and "
                            "login are not probed by this command."
                        ),
                    },
                },
                "confinement_warning": (
                    "In Trusted Local Mode, Codex CLI runs with your user's OS permissions "
                    "and is NOT confined by MAESTRO (its own --sandbox workspace-write "
                    "flag is CLI-level only, not MAESTRO OS confinement)."
                ),
                "credentials": (
                    "managed externally by the official Codex CLI login via HOME or "
                    "CODEX_HOME; MAESTRO never reads credentials or forwards API keys"
                ),
                "environment_forwarded": list(trusted.CHILD_ENV),
                "capabilities": {
                    "semantic_coding": True,
                    "real_model_calls": True,
                    "requires_explicit_model": True,
                    "model_fallback": False,
                    "automatic_retries": False,
                },
                "os_permissions": {
                    "confined_by_maestro": False,
                    "privilege_level": "unconfined_current_user",
                    "network": "unrestricted_by_maestro",
                    "filesystem": "full_user_os_permissions",
                    "fork_allowed": True,
                    "descendant_cleanup_guaranteed": False,
                },
                "cli_approval_permissions": {
                    "maestro_approval_authority": "none_human_exact_hash_required",
                    "cli_flags_applied": [
                        "-a", "never", "--ignore-user-config",
                        "--sandbox", "workspace-write", "--ephemeral",
                    ],
                    "cli_approval_policy": "non_interactive_never_prompt",
                    "cli_self_sandbox": "workspace-write (CLI-enforced only; not MAESTRO OS confinement)",
                    "can_modify_clone_directly": True,
                    "can_approve_or_export": False,
                },
            },
            {
                "id": reviewer.PROVIDER,
                "role": "review",
                "kind": "real-cli",
                "real_agent": True,
                "description": (
                    "Official Anthropic Claude Code CLI optional independent reviewer "
                    "(external binary, user-managed subscription login)."
                ),
                "supported_modes": [trusted.MODE],
                "host_availability": {
                    "status": "not_checked",
                    "probed": False,
                    "requires_external_cli": True,
                    "check_with": "maestro.py doctor",
                },
                "availability_by_mode": {
                    "confined": {
                        "supported_in_architecture": False,
                        "host_availability": "not_applicable",
                        "confined_by_maestro": False,
                        "reason": (
                            "Disabled in Confined Mode: agents.ClaudeCodeAdapter always "
                            "refuses until P1-B confinement design decisions are resolved."
                        ),
                    },
                    trusted.MODE: {
                        "supported_in_architecture": True,
                        "host_availability": "not_checked_use_doctor",
                        "confined_by_maestro": False,
                        "reason": (
                            "Optional independent reviewer in experimental Trusted Local Mode "
                            "(--review-model); built-in tools are disabled by CLI flags, but "
                            "the process runs with your user's OS permissions and is not confined "
                            "by MAESTRO. Host installation and login are not probed by this command."
                        ),
                    },
                },
                "confinement_warning": (
                    "In Trusted Local Mode, Claude Code runs with your user's OS permissions "
                    "and is NOT confined by MAESTRO (--tools \"\" and --permission-mode dontAsk "
                    "are CLI-level restrictions, not OS confinement)."
                ),
                "credentials": (
                    "managed externally by the official Claude Code CLI subscription login "
                    "via HOME or CLAUDE_CONFIG_DIR; MAESTRO never reads credentials or "
                    "forwards API keys"
                ),
                "environment_forwarded": list(reviewer.CHILD_ENV),
                "review_contexts": ["full", "scoped"],
                "protocols": {
                    "full": reviewer.PROTOCOL,
                    "scoped": reviewer.SCOPED_PROTOCOL,
                },
                "capabilities": {
                    "semantic_review": True,
                    "real_model_calls": True,
                    "structured_output_schema": True,
                    "scoped_context_experimental": True,
                },
                "os_permissions": {
                    "confined_by_maestro": False,
                    "privilege_level": "unconfined_current_user",
                    "network": "unrestricted_by_maestro",
                    "filesystem": "full_user_os_permissions",
                    "fork_allowed": True,
                    "descendant_cleanup_guaranteed": False,
                },
                "cli_approval_permissions": {
                    "maestro_approval_authority": "none_human_exact_hash_required",
                    "cli_flags_applied": [
                        "--tools", "", "--permission-mode", "dontAsk",
                        "--safe-mode", "--restricted", "--strict-mcp-config",
                        "--no-session-persistence",
                    ],
                    "cli_approval_policy": "dontAsk_no_builtin_tools_structured_output_only",
                    "cli_self_sandbox": "none_cli_flags_only_not_os_confinement",
                    "can_modify_clone_directly": False,
                    "can_approve_or_export": False,
                },
            },
        ],
        "limitations": [
            "Real agents (codex, claude-code) in Trusted Local Mode run with your user's OS permissions and are NOT confined by MAESTRO.",
            "CLI flags (--sandbox workspace-write, --tools \"\", --permission-mode dontAsk) are CLI-level approval/tool controls, not OS confinement.",
            "Confined Mode runs only deterministic first-party fake agents (fake-codex, fake-claude-code); real adapters refuse there.",
            "This catalog reports static architectural support only: it never probes the host, executes agent binaries, reads credentials, or checks local installation/login state (use `maestro.py doctor` for host checks).",
            "macOS only (Trusted Local requires /usr/bin/python3 3.9); Linux and Windows have no isolation backend.",
            "No token/cost metering, automatic retries, automatic commits/pushes, or silent fallback between modes or fake/live providers.",
        ],
    }
