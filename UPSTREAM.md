# Construction reference and attribution

Pinned upstream: **OrchestratorInc/agent-orchestrator v0.14.3**, commit
`6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c`.
Copyright 2026 Untrivial; Apache License 2.0, preserved in
`LICENSES/agent-orchestrator-Apache-2.0.txt`.

This is a new small Python implementation. No upstream Go package, binary or
dependency is vendored or executed. Conceptual adaptations below preserve the
license attribution; `execution.py` explicitly marks its changed implementation.

| Decision | Exact upstream reference | P0 use |
|---|---|---|
| Adapt | [process_unix.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/pkg/agentruntime/process_unix.go), [process_test.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/pkg/agentruntime/process_test.go) | Own process groups; timeout/cancel must terminate, not merely stop waiting. Descendant termination regression test. |
| Reuse native Git; adapt policy | [commands.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/internal/adapters/workspace/gitworktree/commands.go) | Worktree add/remove argv; retain dirty worktrees. Use unborn worktrees to obey the no-commit constraint. |
| Adapt | [handoff_artifact.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/internal/session_manager/handoff_artifact.go) | Bounded immutable accepted handoff, SHA-256, identity verification after source exit. SQLite transactions replace an artifact-file publication subsystem. |
| Exclude | [remove_test.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/internal/adapters/workspace/gitworktree/remove_test.go) | Upstream retry behavior was inspected; P0 intentionally has zero retries and no force cleanup. |
| Exclude | Same `commands.go` staging/commit-tree/fetch/cherry-pick helpers | No staging, commits, ref publication, fetch or merge; filesystem hashes replace commit-based evidence. |
| Exclude | [codex.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/internal/adapters/agent/codex/codex.go), [claudecode.go](https://github.com/OrchestratorInc/agent-orchestrator/blob/6e8d6e4e04ab210ee8dcf9678e337a6ef6d60a8c/backend/internal/adapters/agent/claudecode/claudecode.go) | P0 does not import provider permission defaults, modify user config, or start real providers. |

The first four rows' source/tests and upstream license were re-read directly at
the pinned commit during P0 construction. The upstream repository has no NOTICE
file at that commit; its LICENSE is reproduced byte-for-byte in `LICENSES/`.
