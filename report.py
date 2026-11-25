"""Strictly read-only Trusted Local task listing and JSON/Markdown reporting.

Guarantees:
- Never creates or adopts a state root.
- Opens SQLite strictly read-only (`?mode=ro`, `PRAGMA query_only = ON`) and reads
  all tables inside a single read transaction (`BEGIN DEFERRED`) for a consistent
  database snapshot.
- Never writes to any task clone, Git object store, Git index, SQLite database, or
  artifact directory: live clone checks use pure read-only Git queries (`rev-parse`,
  `ls-files`, `ls-tree`, `cat-file`) and filesystem scanning, never `git add` or
  `git write-tree`.
- Mirrors real approval/export gate preconditions read-only and never suggests
  `trusted approve` or `trusted export` when evidence is missing, corrupt, invalid,
  stale, or drifted.
- Treats all task/review/diff fields in Markdown output as untrusted content.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile

from execution import PolicyError
import reviewer
import trusted
from workflow import ACTIVE, FAILURES, NEXT
from workspace import digest, read_regular

SCHEMA = "maestro-trusted-report-v1"
ALL_STATUSES = ACTIVE | FAILURES | set(NEXT) | {"approved", "invalidated"}
# Strip/escape ASCII C0, DEL, C1 controls, and Unicode bidirectional override/isolate chars.
_UNSAFE_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _escape_controls(value):
    if not isinstance(value, str):
        value = str(value)
    return _UNSAFE_CTRL_RE.sub(lambda m: "\\u%04x" % ord(m.group(0)), value).replace("\n", " ")


def _safe_prose(value):
    """Escape untrusted text for Markdown prose (neutralizes HTML, links, headings, code spans)."""
    cleaned = _escape_controls(value)
    for ch, repl in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("`", "\\`"), ("[", "\\["), ("]", "\\]")):
        cleaned = cleaned.replace(ch, repl)
    return cleaned


def _safe_code(value):
    """Render untrusted text inside a Markdown inline code span that cannot be broken out of."""
    cleaned = _escape_controls(value)
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", cleaned)), default=0)
    fence = "`" * (longest + 1)
    if cleaned.startswith("`") or cleaned.endswith("`"):
        return "%s %s %s" % (fence, cleaned, fence)
    return "%s%s%s" % (fence, cleaned, fence)


def _open_readonly_db(root):
    """Return (resolved_root, sqlite3.Connection) in strict read-only mode, or (None, None)."""
    raw = Path(root).absolute()
    if raw.is_symlink():
        raise PolicyError("state root cannot be a symlink")
    if not raw.exists():
        return None, None
    if not raw.is_dir():
        raise PolicyError("state root is not a directory")
    resolved = raw.resolve()
    marker = resolved / "MAESTRO-P0"
    if not (marker.exists() or marker.is_symlink()):
        if any(resolved.iterdir()):
            raise PolicyError("state root is not owned by MAESTRO")
        return None, None
    if read_regular(marker)[0] != b"synthetic-only-v1\n":
        raise PolicyError("unrecognized state root")
    db = resolved / "state.sqlite3"
    if not (db.exists() or db.is_symlink()):
        return None, None
    info = db.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PolicyError("unsafe SQLite state file")
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return resolved, conn


def _read_artifact(conn, task_id, kind):
    row = conn.execute(
        "SELECT body, hash FROM artifacts WHERE task_id=? AND kind=?",
        (task_id, kind),
    ).fetchone()
    if row is None:
        return None, None
    value = json.loads(row["body"])
    if not isinstance(value, dict) or digest(value) != row["hash"]:
        raise PolicyError("corrupt evidence: " + kind)
    return value, row["hash"]


def _readonly_check_clone(clone, scratch_home, snap):
    """Verify live clone against recorded snapshot WITHOUT writing to clone, Git objects, or index.

    Returns (matches: bool, detail: str, live_patch_sha256: str | None).
    """
    trusted.clone_config(clone)
    head = trusted.git(clone, scratch_home, "rev-parse", "HEAD").decode("utf-8").strip()
    if head != snap["base"]:
        return False, "clone HEAD changed from recorded base", None
    stage = trusted.git(clone, scratch_home, "ls-files", "--stage", "-z")
    if any(row.startswith(b"160000 ") for row in stage.split(b"\0")):
        return False, "submodules rejected in clone", None
    included = set(trusted.names(
        trusted.git(clone, scratch_home, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    ))
    ignored_raw = trusted.git(
        clone, scratch_home, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"
    )
    ignored = sorted(n.decode("utf-8") for n in ignored_raw.split(b"\0") if n)
    for name in ignored:
        trusted.safe_name(name.rstrip("/"))
    manifest, bodies = trusted.scan(clone, included, ignored)
    if manifest != snap["manifest"]:
        return False, "clone snapshot drifted from recorded evidence", None
    if digest({"base": snap["base"], "tree": snap["tree"], "manifest": manifest}) != snap["sha256"]:
        return False, "clone snapshot hash drifted from recorded evidence", None

    # Verify the immutable evidence tree blobs match scanned bytes/modes via read-only Git queries.
    blobs = trusted.tree_blobs(clone, scratch_home, snap["tree"])
    if set(blobs) != set(bodies):
        return False, "recorded Git evidence tree differs from live included file set", None
    for rel, info in blobs.items():
        if info["body"] != bodies[rel]:
            return False, "recorded Git blob differs from live file bytes: " + rel, None
        if (info["mode"] == "100755") != bool(manifest[rel]["mode"] & 0o100):
            return False, "recorded Git executable mode differs from live file mode: " + rel, None

    # Re-scan once to detect concurrent modification during inspection.
    if trusted.scan(clone, included, ignored)[0] != manifest:
        return False, "clone changed during read-only inspection", None

    patch_bytes = trusted.tree_patch(clone, scratch_home, snap)
    patch_sha = hashlib.sha256(patch_bytes).hexdigest()
    return True, "clone matches recorded snapshot (verified read-only)", patch_sha


def _evaluate_gate_blockers(task, artifacts, review_record, review_summary, issues,
                            live_snapshot_matches, source_guard_matches, live_patch_sha256,
                            task_dir, has_export):
    """Mirror real TrustedEngine approval/export gate checks strictly read-only."""
    blockers = list(issues)
    spec = task["spec"]
    evidence = task["evidence"]
    status = task["status"]
    context = spec.get("execution_context", "normal")
    if context not in ("normal", "test"):
        blockers.append("invalid task execution context")

    if live_snapshot_matches is False:
        blockers.append("live clone snapshot drifted from recorded evidence")
    if source_guard_matches is False:
        blockers.append("source repository guard changed since task baseline")

    if status not in ("awaiting_approval", "approved"):
        return list(dict.fromkeys(blockers))

    # Fail closed: never claim approval/export readiness when live checks were skipped.
    if live_snapshot_matches is None:
        blockers.append("live clone snapshot not verified (--no-live-check); run trusted report without "
                        "--no-live-check before approval or export")
    if source_guard_matches is None:
        blockers.append("source repository guard not verified (--no-live-check); run trusted report without "
                        "--no-live-check before approval or export")

    # 1. Snapshot evidence binding
    snap = artifacts["snapshot"][0] if "snapshot" in artifacts else None
    if snap is None:
        blockers.append("missing snapshot evidence")
    else:
        try:
            snap_val = {k: snap[k] for k in ("base", "tree", "manifest")}
            if (digest(snap_val) != snap.get("sha256")
                    or snap["base"] != spec.get("base")
                    or artifacts["snapshot"][1] != evidence.get("snapshot_artifact_sha256")
                    or snap["sha256"] != evidence.get("snapshot_sha256")):
                blockers.append("snapshot evidence mismatch")
        except (KeyError, TypeError):
            blockers.append("malformed snapshot evidence")

    # 2. Codex artifact & execution-context gate
    codex = artifacts["codex"][0] if "codex" in artifacts else None
    if codex is None or not isinstance(codex.get("version"), str) or not codex["version"].strip():
        blockers.append("missing Codex version evidence")
    elif "offline-fixture" in codex["version"] and context != "test":
        blockers.append("offline-fixture result cannot receive normal approval/export")

    # 3. Verification evidence gate
    ver = artifacts["verification"][0] if "verification" in artifacts else None
    if ver is None:
        blockers.append("missing verification evidence")
    else:
        try:
            expected_cmd = trusted.verification_command(spec.get("verify"))
            if (ver.get("passed") is not True
                    or ver.get("exit_code") != 0
                    or (snap is not None and ver.get("snapshot_sha256") != snap.get("sha256"))
                    or ver.get("command") != expected_cmd
                    or spec.get("verify_command") != expected_cmd
                    or artifacts["verification"][1] != evidence.get("verification_sha256")):
                blockers.append("verification evidence is stale or unsuccessful")
            else:
                trusted.counted(ver.get("summary"))
        except PolicyError as exc:
            blockers.append("verification gate failed: " + str(exc))

    # 4. Independent review gate (when required)
    requested_review = spec.get("review")
    if isinstance(requested_review, dict):
        attempts = evidence.get("review_attempts", 0)
        if status == "awaiting_approval" and os.path.lexists(task_dir / ("review-%d" % (attempts + 1))):
            blockers.append("partial review folder detected on disk without recorded review artifact (run trusted recover)")
        if review_record is None:
            blockers.append("required review has not been completed")
        else:
            if review_record.get("outcome") != "completed":
                blockers.append("latest review attempt did not complete: %s" % review_record.get("outcome"))
            else:
                if (review_record.get("provider") != reviewer.PROVIDER
                        or review_record.get("model_requested") != requested_review.get("model")
                        or review_record.get("model_verified") is not True):
                    blockers.append("review provider or model not verified")
                if "offline-fixture" in str(review_record.get("cli", {}).get("version")) and context != "test":
                    blockers.append("offline-fixture review cannot satisfy normal approval/export")
                scoped = requested_review.get("context") == "scoped"
                scope = review_record.get("context") if scoped else None
                if scoped and (not isinstance(scope, dict)
                               or scope.get("mode") != "scoped"
                               or scope.get("policy") != reviewer.SCOPED_POLICY
                               or scope.get("status") != "selected"
                               or scope.get("budget_estimated_tokens") != requested_review.get("budget_estimated_tokens")):
                    blockers.append("scoped review context evidence mismatch or outdated policy")
                try:
                    validated = reviewer.validate_review(
                        review_record.get("review"),
                        review_record.get("snapshot_sha256"),
                        review_record.get("patch_sha256"),
                        None,
                        scope.get("context_sha256") if (scoped and isinstance(scope, dict)) else None,
                    )
                    if review_record.get("blocking") is not reviewer.blocking(validated):
                        blockers.append("review blocking flag mismatch")
                except PolicyError as exc:
                    blockers.append("review validation failed: " + str(exc))
                if snap is not None:
                    if (review_record.get("snapshot_sha256") != snap.get("sha256")
                            or review_record.get("tree") != snap.get("tree")):
                        blockers.append("review is stale: not bound to current snapshot/tree")
                if live_patch_sha256 is not None and review_record.get("patch_sha256") != live_patch_sha256:
                    blockers.append("review is stale: patch hash differs from current evidence tree")

    # 5. Approval & partial-export checks for approved status
    if status == "approved":
        app = artifacts["approval"][0] if "approval" in artifacts else None
        if app is None:
            blockers.append("missing approval artifact")
        else:
            if (snap is not None and app.get("snapshot_sha256") != snap.get("sha256")
                    or app.get("execution_context", "normal") != context
                    or artifacts["approval"][1] != evidence.get("approval_sha256")):
                blockers.append("approval evidence mismatch")
            if isinstance(requested_review, dict) and app.get("review_sha256") != evidence.get("review_sha256"):
                blockers.append("approval review binding mismatch")
        if not has_export and os.path.lexists(task_dir / "export.patch"):
            blockers.append("partial export detected: export.patch exists without recorded export artifact")

    return list(dict.fromkeys(blockers))


def _next_steps(task, has_clone_ready, has_export, review_summary, gate_blockers, issues,
                live_snapshot_matches, source_guard_matches):
    """Suggest next commands strictly respecting evidence integrity and gate blockers."""
    tid, status = task["id"], task["status"]
    if task["cancel"]:
        return []
    has_integrity_problem = bool(issues) or live_snapshot_matches is False or source_guard_matches is False
    live_unverified = (live_snapshot_matches is None or source_guard_matches is None)
    if status == "preparing":
        return ["trusted implement %s" % tid] if (has_clone_ready and not has_integrity_problem) else []
    if status == "reviewing":
        return ["trusted diff %s" % tid, "trusted verify %s" % tid] if not has_integrity_problem else []
    if status == "awaiting_approval":
        reject = "trusted reject %s --founder NAME --reason TEXT" % tid
        steps = [] if issues else ["trusted diff %s" % tid]
        if any("partial review" in b for b in gate_blockers):
            return steps + ["trusted recover %s" % tid, reject]
        # Never suggest approve when any recorded or live integrity problem exists.
        if has_integrity_problem:
            return steps + [reject]
        if review_summary is not None and review_summary.get("outcome") != "completed":
            non_review_blockers = [b for b in gate_blockers if "review" not in b and "--no-live-check" not in b]
            if not non_review_blockers and review_summary["attempts"] < reviewer.ATTEMPTS:
                steps.append("trusted review %s" % tid)
            return steps + [reject]
        if live_unverified:
            # Fail closed: never suggest approve when live clone/source checks were skipped.
            other_blockers = [b for b in gate_blockers if "--no-live-check" not in b]
            if not other_blockers:
                steps.append("trusted report %s" % tid)
            return steps + [reject]
        if gate_blockers:
            return steps + [reject]
        approve = "trusted approve %s --snapshot %s --founder NAME" % (tid, task["evidence"].get("snapshot_sha256"))
        if review_summary is not None and review_summary.get("blocking"):
            return steps + [reject, approve + " --override-review REASON"]
        return steps + [approve, reject]
    if status == "approved" and not has_export:
        if has_integrity_problem:
            return []
        if live_unverified:
            other_blockers = [b for b in gate_blockers if "--no-live-check" not in b]
            return [] if other_blockers else ["trusted report %s" % tid]
        if gate_blockers:
            return []
        return ["trusted export %s" % tid]
    return []


def list_trusted_tasks(root, *, status=None):
    """Read-only list of Trusted Local tasks from one consistent DB snapshot; never creates state."""
    if status is not None and status not in ALL_STATUSES:
        raise PolicyError("unknown task status filter: " + str(status))
    resolved, conn = _open_readonly_db(root)
    if conn is None:
        return {"mode": trusted.MODE, "notice": trusted.NOTICE, "count": 0, "tasks": []}
    try:
        conn.execute("BEGIN DEFERRED")
        rows = conn.execute("""
            SELECT t.id, t.status, t.spec, t.evidence,
                   MIN(e.at) AS created_at, MAX(e.at) AS updated_at, MIN(e.seq) AS first_seq
            FROM tasks t
            LEFT JOIN events e ON e.task_id = t.id
            GROUP BY t.id
            ORDER BY first_seq ASC
        """).fetchall()
        conn.execute("ROLLBACK")
    finally:
        conn.close()
    tasks = []
    for row in rows:
        spec = json.loads(row["spec"])
        if not isinstance(spec, dict) or spec.get("mode") != trusted.MODE:
            continue
        if status is not None and row["status"] != status:
            continue
        evidence = json.loads(row["evidence"])
        if not isinstance(evidence, dict):
            raise PolicyError("malformed task record: evidence")
        rev = spec.get("review") if isinstance(spec.get("review"), dict) else None
        tasks.append({
            "id": row["id"],
            "status": row["status"],
            "repo": spec.get("repo"),
            "base": spec.get("base"),
            "model": spec.get("model"),
            "review_model": rev.get("model") if rev else None,
            "review_context": rev.get("context", "full") if rev else None,
            "execution_context": spec.get("execution_context", "normal"),
            "snapshot_sha256": evidence.get("snapshot_sha256"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return {"mode": trusted.MODE, "notice": trusted.NOTICE, "count": len(tasks), "tasks": tasks}


def build_trusted_report(root, task_id, *, check_live=True):
    """Build a strictly read-only structured report for one Trusted Local task."""
    if not isinstance(task_id, str) or not re.fullmatch(r"[a-f0-9]{16}", task_id):
        raise PolicyError("invalid task identity")
    resolved, conn = _open_readonly_db(root)
    if conn is None:
        raise PolicyError("state root does not exist or has no MAESTRO tasks")
    try:
        # Single read transaction ensures a consistent snapshot across tasks, artifacts, and events.
        conn.execute("BEGIN DEFERRED")
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise PolicyError("unknown task")
        spec = json.loads(row["spec"])
        evidence = json.loads(row["evidence"])
        if not isinstance(spec, dict) or not isinstance(evidence, dict):
            raise PolicyError("malformed task record")
        if spec.get("mode") != trusted.MODE:
            raise PolicyError("trusted commands require mode trusted-local")
        task = {"id": row["id"], "status": row["status"], "spec": spec,
                "cancel": bool(row["cancel"]), "evidence": evidence}
        events = [dict(r) for r in conn.execute(
            "SELECT seq, at, status, message FROM events WHERE task_id=? ORDER BY seq", (task_id,))]
        has_clone_ready = conn.execute(
            "SELECT 1 FROM artifacts WHERE task_id=? AND kind='clone_ready'", (task_id,)
        ).fetchone() is not None

        issues = []
        artifacts = {}
        for kind in ("source_guard", "codex", "snapshot", "changes", "verification",
                     "approval", "rejection", "export", "cleanup"):
            try:
                val, art_hash = _read_artifact(conn, task_id, kind)
                if val is not None:
                    artifacts[kind] = (val, art_hash)
            except (PolicyError, ValueError) as exc:
                issues.append("%s: %s" % (kind, exc))

        # Verify evidence hash bindings without mutating task state.
        for ev_key, art_key in (("snapshot_artifact_sha256", "snapshot"),
                                ("verification_sha256", "verification"),
                                ("approval_sha256", "approval"),
                                ("rejection_sha256", "rejection")):
            expected = evidence.get(ev_key)
            if expected is not None:
                if art_key not in artifacts:
                    issues.append("missing artifact for %s" % ev_key)
                elif artifacts[art_key][1] != expected:
                    issues.append("hash mismatch for %s" % ev_key)

        if "snapshot" in artifacts:
            snap = artifacts["snapshot"][0]
            if evidence.get("snapshot_sha256") and snap.get("sha256") != evidence.get("snapshot_sha256"):
                issues.append("snapshot sha256 does not match task evidence")

        review_summary = None
        review_record = None
        if isinstance(spec.get("review"), dict):
            attempts = evidence.get("review_attempts", 0)
            review_summary = {
                "required": True,
                "provider": reviewer.PROVIDER,
                "model": spec["review"].get("model"),
                "attempts": attempts,
                "attempts_allowed": reviewer.ATTEMPTS,
                "context_mode": spec["review"].get("context", "full"),
            }
            if attempts:
                try:
                    rec, rec_hash = _read_artifact(conn, task_id, "review.%d" % attempts)
                    if rec is None:
                        issues.append("missing review.%d artifact" % attempts)
                    else:
                        review_record = rec
                        if evidence.get("review_sha256") and rec_hash != evidence["review_sha256"]:
                            issues.append("hash mismatch for review_sha256")
                        review_summary.update({
                            key: rec[key] for key in (
                                "outcome", "error", "models_reported", "model_verified",
                                "snapshot_sha256", "patch_sha256", "blocking", "classification",
                            ) if key in rec
                        })
                        review_summary["cli_version"] = rec.get("cli", {}).get("version")
                        if isinstance(rec.get("review"), dict):
                            review_summary.update({
                                key: rec["review"][key] for key in ("verdict", "summary", "findings")
                                if key in rec["review"]
                            })
                        scope = rec.get("context")
                        if isinstance(scope, dict):
                            review_summary["context"] = {
                                key: scope[key] for key in (
                                    "policy", "status", "included", "included_count", "omitted_count",
                                    "snapshot_file_count", "critical_omitted", "context_sha256",
                                    "audit_sha256", "payload_bytes", "estimated_tokens", "limitations",
                                ) if key in scope
                            }
                            if "included_count" in scope and "snapshot_file_count" in scope:
                                review_summary["scope_notice"] = (
                                    "scoped review: %d files supplied in full, from a %d-file snapshot; "
                                    "not a full-repository review"
                                    % (scope["included_count"], scope["snapshot_file_count"])
                                )
                except (PolicyError, ValueError) as exc:
                    issues.append("review.%d: %s" % (attempts, exc))
        conn.execute("ROLLBACK")
    finally:
        conn.close()

    # Strictly read-only live clone & source-guard checks (zero writes to clone/Git/DB).
    task_dir = resolved / "tasks" / task_id
    live_snapshot_matches, live_snapshot_detail, live_patch_sha256 = None, "not checked", None
    source_guard_matches, source_guard_detail = None, "not checked"
    if check_live:
        with tempfile.TemporaryDirectory(prefix="maestro-report-") as scratch:
            scratch_home = Path(os.path.realpath(scratch))
            if "snapshot" in artifacts:
                snap = artifacts["snapshot"][0]
                clone = task_dir / "clone"
                try:
                    live_snapshot_matches, live_snapshot_detail, live_patch_sha256 = _readonly_check_clone(
                        clone, scratch_home, snap
                    )
                except (PolicyError, OSError, ValueError) as exc:
                    live_snapshot_matches = False
                    live_snapshot_detail = str(exc)
            if "source_guard" in artifacts and spec.get("repo"):
                expected_guard = artifacts["source_guard"][0]
                try:
                    current_guard = trusted.source_guard(Path(spec["repo"]), scratch_home)
                    source_guard_matches = (current_guard == expected_guard)
                    source_guard_detail = (
                        "source repository matches recorded guard" if source_guard_matches
                        else "source repository changed since task baseline"
                    )
                except (PolicyError, OSError, ValueError) as exc:
                    source_guard_matches = False
                    source_guard_detail = str(exc)

    has_export = "export" in artifacts
    gate_blockers = _evaluate_gate_blockers(
        task, artifacts, review_record, review_summary, issues,
        live_snapshot_matches, source_guard_matches, live_patch_sha256,
        task_dir, has_export,
    )
    next_steps = _next_steps(
        task, has_clone_ready, has_export, review_summary, gate_blockers, issues,
        live_snapshot_matches, source_guard_matches,
    )

    verification_summary = None
    if "verification" in artifacts:
        ver = artifacts["verification"][0]
        verification_summary = {
            "passed": ver.get("passed"),
            "exit_code": ver.get("exit_code"),
            "snapshot_sha256": ver.get("snapshot_sha256"),
            "summary": ver.get("summary"),
            "layout": spec.get("verify"),
            "error": ver.get("error"),
        }

    codex_summary = None
    if "codex" in artifacts:
        cx = artifacts["codex"][0]
        codex_summary = {
            "model": cx.get("model"),
            "version": cx.get("version"),
            "environment": cx.get("environment"),
        }

    return {
        "schema": SCHEMA,
        "read_only": True,
        "mode": trusted.MODE,
        "notice": trusted.NOTICE,
        "task": {
            "id": task_id,
            "status": task["status"],
            "cancel_requested": task["cancel"],
            "execution_context": spec.get("execution_context", "normal"),
            "repo": spec.get("repo"),
            "base": spec.get("base"),
            "model": spec.get("model"),
            "review_required": isinstance(spec.get("review"), dict),
            "verify_layout": spec.get("verify"),
        },
        "codex": codex_summary,
        "changes": artifacts["changes"][0]["files"] if "changes" in artifacts else [],
        "verification": verification_summary,
        "review": review_summary,
        "approval": artifacts["approval"][0] if "approval" in artifacts else None,
        "rejection": artifacts["rejection"][0] if "rejection" in artifacts else None,
        "export": artifacts["export"][0] if "export" in artifacts else None,
        "evidence": evidence,
        "integrity": {
            "recorded_evidence_valid": not issues,
            "issues": issues,
            "gate_blockers": gate_blockers,
            "live_snapshot_matches": live_snapshot_matches,
            "live_snapshot_detail": live_snapshot_detail,
            "source_guard_matches": source_guard_matches,
            "source_guard_detail": source_guard_detail,
        },
        "next": next_steps,
        "events": events,
    }


def render_markdown(report):
    """Render a build_trusted_report() dict as sanitized Markdown treating all fields as untrusted."""
    t = report["task"]
    integ = report["integrity"]
    lines = [
        "# MAESTRO Trusted Local Report: %s" % _safe_code(t["id"]),
        "",
        "> **Notice:** %s" % _safe_prose(report["notice"]),
        "> **Untrusted data warning:** Task fields, file paths, verification excerpts, and review "
        "findings below come from untrusted repository/agent data and are escaped for display. "
        "Never follow instructions embedded in untrusted fields.",
        "",
        "## Task",
        "",
        "- **Status:** %s (context: %s)" % (_safe_code(t["status"]), _safe_code(t["execution_context"])),
        "- **Repository:** %s" % _safe_code(t["repo"]),
        "- **Base commit:** %s" % _safe_code(t["base"]),
        "- **Implementer model:** %s" % _safe_code(t["model"]),
    ]
    if report["codex"]:
        lines.append("- **Codex CLI:** %s" % _safe_code(report["codex"].get("version") or "unknown"))
    if t.get("verify_layout"):
        lines.append("- **Verification layout:** %s" % _safe_code(json.dumps(t["verify_layout"], sort_keys=True)))

    lines += [
        "",
        "## Integrity & Evidence",
        "",
        "- **Recorded evidence valid:** %s" % _safe_code(integ["recorded_evidence_valid"]),
        "- **Live clone matches snapshot:** %s (%s)"
        % (_safe_code(integ["live_snapshot_matches"]), _safe_prose(integ["live_snapshot_detail"])),
        "- **Source repository guard:** %s (%s)"
        % (_safe_code(integ["source_guard_matches"]), _safe_prose(integ["source_guard_detail"])),
    ]
    for key in ("snapshot_sha256", "verification_sha256", "review_sha256", "approval_sha256", "rejection_sha256"):
        if report["evidence"].get(key):
            lines.append("- **%s:** %s" % (_safe_prose(key), _safe_code(report["evidence"][key])))
    for issue in integ["issues"]:
        lines.append("- **Evidence issue:** %s" % _safe_prose(issue))
    for blocker in integ.get("gate_blockers") or []:
        if blocker not in integ["issues"]:
            lines.append("- **Gate blocker:** %s" % _safe_prose(blocker))

    lines += ["", "## Changed Files", ""]
    if report["changes"]:
        for item in report["changes"]:
            lines.append("- %s %s" % (_safe_code("[%s]" % item["status"]), _safe_code(item["path"])))
    else:
        lines.append("- *(none recorded)*")

    lines += ["", "## Verification (Seatbelt-Confined)", ""]
    ver = report["verification"]
    if ver is None:
        lines.append("- *(not run)*")
    else:
        lines.append("- **Passed:** %s (exit code: %s)" % (_safe_code(ver["passed"]), _safe_code(ver["exit_code"])))
        if isinstance(ver.get("summary"), dict):
            s = ver["summary"]
            lines.append("- **Counts:** executed=%s, tests_run=%s, failures=%s, errors=%s, skipped=%s"
                         % tuple(_safe_prose(s.get(k)) for k in ("executed", "tests_run", "failures", "errors", "skipped")))
        if ver.get("error"):
            lines.append("- **Error:** %s" % _safe_prose(ver["error"])[:500])

    if report["review"] is not None:
        rev = report["review"]
        lines += ["", "## Independent Review", ""]
        if rev.get("classification"):
            lines.append("> *Classification:* %s" % _safe_prose(rev["classification"]))
            lines.append("")
        lines.append("- **Provider / Model:** %s / requested %s (verified: %s, context: %s)"
                     % (_safe_code(rev["provider"]), _safe_code(rev["model"]),
                        _safe_code(rev.get("model_verified")), _safe_code(rev.get("context_mode"))))
        lines.append("- **Attempts:** %s / %s | **Outcome:** %s"
                     % (_safe_prose(rev["attempts"]), _safe_prose(rev["attempts_allowed"]),
                        _safe_code(rev.get("outcome", "pending"))))
        if rev.get("scope_notice"):
            lines.append("- **Scope notice:** %s" % _safe_prose(rev["scope_notice"]))
        if rev.get("verdict"):
            lines.append("- **Verdict:** %s (blocking: %s)" % (_safe_code(rev["verdict"]), _safe_code(rev.get("blocking"))))
        if rev.get("summary"):
            lines.append("- **Summary:** %s" % _safe_prose(rev["summary"]))
        if rev.get("error"):
            lines.append("- **Error:** %s" % _safe_prose(rev["error"]))
        findings = rev.get("findings") or []
        if findings:
            lines += ["", "### Findings", ""]
            for f in findings:
                loc = f["file"] if f.get("file") else "(general)"
                if f.get("line") is not None:
                    loc += ":%s" % f["line"]
                lines.append("- **%s** %s — **%s**: %s | *Conclusion:* %s"
                             % (_safe_prose("[%s]" % f["severity"]), _safe_code(loc), _safe_prose(f["title"]),
                                _safe_prose(f["observation"]), _safe_prose(f["conclusion"])))

    if report["approval"] or report["rejection"] or report["export"]:
        lines += ["", "## Decision & Export", ""]
        if report["approval"]:
            app = report["approval"]
            lines.append("- **Approved by:** %s (context: %s)"
                         % (_safe_prose(app.get("founder")), _safe_code(app.get("execution_context"))))
            if app.get("review_override"):
                lines.append("- **Review override reason:** %s" % _safe_prose(app["review_override"]))
        if report["rejection"]:
            rej = report["rejection"]
            lines.append("- **Rejected by:** %s — %s"
                         % (_safe_prose(rej.get("founder")), _safe_prose(rej.get("reason"))))
        if report["export"]:
            exp = report["export"]
            lines.append("- **Exported patch:** %s (sha256: %s)"
                         % (_safe_code(exp.get("path")), _safe_code(exp.get("sha256"))))

    lines += ["", "## Next Steps", ""]
    if report["next"]:
        for step in report["next"]:
            lines.append("- %s" % _safe_code("python3 maestro.py " + step))
    else:
        lines.append("- *(none — task is complete, terminal, or blocked by integrity/gate issues)*")

    lines += ["", "## Events", ""]
    for ev in report["events"]:
        lines.append("- %s %s" % (_safe_code("[%s]" % ev["status"]), _safe_prose(ev["message"])))
    return "\n".join(lines) + "\n"
