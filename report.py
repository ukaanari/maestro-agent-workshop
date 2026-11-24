"""Read-only Trusted Local task listing and JSON/Markdown reporting.

Never creates or adopts a state root, never writes to SQLite (uses SQLite
read-only URI mode), and runs any live snapshot/source-guard verification using
a private temporary scratch directory so the task directory stays untouched.
"""
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
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _safe_text(value):
    """Escape ASCII control characters (including ESC and CR) and flatten newlines for Markdown."""
    if not isinstance(value, str):
        value = str(value)
    cleaned = _CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), value)
    return cleaned.replace("\n", " ")


def _open_readonly_db(root):
    """Return (resolved_root, sqlite3.Connection) in read-only mode, or (None, None) if absent."""
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
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
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


def _has_artifact(conn, task_id, kind):
    return conn.execute(
        "SELECT 1 FROM artifacts WHERE task_id=? AND kind=?",
        (task_id, kind),
    ).fetchone() is not None


def _next_steps(task, conn, review_summary):
    tid, status = task["id"], task["status"]
    approve = "trusted approve %s --snapshot %s --founder NAME" % (tid, task["evidence"].get("snapshot_sha256"))
    reject = "trusted reject %s --founder NAME --reason TEXT" % tid
    if status == "preparing":
        return ["trusted implement %s" % tid] if _has_artifact(conn, tid, "clone_ready") else []
    if status == "reviewing":
        return ["trusted diff %s" % tid, "trusted verify %s" % tid]
    if status == "awaiting_approval":
        steps = ["trusted diff %s" % tid]
        if review_summary is not None and review_summary.get("outcome") != "completed":
            return steps + (["trusted review %s" % tid] if review_summary["attempts"] < reviewer.ATTEMPTS else []) + [reject]
        if review_summary is not None and review_summary.get("blocking"):
            return steps + [reject, approve + " --override-review REASON"]
        return steps + [approve, reject]
    if status == "approved" and not _has_artifact(conn, tid, "export"):
        return ["trusted export %s" % tid]
    return []


def list_trusted_tasks(root, *, status=None):
    """Read-only list of Trusted Local tasks; never creates a state directory."""
    if status is not None and status not in ALL_STATUSES:
        raise PolicyError("unknown task status filter: " + str(status))
    resolved, conn = _open_readonly_db(root)
    if conn is None:
        return {"mode": trusted.MODE, "notice": trusted.NOTICE, "count": 0, "tasks": []}
    try:
        rows = conn.execute("""
            SELECT t.id, t.status, t.spec, t.evidence,
                   MIN(e.at) AS created_at, MAX(e.at) AS updated_at, MIN(e.seq) AS first_seq
            FROM tasks t
            LEFT JOIN events e ON e.task_id = t.id
            GROUP BY t.id
            ORDER BY first_seq ASC
        """).fetchall()
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
    """Build a structured read-only report for one Trusted Local task."""
    if not isinstance(task_id, str) or not re.fullmatch(r"[a-f0-9]{16}", task_id):
        raise PolicyError("invalid task identity")
    resolved, conn = _open_readonly_db(root)
    if conn is None:
        raise PolicyError("state root does not exist or has no MAESTRO tasks")
    try:
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

        next_steps = _next_steps(task, conn, review_summary)
    finally:
        conn.close()

    # Read-only live clone & source-guard checks using a throwaway scratch home.
    live_snapshot_matches, live_snapshot_detail = None, "not checked"
    source_guard_matches, source_guard_detail = None, "not checked"
    if check_live:
        task_dir = resolved / "tasks" / task_id
        with tempfile.TemporaryDirectory(prefix="maestro-report-") as scratch:
            scratch_home = Path(os.path.realpath(scratch))
            if "snapshot" in artifacts:
                snap = artifacts["snapshot"][0]
                clone = task_dir / "clone"
                try:
                    current = trusted.snapshot(clone, scratch_home, snap["base"])
                    live_snapshot_matches = (current["sha256"] == snap["sha256"])
                    live_snapshot_detail = (
                        "clone matches recorded snapshot" if live_snapshot_matches
                        else "clone snapshot drifted from recorded evidence"
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
            "live_snapshot_matches": live_snapshot_matches,
            "live_snapshot_detail": live_snapshot_detail,
            "source_guard_matches": source_guard_matches,
            "source_guard_detail": source_guard_detail,
        },
        "next": next_steps,
        "events": events,
    }


def render_markdown(report):
    """Render a build_trusted_report() dict as sanitized, founder-readable Markdown."""
    t = report["task"]
    integ = report["integrity"]
    lines = [
        "# MAESTRO Trusted Local Report: `%s`" % _safe_text(t["id"]),
        "",
        "> **Notice:** %s" % _safe_text(report["notice"]),
        "",
        "## Task",
        "",
        "- **Status:** `%s` (context: `%s`)" % (_safe_text(t["status"]), _safe_text(t["execution_context"])),
        "- **Repository:** `%s`" % _safe_text(t["repo"]),
        "- **Base commit:** `%s`" % _safe_text(t["base"]),
        "- **Implementer model:** `%s`" % _safe_text(t["model"]),
    ]
    if report["codex"]:
        lines.append("- **Codex CLI:** `%s`" % _safe_text(report["codex"].get("version") or "unknown"))
    if t.get("verify_layout"):
        lines.append("- **Verification layout:** `%s`" % _safe_text(json.dumps(t["verify_layout"], sort_keys=True)))

    lines += [
        "",
        "## Integrity & Evidence",
        "",
        "- **Recorded evidence valid:** `%s`" % integ["recorded_evidence_valid"],
        "- **Live clone matches snapshot:** `%s` (%s)"
        % (integ["live_snapshot_matches"], _safe_text(integ["live_snapshot_detail"])),
        "- **Source repository guard:** `%s` (%s)"
        % (integ["source_guard_matches"], _safe_text(integ["source_guard_detail"])),
    ]
    for key in ("snapshot_sha256", "verification_sha256", "review_sha256", "approval_sha256", "rejection_sha256"):
        if report["evidence"].get(key):
            lines.append("- **%s:** `%s`" % (key, _safe_text(report["evidence"][key])))
    for issue in integ["issues"]:
        lines.append("- **Evidence issue:** %s" % _safe_text(issue))

    lines += ["", "## Changed Files", ""]
    if report["changes"]:
        for item in report["changes"]:
            lines.append("- `[%s]` `%s`" % (_safe_text(item["status"]), _safe_text(item["path"])))
    else:
        lines.append("- *(none recorded)*")

    lines += ["", "## Verification (Seatbelt-Confined)", ""]
    ver = report["verification"]
    if ver is None:
        lines.append("- *(not run)*")
    else:
        lines.append("- **Passed:** `%s` (exit code: `%s`)" % (ver["passed"], ver["exit_code"]))
        if isinstance(ver.get("summary"), dict):
            s = ver["summary"]
            lines.append("- **Counts:** executed=%s, tests_run=%s, failures=%s, errors=%s, skipped=%s"
                         % (s.get("executed"), s.get("tests_run"), s.get("failures"), s.get("errors"), s.get("skipped")))
        if ver.get("error"):
            lines.append("- **Error:** %s" % _safe_text(ver["error"])[:500])

    if report["review"] is not None:
        rev = report["review"]
        lines += ["", "## Independent Review", ""]
        if rev.get("classification"):
            lines.append("> *Classification:* %s" % _safe_text(rev["classification"]))
            lines.append("")
        lines.append("- **Provider / Model:** `%s` / requested `%s` (verified: `%s`, context: `%s`)"
                     % (_safe_text(rev["provider"]), _safe_text(rev["model"]),
                        rev.get("model_verified"), _safe_text(rev.get("context_mode"))))
        lines.append("- **Attempts:** %s / %s | **Outcome:** `%s`"
                     % (rev["attempts"], rev["attempts_allowed"], _safe_text(rev.get("outcome", "pending"))))
        if rev.get("scope_notice"):
            lines.append("- **Scope notice:** %s" % _safe_text(rev["scope_notice"]))
        if rev.get("verdict"):
            lines.append("- **Verdict:** `%s` (blocking: `%s`)" % (_safe_text(rev["verdict"]), rev.get("blocking")))
        if rev.get("summary"):
            lines.append("- **Summary:** %s" % _safe_text(rev["summary"]))
        if rev.get("error"):
            lines.append("- **Error:** %s" % _safe_text(rev["error"]))
        findings = rev.get("findings") or []
        if findings:
            lines += ["", "### Findings", ""]
            for f in findings:
                loc = _safe_text(f["file"]) if f.get("file") else "(general)"
                if f.get("line") is not None:
                    loc += ":%s" % f["line"]
                lines.append("- **[%s]** `%s` — **%s**: %s | *Conclusion:* %s"
                             % (_safe_text(f["severity"]), loc, _safe_text(f["title"]),
                                _safe_text(f["observation"]), _safe_text(f["conclusion"])))

    if report["approval"] or report["rejection"] or report["export"]:
        lines += ["", "## Decision & Export", ""]
        if report["approval"]:
            app = report["approval"]
            lines.append("- **Approved by:** %s (context: `%s`)"
                         % (_safe_text(app.get("founder")), _safe_text(app.get("execution_context"))))
            if app.get("review_override"):
                lines.append("- **Review override reason:** %s" % _safe_text(app["review_override"]))
        if report["rejection"]:
            rej = report["rejection"]
            lines.append("- **Rejected by:** %s — %s"
                         % (_safe_text(rej.get("founder")), _safe_text(rej.get("reason"))))
        if report["export"]:
            exp = report["export"]
            lines.append("- **Exported patch:** `%s` (sha256: `%s`)"
                         % (_safe_text(exp.get("path")), _safe_text(exp.get("sha256"))))

    lines += ["", "## Next Steps", ""]
    if report["next"]:
        for step in report["next"]:
            lines.append("- `python3 maestro.py %s`" % _safe_text(step))
    else:
        lines.append("- *(none — task is complete or terminal)*")

    lines += ["", "## Events", ""]
    for ev in report["events"]:
        lines.append("- `[%s]` %s" % (_safe_text(ev["status"]), _safe_text(ev["message"])))
    return "\n".join(lines) + "\n"
