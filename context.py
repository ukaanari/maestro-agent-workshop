"""Deterministic scoped review context: which verified snapshot files the reviewer sees.

Adapted from the Sprint 06A offline selector (experiments/context_selector in that
branch): its Python AST file graph, integer score diffusion, tiered ranking, bounded
definition map and exhaustive audit are reused; its separate Git object loader is not,
because MAESTRO already supplies hash-verified immutable blobs. This is presentation
policy only. The full snapshot, exact patch and verification stay the evidence that
approval and export bind; a scoped review is never a full-repository review.

Repository bytes are data: parsed with `ast`, never imported, executed or obeyed.
Relevance is approximate and file-level (imports, naming conventions, bounded lexical
references); "selected" means no discovered critical file was omitted, not that
semantic coverage is proved. Weights are engineering choices, not tuned probabilities.
"""
import ast
from collections import defaultdict, deque
import difflib
import hashlib
import json
from pathlib import PurePosixPath
import re

POLICY = "maestro-scoped-context-v1"
MAP_BYTES, MAP_SYMBOLS = 2048, 12
LIMITATIONS = (
    "Scoped review: only the listed files were supplied in full; this is not a full-repository review.",
    "Relevance is approximate: Python imports, test naming and bounded lexical references only.",
    "Dynamic imports, fixtures loaded by path, configuration and non-Python consumers are not resolved.",
    "An omitted file is not evidence that it is irrelevant or correct.",
)


def is_test(path):
    p = PurePosixPath(path)
    return p.name.startswith("test_") or p.stem.endswith("_test") or "tests" in p.parts


def parse_python(path, body):
    result = {"definitions": set(), "references": set(), "imports": [], "outline": [],
              "status": "non-python"}
    if not path.endswith(".py"):
        return result
    try:
        tree = ast.parse(body, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        result["status"] = "parse-failed"
        return result
    result["status"] = "parsed"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result["definitions"].add(node.name)
            result["outline"].append([node.lineno, type(node).__name__, node.name])
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            result["references"].add(node.id)
        elif isinstance(node, ast.Attribute):
            result["references"].add(node.attr)
        elif isinstance(node, ast.Import):
            result["imports"].extend((0, n.name, []) for n in node.names)
        elif isinstance(node, ast.ImportFrom):
            result["imports"].append((node.level, node.module or "", [n.name for n in node.names]))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    result["definitions"].add(target.id)
    result["outline"].sort()
    return result


def module_name(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def graph_for(files):
    parsed = {p: parse_python(p, f["body"]) for p, f in sorted(files.items())}
    modules, definitions = defaultdict(set), defaultdict(set)
    for p, info in parsed.items():
        if p.endswith(".py"):
            modules[module_name(p)].add(p)
        for name in info["definitions"]:
            definitions[name].add(p)
    edges, imports = defaultdict(dict), defaultdict(set)

    def link(a, b, weight):
        if a != b:
            edges[a][b] = max(edges[a].get(b, 0), weight)

    for path, info in parsed.items():
        mod = module_name(path)
        package = mod if path.endswith("/__init__.py") else mod.rpartition(".")[0]
        for level, name, names in info["imports"]:
            if level:
                parts = package.split(".") if package else []
                prefix = parts[:len(parts) - level + 1] if level <= len(parts) else []
                name = ".".join(prefix + ([name] if name else []))
            targets = set(modules.get(name, ()))
            for child in names:
                targets.update(modules.get(name + "." + child, ()))
            # Package initializers for dotted imports and re-export chains.
            for count in range(1, len(name.split("."))):
                targets.update(p for p in modules.get(".".join(name.split(".")[:count]), ())
                               if p.endswith("/__init__.py"))
            for target in targets:
                imports[path].add(target)
                link(path, target, 10)
                link(target, path, 6)
        for name in info["references"]:
            targets = definitions.get(name, ())
            if len(targets) <= 3:  # weak, explicitly ambiguous lexical evidence
                for target in targets:
                    link(path, target, 2)
                    link(target, path, 1)
    return parsed, edges, imports


def rank(before, after):
    """Changed paths, parse info, ranked candidates, reasons, direct tests, critical set, scores."""
    changed = {p for p in set(before) | set(after)
               if (before.get(p, {}).get("oid"), before.get(p, {}).get("mode")) !=
                  (after.get(p, {}).get("oid"), after.get(p, {}).get("mode"))}
    _, old_edges, old_imports = graph_for(before)
    info, edges, imports = graph_for(after)
    # Union both trees: a removed import or deleted helper still seeds context.
    for a, neighbors in old_edges.items():
        for b, weight in neighbors.items():
            edges[a][b] = max(edges[a].get(b, 0), weight)
    for a, neighbors in old_imports.items():
        imports[a].update(neighbors)
    reasons, direct_tests = defaultdict(set), set()
    for p in after:
        if is_test(p):
            stem = PurePosixPath(p).stem
            stem = stem[5:] if stem.startswith("test_") else stem[:-5] if stem.endswith("_test") else stem
            if imports[p] & changed or any(PurePosixPath(c).stem == stem for c in changed):
                direct_tests.add(p)
                reasons[p].add("direct-test")
    seeds = {p: 1000000 for p in changed}
    # Added AND removed lines supply identifier hints.
    identifiers = set()
    for p in sorted(changed):
        left = before.get(p, {}).get("body", b"").decode("utf-8", "replace").splitlines()
        right = after.get(p, {}).get("body", b"").decode("utf-8", "replace").splitlines()
        for tag, a, b, c, d in difflib.SequenceMatcher(None, left, right, autojunk=False).get_opcodes():
            if tag != "equal":
                identifiers.update(re.findall(r"[A-Za-z_]\w*", "\n".join(left[a:b] + right[c:d])))
    for p in after:
        if info[p]["definitions"] & identifiers:
            seeds[p] = seeds.get(p, 0) + 100000
            reasons[p].add("diff-symbol")
    for p in direct_tests:
        seeds[p] = seeds.get(p, 0) + 200000
    scores = dict(seeds)
    # Fixed integer diffusion: deterministic, no floating-point convergence.
    for _ in range(8):
        nxt = dict(seeds)
        for a in sorted(scores):
            neighbors = edges.get(a, {})
            total = sum(neighbors.values())
            for b, weight in sorted(neighbors.items()):
                nxt[b] = nxt.get(b, 0) + scores[a] * weight // (2 * total)
        scores = nxt
    distance, queue = {p: 0 for p in changed}, deque(sorted(changed))
    while queue:
        a = queue.popleft()
        if distance[a] >= 2:
            continue
        for b, weight in sorted(edges.get(a, {}).items()):
            if weight >= 6 and b not in distance:
                distance[b] = distance[a] + 1
                queue.append(b)
    dependencies = set().union(*(imports[p] for p in changed)) if changed else set()
    callers = {p for p, targets in imports.items() if targets & changed}
    for p in after:
        if p in dependencies:
            reasons[p].add("changed-import")
        if p in callers:
            reasons[p].add("changed-importer")
        if p in distance and p not in changed:
            reasons[p].add("import-distance-%d" % distance[p])
        if scores.get(p, 0):
            reasons[p].add("graph-reachable")
    for p in changed:
        reasons[p].add("changed-full")
    priority = lambda p: (0 if p in dependencies | callers else 1 if p in direct_tests else
                          2 if distance.get(p, 99) <= 2 else 3, -scores.get(p, 0), p)
    candidates = sorted((p for p in after if p not in changed and scores.get(p, 0)), key=priority)
    critical = (dependencies | callers | direct_tests) & set(after)
    return changed, info, candidates, reasons, direct_tests, critical, scores


def select(before, after, render, budget_bytes):
    """Greedy whole-file admission against the exact rendered reviewer input.

    `before`/`after` map path -> {"body", "mode", "oid"}. `render(selection)` returns the
    exact bytes that would be sent. Changed after-images, deleted base files, the exact
    patch and binding metadata are mandatory and never cut; the map shrinks first.
    Returns (payload, canonical audit bytes, selection summary).
    """
    changed, info, candidates, reasons, direct_tests, critical, scores = rank(before, after)
    universe = sorted(set(before) | set(after))
    selected = set(changed)
    outline, size = [], 0
    for path in sorted(info, key=lambda p: (-scores.get(p, 0), p)):
        if info[path]["status"] == "parsed":
            row = {"path": path, "symbols": info[path]["outline"][:MAP_SYMBOLS],
                   "symbols_omitted": max(0, len(info[path]["outline"]) - MAP_SYMBOLS)}
            cost = len(canonical(row))
            if size + cost <= MAP_BYTES:
                outline.append(row)
                size += cost

    candidate_set = set(candidates)

    def records():
        rows = []
        for p in universe:
            f = after.get(p, before.get(p))
            rows.append({"path": p, "changed": p in changed,
                         "source": "changed" if p in changed and p in after else
                                   "base-deleted" if p not in after else "context",
                         "mode": f["mode"], "oid": f["oid"], "bytes": len(f["body"]),
                         "included": p in selected, "score": scores.get(p, 0),
                         "signals": sorted(reasons[p]),
                         "omission": None if p in selected else
                                     "budget" if p in candidate_set else "not-ranked",
                         "analysis": info.get(p, {}).get("status", "base-only")})
        return rows

    def state(audit_sha256):
        # The audit digest has a fixed width, so selection renders with a placeholder
        # and the final render, with the real digest, has exactly the same size.
        return {"selected": sorted(selected), "changed": sorted(changed), "outline": list(outline),
                "map_files_omitted": len(info) - len(outline), "critical_omitted": sorted(critical - selected),
                "omitted_count": len(universe) - len(selected), "universe_count": len(universe),
                "audit_sha256": audit_sha256}

    placeholder = "0" * 64
    payload = render(state(placeholder))
    while len(payload) > budget_bytes and outline:
        outline.pop()
        payload = render(state(placeholder))
    mandatory = len(payload)
    for p in candidates:
        if mandatory > budget_bytes:
            break
        selected.add(p)
        if len(render(state(placeholder))) > budget_bytes:
            selected.remove(p)
    audit = canonical(records())
    final = state(hashlib.sha256(audit).hexdigest())
    payload = render(final)
    status = ("budget-exceeded" if len(payload) > budget_bytes else
              "incomplete-critical-context" if final["critical_omitted"] else "selected")
    return payload, audit, dict(final, status=status, mandatory_bytes=mandatory,
                                direct_tests=sorted(direct_tests), critical=sorted(critical),
                                parse_failures=sorted(p for p in info if info[p]["status"] == "parse-failed"))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
