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
import fnmatch
import hashlib
import json
import os
from pathlib import PurePosixPath
import pkgutil
import re
import sys
import sysconfig

# v2: tests reaching a changed module through packages are critical.
# v3: imports resolve against the task's verification layout; a changed package initializer,
# a re-exported name or an unresolved local import can no longer end in a silent "selected".
POLICY = "maestro-scoped-context-v3"
TEST_HOPS = 3                          # test -> package __init__ -> package __init__ -> module
REEXPORT_DEPTH = 2                     # package initializers followed for a name a changed file imports
MAP_BYTES, MAP_SYMBOLS = 2048, 12
LEGACY = "legacy"                      # names relative to the repository root or src/, as before v3
LIMITATIONS = (
    "Scoped review: only the listed files were supplied in full; this is not a full-repository review.",
    "Relevance is approximate: Python imports resolved against the verification layout, test naming "
    "and bounded lexical references only.",
    "Dynamic imports, fixtures loaded by path, configuration and non-Python consumers are not resolved.",
    "An omitted file is not evidence that it is irrelevant or correct.",
)


def stdlib_names():
    names = getattr(sys, "stdlib_module_names", None)
    if names is None:  # Python 3.9: the running interpreter's own standard library
        stdlib = sysconfig.get_paths()["stdlib"]
        names = set(sys.builtin_module_names) | {
            m.name for m in pkgutil.iter_modules([stdlib, os.path.join(stdlib, "lib-dynload")])}
    return frozenset(names)


STDLIB = stdlib_names()


def is_test(path, layout=None):
    p = PurePosixPath(path)
    if p.name.startswith("test_") or p.stem.endswith("_test") or "tests" in p.parts:
        return True
    # What the task's own discovery collects: its test directory and file pattern.
    test_dir, pattern = (layout["test_dir"], layout["pattern"]) if layout else ("tests", "test*.py")
    return path.startswith(test_dir + "/") and fnmatch.fnmatchcase(p.name, pattern)


def module_roots(layout=None):
    """The verification run's sys.path entries inside the snapshot, in its order.

    The runner prepends the --pythonpath entries; unittest discovery then inserts its
    top-level directory (the test directory when none is given) first unless already there.
    """
    if layout is None:
        return ["tests"]
    top = layout["test_dir"] if layout["top_level_dir"] is None else layout["top_level_dir"]
    roots = list(layout["pythonpath"]) if top in layout["pythonpath"] else [top] + list(layout["pythonpath"])
    return ["" if r == "." else r for r in roots]


def parse_python(path, body):
    result = {"definitions": set(), "references": set(), "imports": [], "outline": [],
              "bindings": defaultdict(list), "status": "non-python"}
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

    def bind(statements):
        # Module-level names bound by imports, also under if/try: what `from pkg import name` gets.
        for node in statements:
            if isinstance(node, ast.ImportFrom):
                for n in node.names:
                    result["bindings"][n.asname or n.name].append((node.level, node.module or "", n.name))
            elif isinstance(node, ast.Import):
                for n in node.names:
                    if n.asname:
                        result["bindings"][n.asname].append((0, n.name, None))
            elif isinstance(node, ast.If):
                bind(node.body)
                bind(node.orelse)
            elif isinstance(node, ast.Try):
                for block in [node.body, node.orelse, node.finalbody] + [h.body for h in node.handlers]:
                    bind(block)
    bind(tree.body)
    result["outline"].sort()
    return result


def module_name(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def join(directory, name):
    return directory + "/" + name if directory else name


class Resolver:
    """Which snapshot files an import can load.

    Absolute names resolve first as the verification run does: its roots in sys.path
    order, a regular package or module in an earlier root shadowing later ones, and
    namespace portions merged. Only when that finds no file do the pre-v3 names relative
    to the repository root and src/ apply, so ordinary layouts keep their graph.
    """

    def __init__(self, paths, roots):
        self.files = {p for p in paths if p.endswith(".py")}
        self.dirs = {str(d) for p in self.files for d in PurePosixPath(p).parents if str(d) != "."}
        self.roots = roots
        self.legacy = defaultdict(set)
        for p in sorted(self.files):
            self.legacy[module_name(p)].add(p)
        self.packages = {p[:-len("/__init__.py")] for p in self.files if p.endswith("/__init__.py")}
        # Unconfigured roots: plain directories, outside every package, that are not already roots.
        known = set(roots) | {"", "src"}
        plain = {d for d in self.dirs if d not in known and
                 not any(str(a) in self.packages for a in [PurePosixPath(d)] + list(PurePosixPath(d).parents))}
        self.shadow = defaultdict(set)
        for p in self.files:
            parts = p[:-3].split("/")
            if parts[-1] == "__init__":
                parts.pop()
            for k in range(1, len(parts)):
                if "/".join(parts[:k]) in plain:
                    self.shadow[".".join(parts[k:])].add(("/".join(parts[:k]), p))

    def find(self, name, locations):
        """The file one absolute name loads from these sys.path entries; set() for a namespace package."""
        if not name:
            return None
        parts = name.split(".")
        for i, part in enumerate(parts):
            regular, portions = None, []
            for location in locations:
                base = join(location, part)
                if base + "/__init__.py" in self.files or base + ".py" in self.files:
                    regular = base
                    break
                if base in self.dirs:
                    portions.append(base)
            if regular is None:
                if not portions:
                    return None
                if i == len(parts) - 1:
                    return set()
                locations = portions
            elif i == len(parts) - 1:
                return {regular + "/__init__.py" if regular + "/__init__.py" in self.files else regular + ".py"}
            elif regular + "/__init__.py" in self.files:
                locations = [regular]
            else:
                return None  # a module has no submodules
        return None

    def resolve(self, name):
        found = self.find(name, self.roots)
        return found if found else self.legacy.get(name, found)

    def lookup(self, scope, name):
        if scope is None:
            return self.resolve(name)
        if scope == LEGACY:
            return self.legacy.get(name)
        return self.find(name, [scope])

    def absolute(self, path, level, name):
        """(scope, absolute name) pairs for one import statement in `path`."""
        if not level:
            return [(None, name)]
        found = []
        for root in self.roots:
            if root and not path.startswith(root + "/"):
                continue
            parts = (path[len(root) + 1:] if root else path)[:-3].split("/")
            package = parts[:-1]
            if level <= len(package):  # Python refuses a relative import beyond the top-level package
                absolute = ".".join(package[:len(package) - level + 1] + ([name] if name else []))
                found.append((root, absolute))
        # Unchanged pre-v3 names relative to the repository root and src/.
        mod = module_name(path)
        package = mod if path.endswith("/__init__.py") else mod.rpartition(".")[0]
        parts = package.split(".") if package else []
        prefix = parts[:len(parts) - level + 1] if level <= len(parts) else []
        found.append((LEGACY, ".".join(prefix + ([name] if name else []))))
        return found

    def names(self, path):
        """(scope, dotted name) pairs under which `path` can be imported."""
        found = []
        for root in self.roots:
            if not root or path.startswith(root + "/"):
                parts = (path[len(root) + 1:] if root else path)[:-3].split("/")
                if parts[-1] == "__init__":
                    parts.pop()
                if parts:
                    found.append((root, ".".join(parts)))
        return found + [(LEGACY, module_name(path))]


def graph_for(files, roots):
    parsed = {p: parse_python(p, f["body"]) for p, f in sorted(files.items())}
    resolver = Resolver(parsed, roots)
    definitions = defaultdict(set)
    for p, info in parsed.items():
        for name in info["definitions"]:
            definitions[name].add(p)
    edges, imports, explicit = defaultdict(dict), defaultdict(set), defaultdict(set)

    def link(a, b, weight):
        if a != b:
            edges[a][b] = max(edges[a].get(b, 0), weight)

    for path, info in parsed.items():
        for level, name, names in info["imports"]:
            targets, scoped = set(), resolver.absolute(path, level, name)
            for scope, absolute in scoped:
                targets.update(resolver.lookup(scope, absolute) or ())
                for child in names:
                    targets.update(resolver.lookup(scope, absolute + "." + child) or ())
            explicit[path].update(targets)  # what the statement names, not its parent packages
            # Package initializers for dotted imports and re-export chains.
            for scope, absolute in scoped:
                for count in range(1, len(absolute.split("."))):
                    targets.update(p for p in resolver.lookup(scope, ".".join(absolute.split(".")[:count])) or ()
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
    return parsed, resolver, edges, imports, explicit


def reaches(start, targets, explicit, hops=TEST_HOPS):
    """True when `start` reaches a target within `hops` explicit import edges.

    Implicit parent-package edges are not followed, so a test that imports one
    submodule does not inherit everything its package initializer re-exports.
    """
    seen, frontier = {start}, {start}
    for _ in range(hops):
        frontier = {b for a in frontier for b in explicit.get(a, ()) if b not in seen}
        if frontier & targets:
            return True
        seen |= frontier
    return False


def under_changed_packages(parsed, resolver, changed):
    """Modules whose import runs a changed package initializer: those inside that package."""
    packages = {scoped for p in changed if p.endswith("/__init__.py") and p in parsed
                for scoped in resolver.names(p) if scoped[1]}
    return {p for p in parsed if p.endswith(".py") and
            any(name.startswith(n + ".") for scope, name in resolver.names(p) for s, n in packages if s == scope)}


def reexports(parsed, resolver, changed):
    """Files that define a name a changed file imports from a package, through its initializers."""
    def follow(init, name, depth):
        found, bound = set(), parsed.get(init, {}).get("bindings", {})
        for level, module, original in bound.get(name) or bound.get("*", ()):
            for scope, absolute in resolver.absolute(init, level, module):
                submodule = resolver.lookup(scope, absolute + "." + original) if original not in (None, "*") else None
                for target in submodule or resolver.lookup(scope, absolute) or ():
                    found.add(target)
                    if target.endswith("/__init__.py") and depth > 1 and original and not submodule:
                        found |= follow(target, name if original == "*" else original, depth - 1)
        return found

    found = set()
    for path in sorted(changed & set(parsed)):
        for level, module, names in parsed[path]["imports"]:
            for scope, absolute in resolver.absolute(path, level, module):
                for init in resolver.lookup(scope, absolute) or ():
                    if init.endswith("/__init__.py"):
                        for name in names:
                            if name != "*" and not resolver.lookup(scope, absolute + "." + name):
                                found |= follow(init, name, REEXPORT_DEPTH)
    return found - changed


def unresolved(parsed, resolver, changed):
    """Absolute imports that resolve nowhere, although a file in a plain directory carries the name.

    Such a directory is a sys.path entry the task's layout does not declare: a changed file
    inside it, or a changed file it holds, may be what really runs. Standard-library names
    and imports with no such file (third-party packages) are never reported.
    """
    found = set()
    for path, info in parsed.items():
        for level, name, names in info["imports"]:
            if level or name.split(".")[0] in STDLIB or resolver.resolve(name) is not None:
                continue
            for candidate in [name] + [name + "." + child for child in names if child != "*"]:
                for directory, target in sorted(resolver.shadow.get(candidate, ())):
                    if path.startswith(directory + "/") or target in changed:
                        found.add("%s imports %s (%s)" % (path, candidate, target))
    return found


def rank(before, after, layout=None):
    """Changed paths, parse info, ranked candidates, reasons, direct and indirect tests, critical set, scores,
    unresolved local imports."""
    changed = {p for p in set(before) | set(after)
               if (before.get(p, {}).get("oid"), before.get(p, {}).get("mode")) !=
                  (after.get(p, {}).get("oid"), after.get(p, {}).get("mode"))}
    roots = module_roots(layout)
    old_info, old_resolver, old_edges, old_imports, old_explicit = graph_for(before, roots)
    info, resolver, edges, imports, explicit = graph_for(after, roots)
    # Union both trees: a removed import or deleted helper still seeds context.
    for a, neighbors in old_edges.items():
        for b, weight in neighbors.items():
            edges[a][b] = max(edges[a].get(b, 0), weight)
    for a, neighbors in old_imports.items():
        imports[a].update(neighbors)
    for a, neighbors in old_explicit.items():
        explicit[a].update(neighbors)
    reasons, direct_tests = defaultdict(set), set()
    for p in after:
        if is_test(p, layout):
            stem = PurePosixPath(p).stem
            stem = stem[5:] if stem.startswith("test_") else stem[:-5] if stem.endswith("_test") else stem
            if imports[p] & changed or any(PurePosixPath(c).stem == stem for c in changed):
                direct_tests.add(p)
                reasons[p].add("direct-test")
    # Tests that exercise a changed module through its package (tomli: `from . import tomllib`),
    # or enter a package whose changed initializer then runs.
    targets = changed | under_changed_packages(info, resolver, changed)
    indirect_tests = {p for p in after if is_test(p, layout) and p not in direct_tests
                      and reaches(p, targets, explicit)}
    for p in indirect_tests:
        reasons[p].add("indirect-test")
    reexported = reexports(old_info, old_resolver, changed) | reexports(info, resolver, changed)
    for p in reexported:
        reasons[p].add("re-export")
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
    dependencies = (set().union(*(imports[p] for p in changed)) if changed else set()) | reexported
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
    critical = (dependencies | callers | direct_tests | indirect_tests) & set(after)
    priority = lambda p: (0 if p in dependencies | callers else 1 if p in direct_tests | indirect_tests else
                          2 if distance.get(p, 99) <= 2 else 3, -scores.get(p, 0), p)
    # A critical file is always a candidate, even one the score diffusion did not reach.
    candidates = sorted((p for p in after if p not in changed and (scores.get(p, 0) or p in critical)), key=priority)
    missing = unresolved(old_info, old_resolver, changed) | unresolved(info, resolver, changed)
    return changed, info, candidates, reasons, direct_tests, indirect_tests, critical, scores, missing


def select(before, after, render, budget_bytes, layout=None):
    """Greedy whole-file admission against the exact rendered reviewer input.

    `before`/`after` map path -> {"body", "mode", "oid"}; `layout` is the task's verification
    layout (None for the default discovery). `render(selection)` returns the exact bytes
    that would be sent. Changed after-images, deleted base files, the exact patch and
    binding metadata are mandatory and never cut; the map shrinks first.
    Returns (payload, canonical audit bytes, selection summary).
    """
    changed, info, candidates, reasons, direct_tests, indirect_tests, critical, scores, missing = rank(
        before, after, layout)
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
              "unresolved-imports" if missing else
              "incomplete-critical-context" if final["critical_omitted"] else "selected")
    return payload, audit, dict(final, status=status, mandatory_bytes=mandatory,
                                direct_tests=sorted(direct_tests), indirect_tests=sorted(indirect_tests),
                                critical=sorted(critical), unresolved_imports=sorted(missing),
                                parse_failures=sorted(p for p in info if info[p]["status"] == "parse-failed"))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
