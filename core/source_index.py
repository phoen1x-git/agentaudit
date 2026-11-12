"""Bounded, read-only Python symbol lookup for evidence collection.

Resolution labels describe syntax, not runtime dispatch or proven reachability.
No target module is imported, compiled or executed.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import hashlib
import math
import os
from pathlib import Path
import time

from .triage_contract import digest

VERSION = "python-index-v1"
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "site-packages",
             ".mypy_cache", ".pytest_cache", "build", "dist"}


@dataclass(frozen=True)
class SearchBudget:
    max_files: int = 800
    max_bytes: int = 16 * 1024 * 1024
    max_file_bytes: int = 512 * 1024
    max_nodes: int = 500000
    max_directories: int = 10000
    max_seconds: float = 15.0
    max_depth: int = 2
    max_symbols: int = 40
    max_items: int = 48
    max_lines: int = 480
    excerpt_lines: int = 90
    max_neighbors: int = 32
    max_weak_matches: int = 4
    max_dependency_items: int = 16
    max_context_bytes: int = 96 * 1024

    def __post_init__(self):
        for key, value in asdict(self).items():
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or isinstance(value, float) and not math.isfinite(value)
                    or value < 0 or value == 0 and key != "max_depth"):
                raise ValueError(f"{key} must be finite and positive")
            if key != "max_seconds" and not isinstance(value, int):
                raise ValueError(f"{key} must be an integer")
        if self.max_depth > 12:
            raise ValueError("max_depth must be at most 12")


def expression(node) -> str:
    try:
        value = ast.unparse(node)
        return value if len(value) <= 4096 else value[:4096] + " ... (expression omitted)"
    except (ValueError, RecursionError):
        return "(expression unavailable)"


def nature(node) -> str:
    if isinstance(node, ast.Constant):
        return "literal_none" if node.value is None else "literal"
    if isinstance(node, ast.Name):
        return "name"
    if isinstance(node, ast.Call):
        return "call_result"
    if isinstance(node, ast.JoinedStr):
        return "formatted_string"
    if isinstance(node, ast.Starred):
        return "unpacked"
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return "attribute_or_item"
    return "expression"


def traversal_priority(root, path, focus_files):
    """Use the same focused traversal for indexing and saved-source rechecks."""
    rel = path.relative_to(root).as_posix()
    return not any(f == rel or f.startswith(rel + "/") for f in focus_files), rel


class SourceIndex:
    def __init__(self, root: str | Path, budget: SearchBudget | None = None, focus_files=()):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError("source root is not a directory")
        self.budget = budget or SearchBudget()
        self.focus_files = sorted({str(f).replace("\\", "/") for f in focus_files})
        self.files = {}
        self.symbols = {}
        self.definitions = {}
        self.calls = []
        self.references = []
        self.assignments = []
        self.issues = []
        self.manifest = []
        self.usage = {"files": 0, "bytes": 0, "nodes": 0, "directories": 0}
        self.complete = True
        self._resolution_cache = {}
        self._module_cache = {}
        self._callers_map = None
        self._unresolved_calls = {}
        self.started = time.monotonic()
        self._build()
        self.source_sha256 = digest(self.manifest)

    def _issue(self, code, file="", detail=""):
        self.complete = False
        row = {"code": code, "file": file, "detail": detail}
        if row not in self.issues:
            self.issues.append(row)

    def _timed_out(self):
        if time.monotonic() - self.started >= self.budget.max_seconds:
            self._issue("time_budget")
            return True
        return False

    def _build(self):
        # Keep the sink's containing file available even in a large project by allowing
        # a caller to choose a source subtree. Partial coverage is always explicit.
        def walk_error(error):
            self._issue("directory_read_error", detail=type(error).__name__)
        for directory, dirs, names in os.walk(self.root, onerror=walk_error, followlinks=False):
            self.usage["directories"] += 1
            if self.usage["directories"] > self.budget.max_directories or self._timed_out():
                self._issue("directory_budget")
                break
            kept = []
            for name in sorted(dirs):
                p = Path(directory) / name
                if name in SKIP_DIRS:
                    continue
                if p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()):
                    self._issue("directory_link_skipped", p.relative_to(self.root).as_posix())
                    continue
                kept.append(name)
            def priority(path):
                return traversal_priority(self.root, path, self.focus_files)
            dirs[:] = sorted(kept, key=lambda name: priority(Path(directory) / name))
            for name in sorted(names, key=lambda name: priority(Path(directory) / name)):
                if not name.endswith(".py"):
                    continue
                if self._timed_out():
                    return
                if self.usage["files"] >= self.budget.max_files:
                    self._issue("file_budget")
                    return
                path = Path(directory) / name
                rel = path.relative_to(self.root).as_posix()
                self.usage["files"] += 1
                if path.is_symlink():
                    self._issue("file_link_skipped", rel)
                    self.manifest.append({"file": rel, "status": "link_skipped"})
                    continue
                try:
                    size = path.stat().st_size
                    if size > self.budget.max_file_bytes:
                        self._issue("file_size_budget", rel)
                        self.manifest.append({"file": rel, "status": "too_large", "size": size})
                        continue
                    if self.usage["bytes"] + size > self.budget.max_bytes:
                        self._issue("byte_budget", rel)
                        return
                    # Read one extra byte so concurrent growth cannot bypass the bound.
                    with path.open("rb") as stream:
                        raw = stream.read(self.budget.max_file_bytes + 1)
                    self.usage["bytes"] += len(raw)
                    if len(raw) > self.budget.max_file_bytes or self.usage["bytes"] > self.budget.max_bytes:
                        self._issue("byte_budget", rel)
                        return
                    sha = hashlib.sha256(raw).hexdigest()
                    record = {"file": rel, "sha256": sha, "status": "parsed"}
                    self.manifest.append(record)
                    text = raw.decode("utf-8-sig")
                    tree = ast.parse(text)
                    n = 0
                    for _node in ast.walk(tree):
                        n += 1
                        if self.usage["nodes"] + n > self.budget.max_nodes:
                            self._issue("node_budget", rel)
                            record["status"] = "node_budget"
                            return
                    self.usage["nodes"] += n
                    self.files[rel] = {"file": rel, "text": text, "lines": text.splitlines(),
                                       "sha256": sha, "tree": tree, "imports": {},
                                       "scopes": {"": {"kind": "module", "parent": "", "bound": set()}}}
                    self._visit_file(rel)
                except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError) as exc:
                    self._issue("parse_or_read_error", rel, type(exc).__name__)
                    if self.manifest and self.manifest[-1].get("file") == rel:
                        self.manifest[-1]["status"] = "parse_or_read_error"
                    else:
                        self.manifest.append({"file": rel, "status": "read_error"})

    def _visit_file(self, rel):
        index, file = self, self.files[rel]
        stack = []

        class Visitor(ast.NodeVisitor):
            def scope(self):
                return ".".join(x[0] for x in stack)

            def owner(self):
                return next((x[2] for x in reversed(stack) if x[1] == "function"), "")

            def definition(self, node, kind):
                parent = self.scope()
                qual = f"{parent}.{node.name}" if parent else node.name
                sid = f"{rel}::{qual}@{node.lineno}"
                item = {"id": sid, "file": rel, "qual": qual, "name": node.name,
                        "scope": parent, "kind": kind, "line": node.lineno,
                        "end_line": node.end_lineno, "node": node,
                        "class": next((x[0] for x in reversed(stack) if x[1] == "class"), "")}
                index.symbols[sid] = item
                index.definitions.setdefault((rel, parent, node.name), []).append(sid)
                file["scopes"][qual] = {"kind": kind, "parent": parent, "bound": set()}
                # Defaults and decorators execute in the enclosing scope, not the body.
                for dec in node.decorator_list:
                    self.visit(dec)
                if kind == "function":
                    for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
                        self.visit(default)
                stack.append((node.name, kind, sid))
                if kind == "function":
                    args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                    args += [a for a in (node.args.vararg, node.args.kwarg) if a is not None]
                    file["scopes"][qual]["bound"].update(a.arg for a in args)
                for statement in node.body:
                    self.visit(statement)
                stack.pop()

            def visit_FunctionDef(self, node):
                self.definition(node, "function")

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node):
                self.definition(node, "class")

            def visit_Import(self, node):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    module = alias.name if alias.asname else alias.name.split(".")[0]
                    file["imports"].setdefault((self.scope(), local), []).append((module, ""))

            def visit_ImportFrom(self, node):
                module = index._absolute_import(rel, node.module or "", node.level)
                for alias in node.names:
                    file["imports"].setdefault((self.scope(), alias.asname or alias.name), []).append((module, alias.name))

            def visit_Lambda(self, node):
                for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
                    self.visit(default)
                parent = self.scope()
                name = f"<lambda@{node.lineno}:{node.col_offset}>"
                qual = f"{parent}.{name}" if parent else name
                args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                args += [a for a in (node.args.vararg, node.args.kwarg) if a is not None]
                file["scopes"][qual] = {"kind": "function", "parent": parent,
                                         "bound": {a.arg for a in args}}
                stack.append((name, "function", ""))
                self.visit(node.body)
                stack.pop()

            def visit_ListComp(self, node):
                # Comprehension targets are a separate binding scope. Treat all targets
                # conservatively, including the first iterable, rather than guessing order.
                parent = self.scope()
                name = f"<comprehension@{node.lineno}:{node.col_offset}>"
                qual = f"{parent}.{name}" if parent else name
                bound = {n.id for gen in node.generators for n in ast.walk(gen.target) if isinstance(n, ast.Name)}
                file["scopes"][qual] = {"kind": "function", "parent": parent, "bound": bound}
                stack.append((name, "function", ""))
                self.generic_visit(node)
                stack.pop()

            visit_SetComp = visit_ListComp
            visit_DictComp = visit_ListComp
            visit_GeneratorExp = visit_ListComp

            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    scope = file["scopes"].get(self.scope())
                    if scope:
                        scope["bound"].add(node.id)
                if isinstance(node.ctx, ast.Load):
                    index.references.append({"file": rel, "scope": self.scope(), "owner": self.owner(),
                                             "node": node, "name": node.id})

            def visit_Call(self, node):
                index.calls.append({"file": rel, "scope": self.scope(), "owner": self.owner(), "node": node})
                self.generic_visit(node)

            def visit_Assign(self, node):
                index.assignments.append({"file": rel, "scope": self.scope(), "owner": self.owner(),
                                           "node": node, "targets": node.targets, "value": node.value})
                self.generic_visit(node)

            def visit_AnnAssign(self, node):
                index.assignments.append({"file": rel, "scope": self.scope(), "owner": self.owner(),
                                           "node": node, "targets": [node.target], "value": node.value})
                self.generic_visit(node)

        Visitor().visit(file["tree"])

    @staticmethod
    def _absolute_import(rel, module, level):
        if not level:
            return module
        package = rel.replace("/", ".").removesuffix(".py").split(".")[:-1]
        if level > len(package):
            return ""
        prefix = package[:len(package) - level + 1]
        return ".".join(prefix + ([module] if module else []))

    def _module_files(self, module):
        if not module:
            return []
        if module in self._module_cache:
            return self._module_cache[module]
        stem = module.replace(".", "/")
        suffixes = (stem + ".py", stem + "/__init__.py")
        out = [rel for rel in self.files if any(rel == s or rel.endswith("/" + s) for s in suffixes)]
        self._module_cache[module] = out
        return out

    def enclosing(self, rel, line):
        hits = [s for s in self.symbols.values() if s["file"] == rel and s["kind"] == "function"
                and s["line"] <= line <= s["end_line"]]
        return min(hits, key=lambda s: s["end_line"] - s["line"]) if hits else None

    def resolve(self, rel, scope, node):
        """Return (symbol ids, resolution). Empty/ambiguous matches stay explicit."""
        key = (rel, scope, id(node))
        if key not in self._resolution_cache:
            self._resolution_cache[key] = self._resolve(rel, scope, node)
        return self._resolution_cache[key]

    def _resolve(self, rel, scope, node):
        if isinstance(node, ast.Name):
            return self._resolve_name(rel, scope, node.id)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}:
                current = scope
                while current:
                    info = self.files[rel]["scopes"].get(current, {})
                    if info.get("kind") == "class":
                        return self.definitions.get((rel, current, node.attr), []), "class_member_candidate"
                    current = info.get("parent", "")
            parts = expression(node).split(".")
            if all(p.isidentifier() for p in parts):
                base, resolution = self._resolve_name(rel, scope, parts[0])
                classes = [self.symbols[s] for s in base if self.symbols[s]["kind"] == "class"]
                hits = [sid for cls in classes for sid in self.definitions.get((cls["file"], cls["qual"], ".".join(parts[1:])), [])]
                if hits:
                    return hits, "class_member_candidate"
                imports = self._imports(rel, scope, parts[0])
                hits = []
                for module, name in imports:
                    full = ".".join([p for p in [module, name, *parts[1:-1]] if p])
                    for file in self._module_files(full):
                        hits.extend(self.definitions.get((file, "", parts[-1]), []))
                if hits:
                    return list(dict.fromkeys(hits)), "import_binding" if len(imports) == len(hits) == 1 else "ambiguous_binding"
                if imports:
                    return [], "external_or_unresolved_import"
        return [], "unresolved"

    def _scopes(self, rel, scope):
        current = scope
        while current:
            info = self.files[rel]["scopes"].get(current, {})
            # Class bodies are not lexical scopes for method bodies.
            if info.get("kind") != "class" or current == scope:
                yield current
            current = info.get("parent", "")
        yield ""

    def _imports(self, rel, scope, name):
        for current in self._scopes(rel, scope):
            info = self.files[rel]["scopes"].get(current, {})
            if name in info.get("bound", set()):
                return []
            values = self.files[rel]["imports"].get((current, name), [])
            if values:
                return values
        return []

    def _resolve_name(self, rel, scope, name):
        for current in self._scopes(rel, scope):
            info = self.files[rel]["scopes"].get(current, {})
            if name in info.get("bound", set()):
                return [], "shadowed_or_dynamic"
            defs = self.definitions.get((rel, current, name), [])
            if defs:
                return defs, "lexical_binding" if len(defs) == 1 else "ambiguous_binding"
            values = self.files[rel]["imports"].get((current, name), [])
            if values:
                hits = [s for module, imported in values for file in self._module_files(module)
                        for s in self.definitions.get((file, "", imported), [])]
                label = "import_binding" if len(values) == 1 and len(hits) == 1 else "ambiguous_binding"
                return list(dict.fromkeys(hits)), label if hits else "external_or_unresolved_import"
        return [], "unresolved"

    def callers(self, symbol):
        target = self.symbols[symbol]
        if self._callers_map is None:
            self._callers_map = {}
            for call in self.calls:
                ids, resolution = self.resolve(call["file"], call["scope"], call["node"].func)
                leaf = call["node"].func
                name = leaf.id if isinstance(leaf, ast.Name) else leaf.attr if isinstance(leaf, ast.Attribute) else ""
                for sid in ids:
                    self._callers_map.setdefault(sid, []).append({**call, "resolution": resolution if len(ids) == 1 else "ambiguous_binding"})
                if not ids and name and resolution == "unresolved":
                    self._unresolved_calls.setdefault(name, []).append({**call, "resolution": "name_only_candidate"})
        out = list(self._callers_map.get(symbol, [])) + self._unresolved_calls.get(target["name"], [])
        ranks = {"lexical_binding": 0, "import_binding": 1, "class_member_candidate": 2,
                 "ambiguous_binding": 3, "name_only_candidate": 4}
        return sorted(out, key=lambda x: (ranks.get(x["resolution"], 5), x["file"] != target["file"],
                                         x["file"], x["node"].lineno))

    def describe_call(self, call, target=None):
        node = call["node"]
        arguments = [{"position": i, "expression": expression(arg), "nature": nature(arg)}
                     for i, arg in enumerate(node.args[:32])]
        arguments.extend({"keyword": kw.arg, "expression": expression(kw.value),
                          "nature": "unpacked" if kw.arg is None else nature(kw.value)} for kw in node.keywords[:32])
        out = {"expression": expression(node), "arguments": arguments, "bindings": [],
               "binding_complete": False}
        if len(node.args) > 32 or len(node.keywords) > 32:
            out["arguments_omitted"] = True
            return out
        if not target or not isinstance(target["node"], (ast.FunctionDef, ast.AsyncFunctionDef)):
            return out
        args = target["node"].args
        out["binding_scope"] = "syntactic arguments only; decorators, mutation and runtime dispatch are not modeled"
        positional = args.posonlyargs + args.args
        decorators = {expression(d) for d in target["node"].decorator_list}
        implicit_receiver = (isinstance(node.func, ast.Attribute)
                             and isinstance(node.func.value, ast.Name)
                             and (node.func.value.id in {"self", "cls"} or "classmethod" in decorators))
        if implicit_receiver and "staticmethod" not in decorators and target["class"] and positional and positional[0].arg in {"self", "cls"}:
            positional = positional[1:]
        # Dynamic unpacking and duplicate keywords cannot be mapped safely by position.
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            return out
        keys = [k.arg for k in node.keywords]
        if len(keys) != len(set(keys)) or len(node.args) > len(positional):
            return out
        supplied = {a.arg: (v, "positional") for a, v in zip(positional, node.args)}
        accepted_keywords = {a.arg for a in positional + args.kwonlyargs}
        for kw in node.keywords:
            if (kw.arg in supplied or kw.arg in {a.arg for a in args.posonlyargs}
                    or kw.arg not in accepted_keywords):
                return out
            supplied[kw.arg] = (kw.value, "keyword")
        all_pos = args.posonlyargs + args.args
        defaults = {a.arg: v for a, v in zip(all_pos[len(all_pos) - len(args.defaults):], args.defaults)}
        defaults.update({a.arg: v for a, v in zip(args.kwonlyargs, args.kw_defaults) if v is not None})
        params = positional + args.kwonlyargs
        for param in params:
            if param.arg in supplied:
                value, origin = supplied[param.arg]
            elif param.arg in defaults:
                value, origin = defaults[param.arg], "default"
            else:
                out["bindings"].append({"parameter": param.arg, "origin": "missing"})
                continue
            out["bindings"].append({"parameter": param.arg, "expression": expression(value),
                                    "nature": nature(value), "origin": origin})
        out["binding_complete"] = (all(b["origin"] != "missing" for b in out["bindings"])
                                   and args.vararg is None and args.kwarg is None)
        return out

    def span(self, rel, lo, hi, anchor=0, limit=None):
        file = self.files.get(rel)
        if not file:
            return None
        limit = limit or self.budget.excerpt_lines
        lo, hi = max(1, lo), min(len(file["lines"]), hi)
        full_lo, full_hi = lo, hi
        if hi - lo + 1 > limit:
            lo = max(lo, min((anchor or lo) - limit // 2, hi - limit + 1))
            hi = lo + limit - 1
        if lo > hi:
            return None
        return {"file": rel, "sha256": file["sha256"], "start_line": lo, "end_line": hi,
                "complete_span": (lo, hi) == (full_lo, full_hi),
                "lines": [{"line": n, "text": file["lines"][n - 1]} for n in range(lo, hi + 1)]}

    def callee_candidates(self, call):
        ids, resolution = self.resolve(call["file"], call["scope"], call["node"].func)
        aliases = self.callable_assignments(call) if not ids else []
        if aliases:
            return list(dict.fromkeys(row["target"] for row in aliases)), "callable_assignment_candidate", 0
        if ids or resolution != "unresolved":
            return ids, resolution, 0
        func = call["node"].func
        if not isinstance(func, ast.Attribute):
            return [], resolution, 0
        # This is explicitly a name-only candidate set. Exclude ubiquitous container
        # operations from expansion; they remain visible in the exact source excerpts.
        if func.attr in {"get", "append", "items", "values", "keys", "format", "split", "strip",
                         "lower", "upper", "replace", "join", "encode", "decode", "copy", "update",
                         "pop", "add", "remove", "startswith", "endswith"}:
            return [], "unmodeled_container_or_dynamic_method", 0
        def proximity(symbol):
            shared = 0
            for a, b in zip(symbol["file"].split("/")[:-1], call["file"].split("/")[:-1]):
                if a != b:
                    break
                shared += 1
            return symbol["file"] != call["file"], -shared, symbol["file"], symbol["line"]
        hits = sorted((s for s in self.symbols.values() if s["name"] == func.attr and s["kind"] == "function"),
                      key=proximity)
        return [s["id"] for s in hits[:self.budget.max_weak_matches]], "name_only_candidate", max(0, len(hits)-self.budget.max_weak_matches)

    def callable_assignments(self, call):
        """Collect syntactic callable assignments, without asserting runtime binding."""
        func = call["node"].func
        if not isinstance(func, (ast.Name, ast.Attribute)):
            return []
        key = expression(func)
        def owner_class(scope):
            while scope:
                info = self.files[call["file"]]["scopes"].get(scope, {})
                if info.get("kind") == "class":
                    return scope
                scope = info.get("parent", "")
            return ""
        member = isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in {"self", "cls"}
        cls = owner_class(call["scope"]) if member else ""
        result = []
        for assignment in self.assignments:
            if assignment["file"] != call["file"] or assignment["value"] is None:
                continue
            same_scope = assignment["scope"] == call["scope"]
            if not (same_scope or member and cls and owner_class(assignment["scope"]) == cls):
                continue
            if not any(expression(t) == key for t in assignment["targets"]):
                continue
            matches, _ = self.resolve(assignment["file"], assignment["scope"], assignment["value"])
            for sid in matches:
                if self.symbols[sid]["kind"] == "function":
                    result.append({"target": sid, "file": assignment["file"], "line": assignment["node"].lineno,
                                   "end_line": assignment["node"].end_lineno, "expression": expression(assignment["node"]),
                                   "meaning": "syntactic assignment candidate; mutation, subclasses and runtime overrides not ruled out"})
        return result

    def local_dependencies(self, symbol, anchor=None, *, focused=False):
        """Syntactic backward name slice, never a control-flow or data-flow proof."""
        nodes, ancestors = [], {}
        def visit(node, parents):
            if node is not symbol["node"] and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                return
            nodes.append(node)
            ancestors[id(node)] = parents
            for child in ast.iter_child_nodes(node):
                visit(child, parents + [node])
        visit(symbol["node"], [])
        def loaded(node):
            result = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} if node else set()
            if focused and node:
                result -= {"self", "cls"}
                result.update(expression(n) for n in ast.walk(node) if isinstance(n, ast.Attribute)
                              and isinstance(n.value, ast.Name) and n.value.id in {"self", "cls"})
            return result
        def roots(node):
            if isinstance(node, ast.Name):
                return {node.id}
            if isinstance(node, (ast.Subscript, ast.Attribute)):
                if focused and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}:
                    return {expression(node)}
                return roots(node.value)
            if isinstance(node, (ast.Tuple, ast.List)):
                return set().union(*(roots(n) for n in node.elts))
            return set()
        if anchor is not None:
            calls = [n for n in nodes if isinstance(n, ast.Call) and n.lineno <= anchor <= n.end_lineno]
            chooser = max if focused else min
            focus = chooser(calls, key=lambda n: (n.end_lineno-n.lineno, n.end_col_offset-n.col_offset)) if calls else None
            seeds = [focus] if focus else [n for n in nodes if isinstance(n, ast.stmt) and getattr(n, "lineno", -1) == anchor]
            needed = set().union(*(loaded(n) for n in seeds)) if seeds else set()
            bound = anchor
        else:
            seeds = [n for n in nodes if isinstance(n, ast.Return) or focused and isinstance(n, (ast.Yield, ast.YieldFrom))]
            needed = set().union(*(loaded(n.value) for n in seeds)) if seeds else set()
            bound = symbol["end_line"]
        selected = list(seeds)
        writes = []
        for node in nodes:
            if getattr(node, "lineno", bound+1) > bound:
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                writes.append((node, set().union(*(roots(t) for t in targets)), loaded(node.value)))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                writes.append((node, roots(node.target), loaded(node.iter)))
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                call = node.value
                writes.append((node, roots(call.func.value), loaded(call)))
        for _ in range(12 if focused else 1):
            before = set(needed)
            for node, names, uses in sorted(writes, key=lambda r: r[0].lineno, reverse=True):
                if names & needed:
                    if node not in selected:
                        selected.append(node)
                    needed.update(uses)
                    if focused:
                        for parent in ancestors.get(id(node), []):
                            if isinstance(parent, (ast.If, ast.While)):
                                needed.update(loaded(parent.test))
                            elif isinstance(parent, (ast.For, ast.AsyncFor)):
                                needed.update(loaded(parent.iter))
            if before == needed:
                break
        output, seen = [], set()
        for node in selected:
            relevant = [node]
            relevant += [p for p in ancestors.get(id(node), []) if isinstance(p, (ast.If, ast.For, ast.AsyncFor, ast.While))]
            for item in relevant:
                if id(item) in seen:
                    continue
                seen.add(id(item))
                header = item.test if isinstance(item, (ast.If, ast.While)) else item.iter if isinstance(item, (ast.For, ast.AsyncFor)) else item
                output.append({"file": symbol["file"], "lo": item.lineno,
                               "hi": min(header.end_lineno, item.lineno+5), "anchor": item.lineno,
                               "reason": "syntactic name dependency or enclosing condition; path and ordering not proven"})
        omitted = max(0, len(output)-self.budget.max_dependency_items)
        return output[:self.budget.max_dependency_items], omitted
