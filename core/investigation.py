"""Budgeted evidence collection with resumable, source-versioned work queues."""
from __future__ import annotations

import ast
import copy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import time

from .source_index import (SourceIndex, SearchBudget, VERSION as INDEX_VERSION,
                           SKIP_DIRS, expression, traversal_priority)
from .triage_contract import digest
from .inquiry import build_questions, question_seed

VERSION = "evidence-investigation-v1"


def engine_stamp():
    paths = [Path(__file__), *(Path(__file__).with_name(n) for n in
             ("source_index.py", "question_planner.py", "inquiry.py"))]
    return digest({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


class StaleInvestigation(ValueError):
    pass


def identity(fd):
    return digest({"fingerprint": fd.fingerprint, "language": fd.language, "file": fd.sink_uri, "line": fd.sink_line,
                   "sink": fd.sink_func, "entry": fd.entry, "snippet": fd.snippet,
                   "arg_sources": fd.arg_sources, "guards": fd.guards,
                   "analysis_provenance": fd.analysis_provenance})


class Investigator:
    def __init__(self, root, budget: SearchBudget | None = None, index: SourceIndex | None = None, *, strategy="focused"):
        if strategy not in {"broad", "focused"}:
            raise ValueError("unknown investigation strategy")
        self.strategy = strategy
        self.budget = budget or SearchBudget()
        self.index = index or SourceIndex(root, self.budget)
        if str(self.index.root) != str(Path(root).resolve()):
            raise ValueError("index belongs to a different source root")

    def _seeds(self, fd):
        rel = fd.sink_uri.replace("\\", "/")
        symbol = self.index.enclosing(rel, fd.sink_line)
        seeds = [symbol["id"]] if symbol else []
        if fd.entry:
            hits = [s["id"] for s in self.index.symbols.values()
                    if s["file"] == rel and s["kind"] == "function" and s["qual"] == fd.entry]
            seeds.extend(hits)
        for arg in fd.arg_sources:
            file = str(arg.get("src_file") or "").replace("\\", "/")
            if not file or arg.get("kind") == "local":
                continue
            files = [r for r in self.index.files if r == file or ("/" not in file and r.rsplit("/", 1)[-1] == file)]
            if len(files) == 1:
                source = self.index.enclosing(files[0], int(arg.get("src_line") or 0))
                if source:
                    seeds.append(source["id"])
        return list(dict.fromkeys(seeds))

    def _new(self, fd):
        seeds = self._seeds(fd)
        seed_locations = []
        pending = [{"operation": "expand", "symbol": sid, "depth": 0,
                    "anchor": fd.sink_line if self.index.symbols[sid]["file"] == fd.sink_uri.replace("\\", "/")
                    and self.index.symbols[sid]["line"] <= fd.sink_line <= self.index.symbols[sid]["end_line"] else None}
                   for sid in seeds]
        rel = fd.sink_uri.replace("\\", "/")
        file = self.index.files.get(rel)
        if not seeds and file and 1 <= fd.sink_line <= len(file["lines"]):
            location = {"file":rel,"lo":1,"hi":len(file["lines"]),"anchor":fd.sink_line}
            seed_locations.append(location)
            pending.append(self._action("module_context", location,
                                        meaning="module/class execution context; target code not executed"))
            for call in self.index.calls:
                if call["file"] != rel or not call["node"].lineno <= fd.sink_line <= call["node"].end_lineno:
                    continue
                matches, resolution = self.index.resolve(rel,call["scope"],call["node"].func)
                if resolution not in {"lexical_binding","import_binding","class_member_candidate"}:
                    continue
                pending.extend({"operation":"expand","symbol":sid,"depth":1,"anchor":None}
                               for sid in matches if self.index.symbols[sid]["kind"]=="function")
        return {"schema": VERSION, "index_version": INDEX_VERSION,
                "engine_sha256": engine_stamp(),
                "identity": identity(fd), "root": str(self.index.root),
                "source_sha256": self.index.source_sha256,
                "index_focus_files": self.index.focus_files,
                "index_manifest": copy.deepcopy(self.index.manifest),
                "index_complete": self.index.complete, "index_issues": copy.deepcopy(self.index.issues),
                "index_usage": dict(self.index.usage), "budget": asdict(self.budget),
                "strategy": self.strategy, "question_seed": question_seed(fd),
                "status": "pending", "stop_reason": "", "seed_symbols": seeds,
                "seed_locations": seed_locations,
                "items": [], "passages": {}, "visited": [], "expanded_contexts": [],
                "pending": pending,
                "limits": [], "events": [],
                "usage": {"symbols": 0, "items": 0, "lines": 0, "context_bytes": 0}}

    def _location(self, symbol):
        node = symbol["node"]
        lo = min([node.lineno] + [d.lineno for d in node.decorator_list])
        return {"file": symbol["file"], "lo": lo, "hi": symbol["end_line"], "anchor": node.lineno}

    def _action(self, kind, location, **metadata):
        item = {"kind": kind, **metadata}
        return {"operation": "evidence", "location": location, "item": item}

    def _plan(self, sid, depth, state, anchor=None):
        if self.strategy == "focused":
            from .question_planner import plan
            return plan(self, sid, depth, state, anchor)
        ix, symbol = self.index, self.index.symbols[sid]
        location = self._location(symbol)
        if anchor:
            location["anchor"] = anchor
        tasks = [self._action("definition", location, symbol=sid,
                              resolution="definition", scope="source only; not runtime reachability")]
        def dependencies(target, focus=None):
            locations, omitted = ix.local_dependencies(target, focus)
            for loc in locations:
                tasks.append(self._action("local_dependency", loc, symbol=target["id"],
                                          resolution="syntactic_dependency_candidate",
                                          meaning=loc["reason"]))
            if omitted:
                state["limits"].append({"symbol": target["id"], "kind": "dependency_limit", "omitted": omitted})
            return locations
        dependency_locations = dependencies(symbol, anchor)
        neighbors = []
        callers = ix.callers(sid)
        if not callers:
            state["limits"].append({"symbol": sid, "kind": "no_caller_found",
                                     "meaning": "not proof of unreachability"})
        if len(callers) > self.budget.max_neighbors:
            state["limits"].append({"symbol": sid, "kind": "caller_limit", "found": len(callers)})
        weak = [c for c in callers if c["resolution"] in {"name_only_candidate", "ambiguous_binding"}]
        if len(weak) > self.budget.max_weak_matches:
            state["limits"].append({"symbol": sid, "kind": "weak_caller_limit", "found": len(weak)})
        callers = [c for c in callers if c not in weak] + weak[:self.budget.max_weak_matches]
        for call in callers[:self.budget.max_neighbors]:
            strong = call["resolution"] not in {"name_only_candidate", "ambiguous_binding"}
            owner = ix.symbols.get(call["owner"])
            location = self._location(owner) if owner and strong else {"file": call["file"], "lo": call["node"].lineno - 3,
                                                                     "hi": call["node"].end_lineno + 3, "anchor": call["node"].lineno}
            location["anchor"] = call["node"].lineno
            tasks.append(self._action("caller", location, target=sid, owner=call["owner"],
                                      line=call["node"].lineno, resolution=call["resolution"],
                                      call=ix.describe_call(call, symbol if strong else None)))
            if owner:
                neighbors.append((owner["id"], call["node"].lineno))
        callees = [c for c in ix.calls if c["owner"] == sid]
        # Follow calls contributing to the inspected argument/return before unrelated
        # setup or logging calls elsewhere in a large function.
        callees.sort(key=lambda c: (not any(loc["lo"] <= c["node"].lineno <= loc["hi"] for loc in dependency_locations),
                                    c["node"].lineno))
        count = 0
        for call in callees:
            matches, resolution, omitted = ix.callee_candidates(call)
            if omitted:
                state["limits"].append({"symbol": sid, "kind": "weak_callee_limit", "omitted": omitted})
            for target_id in matches:
                if count >= self.budget.max_neighbors:
                    break
                target = ix.symbols[target_id]
                if target["kind"] != "function":
                    continue
                tasks.append(self._action("callee", self._location(target), target=target_id, owner=sid,
                                          line=call["node"].lineno,
                                          resolution=resolution if len(matches) == 1 else "ambiguous_binding",
                                          call=ix.describe_call(call, target if len(matches) == 1 and resolution in {"lexical_binding", "import_binding"} else None)))
                if (resolution != "name_only_candidate" and len(matches) == 1
                        and any(loc["lo"] <= call["node"].lineno <= loc["hi"] for loc in dependency_locations)):
                    dependencies(target)
                neighbors.append((target_id, None))
                count += 1
        if count >= self.budget.max_neighbors:
            state["limits"].append({"symbol": sid, "kind": "callee_limit"})
        # Dependency injection and callbacks can pass a function as a value rather
        # than call it directly (for example a route's dependency default).
        value_dependencies = 0
        direct_positions = {(c["node"].func.lineno, c["node"].func.col_offset) for c in callees}
        header_end = symbol["node"].body[0].lineno if symbol["node"].body else symbol["line"]
        for ref in ix.references:
            if ref["file"] != symbol["file"] or not (
                    ref["owner"] == sid or ref["scope"] == symbol["scope"]
                    and symbol["line"] <= ref["node"].lineno <= header_end):
                continue
            if (ref["node"].lineno, ref["node"].col_offset) in direct_positions:
                continue
            matches, resolution = ix.resolve(ref["file"], ref["scope"], ref["node"])
            for target_id in matches:
                target = ix.symbols[target_id]
                if target_id == sid or target["kind"] != "function":
                    continue
                if value_dependencies >= self.budget.max_neighbors:
                    break
                tasks.append(self._action("callable_dependency", self._location(target), target=target_id,
                                          owner=sid, line=ref["node"].lineno, resolution=resolution,
                                          meaning="function value in body/default/decorator; execution and guard effectiveness not established"))
                neighbors.append((target_id, None))
                value_dependencies += 1
        if value_dependencies >= self.budget.max_neighbors:
            state["limits"].append({"symbol": sid, "kind": "callable_dependency_limit"})
        # Module constants and initializer tables are absent from a function-only excerpt.
        used = {n.id for n in ast.walk(symbol["node"]) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        for assignment in ix.assignments:
            if assignment["file"] != symbol["file"] or assignment["scope"]:
                continue
            names = {n.id for target in assignment["targets"] for n in ast.walk(target) if isinstance(n, ast.Name)}
            if not (names & used):
                continue
            node = assignment["node"]
            tasks.append(self._action("module_assignment", {"file": symbol["file"], "lo": node.lineno,
                                                             "hi": node.end_lineno, "anchor": node.lineno},
                                      names=sorted(names & used), expression=expression(assignment["value"])))
        call_positions = {(c["file"], c["node"].func.lineno, c["node"].func.col_offset)
                          for c in ix.calls if isinstance(c["node"].func, ast.Name)}
        refs = 0
        for ref in ix.references:
            if (ref["file"], ref["node"].lineno, ref["node"].col_offset) in call_positions:
                continue
            matches, resolution = ix.resolve(ref["file"], ref["scope"], ref["node"])
            if sid not in matches:
                continue
            node = ref["node"]
            tasks.append(self._action("function_reference", {"file": ref["file"], "lo": node.lineno - 2,
                                                              "hi": node.end_lineno + 2, "anchor": node.lineno},
                                      target=sid, resolution=resolution,
                                      meaning="reference/registration candidate, not an invocation"))
            refs += 1
            if refs >= self.budget.max_neighbors:
                state["limits"].append({"symbol": sid, "kind": "reference_limit"})
                break
        tasks.extend({"operation": "expand", "symbol": target, "depth": depth + 1, "anchor": focus}
                     for target, focus in dict.fromkeys(neighbors) if target != sid)
        return tasks

    def collect(self, fd, previous=None):
        state = copy.deepcopy(previous) if previous else self._new(fd)
        if (state.get("schema") != VERSION or state.get("index_version") != INDEX_VERSION
                or state.get("engine_sha256") != engine_stamp()
                or state.get("identity") != identity(fd) or state.get("root") != str(self.index.root)
                or state.get("strategy") != self.strategy
                or state.get("source_sha256") != self.index.source_sha256):
            raise StaleInvestigation("candidate/source/index version changed; start a new investigation")
        if any(state["budget"].get(k) != getattr(self.budget, k) for k in (
                "excerpt_lines", "max_neighbors", "max_weak_matches", "max_dependency_items")):
            raise StaleInvestigation("excerpt/neighbor planning changed; start a new investigation")
        for key in ("max_depth", "max_symbols", "max_items", "max_lines", "max_context_bytes"):
            if getattr(self.budget, key) < state["budget"][key]:
                raise StaleInvestigation("collection budgets decreased; refresh the investigation")
        state["budget"] = asdict(self.budget)
        started = time.monotonic()
        visited = set(state["visited"])
        expanded = set(state["expanded_contexts"])
        item_ids = {item["id"] for item in state["items"]}
        line_ids = {(p["file"], row["line"]) for p in state["passages"].values() for row in p["lines"]}
        added, stop = 0, ""
        while state["pending"]:
            if time.monotonic() - started >= self.budget.max_seconds:
                stop = "time_budget"
                break
            task = state["pending"][0]
            if task["operation"] == "expand":
                sid = task["symbol"]
                context = digest({"symbol": sid, "anchor": task.get("anchor")})
                if context in expanded or self.strategy == "broad" and sid in visited:
                    state["pending"].pop(0)
                    continue
                if task["depth"] > self.budget.max_depth:
                    stop = "depth_budget"
                    break
                if len(expanded) >= self.budget.max_symbols:
                    stop = "symbol_budget"
                    break
                if sid not in self.index.symbols:
                    raise StaleInvestigation("pending symbol is absent from the index")
                tasks = self._plan(sid, task["depth"], state, task.get("anchor"))
                state["pending"].pop(0)
                # Evidence for this symbol is collected before expanding its neighbors.
                evidence = [t for t in tasks if t["operation"] == "evidence"]
                neighbors = [t for t in tasks if t["operation"] == "expand"]
                state["pending"] = evidence + state["pending"] + neighbors
                expanded.add(context)
                state["expanded_contexts"].append(context)
                if sid not in visited:
                    visited.add(sid)
                    state["visited"].append(sid)
                state["usage"]["symbols"] = len(expanded)
                continue
            location = task["location"]
            span = self.index.span(location["file"], location["lo"], location["hi"], location["anchor"],
                                   self.budget.excerpt_lines)
            if span is None:
                state["limits"].append({"kind": "missing_excerpt", "file": location["file"]})
                state["pending"].pop(0)
                continue
            passage_id = digest(span)
            item = {**task["item"], "passage": passage_id}
            item_id = digest(item)
            if item_id in item_ids:
                state["pending"].pop(0)
                continue
            item["id"] = item_id
            new_lines = {(span["file"], r["line"]) for r in span["lines"]} - line_ids
            if not new_lines and item["kind"] in {"definition", "local_dependency", "module_assignment"}:
                state["pending"].pop(0)
                continue
            new_bytes = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
            if passage_id not in state["passages"]:
                new_bytes += len(json.dumps(span, ensure_ascii=False).encode("utf-8"))
            if len(state["items"]) >= self.budget.max_items:
                stop = "item_budget"
            elif len(line_ids) + len(new_lines) > self.budget.max_lines:
                stop = "line_budget"
            elif state["usage"]["context_bytes"] + new_bytes > self.budget.max_context_bytes:
                stop = "context_byte_budget"
            if stop:
                break
            state["passages"].setdefault(passage_id, span)
            state["items"].append(item)
            item_ids.add(item_id)
            line_ids.update(new_lines)
            state["pending"].pop(0)
            state["usage"].update(items=len(state["items"]), lines=len(line_ids),
                                    context_bytes=state["usage"]["context_bytes"] + new_bytes)
            added += 1
        state["stop_reason"] = stop
        state["status"] = "bounded" if state["pending"] else "collected"
        if not state["seed_symbols"] and not state.get("seed_locations"):
            state["status"] = "no_source_context"
        if added or not state["events"]:
            state["events"].append({"step": len(state["events"]) + 1, "items_added": added,
                                     "stop_reason": stop, "pending": len(state["pending"])})
        state["inquiry"] = build_questions(fd, state)
        # A collection status never replaces an AI or human judgment.
        return state


def validated_evidence(fd):
    """Recheck persisted source dependencies before exposing evidence to a judge.

    Collection metadata is analysis data, never a verified runtime claim. A complete
    index is relative to its documented exclusions, not the deployed application.
    """
    state = fd.investigation
    if not state:
        return [], {}, []
    if not isinstance(state, dict) or not isinstance(state.get("pending", []), list):
        return [], {"valid": False, "error": "invalid saved investigation"}, ["主动补证记录格式错误"]
    summary = {"status": state.get("status"), "stop_reason": state.get("stop_reason"),
               "strategy": state.get("strategy"), "inquiry": state.get("inquiry", {}),
               "index_complete": state.get("index_complete"), "usage": state.get("usage"),
               "pending_count": len(state.get("pending", [])), "limits": state.get("limits", []),
               "index_issues": state.get("index_issues", []),
               "scope": "Python source syntax; dynamic dispatch, external code and excluded directories are not covered",
               "meaning": "collection completion is not proof of safety, reachability or a vulnerability"}
    try:
        root = Path(fd.src_root).resolve()
        if not root.is_dir():
            raise StaleInvestigation("source root is unavailable")
        if (state.get("schema") != VERSION or state.get("index_version") != INDEX_VERSION
                or state.get("engine_sha256") != engine_stamp()
                or state.get("identity") != identity(fd) or state.get("root") != str(root)):
            raise StaleInvestigation("candidate/source root/engine changed")
        manifest = state["index_manifest"]
        if digest(manifest) != state["source_sha256"]:
            raise StaleInvestigation("index manifest is inconsistent")
        budget = SearchBudget(**state["budget"])
        expected = {r["file"]: r for r in manifest}
        if len(expected) != len(manifest) or len(expected) > budget.max_files:
            raise StaleInvestigation("invalid index manifest size")
        focus_files = state.get("index_focus_files", [])
        if not isinstance(focus_files, list) or any(not isinstance(f, str) for f in focus_files):
            raise StaleInvestigation("invalid index traversal priorities")
        # Check directory membership as well as file contents: a newly added module
        # may turn a previously unique import match into an ambiguous one.
        found, total, directories = set(), 0, 0
        started = time.monotonic()
        def walk_error(error):
            raise StaleInvestigation("source directory could not be read") from error
        for directory, dirs, names in os.walk(root, onerror=walk_error, followlinks=False):
            directories += 1
            if directories > budget.max_directories or time.monotonic() - started > budget.max_seconds:
                raise StaleInvestigation("source recheck exceeded budget")
            kept = []
            for name in sorted(dirs):
                path = Path(directory) / name
                if name in SKIP_DIRS:
                    continue
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    if state["index_complete"]:
                        raise StaleInvestigation("directory link appeared")
                    continue
                kept.append(name)
            def priority(name):
                return traversal_priority(root, Path(directory) / name, focus_files)
            dirs[:] = sorted(kept, key=priority)
            for name in sorted(names, key=priority):
                if not name.endswith(".py"):
                    continue
                if time.monotonic() - started > budget.max_seconds:
                    raise StaleInvestigation("source recheck exceeded budget")
                path = Path(directory) / name
                rel = path.relative_to(root).as_posix()
                found.add(rel)
                if len(found) > budget.max_files:
                    if state["index_complete"]:
                        raise StaleInvestigation("source membership exceeded budget")
                    break
                record = expected.get(rel)
                if record is None:
                    if state["index_complete"]:
                        raise StaleInvestigation("source file added")
                    continue
                if record.get("sha256"):
                    if path.is_symlink() or not path.resolve().is_relative_to(root):
                        raise StaleInvestigation("source file became a link")
                    with path.open("rb") as stream:
                        raw = stream.read(budget.max_file_bytes + 1)
                    total += len(raw)
                    if (len(raw) > budget.max_file_bytes or total > budget.max_bytes
                            or hashlib.sha256(raw).hexdigest() != record["sha256"]):
                        raise StaleInvestigation("indexed source content changed")
            if len(found) > budget.max_files and not state["index_complete"]:
                break
        if set(expected) - found:
            raise StaleInvestigation("indexed source file removed")
        passages = state["passages"]
        items = state["items"]
        if len(items) > budget.max_items or len(passages) > budget.max_items:
            raise StaleInvestigation("saved evidence exceeds budget")
        selected = set()
        for item in items:
            if digest({k: v for k, v in item.items() if k != "id"}) != item["id"]:
                raise StaleInvestigation("evidence item is inconsistent")
            selected.add(item["passage"])
        accepted = []
        gaps = []
        for pid in sorted(selected):
            span = passages[pid]
            record = expected.get(span["file"], {})
            if digest(span) != pid or record.get("sha256") != span["sha256"]:
                raise StaleInvestigation("source passage version is inconsistent")
            accepted.append(span)
            if not span["complete_span"]:
                gaps.append("主动补证包含截断的函数或代码窗口")
        if not state["index_complete"]:
            gaps.append("主动补证的源码索引覆盖不完整")
        if state["pending"] or state["limits"] and any(r["kind"].endswith("_limit") for r in state["limits"]):
            gaps.append("主动补证达到预算或邻接数量限制，仍有待查材料")
        if state["status"] == "no_source_context":
            gaps.append("主动补证未定位到候选所在函数")
        summary.update(valid=True, source_sha256=state["source_sha256"], items=items)
        return accepted, summary, gaps
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        summary.update(valid=False, error=str(exc))
        return [], summary, ["主动补证记录过期或无法校验，需要重新收集"]
