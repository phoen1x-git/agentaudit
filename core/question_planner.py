"""Prefer evidence contributing to a value or its checks over graph expansion."""
from __future__ import annotations

import ast
from .inquiry import topic_for

from .source_index import expression


def plan(investigator, sid, depth, state, anchor=None):
    ix, budget = investigator.index, investigator.budget
    symbol = ix.symbols[sid]
    tasks, neighbors = [], []
    action = investigator._action

    def add_dependencies(target, focus=None):
        locations, omitted = ix.local_dependencies(target, focus, focused=True)
        # Nearby assignment/condition lines share a passage rather than spending
        # one relationship slot for every line of the same construction.
        compact = []
        for loc in sorted(locations, key=lambda row: (row["file"], row["lo"])):
            if (compact and compact[-1]["file"] == loc["file"]
                    and loc["lo"] <= compact[-1]["hi"] + 4
                    and max(loc["hi"],compact[-1]["hi"]) - compact[-1]["lo"] + 1 <= budget.excerpt_lines):
                compact[-1]["hi"] = max(compact[-1]["hi"], loc["hi"])
            else:
                compact.append(dict(loc))
        locations = compact
        for loc in locations:
            tasks.append(action("local_dependency", loc, symbol=target["id"],
                                resolution="syntactic_dependency_candidate", question="source_or_guard",
                                meaning=loc["reason"]))
        if omitted:
            state["limits"].append({"symbol": target["id"], "kind": "dependency_limit", "omitted": omitted})
        return locations

    locations = add_dependencies(symbol, anchor)
    relevant_lines = {n for loc in locations for n in range(loc["lo"], loc["hi"]+1)}
    body_calls = [c for c in ix.calls if c["owner"] == sid]
    relevant_names = set()
    for node in ast.walk(symbol["node"]):
        if getattr(node, "lineno", -1) in relevant_lines and isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            relevant_names.add(node.id)
    header_end = symbol["node"].body[0].lineno if symbol["node"].body else symbol["line"]
    calls = []
    standalone = {id(n.value) for n in ast.walk(symbol["node"])
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)}
    for call in body_calls:
        node = call["node"]
        uses = {n.id for arg in node.args + [k.value for k in node.keywords] for n in ast.walk(arg) if isinstance(n, ast.Name)}
        related = node.lineno in relevant_lines or (id(node) in standalone and bool((uses & relevant_names) - {"self", "cls"}) and (anchor is None or node.lineno <= anchor))
        if related:
            calls.append(call)
    skipped = len(body_calls)-len(calls)
    if skipped:
        state["limits"].append({"symbol": sid, "kind": "unselected_calls", "count": skipped,
                                 "meaning": "not selected by syntactic value/check relation; not proof of irrelevance"})
    calls.sort(key=lambda c: (c["node"].lineno not in relevant_lines, c["node"].lineno))
    count = 0
    seen_callees = set()
    for call in calls:
        matches, resolution, omitted = ix.callee_candidates(call)
        if omitted:
            state["limits"].append({"symbol": sid, "kind": "weak_callee_limit", "omitted": omitted})
        for target_id in matches:
            target = ix.symbols[target_id]
            if target["kind"] != "function" or target_id in seen_callees:
                continue
            seen_callees.add(target_id)
            if count >= budget.max_neighbors:
                state["limits"].append({"symbol": sid, "kind": "callee_limit"})
                break
            strong = len(matches) == 1 and resolution in {"lexical_binding", "import_binding"}
            # Return dependencies precede a large function excerpt. Weak candidates
            # remain useful material but are never given invented argument bindings.
            add_dependencies(target)
            for alias in ix.callable_assignments(call):
                if alias["target"] == target_id:
                    tasks.append(action("binding_candidate", {"file":alias["file"],"lo":alias["line"],"hi":alias["end_line"],"anchor":alias["line"]},
                                        target=target_id,resolution="callable_assignment_candidate",question="binding",meaning=alias["meaning"]))
            tasks.append(action("callee", investigator._location(target), owner=sid, target=target_id,
                                line=call["node"].lineno, question="source_or_guard",
                                resolution=resolution if len(matches)==1 else "ambiguous_binding",
                                call=ix.describe_call(call, target if strong else None)))
            neighbors.append((target_id, None))
            count += 1

    # Include function values in defaults/decorators and related expressions.
    direct = {(c["node"].func.lineno,c["node"].func.col_offset) for c in body_calls}
    seen_values = set()
    for ref in ix.references:
        if ref["file"] != symbol["file"] or (ref["node"].lineno,ref["node"].col_offset) in direct:
            continue
        in_header = ref["scope"] == symbol["scope"] and symbol["line"] <= ref["node"].lineno <= header_end
        in_slice = ref["owner"] == sid and ref["node"].lineno in relevant_lines
        if not (in_header or in_slice):
            continue
        matches, resolution = ix.resolve(ref["file"],ref["scope"],ref["node"])
        for target_id in matches:
            target=ix.symbols[target_id]
            if target_id==sid or target_id in seen_values or target["kind"]!="function":
                continue
            if len(seen_values)>=budget.max_neighbors:
                state["limits"].append({"symbol":sid,"kind":"callable_dependency_limit"})
                break
            tasks.append(action("callable_dependency",investigator._location(target),owner=sid,target=target_id,
                                line=ref["node"].lineno,resolution=resolution,question="guard_or_binding",
                                meaning="function value candidate; runtime execution and effectiveness not established"))
            neighbors.append((target_id,None))
            seen_values.add(target_id)

    used={n.id for n in ast.walk(symbol["node"]) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}
    for assignment in ix.assignments:
        if assignment["file"]!=symbol["file"] or assignment["scope"]:
            continue
        names={n.id for t in assignment["targets"] for n in ast.walk(t) if isinstance(n,ast.Name)}
        if names & used:
            node=assignment["node"]
            tasks.append(action("module_assignment",{"file":symbol["file"],"lo":node.lineno,"hi":node.end_lineno,"anchor":node.lineno},
                                names=sorted(names & used),expression=expression(assignment["value"]),question="source"))

    callers=ix.callers(sid)
    weak={"name_only_candidate","ambiguous_binding","class_member_candidate"}
    selected=[c for c in callers if c["resolution"] not in weak]
    weak_calls=[c for c in callers if c["resolution"] in weak]
    selected += weak_calls[:budget.max_weak_matches]
    if len(callers)>len(selected) or len(selected)>budget.max_neighbors:
        state["limits"].append({"symbol":sid,"kind":"caller_limit","found":len(callers)})
    if not callers:
        state["limits"].append({"symbol":sid,"kind":"no_caller_found","meaning":"not proof of unreachability"})
    for call in selected[:budget.max_neighbors]:
        node=call["node"]; owner=ix.symbols.get(call["owner"])
        loc={"file":call["file"],"lo":node.lineno-3,"hi":node.end_lineno+3,"anchor":node.lineno}
        tasks.append(action("caller",loc,target=sid,owner=call["owner"],line=node.lineno,question="source_and_controller",
                            resolution=call["resolution"],call=ix.describe_call(call,symbol if call["resolution"] not in weak else None)))
        if owner:
            add_dependencies(owner,node.lineno)
            neighbors.append((owner["id"],node.lineno))
    positions={(c["file"],c["node"].func.lineno,c["node"].func.col_offset) for c in ix.calls}
    refs=0
    for ref in ix.references:
        if (ref["file"],ref["node"].lineno,ref["node"].col_offset) in positions:
            continue
        matches,resolution=ix.resolve(ref["file"],ref["scope"],ref["node"])
        if sid not in matches:
            continue
        if refs>=budget.max_neighbors:
            state["limits"].append({"symbol":sid,"kind":"reference_limit"});break
        node=ref["node"]
        tasks.append(action("function_reference",{"file":ref["file"],"lo":node.lineno-2,"hi":node.end_lineno+2,"anchor":node.lineno},
                            target=sid,resolution=resolution,question="controller",meaning="reference/registration candidate, not an invocation"))
        refs+=1
    loc=investigator._location(symbol)
    if anchor is not None: loc["anchor"]=anchor
    tasks.append(action("definition",loc,symbol=sid,resolution="definition",question="coverage",scope="source only; not runtime reachability"))
    priorities = list(dict.fromkeys(topic_for(text) for text in state.get("question_seed", []) if topic_for(text)))
    if priorities:
        def question_priority(task):
            question = task["item"].get("question", "")
            return next((i for i, topic in enumerate(priorities) if topic in question), len(priorities))
        tasks.sort(key=question_priority)
    tasks.extend({"operation":"expand","symbol":target,"depth":depth+1,"anchor":focus}
                 for target,focus in dict.fromkeys(neighbors) if target!=sid or focus!=anchor)
    return tasks
