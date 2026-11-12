"""Small syntax/ordering observations, without evaluating or importing target code.

These probes test named local properties. They do not validate exploitability or
replace taint analysis, controller evidence or full-path verification.
"""
from __future__ import annotations

import ast
import hashlib
import math
from pathlib import Path

from .investigation import identity
from .triage_contract import digest

VERSION = "static-probes-v2"
MAX_FILE_BYTES = 512 * 1024
MAX_LITERAL_NODES = 32
MAX_LITERAL_DEPTH = 8


def engine_stamp():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _bounded_literal(node, depth=0, budget=None):
    """Interpret a tiny literal-only AST subset without invoking Python eval."""
    if budget is None:
        budget = [MAX_LITERAL_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_LITERAL_DEPTH:
        raise ValueError("literal syntax budget exceeded")
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or type(value) in {str, bool, int}:
            return value
        if type(value) is float and math.isfinite(value):
            return value
        raise ValueError("literal type is outside the supported subset")
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_bounded_literal(item, depth + 1, budget) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _bounded_literal(node.operand, depth + 1, budget)
        if type(value) not in {int, float}:
            raise ValueError("unary signs are supported only on numeric literals")
        result = value if isinstance(node.op, ast.UAdd) else -value
        if type(result) is float and not math.isfinite(result):
            raise ValueError("non-finite numeric result")
        return result
    raise ValueError("expression contains unsupported syntax")


def _literal_observation(source):
    if len(source.encode("utf-8")) > 128:
        return {"status": "unsupported", "reason": "literal byte limit exceeded"}
    try:
        tree = ast.parse(source, mode="eval")
        value = _bounded_literal(tree.body)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return {"status": "unsupported", "reason": str(exc)[:160]}
    if isinstance(value, tuple):
        serialized = list(value)
    else:
        serialized = value
    return {"status": "interpreted", "python_type": type(value).__name__, "value": serialized}


def verify(fd):
    record = {"schema": VERSION, "engine_sha256": engine_stamp(), "identity": identity(fd),
              "status": "inconclusive", "observations": [], "references": [], "limits": [],
              "target_code_executed": False, "model_calls": 0,
              "scope": "local Python syntax and same-block statement order; not exploitability or path feasibility"}
    def finish():
        record["record_sha256"] = digest(record)
        return record
    if not fd.sink_uri.endswith(".py"):
        record.update(status="not_applicable", limits=["Python syntax probes only"])
        return finish()
    try:
        if not fd.src_root:
            raise ValueError("source root is missing")
        root = Path(fd.src_root).resolve()
        path = (root / fd.sink_uri).resolve()
        rel = path.relative_to(root).as_posix()
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("verification file-size budget exceeded")
        text = raw.decode("utf-8-sig")
        lines = text.splitlines()
        record["source"] = {"root": str(root), "file": rel, "sha256": hashlib.sha256(raw).hexdigest()}
        if not 1 <= fd.sink_line <= len(lines) or (fd.snippet.strip() and fd.snippet.strip() != lines[fd.sink_line-1].strip()):
            raise ValueError("candidate source line changed")
        tree = ast.parse(text)
        parents, blocks = {}, {}
        def walk(node):
            for _, value in ast.iter_fields(node):
                children = value if isinstance(value, list) else [value]
                if children and all(isinstance(child, ast.stmt) for child in children):
                    for i, child in enumerate(children):
                        blocks[id(child)] = (children, i)
                for child in children:
                    if isinstance(child, ast.AST):
                        parents[id(child)] = node
                        walk(child)
        walk(tree)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "eval" and n.lineno <= fd.sink_line <= n.end_lineno]
        if len(calls) != 1:
            record.update(status="not_applicable", limits=["no unique direct eval call at candidate location"])
            return finish()
        call = calls[0]
        def reference(node):
            if len(record["references"]) >= 32:
                return
            row = {"file": rel, "line": node.lineno, "text": lines[node.lineno-1]}
            if len(row["text"].encode("utf-8")) > 8192:
                record["limits"].append("reference line-size limit")
                return
            if row not in record["references"]:
                record["references"].append(row)
        reference(call)
        clauses, unsupported = [], []
        value_name = call.args[0].id if call.args and isinstance(call.args[0], ast.Name) else ""
        child, parent = call, parents.get(id(call))
        while parent is not None:
            if isinstance(parent, ast.If) and child in parent.body:
                tests = parent.test.values if isinstance(parent.test, ast.BoolOp) and isinstance(parent.test.op, ast.And) else [parent.test]
                for test in tests:
                    if (isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute)
                            and isinstance(test.func.value, ast.Name) and test.func.value.id == value_name
                            and test.func.attr in {"startswith", "endswith"} and len(test.args) == 1
                            and not test.keywords and isinstance(test.args[0], ast.Constant)
                            and isinstance(test.args[0].value, str) and len(test.args[0].value) <= 32):
                        clauses.append({"method": test.func.attr, "literal": test.args[0].value,
                                        "expression": ast.unparse(test), "line": test.lineno})
                        reference(test)
                    else:
                        unsupported.append({"line": test.lineno, "expression": ast.unparse(test)[:1024]})
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
            child, parent = parent, parents.get(id(parent))
        if clauses:
            for probe in ("[probe()]", "(probe())", "{'item': probe()}", "probe()"):
                matches = all((probe.startswith(c["literal"]) if c["method"] == "startswith" else probe.endswith(c["literal"])) for c in clauses)
                if matches:
                    syntax = ast.parse(probe, mode="eval")
                    record["observations"].append({"kind": "boundary_guard_syntax_probe", "probe": probe,
                                                   "recognized_clauses": clauses, "unmodeled_clauses": unsupported,
                                                   "syntax_contains_call": any(isinstance(n, ast.Call) for n in ast.walk(syntax)),
                                                   "observed": "these boundary clauses accept syntax containing a function call",
                                                   "limitation": "probe parsed only; neither probe nor target executed; other checks and full path not tested"})
                    break
        statement = call
        while not isinstance(statement, ast.stmt) and id(statement) in parents:
            statement = parents[id(statement)]
        # Recognize a narrow, syntactic rejection gate in the same statement block.
        # Only tiny literal string sets are inspected; no target expressions run.
        block, offset = blocks.get(id(statement), ([], 0))
        if value_name:
            for gate_index in range(max(0, offset-12), offset):
                gate = block[gate_index]
                if (not isinstance(gate, ast.If) or gate.orelse or len(gate.body) != 1
                        or not isinstance(gate.body[0], (ast.Raise, ast.Return))):
                    continue
                test = gate.test
                if (not isinstance(test, ast.Compare) or not isinstance(test.left, ast.Name)
                        or test.left.id != value_name or len(test.ops) != 1
                        or not isinstance(test.ops[0], ast.NotIn) or len(test.comparators) != 1):
                    continue
                values = test.comparators[0]
                if (not isinstance(values, (ast.Tuple, ast.List, ast.Set)) or not 0 < len(values.elts) <= 16
                        or any(not isinstance(n, ast.Constant) or not isinstance(n.value, str)
                               or len(n.value) > 128 for n in values.elts)):
                    continue
                between = block[gate_index+1:offset]
                if any(isinstance(n, ast.Name) and n.id == value_name and isinstance(n.ctx, (ast.Store,ast.Del))
                       for s in between for n in ast.walk(s)):
                    continue
                classifications = []
                for literal in values.elts:
                    try:
                        parsed = ast.parse(literal.value, mode='eval')
                        classifications.append({'source':literal.value, 'valid_expression_syntax':True,
                            'contains_call_syntax':any(isinstance(n, ast.Call) for n in ast.walk(parsed)),
                            'expression_kind':type(parsed.body).__name__,
                            'literal_interpretation':_literal_observation(literal.value)})
                    except SyntaxError:
                        classifications.append({'source':literal.value, 'valid_expression_syntax':False,
                                                'literal_interpretation':{'status':'unsupported','reason':'invalid expression syntax'}})
                reference(gate); reference(gate.body[0])
                record['observations'].append({'kind':'finite_literal_rejection_gate', 'sink_line':call.lineno,
                    'check_line':gate.lineno,'allowed_syntax':classifications,
                    'observed':'a preceding same-block not-in check exits for values outside a finite literal string collection',
                    'literal_interpretation_scope':'a separate bounded interpreter accepts only primitive constants, tuples/lists and unary numeric signs; no target expression is executed',
                    'limitation':'does not establish the runtime value or type at the gate, overloaded comparison, rebinding, side effects, exceptions or exploitability; no safety conclusion'})
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is call:
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            outputs = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
            block, offset = blocks.get(id(statement), ([], 0))
            for after in block[offset+1:offset+6]:
                if isinstance(after, ast.If) and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                                   and n.func.id == "isinstance" and n.args and isinstance(n.args[0], ast.Name)
                                                   and n.args[0].id in outputs for n in ast.walk(after.test)):
                    reference(after)
                    record["observations"].append({"kind": "post_evaluation_type_check", "sink_line": call.lineno,
                                                   "check_line": after.lineno, "outputs": sorted(outputs),
                                                   "observed": "this type check follows evaluation in the same statement block",
                                                   "limitation": "it is not a pre-evaluation restriction; earlier controls and runtime binding not established"})
        parent = parents.get(id(call))
        if (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                and parent.func.id == "isinstance" and parent.args and parent.args[0] is call):
            reference(parent)
            record["observations"].append({"kind": "type_check_of_eval_result", "sink_line": call.lineno,
                                           "observed": "eval is the argument expression of this type check",
                                           "limitation": "checking the result type does not restrict the expression before evaluation"})
        if not record["observations"]:
            record["limits"].append("no supported local property observed; this is not a safety result")
        record["status"] = "observed" if record["observations"] else "inconclusive"
        return finish()
    except (OSError, UnicodeError, ValueError, SyntaxError, RecursionError) as exc:
        record.update(status="error", limits=[str(exc)])
        return finish()


def validate(fd, read):
    record = fd.verification
    if not record:
        return {}, []
    try:
        if (record["schema"] != VERSION or record["engine_sha256"] != engine_stamp()
                or record["identity"] != identity(fd)
                or digest({k: v for k, v in record.items() if k != "record_sha256"}) != record["record_sha256"]):
            raise ValueError("verification record version mismatch")
        if record["status"] in {"not_applicable", "error"}:
            return {**record, "valid": True}, []
        source = record["source"]
        file = read(source["file"])
        if source["root"] != str(Path(fd.src_root).resolve()) or file is None or file["sha256"] != source["sha256"]:
            raise ValueError("verification source changed")
        for row in record["references"]:
            if (row["file"] != file["path"] or not isinstance(row["line"], int)
                    or not 1 <= row["line"] <= len(file["lines"]) or file["lines"][row["line"]-1] != row["text"]):
                raise ValueError("verification reference changed")
        return {**record, "valid": True}, []
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        return {"valid": False, "error": str(exc)}, ["局部静态验证记录过期或无法校验"]
