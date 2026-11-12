"""Bounded syntax lookup never upgrades candidate relations to runtime proof."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.source_index import SearchBudget, SourceIndex  # noqa: E402


def project(tmp_path, files, budget=None):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return SourceIndex(tmp_path, budget)


def find(index, qual, file="app.py"):
    return next(s for s in index.symbols.values() if s["qual"] == qual and s["file"] == file)


def test_lexical_callers_and_actual_defaults(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(value, flag=True):\n    return eval(value)\n\ndef entry():\n    return run(None)\n"})
    target = find(ix, "run")
    call, = ix.callers(target["id"])
    assert call["resolution"] == "lexical_binding"
    info = ix.describe_call(call, target)
    assert info["bindings"] == [{"parameter": "value", "expression": "None", "nature": "literal_none", "origin": "positional"},
                                {"parameter": "flag", "expression": "True", "nature": "literal", "origin": "default"}]
    assert info["binding_complete"]


def test_relative_import_alias_is_resolved(tmp_path):
    ix = project(tmp_path, {"pkg/handlers.py": "def run(value):\n    return eval(value)\n",
                            "pkg/api.py": "from .handlers import run as execute\ndef endpoint(x):\n    return execute(value=x)\n"})
    target = find(ix, "run", "pkg/handlers.py")
    call, = ix.callers(target["id"])
    assert call["file"] == "pkg/api.py" and call["resolution"] == "import_binding"
    assert ix.describe_call(call, target)["bindings"][0]["expression"] == "x"


def test_module_import_alias_and_nested_closures(tmp_path):
    ix = project(tmp_path, {"pkg/worker.py": "def run(x):\n    return x\n",
                            "app.py": "import pkg.worker as w\ndef outer(value):\n    def inner(x):\n        return w.run(x)\n    return inner(value)\n\ndef unrelated():\n    def inner(x):\n        return x\n    return inner(1)\n"})
    target = find(ix, "run", "pkg/worker.py")
    call, = ix.callers(target["id"])
    assert call["resolution"] == "import_binding"
    local, = ix.callers(find(ix, "outer.inner")["id"])
    assert local["owner"] == find(ix, "outer")["id"]


def test_reassigned_and_parameter_shadowed_names_are_not_bound(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\ndef entry(run):\n    return run(1)\ndef another():\n    run = other\n    return run(2)\n"})
    assert ix.callers(find(ix, "run")["id"]) == []


def test_known_other_import_is_not_a_caller_with_same_leaf_name(tmp_path):
    ix = project(tmp_path, {"first.py": "def run(x):\n    return x\n", "other.py": "def run(x):\n    return x\n",
                            "app.py": "from other import run\nrun(1)\n"})
    assert ix.callers(find(ix, "run", "first.py")["id"]) == []


def test_untyped_receiver_is_explicit_name_only_candidate(tmp_path):
    ix = project(tmp_path, {"app.py": "class Parser:\n    def run(self, x):\n        return x\ndef entry(obj):\n    return obj.run(1)\n"})
    call, = ix.callers(find(ix, "Parser.run")["id"])
    assert call["resolution"] == "name_only_candidate"


def test_method_receiver_and_staticmethod_bindings(tmp_path):
    ix = project(tmp_path, {"app.py": "class Parser:\n    def run(self, x):\n        return x\n    @staticmethod\n    def static(self, x):\n        return x\n    def caller(self):\n        self.run(2)\n        self.static(1, 2)\n"})
    target = find(ix, "Parser.run")
    call, = ix.callers(target["id"])
    assert call["resolution"] == "class_member_candidate"
    assert ix.describe_call(call, target)["bindings"][0]["parameter"] == "x"
    target = find(ix, "Parser.static")
    call, = ix.callers(target["id"])
    assert [b["parameter"] for b in ix.describe_call(call, target)["bindings"]] == ["self", "x"]


@pytest.mark.parametrize("call", ["run(*items)", "run(**options)", "run(1, x=2)"])
def test_unpacking_or_duplicate_binding_stays_incomplete(tmp_path, call):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\n" + call + "\n"})
    target = find(ix, "run")
    found, = ix.callers(target["id"])
    assert not ix.describe_call(found, target)["binding_complete"]


def test_no_caller_is_not_reported_as_unreachable(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return eval(x)\n"})
    assert ix.callers(find(ix, "run")["id"]) == []
    assert not hasattr(ix, "unreachable")


def test_source_is_not_executed_and_parse_failures_are_visible(tmp_path):
    ix = project(tmp_path, {"app.py": 'raise RuntimeError("no execution")\ndef run(x):\n    return x\n',
                            "broken.py": "def not_valid(:\n"})
    assert find(ix, "run") and not ix.complete
    assert ix.issues[0]["code"] == "parse_or_read_error"


@pytest.mark.parametrize("budget,code", [(SearchBudget(max_files=1), "file_budget"),
                                        (SearchBudget(max_file_bytes=10), "file_size_budget"),
                                        (SearchBudget(max_bytes=10), "byte_budget"),
                                        (SearchBudget(max_nodes=2), "node_budget")])
def test_index_budgets_are_explicit(tmp_path, budget, code):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\n", "other.py": "value = 1\n"}, budget)
    assert not ix.complete and any(i["code"] == code for i in ix.issues)


def test_index_is_deterministic_and_versions_content(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\n"})
    assert ix.source_sha256 == SourceIndex(tmp_path).source_sha256
    (tmp_path / "app.py").write_text("def run(x):\n    return 1\n", encoding="utf-8")
    assert ix.source_sha256 != SourceIndex(tmp_path).source_sha256


def test_excerpt_is_anchored_and_marks_omissions(tmp_path):
    text = "def run(x):\n" + "    pass\n" * 200 + "    return x\n"
    ix = project(tmp_path, {"app.py": text})
    span = ix.span("app.py", 1, 202, anchor=202, limit=30)
    assert span["end_line"] == 202 and len(span["lines"]) == 30
    assert not span["complete_span"]


@pytest.mark.parametrize("options", [{"max_files": 0}, {"max_depth": 20}, {"max_seconds": -1},
                                    {"max_seconds": float("nan")}, {"max_seconds": float("inf")},
                                    {"max_files": 1.5}, {"max_lines": True}])
def test_invalid_budgets_are_rejected(options):
    with pytest.raises(ValueError):
        SearchBudget(**options)


def test_large_integer_budget_does_not_overflow_float_validation():
    assert SearchBudget(max_files=10 ** 400).max_files == 10 ** 400


@pytest.mark.parametrize("call", ["run(1, extra=2)", "run(1, **options)"])
def test_unknown_keyword_is_not_a_complete_binding(tmp_path, call):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\n" + call + "\n"})
    target = find(ix, "run")
    found, = ix.callers(target["id"])
    assert not ix.describe_call(found, target)["binding_complete"]


def test_lambda_and_comprehension_parameter_shadowing(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(x):\n    return x\n"
                            "callback = lambda run: run(1)\n"
                            "items = [run(1) for run in functions]\n"})
    assert ix.callers(find(ix, "run")["id"]) == []


def test_multiple_imports_do_not_become_one_strong_binding(tmp_path):
    ix = project(tmp_path, {"worker.py": "def run(x):\n    return x\n",
                            "app.py": "if enabled:\n    from worker import run\nelse:\n    from other import run\nrun(1)\n"})
    call, = ix.callers(find(ix, "run", "worker.py")["id"])
    assert call["resolution"] == "ambiguous_binding"


def test_oversized_files_are_counted_toward_file_budget(tmp_path):
    ix = project(tmp_path, {"a.py": "pass\n" * 10, "b.py": "pass\n" * 10}, SearchBudget(max_files=1, max_file_bytes=10))
    assert ix.usage["files"] == 1 and len(ix.manifest) == 1
    assert any(i["code"] == "file_budget" for i in ix.issues)


def test_backward_slice_finds_earlier_assignment_and_condition(tmp_path):
    ix = project(tmp_path, {"app.py": "def run(request):\n    value = request.body\n" + "    pass\n" * 120 +
                            "    if value is not None:\n        return eval(value)\n"})
    locations, _ = ix.local_dependencies(find(ix, "run"), anchor=124)
    assert {2, 123, 124} <= {location["lo"] for location in locations}
    assert all("not proven" in location["reason"] for location in locations)


def test_callee_return_slice_finds_list_mutation_and_numeric_conversion(tmp_path):
    ix = project(tmp_path, {"app.py": "def parse(values):\n    result = []\n    for value in values:\n"
                            "        numeric = float(value)\n        result.append(numeric)\n    return result\n"})
    locations, _ = ix.local_dependencies(find(ix, "parse"))
    assert {2, 3, 4, 5, 6} <= {location["lo"] for location in locations}


def test_dynamic_callee_candidates_do_not_invent_binding(tmp_path):
    ix = project(tmp_path, {"app.py": "class Parser:\n    def transform(self, x):\n        return x\n"
                            "def run(obj, value):\n    return obj.transform(value)\n"})
    call, = ix.calls
    ids, resolution, _ = ix.callee_candidates(call)
    assert ids == [find(ix, "Parser.transform")["id"]] and resolution == "name_only_candidate"


def test_external_module_member_is_not_matched_to_same_named_local_method(tmp_path):
    ix = project(tmp_path, {"app.py": "import re\nclass Search:\n    def search(self):\n        return None\n"
                            "value = re.search('a', 'data')\n"})
    call, = ix.calls
    ids, resolution, _ = ix.callee_candidates(call)
    assert not ids and resolution == "external_or_unresolved_import"
