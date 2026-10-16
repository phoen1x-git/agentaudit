"""Declarations that exist in two places drift apart; these are the ones that were.

Each test here pins a single source of truth, because the failure mode is silent: a version
bumped in one file and not the other produces two environments that disagree, and a query
added to one list and not the other produces a file that is generated but never run.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PYPROJECT = ROOT / "pyproject.toml"
OUR_PACKAGES = {"core", "tools", "app", "demo", "tests"}
# distribution name -> the name you import
IMPORT_ALIASES = {"PyYAML": "yaml", "pyyaml": "yaml"}


def _pyproject_list(section: str, key: str) -> list[str]:
    """Pull a list of strings out of pyproject.toml without needing tomllib (3.11+)."""
    text = PYPROJECT.read_text(encoding="utf-8")
    start = text.index(f"[{section}]") if f"[{section}]" in text else 0
    m = re.search(rf"^{key}\s*=\s*\[(.*?)\]", text[start:], re.S | re.M)
    if not m:
        return []
    return [s.replace("\n", " ").replace("  ", " ").strip()
            for s in re.findall(r'"([^"]+)"', m.group(1))]


def _declared() -> set[str]:
    names = set()
    for spec in _pyproject_list("project", "dependencies"):
        names.add(re.split(r"[<>=!\[\s]", spec)[0])
    return names


def test_the_declaration_was_found():
    assert "PyYAML" in _declared(), "could not read [project] dependencies from pyproject.toml"


def _our_module_names() -> set[str]:
    """Every module this project ships, by the name it can be imported under.

    The scripts add their own directory to `sys.path`, so a call site reads `import ast_scan`
    rather than `from tools import ast_scan`. Both spellings are ours.
    """
    names = set(OUR_PACKAGES)
    for pkg in ("app", "core", "tools", "demo"):
        for path in (ROOT / pkg).glob("*.py"):
            names.add(path.stem)
    return names


def _imported_roots() -> dict[str, set[str]]:
    """Top-level module names imported by the shipped code -> which files use them.

    `demo/` is skipped on purpose: it is the sample project that `--demo` scans, which is
    fixture data, not part of the tool. Its imports (`fastapi`, `flask`) are deliberately
    absent because the whole point of that project is to be a plausible vulnerable target.
    """
    found: dict[str, set[str]] = {}
    for pkg in ("app", "core", "tools"):
        for path in (ROOT / pkg).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for full in names:
                    found.setdefault(full.split(".")[0], set()).add(path.name)
    return found


# A module imported by an orphan script that is not in the repository:
# `tools/fetch_src_probe.py:286` imports `probe_attack_surface`, which no longer exists, so
# that script raises ImportError if it is ever run. It is on the list to be deleted, and until
# then the set is pinned here -- so a *new* dangling import still fails this test.
KNOWN_MISSING = {"probe_attack_surface"}


def test_every_third_party_import_is_declared():
    """Code that imports something undeclared works on the author's machine and nowhere else."""
    declared = _declared() | set(IMPORT_ALIASES.values())
    ours = _our_module_names()
    undeclared = {}
    for module, files in _imported_roots().items():
        if module in sys.stdlib_module_names or module in ours or module.startswith("_"):
            continue
        if module not in declared and module not in KNOWN_MISSING:
            undeclared[module] = sorted(files)
    assert not undeclared, f"imported but not declared in pyproject.toml: {undeclared}"


def test_the_known_missing_module_is_still_missing():
    """If it comes back, the exemption above should go with it."""
    assert not list(ROOT.rglob("probe_attack_surface.py")), (
        "probe_attack_surface.py exists again -- remove it from KNOWN_MISSING")


def test_the_requirements_files_do_not_restate_the_dependency_list():
    """They are pointers now. A version repeated here would be a second place to change."""
    offenders = []
    for name in ("requirements.txt", "requirements-dev.txt"):
        for i, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if not s.startswith(("-e", "-r", "--")):
                offenders.append(f"{name}:{i}  {s}")
    assert not offenders, (
        "these lines declare a dependency outside pyproject.toml:\n" + "\n".join(offenders))


def test_neither_requirements_file_pins_a_version():
    for name in ("requirements.txt", "requirements-dev.txt"):
        body = (ROOT / name).read_text(encoding="utf-8")
        assert "PyYAML" not in body and "pytest" not in body, f"{name} restates a version"


def test_the_codeql_version_has_one_home():
    """The image and a local checkout must not be able to end up on different CLIs."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    m = re.search(r"^ARG CODEQL_VERSION=(\S+)", dockerfile, re.M)
    assert m, "the Dockerfile no longer declares ARG CODEQL_VERSION"
    version = m.group(1)

    setup = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
    assert version not in setup, f"setup.sh hard-codes {version}; it should read the Dockerfile"
    assert "ARG CODEQL_VERSION" in setup, "setup.sh does not read the version from the Dockerfile"


def test_the_query_list_has_one_owner():
    """`gen_ql.py` writes the queries, so it names them; the frontend must not re-list them."""
    from core.gen_ql import QUERIES
    frontend = (ROOT / "core" / "static_frontend.py").read_text(encoding="utf-8")
    for q in QUERIES:
        assert q not in frontend, f"static_frontend.py re-lists {q}; it should import the list"
    assert "QUERIES" in frontend, "static_frontend.py does not use the shared query list"
