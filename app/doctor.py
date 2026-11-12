#!/usr/bin/env python
"""Say what this machine can and cannot do, in one screen.

Every fact printed here was previously spread across README, CONFIGURING and the source: which
Python, whether the dependency is installed, whether CodeQL is present, whether there is a key
and what the budget is, and where output will land. A reader had to assemble that themselves,
and the failure mode was confusing: without CodeQL a real scan degrades to the offline path
rather than stopping, and without a key triage simply does not run, so both look like "it
worked, and found less".

    agentaudit doctor
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OK = "[ok]"
MISSING = "[--]"
BROKEN = "[!!]"


def _line(mark: str, name: str, detail: str) -> str:
    return f"{mark} {name:<14} {detail}"


def _python() -> str:
    v = sys.version_info
    return _line(OK if v >= (3, 10) else BROKEN, "python",
                 f"{v.major}.{v.minor}.{v.micro} at {sys.executable}")


def _module(name: str, why: str, dist: str | None = None) -> tuple[str, bool]:
    try:
        __import__(name)
    except Exception:
        return _line(BROKEN, name, f"missing ({why}); pip install -e . installs it"), False
    # importlib.metadata rather than __version__: jsonschema deprecated its own attribute and
    # printed a DeprecationWarning into the middle of this screen. The distribution name also
    # differs from the import name often enough that guessing it shows up as "?".
    try:
        from importlib.metadata import version
        ver = version(dist or name)
    except Exception:
        ver = "?"
    return _line(OK, name, ver), True


def _codeql() -> tuple[str, bool]:
    try:
        from core.static_frontend import codeql_exe
        exe = codeql_exe()
    except Exception as e:  # the frontend itself failed to import, which is worth saying
        return _line(BROKEN, "codeql", f"could not ask the frontend: {e}"), False
    if not Path(exe).exists():
        return _line(MISSING, "codeql",
                     f"not at {exe}; a real scan falls back to the offline path"), False
    return _line(OK, "codeql", str(exe)), True


def _llm() -> tuple[str, bool]:
    raw = os.environ.get("DEEPSEEK_KEY_FILE") or os.path.expanduser("~/.deepseek_key")
    key_file = Path(raw)
    budget = os.environ.get("AF_LLM_MAX_CNY", "30.0")
    if key_file.exists():
        return _line(OK, "llm key", f"{key_file} (budget {budget} CNY per run)"), True
    return _line(MISSING, "llm key",
                 f"no file at {key_file}; triage does not run without one"), False


def _out_dir() -> tuple[str, bool]:
    out = Path.cwd() / "out"
    try:
        out.mkdir(parents=True, exist_ok=True)
        probe = out / ".doctor"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        return _line(OK, "output", f"{out} (writable)"), True
    except Exception as e:
        return _line(BROKEN, "output", f"{out} is not writable: {e}"), False


def main() -> int:
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("agentaudit doctor - say what this machine can and cannot do, in one screen")
        print("")
        print("  agentaudit doctor    print the report")
        print("")
        print("It checks Python, the dependencies, CodeQL, the LLM key and its budget,")
        print("and where output lands, and says what each missing piece would unlock.")
        return 0
    from core import __version__

    print(f"agentaudit {__version__} - what this machine can do")
    print()

    print(_python())
    rows = [_module("yaml", "PyYAML is the only runtime dependency", dist="PyYAML"),
            _module("jsonschema", "the candidate contract validator needs it")]
    for text, _ok in rows:
        print(text)

    codeql_text, has_codeql = _codeql()
    llm_text, has_llm = _llm()
    out_text, has_out = _out_dir()
    print(codeql_text)
    print(llm_text)
    print(out_text)

    print()
    print("You can run now:")
    print("  agentaudit scan --demo             the built-in sample; needs neither of the two")
    print("  agentaudit explain out/round-demo  why a candidate was reported")
    print("  agentaudit selftest                the rules' own tests")
    if has_codeql:
        print("  agentaudit scan --path <dir>       a real target, with CodeQL")
    if has_llm:
        print("  agentaudit scan --path <dir> --llm  ... and let the model judge each candidate")

    missing = []
    if not has_codeql:
        missing.append("  CodeQL    unlocks scanning a real project. scripts/setup.sh installs it;\n"
                       "            without it a scan still runs, but only on the AST path, and\n"
                       "            it cannot follow a value across functions.")
    if not has_llm:
        missing.append("  llm key   unlocks --llm. Put the key in ~/.deepseek_key or point\n"
                       "            DEEPSEEK_KEY_FILE at it. Without one, scan reports candidates\n"
                       "            and stops there: no verdict, no reason.")
    if missing:
        print()
        print("Not available, and what it would unlock:")
        print("\n".join(missing))

    if not has_out:
        print()
        print("The output directory is not writable, so nothing will land. Fix that first.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
