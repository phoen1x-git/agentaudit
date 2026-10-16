#!/usr/bin/env python
"""Interactive mode: a menu, so you do not have to remember flags.

    agentaudit                 # opens this
    python app/interactive.py  # same thing

It only starts when it is talking to a real terminal. If stdin is a pipe or a file -- which is
what happens in CI, in a script, or when you pipe output -- it prints the usage instead of
waiting for input, so nothing here can hang an automated run.

Everything it offers is a thin wrapper around the same commands you can type directly; when it
runs one it shows you the exact command line, so the menu teaches the flags instead of hiding
them. Nothing is stateful: quitting and starting again changes nothing.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import __version__, workspace  # noqa: E402

WIDTH = 72


# ---------------------------------------------------------------------------
# terminal helpers
# ---------------------------------------------------------------------------
def force_utf8() -> None:
    """Make Chinese output survive cmd.exe.

    On Windows, Python writes console output through the console's own I/O layer, which takes
    UTF-8 bytes and hands UTF-16 to the console -- the code page does not matter. Wrapping the
    stream in UTF-8 is therefore correct on Windows *and* on a redirected stream.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")   # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            import io
            try:
                buf = stream.buffer
                wrapped = io.TextIOWrapper(buf, encoding="utf-8", errors="replace")
                if stream is sys.stdout:
                    sys.stdout = wrapped
                else:
                    sys.stderr = wrapped
            except AttributeError:
                pass


def enable_ansi() -> bool:
    """Turn on VT escape codes if the terminal supports them. Never make output depend on it."""
    if os.environ.get("NO_COLOR"):
        return False
    if not (sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


class Ui:
    def __init__(self) -> None:
        self.color = enable_ansi()

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def bold(self, text: str) -> str:      return self.paint(text, "1")
    def dim(self, text: str) -> str:       return self.paint(text, "2")
    def green(self, text: str) -> str:     return self.paint(text, "32")
    def yellow(self, text: str) -> str:    return self.paint(text, "33")
    def red(self, text: str) -> str:       return self.paint(text, "31")

    def rule(self) -> None:
        print("-" * WIDTH)

    def title(self, text: str) -> None:
        self.rule()
        print(self.bold(text))
        self.rule()


# ---------------------------------------------------------------------------
# running commands
# ---------------------------------------------------------------------------
def run(argv: list[str]) -> int:
    """Run one of the real scripts, with the terminals connected.

    `argv[0]` is a path relative to the checkout, which is resolved against the checkout --
    the child then runs with the *workspace* as its working directory, because that is where
    it should write. Passing the relative path straight through looks equivalent and is not:
    as soon as the workspace is somewhere else, the script cannot be found.

    The command line is printed first on purpose. The menu is meant to teach the flags, not to
    hide them: every action here is reproducible by typing it out.
    """
    script = (ROOT / argv[0]).resolve()
    if not script.exists():
        print(Ui().red(f"missing script: {argv[0]}"))
        return 2

    print()
    print(Ui().dim("$ python " + " ".join(argv)))
    print()
    try:
        return subprocess.call([sys.executable, str(script), *argv[1:]], cwd=str(workspace()))
    except KeyboardInterrupt:
        print("\n(interrupted)")
        return 130


def rounds() -> list[Path]:
    out = workspace() / "out"
    if not out.is_dir():
        return []
    return sorted([p for p in out.iterdir() if p.is_dir() and p.name.startswith("round-")],
                  key=lambda p: p.stat().st_mtime, reverse=True)


def ask(prompt: str, default: str = "") -> str | None:
    """Ask for a line. Returns None if the input ended (Ctrl-D, or Ctrl-C at the prompt).

    Callers must handle None. Treating "the input ended" as an empty answer is how a menu
    ends up spinning forever: an empty answer is a legitimate thing to type, so it cannot
    double as the end-of-input signal.
    """
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return answer or default


def pause() -> None:
    try:
        input("\n" + Ui().dim("press Enter to go back to the menu"))
    except (EOFError, KeyboardInterrupt):
        print()


# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------
def action_scan(ui: Ui) -> None:
    ui.title("Scan a target")
    print("  1  the bundled sample project     (no CodeQL, no API key, ~1 second)")
    print("  2  a directory on this machine")
    print("  3  a GitHub repository (owner/name)")
    print("  0  back")
    choice = ask("choose")

    if choice is None:
        return
    argv = ["app/scan.py"]
    if choice == "1":
        argv += ["--demo"]
    elif choice == "2":
        path = ask("directory", ".")
        if not path:
            return
        argv += ["--path", path]
    elif choice == "3":
        repo = ask("repository (owner/name)")
        if not repo:
            return
        argv += ["--repo", repo]
    else:
        return

    tag = ask("round name (leave empty for a default)", "menu-round")
    if tag:
        argv += ["--tag", tag]

    triage = ask("triage with an LLM? it costs money (y/N)", "n")
    if triage is None:
        return
    if triage.lower().startswith("y"):
        argv.append("--llm")
        print(ui.yellow("note: this spends API credits; the run prints the cap before it starts"))
    else:
        print(ui.dim("(no LLM triage: you get the candidate list with no verdicts)"))

    rc = run(argv)
    print(ui.green("done") if rc == 0 else ui.red(f"exit code {rc}"))
    allrounds = rounds()
    if allrounds:
        print(f"  the newest round is {allrounds[0]}")


def _pick_round(ui: Ui) -> Path | None:
    items = rounds()
    if not items:
        print(ui.yellow("no rounds yet in"), workspace() / "out")
        print(ui.dim("scan something first (option 1)"))
        return None
    print("  recent rounds:")
    for i, p in enumerate(items[:10], 1):
        from datetime import datetime
        stamp = datetime.fromtimestamp(p.stat().st_mtime).strftime("%m-%d %H:%M")
        n = _count_rows(p)
        print(f"    {i}  {p.name:<28} {stamp}  {n} candidate(s)")
    choice = ask("which one", "1")
    if choice is None or not choice.isdigit() or not 1 <= int(choice) <= min(10, len(items)):
        return None
    return items[int(choice) - 1]


def _count_rows(rd: Path) -> str:
    ts = rd / "findings.tsv"
    if not ts.exists():
        return "?"
    try:
        return str(max(0, len(ts.read_text(encoding="utf-8-sig").strip().splitlines()) - 1))
    except OSError:
        return "?"


def action_round(ui: Ui) -> None:
    ui.title("Open a previous round")
    rd = _pick_round(ui)
    if rd is None:
        return
    print()
    print("  1  explain one candidate        (why was it reported?)")
    print("  2  serve it in a browser        (localhost only)")
    print("  3  regenerate the report and index")
    print("  4  export it as SARIF")
    print("  0  back")
    choice = ask("choose")

    if choice == "1":
        idx = ask("candidate number (1 = first row)", "1")
        if idx is None:
            return
        run(["app/explain.py", str(rd), "--index", idx])
    elif choice == "2":
        run(["app/serve.py", str(rd)])
    elif choice == "3":
        run(["app/make_report.py", str(rd), "--select", "all"])
        run(["app/make_index.py", str(rd)])
    elif choice == "4":
        run(["tools/to_sarif.py", str(rd)])
    else:
        return


def action_selftest(ui: Ui) -> None:
    ui.title("Rule self-tests")
    print(ui.dim("ten suites of labelled cases; seconds to run, no network"))
    rc = run(["tools/run_selftests.py"])
    print(ui.green("all suites passed") if rc == 0 else ui.red("some suites failed"))


def action_validate(ui: Ui) -> None:
    ui.title("Rule configuration")
    run(["tools/validate_config.py"])


def action_log(ui: Ui) -> None:
    ui.title("Scan statistics")
    print(ui.dim("counts only: no source, no paths, no project names. Nothing is uploaded."))
    print("  1  summarise what I have scanned")
    print("  2  export an aggregate that is safe to share")
    print("  0  back")
    choice = ask("choose")
    if choice == "1":
        run(["tools/scan_log.py"])
    elif choice == "2":
        out = workspace() / "scan_stats.json"
        run(["tools/scan_log.py", "--export", "--out", str(out)])
        print(f"\nwrote {out}")
        print(ui.dim("read it before you send it -- it is your decision, not the tool's"))


def action_help(ui: Ui) -> None:
    ui.title("Commands, if you would rather type them")
    from app.cli import COMMANDS
    width = max(len(k) for k in COMMANDS)
    for name, (_script, desc) in COMMANDS.items():
        print(f"  {name:<{width}}  {desc}")
    print()
    print(ui.dim("  agentaudit <command> --help   for one command's options"))


MENU = [
    ("1", "Scan a target", action_scan),
    ("2", "Open a previous round", action_round),
    ("3", "Run the rule self-tests", action_selftest),
    ("4", "Validate the rule configuration", action_validate),
    ("5", "Scan statistics (local, statistics only)", action_log),
    ("6", "List the commands", action_help),
]


def wants_interactive() -> bool:
    """Interactive mode needs a terminal, unless it is forced explicitly.

    `AGENTAUDIT_INTERACTIVE=1` forces it on. That exists so the menu can be driven with
    scripted input in tests -- without the escape hatch, an automated test can only ever
    exercise the "not a terminal" branch.
    """
    if os.environ.get("AGENTAUDIT_INTERACTIVE") == "1":
        return True
    if os.environ.get("AGENTAUDIT_INTERACTIVE") == "0":
        return False
    return bool(sys.stdin.isatty()) if hasattr(sys.stdin, "isatty") else False


def main(argv: list[str] | None = None) -> int:
    force_utf8()
    ui = Ui()

    if not wants_interactive():
        # Not a terminal: never block waiting for input.
        from app.cli import usage
        print("agentaudit: no terminal on stdin, so interactive mode is off.\n")
        usage()
        return 0

    print()
    ui.title(f"agentaudit {__version__}   (type a number, or ctrl-c to quit)")
    print(f"  workspace: {workspace()}")
    print()

    while True:
        for key, label, _fn in MENU:
            print(f"  {key}  {label}")
        print("  0  Quit")
        print()
        choice = ask("what now", "0")
        if choice is None or choice.strip() in ("0", "q", "quit", "exit"):
            print("bye")
            return 0
        choice = choice.strip()
        action = next((fn for key, _label, fn in MENU if key == choice), None)
        if action is None:
            print(ui.yellow(f"no such option: {choice}"))
            continue
        try:
            action(ui)
        except Exception as e:                       # a menu must never die on one action
            print(ui.red(f"that failed: {type(e).__name__}: {e}"))
        pause()


if __name__ == "__main__":
    raise SystemExit(main())
