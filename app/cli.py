#!/usr/bin/env python
"""One command for the whole tool.

    agentaudit scan --demo                 scan a target (--demo / --path / --repo)
    agentaudit explain out/round-x         show why a candidate was reported
    agentaudit serve  out/round-x          read the results in a browser
    agentaudit report out/round-x          render the report draft
    agentaudit index  out/round-x          render the HTML index
    agentaudit round  --tag r1             run one round over a target table
    agentaudit all    --tag r1             prepare -> scan -> report
    agentaudit selftest                    run the rule self-tests
    agentaudit validate                    check core/config/*.yml
    agentaudit log                         show or export the local scan log

Without an install, `python app/scan.py ...` and the other scripts work exactly the same;
every subcommand here just forwards to one of them.

    agentaudit --help        list the commands
    agentaudit scan --help   help for one command
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# name -> (script, one-line description)
COMMANDS: dict[str, tuple[str, str]] = {
    "scan": ("app/scan.py", "scan a target: --demo, --path DIR or --repo OWNER/NAME"),
    "explain": ("app/explain.py", "show why a candidate was reported"),
    "serve": ("app/serve.py", "serve a round directory on localhost"),
    "report": ("app/make_report.py", "render the report draft for a round"),
    "index": ("app/make_index.py", "render the HTML index for a round"),
    "round": ("app/run_round.py", "run one scan round over a target table"),
    "all": ("app/run_all.py", "prepare -> scan -> report, resumable"),
    "selftest": ("tools/run_selftests.py", "run the rule self-tests"),
    "validate": ("tools/validate_config.py", "validate core/config/*.yml"),
    "log": ("tools/scan_log.py", "show or export the local scan statistics log"),
}


def usage(stream=sys.stdout) -> None:
    from core import __version__
    print(f"agentaudit {__version__}", file=stream)
    print("", file=stream)
    print("usage: agentaudit <command> [options]", file=stream)
    print("", file=stream)
    width = max(len(k) for k in COMMANDS)
    for name, (_script, desc) in COMMANDS.items():
        print(f"  {name:<{width}}  {desc}", file=stream)
    print("", file=stream)
    print("  agentaudit <command> --help   for the options of one command", file=stream)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        usage()
        return 0
    if argv[0] in ("-V", "--version", "version"):
        from core import __version__
        print(__version__)
        return 0

    cmd, rest = argv[0], argv[1:]
    if cmd not in COMMANDS:
        print(f"unknown command: {cmd}", file=sys.stderr)
        usage(sys.stderr)
        return 2

    script, _desc = COMMANDS[cmd]
    path = ROOT / script
    if not path.exists():
        print(f"{script} is missing from this checkout", file=sys.stderr)
        return 2

    # Forward the rest of the arguments to the script and run it as a program. Using runpy
    # keeps the scripts usable both ways: `agentaudit scan ...` and `python app/scan.py ...`.
    sys.argv = [f"agentaudit {cmd}", *rest]
    try:
        runpy.run_path(str(path), run_name="__main__")
    except SystemExit as e:
        code = e.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        # `raise SystemExit("message")` -- the script wanted that shown, so show it.
        print(code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
