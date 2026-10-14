# Contributing

Thanks for looking. This is a security tool, so the rules below are mostly about not letting
the output overstate what was actually established.

## Getting set up

```bash
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .                     # optional: gives you the `agentaudit` command
python tools/run_selftests.py        # the rule self-tests
python -m pytest -q                  # the suite CI runs
```

A full scan also needs the CodeQL CLI; `./scripts/setup.sh` installs it. The offline mode
(`python app/scan.py --demo`, or `agentaudit scan --demo`) works without it, and most
development does not need it either.

## What CI runs

In order, and all of it must pass:

```
pip install -e . && agentaudit --version && agentaudit validate
python -m compileall -q app core tools demo tests
python tools/validate_config.py
python tools/run_selftests.py
python app/scan.py --demo --tag ci
python -m pytest -q
```

## Registering a new command

`app/cli.py` is a table of `name -> script`. A new entry point should be a script under
`app/` or `tools/` with the usual `main()` and `if __name__ == "__main__"` guard; add one
line to `COMMANDS` and it is reachable as `agentaudit <name>`. `tests/test_cli.py` checks the
help lists every command and that exit codes survive the hop.

## Where output goes

Working output (`out/`, `data/`, `_targets/`) is resolved through `core.workspace()`:
`AGENTAUDIT_HOME` if set, otherwise the current directory. Never hard-code the package
directory for output — an installed copy would then write into `site-packages`, which the
tests catch but is easy to forget.

## The one rule that matters most

**Never let the output claim more than was done.**

- Results are **candidates**, not vulnerabilities. Nothing was executed. If a change makes the
  report sound like something was verified, it is wrong even if it is phrased carefully.
- Keep facts and inferences in separate places, as `app/make_report.py` does: the code excerpt
  is a fact, everything derived from it is a question.
- When something cannot be determined, report that (`needs_human`, `arg_source=unknown`)
  rather than picking the plausible answer. `LIMITATIONS.md` is the register of what is not
  determined; update it when you add a limit.
- A failure must never be recorded as "no findings". The CodeQL frontend raises on a failed
  analysis for exactly this reason, and `app/scan.py` logs the fallback loudly instead of
  quietly reporting fewer candidates.

## Adding a check for a dangerous function

Edit `core/config/sinks.yml`. It is a config change, not a code change — see
[CONFIGURING.md](CONFIGURING.md) for the fields. Then:

1. `python tools/validate_config.py` — an unknown field name is silent at run time, so this
   step is not optional.
2. If the rule belongs behind a switch (it is noisy, or it trades precision for recall), give
   it a `group` and document why in the comment above it.
3. If it changes what the tool reports by default, say so in the `CHANGELOG.md` and in the
   round metadata, because rounds are only comparable when the settings match.

## Changing the AST checks

`tools/ast_criteria.py` and `core/duality.py` are the pure-Python checks. They have labelled
case suites under `tools/selftest_*.py`:

- Add a case for anything you change, including the case that currently misbehaves. The
  suites were built from real failures; a fix without a case is a fix that will come back.
- Run **all** of them, not just the one you touched: `python tools/run_selftests.py`.
- `tests/test_suites.py::test_every_selftest_file_is_registered` fails if a suite exists on
  disk but is not being run.

## Before you commit

- `tests/test_no_leaks.py` fails if a local path, a secret, or a word from the private project
  this tool came from ends up in the tree. It is easier to read that file than to guess.
- Do not commit `core/config/targets.yml` — it names the repositories you scan, and it is
  gitignored on purpose. Use `targets.example.yml` for anything you want to share.
- Do not paste a real repository name, finding, or `owner/repo#<number>` into a comment, a test
  case, or a docstring. Use a placeholder. Examples that look real are how a target list leaks.

## Pull requests

Small and focused beats large. If a change alters what the scanner reports by default, say so
in the description and in `CHANGELOG.md`, and include the before/after counts you measured.
