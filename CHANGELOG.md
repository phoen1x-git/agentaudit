# Changelog

Notable changes, newest first. This project follows [Keep a Changelog][kac] and
[Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## 0.4.0 — 2026-10-16

### Added

- **A banner** for the interactive mode and the usage text, drawn with block characters and
  generated from a small bitmap rather than typed by hand, so the columns line up. Four
  variants ship (`python app/banner.py` previews them) and `boxed` is the default; switching is
  one word in `app/banner.py`.

  The part that needed care is the fallback. Block elements and box drawing are
  East-Asian-Width "ambiguous" — a CJK console font draws them two cells wide, so a frame that
  is square in Consolas is a staircase in SimSun. The console font is queried by name at
  startup (and `LANG` on other platforms) and a pure-ASCII rendering is used when it is CJK.
  `AGENTAUDIT_ASCII=1` forces it either way.
- **Interactive mode** (`agentaudit`, or `agentaudit interactive`). A menu for when you do not
  want to remember flags: scan a target, open a previous round, run the self-tests, validate
  the configuration, or look at the scan statistics. It echoes the command line it runs, so the
  menu teaches the flags rather than hiding them, and it starts only when there is a terminal —
  piped or in CI it prints usage and exits, so nothing can hang waiting for input.
  `AGENTAUDIT_INTERACTIVE=1` forces it on, which is how the tests drive it.
- `tests/test_docs.py`: keeps the two READMEs structurally in step, checks that every
  subcommand is documented in both, that every documented script exists, and that the rule
  count quoted in the READMEs matches the configuration.
- A `docker` job in CI that builds the image and exercises it (CodeQL present and runnable, the
  entry point works, the bundled sample produces a round).
- A `tests/test_interactive.py` suite.
- `tests/test_ci.py`, which parses the workflow and fails if a `run:` step is unnamed or calls a
  script that does not exist. A malformed workflow does not fail loudly; it does not start.
- `tests/test_packaging.py`: every third-party import is declared in `pyproject.toml`, the
  requirements files restate nothing, the CodeQL version has one home, and the query list is
  imported rather than copied.
- `tests/test_no_leaks.py`, which fails on a machine path, a secret, the private project's
  vocabulary, or a date in a source comment — the last one because a date is a reliable sign
  that a comment was copied out of a private work log and says nothing to a reader.
- `agentaudit targets`, which is the target screener; it was reachable only as a script.
- `assets/demo.gif`, under the headline table of both READMEs: `scan --demo`, then `explain`.

### Fixed

- **Interactive mode spun forever at end of input.** Ctrl-D (or an exhausted script) made the
  menu loop print "no such option" as fast as it could. "The input ended" now has its own
  signal instead of sharing one with "the user pressed Enter".
- **Interactive mode could not run a scan when the workspace was elsewhere.** It resolved the
  script path against the workspace instead of against the checkout, so any run with
  `AGENTAUDIT_HOME` (or simply a different working directory) failed with exit code 2 and no
  explanation.
- The Chinese README had fallen several sections behind the English one (install, reading the
  results, the scan log, `--ignore`, the SARIF row). Both are now in step, and the new test
  above makes that a build failure rather than something nobody notices.

### Changed

- **The numbers in the documents are re-derived instead of asserted.** The rule count in the
  README (52), the rule-suite count (10) and the test count ("more than 120") in
  `CONTRIBUTING.md` are checked by `tests/test_docs.py` against the configuration and against
  pytest's own collection, so a number that drifts fails the build. A number in a README is
  marketing until something verifies it.
- The "at a glance" table at the top of both READMEs had an empty header row. It is down to the
  two rows that answer a reader's first two questions, and both are things they can run.
- **The badge and the issue links point at the real repository.** A placeholder that ships is
  worse than a missing link, because it looks like a link: it renders, it is clickable, and it
  goes nowhere. A test now fails on it anywhere in the tree.
- **The private project this grew out of no longer leaves fingerprints.** A directory of
  internal notes was being shipped as package data — a real target's file name and line number,
  the size of the corpus, notes attributing decisions. It is gone, and `tests/test_no_leaks.py`
  checks for machine paths, secrets, that vocabulary and dates in source comments, so the next
  one fails the build instead of shipping.
- **Both READMEs were restructured around what a reader actually does.** The old order put
  "Reading the results" before "Quick start", with the internals ("Pipeline", "What the output
  looks like") sitting between them — so a first-time reader hit output files for a scan they
  had not run yet, before being told how to run one. The order is now
  why → install → quick start → read the results → … → how it works (internals, last but two).
  The internals sections were merged and moved to the end, and the duplicated artefact tables
  were folded into one.
- The "help me" section is now its own section, right after the reader has seen their first
  round, instead of a sub-heading buried inside the scan-log text. It states what is and is not
  recorded as a table, and repeats that the log is theirs to send or not.
- The author's note is now titled "Author's note" / "作者的话".
- The READMEs explain how to contribute scan statistics, and why they are worth more than a
  star: a check that fires on someone else's code and never on mine is the interesting one.
  `agentaudit log --export` prints a shareable aggregate, and nothing is ever sent for you.
- The Dockerfile runs the CodeQL CLI during the build, so a wrong release layout fails the build
  loudly instead of producing an image whose scanner cannot run. Its entry point is
  `agentaudit scan`, and the image also has the `agentaudit` command available.
- **`tools/target_screener.py` no longer carries a list of real repositories.** It moves to
  `core/config/known_targets.yml`, which is not shipped; `known_targets.example.yml` documents
  the format and starts empty. Its self-test runs offline, against synthetic cases.
- **The image builds for arm64 as well as x64.** The Dockerfile named the x64 CodeQL archive
  directly, so an arm64 build could not have succeeded. The archive is chosen from `TARGETARCH`
  now, and an architecture with no CodeQL release stops the build with a message.
- **The CI `docker` job's last step could never pass.** It started a second container and looked
  there for the first container's output, which by then no longer existed. It is one container
  now, with a volume mounted, and it asserts the findings file landed on the host.
- The one-line banner's ASCII fallback marks the line with `>_` rather than `[]`, which readers
  took for a missing glyph rather than a mark.
- A pass over the tree for code with no live caller removed the dead functions, the duplicate
  declarations and the scripts nothing reached, and matched the documentation to the code.
- Both READMEs were rewritten in a plain register. The Chinese one had been translated sentence
  by sentence from the English, which is why it read like a translation.
- `AGENTAUDIT_INTERACTIVE=0` explicitly disables interactive mode.

## 0.3.0 — 2026-10-14

### Added

- **SARIF 2.1.0 export of the scanner's own findings** (`tools/to_sarif.py`, written to
  `agentaudit.sarif` on every scan). Previously SARIF was only ever *read* — the CodeQL
  frontend's output — so a round could not be viewed in a code-scanning UI. The export uses
  relative paths only (no absolute path, no `originalUriBaseIds`), marks every result
  `warning`, carries the verdict in `properties`, and leaves out rows already triaged
  `not_vuln` unless `--all` is given.
- **A local scan log, and an optional way to share it** (`tools/scan_log.py`). Every scan
  appends counts only — files, candidates, the split across checks and verdicts, elapsed time,
  version, and hashes of the rule configuration. Source, paths, project names, snippets and
  fingerprints are never written, and the record is checked against that rule before it is
  logged. Nothing is uploaded: `--export` writes a small aggregate, runs a redaction check
  over it, and refuses to write anything that fails. `--no-log` or `AGENTAUDIT_NO_LOG=1`
  turns it off, `log --clear` deletes it.
- **`agentaudit` command** and an installable package (`pyproject.toml`). `pip install -e .`
  gives one entry point for the whole tool; `agentaudit --help` lists the subcommands. The
  scripts still run directly, and nothing about that changed.
- **`agentaudit serve <round>`** (`app/serve.py`): reads a round in a browser. It binds to
  127.0.0.1 only, serves one directory, and refuses directory listings and path traversal.
- **`--ignore GLOB`** on `app/scan.py` (repeatable), to skip vendored or generated trees.
- `AGENTAUDIT_HOME` for where output goes. Working output no longer has to live in the
  installation.
- `app/explain.py` — prints why a candidate was reported: the surrounding source, the call
  chain that reaches it, the guards on that path, and where the dangerous argument comes from.
  It says "not determined by this scan" when that is the case, rather than staying silent.
- `--fail-on none|any|vuln` on `app/scan.py`, so a scan can gate a build.
- `--diff [REF]` on `app/scan.py`, to report only candidates in files changed since `REF`.
- `tools/validate_config.py` — validates `core/config/*.yml`. This closes a silent failure
  mode: a misspelled field name made the generator skip an entry, so the check quietly stopped
  covering that function.
- `CONFIGURING.md` (the rule field reference, with the generated rule table) and
  `LIMITATIONS.md` (what the tool does not find, and which of its silences are meaningful).
- `tests/` and a GitHub Actions workflow running on Python 3.10 and 3.12.
- `scripts/setup.sh` — installs the Python dependency and the CodeQL CLI.

### Fixed

- **The skip list was matched against the file's absolute path**, so a project that itself
  lived under a directory called `build`, `venv` or `site-packages` was skipped almost
  entirely — an installed copy reported one candidate instead of thirteen. It is now matched
  against the path relative to the source root, and there are regression tests for both
  directions (nested paths still scanned, real subdirectories still skipped).
- `app/cli.py` swallowed `SystemExit("message")`, so a script's own error text was lost.
- The round's `elapsed_sec` in the scan log is now measured over the same span as the
  "done in" line the user sees.

### Changed

- `demo/` is a package so `--demo` also works from an installed copy.
- The round's `findings.json` also records `src_root`, so `--explain` can show the source
  lines of a run that used the batch pipeline.

## 0.2.0 — 2026-10-14

### Added

- `app/scan.py`: `--demo`, `--path ./dir` and `--repo owner/name`. Scanning a single project
  no longer requires a target table, a fetcher and a database step.
- `demo/`: a synthetic, deliberately vulnerable sample project, so the scanner can be run
  without cloning anything. Six kinds of check fire on it.
- `tools/ast_scan.py`: the offline scan (the AST checks plus the strong/weak-form check).
- Two modes: **full** (CodeQL + the AST checks, also writes `results.sarif`) and **offline**
  (the AST checks only). The run reports which one it used.
- `Dockerfile` and `.dockerignore`, with the CodeQL CLI baked in.
- `core/config/targets.example.yml`, documenting the target table format.

### Changed

- **LLM triage is off by default.** It costs money, so it now runs only with `--llm`, which
  prints the candidate count and `AF_LLM_MAX_CNY` before starting and the actual spend after.
- Reporting a round without triage now says "not triaged" instead of showing a confidence of
  0.0, and `app/make_report.py --select vuln|all|untriaged` controls which rows are written up.
- The CodeQL CLI location is platform-aware and overridable with `AF_CODEQL`.
- `app/run_round.py` reports a missing target table as an error instead of failing at import.

### Fixed

- `.gitignore` did not ignore `core/config/targets.yml`, which names the repositories being
  scanned. A commit could therefore have published a target list.

## 0.1.0 — 2026-10-14

First public release.

### Added

- The scanner: a CodeQL frontend over a configurable sink list, cross-file argument-source
  analysis, a reachability pre-filter, and an LLM triage layer that can answer
  `needs_human` instead of guessing.
- The parameter-taint check (`tools/param_taint_criteria.py`) and its labelled cases.
- Ten rule self-test suites and `tools/run_selftests.py`.
- Synthetic sample output in `examples/`, and the English and Chinese README.
