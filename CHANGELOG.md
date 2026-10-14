# Changelog

Notable changes, newest first. This project follows [Keep a Changelog][kac] and
[Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## Unreleased

### Added

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

### Changed

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
