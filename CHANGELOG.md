# Changelog

Notable changes, newest first. This project follows [Keep a Changelog][kac] and
[Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## 0.6.0 — 2026-11-12

### Added

- **The review bench is four commands, not four scripts.** `agentaudit review-records`,
  `review-pack`, `review-validate` and `review-merge`. They arrived in 0.5.1 under `tools/`,
  where `agentaudit --help` does not look, so the only way to learn they existed was to read
  the section of the README that explains them. That is backwards: the help output is the
  list of what this tool does, and a capability missing from that list has to be found by
  accident first. Each command now names itself in `--help` the way every other one does,
  takes the positional argument the README shows, and says in its option help what it writes
  and where. The scripts still run directly, unchanged.
- **`review-validate --allow-partial`** is documented as what it is: accepting a submission
  that covers some of the packet's cases, which is how a reviewer who ran out of time gets a
  usable partial record instead of an error.

### Changed

- **The command table is 21 entries, and still has one home.** `app/cli.py` lists them;
  `usage()`, the tests and both README tables read from there. The four new descriptions are
  short on purpose, because the help output is a column, not a paragraph.

### Known gaps

- Nothing about the bench changed except how it is reached. The limits stated under 0.5.1
  still hold: a validated submission records agreement between two people, not accuracy, and
  masking removes the model's opinion and the project labels rather than the identities
  inside the source text.

## 0.5.1 — 2026-11-12

A patch release: the human-review bench 0.5.0 shipped without documenting, the tests it
shipped without, and three places where a saved result described something other than what
was actually done.

### Added

- **Human review, from a round to a reviewer's answer and back.** Four scripts and
  `core/review_pack.py`. `tools/build_external_review_records.py` turns a round that carries
  backend evidence into records with no verdict in them. `tools/build_review_pack.py` masks
  the historical model opinions and the project labels, shuffles case order by a seed, and
  writes a packet of three files: `packet.json`, a blank `review-template.json`, and
  `review.html`, which is an offline form that makes no network request and keeps its
  progress in the browser tab. `tools/validate_review_pack.py` then checks packet identity,
  required fields, timezone-aware timestamps, and that every cited evidence id exists in
  that case. `tools/merge_review_submission.py` joins validated submissions back to the
  private identities in a separate file and reports how often two reviewers agreed and how
  long each said they took.
- **What the validation does not do is part of the design, and both tools say so when they
  print.** A confident wrong review passes exactly as well as a correct one: the result file
  is a record of what two people concluded from the same packet, not a measurement of
  accuracy. Masking the model's opinion is also not blindness. Source text, file names and
  anything quoted inside the evidence can still identify the project, so what is removed is
  the opinion, not the identity.
- **Two offline replays for the judgement layer.** `tools/eval_triage.py` replays a fixed set
  of recorded model responses through the triage policy, with no API call and no target
  execution, and checks each response against its recorded hash first. `tools/eval_investigation.py`
  runs each case under three retrieval strategies (no investigator, broad, focused), counts how
  much of the expected source each reached, and calls a focused pass that finds less than the
  broad one a regression. It is offline unless `--llm` is given, and that switch carries its own
  call and spend caps.
- **The tests 0.5.0 shipped without.** The suite collects 473 tests, of which 472 pass and one
  is skipped, up from 195. Most of the new ones cover modules that had none: the CSV parser
  (two arguments in one cell, CRLF, quoted commas, a 200k-character field), `candidates`,
  `investigate`, `import-sarif`, and the review bench end to end. The triage and investigation
  replays read their cases from `tests/fixtures/`, including a real ESLint 10.14.0 SARIF file
  with its URIs rewritten to relative paths.

### Changed

- **The query pack lost a query and a special case.** `get_callchain_and_location.ql` was the
  SARIF-era query; nothing imports it any more and the CSV path asks `get_arg_source.ql`, so
  every compile was paying for a query nobody ran. `add_calls` matched `Process(...)` whose
  target named one particular library function. That is a calling convention written into a
  general query, and it only ever fired on the project it came from; it is gone from all
  three predicates. Regenerating `qlpack.yml` changed the pack name, so CodeQL cannot answer
  from a cached result for the old one.
- **`--evidence` printed nothing useful, and the saved snapshot was never read.** `explain`
  rebuilt its evidence from the file as it is now, so editing a file between the scan and the
  explanation silently changed the evidence under a verdict that was already fixed. It reads
  the snapshot saved in `verdicts.json` instead, and `--evidence` prints that whole passage
  rather than a window around the sink.
- **The rubric stamp ignored the switches.** `run_round` hashed `llm_judge.RUBRIC`, which is
  only the fixed body of the prompt; the argument-source, scope and repository sections are
  appended when their switch is on, so two different rubrics carried the same hash. It now
  hashes `rubric_text()` and records a digest of the triage policy beside it.
- **LLM usage was the process total.** Two rounds in one process each claimed the sum of
  both. The record is the delta around the call.

### Fixed

- **Every snippet was fenced as `python`.** One round can hold `.py`, `.ts` and `.java`, and
  the fence follows the candidate's language now.
- **An imported result printed its rule id where a callee belongs.** When an external result
  has no resolved call name, the report says the backend reported this rule at this line
  instead of putting the rule name in the position the call chain occupies.

### Known gaps

- **The human review measures agreement, not correctness.** Two reviewers who share a
  misreading agree, and the file records that agreement without comment. It is evidence about
  the packet, not about the tool.
- **The query narrowing has not been re-measured.** Removing the special case narrows what
  `add_calls` links, and the comparison in 0.5.0 was one target on one CodeQL version. There
  is no CodeQL on the machine these tests run on, so nothing here would notice a lost row.
- **`eval_triage` and `eval_investigation` have small case sets, and the replay set records
  what the policy should do rather than what it does.** On the day this was written the replay
  matched 6 of the 14 `dev` cases, so neither script runs in CI: their exit codes are a reading
  for whoever is editing the policy, not a gate. The investigation set is ten cases and
  nineteen expected source lines under three strategies, which shows the shape of a regression
  and does not size one.

## 0.5.0 — 2026-11-11

### Added

- **The judgement now carries the evidence it was given.** It used to return a paragraph; it
  returns a `Judgment` with the source snapshot, the lines it quoted, a hash of the input, and
  `blocking_gaps` naming the evidence that was missing. A verdict can be checked against the
  lines that produced it, and a judgement that could not be reached says why instead of
  sounding certain.
- **`agentaudit candidates <round>`** writes `candidates.jsonl` against a frozen schema
  (`candidates/v1`). This is the interface another tool consumes, and it is the first release
  where that interface exists at all. One position is one line: three rules on the same `eval`
  collapse into one candidate, because they are one place to look at. No verdict may appear in
  it. A candidate says where to look; what was concluded lives in a separate file.
- **`agentaudit investigate <round>`** collects the source around each candidate offline: the
  callers, the arguments bound to each parameter, the conditions guarding the call. It is
  bounded on purpose (files, bytes, depth, seconds), and it writes a new round rather than
  mutating the old one.
- **`agentaudit import-sarif <file>`** brings another analyzer's results in as candidates,
  keeping its rule id, so a CodeQL-only, Semgrep-only or commercial-backend result can be
  triaged and adjudicated by the same pipeline.
- **A second language.** `--codeql-language javascript` builds a JS database and runs a
  window-level query. It stops at contract candidates, on purpose: window-level results have
  no call chain and no argument source, and passing them to triage would mean judging half a
  record.
- **Rounds are resumable.** Findings are written incrementally, so a long run that is
  interrupted keeps what it had instead of losing the whole round.
- **`agentaudit doctor`** says what this machine can and cannot do: Python, dependencies,
  CodeQL, the LLM key and its budget, where output lands, and what each missing piece would
  unlock. Two of those fail quietly -- without CodeQL a scan degrades to the offline path,
  without a key triage does not run -- so both used to look like "it worked, and found less".
- **Screening takes a profile.** `agentaudit targets screen --profile your.yml` replaces the
  built-in thresholds with yours: what form of project you want, what you intend to do with
  it, which languages you can read, how stale and how popular it may be. Without a profile
  every user batches to the same list, which is the one thing a screening tool should not do.
  Unknown keys are an error rather than a shrug, because a config key that is silently
  ignored makes the tool look like it answered.
- **The report says what it dropped, and why.** `agentaudit targets report --excluded` adds a
  table of the projects the filters rejected with the reason for each. Most of those reasons
  are about the profile rather than the project, so seeing them is how you learn to write a
  better one.
- **A scan ends by saying what to do next**, and says plainly that a candidate is a place
  worth looking at rather than a finding. Listing four output paths answered "where did it go",
  which is not the question a first-time reader has.

### Changed

- **Every command answers `--help` as itself.** The usage line used to open with the file
  behind the command (`usage: scan.py`, `export_candidates.py`): forwarding through `runpy`
  points `sys.argv[0]` back at the script, and argparse takes its default program name from
  there. Each command now states its own name, and a test walks all of them, because one
  forgotten `prog=` is enough to bring the old line back.
- **`agentaudit candidates out/round-x` works as written.** It required `--round`, so the
  command in this README exited 2 before it looked at the directory. The round is a positional
  argument now, as it is for `explain`, `report`, `index` and `sarif`; `--round` still works.
- **`explain` opens with one candidate instead of all thirteen**, then says how to reach the
  next one, how to print every one, and that a candidate is a place to look rather than a
  finding. A misspelled path now says the directory does not exist instead of "no candidates
  found", which sent the reader looking at the scanner.
- **Five `candidates` options had no explanation at all**, `--out` among them, and `--out` is
  required.
- **`selftest --help` asks instead of running.** That suite is a top-level script, so the flag
  reached nothing and the whole run started; `doctor --help` printed the report for the same
  reason. Both answer the question now.
- **Everything that reaches a terminal is English now.** 163 console lines, argument help, and
  17 raised messages across 24 files. `agentaudit selftest` was half English and half Chinese
  on alternating lines, and `agentaudit targets --help` was Chinese while every other page was
  not. A test runs six commands and reads their output, because a rule about directories
  cannot see a Chinese line printed from `core/`. The count above was low: two error messages
  in `tools/export_candidates.py` were still Chinese, found by typing the documented command
  and reading what came back.
- **The queries write CSV, not SARIF.** The message field carries JSON, and SARIF escapes it a
  second time, so parsing it back was lossy. One CSV row can hold several argument positions.
- **`app/` and `tests/` are English, and now a test says so.** That layer is what a stranger
  opens first; `core/` and `tools/` keep their Chinese notes, because they record what was
  tried and why. The README says this out loud rather than leaving a reader to discover it.
- **The internal-vocabulary guard lost three words.** "Criterion", "scope of a measurement"
  and "red line" are ordinary Chinese technical words; banning them forced awkward prose and
  protected nobody, because the sentence around them is Chinese either way.

### Fixed

- **CodeQL was looked for one directory above the checkout.** That was right in the directory
  this code was extracted from and wrong everywhere else: `scripts/setup.sh` installs into the
  repository, the frontend searched the parent, missed it, and fell back to the offline path.
  A user who had just installed CodeQL got a quieter scan and no message. It now looks inside
  the checkout, and `doctor` prints the path so the two can be compared.
- **One CSV cell over 128 KiB aborted the whole run.** CodeQL writes an entire call chain into
  a single message cell, and Python's `csv` module refuses a field past 131072 characters.
  The failure surfaced as `_csv.Error`, which reads like a finished scan with less to report.
  The ceiling is raised when the module is imported. The SARIF path never had this problem,
  because long text sits in JSON there, so only the CSV path could hit it.
- **The same CSV parsed into different paths on Windows and on Linux.**
  `os.path.isabs("/web/server.py")` is true on Linux and false on Windows, and CodeQL emits
  that shape on both platforms. On Windows the source prefix stayed in the key, so argument
  source evidence was collected and then matched against nothing. A path is absolute here if
  it starts with `/` or with a drive letter.
- **Both CSV parsers are now pure functions with tests.** `parse_argsrc_rows` and
  `parse_result_rows` take rows instead of a file, so the shapes CodeQL actually emits - two
  arguments in one cell, CRLF, quoted commas, a 200k-character field - are checked without a
  CodeQL install. The CSV path had no tests at all before, which is where the two bugs above
  lived.
- **`tools/llm_client.py` no longer falls back to a path on the author's machine.** On any
  other machine that path does not exist, and a missing key surfaced later as "no response"
  rather than "no key".
- **Three switches that the code read were missing from `CONFIGURING.md`**, and `.github`
  placeholders that survived the last release are gone, with a test for each class of mistake.

### Known gaps

- **The query rewrite has been compared on one target, and no further.** Same source tree
  (TaskWeaver `33ccc5e`), same CodeQL 2.27.1, old CSV path against new: the new one returned
  106 of the old 106 sink positions plus 24, all of them inside vendored third-party code
  under `_targets_pylibs/`. A strict superset on positions; extra rows per position, because
  one location can carry several call chains. That is one target, one commit, one CodeQL
  version, so it settles "nothing was dropped here", not "nothing is ever dropped".
- **Nothing on the CodeQL path runs in CI.** The comparison above needs a database and a real
  source tree; the machines that run the tests have neither. The offline path is covered.
- `sink.arg_index` is still `-1` on the AST frontend: that frontend cannot tell which argument
  is the dangerous one.
- `needs_human` remains the most common verdict, and the reason is almost always the same: the
  argument's origin is not inside the code that was handed over. That is a tracing limit, not
  a triage limit.

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
