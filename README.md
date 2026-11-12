# agentaudit

**English** | [中文](README.zh-CN.md)

[![CI](https://github.com/phoen1x-git/agentaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/phoen1x-git/agentaudit/actions/workflows/ci.yml)

A code audit tool for AI agent projects. It reads LLM / Agent code, finds dangerous call sites,
and then works out whether each one's argument can actually be controlled from outside.
When it cannot tell, it writes "unknown" rather than giving a guess.

Its output is a list of **candidates**, not a list of confirmed vulnerabilities.
Every one of them still needs a person to look at it.

| | |
|---|---|
| Try it | `agentaudit scan --demo`, with no CodeQL, no API key and nothing to download |
| What it misses | [LIMITATIONS.md](LIMITATIONS.md), which lists everything it cannot find |

![Running `agentaudit scan --demo`, then `agentaudit explain` on the third candidate](assets/demo.gif)

---

## The problem it solves

Agent projects are full of dangerous calls: `eval`, `subprocess`, `open`, `requests` and so on.
Most of them are necessary. To run a command you have to call `subprocess`. So classic taint
analysis flags all of them, and what comes back is a long list of "there is a dangerous call
here", which is not much use.

```python
# Candidate. Dangerous call? yes. Is it a vulnerability? probably not.
handler = eval(spec_name)          # spec_name comes from a built-in table in this file
```

The real question is not whether a dangerous call exists. It is these three:

| # | Question | Answered by |
|---|---|---|
| ① | Is there a dangerous call? | static analysis |
| ② | Is its argument **externally controlled**? | this project |
| ③ | Does that argument **survive to the sink**? | this project |

`agentaudit` does the second and the third. It turns both into checks that run. And when it
cannot tell, it outputs `needs_human`, meaning a person has to decide. That is a real result,
not a failure.

---

## Install

Requires Python 3.10 or newer. The [CodeQL CLI](https://github.com/github/codeql-cli-binaries)
is optional, and it is a few hundred MB. Without it the scanner runs in the offline mode, which
finds less but needs nothing beyond PyYAML.

```bash
git clone https://github.com/phoen1x-git/agentaudit.git && cd agentaudit
./scripts/setup.sh                 # the dependency + the CodeQL CLI, or:
pip install -e .                   # the dependency only; gives you the `agentaudit` command
```

`setup.sh` needs a bash shell. On macOS, Linux and Git Bash on Windows it runs as-is. In
PowerShell or cmd, use `pip install -e .` and skip CodeQL, or download the CLI yourself and
point `AF_CODEQL` at it.

Either install lets you run the scripts directly (`python app/scan.py ...`). The editable
install also gives you a single command:

```bash
agentaudit scan --demo
agentaudit explain out/round-demo --index 3
agentaudit serve out/round-demo
agentaudit --help
```

Output goes to `./out` under the current directory, or to `$AGENTAUDIT_HOME` if you set it.
Nothing is written into the installation.

### Smoke test

```bash
agentaudit selftest                # or: python tools/run_selftests.py
agentaudit scan --demo             # the bundled sample project; 13 candidates without CodeQL
```

Both run in seconds and need nothing else installed. If these two pass, the install works.
With CodeQL installed the same demo finds more than 13, because a full scan follows values
across functions and the offline mode cannot.

### Docker

If you would rather not install CodeQL, the image has it built in:

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # bundled sample
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

The build picks the CodeQL binary for the architecture it is building for, so x64 and arm64
both work, Apple Silicon included.

The image entry point is `agentaudit scan`, so the arguments are the same ones you would type
locally. Other subcommands need their own entry point:

```bash
docker run --rm --entrypoint agentaudit agentaudit log
docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
```

The image runs the CodeQL CLI once during the build, so if the layout is wrong the build fails
instead of producing an image whose scanner cannot run. CI builds it and runs a smoke test on
every push.

---

## Quick start

Before the first scan, `agentaudit doctor` prints what this machine can and cannot do, and
what each missing piece would unlock. It takes a second and it answers the question the
first scan otherwise raises: "it found thirteen things, is that everything?" Without CodeQL
it is not: a scan falls back to the AST checks, which cannot follow a value across functions.

One command scans something, with no target list and no database to build by hand:

```bash
agentaudit scan --demo                  # the bundled sample project
agentaudit scan --path ./myproject      # a project already on disk
agentaudit scan --repo owner/name       # fetch a public GitHub repo and scan it
```

`--repo` clones the repository and needs `git` on your PATH; if there is no `git` it falls back
to a tarball download. It works without a token on public repositories, but unauthenticated
GitHub requests are rate-limited, so for a larger batch use the token route described under
[Scanning a batch](#scanning-a-batch).

To scan many repositories instead of one, there is a different route: find and screen
candidates, fetch sources and build databases, then scan the batch.

### Or use the menu

A bare `agentaudit` opens this in your terminal:

```
  1  Scan a target
  2  Open a previous round
  3  Run the rule self-tests
  4  Validate the rule configuration
  5  Scan statistics (local, statistics only)
  6  List the commands
  0  Quit
```

It prints the command line that each choice runs, so the menu teaches you the flags rather
than hiding them. And where there is no terminal, in a pipe or in CI for example, it refuses to
start rather than blocking on input.

---

## Reading the results

Every scan writes a round to `out/round-<tag>/`:

| File | What it is |
|---|---|
| `findings.tsv` | the candidate table, one row per candidate, and the main artefact |
| `report_draft.md` | the write-up, one section per candidate |
| `index.html` | sortable / searchable table of every candidate |
| `agentaudit.sarif` | the candidates as SARIF 2.1.0, for a code-scanning UI or an editor |
| `results.csv` | the CodeQL frontend's own raw output (full mode only) |
| `meta.json` | which mode ran, which rule switches were on, how long it took |

Every one of those rows is a candidate. Nothing in this pipeline executes the code it looks
at; it only reads it. So none of it is confirmed.

`findings.tsv` is the raw table. These three commands are how you read it.

### Why was this one reported?

```bash
agentaudit explain out/round-x --index 3
```

Without `--index` or `--fp` it opens the first candidate only and tells you how many are left;
`--all` prints every one. It prints the source around the flagged line, the call chain that
reaches it, the guards on that path, and where the dangerous argument comes from. If the scan
could not determine that, it says so. Run this before believing or dismissing a candidate.

### Watch the whole round in a browser

```bash
agentaudit serve out/round-x
```

Binds to `127.0.0.1`, serves exactly that one directory, and refuses directory listings and path
traversal.

### The report

`report_draft.md` is generated for you, and its header states plainly that the verdicts inside
are AI-assisted and were not verified by execution. [`examples/`](examples/) has a complete
synthetic sample, and its rows cover the four outcomes the scanner distinguishes: `vuln`,
`not_vuln` (not externally controllable), `not_vuln` (blocked by a validator) and `needs_human`
(origin undeterminable). The last one is the important one. A scanner that only ever answers yes
or no is pretending to be more certain than it is.

### In an editor or a code-scanning UI

Every run writes `agentaudit.sarif`. It uses relative paths only, with no absolute path and no
`originalUriBaseIds`, so a copy taken off your machine does not reveal your directory layout.
Every result is `level: warning` and the triage verdict travels in `properties`, because SARIF
levels are read by tools that never see the caveats. Rows already triaged `not_vuln` are left
out; add `--all` to `agentaudit sarif` to include them.

---

## Commands

One command, several subcommands:

| Command | What it does |
|---|---|
| `agentaudit doctor` | say what this machine can and cannot do: dependency, CodeQL, key, where output lands |
| `agentaudit interactive` | a menu, for when you don't want to remember flags (a bare `agentaudit` opens it too) |
| `agentaudit scan` | scan a target: `--demo`, `--path DIR`, `--repo OWNER/NAME` |
| `agentaudit explain <round>` | show why a candidate was reported |
| `agentaudit investigate <round>` | collect the source around each candidate, offline, into a new round |
| `agentaudit import-sarif <file>` | bring another analyzer's results in as candidates |
| `agentaudit serve <round>` | read a round in a browser (localhost only) |
| `agentaudit report <round>` | render the report draft |
| `agentaudit index <round>` | render the HTML index |
| `agentaudit sarif <round>` | export the round as SARIF 2.1.0 |
| `agentaudit candidates <round>` | write the contract file another tool can read (`candidates.jsonl`, see below) |
| `agentaudit round --tag NAME` | run one round over a target table |
| `agentaudit all --tag NAME` | prepare → scan → report, resumable |
| `agentaudit selftest` | run the rule self-tests |
| `agentaudit validate` | check `core/config/*.yml` |
| `agentaudit log` | show or export the local scan statistics |
| `agentaudit targets` | find and screen GitHub targets for a batch. `screen --profile FILE` takes your own criteria instead of the defaults |

Two of those exist for the cases where one scan is not the whole answer.
`agentaudit investigate out/round-x` reads the source around each candidate offline and writes
a new round holding what it found: the callers, the arguments bound to each parameter, and the
conditions around the call, bounded by files, bytes, depth and seconds. It answers "what else
is around this line" without spending a credit. `agentaudit import-sarif other.sarif --src
./myproject` turns another analyzer's results into candidates and sends them down the same
pipeline, so a Semgrep or commercial-backend result can be judged by the same rules instead of
sitting in a second tool.

### The candidates file (`candidates.jsonl`)

`agentaudit candidates out/round-x --repo owner/name --src-root ./myproject --out c.jsonl`
projects a round into `candidates.jsonl`: one line per position, a stable id computed from the
repo, file, line and sink name, and nothing else. Deliberately nothing else: no verdict, no
confidence, no "probably". A candidate is a place that deserves a look; the conclusion lives in
a separate file, and mixing the two is what makes such a file unusable by anything but its
author. The source root is what lets it read each sink line, hash the file and decide the entry
kind; without it the file would have to claim a shape it cannot see.

The schema is frozen in `schemas/candidates.v1.json` and validated by
`tools/check_contract_file.py`. The id does not depend on the rule that found it or on what
anyone concluded, so rewriting a query does not break the trail back to earlier rounds.

---

## How it behaves

Worth reading before you trust any number it gives you.

### Two modes

| Mode | Needs | Finds |
|---|---|---|
| **full** | the CodeQL CLI | the CodeQL queries *and* the AST checks; writes the raw SARIF |
| **offline** | nothing at all | the AST checks only |

If the CodeQL CLI is missing the run says so and uses the offline mode. The mode used is
recorded in `meta.json` and printed at the top of the report, because the two do not find the
same things. `--no-codeql` forces the offline mode.

### LLM triage is off by default

It spends API credits, so it only runs when you ask:

```bash
agentaudit scan --path ./myproject --llm
```

The run prints the candidate count and the hard cap (`AF_LLM_MAX_CNY`, default 30 CNY) before it
starts, and reports what it actually spent afterwards. Without `--llm` you get the candidate
list with no verdicts, and the report says so rather than implying anything was judged.

A `vuln` verdict whose argument source is unknown is downgraded to `needs_human`. Those are the
unstable ones: run the same candidate repeatedly and they flip noticeably more often than the
rest. The original verdict stays in `ai_reason` and in `verdicts.json`, so nothing is lost;
`--no-unknown-downgrade` turns the behaviour off, and the round records whether it was on.

Every verdict also carries the evidence it was given: the source lines it quoted, a hash of
the input, and `blocking_gaps`, which names the evidence that was missing. A judgement that
could not be reached says which gap stopped it instead of sounding certain.

### Using it as a gate

```bash
agentaudit scan --path ./myproject --llm --fail-on vuln # exit 1 only on a `vuln` verdict
agentaudit scan --path ./myproject --diff origin/main   # only files changed since a ref
```

`--fail-on any` exists, but it is rarely the gate you want: it exits 1 as soon as *any*
candidate is reported, and a candidate is a place worth looking at, not a confirmed
vulnerability, so most projects report some. Use `--llm --fail-on vuln` to fail only when
something was actually judged a vulnerability.

`--diff` needs the source tree to be a git checkout, and is meant for "did this pull request
introduce anything", not for a full audit.

### Skipping parts of a tree

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

Patterns are globs relative to the source root, and they are recorded in the round so that two
rounds stay comparable. What you exclude is what you did not scan, so "no candidates in
vendor/" means nothing if `vendor/` was skipped.

### Every option of `scan`

| Option | What it does |
|---|---|
| `--demo` | scan the bundled sample project |
| `--path DIR` | scan a directory on disk |
| `--repo OWNER/NAME` | fetch a GitHub repo and scan it |
| `--project NAME` | name used in reports (default: derived from the path) |
| `--tag NAME` | round directory name (default: derived) |
| `--out DIR` | where to write the round (default: `./out`) |
| `--llm` | triage with an LLM; it spends credits, so it is off by default |
| `--no-unknown-downgrade` | keep a `vuln` verdict even when the argument source is unknown |
| `--no-codeql` | force the offline mode |
| `--codeql-language python\|javascript` | database language (default `python`). Anything but python stops at contract candidates, `trace_level: window` |
| `--lang en\|zh` | report language (default `en`) |
| `--diff [REF]` | only report files changed since `REF` |
| `--fail-on none\|any\|vuln` | exit non-zero, as a build gate |
| `--ignore GLOB` | skip paths matching this glob (repeatable) |
| `--serve` | serve the round on localhost when the scan finishes |
| `--no-sarif` | do not write `agentaudit.sarif` |
| `--no-log` | do not append to the local scan log |

---

## What it checks

The dangerous-call list lives in `core/config/sinks.yml`, a single YAML file holding
52 dangerous-call rules rather than hard-coded logic. `core/gen_ql.py` reads it and generates
the CodeQL queries, so adding your own dangerous function is a config change, not a code
change.

| Group | Examples | Default |
|---|---|---|
| Baseline | `subprocess.run` / `Popen`, `os.system`, `requests.get/post/request`, `eval`, `exec`, `jinja2.from_string`, `*.execute(...)` | **on** |
| Database clients | `.query(...)` on receivers whose name ends in `conn` | **on** |
| File I/O (`AF_SINKS_FS`) | `os.remove/unlink/rename/mkdir/chmod/...`, `shutil.move/rmtree/...` | off |
| Path construction (`AF_SINKS_PATH`) | `os.path.join`, `os.path.abspath` | off |
| HTTP clients (`AF_SINKS_HTTP`) | `httpx.get/post/...`, `httpx.Request`, `httpx.Client` | off |
| Dynamic dispatch (`AF_SINKS_DYNIMP`) | `importlib.import_module`, `__import__`, `import_module` | off |

The groups that are off are off because they are noisy. Turning one on trades precision for
candidate volume. The switch values are recorded in each round's `meta.json`.

Beyond these calls, the kernel checks three more things: whether the endpoints in one file agree
about authentication, whether one function contains both the safe and the unsafe way of doing
the same job, and whether a dangerous point can be reached from an entry point at all.
(Code calls a dangerous point a `sink`, which is where switch names like `AF_SINKS_FS` come
from.)

Adding your own dangerous function is a few lines of YAML. [CONFIGURING.md](CONFIGURING.md) has
the field reference, and `agentaudit validate` checks your edit.

---

## What it does not find

These are deliberate trade-offs, not bugs. The long version is in
[LIMITATIONS.md](LIMITATIONS.md): what the analysis cannot see at all, and which of its silences
are meaningful.

- **Full analysis is Python only.** The static frontend is bound to CodeQL's Python pack. A
  `--codeql-language javascript` pass exists but stops at window-level candidates: it does not
  run the call-chain or argument-source analysis, so it produces no triage.
- **The triage layer is noisy.** Re-run a candidate and a noticeable share of the verdicts
  change. Suspiciously stable results are usually a caching artefact, so change `--tag` when
  re-judging.
- **`arg_source=unknown` is not trustworthy.** That verdict means the model itself does not know
  where the argument comes from; those rows are downgraded by default.
- **"No caller found" is not "unreachable."** Only name-based matching is done, so cross-file
  and dynamic dispatch are missed.
- **Framework mediation.** When the implementation lives in `site-packages` rather than in the
  scanned tree, static analysis stops at the import.
- **The offline mode finds less.** No inter-procedural reachability, no framework modelling.
- **Regenerating the CodeQL queries needs the AgentFuzz reference pack.** Only for regeneration;
  the committed `core/ql/*.ql` work without it (`AF_PAPER_QL` to point at it).
- **Every finding needs human confirmation.** The tool produces candidates, not conclusions.

---

## Configuration

Secrets are always read from files or environment variables, never committed.

| Env var | Purpose | Default |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | path to the LLM API key file | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | path to a GitHub token file (raises API limits) | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **hard per-run spend cap**; the run stops and reports when reached | `30` |
| `AF_JUDGE_MT` | max output tokens for the triage layer | `8000` |
| `AF_CODEQL` | path to the CodeQL CLI | `./_tools/codeql/codeql[.exe]` |
| `AF_PAPER_QL` | path to the AgentFuzz reference QL pack | `./agentfuzz-official/ql` |
| `AF_SRC_DIR` / `AF_DB_DIR` | where fetched sources / databases live | `./_targets/src`, `./_targets/db` |
| `AF_TARGET_MAP` | JSON map `{"short-name": "source root"}` | read from `core/config/targets*.yml` |
| `AF_SINKS_FS` / `_PATH` / `_HTTP` / `_DYNIMP` | enable extra sink groups | off |
| `AF_SINKS_EXTRA` | include the `source: extra` entries at all | `1` |
| `AF_PATH_FILTER` | path filter mode (`rel` = project-relative) | `rel` |
| `AF_SOURCES_FILE` | an **additional** untrusted-source list, added on top of the default | `core/config/sources.yml` |
| `AF_NO_DATAFLOW` | disable inter-procedural argument-source analysis | `0` |
| `AGENTAUDIT_HOME` | where output (`out/`, `data/`) goes | the current directory |
| `AGENTAUDIT_NO_LOG` | set to `1` to stop recording scan statistics | unset |
| `AGENTAUDIT_ASCII` | set to `1` to draw the banner with ASCII only | auto-detected |

The complete list, including the triage-layer patches and the switches for A/B runs, is in
[CONFIGURING.md](CONFIGURING.md). A test fails if one is added without being documented.

---

## How it works

This section is for two kinds of reader: someone reading the code, and someone scanning a
batch rather than a single repository.

One target goes through four stages, and `agentaudit scan` drives all of them:

| Stage | Where | What it does |
|---|---|---|
| Static frontend | `core/static_frontend.py` | build a CodeQL database, run the queries in `core/ql/`, parse the SARIF |
| Strong/weak duality | `core/duality.py` | one function doing the same job safely on one line and unsafely on another |
| Triage | `core/llm_judge.py` | the five axes: `verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| Report material | `app/make_report.py`, `app/make_index.py`, `tools/to_sarif.py` | the draft, the sortable table, the SARIF |

Two more run across all of those: `core/consistency.py` decides what the evidence does not
support and refuses to report it, and `core/cfg.py` owns the rule configuration.
`core/gate.py` (is this target worth scanning at all) and `core/upstream.py` (has this already
been reported upstream) are used by the batch path only.

<a id="scanning-a-batch"></a>

### Scanning a batch

A batch has two slow stages, and both can be restarted. You can stop and re-run either of
them, and finished work is skipped.

Two files are yours, not shipped: the target table lists the repositories you scan, and
`known_targets.yml` lists the ones you have already looked at, which is what makes "not yet
examined" mean something. Copy the examples and fill them in:

```bash
cp core/config/targets.example.yml       core/config/targets.yml
cp core/config/known_targets.example.yml core/config/known_targets.yml
```

```bash
# 1) build a candidate list (needs a GitHub token, and a few minutes)
agentaudit targets fetch        # -> data/target_pool/pool.json
agentaudit targets screen       # -> data/target_pool/screened.json

# 2) pick the ones you want into a batch file, then fetch sources and build databases
python app/prepare_targets.py data/target_pool/batch1.json

# 3) scan and write the reports
agentaudit round    --tag my-round --targets-file core/config/targets.yml
agentaudit report   out/round-my-round
agentaudit index    out/round-my-round
```

`agentaudit all --tag my-round --batch data/target_pool/batch1.json --targets-file
core/config/targets.yml` chains those steps, skipping whatever is already done.

`agentaudit targets report --excluded` prints the projects the filters rejected and the reason
for each. Most of those reasons describe the profile rather than the project, which is what
makes them worth reading: they are how you learn to write a better one.

> **Mind the cost.** The triage stage spends LLM credits. Scripts print an estimated cost up
> front, and `AF_LLM_MAX_CNY` hard-stops a run when the cap is reached.

---

## Reviewing the verdicts by hand

The triage verdict is the one part of this tool that cannot be checked by reading the code.
Whether it is right is an empirical question, and the way to answer it is to hand two people
the same evidence with the model's opinion stripped out, then compare what they concluded.

The shape of this flow exists to remove one bias. Show a reviewer the model's verdict next to
the evidence and you measure agreement with the model rather than agreement with the evidence,
and the number improves the more confident the model is. So the verdict is stripped before the
reviewer sees anything, and the two are only brought back together at the end, in separate
files.

```bash
# 1) a round with backend evidence -> one record per case, with no verdict in it
python tools/build_external_review_records.py out/round-imported --out review/records

# 2) mask the model's opinions and the project labels; write the offline review form
python tools/build_review_pack.py review/records \
    --out review/packet --mapping-out private/mapping.json

# 3) the reviewer opens review/packet/review.html, fills the template, and it is checked
python tools/validate_review_pack.py --packet review/packet/packet.json \
    --submission review/submission.json --out review/validated.json

# 4) join it back to the private identities, and see whether the two reviewers agreed
python tools/merge_review_submission.py --packet review/packet/packet.json \
    --mapping private/mapping.json --validated review/validated.json --out review/merged.json
```

The mapping file is the only thing that names a case, and step 2 refuses to write it inside
the packet directory. What a reviewer sees is a set of evidence ids, the source lines under
each one, and the questions the scanner could not answer. `review.html` is a single file that
makes no network request, so it opens on a machine with no route out.

Two things this does not do, and both tools say so when they print. Validation checks the
form and the citations, not the conclusion: a confident wrong review validates exactly as well
as a correct one, and the file records what two people concluded rather than how often anyone
was right. And masking removes the model's opinion and the project labels, not the identities
inside the source text, so a reviewer who knows the codebase can still recognise it.

The judgement layer has two cheaper checks, and neither needs an API key.
`tools/eval_triage.py` replays a fixed set of recorded model responses through the current
policy and reports how many of them land on the outcome the case declares, exiting non-zero
when one does not. The case set records what the policy is supposed to do, not what it does
today, which is why this runs by hand rather than as a gate.
`tools/eval_investigation.py` runs each case under three retrieval strategies (no investigator,
broad, focused), counts how much of the expected source each one reached, and exits non-zero
when the focused pass finds less than the broad one. It makes no model call unless `--llm` is
given, and that switch carries its own call and spend caps.

---

## Repository layout

```
core/            the kernel (static frontend, triage, reachability, taint tracing, CodeQL queries)
core/config/     the rules: sinks.yml, sources.yml, filters.yml  -- see CONFIGURING.md
tools/           reusable tooling (target selection, fetching, individual checks, self-tests)
app/             entry points (scan.py, run_all.py, explain.py, serve.py, cli.py)
demo/            a deliberately vulnerable sample project, for `--demo`
examples/        synthetic sample output
tests/           the test suite CI runs
scripts/         setup.sh
```

`app/` and `tests/` are written in English, because that is the layer someone opens first.
`core/` and `tools/` carry Chinese comments: they record what was tried and why, which was
written in the author's own language as it happened. The documentation is bilingual.

---

## Documentation

| | |
|---|---|
| [CONFIGURING.md](CONFIGURING.md) | the rule fields, and how to add your own dangerous function |
| [LIMITATIONS.md](LIMITATIONS.md) | what the tool does not find |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to run and extend the tests |
| [CHANGELOG.md](CHANGELOG.md) | what changed |

---

## Help me improve this

If you are willing to send me your scan statistics, I would be genuinely grateful. They cost
you nothing, and they contain no code. They are also the one thing I cannot produce on my own:
how this scanner behaves on code I have never seen. A check that fires on your code and never on
mine is the most useful thing you can send me.

Every scan appends one line to `./data/scan_log.jsonl`, locally:

| Recorded | Never recorded |
|---|---|
| how many files, how many candidates | source code, or any fragment of it |
| the split across checks and across verdicts | file paths or file names |
| elapsed time, tool version, hashes of the rule config | the project name, or anything identifying it |
| your Python minor version, and OS family | anything about you |

```bash
agentaudit log                    # summarise what you have scanned
agentaudit log --export           # a small aggregate, written to scan_stats.json
agentaudit log --clear            # delete it
```

**Nothing is ever uploaded.** There is no network code in any of this, so the only way any of
it leaves your machine is if you carry it out yourself. `--export` re-checks the aggregate
against the table above and refuses to write anything that fails, so read it before you decide.

If you are happy with it, open an
[issue](https://github.com/phoen1x-git/agentaudit/issues) and paste it in. If you would rather
not, that is a perfectly good answer too. The log is yours, and
`--no-log` (or `AGENTAUDIT_NO_LOG=1`) turns the whole thing off.

---

## Author's note

I wrote this while working on AI agent security. What kept stopping me was not finding a
dangerous call; it was deciding what to do with one. Run the same candidate past a model twice
and you do not always get the same answer. A tool that hides that is worse than one that misses
things, because you cannot tell which of its outputs to trust.

So the rule I built it around is narrow: nothing here is allowed to sound more certain than it
is. `needs_human` is a real verdict. Evidence that could not be determined is printed as "not
determined" instead of guessed. Every report says it was not verified by execution.
[`LIMITATIONS.md`](LIMITATIONS.md) is kept current on purpose, because a tool that only lists
its strengths is not telling you anything.

If you run it and it is wrong, in either direction, that is the most useful thing you can send
me. Thank you for reading this far.

---

## Acknowledgements

The CodeQL frontend and the baseline sink list are derived from **AgentFuzz**:

> Fengyu Liu, Yuan Zhang, Jiaqi Luo, Jiarun Dai, Tian Chen, Letian Yuan, Zhengmin Yu,
> Youkun Shi, Ke Li, Chengyuan Zhou, Hao Chen, Min Yang.
> *Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in
> LLM-based Agents.* 34th USENIX Security Symposium (USENIX Security '25), 2025, pp. 3767–3786.

`core/gen_ql.py` regenerates the queries from that reference pack, which is why `AF_PAPER_QL`
points at it. Everything under `source: extra` in `core/config/sinks.yml`, the reachability
check, the parameter-taint check and the triage layer are additions on top of the baseline.

---

## License

MIT. See [LICENSE](LICENSE).

> Please use it only against targets **you are authorised to test**.
