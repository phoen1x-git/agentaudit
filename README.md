# agentaudit

**English** | [中文](README.zh-CN.md)

<!-- CI badge. Uncomment these two lines once the repo has a URL, replacing OWNER/REPO in both
     places; it goes green after the first workflow run. Left commented out on purpose: a badge
     pointing at a repository that does not exist yet renders as a broken image.

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
-->

**Code audit for AI agents.** A static-analysis + LLM-triage scanner that finds dangerous call
sites in LLM / Agent code — and says *"I don't know"* when it doesn't know.

The output is a list of **candidates** to review, not a list of confirmed vulnerabilities.

| | |
|---|---|
| Try it | `agentaudit scan --demo` — no CodeQL, no API key, no downloads |
| What it misses | [LIMITATIONS.md](LIMITATIONS.md) — worth reading before you trust anything below |

---

## The problem it solves

Dangerous calls (`eval`, `subprocess`, `open`, `requests`, …) are everywhere in agent code, and
classic taint analysis flags all of them. Ask a different question and the picture changes
completely:

```python
# Candidate. Dangerous call? yes. Is it a vulnerability? probably not.
handler = eval(spec_name)          # spec_name comes from a built-in table in this file
```

Three questions decide whether a flagged call site is real, and taint analysis only answers the
first:

| # | Question | Answered by |
|---|---|---|
| ① | Is there a dangerous call? | static analysis |
| ② | Is its argument **externally controlled**? | this project |
| ③ | Does that argument **survive to the sink**? | this project |

`agentaudit` turns ② and ③ into runnable checks and treats *"the triage layer can't tell"* as a
reportable outcome (`needs_human`) rather than something to hide behind a confident-looking
guess.

---

## Install

Requires **Python 3.10+**. The [CodeQL CLI](https://github.com/github/codeql-cli-binaries) (a few
hundred MB) is optional — without it the scanner runs in the offline mode, which finds fewer
things but needs nothing.

```bash
git clone <this repo> && cd agentaudit
./scripts/setup.sh                 # the dependency + the CodeQL CLI, or:
pip install -e .                   # the dependency only; gives you the `agentaudit` command
```

Either way the scripts run directly (`python app/scan.py ...`). The editable install also gives
you one command:

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
agentaudit scan --demo             # 13 candidates from the bundled sample project
```

Both run in seconds and need nothing else installed. If these pass, the setup is sane.

### Docker

Prefer not to install CodeQL at all? The image has it baked in:

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # bundled sample
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

The image entry point is `agentaudit scan`, so the arguments are the same ones you would type
locally. Other subcommands need their own entry point:

```bash
docker run --rm --entrypoint agentaudit agentaudit log
docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
```

The `Dockerfile` was written on a machine without Docker, so the first build is the test. It is
built to fail loudly rather than quietly — the CodeQL CLI is executed *during* the build, so a
wrong release layout stops the build instead of producing an image whose scanner cannot run.
CI builds and smoke-tests the image on every push.

### All the commands

| Command | What it does |
|---|---|
| `agentaudit interactive` | a menu, for when you don't want to remember flags (a bare `agentaudit` opens it too) |
| `agentaudit scan` | scan a target — `--demo`, `--path DIR`, `--repo OWNER/NAME` |
| `agentaudit explain <round>` | show why a candidate was reported |
| `agentaudit serve <round>` | read a round in a browser (localhost only) |
| `agentaudit report <round>` | render the report draft |
| `agentaudit index <round>` | render the HTML index |
| `agentaudit sarif <round>` | export the round as SARIF 2.1.0 |
| `agentaudit round --tag NAME` | run one round over a target table |
| `agentaudit all --tag NAME` | prepare → scan → report, resumable |
| `agentaudit selftest` | run the rule self-tests |
| `agentaudit validate` | check `core/config/*.yml` |
| `agentaudit log` | show or export the local scan statistics |
| `agentaudit targets` | find and screen GitHub targets, for a batch rather than one repo |

---

## Quick start

Scan something with one command — no target list, no database to build by hand:

```bash
agentaudit scan --demo                  # the bundled sample project
agentaudit scan --path ./myproject      # a project already on disk
agentaudit scan --repo owner/name       # fetch a GitHub repo and scan it
```

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

It echoes the command line it runs, so the menu teaches you the flags instead of hiding them,
and it refuses to start when there is no terminal (a pipe, or CI) rather than blocking on input.

### What lands in `out/round-<tag>/`

| File | What it is |
|---|---|
| `findings.tsv` | the candidate table, one row per candidate — the primary artefact |
| `report_draft.md` | the write-up, one section per candidate |
| `index.html` | sortable / searchable table of every candidate |
| `agentaudit.sarif` | the candidates as SARIF 2.1.0, for a code-scanning UI or an editor |
| `results.sarif` | the CodeQL frontend's own raw output (full mode only) |
| `meta.json` | which mode ran, which rule switches were on, how long it took |

Every one of those rows is a **candidate**. Nothing in this pipeline executes your code, so
nothing here is confirmed.

---

## Reading the results

`findings.tsv` is the raw table. These three make it usable.

### Why was this one reported?

```bash
agentaudit explain out/round-x --index 3
```

Prints the source around the flagged line, the call chain that reaches it, the guards on that
path, and where the dangerous argument comes from — or states that the scan could not determine
it. **This is the command to run before believing or dismissing a candidate.**

### Watch the whole round in a browser

```bash
agentaudit serve out/round-x
```

Binds to `127.0.0.1`, serves exactly that one directory, and refuses directory listings and path
traversal.

### The report

`report_draft.md` is generated for you, and its header states plainly that the verdicts inside
are AI-assisted and were **not verified by execution**. [`examples/`](examples/) has a complete
synthetic sample — the rows there cover the four outcomes the scanner distinguishes: `vuln`,
`not_vuln` (not externally controllable), `not_vuln` (blocked by a validator) and
**`needs_human`** (origin undeterminable). That last one is the point: a scanner that only ever
outputs `vuln` / `not_vuln` is lying about its own certainty.

### In an editor or a code-scanning UI

Every run writes `agentaudit.sarif`. It uses **relative paths only** — no absolute path, no
`originalUriBaseIds` — so a file taken off your machine does not carry your filesystem layout.
Every result is `level: warning` and the triage verdict travels in `properties`, because SARIF
levels are read by tools that never see the caveats. Rows already triaged `not_vuln` are left
out; add `--all` to `agentaudit sarif` to include them.

---

## Help me improve this

**If you are willing to send me your scan statistics, I would be genuinely grateful.** They cost
you nothing, they contain no code, and they are the one thing I cannot produce on my own: how
this scanner behaves on code I have never seen. A check that fires on your code and never on
mine is the single most useful thing you can hand me.

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

**Nothing is ever uploaded.** There is no network code in any of this, so the only way any of it
leaves your machine is if you carry it out yourself. `--export` re-checks the aggregate against
the table above and refuses to write anything that fails, so read it before you decide.

If you are happy with it, open an [issue](https://github.com/OWNER/REPO/issues) and paste it in. If you would rather not,
that is a perfectly good answer too — the log is yours, and `--no-log` (or `AGENTAUDIT_NO_LOG=1`)
turns the whole thing off.

---

## How it behaves

Things worth knowing before you trust a number.

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
starts, and reports what it actually spent afterwards. Without `--llm` you get the candidate list
with no verdicts — and the report says so, rather than implying anything was judged.

A `vuln` verdict whose argument source is unknown is downgraded to `needs_human`. Those are the
unstable ones: run the same candidate repeatedly and they flip noticeably more often than the
rest. The original verdict stays in `ai_reason` and in `verdicts.json`, so nothing is lost;
`--no-unknown-downgrade` turns the behaviour off, and the round records whether it was on.

### Using it as a gate

```bash
agentaudit scan --path ./myproject --fail-on any        # exit 1 if anything is reported
agentaudit scan --path ./myproject --llm --fail-on vuln # exit 1 only on a `vuln` verdict
agentaudit scan --path ./myproject --diff origin/main   # only files changed since a ref
```

`--diff` needs the source tree to be a git checkout, and is meant for "did this pull request
introduce anything", not for a full audit.

### Skipping parts of a tree

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

Patterns are globs relative to the source root, and are recorded in the round so two rounds stay
comparable. What you exclude, you do not scan — so no candidates from `vendor/` says nothing if
`vendor/` was skipped.

### Every option of `scan`

| Option | What it does |
|---|---|
| `--demo` | scan the bundled sample project |
| `--path DIR` | scan a directory on disk |
| `--repo OWNER/NAME` | fetch a GitHub repo and scan it |
| `--project NAME` | name used in reports (default: derived from the path) |
| `--tag NAME` | round directory name (default: derived) |
| `--out DIR` | where to write the round (default: `./out`) |
| `--llm` | triage with an LLM — spends credits, so it is off by default |
| `--no-unknown-downgrade` | keep a `vuln` verdict even when the argument source is unknown |
| `--no-codeql` | force the offline mode |
| `--lang en\|zh` | report language (default `en`) |
| `--diff [REF]` | only report files changed since `REF` |
| `--fail-on none\|any\|vuln` | exit non-zero, as a build gate |
| `--ignore GLOB` | skip paths matching this glob (repeatable) |
| `--serve` | serve the round on localhost when the scan finishes |
| `--no-sarif` | do not write `agentaudit.sarif` |
| `--no-log` | do not append to the local scan log |

---

## What it checks

The dangerous-call list lives in **`core/config/sinks.yml`** — one YAML file, and it holds
52 dangerous-call rules, not hard-coded logic. `core/gen_ql.py` reads it and generates the CodeQL queries, so adding your own dangerous
function is a config change, not a code change.

| Group | Examples | Default |
|---|---|---|
| Baseline | `subprocess.run` / `Popen`, `os.system`, `requests.get/post/request`, `eval`, `exec`, `jinja2.from_string`, `*.execute(...)` | **on** |
| Database clients | `.query(...)` on receivers whose name ends in `conn` | **on** |
| File I/O (`AF_SINKS_FS`) | `os.remove/unlink/rename/mkdir/chmod/...`, `shutil.move/rmtree/...` | off |
| Path construction (`AF_SINKS_PATH`) | `os.path.join`, `os.path.abspath` | off |
| HTTP clients (`AF_SINKS_HTTP`) | `httpx.get/post/...`, `httpx.Request`, `httpx.Client` | off |
| Dynamic dispatch (`AF_SINKS_DYNIMP`) | `importlib.import_module`, `__import__`, `import_module` | off |

Groups that are off are off because they are noisy; turning one on trades precision for
candidate volume. The switch values are recorded in each round's `meta.json`.

Beyond sinks, the kernel also checks authentication consistency across a file's endpoints,
strong/weak form coexistence within one function, and reachability from an entry point.

Adding your own dangerous function is a few lines of YAML — see
[CONFIGURING.md](CONFIGURING.md) for the field reference, and run
`agentaudit validate` to check your edit.

---

## What it does not find

These are deliberate trade-offs, not bugs. The long version — what the analysis cannot see at
all, and which of its silences are meaningful — is in **[LIMITATIONS.md](LIMITATIONS.md)**.

- **Python only.** The static frontend is bound to CodeQL's Python pack.
- **The triage layer is noisy.** Re-run a candidate and a noticeable share of the verdicts
  change. Suspiciously stable results are usually a *caching* artefact — change `--tag` when
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

For anyone reading the code, or running a batch rather than a single repository.

One target goes through four stages, and `agentaudit scan` drives all of them:

| Stage | Where | What it does |
|---|---|---|
| Static frontend | `core/static_frontend.py` | build a CodeQL database, run the queries in `core/ql/`, parse the SARIF |
| Strong/weak duality | `core/duality.py` | one function doing the same job safely on one line and unsafely on another |
| Triage | `core/llm_judge.py` | the five axes: `verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| Report material | `app/make_report.py`, `app/make_index.py`, `tools/to_sarif.py` | the draft, the sortable table, the SARIF |

Two more sit across those: `core/consistency.py` decides what the evidence does not support and
refuses to report it, and `core/cfg.py` owns the rule configuration. `core/gate.py` (is this
target worth scanning at all) and `core/upstream.py` (has this already been reported upstream)
are used by the batch path only.

### Scanning a batch

A batch has two slow, restartable stages. Both can be stopped and re-run; finished work is
skipped.

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

The screener excludes repositories you have already looked at, which is what makes "not yet
examined" mean something. That list lives in `core/config/known_targets.yml`, which does not
ship -- copy the example and add your own. It is a file rather than a constant in the code
because a list of real repositories says more about whoever wrote the tool than about the tool.

> **Mind the cost.** The triage stage spends LLM credits. Scripts print an estimated cost up
> front, and `AF_LLM_MAX_CNY` hard-stops a run when the cap is reached.

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

## Documentation

| | |
|---|---|
| [CONFIGURING.md](CONFIGURING.md) | the rule fields, and how to add your own dangerous function |
| [LIMITATIONS.md](LIMITATIONS.md) | what the tool does not find |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to run and extend the tests |
| [CHANGELOG.md](CHANGELOG.md) | what changed |

---

## Author's note

I wrote this while working on AI agent security, and the part that kept stopping me was not
finding a dangerous call — it was deciding what to do with one. Run the same candidate past a
model twice and you do not always get the same answer. A tool that hides that is worse than one
that misses things, because you cannot tell **which** of its outputs to trust.

So the rule I built it around is narrow: **nothing here is allowed to sound more certain than it
is.** `needs_human` is a real verdict. Evidence that could not be determined is printed as "not
determined" instead of guessed. Every report says it was not verified by execution.
[`LIMITATIONS.md`](LIMITATIONS.md) is kept current on purpose, because a tool that only lists
its strengths is not telling you anything.

If you run it and it is wrong — in either direction — that is the most useful thing you can send
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

MIT — see [LICENSE](LICENSE).

> Please use it only against targets **you are authorised to test**.
