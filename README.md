# agentaudit

**English** | [中文](README.zh-CN.md)

<!-- Replace OWNER/REPO below with the real location once this repo is pushed, or delete the
     line. The badge goes green as soon as CI has run once. -->
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)

**Code audit for AI agents.** A static-analysis + LLM-triage scanner that finds
dangerous call sites in LLM / Agent code — and says *"I don't know"* when it doesn't know.

The output is a list of **candidates** to review, not a list of confirmed vulnerabilities.

| | |
|---|---|
| Rules | 52 dangerous-call rules in one YAML file, plus the non-call checks ([CONFIGURING.md](CONFIGURING.md)) |
| Self-tests | 10 rule suites, 56 tests ([CHANGELOG.md](CHANGELOG.md)) |
| Try it | `python app/scan.py --demo` — no CodeQL, no API key, no downloads |
| What it misses | [LIMITATIONS.md](LIMITATIONS.md) |

---

## The problem it solves

Dangerous calls (`eval`, `subprocess`, `open`, `requests`, …) are everywhere in agent code,
and classic taint analysis flags all of them. Ask a different question and the picture
changes completely:

```python
# Candidate. Dangerous call? yes. Is it a vulnerability? probably not.
handler = eval(spec_name)          # spec_name comes from a built-in table in this file
```

Three questions decide whether a flagged call site is real, and taint analysis only
answers the first:

| # | Question | Answered by |
|---|---|---|
| ① | Is there a dangerous call? | static analysis |
| ② | Is its argument **externally controlled**? | this project |
| ③ | Does that argument **survive to the sink**? | this project |

`agentaudit` turns ② and ③ into runnable checks (`tools/param_taint_criteria.py`) and treats
*"the triage layer can't tell"* as a reportable outcome (`needs_human`) rather than something
to hide behind a confident-looking guess.

---

## Install

Requires **Python 3.10+** and the
[CodeQL CLI](https://github.com/github/codeql-cli-binaries) (a few hundred MB, optional —
without it the scanner runs in the offline mode).

```bash
git clone <this repo> && cd agentaudit
./scripts/setup.sh                 # dependency + CodeQL CLI, or:
pip install -e .                   # dependency only; gives you the `agentaudit` command
```

Either way the scripts can be run directly (`python app/scan.py ...`). With the editable
install there is also a single command:

```bash
agentaudit scan --demo
agentaudit explain out/round-demo --index 3
agentaudit serve out/round-demo
agentaudit --help
```

Where does output go? To `./out` under the current directory, or to `$AGENTAUDIT_HOME` if you
set it. Nothing is written into the installation.

#### All the commands

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

### Smoke test (offline, no API key, no CodeQL)

```bash
agentaudit selftest                # or: python tools/run_selftests.py
agentaudit scan --demo             # 13 candidates from the bundled sample project
```

These run in seconds and confirm the checks behave as their labelled cases expect — the
fastest way to know the setup is sane before scanning anything.

---

## Reading the results

```bash
agentaudit explain out/round-x --index 3     # why was this one reported?
agentaudit serve out/round-x                 # read the whole round in a browser (localhost only)
```

`serve` binds to `127.0.0.1`, serves exactly that one directory, and refuses directory
listings and path traversal.

### The scan log

Every scan appends one line to `./data/scan_log.jsonl`, containing **counts only**: how many
files, how many candidates, how they split across checks and verdicts, the elapsed time, the
version, and hashes of the rule configuration. No source, no paths, no project names — the
record is checked against that promise before it is written.

```bash
agentaudit log                    # summarise what you have scanned
agentaudit log --export           # a small aggregate you can paste somewhere
agentaudit log --clear            # delete it
```

Nothing is ever uploaded. `--export` runs a redaction check and refuses to write anything that
fails it, so the export is safe to read before you decide what to do with it. Use `--no-log`
(or `AGENTAUDIT_NO_LOG=1`) to turn the log off.

---

## What it checks

The dangerous-call list lives in **`core/config/sinks.yml`** — one YAML file, not hard-coded
logic. `core/gen_ql.py` reads it and generates the CodeQL queries, so adding your own
dangerous functions is a config change, not a code change.

| Group | Examples | Default |
|---|---|---|
| Baseline | `subprocess.run` / `Popen`, `os.system`, `requests.get/post/request`, `eval`, `exec`, `jinja2.from_string`, `*.execute(...)` | **on** |
| Database clients | `.query(...)` on receivers whose name ends in `conn` | **on** |
| File I/O (`AF_SINKS_FS`) | `os.remove/unlink/rename/mkdir/chmod/...`, `shutil.move/rmtree/...` | off |
| Path construction (`AF_SINKS_PATH`) | `os.path.join`, `os.path.abspath` | off |
| HTTP clients (`AF_SINKS_HTTP`) | `httpx.get/post/...`, `httpx.Request`, `httpx.Client` | off |
| Dynamic dispatch (`AF_SINKS_DYNIMP`) | `importlib.import_module`, `__import__`, `import_module` | off |

Groups that are off by default are off because they are noisy; turning one on trades
candidates for noise. The switch values are recorded in each round's `meta.json`, so two runs
are only compared when they used the same settings.

Beyond sinks, the kernel also checks authentication consistency across a file's endpoints,
strong/weak form coexistence within one function, and reachability from an entry point.
[`LIMITATIONS.md`](LIMITATIONS.md) lists what none of this covers.

Adding your own dangerous function is a few lines of YAML — see
[CONFIGURING.md](CONFIGURING.md) for the field reference and
`python tools/validate_config.py` to check your edit.

---

## Pipeline

```
select targets -> fetch & build CodeQL DBs -> static frontend (CodeQL)
  -> reachability triage -> entry-point tracing -> parameter-taint check
  -> LLM triage -> report material
```

| Stage | Entry point | What it does |
|---|---|---|
| Select targets | `tools/target_screener.py` | filter repos by stars / activity / "is this an agent at all?" |
| Fetch & build | `tools/prepare_new_targets.py` | download sources and build CodeQL databases; resumable |
| Static frontend | `core/static_frontend.py` | run the CodeQL queries, parse SARIF |
| Reachability | `tools/reachability_triage.py` | can this sink be reached from outside at all? |
| Entry tracing | `tools/find_entries_for_suspects.py` | walk up to callers, look for exposure markers |
| **Parameter taint** | `tools/param_taint_criteria.py` | is the argument controllable, and is it constrained on the way? |
| LLM triage | `core/llm_judge.py` | five axes: `verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| One-shot run | `app/run_all.py` | prepare -> scan -> report |

---

## Quick start

Scan something with one command — no target list and no database to build by hand:

```bash
python app/scan.py --demo                  # the bundled sample project
python app/scan.py --path ./myproject      # a project already on disk
python app/scan.py --repo owner/name       # fetch a GitHub repo and scan it
```

If you would rather not remember flags, a bare `agentaudit` opens a menu in the terminal:

```
  1  Scan a target
  2  Open a previous round
  3  Run the rule self-tests
  4  Validate the rule configuration
  5  Scan statistics (local, statistics only)
  6  List the commands
```

It echoes the command line it runs, so the menu teaches the flags instead of hiding them, and
it refuses to start when there is no terminal (a pipe or CI) rather than blocking on input.

Output lands in `out/round-<tag>/`:

| File | What it is |
|---|---|
| `report_draft.md` | the write-up, one section per candidate |
| `index.html` | sortable / searchable table of every candidate |
| `findings.tsv` | the raw candidate table |
| `agentaudit.sarif` | the candidates as SARIF 2.1.0, for a code-scanning UI or an editor |
| `results.sarif` | the CodeQL frontend's own raw output (full mode only) |

The SARIF export uses **relative paths only** — no absolute path and no `originalUriBaseIds`
— so a file uploaded from your machine does not carry your filesystem layout. Every result is
`level: warning` and the triage verdict travels in `properties`, because SARIF levels are read
by tools that never see the caveats. Rows already triaged `not_vuln` are left out; add
`--all` to `agentaudit sarif` to include them.

### Two modes

| Mode | Needs | Finds |
|---|---|---|
| **full** | the CodeQL CLI | the CodeQL queries *and* the AST checks; writes SARIF |
| **offline** | nothing at all | the AST checks only |

If the CodeQL CLI is not installed the run says so and uses the offline mode instead. Which
mode produced a round is recorded in `meta.json` and printed at the top of the report, because
the two do not find the same things. `--no-codeql` forces the offline mode.

### Docker

If you would rather not install CodeQL yourself, the image has it baked in:

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # bundled sample
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

The image entry point is `agentaudit scan`, so the arguments above are the same ones you would
type locally. Other subcommands need their own entry point:

```bash
docker run --rm --entrypoint agentaudit agentaudit log
docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
```

**On verifying the image.** The `Dockerfile` was written on a machine without Docker, so the
first build is the test. It is built to fail loudly rather than quietly: the CodeQL CLI is
executed *during* the build, so a wrong release layout stops the build instead of producing an
image whose scanner cannot run. CI builds and smoke-tests the image on every push (the `docker`
job), which is the practical way to keep it honest.

### LLM triage is off by default

It spends API credits, so it only runs when you ask for it:

```bash
python app/scan.py --path ./myproject --llm
```

The run prints the candidate count and the hard cap (`AF_LLM_MAX_CNY`, default 30 CNY)
before it starts, and reports what it actually spent afterwards. Without `--llm` you get the
candidate list with no verdicts — the report says so rather than implying anything was judged.

**A `vuln` verdict with an unknown argument source is downgraded to `needs_human`.** Repeated
runs of the same candidates show those are the unstable ones — they flip roughly one time in
three — so they are kept out of the reportable set. The original verdict stays in `ai_reason`
and in `verdicts.json`, so nothing is lost; pass `--no-unknown-downgrade` to turn the behaviour
off, and the round records whether it was on.

### Seeing why something was reported

```bash
python app/explain.py out/round-my-round --index 3
```

Prints the source around the flagged line, the call chain that reaches it, the guards on that
path, and where the dangerous argument comes from — or that the scan could not determine it.
This is the command to run before believing or dismissing a candidate.

### Using it as a gate

```bash
python app/scan.py --path ./myproject --fail-on any        # exit 1 if anything is reported
python app/scan.py --path ./myproject --llm --fail-on vuln # exit 1 only on a `vuln` verdict
python app/scan.py --path ./myproject --diff origin/main   # only files changed since a ref
```

`--diff` needs the source tree to be a git checkout, and is meant for "did this pull request
introduce anything", not for a full audit.

### Skipping parts of a tree

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

Patterns are globs relative to the source root, and are recorded in the round so two rounds
stay comparable.

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

### The manual pipeline

`app/scan.py` wraps the same engine that can be driven stage by stage, which is what you want
when scanning a whole batch of targets:

```bash
# 1) offline self-check (free)
python tools/run_selftests.py

# 2) select targets (needs a GitHub token)
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) fetch sources and build CodeQL databases (restartable; finished work is skipped)
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) run one round
python app/run_round.py --tag my-round --targets-file core/config/targets.yml

# 5) render the report draft and the HTML index
python app/make_report.py out/round-my-round --lang en
python app/make_index.py  out/round-my-round --lang en
```

> **Mind the cost.** The triage stage spends LLM credits. Scripts print an estimated cost up
> front, and `AF_LLM_MAX_CNY` hard-stops a run when the cap is reached.

---

## What the output looks like

Three artefacts, in increasing order of cost:

| Artefact | Produced by | What it is |
|---|---|---|
| `param_taint_probe.md` | `tools/param_taint_criteria.py` | per-candidate verdict on controllability — **free**, runs before any LLM call |
| `findings.tsv` | `app/run_round.py` | the raw candidate table, one row per candidate |
| `report_draft.md` | `app/make_report.py` | the human-facing draft, only for `vuln` rows |

See **[`examples/`](examples/)** for a complete synthetic sample. The sample rows cover the
four outcomes the scanner distinguishes: `vuln`, `not_vuln` (not externally controllable),
`not_vuln` (blocked by a validator) and **`needs_human`** (origin undeterminable). That last
one matters: a scanner that only ever outputs `vuln` / `not_vuln` is lying about its certainty.

---

## Known limitations

These are deliberate trade-offs, not bugs.

- **Python only.** The static frontend is bound to CodeQL's Python pack. The checks
  themselves are language-agnostic, but a new language means rebuilding the frontend.
- **The LLM triage layer is noisy.** Re-run the same candidate three times and roughly a
  quarter of the verdicts change. "Perfectly stable" results are usually a **caching
  artifact** — always change `--tag` when re-judging.
- **`arg_source=unknown` verdicts are not trustworthy.** That value means the model itself
  does not know where the argument comes from; those rows are downgraded by default.
- **"No caller found" is not "unreachable."** Only name-based matching is done, so cross-file
  dispatch, dynamic dispatch and reflection are missed.
- **Framework mediation.** When an imported implementation lives in `site-packages` rather
  than in the scanned tree, static analysis cannot see it.
- **Regenerating the CodeQL queries needs the AgentFuzz reference pack.** It is only needed
  for regeneration; the committed `core/ql/*.ql` work without it (`AF_PAPER_QL` to point at it).
- **Every finding needs human confirmation.** The tool produces **candidates**, not conclusions.
- **The offline mode finds less.** Without CodeQL there is no inter-procedural reachability
  and no framework modelling, so the candidate list is shorter. Each round records its mode.

The long version of this list, including the patterns the analysis cannot see at all and the
kinds of false positive to expect, is in **[LIMITATIONS.md](LIMITATIONS.md)**.

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
| `AF_SOURCES_FILE` | alternative untrusted-source list | `core/config/sources.yml` |
| `AF_NO_DATAFLOW` | disable inter-procedural argument-source analysis | `0` |
| `AGENTAUDIT_HOME` | where output (`out/`, `data/`) goes | the current directory |
| `AGENTAUDIT_NO_LOG` | set to `1` to stop recording scan statistics | unset |

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

## Acknowledgements

The CodeQL frontend and the baseline sink list are derived from **AgentFuzz**:

> Fengyu Liu, Yuan Zhang, Jiaqi Luo, Jiarun Dai, Tian Chen, Letian Yuan, Zhengmin Yu,
> Youkun Shi, Ke Li, Chengyuan Zhou, Hao Chen, Min Yang.
> *Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in
> LLM-based Agents.* 34th USENIX Security Symposium (USENIX Security '25), 2025, pp. 3767–3786.

`core/gen_ql.py` regenerates the queries from that reference pack, which is why
`AF_PAPER_QL` points at it. Everything under `source: extra` in `core/config/sinks.yml`,
the reachability check, the parameter-taint check and the triage layer are additions on
top of the baseline.

---

## License

MIT — see [LICENSE](LICENSE).

> Please use it only against targets **you are authorised to test**.
