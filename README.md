# agentaudit

**English** | [中文](README.zh-CN.md)

**Code audit for AI agents.** A static-analysis + LLM-triage scanner that finds
dangerous call sites in LLM / Agent code — and says *"I don't know"* when it doesn't know.

The output is a list of **candidates** to review, not a list of confirmed vulnerabilities.

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
[CodeQL CLI](https://github.com/github/codeql-cli-binaries) (a few hundred MB).

```bash
pip install -r requirements.txt

# CodeQL: unpack it next to the project by default, or point AF_CODEQL at it.
#   default lookup: ./_tools/codeql/codeql(.exe)
```

### Smoke test (offline, no API key, no CodeQL)

```bash
python tools/param_taint_criteria.py --selftest      # the criterion answers labelled cases
python tools/run_selftests.py                        # the whole self-test suite
```

These run in seconds and are the fastest way to confirm the setup works.

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

```bash
# 1) offline self-check (free)
python tools/param_taint_criteria.py --selftest

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

---

## Configuration

Secrets are always read from files or environment variables, never committed.

| Env var | Purpose | Default |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | path to the LLM API key file | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | path to a GitHub token file (raises API limits) | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **hard per-run spend cap**; the run stops and reports when reached | `30` |
| `AF_JUDGE_MT` | max output tokens for the triage layer | `8000` |
| `AF_CODEQL` | path to the CodeQL CLI | `./_tools/codeql/codeql(.exe)` |
| `AF_PAPER_QL` | path to the AgentFuzz reference QL pack | `./agentfuzz-official/ql` |
| `AF_TARGET_MAP` | JSON map `{"short-name": "source root"}` | read from `core/config/targets*.yml` |
| `AF_SINKS_FS` / `_PATH` / `_HTTP` / `_DYNIMP` | enable extra sink groups | off |
| `AF_SINKS_EXTRA` | include the `source: extra` entries at all | `1` |
| `AF_PATH_FILTER` | path filter mode (`rel` = project-relative) | `rel` |
| `AF_SOURCES_FILE` | alternative untrusted-source list | `core/config/sources.yml` |
| `AF_NO_DATAFLOW` | disable inter-procedural argument-source analysis | `0` |

---

## Repository layout

```
core/      the kernel (static frontend, triage, reachability, taint tracing, CodeQL queries)
tools/     reusable tooling (target selection, fetching, individual checks, self-tests)
app/       one-shot entry points and orchestration
examples/  synthetic sample output
```

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
