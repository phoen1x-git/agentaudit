# agent-scanner

**English** | [中文](README.zh-CN.md)

A taint-style vulnerability scanner for **LLM / Agent applications**.
Static analysis (CodeQL) selects candidate sites; an LLM assists with triage.

Its distinguishing design goal is **honest uncertainty**: the scanner is built to say
*"I don't know"* instead of guessing, and to make that verdict a first-class outcome
rather than an embarrassment to be papered over.

> ⚠️ Python only at the moment. The LLM triage layer has known noise — see
> [Known limitations](#known-limitations).

---

## Why another scanner?

Dangerous calls in agent code (`eval`, `subprocess`, `open`, `requests`, …) are **not**
a plain data-flow problem. Whether a given `eval(...)` is a vulnerability depends on
**three** questions, and classic taint analysis only answers the first one:

| # | Question | Example (both of these are **false positives**) |
|---|---|---|
| ① | Is there a dangerous call? | — static analysis can answer this |
| ② | Is its argument **externally controlled**? | the argument is a directory name **enumerated locally** |
| ③ | Does the argument **survive to the sink**? | a **validator** midway reduces it to `None` |

This project turns ② and ③ into **runnable criteria**
(`tools/param_taint_criteria.py`), and treats *"the triage layer doesn't know"*
as something to report, not something to hide.

---

## Pipeline

```
select targets → fetch & build DBs → static frontend (CodeQL) → reachability triage
   → entry-point tracing → parameter-taint criterion → LLM triage
   → three-gate review → hands-on verification → report material
```

| Stage | Entry point | What it does |
|---|---|---|
| Select targets | `tools/target_screener.py` | filter repos by stars / activity / "is this an agent?" |
| Fetch & build | `tools/prepare_new_targets.py` | download sources + build CodeQL databases; **resumable** |
| Static frontend | `core/static_frontend.py` | run CodeQL queries, parse SARIF |
| Reachability | `tools/reachability_triage.py` | can the sink be reached from outside? |
| Entry tracing | `tools/find_entries_for_suspects.py` | walk up to callers, look for exposure markers |
| **Parameter taint** | `tools/param_taint_criteria.py` | is the argument controllable / is it constrained en route? |
| LLM triage | `core/llm_judge.py` | five axes: `verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| One-shot run | `app/run_all.py` | prepare → scan → report |

---

## Install

Requires **Python 3.10+** and the
[CodeQL CLI](https://github.com/github/codeql-cli-binaries).

```bash
pip install -r requirements.txt

# CodeQL: unpack it somewhere the frontend can find it.
# Default lookup: <workspace>/_tools/codeql/codeql(.exe) — override for your layout.
```

### Configuration

**Secrets are always read from files/env vars and never committed.**

| Env var | Purpose | Default |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | path to the LLM API key file | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | path to a GitHub token file (raises API limits) | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **hard per-run spend cap** (fuse against runaway loops; stops and reports) | `30` |
| `AF_TARGET_MAP` | JSON map `{"short-name": "source root"}` | read from `core/config/targets*.yml` |
| `AF_JUDGE_MT` | max output tokens for the triage layer | `8000` |

---

## Quick start

```bash
# 1) Smoke test: criterion self-check (offline, free)
python tools/param_taint_criteria.py --selftest

# 2) Select targets (needs a GitHub token)
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) Fetch sources + build CodeQL DBs (restartable; finished work is skipped)
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) Run one round
python app/run_round.py --tag my-round --targets-file core/config/targets.yml
```

★ **Mind the cost.** The triage layer spends LLM credits. Scripts print an **estimated
cost** up front, and `AF_LLM_MAX_CNY` **hard-stops** the run when the cap is reached.

---

## Known limitations

These are deliberate trade-offs, not bugs. They are written down because
**stating uncertainty plainly is more useful than pretending to be precise.**

- ★ **Python only.** The static frontend is bound to CodeQL's Python pack
  (`--language=python`). The criteria themselves are language-agnostic, but a new
  language means rebuilding the frontend.
- ★ **The LLM triage layer is noisy.** Re-run the same candidate three times and
  **roughly a quarter of the verdicts change**. "Perfectly stable" results are often a
  **caching artifact** — always change `--tag` when re-judging.
- ★ **`arg_source=unknown` verdicts are not trustworthy.** That value means the model
  itself does not know where the argument comes from. The candidate filter
  **downgrades this bucket by default**.
- ⚠️ **"No caller found" ≠ "unreachable."** Only name-based matching is done;
  cross-file, dynamic dispatch and reflection are missed.
- ⚠️ **Framework mediation.** When an `import`ed implementation lives in
  `site-packages` (not in the scanned tree), static analysis cannot see it.
- ⚠️ **Every finding needs human confirmation.** The tool produces **candidates**,
  not conclusions.

---

## Repository layout

```
core/     the criteria kernel (static frontend / triage / reachability / taint tracing / CodeQL queries)
tools/    reusable tooling (target selection / fetching / individual criteria / self-checks)
app/      one-shot entry points and orchestration
```

---

## License

MIT — see [LICENSE](LICENSE).

> ★ Please use it only against targets **you are authorised to test**.
