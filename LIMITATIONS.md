# What this tool does not find

A scanner that only lists its strengths is not telling you anything useful. This page lists
what `agentaudit` is known to miss, so you can decide whether it is the right tool before
trusting its output — and so you know which of its silences are meaningful.

Nothing here is a bug report. Most of it is a deliberate limit of "static analysis plus a
model reading the evidence".

---

## 1. Patterns it cannot see at all

| Missed | Why |
|---|---|
| **Cross-file and dynamic dispatch** | If the function that runs is chosen at runtime (`getattr(module, name)()`, a dict of handlers, a plugin registry), the call graph does not connect. The dynamic-dispatch sink group (`AF_SINKS_DYNIMP`) makes the *import* visible, but not which function ends up running. |
| **Reflection and metaprogramming** | `__getattr__`, decorators that rewrite functions, `exec`-generated code, and anything built from strings at import time. |
| **Libraries outside the scanned tree** | When the implementation lives in `site-packages`, the source is not in the database, so the analysis stops at the import. |
| **Values that leave and come back** | Anything stored in a database, a file, a queue or a cache on one turn and read on a later turn. The demo's `agent/memory.py` is exactly this: the store is visible, the flow through it is not. |
| **State inside a framework** | Session state, dependency-injection containers, middleware that injects a user object. The check can see `Depends(...)` in a signature; it cannot see a gateway that authenticates before the request arrives. |
| **Sinks that are not in `core/config/sinks.yml`** | By definition. If your project's dangerous function is not listed, it is invisible — this is the single easiest gap to close, see [CONFIGURING.md](CONFIGURING.md). |
| **Non-Python code** | The frontend is bound to CodeQL's Python pack. Templates, a TypeScript frontend, shell scripts and YAML pipelines are all out of scope. |
| **Python that is not in `.py` files** | Notebooks, code inside string literals, and generated sources that are not written to disk before the scan. |
| **Async, thread and process boundaries** | A value passed through a queue or a future is a new root as far as the analysis is concerned. |
| **Anything requiring execution** | No input is ever sent, nothing is run, no container is started. "Exploitable" is never verified — a real vulnerability and a lookalike are indistinguishable here. |

## 2. Things it will report that you should expect to dismiss

| Reported anyway | Why |
|---|---|
| **Values whose names merely look like input** | The input heuristic matches names like `request.*` and known carrier variables. A local helper that happens to be called `request` will be treated as untrusted, and a genuinely untrusted value with a dull name (`x`, `arg1`) may not be. |
| **Constructors with no caller** | `os.path.join`, once enabled, reports on its own. Building a path is not a vulnerability; using it as a path might be. |
| **The same line, several times** | Each check is independent, so one line can appear once per matching check. The fingerprint keeps them separate on purpose — they are different arguments, not duplicates. |
| **Half of a symmetric pair** | If one function validates and its twin does not, only the twin is reported. That is the strong/weak-form check working as intended, but the pair is easier to read than either half. |
| **Noisy groups, once you turn them on** | `AF_SINKS_FS`, `_PATH`, `_HTTP` and `_DYNIMP` are off by default because enabling them reliably raises the false-positive rate. Treat a run with them on as a different measurement, not a better one. |

## 3. Things it deliberately refuses to decide

| Refusal | Why |
|---|---|
| **Reachability is name-based** | "No caller found" is reported as `unknown`, never as unreachable. Cross-file and dynamic dispatch are missed, so absence of a caller proves nothing. |
| **`arg_source=unknown`** | Reported as an outcome instead of being guessed. Those rows are downgraded rather than promoted. |
| **Whether a designed feature is a vulnerability** | `by_design` and `scope_exceeds` are separate questions from "is the argument controllable", and the report keeps them separate. A shell tool that exists to run commands is reported as a candidate, not a verdict. |
| **Anything about a target you are not authorised to test** | Out of scope by construction; see the note at the end of the README. |

## 4. Operational limits worth knowing before you quote a number

- **The triage layer is not reproducible.** Re-running the same candidate changes roughly a
  quarter of the verdicts. A suspiciously stable result usually means the cache answered,
  not that the analysis was deterministic. Change `--tag` when re-judging.
- **The offline mode is a subset.** Without CodeQL there is no inter-procedural reachability
  and no framework modelling. Compare rounds only within the same mode, which is why every
  round records the mode it ran in.
- **The checks change.** Every round stamps hashes of `sinks.yml`, `filters.yml`,
  `ast_criteria.py` and the triage rubric. Numbers from rounds with different stamps are not
  comparable, and the stamp is the only way to tell.
- **Nothing is a conclusion.** Every row is a **candidate** and needs a human to read the
  source next to it. `--explain` prints exactly the evidence the scan collected, which is
  what that reading should start from.

---

## How to find out for a specific candidate

```bash
python app/explain.py out/round-my-round --index 3
```

It prints the source around the flagged line, the call chain that reaches it, the guards on
that path, and where the dangerous argument comes from — including saying "not determined by
this scan" when that is the case. If the evidence is thin, the candidate is thin.
