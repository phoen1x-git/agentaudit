# ② Parameter-taint criterion · probe result

> ★ Zero cost (pure AST, no LLM, no network). Answers one question:
> **does the sink's argument trace back to a parameter, and is it constrained on the way?**
> ★ Three verdicts: `local` (excluded) / `validated` (excluded) / `pass-through` (**kept**).
> ⚠️ **Synthetic sample** — see [`README.md`](README.md).

- candidates examined: **5**
- ★ **pass-through** (argument is unconstrained ⇒ **not excluded**): **2**, of which **1** has caller evidence
- local (not externally controllable ⇒ excluded): **1**
- validated (blocked by a whitelist/normaliser ⇒ excluded): **2**
- undetermined (missing source / parse failure / complex tracing): **0**
- ★★ **total excluded**: **3** = 60% of candidates removed **before spending anything**

## Per target

| target | pass-through | local | validated | undetermined | total |
|---|---|---|---|---|---|
| demo-agent | **2** | 1 | 2 | 0 | 5 |

## ★ pass-through · caller evidence present (look here first)

- `demo-agent` **src/tools/shell_tool.py:31**  sink=`subprocess.run`  [reachable]
    - parameter `command` travels straight from the function parameter to the sink, no
      validation found; caller `run_tool:88` passes **parameter** `argv` (tracing continues upward)
- `demo-agent` **src/tools/shell_tool.py:12**  sink=`subprocess.run`  [reachable]
    - parameter `args` reaches the sink; caller `run_tool:88` passes a value computed from a parameter

## validated (excluded)

- `demo-agent` src/loaders/file_loader.py:64  sink=`open`
  ⇒ constraint on the path from parameter to sink: **58: normalising call `os.path.realpath()`**;
  **60: whitelist membership test `in ALLOWED_ROOTS`**
- `demo-agent` src/loaders/file_loader.py:71  sink=`open`
  ⇒ constraint on the path from parameter to sink: **58: normalising call `os.path.realpath()`**

## local (excluded)

- `demo-agent` src/registry/plugin_loader.py:24  sink=`eval`
  ⇒ sink argument `spec_name` is a local value / internal call and does not trace back to a
  parameter; `spec_name = _enumerate_builtin_specs()` (produced internally) ⇒ **not externally controllable**

---

★ Caveats (the tool's own, not a sales pitch):

- ⚠️ `pass-through` is a **necessary condition, not a sufficient one** — the argument is
  unconstrained, which does **not** prove an outsider can reach it.
- ⚠️ Caller tracing is **same-module only** (no cross-file, no recursion yet).
- ⚠️ "validated" is judged **conservatively**: only statically visible constraints count,
  so the real number is probably higher — and "undetermined" must never be read as "clean".
- ⚠️ "Sanitiser" detection is **name-based** (`check_` / `validate_` / …) and will
  occasionally mistake a same-named but non-sanitising function.
