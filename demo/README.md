# `demo/` — a deliberately vulnerable sample project

**Everything in this directory is synthetic and intentionally insecure.** It exists so you
can run the scanner end to end and see what its output looks like, without cloning anything
or configuring an API key.

- `demo-agent` is not a real project. The code was written for this demo.
- It is **not installable and must not be deployed, run, or copied into anything real.**
- The vulnerabilities are deliberate: the point is that a scan finds them.

Run it with:

```bash
python app/scan.py --demo
```

## What a scan of this directory reports

With the AST checks (which is what `--demo` uses when CodeQL is not installed):

| File | Line | Check | What is wrong |
|---|---|---|---|
| `agent/app.py` | 21 | inconsistent authentication | two of the four routes require a user, and this one does not |
| `agent/legacy_api.py` | 15 | dangerous call / input-to-sink | `eval()` is handed a value straight out of the request body |
| `agent/legacy_api.py` | 13, 19 | unauthenticated route | both routes are reachable with no auth of any kind |
| `agent/paths.py` | 19 | strong/weak form | the same function builds a path safely on one line and unsafely on the next |
| `agent/tools.py` | 18 | dangerous call | a shell tool runs whatever it is handed, with `shell=True` |
| `agent/tools.py` | 24 | dangerous call | an `eval` tool |
| `agent/tools.py` | 35 | argument source unknown | the value handed to `urlopen` comes from a parameter with no visible origin |
| `agent/tools.py` | 41, 42 | untrusted input to a sink | `os.path.join` on a caller-supplied name (`DOCS_ROOT` is a fixed prefix, the rest is not) |
| `agent/memory.py` | — | *(context only)* | the store that `tools.save_then_run` writes to; nothing in this directory is flagged here |

`memory.py` is included because cross-turn state is what makes agent code awkward to reason
about, and the scanner deliberately does **not** pretend to follow it here: the value a later
turn reads back is only visible to a check that can follow data across turns, which the
offline mode cannot do.

A **full** run (with CodeQL installed) adds the reachability and data-flow checks on top of
the list above, so it usually reports more than this table.
