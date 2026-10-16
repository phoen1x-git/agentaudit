# Configuring the rules

The checks are not hard-coded. The rule files live under `core/config/`, and
`core/gen_ql.py` turns the first three into the CodeQL queries that actually run. Adding a
dangerous function of your own is a **config change**, not a code change.

```
core/config/
  sinks.yml              the dangerous-call list (the main one)
  sources.yml            what counts as untrusted input
  filters.yml            which paths to ignore
  gate.yml               the health gate: which targets are not worth scanning at all
  targets.example.yml    a template target table -- copy it to targets.yml to scan a batch
```

`sinks.yml`, `sources.yml` and `filters.yml` generate queries, so editing them changes what the
scanner looks for. `gate.yml` does not generate anything: it is read at the start of a round and
skips targets that are archived, unmaintained, or not an agent in the first place. It is worth
knowing it exists, because a target silently skipped is a target whose absence from a report is
not evidence of anything. `targets.example.yml` is only a template; `app/scan.py` does not need
it at all.

After editing any of them, run:

```bash
python tools/validate_config.py          # typos are otherwise silent
python app/scan.py --demo                # and confirm the checks still behave
```

The generated queries live in `core/ql/` and are regenerated on every scan. Regenerating
needs the AgentFuzz reference pack (see [`ACKNOWLEDGEMENTS` in the README](README.md#acknowledgements));
the committed `core/ql/*.ql` work without it.

---

## Adding a dangerous function

Say you want `.query(...)` on your own database client to be treated as a sink. Add an entry
to `core/config/sinks.yml`:

```yaml
  - id: myclient-query
    source: extra
    cls: direct
    obj: myclient
    func: query
    note: our internal client hides the SQL string from the driver
```

Then validate and rescan. `--explain` will show the new candidate the same way as any other.

### Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | **yes** | unique name; entries without one are skipped by the generator |
| `source` | **yes** | `paper` = the baseline set (kept for reference, not generated); `extra` = yours |
| `cls` | **yes** | `direct` = matchable by name; `structural` = needs a definition site, so it is **not** generated |
| `name` | one of these | a bare function name, e.g. `eval` |
| `obj` | " | the object name, e.g. `subprocess` in `subprocess.run(...)`; `"*"` means any object (very noisy) |
| `obj2` | " | a two-level attribute, e.g. `os.path` in `os.path.join(...)` |
| `obj_suffix` | " | the object's name must end with this, e.g. `conn` matches `self.conn.query(...)` |
| `func` | " | the method name, used together with one of the `obj*` fields |
| `group` | no | puts the rule behind a switch: `AF_SINKS_<GROUP>=1`. Without it the rule is always on |
| `enabled` | no | set `false` to keep an entry but leave it out (default `true`) |
| `note` | no | free text; ignored by the generator |

At least one of `name` / `obj` / `obj2` / `obj_suffix` must be present, otherwise the entry
can never match anything. `tools/validate_config.py` checks exactly this, plus duplicate ids
and unknown field names — an unknown field is the quiet failure mode, because the generator
simply ignores the entry and the check silently stops covering that function.

### Switch groups

| Group | Switch | Why it is off by default |
|---|---|---|
| `fs` | `AF_SINKS_FS=1` | file operations are everywhere; turning it on trades precision for candidate volume |
| `path` | `AF_SINKS_PATH=1` | `os.path.join` is a constructor, not an executor, so on its own it reports a lot |
| `http` | `AF_SINKS_HTTP=1` | modern stacks use `httpx` rather than `requests`; the group is a recall patch and is noisy |
| `dynimp` | `AF_SINKS_DYNIMP=1` | dynamic imports are normal in ordinary code (lazy loading, plugins) |

Every round records which switches were active in `meta.json`. Two rounds are only directly
comparable when they used the same settings.

---

## Untrusted input (`sources.yml`)

| Field | Meaning |
|---|---|
| `id` | unique name |
| `kind` | `method` = any object's method returns untrusted data; `attr` = an attribute read; `name` = a bare function; `obj_method` = a named object's method |
| `names` | the method / attribute / function names |
| `obj_names` | restrict to these object names (used with `obj_method`) |
| `obj_suffix` | restrict to objects whose name ends with this |

Sources only feed the **argument-source evidence** shown to the triage layer and in
`--explain`. They are hints; the triage layer still reads the code and can conclude
"unknown". Making the list too broad is the failure mode to avoid: if everything counts as
untrusted, every candidate looks like a vulnerability and the output becomes useless.

---

## Ignored paths (`filters.yml`)

Three layers, applied in order: `path_segments` (exact directory-segment match),
`filename_re` (regex on the file name), then `substrings` (the baseline's own blacklist, kept
as a fallback for environment paths such as `miniconda`).

`AF_PATH_FILTER=rel` (the default) matches against the project-relative path rather than the
absolute one, so a directory named `test` somewhere above your checkout no longer excludes
the whole project. `AF_NO_FILTER=1` disables the filter entirely.

### Excluding files for one scan only

For a one-off ("ignore the vendored tree, just this time"), use the command line instead of
editing the config:

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

Patterns are globs relative to the source root. They are recorded in the round's `meta.json`,
so a filtered round is not mistaken for a clean one — excluding files lowers what a scan can
find, and the record is what stops that from being invisible later.

---

## The rules that are on by default

Generated from the current configuration with `python tools/validate_config.py --table`:

<!-- BEGIN GENERATED TABLE -->
| Rule | Matches | Group | Default |
|---|---|---|---|
| `subprocess.run` | `subprocess.run(...)` | - | on (baseline) |
| `subprocess.Popen` | `subprocess.Popen(...)` | - | on (baseline) |
| `os.system` | `os.system(...)` | - | on (baseline) |
| `requests.get` | `requests.get(...)` | - | on (baseline) |
| `requests.post` | `requests.post(...)` | - | on (baseline) |
| `requests.request` | `requests.request(...)` | - | on (baseline) |
| `jinja.from_string` | `jinja.from_string(...)` | - | on (baseline) |
| `eval` | `eval(...)` | - | on (baseline) |
| `exec` | `exec(...)` | - | on (baseline) |
| `session.execute` | `*.execute(...)` | - | on (baseline) |
| `conn-query` | `*conn.query(...)` | - | **on** |
| `os.remove` | `os.remove(...)` | fs | off (`AF_SINKS_FS`) |
| `os.unlink` | `os.unlink(...)` | fs | off (`AF_SINKS_FS`) |
| `os.rename` | `os.rename(...)` | fs | off (`AF_SINKS_FS`) |
| `os.replace` | `os.replace(...)` | fs | off (`AF_SINKS_FS`) |
| `os.mkdir` | `os.mkdir(...)` | fs | off (`AF_SINKS_FS`) |
| `os.makedirs` | `os.makedirs(...)` | fs | off (`AF_SINKS_FS`) |
| `os.rmdir` | `os.rmdir(...)` | fs | off (`AF_SINKS_FS`) |
| `os.chmod` | `os.chmod(...)` | fs | off (`AF_SINKS_FS`) |
| `os.truncate` | `os.truncate(...)` | fs | off (`AF_SINKS_FS`) |
| `os.symlink` | `os.symlink(...)` | fs | off (`AF_SINKS_FS`) |
| `os.link` | `os.link(...)` | fs | off (`AF_SINKS_FS`) |
| `os.walk` | `os.walk(...)` | fs | off (`AF_SINKS_FS`) |
| `os.listdir` | `os.listdir(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.copy` | `shutil.copy(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.copy2` | `shutil.copy2(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.copyfile` | `shutil.copyfile(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.copytree` | `shutil.copytree(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.move` | `shutil.move(...)` | fs | off (`AF_SINKS_FS`) |
| `shutil.rmtree` | `shutil.rmtree(...)` | fs | off (`AF_SINKS_FS`) |
| `open` | `open(...)` | fs | off (`AF_SINKS_FS`) |
| `save_to_file` | `save_to_file(...)` | fs | off (`AF_SINKS_FS`) |
| `write_to_storage` | `write_to_storage(...)` | fs | off (`AF_SINKS_FS`) |
| `urllib.urlretrieve` | `urllib.request.urlretrieve(...)` | fs | off (`AF_SINKS_FS`) |
| `os.path.join` | `os.path.join(...)` | path | off (`AF_SINKS_PATH`) |
| `os.path.abspath` | `os.path.abspath(...)` | path | off (`AF_SINKS_PATH`) |
| `httpx.get` | `httpx.get(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.post` | `httpx.post(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.put` | `httpx.put(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.patch` | `httpx.patch(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.delete` | `httpx.delete(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.head` | `httpx.head(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.request` | `httpx.request(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.stream` | `httpx.stream(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.Request` | `httpx.Request(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.HTTPTransport` | `httpx.HTTPTransport(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.AsyncHTTPTransport` | `httpx.AsyncHTTPTransport(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.Client` | `httpx.Client(...)` | http | off (`AF_SINKS_HTTP`) |
| `httpx.AsyncClient` | `httpx.AsyncClient(...)` | http | off (`AF_SINKS_HTTP`) |
| `importlib.import_module` | `importlib.import_module(...)` | dynimp | off (`AF_SINKS_DYNIMP`) |
| `__import__` | `__import__(...)` | dynimp | off (`AF_SINKS_DYNIMP`) |
| `import_module` | `import_module(...)` | dynimp | off (`AF_SINKS_DYNIMP`) |
<!-- END GENERATED TABLE -->

The checks that do not come from this file — unauthenticated routes, inconsistent
authentication within a file, untrusted input written next to a dangerous call, and the
strong/weak-form check — live in `tools/ast_criteria.py` and `core/duality.py`.

---

## Every switch

The README lists the ones a user normally sets. This is the whole set; every `AF_*` and
`AGENTAUDIT_*` variable read anywhere in the code appears here, and a test fails if one is
added without being documented.

### Paths and credentials

| Variable | Default | What it does |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | `~/.deepseek_key` | where the LLM API key is read from |
| `GITHUB_KEY_FILE` | `~/.github_token` | GitHub token file, which raises the API rate limit |
| `AF_CODEQL` | `./_tools/codeql/codeql[.exe]` | the CodeQL CLI |
| `AF_QL_DIR` | `core/ql`, or the reference pack if that is absent | which QL pack the frontend runs |
| `AF_PAPER_QL` | `./agentfuzz-official/ql` | the AgentFuzz reference pack; needed only to regenerate queries |
| `AF_SRC_DIR` | `./_targets/src` | where fetched sources are kept |
| `AF_DB_DIR` | `./_targets/db` | where CodeQL databases are kept |
| `AF_TARGET_MAP` | read from `core/config/targets*.yml` | JSON map of `{"short-name": "source root"}` |
| `AGENTAUDIT_HOME` | the current directory | where `out/` and `data/` are written |

### What gets scanned

| Variable | Default | What it does |
|---|---|---|
| `AF_SINKS_FS` / `_PATH` / `_HTTP` / `_DYNIMP` | off | turn on those sink groups |
| `AF_SINKS_EXTRA` | `1` | include the `source: extra` entries in `sinks.yml` at all |
| `AF_SOURCES_EXTRA` | `1` | the same, for `sources.yml` |
| `AF_SOURCES_FILE` | `core/config/sources.yml` | an **additional** source list. It is added on top of the default one, not a replacement for it |
| `AF_PATH_FILTER` | `rel` | match filter paths against the absolute path instead of the project-relative one |
| `AF_NO_FILTER` | off | disable the path filter entirely |
| `AF_NO_DATAFLOW` | `0` | disable the inter-procedural argument-source query |
| `AF_ARGFLOW_ATTR` | `0` | also treat attribute reads as taint steps in that query |
| `AF_DUALITY_SDK` | `0` | turn on the SDK-aware part of the strong/weak-form check |
| `AF_KNOWN_TARGETS` | `core/config/known_targets.yml` | where the screener's exclusion list lives |
| `AF_KNOWN_TARGETS` | `core/config/known_targets.yml` | where the screener's exclusion list lives |

### The triage layer

| Variable | Default | What it does |
|---|---|---|
| `AF_LLM_MAX_CNY` | `30` | hard per-run spend cap; the run stops and reports when it is reached |
| `AF_JUDGE_MT` | `8000` | maximum output tokens for one judgement |
| `AF_JUDGE_ARGSRC` | `1` | send the argument-source evidence to the judge |
| `AF_JUDGE_ARGCTX` | `1` | also send the source of the function the argument came from. Without it the judge sees a data-flow statement about a function it cannot read, and can only answer "outside the given code" |
| `AF_JUDGE_OPARG` | `0` | send the operator's own command-line arguments as context |
| `AF_JUDGE_REPOCFG` | `0` | treat a config file that was cloned with the repository as untrusted, rather than lumping it in with the operator's own config |
| `AF_JUDGE_CFGSRC` | `0` | send evidence about where a config value comes from |
| `AF_JUDGE_SCOPE2` | `0` | pin down what "exceeds its intended scope" means on the `scope_exceeds` axis |

### Everything else

| Variable | Default | What it does |
|---|---|---|
| `AF_GH_DOH` | `https://223.5.5.5/resolve` | DNS-over-HTTPS resolver used by the GitHub client; set to `0` to use the system resolver |
| `AGENTAUDIT_NO_LOG` | off | stop recording scan statistics |
| `AGENTAUDIT_ASCII` | auto-detected | draw the banner with ASCII only |
| `AGENTAUDIT_INTERACTIVE` | auto-detected | force interactive mode on or off |
