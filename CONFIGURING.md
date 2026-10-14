# Configuring the rules

The checks are not hard-coded. There are three YAML files under `core/config/`, and
`core/gen_ql.py` turns them into the CodeQL queries that actually run. Adding a dangerous
function of your own is a **config change**, not a code change.

```
core/config/
  sinks.yml     the dangerous-call list (the main one)
  sources.yml   what counts as untrusted input
  filters.yml   which paths to ignore
```

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
