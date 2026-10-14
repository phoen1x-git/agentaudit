# Report draft (generated) - **not verified by execution**

> The verdicts in this report were produced by **AI-assisted triage**. Every inference below is phrased as a question and **exploitability is unverified**. Treat the entries as **candidates**, not as confirmed vulnerabilities.

- Round: `demo_round`  |  generated: 2026-01-01T00:00:00
- Rule stamps: `filters.yml=90cd12e` `rubric=ab12cd3` `sinks.yml=ef45ab6`
- Triage cost this run: 0.42 CNY (14 calls / 3 served from cache). To quote a per-batch price, use the first uncached run, not a cached one that reports 0.
- Produced by: **codeql** (see the README for what each mode covers)
- Candidates 4 -> triaged `vuln` **1** (the rest are not_vuln / needs_human and are not listed here)

## Summary

| # | Rule | Project | Location | Type | Confidence | Upstream |
|---|---|---|---|---|---|---|
| 1 | `py-qs/caller` | demo-agent | `src/tools/shell_tool.py:31` | command execution | 0.78 | not checked |

> Every line above is a **fact**. Whether to disclose is a human decision, not the tool's; but before acting, each entry still has to answer: **is it still there? has anyone reported it? will the maintainers fix it?**

---

## Findings

## 1. demo-agent - `src/tools/shell_tool.py:31` - command execution

**Rule**: `py-qs/caller`  |  **Fingerprint**: `demo-agent/src/tools/shell_tool.py:4f2a91c7de` (for deduplication -- do **not** key on line numbers, they drift)
**AI verdict**: `vuln`  confidence 0.78  (designed feature: yes; exceeds intended scope: yes)

### Verified (source was read)

```python
31: result = subprocess.run(command, shell=True, capture_output=True)
```

Fact: `subprocess.run` is called at line 31. The excerpt above is a **verbatim** quote.

### Unverified (not executed)

Everything below is an **inference**. Nothing here was executed:

- **Argument source**: **may** come from "LLM output"
  - evidence: arg0:param(command@shell_tool.py:22) -- command is a parameter of ShellTool.run, and the caller passes the value returned by the model's tool call.
- **Guards along the path**: **may not** effectively constrain the target value
  - evidence: No validator, whitelist or sandbox between the tool argument and subprocess.run in the excerpt.
- **Designed feature?**: Yes (this call is part of what the project is for)
  - evidence: The tool is named shell_tool and exists to run commands, so executing a command is intended; the absence of any restriction is what exceeds the intended scope.
- **Exceeds intended scope?**: **Possibly** (no isolation where one would be expected / may point anywhere)
  - evidence: The tool is named shell_tool and exists to run commands, so executing a command is intended; the absence of any restriction is what exceeds the intended scope.
- **Conclusion**: A command execution risk **may** exist here; **exploitability is unverified**

### Upstream status (filled in by an actual lookup)

> Record only which channels were checked, when, and what was found. Do **not** write "this has never been reported".

- **Not checked** (the upstream lookup was not run this round). Before disclosing, this still needs: (1) the default branch, (2) a snippet search to see whether the site is still present, (3) a search of public advisories for the repo/package.

### Possible directions (effectiveness not verified)

- avoid shell=True; whitelist or strictly escape the arguments

---
