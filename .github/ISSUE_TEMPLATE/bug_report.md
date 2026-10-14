---
name: Bug report
about: Something is broken, or the output contradicts what the docs say
labels: bug
---

**Do not paste a real finding here.** No repository names, file paths, or `owner/repo#<number>`.
If the problem is with a specific candidate, reduce it to a snippet you wrote yourself.

### What happened

A short description of the behaviour you saw.

### What you expected

Include the exact claim you are testing against — a line from the README, `CONFIGURING.md` or
`LIMITATIONS.md` is ideal.

### How to reproduce

```
```

The fastest reproduction is usually:

```bash
python app/scan.py --demo          # does the bundled sample still work?
python tools/run_selftests.py      # do the rule self-tests pass?
```

### Environment

- Mode: `full` (CodeQL installed) / `offline`
- `python --version`:
- CodeQL version (`_tools/codeql/codeql version`), if used:
- OS:

### If it is a false negative

Please say which check you expected to fire and why. "The tool missed something" is much
harder to act on than "`AF_SINKS_HTTP=1` should have matched this call".
