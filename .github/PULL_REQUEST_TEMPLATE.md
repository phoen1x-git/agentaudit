## What this changes

## Why

## Checklist

- [ ] `python tools/run_selftests.py` passes (all ten suites, not just the one I touched)
- [ ] `python tools/validate_config.py` passes, if I touched `core/config/`
- [ ] `python -m pytest -q` passes
- [ ] No real repository name, finding, or `owner/repo#<number>` in the diff (placeholders only)
- [ ] `CHANGELOG.md` updated if the default behaviour changed
- [ ] `LIMITATIONS.md` updated if I added a new limit

## If this changes what the scanner reports

Before / after on `python app/scan.py --demo`:

| | candidates | per check |
|---|---|---|
| before | | |
| after | | |

If a new check is noisy, consider a `group` in `core/config/sinks.yml` so it is opt-in, and
say so here.
