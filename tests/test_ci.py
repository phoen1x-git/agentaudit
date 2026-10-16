"""The CI config is code too, and nothing else checks it.

A malformed workflow file does not fail a test, or even fail loudly: GitHub simply does not
run it, and the result looks like a repository with no CI. Catching it here costs nothing.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def test_there_is_a_workflow_to_check():
    assert WORKFLOWS, "no workflow files found; the glob is probably wrong"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_the_workflow_parses(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name} does not parse to a mapping"
    assert "jobs" in doc, f"{path.name} has no jobs"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_script_step_is_named(path):
    """A `run:` step without a name shows up as "Run <the whole script>", which is unreadable
    when it is the one that failed. A `uses:` step is fine without one: GitHub names it after
    the action, which reads well enough.
    """
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job_name, job in doc["jobs"].items():
        assert "runs-on" in job, f"{path.name}: job {job_name} has no runs-on"
        steps = job.get("steps") or []
        assert steps, f"{path.name}: job {job_name} has no steps"
        for i, step in enumerate(steps, 1):
            assert step.get("uses") or step.get("run"), \
                f"{path.name}: job {job_name} step {i} does nothing"
            if step.get("run"):
                assert step.get("name"), \
                    f"{path.name}: job {job_name} step {i} runs a script but has no name"


def test_the_commands_the_workflow_runs_exist_in_the_repo():
    """A workflow that calls a script which was renamed fails on the first push, which is a
    slow way to find out."""
    import re
    for path in WORKFLOWS:
        body = path.read_text(encoding="utf-8")
        for named in re.findall(r"\b((?:app|tools|scripts|core)/[\w./-]+\.(?:py|sh))", body):
            assert (ROOT / named).exists(), f"{path.name} runs {named}, which does not exist"
