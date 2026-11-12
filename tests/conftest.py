"""Shared test configuration: a per-test skip list that is currently empty.

The list exists so a known-failing case can be isolated one at a time by adding
`file::function` to BLOCK2, instead of skipping a whole file and burying the cases that pass.
Keep it empty unless something is genuinely broken; when you add an entry, say why in the
commit message so the next reader knows when it can come back out.
"""
from __future__ import annotations

import pytest

BLOCK2_REASON = "temporarily isolated; see the commit that added this entry"

BLOCK2: set[str] = set()

# Parametrised ids can contain characters that do not survive a hand-written escape,
# so match on `file::function` (everything before `[`) as a second chance.
BLOCK2_PREFIX = {n.split("[")[0] for n in BLOCK2 if "[" in n}


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.nodeid in BLOCK2 or item.nodeid.split("[")[0] in BLOCK2_PREFIX:
            item.add_marker(pytest.mark.skip(reason=BLOCK2_REASON))
