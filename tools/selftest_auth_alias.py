# -*- coding: utf-8 -*-
"""Self-test for `_collect_auth_aliases` (auth-dependency aliases).

Background: a project may declare its auth dependency once and reuse the alias:

    # auth/dependencies.py
    type CurrentUser = Annotated[UserContextDict, Depends(get_current_user)]

    # api/proxy_routes.py
    async def clear_session_endpoint(..., user_context: CurrentUser): ...

If the alias is not collected, every endpoint using it is judged "no auth" -> false
positive. These cases cover the forms an alias can take, including PEP 695.
"""
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ast_criteria import _collect_auth_aliases  # noqa: E402

# Optional: a real cached source file, if one is available locally.
CD = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "..", "data", "target_pool", "_src_cache")
DEP = os.path.join(CD, "auth_dependencies.py.txt")

CASES = [
    # (description, source, should an alias be collected)
    ("classic assignment X = Annotated[...Depends(...)]",
     "CurrentUser = Annotated[User, Depends(get_current_user)]\n", True),
    ("PEP695: type X = Annotated[...Depends(...)]",
     "type CurrentUser = Annotated[User, Depends(get_current_user)]\n", True),
    ("FastAPI shorthand X = Depends(...)",
     "CurrentUser = Depends(get_current_user)\n", True),
    ("PEP695 shorthand: type X = Depends(...)",
     "type CurrentUser = Depends(get_current_user)\n", True),
    ("annotated assignment X: T = Annotated[...Depends(...)]",
     "CurrentUser: tp.Alias = Annotated[User, Depends(get_current_user)]\n",
     True),
    ("multi-line Annotated (Depends on the next line)",
     "type CurrentUser = Annotated[\n    User,\n    Depends(get_current_user),\n]\n",
     True),
    ("lower-case name should NOT be collected (it is a plain variable)",
     "helper = Depends(get_current_user)\n", False),
    ("unrelated assignment should not be collected",
     "MAX_SIZE = 1024\n", False),
]

print("=== _collect_auth_aliases ===")
bad = 0
for desc, src, want in CASES:
    got = bool(_collect_auth_aliases(src))
    ok = (got == want)
    bad += (not ok)
    print("  %s %-52s want=%-5s got=%-5s -> %s"
          % ("OK  " if ok else "FAIL", desc, want, got,
             sorted(_collect_auth_aliases(src))))

print()
if os.path.exists(DEP):
    print("=== real file ===")
    real = open(DEP, encoding="utf-8", errors="replace").read()
    al = _collect_auth_aliases(real)
    print("  aliases collected:", sorted(al) or "(none)")
    print("  contains CurrentUser:", "CurrentUser" in al)
    print()

    print("=== single-line regex vs type-prefixed regex ===")
    LINE = r"^[ \t]*([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    LINE_T = r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    for name, pat in (("current", LINE), ("with type prefix", LINE_T)):
        got = re.findall(pat + r"Annotated\s*\[", real, re.M)
        print("  %-18s -> %s" % (name, got))
    print()
else:
    print("(no cached sample source available; skipping the real-file section)")

print("failed %d / %d" % (bad, len(CASES)))
sys.exit(1 if bad else 0)
