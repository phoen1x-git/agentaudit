# -*- coding: utf-8 -*-
"""Self-test entry point: run every suite in one command.

Run this after any change to `ast_criteria.py` or the modules it depends on. Running the
suites one by one by hand is how a suite gets forgotten.

Usage:
    python tools/run_selftests.py

Non-zero exit code means at least one suite failed; fix it before relying on a scan.

Note: the suites are ordered by module dependency (alias collection -> test-path detection
-> request parameters -> exemptions) so a failure points at the earliest broken layer.
"""
import io
import os
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))

SUITES = [
    ("selftest_wrapper_forward.py", "wrapper forwarding chain"),
    ("selftest_auth.py", "authentication detection"),
    ("selftest_auth_alias.py", "auth alias collection / PEP 695"),
    ("selftest_is_test_path.py", "test-path detection"),
    ("selftest_req_param.py", "request object recognition"),
    ("selftest_wellknown.py", "protocol-level public exemptions (.well-known)"),
    ("selftest_router_deps.py", "router-level dependencies"),
    ("selftest_wrapper_self.py", "wrappers must not count themselves as auth"),
    ("selftest_evidence_file.py", "evidence file field must be a path"),
    ("selftest_crossfile_alias.py", "cross-file type aliases"),
]

PY = sys.executable
fails = []
print("=" * 74)
print("self-test entry point - %d suites" % len(SUITES))
print("=" * 74)

for script, desc in SUITES:
    path = os.path.join(HERE, script)
    if not os.path.exists(path):
        print("  %-28s missing" % script)
        fails.append(script)
        continue
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([PY, "-W", "ignore::SyntaxWarning", "-u", path],
                       capture_output=True, env=env, cwd=HERE)
    out = r.stdout.decode("utf-8", "replace")
    tail = [ln for ln in out.strip().split("\n") if ln.strip()][-1:]
    mark = "OK  " if r.returncode == 0 else "FAIL"
    print("  %s %-28s %s" % (mark, script, desc))
    if tail:
        print("       %s" % tail[0])
    if r.returncode != 0:
        fails.append(script)
        for ln in out.split("\n"):
            if ln.strip().startswith("FAIL"):
                print("       %s" % ln.rstrip())

print("-" * 74)
if fails:
    print("FAILED %d / %d: %s" % (len(fails), len(SUITES), ", ".join(fails)))
    print("Do not rely on a scan until these pass -- the checks changed without validation.")
    sys.exit(1)
print("all suites passed.")
